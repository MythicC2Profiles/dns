package dnsserver

import (
	"bytes"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	mythicConfig "github.com/MythicMeta/MythicContainer/config"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"io"
	"mythicDNS/dnsserver/dnsgrpc"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type DnsServer struct {
	server          *dns.Server
	connections     *sync.Map
	connectionMutex *sync.RWMutex
	domains         []string
	TTL             uint32
	debug           bool
	CacheTimeout    time.Duration
}

// DnsMessageStream tracks the progress of a message in chunk transfer
type DnsMessageStream struct {
	Size          uint32
	TotalReceived uint32
	Messages      map[uint32]*dnsgrpc.DnsPacket
	StartBytes    []uint32
}

// DnsConnection tracks all the messages in/out for a callback/payload
type DnsConnection struct {
	outgoingMsgIDs  []uint32
	outgoingBuffers map[uint32][]byte
	outgoingMutex   *sync.RWMutex

	incomingMessages map[uint32]*DnsMessageStream
	incomingMutex    *sync.Mutex
}

func Initialize(configInstance instanceConfig) *DnsServer {
	server := &DnsServer{
		server:          &dns.Server{Addr: fmt.Sprintf("%s:%d", configInstance.BindIP, configInstance.Port), Net: "udp"},
		connections:     &sync.Map{},
		connectionMutex: &sync.RWMutex{},
		TTL:             0,
		debug:           configInstance.Debug,
		domains:         configInstance.Domains,
	}
	// add our own handlefunc per dns instance we make
	instanceHandler := dns.NewServeMux()
	instanceHandler.HandleFunc(".", func(writer dns.ResponseWriter, req *dns.Msg) {
		server.HandleDNSRequest(writer, req)
	})
	server.server.Handler = instanceHandler
	return server
}

func (s *DnsServer) ListenAndServe() error {
	return s.server.ListenAndServe()
}
func (s *DnsServer) getParentDomain(reqDomain string) string {
	longestParent := ""
	for _, parentDomain := range s.domains {
		if dns.IsSubDomain(parentDomain+".", reqDomain) {
			//logging.LogInfo("found parent domain", "parent", parentDomain)
			if len(parentDomain) > len(longestParent) {
				longestParent = parentDomain
			}
		}
	}
	if longestParent == "" {
		logging.LogError(nil, "Got request with parent domain not tracked", "reqDomain", reqDomain)
		return ""
	}
	return longestParent + "."
}
func (s *DnsServer) HandleDNSRequest(writer dns.ResponseWriter, req *dns.Msg) {
	if req == nil {
		return
	}
	if len(req.Question) < 1 {
		logging.LogError(nil, "No questions in DNS request")
		return
	}
	//logging.LogInfo("got dns request", "question", req.Question, "name", req.Question[0].Name)
	domain := s.getParentDomain(req.Question[0].Name)
	if domain == "" {
		logging.LogError(nil, "Not a tracked domain", "domain", domain)
		return
	}
	resp := s.handleMessage(domain, req)
	err := writer.WriteMsg(resp)
	if err != nil {
		logging.LogError(err, "Failed to write response", "domain", domain)
	}
}
func (s *DnsServer) handleMessage(domain string, req *dns.Msg) *dns.Msg {
	subdomain := req.Question[0].Name[:len(req.Question[0].Name)-len(domain)-1]
	//logging.LogInfo("processing req", "sub domain", subdomain, "domain", domain)
	msg, err := s.parseData(subdomain)
	if err != nil {
		logging.LogError(err, "failed to process message as a Mythic DNS message, returning generic name error", "message", subdomain)
		return s.nameErrorResp(req, dns.RcodeNameError)
	}
	// Msg Type -> Handler
	switch msg.Action {
	case dnsgrpc.Actions_AgentToServer:
		// agent is sending a Mythic message
		return s.AgentToServer(domain, msg, req)
	case dnsgrpc.Actions_ServerToAgent:
		// server is responding with a Mythic message response
		return s.ServerToAgent(domain, msg, req)
	case dnsgrpc.Actions_ReTransmit:
		// agent asking server to retransmit a message
		//return s.ReTransmit(domain, msg, req)
	}
	return nil
}
func (s *DnsServer) GetConnection(msg *dnsgrpc.DnsPacket) *DnsConnection {
	var dnsConnection *DnsConnection
	s.connectionMutex.Lock()
	loadSession, ok := s.connections.Load(msg.AgentSessionID)
	if !ok {
		// we haven't seen this AgentSessionID before, start tracking it
		dnsConnection = s.TrackNewConnection(msg)
	} else {
		dnsConnection = loadSession.(*DnsConnection)
	}
	s.connectionMutex.Unlock()
	return dnsConnection
}
func (s *DnsServer) AgentToServer(domain string, msg *dnsgrpc.DnsPacket, req *dns.Msg) *dns.Msg {
	//logging.LogInfo("got message from AgentToServer", "msg", msg)
	dnsConnection := s.GetConnection(msg)
	respAction := dnsConnection.AddIncomingMessage(msg)
	resp := new(dns.Msg)
	resp.Authoritative = true
	s.ackPacket(resp, msg, req, domain)
	s.addResponseAction(resp, msg, req, domain, respAction)
	return resp
}
func (s *DnsServer) ServerToAgent(domain string, msg *dnsgrpc.DnsPacket, req *dns.Msg) *dns.Msg {
	//logging.LogInfo("got message from CheckForMessage", "msg", msg)
	dnsConnection := s.GetConnection(msg)
	resp := new(dns.Msg)
	s.ackPacket(resp, msg, req, domain)

	dnsConnection.outgoingMutex.Lock()
	defer dnsConnection.outgoingMutex.Unlock()
	if _, ok := dnsConnection.outgoingBuffers[msg.MessageID]; !ok {
		logging.LogError(nil, "request for message that doesn't exist", "msg", msg)
		s.addResponseAction(resp, msg, req, domain, dnsgrpc.Actions_MessageLost)
		return resp
	}
	s.addResponseAction(resp, msg, req, domain, dnsgrpc.Actions_ServerToAgent)
	finishedMessage := false
	size := uint32(len(dnsConnection.outgoingBuffers[msg.MessageID]))
	end := msg.Begin + 128
	if req.Question[0].Qtype == dns.TypeTXT {
		end = msg.Begin + 10000 // arbitrary 10k instead of 128 Bytes per response
	}
	if end >= size {
		end = size
		finishedMessage = true
	}
	chunk := make([]byte, end-msg.Begin)
	copy(chunk, dnsConnection.outgoingBuffers[msg.MessageID][msg.Begin:end])
	responsePacket := &dnsgrpc.DnsPacket{
		Action:         dnsgrpc.Actions_ServerToAgent,
		AgentSessionID: msg.AgentSessionID,
		MessageID:      msg.MessageID,
		Size:           size,
		Begin:          msg.Begin,
		Data:           string(chunk),
	}
	s.AddPacketToResponse(msg, responsePacket, resp, req, domain)
	if finishedMessage {
		delete(dnsConnection.outgoingBuffers, msg.MessageID)
		msgIndex := slices.Index(dnsConnection.outgoingMsgIDs, msg.MessageID)
		endIndex := msgIndex + 1
		if endIndex > len(dnsConnection.outgoingMsgIDs) {
			endIndex = len(dnsConnection.outgoingMsgIDs)
		}
		dnsConnection.outgoingMsgIDs = slices.Delete(dnsConnection.outgoingMsgIDs, msgIndex, endIndex)
	}
	//logging.LogInfo("added response to reply", "resp", resp)
	return resp
}
func getChunks(data []byte, chunkSize int) [][]byte {
	chunks := make([][]byte, 0)
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, chunkSize)
		copy(chunk, data[i:end])
		chunks = append(chunks, chunk)
	}
	return chunks
}
func getTxtChunks(data []byte) []string {
	chunks := []string{}
	for i := 0; i < len(data); i += 255 {
		end := i + 255
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, string(data[i:end]))
	}
	return chunks
}
func (s *DnsServer) AddPacketToResponse(msg *dnsgrpc.DnsPacket, responsePacket *dnsgrpc.DnsPacket, resp *dns.Msg, req *dns.Msg, domain string) {
	msgToSend, err := proto.Marshal(responsePacket)
	if err != nil {
		logging.LogError(err, "failed to marshal response packet")
		return
	}
	// add a message id
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeA:
			resp.Authoritative = true
			chunks := getChunks(msgToSend, 4)
			for i, chunk := range chunks {
				resp.Answer = append(resp.Answer,
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(4 + i)},
						A:   chunk,
					},
				)
			}
		case dns.TypeAAAA:
			resp.Authoritative = true
			chunks := getChunks(msgToSend, 16)
			for i, chunk := range chunks {
				resp.Answer = append(resp.Answer,
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(4 + i)},
						AAAA: chunk,
					},
				)
			}
		case dns.TypeTXT:
			resp.Authoritative = true
			chunks := getTxtChunks([]byte(base64.StdEncoding.EncodeToString(msgToSend)))
			resp.Answer = append(resp.Answer,
				&dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 4},
					Txt: chunks,
				},
			)
		}
	}
}
func (s *DnsServer) ackPacket(resp *dns.Msg, msg *dnsgrpc.DnsPacket, req *dns.Msg, domain string) {
	resp = resp.SetReply(req)

	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeA:
			AgentSessionID := make([]byte, net.IPv4len)
			binary.LittleEndian.PutUint32(AgentSessionID, msg.AgentSessionID)
			messageIDRespBuf := make([]byte, net.IPv4len)
			binary.LittleEndian.PutUint32(messageIDRespBuf, msg.MessageID)
			messageStartRespBuf := make([]byte, net.IPv4len)
			binary.LittleEndian.PutUint32(messageStartRespBuf, msg.Begin)
			resp.Authoritative = true
			// resp.RecursionAvailable = complete
			resp.Answer = append(resp.Answer,
				&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   AgentSessionID,
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
					A:   messageIDRespBuf,
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 2},
					A:   messageStartRespBuf,
				},
			)
		case dns.TypeAAAA:
			resp.Authoritative = true
			AgentSessionID := make([]byte, net.IPv6len)
			binary.LittleEndian.PutUint32(AgentSessionID, msg.AgentSessionID)
			messageIDRespBuf := make([]byte, net.IPv6len)
			binary.LittleEndian.PutUint32(messageIDRespBuf, msg.MessageID)
			messageStartRespBuf := make([]byte, net.IPv6len)
			binary.LittleEndian.PutUint32(messageStartRespBuf, msg.Begin)
			// resp.RecursionAvailable = complete
			resp.Answer = append(resp.Answer,
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
					AAAA: AgentSessionID,
				},
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
					AAAA: messageIDRespBuf,
				},
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 2},
					AAAA: messageStartRespBuf,
				},
			)
		case dns.TypeTXT:
			// 255 max characters per string
			resp.Authoritative = true
			resp.Answer = append(resp.Answer,
				&dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
					Txt: []string{
						fmt.Sprintf("%v", msg.AgentSessionID),
					},
				},
				&dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
					Txt: []string{
						fmt.Sprintf("%v", msg.MessageID),
					},
				},
				&dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 2},
					Txt: []string{
						fmt.Sprintf("%v", msg.Begin),
					},
				})
		}
	}
	//logging.LogInfo("setting reply", "resp", resp)
}
func (s *DnsServer) addResponseAction(resp *dns.Msg, msg *dnsgrpc.DnsPacket, req *dns.Msg, domain string, action dnsgrpc.Actions) {

	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeA:
			resp.Authoritative = true
			actionRespBuf := make([]byte, net.IPv4len)
			binary.LittleEndian.PutUint32(actionRespBuf, uint32(action))
			// resp.RecursionAvailable = complete
			resp.Answer = append(resp.Answer,
				&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3},
					A:   actionRespBuf,
				},
			)
		case dns.TypeAAAA:
			resp.Authoritative = true
			actionRespBuf := make([]byte, net.IPv6len)
			binary.LittleEndian.PutUint32(actionRespBuf, uint32(action))
			// resp.RecursionAvailable = complete
			resp.Answer = append(resp.Answer,
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3},
					AAAA: actionRespBuf,
				},
			)
		case dns.TypeTXT:
			resp.Authoritative = true
			resp.Answer = append(resp.Answer,
				&dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3},
					Txt: []string{
						fmt.Sprintf("%v", action),
					},
				})
		}
	}
	//logging.LogInfo("setting reply", "resp", resp)
}
func (s *DnsServer) nameErrorResp(req *dns.Msg, errCode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, errCode)
	resp.Authoritative = true
	return resp
}
func (s *DnsServer) parseData(subdomain string) (*dnsgrpc.DnsPacket, error) {
	subdata := strings.Join(strings.Split(subdomain, "."), "")
	//logging.LogInfo("parsing data", "raw data", subdata)
	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(subdata))
	if err != nil {
		logging.LogError(err, "failed to decode subdata")
		return nil, err
	}
	msg := &dnsgrpc.DnsPacket{}
	err = proto.Unmarshal(data, msg)
	if err != nil {
		logging.LogError(err, "failed to unmarshal data", "data", data)
		return nil, err
	}
	//logging.LogInfo("got msg", "msg", msg)
	return msg, nil
}
func (s *DnsServer) TrackNewConnection(msg *dnsgrpc.DnsPacket) *DnsConnection {
	dnsConn := &DnsConnection{
		outgoingMsgIDs:   []uint32{},          // message IDs that need to be picked up
		outgoingBuffers:  map[uint32][]byte{}, // message IDs to data to send to agent
		outgoingMutex:    &sync.RWMutex{},
		incomingMessages: map[uint32]*DnsMessageStream{},
		incomingMutex:    &sync.Mutex{},
	}
	s.connections.Store(msg.AgentSessionID, dnsConn)
	return dnsConn
}

var tr = &http.Transport{
	TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	MaxIdleConns:      1,
	MaxConnsPerHost:   1,
	DisableKeepAlives: true,
}
var client = &http.Client{
	Transport: tr,
}

func (con *DnsConnection) AddIncomingMessage(msg *dnsgrpc.DnsPacket) dnsgrpc.Actions {
	con.incomingMutex.Lock()
	defer con.incomingMutex.Unlock()
	if con.incomingMessages[msg.MessageID] == nil {
		con.incomingMessages[msg.MessageID] = &DnsMessageStream{
			TotalReceived: 0,
			Messages:      make(map[uint32]*dnsgrpc.DnsPacket),
			Size:          msg.Size,
			StartBytes:    []uint32{},
		}
	}
	if slices.Contains(con.incomingMessages[msg.MessageID].StartBytes, msg.Begin) {
		return msg.Action // this is a duplicate, we've seen this one before
	}
	con.incomingMessages[msg.MessageID].StartBytes = append(con.incomingMessages[msg.MessageID].StartBytes, msg.Begin)
	con.incomingMessages[msg.MessageID].TotalReceived += uint32(len(msg.Data))
	con.incomingMessages[msg.MessageID].Messages[msg.Begin] = msg
	if con.incomingMessages[msg.MessageID].TotalReceived == msg.Size {
		totalBuffer := ""
		// sort all the start bytes to be in order
		sort.Slice(con.incomingMessages[msg.MessageID].StartBytes, func(i, j int) bool { return i < j })
		// iterate over the start bytes and add the corresponding string data together
		for i := 0; i < len(con.incomingMessages[msg.MessageID].StartBytes); i++ {
			totalBuffer += con.incomingMessages[msg.MessageID].Messages[con.incomingMessages[msg.MessageID].StartBytes[i]].Data
		}
		// remove the tracking of this msg.MessageID because we got the whole message
		delete(con.incomingMessages, msg.MessageID)
		// send this totalBuffer off to Mythic for processing
		logging.LogInfo("sending full message to mythic", "message id", msg.MessageID, "agent session id", msg.AgentSessionID)
		requestURL := fmt.Sprintf("http://%s:%d/agent_message", mythicConfig.MythicConfig.MythicServerHost, mythicConfig.MythicConfig.MythicServerPort)
		req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer([]byte(totalBuffer)))
		if err != nil {
			logging.LogError(err, "failed to create request")
		}
		req.Header.Set("mythic", "dns")
		resp, err := client.Do(req)
		if err != nil {
			logging.LogError(err, "failed to send request")
			resp.Body.Close()
			return dnsgrpc.Actions_ReTransmit
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logging.LogError(nil, "bad response from server", "statuscode", resp.StatusCode)
			return dnsgrpc.Actions_ReTransmit
		}
		// add the response to the outgoing buffers for the agent to pick up next
		con.outgoingBuffers[msg.MessageID] = body
		con.outgoingMsgIDs = append(con.outgoingMsgIDs, msg.MessageID)
		return dnsgrpc.Actions_ServerToAgent
	}
	return msg.Action
}
