package dnsserver

import (
	"bytes"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"mythicDNS/dnsserver/dnsgrpc"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	mythicConfig "github.com/MythicMeta/MythicContainer/config"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/miekg/dns"
)

type DnsServer struct {
	server          *dns.Server
	tcpServer       *dns.Server
	connections     *sync.Map
	connectionMutex *sync.RWMutex
	domains         []string
	TTL             uint32
	debug           bool
	CacheTimeout    time.Duration
}

// DnsMessageStream tracks the progress of a message in chunk transfer
type DnsMessageStream struct {
	TotalChunks    uint32
	ChunksReceived map[uint32]bool
	Messages       map[uint32]*dnsgrpc.DnsPacket
}

// DnsConnection tracks all the messages in/out for a callback/payload
type DnsConnection struct {
	outgoingMsgIDs        []uint32
	outgoingBuffers       map[uint32][]byte
	outgoingMsgIDsToClear []uint32
	outgoingMutex         *sync.RWMutex

	incomingMessages map[uint32]*DnsMessageStream
	incomingMutex    *sync.Mutex
}
type AgentMessageMythicUITracking struct {
	AgentCallbackID string `json:"agentCallbackId"`
	ExtraInfo       string `json:"extraInfo"`
	LastUpdateTime  time.Time
	PerformedUpdate bool
}

var AgentIDToMythicIDMap = make(map[uint32]AgentMessageMythicUITracking)
var AgentIDToMythicIDLock sync.RWMutex

func Initialize(configInstance instanceConfig) *DnsServer {
	server := &DnsServer{
		server: &dns.Server{
			Addr:    fmt.Sprintf("%s:%d", configInstance.BindIP, configInstance.Port),
			Net:     "udp",
			UDPSize: 4096,
		},
		tcpServer: &dns.Server{
			Addr:    fmt.Sprintf("%s:%d", configInstance.BindIP, configInstance.Port),
			Net:     "tcp",
			UDPSize: 4096,
		},
		connections:     &sync.Map{},
		connectionMutex: &sync.RWMutex{},
		TTL:             0,
		debug:           configInstance.Debug,
		domains:         configInstance.Domains,
	}
	// add our own handlefunc per dns instance we make
	instanceHandler := dns.NewServeMux()
	instanceHandler.HandleFunc(".", func(writer dns.ResponseWriter, req *dns.Msg) {
		//logging.LogInfo("got a UDP request", "request", req)
		server.HandleDNSRequest(writer, req)
	})
	server.server.Handler = instanceHandler

	instanceTCPHandler := dns.NewServeMux()
	instanceTCPHandler.HandleFunc(".", func(writer dns.ResponseWriter, req *dns.Msg) {
		logging.LogInfo("got a TCP request", "request", req)
		server.HandleDNSRequest(writer, req)
	})
	server.tcpServer.Handler = instanceTCPHandler
	return server
}

func (s *DnsServer) ListenAndServe() error {
	var err error
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		logging.LogInfo("starting UDP server")
		udpErr := s.server.ListenAndServe()
		if udpErr != nil {
			err = udpErr
			logging.LogError(udpErr, "Failed to start UDP server")
		}
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		logging.LogInfo("starting TCP server")
		tcpErr := s.tcpServer.ListenAndServe()
		if tcpErr != nil {
			err = tcpErr
			logging.LogError(tcpErr, "Failed to start TCP server")
		}
		wg.Done()
	}()
	wg.Wait()
	return err
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
		logging.LogError(nil, "Not a tracked domain", "domain", req.Question[0].Name)
		return
	}
	resp := s.handleMessage(domain, req)
	//logging.LogInfo("sending final message back", "response", resp)
	err := writer.WriteMsg(resp)
	if err != nil {
		logging.LogError(err, "Failed to write response", "domain", domain)
	}
}
func (s *DnsServer) handleMessage(domain string, req *dns.Msg) *dns.Msg {
	if len(req.Question[0].Name) == len(domain) {
		logging.LogError(nil, "no subdomain data given")
		return s.nameErrorResp(req, dns.RcodeNameError)
	}
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
	return s.nameErrorResp(req, dns.RcodeNameError)
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
	resp = resp.SetReply(req)
	resp.Authoritative = true
	s.addResponseAction(resp, msg, req, domain, respAction)
	dnsConnection.UpdateTransferStatus(msg.AgentSessionID, msg.Action, msg.CurrentChunk, msg.TotalChunks)
	return resp
}
func (s *DnsServer) getMessageLengthPerChunk(req *dns.Msg) uint32 {
	if req.Question[0].Qtype == dns.TypeA {
		return 128 // in TypeA, need 1B for order, 3B for data per Answer. 1 Answer for Action
	} else if req.Question[0].Qtype == dns.TypeAAAA {
		return 630 // in TypeAAAA, need 1B for order, 15 for data per Answer. 1 Answer for Action
	} else if req.Question[0].Qtype == dns.TypeTXT {
		return 1000 // arbitrary 1k instead of 128 Bytes per response
	}
	return 100
}
func (s *DnsServer) ServerToAgent(domain string, msg *dnsgrpc.DnsPacket, req *dns.Msg) *dns.Msg {
	//logging.LogInfo("got message from CheckForMessage", "msg", msg)
	dnsConnection := s.GetConnection(msg)
	resp := new(dns.Msg)
	resp = resp.SetReply(req)
	resp.Authoritative = true
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
	messageLengthPerChunk := s.getMessageLengthPerChunk(req)
	totalChunks := size / messageLengthPerChunk
	if totalChunks*messageLengthPerChunk < size {
		totalChunks += 1 // might need to add 1 if there's a portion left over
	}
	end := (msg.CurrentChunk * messageLengthPerChunk) + messageLengthPerChunk
	if end >= size {
		end = size
		finishedMessage = true
	}
	chunk := make([]byte, end-(msg.CurrentChunk*messageLengthPerChunk))
	copy(chunk, dnsConnection.outgoingBuffers[msg.MessageID][msg.CurrentChunk*messageLengthPerChunk:end])
	responsePacket := &dnsgrpc.DnsPacket{
		Action:         dnsgrpc.Actions_ServerToAgent,
		AgentSessionID: msg.AgentSessionID,
		MessageID:      msg.MessageID,
		TotalChunks:    totalChunks,
		CurrentChunk:   msg.CurrentChunk,
		Data:           chunk,
	}
	s.AddPacketToResponse(msg, responsePacket, resp, req, domain)
	dnsConnection.UpdateTransferStatus(responsePacket.AgentSessionID, responsePacket.Action, responsePacket.CurrentChunk, responsePacket.TotalChunks)
	if finishedMessage {
		if slices.Contains(dnsConnection.outgoingMsgIDsToClear, msg.MessageID) {
			logging.LogInfo("finished sending message again", "message id", msg.MessageID, "chunk", chunk)
			return resp
		}
		logging.LogInfo("finished sending message", "message id", msg.MessageID)
		if len(dnsConnection.outgoingMsgIDsToClear) > 0 {
			priorMessageID := dnsConnection.outgoingMsgIDsToClear[0]
			//logging.LogInfo("finished message, removing prior buffer", "message id", priorMessageID)
			delete(dnsConnection.outgoingBuffers, priorMessageID)
			msgIndex := slices.Index(dnsConnection.outgoingMsgIDs, priorMessageID)
			endIndex := msgIndex + 1
			if endIndex > len(dnsConnection.outgoingMsgIDs) {
				endIndex = len(dnsConnection.outgoingMsgIDs)
			}
			dnsConnection.outgoingMsgIDs = slices.Delete(dnsConnection.outgoingMsgIDs, msgIndex, endIndex)
			dnsConnection.outgoingMsgIDsToClear = dnsConnection.outgoingMsgIDsToClear[1:]
		}
		dnsConnection.outgoingMsgIDsToClear = append(dnsConnection.outgoingMsgIDsToClear, msg.MessageID)
	}
	//logging.LogInfo("added response to reply", "resp", resp)
	return resp
}
func getChunks(data []byte, chunkSize int) [][]byte {
	chunks := make([][]byte, 0)
	index := 0
	remaining := chunkSize
	endReached := false
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			endReached = true
			remaining = end - len(data) // how many extra bytes there are
			end = len(data)
		}
		chunk := make([]byte, chunkSize+1)
		copy(chunk[1:], data[i:end])
		chunk[0] = byte(index + 1)
		if endReached {
			for j := len(chunk) - 1; j > chunkSize-remaining; j-- {
				chunk[j] = uint8(remaining)
			}
		}
		//logging.LogInfo("adding chunk", "chunk[0]", chunk[0])
		chunks = append(chunks, chunk)
		if !endReached && i+chunkSize >= len(data) {
			chunkPadding := make([]byte, chunkSize+1)
			for j := 1; j <= chunkSize; j++ {
				chunkPadding[j] = byte(remaining)
			}
			chunkPadding[0] = byte(index + 2)
			chunks = append(chunks, chunkPadding)
		}
		index++
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
			chunks := getChunks(msgToSend, net.IPv4len-1)
			for _, chunk := range chunks {
				resp.Answer = append(resp.Answer,
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
						A:   chunk,
					},
				)
			}
		case dns.TypeAAAA:
			chunks := getChunks(msgToSend, net.IPv6len-1)
			for _, chunk := range chunks {
				resp.Answer = append(resp.Answer,
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
						AAAA: chunk,
					},
				)
			}
		case dns.TypeTXT:
			chunks := getTxtChunks([]byte(base64.StdEncoding.EncodeToString(msgToSend)))
			resp.Answer = append(resp.Answer,
				&dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
					Txt: chunks,
				},
			)
		}
	}
}
func (s *DnsServer) addResponseAction(resp *dns.Msg, msg *dnsgrpc.DnsPacket, req *dns.Msg, domain string, action dnsgrpc.Actions) {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeA:
			actionRespBuf := make([]byte, net.IPv4len)
			actionRespBuf[net.IPv4len-1] = byte(action)
			resp.Answer = append(resp.Answer,
				&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   actionRespBuf,
				},
			)
		case dns.TypeAAAA:
			actionRespBuf := make([]byte, net.IPv6len)
			actionRespBuf[net.IPv6len-1] = byte(action)
			resp.Answer = append(resp.Answer,
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
					AAAA: actionRespBuf,
				},
			)
		case dns.TypeTXT:
			resp.Answer = append(resp.Answer,
				&dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
					Txt: []string{
						fmt.Sprintf("%d", action),
					},
				})
		}
	}
	//logging.LogInfo("setting reply", "resp", resp)
}
func (s *DnsServer) nameErrorResp(req *dns.Msg, errCode int) *dns.Msg {
	resp := new(dns.Msg)
	resp = resp.SetReply(req)
	resp.SetRcode(req, errCode)
	resp.Authoritative = true
	return resp
}
func (s *DnsServer) parseData(subdomain string) (*dnsgrpc.DnsPacket, error) {
	subdata := strings.Join(strings.Split(subdomain, "."), "")
	//logging.LogInfo("parseData", "raw data", subdata)
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
	//logging.LogInfo("parseData", "msg", msg)
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
			ChunksReceived: make(map[uint32]bool),
			Messages:       make(map[uint32]*dnsgrpc.DnsPacket),
			TotalChunks:    msg.TotalChunks,
		}
	}
	if _, ok := con.incomingMessages[msg.MessageID].ChunksReceived[msg.CurrentChunk]; ok {
		return msg.Action // this is a duplicate, we've seen this one before
	}
	con.incomingMessages[msg.MessageID].ChunksReceived[msg.CurrentChunk] = true
	con.incomingMessages[msg.MessageID].Messages[msg.CurrentChunk] = msg
	//fmt.Printf("got message: %v\n", msg.Data)
	//con.incomingMessages[msg.MessageID].StartBytes = append(con.incomingMessages[msg.MessageID].StartBytes, msg.Begin)
	//con.incomingMessages[msg.MessageID].TotalReceived += uint32(len(msg.Data))
	//con.incomingMessages[msg.MessageID].Messages[msg.Begin] = msg
	if uint32(len(con.incomingMessages[msg.MessageID].ChunksReceived)) == msg.TotalChunks {
		totalBuffer := make([]byte, 0)
		// sort all the start bytes to be in order
		//sort.Slice(con.incomingMessages[msg.MessageID].StartBytes, func(i, j int) bool { return i < j })
		// iterate over the start bytes and add the corresponding string data together
		for i := uint32(0); i < msg.TotalChunks; i++ {
			totalBuffer = append(totalBuffer, con.incomingMessages[msg.MessageID].Messages[i].Data...)
		}

		//for i := 0; i < len(con.incomingMessages[msg.MessageID].StartBytes); i++ {
		//	copy(totalBuffer[con.incomingMessages[msg.MessageID].Messages[con.incomingMessages[msg.MessageID].StartBytes[i]].Begin:], con.incomingMessages[msg.MessageID].Messages[con.incomingMessages[msg.MessageID].StartBytes[i]].Data)
		//}
		// remove the tracking of this msg.MessageID because we got the whole message
		delete(con.incomingMessages, msg.MessageID)
		go con.UpdateMythicIDTracking(msg.AgentSessionID, totalBuffer)
		finalBuffer := base64.StdEncoding.EncodeToString(totalBuffer)
		// send this totalBuffer off to Mythic for processing
		logging.LogInfo("sending full message to mythic", "message id", msg.MessageID, "agent session id", msg.AgentSessionID)
		requestURL := fmt.Sprintf("http://%s:%d/agent_message", mythicConfig.MythicConfig.MythicServerHost, mythicConfig.MythicConfig.MythicServerPort)
		req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer([]byte(finalBuffer)))
		if err != nil {
			logging.LogError(err, "failed to create request")
		}
		req.Header.Set("mythic", "dns")
		resp, err := client.Do(req)
		if err != nil {
			logging.LogError(err, "failed to send request")
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			return dnsgrpc.Actions_ReTransmit
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logging.LogError(nil, "bad response from server", "statuscode", resp.StatusCode)
			return dnsgrpc.Actions_ReTransmit
		}
		// add the response to the outgoing buffers for the agent to pick up next
		//logging.LogInfo("received response from server", "body", body)
		finalResponse, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			logging.LogError(err, "failed to decode response", "response", string(body))
			return dnsgrpc.Actions_ReTransmit
		}
		con.outgoingBuffers[msg.MessageID] = finalResponse
		con.outgoingMsgIDs = append(con.outgoingMsgIDs, msg.MessageID)
		return dnsgrpc.Actions_ServerToAgent
	}
	return msg.Action
}
func (con *DnsConnection) UpdateMythicIDTracking(AgentSessionID uint32, MythicMessage []byte) {
	callbackUUID := ""
	if len(MythicMessage) > 40 {
		callbackUUIDParsed, err := uuid.Parse(string(MythicMessage[:36]))
		if err != nil {
			logging.LogError(err, "failed to parse callback UUID")
			return
		}
		callbackUUID = callbackUUIDParsed.String()
	} else {
		return
	}
	AgentIDToMythicIDLock.RLock()
	agentData, ok := AgentIDToMythicIDMap[AgentSessionID]
	AgentIDToMythicIDLock.RUnlock()
	if ok {
		// we've seen this AgentSessionID before, but see if it's different and update if necessary
		if agentData.AgentCallbackID != callbackUUID && callbackUUID != "" {
			agentData.AgentCallbackID = callbackUUID
			AgentIDToMythicIDLock.Lock()
			AgentIDToMythicIDMap[AgentSessionID] = agentData
			AgentIDToMythicIDLock.Unlock()
			return
		}
		return
	}

	agentData = AgentMessageMythicUITracking{
		AgentCallbackID: callbackUUID,
		ExtraInfo:       "",
		LastUpdateTime:  time.Now(),
		PerformedUpdate: false,
	}
	AgentIDToMythicIDLock.Lock()
	AgentIDToMythicIDMap[AgentSessionID] = agentData
	AgentIDToMythicIDLock.Unlock()

}
func (con *DnsConnection) UpdateTransferStatus(AgentSessionID uint32, Action dnsgrpc.Actions, currentChunk uint32, size uint32) {
	AgentIDToMythicIDLock.RLock()
	agentStatus, ok := AgentIDToMythicIDMap[AgentSessionID]
	AgentIDToMythicIDLock.RUnlock()
	if !ok {
		return
	}
	if agentStatus.LastUpdateTime.Add(time.Duration(5) * time.Second).After(time.Now()) {
		return
	}
	newMessage := ""
	updateLastCheckinTime := true
	updateLastCheckinTimeC2 := "dns"
	if currentChunk == 0 {
		if agentStatus.ExtraInfo != "" || !agentStatus.PerformedUpdate {
			resp, err := mythicrpc.SendMythicRPCCallbackUpdate(mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackID:                   &agentStatus.AgentCallbackID,
				ExtraInfo:                         &newMessage,
				UpdateLastCheckinTime:             &updateLastCheckinTime,
				UpdateLastCheckinTimeViaC2Profile: &updateLastCheckinTimeC2,
			})
			if err != nil {
				logging.LogError(err, "failed to send callback update")
			} else if !resp.Success {
				if resp.Error != "sql: no rows in result set" {
					logging.LogError(nil, "failed to send callback update", "response", resp.Error, "agent session id", AgentSessionID, "agent callback id", agentStatus.AgentCallbackID)
				}
			}
		}
		AgentIDToMythicIDLock.Lock()
		agentStatus.ExtraInfo = newMessage
		agentStatus.LastUpdateTime = time.Now()
		agentStatus.PerformedUpdate = true
		AgentIDToMythicIDMap[AgentSessionID] = agentStatus
		AgentIDToMythicIDLock.Unlock()
		return
	}
	if Action == dnsgrpc.Actions_ServerToAgent {
		newMessage = fmt.Sprintf("Mythic->Agent: Sending")
	} else if Action == dnsgrpc.Actions_AgentToServer {
		newMessage = fmt.Sprintf("Agent->Mythic: Sending")
	}
	percentage := (float32(currentChunk) / float32(size)) * 100
	newMessage += fmt.Sprintf(" %d/%d (%.2f%%) Chunks...", currentChunk, size, percentage)
	resp, err := mythicrpc.SendMythicRPCCallbackUpdate(mythicrpc.MythicRPCCallbackUpdateMessage{
		AgentCallbackID:                   &agentStatus.AgentCallbackID,
		ExtraInfo:                         &newMessage,
		UpdateLastCheckinTime:             &updateLastCheckinTime,
		UpdateLastCheckinTimeViaC2Profile: &updateLastCheckinTimeC2,
	})
	if err != nil {
		logging.LogError(err, "failed to send callback update")
	} else if !resp.Success {
		logging.LogError(nil, "failed to send callback update", "response", resp.Error, "agent session id", AgentSessionID, "agent callback id", agentStatus.AgentCallbackID)
	}
	AgentIDToMythicIDLock.Lock()
	agentStatus.ExtraInfo = newMessage
	agentStatus.LastUpdateTime = time.Now()
	agentStatus.PerformedUpdate = true
	AgentIDToMythicIDMap[AgentSessionID] = agentStatus
	AgentIDToMythicIDLock.Unlock()
}
