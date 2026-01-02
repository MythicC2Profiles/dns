+++
title = "DNS"
chapter = false
weight = 5
+++

## Overview
This C2 Profile uses DNS requests to communicate between the agent and the C2 container, where messages are aggregated and forwarded to the Mythic API.
The DNS Requests use a format similar to the Sliver C2 Framework's DNS C2 (https://github.com/BishopFox/sliver/blob/master/server/c2/dns.go) and (https://sliver.sh/docs?name=DNS+C2).
However, Mythic's version is a bit different and slightly less complex (this is subject to change as this is currently in beta). 

To configure DNS properly, you'll want a setup like the following:

If your DNS name is `mydomain.com`, then you'll configure DNS with the following three entries:

* Type: A Record, Host: `ns1`, Value: IP address of where Mythic's DNS C2 Profile is running or redirector that'll forward DNS traffic
* Type: A Record, Host: `mydomain.com`, Value: same as above
* Type: NS Record, Host: `dns`, Value: `ns1.mydomain.com.` (note the trailing `.`, it might get auto-added by your provider)
  * This `host` value can be whatever you want and will be the main subdomain for your DNS traffic. Naturally, the longer this is the less room you have for messages.

When building your payload, you'd configure your domain as `dns.mydomain.com`. The comms will then be in the format of `[stuff].dns.mydomain.com`. 


To provide metadata about message transfers and ordering while still minimizing space, Mythic's DNS uses the following protobuf:
```protobuf
syntax = "proto3";
enum Actions {
  AgentToServer = 0;
  ServerToAgent = 1;
  ReTransmit = 2;
  MessageLost = 3;
}
message DnsPacket {
  Actions  Action       = 1;
  uint32 AgentSessionID = 2;
  uint32 MessageID      = 3;
  uint32 TotalChunks    = 4;
  uint32 CurrentChunk   = 5;
  bytes  Data           = 6;
}
```

## When transferring from Agent -> Server:

Agents will put a "chunk" of their message in the "Data" field; this message is then marshalled and converted to base32 format (without padding). 
This "message" is the same as a normal Mythic message _except_ it's NOT base64 encoded. Since we're using protobuf and doing Base32 encoding on top of that, it's unnecessary to also do Base64 encoding.
This resulting base32 message is what gets sent via a DNS Query message to the Mythic server.

Each request gets a reply with 1 answer - the Action. This is used to indicate from the server if everything is:
* AgentToServer - all good, please send the next chunk
* ServerToAgent - the message is finished and processed by Mythic, there is a response waiting for you
* ReTransmit - something went wrong, please resend entire message

## When transferring from Server -> Agent:

Agents will ask for a starting "CurrentChunk" of 0 and will get back the first chunk along with information about the total number of chunks. 
The agent should keep making requests for the next chunk until they've received all chunks.

When data is coming back from Server -> Agent, these protobuf messages will be encoded within A, AAAA, and TXT records. So it's important to be able to parse them back out properly.
The big thing here is that order of these responses is not guaranteed - so a response might have 10 A records in it, but your agent needs to be able to put these in the proper order to be able to unmarshal them.
To do this, we encode an "order" byte as the Most Significant Byte in A and AAAA records. The rest of the bytes (3B and 127B contain the actual data).
As you might suspect, just encoding our data in these fixed-length fields means that we might end up with excess space, so we have to properly remove that.
To do this, Mythic takes the same approach for padding that AES-CBC uses. To be specific, let's take an example:

We're using AAAA records and for the last AAAA record, we only need 100 bytes of data (even though there's 127 bytes of space after we use 1 byte for ordering).
If we don't do any padding, then there's no way to know if one of the trailing \x00 bytes is actually part of the message or not. So, we calculate how many "padding" bytes exist (128 - 1 - 100) and we're left with 27. 
This is the 128 total bytes, minus 1 for ordering, minus the 100 that we're using, leaves us with 27, or \x1B. So, instead of filling the remaining bytes with \x00, we fill them with \x1B.
Now, once we put all the messages in order (identified by their Most Significant Byte - don't include this in the final message though) - we look at the very last byte (\x1B) and remove that many bytes from our message.
Finally, with all that done, we can unmarshal the data properly with protobuf. 

What if you have the exact amount of data you need? Our last chunk needed 127B of data. In that case, there will be one more entry that is nothing but padding, \x7F. That way you _always_ can look at the last Byte and remove that many Bytes.
This allows us to save the extra space that would be taken up by Base64 encoding the whole message first before splitting it up (in that case, there'd still be "padding", but it would always be \x00 bytes).


## General Notes

* The AgentSessionID is generated by the payload when it first executes and is a random uint32 value. This never changes and is NOT your Mythic UUIDs.
* The MessageID is a random uint32 value generated by the payload _for each message_ that it's trying to send to Mythic (not each DnsPacket, but each normal Mythic message). 
* The CurrentChunk value is the uint32 value of the current chunk that's being sent/received (starts with 0).
* The Action indicates to the agent some context. When sending messages from Agent to Server, this will be AgentToServer for every message except for the last one where the server will reply with ServerToAgent to indicate that it got everything and Mythic has a reply.
  * A ReTransmit action asks the agent to stop and retransmit the entire message (all chunks) again - this typically means something happened on the DNS server side and it lost track of the message.
  * A MessageLost action happens when the agent is requesting a message from the server and typically happens if the server component restarts during message transmission. In this case, the server no longer has the message to send and the agent should consider it lost.

For example:
Sending a Mythic Checkin message will be the uuid + message format. That message is chunked up and put into a series of these DnsPacket objects.
The number of chunks depends on the length of the DNS domain being used (along with max domain length and max subdomain length). Let's assume there's two chunks with 100 Bytes of data in the first chunk and 50 Bytes in the second.
The agent would generate one MessageID, and that MessageID would be the same for both chunks. 
TotalChunks would be 2 for both messages. CurrentChunk for the first message would be 0, but would be 1 for the second.


### C2 Workflow
{{<mermaid>}}
sequenceDiagram
    
  
{{< /mermaid >}}

## Configuration Options
The profile reads a `config.json` file and binds to ports to receive DNS requests.

```JSON
{
  "instances": [
    {
      "port": 53,
      "debug": false,
      "bind_ip": "0.0.0.0",
      "domains": ["dns.localhost", "fake.localhost", "this.is.something.longer.localhost"]
    }
  ]
}


```

## Profile Options

#### domains
A list of domains to use for DNS Queries. The longer the domain, the less room there will be to transfer data.

#### killdate
Date for the agent to automatically exit, typically after an assessment is finished.

#### encrypted_exchange_check
True or False for if you want to perform a key exchange with the Mythic Server. When this is true, the agent uses the key specified by the base64 32Byte key to send an initial message to the Mythic server with a newly generated RSA public key. If this is set to `F`, then the agent tries to just use the base64 of the key as a static AES key for encryption. If that key is also blanked out, then the requests will all be in plaintext.

#### callback_interval
A number to indicate how many seconds the agent should wait in between tasking requests.

#### callback_jitter
Percentage of jitter effect for callback interval.

#### Domain Rotation
This indicates how you want your domains to be used (only really matters if you specify more than one domain). `fail-over` will use the first domain until it fails `failover_threshold` times, then it moves to the next one. `round-robin` will just keep using the next one in sequence for each message. `random` will just randomly use them.

#### AESPSK
Indicate if you want to use no crypto (i.e. plaintext) or if you want to use Mythic's aes256_hmac. Using no crypto is really helpful for agent development so that it's easier to see messages and get started faster, but for actual operations you should leave the default to aes256_hmac.

#### failover_threshold
How many times a domain should fail before moving on to the next domain when the domain rotation is `fail-over`.

#### dns_server
What is the DNS Server IP and Port (i.e: `8.8.8.8:53`) to use when issuing DNS requests.

#### record_type
What kinds of requests should the agent make and receive. A, AAAA, or TXT requests.

#### max_query_length
What is the maximum length of a query from the agent to Mythic. The hard limit is 255 by DNS protocol standards, but that could also stand out in environments. The smaller this number, the less data can be sent per request.

#### max_subdomain_length
What is the maximum length of a subdomain to use in queries. The hard limit is 64 by the DNS protocol standards, but that could also stand out in environments. The smaller this number, the less data can be sent per request.


## Development



