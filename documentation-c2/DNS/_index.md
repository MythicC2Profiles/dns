+++
title = "DNS"
chapter = false
weight = 5
+++

## Overview



### C2 Workflow
{{<mermaid>}}
sequenceDiagram
    
  
{{< /mermaid >}}
Legend:

- Solid line is a new connection
- Dotted line is a message within that connection

## Configuration Options
The profile reads a `config.json` file for a set of instances of `Sanic` webservers to stand up (`80` by default) and redirects the content.

```JSON
{
  "instances": [
    {
      "domains": "sub.domain1.com,sub.domain2.com",
      "key": "hmac secret key",
      "msginit": "init",
      "msgdefault": "default"
    }
  ]
}


```



```

  
```

### JSON Parameters
#### Domains
The domains configured for resolution in the DNS Server. Make sure to setup these domains in your registrar and in the payload building.
   
#### HMAC
The HMAC key that will be used to check against each query. Make sure to setup the key correctly in the payload creation page with the same value here.
    
#### msginit
Prefix for the initialization phase. Can be any arbitrary value with a maximum of 63 characters.
    
#### msgdefault
Prefix for the subsequent phases. Can be any arbitrary value with a maximum of 63 characters.

### Profile Options
#### Base64 of a 32-byte AES Key
Base64 value of the AES pre-shared key to use for communication with the agent. This will be auto-populated with a random key per payload, but you can also replace this with the base64 of any 32 bytes you want. If you don't want to use encryption here, blank out this value.


## OPSEC

This profile uses TXT queries to communicate with the DNS server. These queries are likely to stand out in a mature environment.
  
## Development



