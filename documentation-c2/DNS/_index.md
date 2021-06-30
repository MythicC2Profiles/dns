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
      "domains": "domain1.com,domain2.com",
      "key": "hmac secret key",
      "debug": false,
      "msginit": "subdomain for connection initialization (e.g. somethingnotsuspicious1)",
      "msgdefault": "subdomain for default messages (e.g. somethingnotsuspicious2)"
    }
  ]
}


```



```

  
```


### Profile Options
#### Base64 of a 32-byte AES Key
Base64 value of the AES pre-shared key to use for communication with the agent. This will be auto-populated with a random key per payload, but you can also replace this with the base64 of any 32 bytes you want. If you don't want to use encryption here, blank out this value.


## OPSEC

This profile uses TXT queries to communicate with the DNS server. These queries are likely to stand out in a mature environment.
  
## Development

