# Fingerprint Web Server

### Banner Grabbing

_**Request:**_

```shell
┌──(web㉿unk9vvn)-[~]
└─$ nc -v example.com 80
Connection to example.com 80 port [tcp/http] succeeded!
HEAD / HTTP/1.1
```

_**Response:**_

```bash
HTTP/1.1 200 OK                        # This is Response
Date: Fri, 24 Dec 2021 11:29:19 GMT
Server: Apache/2.4.38 (Debian)         # Banner we need
Content-Length: 1179
Connection: close
Content-Type: text/html
```

Here is another response, this time from Microsoft IIS (Using `Telnet`):

_**Request:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ telnet example.com 80
Trying 104.21...
Connected to example.com.
HEAD / HTTP/1.1                       # We write this
```

_**Response:**_

```bash
HTTP/1.1 200 OK                      # This is Response
Server: Microsoft-IIS/7.5            # Banner we need
Date: Fri, 24 Dec 2021 11:40:36 GMT
Content-Type: text/HTML 
Accept-Ranges: bytes 
Content-Length: 7369 
...
```

Here’s what a response from Nginx looks like (Using `Curl`):

_**Request:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ curl -I $WEBSITE
```

_**Response:**_

```bash
HTTP/1.1 200 OK                       # This is Response
Server: nginx/1.17.3                  # Banner we need
Date: Fri, 24 Dec 2021 11:45:02 GMT
Content-Type: text/html
Content-Length: 117
Connection: close
Accept-Ranges: bytes
...
```

### Using Automated Scanning Tools

[**Nikto**](https://github.com/sullo/nikto)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo nikto -host $WEBSITE
```

[**Nmap**](https://nmap.org/)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo nmap -sV --script=banner $WEBSITE
```
