# Map Application Architecture

#### Network Components

**Reverse Proxy**

* A mismatch between the front end server and the back end application, such as a `Server: nginx` header with an ASP.NET application or `Server: nginx` with an Java base CMS, so in this cases we may conclude that Nginx is set as a reverse proxy.
* Duplicate headers (especially the `Server` header).
* Multiple applications hosted on the same IP address or domain (especially if they use different languages).
* Check for the `X-Forwarded-For` HTTP header (the proxy could choose to suppress it).

_**Request:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ curl "$WEBSITE/web-console/ServerInfo.jsp%00"
```

_**Response:**_

```http
HTTP/1.0 200
Pragma: no-cache
Cache-Control: no-cache
Content-Type: text/html
Content-Length: 83
 
<TITLE>Error</TITLE>
<BODY>
<H1>Error</H1>
FW-1 at XXXXXX: Access denied.</BODY>
```

**Load Balancers**

* Not synchronized server clocks and Inconsistent system times (Based on `Date` HTTP header).
* Different internal IP addresses or hostnames in detailed error messages.
* Different addresses returned from Server-Side Request Forgery (SSRF).
* Presence of specific cookies, such as `BIGipServer` cookie introduced by F5 BIG-IP load balancers or `AlteonP` cookie introduced by Nortel’s Alteon WebSystems load balancers.

**load balancing detector Tool**

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo lbd $WEBSITE 80
```

**Content Delivery Network (CDN)**

1. The IPs and servers belong to the CDN provider, and are likely to be out of scope for infrastructure testing.
2. Many CDNs also include features like bot detection, rate limiting, and web application firewalls.
3. CDNs usually cache content, so any changes made to the back end website may not appear immediately.
4. If the site is behind a CDN, then it can be useful to identify the back end servers. If they don’t have proper access control enforced, then you may be able to bypass the CDN (and any protections it offers) by directly accessing the back end servers.

