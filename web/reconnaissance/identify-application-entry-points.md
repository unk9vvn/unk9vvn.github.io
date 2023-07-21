# Identify Application Entry Points

## Request analysis

**GET request to purchase a product**

```http
GET /products/purchase.php?productID=25&price=49.5 HTTP/1.1
Host: www.example.com
Cookie: PHPSESSID=ngd8nfkpq7t04l6bblnaf9846m;
```

**POST request to login to an application**

```http
POST /login.php HTTP/1.1
Host: www.example.com
X-Real-IP: 78.110.172.196
Cookie: PHPSESSID=ngd8nfkpq7t04l6bblnaf9846m;
 
username=admin&password=password&user_token=a93236b8f1f8afee7cff5f9c0
```

## Response analysis

_**Example responses:**_

```http
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Type: text/html;
Date: Mon, 17 Jul 2021 16:06:00 GMT
Server: Apache/2.2.14
Set-Cookie: PHPSESSID=ngd8nfkpq7t04l6bblnaf9846m; expires=Mon, 17-Jul-2021 20:06:00 GMT; Path=/; secure
X-Powered-By: PHP/5.4.45
...
```

Note the non-standard `X-Powered-By` header that reveals information about the Backend server.

```http
HTTP/1.1 403 Forbidden
Date: Mon, 17 Jul 2021 10:36:20 GMT
Server: Apache/2.2.14
Content-Length: 230
Connection: Closed
Content-Type: text/html; charset=iso-8859-1
```

### OWASP Attack Surface Detector

```bash
┌──(web㉿unk9vvn)-[~]
└─$ java -jar attack-surface-detector-cli.jar myApplicationSourceCode/
```

### Burp Suite

`Burp Suite -> Target -> Site map -> Right Click on One Domain -> Engagement tools -> Analyze Target`

### [Arjun](https://github.com/s0md3v/Arjun)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ arjun -u $WEBSITE
```

### [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ python3 Linkfinder.py -i $WEBSITE -d -o cli
```

### Form Tags

```javascript
document.querySelectorAll("form");
```
