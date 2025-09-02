# Identify Application Entry Points

## Check List

* [ ] Identify possible entry and injection points through request and response analysis.

## Cheat Sheet

### Requests

#### Query String

#### [Gau](https://github.com/lc/gau)

```bash
gau $WEBSITE
```

#### [x8](https://github.com/Sh1Yo/x8)

```bash
x8 --url $WEBSITE \
   -X GET POST \
   -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

#### BurpSuite

```http
GET /?page=earbuds HTTP/1.1
Host: localhost
Cache-Control: max-age=0
sec-ch-ua: "Not/A)Brand";v="8", "Chromium";v="126"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=05462b92721e76e0788c8c15d69b539
Connection: keep-alive
```

#### Cookie Header

```http
GET / HTTP/1.1
Host: localhost
Pragma: no-cache
Cache-Control: no-cache
sec-ch-ua: "Not/A) Brand";v="8", "Chromium";v="126"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate  
Sec-Fetch-Dest: document
Sec-Fetch-User: ?1
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=05462b92721e766e0788c8c15d69b539
Connection: keep-alive
```

#### Requests Body

```http
POST /login/ HTTP/1.1
Host: localhost
Content-Length: 29
Cache-Control: max-age=0
sec-ch-ua: "Not/A) Brand";v="8", "Chromium";v="126"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
Origin: http://localhost
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7  
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost/login/
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=05462b92721e766e0788c8c15d69b539
Connection: keep-alive

username=admin&password=admin

```

### Response

#### Cookie Header

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache  
Expires: Mon, 01 Jan 1990 00:00:00 GMT
Date: Wed,09 Oct 2024 14:12:36 GMT
Content-Disposition: attachment; filename="response.bin"; filename*=UTF-8''response.bin
Strict-Transport-Security: max-age=31536000
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: require-trusted-types-for 'script'
Accept-Ch: Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Mobile,  Sec-CH-UA-Form-Factors, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version
Vary: Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Mobile, Sec-CH-UA-Form-Factors, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version
Permissions-Policy: ch-ua-arch, ch-ua-bitness, ch-ua-full-version, ch-ua-full-version-list, ch-ua-model, ch-ua-mobile,ch-ua-form-factors, ch-ua-platform, ch-ua-platform-version=*
Origin-Trial: "feature=WebXRDevicesApi","expiry"=2024-10-09T23:59:59.999Z,version=0"
Report-To: {"group":"youtube_main","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/youtube_main"}]}
Cross-Origin-Embedder-Policy: require-corp; report-to="youtube_main"
P3p: CP="This is not a P3P policy! See http://support.google.com/accounts/answer/151657?hl=en for more info."
Server: RSF
X-Xss-Protection: 0
Set-Cookie: Secure-YEC; Domain=.youtube.com; Expires Thu, 13-Jan-2022 14:12:36 GMT; Path=/; Secure; HttpOnly; SameSite=Lax
Alt-Svc: h3=":443"; ma=2592000, h3-29=":443"; ma=2592000
```

#### Response Body

```html
HTTP/1.1 200 Success
Date: Wed, 09 Oct 2024 10:54:53 GMT
Server: Apache/2.4.62 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 14055
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width,initial-scale=1, maximum-scale=1, shrink-to-fit=no">
<title>HTTP Parameter Pollution</title>
<link rel="icon" type="image/x-icon" href="/assets/img/logo.png"/>
<link href="/bootstrap/css/bootstrap.min.css" rel="stylesheet" type="text/css"/>
<link href="/assets/css/plugins.css" rel="stylesheet" type="text/css"/>  

<link href="/assets/css/components/cards/card.css" rel="stylesheet" type="text/css">
<link href="/assets/css/components/step-progress.css" rel="stylesheet" type="text/css">
<link href="/assets/css/elements/badget-lab.css" rel="stylesheet" type="text/css">
<link href="/assets/css/animation.css" rel="stylesheet" type="text/css">
<link href="/assets/css/custom.css" rel="stylesheet" type="text/css">
<link href="/assets/css/components/custom-tabs.css" rel="stylesheet" type="text/css">
</head>
```
