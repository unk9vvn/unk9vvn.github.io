# Weak Transport Layer Security

## Check List

## Methodology

### Black Box

#### Deprecated Protocol Support

{% stepper %}
{% step %}
Access the target over HTTPS and intercept a normal request, Capture the request in Burp Suite

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the host to Burp Repeater
{% endstep %}

{% step %}
Use an external TLS testing tool ([testssl.sh](https://testssl.sh/) or sslyze) to check supported protocols
{% endstep %}

{% step %}
Test for deprecated protocols such as (SSLv3, TLS 1.0, TLS 1.1)
{% endstep %}

{% step %}
If connection succeeds using TLS 1.0 or TLS 1.1, deprecated protocol support is confirmed
{% endstep %}
{% endstepper %}

***

#### Weak Cipher Suites Enabled

{% stepper %}
{% step %}
Intercept any HTTPS request

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Use a TLS scanning tool to enumerate supported cipher suites
{% endstep %}

{% step %}
Look specifically for (RC4 cipher suites, 3DES, EXPORT cipher suites, NULL ciphers, Anonymous ciphers)
{% endstep %}

{% step %}
If connection negotiation succeeds with weak cipher suites, weak cipher configuration is confirmed
{% endstep %}
{% endstepper %}

***

#### Missing HSTS Header

{% stepper %}
{% step %}
Intercept the HTTPS response

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Check the server response headers, If the response does not contain

```http
Strict-Transport-Security: max-age=...
```
{% endstep %}

{% step %}
If HSTS header is missing or misconfigured, HTTPS downgrade risk exists
{% endstep %}
{% endstepper %}

***

#### Insecure HTTP to HTTPS Redirection

{% stepper %}
{% step %}
Access the application over HTTP

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Observe the response, If the server does not immediately redirect to HTTPS with

```http
HTTP/1.1 301 Moved Permanently
Location: https://target.com/
```
{% endstep %}

{% step %}
Then secure redirection is not enforced, If HTTP version serves content without redirect, insecure transport is confirmed
{% endstep %}
{% endstepper %}

***

#### Certificate Weakness

{% stepper %}
{% step %}
Open the site in a browser and inspect the TLS certificate if the certificate uses (SHA-1, MD5 or Key size < 2048 bits)
{% endstep %}

{% step %}
Then weak certificate configuration is confirmed
{% endstep %}
{% endstepper %}

***

#### Mixed Content

{% stepper %}
{% step %}
Load any HTTPS page and intercept the response

```http
GET /secure-page HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Inspect HTML source for resources loaded over HTTP

```html
<script src="http://...">
<link href="http://...">
```
{% endstep %}

{% step %}
If active content (JS/CSS) loads over HTTP inside HTTPS page, mixed content vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
