# Information Unencrypted Channel

## Check List

## Methodology

### Black Box

#### Login Page Over HTTP

{% stepper %}
{% step %}
Access the login page using HTTP instead of HTTPS, Capture the request in Burp Suite

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

username=test&password=Test123
```
{% endstep %}

{% step %}
Check the request scheme in Burp
{% endstep %}

{% step %}
If credentials are transmitted over `http://` instead of `https://`, sensitive data is exposed in cleartext
{% endstep %}

{% step %}
If login works over HTTP without redirecting to HTTPS, unencrypted credential transmission is confirmed
{% endstep %}
{% endstepper %}

***

#### Registration Page Over HTTP

{% stepper %}
{% step %}
Access the registration page using HTTP, Intercept the request

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 75

{"email":"user@test.com","password":"Password123"}
```
{% endstep %}

{% step %}
Verify whether the request is sent over HTTP
{% endstep %}

{% step %}
If personal data and passwords are transmitted unencrypted, sensitive information disclosure is confirmed
{% endstep %}
{% endstepper %}

***

#### Password Reset Feature

{% stepper %}
{% step %}
Access the forgot-password endpoint over HTTP, Capture the request

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 40

{"email":"victim@target.com"}
```
{% endstep %}

{% step %}
If the email address is transmitted via HTTP without encryption, account-related data exposure is confirmed
{% endstep %}
{% endstepper %}

***

#### Authenticated Session Cookie Without Secure Flag

{% stepper %}
{% step %}
Login normally over HTTPS and intercept the response, Check the Set-Cookie header

```http
HTTP/1.1 200 OK
Set-Cookie: sessionId=abc123xyz; Path=/; HttpOnly
```
{% endstep %}

{% step %}
If the cookie does not contain the `Secure` flag

```http
Set-Cookie: sessionId=abc123xyz; Path=/; HttpOnly
```
{% endstep %}

{% step %}
Then the session cookie can be transmitted over HTTP, Force browse to HTTP

```http
GET /dashboard HTTP/1.1
Host: target.com
Cookie: sessionId=abc123xyz
```
{% endstep %}

{% step %}
If session remains valid over HTTP, session hijacking risk via unencrypted channel is confirmed
{% endstep %}
{% endstepper %}

***

#### API Endpoints Accessible Over HTTP

{% stepper %}
{% step %}
Access API endpoints using HTTP

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token
```
{% endstep %}

{% step %}
If the API responds successfully over HTTP and accepts Authorization headers, token leakage risk exists
{% endstep %}

{% step %}
If sensitive JSON responses are returned over HTTP, unencrypted API communication is confirmed
{% endstep %}
{% endstepper %}

***

#### File Upload Over HTTP

{% stepper %}
{% step %}
Access file upload endpoint via HTTP
{% endstep %}

{% step %}
Capture the request

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----123

------123
Content-Disposition: form-data; name="file"; filename="id.png"
Content-Type: image/png

(binary data)
------123--
```

If file upload works over HTTP, transmitted content can be intercepted
{% endstep %}

{% step %}
If no forced HTTPS redirection exists, unencrypted file transmission is confirmed
{% endstep %}
{% endstepper %}

***

#### Payment or Sensitive Form Submission

{% stepper %}
{% step %}
Access checkout or payment endpoint via HTTP, Capture the request

```http
POST /checkout HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 120

{"cardNumber":"4111111111111111","cvv":"123","expiry":"12/26"}
```
{% endstep %}

{% step %}
If payment details are transmitted over HTTP, critical unencrypted data exposure is confirmed
{% endstep %}
{% endstepper %}

***

#### Internal API Calls in Mobile Applications

{% stepper %}
{% step %}
Analyze mobile app traffic via proxy like burp suite, If API calls are made to

```hurl
http://api.target.com/login
```
{% endstep %}

{% step %}
And credentials or tokens are visible in plaintext, unencrypted transport in mobile backend communication is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
