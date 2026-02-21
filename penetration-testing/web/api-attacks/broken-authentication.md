# Broken Authentication

## Check List

## Methodology

### Black Box

#### Missing Authentication on Sensitive API Endpoint

{% stepper %}
{% step %}
Do not authenticate to the application
{% endstep %}

{% step %}
Directly access a protected API endpoint

```http
GET /api/user/profile HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response returns user data without requiring Authorization header, authentication enforcement is missing
{% endstep %}

{% step %}
Test with random token

```http
GET /api/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer randomtoken123
```
{% endstep %}

{% step %}
If endpoint responds with valid user data or default user context, authentication validation is broken
{% endstep %}

{% step %}
If no 401/403 response is returned for unauthenticated access, Broken Authentication is confirmed
{% endstep %}
{% endstepper %}

***

#### Predictable JWT Secret

{% stepper %}
{% step %}
Login and capture JWT

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
```
{% endstep %}

{% step %}
Decode JWT payload, Identify algorithm

```json
{"alg":"HS256"}
```
{% endstep %}

{% step %}
Attempt to brute-force weak secret using jwt tool
{% endstep %}

{% step %}
If secret is guessable (`"secret", "123456"`), generate new token with modified payload:

```json
{"user":"admin","role":"admin"}
```
{% endstep %}

{% step %}
Sign token with discovered secret, Replace Authorization header

```http
Authorization: Bearer forged_admin_token
```
{% endstep %}

{% step %}
Access privileged endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Authorization: Bearer forged_admin_token
```
{% endstep %}

{% step %}
If access is granted, JWT authentication mechanism is broken
{% endstep %}

{% step %}
If server accepts forged token, Broken Authentication vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Session Fixation via API

{% stepper %}
{% step %}
Access login endpoint and intercept response

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"user1","password":"Pass123"}
```
{% endstep %}

{% step %}
Observe returned session token

```http
Set-Cookie: session=abc123; Path=/; HttpOnly
```
{% endstep %}

{% step %}
Before login, manually set session cookie

```http
Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
Perform login, If server reuses provided session ID after authentication

```http
Set-Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
Then session fixation is possible, Use fixed session in another browser

```http
GET /api/user/profile HTTP/1.1
Host: target.com
Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
If authenticated access is granted, session management is flawed
{% endstep %}

{% step %}
If session ID is not regenerated upon login, Broken Authentication vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
