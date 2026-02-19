# LDAP Injection

## Check List

## Methodology

### Black Box

#### Base Injection

{% stepper %}
{% step %}
Navigate to the registration page and begin a new registration using normal, valid data

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

firstName=Ali&lastName=Rezaei&email=ali.rezaei@test.com&password=Test@123
```
{% endstep %}

{% step %}
Capture the registration request using an intercepting proxy and resend it, confirming that the server processes the standard input without errors

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

firstName=Ali&lastName=Rezaei&email=ali.rezaei2@test.com&password=Test@123
```
{% endstep %}

{% step %}
Start a second registration attempt and modify the request so that the first name field contains an invalid LDAP-related character, such as a double quote `"`, before submitting it to the same endpoint

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

firstName=Ali"&lastName=Rezaei&email=ali.rezaei3@test.com&password=Test@123
```
{% endstep %}

{% step %}
Observe the server’s response, where the application fails to sanitize the user-supplied value and triggers a fatal LDAP-related error `(0x80005000)`, indicating that the unsanitized input is being passed directly to an LDAP operation
{% endstep %}
{% endstepper %}

***

#### LDAP Filter Injection — Denial of Service

{% stepper %}
{% step %}
Install and configure the Cloudron Surfer version: `5.9.0` environment or a local replica. Set up the LDAP test server `(ldapjstestserver.js)` and start Surfer with LDAP-related environment variables to enable directory-based authentication
{% endstep %}

{% step %}
Review the authentication flow in auth.js. Identify that the username value from req.body.username is inserted directly into an LDAP filter without sanitization

```http
(|(uid=${username})(mail=${username})(username=${username})(sAMAccountName=${username}))
```
{% endstep %}

{% step %}
Confirm that the login mechanism performs an LDAP search using this filter before password binding, making the filter fully user-controlled
{% endstep %}

{% step %}
Test normal behavior by logging in using valid credentials, then test with a long benign username to confirm the system remains stable under large but non-malicious input
{% endstep %}

{% step %}
Craft a payload that introduces LDAP filter characters (already demonstrated in your PoC) to expand the resulting filter. Example

```http
payload = "*)" + "(cn=*)"* repeat many times + "(cn=*"
```
{% endstep %}

{% step %}
Send the payload to `/api/login` using the provided Python script. The application constructs a massive LDAP filter, causing excessive processing by the LDAP server and memory exhaustion in Node.js
{% endstep %}

{% step %}
Observe that the server becomes unresponsive and eventually crashes with a heap-exhaustion error, confirming Denial of Service via LDAP Injection
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
