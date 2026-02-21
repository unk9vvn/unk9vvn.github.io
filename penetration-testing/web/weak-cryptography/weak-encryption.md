# Weak Encryption

## Check List

## Methodology

### Black Box

#### Weakly Encrypted Password Reset Token

{% stepper %}
{% step %}
Access the password reset functionality

```http
GET /forgot-password HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Submit a password reset request for your own account

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=test@target.com
```
{% endstep %}

{% step %}
Capture the reset link from email

```hurl
https://target.com/reset?token=MTY5ODc1NjAwMA==
```
{% endstep %}

{% step %}
Decode the token (Base64 test)

```hurl
MTY5ODc1NjAwMA==  →  1698756000
```
{% endstep %}

{% step %}
If token decodes into a timestamp, user ID, or predictable pattern, encryption is weak, Request multiple reset tokens consecutively
{% endstep %}

{% step %}
Compare token values for pattern similarity (incremental values, timestamp correlation, user ID leakage)
{% endstep %}

{% step %}
Attempt to modify the token manually

```hurl
https://target.com/reset?token=MTY5ODc1NjAwMQ==
```
{% endstep %}

{% step %}
If modified token is accepted or partially validated, weak encryption / predictable token confirmed
{% endstep %}

{% step %}
Attempt cross-user reset by generating token for your account and adjusting numeric segment to another user ID
{% endstep %}

{% step %}
If token manipulation grants access to another account’s reset page, weak encryption vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Sensitive Data Encrypted with Reversible Client-Side Logic

{% stepper %}
{% step %}
Login and intercept response containing encrypted data

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```
{% endstep %}

{% step %}
Observe encrypted field

```json
"ssn":"U0lHTkVEX1NTTl8xMjM0"
```
{% endstep %}

{% step %}
Inspect application JavaScript files

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Search for encryption functions, Identify reversible logic such as

```
function encrypt(data){
  return btoa(data);
}
```
{% endstep %}

{% step %}
Decode the value manually

```
U0lHTkVEX1NTTl8xMjM0 → SIGNED_SSN_1234
```
{% endstep %}

{% step %}
If sensitive data is only Base64 encoded or XOR encoded, not cryptographically encrypted, weak encryption confirmed
{% endstep %}

{% step %}
Modify encoded value and resend request. If application accepts modified encoded sensitive data, encryption control is insufficient
{% endstep %}
{% endstepper %}

***

#### Weak TLS Cipher Suite Negotiation

{% stepper %}
{% step %}
Connect to target using a TLS testing tool
{% endstep %}

{% step %}
Force weak cipher negotiation (example with OpenSSL)

```bash
openssl s_client -connect target.com:443 -cipher 'DES-CBC3-SHA'
```
{% endstep %}

{% step %}
If handshake succeeds with 3DES or RC4

```bash
Cipher    : DES-CBC3-SHA
```
{% endstep %}

{% step %}
Weak encryption is supported, Test for export-grade cipher support

```bash
openssl s_client -connect target.com:443 -cipher 'EXP'
```
{% endstep %}

{% step %}
If connection succeeds using export cipher, weak encryption confirmed
{% endstep %}

{% step %}
Verify accepted protocol version

```bash
Protocol  : TLSv1.0
```
{% endstep %}

{% step %}
If TLS 1.0 or weak ciphers are allowed, cryptographic strength is insufficient
{% endstep %}

{% step %}
If handshake succeeds using deprecated cipher suites, weak encryption configuration vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
