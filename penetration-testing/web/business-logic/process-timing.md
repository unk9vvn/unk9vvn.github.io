# Process Timing

## Check List

## Methodology

### Black Box

#### Login Timing Attack – Username Enumeration

{% stepper %}
{% step %}
Identify the login endpoint and intercept a normal authentication request
{% endstep %}

{% step %}
Attempt login with an existing username and incorrect password, Capture the request in Burp Suite

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 52

{"username":"validUser","password":"WrongPass123"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average
{% endstep %}

{% step %}
Now attempt login with a non-existing username and the same incorrect password

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 58

{"username":"randomUser987654","password":"WrongPass123"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average, Compare both averages
{% endstep %}

{% step %}
If requests with a valid username consistently take longer than those with a non-existing username, the application is performing password hash verification only for existing accounts
{% endstep %}
{% endstepper %}

***

#### Password Reset Timing Attack – Email Enumeration

{% stepper %}
{% step %}
Navigate to the password reset feature
{% endstep %}

{% step %}
Submit a reset request using a valid registered email and intercept the request
{% endstep %}

{% step %}
Capture the request in Burp Suite

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 45

{"email":"validuser@target.com"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater
{% endstep %}

{% step %}
Record the response times and calculate the average
{% endstep %}

{% step %}
Now submit a reset request using a non-existing email address

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 49

{"email":"random987654@target.com"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average, Compare both averages
{% endstep %}

{% step %}
If requests for existing emails consistently take longer than non-existing emails, the server is performing additional operations (database lookup, token generation, email dispatch)
{% endstep %}
{% endstepper %}

***

#### API Token Validation Timing Attack – Token Enumeration

{% stepper %}
{% step %}
Access an authenticated API endpoint that requires a Bearer token
{% endstep %}

{% step %}
Send a request with a structurally valid but incorrect token and intercept it Capture the request in Burp Suite

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalidsignature
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average
{% endstep %}

{% step %}
Now send a request with a completely malformed token

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer invalidtoken123
```
{% endstep %}

{% step %}
Send this request `30–50` times, Record the response times and calculate the average and Compare both averages
{% endstep %}

{% step %}
If structurally valid tokens consistently take longer to process than malformed tokens, the backend is performing signature validation and possibly database lookups
{% endstep %}

{% step %}
If timing differences are stable and repeatable, token validation timing vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### 2FA / OTP Verification Timing Attack – Code Brute Optimization

{% stepper %}
{% step %}
Navigate to the OTP verification endpoint
{% endstep %}

{% step %}
Submit an incorrect OTP and intercept the request and Capture the request in Burp Suite

```http
POST /verify-otp HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 24

{"otp":"123456"}
```
{% endstep %}

{% step %}
Send this request `30–50` times and record average response time
{% endstep %}

{% step %}
Now slightly modify the OTP value

```http
POST /verify-otp HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 24

{"otp":"123457"}
```
{% endstep %}

{% step %}
Send `30–50` requests and measure the average and Compare response times between different incorrect OTP values&#x20;
{% endstep %}

{% step %}
If timing difference is consistent, OTP brute-force optimization via timing is confirmed
{% endstep %}
{% endstepper %}

***

#### Username Availability Check Timing Attack – AJAX Enumeration

{% stepper %}
{% step %}
Locate the username availability check endpoint
{% endstep %}

{% step %}
Intercept a request for an existing username and Capture the request in Burp Suite

```http
GET /check-username?username=admin HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 identical requests and record the average response time
{% endstep %}

{% step %}
Now test with a random username

```http
GET /check-username?username=randomUser987654 HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 identical requests and record the average and Compare averages
{% endstep %}

{% step %}
If existing usernames consistently take longer due to database lookup or validation logic, enumeration via timing attack is confirmed
{% endstep %}
{% endstepper %}

***

#### File / Resource ID Enumeration Timing Attack

{% stepper %}
{% step %}
Access a resource-based endpoint
{% endstep %}

{% step %}
Test with a valid resource ID without permission and Capture in Burp Suite

```http
GET /download?fileId=1024 HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 requests and measure average time and Now test with a random non-existing ID

```http
GET /download?fileId=999999 HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 requests and measure average time and Compare results
{% endstep %}

{% step %}
If existing resource IDs consistently take longer due to permission checks or database lookups, resource enumeration via timing attack is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
