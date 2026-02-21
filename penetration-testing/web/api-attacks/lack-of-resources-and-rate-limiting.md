# Lack of Resources and Rate Limiting

## Check List

## Methodology

### Black Box

#### Rate Limiting Password Reset Functionalities

{% stepper %}
{% step %}
Log into the target site and intercept requests using Burp Suite
{% endstep %}

{% step %}
Go to the Forgot Password page and complete the request process
{% endstep %}

{% step %}
Then, using the Burp Suite tool, inspect the requests and identify whether the password reset process is performed using API endpoints
{% endstep %}

{% step %}
If the password forget process was performed using API endpoints, then send the API request to Intruder in the Burp Suite tool, then send 200 requests to the Endpoint API
{% endstep %}

{% step %}
If after sending all 200 requests, you get a status code of 200 in response to the server, and not a 429, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### API Brute Force on Login Endpoint

{% stepper %}
{% step %}
Identify API login endpoint, Intercept normal request

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"victim","password":"WrongPass1"}
```
{% endstep %}

{% step %}
Send request to Burp Intruder and Set payload position on password parameter
{% endstep %}

{% step %}
Configure multiple password attempts, Start attack with high request rate
{% endstep %}

{% step %}
Monitor responses, If API consistently returns `200` or `401` without delay, CAPTCHA, or lockout after numerous attempts, rate limiting is absent
{% endstep %}

{% step %}
If no temporary block or IP restriction occurs after hundreds of requests, brute-force protection is missing
{% endstep %}
{% endstepper %}

***

#### High-Volume API Abuse (DoS Vector)

{% stepper %}
{% step %}
Identify search or heavy-processing endpoint

```http
GET /api/search?q=test HTTP/1.1
Host: target.com
Authorization: Bearer token123
```
{% endstep %}

{% step %}
Send request to Turbo Intruder, Increase concurrent requests significantly
{% endstep %}

{% step %}
Monitor response times and status codes, If server continues processing without throttling, queueing, or `429` responses, no resource control is enforced
{% endstep %}

{% step %}
If high traffic causes degradation without triggering protective mechanisms, resource exhaustion risk exists
{% endstep %}

{% step %}
If API lacks request quotas per `user/IP` and allows uncontrolled request volume, Lack of Resources and Rate Limiting vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
