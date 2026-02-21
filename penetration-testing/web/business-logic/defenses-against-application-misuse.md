# Defenses Against Application Misuse

## Check List

## Methodology

### Black Box

####

{% stepper %}
{% step %}
Access the login endpoint
{% endstep %}

{% step %}
Intercept a normal login request

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=victim&password=WrongPass1
```
{% endstep %}

{% step %}
Send the request to Burp Intruder
{% endstep %}

{% step %}
Set payload position on the password parameter
{% endstep %}

{% step %}
Launch a password brute-force attack with multiple password attempts, Observe server responses
{% endstep %}

{% step %}
If unlimited attempts are allowed without CAPTCHA, delay, or account lockout, rate limiting is absent
{% endstep %}

{% step %}
If no temporary lock or IP block occurs after high number of attempts, misuse protection is missing
{% endstep %}
{% endstepper %}

***

#### No Account Lockout After Failed OTP Attempts

{% stepper %}
{% step %}
Initiate OTP verification process
{% endstep %}

{% step %}
Intercept OTP verification request

```http
POST /api/verify-otp HTTP/1.1
Host: target.com
Cookie: session=temp123
Content-Type: application/json

{"otp":"000000"}
```
{% endstep %}

{% step %}
Send request to Burp Intruder
{% endstep %}

{% step %}
Brute-force OTP values `(000000–999999)`
{% endstep %}

{% step %}
Monitor responses, If unlimited attempts are accepted without invalidation or delay, OTP brute-force protection is missing
{% endstep %}

{% step %}
If OTP remains valid despite multiple failures, application misuse defense is broken
{% endstep %}
{% endstepper %}

***

#### No Rate Limiting on Password Reset

{% stepper %}
{% step %}
Access password reset endpoint, Intercept request

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
{% endstep %}

{% step %}
Send request repeatedly via Burp Intruder
{% endstep %}

{% step %}
Monitor response behavior, If unlimited reset emails are triggered without throttling, email flooding is possible
{% endstep %}

{% step %}
If no CAPTCHA or rate limiting exists, abuse protection is missing
{% endstep %}
{% endstepper %}

***

#### No API Rate Limiting

{% stepper %}
{% step %}
Intercept API request

```http
GET /api/search?q=test HTTP/1.1
Host: target.com
Authorization: Bearer token123
```
{% endstep %}

{% step %}
Send request to Burp Intruder or Turbo Intruder
{% endstep %}

{% step %}
Increase request rate significantly
{% endstep %}

{% step %}
Monitor response codes, If server consistently returns 200 without 429 (Too Many Requests), API rate limiting is not enforced
{% endstep %}

{% step %}
If high request volume does not trigger blocking or throttling, misuse defense is insufficient
{% endstep %}
{% endstepper %}

***

#### Missing CAPTCHA on Critical Forms

{% stepper %}
{% step %}
Access registration or login page
{% endstep %}

{% step %}
Observe whether CAPTCHA is present, Intercept registration request

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=test@test.com&password=Test123
```
{% endstep %}

{% step %}
Replay multiple automated registration requests
{% endstep %}

{% step %}
If accounts can be created programmatically without CAPTCHA validation or anti-automation control, abuse prevention is absent
{% endstep %}

{% step %}
If no bot mitigation exists on high-risk forms, misuse protection vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
