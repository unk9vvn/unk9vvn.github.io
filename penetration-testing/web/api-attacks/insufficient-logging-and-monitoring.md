# Insufficient Logging and Monitoring

## Check List

## Methodology

### Black Box

#### Undetected Brute Force on Login API

{% stepper %}
{% step %}
Identify login endpoint and Intercept request

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"victim","password":"WrongPass1"}
```
{% endstep %}

{% step %}
Send request to Burp Intruder and Launch high-volume password attack
{% endstep %}

{% step %}
Monitor responses and account behavior
{% endstep %}

{% step %}
If no CAPTCHA, no temporary lock, no IP block, and no alert is triggered after excessive failed attempts, monitoring is insufficient
{% endstep %}

{% step %}
If attack continues without detection or interruption, logging and monitoring controls are weak
{% endstep %}

{% step %}
If brute force activity is not mitigated or logged effectively, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Silent ID Enumeration

{% stepper %}
{% step %}
Login as normal user and Intercept object request

```http
GET /api/users/1001 HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Send to Intruder and increment ID sequentially
{% endstep %}

{% step %}
Generate large number of requests in short time
{% endstep %}

{% step %}
If enumeration succeeds without account suspension, throttling, or session invalidation, monitoring is insufficient
{% endstep %}

{% step %}
If no protective action occurs despite abnormal access pattern, logging and alerting mechanisms are inadequate
{% endstep %}

{% step %}
If mass data harvesting is possible without detection, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation Attempt Without Alert

{% stepper %}
{% step %}
Login as normal user and Attempt to access admin endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Repeat unauthorized access multiple times, If repeated access attempts do not trigger temporary blocking, account warning, or response delay, suspicious behavior is not monitored
{% endstep %}

{% step %}
If privilege escalation attempts can be performed repeatedly without detection, logging and monitoring are insufficient
{% endstep %}

{% step %}
If no defensive reaction occurs against repeated unauthorized function access, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Token Manipulation Attempts Not Detected

{% stepper %}
{% step %}
Login and capture `JWT` and Modify token payload and resend

```http
GET /api/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer tampered_token
```
{% endstep %}

{% step %}
Repeat with multiple malformed or forged tokens
{% endstep %}

{% step %}
If server continuously responds without triggering account lock, token invalidation, or anomaly detection, monitoring is weak
{% endstep %}

{% step %}
If repeated invalid token usage does not produce defensive response, authentication misuse is not properly logged
{% endstep %}

{% step %}
If abnormal authentication behavior is allowed without detection or mitigation, Insufficient Logging and Monitoring vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
