# Excessive Data Exposure

## Check List

## Methodology

### Black Box

#### WordPress User Enumeration via Public REST API

{% stepper %}
{% step %}
Check if the target is running WordPress
{% endstep %}

{% step %}
Send a direct GET request to the default WordPress REST API users endpoint

```http
https://target.com/wp-json/wp/v2/users
```
{% endstep %}

{% step %}
Alternative endpoints (in case the main one is blocked)

```http
https://target.com/wp-json/wp/v2/users/?per_page=100
https://target.com/wp-json/wp/v2/users/1
https://target.com/index.php?rest_route=/wp/v2/users
https://target.com/wp-json/wp/v2/users/me
```
{% endstep %}

{% step %}
If the response returns a JSON array with user objects containing any of these fields → vulnerability confirmed

```
id, name, slug, username, login, nickname, url, description
```
{% endstep %}

{% step %}
Enumerate user IDs sequentially

```
https://target.com/wp-json/wp/v2/users/1
https://target.com/wp-json/wp/v2/users/2
...
https://target.com/wp-json/wp/v2/users/100
```
{% endstep %}
{% endstepper %}

***

#### Information Disclosure via Verbose Error Messages

{% stepper %}
{% step %}
Discover any authentication or ID-based endpoint Common ones

```json
/api/login, /api/auth, /v1/sessions, /api/v2/users/{id}, /api/forgot-password, /api/check-email
```
{% endstep %}

{% step %}
Send a request with a completely fake/non-existent user/ID/email

```
{"email": "this-user-definitely-does-not-exist-12345@target.com", "password": "anything"}
```
{% endstep %}

{% step %}
Capture the exact error message and status code
{% endstep %}

{% step %}
Now send the same request with a real-looking but still fake value (or incremental ID)

```json
{"email": "admin@target.com", "password": "wrong"}
```
{% endstep %}

{% step %}
Compare the two responses – look for any of these differences



| Fake user response    | Real user response                | Meaning                             |
| --------------------- | --------------------------------- | ----------------------------------- |
| "User does not exist" | "Invalid password"                | User exists → Enumeration confirmed |
| "Invalid credentials" | "Password is incorrect"           | Same                                |
| 404 Not Found         | 401 Unauthorized or 403 Forbidden | Same                                |
| "account\_not\_found" | "wrong\_password"                 | Same                                |
| Response time 80 ms   | Response time 350 ms              | Possible existence                  |
{% endstep %}

{% step %}
Build a small wordlist of probable emails

```
admin@target.com
support@target.com
john.doe@target.com
jdoe@target.com
```
{% endstep %}
{% endstepper %}

***

#### Information Disclosure

{% stepper %}
{% step %}
Create a normal/low-privilege account on the target
{% endstep %}

{% step %}
Find any API endpoint that returns data about yourself or your resources Common ones

```
GET /api/me
GET /api/v1/profile
GET /api/v2/user
```
{% endstep %}

{% step %}
Call the endpoint with your account and capture the full JSON response
{% endstep %}

{% step %}
Try the same endpoint with other users’ identifiers (if possible)

```
GET /api/v3/accounts?name=admin
GET /api/v3/accounts?id=1
```
{% endstep %}

{% step %}
If we get additional data by sending another username or email address, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
