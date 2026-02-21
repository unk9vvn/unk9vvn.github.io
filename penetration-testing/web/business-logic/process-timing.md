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
Send this request 30–50 times in Burp Repeater and Record the response times and calculate the average
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
Send this request 30–50 times in Burp Repeater and Record the response times and calculate the average, Compare both averages
{% endstep %}

{% step %}
If requests with a valid username consistently take longer than those with a non-existing username, the application is performing password hash verification only for existing accounts
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
