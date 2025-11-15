# Cross Origin Resource Sharing

## Check List

## Methodology

### [Black Box](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-based-xss)

#### CORS Misconfiguration

{% stepper %}
{% step %}
Go to any API endpoint that returns user data like `/api/account, /api/user, /api/profile, /api/keys`
{% endstep %}

{% step %}
Open Burp Suite, Repeater, Send a normal request to the target API and Add or modify the Origin header to your domain

```http
Origin: https://evil.com
```
{% endstep %}

{% step %}
Send the request and Check response headers for&#x20;

```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
{% endstep %}

{% step %}
If both are present, Reflected CORS Misconfig, CONFIRMED
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
