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

### White Box

## Cheat Sheet
