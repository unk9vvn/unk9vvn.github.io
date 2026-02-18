# Session Management Schema

## Check List

## Methodology

### Black Box

#### Cookie Transport Security Test

{% stepper %}
{% step %}
Open the application via HTTP
{% endstep %}

{% step %}
Check if the cookie is sent over an unencrypted connection
{% endstep %}

{% step %}
Send a manual HTTP request with the same cookie
{% endstep %}

{% step %}
Check if the server accepts the request
{% endstep %}

{% step %}
If accepted, weakness is confirmed
{% endstep %}
{% endstepper %}

***

#### Session Expiration & Replay Test

{% stepper %}
{% step %}
Log in and save the SessionID
{% endstep %}

{% step %}
Log out of the account
{% endstep %}

{% step %}
Reuse the same SessionID
{% endstep %}

{% step %}
After the session timeout, reuse the token.
{% endstep %}

{% step %}
Use the token in another browser or device
{% endstep %}

{% step %}
If it were still valid, the weakness would be confirmed
{% endstep %}
{% endstepper %}

***

#### Session Tampering Test

{% stepper %}
{% step %}
Send a valid request with SessionID
{% endstep %}

{% step %}
Change one character of the SessionID
{% endstep %}

{% step %}
Resubmit the request
{% endstep %}

{% step %}
Delete part of the token and submit
{% endstep %}

{% step %}
Replace the desired value and submit
{% endstep %}

{% step %}
If the server accepts the tampered token, the weakness is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
