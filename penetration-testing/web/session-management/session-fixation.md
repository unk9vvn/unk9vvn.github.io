# Session Fixation

## Check List

## Methodology

### Black Box

#### Account Take Over

{% stepper %}
{% step %}
Log in to the target site and inspect the HTTP requests using Burp Suite
{% endstep %}

{% step %}
Check whether a cookie is set for us as soon as we enter the site
{% endstep %}

{% step %}
If the cookie was set before authentication, then complete the authentication process and check whether the same cookie is set after authentication or not
{% endstep %}

{% step %}
If the same cookie was issued, the session fixation vulnerability would be confirmed
{% endstep %}

{% step %}
Then check if the session that is set exists in the URL parameters and in GET form
{% endstep %}

{% step %}
Send the session to a user as a link so that a user can authenticate using that session
{% endstep %}

{% step %}
Then, after the victim authenticates with the attacker's session, the attacker authenticates with the same session and gains access to the victim's panel
{% endstep %}
{% endstepper %}

***

#### Authentication Bypass via Captured Login Responses

{% stepper %}
{% step %}
Send a valid login request (correct email/password)
{% endstep %}

{% step %}
Capture the response using Burp Suite and copy it
{% endstep %}

{% step %}
Log out the user
{% endstep %}

{% step %}
Send a new login request with an incorrect password
{% endstep %}

{% step %}
Replace the 400 Bad Request response with the previously captured legitimate login response (including the valid session cookie)
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
