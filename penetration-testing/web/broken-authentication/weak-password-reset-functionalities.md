# Weak Password Reset Functionalities

## Check List

## Methodology

### Black Box

#### The Exploitation Potential of IDOR in Password Recovery

{% stepper %}
{% step %}
Navigate to the Forgot Password page, typically found at `/forgot-password`, `/reset-password`, `/account/recovery`, or `/login/forgot`, where users initiate password reset requests
{% endstep %}

{% step %}
Enter a registered email address in the email field and submit the form to receive an OTP, capturing the request with Burp Suite to inspect the workflow
{% endstep %}

{% step %}
Locate the email parameter in the POST request body, often used to identify the account for reset and potentially passed unsanitized to the database or logic layer
{% endstep %}

{% step %}
After receiving the OTP for the first account, intercept the final password reset request with Burp Suite, modify the email parameter to a different registered email (`test2@example.com`), and forward it to change the target account’s password
{% endstep %}

{% step %}
Attempt to log in to the target account (`test2@example.com`) with the new password to confirm the IDOR vulnerability allowed unauthorized password reset
{% endstep %}

{% step %}
If login triggers an OTP request (`6-digit code`), note this as the final authentication barrier, then prepare to test for rate limiting weaknesses
{% endstep %}

{% step %}
Use Burp Suite’s Intruder to send multiple POST requests with the login endpoint (e.g., /login), iterating through 6-digit OTP combinations (`000000` to `999999`) in the OTP field, monitoring for a 200 OK response
{% endstep %}

{% step %}
If a 200 OK response is received (`after` `~20 minutes`), use the guessed OTP to complete the login, verifying full account compromise due to lack of rate limiting
{% endstep %}

{% step %}
Test email or related parameters (`username, user_id`) on other authentication-related pages like `/login`, `/account/settings`, `/profile/edit`, or `/reset`, as these often handle user identification and may share similar vulnerabilities
{% endstep %}
{% endstepper %}

***

#### s

{% stepper %}
{% step %}
###


{% endstep %}

{% step %}
###


{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
