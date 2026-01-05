# Weak Password Reset Functionalities

## Check List

## Methodology

### Black Box

#### Reauthentication For Changing Password Bypass

{% stepper %}
{% step %}
Go to accounts settings
{% endstep %}

{% step %}
Add an email address to the email which we have access to (Remember adding an email doesn't require you to re-enter password but changing password does)
{% endstep %}

{% step %}
Confirm the email address
{% endstep %}

{% step %}
Make it primary email (Even this doesn't require you to re-enter password)
{% endstep %}

{% step %}
Now we can change the password by reseting it through the new ema
{% endstep %}
{% endstepper %}

***

#### The Exploitation Potential Of IDOR In Password Recovery

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
Use Burp Suite’s Intruder to send multiple POST requests with the login endpoint (`/login`), iterating through `6-digit` OTP combinations (`000000` to `999999`) in the OTP field, monitoring for a 200 OK response
{% endstep %}

{% step %}
If a 200 OK response is received (`after` `~20 minutes`), use the guessed OTP to complete the login, verifying full account compromise due to lack of rate limiting
{% endstep %}

{% step %}
Test email or related parameters (`username, user_id`) on other authentication-related pages like `/login`, `/account/settings`, `/profile/edit`, or `/reset`, as these often handle user identification and may share similar vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Token Leak Via X-Forwarded-Host

{% stepper %}
{% step %}
Enter a registered email in the Forgot Password form and submit it to request a password reset token, intercepting the request with Burp Suite and starting an ngrok server
{% endstep %}

{% step %}
Locate the Host header in the intercepted request and add an `X-Forwarded-Host` header with an ngrok domain to redirect the token link
{% endstep %}

{% step %}
Check the email for the password reset link; if it contains the ngrok domain (`https:/ngrokDomain/action-token?key=xyz`), it confirms the poisoning vulnerability
{% endstep %}

{% step %}
Enter a victim’s email (`victim@example.com`) in the Forgot Password form, intercept the request, and add the `X-Forwarded-Host` header with the ngrok domain to redirect their token
{% endstep %}

{% step %}
Monitor the ngrok server; when the victim clicks the link, capture the token sent to the attacker’s domain, then use it to reset the victim’s password
{% endstep %}

{% step %}
Attempt to log in to the victim’s account with the new password to confirm full account takeover
{% endstep %}
{% endstepper %}

***

#### [Array Of Email Addresses Instead Of a Single Email Address](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover#password-reset-via-email-parameter)

{% stepper %}
{% step %}
Enter a single email in the password reset form and, if the request was in POST form, intercept the request with Burp Suite to change its text
{% endstep %}

{% step %}
Locate the email\_address parameter in the POST request body, originally set as a single string (`{"email_address":"xyz@gmail.com"}`)
{% endstep %}

{% step %}
Modify the email\_address parameter to an array containing a victim’s email (`admin@breadcrumb.com`) and the attacker’s email (`attacker@evil.com`), sending the modified request&#x20;

Change to `{"email_address":["admin@breadcrumb.com","attacker@evil.com"]}`
{% endstep %}

{% step %}
Check the attacker’s email for the password reset link; if received, it confirms the vulnerability allows token delivery to arbitrary addresses
{% endstep %}

{% step %}
Use the received token to access the password reset page (`https://example.com/reset?token=xyz`) and set a new password for the victim’s account
{% endstep %}

{% step %}
Attempt to log in to the victim’s account with the new password to confirm full account takeover
{% endstep %}
{% endstepper %}

***

#### Account Takeover

{% stepper %}
{% step %}
Log in to the target site and go to the forgotten password page
{% endstep %}

{% step %}
Enter your email address so that the link can be sent to you after the process and During the process, use Burp Suite to intercept the request
{% endstep %}

{% step %}
Then, check in the intercepted request whether the parameters in the request Body include an address to the site itself
{% endstep %}

{% step %}
If the request parameter contains a site path, change that parameter to the `attacker's address` or `ngrok` address, etc., and then check your test email to see if clicking on the link redirects you to the attacker's address. If yes, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Account Takeover Via Redirect Parameters

{% stepper %}
{% step %}
Enter a registered username or email in the Forgot Password form and submit it to trigger the password reset process, inspecting the page source for AJAX requests with Burp Suite
{% endstep %}

{% step %}
Locate the API endpoint handling password reset tokens, such as `/api/REDACTED/resetPasswordToken/` within the `XMLHttpRequest` responses generated in the background
{% endstep %}

{% step %}
Change the API endpoint request that is specific to resetting passwords to the form `api/v1/resetpassword/<username>` and enter it in the url and check whether the user information and tokens used are present in the response
{% endstep %}

{% step %}
Then, using the information provided, such as the username and token, create a link as follows: `https://www.company.com/#/changePassword/<username>/<token>`
{% endstep %}

{% step %}
Submit the crafted link to reset the target user’s password, then attempt to log in with the new password to confirm account takeover
{% endstep %}
{% endstepper %}

***

#### Account Takeover via Token Parameter

{% stepper %}
{% step %}
Enter your email (`attacker@example.com`) and the admin’s email (`admin@dashboard.example.com)` in the Password Reset form on `/login`, submitting requests consecutively in two different tabs to generate tokens
{% endstep %}

{% step %}
Copy the password reset link for your account (`https://dashboard.example.com/password-reset/form?token=28604`) from the email into a notepad
{% endstep %}

{% step %}
Modify the token in the copied link to the next consecutive number (`change 28604 to 28605`) to target the admin’s token
{% endstep %}

{% step %}
Access the modified link, reset the admin’s password using the form, and note the success to confirm the vulnerability
{% endstep %}

{% step %}
Attempt to log in to the admin account with the new password to verify full account takeover
{% endstep %}
{% endstepper %}

***

#### Open Redirect Account Takeover

{% stepper %}
{% step %}
Enter an email (`my-email@gmail.com`) in the forgotten password form and send a POST request to `/ForgotPassword` and use Burp Suite to look for parameters similar to `returnUrl` in the request body that redirect us to a path. These parameters
{% endstep %}

{% step %}
Locate the `returnUrl` parameter in the `POST` request body (`{"email":"my-email@gmail.com","returnUrl":"/reset/password/:userId/:code"}`) and modify it to an external URL (`https://my-website.com/reset/password/:userId/:code`)
{% endstep %}

{% step %}
Send the request and check for a 500 error, indicating the backend rejects external absolute URLs; then test with a relative path (`//my-website.com/reset/password/:userId/:code`) for a 200 response
{% endstep %}

{% step %}
Identify the open redirect vulnerability in the return parameter (`https://app.target.com/login?return=https://google.com`), then combine it by setting `returnUrl` to `/login?return=https://my-website.com/reset/password/:userId/:code`
{% endstep %}

{% step %}
Check the email for the reset link; if it contains the redirect (`https://app.target.com/login?return=https://my-website.com/reset/password/{userID}/{Random-Code})`, it confirms the vulnerability
{% endstep %}
{% endstepper %}

***

#### Expires On Email Change

{% stepper %}
{% step %}
Enter your email (`old-email@gmail.com`) in the Password Reset form and submit it to generate a reset link, leaving it unused
{% endstep %}

{% step %}
Log in to your account and change the email to a new address (`new-email@gmail.com`), confirming the change, then log out
{% endstep %}

{% step %}
Access the old unused password reset link sent to old-email@gmail.com (`https://example.com/reset?token=xyz`) and submit it to reset the password
{% endstep %}

{% step %}
Set a new password using the reset form and submit it to update the account password
{% endstep %}

{% step %}
Attempt to log in with the new password to confirm the account takeover via the old token
{% endstep %}

{% step %}
Test email or related parameters (`username, user_id`) on other password reset-related endpoints like `/reset`, `/password-reset`, `/account/recovery`, or `/user/reset`, as these often handle token expiration and may share similar flaws
{% endstep %}
{% endstepper %}

***

#### [Token Leak via Referrer](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover#password-reset-feature)

{% stepper %}
{% step %}
Request password reset to your email address
{% endstep %}

{% step %}
Click on the password reset link
{% endstep %}

{% step %}
Don't change password
{% endstep %}

{% step %}
Click any 3rd party websites(Facebook, X)
{% endstep %}

{% step %}
Intercept the request in Burp Suite proxy
{% endstep %}

{% step %}
Check if the referer header is leaking password reset token
{% endstep %}
{% endstepper %}

***

#### 0-Click Full Account Takeover

{% stepper %}
{% step %}
Navigate to the target application and click on the **Forgot Password** feature
{% endstep %}

{% step %}
Enter a valid email address and proceed with the password reset flow until you reach the **New Password** submission step
{% endstep %}

{% step %}
Intercept the HTTP request that is sent when submitting the new password using an intercepting proxy (Burp Suite)
{% endstep %}

{% step %}
Observe that the request contains the following parameters

* User email address
* Password reset token
* New password
{% endstep %}

{% step %}
Modify the intercepted request as follows

* Change the email parameter to the victim’s email addres.
* Set the reset token parameter to `null` or an empty value
{% endstep %}

{% step %}
Send the modified request to the server
{% endstep %}

{% step %}
Observe that the server responds with `HTTP 200 OK` without any validation errors
{% endstep %}

{% step %}
Verify that the password for the victim’s account has been successfully changed
{% endstep %}

{% step %}
Log in using the victim’s email address and the newly set password to confirm full account takeover
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
