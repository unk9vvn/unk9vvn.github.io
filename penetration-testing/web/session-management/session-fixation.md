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

#### Improper Session Invalidation Allows Account Access After Logout

{% stepper %}
{% step %}
Login with a valid account
{% endstep %}

{% step %}
Capture the login HTTP 302 Found response using a proxy tool like Burp Suite
{% endstep %}

{% step %}
Log out from the account
{% endstep %}

{% step %}
Clear browser cookies
{% endstep %}

{% step %}
Attempt to log in as a different user
{% endstep %}

{% step %}
During login, replace the server response with the earlier captured 302 response
{% endstep %}

{% step %}
The application logs you into the original session (`victim@example.com`), not the new user
{% endstep %}
{% endstepper %}

***

#### Account Takeover

{% stepper %}
{% step %}
Visit the target site without logging in
{% endstep %}

{% step %}
Check cookies, URL parameters, hidden fields, or response headers for a session identifier (`PHPSESSID`, `JSESSIONID`, `session_id=abc123`)
{% endstep %}

{% step %}
Open two different browsers/incognito windows
{% endstep %}

{% step %}
Visit the site, Note the session ID is generated and sent before login
{% endstep %}

{% step %}
Verify the same session ID persists after refresh or navigation
{% endstep %}

{% step %}
Create a login link containing the attacker-controlled session ID like

```hurl
https://target.com/login
https://target.com/?PHPSESSID=attacker123
https://target.com/dashboard;jsessionid=attacker123
```
{% endstep %}

{% step %}
Send the malicious link via email, chat, or phishing page (victim trusts the domain)
{% endstep %}

{% step %}
Victim clicks the link → Lands on site with attacker’s session ID
{% endstep %}

{% step %}
Victim enters valid credentials and logs in successfully
{% endstep %}

{% step %}
Application does NOT issue a new session ID after successful authentication, `Same attacker123` remains active
{% endstep %}

{% step %}
Attacker visits the site using the same session ID

```hurl
https://target.com/?PHPSESSID=attacker123
```
{% endstep %}

{% step %}
Instantly logged in as the victim, Full session takeover
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
