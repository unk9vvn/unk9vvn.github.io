# Vulnerable Remember Password

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

#### Trigger the Passwordless / Remember Me Login

{% stepper %}
{% step %}
Register or log in normally
{% endstep %}

{% step %}
Tick "`Remember me`", "`Stay logged in`", or use "`Sign in with this device`"
{% endstep %}

{% step %}
Complete login → Note you are logged in
{% endstep %}

{% step %}
Open DevTools → Application → Local Storage / Session Storage / IndexedDB
{% endstep %}

{% step %}
Search for `password`, `cred`, `token`, `user`, `email`
{% endstep %}

{% step %}
If `plain/encoded/base64` credentials found → Credential leak confirmed
{% endstep %}

{% step %}
then go to DevTools → Application → Cookies
{% endstep %}

{% step %}
Look for session cookie with no or very long `Expires/Max-Age` (1 year, "Session" but never expires)
{% endstep %}
{% endstepper %}

***

#### Clickjacking on Auto-Login Page

{% stepper %}
{% step %}
Frame the login/auto-auth page

```html
<iframe src="https://target.com/auto-login" style="opacity:0.1"></iframe>
```
{% endstep %}

{% step %}
If auto-login triggers in iframe → Clickjacking possible
{% endstep %}
{% endstepper %}

***

#### CSRF on Auto-Auth Flow

{% stepper %}
{% step %}
Craft CSRF PoC that visits the auto-login endpoint

```html
<img src="https://target.com/remembered-login-endpoint">
```
{% endstep %}

{% step %}
If victim visits → Automatically logged in as you → CSRF confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
