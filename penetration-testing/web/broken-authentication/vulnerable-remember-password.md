# Vulnerable Remember Password

## Check List

* [ ] Validate that the generated session is managed securely and do not put the user’s credentials in danger.

## Methodology

### Black Box

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
If auto-login triggers in iframe → Clickjacking Possible
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

### Click Jacking <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& cURL

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano rp-clickjacking.sh
```

```bash
// Some code
```
