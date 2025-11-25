# Cookies Attributes

## Check List

## Methodology

### Black Box

#### Insecure Cookie Exposure

{% stepper %}
{% step %}
Log in as a normal user
{% endstep %}

{% step %}
Open DevTools then go to Console
{% endstep %}

{% step %}
Type `document.cookie`
{% endstep %}

{% step %}
Look for any authentication-related cookies ( `accessToken`, `session`, `refreshToken`)
{% endstep %}

{% step %}
Open DevTools, Application, Storage, Cookies to check attributes like

* `HttpOnly`
* `Secure`
* Expiration date
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
