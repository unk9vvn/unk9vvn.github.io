# Exposed Session Variables

## Check List

## Methodology

### Black Box

#### Exposed Session Tokens via Misconfigured

{% stepper %}
{% step %}
Log into a user account on target.com
{% endstep %}

{% step %}
Navigate to Settings, Edit Profile and change your username
{% endstep %}

{% step %}
Intercept the request using a proxy tool like Burp Suite
{% endstep %}

{% step %}
Send the request to Intruder, and set the `Token` header as the payload position
{% endstep %}

{% step %}
Use a list of random session token values, ending with the valid one
{% endstep %}

{% step %}
Launch the attack and analyze the responses
{% endstep %}

{% step %}
Invalid Tokens: Response code `401` with a body length of `431`
{% endstep %}

{% step %}
Valid Token: Response code `200` with a body length of `487`
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
