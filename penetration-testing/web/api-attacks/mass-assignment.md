# Mass Assignment

## Check List

## Methodology

### Black Box

#### Mass Assignment / Over-Privileging

{% stepper %}
{% step %}
Find any endpoint that creates or updates a resource like Registration or Profile update
{% endstep %}

{% step %}
Do the normal flow once with your low-privilege account and intercept the request with Burp Suite
{% endstep %}

{% step %}
In the request body (JSON or form-data), add one by one these classic privileged parameters

```json
"isAdmin": true,
"admin": true,
"role": "admin",
"role": "administrator",
"role": "superadmin",
"permissions": ["admin"],
"level": 999,
"is_staff": true,
"is_superuser": true,
"account_type": "premium",
"verified": true,
"email_verified": true
```
{% endstep %}

{% step %}
Send the modified request and check the response → if it’s 200/201 → possible win
{% endstep %}

{% step %}
Log out and log in again → check if you suddenly became admin
{% endstep %}

{% step %}
If you become an admin, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
