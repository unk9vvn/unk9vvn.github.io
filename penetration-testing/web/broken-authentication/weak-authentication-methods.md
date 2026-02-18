# Weak Authentication Methods

## Check List

## Methodology

### Black Box

#### Authentication Weakness

{% stepper %}
{% step %}
Create an account or change the password to evaluate the password policy
{% endstep %}

{% step %}
Test simple passwords (only numbers, only letters, short passwords, common ones like 123456) and check whether they are accepted
{% endstep %}

{% step %}
Identify the minimum and maximum password length by testing very short and very long passwords
{% endstep %}

{% step %}
Try using the username or personal information inside the password and observe the result.
{% endstep %}

{% step %}
Change the password multiple times and attempt to reuse a previous password
{% endstep %}

{% step %}
Perform multiple failed login attempts and check whether account lockout or rate limiting is enforced
{% endstep %}

{% step %}
If alternative factors such as PIN or security questions exist, test whether they are guessable or vulnerable to brute force
{% endstep %}

{% step %}
Finally, determine whether weaknesses exist in password complexity, password reuse protection, or brute-force protection
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
