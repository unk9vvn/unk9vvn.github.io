# Broken Object Level Authorization

## Check List

## Methodology

### Black Box

#### IDOR

{% stepper %}
{% step %}
Create two accounts on the target (Account A = yours, Account B = second/test account)
{% endstep %}

{% step %}
Perform any action with Account A that returns or uses an object ID, Common places

```
Your profile → returns "id": 12345
Your orders → /api/orders/9876
Your files → /files/abc-xyz-111
Your settings → /api/v1/users/852
```
{% endstep %}

{% step %}
Collect every ID you see in responses (numeric, UUID, base64, hashed, username-based, etc.)
{% endstep %}

{% step %}
Switch to Account B (or log out completely) and repeat the exact same requests but replace the ID with the one from Account A
{% endstep %}

{% step %}
If you can view, modify, or delete Account A’s resource → BOLA confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
