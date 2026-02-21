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

#### Updating Another User’s Object

{% stepper %}
{% step %}
Login as a normal user
{% endstep %}

{% step %}
Intercept profile update request

```http
PUT /api/users/1024 HTTP/1.1
Host: target.com
Authorization: Bearer user_token_1024
Content-Type: application/json

{"phone":"9999999999"}
```
{% endstep %}

{% step %}
Modify object ID

```http
PUT /api/users/1025 HTTP/1.1
Host: target.com
Authorization: Bearer user_token_1024
Content-Type: application/json

{"phone":"8888888888"}
```
{% endstep %}

{% step %}
Forward the request
{% endstep %}

{% step %}
If another user’s profile is updated successfully, write-level object authorization is missing
{% endstep %}

{% step %}
If no ownership validation is enforced server-side, BOLA vulnerability is confirmed.
{% endstep %}
{% endstepper %}

***

#### Accessing Files via Object Key Manipulation

{% stepper %}
{% step %}
Login normally
{% endstep %}

{% step %}
Access file endpoint

```http
GET /api/files/INV-2024-001.pdf HTTP/1.1
Host: target.com
Authorization: Bearer token_userA
```
{% endstep %}

{% step %}
Modify file identifier

```http
GET /api/files/INV-2024-002.pdf HTTP/1.1
Host: target.com
Authorization: Bearer token_userA
```
{% endstep %}

{% step %}
Send request
{% endstep %}

{% step %}
If unauthorized file belonging to another account is returned, object-level access control is missing
{% endstep %}

{% step %}
If file retrieval is based solely on predictable object keys, BOLA is confirmed
{% endstep %}
{% endstepper %}

***

### White Bo

## Cheat Sheet
