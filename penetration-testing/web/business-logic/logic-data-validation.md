# Logic Data Validation

## Check List

## Methodology

### Black Box

#### Accessing Reviews via Manipulated UUID

{% stepper %}
{% step %}
As the Workspace Owner Create a new project
{% endstep %}

{% step %}
Add User A as Member
{% endstep %}

{% step %}
Add User B as Reviewer
{% endstep %}

{% step %}
As User A (Member) Go to the Reviews section then Click Share Review and copy the generated link
{% endstep %}

{% step %}
Intercept and Manipulate the Request Intercept the request using Burp Suite / any proxy too and Send the request to Repeater
{% endstep %}

{% step %}
Modify the request body and change the UUID value to

```
 "uuid": "@evil.com"
```
{% endstep %}

{% step %}
Forward the request
{% endstep %}

{% step %}
The server responds with a malformed review URL like

```json
"reviewURL": https://example.com/sketch/@evil.com
```
{% endstep %}

{% step %}
Login as Owner or Admin and Try to open the review normally
{% endstep %}

{% step %}
The page responds with

```
404 Not Found
```
{% endstep %}

{% step %}
The review becomes inaccessible to the Owner and Admin
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
