# Broken Function Level Authorization

## Check List

## Methodology

### Black Box

#### Vertical Privilege Escalation via Admin Endpoint

{% stepper %}
{% step %}
Login as a normal user, Capture your API token
{% endstep %}

{% step %}
Attempt to access an admin-only endpoint

```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If response returns user list instead of `403/401`, role validation is missing
{% endstep %}

{% step %}
If endpoint is accessible with a low-privileged token, function-level authorization is broken
{% endstep %}

{% step %}
If sensitive administrative functionality is exposed to non-admin user, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Privileged Action via HTTP Method Manipulation

{% stepper %}
{% step %}
Login as normal user, Intercept a normal read-only request

```http
GET /api/users/1024 HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Change HTTP method to privileged action

```http
DELETE /api/users/1024 HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Send modified request
{% endstep %}

{% step %}
If deletion succeeds without admin privileges, function-level authorization is not enforced per HTTP method
{% endstep %}

{% step %}
If server validates authentication but not role-based function access, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Hidden Admin Endpoint Discovery

{% stepper %}
{% step %}
Login as normal user, Browse JavaScript files

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Identify hidden admin endpoint reference

```hurl
/api/v1/admin/export-users
```
{% endstep %}

{% step %}
Directly request endpoint

```http
GET /api/v1/admin/export-users HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If server responds with exported user data instead of access denied, role enforcement is missing
{% endstep %}

{% step %}
If backend relies only on UI restrictions and not server-side role checks, function-level authorization is broken
{% endstep %}
{% endstepper %}

***

#### Role Parameter Tampering

{% stepper %}
{% step %}
Login as normal user, Intercept privileged request structure

```http
POST /api/settings/update HTTP/1.1
Host: target.com
Authorization: Bearer user_token
Content-Type: application/json

{"feature":"maintenance","enabled":false}
```
{% endstep %}

{% step %}
Modify request by adding role field

```json
{"feature":"maintenance","enabled":true,"role":"admin"}
```
{% endstep %}

{% step %}
Send modified request, If privileged system configuration is changed without admin account, server trusts client input for function authorization
{% endstep %}

{% step %}
If administrative functionality is executed by non-admin user, Broken Function Level Authorization vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
