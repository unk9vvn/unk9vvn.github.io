# Circumvention of Work Flows

## Check List

## Methodology

### Black Box

#### Skipping Payment Step in Checkout Process

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Add a product to the cart
{% endstep %}

{% step %}
Proceed to checkout normally
{% endstep %}

{% step %}
Intercept the checkout flow request

```http
POST /api/checkout/start HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"cartId":"789"}
```
{% endstep %}

{% step %}
Observe the next step requires payment authorization
{% endstep %}

{% step %}
Before completing payment, manually access the order confirmation endpoint

```http
POST /api/checkout/confirm HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"orderId":"789","status":"paid"}
```
{% endstep %}

{% step %}
Forward the request without completing payment , If order is confirmed without valid payment transaction ID, workflow validation is missing
{% endstep %}

{% step %}
If backend does not verify payment gateway response before confirming order, workflow bypass is confirmed
{% endstep %}
{% endstepper %}

***

#### Skipping OTP Verification Step

{% stepper %}
{% step %}
Register a new account
{% endstep %}

{% step %}
Submit phone/email verification request
{% endstep %}

{% step %}
Intercept OTP verification request

```http
POST /api/verify-otp HTTP/1.1
Host: target.com
Cookie: session=temp123
Content-Type: application/json

{"otp":"123456"}
```
{% endstep %}

{% step %}
Before submitting correct OTP, attempt to access protected endpoint

```http
GET /api/user/dashboard HTTP/1.1
Host: target.com
Cookie: session=temp123
```
{% endstep %}

{% step %}
Alternatively modify verification flag in request

```http
POST /api/complete-registration HTTP/1.1
Host: target.com
Cookie: session=temp123
Content-Type: application/json

{"verified":true}
```
{% endstep %}

{% step %}
If account becomes fully active without valid OTP validation, workflow circumvention is confirmed
{% endstep %}
{% endstepper %}

***

#### Bypassing Multi-Step KYC Verification

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Access KYC submission page
{% endstep %}

{% step %}
Intercept identity submission request

```http
POST /api/kyc/submit HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"document":"base64data","status":"pending"}
```
{% endstep %}

{% step %}
System requires admin approval before enabling withdrawals
{% endstep %}

{% step %}
Attempt to directly access withdrawal endpoint

```http
POST /api/wallet/withdraw HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"amount":100}
```
{% endstep %}

{% step %}
If withdrawal succeeds despite KYC status being pending, approval workflow is not enforced server-side
{% endstep %}

{% step %}
If sensitive feature becomes accessible without completing mandatory verification steps, workflow bypass vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Skipping Password Confirmation Before Sensitive Action

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Navigate to account deletion feature
{% endstep %}

{% step %}
Application requires password confirmation
{% endstep %}

{% step %}
Intercept confirmation request

```http
POST /api/account/confirm-password HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"password":"WrongPass"}
```
{% endstep %}

{% step %}
Do not wait for successful confirmation, Directly access final action endpoint

```http
POST /api/account/delete HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If account deletion executes without validating successful password confirmation state, workflow control is missing
{% endstep %}

{% step %}
If backend does not enforce sequential state validation, workflow circumvention is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
