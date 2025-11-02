# Payment Functionality

## Check List

## Methodology

### Black Box

#### Payment Gateway Bypass

{% stepper %}
{% step %}
Add items to the cart and proceed to checkout to initiate a payment via the third-party gateway, capturing the redirect URL and parameters with Burp Suite
{% endstep %}

{% step %}
Complete a legitimate low-cost purchase to obtain a valid payment\_id and observe the success redirect parameters (e.g., status=Succeed, payment\_id=abc123)
{% endstep %}

{% step %}
Start a new order, proceed to payment, and cancel it at the gateway to trigger a failure redirect with parameters (status=Failed, payment\_id=xyz789)
{% endstep %}

{% step %}
Intercept the failure redirect response in Burp Suite and modify the parameters to fake success: change `status=Failed` to `status=Succeed` and replace `payment_id=xyz789` with the valid `payment_id=abc123` from the prior transaction
{% endstep %}

{% step %}
Check the target website for order confirmation or invoice; if the order is marked as paid without actual payment, it confirms the bypass vulnerability
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
