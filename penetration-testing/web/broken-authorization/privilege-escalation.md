# Privilege Escalation

## Check List

## Methodology

### Black Box

#### Manipulation of Account Attributes

{% stepper %}
{% step %}
Inspect JavaScript files in the target website to identify parameters like `isEmployee` or `isCorporate`,`admin` and ..., then use Burp Suite to locate them in a GET request to `/customer/{{ID}}`
{% endstep %}

{% step %}
Attempt to modify the parameters by using Burp Suite’s “`Match and Replace`” feature to change false to true in the GET request, but note if it fails
{% endstep %}

{% step %}
Send an OPTIONS request to `/customer/{{ID}}` with Burp Suite to check supported methods, confirming the endpoint accepts a PATCH request
{% endstep %}

{% step %}
Send a PATCH request to `/customer/{{ID}}` with modified parameters (`{"isEmployee": true}`) to escalate privileges, intercepting and altering the request body
{% endstep %}

{% step %}
Return to the website and navigate to the checkout endpoint, adding excessive products to verify if the escalated employee status grants an unauthorized discount
{% endstep %}

{% step %}
Test ID or related parameters (`user_id, customer_id`) on other customer-related endpoints like `/user/{{ID}}`, `/profile/{{ID}}`, `/account/{{ID}}`, or `/customer/update`, as these often handle privilege settings and may share similar vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Registration Feature

{% stepper %}
{% step %}
Enter the registration form and capture the registration process using burp Suite and check if it is a POST or GET request
{% endstep %}

{% step %}
Find the role parameter in the POST request body, which is initially set to {"role": "User"} or may be in numeric form like `{"role": "5"}`, and to try to increase the privilege, change it to `{"role": "Admin"}` or to `{"role": "1"}`
{% endstep %}

{% step %}
Send the modified request and check the account status after registration; if it grants admin access, it confirms the vulnerability
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
