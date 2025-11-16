# Bypassing Authentication Schema

## Check List

* [ ] Ensure that authentication is applied across all services that require it.

## Methodology

### Black Box

#### Auth Type Manipulation

{% stepper %}
{% step %}
Log in to the target site, go to the authentication page, and check if it uses multiple types of authentication, such as password, email, Google, and Facebook
{% endstep %}

{% step %}
Enter the request using an incorrect password and email address. Intercept the POST request using Bupr Suite
{% endstep %}

{% step %}
Then examine the intercepted request and see if you see a parameter called `auth_type`
{% endstep %}

{% step %}
If you see such a parameter that specifies the type of authentication with Google or Facebook or password and email, send the request to the repeater
{% endstep %}

{% step %}
And then change the authentication type in the `auth_type` parameter to facebook

```json
"auth_type": "email" → "facebook"
```
{% endstep %}

{% step %}
If the user information is displayed in the server response, the authentication bypass is confirmed
{% endstep %}
{% endstepper %}

***

####

{% stepper %}
{% step %}
Access registration form
{% endstep %}

{% step %}
Enter email `test@redacted.com`, Capture `POST` request in Burp
{% endstep %}

{% step %}
Notice server prepends or validates only suffix (`@redacted.com`)

```http
email=bishal@redacted.com
```
{% endstep %}

{% step %}
Modify email domain to any external domain

```
email=bishal0x01@bugcrowdninja.com
```
{% endstep %}

{% step %}
Send request
{% endstep %}

{% step %}
Receive verification email at `bishal0x01@bugcrowdninja.com`
{% endstep %}

{% step %}
Click link, Account activated
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

#### Parameter Modification <a href="#parameter-modification" id="parameter-modification"></a>



#### Session ID Prediction <a href="#session-id-prediction" id="session-id-prediction"></a>



#### SQL Injection (HTML Form Authentication) <a href="#sql-injection-html-form-authentication" id="sql-injection-html-form-authentication"></a>



#### PHP Loose Comparison <a href="#php-loose-comparison" id="php-loose-comparison"></a>
