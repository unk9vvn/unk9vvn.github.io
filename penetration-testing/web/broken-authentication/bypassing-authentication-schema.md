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

#### Email Domain Validation Bypass

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

#### Change The Letter Case

{% stepper %}
{% step %}
Use the [enumerate Application](https://unk9vvn.gitbook.io/penetration-testing/web/reconnaissance/enumerate-applications) command to perform the identification process and obtain the sensitive paths of the admin panel
{% endstep %}

{% step %}
Access known admin path

```http
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 in response, then send the following request

```http
GET /AdMiN HTTP/1.1
GET /ADMIN HTTP/1.1
GET /aDmIn HTTP/1.1
GET /Admin HTTP/1.1
GET /aDMIN HTTP/1.1
```
{% endstep %}

{% step %}
If any variation returns 200 OK, Case sensitivity bypass confirmed
{% endstep %}
{% endstepper %}

***

#### HTTP Method Bypass Auth

{% stepper %}
{% step %}
Make a request to the admin panel and check if it gives you a 403 in response
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 then change the HTTP method to PUT or Patch or ...

```http
PATCH /admin HTTP/1.1
HEAD /admin HTTP/1.1
PUT /admin HTTP/.1.1
```
{% endstep %}
{% endstepper %}

***

#### Path Confusion Auth Bypass

{% stepper %}
{% step %}
Request a sensitive route like the panel or admin route and if it gives you a 403, try to mislead the route using the payload below

```http
GET /%2e%2e/admin HTTP/1.1
```
{% endstep %}

{% step %}
If the server response shows login or admin information, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### [Fullname Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection)

{% stepper %}
{% step %}
Navigate to the SignUp page of the target website, typically located at a URL like `/signup` or `/register` Open https://example.com/signup in the browser
{% endstep %}

{% step %}
Identify the “Full Name” input field in the SignUp form, which is prone to processing user input directly into database queries Find the text box labeled “Full Name” in the form
{% endstep %}

{% step %}
Enter the payload `' OR 1=1 --` into the Full Name field to attempt bypassing the query’s conditions and access unauthorized data Input `John' OR 1=1 --` in the Full Name field
{% endstep %}

{% step %}
Click the `“Sign Up”` button to send the payload to the server via a <sub>POST</sub> request
{% endstep %}

{% step %}
Look for a generic error (“Invalid input”) or a `400`/`500` status code, indicating the payload was blocked, or unexpected success, suggesting a vulnerability
{% endstep %}

{% step %}
If a 400/500 error appears, modify the payload to `' OR 1=2 --` and submit again. Compare responses: if `' OR 1=1 --` allows form submission or data access (account creation without valid input) while `' OR 1=2 --` fails, it confirms SQL injection, as the true condition (`1=1`) altered the query’s logic
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

#### Parameter Modification <a href="#parameter-modification" id="parameter-modification"></a>



#### Session ID Prediction <a href="#session-id-prediction" id="session-id-prediction"></a>



#### SQL Injection (HTML Form Authentication) <a href="#sql-injection-html-form-authentication" id="sql-injection-html-form-authentication"></a>



#### PHP Loose Comparison <a href="#php-loose-comparison" id="php-loose-comparison"></a>
