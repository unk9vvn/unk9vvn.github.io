# Stack Traces

## Check List

## Methodology

### Black Box

#### Verbose Error Disclosure via Malformed JSON

{% stepper %}
{% step %}
Identify API endpoint and Send malformed JSON

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":}
```
{% endstep %}

{% step %}
Observe server response, If response contains stack trace

```http
TypeError: Cannot read property 'password' of undefined
    at AuthController.login (/var/www/app/controllers/AuthController.js:47:15)
    at processTicksAndRejections (internal/process/task_queues.js:93:5)
```
{% endstep %}

{% step %}
If file paths, framework names, or line numbers are disclosed, stack trace exposure is confirmed
{% endstep %}
{% endstepper %}

***

#### SQL Error Trigger

{% stepper %}
{% step %}
Identify endpoint that interacts with database
{% endstep %}

{% step %}
Inject invalid input

```http
GET /api/products?id=' HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Observe response, If database error appears

```sql
SQLSTATE[42000]: Syntax error or access violation
in /var/www/app/models/ProductModel.php on line 88
```
{% endstep %}

{% step %}
If backend query structure or file location is exposed, stack trace disclosure exists
{% endstep %}

{% step %}
If internal SQL details are visible, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Invalid HTTP Method Handling

{% stepper %}
{% step %}
Send unsupported HTTP method

```http
TRACE /api/user/profile HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If server returns framework-level exception

```http
Unhandled Exception: MethodNotAllowedException
at Router.handle (/app/core/router.js:102)
```
{% endstep %}

{% step %}
If internal routing structure and file paths are revealed, exception handling is misconfigured
{% endstep %}

{% step %}
If raw stack trace is exposed instead of generic error message, stack trace vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Parameter Type Mismatch

{% stepper %}
{% step %}
Send incorrect parameter type

```http
GET /api/users/abc HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Observe response and If server returns

```http
NumberFormatException: For input string: "abc"
at java.lang.Integer.parseInt(Integer.java:580)
at com.app.UserController.getUser(UserController.java:63)
```
{% endstep %}

{% step %}
If language runtime details and source code paths are disclosed, stack trace exposure exists
{% endstep %}

{% step %}
If detailed exception information is visible in production API responses, Stack Traces vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
