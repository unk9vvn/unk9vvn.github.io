# Improper Error Handling

## Check List

## Methodology

### Black Box

#### Improper Error Handling Leading to Information Disclosure

{% stepper %}
{% step %}
Navigate to the target web application and identify accessible API endpoints
{% endstep %}

{% step %}
Interact with the API endpoint by submitting malformed or unexpected input in request parameters

```http
GET /api/v1/login?user=admin'-- HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Observe the server response and check for detailed error messages returned by the API

```json
{
  "error": "SQL syntax error in users_db at 10.0.0.1",
  "query": "SELECT * FROM users WHERE username = 'admin'--'"
}
```
{% endstep %}

{% step %}
Analyze the response for sensitive information such as Internal database names, Internal IP addresses, SQL queries or Valid usernames or system structure
{% endstep %}

{% step %}
Repeat the request with different malformed inputs to determine whether additional internal system information is disclosed
{% endstep %}

{% step %}
If the API response exposes internal database details, system architecture, or query structures through verbose error messages, the Information Disclosure vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Information Disclosure via Improper Error Handling

{% stepper %}
{% step %}
Navigate to the target web application and identify an endpoint that accepts user-supplied input

```http
GET /product?productId=1 HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Confirm that the application responds normally when a valid numeric value is provided
{% endstep %}

{% step %}
Modify the request by replacing the numeric parameter value with an invalid string input

```http
GET /product?productId=test HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Send the modified request to the server
{% endstep %}

{% step %}
Observe the server response and check whether a **500 Internal Server Error** is returned
{% endstep %}

{% step %}
Scroll through the stack trace output and identify any exposed sensitive information such as Framework name or Internal file paths and ...
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
