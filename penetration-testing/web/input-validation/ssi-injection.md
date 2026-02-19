# SSI Injection

## Check List

## Methodology

### Black Box

#### Read Sensitive File via Server Side Include

{% stepper %}
{% step %}
Identify the target web application and perform basic information gathering to determine the web server type
{% endstep %}

{% step %}
Check whether the server potentially supports **Server-Side Includes (SSI)** by ( Looking for `.shtml` files in the application or Inspecting response headers and server banners)
{% endstep %}

{% step %}
Identify all possible user input points, including ( Cookie , comments,)
{% endstep %}

{% step %}
Select an input field that reflects user-supplied data back into the application (error messages, forum posts, profile fields)
{% endstep %}

{% step %}
Submit a test payload containing an SSI directive, such as

```php
<!--#include virtual="/etc/passwd" -->
```
{% endstep %}

{% step %}
Then, check the server response to see if the payloads we injected are displayed and processed in the response and include the contents of the sensitive `etc/passwd` file. If so, the vulnerability is successfully confirmed
{% endstep %}
{% endstepper %}

***

#### Serer Side Including via HTTP Header&#x20;

{% stepper %}
{% step %}
injection via HTTP headers, for example:

```http
GET / HTTP/1.1
Host: target.com
Referer: <!--#exec cmd="/bin/ps ax"-->
User-Agent: <!--#include virtual="/proc/version"-->
```
{% endstep %}

{% step %}
Send the crafted request using a proxy tool (Burp Suite Repeater)
{% endstep %}

{% step %}
Observe whether the injected SSI directives are executed or included in the generated page
{% endstep %}

{% step %}
Conclude that the application is vulnerable to SSI Injection if server-side directives are successfully executed
{% endstep %}
{% endstepper %}

***

####

### White Box

## Cheat Sheet
