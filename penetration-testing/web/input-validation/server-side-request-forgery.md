# Server Side Request Forgery

## Check List



## Cheat Sheet

### Methodology

{% stepper %}
{% step %}
Go to the site that uses Next Js technology, right click and select View Page Source
{% endstep %}

{% step %}
Search for /\_next/image?url= and see if you see anything
{% endstep %}

{% step %}
And send this request in the form below

```url
GET https://target/_next/image?url=https://attacker.com/p.png&w=100&q=75
```
{% endstep %}

{% step %}
Check if the server has hit our server or not, if it has hit, the vulnerability will be detected
{% endstep %}
{% endstepper %}

***
