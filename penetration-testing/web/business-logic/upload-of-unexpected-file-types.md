# Upload of Unexpected File Types

## Check List



## Cheat Sheet

#### Stored Cross-Site Scripting (Stored XSS) via SVG Upload

{% stepper %}
{% step %}
Login to Account
{% endstep %}

{% step %}
Access your account with valid credentials
{% endstep %}

{% step %}
Open Your Project
{% endstep %}

{% step %}
Navigate to the specific project you want to test
{% endstep %}

{% step %}
Go to the locate the avatar upload form
{% endstep %}

{% step %}
Attach PNG File with SVG Code and Upload a PNG file containing the SVG code

```xml
<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"> <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/> </svg>
```
{% endstep %}

{% step %}
Click forward the request and after creating the image, open it and Check if an alert dialog appears; if not, click the triangle again to confirm
{% endstep %}
{% endstepper %}

***

####

{% stepper %}
{% step %}
###


{% endstep %}

{% step %}
###


{% endstep %}
{% endstepper %}
