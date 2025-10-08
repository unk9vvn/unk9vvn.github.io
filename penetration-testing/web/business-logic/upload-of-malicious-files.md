# Upload of Malicious Files

## Check List



## Cheat Sheet

### Methodology

#### XSS Stored via Upload avatar PNG \[HTML]

{% stepper %}
{% step %}
Create Malicious PNG Payload&#x20;
{% endstep %}

{% step %}
Download the XSS payload PNG from&#x20;

[https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Files/xss\_comment\_exif\_metadata\_double\_quote.png](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Files/xss_comment_exif_metadata_double_quote.png)

or use exiftool to embed:&#x20;

```bash
exiftool -Comment="">alert(prompt('XSS BY ZEROX4'))" xss_comment_exif_metadata_double_quote.pn
```
{% endstep %}

{% step %}
Access Avatar Upload Page
{% endstep %}

{% step %}
Go to the locate the avatar upload form
{% endstep %}

{% step %}
Intercept Upload Request in Burp Suite
{% endstep %}

{% step %}
Modify Content-Type to `text/html`
{% endstep %}

{% step %}
Edit the Content-Type header for the uploaded file from `image/png` to `text/html` in the request
{% endstep %}

{% step %}
Submit Modified Request
{% endstep %}

{% step %}
Forward the altered request to upload the malicious PNG as HTML
{% endstep %}

{% step %}
Verify Stored XSS Execution
{% endstep %}

{% step %}
Confirm the file is saved on example.com and access it to trigger the alert payload
{% endstep %}
{% endstepper %}

***
