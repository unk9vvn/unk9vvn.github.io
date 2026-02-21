# Padding Oracle Attack

## Check List

## Methodology

### Black Box

#### Padding Atatack (PKCS#7)

{% stepper %}
{% step %}
log in to the target site and upload it to your system using burp suite software
{% endstep %}

{% step %}
in the program, go to the add plugin section and download the padding oracle hunter plugin
{% endstep %}

{% step %}
then intercept a request, right-click and select the padding oracle hunter plugin in the plugins section. select a test type between `PKCS#7` and `PKCS#1.5` go to the plugin page
{% endstep %}

{% step %}
the important point is that the `PKCS#7` type has a different GUI page than the `PKCS#1.5` type
{% endstep %}

{% step %}
In the `PKCS#7` test page, there is an HTTP request at the beginning of the page. at the bottom of the request section, there are 4 options: payload, format, URL encoded, and clear section
{% endstep %}

{% step %}
In the middle of the page there are 4 entries called threads, block dize, response padding and plain text
{% endstep %}

{% step %}
at the bottom of the page there is a section called output. under output there are 4 buttons called test, encrypt, decrypt, and stop
{% endstep %}

{% step %}
pipe the request through extensions -> padding oracle hunter -> PKCS#7
{% endstep %}

{% step %}
select the ciphertext value in the request window, click delect payload with hex format, and uncheck URL encoded. the payload will be enclosed within the `§` symbol
{% endstep %}

{% step %}
click the test button and it will provide a summary which will indicate if the server is vulnerable to the padding oracle attack with its corresponding invalid/valid padding payload and response
{% endstep %}

{% step %}
copy either part of the padding response, or the full padding response from the output window and put it in the padding response textbox. you can choose to use either the valid or invalid padding response. click the decrypt button to recover the plaintext
{% endstep %}

{% step %}
To escalate to admin privileges, we will need to modify the plaintext to {“userid”:”100",”isAdmin”:”True”} and convert it to a hexadecimal value
{% endstep %}

{% step %}
copy the modified hexadecimal value to the plaintext textbox and click the encrypt button to compute the corresponding ciphertext
{% endstep %}

{% step %}
update the http request with the newly computed ciphertext and send the request to the server. notice that we are now logged in as an admin
{% endstep %}
{% endstepper %}

***

#### Padding Atatack (PKCS#1 v1.5)

{% stepper %}
{% step %}
pipe the request through extensions -> padding oracle hunter -> PKCS#1 v1.5
{% endstep %}

{% step %}
select the ciphertext value in the request window, click select payload with Hex format, and uncheck URL encoded. The payload will be enclosed within the `§` symbol
{% endstep %}

{% step %}
fill in the public key parameters with public exponent: `65537` and modulus: `91150209829916536965146520317827566881182630249923637533035630164622161072289`
{% endstep %}

{% step %}
click the test button, and it will provide a summary which will indicate if the server is vulnerable to a padding oracle attack with its corresponding invalid/valid padding payload and response
{% endstep %}

{% step %}
copy either part of the padding response, or the full padding response from the output window and put it in the padding response textbox. you can choose to use either the valid or invalid padding response. click the decrypt button, and the plaintext will be recovered after about `50k` requests
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
