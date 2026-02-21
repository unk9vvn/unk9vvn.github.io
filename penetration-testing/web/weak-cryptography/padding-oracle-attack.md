# Padding Oracle Attack

## Check List

## Methodology

### Black Box

#### Padding Atatack (PKCS#7)

{% stepper %}
{% step %}
Log in to the target site and upload it to your system using Burp Suite software
{% endstep %}

{% step %}
In the program, go to the add plugin section and download the Padding Oracle Hunter plugin
{% endstep %}

{% step %}
Then intercept a request, right-click and select the Padding Oracle Hunter plugin in the plugins section. Select a test type between `PKCS#7` and `PKCS#1.5` Go to the plugin page
{% endstep %}

{% step %}
The important point is that the `PKCS#7` type has a different GUI page than the `PKCS#1.5` type
{% endstep %}

{% step %}
In the `PKCS#7` test page, there is an HTTP request at the beginning of the page. At the bottom of the request section, there are 4 options: Payload, format, url encoded, and clear section
{% endstep %}

{% step %}
In the middle of the page there are 4 entries called Threads, Block Size, Response Padding and Plain Text
{% endstep %}

{% step %}
At the bottom of the page there is a section called output. Under output there are 4 buttons called test, encrypt, decrypt, and stop
{% endstep %}

{% step %}
Pipe the request through Extensions -> Padding Oracle Hunter -> PKCS#7
{% endstep %}

{% step %}
Select the ciphertext value in the Request window, click Select Payload with Hex format, and uncheck Url Encoded. The payload will be enclosed within the `§` symbo
{% endstep %}

{% step %}
Click the **Test** button and it will provide a summary which will indicate if the server is vulnerable to the padding oracle attack with its corresponding invalid/valid padding payload and response
{% endstep %}

{% step %}
Copy either part of the padding response, or the full padding response from the Output window and put it in the Padding Response textbox. You can choose to use either the valid or invalid padding response. Click the Decrypt button to recover the plaintext
{% endstep %}

{% step %}
To escalate to admin privileges, we will need to modify the plaintext to {“userid”:”100",”isAdmin”:”True”} and convert it to a hexadecimal value
{% endstep %}

{% step %}
Copy the modified hexadecimal value to the Plaintext textbox and click the Encrypt button to compute the corresponding ciphertext
{% endstep %}

{% step %}
Update the http request with the newly computed ciphertext and send the request to the server. Notice that we are now logged in as an admin
{% endstep %}
{% endstepper %}

***

#### Padding Atatack (PKCS#1 v1.5)

{% stepper %}
{% step %}
Pipe the request through Extensions -> Padding Oracle Hunter -> PKCS#1 v1.5
{% endstep %}

{% step %}
Select the ciphertext value in the Request window, click Select Payload with Hex format, and uncheck Url Encoded. The payload will be enclosed within the `§` symbol
{% endstep %}

{% step %}
Fill in the public key parameters with public exponent: `65537` and modulus: `91150209829916536965146520317827566881182630249923637533035630164622161072289`
{% endstep %}

{% step %}
Click the **Test** button, and it will provide a summary which will indicate if the server is vulnerable to a padding oracle attack with its corresponding invalid/valid padding payload and response
{% endstep %}

{% step %}
Copy either part of the padding response, or the full padding response from the **Output** window and put it in the Padding Response textbox. You can choose to use either the valid or invalid padding response. Click the **Decrypt** button, and the plaintext will be recovered after about `50k` requests
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
