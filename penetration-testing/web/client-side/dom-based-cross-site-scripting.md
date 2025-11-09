# DOM-Based Cross Site Scripting

## Check List

## Methodology

### Black Box

#### DOM in URL Parameter

{% stepper %}
{% step %}
Check the search bar or URL parameter query in the blog page to see if user input is reflected in the HTML output
{% endstep %}

{% step %}
Make a simple search with normal keywords like HI and verify the query appears in the page source or response
{% endstep %}

{% step %}
Then inject a basic HTML tag like `#">` into the query parameter and check if it renders as broken image
{% endstep %}

{% step %}
If the greater-than `>` is HTML-encoded and event handlers are removed, WAF is filtering XSS
{% endstep %}

{% step %}
Then try a script tag directly in the URL query like `#alert(document.domain)` to bypass the WAF
{% endstep %}

{% step %}
If the alert fires on document.domain, reflected XSS is confirmed
{% endstep %}

{% step %}
Test the query parameter on other Microsoft blog endpoints like `/msrc/blog`, `/security`,`/vulnerability`, or `/research` as these often have search functionality with similar reflection
{% endstep %}

{% step %}
Common vulnerable paths include `/msrc/blog/search`, `/security/blog`, `/vulnerability/research`, or `/msrc/search`
{% endstep %}
{% endstepper %}

***

#### DOM in Search Bar

{% stepper %}
{% step %}
Load the target forum or community site and locate the search bar, typically in the top right corner or header
{% endstep %}

{% step %}
Open the site and click the search button
{% endstep %}

{% step %}
Enter a payload like `@prompt(1337)gmail.com` into the search bar and submit the query
{% endstep %}

{% step %}
Type the payload in the search input and hit enter
{% endstep %}

{% step %}
Check if a new window or page opens with advanced search; if the payload is reflected unsanitized in the input field or results, it may trigger XSS
{% endstep %}

{% step %}
Observe the advanced search page for script execution (`alert(1337)`)
{% endstep %}

{% step %}
Copy the generated URL containing the reflected payload and test it in a new tab or send to a victim to verify persistence or delivery

```
https://example.org/search?q=@<script>prompt(1337)</script>gmail.com
```
{% endstep %}
{% endstepper %}

***

#### SPA Sites

{% stepper %}
{% step %}
Find any JavaScript-heavy site or SPA with client-side rendering
{% endstep %}

{% step %}
Check the page source or dev tools to locate JS code using `innerHTML`, `document.write`, `insertAdjacentHTML`, or `outerHTML`
{% endstep %}

{% step %}
Make a normal interaction (`search`, `profile`, `settings`) and use Elements tab to see if user input (`URL param`, form, `localStorage`) flows into these DOM sinks
{% endstep %}

{% step %}
Then inject a test payload like  into the input source (`URL`, `field`, `hash`)
{% endstep %}

{% step %}
Example URL

```
https://target.com/search?q=<img src=x onerror=alert(1)>
```
{% endstep %}

{% step %}
Example Hash

```
#<svg onload=alert(1)>
```
{% endstep %}

{% step %}
If the payload appears in DOM and alert fires without server response change, DOM XSS is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
