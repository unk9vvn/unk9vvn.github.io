# Server Side Template Injection

## Check List

## Methodology

### Black Box

#### Server‑Side Template Injection (SSTI) in Next.js

{% stepper %}
{% step %}
Embed a site that uses Next.js
{% endstep %}

{% step %}
Note down each endpoint that has input, query parameters, POST body fields, headers, and cookies
{% endstep %}

{% step %}
Send sample requests and look for responses with `Content-Type: text/html` — these are SSR targets
{% endstep %}

{% step %}
Inject benign markers like `SSTI_TEST_123` or `{{7*7}}` into parameters and observe reflections in the response
{% endstep %}

{% step %}
Download JS bundles from `/_next/` and search for keywords such as `dangerouslySetInnerHTML`, `innerHTML`, or `fetch(/api)`
{% endstep %}

{% step %}
Send payloads like `{{7*7}}`, `<%=7*7%>`, or `${7*7}` and check for evaluated output ( `49`) or server errors
{% endstep %}

{% step %}
Look for stack traces or error messages revealing `ejs`, `handlebars`, `pug`, or `render()` usage
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
