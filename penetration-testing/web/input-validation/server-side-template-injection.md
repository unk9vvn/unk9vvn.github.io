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

#### Username Parameter

{% stepper %}
{% step %}
Enter the target site and then log in
{% endstep %}

{% step %}
Then go to your profile settings and click on edit profile
{% endstep %}

{% step %}
Change the username field input to an SSTI payload as shown below and save `{{7*7}}`
{% endstep %}

{% step %}
Then go from the profile path to the main site path and refresh the page once
{% endstep %}

{% step %}
If a command has been executed on our name and the number 49 appears, the target is vulnerable
{% endstep %}
{% endstepper %}

***

#### File Uploads

{% stepper %}
{% step %}
Check the API documentation or Burp Suite history for paths like `/admin/media/upload`, `/api/upload`, `/file/upload`, or `/api/attachment`
{% endstep %}

{% step %}
Make a normal POST multipart upload with a simple file (`test.txt`) and valid formats parameter (`formats="jpg;png"`)

```http
POST /admin/media/upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file_upload"; filename="test.txt"
Content-Type: text/plain

test
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="formats"

jpg;png
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```
{% endstep %}

{% step %}
Expected Response

```
File format not allowed (some-id)
```
{% endstep %}

{% step %}
Then modify the formats parameter to inject a test SSTI payload like `test<%= 7*7 %>test` and submit the upload

```http
POST /admin/media/upload?actions=false HTTP/1.1
Host: target.com
Referer: http://target.com/admin/profile/edit
Cookie: cookie

-----------------------------327175120238370517612522354688
Content-Disposition: form-data; name="file_upload"; filename="test.txt"
Content-Type: text/plain

test
-----------------------------327175120238370517612522354688
Content-Disposition: form-data; name="thumb_size"

-----------------------------327175120238370517612522354688
Content-Disposition: form-data; name="formats"

test<%= 7*7 %>test
-----------------------------327175120238370517612522354688
```
{% endstep %}

{% step %}
And Response

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Status: 200 OK
Set-Cookie: cookie
Content-Length: 41

File format not allowed (test49test)
```

If the response reflects the calculation (49), SSTI is confirmed.&#x20;
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
