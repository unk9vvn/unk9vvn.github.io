# Browser Storage

## Check List

## Methodology

### Black Box

#### Browser Storage Exposure

{% stepper %}
{% step %}
During initial analysis, open the target application and inspect browser storage. Use Developer Tools → Application / `Storage` → `LocalStorage` and `SessionStorage`
{% endstep %}

{% step %}
Look for key–value pairs that may store authentication details, API tokens, user profiles, or logs containing user activity
{% endstep %}

{% step %}
Expand JSON objects, arrays, or nested values to identify whether the application stores secrets such as usernames, passwords, session identifiers, or personal data inside `LocalStorage` or `SessionStorage`. Since browser storage is fully accessible to client-side JavaScript, any sensitive data stored there is at risk if an `XSS` vulnerability exists
{% endstep %}

{% step %}
Verify persistence across sessions: Log out, clear browser data, or use an incognito profile. Then log in again and re-check `LocalStorage`/`SessionStorage` to determine whether sensitive values are consistently stored upon authentication. Confirm that the behavior occurs for any authenticated user, not just a specific test account
{% endstep %}

{% step %}
Determine whether the stored data includes credentials or other sensitive fields. Consider how an attacker with JavaScript execution (via `XSS`) could potentially access and extract this information, as `LocalStorage` has no `HttpOnly` protection mechanism
{% endstep %}

{% step %}
Show that sensitive data saved in `LocalStorage` can be read by any script running on the same origin (via the browser console). Highlight that storing sensitive secrets in `LocalStorage` exposes users to credential compromise if a cross-site scripting vulnerability is ever introduced
{% endstep %}
{% endstepper %}

***

#### Discovering Authentication Token Stored in LocalStorage

{% stepper %}
{% step %}
Start by signing into the target application normally. You need an authenticated session so that any tokens created by the Frontend become visible in the browser storage panel
{% endstep %}

{% step %}
Open Developer Tools → Application → Local Storage. Then look at the stored keys (a large JSON object under a single key like User)
{% endstep %}

{% step %}
Copy the entire value of the `LocalStorage` entry and paste it into a text editor. Search for sensitive fields such as&#x20;

```http
- token
- auth_token
- accessToken
- bearer
- session
```
{% endstep %}

{% step %}
Copy the token value exactly as-is like

```http
1affabacb13d3f1041d913341a37c05112c7428
```

This token is readable by any script running in the page, meaning any XSS or malicious browser extension could steal it
{% endstep %}

{% step %}
Open Burp Suite and prepare a request: To confirm whether this token actually functions as an authentication credential, you should send a normal API request using Burp Suite. Target an authenticated endpoint, for example

```http
GET https://target.com/api/v1/me HTTP/1.1
```
{% endstep %}

{% step %}
Add the header

```http
Authorization: Bearer <token>
```
{% endstep %}

{% step %}
Replace \<token> with the value extracted from localStorage. The sample request might look like this:

```http
GET /prefs/v1/account/connected_accounts_info?success_page=%2Fapp%2Fsettings%2Faccount HTTP/2
Host: app.target.com
Sec-Ch-Ua: “Chromium”;v=”127", “Not)A;Brand”;v=”99"
Doist-Platform: web
Accept-Language: en-US
Sec-Ch-Ua-Mobile: ?0
Authorization: Bearer 1affabacb13d3f1041d913341a37c05112c7428
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Doist-Version: 9173
Doist-Screen: 1920x1032
Content-Type: application/json
Doist-Os: Windows
Doist-Locale: en
Sec-Ch-Ua-Platform: “Windows”
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://app.target.com/app/settings/account
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
```
{% endstep %}

{% step %}
Observe the response. The server might return valid user information, confirming
{% endstep %}
{% endstepper %}

***

#### Stored XSS via SVG Upload Leading to LocalStorage Token Theft

{% stepper %}
{% step %}
Begin by identifying an upload/import feature in the application. In this case, the target allowed importing document files such as `.csv` or `.docx,` When opening the file selection dialog, the OS might show the filter “All Supported Types”, restricting uploads to document formats
{% endstep %}

{% step %}
Change the file type filter to “All Files” and attempt to upload an unsupported file format. By switching the filter to All Files, it becomes possible to upload an `.svg` file containing an embedded XSS payload inside an XML `<script>` tag
{% endstep %}

{% step %}
Upload the malicious `.svg` file and intercept the request in Burp Suite. The first upload might succeed silently without revealing where the file was stored. On the second attempt, intercept the request and enable Proxy → Intercept → Response to this request. This reveals the server’s response containing the file’s upload path
{% endstep %}

{% step %}
Visit the discovered file path in the browser. Navigating to the uploaded `.svg` file may trigger execution of the JavaScript payload, confirming stored (persistent) XSS within the application
{% endstep %}

{% step %}
Analyze the application’s authentication flow. Upon login, the application might generate a unique authentication token. This token is stored inside LocalStorage, and is also used as a CSRF protection token. Since LocalStorage is readable via JavaScript, any stored XSS can access values saved there
{% endstep %}

{% step %}
Modify the SVG payload to extract the LocalStorage token. Add an additional line inside the tag to read the `<script>` LocalStorage item, for example

Replace `<item-name>` with the actual key used by the application (IsvSessionToken)
{% endstep %}

{% step %}
Re-upload the modified SVG and access the stored file again. When visiting the stored file path, the SVG executes JavaScript in the browser context of the domain. The payload successfully retrieves the token stored in LocalStorage and displays it

```javascript
alert(localStorage.getItem("IsvSessionToken"));
```
{% endstep %}

{% step %}
This confirms that the attacker can extract sensitive authentication data directly from LocalStorage through stored XSS, Payload Example like

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full"
     xmlns="http://www.w3.org/2000/svg">

<polygon id="triangle" points="0,0 0,50 50,0"
         fill="#009900" stroke="#004400"/>

<script type="text/javascript">
prompt('XSS-Attack');
prompt(document.domain);
prompt(document.cookie);
alert(localStorage.getItem("IsvSessionToken"));
</script>

</svg>
```
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
