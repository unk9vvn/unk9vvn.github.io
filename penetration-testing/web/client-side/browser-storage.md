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
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
