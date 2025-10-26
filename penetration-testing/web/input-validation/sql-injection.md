# SQL Injection

## Check List

## Methodology

### Black Box

#### SQL Injection

{% stepper %}
{% step %}
Log in to the site and look for mechanisms such as calculators or mechanisms that allow you to enter image sizes, etc., or data
{% endstep %}

{% step %}
Trace the request using Burp Suite and check whether values ​​are sent to the server with the POST method and JSON data by changing the numbers and sizes
{% endstep %}

{% step %}
Inject a quote mark (unitWeight=10') into a parameter and submit the request, and check if you get any errors from the server side, such as 500 Internal Server Error
{% endstep %}

{% step %}
The next step is to check whether this error is returned by adding another single quote to the parameter (unitWeight=10'')
{% endstep %}

{% step %}
Then use timebase payload injection for SQL like `'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z` to check if the server is responding to you with a delay
{% endstep %}

{% step %}
If the server responds to you with a delay of 10 seconds, it means the server is vulnerable
{% endstep %}

{% step %}
Inspect cookies by modifying their values with SQL payloads (`cookie=value' OR 1=1`), checking if the server responds differently or exposes sensitive data
{% endstep %}

{% step %}
Analyze HTTP headers (`User-Agent` or `Referer`) by injecting SQL payloads, monitoring for errors or delays that suggest header data is used in database queries
{% endstep %}

{% step %}
Examine POST request bodies, particularly form submissions, by injecting SQL payloads into fields like username or weight, checking for errors or delayed responses
{% endstep %}

{% step %}
Use a proxy tool’s repeater function to systematically test each parameter with SQL payloads, comparing responses to identify injectable points
{% endstep %}
{% endstepper %}

***

#### SQL Injection On Cookie Parameter

{% stepper %}
{% step %}
Intercept browser traffic with a proxy Burp Suite
{% endstep %}

{% step %}
Load the target page so the relevant GET/POST request appears in the proxy
{% endstep %}

{% step %}
Send the request to Repeater (or an editor)
{% endstep %}

{% step %}
Locate the `Cookie:` header and identify parameters ( `lang=...`)
{% endstep %}

{% step %}
Modify the suspicious cookie value to a single quote `'` and send the request
{% endstep %}

{% step %}
Check the server response for SQL errors or 500/DB-syntax messages
{% endstep %}

{% step %}
To confirm, change the value to a second quote (`''`) or otherwise balance the quote and resend; if the error disappears, this further indicates SQLi
{% endstep %}

{% step %}
(Optional verification) Inject a time-based payload compatible with the backend (`IF(1=1,SLEEP(5),0)`) into the cookie and measure response delay
{% endstep %}

{% step %}
If the server responds to you with 5 seconds of delay, it means it is vulnerable
{% endstep %}
{% endstepper %}

***

#### Time-Based SQL Injection

{% stepper %}
{% step %}
Identify input fields or parameters in the target application, such as URL query strings (`id=`) or form inputs, that may interact with a database, focusing on features like search, deletion, or data retrieval endpoints
{% endstep %}

{% step %}
Intercept HTTP requests using a proxy tool (Burp Suite) to capture parameters like id or username, analyzing how they are sent to the server for database queries
{% endstep %}

{% step %}
Test for SQL injection by injecting a single quote (`id=187'`) into the parameter and sending the request, observing for server errors (500 Internal Server Error) that indicate unhandled SQL syntax
{% endstep %}

{% step %}
Confirm the absence of verbose error messages in the response, noting generic error pages or no data leakage, suggesting a potential blind SQL injection vulnerability
{% endstep %}

{% step %}
Inject a time-based payload (`id=187 AND SLEEP(5)`) to test for a delay in the server response, confirming time-based SQL injection if the response is delayed by the specified time (5 seconds)
{% endstep %}

{% step %}
Verify the delay by sending a non-sleeping payload `(id=187 AND 1=1`) and comparing response times to ensure the delay is due to the SLEEP command execution
{% endstep %}

{% step %}
Test for boolean-based conditions using payloads like `id=187 AND IF(1=1,SLEEP(5),0)`, checking for a delay when the condition is true and no delay when false (`1=2`)
{% endstep %}

{% step %}
Extract database metadata by injecting payloads like `id=187 AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0)` to determine the database version character by character, noting delays for true conditions
{% endstep %}

{% step %}
Determine the database name length using payloads like `id=187 AND IF(LENGTH(database())=10,SLEEP(5),0)`, incrementing the length value until a delay confirms the correct length
{% endstep %}

{% step %}
Extract the database name by iterating through each character position with payloads like `id=187 AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)`, testing all possible characters (a-z, 0-9) and noting delays for correct matches
{% endstep %}

{% step %}
Move to the next character position (`SUBSTRING(database(),2,1)='a'`) after identifying the first character, repeating the process until the full database name is extracted
{% endstep %}

{% step %}
Test for additional metadata, such as table names or column names, using payloads like `id=187 AND IF(EXISTS(SELECT table_name FROM information_schema.tables WHERE table_name='users'),SLEEP(5),0)`to confirm the presence of specific tables
{% endstep %}
{% endstepper %}

***

#### SQL Injection in Referrer Header&#x20;

{% stepper %}
{% step %}
Referer is another HTTP header which can be vulnerable to SQL injection once the application is storing it in database without sanitizing it. It's an optional header field that allows the client to specify
{% endstep %}

{% step %}
Go to the homepage and trace the request using Burp Suite
{% endstep %}

{% step %}
Then send the request to the Repeater and check the Referrer header using the following payload

```
GET /index.php HTTP/1.1
Host: [host]
User-Agent: 
Referer: http://www.yaboukir.com' or 1/*
```
{% endstep %}

{% step %}
Then check if the server shows any strange behavior after injecting the payload into this header
{% endstep %}
{% endstepper %}

***

#### SQL injection In Refresh Token Parameter

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

```json
POST /api/v1/token HTTP/1.1
Host: tsftp.informatica.com
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

### White Box

## Cheat Sheet
