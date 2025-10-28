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
Inject a quote mark (`unitWeight=10'`) into a parameter and submit the request, and check if you get any errors from the server side, such as 500 Internal Server Error
{% endstep %}

{% step %}
The next step is to check whether this error is returned by adding another single quote to the parameter (`unitWeight=10''`)
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

#### SQL Injection in Fullname Parameter

{% stepper %}
{% step %}
Navigate to the SignUp page of the target website, typically located at a URL like `/signup` or `/register` Open https://example.com/signup in the browser
{% endstep %}

{% step %}
Identify the “Full Name” input field in the SignUp form, which is prone to processing user input directly into database queries Find the text box labeled “Full Name” in the form
{% endstep %}

{% step %}
Enter the payload `' OR 1=1 --` into the Full Name field to attempt bypassing the query’s conditions and access unauthorized data Input `John' OR 1=1 --` in the Full Name field
{% endstep %}

{% step %}
Click the `“Sign Up”` button to send the payload to the server via a <sub>POST</sub> request
{% endstep %}

{% step %}
Look for a generic error (“Invalid input”) or a `400`/`500` status code, indicating the payload was blocked, or unexpected success, suggesting a vulnerability
{% endstep %}

{% step %}
If a 400/500 error appears, modify the payload to `' OR 1=2 --` and submit again. Compare responses: if `' OR 1=1 --` allows form submission or data access (account creation without valid input) while `' OR 1=2 --` fails, it confirms SQL injection, as the true condition (`1=1`) altered the query’s logic
{% endstep %}
{% endstepper %}

***

#### SQL injection in X-Forwarded-For Header

{% stepper %}
{% step %}
Log in to the target site and record requests using Burp Suite
{% endstep %}

{% step %}
Identify the X-Forwarded-For header in logged requests
{% endstep %}

{% step %}
Routes that set and use the X-Forwarded-For header on sites and usually store its values ​​in the database : `/login` `/signup` `/register` `/logout` `/user/profile` `/profile/update` `/checkout` `/purchase` `/cart/checkout` `/api/*` `/comments` `/comment/post` `/posts` `/posts/create` `/sessions` `/session`\
`/password/reset`
{% endstep %}

{% step %}
Send the request by going to these routes and then setting this header (or if it already exists) and then examine the server response like the following request

```http
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Connection: close
X-Forwarded-For: 127.0.0.1

username=alice&password=Password123
```
{% endstep %}

{% step %}
Now, using a simple payload like the one below, we will check this header to see if the server is giving us an unusual or strange response

```http
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Connection: close
X-Forwarded-For: 127.0.0.1' OR 1=1 --

username=alice&password=Password123
```
{% endstep %}

{% step %}
If an error occurs, test a false condition payload like ' OR 1=2 -- and compare

{% hint style="info" %}
`X-Forwarded-For: 127.0.0.1' OR 1=1 --` succeeds (200 OK), but `' OR 1=2 --` errors (500), proving injectable
{% endhint %}
{% endstep %}

{% step %}
If the attack was successful, we can extract the database version using the following payload

```
IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)
```
{% endstep %}
{% endstepper %}

***

#### Time-based blind SQL injection

{% stepper %}
{% step %}
Navigate to pages on the target website that display database-driven results, such as search pages, product listings, or user dashboards, often found at URLs like `/search`, `/results`, `/list`, `/products`, or `/dashboard`. These pages typically use query parameters for sorting or filtering
{% endstep %}

{% step %}
Look for query parameters controlling sorting or filtering, such as `sortBy`, order, sort, filter, or column, in the URL or form submissions, as these are often passed directly to SQL queries
{% endstep %}

{% step %}
Modify the identified parameter (`sortBy`) with a simple time-based payload like `1 AND SLEEP(5) --` to introduce a 5-second delay if the query executes
{% endstep %}

{% step %}
Use a browser or Burp Suite to send the modified request and measure the response time. A \~5-second delay confirms the payload executed in the database
{% endstep %}

{% step %}
Send a non-delaying request with the original parameter value (`sortBy=1`) or a neutral payload (`sortBy=1 AND 1=1 --`) to ensure no delay occurs, verifying the injection
{% endstep %}

{% step %}
Inject a payload like `1 AND IF(SUBSTRING(DB_NAME(),1,1)='A',SLEEP(5),0) --` to test if the database name starts with 'A', noting a delay for true conditions. Iterate through characters (`A-Z, 0-9`) to extract the name
{% endstep %}

{% step %}
Apply the same payload to similar parameters (order, filter) on other database-driven pages (`/products,` `/list`) to identify additional injection points
{% endstep %}
{% endstepper %}

***

#### Time-Based Blind SQL Injection Testing on Author-Like Parameters

{% stepper %}
{% step %}
Navigate to website pages that handle search or data filtering, such as , /publications, /archive, where user inputs are processed for database queries.
{% endstep %}

{% step %}

{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
