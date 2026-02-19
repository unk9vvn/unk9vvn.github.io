# HTTP Verb Tampering

## Check List

## Methodology

### Black Box

#### HTTP Tampering Bypassing Access Denied

{% stepper %}
{% step %}
Navigate to the target application in a browser.
{% endstep %}

{% step %}
Identify a functionality that is restricted to authenticated users (e.g., user deletion, admin actions).
{% endstep %}

{% step %}
Log out or ensure you are **not authenticated**.
{% endstep %}

{% step %}
Intercept a legitimate restricted request (e.g., a POST or DELETE request) using a proxy tool such as Burp Suite.
{% endstep %}

{% step %}
Observe that the original request uses a restricted HTTP method, for example

```http
POST /admin/deleteUser HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the original request without authentication and confirm that access is denied
{% endstep %}

{% step %}
Modify the HTTP method to an alternative method such as GET or PUT

```http
GET /admin/deleteUser HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the modified request using Burp Suite Repeater
{% endstep %}

{% step %}
Observe the server response
{% endstep %}

{% step %}
If the server processes the request successfully and performs the restricted action without authentication, confirm that authentication bypass is achieved via HTTP method manipulation
{% endstep %}
{% endstepper %}

***

#### Admin Emails & Passwords Exposed via HTTP Method Change

{% stepper %}
{% step %}
Navigate to the target application
{% endstep %}

{% step %}
Access the **Email** section of the platform
{% endstep %}

{% step %}
Interact with the **Reply** feature to trigger a request
{% endstep %}

{% step %}
Intercept the outgoing request using a proxy tool (Burp Suite)
{% endstep %}

{% step %}
Observe that the request is sent to an API endpoint using the **POST** method

```http
POST /index.php/api/rest/latest/windows HTTP/1.1
```
{% endstep %}

{% step %}
Send the intercepted POST request to Burp Repeater
{% endstep %}

{% step %}
Replay the original POST request
{% endstep %}

{% step %}
Confirm that the server responds and returns a JSON response similar to

```http
HTTP/1.1 201 Created
Host: example.com
Cookie: ...
.. ..

{"id":1}
```
{% endstep %}

{% step %}
Modify the HTTP method of the same request from `POST` to `GET`
{% endstep %}

{% step %}
Send the modified GET request to the same endpoint
{% endstep %}

{% step %}
Observe the server response and Confirm that the server returns a full list of registered users ,Verify that the response contains sensitive data such as ( User IDs, Email addresses, Password hashes (or plaintext passwords)
{% endstep %}

{% step %}
Confirm that this data is accessible without proper authorization checks
{% endstep %}
{% endstepper %}

***

#### Improper PATCH Method Handling for Unauthorized User Data Modification

{% stepper %}
{% step %}
Navigate to the target application and authenticate as a **regular user** (non-admin)
{% endstep %}

{% step %}
Identify user-related API endpoints by (Reviewing JavaScript files or Inspecting network traffic in the browser Developer Tools, Enumerating hidden or undocumented paths)
{% endstep %}

{% step %}
Locate an endpoint responsible for updating user data (profile update)
{% endstep %}

{% step %}
Attempt to access or modify another user’s data using common HTTP methods such as

```http
PUT /api/users/{user_id}
POST /api/users/{user_id}
```

Confirm that the server responds with

```http
403 Forbidden
```
{% endstep %}

{% step %}
Modify the HTTP method to **PATCH**

```http
PATCH /api/users/{user_id}
```
{% endstep %}

{% step %}
Keep the same authenticated session of the regular user
{% endstep %}

{% step %}
Craft a JSON request body containing modified user data, for example

```http
{
  "email": "attacker@evil.com"
}
```
{% endstep %}

{% step %}
Send the PATCH request using a proxy tool (e.g., Burp Suite Repeater)
{% endstep %}

{% step %}
Observe the server response and Confirm that the server responds with a success status (200 OK) instead of 403 Forbidden
{% endstep %}

{% step %}
Verify that the targeted user’s data has been modified successfully
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
