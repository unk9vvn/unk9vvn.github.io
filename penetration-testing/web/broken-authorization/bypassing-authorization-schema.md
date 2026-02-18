# Bypassing Authorization Schema

## Check List

## Methodology

### Black Box

#### Broken Authorization

{% stepper %}
{% step %}
Authenticate to the application using a standard (non-administrative) user account
{% endstep %}

{% step %}
Identify administrative functions by: Browsing the application as an admin user (if available), or Enumerating common administrative paths such as

```hurl
https://www.example.com/admin/addUser.jsp
```
{% endstep %}

{% step %}
Capture a legitimate administrative request, for example

```http
POST /admin/addUser.jsp HTTP/1.1
Host: www.example.com

userID=fakeuser&role=3&group=grp001
```
{% endstep %}

{% step %}
Log out from the administrator account
{% endstep %}

{% step %}
Log in as a non-administrative (standard privilege) user
{% endstep %}

{% step %}
Replay the captured administrative request using the standard user’s session
{% endstep %}

{% step %}
Observe whether the server processes the request successfully (creates a new user)
{% endstep %}

{% step %}
If the request succeeds, verify whether the newly created user account is active and functional
{% endstep %}
{% endstepper %}

***

#### Horizontal Bypassing Authorization

{% stepper %}
{% step %}
Register two separate user accounts with identical roles and privileges (`userA` and `userB`)
{% endstep %}

{% step %}
Log in as both users in separate browsers or sessions
{% endstep %}

{% step %}
Capture the session identifiers (`SessionID`) for both users
{% endstep %}

{% step %}
Identify a function accessible to both users, such as

```http
POST /account/viewSettings HTTP/1.1
Host: www.example.com
Cookie: SessionID=USERA_SESSION

username=userA
```
{% endstep %}

{% step %}
Confirm that the legitimate response for `userA` returns only `userA`’s personal data
{% endstep %}

{% step %}
While logged in as `userB`, intercept a similar request and modify (The `username` parameter to `userA` and Keep `SessionID=USERB_SESSION`
{% endstep %}

{% step %}
Send the modified request

```http
POST /account/viewSettings HTTP/1.1
Host: www.example.com
Cookie: SessionID=USERB_SESSION

username=userA
```
{% endstep %}

{% step %}
Observe the server response
{% endstep %}

{% step %}
If the response contains `userA`’s private data while authenticated as `userB`, confirm unauthorized horizontal access
{% endstep %}
{% endstepper %}

***

#### Broken Authorization via Header Handling

{% stepper %}
{% step %}
Identify a restricted endpoint that is blocked by frontend access control (`/admin` or `/console`)
{% endstep %}

{% step %}
Attempt to access the restricted endpoint directly

```http
GET /admin HTTP/1.1
Host: www.example.com
```

If the server gives you a 403 or says "Access Unauthorized" in response
{% endstep %}

{% step %}
Send a normal baseline request without special headers

```http
GET / HTTP/1.1
Host: www.example.c
```

Record the response for comparison.
{% endstep %}

{% step %}
Send a request including the `X-Original-URL` header pointing to a non-existent resource

```http
GET / HTTP/1.1
Host: www.example.com
X-Original-URL: /donotexist1
```

Observe the response
{% endstep %}

{% step %}
Check whether the response returns indicators such as HTTP 404 status code or “Resource not found” message

If so, confirm support for the `X-Original-URL` header
{% endstep %}

{% step %}
Send a request including the `X-Rewrite-URL` header pointing to a non-existent resource

```http
GET / HTTP/1.1
Host: www.example.com
X-Rewrite-URL: /donotexist2
```

Observe the response
{% endstep %}

{% step %}
If the response indicates the non-existent resource was processed, confirm support for the `X-Rewrite-URL` header
{% endstep %}

{% step %}
After confirming header support, attempt access control bypass by sending a request to an allowed endpoint ( `/`) while specifying the restricted endpoint in the supported header

```http
GET / HTTP/1.1
Host: www.example.com
X-Original-URL: /admin
```

or

```http
GET / HTTP/1.1
Host: www.example.com
X-Rewrite-URL: /admin
```
{% endstep %}

{% step %}
Observe whether the application processes the restricted resource and returns its content
{% endstep %}

{% step %}
Confirm the vulnerability if the restricted endpoint becomes accessible through header manipulation despite direct access being blocked
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
