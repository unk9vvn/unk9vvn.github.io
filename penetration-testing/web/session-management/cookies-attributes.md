# Cookies Attributes

## Check List

## Methodology

### Black Box

#### Insecure Cookie Exposure

{% stepper %}
{% step %}
Log in as a normal user
{% endstep %}

{% step %}
Open DevTools then go to Console
{% endstep %}

{% step %}
Type `document.cookie`
{% endstep %}

{% step %}
Look for any authentication-related cookies ( `accessToken`, `session`, `refreshToken`)
{% endstep %}

{% step %}
Open DevTools, Application, Storage, Cookies to check attributes like

* `HttpOnly`
* `Secure`
* Expiration date
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Cookie Tossing State Desynchronization in Custom Gateway Parsers

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
Identify the enterprise's central API Gateway or edge routing layer. In high-throughput environments, developers often replace standard, heavy web-framework middleware with custom, optimized string-parsing routines to evaluate HTTP headers (including the `Cookie` header) with minimal allocation overhead
{% endstep %}

{% step %}
Investigate how this custom cookie parser handles duplicate cookie names. When a browser sends multiple cookies with the exact same name (e.g., `Cookie: session=attacker_token; session=legit_token`), it does so because the cookies have different `Domain` or `Path` attributes, which the browser does not transmit in the request
{% endstep %}

{% step %}
According to RFC 6265, browsers sort cookies by path length (most specific first). Discover if the Gateway's custom parser uses a "first-match-wins" logic (e.g., adding to a Hash Map and ignoring subsequent duplicates) or a "last-match-wins" logic (e.g., overwriting existing keys).
{% endstep %}

{% step %}
Assume the enterprise relies on a wildcard cookie (`Domain=.enterprise.tld; Path=/`) issued by the central Identity Provider to maintain single sign-on across all subdomains.
{% endstep %}

{% step %}
Discover a forgotten, low-security subdomain (e.g., `sandbox.enterprise.tld`) that allows you to set arbitrary cookies (either through an intended feature or a simple Cross-Site Scripting vulnerability)
{% endstep %}

{% step %}
From this subdomain, set a "Shadow Cookie" with the exact same name as the SSO cookie, but scoped to the highly specific path of the target microservice (e.g., `Domain=.enterprise.tld; Path=/api/v2/admin/`)
{% endstep %}

{% step %}
Trigger a request to the target microservice. Your browser will send both cookies. Because your attacker cookie has a more specific path, the browser places it _first_ in the `Cookie` header string
{% endstep %}

{% step %}
If the API Gateway's optimized parser uses "first-match-wins" logic, it extracts your shadowed session token, ignoring the legitimate, highly-privileged session token that follows it
{% endstep %}

{% step %}
If the backend microservice uses the exact same parsing flaw, you can force the victim to execute actions within your attacker-controlled session (Session Fixation/Tainting). However, if the API Gateway and the downstream microservice use _different_ parsing libraries (one reads first, one reads last), you achieve complete State Desynchronization
{% endstep %}

{% step %}
In a Desynchronization scenario, the Gateway might authorize the request based on the victim's legitimate token (reading the last cookie), but the downstream microservice binds the resulting action to the attacker's token (reading the first cookie), leaking sensitive victim data into the attacker's account

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ParseCookies\b[\s\S]{0,300}?\.Split\s*\(\s*['"];\s*['"]\s*\)|Cookies\.TryAdd\s*\(|CookieCollection\.Add\s*\(|Request\.Cookies\s*\[\s*.*?\s*\]\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:parseCookies\b[\s\S]{0,300}?\.split\s*\(\s*['"];\s*['"]\s*\)|putIfAbsent\s*\([^)]*cookie|cookies\.putIfAbsent\s*\(|CookieStore\b|HttpCookie\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:parseCookies\b[\s\S]{0,300}?explode\s*\(\s*['"];\s*['"]\s*,|!array_key_exists\s*\([^)]*cookie|array_key_exists\s*\([^)]*cookie|setcookie\s*\(|\$_COOKIE\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:parseCookies\b[\s\S]{0,300}?\.split\s*\(\s*['"];\s*['"]\s*\)|cookies\.set\s*\(|cookies\.get\s*\(|cookieParser\b|req\.cookies\b|res\.cookie\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ParseCookies.*\.Split\s*\(\s*['"];\s*['"]\s*\)|Cookies\.TryAdd\s*\(|CookieCollection\.Add\s*\(|Request\.Cookies\s*\[)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:parseCookies.*\.split\s*\(\s*['"];\s*['"]\s*\)|putIfAbsent\s*\([^)]*cookie|cookies\.putIfAbsent\s*\(|CookieStore\b|HttpCookie\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:parseCookies.*explode\s*\(\s*['"];\s*['"]\s*,|!array_key_exists\s*\([^)]*cookie|array_key_exists\s*\([^)]*cookie|setcookie\s*\(|\$_COOKIE\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:parseCookies.*\.split\s*\(\s*['"];\s*['"]\s*\)|cookies\.set\s*\(|cookies\.get\s*\(|cookieParser\b|req\.cookies\b|res\.cookie\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class FastCookieParserMiddleware 
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var cookieHeader = context.Request.Headers["Cookie"].ToString();
        var parsedCookies = new Dictionary<string, string>();

        if (!string.IsNullOrEmpty(cookieHeader)) 
        {
            // [1]
            var cookiePairs = cookieHeader.Split(';');
            foreach (var pair in cookiePairs) 
            {
                var parts = pair.Trim().Split('=');
                if (parts.Length == 2) 
                {
                    // [2]
                    // [3]
                    parsedCookies.TryAdd(parts[0], parts[1]); 
                }
            }
        }

        // [4]
        context.Items["VerifiedSession"] = parsedCookies;
        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class FastCookieParserFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest req = (HttpServletRequest) request;
        String cookieHeader = req.getHeader("Cookie");
        Map<String, String> parsedCookies = new HashMap<>();

        if (cookieHeader != null && !cookieHeader.isEmpty()) {
            // [1]
            String[] cookiePairs = cookieHeader.split(";");
            for (String pair : cookiePairs) {
                String[] parts = pair.trim().split("=");
                if (parts.length == 2) {
                    // [2]
                    // [3]
                    parsedCookies.putIfAbsent(parts[0], parts[1]);
                }
            }
        }

        // [4]
        req.setAttribute("VerifiedSession", parsedCookies);
        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class FastCookieParserMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $cookieHeader = $request->header('Cookie');
        $parsedCookies = [];

        if (!empty($cookieHeader)) 
        {
            // [1]
            $cookiePairs = explode(';', $cookieHeader);
            foreach ($cookiePairs as $pair) 
            {
                $parts = explode('=', trim($pair));
                if (count($parts) === 2) 
                {
                    // [2]
                    // [3]
                    if (!array_key_exists($parts[0], $parsedCookies)) {
                        $parsedCookies[$parts[0]] = $parts[1];
                    }
                }
            }
        }

        // [4]
        $request->attributes->set('VerifiedSession', $parsedCookies);
        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class FastCookieParser {
    static middleware(req, res, next) {
        let cookieHeader = req.headers['cookie'];
        let parsedCookies = {};

        if (cookieHeader) {
            // [1]
            let cookiePairs = cookieHeader.split(';');
            for (let pair of cookiePairs) {
                let parts = pair.trim().split('=');
                if (parts.length === 2) {
                    // [2]
                    let key = parts[0];
                    let value = parts[1];
                    
                    // [3]
                    if (!(key in parsedCookies)) {
                        parsedCookies[key] = value;
                    }
                }
            }
        }

        // [4]
        req.verifiedSession = parsedCookies;
        next();
    }
}
```


{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To maximize throughput, the Gateway abandons the framework's native cookie parser and implements a fast string-splitting routine, \[2] The parser processes the cookies sequentially from left to right exactly as the browser transmitted them , \[3] The fatal architectural assumption. By using `TryAdd`, `putIfAbsent`, or equivalent logic, the developer ensures that the _first_ cookie encountered is the one retained in the dictionary. Because RFC 6265 mandates that browsers send cookies with longer paths first, an attacker can effortlessly force their shadowed cookie to the front of the string, guaranteeing it overwrites the victim's legitimate session state in memory, \[4] The poisoned dictionary is passed downstream, causing the entire backend infrastructure to operate on the attacker's injected session state

```http
// 1. Inject the Shadow Cookie via XSS on sandbox.enterprise.tld
document.cookie = "auth_session=ATTACKER_TOKEN; Domain=.enterprise.tld; Path=/api/v1/billing; Secure";

// 2. The victim navigates to the billing portal. The browser sends both cookies.
// The attacker's cookie is sent FIRST due to the highly specific Path.
GET /api/v1/billing/add-credit-card HTTP/1.1
Host: api.enterprise.tld
Cookie: auth_session=ATTACKER_TOKEN; auth_session=LEGITIMATE_VICTIM_TOKEN
```
{% endstep %}

{% step %}
The browser transmits both cookies. The `auth_session=ATTACKER_TOKEN` appears first because its `Path=/api/v1/billing` is longer and more specific than the legitimate cookie's `Path=/`. The API Gateway's custom parser splits the string, extracts the attacker's token, and locks it into the dictionary (ignoring the victim's token that follows it). The downstream service binds the victim's newly added credit card to the attacker's account, resulting in critical data leakage via Session Fixation, entirely orchestrated through Cookie Attribute path sorting
{% endstep %}
{% endstepper %}

***

#### Origin Spoofing via Dynamic SameSite Downgrade in BFF Architectures

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
Analyze the Backend-For-Frontend (BFF) architecture. Modern Single Page Applications (SPAs) rely on BFFs to issue strictly scoped cookies (e.g., `SameSite=Strict` or `Lax`) to defend against Cross-Site Request Forgery (CSRF)
{% endstep %}

{% step %}
Identify the engineering optimization: Enterprise systems rarely operate in total isolation. They must support seamless "Deep Linking" or SSO redirects from external partner networks (e.g., a CRM partner redirecting to the enterprise dashboard via a POST request)
{% endstep %}

{% step %}
Because `SameSite=Strict/Lax` drops cookies on cross-origin POST requests, the integration breaks. To solve this, developers implement a "Dynamic SameSite Downgrade" pipeline. If the BFF detects that the request originates from a trusted partner, it dynamically downgrades the session cookie to `SameSite=None` during the authentication phase or via a specific handshake endpoint
{% endstep %}

{% step %}
Locate the middleware responsible for this downgrade. Check how it verifies the "Trusted Partner". Developers frequently rely on the `Origin` or `Referer` HTTP headers, assuming these headers cannot be forged by standard web clients
{% endstep %}

{% step %}
Evaluate the validation logic applied to the `Origin` header. Look for loose regex matching, `endsWith()` string operations, or parsing flaws that fail to strictly validate the fully qualified domain name
{% endstep %}

{% step %}
Register an attacker-controlled domain that satisfies the flawed validation logic (e.g., if the logic checks `origin.endsWith("trusted-partner.com")`, register `attacker-trusted-partner.com`)
{% endstep %}

{% step %}
Host a malicious page on your registered domain that silently frames the target enterprise application or initiates a cross-origin request to the downgrade endpoint
{% endstep %}

{% step %}
The BFF receives the request, parses your spoofed `Origin` header, incorrectly validates it as a trusted partner, and issues a `Set-Cookie` header rewriting the victim's session cookie to `SameSite=None`
{% endstep %}

{% step %}
With the victim's cookie now downgraded, execute standard CSRF attacks against state-changing API endpoints, completely bypassing the original `SameSite` architectural defense

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Origin\b[\s\S]{0,300}?\.EndsWith\s*\(|Regex\b[\s\S]{0,150}?trusted-partner\.com|cookieOptions\.SameSite\s*=\s*SameSiteMode\.None|cookieOptions\.SameSite\s*=\s*"None"|SameSiteMode\.None\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:origin\b[\s\S]{0,300}?\.endsWith\s*\(|Pattern\b[\s\S]{0,150}?trusted-partner\.com|responseCookie\.sameSite\s*=\s*"None"|SameSite\s*=\s*"None"|CookieSameSite\.NONE\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Origin\b[\s\S]{0,300}?substr\s*\(|preg_match\s*\([^)]*trusted-partner\.com|['"]samesite['"]\s*=>\s*['"]None['"]|SameSite\s*=>\s*['"]None['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:origin\b[\s\S]{0,300}?\.endsWith\s*\(|new\s+RegExp\b[\s\S]{0,150}?trusted-partner\.com|/trusted-partner\\\.com/|sameSite\s*:\s*['"]none['"]|sameSite\s*=\s*['"]none['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Origin.*\.EndsWith\s*\(|Regex.*trusted-partner\.com|cookieOptions\.SameSite\s*=\s*SameSiteMode\.None|cookieOptions\.SameSite\s*=\s*"None"|SameSiteMode\.None\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:origin.*\.endsWith\s*\(|Pattern.*trusted-partner\.com|responseCookie\.sameSite\s*=\s*"None"|SameSite\s*=\s*"None"|CookieSameSite\.NONE\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Origin.*substr\s*\(|preg_match\s*\([^)]*trusted-partner\.com|['"]samesite['"]\s*=>\s*['"]None['"]|SameSite\s*=>\s*['"]None['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:origin.*\.endsWith\s*\(|RegExp.*trusted-partner\.com|/trusted-partner\\\.com/|sameSite\s*:\s*['"]none['"]|sameSite\s*=\s*['"]none['"])
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SameSiteDowngradeMiddleware 
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var origin = context.Request.Headers["Origin"].ToString();

        // [1]
        // [2]
        if (!string.IsNullOrEmpty(origin) && origin.EndsWith("trusted-partner.com")) 
        {
            // [3]
            var sessionCookie = context.Request.Cookies["AuthSession"];
            if (sessionCookie != null) 
            {
                // [4]
                context.Response.Cookies.Append("AuthSession", sessionCookie, new CookieOptions 
                {
                    SameSite = SameSiteMode.None,
                    Secure = true,
                    HttpOnly = true
                });
            }
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class SameSiteDowngradeFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        
        String origin = req.getHeader("Origin");

        // [1]
        // [2]
        if (origin != null && origin.endsWith("trusted-partner.com")) {
            // [3]
            Cookie[] cookies = req.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("AuthSession".equals(cookie.getName())) {
                        // [4]
                        String cookieHeader = String.format("%s=%s; Secure; HttpOnly; SameSite=None", cookie.getName(), cookie.getValue());
                        res.addHeader("Set-Cookie", cookieHeader);
                    }
                }
            }
        }

        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SameSiteDowngradeMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $origin = $request->header('Origin');

        // [1]
        // [2]
        if (!empty($origin) && str_ends_with($origin, "trusted-partner.com")) 
        {
            // [3]
            $sessionCookie = $request->cookie('AuthSession');
            if ($sessionCookie) 
            {
                // [4]
                cookie()->queue('AuthSession', $sessionCookie, 120, '/', null, true, true, false, 'None');
            }
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SameSiteDowngrade {
    static middleware(req, res, next) {
        let origin = req.headers['origin'];

        // [1]
        // [2]
        if (origin && origin.endsWith("trusted-partner.com")) {
            // [3]
            let sessionCookie = req.cookies['AuthSession'];
            if (sessionCookie) {
                // [4]
                res.cookie('AuthSession', sessionCookie, {
                    sameSite: 'none',
                    secure: true,
                    httpOnly: true
                });
            }
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture attempts to verify the caller's origin to allow federated Deep Linking from authorized partner networks, \[2] The `endsWith` string operation is fundamentally flawed. It fails to verify the scheme, port, or exact structural boundaries of the Fully Qualified Domain Name (FQDN), \[3] The gateway detects the active session cookie transmitted by the browser, \[4] Believing the request originated from a trusted source, the gateway dynamically overrides the cookie attributes, explicitly rewriting the `SameSite` directive to `None`. This intended optimization permanently removes the browser-level CSRF protection for the remainder of the session, exposing the user to cross-site attacks from the attacker's spoofed domain

```http
// 1. Attacker registers "attacker-trusted-partner.com" and hosts a malicious HTML page.
// 2. The victim visits the attacker's page. The page makes a hidden fetch request to downgrade the cookie.
OPTIONS /api/system/ping HTTP/1.1
Host: api.enterprise.tld
Origin: https://attacker-trusted-partner.com
Cookie: AuthSession=SECURE_STRICT_TOKEN

// The Server responds with the downgraded cookie:
HTTP/1.1 200 OK
Set-Cookie: AuthSession=SECURE_STRICT_TOKEN; Secure; HttpOnly; SameSite=None
```

```http
// 3. The attacker's page immediately executes a cross-origin POST request (CSRF) to a sensitive endpoint.
POST /api/settings/transfer-ownership HTTP/1.1
Host: api.enterprise.tld
Origin: https://attacker-trusted-partner.com
Cookie: AuthSession=SECURE_STRICT_TOKEN
```
{% endstep %}

{% step %}
The BFF architecture's dynamic SameSite optimization intercepts the attacker's initial cross-origin request. Because `[https://attacker-trusted-partner.com](https://attacker-trusted-partner.com)` successfully passes the `.endsWith("trusted-partner.com")` validation, the server assumes the request is a legitimate B2B integration flow. It rewrites the victim's cookie to `SameSite=None` and sends the `Set-Cookie` header back to the browser. The browser updates the cookie attributes in its local jar. Immediately after, the attacker's payload fires the actual malicious CSRF payload. Because the cookie is now `SameSite=None`, the browser dutifully attaches it to the cross-origin POST request, bypassing the enterprise's primary defense mechanism
{% endstep %}
{% endstepper %}

***

#### Security Boundary Bypass via Cookie Prefix Normalization Collision

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
Identify if the enterprise utilizes Zero-Trust Identity Proxies (e.g., Google Identity-Aware Proxy) or highly secure session configurations that enforce Cookie Prefixes (specifically `__Host-`)
{% endstep %}

{% step %}
Understand the architectural intent: By enforcing the `__Host-` prefix on the session cookie (e.g., `__Host-Session`), the backend guarantees that the browser enforces strict rules: The cookie _must_ be `Secure`, it _must_ have `Path=/`, and crucially, it _must not_ contain a `Domain` attribute. This guarantees the cookie was set by the exact host, preventing compromised subdomains from tossing forged cookies upward to the parent domain
{% endstep %}

{% step %}
Understand the architectural intent: By enforcing the `__Host-` prefix on the session cookie (e.g., `__Host-Session`), the backend guarantees that the browser enforces strict rules: The cookie _must_ be `Secure`, it _must_ have `Path=/`, and crucially, it _must not_ contain a `Domain` attribute. This guarantees the cookie was set by the exact host, preventing compromised subdomains from tossing forged cookies upward to the parent domain
{% endstep %}

{% step %}
Discover the "Cookie Name Sanitization" optimization. Generic web frameworks or logging middleware often normalize HTTP header keys and cookie names to ensure they can be safely mapped to environment variables, JSON objects, or database columns without breaking syntax
{% endstep %}

{% step %}
Look for normalization logic that URL-decodes the cookie keys or replaces non-alphanumeric characters (like spaces, dots, or symbols) with an underscore (`_`) or a hyphen (`-`)
{% endstep %}

{% step %}
Realize that the browser's prefix protection is strictly literal. The browser only applies the strict `__Host-` rules if the cookie name begins with exactly `__Host-` (H-o-s-t-hyphen)
{% endstep %}

{% step %}
Exploit the normalization mismatch. Assume you have compromised a low-security subdomain (`blog.enterprise.tld`). You cannot set a cookie named `__Host-Session` with `Domain=.enterprise.tld` because the browser will reject it
{% endstep %}

{% step %}
Instead, set a cookie named `__Host%2DSession` (URL-encoded hyphen) or `__Host.Session` on the `.enterprise.tld` domain. Because this string does _not_ literally match `__Host-`, the browser allows you to set the `Domain` attribute and gladly transmits it to the highly secure API Gateway
{% endstep %}

{% step %}
The Gateway receives the raw cookie. Its sanitization/normalization middleware processes the key, URL-decodes it (or replaces the dot with a hyphen), transforming the key into the exact string `__Host-Session`
{% endstep %}

{% step %}
The application logic queries its dictionary for `__Host-Session`, retrieves your forged cookie, and authenticates the request, completely bypassing the browser's hardware-level security guarantees

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Cookie\b[\s\S]{0,300}?\.Replace\s*\(\s*[^,]+,\s*"-"\s*\)|HttpUtility\.UrlDecode\s*\(\s*\w+\s*\)|WebUtility\.UrlDecode\s*\(\s*\w+\s*\)|Uri\.UnescapeDataString\s*\(\s*\w+\s*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Cookie\b[\s\S]{0,300}?\.replace\s*\(\s*[^,]+,\s*"-"\s*\)|URLDecoder\.decode\s*\(\s*\w+\s*,|URLDecoder\.decode\s*\(\s*\w+\s*\)|UriUtils\.decode\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Cookie\b[\s\S]{0,300}?str_replace\s*\(\s*[^,]+,\s*['"]-['"]|urldecode\s*\(\s*\$\w+\s*\)|rawurldecode\s*\(\s*\$\w+\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Cookie\b[\s\S]{0,300}?\.replace\s*\(\s*[^,]+,\s*['"]-['"]\s*\)|decodeURIComponent\s*\(\s*\w+\s*\)|decodeURI\s*\(\s*\w+\s*\)|new\s+URLSearchParams\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Cookie.*\.Replace\s*\(\s*[^,]+,\s*"-"\s*\)|HttpUtility\.UrlDecode\s*\(\s*\w+\s*\)|WebUtility\.UrlDecode\s*\(\s*\w+\s*\)|Uri\.UnescapeDataString\s*\(\s*\w+\s*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Cookie.*\.replace\s*\(\s*[^,]+,\s*"-"\s*\)|URLDecoder\.decode\s*\(\s*\w+\s*,|URLDecoder\.decode\s*\(\s*\w+\s*\)|UriUtils\.decode\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Cookie.*str_replace\s*\(\s*[^,]+,\s*['"]-['"]|urldecode\s*\(\s*\$\w+\s*\)|rawurldecode\s*\(\s*\$\w+\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Cookie.*\.replace\s*\(\s*[^,]+,\s*['"]-['"]\s*\)|decodeURIComponent\s*\(\s*\w+\s*\)|decodeURI\s*\(\s*\w+\s*\)|new\s+URLSearchParams\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class CookieNormalizationMiddleware 
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var rawCookies = context.Request.Headers["Cookie"].ToString();
        var normalizedCookies = new Dictionary<string, string>();

        if (!string.IsNullOrEmpty(rawCookies)) 
        {
            var pairs = rawCookies.Split(';');
            foreach (var pair in pairs) 
            {
                var parts = pair.Trim().Split('=');
                if (parts.Length == 2) 
                {
                    // [1]
                    // [2]
                    // [3]
                    var normalizedKey = HttpUtility.UrlDecode(parts[0]);
                    normalizedCookies[normalizedKey] = parts[1];
                }
            }
        }

        // [4]
        context.Items["NormalizedCookies"] = normalizedCookies;
        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class CookieNormalizationFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest req = (HttpServletRequest) request;
        String rawCookies = req.getHeader("Cookie");
        Map<String, String> normalizedCookies = new HashMap<>();

        if (rawCookies != null && !rawCookies.isEmpty()) {
            String[] pairs = rawCookies.split(";");
            for (String pair : pairs) {
                String[] parts = pair.trim().split("=");
                if (parts.length == 2) {
                    try {
                        // [1]
                        // [2]
                        // [3]
                        String normalizedKey = URLDecoder.decode(parts[0], "UTF-8");
                        normalizedCookies.put(normalizedKey, parts[1]);
                    } catch (UnsupportedEncodingException e) {
                        // Handle exception
                    }
                }
            }
        }

        // [4]
        req.setAttribute("NormalizedCookies", normalizedCookies);
        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class CookieNormalizationMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $rawCookies = $request->header('Cookie');
        $normalizedCookies = [];

        if (!empty($rawCookies)) 
        {
            $pairs = explode(';', $rawCookies);
            foreach ($pairs as $pair) 
            {
                $parts = explode('=', trim($pair));
                if (count($parts) === 2) 
                {
                    // [1]
                    // [2]
                    // [3]
                    $normalizedKey = urldecode($parts[0]);
                    $normalizedCookies[$normalizedKey] = $parts[1];
                }
            }
        }

        // [4]
        $request->attributes->set('NormalizedCookies', $normalizedCookies);
        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class CookieNormalization {
    static middleware(req, res, next) {
        let rawCookies = req.headers['cookie'];
        let normalizedCookies = {};

        if (rawCookies) {
            let pairs = rawCookies.split(';');
            for (let pair of pairs) {
                let parts = pair.trim().split('=');
                if (parts.length === 2) {
                    // [1]
                    // [2]
                    // [3]
                    let normalizedKey = decodeURIComponent(parts[0]);
                    normalizedCookies[normalizedKey] = parts[1];
                }
            }
        }

        // [4]
        req.normalizedCookies = normalizedCookies;
        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture extracts the raw string representing the cookie names from the HTTP header, \[2] To support modern integrations where cookie names might contain special characters or spaces, developers implement a URL-Decoding optimization step, \[3] The fundamental security failure. The browser enforces the `__Host-` prefix rules _only_ on the exact literal string. Because the attacker sends `__Host%2DSession`, the browser allows the cookie to be scoped to the parent `.enterprise.tld` domain. The backend middleware blindly URL-decodes `%2D` into a hyphen `-`, causing the resulting string to collide exactly with the expected `__Host-Session` key, \[4] The application logic queries the `NormalizedCookies` dictionary for the `__Host-Session` key, mistakenly trusting that the presence of this key implies the browser enforced the strict Host-only routing constraints

```http
// 1. From a compromised, low-security subdomain (sandbox.enterprise.tld)
// The attacker injects a cookie. Notice the URL-encoded hyphen (%2D).
// Because it does not start exactly with "__Host-", the browser allows the Domain attribute.
document.cookie = "__Host%2DSession=ATTACKER_INJECTED_TOKEN; Domain=.enterprise.tld; Path=/; Secure";

// 2. The victim is tricked into navigating to the secure main application.
GET /api/admin/system-status HTTP/1.1
Host: secure.enterprise.tld
Cookie: __Host%2DSession=ATTACKER_INJECTED_TOKEN
```
{% endstep %}

{% step %}
The browser evaluates the `document.cookie` execution on the sandbox subdomain. It verifies that `__Host%2DSession` does not trigger the strict prefix rules, and thus allows the `Domain=.enterprise.tld` attribute to be set. When the victim navigates to `secure.enterprise.tld`, the browser dutifully transmits the spoofed cookie. The backend `CookieNormalizationMiddleware` parses the request, executes `URLDecode` on `__Host%2DSession`, and places the token into the internal dictionary under the exact key `__Host-Session`. The authentication module queries this dictionary, finds a valid token, and grants access. The attacker successfully forged a session token across domain boundaries, entirely defeating the Zero-Trust prefix architecture through backend data normalization
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
