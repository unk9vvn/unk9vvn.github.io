# Lack of Resources and Rate Limiting

## Check List

## Methodology

### Black Box

#### Rate Limiting Password Reset Functionalities

{% stepper %}
{% step %}
Log into the target site and intercept requests using Burp Suite
{% endstep %}

{% step %}
Go to the Forgot Password page and complete the request process
{% endstep %}

{% step %}
Then, using the Burp Suite tool, inspect the requests and identify whether the password reset process is performed using API endpoints
{% endstep %}

{% step %}
If the password forget process was performed using API endpoints, then send the API request to Intruder in the Burp Suite tool, then send 200 requests to the Endpoint API
{% endstep %}

{% step %}
If after sending all 200 requests, you get a status code of 200 in response to the server, and not a 429, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### API Brute Force on Login Endpoint

{% stepper %}
{% step %}
Identify API login endpoint, Intercept normal request

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"victim","password":"WrongPass1"}
```
{% endstep %}

{% step %}
Send request to Burp Intruder and Set payload position on password parameter
{% endstep %}

{% step %}
Configure multiple password attempts, Start attack with high request rate
{% endstep %}

{% step %}
Monitor responses, If API consistently returns `200` or `401` without delay, CAPTCHA, or lockout after numerous attempts, rate limiting is absent
{% endstep %}

{% step %}
If no temporary block or IP restriction occurs after hundreds of requests, brute-force protection is missing
{% endstep %}
{% endstepper %}

***

#### High-Volume API Abuse (DoS Vector)

{% stepper %}
{% step %}
Identify search or heavy-processing endpoint

```http
GET /api/search?q=test HTTP/1.1
Host: target.com
Authorization: Bearer token123
```
{% endstep %}

{% step %}
Send request to Turbo Intruder, Increase concurrent requests significantly
{% endstep %}

{% step %}
Monitor response times and status codes, If server continues processing without throttling, queueing, or `429` responses, no resource control is enforced
{% endstep %}

{% step %}
If high traffic causes degradation without triggering protective mechanisms, resource exhaustion risk exists
{% endstep %}

{% step %}
If API lacks request quotas per `user/IP` and allows uncontrolled request volume, Lack of Resources and Rate Limiting vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### API Gateway Asymmetry via GraphQL Array Batching Exhaustion

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern applications exposing a single, unified GraphQL endpoint (e.g., `POST /graphql`) shielded by a strict, enterprise-grade API Gateway or Web Application Firewall (WAF) (e.g., AWS API Gateway, Cloudflare, Kong)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's rate-limiting logic and the backend GraphQL engine's execution pipeline
{% endstep %}

{% step %}
Identify the "Layer 7 Rate Limiting" architecture. The API Gateway is configured to protect the backend infrastructure by strictly limiting HTTP requests. It restricts individual IP addresses to 100 requests per minute to prevent brute-force attacks and Denial of Service (DoS)
{% endstep %}

{% step %}
Investigate the backend GraphQL optimization mechanics. To prevent frontend Single Page Applications (SPAs) from suffering latency when loading complex UI views, developers explicitly enable "Query Batching" on the GraphQL engine (e.g., Apollo Server, HotChocolate)
{% endstep %}

{% step %}
Analyze the protocol desynchronization: The API Gateway exclusively inspects and rate-limits the HTTP transport layer. It evaluates "One HTTP Request = One Operational Action"
{% endstep %}

{% step %}
Discover the fatal execution asymmetry: Query Batching allows a client to submit a JSON array of discrete GraphQL queries within a _single_ HTTP request (e.g., `[ {query: "query A"}, {query: "query B"} ]`). The GraphQL engine parses this array and executes every query sequentially or in parallel
{% endstep %}

{% step %}
Understand the vulnerability: The API Gateway and the GraphQL engine possess entirely different definitions of operational unit cost. An attacker can package 10,000 computationally expensive GraphQL queries into a single HTTP POST payload
{% endstep %}

{% step %}
Formulate the Batching Exhaustion payload. Identify a highly complex, deep, or computationally expensive GraphQL query or mutation (e.g., triggering a heavy relational database search or initiating a password reset email)
{% endstep %}

{% step %}
Construct a JSON payload comprising an array containing thousands of identical or iterated copies of the target query
{% endstep %}

{% step %}
Transmit the massive JSON array payload to the `/graphql` endpoint
{% endstep %}

{% step %}
The API Gateway intercepts the HTTP request. It logs exactly _one_ request against the attacker's IP address. The rate limit allows the request to pass
{% endstep %}

{% step %}
The backend GraphQL engine receives the JSON array. Fulfilling its architectural mandate to process batched queries, it unwraps the array and initiates 10,000 independent execution contexts
{% endstep %}

{% step %}
The GraphQL server consumes maximum thread capacity and violently hammers the underlying relational database to execute the 10,000 queries
{% endstep %}

{% step %}
You have successfully bypassed the enterprise Layer 7 rate limits, achieving a catastrophic Resource Exhaustion (DoS) or massively accelerated credential stuffing attack utilizing perfect architectural asymmetry

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(builder\.AddGraphQLServer\(\)\.AddQueryType.*\.EnableBatching\(\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@Bean\s*public\s+BatchExecutionStrategy)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
('batching'\s*=>\s*true)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(new\s+ApolloServer\(\{.*allowBatchedHttpRequests:\s*true)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"builder\.AddGraphQLServer\(\)\.AddQueryType.*\.EnableBatching\(\)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"@Bean\s*public\s+BatchExecutionStrategy"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"'batching'\s*=>\s*true"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"new\s+ApolloServer\(\{.*allowBatchedHttpRequests:\s*true"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void ConfigureServices(IServiceCollection services)
{
    // [1]
    // [2]
    // Standard ASP.NET Rate Limiting applied to HTTP routes
    services.AddRateLimiter(options => {
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: context.Connection.RemoteIpAddress?.ToString(),
                factory: partition => new FixedWindowRateLimiterOptions { PermitLimit = 100 }));
    });

    services.AddGraphQLServer()
        .AddQueryType<Query>()
        .AddMutationType<Mutation>()
        // [3]
        // [4]
        // Disconnects GraphQL execution depth from HTTP transport limits
        .EnableBatching(); 
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Configuration
public class GraphQLConfig {

    // [1]
    // [2]
    // Rate limits are enforced at the API Gateway or Servlet Filter level based on URI and IP.
    
    @Bean
    public BatchExecutionStrategy batchExecutionStrategy() {
        // [3]
        // [4]
        // Enables resolving multiple top-level queries within a single HTTP frame,
        // multiplying the backend CPU impact without ticking the HTTP rate limiter.
        return new BatchExecutionStrategy();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// config/lighthouse.php
return [
    // [1]
    // [2]
    // Laravel Throttle middleware limits requests to 60 per minute
    'route' => [
        'middleware' => ['throttle:60,1'],
    ],

    // [3]
    // [4]
    // Lighthouse natively handles array execution to support Apollo batching
    'batchload' => [
        'enable' => true,
    ],
];
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { ApolloServer } = require('apollo-server-express');
const express = require('express');
const rateLimit = require('express-rate-limit');

const app = express();

// [1]
// [2]
// API Gateway/WAF equivalent implemented at the Express level
const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100 // Limits to 100 HTTP requests per IP
});

app.use('/graphql', limiter);

// [3]
// [4]
// Fatal Architectural Asymmetry: The Apollo Server permits batched arrays by default.
// The rate limiter is totally blind to the contents of the JSON payload.
const server = new ApolloServer({ 
    typeDefs, 
    resolvers,
    // explicitly enabling batching to optimize frontend load times
    allowBatchedHttpRequests: true 
});

server.start().then(() => {
    server.applyMiddleware({ app });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture separates transport-level perimeter defense from business-logic query resolution, delegating brute-force protection to standard API Gateways or WAFs, \[2] The Gateways track resource consumption exclusively by monitoring the volume of incoming HTTP packets per IP address, \[3] To resolve N+1 rendering issues and minimize TCP overhead for mobile clients, backend engineers explicitly instruct the GraphQL engine to accept arrays of queries within a single HTTP payload, \[4] The execution sink. The developers failed to unify the definition of "transactional cost" across the architecture. Because the API Gateway cannot parse or restrict the internal depth of a GraphQL JSON payload, it counts a 10,000-query array as a single HTTP request. The attacker exploits this semantic void by packing massive volumes of intensive operational logic into a singular transport frame. The backend engine, acting as a blind execution multiplexer, unfurls the array and executes the entire payload synchronously, causing immediate compute starvation and database connection pool exhaustion while remaining perfectly compliant with the perimeter rate limits

```http
// 1. Attacker identifies a computationally expensive GraphQL query, such as 
//    a deep relational search or triggering a 2FA email dispatch.
// 2. Attacker formats the payload as a JSON array to invoke the Batching execution model.

POST /graphql HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json
Authorization: Bearer <attacker_token>

[
  {"query": "mutation { triggerPasswordReset(email: \"admin1@evil.com\") { status } }"},
  {"query": "mutation { triggerPasswordReset(email: \"admin2@evil.com\") { status } }"},
  {"query": "mutation { triggerPasswordReset(email: \"admin3@evil.com\") { status } }"},
  // ... 9,997 more identical queries appended in the array ...
  {"query": "mutation { triggerPasswordReset(email: \"admin10000@evil.com\") { status } }"}
]

// 3. The WAF intercepts the request. It logs 1 request to the attacker's IP bucket.
// 4. The WAF forwards the request to the GraphQL backend.
// 5. The Apollo Server parses the array. It spins up 10,000 resolver threads.
// 6. The backend establishes 10,000 concurrent database connections and SMTP dispatches.
// 7. The underlying infrastructure runs out of RAM and CPU immediately. The API crashes.
// 8. The WAF allows the attacker to send 99 more identical HTTP requests this minute.
```
{% endstep %}

{% step %}
To combat initial page load latency, platform architects deployed GraphQL Query Batching, allowing clients to multiplex multiple independent queries into a solitary HTTP transmission. This optimization successfully minimized network overhead but fundamentally shattered the platform's resource allocation accounting. Enterprise API Gateways and WAFs measure abuse strictly through HTTP packet volume. By burying the operational complexity deep within the JSON data layer, developers decoupled the computational cost of the query from the transport cost measured by the perimeter. The attacker weaponized this architectural desynchronization by crafting JSON arrays packed with thousands of intensive instructions. The Gateway, evaluating only the HTTP envelope, authorized the transmission. The GraphQL engine dutifully disassembled the array and executed the enclosed instructions synchronously, successfully circumventing transport-layer rate limits to unleash a devastating application-layer Denial of Service
{% endstep %}
{% endstepper %}

***

#### Database CPU Exhaustion via Deep Pagination Offset Traversal

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on public or authenticated API endpoints exposing massive relational datasets with standard pagination controls (e.g., `/api/v1/users?limit=100&offset=0`, product catalogs, or global audit logs)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API's input validation and database query orchestration
{% endstep %}

{% step %}
Identify the "Shallow Boundary" architecture. To prevent attackers from dumping massive datasets into memory and crashing the application servers (OOM errors), developers strictly validate and enforce a maximum ceiling on the `limit` parameter (e.g., `if (limit > 100) limit = 100;`)
{% endstep %}

{% step %}
Investigate the Offset parameter boundary. The developer implements standard `OFFSET` / `LIMIT` logic to fulfill the client's page requests
{% endstep %}

{% step %}
Analyze the Relational Database (RDBMS) execution plan. In Postgres, MySQL, and SQL Server, the `OFFSET N` command does not instruct the database to instantly jump to a specific index pointer in physical memory. Because relational data is dynamic, the database engine must physically scan, sort, and count every single row from `0` to `N` before discarding them and returning the final `LIMIT` chunk
{% endstep %}

{% step %}
Discover the fatal validation gap: The developer meticulously caps the `limit` to `100`, but completely fails to constrain the absolute maximum value of the `offset` parameter
{% endstep %}

{% step %}
Understand the CPU Exhaustion vulnerability: If an attacker requests `limit=100&offset=5000000`, the application memory remains perfectly safe (it only ever loads 100 records into RAM). However, the underlying database engine is forced to scan and discard 5,000,000 records. This process consumes massive amounts of Database CPU and disk I/
{% endstep %}

{% step %}
Formulate the Deep Pagination payload. Identify an API endpoint querying a table containing millions of&#x20;
{% endstep %}

{% step %}
Construct an HTTP GET request maximizing the `offset` parameter to an extremely high number structurally permitted by the backend integer parser (e.g., `offset=9999999`)
{% endstep %}

{% step %}
To amplify the attack, include complex `ORDER BY` or `WHERE` filters in the query parameters (e.g., `&sort=created_at&status=active`). This forces the database to evaluate the constraints and sort the entire dataset _before_ scanning the 10 million rows to reach the offset
{% endstep %}

{% step %}
Transmit the payload concurrently using 20 to 50 parallel HTTP threads
{% endstep %}

{% step %}
The API Gateway allows the traffic because the volume is low (e.g., 50 requests)
{% endstep %}

{% step %}
The backend API validates the `limit` as safe and dispatches the 50 queries to the database
{% endstep %}

{% step %}
The database attempts to execute 50 parallel, full-table scans with massive offsets, instantly locking 100% of the database CPU cores, causing catastrophic query queuing, transaction timeouts, and global platform failure

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\.Skip\(\s*[a-zA-Z0-9_]+\.Offset\s*\)\.Take\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
(PageRequest\.of\([a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(->offset\(\$[a-zA-Z0-9_]+\)->limit\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(offset:\s*req\.(query|body)\.offset)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"\.Skip\(\s*[a-zA-Z0-9_]+\.Offset\s*\)\.Take\("
```
{% endtab %}

{% tab title="Java" %}
```regexp
"PageRequest\.of\([a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"->offset\(\\$[a-zA-Z0-9_]+\)->limit\("
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"offset:\s*req\.(query|body)\.offset"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/audit/logs")]
public async Task<IActionResult> GetAuditLogs([FromQuery] int limit = 50, [FromQuery] int offset = 0)
{
    // [1]
    // [2]
    // Memory protection boundary enforced
    if (limit > 100) limit = 100;

    // [3]
    // [4]
    // EF Core translates this directly to "ORDER BY ... OFFSET N ROWS FETCH NEXT M ROWS ONLY"
    // Executing this with offset=50000000 locks the SQL Server CPU entirely.
    var logs = await _dbContext.AuditLogs
        .OrderByDescending(l => l.Timestamp)
        .Skip(offset)
        .Take(limit)
        .ToListAsync();

    return Ok(logs);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/users/global")
public ResponseEntity<?> getUsers(
        @RequestParam(defaultValue = "0") int page, 
        @RequestParam(defaultValue = "20") int size) {
    
    // [1]
    // [2]
    int safeSize = Math.min(size, 100);

    // [3]
    // [4]
    // PageRequest.of calculates the offset (page * size). 
    // If an attacker requests page 500,000, the offset becomes massive.
    Pageable pageable = PageRequest.of(page, safeSize, Sort.by("lastLogin").descending());
    
    Page<User> users = userRepository.findAll(pageable);
    
    return ResponseEntity.ok(users.getContent());
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ProductController extends Controller
{
    public function index(Request $request)
    {
        // [1]
        // [2]
        $limit = min($request->input('limit', 20), 100);
        
        // [3]
        // [4]
        // The unchecked offset parameter drives database CPU to 100%
        $offset = $request->input('offset', 0);

        $products = Product::where('status', 'active')
                    ->orderBy('created_at', 'desc')
                    ->offset($offset)
                    ->limit($limit)
                    ->get();

        return response()->json($products);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/catalog/products', async (req, res) => {
    // [1]
    // [2]
    // Developer strictly clamps the limit to prevent memory exhaustion on the Node.js server.
    let limit = parseInt(req.query.limit) || 20;
    if (limit > 100) limit = 100;

    // [3]
    // [4]
    // Fatal Omission: The offset parameter is passed directly into the ORM unchecked.
    // If the offset is 10,000,000, the database engine must physically traverse 
    // and discard 10 million rows.
    let offset = parseInt(req.query.offset) || 0;

    const products = await Product.findAll({
        where: { status: 'active' },
        order: [['created_at', 'DESC']], // Sorting multiplies the DB CPU cost
        limit: limit,
        offset: offset
    });

    res.json(products);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application manages sprawling, multi-million-row database tables, exposing them to clients via paginated API endpoints, \[2] To protect the API application servers from catastrophic memory exhaustion (OOM), architects strictly validate and cap the pagination limit, ensuring the server only ever loads a safe, predefined chunk of records into RAM, \[3] The architecture dictates standard `OFFSET / LIMIT` (or page-based) pagination logic to allow clients to traverse the dataset, \[4] The execution sink. Developers possessed a dangerous blind spot regarding relational database execution plans. They assumed that fetching 100 records from the beginning of the table consumed the same database resources as fetching 100 records from the end of the table. They failed to realize that the `OFFSET` instruction forces the database engine to traverse, evaluate, and discard all preceding records prior to yielding the requested block. By omitting maximum boundary checks on the offset or page numbers, the backend grants the attacker direct mechanical control over the database's sequential scan depths. The attacker simply dials the offset to an extreme value across a handful of concurrent threads, intentionally inducing a permanent CPU deadlock on the backend RDBMS

```http
// 1. Attacker identifies a heavily populated, sortable endpoint (e.g., an enterprise product catalog).
// 2. Attacker prepares a multi-threaded script (e.g., using Python or Burp Intruder).
// 3. The script dispatches 30 concurrent GET requests.
// 4. The payload sets a safe 'limit' to bypass memory checks, but maximizes the 'offset' 
//    while invoking an unindexed or computationally heavy sort.

GET /api/v1/catalog/products?sort=popularity_score&limit=50&offset=8000000 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>

// 5. The API Gateway permits the 30 requests because it falls well below the 100 req/min limit.
// 6. The API Controllers intercept the requests. The 'limit=50' passes validation safely.
// 7. The 30 API threads transmit the query to the PostgreSQL/MySQL database:
//    SELECT * FROM products ORDER BY popularity_score DESC LIMIT 50 OFFSET 8000000;

// 8. The database attempts to sort the entire table by 'popularity_score'.
// 9. For each of the 30 queries, the database physically traverses and discards 8 million rows.
// 10. The database CPU hits 100%. Write locks begin queueing. Legitimate API queries timeout.
// 11. The entire enterprise platform goes offline due to Deep Pagination Exhaustion.
```
{% endstep %}

{% step %}
To provide seamless exploration of massive datasets without compromising application server memory, architects implemented constrained pagination endpoints. This security model strictly enforced data retrieval ceilings, capping the volume of records serialized per HTTP request. The systemic vulnerability arose from a fundamental misunderstanding of RDBMS indexing and offset traversal mechanics. Developers incorrectly assumed that `OFFSET` functioned as an instant memory pointer rather than an active, linear scanning directive. Consequently, they left the offset variable unconstrained. The attacker bypassed perimeter rate limits by launching a low volume of highly toxic queries. By maximizing the offset parameter, the attacker forced the underlying database engine to perform exhaustive, multi-million-row traversal operations strictly to discard the results. This algorithmic abuse weaponized the application's intended querying flexibility, shifting the attack vector from network bandwidth saturation to precise, surgical Database CPU Exhaustion
{% endstep %}
{% endstepper %}

***

#### Rate Limit Bucket Evasion via Topographical Header Spoofing (X-Forwarded-For)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise infrastructure protected by modern external Content Delivery Networks (CDNs) or Web Application Firewalls (WAFs) like Cloudflare or AWS CloudFront, which route traffic to internal Kubernetes clusters or API Gateways (e.g., NGINX, Express, Kong)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's rate-limiting middleware, specifically examining how it extracts the "Client IP" to maintain its rate-limit tracking buckets in Redis
{% endstep %}

{% step %}
Identify the "Reverse Proxy IP Resolution" architecture. Because the application sits behind a CDN, examining the TCP socket's remote IP will always yield the CDN's internal IP address (e.g., `10.0.0.5`). To identify the true user and enforce rate limits, the backend developer configures the framework to trust and parse the `X-Forwarded-For` (XFF) HTTP header
{% endstep %}

{% step %}
Investigate the Trust Proxy configuration. The XFF header is a comma-separated array of IP addresses appended by every proxy in the chain (e.g., `X-Forwarded-For: ClientIP, Proxy1, Proxy2`)
{% endstep %}

{% step %}
Analyze the extraction vulnerability: Developers frequently instruct their web frameworks to blindly "trust proxies" (e.g., `app.set('trust proxy', true)` in Express) or write custo
{% endstep %}

{% step %}
Discover the fatal topographical overlap: The developer assumes that the XFF header is entirely constructed by the trusted CDN. They fail to understand that a malicious client can arbitrarily inject their own fake IP addresses into the XFF header _before_ the request even reaches the CDN
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker sends `X-Forwarded-For: 1.1.1.1`, the CDN intercepts it and appends the attacker's true IP: `X-Forwarded-For: 1.1.1.1, 99.88.77.66`. The backend receives this string. Because the backend is misconfigured to trust the _first_ IP in the chain (or generically trusts all proxies), it incorrectly registers `1.1.1.1` as the client IP
{% endstep %}

{% step %}
Formulate the Rate Limit Evasion payload. You must bypass the backend's brute-force protection (e.g., 5 login attempts per IP) by continually shifting your perceived origin
{% endstep %}

{% step %}
Construct an automated script targeting the authentication endpoint
{% endstep %}

{% step %}
On every single HTTP POST request, dynamically generate a random, fake IP address and inject it into the `X-Forwarded-For` (or `X-Real-IP`, `True-Client-IP`) header
{% endstep %}

{% step %}
The CDN appends your true IP, forwarding the compound header to the&#x20;
{% endstep %}

{% step %}
The backend middleware blindly extracts the first IP (your randomly generated fake IP)
{% endstep %}

{% step %}
The rate-limiting logic creates a brand new Redis bucket for this fake IP. It increments the count to 1 and authorizes the request
{% endstep %}

{% step %}
By continuously rotating the injected XFF header, you guarantee that every single request falls into a fresh rate-limit bucket, allowing infinite, unthrottled brute-forcing and complete neutralization of the platform's anti-abuse architecture

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(ForwardedHeadersOptions\s*\{\s*ForwardedHeaders\s*=\s*ForwardedHeaders\.XForwardedFor\s*\})|(Request\.Headers\["X-Forwarded-For"\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
(request\.getHeader\("X-Forwarded-For"\))|(HttpHeaders\.getFirst\("X-Forwarded-For"\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(request->header\('X-Forwarded-For'\))|(\$request->headers->get\('X-Forwarded-For'\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(app\.set\(['"]trust proxy['"],\s*true\))|(var\s+ip\s*=\s*req\.headers\['x-forwarded-for'\]\.split\(['"],['"]\)\[0\])|(req\.get\(['"]X-Forwarded-For['"]\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"ForwardedHeadersOptions\s*\{\s*ForwardedHeaders\s*=\s*ForwardedHeaders\.XForwardedFor\s*\}|Request\.Headers\[\"X-Forwarded-For\"\]"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"request\.getHeader\(\"X-Forwarded-For\"\)|HttpHeaders\.getFirst\(\"X-Forwarded-For\"\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"request->header\('X-Forwarded-For'\)|\\$request->headers->get\('X-Forwarded-For'\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"app\.set\(['\"]trust proxy['\"],\s*true\)|var\s+ip\s*=\s*req\.headers\['x-forwarded-for'\]\.split\(['\"],['\"]\)\[0\]|req\.get\(['\"]X-Forwarded-For['\"]\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // [1]
    // [2]
    var forwardedHeadersOptions = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    };

    // [3]
    // [4]
    // Clearing the KnownNetworks and KnownProxies lists instructs ASP.NET 
    // to blindly trust the X-Forwarded-For header without verifying if the 
    // upstream sender was actually the trusted Cloudflare CDN.
    forwardedHeadersOptions.KnownNetworks.Clear();
    forwardedHeadersOptions.KnownProxies.Clear();

    app.UseForwardedHeaders(forwardedHeadersOptions);

    app.UseRateLimiter(); // Native ASP.NET Rate Limiting evaluates the spoofed context
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void Configure(ApplicationBuilder app, WebHostEnvironment env)
{
    // [1]
    // [2]
    var forwardedHeadersOptions = new ForwardedHeadersOptions()
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    };

    // [3]
    // [4]
    // Clearing the KnownNetworks and KnownProxies lists instructs ASP.NET
    // to blindly trust the X-Forwarded-For header without verifying if the
    // upstream sender was actually the trusted Cloudflare CDN.
    forwardedHeadersOptions.KnownNetworks.clear();
    forwardedHeadersOptions.KnownProxies.clear();

    app.UseForwardedHeaders(forwardedHeadersOptions);

    app.UseRateLimiter(); // Native ASP.NET Rate Limiting evaluates the spoofed context
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// config/trustedproxy.php
return [
    // [1]
    // [2]
    // Trusting '*' allows the client's injected X-Forwarded-For header to be parsed 
    // and applied by the framework as the authoritative client IP.
    'proxies' => '*',
    
    // [3]
    // [4]
    // The Throttle middleware utilizes $request->ip(), which is now compromised.
    'headers' => Illuminate\Http\Request::HEADER_X_FORWARDED_FOR,
];
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const express = require('express');
const rateLimit = require('express-rate-limit');

const app = express();

// [1]
// [2]
// Fatal Flaw: Setting 'trust proxy' to a boolean 'true' tells Express to trust 
// the ENTIRE X-Forwarded-For chain, allowing the client to dictate their own IP 
// by plucking the leftmost value in the header.
// Correct logic: app.set('trust proxy', '10.0.0.0/8'); // Only trust the immediate internal CDN
app.set('trust proxy', true);

// [3]
// [4]
// The rate limiter relies entirely on req.ip.
// Because 'trust proxy' is misconfigured, req.ip evaluates to the attacker's spoofed value.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5,
    message: "Too many login attempts."
});

app.post('/api/v1/auth/login', loginLimiter, (req, res) => {
    // Brute force target
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The enterprise perimeter operates a multi-hop reverse proxy architecture, utilizing edge CDNs or load balancers before terminating traffic at the application servers, \[2] To enforce behavioral analysis, geolocation, and rate limiting, the backend must ascertain the original user's IP address. It extracts this data from the standard `X-Forwarded-For` HTTP header, \[3] The architecture utilizes robust, memory-backed rate limiters (e.g., Redis) that aggregate and throttle HTTP requests into discrete buckets mapped to the extracted client IP, \[4] The execution sink. Developers fundamentally misunderstood the mutability of topographical HTTP headers. They assumed that the CDN systematically overwrote the entire `X-Forwarded-For` header. In reality, CDNs append the TCP source IP to the _existing_ header value provided by the client. By globally configuring the backend framework to "trust proxies" without explicitly anchoring that trust to the precise internal IP range of the CDN, the developers instructed the framework to parse the entire header chain backwards. The backend blindly extracts the leftmost, attacker-injected IP address. The attacker continuously cycles this injected header, generating an infinite number of microscopic rate-limit buckets, effortlessly brute-forcing the core authentication endpoints without ever tripping the perimeter abuse thresholds

```http
// 1. Attacker writes a Python script to brute-force a victim's password.
// 2. The script targets the login endpoint, which is limited to 5 requests per IP.
// 3. For Request #1, the attacker injects a random IP into the X-Forwarded-For header.

POST /api/v1/auth/login HTTP/1.1
Host: api.enterprise.tld
X-Forwarded-For: 201.55.10.1
Content-Type: application/json

{"username": "admin@enterprise.tld", "password": "Password1"}

// 4. The CDN receives the request. The TCP source IP is 99.88.77.66 (Attacker's real IP).
// 5. The CDN appends the real IP: X-Forwarded-For: 201.55.10.1, 99.88.77.66
// 6. The backend API parses the header, extracts the leftmost IP ("201.55.10.1").
// 7. Rate Limit Bucket [201.55.10.1] increments to 1. Request allowed.

// 8. For Request #2, the attacker rotates the spoofed header.
POST /api/v1/auth/login HTTP/1.1
Host: api.enterprise.tld
X-Forwarded-For: 18.22.44.9
Content-Type: application/json

{"username": "admin@enterprise.tld", "password": "Password2"}

// 9. The CDN appends: X-Forwarded-For: 18.22.44.9, 99.88.77.66
// 10. The backend API extracts the leftmost IP ("18.22.44.9").
// 11. Rate Limit Bucket [18.22.44.9] is newly created and increments to 1. Request allowed.
// 12. The attacker executes 100,000 requests from a single physical IP, completely evading 
//     the 5-request limit by topologically confusing the proxy resolution logic.
```
{% endstep %}

{% step %}
To maintain visibility over client origins across complex reverse-proxy infrastructure, architects configured application servers to read upstream tracking headers (`X-Forwarded-For`). This mechanism transferred the responsibility of identity binding from the raw TCP transport layer to the mutable HTTP application layer. The systemic vulnerability emerged from a topological trust failure. Developers instructed the backend framework to unconditionally trust the proxy chain without explicitly validating that the upstream hop belonged to an authorized internal subnet. The attacker exploited this configuration by pre-loading the `X-Forwarded-For` header with randomized IP values prior to CDN ingestion. The CDN accurately appended the true IP, but the misconfigured backend parser inherently trusted the leftmost, attacker-controlled value. This architectural hallucination decoupled the rate-limiting enforcement engine from physical network reality, allowing the attacker to dynamically spawn infinite, un-throttled execution contexts and seamlessly brute-force the platform's primary authentication boundaries
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
