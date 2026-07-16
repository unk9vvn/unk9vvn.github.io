# Improper Error Handling

## Check List

## Methodology

### Black Box

#### Improper Error Handling Leading to Information Disclosure

{% stepper %}
{% step %}
Navigate to the target web application and identify accessible API endpoints
{% endstep %}

{% step %}
Interact with the API endpoint by submitting malformed or unexpected input in request parameters

```http
GET /api/v1/login?user=admin'-- HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Observe the server response and check for detailed error messages returned by the API

```json
{
  "error": "SQL syntax error in users_db at 10.0.0.1",
  "query": "SELECT * FROM users WHERE username = 'admin'--'"
}
```
{% endstep %}

{% step %}
Analyze the response for sensitive information such as Internal database names, Internal IP addresses, SQL queries or Valid usernames or system structure
{% endstep %}

{% step %}
Repeat the request with different malformed inputs to determine whether additional internal system information is disclosed
{% endstep %}

{% step %}
If the API response exposes internal database details, system architecture, or query structures through verbose error messages, the Information Disclosure vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Information Disclosure via Improper Error Handling

{% stepper %}
{% step %}
Navigate to the target web application and identify an endpoint that accepts user-supplied input

```http
GET /product?productId=1 HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Confirm that the application responds normally when a valid numeric value is provided
{% endstep %}

{% step %}
Modify the request by replacing the numeric parameter value with an invalid string input

```http
GET /product?productId=test HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Send the modified request to the server
{% endstep %}

{% step %}
Observe the server response and check whether a **500 Internal Server Error** is returned
{% endstep %}

{% step %}
Scroll through the stack trace output and identify any exposed sensitive information such as Framework name or Internal file paths and ...
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Fallback Execution in Circuit Breaker Topologies

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-throughput microservice architectures, API Gateways, or Service Meshes that govern internal authentication and routing (e.g., Ocelot, Spring Cloud Gateway, Kong)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Resilience and High Availability" architecture. To prevent cascading system failures when a central microservice (like the Identity Provider or Policy Decision Point) experiences latency, developers wrap critical inter-service HTTP calls in Circuit Breakers (e.g., Polly, Resilience4j, Opossum)
{% endstep %}

{% step %}
Investigate the Circuit Breaker's `Fallback` configuration. When the Circuit Breaker trips (transitions to the "Open" state due to excessive timeouts or 500 errors), or when an individual request times out, the framework executes a predefined fallback method instead of throwing a fatal exception
{% endstep %}

{% step %}
Analyze the business logic within the fallback delegate. In complex enterprises, background workers, cron jobs, and asynchronous queue consumers also route through the API Gateway to reach internal services. If the central Auth service goes down, these critical background processes would fail
{% endstep %}

{% step %}
Discover the fatal error-handling optimization: To ensure internal background tasks remain operational during IAM outages, the developer configures the Circuit Breaker fallback to return a static, highly privileged `ServiceAccount` or `SystemAdmin` authorization context
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that Circuit Breakers only trip during genuine, infrastructure-wide network outages. They implicitly trust that if the fallback executes, it is a necessary failsafe for internal systems, failing to distinguish between internal background traffic and external ingress traffic
{% endstep %}

{% step %}
Formulate the Deterministic Error Induction payload. You must manually force the Circuit Breaker to trip or force your specific request to exceed the timeout threshold, invoking the fallback pipeline
{% endstep %}

{% step %}
Identify an execution bottleneck in the target microservice (e.g., the Identity Provider). This could be an extremely long password that triggers bcrypt CPU exhaustion (Regex/Hash DoS), a massive JWT payload that exhausts the JSON parser, or a recursive GraphQL query
{% endstep %}

{% step %}
Submit the computationally expensive payload to the API Gateway's authentication endpoint
{% endstep %}

{% step %}
The Gateway's Circuit Breaker initiates the HTTP call to the Auth service and starts its internal stopwatch
{% endstep %}

{% step %}
The Auth service struggles to process your malicious payload. The Circuit Breaker's execution timer (e.g., 2000ms) expires
{% endstep %}

{% step %}
The Circuit Breaker catches the `TimeoutException`. Instead of returning a `401 Unauthorized` or `503 Service Unavailable`, it seamlessly routes your execution thread into the configured `Fallback` method
{% endstep %}

{% step %}
The Fallback method returns the hardcoded `SystemAdmin` context. The API Gateway assigns this context to your external HTTP request and proxies you to the downstream business microservice. You have successfully achieved unauthenticated, absolute privilege escalation purely by weaponizing the application's own error-handling resilience mechanisms

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\.FallbackAsync\s*\(\s*new\s+AuthContext\s*\{[\s\S]{0,120}?Role\s*=\s*"Admin"|\.FallbackAsync\s*\([\s\S]{0,120}?(?:Admin|System|ServiceAccount)|new\s+AuthContext\s*\{[\s\S]{0,80}?(?:Role|IsAdmin))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@Fallback\s*\([\s\S]{0,120}?fallbackMethod\s*=|fallbackMethod\s*=\s*".*(?:Admin|System|Auth)"|new\s+AuthContext\s*\([\s\S]{0,80}?(?:ADMIN|SYSTEM))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$circuitBreaker->setFallback\s*\([\s\S]{0,120}?new\s+AuthContext|setFallback\s*\([\s\S]{0,120}?(?:System|Admin)|new\s+AuthContext\s*\(\s*['"]System['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:breaker\.fallback\s*\([\s\S]{0,150}?role\s*:\s*['"](?:Admin|ServiceAccount|System)['"]|fallback\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,120}?role\s*:|return\s*\{[\s\S]{0,80}?role\s*:\s*['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\.FallbackAsync\(.*AuthContext.*Role\s*=\s*"Admin"|FallbackAsync\(.*ServiceAccount
```
{% endtab %}

{% tab title="Java" %}
```regexp
@Fallback\(.*fallbackMethod\s*=.*Admin|new\s+AuthContext\(.*ADMIN
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$circuitBreaker->setFallback\(.*AuthContext\('System'\)|setFallback\(.*Admin
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
breaker\.fallback\(.*role:\s*'ServiceAccount'|fallback\(.*role:\s*'Admin'
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class GatewayAuthenticationMiddleware
{
    private readonly AsyncFallbackPolicy<AuthContext> _fallbackPolicy;
    private readonly AsyncTimeoutPolicy _timeoutPolicy;

    public GatewayAuthenticationMiddleware()
    {
        // [1]
        // [2]
        _timeoutPolicy = Policy.TimeoutAsync(TimeSpan.FromSeconds(2));

        // [3]
        // [4]
        // Fails open to ensure internal metrics and cron jobs aren't disrupted by IAM latency
        _fallbackPolicy = Policy<AuthContext>
            .Handle<TimeoutRejectedException>()
            .Or<HttpRequestException>()
            .FallbackAsync(new AuthContext { 
                IsAuthenticated = true, 
                Role = "SystemAdmin", 
                UserId = "SYSTEM_FALLBACK" 
            });
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var token = context.Request.Headers["Authorization"].FirstOrDefault();

        // Combines policies: Timeout wraps the HTTP call, Fallback wraps the Timeout
        var authContext = await _fallbackPolicy.WrapAsync(_timeoutPolicy).ExecuteAsync(async () => 
        {
            return await _iamClient.ValidateTokenAsync(token);
        });

        if (authContext.IsAuthenticated)
        {
            context.Items["UserContext"] = authContext;
            await next(context);
        }
        else
        {
            context.Response.StatusCode = 401;
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class GatewayAuthenticationFilter implements GlobalFilter {

    @Autowired
    private IamClient iamClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");

        // [1]
        // [2]
        return iamClient.validateToken(token)
                // [3]
                // [4]
                // Resilience4j annotations or programmatic fallback on Timeout/CircuitBreakerOpen exceptions
                .onErrorResume(TimeoutException.class, e -> Mono.just(getSystemFallbackContext()))
                .flatMap(authContext -> {
                    if (authContext.isAuthenticated()) {
                        exchange.getAttributes().put("UserContext", authContext);
                        return chain.filter(exchange);
                    } else {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                });
    }

    private AuthContext getSystemFallbackContext() {
        AuthContext context = new AuthContext();
        context.setAuthenticated(true);
        context.setRole("SystemAdmin");
        return context;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class GatewayAuthenticationMiddleware
{
    protected $iamClient;
    protected $circuitBreaker;

    public function __construct(IamClient $iamClient)
    {
        $this->iamClient = $iamClient;
        
        // [1]
        // [2]
        $this->circuitBreaker = new CircuitBreaker(
            timeout: 2.0,
            threshold: 5
        );

        // [3]
        // [4]
        $this->circuitBreaker->setFallback(function() {
            return new AuthContext(true, 'SystemAdmin', 'SYSTEM_FALLBACK');
        });
    }

    public function handle(Request $request, Closure $next)
    {
        $token = $request->header('Authorization');

        $authContext = $this->circuitBreaker->execute(function() use ($token) {
            return $this->iamClient->validateToken($token);
        });

        if ($authContext->isAuthenticated) {
            $request->attributes->set('UserContext', $authContext);
            return $next($request);
        }

        return response('Unauthorized', 401);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const CircuitBreaker = require('opossum');

class GatewayAuthenticationMiddleware {
    constructor() {
        // [1]
        // [2]
        const options = {
            timeout: 2000, 
            errorThresholdPercentage: 50,
            resetTimeout: 30000
        };

        this.breaker = new CircuitBreaker(iamClient.validateToken, options);

        // [3]
        // [4]
        this.breaker.fallback(() => {
            return {
                isAuthenticated: true,
                role: 'SystemAdmin',
                userId: 'SYSTEM_FALLBACK'
            };
        });
    }

    async handle(req, res, next) {
        let token = req.headers['authorization'];

        try {
            let authContext = await this.breaker.fire(token);

            if (authContext.isAuthenticated) {
                req.userContext = authContext;
                next();
            } else {
                res.status(401).send('Unauthorized');
            }
        } catch (err) {
            res.status(500).send('Internal Gateway Error');
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway acts as the central ingress point, routing both external user traffic and internal background service traffic through the same authentication pipeline, \[2] To prevent thread exhaustion, the gateway enforces a strict 2-second timeout on all calls to the backend Identity and Access Management (IAM) microservice, \[3] The architecture incorporates a Fallback strategy. Developers recognized that if the IAM service experiences a brief outage, critical internal processes (like batch billing or cron jobs) would fail catastrophically, \[4] The fatal error-handling paradigm. The developer assumes that exceptions in the IAM pipeline only originate from infrastructure degradation. By instructing the exception handler to "Fail-Open" and return a highly privileged System Account, they unintentionally map an attacker-induced `TimeoutException` directly to an administrative authorization bypass

```http
// 1. Attacker identifies a heavily nested GraphQL query, a deeply compressed JWT, 
// or an intentionally massive header designed to slow down the backend IAM parser.

POST /api/v1/admin/manage-tenants HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer eyJhb...[100,000 bytes of padding]...
Content-Type: application/json

{"action": "delete", "target": "victim_tenant"}

// 2. The API Gateway receives the request and wraps the IAM validation call in the Circuit Breaker.
// 3. The Backend IAM service struggles to parse the massive 100KB JWT, taking 3.5 seconds.
// 4. The Gateway's Circuit Breaker hits its 2.0-second Timeout limit and throws a TimeoutRejectedException.
// 5. The Error Handler catches the exception, suppresses it, and seamlessly executes the Fallback.
// 6. The Fallback returns the static 'SystemAdmin' context.
// 7. The API Gateway applies the 'SystemAdmin' role to the attacker's active request.
// 8. The Gateway proxies the request to the /manage-tenants backend, destroying the victim tenant.
```
{% endstep %}

{% step %}
To guarantee the high availability of critical background infrastructure during identity service degradation, enterprise architects deployed resilient Circuit Breaker patterns. The security failure emerged from an improper assumption regarding the provenance of exceptions. The developers assumed that application-layer timeouts were exclusively symptoms of network congestion or hardware failure, justifying a "Fail-Open" fallback state to keep internal systems running. The attacker shattered this assumption by crafting a computational payload that deliberately exhausted the Identity Provider's CPU thread, intentionally exceeding the Gateway's timeout threshold. By forcing the error, the attacker hijacked the exception-handling pipeline, riding the resilience fallback mechanism directly into an unauthenticated, system-level authorization context
{% endstep %}
{% endstepper %}

***

#### Ghost Account Provisioning via Distributed Saga Rollback Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on orchestration-heavy endpoints that provision resources across multiple platforms simultaneously (e.g., User Onboarding creating accounts in the local DB, Active Directory, AWS, and Stripe)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Distributed Choreography/Saga" architecture. In modern microservices, global SQL transactions (`System.Transactions`) cannot span across external APIs (like Stripe or Okta)
{% endstep %}

{% step %}
Investigate the API execution sequence. The developer utilizes a "Commit-Then-Publish" or "Publish-Then-Commit" pattern. The Controller executes an external HTTP call to a SaaS provider, receives a successful response, and _then_ executes the local ORM database transaction to record the new entity
{% endstep %}

{% step %}
Analyze the Global Exception Handler middleware. If an exception occurs anywhere in the Controller, the framework's global error handler catches it, automatically rolls back the active local SQL transaction, and returns an `HTTP 400 Bad Request` or `500 Internal Server Error` to the client
{% endstep %}

{% step %}
Discover the out-of-band state desynchronization: The local SQL transaction rolls back perfectly. However, the external API call (e.g., to Okta or AWS) has _already succeeded_. Because the developer relied exclusively on the web framework's native error handling to abort the request, they failed to implement a Compensating Transaction (a Saga Rollback) to manually delete the provisioned external resource
{% endstep %}

{% step %}
Understand the structural assumption: The developer assumes that if an HTTP request returns a `400 Bad Request`, the user perceives the entire operation as a failure, and the system state remains pristine.
{% endstep %}

{% step %}
Formulate the Rollback Asymmetry payload. You must construct a request that perfectly satisfies the validation rules of the _external_ SaaS provider, but intentionally violates a strict database constraint in the _local_ relational database
{% endstep %}

{% step %}
Target a secondary, non-critical field that is saved locally but ignored externally. For example, submit a `Bio` or `CompanyName` string that is 300 characters long, knowing the local SQL column is strictly defined as `VARCHAR(255)`
{% endstep %}

{% step %}
Submit the payload to the enterprise onboarding endpoint
{% endstep %}

{% step %}
The Controller receives the request. It extracts your email and provisions the account in the external Okta/AWS environment. The external service returns a `201 Created`
{% endstep %}

{% step %}
The Controller attempts to save the user profile to the local SQL database. The ORM throws a `DataTruncationException` or `String or binary data would be truncated`
{% endstep %}

{% step %}
The Global Error Handler catches the database exception, rolls back the local `INSERT` transaction, and returns a `400 Bad Request`
{% endstep %}

{% step %}
The vulnerability is fully realized. You possess a fully functional, highly privileged account in the enterprise's external SSO or Cloud environment. However, because the local database transaction was rolled back, your account does not exist in the enterprise's billing engine, audit logs, or Admin UI. You have provisioned a completely invisible "Ghost Account" at the enterprise's expense

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+\w+Client\.\w*Create\w*Async\s*\([\s\S]{0,150}?await\s+\w*dbContext\.\w*SaveChangesAsync|await\s+\w+\.\w*Create\w*Async\s*\([\s\S]{0,150}?SaveChangesAsync|Create.*Async\(\)[\s\S]{0,120}dbContext\.SaveChangesAsync)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:externalService\.(?:create|provision)\s*\([\s\S]{0,150}?repository\.save\s*\(|restTemplate\.(?:postForObject|exchange)\([\s\S]{0,150}?repository\.save|client\.(?:create|provision)\([\s\S]{0,150}?save\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$externalApi->(?:create|provision)\s*\([\s\S]{0,150}?\$model->save\s*\(|Http::post\([\s\S]{0,150}?\$model->save|->create\s*\([\s\S]{0,120}?->save\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:await\s+\w+\.(?:create|provision)\s*\([\s\S]{0,150}?await\s+Model\.create\s*\(|await\s+axios\.(?:post|put)\([\s\S]{0,150}?Model\.create|await\s+\w+\.(?:create|insert)\([\s\S]{0,150}?await\s+\w+\.save)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
await\s+externalClient\.Create.*Async\(\);\s*await\s+dbContext\.SaveChangesAsync\(|Create.*Async\(\).*SaveChangesAsync
```
{% endtab %}

{% tab title="Java" %}
```regexp
externalService\.provision\(.*\);\s*repository\.save\(|externalService\.create\(.*\);\s*repository\.save
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$externalApi->create\(.*\);\s*\$model->save\(|Http::post\(.*\);\s*\$model->save
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
await\s+cloudProvider\.create\(.*\);\s*await\s+Model\.create\(|await\s+axios\.post\(.*\);\s*await\s+Model\.create
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/enterprise/onboard")]
public async Task<IActionResult> OnboardTenant([FromBody] OnboardingRequest request)
{
    // [1]
    // [2]
    // Synchronous call to an external cloud provider (e.g., Okta, AWS, Stripe)
    var externalCloudResponse = await _awsClient.ProvisionTenantInfrastructureAsync(request.TenantName, request.AdminEmail);

    // [3]
    // [4]
    // Local database persistence using Entity Framework
    var newTenant = new Tenant 
    {
        Name = request.TenantName,
        AdminEmail = request.AdminEmail,
        CloudId = externalCloudResponse.Id,
        WelcomeMessage = request.WelcomeMessage // Vulnerable DB constraint (VARCHAR(255))
    };

    _dbContext.Tenants.Add(newTenant);
    
    // If request.WelcomeMessage is > 255 chars, DbUpdateException is thrown here.
    // The global exception middleware catches it, returning 500, but the AWS resources 
    // were already created and are never torn down.
    await _dbContext.SaveChangesAsync();

    return Ok(new { Status = "Provisioned" });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class TenantOnboardingController {

    @Autowired
    private OktaClient oktaClient;
    @Autowired
    private TenantRepository tenantRepo;

    @PostMapping("/api/v1/enterprise/onboard")
    @Transactional
    public ResponseEntity<?> onboardTenant(@RequestBody OnboardingRequest request) throws Exception {
        // [1]
        // [2]
        // Provisions the administrative account in the external SSO provider
        String oktaUserId = oktaClient.createAdminUser(request.getTenantName(), request.getAdminEmail());

        // [3]
        // [4]
        Tenant newTenant = new Tenant();
        newTenant.setName(request.getTenantName());
        newTenant.setAdminEmail(request.getAdminEmail());
        newTenant.setOktaId(oktaUserId);
        newTenant.setWelcomeMessage(request.getWelcomeMessage()); 

        // If a DataIntegrityViolationException (e.g., data truncation) occurs, 
        // the @Transactional annotation rolls back the SQL insert.
        // However, @Transactional cannot roll back the HTTP call to Okta.
        tenantRepo.save(newTenant);

        return ResponseEntity.ok(Map.of("Status", "Provisioned"));
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class TenantOnboardingController extends Controller
{
    public function onboardTenant(Request $request)
    {
        // [1]
        // [2]
        $awsCredentials = ExternalCloudProvider::createWorkspace($request->tenantName);

        // [3]
        // [4]
        DB::beginTransaction();
        try {
            $tenant = new Tenant();
            $tenant->name = $request->tenantName;
            $tenant->aws_id = $awsCredentials->id;
            // Triggers QueryException if string exceeds column length
            $tenant->welcome_message = $request->welcomeMessage; 
            $tenant->save();
            
            DB::commit();
        } catch (\Exception $e) {
            DB::rollBack();
            // The local DB is rolled back, but the AWS Workspace remains active permanently.
            throw $e; 
        }

        return response()->json(['status' => 'Provisioned']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/enterprise/onboard', async (req, res, next) => {
    try {
        // [1]
        // [2]
        let stripeCustomer = await stripe.customers.create({
            email: req.body.adminEmail,
            name: req.body.tenantName
        });

        // [3]
        // [4]
        // Sequelize throws SequelizeValidationError or SequelizeDatabaseError if welcomeMessage is too long.
        await Tenant.create({
            name: req.body.tenantName,
            adminEmail: req.body.adminEmail,
            stripeId: stripeCustomer.id,
            welcomeMessage: req.body.welcomeMessage
        });

        res.send({ status: 'Provisioned' });
    } catch (err) {
        // Express global error handler catches the DB error and returns 500.
        // The Stripe customer is orphaned.
        next(err);
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The enterprise architecture orchestrates resources across multiple third-party boundaries (SSO, Cloud Compute, Billing) during a single monolithic HTTP request, \[2] The execution flow mandates that external resources are provisioned _first_ so their resulting IDs can be stored in the local database, \[3] The architecture relies entirely on the web framework's native Exception Handling and SQL Transactions to manage failure states, fundamentally ignoring the distributed nature of the orchestration, \[4] The fatal desynchronization sink. Developers mistakenly believe that throwing an exception universally aborts an operation. By intentionally triggering a localized SQL constraint error (like Data Truncation), the attacker forces the error handler to terminate the request and roll back the local database. Because no compensating transaction exists to alert the external provider of the failure, the out-of-band state remains permanently altered

```http
// 1. Attacker discovers the enterprise onboarding endpoint which integrates with an external Okta IdP.
// 2. Attacker crafts a payload designed to succeed in Okta, but fail in the local PostgreSQL database.
// The attacker pads the 'welcomeMessage' to 500 characters, exceeding the local VARCHAR(255) limit.

POST /api/v1/enterprise/onboard HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{
  "tenantName": "Attacker Corp",
  "adminEmail": "attacker@evil.com",
  "welcomeMessage": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

// 3. The API invokes Okta: oktaClient.createAdminUser("Attacker Corp", "attacker@evil.com").
// 4. Okta processes the request, provisions the enterprise SSO account, and emails the attacker a password reset link.
// 5. The API attempts to save the Tenant to the local DB.
// 6. PostgreSQL throws: "String or binary data would be truncated in table 'Tenants', column 'WelcomeMessage'."
// 7. The Global Error Handler catches the exception, executes a SQL ROLLBACK, and returns:

HTTP/1.1 400 Bad Request
{
  "error": "Data validation failed."
}

// 8. The attacker checks their email, clicks the Okta activation link, and logs into the Enterprise SSO.
// 9. Because the local database transaction was rolled back, the enterprise billing engine has no record 
//    of the tenant, granting the attacker infinite, invisible access to enterprise cloud applications.
```
{% endstep %}

{% step %}
To deliver frictionless user onboarding, architects designed synchronous orchestration pipelines that interacted sequentially with external SaaS providers and internal relational databases. The security posture incorrectly assumed that local database transactions provided universal atomicity. Developers utilized standard, framework-level error handling to catch unhandled exceptions, implicitly trusting that returning an HTTP 500 voided the entire request. The attacker exploited this assumption by deliberately sabotaging the final step of the execution chain. By submitting a payload that violated a strict, secondary database constraint, the attacker forced the system to generate an unhandled exception _after_ the external API calls had succeeded. The global error handler successfully aborted the local transaction, inadvertently masking the creation of the external resources. This partial-commit failure allowed the attacker to spawn untracked, fully provisioned "Ghost Accounts" in external cloud environments, entirely evading local enterprise audit and billing mechanisms
{% endstep %}
{% endstepper %}

***

#### Information Disclosure via Deferred Execution Stream Bleeding

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on data-heavy endpoints, bulk export features, or administrative grids that return massive arrays of JSON objects (e.g., exporting user logs, downloading massive compliance reports)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Deferred Execution" or "Streaming" architecture. To prevent Out-Of-Memory (OOM) crashes when an API returns 100,000 database rows, modern backend frameworks abandon in-memory lists (e.g., `List<User>`). Instead, they return an asynchronous generator or reactive stream (e.g., `IAsyncEnumerable`, `Flux`, `Stream`, or generic Iterators)
{% endstep %}

{% step %}
Investigate the Serialization pipeline. When a controller returns a deferred stream, the web framework's JSON serializer takes over. It begins writing the HTTP response body to the client's TCP socket chunk-by-chunk _while_ the database query is still actively executing and yielding rows
{% endstep %}

{% step %}
Analyze the Global Exception Handler (`@ControllerAdvice`, `UseExceptionHandler`). Standard error handling middleware operates as a wrapper _around_ the controller. If an exception occurs, the middleware catches it, scrubs the sensitive stack trace, changes the HTTP status code to 500, and returns a safe `{"error": "Internal Server Error"}` JSON object
{% endstep %}

{% step %}
Discover the architectural contradiction: If an exception occurs _during_ a deferred execution stream, the HTTP `200 OK` headers have _already been flushed_ to the client, and half of the JSON array has already been written to the socket. The Global Exception Handler cannot catch this error or change the status code, because the HTTP response has already begun
{% endstep %}

{% step %}
Observe the Framework's safety fallback: To avoid dropping the TCP connection abruptly (which breaks client-side parsers and triggers infinite retry storms in Load Balancers), the underlying JSON serializer catches the unhandled inline exception. It forcefully terminates the JSON array and explicitly serializes the raw `Exception` object directly into the trailing bytes of the HTTP response stream
{% endstep %}

{% step %}
Understand the impact: Because this inline serialization completely bypasses the Global Exception Handler, the raw exception dumps highly classified data—such as SQL syntax, internal connection strings, or the memory state of the database row that caused the crash
{% endstep %}

{% step %}
Formulate the Stream Bleeding payload. You must construct a request that successfully returns the first few valid rows, but deliberately triggers a database-level or mapping-level exception on a subsequent row
{% endstep %}

{% step %}
Target dynamic sorting, filtering, or calculation parameters (e.g., submitting a filter that causes a Division-By-Zero, a Regex timeout, or a spatial data parsing failure on specific records)
{% endstep %}

{% step %}
Authenticate to the application and trigger the bulk export endpoint
{% endstep %}

{% step %}
The application opens the stream, flushes the HTTP 200 OK headers, and begins yielding the first few valid JSON objects to your browser
{% endstep %}

{% step %}
The database engine evaluates your poisoned filter against the 10th row. The database throws a fatal `ArithmeticException` or `SqlException`
{% endstep %}

{% step %}
The exception violently bubbles up through the deferred iterator into the active JSON serializer. Bypassing all security middleware, the serializer catches the raw exception, appends the plaintext stack trace and database metadata into the open HTTP socket, and closes the connection. The attacker views the partially malformed JSON response, extracting the bleeding internal infrastructure secrets

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:public\s+async\s+IAsyncEnumerable<[^>]+>\s+\w+\s*\(|await\s+foreach\s*\(|yield\s+return\s+|AsAsyncEnumerable\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:public\s+Flux<[^>]+>\s+\w+\s*\(|public\s+Mono<[^>]+>\s+\w+\s*\(|Flux\.fromStream\s*\(|Flux\.generate\s*\(|Flux\.create\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:yield\s+return\b|yield\s+\$[A-Za-z_][A-Za-z0-9_]*|Generator\s*<|LazyCollection::make\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:\.cursor\(\)\.pipe\(JSONStream\.stringify\(\)\)|Readable\.from\s*\(|stream\.pipeline\s*\(|for\s+await\s*\(|res\.write\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
public\s+async\s+IAsyncEnumerable<.*>\s+\w+|yield\s+return
```
{% endtab %}

{% tab title="Java" %}
```regexp
public\s+Flux<.*>\s+\w+|Flux\.fromStream|Flux\.generate
```
{% endtab %}

{% tab title="PHP" %}
```regexp
yield\s+return|yield\s+\$
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\.cursor\(\)\.pipe\(JSONStream\.stringify\(\)\)|Readable\.from|res\.write
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/compliance/export")]
public async IAsyncEnumerable<AuditRecord> ExportAuditLogs([FromQuery] string customFilter)
{
    // [1]
    // [2]
    // Deferred execution. The database query evaluates row-by-row.
    // The HTTP response begins flushing to the client immediately.
    var records = _dbContext.AuditLogs
        .FromSqlRaw($"SELECT * FROM AuditLogs WHERE {customFilter}") // Simplified for brevity
        .AsAsyncEnumerable();

    await foreach (var record in records)
    {
        // [3]
        // [4]
        // If the 10th record causes a database exception (e.g., invalid cast or arithmetic overflow triggered by the filter),
        // the exception is thrown HERE, while the System.Text.Json serializer is actively writing to the socket.
        yield return record;
    }
}

// Global Exception Handler (Startup.cs)
// app.UseExceptionHandler(err => err.Run(async context => { 
//      // THIS BLOCK IS NEVER REACHED FOR INLINE STREAM ERRORS 
//      await context.Response.WriteAsync("Safe Error"); 
// }));
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class ComplianceExportController {

    @Autowired
    private AuditRepository auditRepo;

    @GetMapping(value = "/api/v1/compliance/export", produces = MediaType.APPLICATION_NDJSON_VALUE)
    public Flux<AuditRecord> exportAuditLogs(@RequestParam String customFilter) {
        // [1]
        // [2]
        // Spring WebFlux reactive stream. Returns 200 OK instantly and streams data.
        return auditRepo.findWithCustomFilter(customFilter)
            .map(record -> {
                // [3]
                // [4]
                // If map logic or the underlying DB cursor throws an exception mid-stream,
                // the global @ControllerAdvice CANNOT alter the response.
                // WebFlux's default behavior appends the raw exception message to the NDJSON stream to close it safely.
                return processRecord(record);
            });
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ComplianceExportController extends Controller
{
    public function exportAuditLogs(Request $request)
    {
        // [1]
        // [2]
        $customFilter = $request->query('customFilter');
        
        return response()->streamJson(function () use ($customFilter) {
            $cursor = DB::table('audit_logs')->whereRaw($customFilter)->cursor();
            
            // [3]
            // [4]
            foreach ($cursor as $record) {
                // If PDO throws an exception on row 50, it occurs during iteration.
                // The global App\Exceptions\Handler is bypassed because headers are already sent.
                // PHP violently outputs the fatal error stack trace directly into the active chunk.
                yield $record;
            }
        });
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const JSONStream = require('JSONStream');

router.get('/api/v1/compliance/export', (req, res) => {
    // [1]
    // [2]
    res.setHeader('Content-Type', 'application/json');
    res.status(200); // Headers are flushed

    // [3]
    // [4]
    // Streams directly from MongoDB to the HTTP Response via JSONStream
    AuditLog.find({ $where: req.query.customFilter })
        .cursor()
        .on('error', err => {
            // Because headers are sent, the developer writes the error to the stream to avoid a hanging socket.
            // This bypasses the Express global error handler `app.use((err, req, res, next) => {...})`.
            res.write(JSON.stringify({ fatal_error: err.stack }));
            res.end();
        })
        .pipe(JSONStream.stringify())
        .pipe(res);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture handles massive dataset exports by utilizing deferred execution models (Streaming/Generators) to completely eliminate server-side RAM exhaustion, \[2] The web framework binds the database cursor directly to the HTTP response serializer. As the database yields a row, the serializer encodes it and flushes it over the TCP socket, \[3] Enterprise security relies entirely on centralized Global Exception Handlers to scrub sensitive internal stack traces and SQL syntax before returning 500 errors to the user, \[4] The protocol limitation execution sink. Global Exception Handlers operate as request wrappers; they cannot alter the HTTP response if the `200 OK` headers and partial body have already been flushed. When the attacker induces an exception _during_ the database iteration phase, the exception violently interrupts the active serializer. To prevent network deadlocks, the native stream handlers catch the exception and append the raw, unredacted error payload directly into the trailing bytes of the HTTP stream, silently bypassing all application-layer data sanitization mechanisms

```http
// 1. Attacker interacts with a bulk export API that streams data via chunked encoding.
// 2. Attacker crafts a custom sorting or filtering parameter designed to succeed on the first few rows, 
//    but trigger an arithmetic database exception on a subsequent row.

GET /api/v1/compliance/export?customFilter=1/(CAST(Id AS INT)-5)>0 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <user_token>

// 3. The API Gateway receives the request. The Backend establishes the DB cursor and returns HTTP 200 OK.
// 4. The Backend serializer begins streaming the JSON array to the client.

HTTP/1.1 200 OK
Content-Type: application/json
Transfer-Encoding: chunked

[
  {"Id": "1", "Data": "Safe"},
  {"Id": "2", "Data": "Safe"},
  {"Id": "3", "Data": "Safe"},
  {"Id": "4", "Data": "Safe"},

// 5. The DB cursor reaches Id=5. The SQL execution evaluates 1/(5-5). 
// 6. The database throws a DivideByZeroException.
// 7. The deferred stream crashes. The Global Error Handler is bypassed.
// 8. The native serializer catches the error and dumps the plaintext stack trace to close the JSON array.

  {"fatal_stream_exception": "System.Data.SqlClient.SqlException (0x80131904): Divide by zero error encountered. Server: internal-sql-cluster-prodb.database.windows.net. User: svc_compliance_prod_rw. StackTrace: at Microsoft.EntityFrameworkCore.Query..."}
]
```
{% endstep %}

{% step %}
To safely transmit hundreds of thousands of database records without invoking crippling Out-Of-Memory exceptions, backend architects implemented deferred execution pipelines. This optimization bound the database cursor directly to the active HTTP response stream. The enterprise security posture erroneously assumed that the centralized Global Exception Middleware provided absolute, universal sanitization of all application errors. The developers fundamentally overlooked the mechanics of the HTTP protocol: once response headers are flushed, wrapper middleware cannot mutate the payload. The attacker exploited this temporal flaw by supplying input that successfully hydrated the initial objects but deterministically crashed the database engine mid-stream. The resulting unhandled exception tore through the deferred iteration context, landing directly in the native stream writer. Bypassing all centralized scrubbing logic, the framework violently flushed the raw stack traces, database topologies, and internal network strings directly into the client's browser, transforming a simple computational error into a massive internal infrastructure disclosure
{% endstep %}
{% endstepper %}

***



## Cheat Sheet
