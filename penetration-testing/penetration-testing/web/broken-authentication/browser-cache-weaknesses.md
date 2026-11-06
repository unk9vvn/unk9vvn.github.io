# Browser Cache Weaknesses

## Check List

## Methodology

### Black Box

#### History Exposure

{% stepper %}
{% step %}
Go to any page that displays sensitive data like Login Success Page
{% endstep %}

{% step %}
Enter or trigger sensitive information, Enter password And Submit or Load the Page
{% endstep %}

{% step %}
Click Logout, Confirm redirected to login page
{% endstep %}

{% step %}
If the previous page with sensitive data reloads, History Exposure Confirmed
{% endstep %}
{% endstepper %}

***

#### Browser Cache Manually

{% stepper %}
{% step %}
If you are using Chrome browser, go to `chrome://cache` in the URL (For FireFox Browser `about:cache`)
{% endstep %}

{% step %}
Search for target domain
{% endstep %}

{% step %}
If sensitive page is cached, Cache Exposure Confirmed
{% endstep %}
{% endstepper %}

***

#### **Cache Deception**

{% stepper %}
{% step %}
Log in to the target site and complete the authentication process using
{% endstep %}

{% step %}
Go to the final paths that return sensitive information, such as `/profile`, `/dashboard`, `/my-account`, `/settings`, `/username`, and then capture the request using the Burp Suite tool.
{% endstep %}

{% step %}
When you receive a request for a sensitive path that captures information using the Burp suite tool, add an extension to the end of this path, like this

```hurl
https://dashboard.target.com/my-profile/username/.css
```
{% endstep %}

{% step %}
Check if the HTTP response status is 200 and the response body contains `dynamic/user`-specific content your username, email, profile data, instead of a real CSS file
{% endstep %}

{% step %}
If caching headers are present, open the same URL (`/my-profile/username/.css`) in a private/incognito window or different browser (logged out) and confirm the response still returns your private profile data
{% endstep %}
{% endstepper %}

***

### White Box

####

{% stepper %}
{% step %}
Map the entire system using Burp Suite and identify all sensitive pages, including Login, Logout, Profile, Change Password, Account Settings, Admin Panel, Payment Pages, sensitive APIs, and pages containing confidential information
{% endstep %}

{% step %}
Locate Controllers or Endpoints that display sensitive user information after authentication and determine whether Cache-Control, Pragma, and Expires headers are configured to prevent response caching

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(Authorize|HttpGet|HttpPost)[\s\S]{0,200}(Profile|Account|UserInfo|Payment|Admin|Settings|Export|Download)[\s\S]{0,400}(return\s+(View|Ok|File))[\s\S]{0,300}(Cache-Control|Pragma|Expires|no-store|no-cache)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@GetMapping|@PostMapping|@RequestMapping)[\s\S]{0,200}(profile|account|user|payment|admin|settings|export|download)[\s\S]{0,400}(return|ResponseEntity)[\s\S]{0,300}(Cache-Control|Pragma|Expires|no-cache|no-store)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(header\s*\()|(\$_SESSION|\$_GET|\$_POST)[\s\S]{0,300}(profile|account|user|payment|admin|settings|export|download)[\s\S]{0,400}(Cache-Control|Pragma|Expires|no-cache|no-store)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(app\.get|router\.get|app\.post|router\.post)[\s\S]{0,200}(profile|account|user|payment|admin|settings|export|download)[\s\S]{0,400}(res\.setHeader|setHeader|res\.header|Cache-Control|no-store|no-cache)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
(Authorize|HttpGet|HttpPost).{0,200}(Profile|Account|UserInfo|Payment|Admin|Settings|Export|Download).{0,400}(return\s+(View|Ok|File)).{0,300}(Cache-Control|Pragma|Expires|no-store|no-cache)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@GetMapping|@PostMapping|@RequestMapping).{0,200}(profile|account|user|payment|admin|settings|export|download).{0,400}(return|ResponseEntity).{0,300}(Cache-Control|Pragma|Expires|no-cache|no-store)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\s*\(|\$_SESSION|\$_GET|\$_POST.{0,300}(profile|account|user|payment|admin|settings|export|download).{0,400}(Cache-Control|Pragma|Expires|no-cache|no-store)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(app\.get|router\.get|app\.post|router\.post).{0,200}(profile|account|user|payment|admin|settings|export|download).{0,400}(res\.setHeader|setHeader|res\.header|Cache-Control|no-store|no-cache)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[Authorize]
[HttpGet]
public IActionResult Profile()
{
    var user = GetCurrentUser();

    return View(user);
}

```
{% endtab %}

{% tab title="Java" %}
```java
@Authorize
@GetMapping
public Object Profile()
{
    User user = GetCurrentUser();

    return View(user);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[Authorize]
#[HttpGet]
public function Profile()
{
    $user = GetCurrentUser();

    return $this->View($user);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function Profile(request, response)
{
    const user = GetCurrentUser();

    return View(user);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then review the response generation logic and determine whether the application explicitly disables caching

{% tabs %}
{% tab title="C#" %}
```csharp
[Authorize]
public IActionResult Account()
{
    Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    Response.Headers["Pragma"] = "no-cache";
    Response.Headers["Expires"] = "0";

    return View();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Authorize
public Object Account()
{
    response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    response.setHeader("Pragma", "no-cache");
    response.setHeader("Expires", "0");

    return View();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[Authorize]
public function Account()
{
    header("Cache-Control: no-store, no-cache, must-revalidate");
    header("Pragma: no-cache");
    header("Expires: 0");

    return $this->View();
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function Account(request, response)
{
    response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    response.setHeader("Pragma", "no-cache");
    response.setHeader("Expires", "0");

    return View();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Search the source code for Middleware, Filters, or Attributes responsible for cache control and determine whether they are applied consistently across all sensitive pages

{% tabs %}
{% tab title="C#" %}
```csharp
public class NoCacheAttribute : ActionFilterAttribute
{
    public override void OnResultExecuting(ResultExecutingContext context)
    {
        context.HttpContext.Response.Headers["Cache-Control"] =
            "no-store, no-cache, must-revalidate";
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class NoCacheAttribute extends ActionFilterAttribute
{
    @Override
    public void onResultExecuting(ResultExecutingContext context)
    {
        context.getHttpContext().getResponse().setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        );
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class NoCacheAttribute extends ActionFilterAttribute
{
    public function OnResultExecuting(ResultExecutingContext $context)
    {
        $context->HttpContext->Response->Headers["Cache-Control"] =
            "no-store, no-cache, must-revalidate";
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
class NoCacheAttribute
{
    onResultExecuting(context)
    {
        context.httpContext.response.setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        );
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify pages that display sensitive data such as tokens, session identifiers, API keys, personal information, or financial data, and determine whether their responses can be cached

{% tabs %}
{% tab title="C#" %}
```csharp
[Authorize]
[HttpGet]
public IActionResult UserInfo()
{
    return Ok(new
    {
        Username = User.Identity.Name,
        ApiKey = "xxxxxxxxxxxxxxxx",
        Email = "user@example.com"
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Authorize
@GetMapping
public Object UserInfo()
{
    return Ok(Map.of(
        "Username", User.getIdentity().getName(),
        "ApiKey", "xxxxxxxxxxxxxxxx",
        "Email", "user@example.com"
    ));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[Authorize]
#[HttpGet]
public function UserInfo()
{
    return Ok([
        "Username" => User::Identity()->Name,
        "ApiKey" => "xxxxxxxxxxxxxxxx",
        "Email" => "user@example.com"
    ]);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function UserInfo(request, response)
{
    return Ok({
        Username: User.Identity.Name,
        ApiKey: "xxxxxxxxxxxxxxxx",
        Email: "user@example.com"
    });
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then review file download, export, report, and PDF generator endpoints and determine whether their responses are stored in browser or proxy caches

{% tabs %}
{% tab title="C#" %}
```csharp
[Authorize]
[HttpGet]
public IActionResult ExportReport()
{
    byte[] report = GenerateReport();

    return File(
        report,
        "application/pdf",
        "report.pdf"
    );
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Authorize
@GetMapping
public Object ExportReport()
{
    byte[] report = GenerateReport();

    return File(
        report,
        "application/pdf",
        "report.pdf"
    );
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[Authorize]
#[HttpGet]
public function ExportReport()
{
    $report = GenerateReport();

    return File(
        $report,
        "application/pdf",
        "report.pdf"
    );
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function ExportReport(request, response)
{
    const report = GenerateReport();

    return File(
        report,
        "application/pdf",
        "report.pdf"
    );
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In the logout logic, determine whether sensitive pages can still be accessed via the browser back button after logout

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost]
public IActionResult Logout()
{
    HttpContext.SignOutAsync();

    return RedirectToAction("Login");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping
public Object Logout()
{
    HttpContext.signOutAsync();

    return RedirectToAction("Login");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost]
public function Logout()
{
    $this->HttpContext->SignOutAsync();

    return $this->RedirectToAction("Login");
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function Logout(request, response)
{
    HttpContext.signOutAsync();

    return RedirectToAction("Login");
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Inspect HTTP responses and verify whether the following headers are present for sensitive pages:

```http
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Expires: 0
```
{% endstep %}

{% step %}
After authentication, access sensitive pages, then log out and use the browser back button, history, proxy cache, or browser cache to determine whether sensitive information remains accessible without re-authentication
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
