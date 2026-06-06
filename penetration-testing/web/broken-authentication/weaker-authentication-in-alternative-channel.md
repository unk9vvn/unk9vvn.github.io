# Weaker Authentication in Alternative Channel

## Check List

## Methodology

### Black Box

#### SSO Misconfiguration

{% stepper %}
{% step %}
Create a legal organization with SSO enabled and verify successful user login (take a baseline)
{% endstep %}

{% step %}
Extract and record the exact entityId (or `issuer/client_id`) value
{% endstep %}

{% step %}
Create a second test organization and record the same value with a minor invisible change (a trailing space or a case change)
{% endstep %}

{% step %}
Set up a separate key/config for the second organization so that it is completely independent
{% endstep %}

{% step %}
Wait for the settings to propagate to the system
{% endstep %}

{% step %}
Log in with the main organization user via SSO
{% endstep %}

{% step %}
Check that authentication at the IdP is successful, but which organization is the user provisioned to
{% endstep %}

{% step %}
If the user is deleted or is a new user, rerun the login test and check the assignment behavior
{% endstep %}

{% step %}
If the user is transferred to the wrong organization or a global error occurs, a mismatch between the Authentication and Provisioning phases is confirmed\\
{% endstep %}
{% endstepper %}

***

#### TLS Misconfiguration

{% stepper %}
{% step %}
Log in to the target site's authentication page
{% endstep %}

{% step %}
Then, on the target site's authentication page, look for sub-communication channels for authentication (such as `sso` or `auth` subdomains)
{% endstep %}

{% step %}
Look for the `sitemap.xml` file and within this file look for communication channels for authentication
{% endstep %}

{% step %}
Then, after checking the subdomain, enter the subdomain and check whether it uses `http` or `https`
{% endstep %}

{% step %}
If a subdomain that used HTTP for authentication subchannels has a TLS Misconfiguration vulnerability
{% endstep %}
{% endstepper %}

***

### White Box

#### Authentication Bypass via Trust Boundary Violation in Client Certificate Authentication

{% stepper %}
{% step %}
Identify authentication mechanisms based on Client Certificates, Reverse Proxies, or TLS Locate the middleware or component responsible for authentication
{% endstep %}

{% step %}
Identify all variables that determine the certificate authentication status

{% tabs %}
{% tab title="Python" %}
```python
request.META.get('SSL_CLIENT_VERIFY')

request.META.get('HTTP_X_SSL_CLIENT_VERIFY')
```
{% endtab %}

{% tab title="C#" %}
```c#
request.Headers["SSL_CLIENT_VERIFY"]

request.Headers["HTTP_X_SSL_CLIENT_VERIFY"]
```
{% endtab %}

{% tab title="Java" %}
```java
request.getHeader("SSL_CLIENT_VERIFY");

request.getHeader("HTTP_X_SSL_CLIENT_VERIFY");
```
{% endtab %}

{% tab title="PHP" %}
```php
$_SERVER['SSL_CLIENT_VERIFY'];

$_SERVER['HTTP_X_SSL_CLIENT_VERIFY'];
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
request.headers['ssl_client_verify'];

request.headers['http_x_ssl_client_verify'];
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether a security-sensitive value is obtained from multiple sources If both Headers and Environment Variables are supported, examine their processing priority
{% endstep %}

{% step %}
Determine whether Header values can directly satisfy the authentication condition

{% tabs %}
{% tab title="Python" %}
```python
@classmethod 
def contains_certificate(cls, request) -> None: 
    return ( 
        request.META.get('SSL_CLIENT_VERIFY') == 'SUCCESS' 
        or request.META.get('HTTP_X_SSL_CLIENT_VERIFY') == 'SUCCESS' 
    )
```
{% endtab %}

{% tab title="C#" %}
```c#
public static bool ContainsCertificate(HttpRequest request)
{
    return (
        request.Headers["SSL_CLIENT_VERIFY"] == "SUCCESS"
        ||
        request.Headers["HTTP_X_SSL_CLIENT_VERIFY"] == "SUCCESS"
    );
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static boolean containsCertificate(HttpServletRequest request)
{
    return (
        "SUCCESS".equals(request.getHeader("SSL_CLIENT_VERIFY"))
        ||
        "SUCCESS".equals(request.getHeader("HTTP_X_SSL_CLIENT_VERIFY"))
    );
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function containsCertificate($request): bool
{
    return (
        $request->server->get('SSL_CLIENT_VERIFY') == 'SUCCESS'
        ||
        $request->server->get('HTTP_X_SSL_CLIENT_VERIFY') == 'SUCCESS'
    );
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
static containsCertificate(request)
{
    return (
        request.headers['ssl_client_verify'] == 'SUCCESS'
        ||
        request.headers['http_x_ssl_client_verify'] == 'SUCCESS'
    );
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify all Headers related to authentication, user identity, or certificates Locate the code path responsible for receiving the user certificate
{% endstep %}

{% step %}
Determine whether certificate data is obtained from Headers or exclusively from the TLS layer. Examine certificate processing priority and determine whether a Header can replace a real certificate

{% tabs %}
{% tab title="Python" %}
```python
# BRANCH 1: Checked FIRST - user-controllable HTTP header 
if 'HTTP_X_SSL_CLIENT_CERT' in request.META: 
    client_cert = urllib.parse.unquote(request.META['HTTP_X_SSL_CLIENT_CERT']) 
    certificates = client_cert.split('-----END CERTIFICATE-----') 
    # Parses into client_cert, int_cert, root_cert 

# BRANCH 2: Trusted mod_ssl WSGI vars (only used if header absent) 
else: 
    client_cert = request.META.get('SSL_CLIENT_CERT') 
    int_cert = request.META.get('SSL_CLIENT_CERT_CHAIN_0') 
    # ...
```
{% endtab %}

{% tab title="C#" %}
```c#
// BRANCH 1: Checked FIRST - user-controllable HTTP header
if (request.Headers.ContainsKey("HTTP_X_SSL_CLIENT_CERT"))
{
    string client_cert = System.Net.WebUtility.UrlDecode(
        request.Headers["HTTP_X_SSL_CLIENT_CERT"]
    );

    string[] certificates = client_cert.Split("-----END CERTIFICATE-----");

    // Parses into client_cert, int_cert, root_cert
}

// BRANCH 2: Trusted mod_ssl WSGI vars (only used if header absent)
else
{
    string client_cert = request.Headers["SSL_CLIENT_CERT"];
    string int_cert = request.Headers["SSL_CLIENT_CERT_CHAIN_0"];
    // ...
}
```
{% endtab %}

{% tab title="Java" %}
```java
// BRANCH 1: Checked FIRST - user-controllable HTTP header
if (request.getHeader("HTTP_X_SSL_CLIENT_CERT") != null)
{
    String client_cert = java.net.URLDecoder.decode(
        request.getHeader("HTTP_X_SSL_CLIENT_CERT"),
        java.nio.charset.StandardCharsets.UTF_8
    );

    String[] certificates = client_cert.split("-----END CERTIFICATE-----");

    // Parses into client_cert, int_cert, root_cert
}

// BRANCH 2: Trusted mod_ssl WSGI vars (only used if header absent)
else
{
    String client_cert = request.getHeader("SSL_CLIENT_CERT");
    String int_cert = request.getHeader("SSL_CLIENT_CERT_CHAIN_0");
    // ...
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// BRANCH 1: Checked FIRST - user-controllable HTTP header
if (isset($_SERVER['HTTP_X_SSL_CLIENT_CERT']))
{
    $client_cert = urldecode($_SERVER['HTTP_X_SSL_CLIENT_CERT']);

    $certificates = explode(
        '-----END CERTIFICATE-----',
        $client_cert
    );

    // Parses into client_cert, int_cert, root_cert
}

// BRANCH 2: Trusted mod_ssl WSGI vars (only used if header absent)
else
{
    $client_cert = $_SERVER['SSL_CLIENT_CERT'];
    $int_cert = $_SERVER['SSL_CLIENT_CERT_CHAIN_0'];
    // ...
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// BRANCH 1: Checked FIRST - user-controllable HTTP header
if ('http_x_ssl_client_cert' in request.headers)
{
    let client_cert = decodeURIComponent(
        request.headers['http_x_ssl_client_cert']
    );

    let certificates = client_cert.split(
        '-----END CERTIFICATE-----'
    );

    // Parses into client_cert, int_cert, root_cert
}

// BRANCH 2: Trusted mod_ssl WSGI vars (only used if header absent)
else
{
    let client_cert = request.headers['ssl_client_cert'];
    let int_cert = request.headers['ssl_client_cert_chain_0'];
    // ...
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify the certificate validation function, Determine whether certificate validation is based on string comparison or actual X.509 validation
{% endstep %}

{% step %}
Extract all comparisons involving Subject, Issuer, CN, and DN

{% tabs %}
{% tab title="Python" %}
```python
int_cert.subject == root_ca.subject

client_cert.issuer == int_cert.issuer
```
{% endtab %}

{% tab title="C#" %}
```c#
int_cert.Subject == root_ca.Subject

client_cert.Issuer == int_cert.Issuer
```
{% endtab %}

{% tab title="Java" %}
```java
int_cert.getSubject().equals(root_ca.getSubject());

client_cert.getIssuer().equals(int_cert.getIssuer());
```
{% endtab %}

{% tab title="PHP" %}
```php
$int_cert->subject == $root_ca->subject;

$client_cert->issuer == $int_cert->issuer;
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
int_cert.subject == root_ca.subject

client_cert.issuer == int_cert.issuer
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether any signature verification is performed on the certificate chain, Determine whether validation can be bypassed by creating a self-signed certificate with arbitrary Subject/Issuer values
{% endstep %}

{% step %}
Locate the function that creates the user identity after validation

{% tabs %}
{% tab title="Python" %}
```python
set_user(...)
```
{% endtab %}

{% tab title="C#" %}
```c#
SetUser(...);
```
{% endtab %}

{% tab title="Java" %}
```java
setUser(...);
```
{% endtab %}

{% tab title="PHP" %}
```php
set_user(...);
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
setUser(...);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Examine the authorization flow after authentication, Determine whether the identifier extracted from the certificate is used in database lookups
{% endstep %}

{% step %}
Review Apache, Nginx, or Reverse Proxy configuration files and Identify the configuration responsible for forwarding TLS information to the application

```apache
SSLVerifyClient optional

SSLOptions +StdEnvVars +ExportCertData
```
{% endstep %}

{% step %}
Determine whether security-related Headers are removed before reaching the application

```apache
RequestHeader unset X-SSL-CLIENT-VERIFY

RequestHeader unset X-SSL-CLIENT-CERT
```
{% endstep %}

{% step %}
If the Headers are not removed, assess the possibility of Header Spoofing
{% endstep %}

{% step %}
Finally, determine whether authenticated routes can be accessed through Header Spoofing combined with a forged certificate
{% endstep %}
{% endstepper %}

***

#### Authentication Bypass via Unsigned SSO Cookie Trust Leading to Arbitrary Account Takeover

{% stepper %}
{% step %}
Identify all Authentication and Authorization endpoints responsible for issuing tokens
{% endstep %}

{% step %}
Locate methods that obtain user identity information from alternative sources (Cookies, Headers, Sessions, or Query Parameters)
{% endstep %}

{% step %}
Identify all Cookies that are directly used in the authentication process
{% endstep %}

{% step %}
Trace the Cookie processing flow from the point of receipt to the point of use

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("GetTokenSSO")]
public IActionResult GetTokenSSO()
{
   var ssoCookieData = HttpContext.Request.Cookies["sso_ctx"];

   if(String.IsNullOrEmpty(ssoCookieData)) {
      return Unauthorized();
   }
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("GetTokenSSO")
public Object GetTokenSSO()
{
   String ssoCookieData = request.getCookies()["sso_ctx"];

   if (ssoCookieData == null || ssoCookieData.isEmpty()) {
      return Unauthorized();
   }
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpGet("GetTokenSSO")]
public function GetTokenSSO()
{
   $ssoCookieData = $_COOKIE["sso_ctx"];

   if (empty($ssoCookieData)) {
      return $this->Unauthorized();
   }
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.get("GetTokenSSO", (request, response) => {
   const ssoCookieData = request.cookies["sso_ctx"];

   if (!ssoCookieData) {
      return Unauthorized();
   }
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether the Cookie value undergoes security validation before use (such as Signature Validation, HMAC verification, Encryption Verification, etc.)
{% endstep %}

{% step %}
Review all Decode and Deserialize operations performed on Cookie data

{% tabs %}
{% tab title="C#" %}
```csharp
var ssoCookieDecoded = Convert.FromBase64String(ssoCookieData);
var ssoCookie = JObject.Parse(System.Text.Encoding.UTF8.GetString(ssoCookieDecoded));

var userId = ssoCookie["auth_user"];
if(userId == null) {
   return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
byte[] ssoCookieDecoded = java.util.Base64.getDecoder().decode(ssoCookieData);
String json = new String(ssoCookieDecoded, java.nio.charset.StandardCharsets.UTF_8);

JSONObject ssoCookie = new JSONObject(json);

Object userId = ssoCookie.opt("auth_user");
if(userId == null) {
   return Unauthorized();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
$ssoCookieDecoded = base64_decode($ssoCookieData);
$ssoCookie = json_decode($ssoCookieDecoded, true);

$userId = $ssoCookie["auth_user"];
if($userId == null) {
   return Unauthorized();
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const ssoCookieDecoded = Buffer.from(ssoCookieData, "base64");
const ssoCookie = JSON.parse(ssoCookieDecoded.toString("utf8"));

const userId = ssoCookie["auth_user"];
if (userId == null) {
   return Unauthorized();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether the decoded data is directly converted into an application-usable object
{% endstep %}

{% step %}
Identify all security-sensitive fields extracted from the Cookie

{% tabs %}
{% tab title="C#" %}
```csharp
var userId = ssoCookie["auth_user"];
```
{% endtab %}

{% tab title="Java" %}
```java
Object userId = ssoCookie.opt("auth_user");
```
{% endtab %}

{% tab title="PHP" %}
```php
$userId = $ssoCookie["auth_user"];
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const userId = ssoCookie["auth_user"];
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether values extracted from the Cookie are used as user identity without validation
{% endstep %}

{% step %}
Trace the use of the user identifier through database operations

{% tabs %}
{% tab title="C#" %}
```csharp
var user = _context.Users.
    Where(b => b.ID == userId.ToObject<int>()).
    FirstOrDefault();

if(user == null) {
   return NotFound();
}
```
{% endtab %}

{% tab title="Java" %}
```java
User user = _context.Users.stream()
    .filter(b -> b.getID() == userId.toObject(Integer.class))
    .findFirst()
    .orElse(null);

if(user == null) {
   return NotFound();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
$user = $this->_context->Users
    ->where(fn($b) => $b->ID == $userId->toObject('int'))
    ->first();

if($user == null) {
   return NotFound();
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const user = _context.Users
    .filter(b => b.ID == userId.toObject(Number))
    .shift();

if(user == null) {
   return NotFound();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether the application verifies the ownership or authenticity of the user identifier before loading the user record
{% endstep %}

{% step %}
Identify all locations that generate a new token or session after the user is retrieved

{% tabs %}
{% tab title="C#" %}
```csharp
var response = new Models.AuthorizationResponse();
response.role = user.role;
response.accessToken = user.createAccessToken();

return Ok(response);
```
{% endtab %}

{% tab title="Java" %}
```java
AuthorizationResponse response = new AuthorizationResponse();
response.role = user.getRole();
response.accessToken = user.createAccessToken();

return Ok(response);
```
{% endtab %}

{% tab title="PHP" %}
```php
$response = new Models\AuthorizationResponse();
$response->role = $user->role;
$response->accessToken = $user->createAccessToken();

return Ok($response);
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const response = new Models.AuthorizationResponse();
response.role = user.role;
response.accessToken = user.createAccessToken();

return Ok(response);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether Access Token generation is based solely on the user identifier or requires additional identity validation
{% endstep %}

{% step %}
Modify identity-related fields inside the Cookie in a controlled manner and determine whether it is possible to obtain tokens for other users
{% endstep %}

{% step %}
Determine whether changing the user identifier in the Cookie results in Account Takeover, Privilege Escalation, or Authentication Bypass
{% endstep %}

{% step %}
Review all SSO flows and determine whether the trust boundary between the Identity Provider and the application is correctly implemented
{% endstep %}

{% step %}
Determine whether SSO Cookies have a digital signature, expiration validation, session binding, or anti-forgery mechanisms
{% endstep %}

{% step %}
If Base64-encoded Cookies, JSON Cookies, or other user-readable structures are present, treat them as high-priority candidates for Authentication Bypass analysis
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
