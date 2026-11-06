# Broken Authentication

## Check List

## Methodology

### Black Box

#### Missing Authentication on Sensitive API Endpoint

{% stepper %}
{% step %}
Do not authenticate to the application
{% endstep %}

{% step %}
Directly access a protected API endpoint

```http
GET /api/user/profile HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response returns user data without requiring Authorization header, authentication enforcement is missing
{% endstep %}

{% step %}
Test with random token

```http
GET /api/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer randomtoken123
```
{% endstep %}

{% step %}
If endpoint responds with valid user data or default user context, authentication validation is broken
{% endstep %}

{% step %}
If no 401/403 response is returned for unauthenticated access, Broken Authentication is confirmed
{% endstep %}
{% endstepper %}

***

#### Predictable JWT Secret

{% stepper %}
{% step %}
Login and capture JWT

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
```
{% endstep %}

{% step %}
Decode JWT payload, Identify algorithm

```json
{"alg":"HS256"}
```
{% endstep %}

{% step %}
Attempt to brute-force weak secret using jwt tool
{% endstep %}

{% step %}
If secret is guessable (`"secret", "123456"`), generate new token with modified payload:

```json
{"user":"admin","role":"admin"}
```
{% endstep %}

{% step %}
Sign token with discovered secret, Replace Authorization header

```http
Authorization: Bearer forged_admin_token
```
{% endstep %}

{% step %}
Access privileged endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Authorization: Bearer forged_admin_token
```
{% endstep %}

{% step %}
If access is granted, JWT authentication mechanism is broken
{% endstep %}

{% step %}
If server accepts forged token, Broken Authentication vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Session Fixation via API

{% stepper %}
{% step %}
Access login endpoint and intercept response

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"user1","password":"Pass123"}
```
{% endstep %}

{% step %}
Observe returned session token

```http
Set-Cookie: session=abc123; Path=/; HttpOnly
```
{% endstep %}

{% step %}
Before login, manually set session cookie

```http
Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
Perform login, If server reuses provided session ID after authentication

```http
Set-Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
Then session fixation is possible, Use fixed session in another browser

```http
GET /api/user/profile HTTP/1.1
Host: target.com
Cookie: session=fixedsession123
```
{% endstep %}

{% step %}
If authenticated access is granted, session management is flawed
{% endstep %}

{% step %}
If session ID is not regenerated upon login, Broken Authentication vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Asymmetric Cryptographic Downgrade via JWT Algorithm Confusion (RS256 to HS256)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on stateless authentication architectures utilizing JSON Web Tokens (JWT) for session management across distributed microservices
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's JWT validation middleware
{% endstep %}

{% step %}
Identify the "Asymmetric Signature" architecture. To allow dozens of decentralized microservices to verify the JWT without continuously querying a centralized Identity Provider (IdP), the enterprise signs the JWT using an asymmetric RSA keypair (`RS256`). The private key is held securely by the Auth Service. The public key is distributed globally to all microservices (e.g., via a `.pem` file or a JWKS endpoint)
{% endstep %}

{% step %}
Investigate the underlying JWT library configuration. When a microservice receives the token, it calls a verification function (e.g., `jwt.verify(token, publicKey)`)
{% endstep %}

{% step %}
Analyze the cryptographic trust boundary. The JWT specification explicitly includes the `alg` (Algorithm) header within the unencrypted header payload. This header dictates the cryptographic algorithm the client _claims_ was used to sign the token
{% endstep %}

{% step %}
Discover the fatal validation dynamic: If the developer fails to explicitly hardcode the expected algorithm during the `verify()` call, the underlying JWT library reads the unverified `alg` header from the token and dynamically adjusts its verification engine to match
{% endstep %}

{% step %}
Understand the vulnerability: The HMAC algorithm (`HS256`) is symmetric, utilizing a single shared secret for both signing and verifying. If an attacker modifies the JWT header to `alg: "HS256"`, the vulnerable library treats the provided `publicKey` string not as an asymmetric verification key, but as the _symmetric HMAC secret_
{% endstep %}

{% step %}
Formulate the Algorithm Confusion payload. You must obtain the enterprise's public key (often easily accessible via public `/jwks.json` endpoints, public repositories, or extracted from client-side mobile applications)
{% endstep %}

{% step %}
Extract an existing, valid JWT. Base64-decode the header and payload
{% endstep %}

{% step %}
Modify the header: `{"alg": "HS256", "typ": "JWT"}`
{% endstep %}

{% step %}
Modify the payload: Change the `sub` or `role` claims to target a high-privilege administrator (e.g., `{"role": "SuperAdmin", "sub": "admin@enterprise.tld"}`)
{% endstep %}

{% step %}
Generate the forged HMAC signature. Re-encode the modified header and payload. Sign the resulting string using standard HMAC-SHA256, but provide the exact physical string of the enterprise's _Public Key_ (including PEM headers and newlines) as the symmetric signing secret
{% endstep %}

{% step %}
Submit the forged JWT to a protected microservice
{% endstep %}

{% step %}
The microservice's JWT library extracts `alg: "HS256"`. It switches to symmetric verification mode. It hashes the token using its local copy of the public key as the secret. The hashes match perfectly. The library mathematically guarantees the token is authentic, granting the attacker complete, forged administrative access across the stateless enterprise mesh

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
public class AuthenticationMiddleware
{

    public async Task<Response> Handle(
        Request request,
        Func<Request, Task<Response>> next
    )
    {

        string token =
            request.BearerToken();


        string publicKey =
            File.ReadAllText(
                "storage/keys/public.pem"
            );


        try
        {

            // [1]
            // [2]
            // Older versions of php-jwt or careless implementations omit the allowed algorithms array.
            // [3]
            // [4]

            var decoded =
                new JwtSecurityTokenHandler()
                    .ReadJwtToken(token);


            request.Attributes.Add(
                "user",
                decoded
            );


            return await next(request);

        }
        catch (Exception e)
        {

            throw new UnauthorizedAccessException(
                "Unauthorized"
            );
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class AuthenticationMiddleware {

    public Response handle(Request request, Closure next) {

        String token = request.bearerToken();

        String publicKey =
                Files.readString(
                    Paths.get("storage/keys/public.pem")
                );


        try {

            // [1]
            // [2]
            // Older versions of php-jwt or careless implementations omit the allowed algorithms array.
            // [3]
            // [4]

            DecodedJWT decoded =
                    JWT.decode(token);


            request.getAttributes()
                    .add("user", decoded);


            return next.handle(request);

        } catch (Exception e) {

            throw new UnauthorizedException(
                    "Unauthorized"
            );
        }
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
use Firebase\JWT\JWT;

class AuthenticationMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();
        $publicKey = file_get_contents(storage_path('keys/public.pem'));

        try {
            // [1]
            // [2]
            // Older versions of php-jwt or careless implementations omit the allowed algorithms array.
            // [3]
            // [4]
            $decoded = JWT::decode($token, $publicKey);
            
            $request->attributes->add(['user' => $decoded]);
            return $next($request);
        } catch (\Exception $e) {
            abort(401, 'Unauthorized');
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Public key distributed to the microservice
const publicKey = fs.readFileSync('./keys/public.pem', 'utf8');

class AuthenticationMiddleware {
    static async verifyToken(req, res, next) {
        let token = req.headers.authorization?.split(' ')[1];

        try {
            // [1]
            // [2]
            // [3]
            // [4]
            // Fatal Omission: The developer failed to pass { algorithms: ['RS256'] }.
            // The library defaults to trusting the 'alg' header provided by the attacker.
            // If alg=HS256, this function treats 'publicKey' as the HMAC secret password.
            let decoded = jwt.verify(token, publicKey); 
            
            req.user = decoded;
            next();
        } catch (err) {
            res.status(401).send("Unauthorized");
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture achieves high scalability by replacing stateful database session lookups with cryptographically signed, stateless JSON Web Tokens, \[2] The enterprise enforces asymmetric cryptography (`RS256`), ensuring that while any microservice can mathematically _verify_ a token using the public key, only the centralized Identity Provider can _mint_ tokens using the private key, \[3] Developers utilize standardized, open-source JWT libraries to abstract the complex mathematics of signature verification, \[4] The execution sink. Standard JWT specifications intermingle routing metadata (`alg`) with the cryptographic payload. The developer erroneously delegates the algorithm selection process to the unverified metadata provided by the incoming token. By physically extracting the application's public key (often considered non-sensitive data) and manually switching the algorithm directive to `HS256`, the attacker forces the backend library into symmetric execution mode. The backend evaluates the attacker's HMAC signature using the public key string as the shared secret password, perfectly verifying the cryptographic constraints and transforming publicly accessible data into a master authentication skeleton key

```http
// 1. Attacker queries the enterprise's public JWKS or configuration endpoint.
GET /.well-known/jwks.json HTTP/1.1
Host: api.enterprise.tld

// 2. Attacker extracts the Public Key string.
// -----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMI...

// 3. Attacker intercepts their own low-privilege JWT.
// Header: {"alg":"RS256","typ":"JWT"} 
// Payload: {"sub":"user@evil.com","role":"Guest"}

// 4. Attacker modifies the Base64 Header and Payload locally:
// New Header: {"alg":"HS256","typ":"JWT"}
// New Payload: {"sub":"admin@enterprise.tld","role":"SuperAdmin"}

// 5. Attacker executes an HMAC-SHA256 hash using the Public Key PEM string as the secret.
// signature = HMAC-SHA256(Base64(NewHeader) + "." + Base64(NewPayload), PUBLIC_KEY_PEM_STRING)

// 6. Attacker constructs the final JWT and targets a restricted microservice.
POST /api/v1/admin/users/delete HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzd...[FORGED_SIGNATURE]
Content-Type: application/json

{"userId": "991"}

// 7. The microservice's JWT library reads "HS256", loads the public key, hashes the payload, 
//    and compares it to the forged signature. They match.
// 8. The backend authorizes the destructive action based on the spoofed SuperAdmin claim.
```
{% endstep %}

{% step %}
To eliminate database latency in distributed service meshes, architects deployed stateless JWT validation utilizing asymmetric cryptography. This design separated the highly privileged signing authority (Identity Provider) from the decentralized validation nodes (microservices). The security failure emerged from an over-reliance on dynamic specification parsing within the underlying cryptographic libraries. Developers assumed that supplying an asymmetric public key inherently forced the library to execute asymmetric validation. They failed to recognize that the JWT standard allows the client to explicitly dictate the evaluation algorithm. The attacker exploited this dynamic typing by altering the unencrypted token header to a symmetric algorithm (`HS256`). By weaponizing the mathematically un-restricted, widely distributed public key as a symmetric shared secret, the attacker fundamentally inverted the cryptographic architecture. The backend library blindly honored the attacker's algorithm override, mathematically verifying the forged payload and establishing systemic, unmitigated administrative access across the entire platform
{% endstep %}
{% endstepper %}

***

#### Identity Provider (IdP) Account Hijacking via Stateless OAuth state Decoupling

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise Single Page Applications (SPAs) or APIs that support modern authentication protocols like OAuth 2.0 or OpenID Connect (OIDC) via third-party Identity Providers (e.g., "Sign in with Google", "Login with Microsoft")
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the initiation (`/auth/login`) and callback (`/auth/callback`) phases of the OAuth flow
{% endstep %}

{% step %}
Identify the "Stateless Gateway" architecture. To maximize horizontal scaling, the API Gateway does not utilize server-side sessions
{% endstep %}

{% step %}
Investigate the OAuth Initiation Phase. When a user clicks "Sign in with Google," the frontend (or backend) generates a redirect URL pointing to Google's authorization endpoint. This URL includes a `state` parameter (e.g., `state=abc123xyz`) designed to prevent Cross-Site Request Forgery (CSRF)
{% endstep %}

{% step %}
Analyze the Callback Phase binding. When Google redirects the user back to the enterprise application (e.g., `[https://api.enterprise.tld/callback?code=4/P7q7W91...&state=abc123xyz](https://api.enterprise.tld/callback?code=4/P7q7W91...&state=abc123xyz)`), the backend must verify the `state` parameter
{% endstep %}

{% step %}
Discover the fatal Context Decoupling: Because the backend is stateless and lacks server-side sessions, it cannot securely store the `state` parameter generated during the initiation phase. To bypass this, the developer verifies that the `state` parameter matches a specific structural format (e.g., ensuring it is a valid UUID or matching it against a loosely signed JWT), but utterly fails to bind the `state` parameter to the _specific, unauthenticated browser session_ that initiated the flow
{% endstep %}

{% step %}
Understand the Session Forgery (Login CSRF) vulnerability: If the `state` parameter is not cryptographically tethered to the victim's physical browser (e.g., via a secure, HTTP-Only pre-auth cookie), the OAuth callback URL becomes a fully transportable, weaponized login vector
{% endstep %}

{% step %}
Formulate the Pre-Authentication Account Hijacking payload. You must initiate an OAuth flow against your own Identity Provider account, halt the sequence, and trick a victim into consuming the callback
{% endstep %}

{% step %}
Navigate to the enterprise application and click "Sign in with Google.
{% endstep %}

{% step %}
The application redirects you to Google. Authenticate using an attacker-controlled Google account (`attacker@gmail.com`)
{% endstep %}

{% step %}
Google redirects your browser back to the enterprise callback URL containing the authorization `code` and the `state` parameter
{% endstep %}

{% step %}
CRITICA&#x4C;_:_ Intercept this HTTP GET request using Burp Suite and completely drop it. Do not let the enterprise backend process the callback. You now possess a highly perishable, unconsumed OAuth callback URL tethered to your attacker identity
{% endstep %}

{% step %}
Distribute this raw callback URL (e.g., `[https://api.enterprise.tld/callback?code=...&state=](https://api.enterprise.tld/callback?code=...&state=)...`) to an authenticated enterprise victim via phishing, a hidden iframe, or a `<img src="...">` tag inside a trusted forum
{% endstep %}

{% step %}
The victim's browser executes the HTTP GET request. The enterprise backend receives the `code` and `state`. Lacking pre-auth session binding, the backend evaluates the `state` as structurally valid. It exchanges the `code` with Google, retrieves the identity profile (`attacker@gmail.com`), and forcefully logs the victim's browser into the attacker's enterprise account
{% endstep %}

{% step %}
Unaware of the session swap, the victim inputs highly sensitive enterprise data (credit cards, proprietary code) into the application. The attacker logs into the account later and silently extracts the victim's vaulted data

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(public\s+IActionResult\s+Callback\([^\)]+\)\s*\{\s*var\s+token\s*=\s*ExchangeCode)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(public\s+.*\s+callback\([^\)]*code[^\)]*\)\s*\{\s*.*exchangeCode)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(if\s*\(\$request->query\('state'\)\s*==\s*\$stateFromUrl\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(router\.get\(['"]/callback['"],\s*async\s*\(req,\s*res\)\s*=>\s*\{\s*let\s+code\s*=\s*req\.query\.code)(?![^}]*req\.cookies\.pre_auth_state)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"public\s+IActionResult\s+Callback\([^\)]+\)\s*\{\s*var\s+token\s*=\s*ExchangeCode"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"public\s+.*\s+callback\([^\)]*code[^\)]*\)\s*\{\s*.*exchangeCode"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"if\s*\(\\$request->query\('state'\)\s*==\s*\\$stateFromUrl\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"router\.get\(['\"]/callback['\"],\s*async\s*\(req,\s*res\)\s*=>\s*\{\s*let\s+code\s*=\s*req\.query\.code\)(?![^}]*req\.cookies\.pre_auth_state)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/auth/callback")]
public async Task<IActionResult> OAuthCallback([FromQuery] string code, [FromQuery] string state)
{
    // [1]
    // [2]
    if (string.IsNullOrEmpty(state)) return BadRequest("State missing");

    // [3]
    // [4]
    // Validates the structure of the state (e.g., verifying a stateless JWT signature)
    // but fails to map it to a pre-authentication cookie. The callback URL is fully portable.
    if (!_cryptoService.IsStructurallyValidState(state)) return BadRequest("Invalid state structure");

    var idpToken = await _idpClient.ExchangeCodeAsync(code);
    var profile = await _idpClient.GetProfileAsync(idpToken);

    var appToken = _jwtService.GenerateToken(profile.Email);
    
    Response.Cookies.Append("AuthToken", appToken, new CookieOptions { HttpOnly = true });
    return Redirect("/dashboard");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/auth/callback")
public ResponseEntity<?> OAuthCallback(
        @RequestParam String code,
        @RequestParam String state
)
{
    // [1]
    // [2]
    if (state == null || state.isEmpty()) return BadRequest("State missing");

    // [3]
    // [4]
    // Validates the structure of the state (e.g., verifying a stateless JWT signature)
    // but fails to map it to a pre-authentication cookie. The callback URL is fully portable.

    if (!_cryptoService.IsStructurallyValidState(state)) return BadRequest("Invalid state structure");

    var idpToken = _idpClient.ExchangeCodeAsync(code);
    var profile = _idpClient.GetProfileAsync(idpToken);

    var appToken = _jwtService.GenerateToken(profile.Email);

    ResponseCookie cookie =
            ResponseCookie.from("AuthToken", appToken)
                    .httpOnly(true)
                    .build();

    return ResponseEntity
            .status(302)
            .header("Set-Cookie", cookie.toString())
            .header("Location", "/dashboard")
            .build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function OAuthCallback(Request $request)
{
    // [1]
    // [2]
    if (empty($request->query('state'))) return BadRequest("State missing");

    // [3]
    // [4]
    // Validates the structure of the state (e.g., verifying a stateless JWT signature)
    // but fails to map it to a pre-authentication cookie. The callback URL is fully portable.

    if (!$this->cryptoService->IsStructurallyValidState($request->query('state'))) return BadRequest("Invalid state structure");

    $idpToken = $this->idpClient->ExchangeCodeAsync($request->query('code'));
    $profile = $this->idpClient->GetProfileAsync($idpToken);

    $appToken = $this->jwtService->GenerateToken($profile->Email);

    Response::cookie("AuthToken", $appToken, [
        "HttpOnly" => true
    ]);

    return Redirect("/dashboard");
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Stateless OAuth implementation
router.get('/api/v1/auth/login', (req, res) => {
    // Generates a structural UUID, but fails to set an HTTP-Only cookie binding it to the browser.
    const state = crypto.randomUUID(); 
    
    const googleUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=email&state=${state}`;
    res.redirect(googleUrl);
});

router.get('/api/v1/auth/callback', async (req, res) => {
    const code = req.query.code;
    const state = req.query.state;

    // [3]
    // [4]
    // Fatal Flaw: The backend verifies the state is present, but has no mechanism 
    // to verify that THIS specific browser initiated the flow.
    if (!state) return res.status(400).send("Invalid State");

    try {
        // Exchanges the attacker's code, logging the victim into the attacker's account.
        const idpResponse = await axios.post('https://oauth2.googleapis.com/token', {
            code: code,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            redirect_uri: REDIRECT_URI,
            grant_type: 'authorization_code'
        });

        const userInfo = await getGoogleProfile(idpResponse.data.access_token);
        
        // Logs the victim into the application as the attacker
        const sessionJwt = generateEnterpriseToken(userInfo.email);
        res.cookie('session', sessionJwt);
        res.redirect('/dashboard');

    } catch (err) {
        res.status(500).send("Auth Failed");
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application orchestrates federated identity binding via standard OAuth 2.0 or OIDC flows, relying on third-party Identity Providers to assert user identity, \[2] To comply with stateless, cloud-native design principles, the API Gateway actively avoids maintaining server-side session stores, \[3] The architecture implements the OAuth `state` parameter to mitigate CSRF during the callback phase. However, due to the stateless constraints, developers validate the parameter syntactically rather than contextually, \[4] The execution sink. True CSRF protection requires a cryptographic knot tying the execution artifact to the physical execution environment (the browser). By omitting a pre-authentication HTTP-Only cookie, the developers decoupled the callback authorization code from the browser that originated the request. The attacker exploits this mobility by harvesting a pristine, unconsumed callback URL tied to their own malicious identity. By forcing the victim's browser to execute this URL, the backend seamlessly processes the authentication artifact, forcefully overwriting the victim's active session state with the attacker's identity, resulting in stealthy data harvesting via Identity CSRF

```http
// 1. Attacker clicks "Login with Google" on the enterprise site.
// 2. Attacker logs into Google using attacker@evil.com.
// 3. Google redirects the attacker. The attacker uses Burp Suite to intercept and DROP the request:

GET /api/v1/auth/callback?code=4/0AX4XfW...&state=991823-uuid-xyz HTTP/1.1
Host: api.enterprise.tld

// 4. The attacker crafts a phishing email or embeds a hidden <img> tag on an internal enterprise forum:
<img src="https://api.enterprise.tld/api/v1/auth/callback?code=4/0AX4XfW...&state=991823-uuid-xyz" style="display:none;" />

// 5. A victim (Enterprise Employee) views the forum post.
// 6. The victim's browser blindly executes the GET request to the callback URL.
// 7. The enterprise backend receives the request. It finds the `code` and `state`.
// 8. Because there is no pre-auth cookie validation, the backend accepts the request.
// 9. The backend exchanges the code with Google, identifies the user as "attacker@evil.com".
// 10. The backend overwrites the victim's session cookie with the attacker's identity.
// 11. The victim, believing they are still securely logged in, attaches a corporate credit card 
//     to the account to process a payment.
// 12. The attacker logs into attacker@evil.com and extracts the attached credit card data.
```
{% endstep %}

{% step %}
To ensure frictionless horizontal scaling across distributed clusters, infrastructure architects mandated strictly stateless authentication flows. This constraint complicated the management of multi-hop OAuth workflows, prompting developers to adopt synthetic, structure-based validations for the OAuth `state` parameter rather than traditional session-bound cryptography. The security model failed by equating structural integrity with contextual provenance. Developers assumed that receiving a valid authorization code alongside a formatted state parameter mathematically guaranteed the integrity of the login sequence. They overlooked the fundamental transportability of HTTP GET parameters. The attacker weaponized this mobility by initiating a legitimate OAuth flow, capturing the highly ephemeral callback URL, and physically transferring the execution context to the victim's browser. Lacking a pre-authentication binding cookie, the backend obediently processed the transplanted artifact. This architectural gap resulted in a severe Login CSRF vulnerability, forcing the victim into a malicious session state specifically engineered for silent, persistent data harvesting
{% endstep %}
{% endstepper %}

***

#### MFA Circumvention via Execution Context Desynchronization in Polyglot API Gateways

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on zero-trust enterprise perimeters or highly distributed microservice ecosystems employing an API Gateway overlay (e.g., Kong, AWS API Gateway, Apigee) alongside decentralized authorization nodes
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the Multi-Factor Authentication (MFA) step-up flow
{% endstep %}

{% step %}
Identify the "Partial State JWT" architecture. Upon submitting a valid username and password at the `/api/v1/auth/login` endpoint, the Identity Service immediately issues a valid, cryptographically signed JSON Web Token (JWT). However, to enforce MFA, the Identity Service injects a specific claim into the payload: `{"mfa_completed": false}`
{% endstep %}

{% step %}
Investigate the UI Routing logic. The frontend Single Page Application (SPA) reads this claim. Observing `mfa_completed: false`, the SPA refuses to load the main dashboard and forces the user to the `/mfa-verify` screen to input their TOTP code
{% endstep %}

{% step %}
Analyze the backend verification mechanics. When the user submits the correct TOTP code, the Identity Service issues a brand new JWT with the claim `{"mfa_completed": true}`
{% endstep %}

{% step %}
Discover the fatal API Gateway desynchronization: The enterprise ecosystem consists of hundreds of discrete microservices written in different languages (polyglot). To centralize security, the API Gateway is tasked with verifying the JWT signature. The Gateway perfectly validates the cryptographic signature of the token and forwards the request to the downstream microservices
{% endstep %}

{% step %}
Understand the vulnerability: The API Gateway verifies the _authenticity_ of the token, but delegates the _authorization_ (verifying the `mfa_completed` claim) to the individual downstream microservices. Due to organizational fragmentation, several critical microservices (e.g., a legacy billing service or an internal user-management API) simply extract the `user_id` from the decoded token but completely fail to assert `if (token.mfa_completed !== true) throw Error()`
{% endstep %}

{% step %}
Formulate the MFA Bypass payload. You must obtain a primary authentication artifact (e.g., via a compromised password in a data breach or credential stuffing) and bypass the MFA UI to communicate directly with the desynchronized microservices
{% endstep %}

{% step %}
Submit the compromised credentials to `/api/v1/auth/login`
{% endstep %}

{% step %}
The Identity Service verifies the password and returns the partial JWT: `eyJhb... {"sub": "victim", "mfa_completed": false}`
{% endstep %}

{% step %}
The frontend SPA immediately traps you on the MFA input screen. Ignore the UI
{% endstep %}

{% step %}
Extract the partial JWT from the browser's local storage or HTTP response
{% endstep %}

{% step %}
Identify a target microservice endpoint that lacks rigorous internal claim assertion (e.g., `GET /api/v1/billing/payment-methods`)
{% endstep %}

{% step %}
Construct a direct HTTP request to the target endpoint, attaching the partial JWT in the `Authorization` header
{% endstep %}

{% step %}
The API Gateway intercepts the request. It mathematically verifies the JWT signature against the IdP's public key. The signature is flawless. The Gateway proxies the request to the billing microservice
{% endstep %}

{% step %}
The billing microservice extracts the `sub` claim and queries the database. Because it omits the `mfa_completed` assertion, it processes the request and returns the highly classified data. You have successfully bypassed the enterprise's primary MFA perimeter by exploiting an authorization boundary desynchronization across the microservice mesh

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(JwtSecurityTokenHandler\.ValidateToken\(.*\)\s*;\s*var\s+userId\s*=\s*principal\.FindFirst\(.*\)\.Value)(?![^}]*mfa_completed)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(Jwts\.parser\(\)\.parseClaimsJws\(.*\)\s*;\s*String\s+userId\s*=\s*claims\.getSubject\(\))(?![^}]*mfa_completed)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$decoded\s*=\s*JWT::decode.*\s*\$userId\s*=\s*\$decoded->sub)(?![^}]*mfa_completed)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(jwt\.verify\(token.*\);\s*let\s+userId\s*=\s*decoded\.sub;)(?![^}]*mfa_completed)|(req\.user\s*=\s*decoded)(?![^}]*req\.user\.mfa_completed)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"JwtSecurityTokenHandler\.ValidateToken\(.*\)\s*;\s*var\s+userId\s*=\s*principal\.FindFirst\(.*\)\.Value(?![^}]*mfa_completed)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"Jwts\.parser\(\)\.parseClaimsJws\(.*\)\s*;\s*String\s+userId\s*=\s*claims\.getSubject\(\)(?![^}]*mfa_completed)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"\\$decoded\s*=\s*JWT::decode.*\s*\\$userId\s*=\s*\\$decoded->sub(?![^}]*mfa_completed)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"jwt\.verify\(token.*\);\s*let\s+userId\s*=\s*decoded\.sub;(?![^}]*mfa_completed)|req\.user\s*=\s*decoded(?![^}]*req\.user\.mfa_completed)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[Authorize] // Relies on the global JWT bearer configuration
[HttpGet("/api/v1/billing/methods")]
public async Task<IActionResult> GetBillingMethods()
{
    // [1]
    // [2]
    // The [Authorize] attribute only guarantees the JWT was signed by the IdP and hasn't expired.
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    // [3]
    // [4]
    // The developer forgot to implement policy-based authorization enforcing the MFA claim.
    // E.g., [Authorize(Policy = "MfaCompleted")]
    
    var data = await _billingService.GetByUserIdAsync(userId);
    return Ok(data);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
@RequestMapping("/api/v1/billing")
public class BillingController {

    @Autowired
    private BillingRepository billingRepository;

    @GetMapping("/methods")
    public ResponseEntity<?> getMethods(Principal principal) {
        // [1]
        // [2]
        // The Principal object is instantiated successfully because the API Gateway
        // validated the token signature and injected the user ID into the header.
        
        // [3]
        // [4]
        // The service executes business logic entirely ignorant of the 'mfa_completed: false'
        // state residing within the original token payload.
        List<BillingMethod> methods = billingRepository.findByUsername(principal.getName());
        return ResponseEntity.ok(methods);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
@RestController
@RequestMapping("/api/v1/billing")
class BillingController
{

    private $billingRepository;


    public function __construct($billingRepository)
    {
        $this->billingRepository = $billingRepository;
    }


    @GetMapping("/methods")
    public function getMethods($principal)
    {
        // [1]
        // [2]
        // The Principal object is instantiated successfully because the API Gateway
        // validated the token signature and injected the user ID into the header.
        

        // [3]
        // [4]
        // The service executes business logic entirely ignorant of the 'mfa_completed: false'
        // state residing within the original token payload.

        $methods = $this->billingRepository
            ->findByUsername(
                $principal->getName()
            );

        return ResponseEntity::ok($methods);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// The API Gateway already verified the signature. This middleware runs 
// on the individual backend microservice to extract business logic context.
class ServiceAuthorizationMiddleware {
    static extractUser(req, res, next) {
        let token = req.headers.authorization.split(' ')[1];
        
        // Decodes without verifying signature (Gateway handled it)
        let decoded = jwt.decode(token); 

        // [3]
        // [4]
        // Fatal Omission: The microservice blindly assumes that possession of a validly 
        // signed token mathematically implies full authentication. It fails to evaluate 
        // the multi-factor state machine claim injected by the Identity Provider.
        if (decoded && decoded.sub) {
            req.userId = decoded.sub;
            next();
        } else {
            res.status(401).send("Invalid Token Structure");
        }
    }
}

router.get('/api/v1/billing/methods', ServiceAuthorizationMiddleware.extractUser, async (req, res) => {
    // Exfiltrates sensitive data using a token that failed MFA validation
    let methods = await Billing.getMethodsForUser(req.userId);
    res.json(methods);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The enterprise deploys a decentralized, polyglot microservice architecture governed by a centralized API Gateway to handle TLS termination and cryptographic signature verification, \[2] To support dynamic step-up authentication and complex frontend routing, the Identity Provider adopts a "Partial State" pattern, issuing structurally valid JWTs upon password verification but restricting authority via internal metadata claims (`mfa_completed: false`), \[3] The architecture fundamentally relies on the frontend SPA to act as a security enforcer, trapping the user in the MFA UI until the step-up flow produces an authorized token, \[4] The execution sink. Developers decoupled the cryptographic verification of the token from its contextual business authorization. Because the API Gateway only evaluated the mathematical validity of the signature, the responsibility for enforcing the MFA state machine devolved to hundreds of individual microservices. Inevitably, disparate engineering teams omitted the granular claim assertions required to validate the partial state. The attacker exploits this fragmentation by extracting the partially authenticated JWT, bypassing the superficial UI barriers, and communicating directly with the desynchronized microservices. The backend, implicitly trusting the Gateway's signature verification, processes the attacker's requests without enforcing the organizational MFA mandate, yielding complete Account Takeover via valid password compromise alone

```http
// 1. Attacker obtains a victim's password via credential stuffing.
// 2. Attacker invokes the primary login endpoint.

POST /api/v1/auth/login HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{"username": "victim@enterprise.com", "password": "CompromisedPassword123!"}

// 3. The Identity Provider verifies the password and returns the partial JWT.
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token": "eyJhb...[sub: victim, mfa_completed: false]...[VALID_SIGNATURE]"
}

// 4. The SPA traps the attacker on the MFA screen. 
// 5. The attacker ignores the SPA, extracts the token, and bypasses the UI.
// 6. The attacker targets a downstream microservice known to lack granular claim assertion.

GET /api/v1/billing/methods HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer eyJhb...[sub: victim, mfa_completed: false]...[VALID_SIGNATURE]

// 7. The API Gateway intercepts the request. It checks the signature using the public key.
//    Signature is VALID. The Gateway strips TLS and forwards the request to the Billing Service.
// 8. The Billing Service decodes the token, extracts the 'sub' claim, and queries the database.
// 9. The Billing Service ignores the 'mfa_completed' flag.

HTTP/1.1 200 OK
Content-Type: application/json

[
  {"card_type": "Visa", "last_four": "4242", "fingerprint": "xyz123"}
]
```
{% endstep %}

{% step %}
To orchestrate dynamic authentication workflows without relying on stateful server-side sessions, platform architects adopted a Partial State JWT issuance model. This design decoupled initial identity verification from multi-factor authorization, relying on embedded token claims to signal the user's progression through the authentication state machine. The security model collapsed due to an architectural mismatch between centralized gateway verification and decentralized service authorization. Backend developers erroneously equated the API Gateway's cryptographic signature validation with absolute authentication completeness. Consequently, individual microservice controllers uniformly extracted identity metadata from the token without explicitly asserting the requisite multi-factor claims. The attacker weaponized this desynchronization by harvesting the cryptographically valid, partially authenticated token generated during a basic password compromise. By utilizing this token to directly invoke the desynchronized downstream APIs, the attacker entirely bypassed the organizational MFA perimeter, exploiting the microservices' blind trust in the Gateway's incomplete cryptographic vetting
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
