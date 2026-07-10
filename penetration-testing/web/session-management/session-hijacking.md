# Session Hijacking

## Check List

## Methodology

### Black Box

#### Session Fixation – Authentication Bypass

{% stepper %}
{% step %}
There is only one account in different browsers chrome and firefox
{% endstep %}

{% step %}
For example www.example.com I will sign up for one account that is the Chrome browser I filled the details first and last name, password, and confirm password, city, country, phone number, etc and log in now
{% endstep %}

{% step %}
www.example.com same account is created in the firefox browser and I filled the details the same as chrome browser just like as a first and last name, password, and confirm password, city, country, phone number, etc and log in now.
{% endstep %}

{% step %}
Both login into different browsers and I will change for a one-account that is chrome browser that is first and last name, phone number, and change password
{% endstep %}

{% step %}
Changed successfully in a chrome browser and just log out then moves another browser that is firefox and just Refresh the page and I have seen now changes successfully and it's like a **boom**
{% endstep %}
{% endstepper %}

***

### White Box

#### Session Hijacking via CDN Cache-Key Collision on Thundering-Herd Rehydration Endpoints

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
Investigate the "Thundering Herd" mitigation strategy. In massive enterprise deployments, thousands of employees open their laptops simultaneously at 9:00 AM. Their Single Page Applications (SPAs) immediately fire a `GET /api/v1/auth/session` request to rehydrate the user's profile, permissions, and obtain a short-lived access token
{% endstep %}

{% step %}
Identify the architectural optimization: To prevent this daily spike from melting the database, DevOps and Backend engineers coordinate to offload this specific endpoint to the enterprise Content Delivery Network (CDN) or Edge Cache (e.g., Cloudflare, Akamai, Varnish)
{% endstep %}

{% step %}
In the decompiled backend code, locate the authentication rehydration controller. Observe that the developer explicitly sets aggressive caching headers (e.g., `Cache-Control: public, max-age=10`) on the response
{% endstep %}

{% step %}
Understand the fatal engineering assumption: The backend developer assumes the CDN will automatically shard the cache based on the uEvaluate the reality of the Edge configuration: To maximize cache hit ratios and mitigate DDoS attacks, enterprise CDNs are frequently configured to aggressively strip `Cookie` and `Authorization` headers from the Cache-Key calculation, normalizing requests purely by the URL pathser's `Cookie` or `Authorization` header
{% endstep %}

{% step %}
Evaluate the reality of the Edge configuration: To maximize cache hit ratios and mitigate DDoS attacks, enterprise CDNs are frequently configured to aggressively strip `Cookie` and `Authorization` headers from the Cache-Key calculation, normalizing requests purely by the URL path
{% endstep %}

{% step %}
Because the application uses a RESTful, parameter-less path (`/api/v1/auth/session`) for all users, the Cache-Key is identical globally
{% endstep %}

{% step %}
Send a continuous stream of unauthenticated or low-privilege requests to the `/api/v1/auth/session` endpoint using a tool like Burp Intruder (e.g., 5 requests per second)
{% endstep %}

{% step %}
Wait for an Enterprise Administrator to log in and bootstrap their SPA
{% endstep %}

{% step %}
The Administrator's browser hits the endpoint. The request penetrates to the backend (a Cache Miss). The backend generates a highly privileged Session Token and returns it with the `Cache-Control: public` header
{% endstep %}

{% step %}
The CDN intercepts the response, caches the Administrator's Session Token, and serves it to all subsequent requests matching the `/api/v1/auth/session` URL for the next 10 seconds
{% endstep %}

{% step %}
Your background polling script receives the `X-Cache: HIT` response containing the Administrator's raw Session Token. Inject this token into your browser to achieve complete Session Hijacking
{% endstep %}

{% step %}
**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ResponseCache(?:Attribute)?\s*\([^)]*Location\s*=\s*ResponseCacheLocation\.Any[^)]*\)|ResponseCache(?:Attribute)?\s*\([^)]*NoStore\s*=\s*false[^)]*\)|Response\.Headers\s*\[\s*"Cache-Control"\s*\]\s*=\s*"[^"]*\bpublic\b[^"]*"|Response\.Headers\.Add\s*\(\s*"Cache-Control"\s*,\s*"[^"]*\bpublic\b[^"]*"|CacheControlHeaderValue\b[\s\S]{0,150}?(?:Public|MaxAge)|cacheControl\.Public\s*=\s*true|CacheControlHeaderValue\s*\.\s*Parse)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:CacheControl\b[\s\S]{0,100}?cachePublic\s*\(|CacheControl\b[\s\S]{0,100}?maxAge\s*\(|ResponseEntity\b[\s\S]{0,150}?cacheControl\s*\(|response\.setHeader\s*\(\s*"Cache-Control"\s*,\s*"[^"]*\bpublic\b|HttpHeaders\.CACHE_CONTROL\b|setCacheControl\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:header\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|response\s*\(\)->header\s*\(\s*['"]Cache-Control['"]|Response::header\s*\(\s*['"]Cache-Control['"]|Cache-Control:\s*public|cache.headers\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:res\.set\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|res\.header\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|res\.setHeader\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|CacheControl\b[\s\S]{0,100}?maxAge\b[\s\S]{0,100}?public|helmet\b[\s\S]{0,100}?cacheControl|cacheControl\s*:\s*\{)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ResponseCache(?:Attribute)?\s*\([^)]*Location\s*=\s*ResponseCacheLocation\.Any[^)]*\)|ResponseCache(?:Attribute)?\s*\([^)]*NoStore\s*=\s*false[^)]*\)|Response\.Headers\s*\[\s*"Cache-Control"\s*\]\s*=\s*"[^"]*\bpublic\b[^"]*"|Response\.Headers\.Add\s*\(\s*"Cache-Control"\s*,\s*"[^"]*\bpublic\b[^"]*"|CacheControlHeaderValue.*(?:Public|MaxAge)|cacheControl\.Public\s*=\s*true|CacheControlHeaderValue\s*\.\s*Parse)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:CacheControl.*cachePublic\s*\(|CacheControl.*maxAge\s*\(|ResponseEntity.*cacheControl\s*\(|response\.setHeader\s*\(\s*"Cache-Control"\s*,\s*"[^"]*\bpublic\b|HttpHeaders\.CACHE_CONTROL\b|setCacheControl\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:header\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|response\s*\(\)->header\s*\(\s*['"]Cache-Control['"]|Response::header\s*\(\s*['"]Cache-Control['"]|Cache-Control:\s*public|cache.headers\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:res\.set\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|res\.header\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|res\.setHeader\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b|CacheControl.*maxAge.*public|helmet.*cacheControl|cacheControl\s*:\s*\{)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[ApiController]
[Route("api/v1/auth")]
public class AuthRehydrationController : ControllerBase
{
    private readonly ISessionService _sessionService;

    // [1]
    // [2]
    [HttpGet("session")]
    [ResponseCache(Duration = 10, Location = ResponseCacheLocation.Any)]
    public async Task<IActionResult> GetActiveSession()
    {
        var currentToken = Request.Cookies["EnterpriseAuth"];
        
        // [3]
        var sessionState = await _sessionService.RehydrateContextAsync(currentToken);
        
        // [4]
        return Ok(new {
            UserId = sessionState.UserId,
            Role = sessionState.Role,
            ActiveSessionToken = sessionState.MintFreshAccessToken()
        });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
@RequestMapping("/api/v1/auth")
public class AuthRehydrationController {

    @Autowired
    private SessionService sessionService;

    // [1]
    // [2]
    @GetMapping("/session")
    public ResponseEntity<?> getActiveSession(@CookieValue("EnterpriseAuth") String currentToken) {
        
        // [3]
        SessionState sessionState = sessionService.rehydrateContext(currentToken);
        
        // [4]
        return ResponseEntity.ok()
            .cacheControl(CacheControl.maxAge(10, TimeUnit.SECONDS).cachePublic())
            .body(Map.of(
                "UserId", sessionState.getUserId(),
                "Role", sessionState.getRole(),
                "ActiveSessionToken", sessionState.mintFreshAccessToken()
            ));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class AuthRehydrationController extends Controller
{
    public function getActiveSession(Request $request)
    {
        $currentToken = $request->cookie('EnterpriseAuth');
        
        // [3]
        $sessionState = $this->sessionService->rehydrateContext($currentToken);
        
        // [4]
        $response = [
            'UserId' => $sessionState->userId,
            'Role' => $sessionState->role,
            'ActiveSessionToken' => $sessionState->mintFreshAccessToken()
        ];

        // [1]
        // [2]
        return response()->json($response)
                         ->header('Cache-Control', 'public, max-age=10');
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/auth/session', async (req, res) => {
    let currentToken = req.cookies['EnterpriseAuth'];
    
    // [3]
    let sessionState = await sessionService.rehydrateContext(currentToken);
    
    // [1]
    // [2]
    res.set('Cache-Control', 'public, max-age=10');
    
    // [4]
    res.json({
        UserId: sessionState.userId,
        Role: sessionState.role,
        ActiveSessionToken: sessionState.mintFreshAccessToken()
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To mitigate the database impact of a "Thundering Herd" when thousands of client, SPAs bootstrap simultaneously, the developer configures the endpoint to be cacheable,\[2] The catastrophic trust boundary failure: The developer explicitly sets the cache directive to `public`. This tells upstream CDNs and Edge Proxies that the response is completely generic and can be served to _any_ user requesting the exact same URL, \[3] The backend processes the legitimate user's identity and permissions, \[4] The application returns a highly sensitive payload containing a freshly minted `ActiveSessionToken`. Because the cache is public and the CDN normalizes the Cache-Key purely on the `/api/v1/auth/session` URL path, the first user to hit this endpoint traps their active session token inside the Edge Cache, immediately leaking it to the next user who requests the URL

```http
// 1. The Attacker establishes a continuous polling loop.
GET /api/v1/auth/session HTTP/1.1
Host: api.enterprise.tld
Cookie: EnterpriseAuth=ATTACKER_LOW_PRIV_TOKEN

// 2. An Administrator logs in. Their browser requests the session data.
// The CDN caches the Admin's response.
// 3. The Attacker's next automated poll hits the CDN.
HTTP/1.1 200 OK
Cache-Control: public, max-age=10
X-Cache: HIT
Age: 2

{
    "UserId": "admin-991",
    "Role": "SuperAdministrator",
    "ActiveSessionToken": "eyJhbGciOiJSUz...[ADMIN_SESSION_TOKEN]..."
}

// 4. The Attacker injects the leaked token into their local storage and hijacks the session.
```
{% endstep %}

{% step %}
The architectural optimization successfully protected the backend database from traffic spikes, but failed to account for how external CDNs calculate Cache-Keys. By explicitly marking the session rehydration payload as `public`, the backend authorized the Edge layer to ignore the caller's unique HTTP context. When the administrator requested their session, the CDN captured the JSON response containing the newly minted session token. When the attacker polled the exact same URI one second later, the CDN returned the cached administrative payload. The attacker achieves complete Session Hijacking without performing any Man-in-the-Middle attacks or executing Cross-Site Scripting
{% endstep %}
{% endstepper %}

***

#### Session Hijacking via Pub/Sub Channel Prediction in Cross-Device Handoff

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Pay special attention to endpoints interacting with WebSockets or Server-Sent Events (SSE)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Investigate the OAuth2 "Device Authorization Grant" (RFC 8628) or proprietary Cross-Device Login flows. Enterprise users frequently authenticate smart TVs, CLI tools, or headless servers by navigating to a URL (e.g., `enterprise.tld/link`) on their mobile phone and entering a 6-to-8 character alphanumeric `DeviceCode`
{% endstep %}

{% step %}
Identify the engineering bottleneck: The headless device displaying the code must somehow know when the mobile user completes the authentication. The standard implementation requires the device to continuously HTTP poll the backend every 5 seconds, which introduces massive overhead on the API Gateway at an enterprise scale
{% endstep %}

{% step %}
Discover the optimization: Developers replace the heavy HTTP polling with a lightweight WebSocket or SSE connection. The headless device connects to the real-time hub and subscribes to a specific event channel identified solely by the `DeviceCode`
{% endstep %}

{% step %}
Locate the Pub/Sub dispatch logic in the decompiled authentication controller. Observe what happens when the mobile user successfully approves the login request
{% endstep %}

{% step %}
Verify that the backend immediately mints the final authenticated `SessionToken` and broadcasts it directly over the event bus (e.g., Redis Pub/Sub, SignalR, Socket.io) targeting the specific `DeviceCode` channel
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumed that because the headless device physically displays the `DeviceCode`, only that specific physical client could possibly know the code to subscribe to the WebSocket channel
{% endstep %}

{% step %}
Recognize the flaw: The `DeviceCode` is typically a short, human-readable string (e.g., `A7B9-X21P`) with limited entropy, designed for easy typing. Furthermore, the WebSocket subscription endpoint completely lacks authentication
{% endstep %}

{% step %}
Write an automated script to open thousands of concurrent WebSocket connections to the API Gateway
{% endstep %}

{% step %}
Rapidly subscribe to thousands of sequentially generated or brute-forced `DeviceCode` channels
{% endstep %}

{% step %}
Wait for any legitimate enterprise user globally to attempt a cross-device login
{% endstep %}

{% step %}
When the victim enters their code on their phone and clicks "Approve", the backend broadcasts their freshly minted `SessionToken` to the channel. Because your script is anonymously subscribed to that exact channel, the API Gateway pushes the victim's session token directly to your attacker-controlled WebSocket connection, granting you instant account takeover
{% endstep %}

{% step %}
**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Clients\.(?:Group|Groups?|Client)\s*\(\s*(?:deviceCode|deviceId|deviceToken|pairingCode|activationCode)\s*\)\.(?:SendAsync|SendCoreAsync)|IHubContext<[^>]+>\.Clients\.(?:Group|Client)\s*\(|HubContext\b[\s\S]{0,150}?(?:SendAsync|SendCoreAsync)|device(?:Code|Id|Token)[\s\S]{0,80}?SendAsync|Group\s*\(\s*["']device[_-])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:convertAndSend\s*\(\s*["']/topic/(?:device|pairing|activation)[^"]*|SimpMessagingTemplate\b[\s\S]{0,150}?convertAndSend|messagingTemplate\.convertAndSend|sendToUser\s*\(|device(?:Code|Id|Token)[\s\S]{0,80}?convertAndSend|@SendTo\b|@SendToUser\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Redis::publish\s*\(\s*["'](?:device_auth_|device_|pairing_|activation_)[^"']*|publish\s*\(\s*["'](?:device_auth_|device_|pairing_|activation_)|Predis\b[\s\S]{0,150}?publish|broadcast\s*\(|event\s*\(|device(?:Code|Id|Token)[\s\S]{0,80}?publish)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:io\.to\s*\(\s*`?(?:device|pairing|activation)[^`'"]*`?\s*\)\.(?:emit|volatile\.emit)|socket\.to\s*\(|io\.in\s*\(|redis\.publish\s*\(\s*["'](?:device_auth_|device_|pairing_|activation_)|device(?:Code|Id|Token)[\s\S]{0,80}?(?:emit|publish)|ws\.send\s*\([^)]*device)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Clients\.(?:Group|Groups?|Client)\s*\(\s*(?:deviceCode|deviceId|deviceToken|pairingCode|activationCode)\s*\)\.(?:SendAsync|SendCoreAsync)|IHubContext<[^>]+>\.Clients\.(?:Group|Client)\s*\(|HubContext.*(?:SendAsync|SendCoreAsync)|device(?:Code|Id|Token).*SendAsync|Group\s*\(\s*["']device[_-])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:convertAndSend\s*\(\s*["']/topic/(?:device|pairing|activation)[^"]*|SimpMessagingTemplate.*convertAndSend|messagingTemplate\.convertAndSend|sendToUser\s*\(|device(?:Code|Id|Token).*convertAndSend|@SendTo\b|@SendToUser\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Redis::publish\s*\(\s*["'](?:device_auth_|device_|pairing_|activation_)[^"']*|publish\s*\(\s*["'](?:device_auth_|device_|pairing_|activation_)|Predis.*publish|broadcast\s*\(|event\s*\(|device(?:Code|Id|Token).*publish)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:io\.to\s*\(\s*`?(?:device|pairing|activation)[^`'"]*`?\s*\)\.(?:emit|volatile\.emit)|socket\.to\s*\(|io\.in\s*\(|redis\.publish\s*\(\s*["'](?:device_auth_|device_|pairing_|activation_)|device(?:Code|Id|Token).*(?:emit|publish)|ws\.send\s*\([^)]*device)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/device-auth/approve")]
public async Task<IActionResult> ApproveDeviceLogin([FromBody] DeviceApprovalDto request)
{
    // [1]
    var deviceRequest = await _deviceAuthRepo.GetPendingRequestAsync(request.DeviceCode);
    if (deviceRequest == null) return NotFound();

    // [2]
    var sessionToken = _sessionService.GenerateTokenForUser(_currentUser.Id);
    await _deviceAuthRepo.MarkAsApprovedAsync(request.DeviceCode, sessionToken);

    // [3]
    // [4]
    await _hubContext.Clients.Group(request.DeviceCode).SendAsync("AuthenticationCompleted", new {
        Token = sessionToken,
        UserId = _currentUser.Id
    });

    return Ok(new { Message = "Device successfully linked." });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/device-auth/approve")
public ResponseEntity<?> approveDeviceLogin(@RequestBody DeviceApprovalDto request) {
    // [1]
    DeviceRequest deviceRequest = deviceAuthRepo.getPendingRequest(request.getDeviceCode());
    if (deviceRequest == null) return ResponseEntity.notFound().build();

    // [2]
    String sessionToken = sessionService.generateTokenForUser(currentUser.getId());
    deviceAuthRepo.markAsApproved(request.getDeviceCode(), sessionToken);

    // [3]
    // [4]
    Map<String, Object> payload = Map.of(
        "Token", sessionToken,
        "UserId", currentUser.getId()
    );
    messagingTemplate.convertAndSend("/topic/device/" + request.getDeviceCode(), payload);

    return ResponseEntity.ok(Map.of("Message", "Device successfully linked."));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function approveDeviceLogin(Request $request)
{
    // [1]
    $deviceRequest = $this->deviceAuthRepo->getPendingRequest($request->input('device_code'));
    if (!$deviceRequest) return response('Not Found', 404);

    // [2]
    $sessionToken = $this->sessionService->generateTokenForUser($this->currentUser->id);
    $this->deviceAuthRepo->markAsApproved($request->input('device_code'), $sessionToken);

    // [3]
    // [4]
    $payload = json_encode([
        'Token' => $sessionToken,
        'UserId' => $this->currentUser->id
    ]);
    Redis::publish("device_topic_" . $request->input('device_code'), $payload);

    return response()->json(['Message' => 'Device successfully linked.']);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/device-auth/approve', async (req, res) => {
    // [1]
    let deviceRequest = await deviceAuthRepo.getPendingRequest(req.body.deviceCode);
    if (!deviceRequest) return res.status(404).send();

    // [2]
    let sessionToken = sessionService.generateTokenForUser(req.user.id);
    await deviceAuthRepo.markAsApproved(req.body.deviceCode, sessionToken);

    // [3]
    // [4]
    let payload = {
        Token: sessionToken,
        UserId: req.user.id
    };
    io.to(`device_topic_${req.body.deviceCode}`).emit('AuthenticationCompleted', payload);

    res.json({ Message: "Device successfully linked." });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The controller validates the short `DeviceCode` submitted by the authenticated mobile user, \[2] The backend executes the core business logic, upgrading the pending authorization request and generating a powerful, long-lived session token intended for the headless device, \[3] To optimize performance and eliminate HTTP polling latency, the system utilizes a real-time event bus, \[4] The fatal architectural flaw occurs here. The backend blindly broadcasts the raw `SessionToken` to any WebSocket client currently subscribed to the `DeviceCode` group. Because WebSocket channel subscriptions for cross-device flows inherently cannot require authentication (the device isn't logged in yet), the developer relied exclusively on the entropy of the `DeviceCode` as the security boundary. Due to the limited length of the code for human readability, attackers can easily brute-force the subscriptions and passively intercept the broadcasted session token

```http
// 1. Attacker opens a WebSocket connection and subscribes to thousands of brute-forced channels.
// [WebSocket Send]
{"action": "subscribe", "channel": "device_topic_AAAA"}
{"action": "subscribe", "channel": "device_topic_AAAB"}
...
{"action": "subscribe", "channel": "device_topic_X7P9"}

// 2. A legitimate user generates code X7P9 on their Smart TV.
// 3. The user logs into enterprise.tld/link on their phone and approves X7P9.
// 4. The server broadcasts the session token.
// [WebSocket Receive]
{
  "event": "AuthenticationCompleted",
  "data": {
    "Token": "eyJhbGciOiJSUzI1NiI...[VICTIMS_NEW_SESSION_TOKEN]...",
    "UserId": "admin-1199"
  }
}

// 5. Attacker extracts the token from their active WebSocket stream and hijacks the session.
```
{% endstep %}

{% step %}
The architectural decision to optimize the Cross-Device Handoff flow using Real-Time Pub/Sub inadvertently shifted the trust boundary from the secure HTTP request-response cycle to an anonymous broadcast channel. The attacker exploits the lack of authentication on the WebSocket subscription endpoint and the low entropy of the human-readable `DeviceCode`. By subscribing to thousands of potential channels, the attacker intercepts the exact moment a legitimate user approves a login. The backend API Gateway perfectly executes the broadcast logic, pushing the victim's newly minted Session Token directly into the attacker's listening WebSocket connection, resulting in instantaneous, passive Session Hijacking
{% endstep %}
{% endstepper %}

***

#### Session Hijacking via DTO Projection Failure in ORM Eager Loading Graph Serialization

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
Identify if the enterprise platform utilizes a multi-tenant or shared-resource model (e.g., Workspaces, Teams, Projects) where users frequently query the metadata of their peers
{% endstep %}

{% step %}
Investigate the security implementation for concurrent session management. Many enterprise platforms enforce strict policies like "Force Logout All Devices" or "Limit 1 Concurrent Session". To implement this efficiently, developers often store the `ActiveSessionId` or `CurrentJwtSignature` as a standard column directly on the `User` table in the database
{% endstep %}

{% step %}
Analyze the Object Relational Mapping (ORM) architecture. Querying a Workspace and then issuing individual `SELECT` statements for every member of that Workspace causes the infamous "N+1 Query Problem", severely degrading database performance
{% endstep %}

{% step %}
Discover the ORM optimization: To eliminate the N+1 problem, backend engineers utilize "Eager Loading" (e.g., `.Include()` in Entity Framework, `.populate()` in Mongoose, or `@EntityGraph` in Hibernate) to fetch the Workspace and all associated `User` entities in a single, highly optimized SQL `JOIN`
{% endstep %}

{% step %}
Locate the API endpoint that returns Workspace data (e.g., `GET /api/v1/workspaces/current`)
{% endstep %}

{% step %}
Evaluate the Data Transfer Object (DTO) projection pipeline. In rapidly iterating agile teams, developers often skip creating strict DTO classes and mapping fields manually. Instead, they serialize the entire eager-loaded ORM Entity graph directly to JSON and send it to the frontend
{% endstep %}

{% step %}
Authenticate to the platform as a standard, low-privilege employee
{% endstep %}

{% step %}
Navigate to the team dashboard, triggering a request to the `/workspaces/current` endpoint
{% endstep %}

{% step %}
Inspect the raw JSON response in Burp Suite. Expand the `members` array
{% endstep %}

{% step %}
Because the developer failed to implement explicit DTO projection, the JSON serializer recurses through the entire `User` entity for every member of your team. This inadvertently exposes the `ActiveSessionId` column that was added to the entity for security auditing
{% endstep %}

{% step %}
Identify a highly privileged user (e.g., the Workspace Owner or Enterprise Admin) within the `members` array. Extract their `ActiveSessionId` from the JSON payload
{% endstep %}

{% step %}
Inject the extracted session identifier into your browser cookies or authorization headers to seamlessly hijack the administrator's active session

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\.Include\s*\(\s*(?:x\s*=>\s*)?(?:x\.)?(?:Members?|Users?|Owners?|Administrators?|Admins?|Participants?|Collaborators?|Groups?|Roles?|Permissions?|Teams?|Accounts?|Organizations?|Tenants?)\b|\.ThenInclude\s*\(|Include\s*\(\s*["'](?:members?|users?|owners?|administrators?|admins?|participants?|collaborators?|groups?|roles?|permissions?|teams?|accounts?|organizations?|tenants?)["']|Navigation\s*\(\s*["'](?:members?|users?|roles?)["'])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@EntityGraph\s*\([^)]*(?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?)|@NamedEntityGraph\b|joinFetch\s*\(|fetchJoin\s*\(|root\.fetch\s*\(\s*"?(?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?)"?|JOIN\s+FETCH\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:->with\s*\(\s*['"](?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?|organization|tenant)s?['"]|withCount\s*\(|load\s*\(\s*['"](?:members?|users?|roles?|permissions?)['"]|loadMissing\s*\(|belongsToMany\s*\(|hasMany\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:\.populate\s*\(\s*['"](?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?|organization|tenant)s?['"]|populate\s*\(\s*\{[^}]*path\s*:\s*['"](?:members?|users?|roles?|permissions?)['"]|include\s*:\s*\{|\brelations\s*:\s*\[|leftJoinAndSelect\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\.Include\s*\(\s*(?:x\s*=>\s*)?(?:x\.)?(?:Members?|Users?|Owners?|Administrators?|Admins?|Participants?|Collaborators?|Groups?|Roles?|Permissions?|Teams?|Accounts?|Organizations?|Tenants?)\b|\.ThenInclude\s*\(|Include\s*\(\s*["'](?:members?|users?|owners?|administrators?|admins?|participants?|collaborators?|groups?|roles?|permissions?|teams?|accounts?|organizations?|tenants?)["']|Navigation\s*\(\s*["'](?:members?|users?|roles?)["'])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@EntityGraph\s*\([^)]*(?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?)|@NamedEntityGraph\b|joinFetch\s*\(|fetchJoin\s*\(|root\.fetch\s*\(\s*"?(?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?)"?|JOIN\s+FETCH\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:->with\s*\(\s*['"](?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?|organization|tenant)s?['"]|withCount\s*\(|load\s*\(\s*['"](?:members?|users?|roles?|permissions?)['"]|loadMissing\s*\(|belongsToMany\s*\(|hasMany\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:\.populate\s*\(\s*['"](?:members?|users?|owners?|roles?|permissions?|groups?|participants?|teams?|organization|tenant)s?['"]|populate\s*\(\s*\{[^}]*path\s*:\s*['"](?:members?|users?|roles?|permissions?)['"]|include\s*:\s*\{|\brelations\s*:\s*\[|leftJoinAndSelect\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/workspaces/{id}")]
public async Task<IActionResult> GetWorkspace(int id) 
{
    // [1]
    var workspace = await _context.Workspaces
        // [2]
        .Include(w => w.Members)
        .FirstOrDefaultAsync(w => w.Id == id);

    if (workspace == null || !workspace.Members.Any(m => m.Id == _currentUser.Id)) 
    {
        return Unauthorized();
    }

    // [3]
    // [4]
    return Ok(workspace);
}

// In the User Entity Definition:
public class User {
    public int Id { get; set; }
    public string Name { get; set; }
    // Added during Q3 security sprint for the "Logout Everywhere" feature
    public string ActiveSessionToken { get; set; } 
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/workspaces/{id}")
public ResponseEntity<?> getWorkspace(@PathVariable Long id) {
    // [1]
    // [2]
    Workspace workspace = workspaceRepository.findByIdWithMembers(id);

    if (workspace == null || !workspace.hasMember(currentUser.getId())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    // [3]
    // [4]
    return ResponseEntity.ok(workspace);
}

// In Repository:
// @EntityGraph(attributePaths = {"members"})
// Workspace findByIdWithMembers(Long id);

// In User Entity:
// private String name;
// private String activeSessionToken; // Added for concurrent session limitation
```
{% endtab %}

{% tab title="PHP" %}
```php
public function getWorkspace($id) 
{
    // [1]
    // [2]
    $workspace = Workspace::with('members')->findOrFail($id);

    if (!$workspace->members->contains($this->currentUser->id)) 
    {
        return response('Unauthorized', 401);
    }

    // [3]
    // [4]
    return response()->json($workspace);
}

// In User Model:
// protected $fillable = ['name', 'email', 'active_session_token'];
// Developer forgot to add 'active_session_token' to the $hidden array.
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/workspaces/:id', async (req, res) => {
    // [1]
    // [2]
    let workspace = await WorkspaceModel.findById(req.params.id).populate('members');

    if (!workspace || !workspace.members.some(m => m.id === req.user.id)) {
        return res.status(401).send('Unauthorized');
    }

    // [3]
    // [4]
    res.json(workspace);
});

// In User Mongoose Schema:
// name: String,
// activeSessionToken: String // Used to track and invalidate active devices
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The controller securely fetches the Workspace and strictly validates that the requesting user is an authorized member of that workspace, \[2] The architectural optimization: To prevent the ORM from executing a separate `SELECT * FROM Users WHERE id = X` for every single member of the team, the developer explicitly instructs the ORM to eager-load the relation, \[3] The security boundary breakdown: The developer skips mapping the `Workspace` and `User` entities into a strictly defined `WorkspaceResponseDto`. They assume the ORM entities only contain generic profile data, \[4] The framework's JSON serializer takes over. It recursively navigates the entity graph, serializing every column mapped in the `User` table. Because a separate development team recently added the `ActiveSessionToken` field to the database to support a "Force Logout All Devices" feature, the serializer blindly reads this highly sensitive field and dumps it directly into the public HTTP response, exposing the active session tokens of every user in the workspace

```http
// 1. Attacker (Low-Privilege Team Member) views the Workspace Dashboard.
GET /api/v1/workspaces/8821 HTTP/1.1
Host: app.enterprise.tld
Cookie: SessionToken=ATTACKER_LOW_PRIV_TOKEN

// 2. The server serializes the entire Eager-Loaded entity graph.
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 8821,
  "name": "Q3 Financials",
  "members": [
    {
      "id": 14,
      "name": "Attacker",
      "activeSessionToken": "ATTACKER_LOW_PRIV_TOKEN"
    },
    {
      "id": 2,
      "name": "CEO / Workspace Owner",
      "activeSessionToken": "eyJhbGciOi...[CEO_ACTIVE_SESSION_TOKEN]..."
    }
  ]
}
```

```http
// 3. Attacker extracts the CEO's token and injects it into their browser.
GET /api/v1/admin/export-finances HTTP/1.1
Host: app.enterprise.tld
Cookie: SessionToken=eyJhbGciOi...[CEO_ACTIVE_SESSION_TOKEN]...
```
{% endstep %}

{% step %}
The enterprise architecture successfully resolved the N+1 query performance bottleneck via ORM eager loading. However, the system failed to enforce architectural isolation between Database Entities and Data Transfer Objects (DTOs). When the serialization engine traversed the entity graph to build the JSON response, it encountered the `ActiveSessionToken` field—a column appended to the `User` table to satisfy a completely unrelated concurrent session security requirement. The serializer dumped the live session tokens of the entire team into the HTTP response. The attacker effortlessly extracted the Workspace Owner's active session token from the JSON payload, achieving complete Session Hijacking and privilege escalation without any interaction from the victim.
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
