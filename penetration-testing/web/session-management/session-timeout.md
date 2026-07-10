# Session Timeout

## Check List

## Methodology

### Black Box

#### Reusing Session IDs

{% stepper %}
{% step %}
Navigate to `https://example.com/` and log into the AWS Management Console using AWS SSO
{% endstep %}

{% step %}
Keep the session idle until the configured session-timeout period is reached and you are automatically logged out of the AWS Management Console
{% endstep %}

{% step %}
After timeout, directly visit the AWS Access Portal URL (`https://example.com/awsapps/portal`) without performing any new authentication
{% endstep %}

{% step %}
Observe that the portal still grants access and allows re-login into AWS services without requiring a fresh SSO authentication, indicating improper session invalidation
{% endstep %}
{% endstepper %}

***

#### Insufficient Session Expiration

{% stepper %}
{% step %}
Open Browser A (Brave) and Browser B (Firefox)
{% endstep %}

{% step %}
Log into the same user account on both browsers using valid credentials
{% endstep %}

{% step %}
In Browser A, navigate to Account Settings → Change Password
{% endstep %}

{% step %}
Update the password to a new value and confirm the successful password change
{% endstep %}

{% step %}
Switch to Browser B and refresh any authenticated page
{% endstep %}

{% step %}
Observe that the session remains active and no re-authentication is required
{% endstep %}
{% endstepper %}

***

#### Password Change

{% stepper %}
{% step %}
Observe session timeout behavior and identify client-side session-clear requests (`/clearSession`)
{% endstep %}

{% step %}
Intercept outgoing requests with a proxy (Burp) and confirm `/clearSession` is sent periodically
{% endstep %}

{% step %}
Create a match-and-replace rule in the proxy to `block/modify` `/clearSession` so it no longer clears the session
{% endstep %}

{% step %}
Verify the session remains active and automated tests can run uninterrupted
{% endstep %}

{% step %}
Inspect logout flow; identify all endpoints called (`/clearSession`, `/authservice/logout`)
{% endstep %}

{% step %}
Confirm whether logout actually invalidates server-side sessions&#x20;
{% endstep %}
{% endstepper %}

***

### White Box

#### Session Timeout Defeat via Telemetry Sliding Expiration in Distributed Caches

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
Investigate the enterprise's compliance requirements for Session Timeout. High-security applications (banking, healthcare) strictly mandate a 15-minute "Idle Timeout" where inactivity must terminate the session
{% endstep %}

{% step %}
Identify the distributed caching architecture used for session management (e.g., Redis Cluster). To implement the idle timeout, developers utilize a "Sliding Expiration" optimization
{% endstep %}

{% step %}
Observe how the Sliding Expiration works: The API Gateway intercepts every authenticated HTTP request, queries the active session, and blindly resets the Redis Key's Time-To-Live (TTL) back to 15 minutes
{% endstep %}

{% step %}
Discover the architectural clash with modern Single Page Applications (SPAs). Modern SPAs are highly noisy. They continuously emit background network traffic without any human interaction (e.g., GraphQL Subscription keep-alives, unread notification polling, or background telemetry/analytics beacons)
{% endstep %}

{% step %}
Locate the `SessionMiddleware` or `AuthenticationInterceptor` in the decompiled code
{% endstep %}

{% step %}
Verify that the middleware lacks "Route Awareness" or "Intent Awareness". It applies the TTL bump globally to _every_ request carrying a valid session token, completely failing to distinguish between active human interaction (e.g., a mouse click submitting a form) and passive machine polling
{% endstep %}

{% step %}
To exploit this, authenticate to the target enterprise application
{% endstep %}

{% step %}
Leave the computer physically unattended or put the browser tab in the background. Do not interact with the page
{% endstep %}

{% step %}
Monitor the network traffic. Observe that the SPA automatically fires a `/api/v1/telemetry/heartbeat` or `/api/v1/notifications/unread` request every 60 seconds
{% endstep %}

{% step %}
Because each of these passive background requests hits the global session middleware, the Redis TTL is continuously pushed forward, The architectural optimization intended to maintain active sessions completely neutralizes the regulatory Idle Timeout constraint, resulting in an infinite session lifespan on unattended devices

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:SlidingExpiration\s*=\s*TimeSpan(?:\.From(?:Seconds|Minutes|Hours|Days))?\s*\(|AbsoluteExpiration(?:RelativeToNow)?\s*=\s*TimeSpan(?:\.From(?:Seconds|Minutes|Hours|Days))?\s*\(|SetSlidingExpiration\s*\(|DistributedCacheEntryOptions\b[\s\S]{0,150}?(?:SlidingExpiration|AbsoluteExpiration)|IDistributedCache\.(?:Set|SetAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:redisTemplate\.expire\s*\([^)]*,\s*\d+\s*,\s*TimeUnit\.(?:SECONDS|MINUTES|HOURS|DAYS)\)|expire\s*\([^)]*TimeUnit\.(?:SECONDS|MINUTES|HOURS|DAYS)\)|setExpiration\s*\(|Duration\.of(?:Seconds|Minutes|Hours|Days)\s*\(|RedisTemplate\b[\s\S]{0,150}?expire\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Redis::expire\s*\(\s*\$\w+\s*,\s*\d+\s*\)|Redis::setex\s*\(|Cache::put\s*\([^)]*,\s*(?:now\s*\(\)->add(?:Seconds|Minutes|Hours|Days)|\d+)\)|session_set_cookie_params\s*\(|ini_set\s*\(\s*['"]session\.gc_maxlifetime['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:redis\.expire\s*\(\s*\w+\s*,\s*\d+\s*\)|redis\.setEx\s*\(|client\.expire\s*\(|cookie\s*:\s*\{[\s\S]{0,150}?(?:maxAge|expires)|maxAge\s*:\s*\d+|ttl\s*:\s*\d+|rolling\s*:\s*true)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:SlidingExpiration\s*=\s*TimeSpan(?:\.From(?:Seconds|Minutes|Hours|Days))?\s*\(|AbsoluteExpiration(?:RelativeToNow)?\s*=\s*TimeSpan(?:\.From(?:Seconds|Minutes|Hours|Days))?\s*\(|SetSlidingExpiration\s*\(|DistributedCacheEntryOptions.*(?:SlidingExpiration|AbsoluteExpiration)|IDistributedCache\.(?:Set|SetAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:redisTemplate\.expire\s*\([^)]*,\s*\d+\s*,\s*TimeUnit\.(?:SECONDS|MINUTES|HOURS|DAYS)\)|expire\s*\([^)]*TimeUnit\.(?:SECONDS|MINUTES|HOURS|DAYS)\)|setExpiration\s*\(|Duration\.of(?:Seconds|Minutes|Hours|Days)\s*\(|RedisTemplate.*expire\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Redis::expire\s*\(\s*\$\w+\s*,\s*\d+\s*\)|Redis::setex\s*\(|Cache::put\s*\([^)]*,\s*(?:now\s*\(\)->add(?:Seconds|Minutes|Hours|Days)|\d+)\)|session_set_cookie_params\s*\(|ini_set\s*\(\s*['"]session\.gc_maxlifetime['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:redis\.expire\s*\(\s*\w+\s*,\s*\d+\s*\)|redis\.setEx\s*\(|client\.expire\s*\(|cookie\s*:\s*\{.*(?:maxAge|expires)|maxAge\s*:\s*\d+|ttl\s*:\s*\d+|rolling\s*:\s*true)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SessionSlidingMiddleware 
{
    private readonly IDistributedCache _cache;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var sessionId = context.Request.Cookies["EnterpriseSession"];

        if (!string.IsNullOrEmpty(sessionId)) 
        {
            // [1]
            var sessionData = await _cache.GetStringAsync(sessionId);
            
            if (sessionData != null) 
            {
                // [2]
                // [3]
                // [4]
                var options = new DistributedCacheEntryOptions {
                    SlidingExpiration = TimeSpan.FromMinutes(15)
                };
                
                await _cache.SetStringAsync(sessionId, sessionData, options);
                context.Items["Session"] = sessionData;
            }
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class SessionSlidingInterceptor implements HandlerInterceptor {

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String sessionId = getCookie(request, "EnterpriseSession");

        if (sessionId != null) {
            // [1]
            String sessionData = redisTemplate.opsForValue().get(sessionId);
            
            if (sessionData != null) {
                // [2]
                // [3]
                // [4]
                redisTemplate.expire(sessionId, 15, TimeUnit.MINUTES);
                request.setAttribute("Session", sessionData);
            }
        }

        return true;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SessionSlidingMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $sessionId = $request->cookie('EnterpriseSession');

        if ($sessionId) {
            // [1]
            $sessionData = Redis::get($sessionId);
            
            if ($sessionData) {
                // [2]
                // [3]
                // [4]
                Redis::expire($sessionId, 900); // 15 minutes
                $request->attributes->set('Session', $sessionData);
            }
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SessionSlidingMiddleware {
    static async handle(req, res, next) {
        let sessionId = req.cookies['EnterpriseSession'];

        if (sessionId) {
            // [1]
            let sessionData = await redis.get(sessionId);
            
            if (sessionData) {
                // [2]
                // [3]
                // [4]
                await redis.expire(sessionId, 900); // 15 minutes
                req.session = sessionData;
            }
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The global middleware intercepts the HTTP request and successfully validates the existence of the session inside the distributed cache, \[2] The middleware operates globally, meaning it sits at the very edge of the application pipeline and executes before the router determines _which_ specific controller or endpoint is being requested, \[3] The architecture strictly applies the Sliding Expiration optimization. Instead of storing complex "Last Accessed" timestamps inside a database, it relies entirely on the Redis native `EXPIRE` command to push the timeout window forward, \[4] The fatal flaw: Because the middleware executes blindly on every valid token, background SPA requests (like `/api/v1/telemetry/heartbeat` which fires every 60 seconds) seamlessly bump the 15-minute TTL. The server has no mechanism to differentiate a background AJAX poll from an intentional user action, rendering the regulatory idle timeout completely ineffective.

```http
// 1. Victim authenticates and walks away from the computer.
// 2. The organization's policy dictates the session should die in 15 minutes.
// 3. The victim's open browser tab automatically fires background telemetry every 60 seconds.
POST /api/v1/telemetry/heartbeat HTTP/1.1
Host: api.enterprise.tld
Cookie: EnterpriseSession=VALID_TOKEN
Content-Type: application/json

{"active_tab": false, "time_on_page": 3600}

// The server responds, silently bumping the Redis TTL by another 15 minutes.
HTTP/1.1 200 OK
```
{% endstep %}

{% step %}
The enterprise architecture successfully integrated a modern, globally distributed session cache. To meet compliance, they implemented a 15-minute idle timeout using Redis sliding expiration. Concurrently, the frontend engineering team implemented a robust telemetry and observability pipeline that pings the server every minute. Because the global authentication middleware lacks context regarding the _intent_ of the HTTP request, it treats every telemetry ping as active user engagement. The session TTL is perpetually reset. An attacker who steals a locked laptop or hijacks an idle session hours later finds the session perfectly valid, as the background polling completely defeated the absolute timeout boundary
{% endstep %}
{% endstepper %}

***

#### Absolute Timeout Bypass via JWT Clock Skew Resuscitation Loop

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
Identify the Stateless Authentication architecture. The enterprise utilizes JSON Web Tokens (JWT) with very short lifespans (e.g., `exp` = 15 minutes) to mimic session timeouts without storing state in a database
{% endstep %}

{% step %}
Investigate the "Token Refresh" optimization. To prevent users from being logged out while actively working, the SPA silently hits a `/api/auth/refresh` endpoint, exchanging the expiring JWT for a new one.
{% endstep %}

{% step %}
Analyze the engineering edge-case: Due to network latency, mobile packet loss, or heavy server load, a client might send a refresh request _exactly_ as the JWT mathematically expires.
{% endstep %}

{% step %}
To optimize the User Experience and prevent frustrating false-positive logouts, developers implement a "Clock Skew" or "Grace Period" allowance. The JWT parsing library is configured to accept tokens that are technically expired, provided they expired within the last 5 minutes
{% endstep %}

{% step %}
Locate the `RefreshController` in the decompiled code
{% endstep %}

{% step %}
Observe the fatal logical disconnect: The controller relies on the JWT library's built-in validation (which includes the 5-minute skew) to verify the incoming token. If validation passes, the controller blindly mints a _new_ JWT with a _new_ 15-minute lifespan.
{% endstep %}

{% step %}
The developer assumed that the absolute session boundary was safely bounded by the `exp` claim, forgetting that the 5-minute clock skew effectively resuscitates a dead token
{% endstep %}

{% step %}
Authenticate to the application and capture your JWT
{% endstep %}

{% step %}
Wait exactly 15 minutes for the JWT to mathematically expire (the Absolute Timeout). You are now logged out according to strict time boundaries
{% endstep %}

{% step %}
Wait an additional 3 minutes. Your token has been dead for 3 minutes
{% endstep %}

{% step %}
Send a request to the `/api/auth/refresh` endpoint using the dead token
{% endstep %}

{% step %}
Because `Expiration Time + 3 minutes` is less than `Expiration Time + 5 minutes` (the Clock Skew allowance), the validation engine accepts the dead token and mints a brand new, fully authorized token
{% endstep %}

{% step %}
Chain this attack recursively by writing a script that refreshes the token every 18 minutes, granting you infinite session life and bypassing the absolute timeout boundary forever without needing a persistent Refresh Token

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ClockSkew\s*=\s*TimeSpan(?:\.From(?:Seconds|Minutes|Hours))?\s*\(|TokenValidationParameters\b[\s\S]{0,150}?ClockSkew\b|ValidateLifetime\s*=\s*false\b|RequireExpirationTime\s*=\s*false\b|LifetimeValidator\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:setAllowedClockSkewSeconds\s*\(\s*\d+\s*\)|setClockSkew\s*\(\s*Duration\b|setAllowedClockSkew\b|JwtParserBuilder\b[\s\S]{0,150}?setAllowedClockSkewSeconds\b|setAllowedClockSkewSeconds\s*\(\s*\d+\s*\)|setAllowedClockSkew\b|ignoreExpiration\s*\(\s*true\s*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$leeway\s*=\s*\d+\b|JWT::\$leeway\s*=\s*\d+\b|JWT::decode\b[\s\S]{0,150}?\$leeway\b|ignoreExpiration\s*=>\s*true\b|verify_exp\s*=>\s*false\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:clockTolerance\s*:\s*\d+\b|clockTolerance\s*=\s*\d+\b|ignoreExpiration\s*:\s*true\b|ignoreExpiration\s*=\s*true\b|jwt\.verify\s*\([^)]*clockTolerance|jsonwebtoken\b[\s\S]{0,150}?ignoreExpiration\b|leeway\s*:\s*\d+\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ClockSkew\s*=\s*TimeSpan(?:\.From(?:Seconds|Minutes|Hours))?\s*\(|TokenValidationParameters.*ClockSkew\b|ValidateLifetime\s*=\s*false\b|RequireExpirationTime\s*=\s*false\b|LifetimeValidator\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:setAllowedClockSkewSeconds\s*\(\s*\d+\s*\)|setClockSkew\s*\(\s*Duration\b|setAllowedClockSkew\b|JwtParserBuilder.*setAllowedClockSkewSeconds\b|ignoreExpiration\s*\(\s*true\s*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$leeway\s*=\s*\d+\b|JWT::\$leeway\s*=\s*\d+\b|JWT::decode.*\$leeway\b|ignoreExpiration\s*=>\s*true\b|verify_exp\s*=>\s*false\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:clockTolerance\s*:\s*\d+\b|clockTolerance\s*=\s*\d+\b|ignoreExpiration\s*:\s*true\b|ignoreExpiration\s*=\s*true\b|jwt\.verify\s*\([^)]*clockTolerance|jsonwebtoken.*ignoreExpiration\b|leeway\s*:\s*\d+\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/auth/refresh")]
public IActionResult RefreshToken([FromBody] RefreshRequest req) 
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var validationParameters = new TokenValidationParameters 
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = _secretKey,
        ValidateLifetime = true,
        // [1]
        // [2]
        ClockSkew = TimeSpan.FromMinutes(5) 
    };

    try 
    {
        // [3]
        var principal = tokenHandler.ValidateToken(req.Token, validationParameters, out var validatedToken);
        
        // [4]
        var newToken = _jwtService.GenerateNewToken(principal.Identity.Name, TimeSpan.FromMinutes(15));
        return Ok(new { token = newToken });
    } 
    catch 
    {
        return Unauthorized();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/auth/refresh")
public ResponseEntity<?> refreshToken(@RequestBody RefreshRequest req) {
    try {
        // [1]
        // [2]
        JwtParser parser = Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .setAllowedClockSkewSeconds(300) // 5 minutes
            .build();

        // [3]
        Jws<Claims> claims = parser.parseClaimsJws(req.getToken());
        
        // [4]
        String newToken = jwtService.generateNewToken(claims.getBody().getSubject(), 15);
        return ResponseEntity.ok(Map.of("token", newToken));
        
    } catch (JwtException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function refreshToken(Request $request) 
{
    try {
        // [1]
        // [2]
        JWT::$leeway = 300; // 5 minutes
        
        // [3]
        $decoded = JWT::decode($request->input('token'), new Key($this->secretKey, 'HS256'));
        
        // [4]
        $newToken = $this->jwtService->generateNewToken($decoded->sub, 15); // 15 mins
        return response()->json(['token' => $newToken]);
        
    } catch (\Exception $e) {
        return response('Unauthorized', 401);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/auth/refresh', (req, res) => {
    try {
        // [1]
        // [2]
        // [3]
        let decoded = jwt.verify(req.body.token, secretKey, {
            clockTolerance: 300 // 5 minutes
        });

        // [4]
        let newToken = jwtService.generateNewToken(decoded.sub, '15m');
        res.json({ token: newToken });
        
    } catch (err) {
        res.status(401).send('Unauthorized');
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies on stateless JWTs without database-backed Refresh Tokens to maximize API throughput, \[2] To optimize for network unreliability and global server clock drift, the developers explicitly configure the JWT validation engine to allow a 5-minute clock skew (`clockTolerance`, `leeway`, `ClockSkew`), \[3] The library parses the JWT. If the token mathematically expired 3 minutes ago, the validation logic calculates `ExpiredTime + 5 Minutes > CurrentTime` and returns a successful validation state, \[4] The fatal logical error: The refresh controller trusts the successful validation and blindly mints a brand new token with a fresh 15-minute lifespan. It fails to check if the token it just accepted was technically in the "grace period" window. An attacker can mathematically chain these grace periods together to resuscitate dead sessions infinitely

```http
// 1. Attacker holds a JWT that mathematically expired 3 minutes ago.
// 2. The Absolute Timeout boundary has technically been crossed.
// 3. Attacker sends the expired token to the refresh endpoint.

POST /api/v1/auth/refresh HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{"token": "eyJhb...[EXPIRED_TOKEN]..."}
```

```http
// 4. The server applies the 5-minute clock skew, accepts the dead token, and issues a fresh one.

HTTP/1.1 200 OK
Content-Type: application/json

{"token": "eyJhb...[BRAND_NEW_TOKEN_VALID_FOR_15_MINS]..."}
```

The architectural decision to implement stateless JWTs required a mechanism to refresh tokens before they expired. To handle the realities of distributed network latency and clock drift, engineers implemented a standard 5-minute clock skew tolerance. The security breakdown occurred because the refresh endpoint leveraged this exact same parsing engine without enforcing strict boundaries on absolute expiration. When the attacker submits a mathematically dead token, the parsing engine forgives the expiration due to the grace period. The controller immediately mints a fresh token, resetting the absolute timeout clock. By automating this submission every 18 minutes, the attacker establishes a perpetual session resuscitation loop, completely erasing the enterprise's absolute session timeout constraints
{% endstep %}
{% endstepper %}

***

#### Session Timeout Bypass via Offline-First Timestamp Trust in Mobile Synchronization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Pay special attention to endpoints labeled `/sync`, `/offline`, or `/mutations`
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify if the enterprise application is a Progressive Web App (PWA) or an Offline-First Mobile Application (e.g., built with React Native + WatermelonDB)
{% endstep %}

{% step %}
Understand the engineering optimization: Enterprise field workers (e.g., inspectors, logistics drivers) often perform critical actions (e.g., approving invoices, capturing signatures) while completely offline in subways or remote areas
{% endstep %}

{% step %}
To prevent data loss, the mobile app queues these actions locally and synchronizes them with the backend via a bulk API request once an internet connection is restored
{% endstep %}

{% step %}
Analyze the backend Synchronization Controller. Notice the architectural conflict with Session Timeouts: If a worker goes offline for 6 hours, their strict 2-hour backend Session Timeout will naturally expire
{% endstep %}

{% step %}
When the client reconnects and pushes the sync queue, their session token is technically dead. If the backend strictly enforces the timeout, all offline work is rejected and lost
{% endstep %}

{% step %}
Discover the "Timestamp Reconciliation" optimization. To solve this, developers allow the sync endpoint to process actions using an expired session token, _provided_ the `ActionTimestamp` embedded inside the payload indicates the action was taken _before_ the session originally timed out
{% endstep %}

{% step %}
Verify that the backend code calculates the original session validity window by querying the session creation time, and then inherently trusts the client-provided `ActionTimestamp` inside the JSON payload to authorize the historical action
{% endstep %}

{% step %}
Authenticate to the application and capture your session token
{% endstep %}

{% step %}
Wait 24 hours. Your session is now entirely dead, and the absolute timeout has long passed
{% endstep %}

{% step %}
Forge an offline synchronization payload containing a highly privileged action (e.g., transferring funds, approving a workflow)
{% endstep %}

{% step %}
Explicitly manipulate the `ActionTimestamp` inside the JSON array. Set the timestamp to a historical value exactly 5 minutes after your initial login (a moment when your session was demonstrably valid)
{% endstep %}

{% step %}
Submit the sync payload with the dead session token. The backend calculates the historical timeline, trusts your forged client-side timestamp, and executes the highly privileged action despite the session being permanently expired in real-time

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:mutation\.Timestamp\s*(?:<=|>=|<|>)\s*session\.CreatedAt(?:\.Add(?:Seconds|Minutes|Hours|Days)\([^)]*\))?|session\.CreatedAt\.Add(?:Seconds|Minutes|Hours|Days)\([^)]*\)[\s\S]{0,100}?(?:Timestamp|timestamp)|DateTime(?:Offset)?\.UtcNow[\s\S]{0,100}?session\.CreatedAt|TimeSpan\.From(?:Seconds|Minutes|Hours)\([^)]*\)[\s\S]{0,100}?(?:Timestamp|timestamp)|Math\.Abs\s*\([^)]*(?:Timestamp|timestamp)[^)]*session\.CreatedAt)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:action\.getTimestamp\s*\(\s*\)\.(?:isBefore|isAfter|isEqual)\s*\(|Instant\.now\s*\(\s*\)[\s\S]{0,100}?(?:isBefore|isAfter)|Duration\.between\s*\([^)]*(?:session|timestamp)[^)]*\)|ChronoUnit\.(?:SECONDS|MINUTES|HOURS)\.between\s*\(|Math\.abs\s*\([^)]*timestamp[^)]*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:payload\s*\[['"]timestamp['"]\]\s*(?:<=|>=|<|>)\s*\$session->created_at|\$session->created_at\s*(?:<=|>=|<|>)\s*payload\s*\[['"]timestamp['"]\]|Carbon::now\s*\(\s*\)[\s\S]{0,100}?(?:diffInSeconds|diffInMinutes|greaterThan|lessThan)|abs\s*\(\s*.*timestamp.*created_at.*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Math\.abs\s*\(\s*action\.timestamp\s*-\s*session\.createdAt\s*\)|Math\.abs\s*\([^)]*(?:timestamp|createdAt)[^)]*\)|Date\.now\s*\(\s*\)[\s\S]{0,100}?(?:createdAt|timestamp)|dayjs\([^)]*\)\.(?:isBefore|isAfter|diff)\s*\(|moment\([^)]*\)\.(?:isBefore|isAfter|diff)\s*\(|Temporal\.Now\b[\s\S]{0,100}?(?:compare|since))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:mutation\.Timestamp\s*(?:<=|>=|<|>)\s*session\.CreatedAt(?:\.Add(?:Seconds|Minutes|Hours|Days)\([^)]*\))?|session\.CreatedAt\.Add(?:Seconds|Minutes|Hours|Days)\([^)]*\).*(?:Timestamp|timestamp)|DateTime(?:Offset)?\.UtcNow.*session\.CreatedAt|TimeSpan\.From(?:Seconds|Minutes|Hours)\([^)]*\).*(?:Timestamp|timestamp)|Math\.Abs\s*\([^)]*(?:Timestamp|timestamp)[^)]*session\.CreatedAt)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:action\.getTimestamp\s*\(\s*\)\.(?:isBefore|isAfter|isEqual)\s*\(|Instant\.now\s*\(\s*\).*(?:isBefore|isAfter)|Duration\.between\s*\([^)]*(?:session|timestamp)[^)]*\)|ChronoUnit\.(?:SECONDS|MINUTES|HOURS)\.between\s*\(|Math\.abs\s*\([^)]*timestamp[^)]*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:payload\s*\[['"]timestamp['"]\]\s*(?:<=|>=|<|>)\s*\$session->created_at|\$session->created_at\s*(?:<=|>=|<|>)\s*payload\s*\[['"]timestamp['"]\]|Carbon::now\s*\(\s*\).*(?:diffInSeconds|diffInMinutes|greaterThan|lessThan)|abs\s*\(\s*.*timestamp.*created_at.*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Math\.abs\s*\(\s*action\.timestamp\s*-\s*session\.createdAt\s*\)|Math\.abs\s*\([^)]*(?:timestamp|createdAt)[^)]*\)|Date\.now\s*\(\s*\).*(?:createdAt|timestamp)|dayjs\([^)]*\)\.(?:isBefore|isAfter|diff)\s*\(|moment\([^)]*\)\.(?:isBefore|isAfter|diff)\s*\(|Temporal\.Now.*(?:compare|since))
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/sync/offline-mutations")]
public async Task<IActionResult> SyncOfflineData([FromBody] SyncPayload payload) 
{
    var sessionToken = Request.Cookies["EnterpriseSession"];
    var session = await _sessionStore.GetSessionIncludingExpiredAsync(sessionToken);

    if (session == null) return Unauthorized();

    foreach (var mutation in payload.Mutations) 
    {
        // [1]
        // [2]
        var sessionExpirationTime = session.CreatedAt.AddHours(2);
        
        // [3]
        if (mutation.ActionTimestamp <= sessionExpirationTime) 
        {
            // [4]
            await _mutationService.ApplyAsync(session.UserId, mutation);
        }
        else 
        {
            _logger.LogWarning("Rejected offline mutation. Session was expired at the time of action.");
        }
    }

    return Ok(new { status = "Synced" });
}        
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/sync/offline-mutations")
public ResponseEntity<?> syncOfflineData(@RequestBody SyncPayload payload, HttpServletRequest request) {
    String sessionToken = extractCookie(request, "EnterpriseSession");
    Session session = sessionStore.getSessionIncludingExpired(sessionToken);

    if (session == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

    for (Mutation mutation : payload.getMutations()) {
        // [1]
        // [2]
        Instant sessionExpirationTime = session.getCreatedAt().plus(Duration.ofHours(2));
        
        // [3]
        if (mutation.getActionTimestamp().isBefore(sessionExpirationTime) || mutation.getActionTimestamp().equals(sessionExpirationTime)) {
            // [4]
            mutationService.apply(session.getUserId(), mutation);
        } else {
            log.warn("Rejected offline mutation. Session was expired at the time of action.");
        }
    }

    return ResponseEntity.ok(Map.of("status", "Synced"));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function syncOfflineData(Request $request) 
{
    $sessionToken = $request->cookie('EnterpriseSession');
    $session = $this->sessionStore->getSessionIncludingExpired($sessionToken);

    if (!$session) return response('Unauthorized', 401);

    foreach ($request->input('mutations') as $mutation) 
    {
        // [1]
        // [2]
        $sessionExpirationTime = $session->created_at->addHours(2);
        $actionTimestamp = Carbon::parse($mutation['action_timestamp']);
        
        // [3]
        if ($actionTimestamp->lessThanOrEqualTo($sessionExpirationTime)) 
        {
            // [4]
            $this->mutationService->apply($session->user_id, $mutation);
        } 
        else 
        {
            Log::warning("Rejected offline mutation. Session was expired at the time of action.");
        }
    }

    return response()->json(['status' => 'Synced']);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/sync/offline-mutations', async (req, res) => {
    let sessionToken = req.cookies['EnterpriseSession'];
    let session = await sessionStore.getSessionIncludingExpired(sessionToken);

    if (!session) return res.status(401).send('Unauthorized');

    for (let mutation of req.body.mutations) {
        // [1]
        // [2]
        let sessionExpirationTime = new Date(session.createdAt.getTime() + (2 * 60 * 60 * 1000));
        let actionTimestamp = new Date(mutation.actionTimestamp);
        
        // [3]
        if (actionTimestamp <= sessionExpirationTime) {
            // [4]
            await mutationService.apply(session.userId, mutation);
        } else {
            console.warn("Rejected offline mutation. Session was expired at the time of action.");
        }
    }

    res.json({ status: "Synced" });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture handles offline synchronization by explicitly allowing the retrieval of expired session records from the database. This is a deliberate engineering optimization to prevent data loss for field workers, \[2] The backend reconstructs the exact historical validity window of the session, establishing the absolute timeout boundary (e.g., Creation Time + 2 Hours), \[3] The catastrophic trust boundary failure occurs here. The backend relies on the `actionTimestamp` embedded within the JSON payload provided by the client to determine if the action occurred _before_ the session mathematically expired, \[4] The system applies the state mutation. Because the backend inherently trusts the client's clock for historical reconciliation, an attacker can freely forge timestamps indefinitely, completely bypassing the server-side session timeout enforcement

```http
// 1. Attacker's session officially expired 24 hours ago.
// 2. Attacker crafts a sync payload, forging the timestamp to match a historical time when the session was active.
POST /api/v1/sync/offline-mutations HTTP/1.1
Host: api.enterprise.tld
Cookie: EnterpriseSession=DEAD_EXPIRED_TOKEN
Content-Type: application/json

{
  "mutations": [
    {
      "type": "APPROVE_INVOICE",
      "invoiceId": "INV-88910",
      "actionTimestamp": "2026-07-10T14:05:00Z" // Forged to exactly 5 mins after login yesterday
    }
  ]
}
```

```http
// 3. Server authorizes the historical action based on the forged timeline.
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "Synced"}
```
{% endstep %}

{% step %}
The mobile-first architecture prioritized offline resilience and UX over strict real-time authorization. To accommodate workers emerging from offline states with technically expired sessions, developers optimized the sync controller to evaluate the legality of an action based on when the client _claimed_ it happened, rather than the server's current clock. The attacker presents an entirely dead session token alongside a maliciously crafted payload containing a historical timestamp. The backend parses the token, reconstructs the historical validity window, compares it against the attacker's forged payload timestamp, and determines the action was legally taken during the active session window. The highly privileged action is executed against the database, proving that client-side state reconciliation algorithms can fundamentally destroy server-side absolute timeout enforcement
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
