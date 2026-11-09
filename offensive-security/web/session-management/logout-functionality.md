# Logout Functionality

## Check List

## Methodology

### Black Box

#### Logout Bypass

{% stepper %}
{% step %}
Open the browser and go to the login page of the target
{% endstep %}

{% step %}
Enter a valid username/email and password
{% endstep %}

{% step %}
Submit the login form, Successfully access the authenticated dashboard
{% endstep %}

{% step %}
Click the Logout button
{% endstep %}

{% step %}
Confirm you are redirected to the login page or a "Logged out" message appears
{% endstep %}

{% step %}
Immediately after logout, press the Back button (or use keyboard shortcut `Alt + ←`)
{% endstep %}

{% step %}
Observe if the previous authenticated page reloads and you still have full access
{% endstep %}

{% step %}
Navigate freely inside the dashboard
{% endstep %}

{% step %}
Perform a privileged action (change settings, view private data) → If successful → Logout bypass confirmed
{% endstep %}
{% endstepper %}

***

#### **Failure to Invalidate Session on Logout**

{% stepper %}
{% step %}
Login to the application using Chrome Browser and browse the application
{% endstep %}

{% step %}
Use `“Edit this Cookie”` plugin in Chrome and copy all the cookies present
{% endstep %}

{% step %}
Now Logout from the application and Clear the cookies from browser
{% endstep %}

{% step %}
Use “Edit this Cookie” plugin and paste all the cookies that copied earlier
{% endstep %}

{% step %}
Click on Okay and refresh the page , can see the application is getting logged in
{% endstep %}
{% endstepper %}

***

### White Box

#### Session Resuscitation via L1/L2 Cache Desynchronization in API Gateways

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on the Load Balancer or API Gateway behaviors and response times
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Investigate the API Gateway's session validation architecture. In high-traffic enterprise networks, querying the global distributed session store (e.g., Redis Cluster, Cassandra) on every single HTTP request creates a massive network bottleneck
{% endstep %}

{% step %}
Identify the "Two-Tier Caching" (L1/L2) optimization. To reduce latency, developers often implement an L1 In-Memory Cache (e.g., `ConcurrentHashMap`, `MemoryCache`) directly on the API Gateway nodes
{% endstep %}

{% step %}
Observe the lifecycle: When a request arrives, the gateway checks its local L1 cache. On a miss, it queries the L2 Redis cluster, validates the session, and stores the result in its local L1 cache with a short Time-To-Live (TTL) of 5 to 10 minutes
{% endstep %}

{% step %}
Locate the `Logout` controller or middleware in the decompiled code. Analyze the session destruction logic
{% endstep %}

{% step %}
Discover the desynchronization flaw: The logout function explicitly deletes the session from the global L2 Redis cluster, and then removes the token from the _local_ L1 cache of the specific gateway node processing the logout request
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumed that deleting the session from the global store effectively kills it. However, they failed to implement a Pub/Sub broadcast (e.g., Redis Pub/Sub) to invalidate the L1 caches across _all other_ load-balanced gateway nodes
{% endstep %}

{% step %}
To exploit this, authenticate and obtain a valid session token. Send multiple requests to ensure your token is cached in the L1 memory of several different API Gateway nodes
{% endstep %}

{% step %}
Execute the Logout functionality. The specific node you hit destroys the Redis entry and clears its own L1 cache
{% endstep %}

{% step %}
Immediately use Burp Suite to spray authorized requests (using a tool like Turbo Intruder with a high connection count) using the "destroyed" session token
{% endstep %}

{% step %}
Due to Round-Robin or Least-Connections load balancing, your requests will eventually hit a different API Gateway node. Because that node still holds your valid session in its L1 cache (until the 5-minute TTL expires), it never queries Redis and grants you full authenticated access with a logged-out token

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:L1Cache\.(?:Remove|Delete|Evict|Invalidate)\s*\([^)]*\btoken\b|(?:MemoryCache|IMemoryCache)\.(?:Remove|TryRemove|Evict)\s*\([^)]*\btoken\b|Redis\.(?:Delete|KeyDelete|Remove|Unlink)\s*\([^)]*\btoken\b[\s\S]{0,200}?(?:Cache|L1Cache|MemoryCache)\.(?:Remove|Delete|Evict|Invalidate)|(?:localCache|cache)\.(?:Invalidate|Remove|Delete|Evict)\s*\([^)]*\btoken\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:cache\.(?:invalidate|evict|remove)\s*\([^)]*\btoken\b|cacheManager\.getCache\s*\([^)]*\)\.(?:evict|invalidate)\s*\([^)]*\btoken\b|redisTemplate\.(?:delete|unlink)\s*\([^)]*\btoken\b[\s\S]{0,200}?cache\.(?:invalidate|evict|remove)|RedisTemplate\b[\s\S]{0,100}?(?:opsForValue|delete)|localCache\.(?:invalidate|remove|evict)\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Cache::(?:forget|delete|pull)\s*\([^)]*\btoken\b|Redis::(?:del|unlink|hDel)\s*\([^)]*\btoken\b[\s\S]{0,200}?Cache::(?:forget|delete|pull)|apcu_delete\s*\([^)]*\btoken\b|(?:localCache|cache)->(?:invalidate|remove|delete)\s*\([^)]*\btoken\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:memoryCache\.(?:delete|del|remove)\s*\([^)]*\btoken\b|redis\.(?:del|unlink|hDel)\s*\([^)]*\btoken\b[\s\S]{0,200}?(?:memoryCache|cache|lruCache)\.(?:delete|del|remove|invalidate)|lruCache\.(?:delete|del)\s*\([^)]*\btoken\b|(?:localCache|cache)\.(?:invalidate|delete|remove|del)\s*\([^)]*\btoken\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:L1Cache\.(?:Remove|Delete|Evict|Invalidate)\s*\([^)]*\btoken\b|(?:MemoryCache|IMemoryCache)\.(?:Remove|TryRemove|Evict)\s*\([^)]*\btoken\b|Redis\.(?:Delete|KeyDelete|Remove|Unlink)\s*\([^)]*\btoken\b.*(?:Cache|L1Cache|MemoryCache)\.(?:Remove|Delete|Evict|Invalidate)|(?:localCache|cache)\.(?:Invalidate|Remove|Delete|Evict)\s*\([^)]*\btoken\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:cache\.(?:invalidate|evict|remove)\s*\([^)]*\btoken\b|cacheManager\.getCache\s*\([^)]*\)\.(?:evict|invalidate)\s*\([^)]*\btoken\b|redisTemplate\.(?:delete|unlink)\s*\([^)]*\btoken\b.*cache\.(?:invalidate|evict|remove)|RedisTemplate.*(?:opsForValue|delete)|localCache\.(?:invalidate|remove|evict)\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Cache::(?:forget|delete|pull)\s*\([^)]*\btoken\b|Redis::(?:del|unlink|hDel)\s*\([^)]*\btoken\b.*Cache::(?:forget|delete|pull)|apcu_delete\s*\([^)]*\btoken\b|(?:localCache|cache)->(?:invalidate|remove|delete)\s*\([^)]*\btoken\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:memoryCache\.(?:delete|del|remove)\s*\([^)]*\btoken\b|redis\.(?:del|unlink|hDel)\s*\([^)]*\btoken\b.*(?:memoryCache|cache|lruCache)\.(?:delete|del|remove|invalidate)|lruCache\.(?:delete|del)\s*\([^)]*\btoken\b|(?:localCache|cache)\.(?:invalidate|delete|remove|del)\s*\([^)]*\btoken\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class LogoutController : ControllerBase
{
    private readonly IMemoryCache _l1Cache;
    private readonly IDistributedCache _l2Redis;

    [HttpPost("/api/v1/auth/logout")]
    public async Task<IActionResult> Logout()
    {
        var sessionToken = Request.Cookies["SessionToken"];
        if (string.IsNullOrEmpty(sessionToken)) return BadRequest();

        // [1]
        await _l2Redis.RemoveAsync(sessionToken);

        // [2]
        // [3]
        _l1Cache.Remove(sessionToken);

        // [4]
        Response.Cookies.Delete("SessionToken");
        return Ok(new { message = "Logged out successfully" });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class LogoutController {

    @Autowired
    private Cache l1Cache;
    @Autowired
    private RedisTemplate<String, Object> l2Redis;

    @PostMapping("/api/v1/auth/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String sessionToken = extractCookie(request, "SessionToken");
        if (sessionToken == null) return ResponseEntity.badRequest().build();

        // [1]
        l2Redis.delete(sessionToken);

        // [2]
        // [3]
        l1Cache.evict(sessionToken);

        // [4]
        Cookie cookie = new Cookie("SessionToken", null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class LogoutController extends Controller
{
    protected $l1Cache;
    protected $l2Redis;

    public function logout(Request $request)
    {
        $sessionToken = $request->cookie('SessionToken');
        if (!$sessionToken) return response('Bad Request', 400);

        // [1]
        $this->l2Redis->del($sessionToken);

        // [2]
        // [3]
        $this->l1Cache->forget($sessionToken);

        // [4]
        return response()->json(['message' => 'Logged out successfully'])
                         ->withCookie(cookie()->forget('SessionToken'));
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class LogoutController {
    constructor(l1Cache, l2Redis) {
        this.l1Cache = l1Cache;
        this.l2Redis = l2Redis;
    }

    async logout(req, res) {
        let sessionToken = req.cookies['SessionToken'];
        if (!sessionToken) return res.status(400).send("Bad Request");

        // [1]
        await this.l2Redis.del(sessionToken);

        // [2]
        // [3]
        this.l1Cache.delete(sessionToken);

        // [4]
        res.clearCookie('SessionToken');
        res.json({ message: "Logged out successfully" });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The logout logic correctly identifies the need to destroy the authoritative session state in the global L2 Redis cluster, \[2] The developer recognizes that the local gateway node executing this code also holds the session in its L1 memory cache, \[3] The fatal architectural flaw occurs here. The controller explicitly purges the L1 cache _only on the current executing process/node_. In a horizontally scaled cluster with 20 API Gateway nodes, the other 19 nodes are completely unaware of this logout event and will continue to trust their L1 cached state until the TTL naturally expires, \[4] The server instructs the browser to delete the cookie, creating the illusion of a secure logout while leaving active ghost sessions scattered across the gateway tier

```http
// 1. Attacker (or Victim) logs out
POST /api/v1/auth/logout HTTP/1.1
Host: api.enterprise.tld
Cookie: SessionToken=VALID_TOKEN_123

HTTP/1.1 200 OK
Set-Cookie: SessionToken=; Max-Age=0
```

```http
// 2. Attacker immediately uses Burp Intruder to rapidly spray requests 
// with the destroyed cookie, forcing the Load Balancer to route to a different node.
GET /api/v1/user/private-data HTTP/1.1
Host: api.enterprise.tld
Cookie: SessionToken=VALID_TOKEN_123
Connection: close
```
{% endstep %}

{% step %}
The logout request routes to `Node-A`. `Node-A` deletes the session from Redis and clears its own L1 cache. When the attacker sprays requests using the revoked cookie, the Load Balancer routes some of these requests to `Node-B` and `Node-C`. Because `Node-B` previously served a request for this user, it holds the session validation result in its L1 Memory Cache. `Node-B` receives the request, checks L1, finds a hit, skips the Redis lookup entirely, and serves the highly sensitive private data despite the session being fully logged out at the global database level
{% endstep %}
{% endstepper %}

***

#### Token Reanimation via JWT Blacklist LRU Evictio

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
Identify if the enterprise utilizes stateless JSON Web Tokens (JWTs) for authentication. Because stateless JWTs cannot be traditionally destroyed on the server, developers must implement a Token Blacklist (or Blocklist) to support Logout functionality
{% endstep %}

{% step %}
Analyze the Blacklist Service in the decompiled code. Observe that when a user logs out, the backend extracts the JWT ID (`jti`) and expiration time (`exp`), and pushes the `jti` into a global cache like Redis
{% endstep %}

{% step %}
Investigate the "Memory Optimization" strategy. Storing every logged-out JWT ID indefinitely would eventually exhaust the Redis server's RAM (Out of Memory)
{% endstep %}

{% step %}
Discover that developers optimized this by implementing a bounded collection. Instead of setting exact TTLs on every blacklist entry matching the JWT's remaining lifespan, they enforce a hard limit on the blacklist size (e.g., `MAX_BLACKLIST_SIZE = 100,000`)
{% endstep %}

{% step %}
Notice the eviction logic: When the blacklist exceeds the maximum size, the system automatically pops the oldest entries from the collection to make room for new logouts (FIFO / LRU logic)
{% endstep %}

{% step %}
Understand the architectural assumption: The developers assumed that 100,000 logouts would naturally take longer to occur than the standard 2-hour lifespan of their JWTs
{% endstep %}

{% step %}
Obtain a valid JWT for the victim account. Execute the logout endpoint. The victim's `jti` is added to the Redis blacklist
{% endstep %}

{% step %}
Mount a deliberate Cache Flooding attack. Write a script to authenticate as a dummy user, obtain a token, and immediately log out. Repeat this process rapidly to generate hundreds of thousands of new, legitimate logouts
{% endstep %}

{% step %}
The Blacklist Service hits the hardcoded optimization threshold. To prevent an OOM crash, the service begins evicting the oldest entries from the blacklist
{% endstep %}

{% step %}
Your script flushes the victim's `jti` out of the blacklist long before the actual JWT `exp` claim expires
{% endstep %}

{% step %}
Send an authenticated request using the victim's "logged-out" JWT. The API Gateway verifies the cryptographically valid signature, checks the Redis blacklist, finds no match (because it was evicted), and grants full access

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:blacklist\.(?:Add|TryAdd|ContainsKey|Remove)\s*\([^)]*\bjti\b|(?:redis|Redis)\.(?:SortedSetAdd|SortedSetRemove|SortedSetRemoveRangeByRank|KeyDelete)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|if\s*\([^)]*(?:Count|Length)\s*(?:>=|>)\s*MAX_BLACKLIST\b|ZRemRangeByRank\b[\s\S]{0,100}?\bblacklist\b|JwtBlacklist\b|TokenBlacklist\b)entType\b[\s\S]{0,200}?StartsWith\s*\(\s*"text/plain"\s*\)[\s\S]{0,200}?(?:Deserialize|DeserializeObject|JsonSerializer\.Deserialize)|Request\.ContentType\s*==\s*"text/plain"[\s\S]{0,200}?(?:Deserialize|ReadObject)|JsonConvert\.DeserializeObject\s*\([^)]*Request\.InputStream)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:blacklist\.(?:add|remove|contains)\s*\([^)]*\bjti\b|redisTemplate\.(?:opsForZSet|delete)\b[\s\S]{0,100}?(?:add|remove|removeRange)|ZSetOperations\b[\s\S]{0,100}?(?:add|remove|removeRange)|if\s*\([^)]*size\s*\(\s*\)\s*(?:>=|>)\s*MAX_BLACKLIST\b|removeRange\b[\s\S]{0,100}?blacklist\b|JwtBlacklist\b|TokenBlacklist\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:blacklist->(?:add|put|remove)\s*\([^)]*\$?jti\b|Redis::(?:zAdd|zRem|zRemRangeByRank|del)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|if\s*\([^)]*count\s*\([^)]*\)\s*(?:>=|>)\s*MAX_BLACKLIST\b|Cache::(?:put|forget)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|JwtBlacklist\b|TokenBlacklist\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:blacklist\.(?:add|set|delete|has)\s*\([^)]*\bjti\b|redis\.(?:zAdd|zRem|zRemRangeByRank|del|unlink)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|if\s*\([^)]*(?:size|length)\s*(?:>=|>)\s*MAX_BLACKLIST\b|lruCache\.(?:set|delete)\s*\([^)]*\bjti\b|JwtBlacklist\b|TokenBlacklist\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:blacklist\.(?:Add|TryAdd|ContainsKey|Remove)\s*\([^)]*\bjti\b|(?:redis|Redis)\.(?:SortedSetAdd|SortedSetRemove|SortedSetRemoveRangeByRank|KeyDelete)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|if\s*\([^)]*(?:Count|Length)\s*(?:>=|>)\s*MAX_BLACKLIST\b|ZRemRangeByRank.*blacklist|JwtBlacklist\b|TokenBlacklist\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:blacklist\.(?:add|remove|contains)\s*\([^)]*\bjti\b|redisTemplate\.(?:opsForZSet|delete).*(?:add|remove|removeRange)|ZSetOperations.*(?:add|remove|removeRange)|if\s*\([^)]*size\s*\(\s*\)\s*(?:>=|>)\s*MAX_BLACKLIST\b|removeRange.*blacklist|JwtBlacklist\b|TokenBlacklist\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:blacklist->(?:add|put|remove)\s*\([^)]*\$?jti\b|Redis::(?:zAdd|zRem|zRemRangeByRank|del)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|if\s*\([^)]*count\s*\([^)]*\)\s*(?:>=|>)\s*MAX_BLACKLIST\b|Cache::(?:put|forget)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|JwtBlacklist\b|TokenBlacklist\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:blacklist\.(?:add|set|delete|has)\s*\([^)]*\bjti\b|redis\.(?:zAdd|zRem|zRemRangeByRank|del|unlink)\s*\([^)]*(?:jwt_blacklist|blacklist)\b|if\s*\([^)]*(?:size|length)\s*(?:>=|>)\s*MAX_BLACKLIST\b|lruCache\.(?:set|delete)\s*\([^)]*\bjti\b|JwtBlacklist\b|TokenBlacklist\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TokenBlacklistService : ITokenBlacklistService
{
    private readonly IDatabase _redis;
    private const int MAX_BLACKLIST_SIZE = 100000;

    public async Task RevokeTokenAsync(string jti)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        // [1]
        await _redis.SortedSetAddAsync("jwt_blacklist", jti, timestamp);

        // [2]
        var count = await _redis.SortedSetLengthAsync("jwt_blacklist");
        if (count > MAX_BLACKLIST_SIZE)
        {
            // [3]
            // [4]
            await _redis.SortedSetRemoveRangeByRankAsync("jwt_blacklist", 0, 0);
        }
    }

    public async Task<bool> IsRevokedAsync(string jti)
    {
        var score = await _redis.SortedSetScoreAsync("jwt_blacklist", jti);
        return score.HasValue;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class TokenBlacklistService {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    private static final int MAX_BLACKLIST_SIZE = 100000;

    public void revokeToken(String jti) {
        long timestamp = Instant.now().getEpochSecond();
        
        // [1]
        redisTemplate.opsForZSet().add("jwt_blacklist", jti, timestamp);

        // [2]
        Long count = redisTemplate.opsForZSet().size("jwt_blacklist");
        if (count != null && count > MAX_BLACKLIST_SIZE) {
            // [3]
            // [4]
            redisTemplate.opsForZSet().removeRange("jwt_blacklist", 0, 0);
        }
    }

    public boolean isRevoked(String jti) {
        Double score = redisTemplate.opsForZSet().score("jwt_blacklist", jti);
        return score != null;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class TokenBlacklistService
{
    protected $redis;
    const MAX_BLACKLIST_SIZE = 100000;

    public function revokeToken(string $jti): void
    {
        $timestamp = time();
        
        // [1]
        $this->redis->zadd("jwt_blacklist", $timestamp, $jti);

        // [2]
        $count = $this->redis->zcard("jwt_blacklist");
        if ($count > self::MAX_BLACKLIST_SIZE) {
            // [3]
            // [4]
            $this->redis->zremrangebyrank("jwt_blacklist", 0, 0);
        }
    }

    public function isRevoked(string $jti): bool
    {
        $score = $this->redis->zscore("jwt_blacklist", $jti);
        return $score !== false && $score !== null;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TokenBlacklistService {
    static MAX_BLACKLIST_SIZE = 100000;

    constructor(redisClient) {
        this.redis = redisClient;
    }

    async revokeToken(jti) {
        let timestamp = Math.floor(Date.now() / 1000);
        
        // [1]
        await this.redis.zadd("jwt_blacklist", timestamp, jti);

        // [2]
        let count = await this.redis.zcard("jwt_blacklist");
        if (count > TokenBlacklistService.MAX_BLACKLIST_SIZE) {
            // [3]
            // [4]
            await this.redis.zremrangebyrank("jwt_blacklist", 0, 0);
        }
    }

    async isRevoked(jti) {
        let score = await this.redis.zscore("jwt_blacklist", jti);
        return score !== null;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The logout handler securely parses the JWT and adds the unique Token ID (`jti`) to a Redis Sorted Set, using the current timestamp as the sorting score, \[2] The architecture implements a vital memory safety optimization. It checks the cardinality (size) of the blacklist collection to prevent an unbounded memory leak inside the Redis cluster, \[3] The developer enforces a strict upper bound of 100,000 revoked tokens, \[4] The fatal flaw: If the limit is exceeded, the system blindly pops the oldest entry from the blacklist. Because this eviction is based purely on the _volume_ of incoming logouts rather than the mathematical expiration of the token (`exp`), an attacker can easily generate enough garbage logouts to overflow the set, evicting legitimately revoked tokens back into a trusted state

```http
// 1. Victim logs out. Their JTI is added to the blacklist.
POST /api/v1/auth/logout HTTP/1.1
Authorization: Bearer eyJhb...[VICTIM_JWT]...
```

```http
// 2. Attacker runs a script to flood the blacklist with 100,001 dummy logouts.
POST /api/v1/auth/logout HTTP/1.1
Authorization: Bearer eyJhb...[ATTACKER_DUMMY_JWT_1]...
...
POST /api/v1/auth/logout HTTP/1.1
Authorization: Bearer eyJhb...[ATTACKER_DUMMY_JWT_100001]...
```

```http
// 3. Attacker re-uses the Victim's supposedly destroyed JWT
GET /api/v1/admin/dashboard HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer eyJhb...[VICTIM_JWT]...
```

When the victim logged out, the system correctly added their `jti` to the `jwt_blacklist`. However, the attacker's script generated 100,001 subsequent legitimate logouts using automated dummy accounts. The Blacklist Service reached its `MAX_BLACKLIST_SIZE` capacity optimization and executed `zremrangebyrank`, forcefully evicting the victim's `jti` from Redis to make room for the flood. When the attacker presents the victim's token to the API, the cryptographic signature is perfectly valid, and the `exp` time has not yet passed. The API queries Redis to check if the `jti` is blacklisted. Because it was evicted, Redis returns `null`. The system concludes the token is fully active and grants administrative access, proving the memory optimization completely undermined the stateless logout boundary
{% endstep %}
{% endstepper %}

***

#### Zombie Sessions via OIDC Single Logout (SLO) Tenant Context Failure

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
Identify the Identity Federation architecture. In modern multi-tenant B2B environments, relying parties (the microservices) delegate authentication to a central Identity Provider (IdP) via OpenID Connect (OIDC)
{% endstep %}

{% step %}
Investigate the global logout strategy. When a user clicks "Logout" on the central IdP, the IdP terminates the global session and fires Back-Channel Single Logout (SLO) webhooks to all connected downstream microservices, instructing them to destroy their local application sessions
{% endstep %}

{% step %}
Analyze the ORM (Object-Relational Mapping) implementation in the downstream microservice. To enforce strict data isolation in a multi-tenant database, developers typically configure a "Global Tenant Filter" on the DbContext. Every SQL query automatically appends `WHERE tenant_id = @CurrentTenant` based on the context of the active HTTP request
{% endstep %}

{% step %}
Locate the OIDC Back-Channel Logout Webhook controller in the decompiled code
{% endstep %}

{% step %}
Observe how the controller parses the incoming `LogoutToken` (a JWT from the IdP) to extract the `sid` (Session ID). It then calls the ORM to delete the corresponding session record from the database
{% endstep %}

{% step %}
Recognize the architectural clash: The SLO webhook request originates from the central IdP server, _not_ the user's browser. Therefore, the HTTP request carries no tenant identification headers, subdomains, or cookies
{% endstep %}

{% step %}
Determine the outcome: Because the webhook lacks a tenant context, the ORM's Global Tenant Filter resolves the `CurrentTenant` to `null` or a `Default` value
{% endstep %}

{% step %}
The resulting SQL query executed by the ORM becomes: `DELETE FROM Sessions WHERE sid = 'victim_sid' AND tenant_id = NULL`
{% endstep %}

{% step %}
Ensure that this database transaction silently returns `0 rows affected` without throwing an exception, because the record exists under a specific Tenant ID, not `NULL`
{% endstep %}

{% step %}
Exploit this by stealing a victim's active downstream session cookie
{% endstep %}

{% step %}
Wait for the victim to click `"Logout"` via the central enterprise dashboard. The IdP fires the SLO webhook. The downstream microservice returns `200 OK` to the IdP, but fails to actually delete the session due to the tenant filter mismatch, Use the stolen session cookie. You maintain infinite, unrevokable "Zombie" access to the downstream application because the centralized logout pipeline mathematically cannot mutate tenant-scoped data without a tenant context

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:GlobalTenantFilter\b|builder\.HasQueryFilter\s*\(\s*\w+\s*=>\s*\w+\.TenantId\b|HasQueryFilter\s*\([^)]*TenantId\b|HandleSloWebhook\b[\s\S]{0,200}?SessionRepository\.(?:Delete|Remove|DeleteAsync)\b|SessionRepository\.(?:Delete|Remove|DeleteAsync)\s*\([^)]*TenantId\b|TenantContext\.(?:Current|GetCurrent|TenantId)\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:GlobalTenantFilter\b|@Filter\b[\s\S]{0,100}?tenantId|@Where\b[\s\S]{0,100}?tenant_id|Specification\b[\s\S]{0,100}?tenantId|handleSloWebhook\b[\s\S]{0,200}?sessionRepository\.(?:delete|remove|deleteById)\b|sessionRepository\.(?:delete|remove|deleteById)\s*\([^)]*tenantId\b|TenantContext\.(?:getCurrent|getTenantId)\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:GlobalTenantFilter\b|where\s*\(\s*['"]tenant_id['"]\s*,\s*TenantContext::(?:get|getTenantId)\s*\(|where\s*\(\s*['"]tenant_id['"]\s*,\s*\$tenantId\b|handleSloWebhook\b[\s\S]{0,200}?SessionRepository::(?:delete|remove)\b|SessionRepository::(?:delete|remove)\s*\([^)]*tenant_id\b|TenantScope\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:GlobalTenantFilter\b|where\s*\(\s*\{\s*tenantId\s*:\s*tenantContext\.(?:get|getTenantId)\s*\(\s*\)\s*\}\s*\)|findAll\s*\(\s*\{[\s\S]{0,100}?tenantId\b|handleSloWebhook\b[\s\S]{0,200}?sessionRepository\.(?:delete|remove|destroy)\b|sessionRepository\.(?:delete|remove|destroy)\s*\([^)]*tenantId\b|tenantContext\.(?:get|getTenantId)\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:GlobalTenantFilter\b|builder\.HasQueryFilter\s*\(\s*\w+\s*=>\s*\w+\.TenantId\b|HasQueryFilter\s*\([^)]*TenantId\b|HandleSloWebhook.*SessionRepository\.(?:Delete|Remove|DeleteAsync)\b|SessionRepository\.(?:Delete|Remove|DeleteAsync)\s*\([^)]*TenantId\b|TenantContext\.(?:Current|GetCurrent|TenantId)\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:GlobalTenantFilter\b|@Filter.*tenantId|@Where.*tenant_id|Specification.*tenantId|handleSloWebhook.*sessionRepository\.(?:delete|remove|deleteById)\b|sessionRepository\.(?:delete|remove|deleteById)\s*\([^)]*tenantId\b|TenantContext\.(?:getCurrent|getTenantId)\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:GlobalTenantFilter\b|where\s*\(\s*['"]tenant_id['"]\s*,\s*TenantContext::(?:get|getTenantId)\s*\(|where\s*\(\s*['"]tenant_id['"]\s*,\s*\$tenantId\b|handleSloWebhook.*SessionRepository::(?:delete|remove)\b|SessionRepository::(?:delete|remove)\s*\([^)]*tenant_id\b|TenantScope\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:GlobalTenantFilter\b|where\s*\(\s*\{\s*tenantId\s*:\s*tenantContext\.(?:get|getTenantId)\s*\(\s*\)\s*\}\s*\)|findAll\s*\(\s*\{.*tenantId\b|handleSloWebhook.*sessionRepository\.(?:delete|remove|destroy)\b|sessionRepository\.(?:delete|remove|destroy)\s*\([^)]*tenantId\b|tenantContext\.(?:get|getTenantId)\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/auth/backchannel-logout")]
public async Task<IActionResult> HandleSloWebhook([FromForm] string logout_token) 
{
    // [1]
    var claims = _jwtService.ValidateLogoutToken(logout_token);
    var sessionId = claims["sid"];

    // [2]
    // [3]
    var sessionRecord = await _dbContext.Sessions.FirstOrDefaultAsync(s => s.SessionId == sessionId);
    
    if (sessionRecord != null) 
    {
        // [4]
        _dbContext.Sessions.Remove(sessionRecord);
        await _dbContext.SaveChangesAsync();
    }

    return Ok();
}

// In DbContext Configuration:
// builder.Entity<Session>().HasQueryFilter(e => e.TenantId == _tenantContext.CurrentTenantId);
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping(value = "/api/v1/auth/backchannel-logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
public ResponseEntity<?> handleSloWebhook(@RequestParam("logout_token") String logoutToken) {
    // [1]
    Map<String, String> claims = jwtService.validateLogoutToken(logoutToken);
    String sessionId = claims.get("sid");

    // [2]
    // [3]
    SessionRecord sessionRecord = sessionRepository.findBySessionId(sessionId);
    
    if (sessionRecord != null) {
        // [4]
        sessionRepository.delete(sessionRecord);
    }

    return ResponseEntity.ok().build();
}

// In Hibernate Configuration:
// @FilterDef(name = "tenantFilter", parameters = {@ParamDef(name = "tenantId", type = "string")})
// @Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
```
{% endtab %}

{% tab title="PHP" %}
```php
public function handleSloWebhook(Request $request) 
{
    // [1]
    $claims = $this->jwtService->validateLogoutToken($request->input('logout_token'));
    $sessionId = $claims['sid'];

    // [2]
    // [3]
    $sessionRecord = SessionModel::where('session_id', $sessionId)->first();
    
    if ($sessionRecord) 
    {
        // [4]
        $sessionRecord->delete();
    }

    return response('OK', 200);
}

// In SessionModel Scope (Laravel Global Scope):
// static::addGlobalScope('tenant', function (Builder $builder) {
//     $builder->where('tenant_id', TenantContext::getCurrentTenantId());
// });
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/auth/backchannel-logout', async (req, res) => {
    // [1]
    let claims = jwtService.validateLogoutToken(req.body.logout_token);
    let sessionId = claims.sid;

    // [2]
    // [3]
    let sessionRecord = await SessionModel.findOne({ sessionId: sessionId });
    
    if (sessionRecord) {
        // [4]
        await sessionRecord.destroy();
    }

    res.status(200).send("OK");
});

// In Sequelize/Mongoose Global Hooks:
// schema.pre('findOne', function() {
//     this.where({ tenantId: TenantContext.getCurrentTenantId() });
// });
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The controller securely accepts the Back-Channel Logout webhook from the trusted central IdP and extracts the specific session identifier (`sid`) that needs to be revoked, \[2] The architecture relies heavily on ORM-level Global Tenant Filters to ensure data leakage across enterprise tenants is mathematically impossible during normal execution, \[3] Because the HTTP request originated from the IdP server, it contains no tenant identifying headers. The `TenantContext` resolves to `NULL`. The ORM transparently intercepts the `findBySessionId` query and injects `AND tenant_id = NULL,` \[4] The query executes safely but matches exactly zero rows, because the active session belongs to a real tenant (e.g., `tenant_id = 'org_77'`). The code treats this silently, assuming the session was already expired. The local application session remains perfectly valid in the database forever

```http
// 1. Attacker steals the Victim's downstream session cookie via XSS.
// 2. The Central IdP fires the SLO Webhook when the Victim logs out.
POST /api/v1/auth/backchannel-logout HTTP/1.1
Host: downstream-app.enterprise.tld
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1...[VALID_SLO_TOKEN]...
```

```http
// 3. The Downstream app responds 200 OK (but fails to delete the session).
HTTP/1.1 200 OK
```

```http
// 4. Attacker uses the stolen downstream cookie indefinitely.
GET /api/v1/workspaces/confidential-data HTTP/1.1
Host: downstream-app.enterprise.tld
Cookie: AppSession=VICTIM_STOLEN_SESSION_ID
```
{% endstep %}

{% step %}
The central Identity Provider performs its duties flawlessly, logging the user out and broadcasting cryptographic SLO tokens to all relying microservices. The relying downstream microservice receives the webhook, cryptographically validates it, and issues a database delete command. However, the architectural optimization of Global Tenant Filtering blindly intercepts the ORM query. Lacking an HTTP tenant context from the IdP, the query fails to match the victim's tenant-bound session record. The transaction completes with `0 rows affected` and returns a `200 OK` to the IdP. The attacker, holding the local downstream session cookie, discovers that their session never terminates, completely neutralizing the enterprise's federated logout boundary.
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
