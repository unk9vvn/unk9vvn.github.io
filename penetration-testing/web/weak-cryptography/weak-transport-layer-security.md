# Weak Transport Layer Security

## Check List

## Methodology

### Black Box

#### Deprecated Protocol Support

{% stepper %}
{% step %}
Access the target over HTTPS and intercept a normal request, Capture the request in Burp Suite

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the host to Burp Repeater
{% endstep %}

{% step %}
Use an external TLS testing tool ([testssl.sh](https://testssl.sh/) or sslyze) to check supported protocols
{% endstep %}

{% step %}
Test for deprecated protocols such as (SSLv3, TLS 1.0, TLS 1.1)
{% endstep %}

{% step %}
If connection succeeds using TLS 1.0 or TLS 1.1, deprecated protocol support is confirmed
{% endstep %}
{% endstepper %}

***

#### Weak Cipher Suites Enabled

{% stepper %}
{% step %}
Intercept any HTTPS request

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Use a TLS scanning tool to enumerate supported cipher suites
{% endstep %}

{% step %}
Look specifically for (RC4 cipher suites, 3DES, EXPORT cipher suites, NULL ciphers, Anonymous ciphers)
{% endstep %}

{% step %}
If connection negotiation succeeds with weak cipher suites, weak cipher configuration is confirmed
{% endstep %}
{% endstepper %}

***

#### Missing HSTS Header

{% stepper %}
{% step %}
Intercept the HTTPS response

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Check the server response headers, If the response does not contain

```http
Strict-Transport-Security: max-age=...
```
{% endstep %}

{% step %}
If HSTS header is missing or misconfigured, HTTPS downgrade risk exists
{% endstep %}
{% endstepper %}

***

#### Insecure HTTP to HTTPS Redirection

{% stepper %}
{% step %}
Access the application over HTTP

```http
GET / HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Observe the response, If the server does not immediately redirect to HTTPS with

```http
HTTP/1.1 301 Moved Permanently
Location: https://target.com/
```
{% endstep %}

{% step %}
Then secure redirection is not enforced, If HTTP version serves content without redirect, insecure transport is confirmed
{% endstep %}
{% endstepper %}

***

#### Certificate Weakness

{% stepper %}
{% step %}
Open the site in a browser and inspect the TLS certificate if the certificate uses (SHA-1, MD5 or Key size < 2048 bits)
{% endstep %}

{% step %}
Then weak certificate configuration is confirmed
{% endstep %}
{% endstepper %}

***

#### Mixed Content

{% stepper %}
{% step %}
Load any HTTPS page and intercept the response

```http
GET /secure-page HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Inspect HTML source for resources loaded over HTTP

```html
<script src="http://...">
<link href="http://...">
```
{% endstep %}

{% step %}
If active content (JS/CSS) loads over HTTP inside HTTPS page, mixed content vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Authorization Bypass via mTLS Termination Header Smuggling in Zero-Trust API Gateways

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
Identify if the enterprise utilizes a "Zero-Trust" internal mesh architecture requiring Mutual TLS (mTLS) for all service-to-service communication
{% endstep %}

{% step %}
Investigate the API Gateway's TLS offloading strategy. Performing mTLS handshakes and cryptographic certificate extraction on every single internal microservice hop consumes excessive CPU and increases latency
{% endstep %}

{% step %}
Discover the architectural optimization: The edge API Gateway terminates the external mTLS connection. To propagate the cryptographic identity downstream, the Gateway extracts the client certificate's Subject Distinguished Name (DN) or SHA256 Fingerprint and injects it into a standard HTTP header (e.g., `X-Internal-TLS-DN`)
{% endstep %}

{% step %}
Analyze the downstream microservices. Observe that they strictly rely on this injected HTTP header to materialize the transport-layer identity of the caller, assuming the API Gateway serves as an absolute trust boundary
{% endstep %}

{% step %}
Evaluate the API Gateway's ingress routing rules. Understand the engineering assumption: Developers assume that external users _cannot_ provide this header, or that the Gateway automatically overwrites it
{% endstep %}

{% step %}
Discover the routing configuration flaw: The API Gateway successfully injects and overwrites the `X-Internal-TLS-DN` header _if_ a client certificate is presented. However, to support hybrid routing for standard, non-mTLS external customers on the same ingress port, the Gateway leaves incoming headers untouched if no certificate is provided
{% endstep %}

{% step %}
Send a standard, unauthenticated HTTPS request from the public internet (without a client certificate)
{% endstep %}

{% step %}
Manually inject the `X-Internal-TLS-DN` header into your request, populating it with the exact Distinguished Name of a highly privileged internal microservice (e.g., `CN=internal-billing-service, O=Enterprise`)
{% endstep %}

{% step %}
The API Gateway detects no client certificate, skips the mTLS extraction phase, and forwards your request downstream with your spoofed header intact
{% endstep %}

{% step %}
The internal microservice receives the request, reads the header, assumes the transport layer was cryptographically verified by the Gateway, and grants administrative access to the internal mesh

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Request\.Headers\s*\[\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"\s*\]|HttpContext\.Request\.Headers\s*\[\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"\s*\]|Request\.Headers\.TryGetValue\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)")
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:request\.getHeader\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"\s*\)|@RequestHeader\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"|HttpHeaders\.getFirst\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)")
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$request->header\s*\(\s*['"]X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)['"]\s*\)|request\(\)->header\s*\(\s*['"]X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)['"]\s*\)|getallheaders\s*\(\)|apache_request_headers\s*\(\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.headers\s*\[\s*['"](?:x-internal-tls-dn|x-ssl-client-dn|x-ssl-client-cn|x-client-cert|x-forwarded-client-cert|x-client-verify|x-client-subject|x-authenticated-user|x-remote-user|x-forwarded-user|x-original-user|x-client-dn)['"]\s*\]|req\.get\s*\(\s*['"](?:x-internal-tls-dn|x-ssl-client-dn|x-ssl-client-cn|x-client-cert|x-forwarded-client-cert|x-client-verify|x-client-subject|x-authenticated-user|x-remote-user|x-forwarded-user|x-original-user|x-client-dn)['"]\s*\)|req\.header\s*\(\s*['"](?:x-internal-tls-dn|x-ssl-client-dn|x-ssl-client-cn|x-client-cert|x-forwarded-client-cert|x-client-verify|x-client-subject|x-authenticated-user|x-remote-user|x-forwarded-user|x-original-user|x-client-dn)['"]\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Request\.Headers\s*\[\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"\s*\]|HttpContext\.Request\.Headers\s*\[\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"\s*\]|Request\.Headers\.TryGetValue\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)")
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:request\.getHeader\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"\s*\)|@RequestHeader\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)"|HttpHeaders\.getFirst\s*\(\s*"X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)")    
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$request->header\s*\(\s*['"]X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)['"]\s*\)|request\(\)->header\s*\(\s*['"]X-(?:Internal-TLS-DN|SSL-Client-DN|SSL-Client-CN|Client-Cert|Forwarded-Client-Cert|Client-Verify|Client-Subject|Authenticated-User|Remote-User|Forwarded-User|Original-User|Client-DN)['"]\s*\)|getallheaders\s*\(\)|apache_request_headers\s*\(\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.headers\s*\[\s*['"](?:x-internal-tls-dn|x-ssl-client-dn|x-ssl-client-cn|x-client-cert|x-forwarded-client-cert|x-client-verify|x-client-subject|x-authenticated-user|x-remote-user|x-forwarded-user|x-original-user|x-client-dn)['"]\s*\]|req\.get\s*\(\s*['"](?:x-internal-tls-dn|x-ssl-client-dn|x-ssl-client-cn|x-client-cert|x-forwarded-client-cert|x-client-verify|x-client-subject|x-authenticated-user|x-remote-user|x-forwarded-user|x-original-user|x-client-dn)['"]\s*\)|req\.header\s*\(\s*['"](?:x-internal-tls-dn|x-ssl-client-dn|x-ssl-client-cn|x-client-cert|x-forwarded-client-cert|x-client-verify|x-client-subject|x-authenticated-user|x-remote-user|x-forwarded-user|x-original-user|x-client-dn)['"]\s*\))
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[ApiController]
[Route("api/v1/internal/billing")]
public class InternalBillingController : ControllerBase
{
    [HttpPost("execute-transfer")]
    public async Task<IActionResult> ExecuteTransfer([FromBody] TransferDto request)
    {
        // [1]
        // [2]
        var transportIdentity = Request.Headers["X-Internal-TLS-DN"].FirstOrDefault();

        // [3]
        if (string.IsNullOrEmpty(transportIdentity) || !transportIdentity.Contains("CN=internal-billing-service"))
        {
            return StatusCode(403, "Strict mTLS Transport Identity Required");
        }

        // [4]
        await _billingService.ExecuteSystemTransferAsync(request);
        return Ok(new { status = "Transfer Completed" });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
@RequestMapping("/api/v1/internal/billing")
public class InternalBillingController {

    @Autowired
    private BillingService billingService;

    @PostMapping("/execute-transfer")
    public ResponseEntity<?> executeTransfer(@RequestBody TransferDto requestDto, HttpServletRequest request) {
        // [1]
        // [2]
        String transportIdentity = request.getHeader("X-Internal-TLS-DN");

        // [3]
        if (transportIdentity == null || !transportIdentity.contains("CN=internal-billing-service")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Strict mTLS Transport Identity Required");
        }

        // [4]
        billingService.executeSystemTransfer(requestDto);
        return ResponseEntity.ok(Map.of("status", "Transfer Completed"));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class InternalBillingController extends Controller
{
    public function executeTransfer(Request $request)
    {
        // [1]
        // [2]
        $transportIdentity = $request->header('X-Internal-TLS-DN');

        // [3]
        if (empty($transportIdentity) || strpos($transportIdentity, 'CN=internal-billing-service') === false) {
            return response('Strict mTLS Transport Identity Required', 403);
        }

        // [4]
        $this->billingService->executeSystemTransfer($request->all());
        return response()->json(['status' => 'Transfer Completed']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/internal/billing/execute-transfer', async (req, res) => {
    // [1]
    // [2]
    let transportIdentity = req.headers['x-internal-tls-dn'];

    // [3]
    if (!transportIdentity || !transportIdentity.includes("CN=internal-billing-service")) {
        return res.status(403).send("Strict mTLS Transport Identity Required");
    }

    // [4]
    await billingService.executeSystemTransfer(req.body);
    res.json({ status: "Transfer Completed" });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The microservice operates within an internal zero-trust mesh. It implicitly trusts the API Gateway to terminate TLS and forward verified transport layer identity metadata, \[2] To avoid processing expensive X.509 certificates locally, the developer retrieves the identity strictly from an HTTP header, \[3] The service enforces authorization based entirely on this header, assuming the presence of `CN=internal-billing-service` mathematically proves the caller authenticated via a specific client certificate during the TLS handshake, \[4] The fatal architectural breakdown. Because the Edge Gateway failed to strip external attacker-injected headers when a client certificate was omitted, the transport-layer security boundary collapses entirely into simple HTTP header spoofing

```http
// 1. Attacker sends a standard HTTPS request to the public API Gateway.
// 2. The Attacker provides NO client certificate, bypassing the Gateway's mTLS extraction logic.
// 3. The Attacker injects the internal routing header manually.
POST /api/v1/internal/billing/execute-transfer HTTP/1.1
Host: gateway.enterprise.tld
X-Internal-TLS-DN: CN=internal-billing-service, O=Enterprise, C=US
Content-Type: application/json

{
  "sourceAccount": "system_reserve",
  "destinationAccount": "attacker_wallet",
  "amount": 500000
}
```
{% endstep %}

{% step %}
The API Gateway receives the external request. Because no client certificate is presented, the mTLS termination pipeline silently skips the identity extraction phase. Crucially, the Gateway's ingress configuration lacks an explicit instruction to drop `X-Internal-TLS-DN` headers originating from the public internet. The spoofed header is blindly forwarded to the downstream microservice. The internal microservice reads the header, believes the request originated from the highly privileged `internal-billing-service` over a cryptographically secured mTLS tunnel, and executes the financial transfer, resulting in complete internal network compromise
{% endstep %}
{% endstepper %}

***

#### Man-in-the-Middle via Eager Webhook Delivery Optimization (Hostname Verification Erasure)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite.
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify Event-Driven architectures dispatching outbound Webhooks to external Business-to-Business (B2B) partners (e.g., payment confirmations, audit logs, or data synchronization payloads)
{% endstep %}

{% step %}
Analyze the outbound HTTP Client factory used by the background webhook workers
{% endstep %}

{% step %}
Understand the engineering bottleneck: When broadcasting webhooks to thousands of distinct partner servers, many endpoints are poorly configured. Partners frequently use certificates with mismatched Subject Alternative Names (SANs), expired dates, or internal self-signed Root CAs
{% endstep %}

{% step %}
Observe the optimization: Strict TLS validation causes thousands of webhooks to fail, resulting in massive retry queues, database locks, and overwhelming customer support tickets. To ensure high delivery rates, developers implement a custom `ServerCertificateCustomValidationCallback` or `TrustManager`
{% endstep %}

{% step %}
Discover the critical implementation flaw: The custom validation logic is instructed to explicitly return `true` (valid) regardless of whether the target hostname matches the certificate presented by the server
{% endstep %}

{% step %}
Understand the assumption: Developers assume that outbound webhook payloads are "push only" and that TLS encryption alone (even if the identity is unverified) is sufficient to prevent passive eavesdropping on the wire
{% endstep %}

{% step %}
Determine if the webhook payload contains highly sensitive enterprise data, such as OAuth callback codes, PII, or internal administrative tokens
{% endstep %}

{% step %}
To exploit this, position an attacker-controlled server to intercept the webhook traffic (e.g., via BGP Hijacking, DNS Cache Poisoning against the enterprise's resolver, or compromising a router along the network path)
{% endstep %}

{% step %}
When the enterprise attempts to deliver the webhook to `[https://partner.com/webhook](https://partner.com/webhook)`, intercept the TCP connection
{% endstep %}

{% step %}
Present a completely valid TLS certificate belonging to `[https://attacker.com](https://attacker.com)` (easily generated via Let's Encrypt) to the enterprise client
{% endstep %}

{% step %}
Because the enterprise backend explicitly disabled Hostname Verification to optimize delivery, the TLS handshake succeeds despite the domain mismatch, delivering the sensitive webhook payload directly to the attacker

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ServerCertificateCustomValidationCallback\s*=\s*(?:\(.*?\)\s*=>\s*true|delegate\s*\{?\s*return\s+true)|DangerousAcceptAnyServerCertificateValidator|HttpClientHandler\.(?:ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator)|SslClientAuthenticationOptions\.(?:RemoteCertificateValidationCallback|CertificateRevocationCheckMode)|RemoteCertificateValidationCallback\s*=\s*(?:\(.*?\)\s*=>\s*true|delegate)|ServicePointManager\.ServerCertificateValidationCallback|X509CertificateValidator\.None|CertificateValidationCallback)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:checkServerTrusted\s*\(\s*X509Certificate\[\]\s*\w+\s*,\s*String\s+\w+\s*\)\s*\{\s*\}|X509TrustManager\b|TrustAllStrategy\b|NoopHostnameVerifier\b|HostnameVerifier\s*\{\s*public\s+boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true|setHostnameVerifier\s*\(\s*NoopHostnameVerifier|SSLContextBuilder\b.*loadTrustMaterial|OkHttpClient\.Builder\b.*hostnameVerifier|OkHttpClient\.Builder\b.*sslSocketFactory)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYPEER\s*,\s*false\s*\)|curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYHOST\s*,\s*0\s*\)|verify\s*=>\s*false|stream_context_create\s*\([^)]*verify_peer\s*=>\s*false|stream_context_create\s*\([^)]*verify_peer_name\s*=>\s*false|GuzzleHttp\\Client\b.*verify)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|https\.Agent\s*\(\s*\{[^}]*rejectUnauthorized\s*:\s*false|tls\.connect\s*\([^)]*rejectUnauthorized\s*:\s*false|axios\.create\s*\(\s*\{[^}]*httpsAgent|new\s+https\.Agent\s*\(\s*\{[^}]*rejectUnauthorized\s*:\s*false|process\.env\.NODE_TLS_REJECT_UNAUTHORIZED)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ServerCertificateCustomValidationCallback\s*=\s*(?:\(.*?\)\s*=>\s*true|delegate\s*\{?\s*return\s+true)|DangerousAcceptAnyServerCertificateValidator|HttpClientHandler\.(?:ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator)|SslClientAuthenticationOptions\.(?:RemoteCertificateValidationCallback|CertificateRevocationCheckMode)|RemoteCertificateValidationCallback\s*=\s*(?:\(.*?\)\s*=>\s*true|delegate)|ServicePointManager\.ServerCertificateValidationCallback|X509CertificateValidator\.None|CertificateValidationCallback)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:checkServerTrusted\s*\(\s*X509Certificate\[\]\s*\w+\s*,\s*String\s+\w+\s*\)\s*\{\s*\}|X509TrustManager\b|TrustAllStrategy\b|NoopHostnameVerifier\b|HostnameVerifier\s*\{\s*public\s+boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true|setHostnameVerifier\s*\(\s*NoopHostnameVerifier|SSLContextBuilder.*loadTrustMaterial|OkHttpClient\.Builder.*hostnameVerifier|OkHttpClient\.Builder.*sslSocketFactory)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYPEER\s*,\s*false\s*\)|curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYHOST\s*,\s*0\s*\)|verify\s*=>\s*false|stream_context_create\s*\([^)]*verify_peer\s*=>\s*false|stream_context_create\s*\([^)]*verify_peer_name\s*=>\s*false|GuzzleHttp\\Client.*verify)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|https\.Agent\s*\(\s*\{[^}]*rejectUnauthorized\s*:\s*false|tls\.connect\s*\([^)]*rejectUnauthorized\s*:\s*false|axios\.create\s*\(\s*\{[^}]*httpsAgent|new\s+https\.Agent\s*\(\s*\{[^}]*rejectUnauthorized\s*:\s*false|process\.env\.NODE_TLS_REJECT_UNAUTHORIZED)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookDeliveryService 
{
    private readonly HttpClient _httpClient;

    public WebhookDeliveryService() 
    {
        // [1]
        var handler = new HttpClientHandler 
        {
            // [2]
            // [3]
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };
        
        _httpClient = new HttpClient(handler);
    }

    public async Task DeliverPayloadAsync(string partnerUrl, object payload) 
    {
        // [4]
        var content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");
        await _httpClient.PostAsync(partnerUrl, content);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class WebhookDeliveryService {

    private RestTemplate restTemplate;

    public WebhookDeliveryService() throws Exception {
        // [1]
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                // [2]
                // [3]
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        
        CloseableHttpClient httpClient = HttpClients.custom()
            .setSSLContext(sc)
            .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
            .build();
            
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.restTemplate = new RestTemplate(factory);
    }

    public void deliverPayload(String partnerUrl, Object payload) {
        // [4]
        restTemplate.postForObject(partnerUrl, payload, String.class);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebhookDeliveryService 
{
    public function deliverPayload(string $partnerUrl, array $payload): void 
    {
        $ch = curl_init($partnerUrl);
        $jsonData = json_encode($payload);

        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        
        // [1]
        // [2]
        // [3]
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

        // [4]
        curl_exec($ch);
        curl_close($ch);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class WebhookDeliveryService {
    constructor() {
        // [1]
        // [2]
        // [3]
        this.httpsAgent = new https.Agent({
            rejectUnauthorized: false
        });
    }

    async deliverPayload(partnerUrl, payload) {
        // [4]
        await axios.post(partnerUrl, payload, {
            httpsAgent: this.httpsAgent
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The system configures the global HTTP client responsible for dispatching millions of background webhooks, \[2] To eliminate integration failures caused by partner misconfigurations (e.g., staging environments using self-signed certs or IP addresses instead of FQDNs), the developer intercepts the low-level TLS socket validation, \[3] The fatal cryptographic breakdown. By explicitly forcing the validation callback to return `true` or bypassing the Hostname Verifier, the client abandons identity verification. It encrypts the payload, but blindly trusts _any_ server that responds, effectively reducing TLS to opportunistic cleartextm, \[4] Highly sensitive enterprise payloads are beamed over this compromised transport layer. Active network attackers intercepting traffic are immune to certificate validation errors

```http
// 1. Attacker controls the network routing for a target B2B partner (e.g., DNS Hijacking partner.com).
// 2. The enterprise application triggers a background webhook destined for the partner.
// 3. The attacker intercepts the TCP connection and presents a valid certificate for 'attacker.com'.

// [TLS Handshake Details - Interception]
Server Certificate Subject: CN=attacker.com
Client Expected Subject: partner.com
Validation Result: Overridden (True)

// 4. The enterprise backend completes the handshake and delivers the payload to the attacker.
POST /webhook/ingest HTTP/1.1
Host: partner.com
Content-Type: application/json

{
  "event": "user_provisioned",
  "sso_initial_password": "Temp_Password_9912!",
  "admin_access_token": "eyJhbGci...[VALID_API_TOKEN]..."
}
```
{% endstep %}

{% step %}
To optimize webhook delivery reliability and reduce operational overhead, developers intentionally disabled cryptographic hostname verification. When the attacker hijacked the DNS resolution for `partner.com`, the enterprise backend initiated a TLS handshake with the attacker's server. The attacker presented a certificate valid for their own domain. Standard TLS validation would immediately terminate the connection due to a Subject Alternative Name (SAN) mismatch. However, the custom TrustManager optimization swallowed the error and approved the certificate. The backend established a secure, encrypted tunnel directly to the attacker and transmitted the sensitive provisioning payload, proving that resilient delivery optimization entirely negated Transport Layer Security identity boundaries
{% endstep %}
{% endstepper %}

***

#### Cryptographic Downgrade via Resilient B2B Connection Fallback

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
Identify integrations with massive, legacy supply-chain vendors or mainframe financial networks
{% endstep %}

{% step %}
Understand the architectural requirement: Business continuity. If the enterprise backend fails to connect to the supplier's API, manufacturing halts
{% endstep %}

{% step %}
Observe the engineering optimization: Legacy partners frequently fail to support modern TLS 1.3 or strong Authenticated Encryption with Associated Data (AEAD) ciphers. To ensure seamless interoperability, the backend `HttpClient` is wrapped in a "Resilience/Fallback" policy engine (e.g., Polly in C#, Resilience4j in Java)
{% endstep %}

{% step %}
Analyze the fallback logic in the decompiled code. The primary execution path enforces strict TLS 1.2/1.3 with strong ciphers to meet enterprise compliance
{% endstep %}

{% step %}
Discover the fallback mechanism: If the strict TLS handshake fails and throws an `SSLHandshakeException` or `AuthenticationException`, the Catch block (or Retry Policy) automatically generates a degraded TLS context
{% endstep %}

{% step %}
Verify that the degraded context explicitly re-enables obsolete protocols (TLS 1.0, TLS 1.1) and weak, factorable or padding-oracle vulnerable cipher suites (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`)
{% endstep %}

{% step %}
The developer assumption: Handshake failures strictly indicate passive compatibility issues with outdated partner servers, not active manipulation by network adversaries
{% endstep %}

{% step %}
Exploit this by establishing a Man-in-the-Middle position (e.g., ARP spoofing on an internal network segment, or compromising an upstream proxy)
{% endstep %}

{% step %}
When the enterprise backend attempts the strict TLS 1.3 `ClientHello`, actively drop the packet or inject a TCP RST frame, forcing the connection to violently terminate
{% endstep %}

{% step %}
The enterprise backend's resilience optimization catches the exception and immediately retries the connection using the degraded SSL context
{% endstep %}

{% step %}
Accept the degraded connection. Negotiate a weak, obsolete cipher suite. Exploit the weak transport layer cryptography (e.g., via passive decryption if the RSA key is known, or active padding oracle injection) to compromise the B2B transmission payload

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:catch\s*\(\s*.*?Exception.*?\)\s*\{[\s\S]{0,250}?SslProtocols\.(?:Tls|Tls11)\b|SslProtocols\.(?:Tls|Tls11)\b|SecurityProtocolType\.(?:Tls|Tls11)\b|EnabledSslProtocols\s*=\s*SslProtocols\.(?:Tls|Tls11)\b|SslClientAuthenticationOptions[\s\S]{0,150}?SslProtocols\.(?:Tls|Tls11))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:FallbackPolicy[\s\S]{0,150}?TlsVersion\.TLS_1_0|TlsVersion\.(?:TLS_1_0|TLS_1_1)\b|SSLContext\.getInstance\s*\(\s*"TLSv1(?:\.1)?"\s*\)|setEnabledProtocols\s*\(\s*new\s+String\s*\[\][\s\S]{0,120}?TLSv1(?:\.1)?|SSLSocket[\s\S]{0,120}?TLSv1)    
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:stream_context_create[\s\S]{0,200}?STREAM_CRYPTO_METHOD_TLSv1(?:_0)?_CLIENT|STREAM_CRYPTO_METHOD_TLSv1(?:_0)?_CLIENT|STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT|CURLOPT_SSLVERSION\s*,\s*CURL_SSLVERSION_TLSv1\b|crypto_method[\s\S]{0,80}?TLSv1)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:secureProtocol\s*:\s*['"]TLSv1(?:_method)?['"]|secureProtocol\s*:\s*['"]TLSv1_1_method['"]|minVersion\s*:\s*['"]TLSv1['"]|minVersion\s*:\s*['"]TLSv1\.1['"]|tls\.createSecureContext[\s\S]{0,120}?TLSv1)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
SslProtocols\.(?:Tls|Tls11)|SecurityProtocolType\.(?:Tls|Tls11)|EnabledSslProtocols\s*=\s*SslProtocols\.(?:Tls|Tls11)|catch\s*\([^)]*Exception[^)]*\).*SslProtocols\.(?:Tls|Tls11)
```
{% endtab %}

{% tab title="Java" %}
```regexp
TlsVersion\.(?:TLS_1_0|TLS_1_1)|SSLContext\.getInstance\("TLSv1(?:\.1)?"\)|setEnabledProtocols|SSLSocket.*TLSv1|FallbackPolicy.*TlsVersion
```
{% endtab %}

{% tab title="PHP" %}
```regexp
STREAM_CRYPTO_METHOD_TLSv1(?:_0)?_CLIENT|STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT|CURLOPT_SSLVERSION\s*,\s*CURL_SSLVERSION_TLSv1|crypto_method.*TLSv1
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
secureProtocol\s*:\s*['"]TLSv1(?:_method)?['"]|secureProtocol\s*:\s*['"]TLSv1_1_method['"]|minVersion\s*:\s*['"]TLSv1(?:\.1)?['"]|tls\.createSecureContext
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ResilientB2bClient 
{
    public async Task<string> FetchSupplyChainDataAsync(string url) 
    {
        try 
        {
            // [1]
            using var strictClient = new HttpClient();
            return await strictClient.GetStringAsync(url);
        }
        catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException) 
        {
            // [2]
            // [3]
            var handler = new HttpClientHandler 
            {
                // [4]
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | 
                               System.Security.Authentication.SslProtocols.Tls11 | 
                               System.Security.Authentication.SslProtocols.Tls
            };

            using var fallbackClient = new HttpClient(handler);
            return await fallbackClient.GetStringAsync(url);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class ResilientB2bClient {

    public String fetchSupplyChainData(String url) throws Exception {
        try {
            // [1]
            CloseableHttpClient strictClient = HttpClients.createDefault();
            HttpGet request = new HttpGet(url);
            return EntityUtils.toString(strictClient.execute(request).getEntity());
            
        } catch (SSLHandshakeException e) {
            // [2]
            // [3]
            SSLContext sslContext = SSLContexts.custom()
                // [4]
                .setProtocol("TLS") // Allows TLS 1.0/1.1 fallback
                .build();

            CloseableHttpClient fallbackClient = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();
                
            HttpGet request = new HttpGet(url);
            return EntityUtils.toString(fallbackClient.execute(request).getEntity());
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ResilientB2bClient 
{
    public function fetchSupplyChainData(string $url): string 
    {
        // [1]
        $strictContext = stream_context_create([
            'ssl' => [
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            ]
        ]);

        $response = @file_get_contents($url, false, $strictContext);

        if ($response === false) 
        {
            // [2]
            // [3]
            $fallbackContext = stream_context_create([
                'ssl' => [
                    // [4]
                    'crypto_method' => STREAM_CRYPTO_METHOD_ANY_CLIENT, // Allows TLS 1.0 fallback
                    'ciphers' => 'DEFAULT:@SECLEVEL=0'
                ]
            ]);

            $response = file_get_contents($url, false, $fallbackContext);
        }

        return $response;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ResilientB2bClient {
    static async fetchSupplyChainData(url) {
        try {
            // [1]
            return await axios.get(url, {
                httpsAgent: new https.Agent({ minVersion: 'TLSv1.2' })
            });
        } catch (error) {
            // [2]
            if (error.code === 'ECONNRESET' || error.message.includes('SSL routines')) {
                // [3]
                // [4]
                return await axios.get(url, {
                    httpsAgent: new https.Agent({ 
                        minVersion: 'TLSv1',
                        ciphers: 'ALL:@SECLEVEL=0'
                    })
                });
            }
            throw error;
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture strictly enforces modern TLS (1.2/1.3) by default, aiming to comply with enterprise cryptography standards for outbound B2B connections, \[2] The execution flow monitors specifically for cryptographic handshake failures, \[3] To optimize uptime and ensure critical supply-chain data is fetched regardless of legacy partner misconfigurations, the developer implements a resilient fallback catch block, \[4] The fatal cryptographic breakdown. The fallback context explicitly downgrades the minimum protocol version to TLS 1.0 or accepts deprecated cipher suites. Because this downgrade is triggered by an exception (which an active attacker can easily synthesize on the wire), the system provides a built-in, automated downgrade attack vector that completely bypasses the initial strict TLS enforcement

```http
// 1. Attacker is positioned on the local network (ARP Spoofing) or upstream ISP.
// 2. Enterprise backend attempts strict TLS 1.3 connection to legacy_partner.com
[Network Packet: TCP SYN ->]
[Network Packet: TCP SYN-ACK <-]
[Network Packet: TLSv1.3 Client Hello ->]

// 3. Attacker actively injects a forged TCP RST packet to kill the handshake.
[Network Packet: TCP RST (Injected by Attacker) <-]

// 4. Enterprise backend throws SSLHandshakeException, triggering the Fallback Policy.
// 5. Enterprise backend immediately retries with downgraded TLS context.
[Network Packet: TCP SYN ->]
[Network Packet: TCP SYN-ACK <-]
[Network Packet: TLSv1.0 Client Hello (Offering weak CBC ciphers) ->]

// 6. Attacker intercepts and negotiates weak cipher (e.g., TLS_RSA_WITH_AES_128_CBC_SHA).
// 7. Attacker executes Padding Oracle attack against the CBC cipher to decrypt the B2B payload.
```
{% endstep %}

{% step %}
The backend architecture optimized for business continuity inadvertently introduced a protocol downgrade vulnerability. When the attacker actively dropped the initial `ClientHello` packet, the backend's `HttpClient` interpreted the failure as a benign legacy compatibility issue rather than a cryptographic attack. The catch block executed the fallback policy, generating a degraded SSL context that permitted obsolete protocols and weak ciphers. The backend re-initiated the connection, allowing the attacker to successfully negotiate TLS 1.0 with a vulnerable CBC cipher. The attacker then executed standard cryptographic attacks against the weak cipher suite to decrypt the highly sensitive supply chain payload in transit, completely defeating the transport layer security boundary
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
