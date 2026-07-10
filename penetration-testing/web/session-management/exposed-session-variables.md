# Exposed Session Variables

## Check List

## Methodology

### Black Box

#### Exposed Session Tokens via Misconfigured

{% stepper %}
{% step %}
Log into a user account on target.com
{% endstep %}

{% step %}
Navigate to Settings, Edit Profile and change your username
{% endstep %}

{% step %}
Intercept the request using a proxy tool like Burp Suite
{% endstep %}

{% step %}
Send the request to Intruder, and set the `Token` header as the payload position
{% endstep %}

{% step %}
Use a list of random session token values, ending with the valid one
{% endstep %}

{% step %}
Launch the attack and analyze the responses
{% endstep %}

{% step %}
Invalid Tokens: Response code `401` with a body length of `431`
{% endstep %}

{% step %}
Valid Token: Response code `200` with a body length of `487`
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Isomorphic State Hydration Leak in SSR Architectures

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus heavily on initial page loads and HTML source code rather than just XHR/Fetch API responses
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Isomorphic" or Server-Side Rendering (SSR) architecture (e.g., Next.js, Nuxt.js, Blazor Server, or Spring Boot with embedded frontend templates)
{% endstep %}

{% step %}
Understand the engineering optimization: In modern Single Page Applications (SPAs), fetching user session state and permissions via an API _after_ the page loads causes a noticeable "flicker" and increases Time-To-Interactive (TTI)
{% endstep %}

{% step %}
To solve this bottleneck, developers utilize State Hydration. The backend fetches the `SessionSchema` from the distributed cache, uses it to render the initial HTML on the server, and then serializes the _entire_ session object into a global JavaScript variable (e.g., `window.__INITIAL_STATE__` or a hidden `<script type="application/json">` tag)
{% endstep %}

{% step %}
The frontend framework reads this embedded JSON payload to "hydrate" its local state management (like Redux or Vuex) instantly, achieving zero-roundtrip state initialization
{% endstep %}

{% step %}
Locate the Controller or Middleware responsible for passing the backend session context to the SSR rendering engine
{% endstep %}

{% step %}
Evaluate the `SessionSchema` object in the backend code. Look for backend-exclusive variables attached to the session for convenience during internal processing (e.g., `DownstreamApiToken`, `ImpersonationActive`, `InternalRoutingId`, or `MfaRecoverySecret`)
{% endstep %}

{% step %}
Determine if the developer explicitly mapped the `SessionSchema` to a `PublicUserDto` before serialization, or if they blindly serialized the raw backend session object directly into the HTML template to save time and maintain synchronization between backend and frontend state structures
{% endstep %}

{% step %}
Load the web application as a standard, low-privilege user, Inspect the raw HTML source code of the response. Locate the state hydration script block
{% endstep %}

{% step %}
Extract the leaked backend-exclusive session variables from the serialized JSON payload.
{% endstep %}

{% step %}
Utilize the exposed internal token or routing identifier to directly query downstream microservices or internal APIs that trust the token, completely bypassing the API Gateway's intended authorization layer

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:JsonConvert\.SerializeObject\s*\([^)]*\bSession\b|System\.Text\.Json\.JsonSerializer\.Serialize\s*\([^)]*\bSession\b|JSON\.Serialize\s*\([^)]*\bSession\b|ViewData\s*\[\s*["']session["']\s*\]|TempData\s*\[\s*["']session["']\s*\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:ObjectMapper\b[\s\S]{0,100}?writeValueAsString\s*\([^)]*\bsession\b|new\s+ObjectMapper\s*\(|new\s+Gson\s*\(\)\.toJson\s*\([^)]*\bsession\b|JSONObject\.toJSONString\s*\([^)]*\bsession\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:json_encode\s*\(\s*\$session\b|@json\s*\(\s*\$session\b|echo\s+json_encode\s*\(\s*\$session\b|serialize\s*\(\s*\$session\b|\$_SESSION\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:JSON\.stringify\s*\([^)]*\bsession\b|window\.__INITIAL_STATE__\s*=\s*[^;]*session|res\.json\s*\(\s*.*session|res\.send\s*\(\s*.*session|res\.render\s*\([^)]*session|serialize\s*\(\s*session\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:JsonConvert\.SerializeObject\s*\([^)]*\bSession\b|System\.Text\.Json\.JsonSerializer\.Serialize\s*\([^)]*\bSession\b|JSON\.Serialize\s*\([^)]*\bSession\b|ViewData\s*\[\s*["']session["']\s*\]|TempData\s*\[\s*["']session["']\s*\])
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:ObjectMapper.*writeValueAsString\s*\([^)]*\bsession\b|new\s+ObjectMapper\s*\(|new\s+Gson\s*\(\)\.toJson\s*\([^)]*\bsession\b|JSONObject\.toJSONString\s*\([^)]*\bsession\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:json_encode\s*\(\s*\$session\b|@json\s*\(\s*\$session\b|echo\s+json_encode\s*\(\s*\$session\b|serialize\s*\(\s*\$session\b|\$_SESSION\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:JSON\.stringify\s*\([^)]*\bsession\b|window\.__INITIAL_STATE__\s*=\s*.*session|res\.json\s*\(\s*.*session|res\.send\s*\(\s*.*session|res\.render\s*\([^)]*session|serialize\s*\(\s*session\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SsrController : Controller
{
    private readonly ISessionCache _sessionCache;

    [HttpGet("/dashboard")]
    public async Task<IActionResult> Dashboard()
    {
        var sessionId = Request.Cookies["AuthSession"];
        // [1]
        var backendSession = await _sessionCache.GetAsync(sessionId);

        // [2]
        // [3]
        ViewBag.InitialState = JsonConvert.SerializeObject(backendSession);

        // [4]
        return View("~/Views/Spa/Index.cshtml");
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Controller
public class SsrController {

    @Autowired
    private SessionCache sessionCache;
    @Autowired
    private ObjectMapper objectMapper;

    @GetMapping("/dashboard")
    public String dashboard(@CookieValue("AuthSession") String sessionId, Model model) throws Exception {
        // [1]
        BackendSession backendSession = sessionCache.get(sessionId);

        // [2]
        // [3]
        String serializedState = objectMapper.writeValueAsString(backendSession);
        model.addAttribute("initialState", serializedState);

        // [4]
        return "spa-index"; 
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SsrController extends Controller
{
    public function dashboard(Request $request)
    {
        // [1]
        $backendSession = $request->session()->all();

        // [2]
        // [3]
        $serializedState = json_encode($backendSession);

        // [4]
        return view('spa.index', [
            'initialState' => $serializedState
        ]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SsrController {
    static async renderDashboard(req, res) {
        // [1]
        let backendSession = req.session;

        // [2]
        // [3]
        let serializedState = JSON.stringify(backendSession);

        // [4]
        res.render('spa-index', { 
            initialState: serializedState 
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The controller retrieves the authoritative `BackendSession` from the database or memory. This object contains data meant only for server-to-server communication, such as a `DownstreamMicroserviceJwt` used by the backend to fetch user data from an internal billing service, \[2] The architectural flaw: The developer decides to pass the session to the frontend state manager. To avoid writing and maintaining a separate `PublicFrontendSessionDto`, they optimize the workflow by serializing the entire object, \[3] The serialization engine recursively converts the backend session, including its hidden private fields and internal access tokens, into a raw JSON string, \[4] The HTML templating engine (e.g., Razor, Thymeleaf, Blade, EJS) interpolates the JSON directly into the DOM (e.g., `<script>window.__STATE__ = @Html.Raw(ViewBag.InitialState);</script>`). The backend variables are now completely exposed in the client's browser

```http
// 1. Attacker requests the main dashboard page
GET /dashboard HTTP/1.1
Host: app.enterprise.tld
Cookie: AuthSession=LOW_PRIV_TOKEN
```

```http
// 2. The server responds with the SSR HTML containing the hydration state
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <script>
        window.__INITIAL_STATE__ = {
            "userId": "99812",
            "theme": "dark",
            "downstream_internal_jwt": "eyJhbGciOiJSUzI1NiI...[ADMIN_TOKEN]..."
        };
    </script>
</head>
<body>...</body>
</html>
```

```http
// 3. Attacker extracts the leaked `downstream_internal_jwt` from the source code.
// 4. Attacker directly queries the internal/backend microservice using the leaked token.
GET /api/internal/billing/export-all HTTP/1.1
Host: internal-api.enterprise.tld
Authorization: Bearer eyJhbGciOiJSUzI1NiI...[ADMIN_TOKEN]...
```
{% endstep %}

{% step %}
The architectural optimization of Zero-Roundtrip State Hydration completely bypasses the principle of least privilege. Because the developers failed to project the `BackendSession` into a strictly defined frontend DTO, the server-side rendering pipeline faithfully serialized and delivered internal service tokens directly to the browser. The attacker simply Views Source, parses the JSON payload, and leverages the exposed `downstream_internal_jwt` to access internal microservices that implicitly trust the token, resulting in complete enterprise compromise
{% endstep %}
{% endstepper %}

***

#### Sensitive Session Exposure via GraphQL Error Extension Projection

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
Identify if the enterprise utilizes GraphQL Federation (e.g., Apollo Router, HotChocolate) to unify multiple downstream REST APIs and microservices into a single graph
{% endstep %}

{% step %}
In GraphQL architectures, the API Gateway parses the incoming JWT/Cookie and builds a massive `SessionContext` object. This context is passed down through the resolver chain so every subgraph resolver can independently authorize the request without re-parsing the token
{% endstep %}

{% step %}
Investigate the enterprise's Observability and Monitoring optimization. In distributed GraphQL systems, when a specific subgraph fails, debugging is notoriously difficult because the frontend only receives a generic "Internal Server Error"
{% endstep %}

{% step %}
To optimize frontend observability and telemetry (e.g., for Datadog or Sentry RUM), developers implement a Custom Error Formatter. When an exception occurs, this formatter catches the error, extracts the active `SessionContext` from the GraphQL execution state, and appends it to the `extensions` payload of the GraphQL error response
{% endstep %}

{% step %}
The architectural assumption is that the `extensions` block is harmless or that the `SessionContext` only contains safe tracking IDs
{% endstep %}

{% step %}
Analyze the `SessionContext` building logic. Note that it contains deeply sensitive session variables (e.g., `BcryptPasswordHash`, `OAuthRefreshToken`, `InternalRiskScore`, or `GlobalAdminOverrideKey`)
{% endstep %}

{% step %}
Trigger a deliberate validation failure, type mismatch, or subgraph timeout by sending a malformed GraphQL query (e.g., passing a String to an Int argument, or requesting an impossibly deep nested relation)
{% endstep %}

{% step %}
The GraphQL engine throws an exception. The custom Error Formatter intercepts it, injects the `SessionContext` into the error's `extensions` dictionary, and serializes it back to the client
{% endstep %}

{% step %}
Read the GraphQL JSON response. Extract the exposed internal session variables from the `errors[0].extensions.sessionContext` payload
{% endstep %}

{% step %}
Utilize the exposed `GlobalAdminOverrideKey` or `OAuthRefreshToken` to elevate privileges or hijack the session indefinitely

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:error\.Extensions\.Add\s*\(\s*"sessionContext"\s*,|error\.Extensions\s*\[\s*"sessionContext"\s*\]\s*=|extensions\.Add\s*\(\s*"sessionContext"\s*,|GraphQLError\b[\s\S]{0,200}?Extensions\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:extensions\.put\s*\(\s*"sessionContext"\s*,|error\.getExtensions\s*\(\s*\)\.put\s*\(\s*"sessionContext"\s*,|GraphqlErrorBuilder\b[\s\S]{0,200}?extensions\s*\(|GraphQLError\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$error\s*\[\s*['"]extensions['"]\s*\]\s*\[\s*['"]sessionContext['"]\s*\]|['"]extensions['"]\s*=>\s*\[[\s\S]{0,150}?['"]sessionContext['"]|GraphQL\\Error\\Error\b|GraphQL\\Error\\FormattedError\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:err\.extensions\.sessionContext\s*=\s*context|error\.extensions\.sessionContext\s*=\s*context|extensions\s*:\s*\{[\s\S]{0,150}?sessionContext|new\s+GraphQLError\b[\s\S]{0,200}?extensions\b|formatError\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:error\.Extensions\.Add\s*\(\s*"sessionContext"\s*,|error\.Extensions\s*\[\s*"sessionContext"\s*\]\s*=|extensions\.Add\s*\(\s*"sessionContext"\s*,|GraphQLError.*Extensions\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:extensions\.put\s*\(\s*"sessionContext"\s*,|error\.getExtensions\s*\(\s*\)\.put\s*\(\s*"sessionContext"\s*,|GraphqlErrorBuilder.*extensions\s*\(|GraphQLError\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$error\s*\[\s*['"]extensions['"]\s*\]\s*\[\s*['"]sessionContext['"]\s*\]|['"]extensions['"]\s*=>\s*\[.*['"]sessionContext['"]|GraphQL\\Error\\Error\b|GraphQL\\Error\\FormattedError\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:err\.extensions\.sessionContext\s*=\s*context|error\.extensions\.sessionContext\s*=\s*context|extensions\s*:\s*\{.*sessionContext|new\s+GraphQLError.*extensions\b|formatError\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class CustomErrorFilter : IErrorFilter
{
    public IError OnError(IError error)
    {
        // [1]
        if (error.Exception != null && error.ContextData.TryGetValue("SessionContext", out var sessionContext))
        {
            // [2]
            // [3]
            // [4]
            return error.WithExtensions(new Dictionary<string, object?>
            {
                { "code", "SUBGRAPH_FAILURE" },
                { "timestamp", DateTime.UtcNow },
                { "sessionContext", sessionContext } 
            });
        }

        return error;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class CustomDataFetcherExceptionHandler implements DataFetcherExceptionHandler {

    @Override
    public CompletableFuture<DataFetcherExceptionHandlerResult> handleException(DataFetcherExceptionHandlerParameters handlerParameters) {
        Throwable exception = handlerParameters.getException();
        
        // [1]
        SessionContext sessionContext = handlerParameters.getDataFetchingEnvironment().getGraphQlContext().get("SessionContext");

        // [2]
        // [3]
        // [4]
        GraphqlError error = GraphqlErrorBuilder.newError(handlerParameters.getDataFetchingEnvironment())
                .message(exception.getMessage())
                .extensions(Map.of(
                        "code", "SUBGRAPH_FAILURE",
                        "sessionContext", sessionContext
                ))
                .build();

        return CompletableFuture.completedFuture(DataFetcherExceptionHandlerResult.newResult().error(error).build());
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class GraphQLContextErrorFormatter implements ErrorFormatter
{
    public function format(Error $error): array
    {
        $formattedError = Formatter::formatError($error);

        // [1]
        $sessionContext = GraphQLContext::get('SessionContext');

        if ($sessionContext) {
            // [2]
            // [3]
            // [4]
            $formattedError['extensions']['code'] = 'SUBGRAPH_FAILURE';
            $formattedError['extensions']['sessionContext'] = $sessionContext;
        }

        return $formattedError;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const server = new ApolloServer({
    typeDefs,
    resolvers,
    formatError: (err) => {
        // [1]
        let sessionContext = err.extensions?.exception?.context?.sessionContext;

        if (sessionContext) {
            // [2]
            // [3]
            // [4]
            return {
                message: err.message,
                extensions: {
                    code: 'SUBGRAPH_FAILURE',
                    sessionContext: sessionContext
                }
            };
        }
        
        return err;
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Error Formatter intercepts the execution failure. It reaches into the global GraphQL context to retrieve the `SessionContext` object that was built by the API Gateway during the initial request handshake, \[2] To provide maximum debugging context for frontend error-reporting tools (like Sentry), the developer decides to project the backend context into the public response, \[3] The developer assumes that because the GraphQL endpoint is consumed by their own SPA, exposing this data is harmless "telemetry", \[4] The serialization engine blindly attaches the complex `SessionContext` object into the `extensions` block. Any hidden backend properties, such as raw OAuth Refresh Tokens, internal tenant-routing mappings, or temporary impersonation keys, are perfectly serialized and returned in the HTTP response

```http
// 1. Attacker sends a deliberately malformed GraphQL query to trigger a backend exception
POST /graphql HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <low-priv-token>
Content-Type: application/json

{
  "query": "query { getUserProfile(id: \"INVALID_UUID_FORMAT_TO_TRIGGER_ERROR\") { name email } }"
}
```

```http
// 2. The server processes the request, throws a UUID parse exception, and invokes the Error Formatter
HTTP/1.1 200 OK
Content-Type: application/json

{
  "errors": [
    {
      "message": "Invalid UUID string: INVALID_UUID_FORMAT_TO_TRIGGER_ERROR",
      "locations": [ { "line": 1, "column": 9 } ],
      "path": [ "getUserProfile" ],
      "extensions": {
        "code": "SUBGRAPH_FAILURE",
        "sessionContext": {
          "userId": "10045",
          "tenantId": "org-77",
          "oauth_refresh_token": "1//04xxxxx_REFRESH_TOKEN_xxxxx",
          "internal_admin_bypass": false
        }
      }
    }
  ]
}
```
{% endstep %}

{% step %}
By deliberately violating a subgraph's expected input format, the attacker forces the GraphQL execution engine to throw an unhandled exception. The enterprise's centralized Observability optimization intercepts this exception and enriches the GraphQL error payload with the backend `SessionContext` to assist frontend telemetry. This architectural optimization inadvertently dumps the raw backend session state—including the highly sensitive `oauth_refresh_token`—directly into the JSON response. The attacker extracts this refresh token, issues a request to the Identity Provider, and mints a brand new, infinite-lifetime access token, entirely hijacking the account
{% endstep %}
{% endstepper %}

***

#### Authorization Token Leakage via WebSocket Zero-Roundtrip State Synchronization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Pay special attention to persistent connections (WebSockets / Server-Sent Events)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the real-time interaction architecture (e.g., collaborative dashboards, live trading, chat modules). These features typically initiate via a standard HTTP request, authenticate via cookies/headers, and then issue an `HTTP 101 Switching Protocols` to upgrade to a WebSocket
{% endstep %}

{% step %}
Investigate the "Zero-Roundtrip State Hydration" optimization. When a WebSocket connects, the client-side SPA loses its standard HTTP request/response context. Instead of forcing the client to send a `WhoAmI` message and wait for a response, the server optimally broadcasts an initialization frame (e.g., `CONNECTION_ACK` or `SYNC_STATE`) the millisecond the TCP socket opens
{% endstep %}

{% step %}
In the decompiled WebSocket connection handler, analyze how this initialization frame is built
{% endstep %}

{% step %}
Observe that the backend fetches the user's `SessionSchema` from the distributed Redis cache to verify the connection
{% endstep %}

{% step %}
Discover the data leakage flaw: Instead of mapping the `SessionSchema` to a `SafeClientStateDto`, the backend framework directly serializes the entire Redis session hash and pushes it down the WebSocket pipe inside the `SYNC_STATE` payload
{% endstep %}

{% step %}
Analyze the contents of the `SessionSchema` in Redis. Due to the architecture of the real-time system, the session object holds an `InternalBrokerToken` (e.g., a RabbitMQ JWT or Kafka SASL credential) generated during login, which allows the backend WebSocket server to subscribe to internal message queues on the user's behalf
{% endstep %}

{% step %}
Connect to the WebSocket endpoint using a low-privilege account
{% endstep %}

{% step %}
Inspect the raw WebSocket frames in Burp Suite
{% endstep %}

{% step %}
Read the initial `SYNC_STATE` message sent by the server. Extract the leaked `InternalBrokerToken` from the serialized session dictionary
{% endstep %}

{% step %}
Because message brokers (like RabbitMQ with Web-Stomp enabled) are often exposed on the same API gateway for performance reasons, use the extracted broker token to authenticate directly against the internal pub/sub infrastructure. Subscribe to privileged topics (e.g., `/topic/admin.alerts` or `/exchange/financial.transactions`) and bypass the application logic entirely

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+\w+\.SendAsync\s*\([^)]*\bSession(Cache|Store)?\.(?:Get|GetAsync)\b|Clients\.(?:All|Caller|Client|Group)\.SendAsync\s*\([^)]*\bsession\b|HubContext\b[\s\S]{0,200}?SendAsync\b|SessionCache\.(?:Get|GetAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:session\.getBasicRemote\s*\(\s*\)\.sendText\s*\([^)]*\bsession\w*\b|RemoteEndpoint\.Basic\b[\s\S]{0,200}?sendText\s*\(|Session\b[\s\S]{0,200}?getBasicRemote\s*\(\)|ObjectMapper\b[\s\S]{0,100}?writeValueAsString\s*\([^)]*\bsession\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:ws->send\s*\(\s*json_encode\s*\(\s*\$_SESSION\s*\)\s*\)|conn->send\s*\(\s*json_encode\s*\(\s*\$_SESSION\s*\)\s*\)|json_encode\s*\(\s*\$_SESSION\s*\)|Ratchet\\ConnectionInterface\b[\s\S]{0,200}?send\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:ws\.send\s*\(\s*JSON\.stringify\s*\(\s*\{[\s\S]{0,150}?session\s*:\s*req\.session|socket\.emit\s*\([^)]*\bsession\b|io\.emit\s*\([^)]*\bsession\b|socket\.send\s*\(\s*JSON\.stringify\s*\([^)]*\bsession\b|JSON\.stringify\s*\([^)]*\breq\.session\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+\w+\.SendAsync\s*\([^)]*\bSession(Cache|Store)?\.(?:Get|GetAsync)\b|Clients\.(?:All|Caller|Client|Group)\.SendAsync\s*\([^)]*\bsession\b|HubContext.*SendAsync\b|SessionCache\.(?:Get|GetAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:session\.getBasicRemote\s*\(\s*\)\.sendText\s*\([^)]*\bsession\w*\b|RemoteEndpoint\.Basic.*sendText\s*\(|Session.*getBasicRemote\s*\(\)|ObjectMapper.*writeValueAsString\s*\([^)]*\bsession\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:ws->send\s*\(\s*json_encode\s*\(\s*\$_SESSION\s*\)\s*\)|conn->send\s*\(\s*json_encode\s*\(\s*\$_SESSION\s*\)\s*\)|json_encode\s*\(\s*\$_SESSION\s*\)|Ratchet\\ConnectionInterface.*send\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:ws\.send\s*\(\s*JSON\.stringify\s*\(\s*\{.*session\s*:\s*req\.session|socket\.emit\s*\([^)]*\bsession\b|io\.emit\s*\([^)]*\bsession\b|socket\.send\s*\(\s*JSON\.stringify\s*\([^)]*\bsession\b|JSON\.stringify\s*\([^)]*\breq\.session\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class RealTimeHub : Hub
{
    private readonly ISessionCache _sessionCache;

    public override async Task OnConnectedAsync()
    {
        var sessionId = Context.GetHttpContext().Request.Cookies["AuthSession"];
        // [1]
        var sessionData = await _sessionCache.GetAsync(sessionId);

        // [2]
        // [3]
        // [4]
        var initPayload = new 
        {
            type = "SYNC_STATE",
            session = sessionData
        };

        await Clients.Caller.SendAsync("ReceiveMessage", JsonConvert.SerializeObject(initPayload));
        await base.OnConnectedAsync();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class RealTimeWebSocketHandler extends TextWebSocketHandler {

    @Autowired
    private SessionCache sessionCache;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void afterConnectionEstablished(WebSocketSession wsSession) throws Exception {
        String sessionId = extractCookie(wsSession, "AuthSession");
        
        // [1]
        BackendSession sessionData = sessionCache.get(sessionId);

        // [2]
        // [3]
        // [4]
        Map<String, Object> initPayload = new HashMap<>();
        initPayload.put("type", "SYNC_STATE");
        initPayload.put("session", sessionData);

        wsSession.sendMessage(new TextMessage(objectMapper.writeValueAsString(initPayload)));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class RealTimeWebSocketHandler implements MessageComponentInterface 
{
    protected $sessionCache;

    public function onOpen(ConnectionInterface $conn) 
    {
        $sessionId = $this->extractCookie($conn->httpRequest, 'AuthSession');
        
        // [1]
        $sessionData = $this->sessionCache->get($sessionId);

        // [2]
        // [3]
        // [4]
        $initPayload = [
            'type' => 'SYNC_STATE',
            'session' => $sessionData
        ];

        $conn->send(json_encode($initPayload));
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
io.on('connection', async (socket) => {
    let sessionId = parseCookie(socket.handshake.headers.cookie, 'AuthSession');
    
    // [1]
    let sessionData = await sessionCache.get(sessionId);

    // [2]
    // [3]
    // [4]
    let initPayload = {
        type: 'SYNC_STATE',
        session: sessionData
    };

    socket.emit('message', JSON.stringify(initPayload));
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
`[1]` The WebSocket upgrade handler retrieves the active user session from the distributed cache using the HTTP cookie provided during the TCP handshake. This object contains the user's display name, tenant ID, and crucially, an `InternalBrokerToken` generated during login to authenticate against internal message queues, `[2]` To optimize frontend startup time and prevent the client from requesting its profile data over a separate HTTP call, the developer implements Zero-Roundtrip State Hydration, `[3]` The architectural flaw: The developer bypasses DTO projection. Instead of building a specific message containing only the user's public profile, they blindly attach the entire backend `SessionSchema` object to the initialization payload, `[4]` The server immediately broadcasts this payload down the newly established WebSocket tunnel. The raw backend session variables, including the highly sensitive `InternalBrokerToken`, leak directly into the client's network traffic in the first millisecond of the connection

```http
// 1. Attacker initiates the WebSocket upgrade handshake
GET /realtime-hub HTTP/1.1
Host: ws.enterprise.tld
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Cookie: AuthSession=LOW_PRIV_TOKEN
```

```http
// 2. Server accepts the connection
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

```http
// 3. Immediately after the TCP connection upgrades, the server pushes the SYNC frame
// [WebSocket Receive]
{
  "type": "SYNC_STATE",
  "session": {
    "userId": "9912",
    "tenantId": "customer-abc",
    "internal_broker_token": "amqp://svc_account:SecretKey@rabbitmq.internal.tld:5672/vhost"
  }
}
```
{% endstep %}

{% step %}
By analyzing the real-time synchronization architecture, the attacker observes that the initial WebSocket frame aggressively pushes backend state to the client to optimize frontend render times. Because the developer failed to implement a secure projection pipeline between the Redis session cache and the WebSocket output stream, the entire backend dictionary is serialized into the frame. The attacker captures the incoming `SYNC_STATE` message, extracts the `internal_broker_token` (a raw AMQP connection string or JWT meant strictly for server-to-server pub/sub authentication), and connects directly to the enterprise's internal event bus, gaining the ability to read and inject messages across the entire distributed system
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
