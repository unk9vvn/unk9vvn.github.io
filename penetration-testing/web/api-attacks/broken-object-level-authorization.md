# Broken Object Level Authorization

## Check List

## Methodology

### Black Box

#### IDOR

{% stepper %}
{% step %}
Create two accounts on the target (Account A = yours, Account B = second/test account)
{% endstep %}

{% step %}
Perform any action with Account A that returns or uses an object ID, Common places

```
Your profile → returns "id": 12345
Your orders → /api/orders/9876
Your files → /files/abc-xyz-111
Your settings → /api/v1/users/852
```
{% endstep %}

{% step %}
Collect every ID you see in responses (numeric, UUID, base64, hashed, username-based, etc.)
{% endstep %}

{% step %}
Switch to Account B (or log out completely) and repeat the exact same requests but replace the ID with the one from Account A
{% endstep %}

{% step %}
If you can view, modify, or delete Account A’s resource → BOLA confirmed
{% endstep %}
{% endstepper %}

***

#### Updating Another User’s Object

{% stepper %}
{% step %}
Login as a normal user
{% endstep %}

{% step %}
Intercept profile update request

```http
PUT /api/users/1024 HTTP/1.1
Host: target.com
Authorization: Bearer user_token_1024
Content-Type: application/json

{"phone":"9999999999"}
```
{% endstep %}

{% step %}
Modify object ID

```http
PUT /api/users/1025 HTTP/1.1
Host: target.com
Authorization: Bearer user_token_1024
Content-Type: application/json

{"phone":"8888888888"}
```
{% endstep %}

{% step %}
Forward the request
{% endstep %}

{% step %}
If another user’s profile is updated successfully, write-level object authorization is missing
{% endstep %}

{% step %}
If no ownership validation is enforced server-side, BOLA vulnerability is confirmed.
{% endstep %}
{% endstepper %}

***

#### Accessing Files via Object Key Manipulation

{% stepper %}
{% step %}
Login normally
{% endstep %}

{% step %}
Access file endpoint

```http
GET /api/files/INV-2024-001.pdf HTTP/1.1
Host: target.com
Authorization: Bearer token_userA
```
{% endstep %}

{% step %}
Modify file identifier

```http
GET /api/files/INV-2024-002.pdf HTTP/1.1
Host: target.com
Authorization: Bearer token_userA
```
{% endstep %}

{% step %}
Send request
{% endstep %}

{% step %}
If unauthorized file belonging to another account is returned, object-level access control is missing
{% endstep %}

{% step %}
If file retrieval is based solely on predictable object keys, BOLA is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### BOLA via Disconnected Nested Resource Routing (Hierarchical IDOR)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise APIs that utilize strictly enforced RESTful hierarchical routing (e.g., `/api/v1/companies/{company_id}/invoices/{invoice_id}`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's routing and the backend authorization middleware
{% endstep %}

{% step %}
Identify the "Hierarchical Validation" architecture. In complex multi-tenant B2B SaaS platforms, users belong to Organizations or Workspaces. To secure the platform, developers write global middleware that intercepts every request matching `/api/v1/workspaces/{workspace_id}/*`
{% endstep %}

{% step %}
Investigate the Middleware logic. The middleware extracts the `workspace_id` from the URL, queries the database to verify if the active JWT session belongs to that specific Workspace, and either throws a `403 Forbidden` or allows the request to proceed to the controller
{% endstep %}

{% step %}
Analyze the Controller extraction logic. After the middleware passes, the specific route controller (e.g., `GetInvoiceDetails`) takes over. The controller extracts the `invoice_id` from the URL parameter
{% endstep %}

{% step %}
Discover the fatal database query desynchronization: Because the middleware _already_ verified the user's access to the Workspace, the controller developer implicitly assumes the user is fully authorized. To retrieve the invoice, the developer executes a simple, primary-key lookup: `SELECT * FROM invoices WHERE id = {invoice_id}`
{% endstep %}

{% step %}
Understand the vulnerability: The controller completely fails to enforce the relationship between the parent resource (`workspace_id`) and the child resource (`invoice_id`). It queries the database solely using the child identifier
{% endstep %}

{% step %}
Formulate the Hierarchical BOLA payload. You must satisfy the middleware's authorization gate while independently manipulating the controller's data extraction sink
{% endstep %}

{% step %}
Identify your own valid `workspace_id` (e.g., `WS-ATTACKER-99`)
{% endstep %}

{% step %}
Enumerate, guess, or extract a valid `invoice_id` belonging to a completely different, highly classified enterprise tenant (e.g., `INV-VICTIM-01`)
{% endstep %}

{% step %}
Construct the fractured REST payload: `GET /api/v1/workspaces/WS-ATTACKER-99/invoices/INV-VICTIM-01`
{% endstep %}

{% step %}
Transmit the request to the API
{% endstep %}

{% step %}
The global authorization middleware executes. It extracts `WS-ATTACKER-99`. It verifies your JWT is linked to `WS-ATTACKER-99`. The middleware approves the request
{% endstep %}

{% step %}
The Controller executes. It extracts `INV-VICTIM-01`. It executes `SELECT * FROM invoices WHERE id = 'INV-VICTIM-01'`. The database returns the victim's invoice
{% endstep %}

{% step %}
The API serializes the victim's data and returns it in the HTTP 200 OK response. You have successfully bypassed Object Level Authorization by exploiting the relational disconnect between hierarchical path validation and primary-key data retrieval

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(_dbContext\.Invoices\.FindAsync\(invoiceId\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(invoiceRepository\.findById\(\s*invoiceId\s*\)\.orElseThrow)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$invoice\s*=\s*Invoice::find\(\$invoiceId\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(Invoice\.findByPk\(\s*req\.params\.invoiceId\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"_dbContext\.Invoices\.FindAsync\(invoiceId\)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"invoiceRepository\.findById\(\s*invoiceId\s*\)\.orElseThrow"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"\\$invoice\s*=\s*Invoice::find\(\\$invoiceId\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"Invoice\.findByPk\(\s*req\.params\.invoiceId\s*\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// [1]
// [2]
[AuthorizeWorkspace] // Custom ActionFilter securely validating the {workspaceId} parameter
[HttpGet("/api/v1/workspaces/{workspaceId}/invoices/{invoiceId}")]
public async Task<IActionResult> GetInvoice(string workspaceId, string invoiceId)
{
    // [3]
    // [4]
    // The controller assumes the AuthorizeWorkspace attribute guarantees absolute safety.
    // It blindly fetches the invoice by its ID, allowing cross-tenant BOLA.
    var invoice = await _dbContext.Invoices.FindAsync(invoiceId);

    if (invoice == null) return NotFound();

    return Ok(invoice);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
@RequestMapping("/api/v1/workspaces/{workspaceId}/invoices")
public class InvoiceController {

    @Autowired
    private InvoiceRepository invoiceRepository;

    // [1]
    // [2]
    @PreAuthorize("@securityService.hasWorkspaceAccess(authentication, #workspaceId)")
    @GetMapping("/{invoiceId}")
    public ResponseEntity<?> getInvoice(@PathVariable String workspaceId, @PathVariable String invoiceId) {
        
        // [3]
        // [4]
        // Bypasses BOLA protections by omitting the parent boundary context
        Invoice invoice = invoiceRepository.findById(invoiceId).orElseThrow();
        
        return ResponseEntity.ok(invoice);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// [1]
// [2]
// Route group protected by a tenant-verification middleware
Route::middleware('check.workspace')->group(function () {
    
    Route::get('/api/v1/workspaces/{workspaceId}/invoices/{invoiceId}', function ($workspaceId, $invoiceId) {
        // [3]
        // [4]
        // Laravel's findOrFail strictly queries the primary key, disregarding the URL's workspace context.
        $invoice = Invoice::findOrFail($invoiceId);
        
        return response()->json($invoice);
    });
});
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Global middleware verifies the user belongs to the workspace in the URL
router.use('/api/v1/workspaces/:workspaceId/*', async (req, res, next) => {
    const hasAccess = await AuthService.verifyWorkspaceAccess(req.user.id, req.params.workspaceId);
    if (!hasAccess) return res.status(403).send("Forbidden");
    next();
});

// [3]
// [4]
// The controller route handling the specific resource
router.get('/api/v1/workspaces/:workspaceId/invoices/:invoiceId', async (req, res) => {
    
    // Fatal Flaw: The developer queries exclusively by the Primary Key (invoiceId).
    // They fail to include the workspaceId in the database query, severing the relationship.
    // Correct logic: Invoice.findOne({ where: { id: invoiceId, workspaceId: workspaceId }})
    let invoice = await Invoice.findByPk(req.params.invoiceId);
    
    if (!invoice) return res.status(404).send("Not found");
    
    res.json(invoice);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture enforces strict RESTful conventions, requiring clients to specify the complete resource hierarchy (Parent -> Child) to access data, \[2] To enforce centralized security and adhere to DRY (Don't Repeat Yourself) principles, engineers deploy routing middleware designed to validate the user's cryptographic authorization against the Parent identifier (`workspaceId`), \[3] The architecture delegates the actual data retrieval to the specific route controller, \[4] The execution sink. The developers conflate perimeter authentication with object-level authorization. By securing the perimeter (the Parent ID), they implicitly trust the inner payload (the Child ID). When the database query is constructed, the developer utilizes a Primary Key lookup, completely discarding the verified Parent ID context. The attacker subverts this architecture by crafting a hybrid URL: matching their own authorized Parent ID with an unauthorized victim's Child ID. The middleware validates the attacker's context and opens the gate, while the controller obediently fetches and returns the victim's classified data

```http
// 1. Attacker controls Workspace WS-999.
// 2. Attacker discovers a valid Invoice ID (INV-4044) belonging to a Fortune 500 client.
// 3. Attacker attempts direct access, but fails because they don't belong to the Fortune 500 workspace.

GET /api/v1/workspaces/WS-FORTUNE500/invoices/INV-4044 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
// Response: 403 Forbidden (Blocked by Middleware)

// 4. Attacker constructs the disconnected BOLA payload, injecting their authorized workspace.

GET /api/v1/workspaces/WS-999/invoices/INV-4044 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>

// 5. Middleware checks if Attacker has access to WS-999. Result: TRUE.
// 6. Controller queries DB: SELECT * FROM invoices WHERE id = 'INV-4044'.
// 7. The database returns the Fortune 500 invoice.

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "INV-4044",
  "workspace_id": "WS-FORTUNE500",
  "client": "Acme Corp",
  "total_amount": 1500000.00,
  "wire_instructions": "..."
}
```
{% endstep %}

{% step %}
To secure complex, multi-tenant B2B architectures, platform engineers deployed hierarchical routing middleware designed to enforce access controls at the organizational perimeter. This optimization centralized authorization logic, freeing downstream controllers to focus exclusively on business logic and data retrieval. The systemic security failure arose from a relational disconnect between path validation and database execution. Developers implicitly assumed that because a RESTful URL implies a strict parent-child hierarchy, the incoming data naturally adheres to that hierarchy. Consequently, they optimized the database query by selecting resources strictly by their primary keys, entirely discarding the verified parent context. The attacker actively shattered this implied hierarchy by generating a synthetic, impossible URL. By passing the authorization gate with their own organizational ID while injecting a victim's asset ID into the extraction sink, the attacker exploited the controller's blind primary-key lookup to effortlessly exfiltrate highly classified, cross-tenant data
{% endstep %}
{% endstepper %}

***

#### BOLA via GraphQL Edge/Node Resolver Context Loss

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on single-endpoint GraphQL APIs (`POST /graphql`) serving highly interconnected, graph-based data models (e.g., Users -> Organizations -> Repositories -> Commits)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the GraphQL schema and the backend Resolver orchestration logic
{% endstep %}

{% step %}
Identify the "Graph Traversal" architecture. In GraphQL, queries are not resolved linearly. They are resolved hierarchically via a tree of individual Resolver functions. A query for `user { documents { title } }` executes the `User` resolver, which then passes its output down to the `documents` resolver
{% endstep %}

{% step %}
Investigate the Authorization logic at the Root Query level. To secure user data, developers apply strict authorization checks to the top-level `me` or `viewer` query, guaranteeing that the `me` node exactly matches the `context.user.id` derived from the active JWT
{% endstep %}

{% step %}
Analyze the Node-level (Edge) resolvers. To fulfill requests for nested objects, developers write dedicated resolvers for specific types (e.g., `DocumentResolver`)
{% endstep %}

{% step %}
Discover the fatal Context Delegation gap: The developer structurally assumes that the `DocumentResolver` is _only_ ever called safely via an authorized parent node (like `me`). Because they believe the parent already checked the authorization, they completely omit Object Level Authorization inside the nested `DocumentResolver`
{% endstep %}

{% step %}
Understand the Graph Alias & Input vulnerability: GraphQL allows users to pass arguments directly to nested fields (e.g., fetching a specific document from a list by passing an `id` argument). If the nested resolver extracts this `id` argument and fetches it from the database without re-validating it against the parent object's ID or the global user context, the graph is broken
{% endstep %}

{% step %}
Formulate the GraphQL BOLA payload. You must traverse through an authorized, highly secure root node, and then exploit a vulnerable, un-authorized nested edge resolver using a victim's ID
{% endstep %}

{% step %}
Construct a GraphQL query starting with the authorized `me` node
{% endstep %}

{% step %}
Traverse down to the target nested object, injecting the victim's ID into the query argument
{% endstep %}

{% step %}
Payload structure: `query { me { specific_document(id: "VICTIM_DOC_ID") { title, secret_content } } }`
{% endstep %}

{% step %}
Transmit the GraphQL payload to the endpoint
{% endstep %}

{% step %}
The GraphQL execution engine parses the query. It executes the `me` resolver. The `me` resolver verifies your JWT and returns your User object. Authorization passes
{% endstep %}

{% step %}
The engine traverses down and executes the `specific_document` resolver. It passes the argument `id: "VICTIM_DOC_ID"`&#x20;
{% endstep %}

{% step %}
The nested resolver executes `SELECT * FROM documents WHERE id = 'VICTIM_DOC_ID'`. Because it lacks internal BOLA checks, it returns the victim's document. The engine links the victim's document to your `me` node and returns the combined JSON response, successfully achieving BOLA by exploiting the loss of authorization context during deep graph traversal

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(public\s+async\s+Task<Document>\s+GetDocumentAsync\(string\s+id\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@QueryMapping\s*public\s*Document\s*getDocument\(@Argument\s*String\s*id\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(public\s+function\s+getDocument\(\$id\)\s*\{\s*return\s+\$this->documentRepository->find\(\$id\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(resolve\s*\(parent,\s*args,\s*context\)\s*\{\s*return\s*db\.Documents\.findById\(args\.id\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"public\s+async\s+Task<Document>\s+GetDocumentAsync\(string\s+id\)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"@QueryMapping\s+public\s+Document\s+getDocument\(@Argument\s+String\s+id\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"public\s+function\s+getDocument\(\$id\)\s*\{\s*return\s+\$this->documentRepository->find\(\$id\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"resolve\s*\(parent,\s*args,\s*context\)\s*\{\s*return\s*db\.Documents\.findById\(args\.id\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[ExtendObjectType("User")]
public class UserResolvers
{
    // [1]
    // [2]
    // [3]
    // [4]
    // Resolving a nested field. The [Parent] attribute injects the authorized User object,
    // but the developer entirely ignores it when constructing the Entity Framework query.
    public async Task<Document> GetSpecificDocumentAsync(
        [Parent] User user, 
        string documentId, 
        [Service] ApplicationDbContext dbContext)
    {
        // Executes without BOLA validation
        return await dbContext.Documents.FindAsync(documentId);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Controller
public class UserDocumentResolver {

    @Autowired
    private DocumentRepository documentRepository;

    // [1]
    // [2]
    // [3]
    // [4]
    @SchemaMapping(typeName = "User", field = "specific_document")
    public Document getSpecificDocument(User parent, @Argument String id) {
        
        // Developer assumes GraphQL execution guarantees ownership.
        // The database lookup is entirely decoupled from the 'parent' object.
        return documentRepository.findById(id).orElse(null);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class UserDocumentResolver
{
    private $documentRepository;


    public function __construct($documentRepository)
    {
        $this->documentRepository = $documentRepository;
    }


    // [1]
    // [2]
    // [3]
    // [4]
    public function getSpecificDocument($parent, $id)
    {

        // Developer assumes GraphQL execution guarantees ownership.
        // The database lookup is entirely decoupled from the 'parent' object.

        return $this->documentRepository
            ->findById($id);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const resolvers = {
    Query: {
        // [1]
        // [2]
        // Secure root query. Verifies the user context perfectly.
        me: async (_, args, context) => {
            if (!context.user) throw new AuthenticationError('Not logged in');
            return await db.User.findByPk(context.user.id);
        }
    },
    User: {
        // [3]
        // [4]
        // Nested resolver on the User type.
        // The developer assumes 'parent' is the authorized user, but fails to scope 
        // the database query to ensure the requested document actually belongs to 'parent.id'.
        specific_document: async (parent, args, context) => {
            // Fatal Flaw: Blind primary key lookup bypassing the parent's contextual boundary.
            // Correct logic: return await db.Document.findOne({ id: args.id, ownerId: parent.id })
            return await db.Document.findByPk(args.id);
        }
    }
};
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture exposes a single, unified GraphQL endpoint, allowing clients to dynamically traverse relational graphs and query deeply nested data structures in a single HTTP request, \[2] To secure the graph, architects apply robust Authentication and Authorization guards at the "Root" query level, ensuring users can only initiate graphs from their own verified identity node, \[3] The architecture breaks down database queries into discrete, isolated Resolver functions that map to specific nodes and edges within the schema, \[4] The execution sink. GraphQL execution is hierarchical, but memory context is not inherently secure unless explicitly constrained. Developers implicitly trusted the GraphQL engine's routing, assuming that reaching a nested resolver naturally proved ownership of the requested resource. By passing an arbitrary database ID argument into a nested resolver, the attacker forces the resolver to execute an unconstrained primary-key lookup. The resolver, devoid of BOLA safeguards, retrieves the victim's data and blindly attaches it to the attacker's authorized root node, successfully exfiltrating the data via architectural context loss

```http
// 1. Attacker authenticates to the GraphQL API.
// 2. Attacker discovers a query pattern allowing specific argument passing on nested nodes.
// 3. Attacker identifies a victim's highly confidential Document ID (DOC-99182).
// 4. Attacker constructs a GraphQL query traversing their own 'me' root node to reach the vulnerable edge.

POST /graphql HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "query": "query { me { id username specific_document(id: \"DOC-99182\") { id title confidential_body } } }"
}

// 5. The GraphQL engine executes the 'me' resolver. It returns the attacker's user object.
// 6. The engine executes the 'specific_document' resolver, passing "DOC-99182".
// 7. The resolver queries the database purely by ID, bypassing ownership validation.
// 8. The API returns the deeply nested, exfiltrated BOLA payload:

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "me": {
      "id": "USR-111",
      "username": "attacker",
      "specific_document": {
        "id": "DOC-99182",
        "title": "Q4 Financial Disclosures - Confidential",
        "confidential_body": "The upcoming merger with Acme Corp will..."
      }
    }
  }
}
```
{% endstep %}

{% step %}
To maximize API flexibility and eliminate over-fetching, enterprise engineers transitioned from RESTful architectures to GraphQL. This paradigm shift replaced monolithic controllers with fragmented, highly modular Resolver functions. The security failure materialized from a deep misunderstanding of GraphQL's execution context lifecycle. Developers anchored their security models to the Root Query, erroneously assuming that authorization dynamically cascaded down the graph hierarchy. They failed to realize that every nested resolver operates as a completely independent execution sink unless explicitly instructed to validate its parameters against its parent's context. The attacker actively exploited this functional isolation. By injecting a victim's unique identifier deep into the graph arguments, the attacker coerced the isolated nested resolver into executing an unconstrained database query. The GraphQL engine, fulfilling its design, seamlessly stitched the victim's highly classified data into the attacker's authorized graph structure, achieving a devastating Object Level Authorization bypass through structural context decoupling
{% endstep %}
{% endstepper %}

***

#### Out-of-Band BOLA via Asynchronous Event Queue Desynchronization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on endpoints executing heavy computational tasks, such as generating PDF Compliance Reports, exporting massive CSV ledgers, or triggering cross-system account migrations
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's job-publishing logic and the background worker's event-consuming logic
{% endstep %}

{% step %}
Identify the "Asynchronous Message Queue" architecture. Executing a 30-second PDF rendering job blocks the main HTTP thread, leading to 504 Gateway Timeouts. To resolve this, developers adopt an Event-Driven architecture: the HTTP API receives the request, publishes a lightweight JSON job payload to a message broker (e.g., RabbitMQ, Kafka, AWS SQS), and instantly returns a `202 Accepted`. A background worker fleet continuously consumes these messages and processes the heavy logic
{% endstep %}

{% step %}
Investigate the API publisher logic. The user requests a report export (e.g., `POST /api/v1/reports/export`). The payload contains the `reportId`. The HTTP API verifies the user's JWT, constructs the event payload `{"userId": 105, "reportId": "RPT-88", "action": "EXPORT"}`, and pushes it to Kafka
{% endstep %}

{% step %}
Analyze the Background Worker consumer logic. The worker node receives the JSON payload. It extracts the `reportId` to fetch the data from the database, generates the PDF, and extracts the `userId` to determine which email address to send the final PDF to
{% endstep %}

{% step %}
Discover the fatal authorization void: The HTTP API layer assumes the background worker handles the data retrieval. The background worker operates completely outside the HTTP lifecycle—it has no incoming HTTP request, no headers, and no JWT. It is purely a headless compute node
{% endstep %}

{% step %}
Understand the vulnerability: If the HTTP API fails to perform Object Level Authorization _before_ publishing the message to the queue, the background worker is entirely defenseless. The worker blindly trusts the message broker, assuming any message placed on the queue has already been completely authorized
{% endstep %}

{% step %}
Formulate the Out-of-Band BOLA payload. You must initiate a background job targeting a victim's asset, relying on the headless worker's lack of context to bypass BOLA and physically deliver the data to your inbox
{% endstep %}

{% step %}
Identify the ID of a highly sensitive asset belonging to another tenant (e.g., `RPT-VICTIM-99`)
{% endstep %}

{% step %}
Submit the export request to the API: `POST /api/v1/reports/export` with `{"reportId": "RPT-VICTIM-99"}`
{% endstep %}

{% step %}
The HTTP API verifies your JWT. It extracts your `userId` (`ATTACKER_ID`). It constructs the Kafka message: `{"userId": "ATTACKER_ID", "reportId": "RPT-VICTIM-99"}`. Crucially, it skips checking if you own `RPT-VICTIM-99` and publishes the message
{% endstep %}

{% step %}
The HTTP API returns `202 Accepted` to your browser
{% endstep %}

{% step %}
The headless background worker picks up the message. Lacking BOLA checks, it executes `SELECT * FROM reports WHERE id = 'RPT-VICTIM-99'`. It renders the highly classified data into a PDF
{% endstep %}

{% step %}
The worker looks up the email address for `ATTACKER_ID`. It attaches the PDF and dispatches the email. You have successfully exfiltrated cross-tenant data completely out-of-band via an asynchronous architecture vulnerability

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(channel\.BasicPublish\([^,]+,\s*[^,]+,\s*[^,]+,\s*JsonConvert\.SerializeObject\(jobData\)\))|(_queue\.Publish\([^,]+,\s*new\s+ExportJob\(user\.Id,\s*request\.DocumentId\)\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(kafkaTemplate\.send\("exports",\s*new\s*ExportJob\(user\.getId\(\),\s*request\.getDocId\(\)\)\))|(rabbitTemplate\.convertAndSend\([^,]+,\s*new\s+ExportJob\(user\.getId\(\),\s*request\.getDocId\(\)\)\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$channel->basic_publish\([^,]+,\s*[^,]+,\s*json_encode\(\$jobData\)\))|(\$queue->publish\([^,]+,\s*\[\s*'userId'\s*=>\s*\$request->user\(\)->id,\s*'documentId'\s*=>\s*\$request->documentId\s*\]\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(queue\.publish\(['"][^'"]+['"],\s*\{\s*userId:\s*req\.user\.id,\s*documentId:\s*req\.body\.documentId)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"channel\.BasicPublish\([^,]+,\s*[^,]+,\s*[^,]+,\s*JsonConvert\.SerializeObject\(jobData\)\)|_queue\.Publish\([^,]+,\s*new\s+ExportJob\(user\.Id,\s*request\.DocumentId\)\)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"kafkaTemplate\.send\(\"exports\",\s*new\s*ExportJob\(user\.getId\(\),\s*request\.getDocId\(\)\)\)|rabbitTemplate\.convertAndSend\([^,]+,\s*new\s+ExportJob\(user\.getId\(\),\s*request\.getDocId\(\)\)\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"\\$channel->basic_publish\([^,]+,\s*[^,]+,\s*json_encode\(\\$jobData\)\)|\\$queue->publish\([^,]+,\s*\[\s*'userId'\s*=>\s*\\$request->user\(\)->id,\s*'documentId'\s*=>\s*\\$request->documentId\s*\]\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"queue\.publish\(['\"][^'\"]+['\"],\s*\{\s*userId:\s*req\.user\.id,\s*documentId:\s*req\.body\.documentId"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/exports/generate")]
public async Task<IActionResult> RequestExport([FromBody] ExportRequest request)
{
    var userId = User.GetUserId();
    
    // [1]
    // [2]
    var message = new ExportMessage 
    { 
        UserId = userId, 
        ReportId = request.ReportId // Untrusted input mapped directly to the message queue
    };

    await _sqsClient.SendMessageAsync("report-queue", JsonConvert.SerializeObject(message));
    return Accepted();
}

// Background Hosted Service
protected override async Task ExecuteAsync(CancellationToken stoppingToken)
{
    // [3]
    // [4]
    // Worker blindly processes the queue, causing Out-of-Band BOLA
    var report = await _dbContext.Reports.FindAsync(message.ReportId);
    var user = await _dbContext.Users.FindAsync(message.UserId);

    var file = GeneratePdf(report);
    await _emailSender.SendAsync(user.Email, file);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class ExportController {

    @Autowired
    private KafkaTemplate<String, ExportEvent> kafkaTemplate;

    @PostMapping("/api/v1/exports/generate")
    public ResponseEntity<?> triggerExport(@RequestBody ExportRequest request, Principal principal) {
        // [1]
        // [2]
        ExportEvent event = new ExportEvent();
        event.setRequesterUsername(principal.getName());
        event.setDocumentId(request.getDocumentId());

        // Publishes the un-authorized ID directly to the Kafka topic
        kafkaTemplate.send("document-exports", event);

        return ResponseEntity.accepted().build();
    }
}

@Service
public class ExportWorker {

    @KafkaListener(topics = "document-exports")
    public void processExport(ExportEvent event) {
        // [3]
        // [4]
        // BOLA occurs here in the background execution environment
        Document doc = documentRepository.findById(event.getDocumentId()).orElseThrow();
        User user = userRepository.findByUsername(event.getRequesterUsername());

        pdfService.generateAndEmail(doc, user.getEmail());
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ExportController
{
    private $kafkaTemplate;

    public function __construct($kafkaTemplate)
    {
        $this->kafkaTemplate = $kafkaTemplate;
    }

    public function triggerExport($request, $principal)
    {
        // [1]
        // [2]
        $event = new ExportEvent();

        $event->setRequesterUsername(
            $principal->getName()
        );

        $event->setDocumentId(
            $request->getDocumentId()
        );


        // Publishes the un-authorized ID directly to the Kafka topic
        $this->kafkaTemplate->send(
            "document-exports",
            $event
        );


        return response()->accepted()->build();
    }
}

class ExportWorker
{

    public function processExport($event)
    {
        // [3]
        // [4]
        // BOLA occurs here in the background execution environment

        $doc = $this->documentRepository
            ->findById(
                $event->getDocumentId()
            );


        $user = $this->userRepository
            ->findByUsername(
                $event->getRequesterUsername()
            );


        $this->pdfService->generateAndEmail(
            $doc,
            $user->getEmail()
        );
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// HTTP API Tier
router.post('/api/v1/exports/generate', requireAuth, async (req, res) => {
    // [1]
    // [2]
    // The developer focuses entirely on rapid response times, pushing the 
    // workload to RabbitMQ. They fail to verify ownership of 'req.body.targetId'
    // BEFORE placing the job in the queue.
    const jobData = {
        requesterId: req.user.id,
        requesterEmail: req.user.email,
        targetId: req.body.targetId 
    };

    await rabbitChannel.sendToQueue('pdf_exports', Buffer.from(JSON.stringify(jobData)));
    
    return res.status(202).send("Export started. You will receive an email shortly.");
});

// Background Worker Tier (Headless)
rabbitChannel.consume('pdf_exports', async (msg) => {
    const job = JSON.parse(msg.content.toString());

    // [3]
    // [4]
    // The worker operates in an ambient void, entirely devoid of HTTP context.
    // It blindly trusts the message contents, fetching the victim's data by Primary Key 
    // and emailing it to the attacker.
    const sensitiveData = await Database.Report.findByPk(job.targetId);
    
    const pdf = await PdfGenerator.render(sensitiveData);
    await EmailService.send(job.requesterEmail, "Your Export", pdf);
    
    rabbitChannel.ack(msg);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture handles computationally expensive tasks, employing an Event-Driven model to ensure the HTTP API remains highly responsive and avoids TCP connection timeouts, \[2] The backend API's sole responsibility is translating the incoming HTTP request into a structured JSON event and rapidly dispatching it to a central Message Broker (Kafka/RabbitMQ), \[3] The architecture relies on headless, background consumer nodes to ingest the events, retrieve the necessary data from the primary database, and process the heavy workload out-of-band, \[4] The execution sink. The developers suffered a catastrophic paradigm failure regarding architectural trust boundaries. By viewing the Message Broker as an internal, trusted component, they deferred Object Level Authorization to the background workers. However, background workers intrinsically lack cryptographic security contexts (ambient HTTP request properties or JWTs). Left without context, the workers blindly trusted the parameters explicitly defined in the message payload. The attacker bypassed the system by providing their own verified user identity alongside a victim's document identifier. The API published the forged linkage, and the background worker obediently compiled the highly classified cross-tenant data, physically delivering the exfiltrated payload directly into the attacker's email inbox without triggering a single synchronous API security alert
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
