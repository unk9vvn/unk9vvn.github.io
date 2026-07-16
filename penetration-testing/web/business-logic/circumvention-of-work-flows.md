# Circumvention of Work Flows

## Check List

## Methodology

### Black Box

#### Skipping Payment Step in Checkout Process

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Add a product to the cart
{% endstep %}

{% step %}
Proceed to checkout normally
{% endstep %}

{% step %}
Intercept the checkout flow request

```http
POST /api/checkout/start HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"cartId":"789"}
```
{% endstep %}

{% step %}
Observe the next step requires payment authorization
{% endstep %}

{% step %}
Before completing payment, manually access the order confirmation endpoint

```http
POST /api/checkout/confirm HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"orderId":"789","status":"paid"}
```
{% endstep %}

{% step %}
Forward the request without completing payment , If order is confirmed without valid payment transaction ID, workflow validation is missing
{% endstep %}

{% step %}
If backend does not verify payment gateway response before confirming order, workflow bypass is confirmed
{% endstep %}
{% endstepper %}

***

#### Skipping OTP Verification Step

{% stepper %}
{% step %}
Register a new account
{% endstep %}

{% step %}
Submit phone/email verification request
{% endstep %}

{% step %}
Intercept OTP verification request

```http
POST /api/verify-otp HTTP/1.1
Host: target.com
Cookie: session=temp123
Content-Type: application/json

{"otp":"123456"}
```
{% endstep %}

{% step %}
Before submitting correct OTP, attempt to access protected endpoint

```http
GET /api/user/dashboard HTTP/1.1
Host: target.com
Cookie: session=temp123
```
{% endstep %}

{% step %}
Alternatively modify verification flag in request

```http
POST /api/complete-registration HTTP/1.1
Host: target.com
Cookie: session=temp123
Content-Type: application/json

{"verified":true}
```
{% endstep %}

{% step %}
If account becomes fully active without valid OTP validation, workflow circumvention is confirmed
{% endstep %}
{% endstepper %}

***

#### Bypassing Multi-Step KYC Verification

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Access KYC submission page
{% endstep %}

{% step %}
Intercept identity submission request

```http
POST /api/kyc/submit HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"document":"base64data","status":"pending"}
```
{% endstep %}

{% step %}
System requires admin approval before enabling withdrawals
{% endstep %}

{% step %}
Attempt to directly access withdrawal endpoint

```http
POST /api/wallet/withdraw HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"amount":100}
```
{% endstep %}

{% step %}
If withdrawal succeeds despite KYC status being pending, approval workflow is not enforced server-side
{% endstep %}

{% step %}
If sensitive feature becomes accessible without completing mandatory verification steps, workflow bypass vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Skipping Password Confirmation Before Sensitive Action

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Navigate to account deletion feature
{% endstep %}

{% step %}
Application requires password confirmation
{% endstep %}

{% step %}
Intercept confirmation request

```http
POST /api/account/confirm-password HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"password":"WrongPass"}
```
{% endstep %}

{% step %}
Do not wait for successful confirmation, Directly access final action endpoint

```http
POST /api/account/delete HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If account deletion executes without validating successful password confirmation state, workflow control is missing
{% endstep %}

{% step %}
If backend does not enforce sequential state validation, workflow circumvention is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### State Machine Acceleration via Non-Idempotent Transition Overloading in Bulk Processing Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on administrative, procurement, or moderation dashboards that manage multi-stage enterprise workflows (e.g., `Draft` -> `L1_Approval` -> `L2_Approval` -> `Finance_Release`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Bulk Processing" architecture. In massive enterprise environments, requiring managers to click "Approve" individually on hundreds of expense reports causes severe operational friction
{% endstep %}

{% step %}
Investigate the UI optimization. Developers implement a "Bulk Approve" feature, allowing a user to select multiple checkboxes in the grid and dispatch a single HTTP `POST` request containing an array of resource IDs (e.g., `{"documents": [101, 102, 103]}`)
{% endstep %}

{% step %}
Analyze the Workflow Orchestrator's state transition logic. Modern state machines (like Spring StateMachine or Stateless) are driven by _Events_ rather than direct string updates. Instead of writing `UPDATE status = 'L2'`, the code fires an event: `stateMachine.fire(Events.APPROVE)`
{% endstep %}

{% step %}
Discover the fatal loop optimization: To process the bulk array rapidly, the backend iterates through the array of IDs, loads each document, and fires the `APPROVE` event
{% endstep %}

{% step %}
Understand the architectural assumption: The developer explicitly assumes that the frontend UI mathematically prevents a user from selecting the _same_ document twice. Consequently, they assume the bulk array contains a mathematically distinct set of unique identifiers
{% endstep %}

{% step %}
Recognize the state machine vulnerability: Because the state machine is configured to gracefully advance to the next node upon receiving an `APPROVE` event, firing the event _multiple times sequentially_ against the exact same memory object will rapidly propel the document through multiple distinct approval tiers within a single execution&#x20;
{% endstep %}

{% step %}
Formulate the Transition Overloading payload. Identify a document currently residing in Step 1 (`L1_Approval`), which you are authorized to approve
{% endstep %}

{% step %}
Construct a bulk approval payload, but deliberately duplicate the target document's ID multiple times within the array. The number of duplications should equal the remaining number of steps in the entire workflow
{% endstep %}

{% step %}
Payload structure: `{"documents": [101, 101, 101]}`&#x20;
{% endstep %}

{% step %}
Transmit the payload to the bulk approval endpoint
{% endstep %}

{% step %}
The backend iteration loop begins, Iteration 1: Loads Document 101. Validates you have `L1` rights. Fires `APPROVE`. State becomes `L2_Approval`. Iteration 2: Loads Document 101. The context validation might rely on a cached authorization check executed prior to the loop, or the validation logic only enforces that you are _a_ participant in the workflow. It fires `APPROVE` again. State becomes `Finance_Release,` Iteration 3: Loads Document 101. Fires `APPROVE`. State becomes `Funds_Dispersed`
{% endstep %}

{% step %}
The loop finishes and executes a single bulk `COMMIT` to the database. You have successfully circumvented the entire enterprise multi-tier authorization hierarchy by utilizing execution loops to forcefully accelerate the state machine

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:foreach\s*\(\s*.*\s+in\s+request\.(?:DocumentIds|Ids|RecordIds)[\s\S]{0,200}?(?:Fire|Raise|Trigger)\s*\([\s\S]{0,80}?(?:Approve|Reject|Publish|Delete)|request\.(?:DocumentIds|Ids)[\s\S]{0,200}?(?:workflow|stateMachine)\.(?:Fire|Send|Transition))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:request\.getIds\(\)\.forEach\s*\([\s\S]{0,200}?(?:stateMachine\.sendEvent|workflow\.advance|transition)|getIds\(\)[\s\S]{0,200}?(?:approve|reject|publish|delete))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:foreach\s*\(\s*\$ids\s+as\s+\$id\s*\)[\s\S]{0,200}?(?:applyTransition|transition|approve|publish|delete)\s*\(|\$request->(?:ids|documentIds)[\s\S]{0,150}?applyTransition)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:documentIds\.map\s*\(\s*id\s*=>\s*[\s\S]{0,150}?(?:workflow\.advance|workflow\.transition|stateMachine\.send)|ids\.forEach\s*\([\s\S]{0,150}?(?:approve|reject|publish|delete))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
foreach\s*\(.*in\s+request\.DocumentIds\).*?(Fire|Raise|Trigger).*?(Approve|Reject|Publish)|request\.(DocumentIds|Ids).*workflow.*(Fire|Transition)
```
{% endtab %}

{% tab title="Java" %}
```regexp
request\.getIds\(\)\.forEach\(.*stateMachine\.sendEvent|getIds\(\).*workflow\.advance|approve.*getIds
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$ids\s+as\s+\$id\).*?(applyTransition|transition)\('(approve|reject|publish|delete)'
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
documentIds\.map\(id\s*=>\s*workflow\.advance|ids\.forEach\(.*workflow\.transition
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/documents/bulk-approve")]
public async Task<IActionResult> BulkApproveAsync([FromBody] BulkApproveDto request)
{
    var userId = User.GetUserId();

    // [1]
    // [2]
    var canApprove = await _authService.VerifyBulkAccessAsync(userId, request.DocumentIds);
    if (!canApprove) return Forbid();

    // [3]
    // [4]
    // Developer assumes the frontend grid only supplies unique IDs
    foreach (var id in request.DocumentIds)
    {
        var document = await _dbContext.Documents.FindAsync(id);
        
        // Stateless framework fires the trigger. 
        // L1 -> L2 -> Finance -> Dispersed
        document.StateMachine.Fire(Trigger.Approve);
    }

    await _dbContext.SaveChangesAsync();
    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class BulkApprovalController {

    @Autowired
    private DocumentRepository documentRepo;
    @Autowired
    private WorkflowEngine workflowEngine;

    @PostMapping("/api/v1/documents/bulk-approve")
    @Transactional
    public ResponseEntity<?> bulkApprove(@RequestBody BulkApproveRequest request, Principal principal) {
        
        // [1]
        // [2]
        // Bulk validation assumes the list represents discrete, unique entities
        if (!authService.canApproveDocuments(principal.getName(), request.getDocumentIds())) {
            return ResponseEntity.status(403).build();
        }

        // [3]
        // [4]
        // Iterates through the raw array provided by the attacker
        for (Long docId : request.getDocumentIds()) {
            Document doc = documentRepo.findById(docId).orElseThrow();
            
            // The workflow engine evaluates the CURRENT state and advances it.
            // If docId is supplied 3 times, the engine fires the APPROVE event 3 times.
            workflowEngine.sendEvent(doc, WorkflowEvent.APPROVE);
            
            documentRepo.save(doc);
        }

        return ResponseEntity.ok().build();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class BulkApprovalController extends Controller
{
    public function bulkApprove(Request $request)
    {
        $documentIds = $request->input('document_ids', []);

        // [1]
        // [2]
        if (!Auth::user()->canApproveAll($documentIds)) {
            abort(403);
        }

        DB::beginTransaction();

        // [3]
        // [4]
        foreach ($documentIds as $id) {
            $document = Document::find($id);
            
            // Applies the state transition without idempotency checks
            $document->applyTransition('approve');
            $document->save();
        }

        DB::commit();

        return response()->json(['status' => 'Processed']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/documents/bulk-approve', async (req, res) => {
    let documentIds = req.body.documentIds;

    // [1]
    // [2]
    if (!await authService.canApproveList(req.user.id, documentIds)) {
        return res.status(403).send('Forbidden');
    }

    // [3]
    // [4]
    // Iterating over un-sanitized, potentially duplicate arrays
    for (let id of documentIds) {
        let doc = await Document.findByPk(id);
        
        // State machine advances automatically based on the event
        doc.workflow.trigger('APPROVE');
        
        await doc.save();
    }

    res.send({ status: 'Processed' });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes high-volume compliance transitions via bulk arrays to minimize API chatter, \[2] The authorization service evaluates the user's access against the entire collection of IDs simultaneously, optimizing database queries, \[3] The execution loop natively trusts the structural uniqueness of the incoming JSON array, explicitly bypassing `distinct()` or `Set` conversions, \[4] The execution sink. Modern workflow engines abstract complex state evaluation into simple event triggers (e.g., `APPROVE`). By intentionally supplying duplicate identifiers in a single payload, the attacker exploits the sequential loop. The engine faithfully registers multiple consecutive `APPROVE` events against the same memory object. This forcefully propels the state machine through subsequent workflow tiers that the attacker inherently lacks the authorization to influence, resulting in full organizational circumvention

```http
// 1. Attacker is a Level 1 Manager. They submit an expense report.
// 2. The expense report (ID: 9918) requires L1, L2, and Finance approval.
// 3. Attacker intercepts the HTTP request from their bulk approval dashboard.

POST /api/v1/expenses/bulk-approve HTTP/1.1
Host: internal.enterprise.tld
Authorization: Bearer <l1_manager_token>
Content-Type: application/json

{
  "documentIds": [9918, 9918, 9918]
}

// 4. The backend verifies the attacker is authorized to execute L1 actions on ID 9918. Validation passes.
// 5. Loop 1: Loads 9918. Current State: L1_Pending. Fires APPROVE. State shifts to L2_Pending.
// 6. Loop 2: Loads 9918. Current State: L2_Pending. Fires APPROVE. State shifts to Finance_Pending.
// 7. Loop 3: Loads 9918. Current State: Finance_Pending. Fires APPROVE. State shifts to Funds_Released.

// 8. The backend commits the transaction.
HTTP/1.1 200 OK
{
  "status": "Processed",
  "processed_count": 3
}

// 9. The attacker successfully executed an L2 and Finance level transition by overloading the 
//    event trigger within a single authorized execution context.
```
{% endstep %}

{% step %}
To eliminate repetitive manual operations within enterprise dashboards, architects implemented bulk-processing endpoints utilizing dynamic state machine orchestrators. By abstracting transition logic into generic event triggers, developers isolated the complexity of multi-tiered workflows. The security posture failed due to an assumption of structural data integrity: the developers trusted that front-end grid selections naturally produced arrays of unique identifiers. By feeding a highly redundant array into the bulk endpoint, the attacker induced consecutive execution iterations upon a single memory reference. The state machine, oblivious to the external array's composition, blindly honored the rapid succession of event triggers. This non-idempotent progression allowed the attacker to forcefully drive the workflow object through restricted validation gates, circumventing the entirety of the enterprise's hierarchical business logic
{% endstep %}
{% endstepper %}

***

#### Workflow Bypass via Cryptographic Disassociation in Stateless Guest Migrations

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on frictionless onboarding platforms, e-commerce checkouts, or loan origination applications that permit a user to begin a complex workflow anonymously (as a Guest) and convert to an authenticated account later in the flow
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Stateless Guest Workflow" architecture. Creating incomplete database records for millions of abandoned guest sessions destroys relational database performance
{% endstep %}

{% step %}
Investigate the Edge state management optimization. To track a guest's progress through an expensive workflow (e.g., Step 1: Upload ID, Step 2: KYC Provider Clears Identity, Step 3: Fund Account), the API Gateway utilizes a cryptographically signed Interaction Token (e.g., a JWE, signed cookie, or specialized JWT like `Guest-Workflow-State`)
{% endstep %}

{% step %}
Analyze the token's payload logic. As the guest completes Step 1 and Step 2, the backend issues a progressively updated token to the client's browser containing the state flags (e.g., `{"step": 3, "kyc_cleared": true, "session_id": "temp_8819"}`)
{% endstep %}

{% step %}
Discover the Identity Binding vulnerability: When the user finally creates an account or logs in at Step 3 to claim the workflow, the backend must merge the guest's progress into the authenticated database record
{% endstep %}

{% step %}
Understand the architectural assumption: The backend meticulously verifies the cryptographic signature of the `Guest-Workflow-State` token, ensuring it was legitimately generated by the server. However, it fundamentally fails to enforce a Cryptographic Binding between the stateless guest token and the target cryptographic User ID
{% endstep %}

{% step %}
Formulate the State Migration payload. You must complete the arduous, highly restricted steps of the workflow utilizing a disposable, clean identity, and then seamlessly transfer that completed state to a completely different, fraudulent identity
{% endstep %}

{% step %}
Begin the workflow as an anonymous guest. Submit valid, legitimate documentation (e.g., a real driver's license, valid credit&#x20;
{% endstep %}

{% step %}
Complete Step 2. The backend confirms your pristine background and issues the cryptographically signed `Guest-Workflow-State` token indicating `kyc_cleared: true`
{% endstep %}

{% step %}
Halt the workflow. Extract the signed token from your browser's cookies or local storage
{% endstep %}

{% step %}
Establish a completely new, parallel session. Authenticate to the platform using the target fraudulent account (an account that inherently fails KYC checks)
{% endstep %}

{% step %}
Navigate to the final step of the workflow. Inject the stolen, signed `Guest-Workflow-State` token from the clean session into the fraudulent session's HTTP headers
{% endstep %}

{% step %}
The backend validates the signature of the guest token. The signature is mathematically flawless. The backend extracts the `kyc_cleared: true` flag and permanently commits it to the fraudulent account's database record. You have successfully circumvented the enterprise compliance gateway by exploiting un-bound stateless token mobility

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:jwt\.verify\s*\(\s*(?:guestToken|workflowCookie|guestState)[\s\S]{0,150}?\)[\s\S]{0,150}?(?:UpdateWorkflowState|UpdateState|SetStatus|Approve|MarkAs)|(?:JwtSecurityTokenHandler|ValidateToken)[\s\S]{0,150}?(?:workflow|guest|state)[\s\S]{0,150}?(?:Update|Set|Approve|Complete))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Jwts\.parser\(\)\.parseClaimsJws\s*\(\s*(?:workflowCookie|guestToken)[\s\S]{0,150}?\)[\s\S]{0,150}?(?:setKyc|setStatus|updateState|approve)|parseClaimsJws[\s\S]{0,150}?(?:workflow|guest|state)[\s\S]{0,120}?(?:set|update|approve))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:JWT::decode\s*\(\s*\$request->cookie\s*\(\s*['"](?:Guest-State|guestToken)['"][\s\S]{0,150}?\)[\s\S]{0,150}?\)[\s\S]{0,150}?(?:markAsCleared|updateState|setStatus|approve)|JWT::decode[\s\S]{0,200}?(?:workflow|guest|state))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:const\s+\w+\s*=\s*jwt\.verify\s*\(\s*req\.cookies\s*\[\s*['"](?:Guest-State|guestToken)['"]\s*\][\s\S]{0,150}?\)[\s\S]{0,150}?(?:updateState|setStatus|approve|complete)|jwt\.verify[\s\S]{0,150}?(?:workflow|guest|state))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
jwt\.verify\(guestToken.*\).*?(UpdateWorkflowState|UpdateState|SetStatus)|ValidateToken.*workflow.*Update
```
{% endtab %}

{% tab title="Java" %}
```regexp
Jwts\.parser\(\)\.parseClaimsJws\(workflowCookie\).*?(setKyc|setStatus|updateState)|parseClaimsJws.*workflow
```
{% endtab %}

{% tab title="PHP" %}
```regexp
JWT::decode\(\$request->cookie\('Guest-State'.*?\).*?(markAsCleared|updateState|setStatus)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
jwt\.verify\(req\.cookies\['Guest-State'\]\).*?(updateState|setStatus|approve)|jwt\.verify.*workflow
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/onboarding/finalize")]
[Authorize]
public async Task<IActionResult> FinalizeOnboarding()
{
    // [1]
    // [2]
    var guestToken = Request.Cookies["Guest-Workflow-State"];
    if (string.IsNullOrEmpty(guestToken)) return BadRequest();

    // [3]
    // [4]
    var handler = new JwtSecurityTokenHandler();
    var principal = handler.ValidateToken(guestToken, _tokenValidationParameters, out var validatedToken);

    var kycCleared = principal.Claims.FirstOrDefault(c => c.Type == "kyc_cleared")?.Value;

    if (kycCleared != "true") return Forbid();

    // Blind migration of state from the floating token to the hard database record
    var userId = User.GetUserId();
    var userRecord = await _dbContext.Users.FindAsync(userId);
    
    userRecord.KycStatus = "CLEARED";
    await _dbContext.SaveChangesAsync();

    Response.Cookies.Delete("Guest-Workflow-State");
    return Ok(new { Status = "Account Fully Activated" });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/onboarding/finalize")
public ResponseEntity<?> finalizeOnboarding(@CookieValue("Guest-Workflow-State") String guestToken, Principal principal) {
    // [1]
    // [2]
    try {
        // [3]
        // [4]
        // Mathematical validation of the server's signature
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(guestToken)
                .getBody();

        if (!Boolean.TRUE.equals(claims.get("kyc_cleared", Boolean.class))) {
            return ResponseEntity.status(403).body("KYC incomplete.");
        }

        User currentUser = userRepository.findById(principal.getName()).orElseThrow();
        currentUser.setKycStatus("CLEARED");
        userRepository.save(currentUser);

        // Cookie clearing logic omitted
        return ResponseEntity.ok(Map.of("status", "Account Fully Activated"));

    } catch (JwtException e) {
        return ResponseEntity.status(401).body("Invalid workflow state.");
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class OnboardingController extends Controller
{
    public function finalizeOnboarding(Request $request)
    {
        // [1]
        // [2]
        $guestToken = $request->cookie('Guest-Workflow-State');
        
        try {
            // [3]
            // [4]
            // Server validates the cryptographic signature
            $workflowState = JWT::decode($guestToken, new Key(env('JWT_SECRET'), 'HS256'));

            if (!isset($workflowState->kyc_cleared) || $workflowState->kyc_cleared !== true) {
                abort(403, 'KYC incomplete.');
            }

            $user = auth()->user();
            $user->kyc_status = 'CLEARED';
            $user->save();

            return response()->json(['status' => 'Account Fully Activated'])
                             ->withoutCookie('Guest-Workflow-State');

        } catch (\Exception $e) {
            abort(401, 'Invalid workflow state.');
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/onboarding/finalize', authenticateUser, async (req, res) => {
    // [1]
    // [2]
    // Retrieves the stateless guest workflow token from the cookie
    let guestToken = req.cookies['Guest-Workflow-State'];
    if (!guestToken) return res.status(400).send('No active workflow found.');

    try {
        // [3]
        // [4]
        // Cryptographic signature is verified. The server mathematically proves 
        // IT issued this token. However, it fails to verify WHO it was issued for.
        let workflowState = jwt.verify(guestToken, process.env.JWT_SECRET);

        if (workflowState.kyc_cleared !== true) {
            return res.status(403).send('KYC incomplete.');
        }

        // The state from the stateless token is permanently bound to the active user session
        let currentUser = await User.findByPk(req.user.id);
        currentUser.kycStatus = 'CLEARED';
        currentUser.workflowCompleted = true;
        await currentUser.save();

        res.cookie('Guest-Workflow-State', '', { maxAge: 0 }); // Clear token
        res.send({ status: 'Account Fully Activated' });
    } catch (err) {
        res.status(401).send('Invalid workflow state.');
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture delays database writes during complex, multi-stage guest operations to preserve primary relational database performance and eliminate abandoned-session bloat, \[2] To orchestrate the sequence across stateless microservices, the API leverages a cryptographically signed cookie to store the user's progress tree, \[3] The security model relies entirely on the mathematical immutability of the JWT signature. The developer correctly guarantees that an external attacker cannot alter the `kyc_cleared` boolean to `true,` \[4] The execution paradox. While the signature proves the token was generated by the server, it contains no contextual binding (e.g., `device_fingerprint`, `session_hash`, or pre-authorization identifier). The stateless token is perfectly mobile. By harvesting a token minted for a legitimate, clean identity and injecting it into the HTTP stream of a fraudulent identity, the attacker forces the backend to permanently append the validated state to the wrong entity, seamlessly bypassing the expensive compliance workflow

```http
// 1. Attacker utilizes an anonymous proxy and a stolen, completely valid ID to start the workflow.
// 2. Attacker completes the KYC provider checks successfully. 
// 3. The server issues the signed workflow state cookie.
// Set-Cookie: Guest-Workflow-State=eyJhb...[valid_signature]; HttpOnly

// 4. Attacker abandons the guest session. They extract the JWT.
// 5. Attacker logs into their primary, fraudulent account which is heavily restricted.
// 6. Attacker bypasses the UI and directly invokes the finalization endpoint, injecting the stolen cookie.

POST /api/v1/onboarding/finalize HTTP/1.1
Host: secure.enterprise.tld
Authorization: Bearer <fraudulent_account_token>
Cookie: Guest-Workflow-State=eyJhb...[valid_signature]
Content-Type: application/json

// 7. The backend receives the request.
// 8. The backend evaluates the JWT signature. It is valid.
// 9. The backend reads "kyc_cleared": true from the JWT.
// 10. The backend merges the state into the Fraudulent Account.
// 11. The fraudulent account is fully activated without ever interacting with the KYC provider.
```
{% endstep %}

{% step %}
To support frictionless customer acquisition, platform architects designed a delayed-persistence pipeline utilizing stateless, cryptographically signed cookies to track guest progress. The security failure stemmed from a critical omission in contextual cryptography. Developers erroneously equated token authenticity with token provenance. By failing to embed an immutable environmental anchor (such as an initial session fingerprint or a shadow ID) into the JWT payload, the architecture rendered the validated workflow state entirely untethered. The attacker exploited this by bifurcating their identity: navigating the rigorous compliance gates utilizing a pristine identity to generate the cryptographically valid token, and subsequently transplanting that token into a blocked, fraudulent session. The backend, evaluating only the mathematical signature, blindly merged the illicitly transplanted state into the target record, definitively circumventing the enterprise workflow
{% endstep %}
{% endstepper %}

***

#### Compliance Gateway Circumvention via ORM Tombstone Resurrection (Soft-Delete Desynchronization)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on regulated financial, legal, or moderation platforms where compliance operations depend on asynchronous background reviews (e.g., SLAs dictating "All pending transactions must be reviewed within 48 hours")
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Data Retention / Soft Delete" architecture. To comply with strict enterprise audit requirements, records are never physically `DELETE`d from the database. Instead, the ORM flags them with a tombstone (e.g., `deleted_at = TIMESTAMP`)
{% endstep %}

{% step %}
Investigate the ORM's global query configuration. To ensure deleted records do not clutter active user dashboards or internal administrative queues, developers utilize Global Query Filters (e.g., Entity Framework's `HasQueryFilter`, Laravel's `SoftDeletes` trait, Hibernate's `@Where(clause = "deleted = fals`
{% endstep %}

{% step %}
Analyze the background Compliance SLA pipeline. The business enforces a Service Level Agreement: "If a transaction sits in the Fraud Queue for > 48 hours without manual administrative intervention, automatically advance the workflow to `APPROVED`&#x20;
{% endstep %}

{% step %}
Discover the architectural synchronization gap: The background SLA worker queries the database for records that have been in the `PENDING` state for > 48 hours. However, because the SLA worker utilizes the standard ORM repository, the Global Query Filter is implicitly applied. The SLA worker _cannot see_ soft-deleted records
{% endstep %}

{% step %}
Understand the vulnerability lifecycle. The application allows users to "Cancel" and "Undo Cancel" (Restore) their pending transactions
{% endstep %}

{% step %}
Formulate the Temporal Desynchronization payload. You must initiate a restricted workflow, deliberately hide the entity from the compliance queue using the soft-delete mechanism, wait for the background SLA timer to expire, and then resurrect the entity
{% endstep %}

{% step %}
Submit a high-risk transaction (e.g., a wire transfer). The system places it in `PENDING_REVIEW`. The transaction is added to the administrative dashboard for human inspection
{% endstep %}

{% step %}
Immediately hit the `DELETE /api/v1/transfers/{id}` endpoint to cancel the transaction
{% endstep %}

{% step %}
The ORM marks the row with `deleted_at = NOW()`. Because of the global filter, the transaction instantly vanishes from the human administrator's Fraud Queue dashboard. It is completely invisible to the business
{% endstep %}

{% step %}
Wait 48 hours and 1 minute. The background SLA worker runs continuously during this time, but because the record is soft-deleted, the worker ignores it
{% endstep %}

{% step %}
Hit the `POST /api/v1/transfers/{id}/restore` endpoint. The API nullifies the `deleted_at` flag. The record is resurrected
{% endstep %}

{% step %}
Crucially, the record's initial creation timestamp and state (`PENDING_REVIEW`) were unaltered during the suspension
{% endstep %}

{% step %}
One minute later, the background SLA worker executes its scheduled query. It suddenly detects your resurrected record. It calculates the elapsed time: `NOW() - created_at > 48 hours`. It determines the transaction has exceeded the maximum compliance hold duration. The worker executes the automatic fallback logic, permanently advancing the workflow state to `APPROVED`, silently bypassing human authorization

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\.HasQueryFilter\s*\(\s*\w+\s*=>\s*!?\s*\w*\.IsDeleted\s*\)|ModelBuilder[\s\S]{0,150}?HasQueryFilter[\s\S]{0,100}?IsDeleted|IgnoreQueryFilters\s*\(\s*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@Where\s*\(\s*clause\s*=\s*"[^"]*deleted_at\s+IS\s+NULL"|@SQLDelete\s*\([\s\S]{0,100}?deleted|@Filter\s*\([\s\S]{0,100}?deleted)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:use\s+SoftDeletes\s*;|Illuminate\\Database\\Eloquent\\SoftDeletes|withTrashed\s*\(\s*\)|onlyTrashed\s*\(\s*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:defaultScope\s*:\s*\{\s*where\s*:\s*\{\s*deletedAt\s*:\s*null|paranoid\s*:\s*true|deletedAt\s*:\s*null)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\.HasQueryFilter\(e\s*=>\s*!e\.IsDeleted\)|HasQueryFilter.*IsDeleted|IgnoreQueryFilters
```
{% endtab %}

{% tab title="Java" %}
```regexp
@Where\(clause\s*=\s*"deleted_at\s+IS\s+NULL"\)|@Where.*deleted|@SQLDelete
```
{% endtab %}

{% tab title="PHP" %}
```regexp
use\s+SoftDeletes;|SoftDeletes|withTrashed|onlyTrashed
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
defaultScope:\s*\{\s*where:\s*\{\s*deletedAt:\s*null|paranoid:\s*true
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// [1]
// [2]
// Entity Framework Global Query Filter permanently hides soft-deleted records from all queries
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<WireTransfer>().HasQueryFilter(t => t.DeletedAt == null);
}

// Background Worker evaluating Compliance SLAs
public class ComplianceSlaWorker : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var cutoffTime = DateTime.UtcNow.AddHours(-48);

            // [3]
            // [4]
            // Queries all transfers in pending state older than 48 hours.
            // Due to the Global Query Filter, soft-deleted records are entirely ignored.
            var expiredTransfers = await _dbContext.WireTransfers
                .Where(t => t.Status == "PENDING_REVIEW" && t.CreatedAt < cutoffTime)
                .ToListAsync();

            foreach (var transfer in expiredTransfers)
            {
                // Business rule: Do not block customer funds indefinitely if admins are backlogged.
                // Auto-advance workflow.
                transfer.Status = "APPROVED";
                transfer.Notes = "Auto-approved via 48h SLA expiration.";
            }

            await _dbContext.SaveChangesAsync();
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
// [1]
// [2]
@Entity
@SQLDelete(sql = "UPDATE wire_transfer SET deleted_at = NOW() WHERE id=?")
@Where(clause = "deleted_at IS NULL") // Global visibility mask
public class WireTransfer {
    // ...
}

@Service
public class ComplianceSlaWorker {

    @Autowired
    private WireTransferRepository transferRepo;

    @Scheduled(fixedRate = 300000)
    public void evaluateSlas() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(48);

        // [3]
        // [4]
        // The @Where clause prevents the repository from seeing the attacker's suspended record.
        List<WireTransfer> expired = transferRepo.findByStatusAndCreatedAtBefore("PENDING_REVIEW", cutoff);

        for (WireTransfer transfer : expired) {
            transfer.setStatus("APPROVED");
            transferRepo.save(transfer);
        }
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
// [1]
// [2]
class WireTransfer extends Model
{
    use SoftDeletes; // Automatically applies 'deleted_at IS NULL' to all queries
}

// Artisan Console Command running via Cron
class EvaluateComplianceSlas extends Command
{
    public function handle()
    {
        $cutoffTime = now()->subHours(48);

        // [3]
        // [4]
        // The SoftDeletes trait obscures cancelled transactions. 
        // When restored, the original 'created_at' timestamp forces the query to pick it up immediately.
        $expiredTransfers = WireTransfer::where('status', 'PENDING_REVIEW')
                                        ->where('created_at', '<', $cutoffTime)
                                        ->get();

        foreach ($expiredTransfers as $transfer) {
            $transfer->status = 'APPROVED';
            $transfer->save();
            
            Log::info("Transfer {$transfer->id} auto-approved due to SLA expiration.");
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
const WireTransfer = sequelize.define('WireTransfer', {
    // fields
}, {
    paranoid: true // Enables soft deletes, injecting 'deletedAt IS NULL' into all reads
});

class ComplianceSlaWorker {
    static async evaluateSlas() {
        const cutoff = new Date(Date.now() - (48 * 60 * 60 * 1000));

        // [3]
        // [4]
        // Paranoid mode hides the record while the SLA timer ticks down in reality.
        let expiredTransfers = await WireTransfer.findAll({
            where: {
                status: 'PENDING_REVIEW',
                createdAt: { [Op.lt]: cutoff }
            }
        });

        for (let transfer of expiredTransfers) {
            transfer.status = 'APPROVED';
            await transfer.save();
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To comply with strict data-retention regulations, the enterprise employs Tombstone records (Soft Deletes) instead of permanent physical SQL destruction, \[2] To prevent deleted records from corrupting active operational dashboards and standard API responses, developers utilize robust ORM features (Global Query Filters) to automatically append visibility constraints (`deleted_at IS NULL`) to every backend query, \[3] The architecture incorporates asynchronous compliance fallback pipelines. To protect end-users from being permanently locked out of their funds due to administrative backlogs, a background worker automatically advances the workflow if a transaction languishes in the review queue beyond a defined SLA, \[4] The temporal execution paradox. The global query filter fundamentally fractures the synchronization between the entity's actual chronological age and its active visibility within the system. The attacker purposefully soft-deletes the record, plunging it into an invisible suspended animation while the physical clock continues to tick. Upon restoring the record 48 hours later, it rematerializes within the active queue possessing an expiration age that exceeds the maximum tolerance threshold. The background worker, unaware of the suspension, instantly evaluates the chronological disparity and blindly authorizes the workflow transition, perfectly bypassing human oversight

```http
// 1. Attacker initiates a high-risk wire transfer that flags compliance filters.
POST /api/v1/transfers HTTP/1.1
Host: bank.enterprise.tld
Authorization: Bearer <valid_token>
Content-Type: application/json

{"destination": "OFFSHORE_ACCT", "amount": 100000}

// 2. The API returns:
// HTTP/1.1 201 Created
// {"id": "TXN-9988", "status": "PENDING_REVIEW", "created_at": "2026-07-16T11:00:00Z"}

// 3. Attacker immediately cancels the transfer, triggering the Soft Delete.
DELETE /api/v1/transfers/TXN-9988 HTTP/1.1
Host: bank.enterprise.tld

// 4. The transaction drops out of the human Fraud Analyst dashboard due to the Global Query Filter.
// 5. Attacker waits exactly 48 hours and 5 minutes (until 2026-07-18T11:05:00Z).

// 6. Attacker invokes the application's "Restore / Undo Cancel" feature.
POST /api/v1/transfers/TXN-9988/restore HTTP/1.1
Host: bank.enterprise.tld

// 7. The ORM removes the 'deleted_at' flag. The transaction rematerializes in the database 
//    with its original status (PENDING_REVIEW) and original created_at timestamp.

// 8. The scheduled ComplianceSlaWorker fires. It queries for PENDING_REVIEW transactions 
//    older than 48 hours. 
// 9. It immediately detects TXN-9988. It assumes the transaction was neglected by analysts.
// 10. The worker auto-advances the workflow state to APPROVED, dispatching the funds.
```
{% endstep %}

{% step %}
To fulfill regulatory data-retention mandates without cluttering operational dashboards, architects leveraged ORM-level Global Query Filters to manage Soft Deleted records transparently. Separately, to prevent indefinite customer lock-out due to administrative backlogs, they deployed temporal SLA workers designed to default-approve neglected transactions. The vulnerability emerged from the intersection of these two disjointed operational optimizations. Developers mistakenly assumed that the continuous chronological aging of a record occurred strictly while the record was visible to the administrative pipeline. The attacker subverted this logic by intentionally soft-deleting their flagged transaction, effectively hiding it from human review while allowing the immutable creation timestamp to age out the SLA threshold. By resurrecting the tombstone record after the critical deadline had passed, the attacker reintroduced an aged asset into the active execution pipeline. The automated SLA worker instantly observed the chronological disparity and authorized the transaction, turning an administrative failsafe into a deterministic mechanism for compliance circumvention
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
