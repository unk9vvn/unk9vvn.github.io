# Session Puzzling

## Check List

## Methodology

### Black Box

#### Bypassing Authentication

{% stepper %}
{% step %}
Navigate to the target application in a browser
{% endstep %}

{% step %}
Observe that a new HTTP session is created and a session ID is assigned to your browser
{% endstep %}

{% step %}
Go to the **Forgot Password** page.
{% endstep %}

{% step %}
Enter a **valid username** (one that exists in the system).
{% endstep %}

{% step %}
Submit the reset password request.
{% endstep %}

{% step %}
Intercept the request/response using a proxy tool (e.g., Burp Suite).
{% endstep %}

{% step %}
Observe that upon submitting a valid username: A session variable (e.g., `userid`) is created on the server, The session variable stores the supplied username, No authentication has occurred yet
{% endstep %}

{% step %}
Without completing the password reset process and without logging in, manually navigate to a post-authentication page, such as: `/home` , `/dashboard` , `/edit-profile`
{% endstep %}

{% step %}
Send the request while keeping the same session cookie
{% endstep %}

{% step %}
Observe that the application allows access to the protected page
{% endstep %}

{% step %}
Confirm that: The application uses the session variable (`userid`) to fetch user-specific data and There is no additional session variable (`authenticated = true`) being validated, Authentication status is not explicitly checked before granting access
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Unified State Management in Multi-Step Recovery Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack.
{% endstep %}

{% step %}
Investigate the application's global session management strategy. In monolithic enterprise applications, developers often consolidate state into a single, global session dictionary (e.g., `HttpContext.Session` or `$_SESSION`) to avoid the complexity of managing multiple isolated state containers
{% endstep %}

{% step %}
Identify the Authorization Middleware. Observe how the system determines if a user is authenticated. Typically, it checks for the existence of a specific, highly privileged key within the session dictionary, such as `AuthenticatedUserId` or `PrincipalId`
{% endstep %}

{% step %}
Analyze the engineering optimization: Building secure, multi-step workflows (like Account Recovery, Multi-Factor Authentication enrollment, or Identity Verification) requires maintaining user context across several stateless HTTP requests
{% endstep %}

{% step %}
Discover that instead of issuing a transient, cryptographically signed JWT or creating a dedicated database table to track these temporary flows, the developers optimized the architecture by reusing the existing global session dictionary
{% endstep %}

{% step %}
Locate the `PasswordRecoveryController` in the decompiled code. Observe the first step of the flow: the user submits an email address
{% endstep %}

{% step %}
Verify that upon finding a matching user, the controller temporarily pushes the victim's database ID into the exact same `AuthenticatedUserId` session key to persist the context for "Step 2" of the recovery wizard
{% endstep %}

{% step %}
The architectural assumption is that the user is functionally locked inside the "Recovery Wizard" UI and cannot deviate from the flow. The developer forgot that the HTTP session state is globally shared across the entire application, and the client browser can simply navigate away
{% endstep %}

{% step %}
Initiate the Password Recovery flow as an attacker. Submit the email address of a highly privileged administrative victim
{% endstep %}

{% step %}
The backend queries the database, finds the administrator, generates a recovery code (sent via email), and crucially, writes the Administrator's ID into your active session dictionary to track your progress
{% endstep %}

{% step %}
Stop interacting with the recovery wizard. Do not submit the recovery code
{% endstep %}

{% step %}
Open a new tab and navigate directly to the enterprise's internal administrative dashboard
{% endstep %}

{% step %}
The Global Authorization Middleware intercepts your request, inspects the global session dictionary, finds the `AuthenticatedUserId` (which was just populated with the Admin's ID by the recovery module), and grants you full access without ever requiring a password or 2FA

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Session\.(?:Set|SetString|SetInt32)\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|HttpContext\.Session\.(?:Set|SetString|SetInt32)\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|HttpContext\.User\b|ClaimsPrincipal\b|ClaimsIdentity\b|SignInManager\.(?:SignInAsync|PasswordSignInAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:setAttribute\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|HttpSession\.setAttribute\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|SecurityContextHolder\.getContext\s*\(\)|UsernamePasswordAuthenticationToken\b|Authentication\b|Principal\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$_SESSION\[['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\]\s*=|\$request->session\(\)->put\s*\(\s*['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\s*,|session\(\)->put\s*\(\s*['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\s*,|Auth::login\b|Auth::attempt\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.session\.(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)\s*=|req\.session\[['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\]\s*=|req\.login\s*\(|passport\.serializeUser\s*\(|passport\.deserializeUser\s*\(|express-session\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Session\.(?:Set|SetString|SetInt32)\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|HttpContext\.Session\.(?:Set|SetString|SetInt32)\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|HttpContext\.User\b|ClaimsPrincipal\b|ClaimsIdentity\b|SignInManager\.(?:SignInAsync|PasswordSignInAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:setAttribute\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|HttpSession\.setAttribute\s*\(\s*"(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)"\s*,|SecurityContextHolder\.getContext\s*\(\)|UsernamePasswordAuthenticationToken\b|Authentication\b|Principal\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$_SESSION\[['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\]\s*=|\$request->session\(\)->put\s*\(\s*['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\s*,|session\(\)->put\s*\(\s*['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\s*,|Auth::login\b|Auth::attempt\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.session\.(?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)\s*=|req\.session\[['"](?:(?:Authenticated|Current)?User(?:Id)?|PrincipalId|IdentityId|AccountId)['"]\]\s*=|req\.login\s*\(|passport\.serializeUser\s*\(|passport\.deserializeUser\s*\(|express-session\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class PasswordRecoveryController : ControllerBase 
{
    private readonly IUserRepository _userRepo;
    private readonly IEmailService _emailService;

    [HttpPost("/api/v1/recovery/step1")]
    public async Task<IActionResult> InitiateRecovery([FromForm] string email) 
    {
        var user = await _userRepo.FindByEmailAsync(email);
        if (user != null) 
        {
            var otp = CryptoUtils.GenerateOtp();
            await _emailService.SendRecoveryCodeAsync(user.Email, otp);
            
            // [1]
            // [2]
            // [3]
            HttpContext.Session.SetString("AuthenticatedUserId", user.Id.ToString());
            HttpContext.Session.SetString("PendingOtp", otp);
        }
        
        // [4]
        return Ok(new { message = "If the email exists, a code was sent." });
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class PasswordRecoveryController {

    @Autowired
    private UserRepository userRepo;
    @Autowired
    private EmailService emailService;

    @PostMapping("/api/v1/recovery/step1")
    public ResponseEntity<?> initiateRecovery(@RequestParam("email") String email, HttpServletRequest request) {
        User user = userRepo.findByEmail(email);
        if (user != null) {
            String otp = CryptoUtils.generateOtp();
            emailService.sendRecoveryCode(user.getEmail(), otp);
            
            // [1]
            // [2]
            // [3]
            request.getSession().setAttribute("AuthenticatedUserId", String.valueOf(user.getId()));
            request.getSession().setAttribute("PendingOtp", otp);
        }
        
        // [4]
        return ResponseEntity.ok(Map.of("message", "If the email exists, a code was sent."));
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class PasswordRecoveryController extends Controller
{
    public function initiateRecovery(Request $request) 
    {
        $user = $this->userRepo->findByEmail($request->input('email'));
        if ($user) 
        {
            $otp = CryptoUtils::generateOtp();
            $this->emailService->sendRecoveryCode($user->email, $otp);
            
            // [1]
            // [2]
            // [3]
            session(['AuthenticatedUserId' => clone $user->id]);
            session(['PendingOtp' => $otp]);
        }
        
        // [4]
        return response()->json(['message' => 'If the email exists, a code was sent.']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/recovery/step1', async (req, res) => {
    let user = await userRepo.findByEmail(req.body.email);
    if (user) {
        let otp = CryptoUtils.generateOtp();
        await emailService.sendRecoveryCode(user.email, otp);
        
        // [1]
        // [2]
        // [3]
        req.session.AuthenticatedUserId = user.id.toString();
        req.session.PendingOtp = otp;
    }
    
    // [4]
    res.json({ message: "If the email exists, a code was sent." });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The controller successfully identifies the target user requesting a password reset, \[2] To optimize context persistence across the multi-step recovery UI (preventing the need to continuously pass the email or a JWT parameter back and forth), the developer leverages the existing server-side session, \[3] The fundamental Session Puzzling flaw occurs here. The developer carelessly reuses the exact same session key (`AuthenticatedUserId`) that the Global Authentication Middleware uses to verify if a user is fully logged in, \[4] The server responds securely (avoiding user enumeration by returning a generic message), but the global session dictionary in the backend memory is already irreversibly polluted. The attacker's session is now inextricably tied to the victim's identity

```http
// 1. Attacker initiates password recovery for the Enterprise Admin.
POST /api/v1/recovery/step1 HTTP/1.1
Host: identity.enterprise.tld
Content-Type: application/x-www-form-urlencoded
Cookie: EnterpriseSession=ATTACKER_ANONYMOUS_SESSION

email=admin@enterprise.tld

// 2. Server responds, silently poisoning the attacker's session state.
HTTP/1.1 200 OK
```

```http
// 3. Attacker abandons the recovery wizard and navigates directly to the core application.
GET /api/v1/admin/user-management HTTP/1.1
Host: portal.enterprise.tld
Cookie: EnterpriseSession=ATTACKER_ANONYMOUS_SESSION
```
{% endstep %}

{% step %}
The backend architectural decision to reuse a single global session dictionary for both authorization and multi-step workflow context created a severe namespace collision. When the attacker initiates the password reset for the administrator, the `PasswordRecoveryController` injects the Admin's ID into the session to prepare for "Step 2". By intentionally breaking the expected UI flow (Puzzling) and forcing a request to an entirely different module, the Global Authorization Middleware reads the populated session variable. It has no mechanism to distinguish whether the variable was set by a successful `/login` execution or by the `/recovery` module. It assumes full authentication and grants the attacker total administrative access
{% endstep %}
{% endstepper %}

***

#### Unauthorized Action Execution via SPA Context State Overloading

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Pay attention to Single Page Application (SPA) routing behaviors
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Evaluate the B2B platform's architectural design regarding resource targeting. In modern SPAs, deeply nested routing (e.g., `/api/v1/orgs/123/departments/456/invoices/789/approve`) often creates complex frontend state management issues
{% endstep %}

{% step %}
Identify the "Active Context" optimization. To simplify backend controller signatures and prevent authorization bypasses via parameter tampering, developers omit the target ID from the HTTP request entirely. Instead, when a user clicks an item in a list, the SPA calls a `/api/v1/context/set-active` endpoint, storing the `ActiveDocumentId` securely in the server-side session
{% endstep %}

{% step %}
The underlying architectural assumption is that the `ActiveDocumentId` can only be set if the user successfully views the document list, which enforces ownership constraints
{% endstep %}

{% step %}
Search the decompiled codebase for any other controllers, API endpoints, or public features that also write to the `ActiveDocumentId` session variable
{% endstep %}

{% step %}
Discover a low-privilege or public "Tracking" feature. For instance, a public "Track Package Status" or "Invoice Validation" portal that allows anyone with a tracking UUID to view the public metadata of a document
{% endstep %}

{% step %}
Verify that to render the public tracking page, the public controller utilizes the exact same shared library or base class, which inadvertently writes the victim's Document ID into the session's `ActiveDocumentId` key
{% endstep %}

{% step %}
Find a highly privileged state-mutating endpoint (e.g., `/api/v1/document/approve` or `/api/v1/document/delete`). Verify that this endpoint takes zero parameters, instead pulling the target directly from `Session["ActiveDocumentId"]`
{% endstep %}

{% step %}
Authenticate to the application as a low-privilege user (who lacks access to the target document)
{% endstep %}

{% step %}
Access the public Tracking endpoint using the target document's UUID. This action safely returns public metadata, but silently overwrites your server-side session state, setting your `ActiveDocumentId` to the victim's private document
{% endstep %}

{% step %}
Immediately issue a POST request to the parameter-less `/approve` endpoint
{% endstep %}

{% step %}
The backend retrieves the document ID from your session (placed there by the public tracker), assumes you navigated there via the secure internal dashboard, and blindly executes the approval workflow on the victim's resource
{% endstep %}

{% step %}
**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Session\s*\[\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"\s*\]\s*=|HttpContext\.Session\.(?:SetString|SetInt32|Set)\s*\(\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"|Session\s*\[\s*"[^"]*(?:Id|ID)"\s*\]\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:session\.setAttribute\s*\(\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"|HttpSession\.setAttribute\s*\(\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"|setAttribute\s*\(\s*"[^"]*(?:Id|ID)"\s*,)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$_SESSION\s*\[\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"]\s*\]|\$request->session\(\)->put\s*\(\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"]|session\(\)->put\s*\(\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.session\.(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)\s*=|req\.session\s*\[\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"]\s*\]\s*=|req\.session\.[A-Za-z0-9_]*(?:Id|ID)\s*=)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Session\s*\[\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"\s*\]\s*=|HttpContext\.Session\.(?:SetString|SetInt32|Set)\s*\(\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"|Session\s*\[\s*"[^"]*(?:Id|ID)"\s*\]\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:session\.setAttribute\s*\(\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"|HttpSession\.setAttribute\s*\(\s*"(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)"|setAttribute\s*\(\s*"[^"]*(?:Id|ID)"\s*,)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$_SESSION\s*\[\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"]\s*\]|\$request->session\(\)->put\s*\(\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"]|session\(\)->put\s*\(\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.session\.(?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)\s*=|req\.session\s*\[\s*['"](?:(?:Active|Current|Selected)(?:Document|Project|Workspace|Organization|Org|Tenant|Account|Company|Customer|Order|Invoice|Cart|Case|Folder|File|Resource|Record)(?:Id)?)['"]\s*\]\s*=|req\.session\.[A-Za-z0-9_]*(?:Id|ID)\s*=)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// The Public Tracker (No Auth Required)
[HttpGet("/api/v1/public/track")]
public async Task<IActionResult> TrackDocument([FromQuery] string trackingId) 
{
    var doc = await _documentRepo.FindByTrackingIdAsync(trackingId);
    if (doc == null) return NotFound();

    // [1]
    // [2]
    HttpContext.Session.SetString("ActiveDocumentId", doc.Id.ToString());

    return Ok(new { Status = doc.PublicStatus });
}

// The Private Workflow Action (Auth Required, but Parameter-less)
[HttpPost("/api/v1/workflow/approve")]
public async Task<IActionResult> ApproveDocument() 
{
    // [3]
    var activeId = HttpContext.Session.GetString("ActiveDocumentId");
    
    // [4]
    await _workflowService.ExecuteApprovalAsync(activeId, _currentUser.Id);
    
    return Ok(new { Message = "Document Approved" });
}
```
{% endtab %}

{% tab title="Java" %}
```java
// The Public Tracker (No Auth Required)
@GetMapping("/api/v1/public/track")
public ResponseEntity<?> trackDocument(@RequestParam("trackingId") String trackingId, HttpServletRequest request) {
    Document doc = documentRepo.findByTrackingId(trackingId);
    if (doc == null) return ResponseEntity.notFound().build();

    // [1]
    // [2]
    request.getSession().setAttribute("ActiveDocumentId", String.valueOf(doc.getId()));

    return ResponseEntity.ok(Map.of("Status", doc.getPublicStatus()));
}

// The Private Workflow Action (Auth Required, but Parameter-less)
@PostMapping("/api/v1/workflow/approve")
public ResponseEntity<?> approveDocument(HttpServletRequest request) {
    // [3]
    String activeId = (String) request.getSession().getAttribute("ActiveDocumentId");
    
    // [4]
    workflowService.executeApproval(activeId, currentUser.getId());
    
    return ResponseEntity.ok(Map.of("Message", "Document Approved"));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// The Public Tracker (No Auth Required)
public function trackDocument(Request $request) 
{
    $doc = $this->documentRepo->findByTrackingId($request->query('trackingId'));
    if (!$doc) return response('Not Found', 404);

    // [1]
    // [2]
    session(['ActiveDocumentId' => $doc->id]);

    return response()->json(['Status' => $doc->publicStatus]);
}

// The Private Workflow Action (Auth Required, but Parameter-less)
public function approveDocument(Request $request) 
{
    // [3]
    $activeId = session('ActiveDocumentId');
    
    // [4]
    $this->workflowService->executeApproval($activeId, $this->currentUser->id);
    
    return response()->json(['Message' => 'Document Approved']);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// The Public Tracker (No Auth Required)
router.get('/api/v1/public/track', async (req, res) => {
    let doc = await documentRepo.findByTrackingId(req.query.trackingId);
    if (!doc) return res.status(404).send();

    // [1]
    // [2]
    req.session.ActiveDocumentId = doc.id;

    res.json({ Status: doc.publicStatus });
});

// The Private Workflow Action (Auth Required, but Parameter-less)
router.post('/api/v1/workflow/approve', async (req, res) => {
    // [3]
    let activeId = req.session.ActiveDocumentId;
    
    // [4]
    await workflowService.executeApproval(activeId, req.user.id);
    
    res.json({ Message: "Document Approved" });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The public endpoint successfully locates the document using an unguessable tracking UUID, \[2] The developer reuses a core service method to hydrate the document, which implicitly writes the internal database ID into the session's `ActiveDocumentId` to maintain architectural consistency with the rest of the SPA, \[3] The private, highly secure action endpoint takes absolutely no parameters from the HTTP request. This was an engineering optimization intended to explicitly prevent Insecure Direct Object Reference (IDOR) attacks, ensuring the user can only act on the document currently bound to their session context, \[4] The system blindly executes the approval workflow. It operates on the fatal assumption that the only way `ActiveDocumentId` gets populated is if the user navigated through the secure, permission-checked Dashboard UI

```http
// 1. Attacker is logged in as a low-level employee.
// 2. Attacker interacts with the public tracking page for the CEO's private contract.
GET /api/v1/public/track?trackingId=ext-uuid-contract-991 HTTP/1.1
Host: b2b.enterprise.tld
Cookie: SessionToken=ATTACKER_LOW_PRIV_SESSION

// 3. The server responds with the public status, silently setting the session variable.
HTTP/1.1 200 OK
Content-Type: application/json

{"Status": "Pending Signature"}
```

```http
// 4. Attacker forces a request to the parameter-less approval endpoint.
POST /api/v1/workflow/approve HTTP/1.1
Host: b2b.enterprise.tld
Cookie: SessionToken=ATTACKER_LOW_PRIV_SESSION
```
{% endstep %}

{% step %}
The architectural optimization to mitigate IDOR via server-side "Active Context" management created a fatal state-overlap boundary. By interacting with a seemingly benign, public-facing read-only endpoint, the attacker successfully solved the Session Puzzle, injecting the internal ID of a highly classified document directly into their server-side session cache. When the attacker subsequently invoked the parameter-less `/approve` endpoint, the backend extracted the poisoned `ActiveDocumentId`, bypassed all ownership validation logic (assuming it was verified during the context-setting phase), and authorized the fraudulent approval on behalf of the attacker
{% endstep %}
{% endstepper %}

***

#### SAML Just-In-Time Provisioning Hijack via Form Wizard Data Overlap

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
Evaluate the enterprise's Identity Federation logic. Notice that the application supports multi-tenant SSO via SAML or OIDC, and explicitly enables Just-In-Time (JIT) Provisioning to automatically create local database accounts when users log in via their corporate Identity Provider (IdP)
{% endstep %}

{% step %}
Investigate the "SSO Migration" optimization. When an enterprise migrates from local passwords to SSO, users often have existing local accounts. To seamlessly link the incoming SAML assertion to the existing local account, the system relies on matching the email address
{% endstep %}

{% step %}
Look for the `AssertionConsumerService` (ACS) endpoint in the decompiled code. Analyze how it extracts the email from the SAML token to map the user
{% endstep %}

{% step %}
Discover the fallback overlap: If the SAML token lacks an explicitly trusted email claim, or if the system requires a manual "Account Link" step, the developer allows the ACS controller to read a specific session variable (e.g., `PendingIdentityEmail`) as a trusted source of truth to execute the account binding
{% endstep %}

{% step %}
Search the codebase for other endpoints that populate the `PendingIdentityEmail` session key
{% endstep %}

{% step %}
Locate a low-privilege "Guest Invite" or "Pre-Registration" feature. For instance, when a user wants to invite an external contractor, they enter the contractor's email. The backend stores this email in `Session["PendingIdentityEmail"]` so the next page in the wizard can send the invitation link
{% endstep %}

{% step %}
The architectural assumption is that `Session["PendingIdentityEmail"]` strictly represents an identity _the current user is actively trying to prove ownership of_ during a controlled workflow
{% endstep %}

{% step %}
Begin the "Guest Invite" wizard as an attacker. Enter the target victim's email address (e.g., `admin@enterprise.tld`)
{% endstep %}

{% step %}
The backend validates the email format and pushes `admin@enterprise.tld` into your active session
{% endstep %}

{% step %}
Abort the invite flow. Immediately initiate an SSO login using a completely different, attacker-controlled Identity Provider (e.g., a rogue tenant you registered)
{% endstep %}

{% step %}
Authenticate to your rogue IdP. Your IdP redirects you back to the enterprise's ACS endpoint with a valid, cryptographically signed SAML token belonging to the attacker
{% endstep %}

{% step %}
The ACS endpoint receives the valid token, begins the JIT provisioning process, reads the `PendingIdentityEmail` from your session, and irreversibly binds your rogue SAML identity to the Administrator's existing local account

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Session\s*\[\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"\s*\]\s*=|HttpContext\.Session\.(?:Set|SetString|SetInt32)\s*\(\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"|Bind(?:Sso|OAuth|Oidc|External)Identity\b[\s\S]{0,150}?Session|SignInManager\.(?:ExternalLoginSignInAsync|GetExternalLoginInfoAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:session\.setAttribute\s*\(\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"|HttpSession\.setAttribute\s*\(\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"|bind(?:Sso|OAuth|Oidc|External)Identity\b[\s\S]{0,150}?session|OAuth2AuthenticationToken\b|OidcUser\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$_SESSION\s*\[\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]\s*\]|\$request->session\(\)->put\s*\(\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]|session\(\)->put\s*\(\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]|bind(?:Sso|OAuth|Oidc|External)Identity)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.session\.(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)\s*=|req\.session\s*\[\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]\s*\]\s*=|bind(?:Sso|OAuth|Oidc|External)Identity\b[\s\S]{0,150}?session|passport\.authenticate\s*\(\s*['"](google|github|microsoft|azure-ad|oidc|oauth2|saml)['"])
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Session\s*\[\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"\s*\]=|HttpContext\.Session\.(?:Set|SetString|SetInt32)\s*\(\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"|Bind(?:Sso|OAuth|Oidc|External)Identity.*Session|SignInManager\.(?:ExternalLoginSignInAsync|GetExternalLoginInfoAsync)\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:session\.setAttribute\s*\(\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"|HttpSession\.setAttribute\s*\(\s*"(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)"|bind(?:Sso|OAuth|Oidc|External)Identity.*session|OAuth2AuthenticationToken\b|OidcUser\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$_SESSION\s*\[\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]\s*\]|\$request->session\(\)->put\s*\(\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]|session\(\)->put\s*\(\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]|bind(?:Sso|OAuth|Oidc|External)Identity)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.session\.(?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)\s*=|req\.session\s*\[\s*['"](?:(?:Pending|Temporary|Temp|PreAuth|Unverified|External|Sso|OAuth|Oidc)(?:Identity|User|Email|Account|Principal|Login|Subject|Claims|Provider|Token|Session)(?:Id|Email|Name)?)['"]\s*\]\s*=|bind(?:Sso|OAuth|Oidc|External)Identity.*session|passport\.authenticate\s*\(\s*['"](google|github|microsoft|azure-ad|oidc|oauth2|saml)['"])
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// The Unauthenticated/Low-Privilege Invite Wizard
[HttpPost("/api/v1/invite/step1")]
public IActionResult StartInvite([FromForm] string email) 
{
    // [1]
    // [2]
    HttpContext.Session.SetString("PendingIdentityEmail", email);
    return Ok(new { NextStep = "/api/v1/invite/step2" });
}

// The SAML Assertion Consumer Service (ACS)
[HttpPost("/saml/acs")]
public async Task<IActionResult> SamlCallback() 
{
    var samlResponse = DecodeSamlResponse(Request.Form["SAMLResponse"]);
    
    // [3]
    var targetEmail = HttpContext.Session.GetString("PendingIdentityEmail") 
                      ?? samlResponse.GetClaim("email");

    // [4]
    var localUser = await _userRepo.FindByEmailAsync(targetEmail);
    if (localUser != null) 
    {
        await _userRepo.BindSsoIdentityAsync(localUser.Id, samlResponse.Issuer, samlResponse.NameId);
        return Redirect("/dashboard");
    }

    return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
// The Unauthenticated/Low-Privilege Invite Wizard
@PostMapping("/api/v1/invite/step1")
public ResponseEntity<?> startInvite(@RequestParam("email") String email, HttpServletRequest request) {
    // [1]
    // [2]
    request.getSession().setAttribute("PendingIdentityEmail", email);
    return ResponseEntity.ok(Map.of("NextStep", "/api/v1/invite/step2"));
}

// The SAML Assertion Consumer Service (ACS)
@PostMapping("/saml/acs")
public String samlCallback(HttpServletRequest request) {
    SamlResponse samlResponse = decodeSamlResponse(request.getParameter("SAMLResponse"));
    
    // [3]
    String targetEmail = (String) request.getSession().getAttribute("PendingIdentityEmail");
    if (targetEmail == null) {
        targetEmail = samlResponse.getClaim("email");
    }

    // [4]
    User localUser = userRepo.findByEmail(targetEmail);
    if (localUser != null) {
        userRepo.bindSsoIdentity(localUser.getId(), samlResponse.getIssuer(), samlResponse.getNameId());
        return "redirect:/dashboard";
    }

    throw new SecurityException("Unauthorized");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// The Unauthenticated/Low-Privilege Invite Wizard
public function startInvite(Request $request) 
{
    // [1]
    // [2]
    session(['PendingIdentityEmail' => $request->input('email')]);
    return response()->json(['NextStep' => '/api/v1/invite/step2']);
}

// The SAML Assertion Consumer Service (ACS)
public function samlCallback(Request $request) 
{
    $samlResponse = $this->decodeSamlResponse($request->input('SAMLResponse'));
    
    // [3]
    $targetEmail = session('PendingIdentityEmail') ?? $samlResponse->getClaim('email');

    // [4]
    $localUser = $this->userRepo->findByEmail($targetEmail);
    if ($localUser) 
    {
        $this->userRepo->bindSsoIdentity($localUser->id, $samlResponse->issuer, $samlResponse->nameId);
        return redirect('/dashboard');
    }

    return response('Unauthorized', 401);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// The Unauthenticated/Low-Privilege Invite Wizard
router.post('/api/v1/invite/step1', (req, res) => {
    // [1]
    // [2]
    req.session.PendingIdentityEmail = req.body.email;
    res.json({ NextStep: '/api/v1/invite/step2' });
});

// The SAML Assertion Consumer Service (ACS)
router.post('/saml/acs', async (req, res) => {
    let samlResponse = decodeSamlResponse(req.body.SAMLResponse);
    
    // [3]
    let targetEmail = req.session.PendingIdentityEmail || samlResponse.getClaim('email');

    // [4]
    let localUser = await userRepo.findByEmail(targetEmail);
    if (localUser) {
        await userRepo.bindSsoIdentity(localUser.id, samlResponse.issuer, samlResponse.nameId);
        return res.redirect('/dashboard');
    }

    res.status(401).send('Unauthorized');
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application implements a multi-step wizard for guest invitations., \[2] To seamlessly pass data between the wizard's steps without risking DOM-based tampering, the developer stores the target email address in the user's secure server-side session, \[3] The fatal namespace collision. The JIT SAML provisioning pipeline prioritizes the session variable over the cryptographic claims provided by the IdP token. This was likely an engineering optimization to support legacy "Account Linking" flows where users typed an email into a form before logging in via SSO, \[4] The system blindly trusts the session variable as the definitive target for account binding. It modifies the existing local account, attaching the attacker's IdP Subject ID (`NameId`) to it. Future logins via the attacker's rogue IdP will now automatically authenticate as the victim

```http
// 1. Attacker starts an arbitrary form wizard, injecting the Admin's email into their session.
POST /api/v1/invite/step1 HTTP/1.1
Host: portal.enterprise.tld
Content-Type: application/x-www-form-urlencoded
Cookie: SessionToken=ATTACKER_GUEST_SESSION

email=admin@enterprise.tld

// 2. Server responds, silently poisoning the attacker's session state.
HTTP/1.1 200 OK
```

```http
// 3. Attacker initiates an SSO login using their own rogue Identity Provider.
// 4. Rogue IdP redirects back to the enterprise ACS endpoint.
POST /saml/acs HTTP/1.1
Host: portal.enterprise.tld
Content-Type: application/x-www-form-urlencoded
Cookie: SessionToken=ATTACKER_GUEST_SESSION

SAMLResponse=PD94b...[ATTACKERS_ROGUE_SAML_TOKEN]...
```
{% endstep %}

{% step %}
The architectural decision to optimize state passing via the global session dictionary resulted in a catastrophic logic bypass. When the attacker initiates the invite wizard, the system writes `admin@enterprise.tld` into the active session block. By instantly pivoting to the SAML SSO pipeline, the attacker solves the Session Puzzle. The ACS endpoint validates the cryptographic integrity of the attacker's SAML token, but relies on the poisoned session variable (`PendingIdentityEmail`) to determine _which_ local account to map the token to. The backend permanently links the attacker's rogue SSO Identity Provider to the Administrator's local account. The attacker achieves complete Account Takeover without ever possessing the victim's password, MFA token, or legitimate SSO credentials
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
