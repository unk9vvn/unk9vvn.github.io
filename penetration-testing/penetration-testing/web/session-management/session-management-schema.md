# Session Management Schema

## Check List

## Methodology

### Black Box

#### Cookie Transport Security Test

{% stepper %}
{% step %}
Open the application via HTTP
{% endstep %}

{% step %}
Check if the cookie is sent over an unencrypted connection
{% endstep %}

{% step %}
Send a manual HTTP request with the same cookie
{% endstep %}

{% step %}
Check if the server accepts the request
{% endstep %}

{% step %}
If accepted, weakness is confirmed
{% endstep %}
{% endstepper %}

***

#### Session Expiration & Replay Test

{% stepper %}
{% step %}
Log in and save the SessionID
{% endstep %}

{% step %}
Log out of the account
{% endstep %}

{% step %}
Reuse the same SessionID
{% endstep %}

{% step %}
After the session timeout, reuse the token.
{% endstep %}

{% step %}
Use the token in another browser or device
{% endstep %}

{% step %}
If it were still valid, the weakness would be confirmed
{% endstep %}
{% endstepper %}

***

#### Session Tampering Test

{% stepper %}
{% step %}
Send a valid request with SessionID
{% endstep %}

{% step %}
Change one character of the SessionID
{% endstep %}

{% step %}
Resubmit the request
{% endstep %}

{% step %}
Delete part of the token and submit
{% endstep %}

{% step %}
Replace the desired value and submit
{% endstep %}

{% step %}
If the server accepts the tampered token, the weakness is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via Session Schema Projection Truncation in Distributed Service Meshes

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
Identify the architecture's strategy for propagating session state between the API Gateway (or Backend-For-Frontend) and downstream microservices
{% endstep %}

{% step %}
Observe if the central Identity Service manages a massive, monolithic `HeavySessionSchema` (containing hundreds of entitlements, nested tenant access policies, and explicit deny rules) that is too large to realistically forward in every HTTP request
{% endstep %}

{% step %}
Investigate how the API Gateway projects or compresses this heavy schema into a `LightweightSessionDto` before injecting it into downstream request headers (e.g., `X-Forwarded-Session` or gRPC metadata) to prevent HTTP `431 Request Header Fields Too Large` errors.
{% endstep %}

{% step %}
In the decompiled projection logic, analyze the mapping loop that iterates over the user's policies and roles. Look for hardcoded optimization thresholds (e.g., `MAX_POLICIES = 50`) implemented to guarantee header size compliance
{% endstep %}

{% step %}
Evaluate the specific structure of the session schema. Enterprise systems frequently employ a hybrid authorization model where a user receives baseline "Allow" roles, coupled with explicit "Deny" policies (`Deny_Billing_Access`) that override the baseline
{% endstep %}

{% step %}
Determine if the projection loop truncates the policy array blindly when the maximum threshold is reached, without prioritizing explicit "Deny" rules over "Allow" rules or sorting the array prior to iteration
{% endstep %}

{% step %}
Confirm if downstream microservices rely entirely on the projected `LightweightSessionDto` to materialize their local authorization context, assuming the projection is a complete and accurate representation of the user's constraints
{% endstep %}

{% step %}
From an attacker-controlled account, interact with a feature that allows you to inflate your session schema with benign, low-impact data. For example, create 50 empty sub-organizations, generate 50 custom read-only roles, or join 50 public groups
{% endstep %}

{% step %}
Monitor the API Gateway's behavior as your active session schema swells in size inside the database.
{% endstep %}

{% step %}
Trigger an authorization check against a restricted endpoint. The API Gateway will project your massive schema, truncate the array at the 50-item limit, and push the explicit `Deny` rules out of the bounds of the `LightweightSessionDto`
{% endstep %}

{% step %}
The downstream service receives a truncated session schema devoid of the `Deny` rules, defaults back to the baseline "Allow" role, and grants unauthorized access

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|(?:Count|Length)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|\.Count\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|policies\.Count\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|\.size\s*\(\s*\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|CollectionUtils\.size\s*\(.*?\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|count\s*\(\s*\$?\w+\s*\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|sizeof\s*\(\s*\$?\w+\s*\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|Array\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|Object\.keys\s*\(.*?\)\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|(?:Count|Length)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|\.Count\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|policies\.Count\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|\.size\s*\(\s*\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|CollectionUtils\.size\s*\(.*?\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|count\s*\(\s*\$?\w+\s*\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|sizeof\s*\(\s*\$?\w+\s*\)\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:MAX_POLIC(?:Y|IES)\s*=\s*\d+\b|\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|Array\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b|Object\.keys\s*\(.*?\)\.length\s*(?:>=|>|==)\s*MAX_POLIC(?:Y|IES)\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SessionMapper 
{
    private const int MAX_POLICIES = 50;

    public LightweightSessionDto ProjectForMicroservice(HeavySessionSchema heavySchema) 
    {
        var lightweightSession = new LightweightSessionDto();
        lightweightSession.UserId = heavySchema.UserId;
        lightweightSession.Policies = new List<string>();

        // [1]
        var allPolicies = heavySchema.Policies;

        // [2]
        for (int i = 0; i < allPolicies.Count; i++) 
        {
            if (i >= MAX_POLICIES) 
            {
                // [3]
                Console.WriteLine("Truncated policies for " + heavySchema.UserId + " to prevent header overflow");
                break;
            }
            lightweightSession.Policies.Add(allPolicies[i]);
        }

        return lightweightSession;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class SessionMapper {
    private static final int MAX_POLICIES = 50;

    public LightweightSessionDto projectForMicroservice(HeavySessionSchema heavySchema) {
        LightweightSessionDto lightweightSession = new LightweightSessionDto();
        lightweightSession.setUserId(heavySchema.getUserId());
        lightweightSession.setPolicies(new ArrayList<>());

        // [1]
        List<String> allPolicies = heavySchema.getPolicies();

        // [2]
        for (int i = 0; i < allPolicies.size(); i++) {
            if (i >= MAX_POLICIES) {
                // [3]
                System.out.println("Truncated policies for " + heavySchema.getUserId() + " to prevent header overflow");
                break;
            }
            lightweightSession.getPolicies().add(allPolicies.get(i));
        }

        return lightweightSession;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SessionMapper 
{
    const MAX_POLICIES = 50;

    public function projectForMicroservice(HeavySessionSchema $heavySchema): LightweightSessionDto 
    {
        $lightweightSession = new LightweightSessionDto();
        $lightweightSession->userId = $heavySchema->userId;
        $lightweightSession->policies = [];

        // [1]
        $allPolicies = $heavySchema->policies;

        // [2]
        for ($i = 0; $i < count($allPolicies); $i++) 
        {
            if ($i >= self::MAX_POLICIES) 
            {
                // [3]
                error_log("Truncated policies for " . $heavySchema->userId . " to prevent header overflow");
                break;
            }
            $lightweightSession->policies[] = $allPolicies[$i];
        }

        return $lightweightSession;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SessionMapper {
    static MAX_POLICIES = 50;

    static projectForMicroservice(heavySchema) {
        let lightweightSession = new LightweightSessionDto();
        lightweightSession.userId = heavySchema.userId;
        lightweightSession.policies = [];

        // [1]
        let allPolicies = heavySchema.policies;

        // [2]
        for (let i = 0; i < allPolicies.length; i++) {
            if (i >= this.MAX_POLICIES) {
                // [3]
                console.warn("Truncated policies for " + heavySchema.userId + " to prevent header overflow");
                break;
            }
            lightweightSession.policies.push(allPolicies[i]);
        }

        return lightweightSession;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture extracts the complete, authoritative list of policies from the primary schema. This list contains both `Allow` and `Deny` rules, typically returned in the order they were inserted into the database, \[2] To optimize downstream header propagation and protect the internal infrastructure from HTTP header size limits, the mapper iterates over the policies, \[3] The critical assumption fails here: The projection logic applies a blunt truncation when the hardcoded threshold is reached. It lacks semantic awareness of the policies it is discarding. If the user pads their profile, the explicit `Deny` policies are pushed past the 50th index and are silently erased from the materialized downstream session

```http
POST /api/v1/workspaces HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"workspace_name": "Padding_1"}
... (Request repeated 50 times to generate 50 default 'Workspace_Reader' policies)
```

```http
GET /api/v1/billing/invoices HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>
```
{% endstep %}

{% step %}
The API Gateway successfully parses the user's token and retrieves the schema containing 50 `Workspace_Reader` policies and 1 `Deny_Billing` policy at the end of the array. The projection pipeline triggers, reaching the `MAX_POLICIES` threshold exactly after mapping the 50 padding policies. The `Deny_Billing` policy is truncated. The `LightweightSessionDto` is forwarded to the Billing Microservice. The Billing Microservice evaluates the projected schema, finds no explicit denial, defaults to the user's baseline organizational privileges, and returns the restricted invoices. The optimization intended to protect network stability fundamentally broke the authorization materialization pipeline
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via Session Hydration Pipeline Routing Confusion in Identity Federation

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
Examine the enterprise's Identity Federation architecture (e.g., SAML 2.0 or OIDC). Note how the API Gateway trusts external Identity Providers (IdPs) to assert user identities
{% endstep %}

{% step %}
Identify the "Lazy Session Hydration" optimization. In modern federated systems, the API Gateway parses the external SAML/OIDC assertion, creates a `BarebonesSessionContext` (containing only structural claims), and passes it downstream. Downstream services must hydrate the complex roles from their own local databases only when required
{% endstep %}

{% step %}
Look for a polymorphic hydration pipeline. Often, downstream services must handle requests from both Human Users and Internal Service Accounts. To optimize this, the pipeline inspects a specific string claim in the barebones session (e.g., `is_service_account`) to determine which database repository to query
{% endstep %}

{% step %}
Understand the trust boundary assumption: The developers assume that the `is_service_account` claim is injected securely by the API Gateway during internal token generation, representing an immutable structural type
{% endstep %}

{% step %}
Discover that the API Gateway's external token mapper blindly copies custom attributes from the external Bring-Your-Own (BYO) IdP directly into the internal barebones session claims dictionary
{% endstep %}

{% step %}
Setup an attacker-controlled BYO IdP (e.g., a free Okta developer tenant) and configure a custom SAML attribute or OIDC claim named is\_service\_account and set it to the string "true"
{% endstep %}

{% step %}
Set the `subject_id` (or `NameID`) of your federated user to exactly match the known UUID or ClientID of a highly privileged internal Service Account
{% endstep %}

{% step %}
Authenticate through the API Gateway using your BYO IdP. The Gateway creates a barebones session containing your injected claim and the target Service Account's ID, scoped to your isolated tenant
{% endstep %}

{% step %}
Access a privileged endpoint. The downstream service's polymorphic hydration pipeline reads the claim, skips the standard user repository, and routes the lookup to the `ServiceAccountRepository`
{% endstep %}

{% step %}
Because Service Accounts are often globally scoped (not tenant-bound), the repository matches the `subject_id` and hydrates the global system administrative roles into your local session schema

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:HydrateSession\s*\(\s*BarebonesSessionContext\b|\.Claims\.TryGetValue\s*\(\s*"is_service_account"\b|ServiceAccountRepository\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:hydrateSession\s*\(\s*BarebonesSessionContext\b|\.getClaims\s*\(\)\.containsKey\s*\(\s*"is_service_account"\s*\)|\.getClaims\s*\(\)\.get\s*\(\s*"is_service_account"\s*\)|ServiceAccountRepository\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:hydrateSession\s*\(\s*new\s+BarebonesSessionContext\b|\$claims\s*\[\s*['"]is_service_account['"]\s*\]|\$claims->get\s*\(\s*['"]is_service_account['"]\s*\)|ServiceAccountRepository\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:hydrateSession\s*\(\s*new\s+BarebonesSessionContext\b|\.claims\.get\s*\(\s*['"]is_service_account['"]\s*\)|\.claims\s*\?\.\s*get\s*\(\s*['"]is_service_account['"]\s*\)|\.claims\s*\[\s*['"]is_service_account['"]\s*\]|ServiceAccountRepository\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:HydrateSession\s*\(\s*BarebonesSessionContext\b|\.Claims\.TryGetValue\s*\(\s*"is_service_account"|ServiceAccountRepository\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:hydrateSession\s*\(\s*BarebonesSessionContext\b|\.getClaims\s*\(\)\.containsKey\s*\(\s*"is_service_account"\s*\)|\.getClaims\s*\(\)\.get\s*\(\s*"is_service_account"\s*\)|ServiceAccountRepository\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:hydrateSession\s*\(\s*new\s+BarebonesSessionContext\b|\$claims\s*\[\s*['"]is_service_account['"]\s*\]|\$claims->get\s*\(\s*['"]is_service_account['"]\s*\)|ServiceAccountRepository\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:hydrateSession\s*\(\s*new\s+BarebonesSessionContext\b|\.claims\.get\s*\(\s*['"]is_service_account['"]\s*\)|\.claims\s*\?\.\s*get\s*\(\s*['"]is_service_account['"]\s*\)|\.claims\s*\[\s*['"]is_service_account['"]\s*\]|ServiceAccountRepository\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SessionHydrator 
{
    private readonly IServiceAccountRepository _saRepo;
    private readonly IUserRepository _userRepo;

    public HydratedSessionSchema HydrateSession(BarebonesSessionContext context) 
    {
        var hydrated = new HydratedSessionSchema();
        hydrated.SubjectId = context.SubjectId;

        // [1]
        string isServiceAccountClaim = null;
        context.Claims.TryGetValue("is_service_account", out isServiceAccountClaim);

        // [2]
        if (isServiceAccountClaim == "true") 
        {
            // [3]
            var saRecord = _saRepo.FindById(context.SubjectId);
            hydrated.Roles = saRecord.GlobalSystemRoles;
        } 
        else 
        {
            var userRecord = _userRepo.FindBySubjectAndTenant(context.SubjectId, context.TenantId);
            hydrated.Roles = userRecord.TenantRoles;
        }

        return hydrated;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class SessionHydrator {
    private ServiceAccountRepository saRepo;
    private UserRepository userRepo;

    public HydratedSessionSchema hydrateSession(BarebonesSessionContext context) {
        HydratedSessionSchema hydrated = new HydratedSessionSchema();
        hydrated.setSubjectId(context.getSubjectId());

        // [1]
        String isServiceAccountClaim = context.getClaims().get("is_service_account");

        // [2]
        if ("true".equals(isServiceAccountClaim)) {
            // [3]
            ServiceAccount saRecord = saRepo.findById(context.getSubjectId());
            hydrated.setRoles(saRecord.getGlobalSystemRoles());
        } else {
            User userRecord = userRepo.findBySubjectAndTenant(context.getSubjectId(), context.getTenantId());
            hydrated.setRoles(userRecord.getTenantRoles());
        }

        return hydrated;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SessionHydrator 
{
    private $saRepo;
    private $userRepo;

    public function hydrateSession(BarebonesSessionContext $context): HydratedSessionSchema 
    {
        $hydrated = new HydratedSessionSchema();
        $hydrated->subjectId = $context->subjectId;

        // [1]
        $isServiceAccountClaim = $context->claims['is_service_account'] ?? null;

        // [2]
        if ($isServiceAccountClaim === "true") 
        {
            // [3]
            $saRecord = $this->saRepo->findById($context->subjectId);
            $hydrated->roles = $saRecord->globalSystemRoles;
        } 
        else 
        {
            $userRecord = $this->userRepo->findBySubjectAndTenant($context->subjectId, $context->tenantId);
            $hydrated->roles = $userRecord->tenantRoles;
        }

        return $hydrated;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SessionHydrator {
    constructor(saRepo, userRepo) {
        this.saRepo = saRepo;
        this.userRepo = userRepo;
    }

    hydrateSession(context) {
        let hydrated = new HydratedSessionSchema();
        hydrated.subjectId = context.subjectId;

        // [1]
        let isServiceAccountClaim = context.claims["is_service_account"];

        // [2]
        if (isServiceAccountClaim === "true") {
            // [3]
            let saRecord = this.saRepo.findById(context.subjectId);
            hydrated.roles = saRecord.globalSystemRoles;
        } else {
            let userRecord = this.userRepo.findBySubjectAndTenant(context.subjectId, context.tenantId);
            hydrated.roles = userRecord.tenantRoles;
        }

        return hydrated;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The `BarebonesSessionContext` contains a dictionary of claims mapped from the external Identity Provider. The API Gateway blindly mapped all attributes from the SAML/OIDC assertion into this context, assuming custom claims are harmless metadata \[2] The downstream hydration pipeline queries the `is_service_account` string claim. The developers assumed this claim was a structural marker strictly generated by internal token issuers, completely ignoring the trust boundary cross \[3] The routing confusion occurs. The pipeline trusts the attacker's injected claim and routes the query to the `ServiceAccountRepository` instead of the `UserRepository`. Because Service Accounts manage global infrastructure, the repository query does not scope the lookup to the `TenantId`. The attacker's `subject_id` matches an internal service account UUID, granting them global materialized roles

```http
POST /saml/acs HTTP/1.1
Host: gateway.enterprise.tld
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIj8%2B...
(Decoded SAML Assertion)
<saml:AttributeStatement>
    <saml:Attribute Name="is_service_account">
        <saml:AttributeValue>true</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="subject_id">
        <saml:AttributeValue>internal-billing-service-uuid</saml:AttributeValue>
    </saml:Attribute>
</saml:AttributeStatement>
```

```http
GET /api/v1/system/global-configuration HTTP/1.1
Host: downstream.enterprise.tld
X-Forwarded-Session: <barebones-session-token>
```
{% endstep %}

{% step %}
The API Gateway processes the SAML response, generating a valid internal session token that blindly includes the `is_service_account` claim. When the request reaches the downstream microservice, the hydrator reads the claim, triggers the polymorphic routing logic, and accesses the `ServiceAccountRepository`. It queries the `internal-billing-service-uuid`, retrieves the system-level roles, and materializes them into the active memory context. The attacker successfully bypasses tenant isolation and accesses global system endpoints because the hydration pipeline's structural routing mechanism relied on data originating from outside the trust boundary
{% endstep %}
{% endstepper %}

***

#### Security Constraint Erasure via Session Schema Snapshot Upcasting Failure

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
Identify if the application utilizes an Event Sourced architecture. In these systems, the `SessionSchema` is not stored as a single row in a database; rather, it is dynamically calculated by replaying a continuous stream of events (e.g., `UserCreated`, `RoleAssigned`, `MfaEnrolled`)
{% endstep %}

{% step %}
Recognize the "Snapshot" optimization. Replaying thousands of events on every request introduces unacceptable latency. To solve this, the system periodically serializes the aggregated schema into a Snapshot and stores it. Future rehydrations load the latest Snapshot and only replay events appended _after_ the Snapshot's creation
{% endstep %}

{% step %}
Analyze the Snapshot Generation pipeline. As enterprise software evolves, the schema structure changes. Developers implement handlers to translate legacy events (e.g., `ProfileUpdatedV1Event`) into the modern aggregate state during the rehydration phase
{% endstep %}

{% step %}
Review the codebase for legacy API endpoints or background synchronization workers that still accept or emit `v1` payloads
{% endstep %}

{% step %}
Determine what happens when a legacy `v1` event is applied to a modern `v2` session aggregate
{% endstep %}

{% step %}
Specifically, check if the legacy event handler utilizes a generic mapping logic (e.g., deserializing a JSON payload and binding it to the aggregate properties) instead of applying a surgical delta
{% endstep %}

{% step %}
Notice that `v1` payloads inherently lack the security-critical fields introduced in `v2` (e.g., `IsMfaVerified`)
{% endstep %}

{% step %}
Trigger a security constraint in the modern UI (e.g., enroll in MFA, which appends an `MfaEnrolledV2Event` to your stream)
{% endstep %}

{% step %}
Immediately send a profile update payload to the legacy endpoint. The system appends a `ProfileUpdatedV1Event` to your stream
{% endstep %}

{% step %}
Force the system to generate a new Snapshot (e.g., by issuing enough requests to hit the snapshot threshold). The aggregator replays your events. When it hits the `ProfileUpdatedV1Event`, the generic mapping logic overwrites the aggregate state. Because the `v1` payload lacks the `IsMfaVerified` field, the deserializer defaults it to `false`
{% endstep %}

{% step %}
The system writes the corrupted aggregate to the database as the new authoritative Snapshot. Your modern security constraints have been permanently erased from the materialized session

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ApplyV\d+Event\s*\(\s*\w+V\d+Event\b|isMfaVerified\s*=\s*legacyData\b|Legacy\w*Dto\b|AggregateRoot\b[\s\S]{0,300}?\bapply\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:applyV\d+Event\s*\(\s*\w+V\d+Event\b|isMfaVerified\s*=\s*legacyData\b|Legacy\w*Dto\b|extends\s+AggregateRoot\b[\s\S]{0,300}?\bapply\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:applyV\d+Event\s*\(\s*new\s+\w+V\d+Event\b|isMfaVerified\s*=\s*\$legacyData\b|Legacy\w*Dto\b|class\s+\w+\s+extends\s+AggregateRoot\b[\s\S]{0,300}?\bapply\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:applyV\d+Event\s*\(\s*new\s+\w+V\d+Event\b|isMfaVerified\s*=\s*legacyData\b|Legacy\w*Dto\b|extends\s+AggregateRoot\b[\s\S]{0,300}?\bapply\b)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:ApplyV\d+Event\s*\(\s*\w+V\d+Event\b|isMfaVerified\s*=\s*legacyData\b|Legacy\w*Dto\b|AggregateRoot\b.*apply\b)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:applyV\d+Event\s*\(\s*\w+V\d+Event\b|isMfaVerified\s*=\s*legacyData\b|Legacy\w*Dto\b|extends\s+AggregateRoot\b.*apply\b)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:applyV\d+Event\s*\(\s*new\s+\w+V\d+Event\b|isMfaVerified\s*=\s*\$legacyData\b|Legacy\w*Dto\b|class\s+\w+\s+extends\s+AggregateRoot\b.*apply\b)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:applyV\d+Event\s*\(\s*new\s+\w+V\d+Event\b|isMfaVerified\s*=\s*legacyData\b|Legacy\w*Dto\b|extends\s+AggregateRoot\b.*apply\b)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SessionAggregate 
{
    public bool IsMfaVerified { get; set; } // Introduced in V2
    public string ProfileData { get; set; }

    // [1]
    public void ApplyV1Event(ProfileUpdatedV1Event legacyEvent) 
    {
        // [2]
        var legacyData = JsonConvert.DeserializeObject<LegacyProfileDto>(legacyEvent.Payload);
        
        // [3]
        this.ProfileData = legacyData.Profile;
        
        // [4]
        this.IsMfaVerified = legacyData.IsMfaVerified; 
    }

    public void ApplyV2Event(MfaEnrolledV2Event modernEvent) 
    {
        this.IsMfaVerified = true;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class SessionAggregate {
    private boolean isMfaVerified; // Introduced in V2
    private String profileData;

    // [1]
    public void applyV1Event(ProfileUpdatedV1Event legacyEvent) {
        // [2]
        ObjectMapper mapper = new ObjectMapper();
        LegacyProfileDto legacyData = mapper.convertValue(legacyEvent.getPayload(), LegacyProfileDto.class);
        
        // [3]
        this.profileData = legacyData.getProfile();
        
        // [4]
        this.isMfaVerified = legacyData.isMfaVerified(); 
    }

    public void applyV2Event(MfaEnrolledV2Event modernEvent) {
        this.isMfaVerified = true;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SessionAggregate 
{
    public bool $isMfaVerified = false; // Introduced in V2
    public string $profileData = "";

    // [1]
    public function applyV1Event(ProfileUpdatedV1Event $legacyEvent): void 
    {
        // [2]
        $legacyData = json_decode($legacyEvent->payload, true);
        
        // [3]
        $this->profileData = $legacyData['profile'] ?? "";
        
        // [4]
        $this->isMfaVerified = $legacyData['isMfaVerified'] ?? false; 
    }

    public function applyV2Event(MfaEnrolledV2Event $modernEvent): void 
    {
        $this->isMfaVerified = true;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SessionAggregate {
    constructor() {
        this.isMfaVerified = false; // Introduced in V2
        this.profileData = "";
    }

    // [1]
    applyV1Event(legacyEvent) {
        // [2]
        let legacyData = JSON.parse(legacyEvent.payload);
        
        // [3]
        this.profileData = legacyData.profile || "";
        
        // [4]
        this.isMfaVerified = legacyData.isMfaVerified || false; 
    }

    applyV2Event(modernEvent) {
        this.isMfaVerified = true;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The `SessionAggregate` contains event handlers responsible for mutating its internal state based on the historical event stream. It explicitly supports legacy `v1` events to maintain backward compatibility for offline clients or un-migrated mobile apps, \[2] The handler parses the legacy JSON payload into a DTO or dictionary, \[3] The expected business logic applies the profile updates to the aggregate state, \[4] The fatal architectural flaw occurs here. Because `isMfaVerified` did not exist in the `v1` schema, the deserializer resolves it to `false` or `null`. By blindly assigning this default value back into the aggregate state, the event handler permanently overwrites and destroys the legitimate `isMfaVerified = true` state established by earlier `v2` events in the stream

```http
// 1. Establish the modern constraint

POST /api/v2/auth/mfa/enroll HTTP/1.1
Host: app.enterprise.tld
Authorization: Bearer <token>
Content-Type: application/json

{"method": "authenticator", "code": "123456"}
```
{% endstep %}

{% step %}
```http
// 2. Submit a legacy event to poison the aggregate state

POST /api/v1/profile/update HTTP/1.1
Host: app.enterprise.tld
Authorization: Bearer <token>
Content-Type: application/json

{"profile": "attacker_updated"}
```

```http
// 3. Force Snapshot generation (Trigger replay of events)

POST /api/v2/user/ping HTTP/1.1
... (Request repeated until snapshot threshold is met)
```

```http
// 4. Access an MFA-restricted endpoint

GET /api/v2/admin/financials HTTP/1.1
Host: app.enterprise.tld
Authorization: Bearer <token>
```
{% endstep %}

{% step %}
The system successfully enforces MFA and emits the `MfaEnrolledV2Event`, setting `isMfaVerified = true` in memory. The attacker then submits a profile update using the legacy `v1` API. The Event Store securely appends the `ProfileUpdatedV1Event`. To optimize rehydration, the background worker generates a new Snapshot. It creates a new `SessionAggregate` and replays the stream. It applies the `MfaEnrolledV2Event` (MFA becomes true), and then applies the `ProfileUpdatedV1Event`. The legacy handler maps the missing `v1` MFA field as `false` and forcefully overwrites the aggregate's internal state. The worker saves this corrupted aggregate as the new authoritative Snapshot. When the attacker accesses the financial endpoint, the API Gateway loads the latest Snapshot, observes that `isMfaVerified` is `false`, bypasses the MFA constraint logic (assuming the user legally downgraded their security posture), and grants access. The Snapshot optimization silently destroyed the security constraints
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
