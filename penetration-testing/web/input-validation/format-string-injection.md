# Format String Injection

## Check List

## Methodology

### Black Box

#### Format string attack

{% stepper %}
{% step %}
Navigate to the target web application and identify an input parameter that is user-controllable, Normal request

```http
GET /userinfo?username=unk9vvn HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Using Burp Suite, intercept the request and check whether the value of the username parameter is processed on the server side, Inject a payload containing Conversion Specifiers into the username parameter

```perl
%s%s%s%n
```
{% endstep %}

{% step %}
Injected request

```http
GET /userinfo?username=%25s%25s%25s%25n HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Send the request and observe the server response to determine whether the application crashes or displays unexpected output, If needed, inject another payload containing different Conversion Specifiers

```perl
%p%p%p%p%p
```
{% endstep %}

{% step %}
Injected request

```http
GET /userinfo?username=%25p%25p%25p%25p%25p HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Then observe the server response to determine whether an error such as HTTP 500 or a timeout occurs, If the application crashes or displays unexpected output, the vulnerability is confirmed
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
