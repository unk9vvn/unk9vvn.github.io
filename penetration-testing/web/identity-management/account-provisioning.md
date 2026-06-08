# Account Provisioning

## Check List

* [ ] Verify which accounts may provision other accounts and of what type.

## Methodology&#x20;

### Black Box

#### Account Provisioning

{% stepper %}
{% step %}
Prepare target URL and optional Auth cookie
{% endstep %}

{% step %}
Identify routes and endpoints using scripts written, combine and deduplicate Katana and FFUF outputs into one file (`/tmp/all_endpoints.txt`)
{% endstep %}

{% step %}
CSRF testing with XSRFProbe: for each endpoint run XSRFProbe (use `-c` if cookie is provided) with `--random-agent --malicious --crawl`. XSRFProbe attempts to detect CSRF vulnerabilities and, if successful, generates a PoC and an HTML report
{% endstep %}
{% endstepper %}

***

### White Box

#### Identity Provisioning Attribute Mapping

{% stepper %}
{% step %}
Map the entire system using Burp Suite and identify all functionalities related to **Provisioning, Create User, Sync User, Import User, SCIM, LDAP Sync, SSO Provisioning, Azure AD Provisioning, and User Management**
{% endstep %}

{% step %}
Locate the Controller, Service, or Job responsible for automatic user creation in the source code and trace the full user creation flow from data input to database storage

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost]
[Route("scim/v2/Users")]
public IActionResult CreateUser([FromBody] ScimUserRequest request)
{
    var user = new User
    {
        Username = request.UserName,
        Email = request.Emails.FirstOrDefault()?.Value,
        FirstName = request.Name?.GivenName,
        LastName = request.Name?.FamilyName
    };

    _context.Users.Add(user);
    _context.SaveChanges();

    return Ok(user);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping
@RequestMapping("scim/v2/Users")
public Object CreateUser(@RequestBody ScimUserRequest request)
{
    User user = new User();
    user.setUsername(request.getUserName());
    user.setEmail(request.getEmails().stream().findFirst().map(e -> e.getValue()).orElse(null));
    user.setFirstName(request.getName() != null ? request.getName().getGivenName() : null);
    user.setLastName(request.getName() != null ? request.getName().getFamilyName() : null);

    _context.getUsers().add(user);
    _context.saveChanges();

    return Ok(user);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost]
#[Route("scim/v2/Users")]
public function CreateUser(ScimUserRequest $request)
{
    $user = new User();
    $user->Username = $request->UserName;
    $user->Email = $request->Emails[0]->Value;
    $user->FirstName = $request->Name?->GivenName;
    $user->LastName = $request->Name?->FamilyName;

    $this->_context->Users->add($user);
    $this->_context->saveChanges();

    return Ok($user);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.post("/scim/v2/Users", (request, response) => {
    const user = new User();

    user.Username = request.body.UserName;
    user.Email = request.body.Emails?.[0]?.Value;
    user.FirstName = request.body.Name?.GivenName;
    user.LastName = request.body.Name?.FamilyName;

    _context.Users.add(user);
    _context.saveChanges();

    return Ok(user);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review provisioning input models and determine which fields are directly received from external providers (SCIM, SSO, LDAP, Azure AD, Okta, etc.)

{% tabs %}
{% tab title="C#" %}
```csharp
public class ScimUserRequest
{
    public string UserName { get; set; }

    public bool Active { get; set; }

    public string ExternalId { get; set; }

    public List<string> Roles { get; set; }

    public List<GroupDto> Groups { get; set; }

    public EnterpriseUser EnterpriseUser { get; set; }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class ScimUserRequest
{
    private String userName;
    private boolean active;
    private String externalId;
    private List<String> roles;
    private List<GroupDto> groups;
    private EnterpriseUser enterpriseUser;

    // getters/setters
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ScimUserRequest
{
    public string $UserName;

    public bool $Active;

    public string $ExternalId;

    public array $Roles;

    public array $Groups;

    public EnterpriseUser $EnterpriseUser;
}

```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ScimUserRequest
{
    constructor()
    {
        this.UserName = null;
        this.Active = false;
        this.ExternalId = null;
        this.Roles = [];
        this.Groups = [];
        this.EnterpriseUser = null;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Determine whether Role, Group, Permission, Department, Manager, Tenant, Organization, or other security attributes are directly assigned from incoming data

{% tabs %}
{% tab title="C#" %}
```csharp
var user = new User
{
    Username = request.UserName,
    Email = request.Email,
    Role = request.Roles.FirstOrDefault(),
    Department = request.Department,
    TenantId = request.TenantId,
    IsAdmin = request.IsAdmin
};

_context.Users.Add(user);
_context.SaveChanges();
```
{% endtab %}

{% tab title="Java" %}
```java
User user = new User();

user.setUsername(request.getUserName());
user.setEmail(request.getEmail());
user.setRole(request.getRoles().stream().findFirst().orElse(null));
user.setDepartment(request.getDepartment());
user.setTenantId(request.getTenantId());
user.setAdmin(request.isAdmin());

_context.getUsers().add(user);
_context.saveChanges();
```
{% endtab %}

{% tab title="PHP" %}
```php
$user = new User();
$user->Username = $request->UserName;
$user->Email = $request->Email;
$user->Role = $request->Roles[0];
$user->Department = $request->Department;
$user->TenantId = $request->TenantId;
$user->IsAdmin = $request->IsAdmin;

$this->_context->Users->add($user);
$this->_context->saveChanges();
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const user = new User();

user.Username = request.body.UserName;
user.Email = request.body.Email;
user.Role = request.body.Roles?.[0];
user.Department = request.body.Department;
user.TenantId = request.body.TenantId;
user.IsAdmin = request.body.IsAdmin;

_context.Users.add(user);
_context.saveChanges();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the mapping logic between external identity provider data and internal user accounts and determine whether validation is performed on Role, Group, or privilege level

{% tabs %}
{% tab title="C#" %}
```csharp
foreach (var role in request.Roles)
{
    user.Roles.Add(new UserRole
    {
        Name = role
    });
}

_context.SaveChanges();
```
{% endtab %}

{% tab title="Java" %}
```java
for (String role : request.getRoles())
{
    user.getRoles().add(new UserRole(role));
}

_context.saveChanges();
```
{% endtab %}

{% tab title="PHP" %}
```php
foreach ($request->Roles as $role)
{
    $user->Roles[] = new UserRole([
        "Name" => $role
    ]);
}

$this->_context->saveChanges();
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
for (const role of request.body.Roles)
{
    user.Roles.push({ Name: role });
}

_context.saveChanges();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In provisioning flows, verify whether trusted identifiers such as Email, UPN, ExternalId, ObjectId, or EmployeeId are used without validation to link users to existing accounts

{% tabs %}
{% tab title="C#" %}
```csharp
var user = _context.Users
    .FirstOrDefault(x => x.Email == request.Email);

if (user == null)
{
    user = new User();
}

user.Email = request.Email;
user.Role = request.Role;

_context.SaveChanges();
```
{% endtab %}

{% tab title="Java" %}
```java
User user = _context.getUsers()
    .stream()
    .filter(x -> x.getEmail().equals(request.getEmail()))
    .findFirst()
    .orElse(null);

if (user == null)
{
    user = new User();
}

user.setEmail(request.getEmail());
user.setRole(request.getRole());

_context.saveChanges();
```
{% endtab %}

{% tab title="PHP" %}
```php
$user = $this->_context->Users
    ->where(fn($x) => $x->Email == $request->Email)
    ->first();

if ($user == null)
{
    $user = new User();
}

$user->Email = $request->Email;
$user->Role = $request->Role;

$this->_context->saveChanges();
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
let user = _context.Users.find(x => x.Email === request.body.Email);

if (!user)
{
    user = new User();
}

user.Email = request.body.Email;
user.Role = request.body.Role;

_context.saveChanges();

```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
If synchronization or auto-provisioning exists, also analyze the update logic for existing users, as many provisioning vulnerabilities occur during account updates

{% tabs %}
{% tab title="C#" %}
```csharp
var user = _context.Users
    .FirstOrDefault(x => x.ExternalId == request.ExternalId);

user.Role = request.Role;
user.Groups = request.Groups;
user.IsAdmin = request.IsAdmin;

_context.SaveChanges();
```
{% endtab %}

{% tab title="Java" %}
```java
User user = _context.getUsers()
    .stream()
    .filter(x -> x.getExternalId().equals(request.getExternalId()))
    .findFirst()
    .orElse(null);

user.setRole(request.getRole());
user.setGroups(request.getGroups());
user.setAdmin(request.isAdmin());

_context.saveChanges();
```
{% endtab %}

{% tab title="PHP" %}
```php
$user = $this->_context->Users
    ->where(fn($x) => $x->ExternalId == $request->ExternalId)
    ->first();

$user->Role = $request->Role;
$user->Groups = $request->Groups;
$user->IsAdmin = $request->IsAdmin;

$this->_context->saveChanges();
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
let user = _context.Users.find(x => x.ExternalId === request.body.ExternalId);

user.Role = request.body.Role;
user.Groups = request.body.Groups;
user.IsAdmin = request.body.IsAdmin;

_context.saveChanges();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Intercept provisioning requests and modify values such as Role, Group, Permission, Tenant, Organization, Department, Manager, ExternalId, Email, and other security-sensitive fields, then determine whether it is possible to create or update accounts with elevated privileges
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Manual Create CSRF

#### [XSRFProbe](https://github.com/0xInfection/XSRFProbe)

{% hint style="info" %}
Non-Authenticated Endpoint
{% endhint %}

```bash
xsrfprobe -u https://$WEBSITE/profile/update -v
```

{% hint style="info" %}
Authenticated Endpoint
{% endhint %}

```bash
xsrfprobe -u https://$WEBSITE/profile/update -v -c "$COOKIE"
```

#### CSRFShark

{% embed url="https://csrfshark.github.io/app/" %}

### Auto Create CSRF

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF ](https://github.com/ffuf/ffuf)& [XSRFprobe](https://github.com/0xInfection/XSRFProbe)

{% hint style="info" %}
Create Script
{% endhint %}

<pre class="language-bash"><code class="lang-bash"><strong>#!/bin/bash
</strong>
WEBSITE=$1
COOKIE=$2

if [ -z "$WEBSITE" ]; then
    echo "Usage: $0 https://example.com [cookie]"
    exit 1
fi

echo "[*] Running katana for passive endpoint discovery..."
katana -u "$WEBSITE" -jc -d 2 -o /tmp/katana_raw.txt

echo "[*] Running ffuf for fuzzing endpoint parameters..."
ffuf -u "$WEBSITE/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -of csv -o /tmp/ffuf_results.csv > /dev/null

cut -d ',' -f1 /tmp/ffuf_results.csv | grep "$WEBSITE" > /tmp/ffuf_raw.txt

cat /tmp/katana_raw.txt /tmp/ffuf_raw.txt | sort -u > /tmp/all_endpoints.txt

echo "[*] Checking endpoints for CSRF using xsrfprobe..."

mkdir -p /tmp/results
> /tmp/results/vulnerable_csrf.txt

while read endpoint; do
    echo "[*] Testing: $endpoint"

    if [ -n "$COOKIE" ]; then
        xsrfprobe -u "$endpoint" -c "$COOKIE" --random-agent --malicious --crawl -o /tmp/results/report.html
    else
        xsrfprobe -u "$endpoint" --random-agent --malicious --crawl -o /tmp/results/report.html
    fi

    if grep -q "PoC generated" /tmp/results/report.html; then
        echo "[+] Potential CSRF at: $endpoint"
        echo "$endpoint" >> /tmp/results/vulnerable_csrf.txt
    else
        echo "[-] Not vulnerable: $endpoint"
    fi
done &#x3C; /tmp/all_endpoints.txt

echo
echo "✅ CSRF Scan Complete."
echo "📄 Vulnerable endpoints saved in: /tmp/results/vulnerable_csrf.txt"
</code></pre>

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo nano csrf-hunter.sh;sudo ./csrf-hunter.sh $WEBSITE
```
