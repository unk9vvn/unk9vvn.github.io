# User Registration

## Check List

* [ ] Verify that the identity requirements for user registration are aligned with business and security requirements.
* [ ] Validate the registration process.

## Methodology&#x20;

### Black Box

#### Punycode Email IDN Homograph Attack For Account Takeover

{% stepper %}
{% step %}
Register Normal Account Go to target signup page and create account with normal email like `security@gmail.com` Use Burp Collaborator domain as callback: `security@gmail.com.bcrkly6yl8ke552nzjt7jtu52w8nwdk2.oastify.co` Log in to validate account works, then logout
{% endstep %}

{% step %}
Generate Punycode Email Use Punycode generator (punycoder.com or custom script) to replace domain chars, "`a`" with "`à`" in gmail.com Result: `security@gmàil.com` → `security@xn--gml-hoa.com.bcrkly6yl8ke552nzjt7jtu52w8nwdk2.oastify.com`
{% endstep %}

{% step %}
Intercept Signup with Punycode Turn on Burp interception Attempt signup with Punycode email, intercept request and manually replace email field with Punycode version (browsers auto-encode, so modify manually) Forward request Check response for "Email already exists" (indicates normalization treats both as same, confirming vuln)
{% endstep %}

{% step %}
Trigger Password Reset with Punycode Go to forgot password page Intercept request, enter Punycode email: `security@gmàil.com.bcrkly6yl8ke552nzjt7jtu52w8nwdk2.oastify.com` Forward and monitor Burp Collaborator for <sub>SMTP</sub> callback with reset link
{% endstep %}

{% step %}
Reset and Takeover Copy reset link from Collaborator, open in browser and set new password Logout, then login with original normal email (security@gmail.com) and new password Access confirmed: account hijacked Advanced: Punycode in Username (Local-Part) Repeat steps but modify username part: signup with `ṡecurity@gmail.com` (Punycode: `xn--security-7ca@gmail.com`) Intercept/modify as before For reset, use normal username: `security@gmail.com` If callback received, reset and login with original full email for zero-click takeover Bonus: If 2FA enabled, register Punycode variant, setup attacker's 2FA, then use it to access victim's original email account via normalization flaw
{% endstep %}
{% endstepper %}

***

#### A Punycode Path to Account Takeover

{% stepper %}
{% step %}
Navigate to the target website’s **sign-up** page
{% endstep %}

{% step %}
Register a new account using an email address you control, for example via Burp Collaborator

```html
XYZ@gmail.com.<collaborator-domain>
```
{% endstep %}

{% step %}
Complete the registration process successfully
{% endstep %}

{% step %}
Log out of the account
{% endstep %}

{% step %}
Go to the **Forgot Password** / password reset page
{% endstep %}

{% step %}
Intercept the password reset request using Burp Suite
{% endstep %}

{% step %}
Modify the email domain in the request by replacing the ASCII character with a visually similar Unicode character (IDN homograph), for example

```
@gmail.com
```

to

```
@gmàil.com
```
{% endstep %}

{% step %}
Forward the modified request
{% endstep %}

{% step %}
Observe that the password reset email is sent to the attacker-controlled inbox (Burp Collaborator)
{% endstep %}

{% step %}
Open the password reset link received in the attacker inbox
{% endstep %}

{% step %}
Set a new password for the account
{% endstep %}

{% step %}
Log in using the new password
{% endstep %}

{% step %}
Confirm that full access to the victim account is obtained, resulting in account takeover
{% endstep %}
{% endstepper %}

***

### White Box

#### Privilege Escalation via User-Controlled Role Assignment During Registration

{% stepper %}
{% step %}
Map the entire application using Burp Suite and identify all user registration capabilities (Register, Signup, Create Account, Invite User, Self Registration)
{% endstep %}

{% step %}
Locate the Controller, Route, or Endpoint responsible for account creation in the source code and trace the complete registration flow through user creation

{% tabs %}
{% tab title="C#" %}
```c#
[HttpPost]
[Route("register")]
public IActionResult Register(RegisterRequest request)
{
    var user = new User();

    user.Username = request.Username;
    user.Email = request.Email;
    user.Password = HashPassword(request.Password);

    _context.Users.Add(user);
    _context.SaveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping
@RequestMapping("register")
public Object Register(RegisterRequest request)
{
    User user = new User();

    user.setUsername(request.getUsername());
    user.setEmail(request.getEmail());
    user.setPassword(HashPassword(request.getPassword()));

    _context.getUsers().add(user);
    _context.saveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost]
#[Route("register")]
public function Register(RegisterRequest $request)
{
    $user = new User();

    $user->Username = $request->Username;
    $user->Email = $request->Email;
    $user->Password = HashPassword($request->Password);

    $this->_context->Users->add($user);
    $this->_context->saveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.post("/register", (request, response) => {
    const user = new User();

    user.Username = request.body.Username;
    user.Email = request.body.Email;
    user.Password = HashPassword(request.body.Password);

    _context.Users.add(user);
    _context.saveChanges();

    return Ok();
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In the registration logic, determine whether Role, Group, Permission, Claims, AccessLevel, or IsAdmin values are accepted from user input

{% tabs %}
{% tab title="C#" %}
```c#
[HttpPost]
[Route("register")]
public IActionResult Register(RegisterRequest request)
{
    var user = new User();

    user.Username = request.Username;
    user.Email = request.Email;
    user.Password = HashPassword(request.Password);

    user.Role = request.Role;
    user.IsAdmin = request.IsAdmin;

    _context.Users.Add(user);
    _context.SaveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping
@RequestMapping("register")
public Object Register(RegisterRequest request)
{
    User user = new User();

    user.setUsername(request.getUsername());
    user.setEmail(request.getEmail());
    user.setPassword(HashPassword(request.getPassword()));

    user.setRole(request.getRole());
    user.setAdmin(request.isAdmin());

    _context.getUsers().add(user);
    _context.saveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost]
#[Route("register")]
public function Register(RegisterRequest $request)
{
    $user = new User();

    $user->Username = $request->Username;
    $user->Email = $request->Email;
    $user->Password = HashPassword($request->Password);

    $user->Role = $request->Role;
    $user->IsAdmin = $request->IsAdmin;

    $this->_context->Users->add($user);
    $this->_context->saveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.post("/register", (request, response) => {
    const user = new User();

    user.Username = request.body.Username;
    user.Email = request.body.Email;
    user.Password = HashPassword(request.body.Password);

    user.Role = request.body.Role;
    user.IsAdmin = request.body.IsAdmin;

    _context.Users.add(user);
    _context.saveChanges();

    return Ok();
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the registration models (DTOs, ViewModels, RequestModels) and determine which fields are directly bound from the HTTP request

{% tabs %}
{% tab title="C#" %}
```c#
public class RegisterRequest
{
    public string Username { get; set; }

    public string Email { get; set; }

    public string Password { get; set; }

    public string Role { get; set; }

    public bool IsAdmin { get; set; }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class RegisterRequest
{
    private String username;

    private String email;

    private String password;

    private String role;

    private boolean isAdmin;

    public String getUsername() { return username; }

    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }

    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }

    public void setPassword(String password) { this.password = password; }

    public String getRole() { return role; }

    public void setRole(String role) { this.role = role; }

    public boolean isAdmin() { return isAdmin; }

    public void setAdmin(boolean admin) { isAdmin = admin; }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class RegisterRequest
{
    public string $Username;

    public string $Email;

    public string $Password;

    public string $Role;

    public bool $IsAdmin;
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class RegisterRequest
{
    constructor()
    {
        this.Username = null;
        this.Email = null;
        this.Password = null;
        this.Role = null;
        this.IsAdmin = false;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Continue tracing the processing flow and determine whether Role or Permission values are overwritten with fixed secure values before the user is stored, or whether they are used directly from user input

{% tabs %}
{% tab title="C#" %}
```c#
var user = new User();

user.Username = request.Username;
user.Email = request.Email;
user.Password = HashPassword(request.Password);

user.Role = request.Role;

_context.Users.Add(user);
_context.SaveChanges();
```
{% endtab %}

{% tab title="Java" %}
```java
User user = new User();

user.setUsername(request.getUsername());
user.setEmail(request.getEmail());
user.setPassword(HashPassword(request.getPassword()));

user.setRole(request.getRole());

_context.getUsers().add(user);
_context.saveChanges();
```
{% endtab %}

{% tab title="PHP" %}
```php
$user = new User();

$user->Username = $request->Username;
$user->Email = $request->Email;
$user->Password = HashPassword($request->Password);

$user->Role = $request->Role;

$this->_context->Users->add($user);
$this->_context->saveChanges();
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const user = new User();

user.Username = request.Username;
user.Email = request.Email;
user.Password = HashPassword(request.Password);

user.Role = request.Role;

_context.Users.add(user);
_context.saveChanges();
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
If Invite, Tenant Registration, Organization Registration, or SSO Registration functionality exists, review those paths as well because user-creation logic is commonly duplicated in those areas

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(Register|Signup|CreateAccount|CreateUser|InviteUser|CompleteInvite|TenantRegistration|SSORegistration)|(\[HttpPost\])|(\[Route\s*\(\s*"register)|(RegisterRequest)|(InviteRegisterRequest)|(user\.(Role|IsAdmin|Permission|Permissions|Group|Claims|AccessLevel)\s*=)|(request\.(Role|IsAdmin|Permission|Permissions|Group|Claims|AccessLevel))|(_context\.Users\.Add)|(\.SaveChanges\s*\()|(ClaimTypes\.Role)|(new\s+Claim\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regex
(@PostMapping)|(@RequestMapping)|(@RequestBody)|(register|signup|createUser|createAccount|inviteUser|completeInvite)|(RegisterRequest|SignupRequest)|(setRole\s*\()|(setAdmin\s*\()|(setPermission)|(setAccessLevel)|(request\.getRole\s*\()|(request\.isAdmin\s*\())|(save\s*\()|(saveAndFlush\s*\()|(new\s+SimpleGrantedAuthority)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(register|signup|createuser|createaccount|inviteuser|completeinvite)|(\$_POST)|(\$request->input)|(\$request->get)|(\$request->role)|(\$request->is_admin)|(->role\s*=)|(->permission\s*=)|(->group\s*=)|(->is_admin\s*=)|(->access_level\s*=)|(User::create)|(save\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(router\.post)|(app\.post)|(register|signup|createuser|createaccount|inviteuser|completeinvite)|(req\.body\.(role|isAdmin|permission|permissions|group|claims|accessLevel))|(\.role\s*=)|(\.isAdmin\s*=)|(\.permission\s*=)|(\.accessLevel\s*=)|(User\.create)|(user\.save\s*\()|(jwt\.sign\s*\()|(roles\s*:)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
Register|Signup|CreateAccount|CreateUser|InviteUser|CompleteInvite|TenantRegistration|SSORegistration|\[HttpPost\]|\[Route\s*\(\s*"register|RegisterRequest|InviteRegisterRequest|user\.(Role|IsAdmin|Permission|Permissions|Group|Claims|AccessLevel)\s*=|request\.(Role|IsAdmin|Permission|Permissions|Group|Claims|AccessLevel)|_context\.Users\.Add|\.SaveChanges\s*\(|ClaimTypes\.Role|new\s+Claim\s*\(
```
{% endtab %}

{% tab title="Java" %}
```regex
@PostMapping|@RequestMapping|@RequestBody|register|signup|createUser|createAccount|inviteUser|completeInvite|RegisterRequest|SignupRequest|setRole\s*\(|setAdmin\s*\(|setPermission|setAccessLevel|request\.getRole\s*\(|request\.isAdmin\s*\(|save\s*\(|saveAndFlush\s*\(|new\s+SimpleGrantedAuthority
```
{% endtab %}

{% tab title="PHP" %}
```regex
register|signup|createuser|createaccount|inviteuser|completeinvite|\$_POST|\$request->input|\$request->get|\$request->role|\$request->is_admin|->role\s*=|->permission\s*=|->group\s*=|->is_admin\s*=|->access_level\s*=|User::create|save\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regex
router\.post|app\.post|register|signup|createuser|createaccount|inviteuser|completeinvite|req\.body\.(role|isAdmin|permission|permissions|group|claims|accessLevel)|\.role\s*=|\.isAdmin\s*=|\.permission\s*=|\.accessLevel\s*=|User\.create|user\.save\s*\(|jwt\.sign\s*\(|roles\s*:
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
[HttpPost]
[Route("invite/register")]
public IActionResult CompleteInvite(InviteRegisterRequest request)
{
    var user = new User();

    user.Email = request.Email;
    user.Role = request.Role;

    _context.Users.Add(user);
    _context.SaveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping
@RequestMapping("invite/register")
public Object CompleteInvite(InviteRegisterRequest request)
{
    User user = new User();

    user.setEmail(request.getEmail());
    user.setRole(request.getRole());

    _context.getUsers().add(user);
    _context.saveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
#[HttpPost]
#[Route("invite/register")]
public function CompleteInvite(InviteRegisterRequest $request)
{
    $user = new User();

    $user->Email = $request->Email;
    $user->Role = $request->Role;

    $this->_context->Users->add($user);
    $this->_context->saveChanges();

    return Ok();
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
app.post("/invite/register", (request, response) => {
    const user = new User();

    user.Email = request.body.Email;
    user.Role = request.body.Role;

    _context.Users.add(user);
    _context.saveChanges();

    return Ok();
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Intercept the registration request and add or modify fields such as Role, Permission, Group, Claims, IsAdmin, AccessLevel, and similar values, then determine whether an account is created with elevated privileges
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Find Register Form

#### [Katana ](https://github.com/projectdiscovery/katana)& [cURL](https://curl.se/) & [WayBackURL](https://github.com/tomnomnom/waybackurls)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano smart-register-path.sh
```

```bash
#!/bin/bash

# --- Colors for better output ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

DOMAIN=$1
[ -z "$DOMAIN" ] && { echo -e "${RED}Usage: $0 <domain.com>${NC}"; exit 1; }

# --- Detect protocol based on open ports ---
echo -e "${BLUE}[*] Detecting protocol for $DOMAIN ...${NC}"
HTTP_OPEN=$(timeout 2 bash -c "</dev/tcp/$DOMAIN/80" && echo "open" || echo "")
HTTPS_OPEN=$(timeout 2 bash -c "</dev/tcp/$DOMAIN/443" && echo "open" || echo "")

if [[ -n "$HTTPS_OPEN" ]]; then
  PROTO="https"
elif [[ -n "$HTTP_OPEN" ]]; then
  PROTO="http"
else
  echo -e "${RED}[-] Neither port 80 nor 443 is open on $DOMAIN. Exiting.${NC}"
  exit 1
fi

echo -e "${GREEN}[+] Using protocol: $PROTO://$DOMAIN${NC}"

# --- Setup output directory ---
OUTDIR="/tmp/register_crawl"
mkdir -p "$OUTDIR"
URL="$PROTO://$DOMAIN"

# --- Clean previous files ---
rm -f "$OUTDIR"/*.txt "$OUTDIR"/*.html

# --- Crawl with katana ---
echo -e "${BLUE}[*] Crawling with katana...${NC}"
katana -u "$URL" -d 3 -jsl -fr -silent -o "$OUTDIR/katana.txt"

# --- Check URL history with waybackurls ---
echo -e "${BLUE}[*] Fetching historical URLs with waybackurls...${NC}"
echo "$DOMAIN" | waybackurls >> "$OUTDIR/wayback.txt"

# --- Add common registration paths ---
echo -e "${BLUE}[*] Adding common registration paths...${NC}"
COMMON_PATHS=(
  "/register" "/signup" "/join" "/create-account" "/new-user" 
  "/registration" "/sign-up" "/onboarding" "/account/create"
  "/account/register" "/users/sign_up" "/users/new"
  "/auth/register" "/auth/signup" "/membership" "/subscribe"
  "/free-trial" "/start" "/begin" "/account/new"
)

for path in "${COMMON_PATHS[@]}"; do
  echo "$PROTO://$DOMAIN$path" >> "$OUTDIR/common_paths.txt"
done

# --- Merge and deduplicate URLs ---
echo -e "${BLUE}[*] Merging and deduplicating URLs...${NC}"
if [ -f "$OUTDIR/katana.txt" ]; then cat "$OUTDIR/katana.txt" >> "$OUTDIR/all_raw.txt"; fi
if [ -f "$OUTDIR/wayback.txt" ]; then cat "$OUTDIR/wayback.txt" >> "$OUTDIR/all_raw.txt"; fi
if [ -f "$OUTDIR/common_paths.txt" ]; then cat "$OUTDIR/common_paths.txt" >> "$OUTDIR/all_raw.txt"; fi
cat "$OUTDIR/all_raw.txt" | sort -u > "$OUTDIR/all_unique.txt"

# --- Filter for HTML pages ---
echo -e "${BLUE}[*] Filtering for accessible HTML pages...${NC}"
cat "$OUTDIR/all_unique.txt" | httpx -silent -mc 200,201,202,203,204,301,302 > "$OUTDIR/accessible_urls.txt"

# --- Filter for potential registration-related URLs ---
echo -e "${BLUE}[*] Filtering for potential registration-related URLs...${NC}"
grep -iE 'signup|register|sign[-_]?up|sign[-_]?in|create[_-]?account|join|new[_-]?user|account|login|auth|user|signup|apply|admission|enroll|membership|subscribe|trial|onboard' "$OUTDIR/accessible_urls.txt" | sort -u > "$OUTDIR/register_candidates.txt"

# --- Add homepage to candidates ---
echo "$URL" >> "$OUTDIR/register_candidates.txt"
cat "$OUTDIR/register_candidates.txt" | sort -u > "$OUTDIR/final_candidates.txt"

if [ ! -s "$OUTDIR/final_candidates.txt" ]; then
  echo -e "${RED}[-] No potential registration paths found.${NC}"
  exit 1
fi

echo -e "${GREEN}[+] Candidate URLs for registration forms:${NC}"
cat "$OUTDIR/final_candidates.txt"

# --- Create directory for found forms ---
FORMS_DIR="$OUTDIR/forms"
mkdir -p "$FORMS_DIR"

# --- Function to check if a form is likely a registration form ---
is_registration_form() {
  local form="$1"
  local score=0
  
  # --- Check for registration-related elements ---
  if echo "$form" | grep -qi "register\|signup\|sign up\|create account\|join"; then
    ((score+=3))
  fi
  
  # --- Check for common registration form fields ---
  if echo "$form" | grep -qi "email\|e-mail"; then
    ((score+=2))
  fi
  
  if echo "$form" | grep -qi "password"; then
    ((score+=2))
  fi
  
  if echo "$form" | grep -qi "confirm\|verify\|repeat" && echo "$form" | grep -qi "password"; then
    ((score+=3))
  fi
  
  if echo "$form" | grep -qi "username\|user name\|login\|account"; then
    ((score+=2))
  fi
  
  if echo "$form" | grep -qi "name\|first\|last\|full name"; then
    ((score+=1))
  fi
  
  if echo "$form" | grep -qi "agree\|terms\|policy\|consent"; then
    ((score+=2))
  fi
  
  if echo "$form" | grep -qi "captcha\|recaptcha\|robot"; then
    ((score+=1))
  fi
  
  if echo "$form" | grep -qi "phone\|mobile\|sms\|verification"; then
    ((score+=1))
  fi
  
  if echo "$form" | grep -qi "submit\|register\|signup\|join\|create\|continue"; then
    ((score+=1))
  fi
  
  # --- If score is above 5, it's likely a registration form ---
  if [ $score -ge 5 ]; then
    return 0
  else
    return 1
  fi
}

# --- Check each URL for registration forms ---
echo -e "${BLUE}[*] Checking URLs for registration forms...${NC}"
FOUND_FORMS=0

while read -r url; do
  echo -e "${YELLOW}[~] Checking: $url${NC}"
  html=$(curl -Lks "$url")
  
  # --- Use more patterns to find forms ---
  if [ -z "$html" ]; then
    echo -e "${RED}  [-] Failed to fetch content${NC}"
    continue
  fi
  
  # --- Save complete page HTML ---
  echo "$html" > "$FORMS_DIR/$(echo "$url" | md5sum | cut -d' ' -f1).html"
  
  # --- Check POST forms ---
  echo "$html" | grep -i -o '<form[^>]*method="post"[^>]*>.*</form>' -s | while read -r form; do
    if is_registration_form "$form"; then
      ((FOUND_FORMS++))
      FORM_FILE="$FORMS_DIR/register_form_${FOUND_FORMS}.html"
      echo "$form" > "$FORM_FILE"
      
      echo -e "\n${GREEN}[✔] Found potential registration form at: $url${NC}"
      echo -e "${BLUE}[*] Form input fields found:${NC}"
      
      # --- Extract form fields using grep (for better compatibility) ---
      echo "$form" | grep -o '<input[^>]*>' | grep 'name=' | sed 's/^.*name="\([^"]*\)".*$/- \1/' | sort -u
      
      echo -e "${GREEN}[+] Saved form HTML to: $FORM_FILE${NC}"
    fi
  done
  
  # --- Check for JavaScript-based forms ---
  if echo "$html" | grep -q "sign[Uu]p\|register\|createAccount" && echo "$html" | grep -q "function\|addEventListener\|onSubmit"; then
    echo -e "\n${YELLOW}[!] Detected potential JavaScript-based registration form at: $url${NC}"
    echo -e "${YELLOW}[!] JavaScript forms may need manual inspection${NC}"
  fi
  
done < "$OUTDIR/final_candidates.txt"

# --- Final results ---
if [ $FOUND_FORMS -gt 0 ]; then
  echo -e "\n${GREEN}[+] Found $FOUND_FORMS potential registration forms.${NC}"
  echo -e "${GREEN}[+] All forms saved to: $FORMS_DIR${NC}"
else
  echo -e "\n${RED}[-] No registration forms found.${NC}"
  
  # --- Suggestions for manual checks ---
  echo -e "${YELLOW}[!] Suggestions for manual investigation:${NC}"
  echo -e "${YELLOW}[!] 1. Check for JavaScript-based forms${NC}"
  echo -e "${YELLOW}[!] 2. Look for hidden registration links${NC}"
  echo -e "${YELLOW}[!] 3. Check if registration requires redirects to third-party services${NC}"
fi

# --- More information about results ---
echo -e "\n${BLUE}[*] Summary:${NC}"
echo -e "${BLUE}[*] Checked URLs: $(wc -l < "$OUTDIR/final_candidates.txt")${NC}"
echo -e "${BLUE}[*] Found forms: $FOUND_FORMS${NC}"
echo -e "${BLUE}[*] All results saved to: $OUTDIR${NC}"

exit 0
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x smart-register-path.sh;sudo ./smart-register-path.sh $WEBSITE
```
