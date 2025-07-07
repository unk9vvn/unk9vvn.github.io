# Weak Username Policy

## Check List

* [ ] _Determine whether a consistent account name structure renders the application vulnerable to account enumeration._
* [ ] _Determine whether the application’s error messages permit account enumeration._

## Cheat Sheet

### Status Code

#### [FFUF](https://github.com/ffuf/ffuf)

_Create Script_

```bash
sudo nano sc-weak-username.sh
```

```bash
#!/bin/bash

# Usage check
if [ $# -lt 2 ]; then
    echo "Usage: $0 <domain.com/login> <userlist.txt>"
    exit 1
fi

URL="$1"
USERLIST="$2"

# Use a fake password for testing
FAKE_PASS="WrongPassword123!"

# Fetch the login page HTML
HTML=$(curl -s "$URL")

# Extract the first form block
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p')

# Extract the form action attribute (defaults to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="/"

# Extract the form method (defaults to GET)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="get"

# Build the full action URL
if [[ "$ACTION" == /* ]]; then
  BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
  FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
  FULL_ACTION="$ACTION"
else
  BASE_URL=$(echo "$URL" | sed 's|\(https\?://.*/\).*|\1|')
  FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username input field name
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"

# Extract password input field name (optional)
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# Extract CSRF token or nonce if present
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
  CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Build POST/GET data with placeholders
DATA="${USERNAME_FIELD}=FUZZ&${PASSWORD_FIELD}=${FAKE_PASS}"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract cookies if any
COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I')

# Prepare common headers
HEADERS=(-H "Content-Type: application/x-www-form-urlencoded" -H "User-Agent: WeakEnumBot/1.0")
[ -n "$COOKIES" ] && HEADERS+=(-H "Cookie: $COOKIES")

# Run ffuf for username fuzzing
if [[ "$METHOD" == "get" ]]; then
  FFUF_URL="${FULL_ACTION}?${DATA}"
  ffuf -u "$FFUF_URL" \
       -w "$USERLIST:FUZZ" \
       -X GET \
       -ac -c -r \
       -mc 200 \
       -fr "invalid username|user not found|login failed|unauthorized|نام کاربری وجود ندارد" \
       "${HEADERS[@]}"
else
  ffuf -u "$FULL_ACTION" \
       -w "$USERLIST:FUZZ" \
       -X POST \
       -d "$DATA" \
       -ac -c -r \
       -mc 200 \
       -fr "invalid username|user not found|login failed|unauthorized|نام کاربری وجود ندارد" \
       "${HEADERS[@]}"
fi
```

_Run Script_

```bash
sudo chmod +x sc-user-enum.sh;sudo ./sc-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```
