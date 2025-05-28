# Role Definitions

## Check List

* [ ] _Identify and document roles used by the application._
* [ ] _Attempt to switch, change, or access another role._
* [ ] _Review the granularity of the roles and the needs behind the permissions given._

## Cheat Sheet

### Roles Identification

#### [FFUF](https://github.com/ffuf/ffuf)

#### Hidden Directories

_Create Script_

```bash
sudo nano hidden-dir-files.sh
```

```bash
#!/bin/bash
​
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <WEBSITE>"
    exit 1
fi
​
WEBSITE="$1"
​
# Validate URL format
if ! [[ "$WEBSITE" =~ ^https?:// ]]; then
    echo "Error: WEBSITE must start with http:// or https://"
    exit 1
fi
​
# Create temporary files
COOKIE_FILE=$(mktemp)
​
# Cleanup function
cleanup()
{
    rm -f "$COOKIE_FILE"
}
trap cleanup EXIT
​
# User-Agent and headers
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
HEADERS=(
    "User-Agent: $USER_AGENT"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    "Accept-Language: en-US,fa-IR;q=0.5"
    "Accept-Encoding: gzip, deflate, br, zstd"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: document"
    "Sec-Fetch-Mode: navigate"
    "Sec-Fetch-Site: cross-site"
    "DNT: 1"
    "Sec-GPC: 1"
    "Priority: u=0, i"
    "Te: trailers"
)
​
# Extract cookies
COOKIES=$(curl -s -I "$WEBSITE" | awk 'BEGIN {IGNORECASE=1} /^set-cookie:/ {print substr($0, 13)}' | awk -F';' '{print $1}' | tr '\n' '; ' | sed 's/; $//')
​
# Append cookies if available
if [[ -n "$COOKIES" ]]; then
    HEADERS+=("Cookie: $COOKIES")
fi
​
# Convert headers into ffuf parameters
HEADER_PARAMS=()
for HEADER in "${HEADERS[@]}"; do
    HEADER_PARAMS+=("-H" "$HEADER")
done

echo "[+] Scanning directories on $WEBSITE"
ffuf -u "$WEBSITE/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt \
     -c -mc 200 \
     -o /tmp/dirs.txt -of json \
     "${HEADER_PARAMS[@]}"

echo "[+] Extracting found directories"
DIRS=$(jq -r '.results[].input.FUZZ' dirs.txt)

for dir in $DIRS; do
    echo "[+] Scanning files in $dir"
    ffuf -u "$WEBSITE/$dir/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt \
    -c -mc 200 \
    "${HEADER_PARAMS[@]}"
done
```

_Run Script_

```bash
sudo chmod +x hidden-dir-files.sh;sudo ./hidden-dir-files.sh $WEBSITE
```

#### Cookie and Account

_Create Script_

```bash
sudo nano cookie-account-identify.sh
```

```bash
#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <WEBSITE>"
    exit 1
fi

WEBSITE="$1"

# Validate URL format
if ! [[ "$WEBSITE" =~ ^https?:// ]]; then
    echo "Error: WEBSITE must start with http:// or https://"
    exit 1
fi

# Create temporary files
COOKIE_FILE=$(mktemp)

# Cleanup function
cleanup()
{
    /usr/bin/rm -f "$COOKIE_FILE"
}
trap cleanup EXIT

# User-Agent and headers
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
HEADERS=(
    "User-Agent: $USER_AGENT"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    "Accept-Language: en-US,fa-IR;q=0.5"
    "Accept-Encoding: gzip, deflate, br, zstd"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: document"
    "Sec-Fetch-Mode: navigate"
    "Sec-Fetch-Site: cross-site"
    "DNT: 1"
    "Sec-GPC: 1"
    "Priority: u=0, i"
    "Te: trailers"
)

# Extract cookies
COOKIES=$(curl -s -I "$WEBSITE" | awk 'BEGIN {IGNORECASE=1} /^set-cookie:/ {print substr($0, 13)}' | awk -F';' '{print $1}' | tr '\n' '; ' | sed 's/; $//')

# Function to analyze cookies for sensitive parameters
analyze_cookies()
{
    local COOKIE_PARAMS=($(echo "$COOKIES" | tr ';' '\n' | awk -F'=' '{print $1}'))
    local SENSITIVE_KEYWORDS=("admin" "role" "user" "privilege" "access" "auth" "session" "token" "isAdmin")
    
    for PARAM in "${COOKIE_PARAMS[@]}"; do
        for KEYWORD in "${SENSITIVE_KEYWORDS[@]}"; do
            if [[ "$PARAM" =~ $KEYWORD ]]; then
                echo "Potentially sensitive cookie parameter detected: $PARAM"
            fi
        done
    done
}

# Run cookie analysis
if [[ -n "$COOKIES" ]]; then
    HEADERS+=("Cookie: $COOKIES")
    analyze_cookies
fi

# Convert headers into ffuf parameters
HEADER_PARAMS=()
for HEADER in "${HEADERS[@]}"; do
    HEADER_PARAMS+=("-H" "$HEADER")
done

# Common user enumeration paths for CMS
CMS_USER_PATHS=(
    "author/FUZZ"  # WordPress
    "user/FUZZ"    # Drupal
)

# Check if paths exist before running ffuf
for PATH in "${CMS_USER_PATHS[@]}"; do
    STATUS_CODE=$(curl -o /dev/null -s -w "%{http_code}" "$WEBSITE/$PATH")
    if [[ "$STATUS_CODE" == "200" ]]; then
        echo "Path exists: $WEBSITE/$PATH - Running ffuf"
        ffuf -w /usr/share/seclists/Usernames/Names/names.txt \
             -u "$WEBSITE/$PATH/FUZZ" \
             -c -mc 200 \
             "${HEADER_PARAMS[@]}"
    else
        echo "Skipping $WEBSITE/$PATH - Not Found"
    fi
    sleep 1 # Prevent too many requests in a short time
done
```

_Run Script_

```bash
sudo chmod +x cookie-account-identify.sh;sudo ./cookie-account-identify.sh $WEBSITE
```
