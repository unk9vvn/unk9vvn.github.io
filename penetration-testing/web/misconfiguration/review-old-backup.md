# Review Old Backup

## Check List

* [ ] Find and analyze unreferenced files that might contain sensitive information.

## Cheat Sheet

### Methodology

#### Sensitive Backup/File Disclosure Via Directory Enumeration And Brute-Forcing&#x20;

{% stepper %}
{% step %}
Using the first commands related to <sub>Google Dork,</sub> we replace <sub>$WEBSITE</sub> with the target domain name and then execute it
{% endstep %}

{% step %}
Then, using the `X8` command and subsequent commands, we execute hidden parameters that contain old and sensitive files on the target
{% endstep %}

{% step %}
Then, we run the following commands on the target using <sub>Gobuster</sub> and <sub>FFUF</sub> tools and a combination of tools such as <sub>FFUF</sub> and <sub>Katana</sub> to identify all sensitive paths and sensitive files on the target
{% endstep %}

{% step %}
Then, we can use the script we created to run all these tools with one click on the target using their switches that speed up the work. If old files are backed up and saved, which the programmer may not have deleted, and contain important information such as web server configuration and admin password and username, they will be found and cause vulnerability
{% endstep %}
{% endstepper %}

***

### Use of Publicly Available Information

#### [Google](https://google.com)

{% hint style="info" %}
Backup File Extension
{% endhint %}

```bash
ext:bak | 
ext:bck | 
ext:bac | 
ext:old | 
ext:tmp | 
ext:bkp | 
ext:bak | 
ext:old | 
ext:sql | 
ext:backup | 
ext:tar | 
ext:daf 
site:$WEBSITE
```

{% hint style="info" %}
Backup File Names
{% endhint %}

```bash
intitle:"index of" | 
"manifest.xml" | 
"travis.yml" | 
"vim_settings.xml" | 
"database" | 
"prod.env" | 
"prod.secret.exs" | 
".npmrc_auth" | 
".dockercfg" | 
"WebServers.xml" | 
"back.sql" | 
"backup.sql" | 
"accounts.sql" | 
"backups.sql" | 
"clients.sql" | 
"data.sql" | 
"database.sql" | 
"database.sqlite" | 
"users.sql" | 
"db.sql" | 
"db.sqlite" | 
"db.backup.sql" | 
"dbase.sql" | 
"db.dump.sql" | 
"dump.sql" | 
"mysql.sql" | 
"bash_history" | 
"sftp-config.json" | 
"sftp.json" | 
"secrets.yml" | 
".esmtprc" | 
"passwd" | 
"LocalSettings.php" | 
"config.php" | 
"config.inc.php" | 
"prod.secret.exs" | 
"configuration.php" | 
".sh_history" | 
"shadow" | 
"proftpdpasswd" | 
"pgpass" | 
"idea14.key" | 
"hub" | 
".bash_profile" | 
".env" | 
"wp-config.php" | 
"credentials" | 
"id_rsa" | 
"id_dsa" | 
".ovpn" | 
".cscfg" | 
".rdp" | 
".mdf" | 
".sdf" | 
".sqlite" | 
".psafe3" | 
"secret_token.rb" | 
"carrierwave.rb" | 
"database.yml" | 
".keychain" | 
".kwallet" | 
".exports" | 
"config.yaml" | 
"settings.py" | 
"credentials.xml" 
site:$WEBSITE
```

#### [x8](https://github.com/Sh1Yo/x8)

{% hint style="info" %}
Find Hidden Parameters
{% endhint %}

```bash
x8 --url $WEBSITE \
   -X GET POST \
   -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

#### [Arjun](https://github.com/s0md3v/Arjun)

```bash
arjun -u $WEBSITE/endpoint.php \
      -m GET,POST,HEAD,PUT \
      -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
      --headers 'User-Agent: Mozilla/5.0'
```

### Blind Guessing

#### [Gobuster](https://github.com/OJ/gobuster)

{% hint style="info" %}
Backup Ext Fuzz
{% endhint %}

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
             -x old,bak,bck,bac,tmp,bkp,bak,old,backup,daf,tar,tar.gz \
             -u $WEBSITE
```

#### [DirSearch](https://github.com/maurosoria/dirsearch)

{% hint style="info" %}
Backup Ext Fuzz
{% endhint %}

```bash
dirsearch -u $WEBSITE \
          -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json \
          --deep-recursive \
          --force-recursive \
          --exclude-sizes=0B \
          --random-agent \
          --full-url
```

#### [Katana](https://github.com/projectdiscovery/katana) & [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano backup-smart-fuzzer.sh
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

# Cleanup function
cleanup()
{
    rm -f "$KATANA_OUTPUT" "$URLS_FILE" "$COOKIE_FILE"
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
sed -E 's/\?.*//; s/\.aspx$//; s/\/[^/]+\.json$//' "$KATANA_OUTPUT" | grep -Ev '\.js$|&amp' | sort -u > "$URLS_FILE"

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

# Extract cookies
COOKIES=$(curl -s -I "$WEBSITE" | awk 'BEGIN {IGNORECASE=1} /^set-cookie:/ {print substr($0, 13)}' | awk -F';' '{print $1}' | tr '\n' '; ' | sed 's/; $//')

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
ffuf -w "$URLS_FILE":URL \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -e .json,.xml,.bak,.sql,.zip,.log,.config,.env,old,bak,bck,bac,tmp,bkp,bak,old,backup,daf,tar,tar.gz \
     -u URL/DIR \
     -recursion \
     -recursion-depth 2 \
     -r -s -c -mc 200,301,302 \
     "${HEADER_PARAMS[@]}"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x backup-fuzzer.sh;sudo ./backup-fuzzer.sh $WEBSITE
```
