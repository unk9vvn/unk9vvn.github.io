# Enumerate Admin Interfaces

## Check List

* [ ] _Identify hidden administrator interfaces and functionality._

## Cheat Sheet

### Search Engine Discovery

#### robots.txt

```bash
curl $WEBSITE/robots.txt
```

#### [Google](https://www.google.com)

<pre class="language-bash"><code class="lang-bash">inurl:admin |
inurl:adminstrator |
inurl:admin-panel |
inurl:admin-dashboard |
inurl:wp-admin |
inurl:phpmyadmin |
inurl:dbadmin |
inurl:controlpanel |
inurl:adminpanel |
inurl:login |
intitle:admin |
intitle:login
<strong>site:$WEBSITE
</strong></code></pre>

#### [Censys](https://search.censys.io/)

```bash
services.http.response.body:"admin" OR
services.http.response.body:"adminstrator" OR
services.http.response.body:"admin-panel" OR
services.http.response.body:"admin-dashboard" OR
services.http.response.body:"wp-admin" OR
services.http.response.body:"phpmyadmin" OR
services.http.response.body:"dbadmin" OR
services.http.response.body:"controlpanel" OR
services.http.response.body:"adminpanel" OR
services.http.response.body:"login"
$WEBSITE
```

### Port Scan

#### [Nmap](https://nmap.org/download.html)

```bash
nmap -p0-10000 \
     -sS \
     -sV \
     --mtu 5000 \
     --script http-enum,http-frontpage-login \
     $WEBSITE
```

### Subdomain Fuzzing

#### [DNSEnum](https://github.com/fwaeytens/dnsenum)

```bash
dnsenum $WEBSITE \
        -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

#### [Gobuster](https://github.com/OJ/gobuster)

```bash
gobuster dns \
         --wildcard \
         -d $WEBSITE \
         -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

### Directory Fuzzing

#### [Nuclei](https://github.com/projectdiscovery/nuclei)

```bash
nuclei -u $WEBSITE -tags panel login
```

#### [Gobuster](https://github.com/OJ/gobuster)

```bash
gobuster dir -u $WEBSITE \
             -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

#### [FFUF](https://github.com/ffuf/ffuf)

```bash
ffuf -u $WEBSITE/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
     -r -c -mc 200
```

#### [URLFinder](https://github.com/projectdiscovery/urlfinder)

```bash
urlfinder -d $WEBSITE
```

#### [waybackurls](https://github.com/tomnomnom/waybackurls)

```bash
waybackurls $WEBSITE
```

### Comment and Links

#### [Katana](https://github.com/projectdiscovery/katana)

_Extract URLs_

```bash
katana -u $WEBSITE \
  -fr "(static|assets|img|images|css|fonts|icons)/" \
  -o /tmp/katana_output.txt \
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

cat /tmp/katana_output.txt | \
sed 's/\?.*//g' | \
sed 's/\.aspx$//' | \
sed 's/\/[^/]*\.json$//' | \
grep -v '\.js$' | \
grep -v '&amp' | \
sort -u > /tmp/urls.txt
```

_Create Script_

```bash
sudo nano fuzz-login.sh
```

```bash
#!/bin/bash

# Path to the sensitive words list
SENSITIVE_WORDS="/usr/share/seclists/Discovery/Web-Content/Logins.fuzz.txt"

# Path to the URLs file
URLS_FILE="/tmp/urls.txt"

# Iterate through each sensitive word
while read -r word; do
    # Search for the word in the URLs file (case-insensitive)
    matches=$(grep -i "$word" "$URLS_FILE")
    
    # If matches are found, print the sensitive word and matched URLs
    if [[ ! -z "$matches" ]]; then
        echo "Sensitive word found: $word"
        echo "$matches"
        echo "--------------------"
    fi
done < "$SENSITIVE_WORDS"
```

_Run Script_

```bash
sudo chmod +x fuzz-login.sh;sudo ./fuzz-login.sh $WEBSITE
```
