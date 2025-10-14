# Search Engine Discovery

## Check List <a href="#check-list" id="check-list"></a>

* [ ] Identify what sensitive design and configuration information of the application, system, or organization is exposed directly (on the organization’s website) or indirectly (via third-party services).

## Cheat Sheet

### [Google](https://www.exploit-db.com/google-hacking-database) <a href="#google-hacking" id="google-hacking"></a>

#### Subdomain Gathering&#x20;

```bash
uncover -gg 'site:$WEBSITE'
```

#### Negative Search

```bash
uncover -gg '-www -shop -share -ir -mfa site:$WEBSITE'
```

#### File Upload Endpoints

```bash
uncover -gg '"admin" site:$WEBSITE'
```

#### Http Title

```bash
uncover -gg 'intitle:"Login" site:$WEBSITE'
```

#### All http Title

```bash
uncover -gg 'allintitle:"Login" site:$WEBSITE'
```

#### Http Text

```bash
uncover -gg 'intext:"Login" site:$WEBSITE'
```

#### File Type

{% code fullWidth="false" %}
```bash
uncover -gg 'filetype:pdf | 
filetype:csv | 
filetype:xls | 
filetype:json | 
filetype:xml | 
filetype:ini | 
filetype:ppt | 
filetype:docx | 
filetype:doc | 
filetype:pptx | 
filetype:txt | 
filetype:xlsx | 
filetype:env 
site:$WEBSITE'
```
{% endcode %}

#### Extension

```bash
uncover -gg 'ext:log | 
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
site:$WEBSITE'
```

#### Sensitive Documents

```bash
uncover -gg 'ext:txt | 
ext:pdf | 
ext:xml | 
ext:xls | 
ext:xlsx | 
ext:ppt | 
ext:pptx | 
ext:doc | 
ext:docx 
site:$WEBSITE'
```

#### Sensitive JS

```bash
uncover -gg 'intitle:"index of" inurl:"/js/" ("config.js" | "credentials.js" | "secrets.js" | "keys.js" | "password.js" | "api_keys.js" | "auth_tokens.js" | "access_tokens.js" | "sessions.js" | "authorization.js" | "encryption.js" | "certificates.js" | "ssl_keys.js" | "passphrases.js" | "policies.js" | "permissions.js" | "privileges.js" | "hashes.js" | "salts.js" | "nonces.js" | "signatures.js" | "digests.js" | "tokens.js" | "cookies.js" | "topsecr3tdonotlook.js") site:$WEBSITE'
```

#### Backup Files

```bash
uncover -gg 'intitle:index.of "backup" OR "bkp" OR "bak" | 
intitle:index.of id_rsa OR id_dsa filetype:key 
site:$WEBSITE'
```

#### URI

```bash
uncover -gg 'inurl:conf | 
inurl:env | 
inurl:cgi | 
inurl:bin | 
inurl:etc | 
inurl:root | 
inurl:sql | 
inurl:backup | 
inurl:admin | 
inurl:api | 
inurl:swagger | 
inurl:database | 
inurl:php 
site:$WEBSITE'
```

#### API  Endpoints

```bash
uncover -gg 'inurl:api | 
site:*/rest | 
site:*/v1 | 
site:*/v2 | 
site:*/v3 
site:$WEBSITE'
```

#### High % Inurl Keywords

```bash
uncover -gg 'inurl:conf | 
inurl:env | 
inurl:cgi | 
inurl:bin | 
inurl:etc | 
inurl:root | 
inurl:sql | 
inurl:backup | 
inurl:admin | 
inurl:php 
site:$WEBSITE'
```

#### Server Errors

```bash
uncover -gg 'inurl:"error" | 
intitle:"exception" | 
intitle:"failure" | 
intitle:"server at" | 
intext:"confidential" | 
intext:"Not for Public Release" | 
intext:"internal use only" | 
intext:"do not distribute" | 
inurl:exception | 
"database error" | 
"SQL syntax" | 
"undefined index" | 
"unhandled exception" | 
"stack trace" | 
inurl:error.log OR inurl:debug.log filetype:log 
site:$WEBSITE'
```

#### XSS Parameters

```bash
uncover -gg 'inurl:q= | 
inurl:s= | 
inurl:search= | 
inurl:query= | 
inurl:keyword= | 
inurl:lang= | 
inurl:& 
site:$WEBSITE'
```

#### Open Redirect Parameters

```bash
uncover -gg 'inurl:url= | 
inurl:return= | 
inurl:next= | 
inurl:redirect= | 
inurl:redir= | 
inurl:ret= | 
inurl:r2= | 
inurl:page= | 
inurl:& | 
inurl:http 
site:$WEBSITE'
```

#### SQLi Parameters

```bash
uncover -gg 'inurl:id= | 
inurl:pid= | 
inurl:category= | 
inurl:cat= | 
inurl:action= | 
inurl:sid= | 
inurl:dir= | 
inurl:& 
site:$WEBSITE'
```

#### SSRF Parameters

```bash
uncover -gg 'inurl:http | 
inurl:url= | 
inurl:path= | 
inurl:dest= | 
inurl:html= | 
inurl:data= | 
inurl:domain= | 
inurl:page= | 
inurl:& 
site:$WEBSITE'
```

#### LFI Parameters

```bash
uncover -gg 'inurl:include | 
inurl:dir | 
inurl:detail= | 
inurl:file= | 
inurl:folder= | 
inurl:inc= | 
inurl:locate= | 
inurl:doc= | 
inurl:conf= | 
inurl:& 
site:$WEBSITE'
```

#### RCE Parameters

```bash
uncover -gg 'inurl:cmd | 
inurl:exec= | 
inurl:query= | 
inurl:code= | 
inurl:do= | 
inurl:run= | 
inurl:read= | 
inurl:ping= | 
inurl:& 
site:$WEBSITE'
```

#### API Docs

```bash
uncover -gg 'inurl:apidocs | 
inurl:api-docs | 
inurl:swagger | 
inurl:api-explorer 
site:$WEBSITE'
```

#### Login Pages

```bash
uncover -gg 'inurl:login | 
inurl:signin | 
intitle:login | 
intitle:signin | 
inurl:secure 
site:$WEBSITE'
```

#### Environments

```bash
uncover -gg 'inurl:test | 
inurl:env | 
inurl:dev | 
inurl:staging | 
inurl:sandbox | 
inurl:debug | 
inurl:temp | 
inurl:exports | 
inurl:downloads | 
inurl:internal | 
inurl:demo 
site:$WEBSITE'
```

#### Sensitive Parameters

```bash
uncover -gg 'inurl:email= | 
inurl:phone= | 
inurl:password= | 
inurl:pass= | 
inurl:pwd= | 
inurl:secret= | 
inurl:& 
site:$WEBSITE'
```

#### Cached Site

```bash
uncover -gg 'cache:"$WEBSITE"'
```

#### Link to a Specific URL

```bash
uncover -gg 'link:$WEBSITE'
```

#### Bug Bounty Reports

```bash
uncover -gg '"submit vulnerability report" | 
"powered by bugcrowd" | 
"powered by hackerone" 
site:$WEBSITE'
```

#### Adobe Experience Manager&#x20;

```bash
uncover -gg 'inurl:/content/usergenerated | 
inurl:/content/dam | 
inurl:/jcr:content | 
inurl:/libs/granite | 
inurl:/etc/clientlibs | 
inurl:/content/geometrixx | 
inurl:/bin/wcm | 
inurl:/crx/de 
site:$WEBSITE'
```

#### WordPress

```bash
uncover -gg 'inurl:/wp-admin/admin-ajax.php site:$WEBSITE'
```

#### Drupal

```bash
uncover -gg 'intext:"Powered by" & intext:Drupal & inurl:user site:$WEBSITE'
```

#### Joomla

```bash
uncover -gg 'site:*/joomla/login site:$WEBSITE'
```

### [Shodan](https://www.shodan.io/) <a href="#shodan" id="shodan"></a>

#### City

```bash
uncover -s 'city:"Tehran"'
```

#### Country

```bash
uncover -s 'country:"IR"'
```

#### GEO

```bash
uncover -s 'geo:"56.913055,118.250862"'
```

#### Vulns

```bash
uncover -s 'vuln:"CVE-2019-19781"'
```

#### Hostname

```bash
uncover -s 'server:"aws" hostname:"$WEBSITE"'
```

#### Net

```bash
uncover -s 'net:"210.214.0.0/16"'
```

#### Http Title

```bash
uncover -s 'http.title:"Login"'
```

#### Organization

```bash
uncover -s 'org:"United States Department"'
```

#### Autonomous System Number

```bash
uncover -s 'asn:"AS29068"'
```

#### Operating System

```bash
uncover -s 'os:"windows server 2022"'
```

#### Port

```bash
uncover -s 'port:"21"'
```

#### SSL/TLS Certificates

```bash
uncover -s 'ssl.cert.issuer.cn:"$WEBSITE" ssl.cert.subject.cn:"$WEBSITE"'
```

#### Before/After

```bash
uncover -s 'product:"apache" after:"01/01/2020" before:"01/01/2024"'
```

#### Device Type

```bash
uncover -s 'device:"webcam"'
```

#### Product

```bash
uncover -s 'product:"MySQL"'
```

#### Server

```bash
uncover -s 'server:"nginx"'
```

#### SSH Fingerprint

```bash
uncover -s 'dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0'
```

#### PEM Certificates

```bash
uncover -s 'http.title:"Index of /" http.html:".pem"'
```

#### Industrial Control Systems

```bash
uncover -s 'port:"502" port:"102"'
```

#### Exchange 2013 / 2016

```bash
uncover -s '"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"'
```

#### SMB (Samba) File Shares

```bash
uncover -s '"Authentication: disabled" port:445'
```

#### Specifically Domain Controllers

```bash
uncover -s '"Authentication: disabled" NETLOGON SYSVOL -unix port:445'
```

#### FTP Servers with Anonymous Login

```bash
uncover -s '"220" "230 Login successful." port:21'
```

#### D-Link Webcams

```bash
uncover -s 'd-Link Internet Camera, 200 OK'
```

#### Android IP Webcam Server

```bash
uncover -s 'Server:"IP Webcam Server" "200 OK"'
```

#### Security DVRs

```bash
uncover -s 'html:"DVR_H264 ActiveX"'
```

#### HP Printers

```bash
uncover -s '"Serial Number:" "Built:" "Server: HP HTTP"'
```

#### Chromecast / Smart TVs

```bash
uncover -s '"Chromecast:" port:8008'
```

#### Ethereum Miners

```bash
uncover -s '"ETH" "speed" "Total"'
```

#### Misconfigured WordPress

```bash
uncover -s 'http.html:"* The wp-config.php creation script uses this file"'
```

### [GitHub](https://github.com/explore) <a href="#github" id="github"></a>

#### WebServers Configuration File

```bash
gh search code 'path:**/WebServer.xml'
```

#### .bash\_history Commands

```bash
gh search code 'path:**/.bash_history'
```

#### /etc/passwd File

```bash
gh search code 'path:**/passwd path:etc'
```

#### Password in config.php

```bash
gh search code 'path:**/config.php dbpasswd'
```

#### Shodan API Key in Python Script

```bash
gh search code 'shodan_api_key language:python'
```

#### /etc/shadow File

```bash
gh search code 'path:**/shadow path:etc'
```

#### wp-config.php File

```bash
gh search code 'path:**/wp-config.php'
```

#### MySQL Dump File

```bash
gh search code 'path:*.sql mysql dump'
```

### [Censys](https://search.censys.io/) <a href="#censys" id="censys"></a>

#### City

```bash
uncover -cs 'location.city: "Tehran"'
```

#### Country

```bash
uncover -cs 'location.country: "Iran"'
```

#### GEO

```bash
uncover -cs 'location.coordinates.latitude: 38.8951 and location.coordinates.longitude: -77.0364'
```

#### Vulns

```bash
uncover -cs 'vulnerabilities.cve.keyword: "CVE-2021-34527"'
```

#### Hostname

```bash
uncover -cs 'name: "$WEBSITE"'
```

#### NET

```bash
uncover -cs 'ip: [1.1.1.1 to 1.1.255.255]'
```

#### Http Title

```bash
uncover -cs 'services.http.response.html_title: "Login Page"'
```

#### Organization

```bash
uncover -cs 'autonomous_system.name: "Google"'
```

#### Autonomous System Number

```bash
uncover -cs 'autonomous_system.asn: 13335'
```

#### Operating System

```bash
uncover -cs 'operating_system.product: "Windows"'
```

#### Port

```bash
uncover -cs 'services.port=`80`'
```

#### SSL/TLS Certificates

```bash
uncover -cs 'services.tls.certificate.parsed.subject.common_name: "$WEBSITE"'
```

#### Before/After

```bash
uncover -cs 'services.software.product: "apache" AND services.observed_at: [2020-01-01 TO 2024-01-01]'
```

#### Device Type

```bash
uncover -cs 'labels: device'
```

#### Product

```bash
uncover -cs 'services.software.vendor=`Apache`'
```

#### Server

```bash
uncover -cs 'services.http.response.headers.server: "nginx"'
```

#### SSH Fingerprint

```bash
uncover -cs 'services.ssh.v2.fingerprint_sha256: "dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0"'
```

#### PEM Certificates

```bash
uncover -cs 'services: (http.response.html_title: "Index of /" and http.response.body: ".pem")'
```

#### Industrial Control Systems

```bash
uncover -cs 'labels: ics'
```

#### Exchange 2013 / 2016

```bash
uncover -cs 'services: (http.response.headers: (key: "X-AspNet-Version" and value.headers: "*") and http.response.html_title: "Outlook" and not http.response.headers: (key: "x-owa-version" and value.headers: "*"))'
```

#### SMB (Samba) File Shares

```bash
uncover -cs 'services: (service_name: SMB and banner: "shared_folder")'
```

#### Specifically Domain Controllers

```bash
uncover -cs '"Authentication: disabled" and services: (service_name: NETLOGON and service_name: SYSVOL) and not operating_system.product: "unix" and services.port: 445'
```

#### FTP Servers with Anonymous Login

```bash
uncover -cs 'services.ftp.status_code: 230'
```

#### Webcams

```bash
uncover -cs 'services.http.response.headers: (key: "Server" and value.headers: "Webcam")'
```

#### Android IP Webcam Server

```bash
uncover -cs 'services.http.response.html_title: "IP Webcam"'
```

#### Security DVRs

```bash
uncover -cs 'services.http.response.html_title: "Security DVR"'
```

#### Printers

```bash
uncover -cs 'services.http.response.headers: (key: "Server" and value.headers: "Printer")'
```

#### Chromecast / Smart TVs

```bash
uncover -cs 'services.http.response.headers: (key: "Server" and value.headers: {"Chromecast", "Smart TV"})'
```

#### Ethereum Miners

```bash
uncover -cs 'services.http.response.html_title: "Ethereum Miner"'
```

#### Misconfiguration WordPress

```bash
uncover -cs 'services: (http.response.html_title: "WordPress" and http.response.headers: (key: "Favicon" and value.headers: "c4d2e77e3e9a4c8d4d2e9b6c9f6d3c6f"))'
```

#### Services on Ports 22-25

```bash
uncover -cs 'services.port: {22,23,24,25}'
```

#### Elasticsearch Service on Port 443

```bash
uncover -cs '(services.service_name=`ELASTICSEARCH`) and service.port=`443`'
```

#### Login Page with Specific Banner Hash in Iran

```bash
uncover -cs '((services.banner_hashes=`sha256:4d3efcb4c2cc2cdb96dddf455977c3291f4b0f6a8a290bfc15e460d917703226`) and labels=`login-page`) and location.country=`Iran`'
```

#### OWA Login Page

```bash
uncover -cs 'same_service(services.http.response.favicons.name: */owa/auth/* and services.http.response.html_title={"Outlook Web App", "Outlook"})'
```

#### Exchange Server in Iran

```bash
uncover -cs '(services.software.product=`Exchange Server`) and location.country=`Iran`'
```

### [Zoomeye](https://www.zoomeye.hk/) <a href="#zoomeye" id="zoomeye"></a>

#### GEO

```bash
uncover -ze 'geo:"35.6892,51.3890"'
```

#### Vuln

```bash
uncover -ze 'vuln:"CVE-2021-34527"'
```

#### Net

```bash
uncover -ze 'net:"192.168.0.0/24"'
```

#### Http Title

```bash
uncover -ze 'port:80 AND title:"Login Page"'
```

#### Organization

```bash
uncover -ze 'organization:"Google"'
```

#### SSL/TLS Certificates

```bash
uncover -ze 'ssl.cert.subject.cn:"$WEBSITE"'
```

#### Before/After

```bash
uncover -ze 'product:"apache" after:"2020-01-01" before:"2024-01-01"'
```

#### Product

```bash
uncover -ze 'product:"Apache"'
```

#### Server

```bash
uncover -ze 'server:"nginx"'
```

#### SSH Fingerprint

```bash
uncover -ze 'dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0'
```

#### PEM Certificates

```bash
uncover -ze 'http.title:"Index of /" http.html:".pem"'
```

#### Industrial Control Systems

```bash
uncover -ze 'ics:"SCADA"'
```

#### Exchange 2013 / 2016

```bash
uncover -ze '"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"'
```

#### SMB (Samba) File Shares

```bash
uncover -ze '"Authentication: disabled" port:445'
```

#### Specifically Domain Controllers

```bash
uncover -ze 'smb.share:"SYSVOL" OR smb.share:"NETLOGON"'
```

#### FTP Servers with Anonymous Login

```bash
uncover -ze 'port:21 ,ftp.anonymous:"true"'
```

#### D-Link Webcams

```bash
uncover -ze 'title:"d-Link Internet Camera" AND http.status_code:"200"'
```

#### Android IP Webcam Server

```bash
uncover -ze 'Server:"IP Webcam Server" "200 OK"'
```

#### Security DVRs

```bash
uncover -ze 'port:80 AND "DVR_H264 ActiveX"'
```

#### HP Printers

```bash
uncover -ze '"Serial Number:" "Built:" "Server: HP HTTP"'
```

#### Chromecast / Smart TVs

```bash
uncover -ze 'product:"Chromecast" OR product:"Smart TV"'
```

#### Ethereum Miners

```bash
uncover -ze '"ETH" "speed" "Total"'
```

#### Misconfigured WordPress

```bash
uncover -ze 'http.title:"WordPress" AND http.favicon.hash:"c4d2e77e3e9a4c8d4d2e9b6c9f6d3c6f"'
```

#### Web Application

```bash
uncover -ze 'webapp:wordpress'
```

#### Version

```bash
uncover -ze 'ver: 2.1'
```

#### ProFTPD Server

```bash
uncover -ze 'app: ProFTPD'
```

#### Device Type

```bash
uncover -ze 'device: router'
```

#### Operating System

```bash
uncover -ze 'os: windows'
```

#### Service

```bash
uncover -ze 'service: http'
```

#### IP

```bash
uncover -ze 'ip: 192.168.1.1'
```

#### Devices in 192.168.1.1/24 Network Range

```bash
uncover -ze 'cidr: 192.168.1.1/24'
```

#### Hostname

```bash
uncover -ze 'hostname: $WEBSITE'
```

#### Port

```bash
uncover -ze 'port: 80'
```

#### City

```bash
uncover -ze 'city: tehran'
```

#### Country

```bash
uncover -ze 'country: iran'
```

#### Autonomous System Number

```bash
uncover -ze 'asn: 8978'
```

#### Header

```bash
uncover -ze 'header: server'
```

#### Found 'hello' in Description'

```bash
uncover -ze 'desc: hello'
```

#### Title

```bash
uncover -ze 'title: $WEBSITE'
```

#### Site

```bash
uncover -ze 'site: $WEBSITE'
```
