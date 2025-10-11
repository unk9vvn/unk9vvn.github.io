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

<pre class="language-bash"><code class="lang-bash"><strong>uncover -gg 'allintitle:"Login" site:$WEBSITE'
</strong></code></pre>

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

<pre class="language-bash"><code class="lang-bash"><strong>uncover -gg 'inurl:api | 
</strong>site:*/rest | 
site:*/v1 | 
site:*/v2 | 
site:*/v3 
site:$WEBSITE'
</code></pre>

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

<pre class="language-bash"><code class="lang-bash"><strong>uncover -gg 'inurl:id= | 
</strong>inurl:pid= | 
inurl:category= | 
inurl:cat= | 
inurl:action= | 
inurl:sid= | 
inurl:dir= | 
inurl:&#x26; 
site:$WEBSITE'
</code></pre>

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

<pre class="language-bash"><code class="lang-bash"><strong>uncover -gg 'inurl:/content/usergenerated | 
</strong>inurl:/content/dam | 
inurl:/jcr:content | 
inurl:/libs/granite | 
inurl:/etc/clientlibs | 
inurl:/content/geometrixx | 
inurl:/bin/wcm | 
inurl:/crx/de 
site:$WEBSITE'
</code></pre>

#### WordPress

```bash
uncover -gg 'inurl:/wp-admin/admin-ajax.php site:$WEBSITE'
```

#### Drupal

<pre class="language-bash"><code class="lang-bash"><strong>uncover -gg 'intext:"Powered by" &#x26; intext:Drupal &#x26; inurl:user site:$WEBSITE'
</strong></code></pre>

#### Joomla

<pre class="language-bash"><code class="lang-bash"><strong>uncover -gg 'site:*/joomla/login site:$WEBSITE'
</strong></code></pre>

### [Duckduckgo](https://duckduckgo.com/)

#### Subdomains

<pre class="language-bash"><code class="lang-bash"><strong>site:$WEBSITE
</strong></code></pre>

#### Http Title

```bash
intitle:"Login" site:$WEBSITE
```

#### All Http Title

```bash
allintitle:"Login" site:$WEBSITE
```

#### Http Text&#x20;

```bash
intext:"Login" site:$WEBSITE
```

#### File Type

```bash
filetype:pdf OR filetype:csv OR filetype:xls site:$WEBSITE
```

#### Extension&#x20;

```bash
ext:daf OR ext:bak OR ext:zip OR ext:log site:$WEBSITE
```

#### URI

```bash
inurl:login | 
inurl:logon | 
inurl:sign-in | 
inurl:signin | 
inurl:portal 
site:$WEBSITE
```

#### Cached Site

```bash
cache:$WEBSITE
```

#### Link to a Specific URL

```bash
link:$WEBSITE
```

#### Information Site

```bash
info:$WEBSITE
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

<pre class="language-bash"><code class="lang-bash"><strong>uncover -s 'net:"210.214.0.0/16"'
</strong></code></pre>

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

<pre class="language-bash"><code class="lang-bash"><strong>uncover -s 'product:"apache" after:"01/01/2020" before:"01/01/2024"'
</strong></code></pre>

#### Device Type

```bash
uncover -s 'device:"webcam"'
```

#### Product

```bash
uncover -s 'product:"MySQL"'
```

#### Server

<pre class="language-bash"><code class="lang-bash"><strong>uncover -s 'server:"nginx"'
</strong></code></pre>

#### SSH Fingerprint

<pre class="language-bash"><code class="lang-bash"><strong>uncover -s 'dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0'
</strong></code></pre>

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
path:**/WebServer.xml
```

#### .bash\_history Commands

```bash
path:**/.bash_history
```

#### /etc/passwd File

```bash
path:**/passwd path:etc
```

#### Password in config.php

```bash
path:**/config.php dbpasswd
```

#### Shodan API Key in Python Script

```bash
shodan_api_key language:python
```

#### /etc/shadow File

```bash
path:**/shadow path:etc
```

#### wp-config.php File

```bash
path:**/wp-config.php
```

#### MySQL Dump File

```bash
path:*.sql mysql dump
```

### [Censys](https://search.censys.io/) <a href="#censys" id="censys"></a>

#### City

```bash
location.city: "Tehran"
```

#### Country

```bash
location.country: "Iran"
```

#### GEO

```bash
location.coordinates.latitude: 38.8951 and location.coordinates.longitude: -77.0364
```

#### Vulns

```bash
vulnerabilities.cve.keyword: "CVE-2021-34527"
```

#### Hostname

```bash
name: "$WEBSITE"
```

#### NET

```bash
ip: [1.1.1.1 to 1.1.255.255]
```

#### Http Title

```bash
services.http.response.html_title: "Login Page" 
```

#### Organization

```bash
autonomous_system.name: "Google"
```

#### Autonomous System Number

```bash
autonomous_system.asn: 13335
```

#### Operating System

```bash
operating_system.product: "Windows"
```

#### Port

```bash
services.port=`80`
```

#### SSL/TLS Certificates

```bash
services.tls.certificate.parsed.subject.common_name: "$WEBSITE"
```

#### Before/After

```bash
services.software.product: "apache" AND services.observed_at: [2020-01-01 TO 2024-01-01]
```

#### Device Type

```bash
labels: device
```

#### Product

```bash
services.software.vendor=`Apache`
```

#### Server

```bash
services.http.response.headers.server: "nginx"
```

#### SSH Fingerprint

```bash
services.ssh.v2.fingerprint_sha256: "dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0"
```

#### PEM Certificates

```bash
services: (http.response.html_title: "Index of /" and http.response.body: ".pem")
```

#### Industrial Control Systems

```bash
labels: ics
```

#### Exchange 2013 / 2016

```bash
services: (http.response.headers: (key: "X-AspNet-Version" and value.headers: "*") and http.response.html_title: "Outlook" and not http.response.headers: (key: "x-owa-version" and value.headers: "*"))
```

#### SMB (Samba) File Shares

```bash
services: (service_name: SMB and banner: "shared_folder")
```

#### Specifically Domain Controllers

```bash
"Authentication: disabled" and services: (service_name: NETLOGON and service_name: SYSVOL) and not operating_system.product: "unix" and services.port: 445
```

#### FTP Servers with Anonymous Login

```bash
services.ftp.status_code: 230
```

#### Webcams

```bash
services.http.response.headers: (key: "Server" and value.headers: "Webcam")
```

#### Android IP Webcam Server

```bash
services.http.response.html_title: "IP Webcam"
```

#### Security DVRs

```bash
services.http.response.html_title: "Security DVR"
```

#### Printers

```bash
services.http.response.headers: (key: "Server" and value.headers: "Printer")
```

#### Chromecast / Smart TVs

```bash
services.http.response.headers: (key: "Server" and value.headers: {"Chromecast", "Smart TV"})
```

#### Ethereum Miners

```bash
services.http.response.html_title: "Ethereum Miner"
```

#### Misconfiguration WordPress

```bash
services: (http.response.html_title: "WordPress" and http.response.headers: (key: "Favicon" and value.headers: "c4d2e77e3e9a4c8d4d2e9b6c9f6d3c6f"))
```

#### Services on Ports 22-25

```bash
services.port: {22,23,24,25}
```

#### Elasticsearch Service on Port 443

```bash
(services.service_name=`ELASTICSEARCH`) and service.port=`443`
```

#### Login Page with Specific Banner Hash in Iran

```bash
((services.banner_hashes=`sha256:4d3efcb4c2cc2cdb96dddf455977c3291f4b0f6a8a290bfc15e460d917703226`) and labels=`login-page`) and location.country=`Iran` 
```

#### OWA Login Page

```bash
same_service(services.http.response.favicons.name: */owa/auth/* and services.http.response.html_title={"Outlook Web App", "Outlook"}) 
```

#### Exchange Server in Iran

```bash
(services.software.product=`Exchange Server`) and location.country=`Iran` 
```

### [Zoomeye](https://www.zoomeye.hk/) <a href="#zoomeye" id="zoomeye"></a>

#### GEO

```bash
geo:"35.6892,51.3890"
```

#### Vuln

```bash
vuln:"CVE-2021-34527"
```

#### Net

```bash
net:"192.168.0.0/24"
```

#### Http Title

```bash
port:80 AND title:"Login Page"
```

#### Organization

```bash
organization:"Google"
```

#### SSL/TLS Certificates

```bash
ssl.cert.subject.cn:"$WEBSITE"
```

#### Before/After

```bash
product:"apache" after:"2020-01-01" before:"2024-01-01"
```

#### Product

```bash
product:"Apache"
```

#### Server

```bash
server:"nginx"
```

#### SSH Fingerprint

```bash
dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0
```

#### PEM Certificates

```bash
http.title:"Index of /" http.html:".pem"
```

#### Industrial Control Systems

```bash
ics:"SCADA"
```

#### Exchange 2013 / 2016

```bash
"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"
```

#### SMB (Samba) File Shares

```bash
"Authentication: disabled" port:445
```

#### Specifically Domain Controllers

```bash
smb.share:"SYSVOL" OR smb.share:"NETLOGON"
```

#### FTP Servers with Anonymous Login

```bash
port:21 ,ftp.anonymous:"true"
```

#### D-Link Webcams

```bash
title:"d-Link Internet Camera" AND http.status_code:"200"
```

#### Android IP Webcam Server

```bash
Server:"IP Webcam Server" "200 OK"
```

#### Security DVRs

```bash
port:80 AND "DVR_H264 ActiveX"
```

#### HP Printers

```bash
"Serial Number:" "Built:" "Server: HP HTTP"
```

#### Chromecast / Smart TVs

```bash
product:"Chromecast" OR product:"Smart TV"
```

#### Ethereum Miners

```bash
"ETH" "speed" "Total"
```

#### Misconfigured WordPress

```bash
http.title:"WordPress" AND http.favicon.hash:"c4d2e77e3e9a4c8d4d2e9b6c9f6d3c6f"
```

#### Web Application

```bash
webapp:wordpress
```

#### Version

```bash
ver: 2.1
```

#### ProFTPD Server

```bash
app: ProFTPD
```

#### Device Type

```bash
device: router
```

#### Operating System

```bash
os: windows
```

#### Service

```bash
service: http
```

#### IP

```bash
ip: 192.168.1.1
```

#### Devices in 192.168.1.1/24 Network Range

```bash
cidr: 192.168.1.1/24 
```

#### Hostname

```bash
hostname: $WEBSITE
```

#### Port

```bash
port: 80
```

#### City

```bash
city: tehran
```

#### Country

```bash
country: iran
```

#### Autonomous System Number

```bash
asn: 8978
```

#### Header

```bash
header: server
```

#### Found 'hello' in Description'

```bash
desc: hello
```

#### Title

```bash
title: $WEBSITE
```

#### Site

```bash
site: $WEBSITE
```
