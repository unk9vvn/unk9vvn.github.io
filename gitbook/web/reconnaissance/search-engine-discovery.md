# Search Engine Discovery

## Check List <a href="#check-list" id="check-list"></a>

* [ ] _Identify what sensitive design and configuration information of the application, system, or organization is exposed directly (on the organization’s website) or indirectly (via third-party services)._

## Cheat Sheet <a href="#cheat-sheet" id="cheat-sheet"></a>

### [Google](https://www.exploit-db.com/google-hacking-database) <a href="#google-hacking" id="google-hacking"></a>

_Subdomains Gathering_&#x20;

```bash
site:$WEBSITE
```

_Negative Search_

```bash
-www -shop -share -ir -mfa site:$WEBSITE 
```

_File Upload Endpoints_

```bash
"admin" site:$WEBSITE 
```

_Http Title_

```bash
intitle:"Login" site:$WEBSITE
```

_All http Title_

```bash
allintitle:"Login" site:$WEBSITE
```

_Http Text_

```bash
intext:"Login" site:$WEBSITE
```

_File Type_

{% code fullWidth="false" %}
```bash
filetype:pdf | 
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
site:$WEBSITE
```
{% endcode %}

_Extension_

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

_Sensitive Documents_

```bash
ext:txt | 
ext:pdf | 
ext:xml | 
ext:xls | 
ext:xlsx | 
ext:ppt | 
ext:pptx | 
ext:doc | 
ext:docx 
site:$WEBSITE
```

_Sensitive JS Libs_

```bash
intitle:"index of" inurl:"/js/" ("config.js" | "credentials.js" | "secrets.js" | "keys.js" | "password.js" | "api_keys.js" | "auth_tokens.js" | "access_tokens.js" | "sessions.js" | "authorization.js" | "encryption.js" | "certificates.js" | "ssl_keys.js" | "passphrases.js" | "policies.js" | "permissions.js" | "privileges.js" | "hashes.js" | "salts.js" | "nonces.js" | "signatures.js" | "digests.js" | "tokens.js" | "cookies.js" | "topsecr3tdonotlook.js") site:$WEBSITE
```

_Backup Files_

```bash
intitle:index.of "backup" OR "bkp" OR "bak" | 
intitle:index.of id_rsa OR id_dsa filetype:key 
site:$WEBSITE
```

_URI_

```bash
inurl:conf | 
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
site:$WEBSITE
```

_API  Endpoints_

```bash
inurl:api | 
site:*/rest | 
site:*/v1 | 
site:*/v2 | 
site:*/v3 
site:$WEBSITE
```

_High % inurl keywords_

```bash
inurl:conf | 
inurl:env | 
inurl:cgi | 
inurl:bin | 
inurl:etc | 
inurl:root | 
inurl:sql | 
inurl:backup | 
inurl:admin | 
inurl:php 
site:$WEBSITE
```

_Server Errors_

```bash
inurl:"error" | 
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
site:$WEBSITE
```

_XSS Parameters_

```bash
inurl:q= | 
inurl:s= | 
inurl:search= | 
inurl:query= | 
inurl:keyword= | 
inurl:lang= | 
inurl:& 
site:$WEBSITE
```

_Open Redirect Parameters_

```bash
inurl:url= | 
inurl:return= | 
inurl:next= | 
inurl:redirect= | 
inurl:redir= | 
inurl:ret= | 
inurl:r2= | 
inurl:page= | 
inurl:& | 
inurl:http 
site:$WEBSITE
```

_SQLi Parameters_

```bash
inurl:id= | 
inurl:pid= | 
inurl:category= | 
inurl:cat= | 
inurl:action= | 
inurl:sid= | 
inurl:dir= | 
inurl:& 
site:$WEBSITE
```

_SSRF Parameters_

```bash
inurl:http | 
inurl:url= | 
inurl:path= | 
inurl:dest= | 
inurl:html= | 
inurl:data= | 
inurl:domain= | 
inurl:page= | 
inurl:& 
site:$WEBSITE
```

_LFI Parameters_

```bash
inurl:include | 
inurl:dir | 
inurl:detail= | 
inurl:file= | 
inurl:folder= | 
inurl:inc= | 
inurl:locate= | 
inurl:doc= | 
inurl:conf= | 
inurl:& 
site:$WEBSITE
```

_RCE Parameters_

```bash
inurl:cmd | 
inurl:exec= | 
inurl:query= | 
inurl:code= | 
inurl:do= | 
inurl:run= | 
inurl:read= | 
inurl:ping= | 
inurl:& 
site:$WEBSITE
```

_API Docs_

```bash
inurl:apidocs | 
inurl:api-docs | 
inurl:swagger | 
inurl:api-explorer 
site:$WEBSITE
```

_Login Pages_

```bash
inurl:login | 
inurl:signin | 
intitle:login | 
intitle:signin | 
inurl:secure 
site:$WEBSITE
```

_Test Environments_

```bash
inurl:test | 
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
site:$WEBSITE
```

_Sensitive Parameters_

```bash
inurl:email= | 
inurl:phone= | 
inurl:password= | 
inurl:pass= | 
inurl:pwd= | 
inurl:secret= | 
inurl:& 
site:$WEBSITE
```

_Cached Site_

```bash
cache:"$WEBSITE"
```

_Link to a Specific URL_

```bash
link:$WEBSITE
```

_Bug Bounty Reports_

```bash
"submit vulnerability report" | 
"powered by bugcrowd" | 
"powered by hackerone" 
site:$WEBSITE
```

_Adobe Experience Manager_&#x20;

```bash
inurl:/content/usergenerated | 
inurl:/content/dam | 
inurl:/jcr:content | 
inurl:/libs/granite | 
inurl:/etc/clientlibs | 
inurl:/content/geometrixx | 
inurl:/bin/wcm | 
inurl:/crx/de 
site:$WEBSITE
```

_WordPress_

```bash
inurl:/wp-admin/admin-ajax.php site:$WEBSITE
```

_Drupal_

```bash
intext:"Powered by" & intext:Drupal & inurl:user site:$WEBSITE
```

_Joomla_

```bash
site:*/joomla/login site:$WEBSITE
```

### [Duckduckgo](https://duckduckgo.com/)

_Subdomains_

```bash
site:$WEBSITE
```

_Http Title_

```bash
intitle:"Login" site:$WEBSITE
```

_All Http Title_

```bash
allintitle:"Login" site:$WEBSITE
```

_Http Text_&#x20;

```bash
intext:"Login" site:$WEBSITE
```

_File Type_

```bash
filetype:pdf OR filetype:csv OR filetype:xls site:$WEBSITE
```

_Extension_&#x20;

```bash
ext:daf OR ext:bak OR ext:zip OR ext:log site:$WEBSITE
```

_URI_

```bash
inurl:login | 
inurl:logon | 
inurl:sign-in | 
inurl:signin | 
inurl:portal 
site:$WEBSITE
```

_Cached Site_

```bash
cache:$WEBSITE
```

_Link to a Specific URL_

```bash
link:$WEBSITE
```

_Information Site_

```bash
info:$WEBSITE
```

### [Shodan](https://www.shodan.io/) <a href="#shodan" id="shodan"></a>

_City_

```bash
city:"Tehran"
```

_Country_

```bash
country:"IR"
```

_Geo_

```bash
geo:"56.913055,118.250862"
```

_Vuln_

```bash
vuln:"CVE-2019-19781"
```

_Hostname_

```bash
'server:"aws" hostname:"$WEBSITE"'
```

_Net_

```bash
net:"210.214.0.0/16"
```

_HTTP Title_

```bash
http.title:"Login"
```

_Organization_

```bash
org:"United States Department"
```

_Autonomous System Number_

```bash
asn:"AS29068"
```

_Operating System_

```bash
os:"windows server 2022"
```

_Port_

```bash
port:"21"
```

_SSL/TLS Certificates_

```bash
ssl.cert.issuer.cn:"$WEBSITE" ssl.cert.subject.cn:"$WEBSITE"
```

_Before/After_

```bash
product:"apache" after:"01/01/2020" before:"01/01/2024"
```

_Device Type_

```bash
device:"webcam"
```

_Product_

```bash
product:"MySQL"
```

_Server_

```bash
server:"nginx"
```

_SSH Fingerprint_

```bash
dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0
```

_PEM Certificates_

```bash
http.title:"Index of /" http.html:".pem"
```

_Industrial Control Systems_

```bash
'port:"502" port:"102"'
```

_Exchange 2013 / 2016_

```bash
"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"
```

_SMB (Samba) File Shares_

```bash
"Authentication: disabled" port:445
```

_Specifically domain controllers_

```bash
"Authentication: disabled" NETLOGON SYSVOL -unix port:445
```

_FTP Servers with Anonymous Login_

```bash
"220" "230 Login successful." port:21
```

_D-Link Webcams_

```bash
d-Link Internet Camera, 200 OK
```

_Android IP Webcam Server_

```bash
Server:"IP Webcam Server" "200 OK"
```

_Security DVRs_

```bash
html:"DVR_H264 ActiveX"
```

_HP Printers_

```bash
"Serial Number:" "Built:" "Server: HP HTTP"
```

_Chromecast / Smart TVs_

```bash
"Chromecast:" port:8008
```

_Ethereum Miners_

```bash
“ETH” “speed” “Total”
```

_Misconfigured WordPress_

```bash
http.html:"* The wp-config.php creation script uses this file"
```

### [GitHub](https://github.com/explore) <a href="#github" id="github"></a>

_WebServers Configuration File_

```bash
path:**/WebServer.xml
```

_.bash\_history Commands_

```bash
path:**/.bash_history
```

_/etc/passwd File_

```bash
path:**/passwd path:etc
```

_Password in config.php_

```bash
path:**/config.php dbpasswd
```

_Shodan API Key in Python Script_

```bash
shodan_api_key language:python
```

_/etc/shadow File_

```bash
path:**/shadow path:etc
```

_wp-config.php File_

```bash
path:**/wp-config.php
```

_MySQL Dump File_

```bash
path:*.sql mysql dump
```

### [Censys](https://search.censys.io/) <a href="#censys" id="censys"></a>

_City_

```bash
location.city: "Tehran"
```

_Country_

```bash
location.country: "Iran"
```

_GEO_

```bash
location.coordinates.latitude: 38.8951 and location.coordinates.longitude: -77.0364
```

_Vuln_

```bash
vulnerabilities.cve.keyword: "CVE-2021-34527"
```

_Hostname_

```bash
name: "$WEBSITE"
```

_NET_

```bash
ip: [1.1.1.1 to 1.1.255.255]
```

_Http Title_

```bash
services.http.response.html_title: "Login Page" 
```

_Organization_

```bash
autonomous_system.name: "Google"
```

_Autonomous System Number_

```bash
autonomous_system.asn: 13335
```

_Operating System_

```bash
operating_system.product: "Windows"
```

_Port_

```bash
services.port=`80`
```

_SSL/TLS Certificates_

```bash
services.tls.certificate.parsed.subject.common_name: "$WEBSITE"
```

_Before/After_

```bash
services.software.product: "apache" AND services.observed_at: [2020-01-01 TO 2024-01-01]
```

_Device Type_

```bash
labels: device
```

_Product_

```bash
services.software.vendor=`Apache`
```

_Server_

```bash
services.http.response.headers.server: "nginx"
```

_SSH Fingerprint_

```bash
services.ssh.v2.fingerprint_sha256: "dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0"
```

_PEM Certificates_

```bash
services: (http.response.html_title: "Index of /" and http.response.body: ".pem")
```

_Industrial Control Systems_

```bash
labels: ics
```

_Exchange 2013 / 2016_

```bash
services: (http.response.headers: (key: "X-AspNet-Version" and value.headers: "*") and http.response.html_title: "Outlook" and not http.response.headers: (key: "x-owa-version" and value.headers: "*"))
```

_SMB (Samba) File Shares_

```bash
services: (service_name: SMB and banner: "shared_folder")
```

_Specifically domain controllers_

```bash
"Authentication: disabled" and services: (service_name: NETLOGON and service_name: SYSVOL) and not operating_system.product: "unix" and services.port: 445
```

_FTP Servers with Anonymous Login_

```bash
services.ftp.status_code: 230
```

_Webcams_

```bash
services.http.response.headers: (key: "Server" and value.headers: "Webcam")
```

_Android IP Webcam Server_

```bash
services.http.response.html_title: "IP Webcam"
```

_Security DVRs_

```bash
services.http.response.html_title: "Security DVR"
```

_Printers_

```bash
services.http.response.headers: (key: "Server" and value.headers: "Printer")
```

_Chromecast / Smart TVs_

```bash
services.http.response.headers: (key: "Server" and value.headers: {"Chromecast", "Smart TV"})
```

_Ethereum Miners_

```bash
services.http.response.html_title: "Ethereum Miner"
```

_Misconfigured WordPress_

```bash
services: (http.response.html_title: "WordPress" and http.response.headers: (key: "Favicon" and value.headers: "c4d2e77e3e9a4c8d4d2e9b6c9f6d3c6f"))
```

_Services on Ports 22-25_

```bash
services.port: {22,23,24,25}
```

_Elasticsearch Service on Port 443_

```bash
(services.service_name=`ELASTICSEARCH`) and service.port=`443`
```

_Login Page with Specific Banner Hash in Iran_

```bash
((services.banner_hashes=`sha256:4d3efcb4c2cc2cdb96dddf455977c3291f4b0f6a8a290bfc15e460d917703226`) and labels=`login-page`) and location.country=`Iran` 
```

_OWA Login Page_

```bash
same_service(services.http.response.favicons.name: */owa/auth/* and services.http.response.html_title={"Outlook Web App", "Outlook"}) 
```

_Exchange Server in Iran_

```bash
(services.software.product=`Exchange Server`) and location.country=`Iran` 
```

### [Zoomeye](https://www.zoomeye.hk/) <a href="#zoomeye" id="zoomeye"></a>

_GEO_

```bash
geo:"35.6892,51.3890"
```

_Vuln_

```bash
vuln:"CVE-2021-34527"
```

_Net_

```bash
net:"192.168.0.0/24"
```

_Http Title_

```bash
port:80 AND title:"Login Page"
```

_Organization_

```bash
organization:"Google"
```

_SSL/TLS Certificates_

```bash
ssl.cert.subject.cn:"$WEBSITE"
```

_Before/After_

```bash
product:"apache" after:"2020-01-01" before:"2024-01-01"
```

_Product_

```bash
product:"Apache"
```

_Server_

```bash
server:"nginx"
```

_SSH Fingerprint_

```bash
dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0
```

_PEM Certificates_

```bash
http.title:"Index of /" http.html:".pem"
```

_Industrial Control Systems_

```bash
ics:"SCADA"
```

_Exchange 2013 / 2016_

```bash
"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"
```

_SMB (Samba) File Shares_

```bash
"Authentication: disabled" port:445
```

_Specifically domain controllers_

```bash
smb.share:"SYSVOL" OR smb.share:"NETLOGON"
```

_FTP Servers with Anonymous Login_

```bash
port:21 ,ftp.anonymous:"true"
```

_D-Link Webcams_

```bash
title:"d-Link Internet Camera" AND http.status_code:"200"
```

_Android IP Webcam Server_

```bash
Server:"IP Webcam Server" "200 OK"
```

_Security DVRs_

```bash
port:80 AND "DVR_H264 ActiveX"
```

_HP Printers_

```bash
"Serial Number:" "Built:" "Server: HP HTTP"
```

_Chromecast / Smart TVs_

```bash
product:"Chromecast" OR product:"Smart TV"
```

_Ethereum Miners_

```bash
“ETH” “speed” “Total”
```

_Misconfigured WordPress_

```bash
http.title:"WordPress" AND http.favicon.hash:"c4d2e77e3e9a4c8d4d2e9b6c9f6d3c6f"
```

_Web Application_

```bash
webapp:wordpress
```

_Version_

```bash
ver: 2.1
```

_ProFTPD Server_

```bash
app: ProFTPD
```

_Device Type_

```bash
device: router
```

_Operating System_

```bash
os: windows
```

_Service_

```bash
service: http
```

_IP_

```bash
ip: 192.168.1.1
```

_Devices in 192.168.1.1/24 Network Range_

```bash
cidr: 192.168.1.1/24 
```

_Hostname_

```bash
hostname: $WEBSITE
```

_Port_

```bash
port: 80
```

_City_

```bash
city: tehran
```

_Country_

```bash
country: iran
```

_Autonomous System Number_

```bash
asn:8978
```

_Header_

```bash
header: server
```

_Found 'hello' in Description'_

```bash
desc: hello
```

_Title_

```bash
title: $WEBSITE
```

_Site_

```bash
site: $WEBSITE
```
