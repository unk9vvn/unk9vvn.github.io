# Infrastructure

## Check List

* [ ] _Use search engines for basic information gathering._
* [ ] _Explore specialized websites for additional insights._
* [ ] _Perform Whois lookups for domain information._
* [ ] _Investigate DNS records for domain details._
* [ ] _Check IP addresses for location and hosting information._
* [ ] _Network mapping and relationship analysis._
* [ ] _Utilize Recon-NG for automated data gathering._
* [ ] _Extract metadata from files and images._

## Cheat Sheet

### Search Engine&#x20;

#### [Google](https://www.exploit-db.com/google-hacking-database)

_Sub Domains_

```bash
site:$WEBSITE
```

_HTTP Title_

```bash
intitle:"login" |
intitle:"admin" |
intitle:"administrator"
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
inurl:php
site:$WEBSITE
```

_File Types_

```bash
filetype:pdf |
filetype:csv |
filetype:xls |
filetype:xlsx
site:$WEBSITE
```

_Extensions_

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

_Exact Phrase_

```bash
"choose file" site:$WEBSITE 
```

_Cache_

```bash
cache:"$WEBSITE"
```

#### [Shodan](https://www.shodan.io/)&#x20;

_Port_

```bash
port:22
```

_Country_

```bash
country:"IR"
```

_City_

```bash
city:"Tehran"
```

_Organization_

```bash
org:"United States Department"
```

_Product_

```bash
product:"Apache"
```

_Date_

```bash
product:"apache" after:"22/02/2009" before:"14/3/2010"
```

#### [Censys](https://search.censys.io/)

_Service_

```bash
services.service_name: "HTTP"
```

_Country_

```bash
location.country: "Iran"
```

_TLS Cipher_

```bash
services.tls.certificate.parsed.subject.common_name: "$WEBSITE"
```

_ASN_

```bash
autonomous_system.asn: 15169
```

_Banner_

```bash
services.banner: "Apache"
```

#### [Zoomeye](https://www.zoomeye.hk/)

_Port_

```bash
port:80
```

_Application_

```bash
app:"Apache"
```

_Country_

```bash
country:"Iran"
```

_IP_

```bash
ip:"$TARGET"
```

_City_

```bash
city:"Tehran"
```

_OS_

```bash
os:"Windows"
```

### Useful Website

{% embed url="https://osintframework.com/" %}

{% embed url="https://crt.sh/" %}

{% embed url="http://web.archive.org/" %}

{% embed url="https://lookup.icann.org/" %}

{% embed url="https://builtwith.com/" %}

{% embed url="http://www.whatcms.org/" %}

### Whois

_Whois_

{% embed url="https://whois.domaintools.com/" %}

{% embed url="https://lookup.icann.org/" %}

{% embed url="https://who.is/" %}

{% embed url="https://www.whoxy.com/" %}

{% embed url="https://www.godaddy.com/en-ca/whois" %}

_Revers Whois_

{% embed url="https://viewdns.info/reversewhois/" %}

{% embed url="https://www.whoxy.com/reverse-whois/" %}

{% embed url="https://www.reversewhois.io/" %}

{% embed url="https://osint.sh/reversewhois/" %}

### DNS

{% embed url="https://dnsdumpster.com/" %}

{% embed url="http://searchdns.netcraft.com/" %}

{% embed url="https://viewdns.info/" %}

### IP Address

{% embed url="https://securitytrails.com/" %}

### [Maltego](https://www.maltego.com/)

_Domain Scan_

`Run Machine > URL To Network And Domain Information > Fill in Input your Target > Right Click Domain > All Transforms`

_Create New Graph_

`Application Menu > New`

`Entity Palette > Infrastructure > Drag & Drop Domain > Enter Domain Name`

_Get IP Address_

`Right-click Domain > Run Transforms > All Transforms > [Securitytrails] DNS History Field A`

_DNS Records_

`Right-click Domain > Run Transforms > All Transforms > [WhoisXML] DNS lookup`

_Name Servers_

`Right-click Domain > Run Transforms > All Transforms > [Securitytrails] DNS History Field NS`

`Right-click Domain > Run Transforms > All Transforms > To DNS Name - NS`

_Mail Servers_

`Right-click Domain > Run Transforms > All Transforms > To DNS Name - MX`

_Whois Information_

`Right-click Domain > Run Transforms > Domain owner detail`

`Right-click Domain > Run Transforms > Domain owner detail > To Entities from WHOIS [IBM Watson]`

`Right-click Domain > Run Transforms > Domain owner detail > To Entities from WHOIS > To WHOIS Records [Whois XML]`

_Emails Related to Domain_

`Right-click Domain > Run Transforms > Find in Entity Properties > To E-Mail addresses [within Properties]`

`Right-click Domain > Run Transforms > hunter > Find Email Address [Hunter]`

_Subdomains_

`Right-click Domain > Run Transforms > All Transforms > [Securitytrails] List Subdomains`

`Right-click Domain > Run Transforms > All Transforms > To Subdomains (+Historical)[Shodan]`

`Right-click Domain > Run Transforms > All Transforms > To Subdomains(Passive DNS)[OTX]`

`Right-click Domain > Run Transforms > All Transforms > To Subdomains[Shodan]`

`Right-click Domain > Run Transforms > All Transforms > To Subdomains[VirusTotal Public API]`

_Phone Numbers_

`Right-click Domain > Run Transforms > To Phone numbers [From whois info]`

`Right-click Domain > Run Transforms > To Phone Numbers [using Search Engine]`

`Right-click Domain > Run Transforms > To Phone Numbers [within Properties]`

### [Recon-NG](https://github.com/lanmaster53/recon-ng)

_Run Recon-ng_

```bash
recon-ng
```

_List Commands_

```bash
[recon-ng][default] > help
```

_View All Modules_

```bash
[recon-ng][default] > marketplace search
```

_Install a Module_

```bash
[recon-ng][default] > marketplace install recon/domains-contacts/hunter_io
```

_Load a Module_

```bash
[recon-ng][default] > modules load hunter_io
```

_List Module Options_

```bash
[recon-ng][default][hunter_io] > options list
```

_Set Module Options_

```bash
[recon-ng][default][hunter_io] > options set SOURCE $WEBSITE
```

_Run Module_

```bash
[recon-ng][default][hunter_io] > run
```

_List API Keys_

```bash
[recon-ng][default] > keys list
```

_Add API Key_

```bash
[recon-ng][default] > keys add hunter_io 9918b4ea[...]b46a73f071 
```

_Remove API Key_

```bash
[recon-ng][default] > keys remove hunter_io 
```

### Metadata Extraction

#### [Metagoofil](https://github.com/laramies/metagoofil)

```bash
metagoofil -d $WEBSITE -t pdf,xls,xlsx,csv -l 100 -n 7 -f ~/result.html
```

#### [**ExifTool**](https://github.com/exiftool/exiftool)

```bash
exiftool $FILE
```

#### [FOCA](https://github.com/ElevenPaths/FOCA)

`Application Menu > Project > New Project > Fill the Inputs > Create > Select Path for Result > Select Extensions and Search Engine > Search All`&#x20;
