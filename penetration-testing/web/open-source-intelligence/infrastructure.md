# Infrastructure

## Check List

* [ ] Use search engines for basic information gathering.
* [ ] Explore specialized websites for additional insights.
* [ ] Perform Whois lookups for domain information.
* [ ] Investigate DNS records for domain details.
* [ ] Check IP addresses for location and hosting information.
* [ ] Network mapping and relationship analysis.
* [ ] Utilize Recon-NG for automated data gathering.
* [ ] Extract metadata from files and images.

## Cheat Sheet

### Search Engine&#x20;

#### [Google](https://www.exploit-db.com/google-hacking-database)

{% hint style="info" %}
Sub Domains
{% endhint %}

```bash
site:$WEBSITE
```

{% hint style="info" %}
HTTP Title
{% endhint %}

```bash
intitle:"login" |
intitle:"admin" |
intitle:"administrator"
site:$WEBSITE
```

{% hint style="info" %}
URI
{% endhint %}

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

{% hint style="info" %}
File Types
{% endhint %}

```bash
filetype:pdf |
filetype:csv |
filetype:xls |
filetype:xlsx
site:$WEBSITE
```

{% hint style="info" %}
Extensions
{% endhint %}

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

{% hint style="info" %}
Exact Phrase
{% endhint %}

```bash
"choose file" site:$WEBSITE 
```

{% hint style="info" %}
Cache
{% endhint %}

```bash
cache:"$WEBSITE"
```

#### [Shodan](https://www.shodan.io/)&#x20;

{% hint style="info" %}
Port
{% endhint %}

```bash
port:22
```

{% hint style="info" %}
Country
{% endhint %}

```bash
country:"IR"
```

{% hint style="info" %}
City
{% endhint %}

```bash
city:"Tehran"
```

{% hint style="info" %}
Organization
{% endhint %}

```bash
org:"United States Department"
```

{% hint style="info" %}
Product
{% endhint %}

```bash
product:"Apache"
```

{% hint style="info" %}
Date
{% endhint %}

```bash
product:"apache" after:"22/02/2009" before:"14/3/2010"
```

#### [Censys](https://search.censys.io/)

{% hint style="info" %}
Service
{% endhint %}

```bash
services.service_name: "HTTP"
```

{% hint style="info" %}
Country
{% endhint %}

```bash
location.country: "Iran"
```

{% hint style="info" %}
TLS Cipher
{% endhint %}

```bash
services.tls.certificate.parsed.subject.common_name: "$WEBSITE"
```

{% hint style="info" %}
ASN
{% endhint %}

```bash
autonomous_system.asn: 15169
```

{% hint style="info" %}
Banner
{% endhint %}

```bash
services.banner: "Apache"
```

#### [Zoomeye](https://www.zoomeye.hk/)

{% hint style="info" %}
Port
{% endhint %}

```bash
port:80
```

{% hint style="info" %}
Application
{% endhint %}

```bash
app:"Apache"
```

{% hint style="info" %}
Country
{% endhint %}

```bash
country:"Iran"
```

{% hint style="info" %}
IP
{% endhint %}

```bash
ip:"$TARGET"
```

{% hint style="info" %}
City
{% endhint %}

```bash
city:"Tehran"
```

{% hint style="info" %}
OS
{% endhint %}

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

{% hint style="info" %}
Whois
{% endhint %}

{% embed url="https://whois.domaintools.com/" %}

{% embed url="https://lookup.icann.org/" %}

{% embed url="https://who.is/" %}

{% embed url="https://www.whoxy.com/" %}

{% embed url="https://www.godaddy.com/en-ca/whois" %}

{% hint style="info" %}
Revers Whois
{% endhint %}

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

{% hint style="info" %}
Domain Scan
{% endhint %}

{% hint style="warning" %}
Run Machine > URL To Network And Domain Information > Fill in Input your Target > Right Click Domain > All Transforms
{% endhint %}

{% hint style="info" %}
Create New Graph
{% endhint %}

{% hint style="warning" %}
Application Menu > New
{% endhint %}

{% hint style="warning" %}
Entity Palette > Infrastructure > Drag & Drop Domain > Enter Domain Name
{% endhint %}

{% hint style="info" %}
Get IP Address
{% endhint %}

{% hint style="warning" %}
Right-click Domain > Run Transforms > All Transforms > \[Securitytrails] DNS History Field A
{% endhint %}

{% hint style="info" %}
DNS Records
{% endhint %}

{% hint style="warning" %}
Right-click Domain > Run Transforms > All Transforms > \[WhoisXML] DNS lookup
{% endhint %}

{% hint style="info" %}
Name Servers
{% endhint %}

{% hint style="warning" %}
Right-click Domain > Run Transforms > All Transforms > \[Securitytrails] DNS History Field NS
{% endhint %}

{% hint style="warning" %}
Right-click Domain > Run Transforms > All Transforms > To DNS Name - NS
{% endhint %}

{% hint style="info" %}
Mail Servers
{% endhint %}

{% hint style="warning" %}
Right-click Domain > Run Transforms > All Transforms > To DNS Name - MX
{% endhint %}

{% hint style="info" %}
Whois Information
{% endhint %}

{% hint style="warning" %}
Right-click Domain > Run Transforms > Domain owner detail
{% endhint %}

{% hint style="warning" %}
Right-click Domain > Run Transforms > Domain owner detail > To Entities from WHOIS \[IBM Watson]
{% endhint %}

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
