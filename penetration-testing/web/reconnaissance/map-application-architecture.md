# Map Application Architecture

## Check List&#x20;

* [ ] Generate a map of the application at hand based on the research conducted.

## Cheat Sheet

### Application Components <a href="#application-components" id="application-components"></a>

#### **Web Server**

#### [Nmap](https://nmap.org/)

```bash
nmap -p 80,443 -sS -sV --mtu 5000 --script http-server-header $WEBSITE
```

[Whatweb](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Curl](https://curl.se/download.html)

```bash
curl -I $WEBSITE
```

#### [Censys](https://search.censys.io/)

```bash
services.http.response.headers: (key: "Server" and value.headers: "*")
```

#### **Platform-as-a-Service**&#x20;

#### [Nmap](https://nmap.org/)

```bash
nmap -p 80,443 -sS -sV --mtu 5000 --script http-server-header,http-enum $WEBSITE
```

#### [Amass](https://github.com/owasp-amass/amass)

```bash
amass enum -passive -d $WEBSITE
```

#### [DNSEnum](https://github.com/SparrowOchon/dnsenum2)

```bash
dnsenum $WEBSITE -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

#### [Censys ](https://search.censys.io/)

```bash
services.http.response.body: {"cloud", "platform", "app engine", "heroku", "azurewebsites"}
```

#### **Serverless**

#### [Nmap ](https://nmap.org/)

```bash
nmap -sS -sV --mtu 5000 --script http-enum,http-title,http-headers $WEBSITE
```

#### [Censys ](https://search.censys.io/)

```bash
services.http.response.body: {"lambda", "cloud functions", "azure functions", "serverless"}
```

#### **Microservices**

#### [Nmap](https://nmap.org/)

```bash
nmap -sS -sV --mtu 5000 --script http-enum,http-title,http-headers $WEBSITE
```

#### [Kube-Hunter](https://github.com/aquasecurity/kube-hunter)

```bash
kube-hunter --remote $CLUSTER
```

#### [Nikto](https://github.com/sullo/nikto)

```bash
nikto -h $WEBSITE
```

#### [Curl](https://curl.se/download.html)

```bash
curl -I $WEBSITE
```

#### [Censys](https://search.censys.io/)

```bash
services.http.response.body: {"microservices", "kubernetes", "docker", "service mesh"}
```

#### **Static Storage**

#### [Nmap](https://nmap.org/)

```bash
nmap -sS -sV --mtu 5000 --script http-enum,http-title,http-headers $WEBSITE
```

#### [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)

```bash
gcpbucketbrute -k $USER -u
```

#### [CloudHunter](https://github.com/belane/CloudHunter)

```bash
cloudhunter $WEBSITE
```

#### [Censys ](https://search.censys.io/)

```bash
services.http.response.body: {"s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net"}
```

#### Enum Clouds

Extract Cloud IPv4 Ranges

{% hint style="info" %}
Extract Cloud IPv4 Ranges
{% endhint %}

{% hint style="info" %}
Google
{% endhint %}

```bash
wget -qO- https://www.gstatic.com/ipranges/cloud.json | \
jq '.prefixes[] | .ipv4Prefix' -r
```

{% hint style="info" %}
Amazon
{% endhint %}

```bash
wget -qO- https://ip-ranges.amazonaws.com/ip-ranges.json | \
jq '.prefixes[] | .ip_prefix' -r
```

{% hint style="info" %}
Azure
{% endhint %}

```bash
jq < /path_file/ServiceTags_Public_*.json '.values | .[] | .properties.addressPrefixes | .[]' -r
```

**Scanning Large Ranges**

{% hint style="info" %}
Amazon
{% endhint %}

```bash
wget -qO- https://ip-ranges.amazonaws.com/ip-ranges.json | \
jq '.prefixes[] | if .region=="us-east-1" then .ip_prefix else empty end' -r | \
sort -u > /tmp/range-ip-output.txt
```

[Msscan](https://github.com/robertdavidgraham/masscan)

```bash
masscan -iL /tmp/range-ip-output.txt -oL /tmp/range-ip-output.masscan -p 80,443 --rate 10000000 && head -25 /tmp/range-ip-output.masscan
```

[awk](https://linux.die.net/man/1/awk)

```bash
awk '/open/ {print $4}' /tmp/range-ip-output.masscan > /tmp/range-ip-output.tlsopen && head -25 /tmp/range-ip-output.tlsopen
```

**Attributing Hosts**

{% hint style="info" %}
Extract TLS IP
{% endhint %}

```bash
head -1 /tmp/range-ip-output.tlsopen && export IP=$(head -1 /tmp/range-ip-output.tlsopen)
```

{% hint style="info" %}
OpenSSL
{% endhint %}

```bash
openssl s_client -connect $IP:443 2>/dev/null | \
openssl x509 -text | \
grep Subject:
```

**TLS Scan**

{% hint style="info" %}
TLS Test
{% endhint %}

```bash
echo $IP | \
tls-scan --port=443 --cacert=ca-bundle.crt -o /tmp/range-ip-output-tlsinfo.json
```

**Interpreting TLS Scan Results**

{% hint style="info" %}
Extract Subject
{% endhint %}

```bash
cat /tmp/range-ip-output-tlsinfo.json | \
jq '[.ip, .certificateChain[].subjectCN] | join(",")' -r > /tmp/range-ip-output-tlsinfo.csv | \
head -2 /tmp/range-ip-output-tlsinfo.csv
```

#### **Database**

#### [Nmap ](https://nmap.org/)

```bash
nmap -p 3306,5432,1433,1521 \
     -sS -sV --mtu 5000 \
     --script db2-das-info,mysql-info,ms-sql-info,mongodb-info,oracle-tns-version $WEBSITE
```

#### [Netcat ](https://nmap.org/ncat/)

```bash
nc $WEBSITE 3306
```

#### [Whatweb](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Metasploit](https://www.metasploit.com/)

```bash
msfconsole -qx "
    use auxiliary/scanner/mysql/mysql_version;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

```bash
msfconsole -qx "
    use auxiliary/scanner/postgres/postgres_version;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

#### [Censys ](https://search.censys.io/)

```bash
services.service_name: {MYSQL, POSTGRES, MSSQL}
```

#### **Authentication**

#### [Nmap ](https://nmap.org/)

{% hint style="info" %}
Identifying Authentication Services Using Related Scripts
{% endhint %}

```bash
nmap -sS -sV --mtu 5000 --script http-auth-finder $WEBSITE
```

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
&#x20;Checking SSH-Based Authentication
{% endhint %}

```bash
nmap -p 22 -sS -sV --mtu 5000 --script ssh-auth-methods $WEBSITE
```

#### [Whatweb](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Censys ](https://search.censys.io/)

```bash
services: (http.response.headers: (key: "WWW-Authenticate" and value.headers: *)) and services.port: 80 or services: (service_name: SSH and banner: * and port: 22)
```

#### **Third Party Services and APIs**

#### [Nmap ](https://nmap.org/)

```bash
nmap -p 80,443 -sS -sV --mtu 5000 --script http-enum $WEBSITE
```

#### [Whatweb ](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Curl ](https://curl.se/download.html)

```bash
wget -qO- $WEBSITE | grep -E "api|cdn|sdk"
```

#### [Dirsearch](https://github.com/maurosoria/dirsearch)

```bash
dirsearch -u $WEBSITE -e api,php,json,xml
```

#### Dig

```bash
dig $WEBSITE
```

#### [Amass](https://github.com/owasp-amass/amass)

```bash
amass enum -d $WEBSITE
```

#### [Censys ](https://search.censys.io/)

```bash
services.http.response.body: {"api", "third-party", "integration", "webhook"}
```

### Network Components <a href="#network-components" id="network-components"></a>

#### **Reverse Proxy**

#### [Nmap ](https://nmap.org/)

```bash
nmap -p 80,443 -sS -sV --mtu 5000 --script http-server-header,reverse-index $WEBSITE
```

#### [Whatweb](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Curl ](https://curl.se/download.html)

```bash
curl -I $WEBSITE
```

#### [DNSRecon](https://github.com/darkoperator/dnsrecon)

```bash
dnsrecon -d $WEBSITE
```

#### [wafw00f](https://github.com/EnableSecurity/wafw00f)

```bash
wafw00f $WEBSITE
```

#### [Censys ](https://search.censys.io/)

```bash
services.http.response.headers: (key: "Server" and value.headers: {"nginx", "Apache", "HAProxy"})
```

#### **Load Balancer**

#### [Nmap](https://nmap.org/)

```bash
nmap -p 80,443 -sS -sV --mtu 5000 --script http-server-header $WEBSITE
```

#### [Whatweb ](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Curl ](https://curl.se/download.html)

```bash
for i in {1..10}; do curl -I $WEBSITE; done        
```

#### [Censys ](https://search.censys.io/)

```bash
services.http.response.headers: (key: "Server" and value.headers: {"nginx", "HAProxy", "F5", "AWS ELB"})
```

#### **Content Delivery Network**&#x20;

[**Nmap**](https://nmap.org/)

```bash
nmap -p 80,443 
     -sS -sV --mtu 5000 
     --script http-trace --script-args=http-trace.host=$WEBSITE $WEBSITE
```

#### [Whatweb](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Curl](https://curl.se/download.html)

```bash
curl -I $WEBSITE
```

#### Dig&#x20;

```bash
dig $WEBSITE
```

#### [Censys](https://search.censys.io/)

```bash
services.http.response.headers: (key: "Server" and value.headers: {"Cloudflare", "Akamai", "Fastly", "Amazon CloudFront"})
```

### Security Components <a href="#security-components" id="security-components"></a>

#### **Network Firewall**

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
&#x20;Identifying Software-Based Firewalls
{% endhint %}

```bash
nmap -sS -sV --mtu 5000 --script firewall-bypass $WEBSITE
```

#### [Whatweb ](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Censys](https://search.censys.io/)

```bash
services: (port: {80, 443} and http.response.headers: (key: "Server" and value.headers: "*Firewall*"))
```

#### **Web Application Firewall**&#x20;

#### [Nmap ](https://nmap.org/)

```bash
nmap -p 80,443 -sS -sV --mtu 5000 --script http-waf-fingerprint $WEBSITE
```

#### [Metasploit](https://www.metasploit.com/)

_Identifying Cloud Based WAFs_

```bash
msfconsole -qx "use auxiliary/gather/cloud_lookup;set HOSTNAME $WEBSITE;run;exit"
```

#### [Whatweb ](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [Curl ](https://curl.se/download.html)

```bash
curl -I $WEBSITE
```

#### [Wafw00f](https://www.google.com/url?sa=t\&source=web\&rct=j\&opi=89978449\&url=https://github.com/EnableSecurity/wafw00f\&ved=2ahUKEwjCjuW1y72JAxWfT6QEHbawO-sQFnoECBcQAQ\&usg=AOvVaw3tty-vJLqjI9Qi4sNKb0Kv)

```bash
wafw00f $WEBSITE
```

#### [Censys](https://search.censys.io/)

```bash
services.http.response.headers: (key: "Server" and value.headers: {"ModSecurity", "Cloudflare", "Imperva", "AWS WAF"})
```
