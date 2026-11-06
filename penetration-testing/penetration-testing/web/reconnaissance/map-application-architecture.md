# Map Application Architecture

## Check List&#x20;

* [ ] Generate a map of the application at hand based on the research conducted.

## Methodology

#### Application Components

{% stepper %}
{% step %}
Perform a stealth TCP scan on common web ports to detect server software and versions, extracting server headers to identify technologies like Apache or Nginx for vulnerability mapping
{% endstep %}

{% step %}
Use a web fingerprinting tool to analyze the target, identifying server-side technologies, CMS, or frameworks, and cross-referencing with known exploits
{% endstep %}

{% step %}
Fetch HTTP headers to extract server details, such as software version or custom headers, to confirm the web server stack and assess misconfigurations
{% endstep %}

{% step %}
Scan web ports with enumeration scripts to identify PaaS-specific headers or patterns, detecting platforms like Heroku or Google App Engine
{% endstep %}

{% step %}
Conduct passive subdomain enumeration to uncover PaaS-hosted subdomains, revealing cloud-based infrastructure tied to the target
{% endstep %}

{% step %}
Query DNS records with a wordlist to identify subdomains potentially hosted on PaaS platforms, expanding the attack surface
{% endstep %}

{% step %}
Search for PaaS-specific terms in HTTP response bodies to confirm the presence of cloud platforms like Azure or Heroku, prioritizing tests for platform-specific misconfigurations
{% endstep %}

{% step %}
Scan web ports with scripts to detect serverless indicators, such as Lambda or Cloud Functions, by analyzing response headers, titles, or body content
{% endstep %}

{% step %}
Query response bodies for serverless-related terms to identify functions hosted on platforms like AWS Lambda or Azure Functions, assessing exposure risks
{% endstep %}

{% step %}
Use fingerprinting tools to confirm serverless environments, checking for unique response patterns or API gateway references
{% endstep %}

{% step %}
Perform port scanning with enumeration scripts to identify microservices-related endpoints, such as Kubernetes or Docker, by analyzing headers and titles
{% endstep %}

{% step %}
Run a Kubernetes-specific scanning tool on suspected cluster IPs to detect exposed nodes, services, or APIs, identifying misconfigured microservices
{% endstep %}

{% step %}
Use a web vulnerability scanner to enumerate paths and detect microservices frameworks, checking for common configuration files or API endpoints
{% endstep %}

{% step %}
Search response bodies for microservices-related terms like Kubernetes or service mesh to confirm the architecture and prioritize testing for orchestration vulnerabilities
{% endstep %}

{% step %}
Scan web ports with scripts to identify static storage endpoints, such as S3 buckets or Google Cloud Storage, by analyzing response headers or body content
{% endstep %}

{% step %}
Execute a bucket enumeration tool to brute-force cloud storage names associated with the target, identifying publicly accessible or misconfigured buckets
{% endstep %}

{% step %}
Run a cloud-specific scanning tool to detect exposed storage services across AWS, Google Cloud, or Azure, checking for sensitive data exposure
{% endstep %}

{% step %}
Query response bodies for cloud storage signatures to confirm the presence of S3, GCS, or Azure Blob Storage, assessing risks like public read access
{% endstep %}

{% step %}
Extract IPv4 ranges for major cloud providers (Google, AWS, Azure) by querying their public IP range APIs, identifying potential cloud-hosted assets
{% endstep %}

{% step %}
Filter cloud IP ranges for a specific region (e.g., us-east-1) to narrow reconnaissance to the target’s likely infrastructure, reducing irrelevant results
{% endstep %}

{% step %}
Perform high-speed port scanning on identified cloud IP ranges, focusing on web ports to discover live hosts and services
{% endstep %}

{% step %}
Extract IPs with open TLS ports from scan results, prioritizing them for certificate analysis to uncover associated domains or subdomains
{% endstep %}

{% step %}
Analyze TLS certificates for extracted IPs to retrieve subject details, linking IPs to target domains or identifying wildcard certificates
{% endstep %}

{% step %}
Parse TLS scan results to extract subject common names (CN) and map them to IPs, confirming ownership and identifying related assets
{% endstep %}

{% step %}
Scan common database ports (e.g., 3306 for MySQL, 5432 for PostgreSQL) with scripts to identify database services, versions, and configurations
{% endstep %}

{% step %}
Connect to database ports to retrieve banners or version information, confirming the presence of MySQL, PostgreSQL, or MSSQL instances
{% endstep %}

{% step %}
Use a fingerprinting tool to detect database-related technologies in the web stack, cross-referencing with port scan findings
{% endstep %}

{% step %}
Run automated database scanners to enumerate version details for MySQL or PostgreSQL, identifying vulnerabilities like outdated versions or weak authentication
{% endstep %}

{% step %}
Query a network intelligence platform for database services (e.g., MySQL, MSSQL) to confirm exposed instances and assess access risks
{% endstep %}

{% step %}
Scan web ports with authentication-specific scripts to detect login pages or authentication endpoints, identifying potential targets for credential testing
{% endstep %}

{% step %}
Perform SSH port scanning to enumerate supported authentication methods, checking for weak or unsupported methods like password-based login
{% endstep %}

{% step %}
Use a fingerprinting tool to identify authentication-related technologies or frameworks, confirming the presence of login interfaces
{% endstep %}

{% step %}
Query response headers for WWW-Authenticate or SSH banners to detect authentication mechanisms, prioritizing tests for misconfigured access controls
{% endstep %}

{% step %}
Scan web ports with enumeration scripts to identify third-party services or APIs, analyzing headers and titles for integration clues
{% endstep %}

{% step %}
Use a fingerprinting tool to detect third-party SDKs, CDNs, or APIs embedded in the website, noting their versions for vulnerability research
{% endstep %}

{% step %}
Fetch the website’s content and search for API, CDN, or SDK references in the response body, identifying external service dependencies
{% endstep %}

{% step %}
Enumerate paths with a directory scanner, targeting extensions like .api, .json, or .xml to uncover API endpoints or webhook configurations
{% endstep %}

{% step %}
Query DNS records to identify third-party service domains, such as CDNs or cloud APIs, linked to the target
{% endstep %}

{% step %}
Perform subdomain enumeration to discover third-party-hosted subdomains, expanding reconnaissance to external integrations
{% endstep %}

{% step %}
Search response bodies for terms like “api” or “webhook” to confirm third-party service integrations, assessing risks like exposed API keys or misconfigured webhooks
{% endstep %}
{% endstepper %}

***

#### Network Components

{% stepper %}
{% step %}
Perform a stealth TCP scan on common web ports to identify server headers and reverse proxy indicators, extracting software details like Nginx or Apache to confirm proxy presence
{% endstep %}

{% step %}
Use a web fingerprinting tool to analyze the target, detecting reverse proxy technologies or configurations through response patterns or headers
{% endstep %}

{% step %}
Fetch HTTP headers to inspect server or proxy-specific headers, identifying signatures of reverse proxies like HAProxy or Nginx
{% endstep %}

{% step %}
Query DNS records to map the target’s infrastructure, checking for CNAMEs or IPs that suggest proxying through external services
{% endstep %}

{% step %}
Run a WAF detection tool to identify if a reverse proxy is paired with a web application firewall, noting its type for potential bypass testing
{% endstep %}

{% step %}
Search a network intelligence platform for headers indicating reverse proxy software, confirming the use of Nginx, Apache, or HAProxy in the target’s stack
{% endstep %}

{% step %}
Scan web ports with scripts to detect load balancer signatures, analyzing server headers for indicators like F5 or AWS ELB
{% endstep %}

{% step %}
Use a fingerprinting tool to identify load balancer technologies, checking for patterns in responses that suggest traffic distribution
{% endstep %}

{% step %}
Send multiple HTTP header requests to the target, observing variations in server headers or response times to detect load balancer presence across multiple backend servers
{% endstep %}

{% step %}
Query a network intelligence platform for headers associated with load balancers like Nginx, HAProxy, or AWS ELB, confirming their role in the infrastructure
{% endstep %}

{% step %}
Perform a stealth TCP scan with scripts to trace HTTP responses, identifying CDN-specific headers or behaviors from providers like Cloudflare or Akamai
{% endstep %}

{% step %}
Use a fingerprinting tool to detect CDN usage, analyzing response headers or content delivery patterns for CDN-specific signatures
{% endstep %}

{% step %}
Fetch HTTP headers to identify CDN providers through server headers or custom headers like CF-Ray for Cloudflare or X-Akamai for Akamai
{% endstep %}

{% step %}
Query DNS records to check for CNAMEs pointing to CDN providers, confirming the use of services like Amazon CloudFront or Fastly
{% endstep %}

{% step %}
Search a network intelligence platform for headers indicating CDN presence, verifying providers like Cloudflare, Akamai, or Fastly in the target’s infrastructure
{% endstep %}

{% step %}
Document all findings, including header details, DNS records, and detected components, to create a comprehensive proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of identified components, such as misconfigured proxies, load balancers, or CDNs, to prioritize reporting based on potential vulnerabilities like header manipulation or cache poisoning
{% endstep %}
{% endstepper %}

***

#### Security Components

{% stepper %}
{% step %}
Perform a stealth TCP scan with firewall bypass scripts to identify software-based firewalls, testing evasion techniques and analyzing responses for firewall signatures
{% endstep %}

{% step %}
Use a web fingerprinting tool to detect firewall technologies through response patterns, headers, or blocked requests that indicate filtering
{% endstep %}

{% step %}
Query a network intelligence platform for services on web ports with firewall-related server headers, confirming the presence of network-level filtering
{% endstep %}

{% step %}
Execute a targeted port scan on web ports with WAF fingerprinting scripts to detect WAF technologies, analyzing blocking responses or custom error pages
{% endstep %}

{% step %}
Run a cloud lookup module to identify cloud-based WAF services like Cloudflare, AWS WAF, or Akamai, mapping the target's WAF infrastructure
{% endstep %}

{% step %}
Use a fingerprinting tool to detect WAF presence through behavioral analysis of HTTP responses and error patterns
{% endstep %}

{% step %}
Fetch HTTP headers to inspect server or WAF-specific headers, identifying providers like ModSecurity, Cloudflare, or Imperva
{% endstep %}

{% step %}
Deploy a specialized WAF detection tool to confirm WAF type and version, testing various payloads to trigger blocking responses and fingerprint the protection layer
{% endstep %}

{% step %}
Search a network intelligence platform for WAF-specific server headers, verifying the presence of ModSecurity, Cloudflare, Imperva, or AWS WAF in the target's stack
{% endstep %}

{% step %}
Document all WAF findings, including detection method, WAF type, and blocking behavior, to create a comprehensive proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess WAF bypass potential by testing various payloads, encodings, or request patterns to identify weaknesses or evasion opportunities for further testing
{% endstep %}

{% step %}
Evaluate the impact of identified security components, such as misconfigured firewalls or bypassable WAFs, to prioritize reporting based on potential exploitation severity
{% endstep %}
{% endstepper %}

***

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

{% hint style="info" %}
Identifying Cloud Based WAFs
{% endhint %}

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
