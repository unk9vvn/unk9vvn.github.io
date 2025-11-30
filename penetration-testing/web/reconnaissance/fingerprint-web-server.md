# Fingerprint Web Server

## Check List

* [ ] Determine the version and type of running web server to enable further discovery of any known vulnerabilities.

## Methodology

#### Banner Grabbing

{% stepper %}
{% step %}
Connect to the target website’s HTTP service to retrieve server banners, identifying software and version details for potential vulnerability mapping
{% endstep %}

{% step %}
Manually interact with the HTTP service to capture raw server responses, extracting information about server software, custom headers, or configurations
{% endstep %}

{% step %}
Fetch HTTP headers from the target to analyze server details, powered-by information, or security headers, uncovering potential misconfigurations or outdated software
{% endstep %}

{% step %}
Perform stealth scanning and service enumeration on the target, using scripts to extract page titles, headers, supported HTTP methods, and favicon details, building a comprehensive profile of the web server
{% endstep %}

{% step %}
Use an online service to query the target’s technology stack, gathering details about CMS, frameworks, hosting providers, or server software for reconnaissance
{% endstep %}

{% step %}
Leverage a DNS reconnaissance tool to enumerate subdomains, DNS records, and associated IP addresses, mapping the target’s infrastructure and potential entry points
{% endstep %}

{% step %}
Search for web servers by their server header to identify instances running specific software, narrowing down targets for version-specific exploit research
{% endstep %}

{% step %}
Query SSL certificate fingerprints (SHA-1 or SHA-256) to locate hosts with matching certificates, revealing related domains or misconfigured SSL setups
{% endstep %}

{% step %}
Identify hosts by SSL certificate common name (CN) to uncover subdomains or assets tied to the target, expanding the attack surface for testing
{% endstep %}

{% step %}
Detect operating systems via response headers to identify server OS types, prioritizing outdated or vulnerable systems for exploit targeting
{% endstep %}

{% step %}
Search for powered-by headers to identify backend technologies like PHP or ASP.NET, assessing version-specific vulnerabilities or misconfigurations
{% endstep %}
{% endstepper %}

***

#### Using Automated Scanning Tools

{% stepper %}
{% step %}
Run a WAF detection tool to identify the presence and type of web application firewall, analyzing bypass opportunities or WAF-specific weaknesses
{% endstep %}

{% step %}
Use an automated WAF identification tool to confirm firewall presence and fingerprint its technology, aiding in crafting payloads to evade protections
{% endstep %}

{% step %}
Execute a web fingerprinting tool to detect CMS, frameworks, and server technologies, building a detailed profile of the target’s stack for vulnerability prioritization
{% endstep %}

{% step %}
Deploy an automated reconnaissance suite to perform comprehensive scanning, combining subdomain enumeration, port scanning, and vulnerability checks for a holistic assessment
{% endstep %}

{% step %}
Conduct a web vulnerability scan to identify common issues like XSS, SQLi, or misconfigurations, prioritizing findings based on severity and exploitability
{% endstep %}

{% step %}
Fingerprint GraphQL endpoints on the target to detect exposed APIs, analyzing schema details or misconfigurations for potential data exposure or injection attacks
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Banner Grabbing

#### [**Netcat**](https://sectools.org/tool/netcat/)

```shell
nc -v $WEBSITE 80
```

#### [Telnet](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/telnet)

```bash
telnet $WEBSITE 80
```

#### [Curl](https://curl.se/download.html)

```bash
curl -I $WEBSITE
```

#### [**Nmap**](https://nmap.org/)

```bash
nmap -sS -sV -Pn --mtu 5000 \
     --script http-title,http-headers,http-server-header,http-security-headers,http-methods,http-put,http-robots.txt,http-favicon \
     $WEBSITE
```

#### NetCraft

{% embed url="https://sitereport.netcraft.com/" %}

#### Dnsdumpster

{% embed url="https://dnsdumpster.com/" %}

#### [Censys](https://search.censys.io/)

Server Header

```bash
uncover -cs 'services.http.response.headers.server: "nginx"'
```

SSL Certificate SHA-1 Fingerprint

```bash
uncover -cs 'services.tls.certificates.leaf_data.fingerprint_sha1: $HASH'
```

SSL Certificate SHA-256 Fingerprint

```bash
uncover -cs 'services.tls.certificates.leaf_data.fingerprint_sha256: $HASH'
```

Common Name (CN) in SSL Certificate

```bash
uncover -cs 'services.tls.certificates.leaf_data.subject.common_name: "$WEBSITE"'
```

Operating System

```bash
uncover -cs 'services.http.response.headers: (key: "OS" and value.headers: "Linux")'
```

Powered By Header

```bash
uncover -cs 'services.http.response.headers.x_powered_by: "PHP/7.4.9"'
```

### Using Automated Scanning Tools <a href="#using-automated-scanning-tools" id="using-automated-scanning-tools"></a>

#### [WAFW00F](https://github.com/EnableSecurity/wafw00f)

```sh
wafw00f $WEBSITE
```

#### [WhatWaf](https://github.com/Ekultek/WhatWaf)

```sh
whatwaf -u $WEBSITE
```

#### [WhatWeb](https://github.com/urbanadventurer/WhatWeb)

```sh
whatweb $WEBSITE
```

#### [Sn1per](https://sn1persecurity.com/wordpress/)

```sh
sniper -t $WEBSITE
```

#### [Arachni](https://github.com/Arachni/arachni?tab=readme-ov-file)

```sh
arachni $WEBSITE
```

#### [Graphw00f](https://github.com/dolevf/graphw00f)

```sh
graphw00f -f -t $WEBSITE
```
