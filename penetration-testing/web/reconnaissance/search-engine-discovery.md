# Search Engine Discovery

## Check List <a href="#check-list" id="check-list"></a>

* [ ] Identify what sensitive design and configuration information of the application, system, or organization is exposed directly (on the organization’s website) or indirectly (via third-party services).

## Methodology

#### Google

{% stepper %}
{% step %}
Enumerate all subdomains of the target website by leveraging search queries to identify all accessible subdomains, providing a comprehensive map of potential entry points for further testing
{% endstep %}

{% step %}
Filter out common or irrelevant subdomains to focus on unique or less-secured subdomains, reducing noise and prioritizing high-value targets for vulnerability assessment
{% endstep %}

{% step %}
Identify admin-related endpoints that may handle file uploads or sensitive operations, targeting interfaces likely to expose critical functionality or misconfigurations
{% endstep %}

{% step %}
Locate login pages by searching for specific page titles, uncovering authentication interfaces that may be vulnerable to credential-based attacks or misconfigured access controls
{% endstep %}

{% step %}
Search for pages containing specific text, such as authentication-related terms, to discover hidden or misconfigured entry points that could reveal sensitive functionality
{% endstep %}

{% step %}
Enumerate files by their type, such as configuration files, PDFs, or database dumps, to identify exposed sensitive documents that may leak critical information
{% endstep %}

{% step %}
Discover configuration and backup files with specific extensions, such as `.conf`, `.bak`, or `.env`, to uncover Misconfigurations or unprotected data that could aid in exploitation
{% endstep %}

{% step %}
Identify exposed JavaScript files containing sensitive information, such as API keys, credentials, or tokens, by targeting configuration scripts in publicly accessible directories
{% endstep %}

{% step %}
Search for backup directories or cryptographic keys, like id\_rsa or id\_dsa, to reveal sensitive files that may have been inadvertently exposed due to poor access controls
{% endstep %}

{% step %}
Locate URIs with keywords indicative of sensitive functionality, such as "conf," "api," or "admin," to prioritize endpoints likely to yield vulnerabilities like LFI or unauthorized access
{% endstep %}

{% step %}
Identify API endpoints by targeting URLs with patterns like "api," "rest," or versioned paths (e.g., `/v1`, `/v2`), focusing on interfaces prone to misconfigurations or insecure access
{% endstep %}

{% step %}
Detect server errors, stack traces, or debug logs by searching for error-related terms or exposed log files, revealing misconfigured systems or sensitive debugging information
{% endstep %}

{% step %}
Find parameters vulnerable to cross-site scripting (XSS) by targeting inputs like search or query fields, testing for injection points that could allow malicious script execution
{% endstep %}

{% step %}
Identify parameters susceptible to open redirect vulnerabilities by focusing on URL-handling inputs, such as redirect or return parameters, to test for unauthorized redirection capabilities
{% endstep %}
{% endstepper %}

***

#### Shodan

{% stepper %}
{% step %}
Register with Shodan and obtain an API key to enable advanced queries and rate-limited access, facilitating integration with automated tools like CLI or Python scripts for streamlined reconnaissance
{% endstep %}

{% step %}
Identify the target organization or domain using the `filter org:"organization_name"` to narrow results to specific assets, focusing the attack surface on relevant infrastructure within the bug bounty scope
{% endstep %}

{% step %}
Discover subdomains and hosts with `hostname:"target.com"` or `ssl.cert.subject.cn:"target.com"` to uncover forgotten subdomains or SSL certificate-linked assets, revealing new entry points for testing
{% endstep %}

{% step %}
Scan for open ports using `port:"80"` or `port:"22"` to identify exposed services like web servers or SSH, prioritizing commonly vulnerable ports such as 8080 for proxies or 443 for HTTPS
{% endstep %}

{% step %}
Search for operating systems with os:"Windows Server" or os:"Linux" to find devices running outdated or known-vulnerable OS versions, enabling prioritization of tests based on exploitable systems
{% endstep %}

{% step %}
Identify software products and versions with `product:"Apache" or product:"Jenkins"` to discover outdated applications matching known CVEs, combining with `after:"2020-01-01"` to focus on recent instances
{% endstep %}

{% step %}
Filter by known vulnerabilities using `vuln:"CVE-2019-19781"` to pinpoint directly exploitable devices, prioritizing high-severity issues like RCE or data disclosure for efficient testing
{% endstep %}

{% step %}
Restrict searches geographically with `country:"US" or city:"New York"` to focus on assets in specific regions, aligning with localized or regulatory-focused bug bounty requirements
{% endstep %}

{% step %}
Search network ranges with `net:"192.168.1.0/24"` to scan organizational IP blocks, identifying internal or cloud infrastructure like staging or development servers
{% endstep %}

{% step %}
Identify specific web servers with `server:"nginx" or http.title:"Login"` to discover login pages or admin panels, highlighting potential entry points for brute-force or XSS testing
{% endstep %}

{% step %}
Search for SSL/TLS certificates with `ssl.cert.issuer.cn:"target.com"` to find related domains, uncovering wildcard subdomains or certificate misconfigurations that expand the attack surface
{% endstep %}

{% step %}
Filter by time range with `before:"2024-01-01"` `after:"2020-01-01`" to focus on recently active assets, eliminating outdated results and prioritizing current infrastructure
{% endstep %}

{% step %}
Identify device types with device:"webcam" or product:"MySQL" to discover exposed IoT or database instances, targeting risks like default credentials or misconfigured access
{% endstep %}

{% step %}
Search for SSH fingerprints with `ssh.fingerprint:"dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0`" to identify hosts with weak or reused keys, assessing potential for brute-force or MITM attacks
{% endstep %}

{% step %}
Discover PEM files or certificates with `http.title:"Index of /" http.html:".pem"` to find open directories exposing private keys, highlighting sensitive data disclosure for privilege escalation testing
{% endstep %}

{% step %}
Identify industrial control systems with `port:"502" port:"102"` to uncover exposed <sub>ICS/SCADA</sub> systems, targeting critical infrastructure risks relevant to specialized bug bounty programs
{% endstep %}

{% step %}
Search for vulnerable Exchange servers with `"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"` to identify outdated instances, facilitating tests for CVEs like ProxyLogon or RCE vulnerabilities
{% endstep %}

{% step %}
Filter SMB shares with `"Authentication: disabled" port:445` to find exposed file shares, assessing risks of unauthorized access or data leakage in organizational networks
{% endstep %}
{% endstepper %}

***

#### GitHub

{% stepper %}
{% step %}
Register for a GitHub account and obtain an API token to enable advanced search capabilities and rate-limited access, allowing integration with automated tools like CLI or Python scripts for efficient reconnaissance
{% endstep %}

{% step %}
Identify repositories related to the target organization by searching for keywords like the organization name or domain (e.g., "target.com") to uncover public Repos containing sensitive information
{% endstep %}

{% step %}
Search for sensitive configuration files using `path:/WebServer.xml` or `path:/wp-config.php` to find exposed server configurations, database credentials, or API keys inadvertently committed to repositories
{% endstep %}

{% step %}
Look for command history files with `path:**/.bash_history` to discover executed commands that may reveal sensitive operations, internal paths, or credentials exposed in public repositories
{% endstep %}

{% step %}
Identify system files like `path:/passwd path:etc` or `path:/shadow path:etc` to uncover repositories containing sensitive server files, indicating potential misconfigurations or leaks
{% endstep %}

{% step %}
Search for database credentials in configuration files with `path:**/config.php` dbpasswd to find exposed passwords or connection strings, prioritizing files likely to contain sensitive data
{% endstep %}

{% step %}
Discover API keys in code with `shodan_api_key language:python` to identify hardcoded credentials for external services, which could lead to unauthorized access if exploited
{% endstep %}

{% step %}
Find SQL dump files using `path:*.sql` mysql dump to uncover database backups containing sensitive data like user information or application schemas exposed in public repositories
{% endstep %}

{% step %}
Search for environment files with `path:**/.env` to identify misconfigured repositories exposing environment variables, such as API tokens, database credentials, or secret keys
{% endstep %}

{% step %}
Look for backup files or sensitive extensions with `path:/`_`.bak` or `path:/`_`.old` to find outdated or temporary files that may contain sensitive configurations or data
{% endstep %}

{% step %}
Identify repositories with specific frameworks like `path:/wp-config.php` for WordPress or `path:/settings.py`for Django, targeting framework-specific files prone to credential exposure
{% endstep %}

{% step %}
Use language filters like `language:python` or `language:php` to narrow searches to specific programming languages, focusing on codebases likely to contain sensitive logic or hardcoded secrets
{% endstep %}

{% step %}
Combine organization and keyword searches with `org:target_org config` to find repositories owned by the target containing specific terms like "config" or "secret," increasing the likelihood of finding sensitive data
{% endstep %}

{% step %}
Verify findings by accessing the repository and checking file contents to confirm the presence of sensitive information, such as API keys, passwords, or internal paths
{% endstep %}

{% step %}
Document all relevant findings, including repository URLs, file paths, and snippets of exposed sensitive data, to create a clear proof-of-concept for reporting
{% endstep %}

{% step %}
Assess the impact of exposed data, such as potential for unauthorized access, data leakage, or privilege escalation, to prioritize findings based on severity
{% endstep %}

{% step %}
Submit findings through the target’s responsible disclosure program, ensuring clear documentation of the repository, file, and potential impact, distinguishing from unrelated or non-exploitable leaks
{% endstep %}
{% endstepper %}

***

#### Censys

{% stepper %}
{% step %}
Register with Censys and obtain an API key to access advanced search features and rate-limited queries, enabling seamless integration with tools like the Censys CLI or Python SDK for automated reconnaissance workflows
{% endstep %}

{% step %}
Define the target scope by using `location.country: "Iran" or location.city: "Tehran"` to geographically filter results, narrowing down to regional assets relevant to localized bug bounty programs or compliance-focused assessments
{% endstep %}

{% step %}
Enumerate hosts and subdomains with `name: "target.com"` to discover exposed hosts associated with the target domain, uncovering forgotten infrastructure or wildcard configurations that expand the potential attack surface
{% endstep %}

{% step %}
Search IP ranges using `ip: [1.1.1.1 to 1.1.255.255]` to scan organizational network blocks, identifying internal servers, cloud instances, or development environments for targeted vulnerability testing
{% endstep %}

{% step %}
Identify login or authentication pages with `services.http.response.html_title: "Login Page"` to locate exposed admin interfaces, prioritizing them for brute-force, credential stuffing, or XSS assessments
{% endstep %}

{% step %}
Filter by organization or autonomous system with `autonomous_system.name: "Google"` or `autonomous_system.asn: 13335` to focus on assets owned by the target entity, ensuring results align with bug bounty scope and avoiding unrelated infrastructure
{% endstep %}

{% step %}
Detect operating systems with `operating_system.product: "Windows"` to find devices running potentially outdated OS versions, facilitating OS-specific exploit chaining or misconfiguration analysis
{% endstep %}

{% step %}
Scan for open ports using `services.port:80` to enumerate exposed services like HTTP/HTTPS, combining with other filters to prioritize high-risk ports such as 22 for SSH or 445 for SMB
{% endstep %}

{% step %}
Search for SSL/TLS certificates with `services.tls.certificate.parsed.subject.common_name: "target.com"` to uncover related domains and subdomains via certificate transparency data, revealing hidden assets or misissued certs
{% endstep %}

{% step %}
Identify software products and versions with `services.software.product: "apache" AND services.observed_at: [2020-01-01 TO 2024-01-01]` to detect outdated applications vulnerable to known CVEs, using time-based filters to focus on active, exploitable instances
{% endstep %}

{% step %}
Query server headers with `services.http.response.headers.server: "nginx"` to discover web server types and configurations, highlighting potential misconfigurations like exposed version info for targeted exploits
{% endstep %}

{% step %}
Search for SSH fingerprints using `services.ssh.v2.fingerprint_sha256: "dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0"` to identify hosts with weak or duplicated keys, assessing risks for brute-force attacks or key compromise
{% endstep %}

{% step %}
Discover exposed certificates or PEM files with `services: (http.response.html_title: "Index of /" and http.response.body: ".pem")` to find open directories leaking private keys, enabling privilege escalation or lateral movement testing
{% endstep %}

{% step %}
Filter for industrial control systems with `labels: ics` to uncover OT/SCADA devices in scope, targeting critical infrastructure exposures relevant to specialized security programs
{% endstep %}

{% step %}
Identify vulnerable Exchange servers using `services: (http.response.headers: (key: "X-AspNet-Version" and value.headers: "")` and `http.response.html_title: "Outlook"` and `not http.response.headers: (key: "x-owa-version" and value.headers: ""))`  to detect legacy versions prone to RCE like ProxyLogon
{% endstep %}

{% step %}
Enumerate SMB shares with `services: (service_name: SMB and banner: "shared_folder")` to find accessible file shares, evaluating unauthorized data access risks in networked environments
{% endstep %}

{% step %}
Search for domain controllers specifically with `"Authentication: disabled" and services: (service_name: NETLOGON and service_name: SYSVOL)` and `not operating_system.product: "unix"` and `services.port: 445` to pinpoint Windows AD exposures for credential harvesting or escalation
{% endstep %}

{% step %}
Query FTP servers for anonymous access with `services.ftp.status_code: 230` to identify open anonymous logins, testing for directory traversal or file disclosure vulnerabilities
{% endstep %}

{% step %}
Locate exposed webcams or IoT devices with `services.http.response.headers: (key: "Server" and value.headers: "Webcam")` to discover unsecured cameras, assessing default credential risks or command injection
{% endstep %}

{% step %}
Filter Android IP Webcam servers with `services.http.response.html_title: "IP Webcam"` to find mobile-exposed streams, checking for unauthorized access or integration with broader network compromises
{% endstep %}

{% step %}
Identify security DVRs with `services.http.response.html_title: "Security DVR"` to uncover surveillance systems, prioritizing tests for weak authentication or remote control exploits
{% endstep %}

{% step %}
Search for printers with `services.http.response.headers: (key: "Server" and value.headers: "Printer")` to detect networked printing devices, targeting spooler vulnerabilities or credential leaks
{% endstep %}

{% step %}
Discover Chromecast or smart TVs using `services.http.response.headers: (key: "Server" and value.headers: {"Chromecast", "Smart TV"})` to identify media devices, evaluating discovery protocol abuses or unauthorized casting
{% endstep %}

{% step %}
Query Ethereum miners with `services.http.response.html_title: "Ethereum Miner"` to find exposed mining rigs, assessing risks like unauthorized pool redirection or resource hijacking
{% endstep %}

{% step %}
Detect misconfigured WordPress instances with `services: (http.response.html_title: "WordPress"` and `http.response.headers: (key: "Favicon" and value.headers: "c4d2e77e3e9a4c8d4d2e9b6c9f6d3c6f"))` to uncover default setups vulnerable to known plugins or theme exploits
{% endstep %}

{% step %}
Enumerate services on specific ports like `services.port: {22,23,24,25}` to scan for multiple low-hanging fruits such as SSH, Telnet, or email servers in a single query
{% endstep %}

{% step %}
Search for Elasticsearch on unusual ports with `(services.service_name=ELASTICSEARCH)`and `service.port=443` to find misconfigured search engines exposing data queries or indices
{% endstep %}
{% endstepper %}

***

#### Zoomeye

{% stepper %}
{% step %}
Register with Zoomeye and obtain an API key to unlock advanced search capabilities and rate-limited queries, enabling integration with CLI tools or Python scripts for automated reconnaissance and threat intelligence gathering
{% endstep %}

{% step %}
Define the target scope by querying with `hostname: "target.com"` to enumerate hosts and subdomains associated with the target domain, uncovering exposed infrastructure or wildcard configurations that broaden the attack surface
{% endstep %}

{% step %}
Search IP addresses or ranges using `ip: "8.8.8.8"` or `cidr: "192.168.1.0/24"` to scan specific addresses or network blocks, identifying internal servers, cloud instances, or organizational assets for vulnerability prioritization
{% endstep %}

{% step %}
Filter by autonomous system number with `asn: 8978` to focus on assets within a specific network provider, aligning results with bug bounty scopes and revealing interconnected infrastructure
{% endstep %}

{% step %}
Identify open ports using `port: 80` or `port: {80,22,443}` to discover exposed services like HTTP, SSH, or HTTPS, combining with logical OR for multi-port scans to target common entry points efficiently
{% endstep %}

{% step %}
Search for operating systems with `os: "windows"` or `os: "linux"` to find devices running outdated or vulnerable OS versions, facilitating OS-specific exploit research or misconfiguration detection
{% endstep %}

{% step %}
Enumerate applications and versions using `app: "Apache"` or `ver: "2.1"` to detect software with known CVEs, prioritizing outdated instances for RCE or disclosure testing
{% endstep %}

{% step %}
Query services with `service: "http"` or `service: {"http","ssh"}` to locate specific protocols or daemons, using OR logic to uncover diverse exposed endpoints in a single search
{% endstep %}

{% step %}
Discover devices by type with `device: "router"` to identify IoT or networking gear, assessing risks like default credentials or firmware vulnerabilities in scoped environments
{% endstep %}

{% step %}
Filter geographically with `country: "IR"` or `city: "Tehran"` to narrow results to regional assets, supporting localized reconnaissance for compliance-driven or geo-specific bug bounties
{% endstep %}

{% step %}
Search by organization using `organization: "Google"` to pinpoint assets owned by the target entity, ensuring queries stay within program boundaries and highlight corporate exposures
{% endstep %}

{% step %}
Query web applications with `webapp: "wordpress"` to find framework-specific instances, targeting misconfigurations like exposed admin panels or plugin vulnerabilities
{% endstep %}

{% step %}
Identify products with `product: "MySQL"` to uncover database servers or tools, evaluating exposure risks such as unauthorized query access or credential leaks
{% endstep %}

{% step %}
Search server headers or banners with `header: "server"` to detect web server types like `"nginx"`, revealing version details for targeted exploit development
{% endstep %}

{% step %}
Filter by descriptions or titles using `desc: "hello" or title: "Login"` to locate pages with specific content, highlighting authentication interfaces or debug endpoints
{% endstep %}

{% step %}
Enumerate sites with `site: "target.com"` to discover indexed web assets, combining with keywords for content-based reconnaissance like exposed APIs or error pages
{% endstep %}

{% step %}
Use time-based filters with `after: "2020-01-01" before: "2024-01-01"` to focus on recently active devices, eliminating stale data and prioritizing current, exploitable infrastructure
{% endstep %}

{% step %}
Query for vulnerabilities with `vuln: "CVE-2021-34527"` to directly identify assets matching known exploits, streamlining high-impact testing like RCE chains
{% endstep %}

{% step %}
Combine filters logically with operators like `country:"FR" + os:"Linux"` to create complex queries, such as `(app:"Jenkins" + port:8080)` for precise targeting of vulnerable CI/CD tools
{% endstep %}

{% step %}
Leverage facets for host searches (app, device, service, os, port, country, city) or web searches (webapp, component, framework, frontend, server, waf, os, country, city) to generate summary reports on search distributions, aiding in attack surface prioritization
{% endstep %}

{% step %}
Document query results including IPs, ports, banners, and geolocations to build a comprehensive asset inventory, verifying exposures with manual follow-up scans
{% endstep %}

{% step %}
Assess impact by cross-referencing findings with CVE databases or exploit frameworks, prioritizing assets for deeper penetration testing or responsible disclosure
{% endstep %}
{% endstepper %}

***

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
gh search code "path:**/WebServer.xml" -R $URI
```

#### .bash\_history Commands

```bash
gh search code "path:**/.bash_history" -R $URI
```

#### /etc/passwd File

```bash
gh search code "path:**/passwd path:etc" -R $URI
```

#### Password in config.php

```bash
gh search code "path:**/config.php dbpasswd" -R $URI
```

#### Shodan API Key in Python Script

```bash
gh search code "shodan_api_key language:python" -R $URI
```

#### /etc/shadow File

```bash
gh search code "path:**/shadow path:etc" -R $URI
```

#### wp-config.php File

```bash
gh search code "path:**/wp-config.php" -R $URI
```

#### MySQL Dump File

```bash
gh search code "path:*.sql mysql dump" -R $URI
```

#### Scan Commits

```bash
gh search commits "cve OR vuln OR security OR xss OR ssrf OR sensitive" \
          -R swagger-api/swagger-ui
```

#### Scan Pull & Issues

{% hint style="info" %}
Patch list
{% endhint %}

```bash
gh pr list -S "cve OR vuln OR security OR xss OR ssrf OR sensitive" \
           -s all \
           -R $URI
```

{% hint style="info" %}
View details
{% endhint %}

```bash
gh pr view $PR_NUMBER -R $URI
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
