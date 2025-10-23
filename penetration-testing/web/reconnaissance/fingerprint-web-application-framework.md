# Fingerprint Web Application Framework

## Check List

* [ ] Fingerprint the components being used by the web applications.

## Methodology

#### HTTP Headers

{% stepper %}
{% step %}
Fetch HTTP headers from the target website to extract the X-Powered-By header, identifying backend technologies like PHP or ASP.NET, and noting version details for potential vulnerability research
{% endstep %}

{% step %}
Analyze the response headers to identify the X-Generator header, revealing CMS or framework details such as WordPress or Drupal, which can indicate specific vulnerabilities or misconfigurations
{% endstep %}

{% step %}
Inspect additional headers like Server, Content-Type, or Cache-Control to gather information about the web server software, version, and caching behavior, cross-referencing with known CVEs
{% endstep %}

{% step %}
Examine security headers such as X-Frame-Options, Strict-Transport-Security, or Content-Security-Policy to assess the target’s security posture and identify weak or missing configurations
{% endstep %}

{% step %}
Query a network intelligence platform to search for servers or response bodies indicating specific technologies like ASP.NET or Microsoft-IIS, narrowing down targets for platform-specific exploit testing
{% endstep %}

{% step %}
Use a web fingerprinting tool to identify the target’s CMS, frameworks, or plugins, collecting detailed technology stack information to prioritize vulnerability scanning
{% endstep %}

{% step %}
Document all header details, including X-Powered-By, X-Generator, and server versions, along with fingerprinting results, to create a comprehensive proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of exposed technologies or versions, such as outdated software or weak security headers, to prioritize reporting based on potential exploit severity
{% endstep %}
{% endstepper %}

***

#### Cookies

{% stepper %}
{% step %}
Fetch HTTP response headers from the target website to extract Set-Cookie headers, identifying session cookies and their attributes like name, path, domain, or security flags
{% endstep %}

{% step %}
Analyze the Set-Cookie header for specific session cookie names associated with known CMS or frameworks (e.g., CAKEPHP, laravel\_session, wp-settings), indicating the underlying technology stack
{% endstep %}

{% step %}
Check cookie attributes such as Secure, HttpOnly, SameSite, and Expires to evaluate session management security, identifying risks like missing protections or overly permissive settings
{% endstep %}

{% step %}
Identify duplicate or redundant Set-Cookie headers (e.g., multiple CAKEPHP cookies) to detect misconfigurations that could lead to session fixation or cookie overwrites
{% endstep %}

{% step %}
Cross-reference session cookie names with a list of known CMS or framework identifiers (e.g., zope3, kohanasession, BITRIX\_) to confirm the platform and research version-specific vulnerabilities
{% endstep %}

{% step %}
Test for session cookie persistence by sending requests with and without cookies, observing server behavior to detect improper session handling or authentication bypass opportunities
{% endstep %}

{% step %}
Document all Set-Cookie headers, including cookie names, values, attributes, and associated CMS/framework, to create a detailed proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of identified issues, such as weak session management, exposed CMS versions, or missing security flags, to prioritize reporting based on potential exploit severity
{% endstep %}
{% endstepper %}

***

#### HTML Source Code

{% stepper %}
{% step %}
Fetch the target website’s HTML source code and search for specific JavaScript references (e.g., gtag.js) to identify third-party analytics scripts or tracking tools, noting associated IDs or keys
{% endstep %}

{% step %}
Extract HTML comments to uncover references to analytics platforms (e.g., Google Analytics, Site Kit), developer notes, or configuration details that may expose sensitive information
{% endstep %}

{% step %}
Inspect tags for generator attributes to identify CMS platforms like WordPress, Joomla, Drupal, or MediaWiki, along with version numbers, to pinpoint potential vulnerabilities
{% endstep %}

{% step %}
Search for CMS-specific markers in the HTML source, such as for phpBB or specific comments like \<!-- START headerTags.cfm for Adobe ColdFusion, to confirm the technology stack
{% endstep %}

{% step %}
Identify framework-specific identifiers like \_\_VIEWSTATE for ASP.NET or \<!-- ZK for ZK Framework, revealing backend technologies for targeted vulnerability research
{% endstep %}

{% step %}
Look for proprietary platform markers, such as for Business Catalyst or ndxz-studio for Indexhibit, to detect niche CMS or hosting solutions
{% endstep %}

{% step %}
Analyze comments for sensitive data, such as API keys, domain configurations, or internal references, that could lead to unauthorized access or information disclosure
{% endstep %}

{% step %}
Use a web technology identification tool to cross-reference findings, confirming CMS, frameworks, or libraries in use, and mapping them to known vulnerabilities
{% endstep %}

{% step %}
Document all findings, including script references, comment snippets, meta tags, and identified platforms, to create a comprehensive proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of exposed CMS versions, hardcoded keys, or misconfigured analytics scripts, prioritizing reporting based on potential exploit severity
{% endstep %}
{% endstepper %}

***

#### Specific File and Folders

{% stepper %}
{% step %}
Configure a proxy tool to intercept and map the target website's sitemap, identifying potential paths or endpoints for fuzzing like directories or file extensions that may expose sensitive resources
{% endstep %}

{% step %}
Select a specific domain or endpoint within the proxy tool's sitemap and send it to an automated fuzzing module to prepare for targeted directory or file enumeration
{% endstep %}

{% step %}
Mark variable positions in the target URL (e.g., directory name or file extension) to enable fuzzing, replacing placeholders with payloads to test for hidden or misconfigured resources
{% endstep %}

{% step %}
Integrate a comprehensive wordlist into the fuzzing module's payload settings, selecting lists containing common directory names, file extensions, or backup file patterns for thorough coverage
{% endstep %}

{% step %}
Launch the fuzzing attack to send multiple requests with varying payloads, monitoring responses for indicators like 200 OK, directory listings, or file downloads that reveal sensitive files
{% endstep %}

{% step %}
Analyze attack results to identify successful payloads, noting response codes, lengths, or content differences that indicate exposed configuration files, backups, or administrative interfaces
{% endstep %}

{% step %}
Follow up on discovered files or folders by accessing them manually to extract sensitive data such as credentials, database dumps, or internal documentation for impact assessment
{% endstep %}

{% step %}
Document all fuzzing results, including successful payloads, response details, and discovered resources, to create a detailed proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of exposed files or folders, such as information disclosure, unauthorized access, or chainable vulnerabilities, to prioritize reporting based on severity
{% endstep %}
{% endstepper %}

***

#### File Extensions

{% stepper %}
{% step %}
Use a web technology detection tool to analyze the target website's headers, scripts, and content, identifying file extensions associated with detected CMS, frameworks, or libraries like PHP, ASPX, or JSP
{% endstep %}

{% step %}
Query an online technology profiler by entering the target URL to extract details on server technologies, including supported file extensions and associated versions for vulnerability mapping
{% endstep %}

{% step %}
Run a web fingerprinting tool on the target to scan for CMS, plugins, and server software, noting file extensions like .php, .html, or .asp that indicate the platform's capabilities
{% endstep %}

{% step %}
Execute a directory brute-forcing tool with the target URL, filtering for successful responses (e.g., 200 OK) and targeting specific extensions like PHP, ASPX, or JSP to uncover hidden files or misconfigurations
{% endstep %}

{% step %}
Perform file extension enumeration using a comprehensive wordlist, testing for a wide range of formats including configuration files (.conf, .ini), backups (.bak, .zip), databases (.sql, .db), and archives (.tar.gz, .rar) to detect exposed sensitive resources
{% endstep %}

{% step %}
Analyze discovered files for platform indicators such as .php3-.php5 for PHP versions or .aspx for ASP.NET, cross-referencing with known vulnerabilities or misconfigurations
{% endstep %}

{% step %}
Validate enumerated extensions by accessing discovered files to check for content like configuration data, logs, or source code that may reveal internal details or credentials
{% endstep %}

{% step %}
Document all identified extensions, associated technologies, and accessible files, including response codes and content snippets, to create a detailed proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of exposed file extensions, such as information disclosure from config files or RCE from executable scripts, to prioritize reporting based on severity
{% endstep %}
{% endstepper %}

***

#### Error Message

{% stepper %}
{% step %}
Fetch the target website’s response content and search for error-related keywords like “syntax error” to identify debugging messages or stack traces exposed in the HTML output
{% endstep %}

{% step %}
Analyze retrieved error messages, such as PHP parse errors or unexpected token errors, to extract details like file paths (e.g., /var/www/html/index.php) or line numbers that reveal server-side structure
{% endstep %}

{% step %}
Inspect error messages for specific technology indicators, such as PHP, MySQL, or Apache errors, to confirm the server’s software stack and cross-reference with known vulnerabilities
{% endstep %}

{% step %}
Test the target URL with malformed requests or invalid parameters to trigger additional error responses, uncovering further details about the application’s backend or configuration
{% endstep %}

{% step %}
Check for full path disclosures in error messages to map the server’s filesystem, identifying potential targets for local file inclusion (LFI) or directory traversal attacks
{% endstep %}

{% step %}
Document all error messages, including the triggering URL, error type, file paths, and line numbers, to create a comprehensive proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of exposed error messages, such as information disclosure, potential for chaining with other vulnerabilities, or server misconfiguration, to prioritize reporting based on severity
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### HTTP Headers

#### X-Powered-By

```bash
curl -s -I $WEBSITE | grep -i "X-Powered-By"
```

```http
HTTP/1.1 200 OK
Date: Sat, 19 Oct 2024 12:53:32 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1991 08:55:00 GMT
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 20336
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

#### X-Generator

```bash
curl -s -I $WEBSITE | grep -i "X-Generator"
```

```http
HTTP/2 200 OK
Date: Sun, 20 Oct 2024 19:44:37 GMT
Content-Type: text/html; charset=utf-8
Cache-Control: public, max-age=2678400
Content-Language: en
Expires: Sun, 19 Nov 1978 05:00:00 GMT
Last-Modified: Thu, 17 Oct 2024 20:23:57 GMT
Link: <https://www.clubtexting.com/mass-texting-service>; rel="canonical", <https://www.clubtexting.com/node/2>; rel="shortlink"
Strict-Transport-Security: max-age=0
Traceparent: 00-17ff572e152af0e16aa14393ed1665c0-d07a1342ce2b0ab2-01
Vary: Cookie, Accept-Encoding
X-Content-Type-Options: nosniff
X-Debug-Info: eyJyZXRyaWVzIjowfQ==
X-Frame-Options: SAMEORIGIN
X-Generator: Wordpress
X-Platform-Cluster: dtrg7uteophra-main-bvxeaći
X-Platform-Processor: 7w2v5maie5xeye7eoz3s2122sa
X-Platform-Router: vpnpkzvsdhodouspycwfpqtbfu
CF-Cache-Status: HIT
Age: 256840
Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v4?s=n%2BuAuXK14P=iiu7C=tAY460JZghéRNpsdtyNz4zKvPZdQAB2xgUlKx4151BHwgzPf6kq9x04Xu0IyLqfpfkRuZLSLDNIOWUJ2YwrW8aIkprtCIhiXuZf%2BJa6XrteYB%2FUQ"}],"group":"cf-nel","max_age":604800}
NEL: {"success_fraction":0,"report_to":"cf-nel","max_age":604800}
Server: cloudflare
CF-Ray: 8d5b80e93f87dca5-PRA
Server-Timing:
Alt-Svc: h3=":443"; ma=86400
```

#### [Censys](https://search.censys.io/)

```bash
services.http.response.body: "ASP.NET" OR services.http.response.headers.server: "Microsoft-IIS" OR services.microsoft_sqlserver
```

#### [WhatWeb](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSIET
```

### Cookies

#### Set-Cookie

```bash
curl -s -I $WEBSITE | grep -i "Set-Cookie:"
```

```http
HTTP/1.1 200 OK
Date: Sun, 20 Oct 2024 19:38:17 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: CAKEPHP=jiflsfmsmeqhou0q38jbrlj380; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: CAKEPHP=jiflsfmsmeqhou0q38jbrlj380; path=/
Set-Cookie: CAKEPHP=jiflsfmsmeqhou0q38jbrlj380; path=/
Vary: Accept-Encoding
Content-Length: 52161
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

#### Session Cookie Parameters <a href="#cookies-1" id="cookies-1"></a>

|   Framework  |              Cookie name             |
| :----------: | :----------------------------------: |
|     Zope     |                 zope3                |
|    CakePHP   |                cakephp               |
|    Kohana    |             kohanasession            |
|    Laravel   |           laravel\_session           |
|     phpBB    |               phpbb3\_               |
|   WordPress  |              wp-settings             |
|   1C-Bitrix  |               BITRIX\_               |
|    AMPcms    |                  AMP                 |
|  Django CMS  |                django                |
|  DotNetNuke  |          DotNetNukeAnonymous         |
|     e107     |               e107\_tz               |
|   EPiServer  |          EPiTrace, EPiServer         |
| Graffiti CMS |              graffitibot             |
|  Hotaru CMS  |            hotaru\_mobile            |
|  ImpressCMS  |              ICMSession              |
|    Indico    |             MAKACSESSION             |
|  InstantCMS  |         InstantCMS\[logdate]         |
|  Kentico CMS |          CMSPreferredCulture         |
|     MODx     |             SN4\[12symb]             |
|     TYPO3    |            fe\_typo\_user            |
|  Dynamicweb  |              Dynamicweb              |
|    LEPTON    | lep\[some\_numeric\_value]+sessionid |
|      Wix     |            Domain=.wix.com           |
|     VIVVO    |            VivvoSessionId            |

### HTML Source Code&#x20;

#### Comment

```bash
curl -s $WEBSITE | grep -o "gtag.js"
```

```html
<!-- Google tag (gtag.js) snippet added by Site Kit -->

<!-- Google Analytics snippet added by Site Kit -->
<script src="https://www.googletagmanager.com/gtag/js?id=G-EVWGW1CZ2C6" id="google_gtagjs-js" async></script>
<script id="google_gtagjs-js-after">
    window.dataLayer = window.dataLayer || [];
    function gtag(){
        dataLayer.push(arguments);
    }
    gtag('set', 'linker', {
        "domains":["www.zkracing.com.my"]
    });
</script>
```

#### HTML Source Code <a href="#html-source-code-1" id="html-source-code-1"></a>

| Application |                                     Keyword                                    |
| :---------: | :----------------------------------------------------------------------------: |
|  WordPress  |              `<meta name="generator" content="WordPress 3.9.2" />`             |
|    phpBB    |                               `<body id="phpbb"`                               |
|  Mediawiki  |             `<meta name="generator" content="MediaWiki 1.21.9" />`             |
|    Joomla   | `<meta name="generator" content="Joomla! - Open Source Content Management" />` |
|    Drupal   |       `<meta name="Generator" content="Drupal 7 (http://drupal.org)" />`       |
|  DotNetNuke |    `DNN Platform - [http://www.dnnsoftware.com](http://www.dnnsoftware.com)`   |

#### **Specific Markers**

|     Framework     |           Keyword           |
| :---------------: | :-------------------------: |
|  Adobe ColdFusion | `<!-- START headerTags.cfm` |
| Microsoft ASP.NET |        `__VIEWSTATE`        |
|         ZK        |          `<!-- ZK`          |
| Business Catalyst |      `<!-- BC_OBNW -->`     |
|     Indexhibit    |        `ndxz-studio`        |

#### Wappalyzer

{% embed url="https://www.wappalyzer.com/" %}

### Specific File and Folders

#### BurpSuite

{% hint style="warning" %}
Burp Suite > Target > Right Click on One Domain > Send to Intruder > Intruder > Add Variable to Target Fuzzing > Payloads > Payloads Setting Add Wordlist > Start Attack
{% endhint %}

### File Extensions

#### Wappalyzer

{% embed url="https://www.wappalyzer.com/" %}

#### BuiltWith

{% embed url="https://builtwith.com/" %}

#### [WhatWeb](https://github.com/urbanadventurer/WhatWeb)

```bash
whatweb $WEBSITE
```

#### [FreoxBuster](https://github.com/epi052/feroxbuster)

```bash
feroxbuster --url $WEBSITE -C 200 -x php,aspx,jsp
```

#### [DirSearch](https://github.com/maurosoria/dirsearch)

```bash
dirsearch -u $WEBSITE \
          -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
          -e php,cgi,htm,html,shtm,sql.gz,sql.zip,shtml,lock,js,jar,txt,bak,inc,smp,csv,cache,zip,old,conf,config,backup,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,wasl,tar.gz,tar.bz2,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5
```

### Error Message&#x20;

```bash
curl -s $WEBSITE | grep -i "syntax error"
```

```php
Parse error: syntax error, unexpected 'S SERVER' (T_VARIABLE) in /var/www/html/index.php on line 5
```
