# Map Execution Paths

## Check List&#x20;

* [ ] Map the target application and understand the principal workflows.

## Methodology

#### Path

{% stepper %}
{% step %}
Use a proxy tool to map the target website by analyzing its sitemap, identifying all accessible pages, endpoints, and resources to build a comprehensive view of the application’s structure
{% endstep %}

{% step %}
Perform a targeted analysis within the proxy tool by selecting a domain and running engagement tools to extract detailed insights about endpoints, parameters, and linked resources
{% endstep %}

{% step %}
Configure a web application scan in the proxy tool, selecting a preset scan mode to crawl the target, enumerating URLs, and summarizing findings to identify hidden or sensitive paths
{% endstep %}

{% step %}
Execute a directory brute-forcing tool with the target URL, filtering for specific response codes (e.g., 200) and targeting file extensions like PHP, ASPX, or JSP to discover hidden files or directories
{% endstep %}

{% step %}
Run a directory enumeration tool with a comprehensive wordlist, testing for a wide range of file extensions (e.g., php, html, js, config, backup) to uncover sensitive files, backups, or misconfigured endpoints
{% endstep %}

{% step %}
Analyze discovered paths for sensitive resources like configuration files (.conf, .ini), database backups (.sql, .db), or logs (.log), checking for exposed credentials or internal data
{% endstep %}

{% step %}
Cross-reference enumerated paths with the proxy tool’s sitemap to validate findings, ensuring all discovered endpoints are tested for accessibility and functionality
{% endstep %}

{% step %}
Document all identified paths, including URLs, file extensions, and response codes, to create a detailed proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of discovered files or directories, such as exposed admin panels, configuration leaks, or backup files, to prioritize reporting based on severity
{% endstep %}
{% endstepper %}

***

#### Data Flow

{% stepper %}
{% step %}
Configure a proxy tool to intercept and map the target website’s sitemap, capturing all accessible pages, endpoints, and resources to understand the application’s structure and data flow
{% endstep %}

{% step %}
Select multiple domains within the proxy tool’s sitemap and perform a targeted analysis to trace data interactions, identifying how requests and responses flow between domains, subdomains, or external services
{% endstep %}

{% step %}
Examine HTTP requests and responses in the sitemap to identify parameters, headers, and cookies, mapping how data is transmitted across endpoints like forms, APIs, or redirects
{% endstep %}

{% step %}
Analyze request chains to detect sensitive data (e.g., tokens, session IDs, or user inputs) passed between pages or domains, checking for improper handling or exposure
{% endstep %}

{% step %}
Identify cross-domain interactions by reviewing Referer headers, CORS policies, or API calls, assessing risks like data leakage or unauthorized access to external services
{% endstep %}

{% step %}
Inspect response bodies for sensitive information, such as inline JavaScript variables or hidden inputs, that may reveal internal data flows or configuration details
{% endstep %}

{% step %}
Document all data flow paths, including request sequences, parameter names, and sensitive data exposures, to create a comprehensive proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of identified data flow issues, such as exposed credentials, session mismanagement, or cross-origin vulnerabilities, to prioritize reporting based on severit
{% endstep %}
{% endstepper %}

***

#### Race

{% stepper %}
{% step %}
Configure a proxy tool to intercept and map the target website’s sitemap, identifying critical endpoints like forms, API calls, or resource-modifying requests prone to race conditions
{% endstep %}

{% step %}
Select a specific domain or endpoint within the proxy tool’s sitemap and use an extension designed for rapid request manipulation to prepare for race condition testing
{% endstep %}

{% step %}
Send the selected request to a specialized tool within the proxy suite, enabling high-speed, concurrent request execution to simulate multiple simultaneous submissions
{% endstep %}

{% step %}
Modify the tool’s configuration to include a wordlist or parameter values, targeting inputs like session tokens, user IDs, or resource identifiers that could trigger race conditions
{% endstep %}

{% step %}
Execute the attack by sending multiple concurrent requests to the target endpoint, aiming to exploit timing issues that allow unauthorized actions, such as duplicate resource creation or privilege escalation
{% endstep %}

{% step %}
Monitor responses for anomalies, such as unexpected success codes, data overwrites, or inconsistent states, indicating a successful race condition exploit\\
{% endstep %}

{% step %}
Document the request sequence, timing details, and response outcomes to create a detailed proof-of-concept, including steps to reproduce the race condition
{% endstep %}

{% step %}
Assess the impact of the race condition, such as unauthorized access, data corruption, or resource abuse, to prioritize reporting based on severity for responsible disclosure
{% endstep %}
{% endstepper %}

***

#### .Git File

{% stepper %}
{% step %}
Navigate to the target domain in a web browser.
{% endstep %}

{% step %}
Directly access the Git configuration file by visiting:

```hurl
https://example.com/.git/config
```
{% endstep %}

{% step %}
Observe that the server responds with **HTTP 200 OK** and allows the `.git/config` file to be downloaded
{% endstep %}

{% step %}
Confirm that the `.git/` directory is publicly accessible.
{% endstep %}

{% step %}
Use an automated dumping tool (e.g., git-dumper) to retrieve the exposed repository

```bash
./git_dumper.py https://victim.com/.git/ /tmp/victim-source
```
{% endstep %}

{% step %}
Wait for the tool to finish downloading the full `.git` directory and reconstruct the repository.
{% endstep %}

{% step %}
Navigate to the dumped repository directory

```bash
cd /tmp/victim-source
```
{% endstep %}

{% step %}
Review the commit history

```bash
git log
```
{% endstep %}

{% step %}
Inspect source code and commit diffs for sensitive information such as

* API keys
* Database credentials
* Access tokens
* Internal endpoints
{% endstep %}

{% step %}
Confirm that sensitive secrets are exposed within the source code or Git history
{% endstep %}

{% step %}
Verify that full source code access is achieved without authentication
{% endstep %}

{% step %}
Conclude that the exposed `.git/` directory results in full source code disclosure and potential compromise of the application
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Path

#### Burp Suite

{% hint style="info" %}
Mapping a Website with Burp Suite
{% endhint %}

{% hint style="warning" %}
Burp Suite > Target > Site map > Right Click on One Domain > Engagement tools > Analyze Target
{% endhint %}

{% hint style="info" %}
Crawling a Website with Burp Suite
{% endhint %}

{% hint style="warning" %}
Burp Suite > ِDashbord > New Scan > Use Web app Scan > Use a preset scan mode > Analyze Target in Summary
{% endhint %}

#### [FeroxBuster](https://www.google.com/url?sa=t\&source=web\&rct=j\&opi=89978449\&url=https://github.com/epi052/feroxbuster\&ved=2ahUKEwiU3pPJrqGJAxV1Q6QEHe2kNVcQFnoECBkQAQ\&usg=AOvVaw3nTxxRaPVVZSoVDW5LKrjt)

```bash
feroxbuster --url $WEBSITE -C 200 -x php,aspx,jsp
```

#### [DirSearch](https://www.google.com/url?sa=t\&source=web\&rct=j\&opi=89978449\&url=https://github.com/maurosoria/dirsearch\&ved=2ahUKEwjJ3-LUrqGJAxWBVqQEHcsEKvkQFnoECAoQAQ\&usg=AOvVaw09pWqpI-PVNuVwz_h5SCtz)

```bash
dirsearch -u $WEBSITE \
          -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
          -e php,cgi,htm,html,shtm,sql.gz,sql.zip,shtml,lock,js,jar,txt,bak,inc,smp,csv,cache,zip,old,conf,config,backup,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,wasl,tar.gz,tar.bz2,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5
```

### Data Flow&#x20;

#### [x8](https://github.com/Sh1Yo/x8)

{% hint style="info" %}
Find Parameters
{% endhint %}

```bash
x8 -u "$WEBSITE" \
   -X GET POST \
   -w /usr/share/x8/smalists/sam-cc-parameters-mixedcase-all.txt \
   --mimic-browser \
   --verify
```

#### [Burp Suite](https://portswigger.net/burp/releases/community/latest)

{% hint style="warning" %}
Burp Suite > Target > Site map > Analyze Three Domain&#x20;
{% endhint %}

### Race

#### [Burp Suite](https://portswigger.net/burp/releases/community/latest)

{% hint style="warning" %}
Burp Suite > Target > Right Click on One Domain > Extensions > Turbo intruder > send to turbo intruder > Add to WordList path in line "for word in open('/usr/share/dict/words')" > Attack
{% endhint %}
