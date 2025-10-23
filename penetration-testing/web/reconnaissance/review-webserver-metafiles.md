# Review Webserver Metafiles

## Check List <a href="#check-list" id="check-list"></a>

* [ ] Identify hidden or obfuscated paths and functionality through the analysis of metadata files.
* [ ] Extract and map other information that could lead to better understanding of the systems at hand.

## Methodology

#### Webserver Metafiles

{% stepper %}
{% step %}
Retrieve the robots.txt file from the target website to identify disallowed paths, hidden directories, or sensitive endpoints that may reveal internal structure or unintended exposures
{% endstep %}

{% step %}
Access the xmlrpc.php file to check for WordPress XML-RPC interfaces, assessing potential vulnerabilities like brute-force attacks or remote method execution
{% endstep %}

{% step %}
Fetch the sitemap.xml file to enumerate indexed URLs, uncovering pages, APIs, or resources that may expose additional attack surfaces or hidden content
{% endstep %}

{% step %}
Query the security.txt file to discover security contact information or vulnerability disclosure policies, identifying the target’s bug bounty program details or reporting channels
{% endstep %}

{% step %}
Check for the humans.txt file to gather metadata about the site’s developers or contributors, potentially revealing internal team details or associated technologies
{% endstep %}

{% step %}
Access the WordPress REST API endpoint to enumerate user information or public API data, testing for unauthorized data leaks or misconfigured access controls
{% endstep %}

{% step %}
Extract META tags from the target’s homepage to identify metadata like generator tags, CMS versions, or author details, providing insights into the technology stack or potential vulnerabilities
{% endstep %}
{% endstepper %}

***

## Cheat Sheet <a href="#cheat-sheet" id="cheat-sheet"></a>

### robots.txt

```bash
curl $WEBSITE/robots.txt
```

### xmlrpc.php

```bash
curl $WEBSITE/xmlrpc.php
```

### sitemap.xml

```bash
curl $WEBSITE/sitemap.xml
```

### security.txt

```shell
curl $WEBSITE/security.txt
```

### humans.txt

```sh
curl $WEBSITE/humans.txt
```

### WordPress API

```sh
curl $WEBSITE/wp-json/wp/v2/users/
```

### META tags

```sh
curl $WEBSITE | grep 'meta'
```
