# Fingerprint Web Application Framework

## Check List

* [ ] _Fingerprint the components being used by the web applications._

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

`Burp Suite > Target > Right Click on One Domain > Send to Intruder > Intruder > Add Variable to Target Fuzzing > Payloads > Payloads Setting Add WordList > Start Attack`

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

```
Parse error: syntax error, unexpected 'S SERVER' (T_VARIABLE) in /var/www/html/index.php on line 5
```
