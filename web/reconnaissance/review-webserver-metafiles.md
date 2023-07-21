# Review Webserver Metafiles

## robots.txt file

_**Request:**_

```bash
	
┌──(web㉿unk9vvn)-[~]
└─$ curl -O -Ss http://www.apple.com/robots.txt && head -n5 robots.txt
```

_**Response:**_

```markup
# robots.txt for http://www.apple.com/
User-agent: *
Disallow: /*/includes/*
Disallow: /*retail/availability*
Disallow: /*retail/availabilitySearch*
Disallow: /*retail/pickupEligibility*
Disallow: /*shop/signed_in_account*
Disallow: /*shop/sign_in*
Disallow: /*shop/sign_out*
```

### Robots META Tag

```html
<html>
<head>
<title>...</title>
<META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW">
</head>
```

### Miscellaneous META Information Tags

```html
...
<meta name="DC.Title" content="United Nations | Peace, dignity and equality
on a healthy planet">
<meta name="DC.Description" content="Peace, dignity and equality on a healthy planet">
<meta name="DC.Creator" content="United Nations">
<meta name="DC.Publisher" content="United Nations">
<meta property="og:site_name" content="United Nations"> 
<meta property="og:title" content="United Nations | Peace, dignity and equality
on a healthy planet">
<meta property="og:description" content="Peace, dignity and equality on a healthy planet">
<meta property="og:image" content="https://www.un.org/sites/un2.un.org/files/107449.jpg">
<meta property="og:image:width" content="3000">
<meta property="og:image:height" content="2010">
<meta property="og:url" content="https://www.un.org/en/"> 
<meta property="og:type" content="article">
<meta name="twitter:card" content="summary_large_image"> 
<meta name="twitter:title" content="United Nations | Peace, dignity and equality
on a healthy planet">
<meta name="twitter:url" content="https://www.un.org/en/">
<meta name="twitter:description" content="Peace, dignity and equality on a healthy planet">
<meta name="twitter:image" content="https://www.un.org/sites/un2.un.org/files/107449.jpg">
<meta name="twitter:image:width" content="3000px"> 
<meta name="twitter:image:height" content="2010px"> 
...
```

### WordPress API

```html
<head>
...
  <link rel='https://api.w.org/' href='http://example.com/wp-json/' />
  <link rel="alternate" type="application/json" href="http://example.com/wp-json/wp/v2/pages/1853">
  <link rel="alternate" type="application/json+oembed" href="http://example.com/wp-json/oembed/1.0/embed?url=..." />
  <link rel="alternate" type="text/xml+oembed" href="http://example.com/wp-json/oembed/1.0/embed?url=..." />
</head>
```

### XML-RPC

```html
<link rel="EditURI" type="application/rsd+xml" titlhte="RSD" href="http://example.com/xmlrpc.php?rsd">
```

RSD is Really Simple Discovery

<pre class="language-xml"><code class="lang-xml">&#x3C;rsd version="1.0">
  &#x3C;service>
    &#x3C;engineName>WordPress&#x3C;/engineName>
    &#x3C;engineLink>https://wordpress.org/&#x3C;/engineLink>
<strong>    &#x3C;homePageLink>http://example.com&#x3C;/homePageLink>
</strong>    &#x3C;apis>
      &#x3C;api name="WordPress" blogID="1" preferred="true" apiLink="http://example.com/xmlrpc.php"/>
      &#x3C;api name="Movable Type" blogID="1" preferred="false" apiLink="http://example.com/xmlrpc.php"/>
      &#x3C;api name="MetaWeblog" blogID="1" preferred="false" apiLink="http://example.com/xmlrpc.php"/>
      &#x3C;api name="Blogger" blogID="1" preferred="false" apiLink="http://example.com/xmlrpc.php"/>
      &#x3C;api name="WP-API" blogID="1" preferred="false" apiLink="http://example.com/wp-json/"/>
    &#x3C;/apis>
  &#x3C;/service>
&#x3C;/rsd>
</code></pre>

### Pingbacks

```html
<link rel="pingback" href="http://www.example.com/xmlrpc.php" />
```

#### wlwmanifest

```html
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="http://example.com/import/wlwmanifest.xml">
```

From this link, you can find some sensitive private paths of the WordPress website that may have been customized, for example admin panel path.

```xml
<manifest
  xmlns="http://schemas.microsoft.com/wlw/manifest/weblog">
  <options>
    <clientType>WordPress</clientType>
    <supportsKeywords>Yes</supportsKeywords>
    <supportsGetTags>Yes</supportsGetTags>
  </options>
  <weblog>
    <serviceName>WordPress</serviceName>
    <imageUrl>images/wlw/wp-icon.png</imageUrl>
    <watermarkImageUrl>images/wlw/wp-watermark.png</watermarkImageUrl>
    <homepageLinkText>View site</homepageLinkText>
    <adminLinkText>Dashboard</adminLinkText>
    <adminUrl>
      <![CDATA[ {blog-postapi-url}/../wp-admin/ ]]>
    </adminUrl>
    <postEditingUrl>
      <![CDATA[ {blog-postapi-url}/../wp-admin/post.php?action=edit&post={post-id} ]]>
    </postEditingUrl>
  </weblog>
  <buttons>
    <button>
      <id>0</id>
      <text>Manage Comments</text>
      <imageUrl>images/wlw/wp-comments.png</imageUrl>
      <clickUrl>
        <![CDATA[ {blog-postapi-url}/../wp-admin/edit-comments.php ]]>
      </clickUrl>
    </button>
  </buttons>
</manifest>
```

## sitemap.xml file

_**Request:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ wget --no-verbose https://www.google.com/sitemap.xml && head -n8 sitemap.xml
```

_**Response:**_

```xml
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.google.com/schemas/sitemap/0.84">
<sitemap>
<loc>https://www.google.com/gmail/sitemap.xml</loc>
</sitemap>
<sitemap>
<loc>https://www.google.com/forms/sitemaps.xml</loc>
</sitemap>
...
```

_**Request:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ wget --no-verbose https://www.google.com/gmail/sitemap.xml && head -n10 sitemap.xml
```

_**Response:**_

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
<url>
<loc>https://www.google.com/intl/am/gmail/about/</loc>
<xhtml:link href="https://www.google.com/gmail/about/" hreflang="x-default" rel="alternate"/>
<xhtml:link href="https://www.google.com/intl/el/gmail/about/" hreflang="el" rel="alternate"/>
<xhtml:link href="https://www.google.com/intl/it/gmail/about/" hreflang="it" rel="alternate"/>
<xhtml:link href="https://www.google.com/intl/ar/gmail/about/" hreflang="ar" rel="alternate"/>
...
```

## security.txt file

```bash
┌──(web㉿unk9vvn)-[~]
└─$ wget --no-verbose $WEBSITE/security.txt && cat security.txtas
```

```bash
┌──(web㉿unk9vvn)-[~]
└─$ wget --no-verbose $WEBSITE/.well-known/security.txt && cat security.txt
```

_**Request:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ wget --no-verbose https://www.facebook.com/security.txt && cat security.txt
```

_**Response:**_

```html
Contact: https://www.facebook.com/whitehat/report/
Acknowledgments: https://www.facebook.com/whitehat/thanks/
Hiring: https://www.facebook.com/careers/teams/security/
 
# Found a bug? Our bug bounty policy:
Policy: https://www.facebook.com/whitehat/info/
 
# What we do when we find a bug in another product:
Policy: https://www.facebook.com/security/advisories/Vulnerability-Disclosure-Policy
 
Expires: Mon, 24 Jan 2022 07:05:50 -0800
```

## humans.txt file

_**Request:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ wget --no-verbose https://www.gov.uk/humans.txt && cat humans.txt
```

_**Response:**_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ curl $WEBSITE/.well-known/
```
