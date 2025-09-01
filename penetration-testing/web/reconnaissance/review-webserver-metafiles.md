# Review Webserver Metafiles

## Check List <a href="#check-list" id="check-list"></a>

* [ ] Identify hidden or obfuscated paths and functionality through the analysis of metadata files.
* [ ] Extract and map other information that could lead to better understanding of the systems at hand.

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
