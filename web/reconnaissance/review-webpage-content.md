# Review Webpage Content

## Review webpage comments

```html
<!-- Query: SELECT 1D,FName FROM tblusers WHERE active='1' -->
<!-- Insert Images into SQL database by admin password for testing: DBP@assw0rD -->
<!--Restart 192.168.290.120, If the images fail to load-->
<!-- Changed by: Ali Naseri , Mon Mar 10 14:13:45 2020-->
<!-- Called by /login/login.php -->
<!-- strPath c:\webroot\daily\home\Default.asp-->
<!-- Make sure that /var/www/html/conf/server.conf is updated -->
<!-- ImageReady Preload Script (splash.psd) -->
<!-- Vignette StoryServer 4 Sun Jan 13 00:04:01 -->
<!-- NCompass Resolution Template File -->
<!-- Lotus-Domino (Release 5.0.9 - November 16, 2020 on AIX) -->
```

### Burp Suite

`Burp Suite -> Target -> Site map -> Right Click on One Domain -> Engagement tools -> Find comments`

## Review JavaScript files and JS codes

```html
<script type="text/javascript">
  /* <![CDATA[ */
    function login(){
      pass=prompt("Enter password");
      if ( pass == "123456azerty" ) {
         alert("You can enter now."); }
      else {
         alert("wrong password !"); }
    }
 /* ]]> */
</script>
```

```javascript
const myS3Credentials = {
  accessKeyId: config('AWSS3AccessKeyID'),
  secretAcccessKey: config('AWSS3SecretAccessKey'),
};
```

```javascript
var conString = "tcp://postgres:1234@localhost/postgres";
```

Google Map API key found:

```javascript
[/<script type="application/json">
...
{"GOOGLE_MAP_API_KEY":"AIzaSyDUEBnKgwiqMNpDplT6ozE4Z0XxuAbqDi4", "RECAPTCHA_KEY":"6LcPscEUiAAAAHOwwM3fGvIx9rsPYUq62uRhGjJ0"}
...
</script>
code]</pre>
We can check if it is restricted or not, by a tool called <a href="https://github.com/ozguralp/gmapsapiscanner/" target="_blank" rel="noopener">Google Map API Scanner</a>:
<pre></pre>
<p style="text-align: justify;">if it is restricted only per the Google Map APIs, we can use that API Key to query unrestricted Google Map APIs and the application owner must to pay for that. In some cases, we may find sensitive routes from JavaScript code, such as links to admin pages:</p>
 
<pre>
<script type="application/json">
...
"runtimeConfig":{"BASE_URL_VOUCHER_API":"https://staging-voucher.victim.net/api", "BASE_BACKOFFICE_API":"https://10.10.10.2/api", "ADMIN_PAGE":"/hidden_administrator"}
...
</script>
```

### Burp Suite

`Burp Suite -> Target -> Site map -> Right Click on One Domain -> Engagement tools -> Find scripts`

### [JsSearch](https://github.com/incogbyte/jsearch)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ python3 jsearch.py -u $WEBSITE
```

### [Javascript Security Analysis](https://github.com/w9w/JSA)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ echo $WEBSITE | python3 jsa.pys
```

## Identify source map files or other front-end debug files

```json
{
  version : 3,
  file: "out.js",
  sourceRoot : "",
  sources: ["foo.js", "bar.js"],
  names: ["src", "maps", "are", "fun"],
  mappings: "AAgBC,SAAQ,CAAEA"
}
```

### Burp Suite

`Burp Suite -> Target -> Site map ->Right Click on One Domain -> Engagement tools -> Discover content`

## Identify application links and endpoints

### [WaybackURLs](https://github.com/tomnomnom/waybackurls)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ cat websites.txt | waybackurls
```

### [GoSpider](https://github.com/jaeles-project/gospider)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ gospider -s $WEBSITE --js -t 20 -d 2 --sitemap --robots -w --other-source
```

### [Getallurls](https://github.com/lc/gau)

```bash
┌──(web㉿unk9vvn)-[~]
└─$ gau $WEBSITE --threads 5 --subs
```
