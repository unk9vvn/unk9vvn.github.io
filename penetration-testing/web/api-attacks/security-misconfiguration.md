# Security Misconfiguration

## Check List

## Methodology

### Black Box

#### Debug Endpoint Exposed in Production API

{% stepper %}
{% step %}
Access the API without authentication
{% endstep %}

{% step %}
Attempt to discover debug or test endpoints

```http
GET /api/debug HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response returns environment variables, stack trace, or configuration data, debug endpoint is exposed
{% endstep %}

{% step %}
Test additional common debug paths

```http
GET /api/test HTTP/1.1
Host: target.com
```

or

```http
GET /api/v1/status HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If internal configuration or sensitive metadata is returned, production misconfiguration is confirmed
{% endstep %}

{% step %}
If debug functionality is accessible publicly, Security Misconfiguration vulnerability exists
{% endstep %}
{% endstepper %}

***

#### Verbose Error Messages in API

{% stepper %}
{% step %}
Send malformed JSON to an endpoint

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":}
```
{% endstep %}

{% step %}
Observe server response, If full stack trace, file path, framework version, or SQL query is disclosed

```http
Exception in file /var/www/app/controllers/AuthController.js line 47
```
{% endstep %}

{% step %}
Then error handling is misconfigured
{% endstep %}

{% step %}
If internal implementation details are exposed, Security Misconfiguration is confirmed
{% endstep %}
{% endstepper %}

***

#### Directory Listing Enabled on API Path

{% stepper %}
{% step %}
Attempt directory access

```http
GET /api/ HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If response shows directory index listing endpoints or files, directory listing is enabled, Test additional paths

```http
GET /api/v1/ HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
If internal API structure is revealed, configuration hardening is missing
{% endstep %}

{% step %}
If sensitive routes are exposed via directory listing, misconfiguration is confirmed
{% endstep %}
{% endstepper %}

***

#### Default Credentials on API Admin Panel

{% stepper %}
{% step %}
Identify administrative API interface
{% endstep %}

{% step %}
Attempt authentication with common default credentials

```http
POST /api/admin/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":"admin"}
```
{% endstep %}

{% step %}
If login succeeds using default or weak credentials, default configuration remains active
{% endstep %}

{% step %}
If administrative access is granted without credential hardening, Security Misconfiguration vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### CORS Misconfiguration Allowing Arbitrary Origin

{% stepper %}
{% step %}
Send preflight request

```http
OPTIONS /api/user/profile HTTP/1.1
Host: target.com
Origin: https://attacker.com
Access-Control-Request-Method: GET
```
{% endstep %}

{% step %}
Observe response headers

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
{% endstep %}

{% step %}
If API allows wildcard origin with credentials enabled, cross-origin data access is possible
{% endstep %}

{% step %}
If sensitive API responses are accessible cross-origin due to permissive CORS policy, Security Misconfiguration is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
