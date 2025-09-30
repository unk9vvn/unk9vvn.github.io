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
