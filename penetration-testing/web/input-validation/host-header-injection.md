# Host Header Injection

## Check List

## Methodology

### Black Box

#### Spoofing with a Malicious Domain

{% stepper %}
{% step %}
Modify the Host header to include a rogue domain (e.g., attacker.com) to test if the application generates links, redirects, or emails pointing to the malicious domain, potentially enabling cache poisoning or password reset poisoning, like this Request

```http
GET /reset-password HTTP/1.1  
Host: attacker.com
```
{% endstep %}

{% step %}
Send HTTP requests with the altered Host header and monitor responses for references to the rogue domain in links, redirects, or email content
{% endstep %}

{% step %}
{% hint style="info" %}
The important point is that this vulnerability must be tested in the forgotten password functionality, this is usually a good point to test this vulnerability
{% endhint %}
{% endstep %}
{% endstepper %}

***

#### Adding a Prefix to the Host Header

{% stepper %}
{% step %}
Prepend a malicious prefix to the target domain (e.g., attackertarget.com) to trick the application into processing requests as if they originate from a legitimate domain,&#x20;

```http
GET /admin.php HTTP/1.1
Host: attackertarget.com
```
{% endstep %}

{% step %}
Analyze responses for generated URLs or redirects that include the prefixed domain, indicating a bypass of host validation
{% endstep %}
{% endstepper %}

***

#### Using Absolute URL Path in Host Header

{% stepper %}
{% step %}
Inject a full URL (e.g., https://target.com/admin.php) into the Host header to exploit applications that parse it as part of the request path, potentially bypassing filters or confusing backend logic

```http
GET /admin.php HTTP/1.1
Host: https://target.com/admin.php
```
{% endstep %}

{% step %}
Check for server errors, redirects, or unexpected responses that suggest improper parsing of the Host header
{% endstep %}
{% endstepper %}

***

#### Subdomain-Based Host Injection

{% stepper %}
{% step %}
Supply a subdomain of the target (e.g., subdomain.target.com) to test if weak validation allows access to restricted resources or bypasses access controls

```http
GET /admin.php HTTP/1.1
Host: subdomain.target.com
```
{% endstep %}

{% step %}
Monitor responses for successful access to protected pages or data leaks, indicating a failure in subdomain-specific validation
{% endstep %}
{% endstepper %}

***

#### Injecting Leading Spaces or Tabs

{% stepper %}
{% step %}
Add leading spaces or tabs to the Host header to exploit inconsistent header parsing by servers or proxies, potentially causing misrouting or access to unintended resources

```http
GET /admin.php HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Observe response differences, such as routing to default virtual hosts or error pages, to identify parsing vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Specifying a Non-Standard Port

{% stepper %}
{% step %}
Include a port in the Host header (e.g., target.com:8080) to test if the application bypasses host-based access controls or misroutes requests due to port-specific logic

```http
GET /admin.php HTTP/1.1
Host: target.com:8080
```
{% endstep %}

{% step %}
Analyze responses for changes in routing, error codes, or access to restricted endpoints, indicating potential misconfigurations
{% endstep %}
{% endstepper %}

***

#### Manipulating X-Forwarded-Host Header

{% stepper %}
{% step %}
Inject a malicious domain into the X-Forwarded-Host header to test if proxies or applications trust it over the Host header, potentially redirecting requests to attacker-controlled servers

```http
GET /admin.php HTTP/1.1
X-Forwarded-Host: attacker.com
```
{% endstep %}

{% step %}
Check for responses that include the malicious domain in links, redirects, or API calls, confirming improper header handling
{% endstep %}
{% endstepper %}

***

#### Using Server’s IP Address

{% stepper %}
{% step %}
Replace the domain in the Host header with the server’s IP address to bypass virtual host routing or access controls, potentially accessing default or unintended virtual hosts.

```http
GET /admin.php HTTP/1.1
Host: <target IP>
```
{% endstep %}

{% step %}
Monitor responses for exposed resources or different content served compared to the domain-based request
{% endstep %}
{% endstepper %}

***

#### Empty Host Header Testing

{% stepper %}
{% step %}
Send a blank Host header to test if the server defaults to the first virtual host or exhibits unexpected behavior, potentially exposing sensitive resources

```http
GET /admin.php HTTP/1.1
Host: 
```
{% endstep %}

{% step %}
Analyze responses for default pages, error messages, or access to unintended virtual hosts, indicating misconfigured server logic
{% endstep %}
{% endstepper %}

***

#### Multiple Host Headers

{% stepper %}
{% step %}
Send multiple Host headers with conflicting values (e.g., target.com and attacker.com) to exploit inconsistencies between frontend and backend parsing, potentially bypassing validation

```http
GET /admin.php HTTP/1.1
Host: target.com
Host: attacker.com
```
{% endstep %}

{% step %}
Check for responses that prioritize the malicious Host header, leading to redirects, links, or data exposure to attacker-controlled domains
{% endstep %}
{% endstepper %}

***

#### Targeting Another Site on the Same IP

{% stepper %}
{% step %}
Identify other domains hosted on the same IP and inject one into the Host header to test for access to unintended resources or data from co-hosted sites

```http
GET /admin.php HTTP/1.1
Host: target2.com
```
{% endstep %}

{% step %}
Monitor responses for content from the alternate domain, indicating improper virtual host isolation or shared resource exposure
{% endstep %}
{% endstepper %}

***

#### Host Header Injection in SSRF

{% stepper %}
{% step %}
Inject an internal hostname (e.g., internal-service.local) into the Host header to test for SSRF vulnerabilities, bypassing filters that rely on Host header validation

```http
Host: internal-service.local
```
{% endstep %}

{% step %}
Analyze responses for access to internal APIs, metadata services, or restricted endpoints, confirming SSRF exploitability
{% endstep %}
{% endstepper %}

***

#### DNS Rebinding via Host Header

{% stepper %}
{% step %}
Use a rebinding domain (e.g., rebinding.attacker.com) in the Host header to trick the application into processing requests that bypass same-origin or network protections

```http
Host: rebinding.attacker.com
```
{% endstep %}

{% step %}
Test for responses that allow access to internal resources or violate same-origin policies, leveraging DNS rebinding services for validation
{% endstep %}
{% endstepper %}

***

#### Injecting Special Characters in Host Header

{% stepper %}
{% step %}
Insert special characters (e.g., null bytes, CRLF, or Unicode) into the Host header to bypass validation filters or trigger parsing errors that expose sensitive functionality

```http
GET /admin.php HTTP/1.1
Host: target.com%00.attacker.com
```
{% endstep %}

{% step %}
Monitor responses for errors, misrouting, or unexpected access to resources, indicating filter bypass vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Path Traversal in Host Header

{% stepper %}
{% step %}
Inject path traversal sequences (e.g., ../../attacker.com) into the Host header to test if the application misinterprets it as part of the request path, leading to unintended behavior

```http
GET /admin.php HTTP/1.1
Host: ../../attacker.com
```
{% endstep %}

{% step %}
Analyze responses for path traversal effects, such as access to restricted endpoints or server errors, indicating parsing vulnerabilities
{% endstep %}
{% endstepper %}

***

#### Encoded Host Header Values

{% stepper %}
{% step %}
Use URL-encoded or double-encoded values in the Host header (e.g., %74%61%72%67%65%74.com) to bypass validation mechanisms or confuse parsing logic

```http
GET /admin.php HTTP/1.1
Host: %74%61%72%67%65%74.com
```
{% endstep %}

{% step %}
Check for responses that process the encoded header as valid, potentially leading to redirects or access to attacker-controlled domains
{% endstep %}
{% endstepper %}

***

#### Chaining X-Forwarded Headers for Injection

{% stepper %}
{% step %}
Inject malicious payloads into X-Forwarded-Host or X-Forwarded-For headers to test for XSS or SQL injection vulnerabilities, exploiting improper header handling in frontend or backend systems

```http
X-Forwarded-Host: evil.com"><img src/onerror=prompt(document.cookie)>

X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
```
{% endstep %}

{% step %}
Monitor responses for script execution (e.g., XSS via prompt(document.cookie)) or delayed responses (e.g., SQLi via sleep-based payloads), confirming injection success
{% endstep %}
{% endstepper %}

***

#### Host Header Injection via Account Takeover

{% stepper %}
{% step %}
Intercept the password reset request using a proxy tool to capture headers, parameters, and body content, identifying the structure of the request sent to the server
{% endstep %}

{% step %}
Analyze the Host header and related headers like Origin or Referer to understand how the application processes domain inputs during the password reset flow
{% endstep %}

{% step %}
Examine the request body for parameters such as username or email to confirm the data triggering the reset link generation
{% endstep %}

{% step %}
Modify the Host header with a malicious domain (e.g., attacker.com) to test if the server reflects it in the password reset link sent to the user’s email
{% endstep %}

{% step %}
Send the modified request and check the email for the reset link, noting if the malicious domain appears in the URL or token path
{% endstep %}

{% step %}
Document the reset link’s URL and token, assessing whether it points to the attacker-controlled domain and is clickable
{% endstep %}

{% step %}
Test appending a malicious prefix to the target domain (e.g., attacker.login.redacted.com) in the Host header to bypass domain validation checks
{% endstep %}

{% step %}
Submit the request and verify if the reset link reflects the prefixed domain, checking for server-side truncation or errors (e.g., stripping .com from the prefix)
{% endstep %}

{% step %}
Evaluate if the resulting link leads to an inaccessible host or “site can’t be reached” error, indicating partial validation by the server
{% endstep %}

{% step %}
Inject a malicious domain with a colon separator (e.g., attacker.com:login.redacted.com) in the Host header to exploit improper parsing of domain components
{% endstep %}

{% step %}
Send the request and monitor the email for a reset link containing the malicious domain in its correct form (e.g., https://attacker.com/...)
{% endstep %}

{% step %}
Verify if clicking the link triggers an HTTP pingback to an attacker-controlled server (e.g., Burp Collaborator), confirming token leakage
{% endstep %}

{% step %}
Document the exact Host header manipulation (e.g., colon injection), the resulting reset link, and any received pingbacks with tokens for proof-of-concept
{% endstep %}

{% step %}
Test additional headers like X-Forwarded-Host with a malicious domain to check if the server prioritizes it over the Host header in the reset link generation
{% endstep %}

{% step %}
Analyze server responses for inconsistencies in domain handling, noting any bypasses that result in a functional reset link pointing to the attacker’s domain
{% endstep %}

{% step %}
Reproduce the attack multiple times to confirm reliability, ensuring the manipulation consistently delivers a usable reset token to the attacker
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
