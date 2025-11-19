# Directory Traversal File Include

## Check List

## Methodology

### Black Box

#### [Directory Traversal (Local File Inclusion)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#local-file-inclusion)

{% stepper %}
{% step %}
Identify endpoints serving static assets or files such as `/assets/`, `/static/`, `/files/`, or similar paths
{% endstep %}

{% step %}
Map the base directory by requesting valid assets like `/assets/logo.png` or `/assets/style.css`
{% endstep %}

{% step %}
Capture legitimate request using proxy tools like Burp Suite or curl
{% endstep %}

{% step %}
Modify the file path parameter to include traversal sequence `../` immediately after the asset base
{% endstep %}

{% step %}
Construct payload URL as `https://target.com/assets/../build.sbt`
{% endstep %}

{% step %}
Send request and inspect response for non-asset file contents
{% endstep %}

{% step %}
Test for project configuration files using `/assets/../.git/config`
{% endstep %}

{% step %}
Attempt access to build files with `/assets/../build.sbt` or `/assets/../pom.xml`
{% endstep %}

{% step %}
Target application configuration via `/assets/../application.conf` or `/assets/../conf/routes`
{% endstep %}

{% step %}
Test traversal to root directory files like `/assets/../../../../../etc/passwd`
{% endstep %}

{% step %}
Verify Windows environments with `/assets/../../../../../windows/win.ini`
{% endstep %}

{% step %}
Check response headers and body for file contents outside assets directory
{% endstep %}

{% step %}
Confirm successful read by presence of expected file markers like \[core] in `.git/config`
{% endstep %}

{% step %}
Document full request URL and response snippet showing sensitive data
{% endstep %}

{% step %}
Test encoded variations using `%2e%2e%2f` for `../` to bypass basic filters
{% endstep %}

{% step %}
Attempt double encoding `%252e%252e%252f` if single encoding is blocked
{% endstep %}

{% step %}
Verify if trailing slash affects traversal like `/assets/../build.sbt/`
{% endstep %}

{% step %}
Test null byte injection with `/assets/../build.sbt%00.png` if language supports it
{% endstep %}

{% step %}
Check if file extension enforcement can be bypassed by appending `.png` to traversal payload
{% endstep %}

{% step %}
Assess depth of traversal needed based on directory structure from valid assets
{% endstep %}
{% endstepper %}

***

#### File Path & File Access Vulnerabilities

{% stepper %}
{% step %}
Perform reconnaissance by crawling the target website to enumerate all accessible endpoints
{% endstep %}

{% step %}
Use tools like gau to extract archived URLs from various sources and save to a file
{% endstep %}

{% step %}
Employ Burp Suite Spider or custom scripts to crawl and identify hidden or dynamic parameters
{% endstep %}

{% step %}
Collect all URLs into a list for further analysis
{% endstep %}

{% step %}
Filter URLs to identify parameters tied to file operations such as&#x20;

```
file=, document=, folder=, root=, path=, pg=, style=, pdf=, template=, 
php_path=, doc=, page=, name=, cat=, dir=, action=, board=, date=, detail=,
download=, prefix=, include=, inc=, locate=, show=, site=, type=, view=,
content=, layout=, mod=, conf=, url=
```
{% endstep %}

{% step %}
Automate parameter filtering using gf patterns or Burp Suite search functionality
{% endstep %}

{% step %}
Utilize scripts like <sub>PwnTraverse</sub> to highlight potentially dangerous parameters in the URL list
{% endstep %}

{% step %}
Manually inspect isolated parameters for user-controlled input leading to inclusion
{% endstep %}

{% step %}
Capture baseline requests for each parameter using proxy tools like Burp Suite or browser developer tools
{% endstep %}

{% step %}
Test parameters with legitimate file names to confirm normal functionality
{% endstep %}

{% step %}
Inject traversal sequences like `../` to attempt escaping the intended directory
{% endstep %}

{% step %}
Replace parameter values with payloads such as `../etc/passwd` or `../../etc/passwd`
{% endstep %}

{% step %}
Send modified requests and examine response contents for sensitive file disclosure
{% endstep %}

{% step %}
Verify if responses contain system file contents like `/etc/passwd` or directory listings
{% endstep %}

{% step %}
Test additional payloads including `../../../var/www/html/config.php` and `../../../../root/.ssh/id_rsa`
{% endstep %}

{% step %}
Check HTTP response status codes for successful access such as 200 OK
{% endstep %}

{% step %}
Attempt traversal to application-specific files like `config.php` or database credentials
{% endstep %}

{% step %}
Test across different traversal depths by adding more `../` sequences
{% endstep %}

{% step %}
Verify vulnerability on Unix/Linux by targeting `/etc/passwd` and on Windows by targeting files like `C:/Windows/system.ini`
{% endstep %}

{% step %}
Test parameters across all HTTP methods like GET and POST if applicable
{% endstep %}

{% step %}
Check persistence of vulnerability with different file extensions and URL encodings
{% endstep %}
{% endstepper %}

***

#### [Path Traversal Filter Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#null-byte)

{% stepper %}
{% step %}
Many applications that place user input into file paths implement some kind of defense against path traversal attacks, and these can often be circumvented
{% endstep %}

{% step %}
if application blocks or strips directory traversal sequence there is many bypassing technique is available
{% endstep %}

{% step %}
we might directly access absolute path `file=/etc/passwd` with out using any traversal
{% endstep %}

{% step %}
You might be able to use various non-standard encoding, such as `..%c0%af` or `..%252f`, to bypass the input filter
{% endstep %}

{% step %}
filter-bypass-technique might user `....//` or `....\` if one `..../` or `....\` is blocked than after removing them we traverse it
{% endstep %}

{% step %}
If an application requires that the user-supplied filename must start with the expected base folder, such as `/var/www/images`, then it might be possible to include the required base folder followed by suitable traversal sequences. For example `filename=/var/www/images/../../../etc/passwd`
{% endstep %}

{% step %}
If an application requires that the user-supplied filename must end with an expected file extension, such as `.png`, then it might be possible to use a null byte to effectively terminate the file path before the required extension. For example`filename=../../../etc/passwd%00.png`
{% endstep %}
{% endstepper %}

***

#### File Upload Path Traversal (Upload-Based Path Traversal)

{% stepper %}
{% step %}
locate file-related endpoints like `/fileupload`
{% endstep %}

{% step %}
Capture the file upload request using a proxy tool like Burp Suite or curl
{% endstep %}

{% step %}
Test file upload functionality by sending a benign file with a command like&#x20;

```bash
curl -X POST -F "file=@test.txt" https://target.com/fileupload/
```
{% endstep %}

{% step %}
Verify if the uploaded file is publicly accessible by checking the returned URL in a browser
{% endstep %}

{% step %}
Confirm the file’s storage location, noting any CDN or external hosting like cdn.bubble.io
{% endstep %}

{% step %}
Attempt to upload a file with a path traversal sequence in the filename, such as `../../../../../../../etc/passwd`
{% endstep %}

{% step %}
Send the traversal payload using curl and Burp Suite Request

```bash
curl -X POST -F "file=@../../../../../../../etc/passwd" https://target.com/fileupload/
```
{% endstep %}

{% step %}
Check the response for a URL pointing to the uploaded file and access it in a browser
{% endstep %}

{% step %}
Test multiple traversal depths `(../../, ../../../, etc.)` to bypass directory restrictions
{% endstep %}

{% step %}
Attempt to access additional sensitive files like `/etc/group`, `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, `/etc/fstab`, `/etc/profile`, `/etc/issue`, `/etc/nginx/nginx.conf`, and `/etc/mysql/mariadb.conf.d/50-server.cnf`
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
