# Review Webpage Content

## Check List

* [ ] Review webpage comments and metadata to find any information leakage.
* [ ] Gather JavaScript files and review the JS code to better understand the application and to find any information leakage.
* [ ] Identify if source map files or other front-end debug files exist.

## Methodology

#### Comment and Metadata

{% stepper %}
{% step %}
Fetch the target webpage and parse all HTML comments to extract developer notes, author details, email addresses, API keys, internal IPs, or hardcoded credentials often left in production code
{% endstep %}

{% step %}
Retrieve dashboard or admin pages and inspect embedded comments for sensitive information such as admin usernames, passwords, backup server IPs, SMTP credentials, or debug API endpoints
{% endstep %}

{% step %}
Access XML files or endpoints and examine DOCTYPE declarations containing inline comments to uncover author information, API keys, or structural notes about sensitive data handling
{% endstep %}

{% step %}
Parse XML DTD sections for comments revealing admin credentials, SFTP keys, or access control structures that should not be exposed in production
{% endstep %}

{% step %}
Scrape HTML tags from the target page to extract non-standard metadata fields like author, email, api-key, or custom attributes that may contain sensitive configuration data
{% endstep %}

{% step %}
Automate extraction of all HTML comments across multiple pages using crawling tools to identify patterns of leaked credentials or internal documentation
{% endstep %}

{% step %}
Search for version control hints, environment indicators (e.g., “Staging”), or debug flags within comments and metadata to confirm environment type and potential misconfigurations
{% endstep %}

{% step %}
Cross-reference extracted emails, usernames, or API keys with external breach databases or password lists to assess reuse and exploitation potential
{% endstep %}

{% step %}
Document all findings with full context (URL, comment block, metadata field) to build high-impact proof-of-concept reports for responsible disclosure
{% endstep %}
{% endstepper %}

***

#### Identifying JavaScript Code and Gathering JavaScript File

{% stepper %}
{% step %}
Fetch the target webpage and parse all tags to extract inline JavaScript code, identifying sensitive data such as API keys, database connection strings, or authentication tokens embedded within configuration objects
{% endstep %}

{% step %}
Analyze inline JavaScript for function calls or external API integrations (e.g., Google Maps, reCAPTCHA) to uncover hardcoded credentials or keys that could be exploited for unauthorized access
{% endstep %}

{% step %}
Inspect JavaScript code for fetch requests or AJAX calls to internal endpoints, noting headers like Authorization that may expose bearer tokens or sensitive API keys
{% endstep %}

{% step %}
Crawl the target website to enumerate all JavaScript files (.js) referenced in tags or dynamically loaded, capturing URLs for further analysis
{% endstep %}

{% step %}
Use a web crawling tool to extract URLs ending in .js, focusing on files hosted on the target domain or third-party services to identify configuration scripts or libraries
{% endstep %}

{% step %}
Download identified JavaScript files and search for sensitive information such as API keys, database credentials, or internal endpoints exposed within the code
{% endstep %}

{% step %}
Cross-reference extracted keys or tokens with external services (e.g., Google APIs, reCAPTCHA) to verify their validity and assess potential misuse risks
{% endstep %}

{% step %}
Analyze JavaScript files for commented-out sections or debug logs that may reveal internal logic, environment details, or sensitive data inadvertently left in production
{% endstep %}

{% step %}
Document all findings, including script locations, extracted keys, and affected endpoints, to create a comprehensive proof-of-concept for responsible disclosure
{% endstep %}

{% step %}
Assess the impact of exposed credentials or tokens, such as unauthorized API access, data leakage, or database compromise, to prioritize reporting based on severity
{% endstep %}
{% endstepper %}

***

#### Identifying Source Map Files

{% stepper %}
{% step %}
Crawl the target website to enumerate all URLs, focusing on locating source map files (.map) that reveal original source code paths, internal file structures, or developer comments
{% endstep %}

{% step %}
Inspect retrieved source map files for sensitive information such as absolute file paths (e.g., /home/sysadmin/project/src) or project-specific details that expose development environment structures
{% endstep %}

{% step %}
Analyze source map JSON files for embedded credentials, such as client IDs, client secrets, or OAuth token URIs, that could enable unauthorized access to external services
{% endstep %}

{% step %}
Use a URL discovery tool to extract all accessible endpoints from the target, identifying pages, APIs, or static files that may link to source maps or sensitive resources
{% endstep %}

{% step %}
Employ a web crawling tool to comprehensively map the target’s URLs, prioritizing endpoints that reference JavaScript or CSS files potentially linked to source maps
{% endstep %}

{% step %}
Filter crawled URLs for CSS files (.css) to identify stylesheets, checking for references to source maps or comments containing sensitive configuration data
{% endstep %}

{% step %}
Run a specialized tool to extract JavaScript and CSS links from the target, focusing on endpoints that may expose source map files or internal API references
{% endstep %}

{% step %}
Verify the presence of source maps by appending .map to identified JavaScript or CSS file URLs (e.g., main.chunk.js.map), downloading and parsing them for sensitive data
{% endstep %}

{% step %}
Cross-reference extracted paths or credentials from source maps with the target’s infrastructure to assess risks like code exposure, directory traversal, or service compromise
{% endstep %}

{% step %}
Document all findings, including URLs, source map contents, and exposed credentials, to build a detailed proof-of-concept for responsible disclosure
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Comment and Metadata&#x20;

#### HTML Comment&#x20;

{% hint style="info" %}
Simple Page
{% endhint %}

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sample Page</title>
</head>
<body>
    <h1>Welcome to My Website</h1>

    <!-- 
        Author: John Doe
        Email: johndoe@example.com
        API Key: 12345-ABCDE-67890-FGHIJ
        Last Updated: 2024-10-02
        This section contains confidential information about our project.
    -->

    <p>This is a sample paragraph of text on the page.</p>
    
    <!-- 
        Sensitive information: 
        User credentials for accessing the database:
        Username: admin
        Password: SuperSecretPassword123
    -->

    <footer>
        <p>&copy; 2024 My Website</p>
    </footer>
</body>
</html>
```

{% hint style="info" %}
Dashboard Page
{% endhint %}

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internal Admin Portal</title>
</head>
<body>
    <h1>Admin Dashboard</h1>

    <!-- 
        Developer Instructions:
        - Do not expose these credentials in production.
        Admin Username: master_admin
        Admin Password: qwertySecurePass2024!
        Backup Server IP: 172.16.10.45
        SMTP Server: smtp.internal.example.com
        SMTP Credentials: admin@example.com / Password1234!
    -->

    <p>Access the secure features of the admin panel below.</p>

    <!-- 
        Debug Info:
        Current Environment: Staging
        API Endpoint: https://staging-api.example.com/v1/
        API Key: ABCD1234EFGH5678IJKL  // Use this for all API requests
    -->

    <footer>
        <p>&copy; 2024 Internal Admin Portal</p>
    </footer>
</body>
</html>

```

#### DTD XML

{% hint style="info" %}
DOCTYPE note
{% endhint %}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
    <!-- 
        Author: Jane Doe
        Email: janedoe@example.com
        API Key: ABCDEFGHIJKL-12345
        This DTD defines the structure for sensitive information.
    -->
    <!ELEMENT note (to, from, heading, body)>
    <!ELEMENT to (#PCDATA)>
    <!ELEMENT from (#PCDATA)>
    <!ELEMENT heading (#PCDATA)>
    <!ELEMENT body (#PCDATA)>
]>

<note>
    <to>Tove</to>
    <from>Jani</from>
    <heading>Reminder</heading>
    <body>Don't forget me this weekend!</body>
</note>
```

{% hint style="info" %}
DOCTYPE Credentials
{% endhint %}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credentials [
    <!-- 
        Admin Credentials:
        Username: super_user
        Password: 12345StrongPass!
        SFTP Access Key: X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6
        Use this DTD to structure access control for internal users.
    -->
    <!ELEMENT credentials (user, password, access_key)>
    <!ELEMENT user (#PCDATA)>
    <!ELEMENT password (#PCDATA)>
    <!ELEMENT access_key (#PCDATA)>
]>

<credentials>
    <user>admin</user>
    <password>adminPass2024!</password>
    <access_key>X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6</access_key>
</credentials>

```

#### Meta Tags

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sample Page</title>

    <!-- 
        Meta Information:
        Author: Alice Smith
        Email: alicesmith@example.com
        API Key: ZYXWVUTSRQP-98765
        Description: This page contains confidential information.
    -->

    <meta name="author" content="Alice Smith">
    <meta name="email" content="alicesmith@example.com"> <!-- Sensitive info -->
    <meta name="api-key" content="ZYXWVUTSRQP-98765"> <!-- Sensitive info -->
    <meta name="description" content="This is a sample webpage.">
</head>
<body>
    <h1>Welcome to My Website</h1>
    <p>This is a sample paragraph of text on the page.</p>
</body>
</html>

```

### Identifying JavaScript Code and Gathering JavaScript File &#x20;

#### tag \<script>

```javascript
<script>
const config = {
  GOOGLE_MAP_API_KEY: "AIzaSyDUEBnKgwiqMNpDplT6ozE4Z0XxuAbqDi4",
  RECAPTCHA_KEY: "6LcPscEUiAAAAHOwwM3fGvIx9rsPYUq62uRhGjJ0"
};

function initializeGoogleMap() {
  const script = document.createElement('script');
  script.src = `https://maps.googleapis.com/maps/api/js?key=${config.GOOGLE_MAP_API_KEY}`;
  script.async = true;
  script.defer = true;
  document.head.appendChild(script);
}

function executeRecaptcha() {
  grecaptcha.ready(function() {
    grecaptcha.execute(config.RECAPTCHA_KEY, { action: 'submit' }).then(function(token) {
      console.log('Recaptcha Token:', token);
    });
  });
}

initializeGoogleMap();
executeRecaptcha();
<script/>
```

```javascript
    <script>
        const config = {
            FETCH_API_KEY: "XYZ12345-APITOKEN-SENSITIVE",  // Sensitive info
            DB_CONNECTION_STRING: "mongodb+srv://admin:secretPassword@cluster0.mongodb.net/secureDB"  // Sensitive DB info
        };

        function fetchData() {
            fetch('https://internal-api.example.com/data', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${config.FETCH_API_KEY}`,
                }
            })
            .then(response => response.json())
            .then(data => console.log('Fetched data:', data))  // Potential exposure of sensitive data
            .catch(error => console.error('Error fetching data:', error));
        }

        fetchData();
    </script>
```

#### JS Sources

#### [Katana](https://github.com/projectdiscovery/katana)

```bash
katana -u $WEBSITE | grep "\.js$"
```

#### [GoSpider](https://github.com/jaeles-project/gospider)

```bash
gospider –s $WEBSITE | grep "\.js$"
```

### Identifying Source Map Files&#x20;

#### Black Box&#x20;

```json
{
  "version": 3,
  "file": "static/js/main.chunk.js",
  "sources": [
    "/home/sysadmin/cashsystem/src/actions/index.js",
    "/home/sysadmin/cashsystem/src/actions/reportAction.js",
    "/home/sysadmin/cashsystem/src/actions/cashoutAction.js",
    "/home/sysadmin/cashsystem/src/actions/userAction.js"
  ]
}
```

```json
{
    "installed": {
        "client_id": "█████",
        "project_id": "███████",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": "████████",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
    }
}
```

#### HTML Sources

#### [Gau](https://github.com/lc/gau)

```bash
gau $WEBSITE
```

#### [Katana](https://github.com/projectdiscovery/katana)

```bash
katana -u $WEBSITE 
```

#### [GoSpider](https://github.com/jaeles-project/gospider)

```bash
gospider –s $WEBSITE 
```

#### CSS Sources&#x20;

#### [Katana](https://github.com/projectdiscovery/katana)

```bash
katana -u $WEBSITE | grep "\.css*"
```

#### [GoSpider](https://github.com/jaeles-project/gospider)

```bash
gospider –s $WEBSITE | grep "\.css*"
```

#### [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

```bash
linkfinder -d $WEBSITE
```
