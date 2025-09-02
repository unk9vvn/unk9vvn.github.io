# Review Webpage Content

## Check List

* [ ] Review webpage comments and metadata to find any information leakage.
* [ ] Gather JavaScript files and review the JS code to better understand the application and to find any information leakage.
* [ ] Identify if source map files or other front-end debug files exist.

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
