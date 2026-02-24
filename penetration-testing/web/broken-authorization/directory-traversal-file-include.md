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
Test traversal to root directory files like `/assets/../../../../../etc/passwd`
{% endstep %}

{% step %}
Verify Windows environments with `/assets/../../../../../windows/win.ini`
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
Test across different traversal depths by adding more `../` sequences
{% endstep %}

{% step %}
Verify vulnerability on Unix/Linux by targeting `/etc/passwd` and on Windows by targeting files like `C:/Windows/system.ini`
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

#### Path Injection

{% stepper %}
{% step %}
Map the entire target system using Burp Suite tools
{% endstep %}

{% step %}
Map start and end points in Xmind
{% endstep %}

{% step %}
Decompile the program into the language it was written in
{% endstep %}

{% step %}
Look for file receiving parameters in the endpoints, such as path or filename parameters
{% endstep %}

{% step %}
Then, in the file reception processing logic, check whether the process reads the file directly or not, like the code below

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>Request\.(Query|Params|RouteValues))|(?<Sink>HttpClient\s*\(|GetAsync\s*\(|WebRequest\.Create)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>request\.getParameter|@PathVariable|@RequestParam)|(?<Sink>HttpClient|HttpURLConnection|\.openConnection\s*\(|\.execute\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_(GET|POST|REQUEST))|(?<Sink>curl_exec|file_get_contents\s*\(|fsockopen\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.(params|query|body))|(?<Sink>http\.get\s*\(|axios\s*\(|fetch\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux)**

{% tabs %}
{% tab title="C#" %}
```regex
(Request\.(Query|Params|RouteValues))|(HttpClient\s*\(|GetAsync\s*\(|WebRequest\.Create)
```
{% endtab %}

{% tab title="Java" %}
```regex
(request\.getParameter|@PathVariable|@RequestParam)|(HttpClient|HttpURLConnection|\.openConnection\s*\(|\.execute\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_(GET|POST|REQUEST))|(curl_exec|file_get_contents\s*\(|fsockopen\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.(params|query|body))|(http\.get\s*\(|axios\s*\(|fetch\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```c#
string apiBase = "https://my.api/api/v1";
string orderApi = apiBase + "/order/get";

string apiUrl = orderApi + request.Params["orderId"];

var response = http.Get(apiUrl);
```
{% endtab %}

{% tab title="Java" %}
```java
String apiBase = "https://my.api/api/v1";
String orderApi = apiBase + "/order/get";

String apiUrl = orderApi + request.getParameter("orderId");

HttpResponse<String> response = http.get(apiUrl);
```
{% endtab %}

{% tab title="PHP" %}
```php
$apiBase = "https://my.api/api/v1";
$orderApi = $apiBase . "/order/get";

$apiUrl = $orderApi . $request->params['orderId'];

$response = $http->get($apiUrl);
```
{% endtab %}

{% tab title="Node.js" %}
```js
const apiBase = "https://my.api/api/v1";
const orderApi = apiBase + "/order/get";

const apiUrl = orderApi + request.params.orderId;

const response = http.get(apiUrl);
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

#### Path Traversal + SSRF

{% stepper %}
{% step %}
Map the entire target system using the Burp Suite tool
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Look for features that allow downloading files from an external source
{% endstep %}

{% step %}
Then review the method or function that processes the endpoint of this feature, like in the code below

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>Request\.(Query|Form|Params))|(?<Sink>WebRequest\.Create\s*\(|HttpClient\s*\(|GetStreamAsync\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>@RequestParam|@PathVariable|request\.getParameter|\bString\s+\w+\s*\))|(?<Sink>new\s+URL\s*\(|\.openStream\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_(GET|POST|REQUEST))|(?<Sink>file_get_contents\s*\(|curl_exec\s*\(|fopen\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.(query|params|body))|(?<Sink>http\.get\s*\(|https\.get\s*\(|axios\s*\(|fetch\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
(Request\.(Query|Form|Params))|(WebRequest\.Create\s*\(|HttpClient\s*\(|GetStreamAsync\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regex
(@RequestParam|@PathVariable|request\.getParameter|\bString\s+\w+\s*\))|(new\s+URL\s*\(|\.openStream\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_(GET|POST|REQUEST))|(file_get_contents\s*\(|curl_exec\s*\(|fopen\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.(query|params|body))|(http\.get\s*\(|https\.get\s*\(|axios\s*\(|fetch\s*\()
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void DownloadSubtitles(string subtitleName, string url, string subtitleLanguage, object videoId)
{
    // ...
    using (var outStream = new FileStream(filePath, FileMode.Create))
    using (var webStream = new System.Net.WebClient().OpenRead(url)) // Oops, user controls this URL
    {
        int b;
        while ((b = webStream.ReadByte()) != -1)
        {
            outStream.WriteByte((byte)b);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void downloadSubtitles(String subtitleName, String url, String subtitleLanguage, Object videoId) throws Exception {
    // ...
    try (FileOutputStream out = new FileOutputStream(filePath);
         InputStream in = new URL(url).openStream()) { // Oops, user controls this URL

        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function downloadSubtitles($subtitleName, $url, $subtitleLanguage, $videoId)
{
    // ...
    $out = fopen($filePath, 'w');
    $in = fopen($url, 'r'); // Oops, user controls this URL

    while (!feof($in)) {
        fwrite($out, fgetc($in));
    }

    fclose($in);
    fclose($out);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js

function downloadSubtitles(subtitleName, url, subtitleLanguage, videoId) {
    // ...
    const file = fs.createWriteStream(filePath);

    const client = url.startsWith('https') ? https : http;

    client.get(url, (response) => { // Oops, user controls this URL
        response.on('data', (chunk) => {
            file.write(chunk);
        });

        response.on('end', () => {
            file.end();
        });
    });
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
After downloading the file, check in the code whether it calls functions that perform extraction, such as unzip methods or similar functions

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>Request\.(Query|Form|Params))|(?<Sink>FileStream\s*\(|File\.WriteAll|Path\.Combine)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>@RequestParam|@PathVariable|request\.getParameter|\bString\s+\w+File(Name)?\b)|(?<Sink>new\s+FileOutputStream\s*\(|Files\.write\s*\(|new\s+File\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_(GET|POST|FILES|REQUEST))|(?<Sink>fopen\s*\(|file_put_contents\s*\(|move_uploaded_file)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.(body|query|params|files))|(?<Sink>fs\.writeFile|fs\.createWriteStream|path\.join)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
(Request\.(Query|Form|Params))|(FileStream\s*\(|File\.WriteAll|Path\.Combine)
```
{% endtab %}

{% tab title="Java" %}
```regex
(@RequestParam|@PathVariable|request\.getParameter|\bString\s+\w+File(Name)?\b)|(new\s+FileOutputStream\s*\(|Files\.write\s*\(|new\s+File\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_(GET|POST|FILES|REQUEST))|(fopen\s*\(|file_put_contents\s*\(|move_uploaded_file)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.(body|query|params|files))|(fs\.writeFile|fs\.createWriteStream|path\.join)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public static string UnzipFile(string stagingDir, string zipFileName, string originalFileName)
{
    // ...
    var fos = new FileStream($"{stagingDir}/{originalFileName}", FileMode.Create); // User controls originalFileName

    // Write the file...

    // Later, it gets renamed, but the damage is already done
    File.Move(filePath, newFilePath);

    return newFilePath;
}
```
{% endtab %}

{% tab title="Java" %}
```java
static String unzipFile(String stagingDir, String zipFileName, String originalFileName) throws Exception {
    // ...
    FileOutputStream fos = new FileOutputStream(stagingDir + "/" + originalFileName);  // User controls originalFileName

    // Write the file...

    // Later, it gets renamed, but the damage is already done
    file.renameTo(newFile);

    return newFile.getPath();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function unzipFile($stagingDir, $zipFileName, $originalFileName)
{
    // ...
    $fos = fopen($stagingDir . "/" . $originalFileName, 'w'); // User controls originalFileName

    // Write the file...

    // Later, it gets renamed, but the damage is already done
    rename($filePath, $newFilePath);

    return $newFilePath;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function unzipFile(stagingDir, zipFileName, originalFileName) {
    // ...
    const fos = fs.createWriteStream(`${stagingDir}/${originalFileName}`); // User controls originalFileName

    // Write the file...

    // Later, it gets renamed, but the damage is already done
    fs.renameSync(filePath, newFilePath);

    return newFilePath;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

#### Path Traversal to RCE

{% stepper %}
{% step %}
Map the entire target system or product using the Burp Suite tool
{% endstep %}

{% step %}
Draw the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
In the service, find a feature that creates its own custom command-line interface (such as `cmd`)
{% endstep %}

{% step %}
Then identify the switches and commands in this command-line interface that are related to authentication
{% endstep %}

{% step %}
In the code, find the authentication endpoint processing logic (like in the code below). Determine the request type and review the inputs it receives

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("Login")]
public IActionResult Login([FromBody] CheckCredentialReq req) // [1]
{
    CheckCredentialResp checkCredentialResp = new CheckCredentialResp();
    this.ValidateLoginInput(req);

    try
    {
        var stopwatch = new Stopwatch();
        stopwatch.Start();

        checkCredentialResp = new AuthenticationCore().DoLogin(req); // [2]

        stopwatch.Stop();
        base.logger.LogInfo(
            $"Total time taken to execute login: [{stopwatch.Elapsed.TotalSeconds:0.00}] second(s)",
            "Login",
            57
        );
    }
    catch (Exception ex)
    {
        base.logger.LogError(ex.Message + " : " + ex.StackTrace, "Login", 61);
        checkCredentialResp.errList = checkCredentialResp?.errList ?? new List<Error>();

        if (checkCredentialResp.errList.Count == 0)
        {
            checkCredentialResp.errList.Add(new Error
            {
                errorCode = 500,
                errLogMessage = "Internal server error."
            });
        }
    }

    return this.Ok(checkCredentialResp);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("Login")
public ResponseEntity<CheckCredentialResp> login(@RequestBody CheckCredentialReq req) { // [1]

    CheckCredentialResp checkCredentialResp = new CheckCredentialResp();
    this.validateLoginInput(req);

    try {
        long startTime = System.currentTimeMillis();

        checkCredentialResp = new AuthenticationCore().doLogin(req); // [2]

        long endTime = System.currentTimeMillis();
        double elapsedSeconds = (endTime - startTime) / 1000.0;

        logger.info(String.format("Total time taken to execute login: [%.2f] second(s)", elapsedSeconds));
    } catch (Exception ex) {
        logger.error(ex.getMessage() + " : " + Arrays.toString(ex.getStackTrace()));

        if (checkCredentialResp == null || checkCredentialResp.getErrList() == null) {
            checkCredentialResp.setErrList(new ArrayList<>());
        }

        if (checkCredentialResp.getErrList().isEmpty()) {
            checkCredentialResp.getErrList().add(new Error(500, "Internal server error."));
        }
    }

    return ResponseEntity.ok(checkCredentialResp);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function login(CheckCredentialReq $req)
{
    $checkCredentialResp = new CheckCredentialResp();
    $this->validateLoginInput($req);

    try {
        $start = microtime(true);

        $checkCredentialResp = (new AuthenticationCore())->doLogin($req); // [2]

        $end = microtime(true);
        $elapsed = $end - $start;
        $this->logger->info(sprintf("Total time taken to execute login: [%.2f] second(s)", $elapsed));
    } catch (Exception $ex) {
        $this->logger->error($ex->getMessage() . " : " . $ex->getTraceAsString());

        if (!isset($checkCredentialResp->errList) || $checkCredentialResp->errList === null) {
            $checkCredentialResp->errList = [];
        }

        if (count($checkCredentialResp->errList) === 0) {
            $checkCredentialResp->errList[] = (object)[
                'errorCode' => 500,
                'errLogMessage' => 'Internal server error.'
            ];
        }
    }

    return $this->ok($checkCredentialResp);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
router.post('/Login', async (req, res) => { // [1]
    let checkCredentialResp = {};

    try {
        const start = Date.now();

        checkCredentialResp = await new AuthenticationCore().doLogin(req.body); // [2]

        const elapsed = (Date.now() - start) / 1000;
        logger.info(`Total time taken to execute login: [${elapsed.toFixed(2)}] second(s)`);
    } catch (ex) {
        logger.error(`${ex.message} : ${ex.stack}`);

        if (!checkCredentialResp.errList) {
            checkCredentialResp.errList = [];
        }

        if (checkCredentialResp.errList.length === 0) {
            checkCredentialResp.errList.push({
                errorCode: 500,
                errLogMessage: "Internal server error."
            });
        }
    }

    res.json(checkCredentialResp);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the code flow and the used functions to check whether, under certain conditions, user input can be passed to the authentication switch in the command-line interface. (In this example, the authentication switch in the CLI is `QLogin`, which is used in line `[1]` in the code below

{% tabs %}
{% tab title="C#" %}
```csharp
private bool DoRemoteCSLogin(CheckCredentialReq loginRequest, ref CheckCredentialResp loginResponse)
{
    int num = 0;
    string empty = string.Empty;
    bool flag = !loginRequest.usernameFieldSpecified;
    bool result;

    if (flag)
    {
        base.logger.LogError("username is not specified. Invalid remote CS login.", "DoRemoteCSLogin", 2154);
        this.FillLoginResponseWithError(ref loginResponse, num, empty, 1127, "unknown error", "");
        result = false;
    }
    else
    {
        bool flag2 = !this.DecodePass(ref loginRequest, ref loginResponse);
        if (flag2)
        {
            result = false;
        }
        else
        {
            loginRequest.username = this.GetFullUsername(loginRequest);
            string commserverName = loginRequest.commserver.Split('*')[0];

            string text;
            string text2;
            num = new QLogin().DoQlogin(loginRequest.commserver, loginRequest.username, loginRequest.password, out text, out text2, out empty, 5, false); // [1]

            bool flag3 = num == 0;
            if (flag3)
            {
                base.logger.LogTrace("Commcell login succeeded for user " + loginRequest.username + " for Commserver " + loginRequest.commserver, "DoRemoteCSLogin", 2175);

                int value;
                string text3;
                num = new QLogin().GetQSDKUserInfo(commserverName, loginRequest.username, text, out value, out text3, out empty); // [2]

                bool flag4 = num == 0;
                if (flag4)
                {
                    // ...
                }
            }
        }
    }

    return result;
}
```
{% endtab %}

{% tab title="Java" %}
```java
private boolean doRemoteCSLogin(CheckCredentialReq loginRequest, CheckCredentialResp loginResponse) {
    int num = 0;
    String empty = "";
    boolean result;

    boolean flag = !loginRequest.isUsernameFieldSpecified();
    if (flag) {
        logger.error("username is not specified. Invalid remote CS login.");
        fillLoginResponseWithError(loginResponse, num, empty, 1127, "unknown error", "");
        result = false;
    } else {
        boolean flag2 = !decodePass(loginRequest, loginResponse);
        if (flag2) {
            result = false;
        } else {
            loginRequest.setUsername(getFullUsername(loginRequest));
            String commserverName = loginRequest.getCommserver().split("\\*")[0];

            String text;
            String text2;
            num = new QLogin().doQlogin(loginRequest.getCommserver(), loginRequest.getUsername(), loginRequest.getPassword(), out text, out text2, out empty, 5, false); // [1]

            boolean flag3 = num == 0;
            if (flag3) {
                logger.trace("Commcell login succeeded for user " + loginRequest.getUsername() +
                             " for Commserver " + loginRequest.getCommserver());

                int value;
                String text3;
                num = new QLogin().getQSDKUserInfo(commserverName, loginRequest.getUsername(), text, out value, out text3, out empty); // [2]

                boolean flag4 = num == 0;
                if (flag4) {
                    // ...
                }
            }
        }
    }

    return result;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function doRemoteCSLogin($loginRequest, &$loginResponse) {
    $num = 0;
    $empty = "";
    $result = false;

    $flag = !$loginRequest->usernameFieldSpecified;
    if ($flag) {
        $this->logger->error("username is not specified. Invalid remote CS login.");
        $this->fillLoginResponseWithError($loginResponse, $num, $empty, 1127, "unknown error", "");
        $result = false;
    } else {
        $flag2 = !$this->decodePass($loginRequest, $loginResponse);
        if ($flag2) {
            $result = false;
        } else {
            $loginRequest->username = $this->getFullUsername($loginRequest);
            $commserverName = explode('*', $loginRequest->commserver)[0];

            $text = null;
            $text2 = null;
            $num = (new QLogin())->doQlogin($loginRequest->commserver, $loginRequest->username, $loginRequest->password, $text, $text2, $empty, 5, false); // [1]

            $flag3 = $num === 0;
            if ($flag3) {
                $this->logger->trace("Commcell login succeeded for user {$loginRequest->username} for Commserver {$loginRequest->commserver}");

                $value = null;
                $text3 = null;
                $num = (new QLogin())->getQSDKUserInfo($commserverName, $loginRequest->username, $text, $value, $text3, $empty); // [2]

                $flag4 = $num === 0;
                if ($flag4) {
                    // ...
                }
            }
        }
    }

    return $result;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function doRemoteCSLogin(loginRequest, loginResponse) {
    let num = 0;
    let empty = "";
    let result = false;

    const flag = !loginRequest.usernameFieldSpecified;
    if (flag) {
        logger.error("username is not specified. Invalid remote CS login.");
        fillLoginResponseWithError(loginResponse, num, empty, 1127, "unknown error", "");
        result = false;
    } else {
        const flag2 = !decodePass(loginRequest, loginResponse);
        if (flag2) {
            result = false;
        } else {
            loginRequest.username = getFullUsername(loginRequest);
            const commserverName = loginRequest.commserver.split('*')[0];

            let text, text2;
            num = (new QLogin()).doQlogin(loginRequest.commserver, loginRequest.username, loginRequest.password, (t, t2, e) => { text = t; text2 = t2; empty = e; }, 5, false); // [1]

            const flag3 = num === 0;
            if (flag3) {
                logger.trace(`Commcell login succeeded for user ${loginRequest.username} for Commserver ${loginRequest.commserver}`);

                let value, text3;
                num = (new QLogin()).getQSDKUserInfo(commserverName, loginRequest.username, text, (v, t3, e) => { value = v; text3 = t3; empty = e; }); // [2]

                const flag4 = num === 0;
                if (flag4) {
                    // ...
                }
            }
        }
    }

    return result;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Enter the function and check whether the inputs and arguments used for `QLogin` are placed directly into command instructions. (In the example below, `commserver`, which is user input, is used as `text` and `text2` in the code above

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(string\.Format\s*\()|(\$\s*".*-\w+\s*\{.*\}")|(Process(StartInfo)?\s*\()|(handleQAPIReq\s*\()|(Split\s*\(\s*['"].\*['"])
```
{% endtab %}

{% tab title="Java" %}
```regex
(String\.format\s*\()|(\$\s*".*-\w+\s*\{.*\}")|(Runtime\.getRuntime\(\)\.exec)|(ProcessBuilder\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(sprintf\s*\()|(`.*\$\w+.*`)|(shell_exec\s*\()|(exec\s*\()|(system\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(exec\s*\()|(spawn\s*\()|(child_process)|(template\s*string\s*`.*-\w+\$\{.*\}`)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
string\.Format\s*\(|\$\s*".*-\w+\s*\{.*\}"|Process(StartInfo)?\s*\(|handleQAPIReq\s*\(|Split\s*\(\s*['"].\*['"]
```
{% endtab %}

{% tab title="Java" %}
```regex
String\.format\s*\(|\$\s*".*-\w+\s*\{.*\}"|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regex
sprintf\s*\(|`.*\$\w+.*`|shell_exec\s*\(|exec\s*\(|system\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regex
exec\s*\(|spawn\s*\(|child_process|`.*-\w+\$\{.*\}`
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
internal int DoQlogin(string commserverName, string userName, string password, out string token, out string qsdkGuid, out string errorString, int samlTokenValidityInMins = 5, bool isCreateSamlTokenRequest = false)
{
    string[] array = commserverName.Split('*', StringSplitOptions.None);
    string text = array[0];
    string text2 = string.IsNullOrEmpty(this.csClientName) ? text : this.csClientName;
    string text3;
    errorString = text3 = string.Empty;
    qsdkGuid = text3;
    token = text3;

    if (array.Length > 1)
    {
        text2 = array[1];
    }

    string commandParameters = string.Empty;

    if (isCreateSamlTokenRequest)
    {
        commandParameters = string.Format("-cs {0} -csn {1} -getsamlToken -gt -u {2} -clp {3} -validformins {4} -featureType {5}",
            text, text2, userName, password, samlTokenValidityInMins, this.SAMLTokenFeatureType); // [1]
    }
    else
    {
        commandParameters = string.Format(" -cs {0} -csn {1} -gt -u {2} -clp {3} ",
            text, text2, userName, password); // [2]
    }

    string pinfoXML = QLogin.GetPInfoXML(0, string.Empty, 0,
        Convert.ToInt32(QLogin.QCOMMANDS.QCOMMAND_LOGIN).ToString(),
        Convert.ToInt32(QLogin.QAPI_OperationSubType.QQAPI_OPERATION_NOSUBCOMMAND).ToString(),
        0U, commandParameters, commserverName, null, false, null); // [3]

    string empty = string.Empty;
    string empty2 = string.Empty;
    int num = new QAPICommandCppSharp().handleQAPIReq(pinfoXML, empty, ref empty2); // [4]

    if (num == 0)
    {
        token = empty2;
        if (!isCreateSamlTokenRequest)
        {
            string xml = CVWebConf.GetDecryptedPassword(token);
            QAllTokenInfo qallTokenInfo = new QAllTokenInfo();
            XMLDecoder.ReadXml(xml, qallTokenInfo);
            qsdkGuid = CVWebConf.decodePass(Convert.ToBase64String(qallTokenInfo.tokenInfo[0].guid));
        }
    }

    return num;
}
```
{% endtab %}

{% tab title="Java" %}
```java
int doQlogin(String commserverName, String userName, String password, Holder<String> token, Holder<String> qsdkGuid, Holder<String> errorString, int samlTokenValidityInMins, boolean isCreateSamlTokenRequest) {
    String[] array = commserverName.split("\\*");
    String text = array[0];
    String text2 = (this.csClientName == null || this.csClientName.isEmpty()) ? text : this.csClientName;
    String text3 = "";
    errorString.value = text3;
    qsdkGuid.value = text3;
    token.value = text3;

    if (array.length > 1) {
        text2 = array[1];
    }

    String commandParameters = "";
    if (isCreateSamlTokenRequest) {
        commandParameters = String.format("-cs %s -csn %s -getsamlToken -gt -u %s -clp %s -validformins %d -featureType %s",
            text, text2, userName, password, samlTokenValidityInMins, this.SAMLTokenFeatureType); // [1]
    } else {
        commandParameters = String.format(" -cs %s -csn %s -gt -u %s -clp %s ", text, text2, userName, password); // [2]
    }

    String pinfoXML = QLogin.getPInfoXML(0, "", 0,
        Integer.toString(QLogin.QCOMMANDS.QCOMMAND_LOGIN.ordinal()),
        Integer.toString(QLogin.QAPI_OperationSubType.QQAPI_OPERATION_NOSUBCOMMAND.ordinal()),
        0, commandParameters, commserverName, null, false, null); // [3]

    String empty = "";
    StringHolder empty2 = new StringHolder("");
    int num = new QAPICommandCppSharp().handleQAPIReq(pinfoXML, empty, empty2); // [4]

    if (num == 0) {
        token.value = empty2.value;
        if (!isCreateSamlTokenRequest) {
            String xml = CVWebConf.getDecryptedPassword(token.value);
            QAllTokenInfo qallTokenInfo = new QAllTokenInfo();
            XMLDecoder.readXml(xml, qallTokenInfo);
            qsdkGuid.value = CVWebConf.decodePass(Base64.getEncoder().encodeToString(qallTokenInfo.tokenInfo[0].guid));
        }
    }

    return num;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function doQlogin($commserverName, $userName, $password, &$token, &$qsdkGuid, &$errorString, $samlTokenValidityInMins = 5, $isCreateSamlTokenRequest = false) {
    $array = explode('*', $commserverName);
    $text = $array[0];
    $text2 = empty($this->csClientName) ? $text : $this->csClientName;
    $text3 = "";
    $errorString = $text3;
    $qsdkGuid = $text3;
    $token = $text3;

    if (count($array) > 1) {
        $text2 = $array[1];
    }

    if ($isCreateSamlTokenRequest) {
        $commandParameters = sprintf("-cs %s -csn %s -getsamlToken -gt -u %s -clp %s -validformins %d -featureType %s",
            $text, $text2, $userName, $password, $samlTokenValidityInMins, $this->SAMLTokenFeatureType); // [1]
    } else {
        $commandParameters = sprintf(" -cs %s -csn %s -gt -u %s -clp %s ", $text, $text2, $userName, $password); // [2]
    }

    $pinfoXML = QLogin::getPInfoXML(0, "", 0, strval(QLogin::QCOMMANDS['QCOMMAND_LOGIN']), strval(QLogin::QAPI_OperationSubType['QQAPI_OPERATION_NOSUBCOMMAND']), 0, $commandParameters, $commserverName, null, false, null); // [3]

    $empty = "";
    $empty2 = "";
    $num = (new QAPICommandCppSharp())->handleQAPIReq($pinfoXML, $empty, $empty2); // [4]

    if ($num === 0) {
        $token = $empty2;
        if (!$isCreateSamlTokenRequest) {
            $xml = CVWebConf::getDecryptedPassword($token);
            $qallTokenInfo = new QAllTokenInfo();
            XMLDecoder::readXml($xml, $qallTokenInfo);
            $qsdkGuid = CVWebConf::decodePass(base64_encode($qallTokenInfo->tokenInfo[0]->guid));
        }
    }

    return $num;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function doQlogin(commserverName, userName, password, callback, samlTokenValidityInMins = 5, isCreateSamlTokenRequest = false) {
    let array = commserverName.split('*');
    let text = array[0];
    let text2 = !this.csClientName ? text : this.csClientName;
    let token = "";
    let qsdkGuid = "";
    let errorString = "";

    if (array.length > 1) {
        text2 = array[1];
    }

    let commandParameters = "";
    if (isCreateSamlTokenRequest) {
        commandParameters = `-cs ${text} -csn ${text2} -getsamlToken -gt -u ${userName} -clp ${password} -validformins ${samlTokenValidityInMins} -featureType ${this.SAMLTokenFeatureType}`; // [1]
    } else {
        commandParameters = ` -cs ${text} -csn ${text2} -gt -u ${userName} -clp ${password} `; // [2]
    }

    let pinfoXML = QLogin.getPInfoXML(0, "", 0, QLogin.QCOMMANDS.QCOMMAND_LOGIN.toString(),
        QLogin.QAPI_OperationSubType.QQAPI_OPERATION_NOSUBCOMMAND.toString(),
        0, commandParameters, commserverName, null, false, null); // [3]

    let empty = "";
    let empty2 = "";
    let num = new QAPICommandCppSharp().handleQAPIReq(pinfoXML, empty, (res) => { empty2 = res; }); // [4]

    if (num === 0) {
        token = empty2;
        if (!isCreateSamlTokenRequest) {
            let xml = CVWebConf.getDecryptedPassword(token);
            let qallTokenInfo = new QAllTokenInfo();
            XMLDecoder.readXml(xml, qallTokenInfo);
            qsdkGuid = CVWebConf.decodePass(Buffer.from(qallTokenInfo.tokenInfo[0].guid).toString('base64'));
        }
    }

    return num;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
After reaching `QLogin`, which performs authentication commands, review the CLI switches responsible for authentication and check whether there is a switch or feature related to admin access or obtaining a valid admin token (such as `localadmin-`)
{% endstep %}

{% step %}
First, test with a low-privilege or local user to see whether this feature works and grants a high-level role or token. If not, review the CLI processor and check whether it uses `dotnet.exe`, since this processor may run with `SYSTEM-level` privileges
{% endstep %}

{% step %}
Due to improper input validation and sanitization of user-supplied arguments in the CLI, it may be possible to inject the desired switch into a user-controlled parameter (such as the Password field) and send the request
{% endstep %}

{% step %}
If you encounter issues obtaining the admin username or related information, review the database to identify the admin username and then resend the request
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
