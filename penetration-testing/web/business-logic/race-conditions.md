# Race Conditions

## Check List

## Cheat Sheet

## Methodology&#x20;

### Black Box

#### Race Condition / Concurrency Testing

{% stepper %}
{% step %}
Create a free account on target
{% endstep %}

{% step %}
Navigate to the section offering `“Claim Free <resource>”` or `“Purchase <item>”`
{% endstep %}

{% step %}
Trigger the action and observe the redirect or request to

`https:///api//start?item=<resource_name>`<br>
{% endstep %}

{% step %}
Capture the final transaction request

```http
POST /api/v1/<api-endpoint>
```
{% endstep %}

{% step %}
Duplicate this request 5–15 times
{% endstep %}

{% step %}
Modify a minor field like `parameter` in each duplicate
{% endstep %}

{% step %}
Send all modified requests simultaneously (parallel execution)
{% endstep %}

{% step %}
Check if multiple successful transactions occur for the same action
{% endstep %}
{% endstepper %}

***

#### [Quota‑Limit Bypass via Concurrent Folder‑Creation Requests](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition#rate-limit-bypass)

{% stepper %}
{% step %}
Navigate to the Knowledge section on `<platform>` and select a specific `<knowledge_space>` (e.g., project or team space)
{% endstep %}

{% step %}
Create folders until you reach the configured limit `<max_folder_count>` (10 folders)
{% endstep %}

{% step %}
Attempt to create one additional folder and confirm the server returns a “limit reached” error
{% endstep %}

{% step %}
Delete one folder so the total count becomes `<max_folder_count - 1>`
{% endstep %}

{% step %}
Immediately after deletion, send `N` parallel folder-creation requests (2–20) to `POST <folder_creation_endpoint>` with payloads containing `<folder_name>` (use distinct names for each request)
{% endstep %}

{% step %}
Verify whether the total number of folders for `<knowledge_space>` exceeds `<max_folder_count>`
{% endstep %}
{% endstepper %}

***

#### Non‑Idempotent Request Replay

{% stepper %}
{% step %}
Log in to Account Sign in to the platform using valid credentials
{% endstep %}

{% step %}
Purchase a Gift Card Buy a gift card on the platform
{% endstep %}

{% step %}
Redeem Gift Card Navigate to https://sandbox.reverb.com//redeem and initiate the gift card redemption process
{% endstep %}

{% step %}
Intercept Redemption Request Capture the POST request to /fi/redeem containing utf8, authenticity\_token, token, and commit parameters using Burp Suite Pro
{% endstep %}

{% step %}
Send Request to Turbo Intruder Transfer the intercepted request to Turbo Intruder
{% endstep %}

{% step %}
Set External HTTP Header Configure the external HTTP header x-request: %s in Turbo Intruder
{% endstep %}

{% step %}
Execute the Attack Run the attack in Turbo Intruder and observe multiple 200 OK responses
{% endstep %}

{% step %}
Verify Increased Balance Check the account balance to confirm that the gift card value has been redeemed multiple times
{% endstep %}
{% endstepper %}

***

#### Race Condition (Concurrent Redemption / Double-spend)

{% stepper %}
{% step %}
Log in to Account Sign in to the platform using valid credentials
{% endstep %}

{% step %}
Purchase a Gift Card Buy a gift card on the platform
{% endstep %}

{% step %}
Redeem Gift Card Navigate to `https://sandbox.reverb.com//redeem` and initiate the gift card redemption process
{% endstep %}

{% step %}
Intercept Redemption Request Capture the `POST` request to `/fi/redeem` containing utf8, `authenticity_token`, token, and commit parameters using Burp Suite Pro
{% endstep %}

{% step %}
Send Request to Turbo Intruder Transfer the intercepted request to Turbo Intruder and apply the provided Python script with 30 concurrent connections
{% endstep %}

{% step %}
Set External HTTP Header Configure the external HTTP header `x-request: %s` in Turbo Intruder
{% endstep %}

{% step %}
Execute the Attack Run the attack in Turbo Intruder and observe multiple `200 OK` responses
{% endstep %}

{% step %}
Verify Increased Balance Check the account balance to confirm that the gift card value has been redeemed multiple times
{% endstep %}
{% endstepper %}

***

#### Authentication Token Issuance Race

{% stepper %}
{% step %}
Prepare a list of login payloads (include incorrect passwords and the correct password)
{% endstep %}

{% step %}
Choose concurrency level (start with 20–50 parallel requests)
{% endstep %}

{% step %}
Capture a valid login POST request and send it to Burp/Turbo Intruder or a parallel-request tool
{% endstep %}

{% step %}
Configure the tool to send your prepared payloads simultaneously
{% endstep %}

{% step %}
Launch the parallel attack
{% endstep %}

{% step %}
Inspect responses and identify any response that returns a JWT
{% endstep %}

{% step %}
Decode the JWT and extract the authCode (or equivalent MFA state)
{% endstep %}

{% step %}
Construct a login/verify request using the captured JWT and a random 6-digit OTP
{% endstep %}

{% step %}
Send the verify request and check for successful authentication (session or 200 OK)
{% endstep %}

{% step %}
Repeat attempts as needed (race is probabilistic) and log successful JWTs/responses
{% endstep %}
{% endstepper %}

***

#### Email‑verification Race

{% stepper %}
{% step %}
Create a new account (email remains unverified)
{% endstep %}

{% step %}
Find and capture the email verification POST request (the one sent when clicking the verification link)
{% endstep %}

{% step %}
Find and capture the change-email request (the POST that updates the account email)
{% endstep %}

{% step %}
Prepare two requests: (A) change-email → set target email ([victim@domain.com](mailto:victim@domain.com)), (B) verify-email → same valid verification token
{% endstep %}

{% step %}
Use a parallel-request tool (Turbo Intruder / Burp / parallel curl) to send A and B simultaneously (high concurrency / single-packet timing)
{% endstep %}

{% step %}
Inspect responses for success; check the account’s email status
{% endstep %}

{% step %}
Confirm by performing an action that requires a verified email (invite, access feature, etc)
{% endstep %}

{% step %}
Repeat to verify reproducibility and log any successful attempts
{% endstep %}
{% endstepper %}

***

### White Box

#### Race Condition / Remote Code Execution

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
Look for endpoints that allow users to upload files
{% endstep %}

{% step %}
In the code, review the function that processes the file upload endpoint to understand how the user uses this feature
{% endstep %}

{% step %}
Analyze the file upload process and check whether the user’s file is copied directly to the system and whether the uploaded file type is validated or not (like in the code below)

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("spack/upload")]
[Consumes("multipart/form-data")]
[Produces("application/json")]
[ProducesResponseType(StatusCodes.Status202Accepted)]
public IActionResult Upload(
    HttpRequest httpRequest,
    HttpResponse httpResponse,
    IFormFile spackFile,
    IFormFile spackChecksumFile,
    string updatetype = "full",
    string flavour = "premium")
{
    string spackFilePath = "/var/versa/ecp/share/files/" + spackFile.FileName;
    string spackSigFilePath = "/var/versa/ecp/share/files/" + spackChecksumFile.FileName;

    try
    {
        CopyPackage(spackFile, spackFilePath); // [1]
        CopyPackage(spackChecksumFile, spackSigFilePath); // [2]

        string bearerToken = UserContextHolder.GetContext().GetUserAccessTken(); // [3]
        if (bearerToken != null)
        {
            ...
        }

        Status status = new Status();
        status.SetStatus("Bearer Token empty");
        return StatusCode(StatusCodes.Status500InternalServerError, status);
    }
    catch (Exception e)
    {
        System.IO.File.Delete(spackFilePath); // [4]
        System.IO.File.Delete(spackSigFilePath); // [5]
        logger.LogError(e, "Error while uploading Spack");
        return HandleException(e, httpRequest);
    }
}
```


{% endtab %}

{% tab title="JavaScript" %}
```javascript
@PostMapping(value = {"spack/upload"}, produces = {"application/json"}, consumes = {"multipart/form-data"})
@ResponseBody
@ResponseStatus(HttpStatus.ACCEPTED)
public ResponseEntity<?> upload(HttpServletRequest httpRequest, HttpServletResponse httpResponse, @RequestParam(name = "spackFile", required = true) MultipartFile spackFile, @RequestParam(name = "spackChecksumFile", required = true) MultipartFile spackChecksumFile, @RequestParam(value = "updatetype", defaultValue = "full") String updateType, @RequestParam(value = "flavour", defaultValue = "premium") String flavour) throws Exception {
    String spackFilePath = "/var/versa/ecp/share/files/" + spackFile.getOriginalFilename();
    String spackSigFilePath = "/var/versa/ecp/share/files/" + spackChecksumFile.getOriginalFilename();
    try {
        copyPackage(spackFile, spackFilePath); [1]
        copyPackage(spackChecksumFile, spackSigFilePath); [2]
        String bearerToken = UserContextHolder.getContext().getUserAccessTken(); [3]
        if (bearerToken != null) {
           ...
        }
        Status status = new Status();
        status.setStatus("Bearer Token empty");
        return new ResponseEntity<>(status, HttpStatus.INTERNAL_SERVER_ERROR);
    } catch (Exception e) {
        Files.deleteIfExists(Paths.get(spackFilePath, new String[0])); [4]
        Files.deleteIfExists(Paths.get(spackSigFilePath, new String[0])); [5]
        logger.error("Error while uploading Spack", (Throwable) e);
        return handleException(e, httpRequest);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function upload(Request $request)
{
    $spackFile = $request->files->get('spackFile');
    $spackChecksumFile = $request->files->get('spackChecksumFile');
    $updateType = $request->get('updatetype', 'full');
    $flavour = $request->get('flavour', 'premium');

    $spackFilePath = "/var/versa/ecp/share/files/" . $spackFile->getClientOriginalName();
    $spackSigFilePath = "/var/versa/ecp/share/files/" . $spackChecksumFile->getClientOriginalName();

    try {
        copyPackage($spackFile, $spackFilePath); // [1]
        copyPackage($spackChecksumFile, $spackSigFilePath); // [2]

        $bearerToken = UserContextHolder::getContext()->getUserAccessTken(); // [3]
        if ($bearerToken !== null) {
            ...
        }

        $status = new Status();
        $status->setStatus("Bearer Token empty");
        return new ResponseEntity($status, 500);

    } catch (Exception $e) {
        @unlink($spackFilePath); // [4]
        @unlink($spackSigFilePath); // [5]
        $logger->error("Error while uploading Spack", [$e]);
        return $this->handleException($e, $request);
    }
}

```
{% endtab %}

{% tab title="Node JS" %}
```js
async function upload(req, res) {
    const spackFile = req.files.spackFile;
    const spackChecksumFile = req.files.spackChecksumFile;
    const updateType = req.body.updatetype || "full";
    const flavour = req.body.flavour || "premium";

    const spackFilePath = "/var/versa/ecp/share/files/" + spackFile.originalname;
    const spackSigFilePath = "/var/versa/ecp/share/files/" + spackChecksumFile.originalname;

    try {
        copyPackage(spackFile, spackFilePath); // [1]
        copyPackage(spackChecksumFile, spackSigFilePath); // [2]

        const bearerToken = UserContextHolder.getContext().getUserAccessTken(); // [3]
        if (bearerToken !== null) {
            ...
        }

        const status = new Status();
        status.setStatus("Bearer Token empty");
        return res.status(500).json(status);

    } catch (e) {
        fs.unlinkSync(spackFilePath); // [4]
        fs.unlinkSync(spackSigFilePath); // [5]
        logger.error("Error while uploading Spack", e);
        return handleException(e, req, res);
    }
}
```
{% endtab %}
{% endtabs %}

**VSCode**

{% tabs %}
{% tab title="C# Regex" %}
```regex
(?<Source>IFormFile|OpenReadStream\s*\(|Request\.Form\.Files)|(?<Sink>File(Stream|\.Copy|\.Delete)\s*\()
```
{% endtab %}

{% tab title="JavaScript Regex" %}
```regex
(?<Source>MultipartFile|\w+\.getInputStream\s*\()|(?<Sink>Files\.(copy|deleteIfExists)\s*\(|Paths\.get\s*\()
```
{% endtab %}

{% tab title="PHP Regex" %}
```regex
(?<Source>\$_FILES|\['tmp_name'\])|(?<Sink>move_uploaded_file|copy\s*\(|unlink\s*\()
```
{% endtab %}

{% tab title="Node JS Regex" %}
```regex
(?<Source>req\.files|multer|file\.path)|(?<Sink>fs\.(createWriteStream|copyFile|unlink))
```
{% endtab %}
{% endtabs %}

**RipGrep**

{% tabs %}
{% tab title="C# Regex" %}
```regex
(IFormFile|OpenReadStream\s*\(|Request\.Form\.Files)|(File(Stream|\.Copy|\.Delete)\s*\()
```
{% endtab %}

{% tab title="JavaScript Regex" %}
```regex
(MultipartFile|\w+\.getInputStream\s*\()|(Files\.(copy|deleteIfExists)\s*\(|Paths\.get\s*\()
```
{% endtab %}

{% tab title="PHP Regex" %}
```regex
(\$_FILES|\['tmp_name'\])|(move_uploaded_file|copy\s*\(|unlink\s*\()
```
{% endtab %}

{% tab title="Node JS Regex" %}
```regex
(req\.files|multer|file\.path)|(fs\.(createWriteStream|copyFile|unlink))
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```csharp
private void CopyPackage(IFormFile uploadFile, string filePath)
{
    lock (_lock)
    {
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }

        using (Stream inputStream = uploadFile.OpenReadStream())
        using (FileStream fileStream = new FileStream(filePath, FileMode.Create))
        {
            inputStream.CopyTo(fileStream);
        }
    }
}

```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
private synchronized void copyPackage(MultipartFile uploadFile, String filePath) throws Exception {
    Files.deleteIfExists(Paths.get(filePath, new String[0])); 
    InputStream inputStream = uploadFile.getInputStream();
    try {
        Files.copy(inputStream, Paths.get(filePath, new String[0]), new CopyOption[0]);
        if (inputStream != null) {
            inputStream.close();
        }
    } catch (Throwable th) {
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
        }
        throw th;
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function copyPackage($uploadFile, $filePath)
{
    if (file_exists($filePath)) {
        unlink($filePath);
    }

    $inputStream = fopen($uploadFile['tmp_name'], 'rb');
    try {
        $outputStream = fopen($filePath, 'wb');
        stream_copy_to_stream($inputStream, $outputStream);
        fclose($outputStream);
        fclose($inputStream);
    } catch (Throwable $th) {
        if (is_resource($inputStream)) {
            fclose($inputStream);
        }
        throw $th;
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```javascript
async function copyPackage(uploadFile, filePath) {
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }

    const readStream = uploadFile.stream;
    const writeStream = fs.createWriteStream(filePath);

    await new Promise((resolve, reject) => {
        readStream.pipe(writeStream);
        writeStream.on('finish', resolve);
        writeStream.on('error', reject);
    });
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
After the vulnerable code, check whether the uploaded file may be deleted due to security checks such as permission checks, authentication, or user token validation
{% endstep %}

{% step %}
If the file is first copied, then security checks are performed, and then the file is deleted, exactly between lines `[1]` to `[5]`, the **Race Condition** vulnerability can be exploited by sending about 1000 simultaneous requests between the vulnerable point and the file deletion point. And the uploaded malicious file can be used

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("spack/upload")]
[Produces("application/json")]
[Consumes("multipart/form-data")]
[ProducesResponseType(StatusCodes.Status202Accepted)]
public async Task<IActionResult> Upload(
    HttpRequest httpRequest,
    HttpResponse httpResponse,
    IFormFile spackFile,
    IFormFile spackChecksumFile,
    string updatetype = "full",
    string flavour = "premium")
{
    string spackFilePath = "/var/versa/ecp/share/files/" + spackFile.FileName;
    string spackSigFilePath = "/var/versa/ecp/share/files/" + spackChecksumFile.FileName;

    try
    {
        CopyPackage(spackFile, spackFilePath); // [1]
        CopyPackage(spackChecksumFile, spackSigFilePath); // [2]

        string bearerToken = UserContextHolder.GetContext().GetUserAccessToken(); // [3]
        if (bearerToken != null)
        {
            // ...
        }

        var status = new Status();
        status.StatusValue = "Bearer Token empty";
        return StatusCode(StatusCodes.Status500InternalServerError, status);
    }
    catch (Exception e)
    {
        if (System.IO.File.Exists(spackFilePath))
            System.IO.File.Delete(spackFilePath); // [4]

        if (System.IO.File.Exists(spackSigFilePath))
            System.IO.File.Delete(spackSigFilePath); // [5]

        logger.LogError(e, "Error while uploading Spack");

```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
@PostMapping(value = {"spack/upload"}, produces = {"application/json"}, consumes = {"multipart/form-data"})
@ResponseBody
@ResponseStatus(HttpStatus.ACCEPTED)
public ResponseEntity<?> upload(HttpServletRequest httpRequest, HttpServletResponse httpResponse, @RequestParam(name = "spackFile", required = true) MultipartFile spackFile, @RequestParam(name = "spackChecksumFile", required = true) MultipartFile spackChecksumFile, @RequestParam(value = "updatetype", defaultValue = "full") String updateType, @RequestParam(value = "flavour", defaultValue = "premium") String flavour) throws Exception {
    String spackFilePath = "/var/versa/ecp/share/files/" + spackFile.getOriginalFilename();
    String spackSigFilePath = "/var/versa/ecp/share/files/" + spackChecksumFile.getOriginalFilename();
    try {
        copyPackage(spackFile, spackFilePath); [1]
        copyPackage(spackChecksumFile, spackSigFilePath); [2]
        String bearerToken = UserContextHolder.getContext().getUserAccessTken(); [3]
        if (bearerToken != null) {
           ...
        }
        Status status = new Status();
        status.setStatus("Bearer Token empty");
        return new ResponseEntity<>(status, HttpStatus.INTERNAL_SERVER_ERROR);
    } catch (Exception e) {
        Files.deleteIfExists(Paths.get(spackFilePath, new String[0])); [4]
        Files.deleteIfExists(Paths.get(spackSigFilePath, new String[0])); [5]
        logger.error("Error while uploading Spack", (Throwable) e);
        return handleException(e, httpRequest);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function upload(Request $request)
{
    $spackFile = $request->file('spackFile');
    $spackChecksumFile = $request->file('spackChecksumFile');

    $spackFilePath = "/var/versa/ecp/share/files/" . $spackFile->getClientOriginalName();
    $spackSigFilePath = "/var/versa/ecp/share/files/" . $spackChecksumFile->getClientOriginalName();

    try {
        $this->copyPackage($spackFile, $spackFilePath); // [1]
        $this->copyPackage($spackChecksumFile, $spackSigFilePath); // [2]

        $bearerToken = UserContextHolder::getContext()->getUserAccessToken(); // [3]
        if ($bearerToken !== null) {
            // ...
        }

        return response()->json(['status' => 'Bearer Token empty'], 500);
    } catch (Exception $e) {
        if (file_exists($spackFilePath))
            unlink($spackFilePath); // [4]

        if (file_exists($spackSigFilePath))
            unlink($spackSigFilePath); // [5]

        logger()->error("Error while uploading Spack", [$e]);
        return $this->handleException($e, $request);
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
fastify.post('/spack/upload', async (request, reply) => {
    const spackFile = request.body.spackFile;
    const spackChecksumFile = request.body.spackChecksumFile;

    const spackFilePath = "/var/versa/ecp/share/files/" + spackFile.filename;
    const spackSigFilePath = "/var/versa/ecp/share/files/" + spackChecksumFile.filename;

    try {
        await copyPackage(spackFile, spackFilePath); // [1]
        await copyPackage(spackChecksumFile, spackSigFilePath); // [2]

        const bearerToken = UserContextHolder.getContext().getUserAccessToken(); // [3]
        if (bearerToken != null) {
            // ...
        }

        return reply.code(500).send({ status: "Bearer Token empty" });
    } catch (e) {
        if (fs.existsSync(spackFilePath))
            fs.unlinkSync(spackFilePath); // [4]

        if (fs.existsSync(spackSigFilePath))
            fs.unlinkSync(spackSigFilePath); // [5]

        request.log.error(e, "Error while uploading Spack");
        return handleException(e, request, reply);
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***
