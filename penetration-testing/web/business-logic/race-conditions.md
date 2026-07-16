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

#### Financial Double-Spending via Read-Replica Synchronization Lag

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-throughput financial endpoints, inventory reservation systems, or enterprise resource provisioning APIs where strict negative balances are forbidden
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Database CQRS / Read-Replica" architecture. To survive massive global traffic, enterprise architectures decouple database operations. They provision a single primary "Write Master" database and multiple distributed "Read Replica" databases
{% endstep %}

{% step %}
Investigate the connection routing logic within the backend ORM. To minimize load on the Write Master, developers configure the framework to route all `SELECT` statements to the Read Replicas, and all `INSERT`/`UPDATE`/`DELETE` statements to the Write Master
{% endstep %}

{% step %}
Analyze the business logic validation phase. Before deducting funds or allocating inventory, the service must verify the user's current balance (e.g., `if (account.Balance < transaction.Amount) throw Exception();`)
{% endstep %}

{% step %}
Discover the fatal architectural desynchronization: The developer heavily optimized the application by explicitly marking the validation query as a "Read-Only" operation (e.g., using `@Transactional(readOnly = true)` or resolving a `ReadOnlyDbContext`). This forces the validation query to execute against the Read Replica
{% endstep %}

{% step %}
Understand the physical constraints of distributed databases: Data written to the Write Master is not instantly available on the Read Replicas. There is a physical Replication Lag (typically 15ms to 100ms) as the transaction logs stream across the network and are applied to the replica nodes
{% endstep %}

{% step %}
Formulate the Asymmetric Race Condition payload. You must execute a highly concurrent batch of requests that complete their validation phases _before_ the first request's write operation propagates to the Read Replica
{% endstep %}

{% step %}
Identify the target endpoint (e.g., `POST /api/v1/accounts/transfer`). Determine your current active balance (e.g., `$100.00`)
{% endstep %}

{% step %}
Configure a high-performance concurrency tool (e.g., Burp Suite Turbo Intruder) utilizing HTTP/2 multiplexing and single-packet attacks to eliminate network handshake jitter
{% endstep %}

{% step %}
Transmit 50 identical transfer requests for `$100.00` simultaneously within a 5-millisecond window
{% endstep %}

{% step %}
The API Gateway distributes the 50 requests across multiple backend pods
{% endstep %}

{% step %}
All 50 pods execute the validation `SELECT` query against the Read Replica. Because the Replication Lag window (e.g., 50ms) has not passed, the Read Replica accurately reports a `$100.00` balance to _all 50 concurrent requests_
{% endstep %}

{% step %}
All 50 pods pass the validation check and execute the `UPDATE` query against the Write Master. The Write Master obediently processes the updates sequentially, driving the account balance into massive negative territory (`-$4,900.00`) and successfully executing cross-cluster double-spending without violating local thread safety

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\[?Transactional\s*\(\s*readOnly\s*=\s*true\s*\)?|var\s+\w+\s*=\s*await\s+_readOnlyDbContext\.[A-Za-z0-9_]+|_readOnlyDbContext\.[A-Za-z0-9_]+[\s\S]{0,120}?(?:Account|Balance|Payment|Transaction|Permission)|UseQueryTrackingBehavior[\s\S]{0,120}?NoTracking)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@Transactional\s*\(\s*readOnly\s*=\s*true\s*\)|@Transactional\s*\([^)]*readOnly\s*=\s*true|repository\.[A-Za-z0-9_]+\([\s\S]{0,120}?(?:balance|account|payment|transaction)|EntityManager[\s\S]{0,120}?(?:readOnly|Replica))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:DB::connection\s*\(\s*['"]replica['"]\s*\)->table|DB::connection\s*\(\s*['"]read['"]\s*\)|connection\s*\(\s*['"]replica['"]\s*\)[\s\S]{0,120}?(?:balance|account|transaction|payment))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Account\.findOne\s*\(\s*\{[\s\S]{0,120}?transaction\s*:\s*null[\s\S]{0,100}?useMaster\s*:\s*false|useMaster\s*:\s*false|replica[\s\S]{0,120}?(?:Account|Balance|Payment|Transaction)|readReplica[\s\S]{0,120}?find)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Transactional\(readOnly\s*=\s*true\)|_readOnlyDbContext\.[A-Za-z0-9_]+|UseQueryTrackingBehavior.*NoTracking
```
{% endtab %}

{% tab title="Java" %}
```regexp
@Transactional\(readOnly\s*=\s*true\)|@Transactional.*readOnly\s*=\s*true|EntityManager.*readOnly|repository\..*balance
```
{% endtab %}

{% tab title="PHP" %}
```regexp
DB::connection\('replica'\)->table|DB::connection\('read'\)|connection\('replica'\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
Account\.findOne\(\{.*transaction:\s*null.*useMaster:\s*false|useMaster:\s*false|replica.*find
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TransferService
{
    private readonly ApplicationDbContext _writeDb;
    private readonly ReadOnlyDbContext _replicaDb;

    public async Task<IActionResult> ExecuteTransferAsync(TransferRequest request)
    {
        // [1]
        // [2]
        // Developer optimizes read performance by querying the replica
        var accountBalance = await _replicaDb.Accounts
            .Where(a => a.Id == request.AccountId)
            .Select(a => a.Balance)
            .SingleOrDefaultAsync();

        // [3]
        // [4]
        if (accountBalance < request.Amount)
        {
            return BadRequest("Insufficient funds.");
        }

        // Master DB updates the balance sequentially, but the validation has already passed
        var accountToUpdate = await _writeDb.Accounts.FindAsync(request.AccountId);
        accountToUpdate.Balance -= request.Amount;
        
        await _writeDb.SaveChangesAsync();

        return Ok();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class TransferService {

    @Autowired
    private AccountReadRepository readRepo;
    @Autowired
    private AccountWriteRepository writeRepo;

    // [1]
    // [2]
    @Transactional(readOnly = true)
    public BigDecimal getAvailableBalance(UUID accountId) {
        // Framework routes this to the Read Replica pool
        return readRepo.findById(accountId).orElseThrow().getBalance();
    }

    // [3]
    // [4]
    @Transactional
    public ResponseEntity<?> executeTransfer(TransferRequest request) {
        
        // Evaluates balance against the replica, subject to 50ms replication lag
        BigDecimal currentBalance = getAvailableBalance(request.getAccountId());

        if (currentBalance.compareTo(request.getAmount()) < 0) {
            return ResponseEntity.badRequest().body("Insufficient funds.");
        }

        // Writes to the Master database
        Account account = writeRepo.findById(request.getAccountId()).orElseThrow();
        account.setBalance(account.getBalance().subtract(request.getAmount()));
        writeRepo.save(account);

        return ResponseEntity.ok().build();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class TransferService extends Controller
{
    public function executeTransfer(Request $request)
    {
        // [1]
        // [2]
        // Explicitly reading from the configured read replica connection
        $account = DB::connection('replica')->table('accounts')->find($request->accountId);

        // [3]
        // [4]
        if ($account->balance < $request->amount) {
            return response()->json(['error' => 'Insufficient funds.'], 400);
        }

        // Eloquent default connection routes to the Write Master
        DB::table('accounts')
            ->where('id', $request->accountId)
            ->decrement('balance', $request->amount);

        return response()->json(['status' => 'Success']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TransferService {
    static async executeTransfer(req, res) {
        // [1]
        // [2]
        // Sequelize configured to round-robin reads across replicas
        let accountState = await Account.findOne({ 
            where: { id: req.body.accountId },
            useMaster: false 
        });

        // [3]
        // [4]
        if (accountState.balance < req.body.amount) {
            return res.status(400).send("Insufficient funds.");
        }

        // Writes to the primary instance
        await Account.decrement('balance', { 
            by: req.body.amount, 
            where: { id: req.body.accountId } 
        });

        res.send({ status: "Success" });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture handles extreme read-heavy workloads. To prevent the primary database from locking during complex table scans, all read operations are strictly routed to asynchronously replicated secondary databases, \[2] The developer treats the validation check (e.g., retrieving the current balance) as a standard read operation, optimizing it via the Read Replica connection pool, \[3] The architecture relies entirely on the illusion of synchronous data. The developer implicitly assumes that the moment the Write Master updates a row, the Read Replica instantly reflects it, \[4] The execution sink. The validation boundary and the mutation boundary are physically separated by network replication latency. By flooding the endpoint with parallel requests, the attacker perfectly overlaps the execution timelines. All concurrent validation threads query the replica simultaneously, successfully reading the unmodified balance. Before the Write Master can process the first deduction and stream the commit log to the replica, the subsequent threads have already passed the compliance gate, executing massive localized double-spending

```http
// 1. Attacker has $50 in their account. They want to transfer $50 to an external account 10 times.
// 2. Attacker loads Burp Suite Turbo Intruder and configures an HTTP/2 single-packet attack 
//    to bypass network jitter and deliver all payloads perfectly concurrently.

POST /api/v1/transfer HTTP/2
Host: finance.enterprise.tld
Authorization: Bearer <valid_token>
Content-Type: application/json

{"destination": "ATTACKER_EXTERNAL", "amount": 50.00}

// 3. The server receives 10 identical requests simultaneously.
// 4. Pod 1 queries Replica: Balance is $50. Check passes.
// 5. Pod 2 queries Replica: Balance is $50. Check passes.
// 6. Pod 3 queries Replica: Balance is $50. Check passes.

// 7. Pod 1 executes UPDATE on Master. Master Balance becomes $0.
// 8. Pod 2 executes UPDATE on Master. Master Balance becomes -$50.
// 9. Pod 3 executes UPDATE on Master. Master Balance becomes -$100.

// 10. 50ms later, the Read Replica finally synchronizes and updates its value to -$100.
//     The attacker has successfully exfiltrated $500 using only $50 of initial capital.
```
{% endstep %}

{% step %}
To ensure maximum availability and prevent read-write lock contention on the primary database, enterprise architects deployed a distributed CQRS infrastructure utilizing asynchronous Read Replicas. This optimization structurally decoupled the validation tier from the persistence tier. Developers incorrectly assumed that application-level validation was mathematically atomic. By routing the compliance checks to the Read Replica, they introduced a physical network delay into the transaction's critical section. The attacker exploited this temporal gap by deploying extreme concurrency. The barrage of requests executed faster than the database cluster could synchronize its internal commit logs. The replication lag acted as a sustained "approval window," allowing all concurrent threads to validate against a stale, pristine balance before executing devastating, cumulative mutations on the primary database
{% endstep %}
{% endstepper %}

***

#### Critical Section Bypass via Garbage Collection Temporal Lock Expiration

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on distributed microservices that enforce strict singularity, such as claiming a unique promotional code, provisioning a singular IP address, or executing a daily payout job
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Distributed Locking" architecture. Because the application runs across 50 Kubernetes pods, standard thread locks (`lock()`, `synchronized`) do not work. To prevent race conditions, the developers utilize a distributed locking mechanism via Redis (e.g., Redlock, `SETNX`)
{% endstep %}

{% step %}
Investigate the Lock Expiration optimization. If a pod acquires a lock and then suffers a catastrophic hardware failure or is OOM-killed, the lock would remain in Redis forever, permanently deadlocking the business process. To solve this, developers enforce a strict Time-To-Live (TTL) on the lock (e.g., `SET resource_key 'LOCKED' NX PX 2000` to expire the lock in 2 seconds)
{% endstep %}

{% step %}
Analyze the execution flow within the critical section. After the lock is acquired, the application parses the incoming HTTP payload, validates business rules, and executes the database update
{% endstep %}

{% step %}
Discover the temporal vulnerability: The developer assumes that the application thread will always complete the critical section faster than the 2-second lock TTL. They fail to account for runtime pauses induced by the underlying language framework (e.g., V8, CLR, JVM)
{% endstep %}

{% step %}
Understand the Garbage Collection (GC) exploit mechanism. In managed languages, memory allocation spikes force the runtime to pause all executing threads to run a "Stop-The-World" Garbage Collection cycle. If an attacker can force a massive allocation, they can freeze the executing thread
{% endstep %}

{% step %}
Formulate the Lock Expiration payload. You must execute two concurrent requests. The first request must acquire the lock, then immediately force the server to freeze itself for longer than the TTL threshold. The second request will then easily acquire the expired lock
{% endstep %}

{% step %}
Target the data parsing layer (e.g., the JSON deserializer or an XML parser) that occurs _inside_ the critical section
{% endstep %}

{% step %}
Construct a computationally devastating payload. Create a massive JSON object with 100,000 deeply nested arrays, or an exponentially complex regular expression input
{% endstep %}

{% step %}
Fire Request A containing the massive payload
{% endstep %}

{% step %}
Request A acquires the Redis lock (TTL: 2000ms). Request A proceeds to the JSON parsing phase. The massive payload exhausts the Young Generation memory heap, triggering a Stop-The-World GC pause. The thread freezes for 2500ms
{% endstep %}

{% step %}
The Redis lock expires and is automatically deleted by the Redis server
{% endstep %}

{% step %}
Fire Request B (a normal, lightweight request). Request B queries Redis, sees no lock, and acquires it. Request B executes the critical database mutation
{% endstep %}

{% step %}
Request A's GC pause ends. The thread wakes up. Completely unaware that its lock has expired, Request A continues execution, performing the exact same database mutation. The critical section is breached, and the Race Condition succeeds

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+_redis\.StringSetAsync\s*\([\s\S]{0,150}?,\s*TimeSpan\.FromSeconds\s*\(\s*[1-5]\s*\)|StringSetAsync[\s\S]{0,150}?FromSeconds\s*\(\s*[1-5]\s*\)|IDistributedLock[\s\S]{0,150}?TTL|DistributedLock[\s\S]{0,120}?Expiration)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:redisTemplate\.opsForValue\(\)\.setIfAbsent\s*\([\s\S]{0,150}?,\s*[1-5]\s*,\s*TimeUnit\.SECONDS\)|setIfAbsent[\s\S]{0,150}?TimeUnit\.SECONDS|RedisLock[\s\S]{0,120}?expire|lock[\s\S]{0,100}?leaseTime)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$redis->set\s*\([\s\S]{0,150}?'nx'\s*,\s*'ex'\s*,\s*[1-5]\s*\)|Redis::set[\s\S]{0,120}?(?:NX|EX)|setnx[\s\S]{0,120}?expire|lock[\s\S]{0,100}?seconds)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:redis\.set\s*\([\s\S]{0,150}?['"]NX['"][\s\S]{0,80}?['"]PX['"]\s*,\s*[1-5]000|redis\.set\s*\([\s\S]{0,150}?NX[\s\S]{0,80}?PX|redlock[\s\S]{0,150}?ttl|lock[\s\S]{0,120}?duration)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
_redis\.StringSetAsync\(.*TimeSpan\.FromSeconds\([1-5]\)|StringSetAsync.*FromSeconds\([1-5]\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
redisTemplate\.opsForValue\(\)\.setIfAbsent\(.*[1-5],\s*TimeUnit\.SECONDS\)|setIfAbsent.*TimeUnit\.SECONDS
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$redis->set\(.*'nx',\s*'ex',\s*[1-5]\)|Redis::set.*NX.*EX
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
redis\.set\(.*'NX',\s*'PX',\s*[1-5]000\)|redis\.set\(.*NX.*PX
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/promotions/claim")]
public async Task<IActionResult> ClaimPromotion([FromQuery] string code)
{
    var lockKey = $"lock:promo:{code}";

    // [1]
    // [2]
    var lockAcquired = await _redis.StringSetAsync(lockKey, "LOCKED", TimeSpan.FromSeconds(2), When.NotExists);

    if (!lockAcquired) return StatusCode(429, "Processing...");

    try
    {
        // [3]
        // [4]
        using var reader = new StreamReader(Request.Body);
        var rawBody = await reader.ReadToEndAsync();
        
        // Massive allocation causes Gen 2 Garbage Collection pause blocking the thread
        var data = JsonConvert.DeserializeObject<dynamic>(rawBody);

        var promo = await _dbContext.Promotions.SingleOrDefaultAsync(p => p.Code == code && !p.Claimed);
        if (promo == null) return BadRequest("Already claimed");

        promo.Claimed = true;
        await _dbContext.SaveChangesAsync();

        return Ok(new { Status = "Claimed successfully" });
    }
    finally
    {
        await _redis.KeyDeleteAsync(lockKey);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class PromotionController {

    @Autowired
    private StringRedisTemplate redisTemplate;
    @Autowired
    private PromotionRepository promoRepo;

    @PostMapping("/api/v1/promotions/claim")
    public ResponseEntity<?> claimPromotion(@RequestParam String code, @RequestBody String rawJson) throws Exception {
        String lockKey = "lock:promo:" + code;

        // [1]
        // [2]
        // Redisson / RedisTemplate acquiring a lock with a 2-second lease time
        Boolean lockAcquired = redisTemplate.opsForValue().setIfAbsent(lockKey, "LOCKED", 2, TimeUnit.SECONDS);

        if (Boolean.FALSE.equals(lockAcquired)) {
            return ResponseEntity.status(429).body("Processing...");
        }

        try {
            // [3]
            // [4]
            // Heavy deserialization occurs inside the critical section.
            // A massive payload triggers a Stop-The-World GC pause lasting > 2000ms.
            ObjectMapper mapper = new ObjectMapper();
            JsonNode payload = mapper.readTree(rawJson);

            Promotion promo = promoRepo.findByCodeAndClaimedFalse(code).orElseThrow();
            promo.setClaimed(true);
            promo.setClaimedBy(getCurrentUser());
            promoRepo.save(promo);

            return ResponseEntity.ok("Claimed successfully");
        } finally {
            redisTemplate.delete(lockKey);
        }
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class PromotionController extends Controller
{
    public function claimPromotion(Request $request)
    {
        $code = $request->query('code');
        $lockKey = "lock:promo:{$code}";

        // [1]
        // [2]
        if (!Redis::set($lockKey, 'LOCKED', 'EX', 2, 'NX')) {
            return response()->json(['error' => 'Processing...'], 429);
        }

        try {
            // [3]
            // [4]
            // PHP decodes the massive JSON payload, causing memory allocation limits 
            // to strain or regex evaluations to hang the process.
            $data = json_decode($request->getContent(), true);

            $promo = Promotion::where('code', $code)->where('claimed', false)->firstOrFail();
            
            $promo->claimed = true;
            $promo->save();

            return response()->json(['status' => 'Claimed successfully']);
        } finally {
            Redis::del($lockKey);
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/promotions/claim', async (req, res) => {
    const promoCode = req.query.code;
    const lockKey = `lock:promo:${promoCode}`;

    // [1]
    // [2]
    // Distributed lock with a 2-second TTL to prevent pod-crash deadlocks
    const lockAcquired = await redis.set(lockKey, 'LOCKED', 'NX', 'PX', 2000);
    
    if (!lockAcquired) {
        return res.status(429).send('Please wait, processing...');
    }

    try {
        // [3]
        // [4]
        // The attacker passes a massive, heavily nested JSON body.
        // Node.js parses this synchronously, or garbage collects the massive string allocation,
        // freezing the V8 Event Loop for > 2000ms.
        let parsedData = JSON.parse(req.rawBody);

        let promo = await Promotion.findOne({ where: { code: promoCode, claimed: false } });
        
        if (!promo) return res.status(400).send('Already claimed');

        promo.claimed = true;
        promo.claimedBy = req.user.id;
        await promo.save();

        res.send({ status: 'Claimed successfully' });
    } finally {
        // The lock is deleted, but if it already expired, this delete does nothing.
        await redis.del(lockKey);
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application orchestrates operations across multiple distributed pods. To ensure singularity (e.g., a promotional code can only be claimed once globally), developers implement Redis-backed distributed locks, \[2] To prevent a pod crash from stranding the lock in Redis and permanently disabling the feature, the developers enforce a strict Time-To-Live (TTL) on the lock, optimizing for system self-healing, \[3] The architecture processes untrusted input _inside_ the locked critical section, \[4] The execution sink. The developers assume that code executes instantaneously, failing to account for runtime environment pauses. By injecting a payload designed to exhaust heap memory or trigger exponential regex evaluation, the attacker forces the host language to suspend the executing thread. The thread remains frozen while the Redis server decrements the TTL. Once the lock expires, a second request can enter the critical section. When the first thread completes its Garbage Collection cycle, it blindly resumes execution, oblivious to the fact that its lock has expired, perfectly overlapping the database mutations

```http
// 1. Attacker obtains a highly valuable, single-use promotional code (e.g., $500_CREDIT).
// 2. Attacker prepares a massive, deeply nested JSON payload designed to trigger a 3-second 
//    Garbage Collection pause in the target framework (e.g., 50,000 nested arrays).

// 3. Attacker sends Request A:
POST /api/v1/promotions/claim?code=500_CREDIT HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_account_1>
Content-Type: application/json

{"data": [[[[[[[[[[[[[[...50,000 times...]]]]]]]]]]]]]]}

// 4. Request A acquires the lock (TTL: 2000ms).
// 5. The server attempts to deserialize Request A. The GC triggers. The thread freezes.
// 6. 2001ms elapses. The Redis lock is automatically purged.

// 7. Attacker immediately sends Request B:
POST /api/v1/promotions/claim?code=500_CREDIT HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_account_2>
Content-Type: application/json

{"data": "fast_payload"}

// 8. Request B queries Redis. The lock does not exist. Request B acquires a NEW lock.
// 9. Request B verifies the promo code, marks it as claimed, and credits Account 2.
// 10. Request A wakes up from the GC pause. It resumes execution.
// 11. Request A verifies the promo code (which may still be uncommitted by B depending on exact millisecond overlap), 
//     marks it as claimed, and credits Account 1.
// 12. Both accounts are credited from a single-use token.
```
{% endstep %}

{% step %}
To enforce absolute exclusivity across distributed microservice clusters, enterprise engineers implemented Redis-backed distributed locks. To protect the cluster from irrecoverable deadlocks caused by transient pod failures, they applied aggressive, short-lived Time-To-Live (TTL) expirations to the locks. This optimization transferred the burden of thread synchronization from the database to the application's runtime environment. Developers mistakenly assumed that application threads execute linearly and predictably. The attacker bypassed this assumption by engineering a payload that intentionally triggered a massive Stop-The-World Garbage Collection cycle. By freezing the application thread for a duration exceeding the lock's TTL, the attacker manipulated the external Redis server into revoking the lock. The attacker's secondary request seamlessly bypassed the synchronization barrier. When the primary thread recovered, it blindly resumed execution, shattering the critical section and permanently violating the application's single-use business constraints
{% endstep %}
{% endstepper %}

***

#### Billing Bypass via Asynchronous Read-Modify-Write in Distributed Gateways

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on API Gateways, Edge Proxies, or enterprise billing layers that enforce complex, tiered rate limits or metered quotas (e.g., charging per API call, enforcing burst limits)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the API Gateway's billing and rate-limiting middleware
{% endstep %}

{% step %}
Identify the "Application-Layer Quota Evaluation" architecture. In simple rate-limiting scenarios, developers use atomic Redis commands (like `INCR`). However, in complex B2B enterprises, billing logic involves multiple variables: rolling windows, tier multipliers, free-tier allocations, and overage billing
{% endstep %}

{% step %}
Investigate the execution bottleneck. Evaluating complex, multi-variable logic using raw Redis Lua scripts is notoriously difficult to debug and maintain
{% endstep %}

{% step %}
Discover the "Read-Modify-Write" optimization. To maintain agile business logic, the Gateway developers read the raw quota metrics from Redis via a standard `GET`, execute the complex billing calculations in the native application language (C#, Java, Node.js), and write the updated values back to Redis using a `SET` command
{% endstep %}

{% step %}
Analyze the concurrency model. The API Gateway serves thousands of concurrent requests across hundreds of distributed nodes
{% endstep %}

{% step %}
Understand the architectural assumption: The developers assume that individual API requests from a single tenant arrive with enough temporal spacing that the `GET -> Calculate -> SET` pipeline will not intersect with itself. They fail to employ an optimistic concurrency control (OCC) mechanism or a distributed lock around the billing calculation
{% endstep %}

{% step %}
Formulate the State Desynchronization payload. You must flood the API Gateway with a massive burst of concurrent requests that all trigger the `GET` command simultaneously, before any single request can reach the `SET` command
{% endstep %}

{% step %}
Identify an expensive, heavily metered API endpoint (e.g., executing a Machine Learning model, sending an SMS, or fetching a heavy financial report)
{% endstep %}

{% step %}
Configure a high-speed concurrency tool to multiplex the HTTP/2 stream, packing 500 identical requests into a single network frame to perfectly align their execution times on the backend
{% endstep %}

{% step %}
Transmit the burst to the API Gateway
{% endstep %}

{% step %}
The Gateway routes the 500 requests across its distributed workers
{% endstep %}

{% step %}
All 500 threads hit the billing middleware simultaneously. They all execute the `GET` command against Redis. Redis returns the current usage (e.g., `990` calls used out of `1000`)
{% endstep %}

{% step %}
All 500 threads evaluate the complex logic: `if (990 < 1000)`. The condition passes for all 500 threads
{% endstep %}

{% step %}
All 500 threads calculate the new usage: `990 + 1 = 991`
{% endstep %}

{% step %}
All 500 threads execute the `SET` command against Redis, forcefully writing the value `991`. The attacker successfully executes 500 heavily metered API operations while only incrementing the global billing ledger by exactly 1 unit, achieving catastrophic financial subversion

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:await\s+cache\.GetAsync\s*\(\s*quotaKey\s*\)[\s\S]{0,200}?await\s+cache\.SetAsync\s*\(\s*quotaKey|(?:GetAsync|StringGetAsync)\s*\(\s*quotaKey[\s\S]{0,200}?(?:SetAsync|StringSetAsync)\s*\(\s*quotaKey)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:redisTemplate\.opsForValue\(\)\.get\s*\(\s*quotaKey\s*\)[\s\S]{0,200}?redisTemplate\.opsForValue\(\)\.set\s*\(\s*quotaKey|opsForValue\(\)\.get[\s\S]{0,200}?opsForValue\(\)\.set)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$redis->get\s*\(\s*\$quotaKey\s*\)[\s\S]{0,200}?\$redis->set\s*\(\s*\$quotaKey|\$redis->get[\s\S]{0,200}?\$redis->set|Redis::get[\s\S]{0,150}?Redis::set)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:let\s+\w+\s*=\s*await\s+redis\.get\s*\(\s*quotaKey\s*\)[\s\S]{0,200}?await\s+redis\.set\s*\(\s*quotaKey|redis\.get\s*\(\s*quotaKey[\s\S]{0,200}?redis\.set\s*\(\s*quotaKey)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
await\s+cache\.GetAsync\(quotaKey\).*await\s+cache\.SetAsync\(quotaKey|GetAsync\(quotaKey\).*SetAsync\(quotaKey
```
{% endtab %}

{% tab title="Java" %}
```regexp
redisTemplate\.opsForValue\(\)\.get\(quotaKey\).*redisTemplate\.opsForValue\(\)\.set\(quotaKey|opsForValue\(\)\.get.*opsForValue\(\)\.set
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$redis->get\(\$quotaKey\).*?\$redis->set\(\$quotaKey|\$redis->get.*\$redis->set
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
let\s+usage\s*=\s*await\s+redis\.get\(quotaKey\).*await\s+redis\.set\(quotaKey|redis\.get\(quotaKey\).*redis\.set\(quotaKey
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class GatewayBillingMiddleware
{
    private readonly IDatabase _redis;
    private readonly RequestDelegate _next;

    public async Task InvokeAsync(HttpContext context)
    {
        var tenantId = context.User.GetTenantId();
        var quotaKey = $"billing:usage:{tenantId}";

        // [1]
        // [2]
        var usageJson = await _redis.StringGetAsync(quotaKey);
        var usage = string.IsNullOrEmpty(usageJson) 
            ? new BillingRecord() 
            : JsonConvert.DeserializeObject<BillingRecord>(usageJson);

        // [3]
        // [4]
        var dynamicLimit = CalculateLimit(usage.PlanType);

        if (usage.TotalCalls >= dynamicLimit)
        {
            context.Response.StatusCode = 429;
            await context.Response.WriteAsync("Quota Exceeded");
            return;
        }

        usage.TotalCalls += 1;

        // Writes the stale increment back to Redis
        await _redis.StringSetAsync(quotaKey, JsonConvert.SerializeObject(usage));

        await _next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class GatewayBillingFilter implements GlobalFilter {

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String tenantId = getTenantId(exchange);
        String quotaKey = "billing:usage:" + tenantId;

        // [1]
        // [2]
        // Non-atomic Read-Modify-Write pipeline
        String usageStr = redisTemplate.opsForValue().get(quotaKey);
        BillingRecord usage = parseUsage(usageStr);

        // [3]
        // [4]
        long limit = calculateDynamicLimit(usage);

        if (usage.getCount() >= limit) {
            exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            return exchange.getResponse().setComplete();
        }

        usage.increment();
        
        // Clobbers concurrent updates without Optimistic Concurrency Control (OCC)
        redisTemplate.opsForValue().set(quotaKey, serializeUsage(usage));

        return chain.filter(exchange);
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class GatewayBillingMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $tenantId = $request->user()->tenant_id;
        $quotaKey = "billing:usage:{$tenantId}";

        // [1]
        // [2]
        $usageJson = Redis::get($quotaKey);
        $usage = $usageJson ? json_decode($usageJson, true) : ['count' => 0, 'tier' => 'basic'];

        // [3]
        // [4]
        $limit = $this->calculateDynamicLimit($usage);

        if ($usage['count'] >= $limit) {
            return response('Quota Exceeded', 429);
        }

        $usage['count']++;

        // Unprotected SET command replaces value, destroying concurrent increments
        Redis::set($quotaKey, json_encode($usage));

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class GatewayBillingMiddleware {
    static async enforceQuota(req, res, next) {
        let tenantId = req.user.tenantId;
        let quotaKey = `billing:usage:${tenantId}`;

        // [1]
        // [2]
        // Reads the current usage from Redis
        let usageData = await redis.get(quotaKey);
        let usage = usageData ? JSON.parse(usageData) : { count: 0, tier: 'basic' };

        // [3]
        // [4]
        // Complex application-layer logic replacing simple atomic INCR
        let limit = usage.tier === 'premium' ? 10000 : 1000;

        if (usage.count >= limit) {
            return res.status(429).send('Billing quota exceeded.');
        }

        usage.count += 1;

        // Overwrites the Redis key. Concurrent requests will clobber this value.
        await redis.set(quotaKey, JSON.stringify(usage));

        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API Gateway intercepts all ingress traffic to meter usage and enforce financial billing quotas across multi-tenant enterprise deployments, \[2] The developers avoid atomic Redis operations (`INCR`, `HINCRBY`) because the billing model relies on complex, dynamically shifting metadata (e.g., rollover credits, distinct time-based tiering) that cannot be easily evaluated within the database, \[3] To support this complex logic, the architecture extracts the state into application memory, recalculates it, and pushes it back to the datastore, \[4] The execution sink. The developers mistakenly equate single-user traffic with single-threaded execution. By failing to implement Optimistic Concurrency Control (e.g., using Redis `WATCH` transactions or checking `version` flags), the pipeline is entirely exposed to race conditions. When the attacker synchronizes hundreds of requests, all threads evaluate the exact same base state. They perform identical calculations and issue identical `SET` commands, continuously overwriting each other. The gateway silently drops 99% of the billable events, authorizing the attacker to aggressively mine expensive API resources while mathematically registering a negligible footprint on the financial ledger

```http
// 1. Attacker purchases the lowest tier API plan, providing 1,000 monthly calls.
// 2. Attacker prepares a script to consume a highly expensive endpoint (e.g., generating a 50-page PDF report).
// 3. Attacker uses HTTP/2 multiplexing to send 1,000 requests in a single burst.

POST /api/v1/reports/generate HTTP/2
Host: gateway.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{"reportType": "Comprehensive_Audit"}

// 4. The Gateway receives the burst. 1,000 threads execute the billing middleware concurrently.
// 5. Thread 1 executes GET. Receives count: 0.
// 6. Thread 500 executes GET. Receives count: 0.
// 7. Thread 1000 executes GET. Receives count: 0.

// 8. All threads evaluate: 0 < 1000. All threads authorize the request.
// 9. All threads calculate: 0 + 1 = 1.
// 10. All threads execute SET. Redis key becomes {"count": 1}.

// 11. The backend mesh successfully generates 1,000 massive PDF reports.
// 12. The attacker's dashboard reports they have used 1 out of 1,000 monthly calls.
// 13. The attacker repeats this burst indefinitely, extracting massive computational value for free.
```
{% endstep %}

{% step %}
To support highly complex, dynamic B2B billing models, platform architects shifted quota calculation logic out of atomic datastore operations and into the application layer. This optimization utilized a Read-Modify-Write pipeline against a distributed Redis cache. The security failure stemmed from the omission of optimistic concurrency controls (OCC). Developers implicitly trusted that API requests originating from a single tenant would naturally space themselves out across the network, avoiding collisions. The attacker systematically shattered this assumption by launching heavily multiplexed, synchronized HTTP/2 request bursts. The distributed gateway workers instantly queried the datastore, uniformly receiving the exact same pristine baseline quota. Because the gateway lacked transactional isolation, all parallel threads independently verified the stale quota, authorized the expensive backend action, and overwrote the billing cache with identical, negligible increments. This Race Condition effectively nullified the platform's financial metering, enabling infinite, unmetered extraction of premium enterprise resources
{% endstep %}
{% endstepper %}

***
