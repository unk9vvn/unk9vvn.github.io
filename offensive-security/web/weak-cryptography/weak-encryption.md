# Weak Encryption

## Check List

## Methodology

### Black Box

#### Weakly Encrypted Password Reset Token

{% stepper %}
{% step %}
Access the password reset functionality

```http
GET /forgot-password HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Submit a password reset request for your own account

```http
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=test@target.com
```
{% endstep %}

{% step %}
Capture the reset link from email

```hurl
https://target.com/reset?token=MTY5ODc1NjAwMA==
```
{% endstep %}

{% step %}
Decode the token (Base64 test)

```hurl
MTY5ODc1NjAwMA==  →  1698756000
```
{% endstep %}

{% step %}
If token decodes into a timestamp, user ID, or predictable pattern, encryption is weak, Request multiple reset tokens consecutively
{% endstep %}

{% step %}
Compare token values for pattern similarity (incremental values, timestamp correlation, user ID leakage)
{% endstep %}

{% step %}
Attempt to modify the token manually

```hurl
https://target.com/reset?token=MTY5ODc1NjAwMQ==
```
{% endstep %}

{% step %}
If modified token is accepted or partially validated, weak encryption / predictable token confirmed
{% endstep %}

{% step %}
Attempt cross-user reset by generating token for your account and adjusting numeric segment to another user ID
{% endstep %}

{% step %}
If token manipulation grants access to another account’s reset page, weak encryption vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Sensitive Data Encrypted with Reversible Client-Side Logic

{% stepper %}
{% step %}
Login and intercept response containing encrypted data

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```
{% endstep %}

{% step %}
Observe encrypted field

```json
"ssn":"U0lHTkVEX1NTTl8xMjM0"
```
{% endstep %}

{% step %}
Inspect application JavaScript files

```http
GET /static/app.js HTTP/1.1
Host: target.com
```
{% endstep %}

{% step %}
Search for encryption functions, Identify reversible logic such as

```
function encrypt(data){
  return btoa(data);
}
```
{% endstep %}

{% step %}
Decode the value manually

```
U0lHTkVEX1NTTl8xMjM0 → SIGNED_SSN_1234
```
{% endstep %}

{% step %}
If sensitive data is only Base64 encoded or XOR encoded, not cryptographically encrypted, weak encryption confirmed
{% endstep %}

{% step %}
Modify encoded value and resend request. If application accepts modified encoded sensitive data, encryption control is insufficient
{% endstep %}
{% endstepper %}

***

#### Weak TLS Cipher Suite Negotiation

{% stepper %}
{% step %}
Connect to target using a TLS testing tool
{% endstep %}

{% step %}
Force weak cipher negotiation (example with OpenSSL)

```bash
openssl s_client -connect target.com:443 -cipher 'DES-CBC3-SHA'
```
{% endstep %}

{% step %}
If handshake succeeds with 3DES or RC4

```bash
Cipher    : DES-CBC3-SHA
```
{% endstep %}

{% step %}
Weak encryption is supported, Test for export-grade cipher support

```bash
openssl s_client -connect target.com:443 -cipher 'EXP'
```
{% endstep %}

{% step %}
If connection succeeds using export cipher, weak encryption confirmed
{% endstep %}

{% step %}
Verify accepted protocol version

```bash
Protocol  : TLSv1.0
```
{% endstep %}

{% step %}
If TLS 1.0 or weak ciphers are allowed, cryptographic strength is insufficient
{% endstep %}

{% step %}
If handshake succeeds using deprecated cipher suites, weak encryption configuration vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Cleartext Recovery via Deterministic Ciphertext Collision (Searchable Encryption Downgrade)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the enterprise's Personally Identifiable Information (PII) vault architecture. Data privacy regulations (GDPR, CCPA) strictly mandate that sensitive fields (e.g., Social Security Numbers, National IDs, Credit Cards) must be encrypted at rest in the database
{% endstep %}

{% step %}
Investigate the operational bottleneck: While encrypting the data fulfills compliance, the business application still requires the ability to query the database for exact matches (e.g., `SELECT * FROM Users WHERE NationalId = ?`)
{% endstep %}

{% step %}
Analyze the cryptographic optimization implemented by the developers to solve this searchability paradox. A cryptographically secure cipher (like AES-CBC with a random IV, or AES-GCM) is semantically secure, meaning encrypting the same plaintext twice produces two completely different ciphertexts. This makes exact-match SQL queries impossible
{% endstep %}

{% step %}
Discover the architectural downgrade: To restore database indexing and `WHERE` clause functionality, the developers explicitly abandon semantic security. They configure the encryption engine to use Electronic Codebook (ECB) mode, or they use Cipher Block Chaining (CBC) with a static, hardcoded Initialization Vector (IV)
{% endstep %}

{% step %}
Understand the fatal cryptographic assumption: The developer assumes that because the encryption key remains securely locked in a Key Management Service (KMS), the ciphertext is immune to decryption, regardless of the cipher mode
{% endstep %}

{% step %}
Verify the vulnerability by creating two distinct accounts within the application, providing the exact same value for a sensitive field (e.g., entering the same fake National ID `999-00-1234` for both accounts)
{% endstep %}

{% step %}
Utilize an application feature that reflects encrypted data, or exploit a low-severity Information Disclosure (e.g., an over-permissive API endpoint, a bulk metadata export, or an Insecure Direct Object Reference) to extract the raw encrypted blobs from the database
{% endstep %}

{% step %}
Observe that the encrypted blobs for both accounts are perfectly identical. You have confirmed deterministic encryption
{% endstep %}

{% step %}
Exploit this via a Chosen-Plaintext Attack (CPA) / Dictionary Attack. Because the enterprise system allows you to encrypt arbitrary data through your own profile updates, programmatically inject thousands of known National IDs into your account and harvest the resulting ciphertexts
{% endstep %}

{% step %}
Build a rainbow table mapping known plaintexts to their deterministic ciphertexts
{% endstep %}

{% step %}
Scan the leaked or exported database records. By matching the ciphertexts of other users against your generated rainbow table, you passively decrypt the highly sensitive PII of the entire enterprise customer base without ever extracting the master encryption key

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:CipherMode\.ECB|Aes\.Create\(\)[\s\S]{0,150}?Mode\s*=\s*CipherMode\.ECB|AES[\s\S]{0,100}?ECB|CreateEncryptor[\s\S]{0,120}?ECB|PaddingMode\.(?:PKCS7|Zeros)[\s\S]{0,100}?CipherMode\.ECB)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:"AES/ECB/(?:PKCS5Padding|NoPadding)"|Cipher\.getInstance\s*\(\s*"AES/ECB[^"]*"|Cipher\.getInstance[\s\S]{0,120}?ECB|AES/ECB|mode\s*=\s*ECB)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:['"]aes-[0-9]+-ecb['"]|openssl_encrypt\s*\([\s\S]{0,150}?aes-[0-9]+-ecb|openssl_cipher_iv_length[\s\S]{0,100}?ecb|cipher[\s\S]{0,100}?ECB)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:createCipheriv\s*\(\s*['"]aes-[0-9]+-ecb['"]|createCipher\s*\(\s*['"]aes-[0-9]+-ecb['"]|['"]aes-[0-9]+-ecb['"]|crypto\.createCipheriv[\s\S]{0,120}?ecb)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
CipherMode\.ECB|Aes\.Create\(\).*Mode\s*=\s*CipherMode\.ECB|CreateEncryptor.*ECB
```
{% endtab %}

{% tab title="Java" %}
```regexp
AES/ECB/(PKCS5Padding|NoPadding)|Cipher\.getInstance\(.*ECB|Cipher\.getInstance.*ECB
```
{% endtab %}

{% tab title="PHP" %}
```regexp
aes-[0-9]+-ecb|openssl_encrypt.*ecb|cipher.*ECB
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
createCipheriv\(.*aes-[0-9]+-ecb|createCipher\(.*aes-[0-9]+-ecb|aes-[0-9]+-ecb
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class PiiEncryptionService 
{
    private readonly byte[] _masterKey;

    public PiiEncryptionService(IKeyManagementService kms) 
    {
        _masterKey = kms.GetMasterKey();
    }

    public string EncryptForSearch(string sensitiveData) 
    {
        // [1]
        // [2]
        using var aes = Aes.Create();
        aes.Key = _masterKey;
        // [3]
        aes.Mode = CipherMode.ECB; 
        aes.Padding = PaddingMode.PKCS7;

        var inputBytes = Encoding.UTF8.GetBytes(sensitiveData);
        
        // [4]
        using var encryptor = aes.CreateEncryptor();
        var ciphertext = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
        
        return Convert.ToBase64String(ciphertext);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class PiiEncryptionService {

    private final SecretKeySpec masterKey;

    public PiiEncryptionService(KeyManagementService kms) {
        this.masterKey = new SecretKeySpec(kms.getMasterKey(), "AES");
    }

    public String encryptForSearch(String sensitiveData) throws Exception {
        // [1]
        // [2]
        // [3]
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, masterKey);
        
        byte[] inputBytes = sensitiveData.getBytes(StandardCharsets.UTF_8);
        
        // [4]
        byte[] ciphertext = cipher.doFinal(inputBytes);
        
        return Base64.getEncoder().encodeToString(ciphertext);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class PiiEncryptionService 
{
    protected $masterKey;

    public function __construct(KeyManagementService $kms) 
    {
        $this->masterKey = $kms->getMasterKey();
    }

    public function encryptForSearch(string $sensitiveData): string 
    {
        // [1]
        // [2]
        // [3]
        // [4]
        $ciphertext = openssl_encrypt(
            $sensitiveData, 
            'aes-256-ecb', 
            $this->masterKey, 
            OPENSSL_RAW_DATA
        );

        return base64_encode($ciphertext);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class PiiEncryptionService {
    constructor(kms) {
        this.masterKey = kms.getMasterKey();
    }

    encryptForSearch(sensitiveData) {
        // [1]
        // [2]
        // [3]
        let cipher = crypto.createCipheriv('aes-256-ecb', this.masterKey, null);
        
        // [4]
        let ciphertext = cipher.update(sensitiveData, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        
        return ciphertext.toString('base64');
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The service accepts highly sensitive plaintext data that must be securely stored, but also rapidly queried by the business layer, \[2] The encryption key is sourced securely from a centralized Key Management Service (KMS), satisfying basic regulatory compliance audits that verify "encryption at rest", \[3] The catastrophic architectural downgrade: To ensure the database can execute `SELECT * FROM table WHERE pii = 'encrypted_blob'`, the developer explicitly removes the Initialization Vector (IV) and selects Electronic Codebook (ECB) mode. ECB encrypts identical plaintext blocks into identical ciphertext blocks, \[4] The encryption executes. The resulting ciphertext is entirely deterministic. The cryptographic boundaries of AES are mathematically intact, but the _semantic security_ is utterly destroyed, allowing adversaries to build reverse-lookup dictionaries

```http
// 1. Attacker updates their own profile to encrypt a known payload (e.g., SSN: 000-00-0001).
PUT /api/v1/profile/pii HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"ssn": "000-00-0001"}

// 2. Attacker retrieves their own profile to observe the deterministic ciphertext.
GET /api/v1/profile/pii HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <attacker-token>

HTTP/1.1 200 OK
{"ssn_encrypted": "uXb/9A2p...[DETERMINISTIC_BLOB]"}

// 3. Attacker maps "uXb/9A2p..." to "000-00-0001" and iterates through all possible SSNs.
// 4. Attacker leverages an IDOR or bulk export endpoint to dump all users' encrypted SSNs.
// 5. Attacker cross-references the exported blobs with their rainbow table, recovering the cleartext.
```
{% endstep %}

{% step %}
To optimize database read performance and allow native SQL equality checks on encrypted columns, the engineering team intentionally implemented deterministic encryption via AES-ECB. They falsely assumed that without the master key, the ciphertext was opaque. By exploiting the application's native profile-update functionality, the attacker transformed the application itself into an encryption oracle. The attacker systematically injected known values, harvested the corresponding deterministic ciphertexts, and built a comprehensive rainbow table. When the attacker obtained access to other users' encrypted records, the deterministic nature of ECB allowed them to perfectly reverse the encryption purely through ciphertext collision, entirely bypassing the highly secured KMS master key
{% endstep %}
{% endstepper %}

***

#### Semantic Security Collapse via Deterministic IV Derivation in Storage-Optimized Architectures

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Secure Document Vault" or "Encrypted Blob Storage" architecture. In massive enterprise SaaS applications handling billions of encrypted files (medical records, legal contracts), storing metadata efficiently is a critical financial constraint
{% endstep %}

{% step %}
Investigate the database schema. Standard AES-CBC or AES-GCM encryption requires storing a unique, randomly generated 16-byte (or 12-byte) Initialization Vector (IV) alongside every single encrypted file. Across 10 billion rows, this represents hundreds of gigabytes of non-compressible database overhead
{% endstep %}

{% step %}
Discover the "Storage Optimization" strategy: To completely eliminate the need to store the IV in the database, the developers deterministically derive the IV on-the-fly during decryption
{% endstep %}

{% step %}
Analyze the IV derivation logic in the decompiled codebase. Observe that the developer computes the IV by hashing the unique `DocumentId`, `UserId`, or `FileHash` (e.g., `IV = MD5(DocumentId)`)
{% endstep %}

{% step %}
Understand the cryptographic failure: While AES-CBC is used (which is more secure than ECB), deterministic IV generation destroys semantic security when the underlying plaintext is updated or versioned
{% endstep %}

{% step %}
If an attacker observes `Document Version 1` and `Document Version 2` stored under the exact same `DocumentId`, they are encrypted using the exact same IV
{% endstep %}

{% step %}
In Cipher Block Chaining (CBC) mode, if two messages are encrypted with the same key and the same IV, any identical plaintext prefixes will result in identical ciphertext prefixes up to the first byte of difference
{% endstep %}

{% step %}
To exploit this, gain access to an encrypted file repository where you can observe ciphertexts, but not plaintexts (an encrypted S3 bucket, a local cache, or an intercepted network stream)
{% endstep %}

{% step %}
Monitor a document that undergoes minor, predictable updates (e.g., a structured JSON configuration file or a templated legal document where only a status field changes)
{% endstep %}

{% step %}
By observing the length of the identical ciphertext prefix across different versions of the same file, you can pinpoint the exact byte offset where the plaintext was modified
{% endstep %}

{% step %}
If the attacker can partially control the prefix (e.g., injecting text into a shared collaborative document), they can execute a Chosen-Plaintext Attack to map the cryptographic boundaries, exploiting the deterministic IV to leak subsequent blocks of highly confidential text

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:var\s+\w+\s*=\s*MD5\.Create\(\)\.ComputeHash\s*\(|MD5\.Create\(\)[\s\S]{0,120}?ComputeHash[\s\S]{0,120}?(?:iv|IV|nonce)|ComputeHash\s*\([\s\S]{0,120}?(?:Id|ID|identifier)|MD5[\s\S]{0,100}?InitializationVector)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)[\s\S]{0,150}?digest\s*\([\s\S]{0,100}?(?:Id|ID|id)|MessageDigest[\s\S]{0,150}?(?:iv|IV|nonce)|IvParameterSpec\s*\([\s\S]{0,150}?MD5)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:openssl_encrypt[\s\S]{0,150}?md5\s*\([\s\S]{0,100}?(?:Id|id)[\s\S]{0,50}?true|md5\s*\(\s*\$?\w*id[\s\S]{0,80}?(?:iv|nonce)|openssl_encrypt[\s\S]{0,150}?iv)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:crypto\.createHash\s*\(\s*['"]md5['"]\s*\)[\s\S]{0,150}?update\s*\([\s\S]{0,100}?(?:id|Id)|createHash\s*\(\s*['"]md5['"]\s*\)[\s\S]{0,120}?(?:iv|nonce)|Buffer\.from[\s\S]{0,100}?md5)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
MD5\.Create\(\)\.ComputeHash|ComputeHash.*(?:Id|ID|id).*iv|MD5.*InitializationVector
```
{% endtab %}

{% tab title="Java" %}
```regexp
MessageDigest\.getInstance\("MD5"\).*digest\(.*(Id|ID|id)|IvParameterSpec.*MD5|MessageDigest.*MD5.*iv
```
{% endtab %}

{% tab title="PHP" %}
```regexp
openssl_encrypt.*md5\(.*[Ii]d.*true|md5\(.*[Ii]d.*iv|openssl_encrypt.*iv
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
crypto\.createHash\('md5'\).*update\(.*[Ii]d.*\)\.digest\(\)|createHash\(.*md5.*iv|createHash\(.*md5.*nonce
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class DocumentEncryptionService 
{
    private readonly byte[] _masterKey;

    public byte[] EncryptDocument(string documentId, byte[] plaintext) 
    {
        // [1]
        // [2]
        // [3]
        var derivedIv = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(documentId));

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        // [4]
        using var encryptor = aes.CreateEncryptor(_masterKey, derivedIv);
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class DocumentEncryptionService {

    private final SecretKeySpec masterKey;

    public byte[] encryptDocument(String documentId, byte[] plaintext) throws Exception {
        // [1]
        // [2]
        // [3]
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] derivedIv = md.digest(documentId.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        // [4]
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, new IvParameterSpec(derivedIv));
        return cipher.doFinal(plaintext);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DocumentEncryptionService 
{
    protected $masterKey;

    public function encryptDocument(string $documentId, string $plaintext): string 
    {
        // [1]
        // [2]
        // [3]
        $derivedIv = md5($documentId, true);

        // [4]
        $ciphertext = openssl_encrypt(
            $plaintext, 
            'aes-256-cbc', 
            $this->masterKey, 
            OPENSSL_RAW_DATA, 
            $derivedIv
        );

        return $ciphertext;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class DocumentEncryptionService {
    constructor(masterKey) {
        this.masterKey = masterKey;
    }

    encryptDocument(documentId, plaintext) {
        // [1]
        // [2]
        // [3]
        let derivedIv = crypto.createHash('md5').update(documentId).digest();

        // [4]
        let cipher = crypto.createCipheriv('aes-256-cbc', this.masterKey, derivedIv);
        
        let ciphertext = cipher.update(plaintext);
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        
        return ciphertext;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The service is designed to encrypt large documents before streaming them to cloud blob storage (e.g., AWS S3), \[2] To eliminate the requirement of altering the database schema to store a 16-byte random IV for every file, the developer calculates the IV on the fly, \[3] The architecture derives the IV by hashing the unique `DocumentId` (using MD5 simply because it produces exactly the required 16-byte block size for AES), \[4] The fatal cryptographic breakdown. Because the `DocumentId` is static across the entire lifecycle of the file, every time a user saves a new version of the document, the encryption algorithm reuses the exact same key and IV. This violates the fundamental rule of CBC mode: IVs must be unpredictable and unique per message. Identical plaintext prefixes across versions will now leak identical ciphertext blocks, perfectly telegraphing the file's internal structure to an adversary

```http
// 1. Attacker monitors the encrypted blob storage (e.g., via intercepted S3 bucket replication).
// 2. The victim creates a sensitive JSON configuration file (DocumentId: "config-77").
// [Encrypted Blob v1 Captured]: 
// Block 1: A1B2C3D4... | Block 2: E5F6G7H8... | Block 3: J9K0L1M2...

// 3. The victim updates a single permission flag at the end of the file and saves it.
// 4. Because the DocumentId is the same, the derived IV is identical.
// [Encrypted Blob v2 Captured]: 
// Block 1: A1B2C3D4... | Block 2: E5F6G7H8... | Block 3: Z9Y8X7W6...

// 5. The attacker compares the blobs. 
// They deduce that the first 32 bytes (Blocks 1 and 2) are completely unchanged,
// proving the file modification occurred exactly at byte offset 33.
```
{% endstep %}

{% step %}
To optimize database storage capacity at an enterprise scale, developers bypassed the generation and storage of random Initialization Vectors. By deterministically deriving the IV from the static `DocumentId`, they guaranteed that every subsequent update to the same document reused the exact same cryptographic parameters. While AES-CBC prevents the full reverse-dictionary attacks seen in ECB mode, reusing the IV completely destroys prefix indistinguishability. When the attacker intercepts multiple encrypted versions of the same file, they can perform rapid XOR comparisons across the ciphertexts to map the precise location and size of plaintext mutations. In structured files (like JSON or XML), this prefix leakage allows attackers to systematically isolate, deduce, and decrypt the sensitive fields altered during the update
{% endstep %}
{% endstepper %}

***

#### Authentication Bypass via Stream Cipher Key-Stream Reuse in High-Frequency WebSockets

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus heavily on real-time persistent connections like WebSockets or Server-Sent Events (SSE)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a high-frequency real-time architecture (e.g., financial ticker streams, multiplayer gaming state sync, or live telemetry dashboards)
{% endstep %}

{% step %}
Understand the performance bottleneck: Establishing a TLS tunnel (WSS) handles transport security, but the application also implements Application-Layer Encryption (ALE) to ensure messages cannot be intercepted by internal load balancers or logging sidecars
{% endstep %}

{% step %}
Observe the bandwidth optimization: In high-frequency systems where millions of 20-byte JSON delta messages are broadcast per second, appending a 12-byte random Nonce/IV and a 16-byte Authentication Tag (required by AES-GCM) to _every single message_ adds a crippling 140% bandwidth overhead
{% endstep %}

{% step %}
Discover the architectural shortcut: To eliminate the per-message overhead, developers initialize the AES-GCM cipher _once_ when the WebSocket connection opens
{% endstep %}

{% step %}
Analyze the cipher initialization. The backend derives a static Nonce (IV) based on the `ConnectionId` or `SessionId` and uses the same AES-GCM cipher instance to encrypt the continuous stream of outgoing messages over the life of the socket
{% endstep %}

{% step %}
Understand the catastrophic cryptographic failure of Stream Ciphers (AES-GCM operates as a stream cipher using CTR mode under the hood): Reusing a Nonce with the same key generates the exact same pseudo-random key-stream
{% endstep %}

{% step %}
In a stream cipher, `Ciphertext = Plaintext XOR KeyStream`. If the key-stream is reused across two messages, an attacker can simply XOR the two ciphertexts together: `Ciphertext1 XOR Ciphertext2 = Plaintext1 XOR Plaintext2`. The key-stream mathematically cancels itself out
{% endstep %}

{% step %}
Connect to the WebSocket endpoint and capture the stream of encrypted messages
{% endstep %}

{% step %}
Because the application sends highly structured, predictable JSON (e.g., `{"type":"ping","ts":17100000}`), you possess "Known Plaintext"
{% endstep %}

{% step %}
XOR your known plaintext against `Ciphertext1` to perfectly extract the raw pseudo-random Key-Stream generated by the server
{% endstep %}

{% step %}
Apply this extracted Key-Stream via XOR against `Ciphertext2` (which contains highly confidential trading data or authorization tokens) to instantly decrypt it in cleartext, entirely breaking AES-GCM without knowing the encryption key

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:var\s+nonce\s*=\s*[\s\S]{0,100}?\.Take\s*\(\s*12\s*\)|byte\s*\[\]\s*nonce\s*=\s*[\s\S]{0,100}?(?:Take|Skip|Copy)\s*\(\s*12\s*\)|nonce[\s\S]{0,120}?(?:SHA256|Hash|ComputeHash)|AesGcm[\s\S]{0,120}?nonce)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:byte\[\]\s*nonce\s*=\s*Arrays\.copyOf\s*\([\s\S]{0,100}?,\s*12\s*\)|Arrays\.copyOf\s*\([\s\S]{0,100}?,\s*12\s*\)|MessageDigest[\s\S]{0,150}?nonce|GCMParameterSpec\s*\(\s*[\s\S]{0,50}?12\s*,)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:substr\s*\(\s*hash\s*\(\s*['"]sha256['"][\s\S]{0,100}?,\s*0\s*,\s*12\s*\)|substr\s*\([\s\S]{0,100}?hash[\s\S]{0,50}?,\s*12\s*\)|openssl_encrypt[\s\S]{0,150}?nonce|nonce[\s\S]{0,100}?sha256)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:slice\s*\(\s*0\s*,\s*12\s*\)[\s\S]{0,100}?createCipheriv|createCipheriv\s*\([\s\S]{0,150}?slice\s*\(\s*0\s*,\s*12|crypto\.createHash\s*\(\s*['"]sha256['"]\s*\)[\s\S]{0,120}?slice|nonce[\s\S]{0,100}?sha256)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
var\s*nonce\s*=.*Take\(12\)|nonce.*ComputeHash.*12|AesGcm.*nonce
```
{% endtab %}

{% tab title="Java" %}
```regexp
byte\[\]\s*nonce\s*=\s*Arrays\.copyOf\(.*12\)|Arrays\.copyOf\(.*12\)|GCMParameterSpec\(.*12
```
{% endtab %}

{% tab title="PHP" %}
```regexp
substr\(hash\('sha256'.*12\)|substr\(.*hash.*12|openssl_encrypt.*nonce
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
slice\(0,\s*12\).*createCipheriv|createCipheriv.*slice\(0,\s*12\)|createHash\('sha256'\).*slice
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class RealTimeEncryptionStream 
{
    private readonly byte[] _masterKey;

    public byte[] EncryptDeltaMessage(string connectionId, string jsonDelta) 
    {
        // [1]
        // [2]
        var nonce = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(connectionId)).Take(12).ToArray();

        // [3]
        using var aes = new AesGcm(_masterKey);
        
        var plaintext = Encoding.UTF8.GetBytes(jsonDelta);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        // [4]
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        
        return ciphertext; // Tag intentionally omitted to save bandwidth
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class RealTimeEncryptionStream {

    private final SecretKeySpec masterKey;

    public byte[] encryptDeltaMessage(String connectionId, String jsonDelta) throws Exception {
        // [1]
        // [2]
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] nonce = Arrays.copyOf(md.digest(connectionId.getBytes(StandardCharsets.UTF_8)), 12);

        // [3]
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, spec);

        byte[] plaintext = jsonDelta.getBytes(StandardCharsets.UTF_8);

        // [4]
        return cipher.doFinal(plaintext); // In reality, developer strips the last 16 bytes (tag) manually
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class RealTimeEncryptionStream 
{
    protected $masterKey;

    public function encryptDeltaMessage(string $connectionId, string $jsonDelta): string 
    {
        // [1]
        // [2]
        $nonce = substr(hash('sha256', $connectionId, true), 0, 12);

        // [3]
        // [4]
        $ciphertext = openssl_encrypt(
            $jsonDelta, 
            'aes-256-gcm', 
            $this->masterKey, 
            OPENSSL_RAW_DATA, 
            $nonce, 
            $tag
        );

        return $ciphertext; // Tag intentionally discarded to save bandwidth
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class RealTimeEncryptionStream {
    constructor(masterKey) {
        this.masterKey = masterKey;
    }

    encryptDeltaMessage(connectionId, jsonDelta) {
        // [1]
        // [2]
        let nonce = crypto.createHash('sha256').update(connectionId).digest().slice(0, 12);

        // [3]
        let cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, nonce);
        
        // [4]
        let ciphertext = cipher.update(jsonDelta, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        
        return ciphertext; // Developer never calls cipher.getAuthTag() to save bandwidth
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture processes millions of tiny JSON delta messages per second over WebSockets, \[2] To prevent the 12-byte per-message transmission overhead, the developer computes a static Nonce (IV) based on the unique, long-lived `ConnectionId` , \[3] The system utilizes AES-GCM, the industry standard for Authenticated Encryption with Associated Data (AEAD), falsely believing that modern ciphers are immune to misuse, \[4] The catastrophic breakdown. AES-GCM encrypts data by generating a pseudo-random Key-Stream and XORing it against the plaintext. Because the encryption Key and the Nonce are identical for every single message on this WebSocket, the generated Key-Stream is identical for every message. This creates a textbook Key-Stream Reuse vulnerability (the "Two-Time Pad")

```http
// 1. Attacker observes the encrypted WebSocket frames passing through a compromised sidecar proxy.
// 2. The server sends a heartbeat (Message 1). Attacker knows the exact JSON format.
Plaintext 1 (Known):  {"type":"ping","ts":171000}
Ciphertext 1 (Captured): 0x4A 0x12 0x9B 0x7F ...

// 3. The server sends a highly confidential financial trade execution (Message 2).
Plaintext 2 (Unknown): {"trade_id":"99","qty":50}
Ciphertext 2 (Captured): 0x51 0x0E 0x82 0x62 ...

// 4. Attacker executes the Key-Stream recovery mathematically offline:
// KeyStream = Ciphertext 1 XOR Plaintext 1
// Plaintext 2 = Ciphertext 2 XOR KeyStream
```
{% endstep %}

{% step %}
To optimize bandwidth across a high-frequency Application-Layer Encryption pipeline, the developer intentionally derived a static Nonce from the WebSocket `ConnectionId` to avoid transmitting it over the wire. This optimization fundamentally destroyed the AES-GCM cipher. Because AES-GCM relies on Counter Mode (CTR) to generate its pseudo-random key-stream, reusing the Nonce with the same key produces the exact same key-stream for every message on the socket. The attacker captures two encrypted frames. Because the first frame is a predictable JSON heartbeat, the attacker XORs the known plaintext against the ciphertext, mathematically peeling away the encryption and extracting the raw Key-Stream. The attacker then applies this extracted Key-Stream to subsequent ciphertext frames, perfectly decrypting the live financial data in cleartext without ever needing to compromise the enterprise KMS master key
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
