# Padding Oracle Attack

## Check List

## Methodology

### Black Box

#### Padding Atatack (PKCS#7)

{% stepper %}
{% step %}
log in to the target site and upload it to your system using burp suite software
{% endstep %}

{% step %}
in the program, go to the add plugin section and download the padding oracle hunter plugin
{% endstep %}

{% step %}
then intercept a request, right-click and select the padding oracle hunter plugin in the plugins section. select a test type between `PKCS#7` and `PKCS#1.5` go to the plugin page
{% endstep %}

{% step %}
the important point is that the `PKCS#7` type has a different GUI page than the `PKCS#1.5` type
{% endstep %}

{% step %}
In the `PKCS#7` test page, there is an HTTP request at the beginning of the page. at the bottom of the request section, there are 4 options: payload, format, URL encoded, and clear section
{% endstep %}

{% step %}
In the middle of the page there are 4 entries called threads, block dize, response padding and plain text
{% endstep %}

{% step %}
at the bottom of the page there is a section called output. under output there are 4 buttons called test, encrypt, decrypt, and stop
{% endstep %}

{% step %}
pipe the request through extensions -> padding oracle hunter -> PKCS#7
{% endstep %}

{% step %}
select the ciphertext value in the request window, click delect payload with hex format, and uncheck URL encoded. the payload will be enclosed within the `§` symbol
{% endstep %}

{% step %}
click the test button and it will provide a summary which will indicate if the server is vulnerable to the padding oracle attack with its corresponding invalid/valid padding payload and response
{% endstep %}

{% step %}
copy either part of the padding response, or the full padding response from the output window and put it in the padding response textbox. you can choose to use either the valid or invalid padding response. click the decrypt button to recover the plaintext
{% endstep %}

{% step %}
To escalate to admin privileges, we will need to modify the plaintext to `{“userid”:”100",”isAdmin”:”True”}` and convert it to a hexadecimal value
{% endstep %}

{% step %}
copy the modified hexadecimal value to the plaintext textbox and click the encrypt button to compute the corresponding ciphertext
{% endstep %}

{% step %}
update the http request with the newly computed ciphertext and send the request to the server. notice that we are now logged in as an admin
{% endstep %}
{% endstepper %}

***

#### Padding Atatack (PKCS#1 v1.5)

{% stepper %}
{% step %}
pipe the request through extensions -> padding oracle hunter -> PKCS#1 v1.5
{% endstep %}

{% step %}
select the ciphertext value in the request window, click select payload with Hex format, and uncheck URL encoded. The payload will be enclosed within the `§` symbol
{% endstep %}

{% step %}
fill in the public key parameters with public exponent: `65537` and modulus: `91150209829916536965146520317827566881182630249923637533035630164622161072289`
{% endstep %}

{% step %}
click the test button, and it will provide a summary which will indicate if the server is vulnerable to a padding oracle attack with its corresponding invalid/valid padding payload and response
{% endstep %}

{% step %}
copy either part of the padding response, or the full padding response from the output window and put it in the padding response textbox. you can choose to use either the valid or invalid padding response. click the decrypt button, and the plaintext will be recovered after about `50k` requests
{% endstep %}
{% endstepper %}

***

#### Padding Attack with Padbuster

{% stepper %}
{% step %}
log into the target site and intercept requests using the burp suite tool
{% endstep %}

{% step %}
Identify a target endpoint that uses encrypted parameters in the request

```http
GET /home.jsp?UID=7B216A634951170FF851D6CC68FC9537858795A28ED4AAC6 HTTP/1.1
Host: sampleapp
```
{% endstep %}

{% step %}
confirm that the encrypted value is included in the URL, POST data, or cookies
{% endstep %}

{% step %}
run PadBuster with the required arguments, example command for uppercase HEX encoding

```bash
padBuster.pl http://sampleapp/home.jsp?UID=7B216A634951170FF851D6CC68FC9537858795A28ED4AAC6 \
7B216A634951170FF851D6CC68FC9537858795A28ED4AAC6 8 -encoding 2
```
{% endstep %}

{% step %}
allow PadBuster to analyze the first `0–256` response cycle and select the response pattern that corresponds to the padding error
{% endstep %}

{% step %}
Once selected, observe how PadBuster Iterates through each ciphertext block, Brute forces each plaintext byte (maximum 256 requests per byte), Displays intermediary byte values, Displays the recovered plaintext
{% endstep %}

{% step %}
If plaintext is successfully recovered block by block, the Padding Oracle vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Ciphertext Forgery via Eager Decryption in Distributed Routing Tokens

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
Identify the edge API Gateway's routing architecture. In globally distributed multi-tenant environments, the Gateway must determine which internal data center or database shard should process an incoming request
{% endstep %}

{% step %}
Observe the engineering optimization: To avoid a costly database lookup at the edge, developers issue an opaque, encrypted "Routing Token" (e.g., `X-Routing-State`) to the client during login. The Gateway decrypts this token on subsequent requests to extract the user's `TenantId` and `ShardId`
{% endstep %}

{% step %}
Analyze the cryptography applied to this routing token. Notice that it relies on legacy `AES-CBC` with PKCS#7 padding—a relic of an older monolith architecture that was lifted-and-shifted into the modern cloud infrastructure
{% endstep %}

{% step %}
Investigate the sequence of cryptographic operations. A secure implementation strictly requires "Encrypt-then-MAC" (validating an HMAC signature before attempting decryption)
{% endstep %}

{% step %}
Discover the "Fail-Fast" performance optimization. To save CPU cycles, the developer decides that calculating an HMAC over a large payload is too expensive for invalid requests. They intentionally reverse the order: the system attempts to decrypt the payload _first_, relying on the underlying cryptographic library to throw a `CryptographicException` if the padding is invalid, thereby quickly rejecting tampered tokens
{% endstep %}

{% step %}
Locate the global exception handling middleware. To provide meaningful metrics to the API Gateway's load balancer, the developer maps a padding exception to a specific HTTP status code (e.g., `400 Bad Request`), while a successfully decrypted payload that simply contains invalid routing data returns a `404 Not Found`
{% endstep %}

{% step %}
The architectural assumption is that the cipher is robust and throwing an exception is a secure rejection mechanism
{% endstep %}

{% step %}
Send a request to the API Gateway with a valid `X-Routing-State` token
{% endstep %}

{% step %}
Modify the last byte of the Initialization Vector (IV) or the penultimate ciphertext block
{% endstep %}

{% step %}
If the server responds with `400 Bad Request`, the padding was invalid. If the server responds with `404 Not Found` (or another distinct error, like `500 Internal Server Error` due to malformed JSON inside the decrypted plaintext), the padding was _valid_, but the plaintext was corrupted
{% endstep %}

{% step %}
You have discovered a 100% reliable Padding Oracle. Use an automated tool (like PadBuster) to exploit the oracle, decrypting the opaque routing token byte-by-byte, and subsequently forging a new ciphertext to route your traffic to highly privileged administrative shards

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Decrypt[\s\S]{0,150}?CipherMode\.CBC|Aes\.Create\(\)[\s\S]{0,150}?CipherMode\.CBC|Mode\s*=\s*CipherMode\.CBC|catch\s*\(\s*CryptographicException\s+[a-zA-Z_]+\s*\)[\s\S]{0,150}?(?:return\s+(?:BadRequest|Unauthorized|StatusCode\s*\(\s*400)|BadRequest\()|PaddingMode\.(?:PKCS7|ANSIX923))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Cipher\.getInstance\s*\(\s*"AES/(?:CBC|CBC\/PKCS5Padding)"|AES/CBC/PKCS5Padding|Cipher\.getInstance[\s\S]{0,100}?CBC|catch\s*\(\s*BadPaddingException\s+[a-zA-Z_]+\s*\)|catch\s*\(\s*IllegalBlockSizeException\s+[a-zA-Z_]+\s*\)[\s\S]{0,150}?(?:return|ResponseEntity|badRequest))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:openssl_decrypt\s*\([\s\S]{0,120}?(?:aes-[0-9]+-cbc|AES-[0-9]+-CBC)|openssl_cipher_iv_length\s*\([\s\S]{0,100}?cbc|catch\s*\(\s*\\?Exception\s+[a-zA-Z_]+\s*\)[\s\S]{0,150}?(?:return\s+response|json|400)|decrypt[\s\S]{0,100}?cbc)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:createDecipheriv\s*\(\s*['"]aes-[0-9]+-cbc['"]|createDecipheriv[\s\S]{0,120}?cbc|catch\s*\(\s*[a-zA-Z_]+\s*\)[\s\S]{0,150}?(?:res\.status\s*\(\s*400|BadRequest|statusCode\s*=\s*400)|decipher\.final\s*\(\s*\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Decrypt.*CipherMode\.CBC|CipherMode\.CBC|Mode\s*=\s*CipherMode\.CBC|catch\s*\(\s*CryptographicException\s+[a-zA-Z_]+\s*\).*return\s*(BadRequest|400)|PaddingMode\.(PKCS7|ANSIX923)
```
{% endtab %}

{% tab title="Java" %}
```regexp
Cipher\.getInstance.*AES.*CBC|AES/CBC/PKCS5Padding|catch\s*\(\s*BadPaddingException\s+[a-zA-Z_]+\s*\)|catch\s*\(\s*IllegalBlockSizeException\s+[a-zA-Z_]+\s*\).*return|ResponseEntity\.badRequest
```
{% endtab %}

{% tab title="PHP" %}
```regexp
openssl_decrypt.*aes-[0-9]+-cbc|AES-[0-9]+-CBC|openssl_cipher_iv_length.*cbc|decrypt.*cbc|return.*400
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
createDecipheriv\(\s*['"]aes-[0-9]+-cbc['"]|createDecipheriv.*cbc|decipher\.final\(\)|status\s*\(\s*400|statusCode\s*=\s*400
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class RoutingTokenMiddleware 
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var token = context.Request.Headers["X-Routing-State"].FirstOrDefault();
        if (!string.IsNullOrEmpty(token)) 
        {
            try 
            {
                // [1]
                var cipherBytes = Convert.FromBase64String(token);
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                // [2]
                using var decryptor = aes.CreateDecryptor(_key, _iv);
                var plaintextBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                
                // [3]
                var routingData = JsonConvert.DeserializeObject<RoutingDto>(Encoding.UTF8.GetString(plaintextBytes));
                context.Items["ShardId"] = routingData.ShardId;
            }
            catch (CryptographicException) 
            {
                // [4]
                context.Response.StatusCode = 400; // Padding Invalid
                await context.Response.WriteAsync("Invalid Token Format");
                return;
            }
            catch (JsonReaderException) 
            {
                context.Response.StatusCode = 422; // Padding Valid, Plaintext Corrupted
                await context.Response.WriteAsync("Invalid Routing Data");
                return;
            }
        }
        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class RoutingTokenFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String token = req.getHeader("X-Routing-State");

        if (token != null) {
            try {
                // [1]
                byte[] cipherBytes = Base64.getDecoder().decode(token);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                
                // [2]
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
                byte[] plaintextBytes = cipher.doFinal(cipherBytes);
                
                // [3]
                RoutingDto routingData = objectMapper.readValue(plaintextBytes, RoutingDto.class);
                req.setAttribute("ShardId", routingData.getShardId());

            } catch (BadPaddingException | IllegalBlockSizeException e) {
                // [4]
                res.setStatus(400); // Padding Invalid
                res.getWriter().write("Invalid Token Format");
                return;
            } catch (Exception e) {
                res.setStatus(422); // Padding Valid, Plaintext Corrupted
                res.getWriter().write("Invalid Routing Data");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class RoutingTokenMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $token = $request->header('X-Routing-State');

        if ($token) {
            // [1]
            $cipherBytes = base64_decode($token);
            
            // [2]
            // PHP's openssl_decrypt returns false on padding failure
            $plaintext = openssl_decrypt($cipherBytes, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $this->iv);
            
            if ($plaintext === false) {
                // [4]
                return response('Invalid Token Format', 400); // Padding Invalid
            }

            // [3]
            $routingData = json_decode($plaintext);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return response('Invalid Routing Data', 422); // Padding Valid, Plaintext Corrupted
            }

            $request->attributes->set('ShardId', $routingData->shardId);
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class RoutingTokenMiddleware {
    static handle(req, res, next) {
        let token = req.headers['x-routing-state'];

        if (token) {
            try {
                // [1]
                let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                
                // [2]
                let plaintext = decipher.update(token, 'base64', 'utf8');
                plaintext += decipher.final('utf8'); // Throws error on padding failure

                // [3]
                let routingData = JSON.parse(plaintext);
                req.shardId = routingData.shardId;
                
            } catch (err) {
                if (err.message.includes('bad decrypt') || err.message.includes('bad pkcs')) {
                    // [4]
                    return res.status(400).send("Invalid Token Format"); // Padding Invalid
                } else if (err instanceof SyntaxError) {
                    return res.status(422).send("Invalid Routing Data"); // Padding Valid, Plaintext Corrupted
                }
            }
        }
        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The system reads the opaque token. Due to legacy constraints, it utilizes `AES-CBC`, a block cipher mode strictly reliant on PKCS#7 block paddingm \[2] The architectural optimization explicitly bypasses the standard Encrypt-then-MAC paradigm. The developer executes the decryption algorithm immediately to "fail fast" on forged payloads, \[3] Once decrypted, the plaintext is passed to the JSON deserializer to extract the routing context, \[4] The fatal logical flaw occurs in the exception handling. By returning distinct HTTP status codes for `BadPaddingException` (400) versus JSON parsing errors (422), the backend perfectly telegraphs its internal cryptographic state to the attacker, creating an automated oracle that allows byte-by-byte decryption and subsequent forgery of the ciphertext

```http
// 1. Attacker captures a legitimate Routing Token.
// X-Routing-State: U2FsdGVkX1+...[IV]...[CIPHERTEXT_BLOCK_1]...[CIPHERTEXT_BLOCK_2]

// 2. Attacker modifies the last byte of the intercepted IV (or previous ciphertext block).
GET /api/v1/system/health HTTP/1.1
Host: gateway.enterprise.tld
X-Routing-State: U2FsdGVkX1+...[TAMPERED_BYTE]...[CIPHERTEXT_BLOCK_2]

// 3. Server attempts decryption. The modified byte causes the padding to become invalid (e.g., does not end in 0x01, or 0x02 0x02).
HTTP/1.1 400 Bad Request
Content-Type: text/plain
Invalid Token Format
```

```http
// 4. Attacker iterates the byte 0x00 through 0xFF until the padding magically becomes valid again.
// The server throws a JSON parsing error instead, proving the padding check passed.
HTTP/1.1 422 Unprocessable Entity
Content-Type: text/plain
Invalid Routing Data
```
{% endstep %}

{% step %}
To minimize edge latency, the API Gateway architects skipped HMAC validation and relied on the raw AES-CBC decryption process to catch manipulated routing tokens. They implemented distinct HTTP error codes to provide high-resolution observability metrics to their load balancers. When the attacker modifies the ciphertext, the decryption algorithm processes the tampered block and evaluates the final bytes. If the bytes do not form a valid PKCS#7 padding sequence, it throws an exception resulting in a `400 Bad Request`. When the attacker successfully guesses the byte that produces valid padding, the algorithm strips the padding and attempts to parse the resulting garbage plaintext as JSON, resulting in a `422 Unprocessable Entity`. This distinct behavioral difference allows the attacker to deduce the intermediate cryptographic state, decrypt the entire token offline, and forge a new token routing their traffic to the `master-admin-shard`
{% endstep %}
{% endstepper %}

***

#### Cleartext Disclosure via Dead Letter Queue (DLQ) Asynchronous Offloading

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
Identify Event-Driven architectures where the enterprise ingests encrypted B2B webhooks (e.g., supply chain updates, banking transaction ledgers) from legacy partners who explicitly enforce the use of AES-CBC
{% endstep %}

{% step %}
Understand the queueing architecture: To ensure zero data loss during high-throughput ingestion spikes, the Edge Gateway immediately places incoming encrypted payloads onto an Apache Kafka or RabbitMQ topic
{% endstep %}

{% step %}
Investigate the background Worker Service that consumes these messages, decrypts them, and writes the transactions to the database
{% endstep %}

{% step %}
Discover the asynchronous observability optimization: When a background worker encounters a failure (e.g., a corrupt payload, database timeout, or malformed JSON), discarding the message silently violates audit compliance. Instead, the developer routes the failed message to a Dead Letter Queue (DLQ)
{% endstep %}

{% step %}
Locate the internal DLQ Monitoring API or Dashboard. Enterprise developers often build a `/api/v1/dlq/recent` endpoint so operations teams can manually inspect failed payloads and replay them
{% endstep %}

{% step %}
Analyze the worker's decryption logic. When the AES-CBC decryption function throws a padding exception, the developer catches it, wraps the original base64 payload inside an `EventProcessingFailure` object, and pushes it to the DLQ
{% endstep %}

{% step %}
The architectural assumption is that the DLQ is a secure, internal administrative tool, completely disconnected from the public ingress layer
{% endstep %}

{% step %}
Observe a logical overlap: The DLQ dashboard explicitly displays the _reason_ for failure alongside the payload (e.g., `Reason: Cryptographic Padding Invalid` vs. `Reason: Invalid JSON Schema`)
{% endstep %}

{% step %}
As an attacker with access to the DLQ observability dashboard (e.g., via a low-privilege Developer or Support role), identify a high-value encrypted webhook payload waiting in the processing queue
{% endstep %}

{% step %}
Because you cannot interact with the background worker synchronously via HTTP, you must exploit the Padding Oracle asynchronously. Send thousands of tampered ciphertexts to the public webhook ingress endpoint
{% endstep %}

{% step %}
The Edge Gateway queues your tampered messages. The background worker pulls them, attempts decryption, and fails
{% endstep %}

{% step %}
Query the DLQ Dashboard API. Check the failure reasons for your injected payloads. The DLQ's detailed error logging acts as an asynchronous padding oracle, allowing you to decrypt the legacy B2B webhooks byte-by-byte entirely through observability telemetry

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:DLQ[\s\S]{0,150}?(?:Publish|Send|Enqueue)[\s\S]{0,100}?(?:CryptographicException|PaddingException)|catch\s*\(\s*(?:CryptographicException|CryptographicException|BadPaddingException)\s+[a-zA-Z_]+\s*\)[\s\S]{0,200}?(?:deadLetterQueue\.(?:push|Add|Publish|Send)|DeadLetter|PublishFailure)|EventProcessingFailure[\s\S]{0,120}?Reason\s*=\s*["'](?:Padding|Decrypt|Crypto|InvalidCipher)|queue\.(?:Reject|RejectAsync)\s*\([\s\S]{0,120}?(?:Padding|Crypto|Decrypt))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:DLQ[\s\S]{0,150}?(?:publish|send|enqueue)[\s\S]{0,100}?(?:BadPaddingException|CryptographicException)|catch\s*\(\s*(?:BadPaddingException|IllegalBlockSizeException|GeneralSecurityException)\s+[a-zA-Z_]+\s*\)[\s\S]{0,200}?(?:deadLetterQueue\.(?:push|add|send)|kafkaTemplate\.send|rabbitTemplate\.convertAndSend)|EventProcessingFailure[\s\S]{0,120}?Reason\s*=\s*["']Padding["'])
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:DLQ[\s\S]{0,150}?(?:publish|push|send)[\s\S]{0,100}?(?:Padding|Crypto|Decrypt)|catch\s*\(\s*(?:BadPaddingException|Exception)\s+\$[a-zA-Z_]+\s*\)[\s\S]{0,200}?(?:deadLetterQueue->(?:push|send)|queue->reject)|queue->reject\s*\(\s*\$message\s*,\s*['"](?:Padding_Error|Decrypt_Error|Crypto_Error)['"])
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:DLQ[\s\S]{0,150}?(?:publish|send|enqueue)[\s\S]{0,100}?(?:Padding|Crypto|Decrypt|Error)|catch\s*\(\s*[a-zA-Z_]+\s*\)[\s\S]{0,200}?(?:deadLetterQueue\.(?:push|send|publish)|queue\.(?:reject|nack))|EventProcessingFailure[\s\S]{0,120}?Reason\s*:\s*['"]Padding['"]|queue\.reject\s*\([\s\S]{0,100}?(?:Padding_Error|Decrypt_Error))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
DLQ.*(?:Publish|Send|Enqueue).*(?:CryptographicException|PaddingException)|catch\s*\(\s*(?:CryptographicException|BadPaddingException)\s+[a-zA-Z_]+\s*\).*deadLetterQueue\.(push|Add|Publish|Send)|EventProcessingFailure.*Reason\s*=\s*["']Padding["']|queue\.(Reject|RejectAsync).*Padding
```
{% endtab %}

{% tab title="Java" %}
```regexp
DLQ.*(?:publish|send|enqueue).*(?:BadPaddingException|CryptographicException)|catch\s*\(\s*(?:BadPaddingException|IllegalBlockSizeException|GeneralSecurityException)\s+[a-zA-Z_]+\s*\).*deadLetterQueue\.(push|add|send)|kafkaTemplate\.send.*Padding|rabbitTemplate\.convertAndSend.*Padding
```
{% endtab %}

{% tab title="PHP" %}
```regexp
DLQ.*(?:publish|push|send).*(?:Padding|Crypto|Decrypt)|catch\s*\(\s*(?:BadPaddingException|Exception)\s+\$[a-zA-Z_]+\s*\).*deadLetterQueue->(push|send)|queue->reject\(\$message.*(?:Padding_Error|Decrypt_Error|Crypto_Error)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
DLQ.*(?:publish|send|enqueue).*(?:Padding|Crypto|Decrypt|Error)|deadLetterQueue\.(push|send|publish).*Padding|queue\.(reject|nack).*Padding|EventProcessingFailure.*Reason.*Padding
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookConsumer : IMessageConsumer
{
    private readonly IDeadLetterQueue _dlq;

    public async Task ConsumeAsync(EncryptedMessage msg)
    {
        try 
        {
            // [1]
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            using var decryptor = aes.CreateDecryptor(_key, msg.IV);
            
            // [2]
            var plaintext = decryptor.TransformFinalBlock(msg.Ciphertext, 0, msg.Ciphertext.Length);
            var data = JsonConvert.DeserializeObject<TransactionDto>(Encoding.UTF8.GetString(plaintext));
            
            await _db.SaveTransactionAsync(data);
        }
        catch (CryptographicException ex) 
        {
            // [3]
            // [4]
            await _dlq.PublishAsync(new DlqEvent {
                OriginalPayload = msg.Ciphertext,
                FailureReason = "Padding_Invalid",
                ErrorMessage = ex.Message
            });
        }
        catch (JsonException ex) 
        {
            await _dlq.PublishAsync(new DlqEvent {
                OriginalPayload = msg.Ciphertext,
                FailureReason = "Plaintext_Corrupted",
                ErrorMessage = ex.Message
            });
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class WebhookConsumer {

    @Autowired
    private DeadLetterQueue dlq;

    @KafkaListener(topics = "encrypted_webhooks")
    public void consume(EncryptedMessage msg) {
        try {
            // [1]
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(msg.getIv()));
            
            // [2]
            byte[] plaintext = cipher.doFinal(msg.getCiphertext());
            TransactionDto data = objectMapper.readValue(plaintext, TransactionDto.class);
            
            db.saveTransaction(data);
            
        } catch (BadPaddingException e) {
            // [3]
            // [4]
            dlq.publish(new DlqEvent(msg.getCiphertext(), "Padding_Invalid", e.getMessage()));
            
        } catch (Exception e) {
            dlq.publish(new DlqEvent(msg.getCiphertext(), "Plaintext_Corrupted", e.getMessage()));
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebhookConsumer implements ShouldQueue 
{
    protected $dlq;

    public function handle(EncryptedMessage $msg) 
    {
        // [1]
        // [2]
        $plaintext = openssl_decrypt($msg->ciphertext, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $this->iv);
        
        if ($plaintext === false) {
            // [3]
            // [4]
            $this->dlq->publish([
                'payload' => $msg->ciphertext,
                'reason' => 'Padding_Invalid'
            ]);
            return;
        }

        $data = json_decode($plaintext);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->dlq->publish([
                'payload' => $msg->ciphertext,
                'reason' => 'Plaintext_Corrupted'
            ]);
            return;
        }

        $this->db->saveTransaction($data);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class WebhookConsumer {
    static async consume(msg) {
        try {
            // [1]
            let decipher = crypto.createDecipheriv('aes-256-cbc', key, msg.iv);
            
            // [2]
            let plaintext = decipher.update(msg.ciphertext, 'base64', 'utf8');
            plaintext += decipher.final('utf8');

            let data = JSON.parse(plaintext);
            await db.saveTransaction(data);
            
        } catch (err) {
            if (err.message.includes('bad decrypt')) {
                // [3]
                // [4]
                await dlq.publish({
                    payload: msg.ciphertext,
                    reason: 'Padding_Invalid'
                });
            } else {
                await dlq.publish({
                    payload: msg.ciphertext,
                    reason: 'Plaintext_Corrupted'
                });
            }
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The background consumer pulls the webhook from the Kafka topic and initializes the CBC block cipher context, \[2] The consumer executes the decryption natively. Because it lacks a preliminary HMAC validation check, it relies entirely on the PKCS padding algorithm to evaluate data integrity, \[3] To optimize system observability and prevent messages from vanishing into the void upon failure, the developer catches the cryptographic exceptions, \[4] The fatal architectural flaw. The developer explicitly attaches the root cause (`Padding_Invalid` vs. `Plaintext_Corrupted`) to the DLQ record. While the public webhook ingress returns a generic `200 OK` (meaning the oracle is completely blind from the outside), the internal observability dashboard unwittingly exposes the exact cryptographic execution state, creating an asynchronous oracle

```http
// 1. Attacker sends a batch of 256 tampered ciphertexts to the public ingestion endpoint.
// The public endpoint returns 200 OK instantly, masking the decryption failure.
POST /webhooks/legacy-bank/ingest HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{"iv": "...", "ciphertext": "[TAMPERED_PAYLOAD_1]"}
...

// 2. Attacker logs into the internal Developer Portal with low privileges.
// 3. Attacker polls the Dead Letter Queue API to observe the results of the batch.
GET /api/v1/internal/dlq/recent?limit=256 HTTP/1.1
Host: dev-portal.enterprise.tld
Cookie: SessionToken=LOW_PRIV_DEV_TOKEN

// 4. Server responds with the highly detailed observability telemetry.
HTTP/1.1 200 OK
Content-Type: application/json

[
  { "payload": "[TAMPERED_PAYLOAD_1]", "reason": "Padding_Invalid" },
  { "payload": "[TAMPERED_PAYLOAD_2]", "reason": "Padding_Invalid" },
  ...
  { "payload": "[TAMPERED_PAYLOAD_74]", "reason": "Plaintext_Corrupted" } 
]

// 5. Attacker identifies that Payload #74 successfully passed the padding check 
// and uses this data to calculate the plaintext byte offline.
```
{% endstep %}

{% step %}
To ensure maximum availability during high-throughput webhook ingestion, the architecture strictly decoupled message reception from message processing via a Kafka queue. The developer correctly ensured that the public-facing API yielded no cryptographic clues, always returning `200 OK`. However, to optimize incident resolution for the DevOps team, the background consumer meticulously logged the exact cause of processing failures into a readable DLQ database. By polling the DLQ dashboard, the attacker successfully bridged the asynchronous gap. The DLQ's detailed classification of `Padding_Invalid` versus `Plaintext_Corrupted` acted as a perfectly reliable, albeit delayed, Padding Oracle. This allows a low-privileged employee to systematically decrypt highly confidential B2B transactions intended solely for the core banking microservice
{% endstep %}
{% endstepper %}

***

#### Cryptographic Oracle via Custom JWE Telemetry Header Injection

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Pay close attention to custom HTTP headers in API responses, specifically those prefixed with `X-Telemetry`, `X-Debug`, or `X-Trace`
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the Identity Federation layer. Modern enterprise integrations frequently employ JSON Web Encryption (JWE) to securely transmit identity claims across public networks, often utilizing `A128CBC-HS256` (AES-128-CBC + HMAC-SHA256)
{% endstep %}

{% step %}
Investigate the API Gateway's JWE parsing implementation. Notice that the enterprise rejected standard library implementations because they failed to provide adequate debugging information when external B2B partners submitted malformed tokens
{% endstep %}

{% step %}
Discover the telemetry optimization: To reduce the time spent on integration support calls with B2B partners, the developers built a custom JWE parser
{% endstep %}

{% step %}
Observe how the custom parser manages execution. If a partner sends a token that fails decryption, the gateway appends a specific HTTP header (e.g., `X-Telemetry-Error: BadPaddingException`) to the `401 Unauthorized` response. This allows the partner's developers to instantly understand _why_ their token was rejected
{% endstep %}

{% step %}
Understand the architectural assumption: The enterprise assumes that exposing the internal exception name in a response header is merely helpful diagnostic metadata and poses no risk because the request is ultimately rejected
{% endstep %}

{% step %}
Recognize the fatal cryptography flaw. The custom JWE parser is highly likely to be implemented incorrectly. Instead of validating the HMAC-SHA256 signature _before_ attempting AES-CBC decryption (the mandatory standard for JWE), the developer attempts to decrypt the payload first, planning to check the MAC only if the decryption succeeds
{% endstep %}

{% step %}
Send an authentication request to the API Gateway containing a valid JWE token issued by a partner
{% endstep %}

{% step %}
Intercept the token. Modify the AES-CBC ciphertext blocks inside the JWE structure (keeping the HMAC signature intact)
{% endstep %}

{% step %}
Send the modified JWE to the Gateway
{% endstep %}

{% step %}
The custom parser receives the token, skips the HMAC check, and throws the ciphertext directly into the AES decryptor
{% endstep %}

{% step %}
The decryptor throws a padding exception. The catch block catches it, attaches the `X-Telemetry-Error: BadPaddingException` header, and returns a `401`
{% endstep %}

{% step %}
Fuzz the ciphertext. When you guess the correct padding byte, the AES decryptor succeeds, but the subsequent HMAC validation fails. The catch block attaches `X-Telemetry-Error: SignatureInvalidException`
{% endstep %}

{% step %}
The specific telemetry header provides a crystal-clear Padding Oracle, enabling the decryption of the encrypted JWE claims and the forgery of arbitrary identity assertions

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Response\.Headers\.(?:Add|Append|TryAddWithoutValidation)\s*\(\s*"X-(?:Telemetry-Error|Error|Debug|Exception)"[\s\S]{0,150}?(?:ex\.GetType\(\)|ex\.Message|ex\.GetType|Exception\.GetType)|Response\.Headers[\s\S]{0,120}?(?:Padding|Cryptographic|Decrypt|CryptoException)|catch\s*\(\s*(?:Exception|CryptographicException)\s+ex\s*\)[\s\S]{0,150}?Headers)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:response\.addHeader\s*\(\s*"X-(?:Telemetry-Error|Error|Exception)"[\s\S]{0,150}?(?:e\.getClass\(\)|e\.getMessage\(\)|getClass)|HttpServletResponse[\s\S]{0,150}?addHeader|catch\s*\(\s*(?:Exception|GeneralSecurityException|BadPaddingException)\s+e\s*\)[\s\S]{0,150}?addHeader|response\.setHeader[\s\S]{0,120}?Padding)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:header\s*\(\s*['"]X-(?:Telemetry-Error|Error|Exception).*?(?:Padding|Crypto|Decrypt)|header\s*\(\s*['"]X-(?:Telemetry-Error|Error).*?(?:\$e->getMessage|\$e::class)|catch\s*\(\s*(?:Exception|Throwable)\s+\$[a-zA-Z_]+\s*\)[\s\S]{0,150}?header)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:res\.setHeader\s*\(\s*['"]x-(?:telemetry-error|error|exception)['"][\s\S]{0,150}?(?:err\.name|err\.message|err\.constructor)|res\.header\s*\([\s\S]{0,120}?Padding|catch\s*\(\s*err\s*\)[\s\S]{0,150}?setHeader|response\.setHeader[\s\S]{0,120}?Crypto)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Response\.Headers\.(Add|Append|TryAddWithoutValidation).*X-(Telemetry-Error|Error|Exception).*?(ex\.GetType|ex\.Message)|Response\.Headers.*Padding|catch\s*\(\s*(Exception|CryptographicException).*Headers
```
{% endtab %}

{% tab title="Java" %}
```regexp
response\.addHeader\("X-(Telemetry-Error|Error|Exception)".*(e\.getClass|e\.getMessage)|HttpServletResponse.*addHeader|addHeader.*Padding|catch\s*\(\s*(Exception|BadPaddingException|GeneralSecurityException).*addHeader
```
{% endtab %}

{% tab title="PHP" %}
```regexp
header\(['"]X-(Telemetry-Error|Error|Exception).*?(Padding|Crypto|Decrypt)|header\(.*\$e->getMessage|catch\s*\(\s*(Exception|Throwable).*header
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
res\.setHeader\(['"]x-(telemetry-error|error|exception).*?(err\.name|err\.message)|setHeader.*Padding|catch\s*\(\s*err\s*\).*setHeader|setHeader.*Crypto
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class JweTelemetryMiddleware 
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next) 
    {
        var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
        
        if (!string.IsNullOrEmpty(token)) 
        {
            try 
            {
                var jweParts = token.Split('.');
                var iv = Base64UrlDecode(jweParts[2]);
                var ciphertext = Base64UrlDecode(jweParts[3]);
                var mac = Base64UrlDecode(jweParts[4]);

                // [1]
                // [2]
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                using var decryptor = aes.CreateDecryptor(_encryptionKey, iv);
                var plaintextBytes = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);

                // [3]
                var calculatedMac = ComputeHmac(plaintextBytes);
                if (!calculatedMac.SequenceEqual(mac)) throw new SecurityException("SignatureInvalidException");

                context.Items["Claims"] = Encoding.UTF8.GetString(plaintextBytes);
            }
            catch (Exception ex) 
            {
                // [4]
                context.Response.StatusCode = 401;
                context.Response.Headers.Add("X-Telemetry-Error", ex.GetType().Name);
                return;
            }
        }
        await next(context);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public class JweTelemetryFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String token = req.getHeader("Authorization");

        if (token != null && token.startsWith("Bearer ")) {
            try {
                String[] jweParts = token.substring(7).split("\\.");
                byte[] iv = Base64.getUrlDecoder().decode(jweParts[2]);
                byte[] ciphertext = Base64.getUrlDecoder().decode(jweParts[3]);
                byte[] mac = Base64.getUrlDecoder().decode(jweParts[4]);

                // [1]
                // [2]
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
                byte[] plaintextBytes = cipher.doFinal(ciphertext);

                // [3]
                byte[] calculatedMac = computeHmac(plaintextBytes);
                if (!MessageDigest.isEqual(calculatedMac, mac)) throw new SecurityException("SignatureInvalidException");

                req.setAttribute("Claims", new String(plaintextBytes));

            } catch (Exception e) {
                // [4]
                res.setStatus(401);
                res.addHeader("X-Telemetry-Error", e.getClass().getSimpleName());
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class JweTelemetryMiddleware 
{
    public function handle($request, Closure $next) 
    {
        $token = $request->bearerToken();

        if ($token) 
        {
            try {
                $jweParts = explode('.', $token);
                $iv = base64_decode(strtr($jweParts[2], '-_', '+/'));
                $ciphertext = base64_decode(strtr($jweParts[3], '-_', '+/'));
                $mac = base64_decode(strtr($jweParts[4], '-_', '+/'));

                // [1]
                // [2]
                $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', $this->encryptionKey, OPENSSL_RAW_DATA, $iv);
                if ($plaintext === false) throw new \RuntimeException("BadPaddingException");

                // [3]
                $calculatedMac = hash_hmac('sha256', $plaintext, $this->macKey, true);
                if (!hash_equals($calculatedMac, $mac)) throw new \Exception("SignatureInvalidException");

                $request->attributes->set('Claims', $plaintext);

            } catch (\Exception $e) {
                // [4]
                return response('Unauthorized', 401)->header('X-Telemetry-Error', (new \ReflectionClass($e))->getShortName());
            }
        }

        return $next($request);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class JweTelemetryMiddleware {
    static handle(req, res, next) {
        let authHeader = req.headers['authorization'];

        if (authHeader && authHeader.startsWith('Bearer ')) {
            try {
                let jweParts = authHeader.substring(7).split('.');
                let iv = Buffer.from(jweParts[2], 'base64');
                let ciphertext = Buffer.from(jweParts[3], 'base64');
                let mac = Buffer.from(jweParts[4], 'base64');

                // [1]
                // [2]
                let decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
                let plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

                // [3]
                let calculatedMac = crypto.createHmac('sha256', macKey).update(plaintext).digest();
                if (!crypto.timingSafeEqual(calculatedMac, mac)) throw new Error("SignatureInvalidException");

                req.claims = plaintext.toString('utf8');

            } catch (err) {
                // [4]
                let errorName = err.message.includes('bad decrypt') ? 'BadPaddingException' : err.message;
                res.set('X-Telemetry-Error', errorName);
                return res.status(401).send('Unauthorized');
            }
        }
        next();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The system extracts the raw binary components of the JSON Web Encryption (JWE) token, \[2] The developer built a custom parser, unaware of the strict operational hierarchy required by Authenticated Encryption. They pass the unverified ciphertext directly into the CBC decryptor, \[3] The architecture verifies the MAC _after_ the decryption succeeds. This violates the "Encrypt-then-MAC" paradigm entirely, exposing the block cipher to manipulation before its integrity is proven, \[4] The fatal observability optimization. To assist external partners in debugging their JWE generation logic, the gateway catches the resulting exception and reflects its exact class name back to the client via an HTTP header. This explicitly converts the internal cryptographic failure state into a public-facing API contract

```http
// 1. Attacker intercepts a valid JWE from a B2B partner.
// 2. Attacker modifies the ciphertext to execute the oracle attack.
GET /api/v1/partner/dashboard HTTP/1.1
Host: gateway.enterprise.tld
Authorization: Bearer eyJhbG...[TAMPERED_CIPHERTEXT]...[VALID_MAC]

// 3. The server attempts decryption, fails the PKCS#7 check, and returns the telemetry header.
HTTP/1.1 401 Unauthorized
X-Telemetry-Error: BadPaddingException
Content-Length: 12
Unauthorized
```

```http
// 4. Attacker successfully guesses the padding byte. The server decrypts the payload, 
// moves to the next line of code, fails the HMAC validation, and returns a different telemetry header.
HTTP/1.1 401 Unauthorized
X-Telemetry-Error: SignatureInvalidException
Content-Length: 12
Unauthorized
```
{% endstep %}

{% step %}
To support complex B2B identity federation, the enterprise implemented a custom JWE parser. To optimize Developer Experience (DX) and reduce support tickets, they attached the internal Java/C# exception names to the HTTP response headers. By ignoring the strict Encrypt-then-MAC order of operations, the developers exposed the AES-CBC decryptor to tampered payloads. The attacker manipulates the ciphertext blocks. When the padding is mathematically invalid, the API returns `X-Telemetry-Error: BadPaddingException`. When the attacker's fuzzing achieves valid padding, the code proceeds to the HMAC check, fails, and returns `X-Telemetry-Error: SignatureInvalidException`. This telemetry optimization provided a flawless, synchronous Padding Oracle, allowing the attacker to completely decrypt the sensitive identity claims embedded within the JWE token
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
