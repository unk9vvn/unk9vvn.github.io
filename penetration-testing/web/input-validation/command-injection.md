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

## Cheat Sheet
