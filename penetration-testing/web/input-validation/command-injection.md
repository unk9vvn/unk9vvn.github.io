# Command Injection

## Check List

## Methodology

### [Black Box](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

#### Reflected Command Injection In an Embedded Cloud Shell

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

#### XML field

{% stepper %}
{% step %}
When you identify an XML-based API endpoint (processing user data like number, email, or mobile), test fields such as `<Number>` for Blind OS Command Injection using time-delay payloads to confirm execution without visible output. Focus on common XML processing endpoints across enterprise or government web services
{% endstep %}

{% step %}
Capture a legitimate XML request using Burp Suite when submitting personal data through the web service (profile update, form submission)
{% endstep %}

{% step %}
Locate the target field (`<Number>1234567890123</Number>`) that accepts user input and is likely passed to a backend shell command
{% endstep %}

{% step %}
Send a baseline request with normal input and record the average response time (\~56 ms)
{% endstep %}

{% step %}
Inject a cross-platform time-delay payload into the field using command chaining to force a `~10–15` second delay:

```bash
<Number>|ping -n 11 127.0.0.1||ping -c 11 127.0.0.1</Number>
```
{% endstep %}

{% step %}
Measure the response time; if it increases significantly (`~11,876 ms`), it confirms blind command execution
{% endstep %}
{% endstepper %}

***

#### Language Parameter

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

```
{${system("cat+/etc/passwd"J)}}
```
{% endstep %}

{% step %}
Send the request and then check whether the server's response shows the sensitive file content
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet
