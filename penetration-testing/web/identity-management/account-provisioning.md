# Account Provisioning

## Check List

* [ ] Verify which accounts may provision other accounts and of what type.

## Cheat Sheet

### Manual Create CSRF

#### [XSRFProbe](https://github.com/0xInfection/XSRFProbe)

{% hint style="info" %}
Non-Authenticated Endpoint
{% endhint %}

```bash
xsrfprobe -u https://$WEBSITE/profile/update -v
```

{% hint style="info" %}
Authenticated Endpoint
{% endhint %}

```bash
xsrfprobe -u https://$WEBSITE/profile/update -v -c "$COOKIE"
```

#### CSRFShark

{% embed url="https://csrfshark.github.io/app/" %}

### Auto Create CSRF

#### [Katana ](https://github.com/projectdiscovery/katana)& [FFUF ](https://github.com/ffuf/ffuf)& [XSRFprobe](https://github.com/0xInfection/XSRFProbe)

{% hint style="info" %}
Create Script
{% endhint %}

<pre class="language-bash"><code class="lang-bash"><strong>#!/bin/bash
</strong>
WEBSITE=$1
COOKIE=$2

if [ -z "$WEBSITE" ]; then
    echo "Usage: $0 https://example.com [cookie]"
    exit 1
fi

echo "[*] Running katana for passive endpoint discovery..."
katana -u "$WEBSITE" -jc -d 2 -o /tmp/katana_raw.txt

echo "[*] Running ffuf for fuzzing endpoint parameters..."
ffuf -u "$WEBSITE/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -of csv -o /tmp/ffuf_results.csv > /dev/null

cut -d ',' -f1 /tmp/ffuf_results.csv | grep "$WEBSITE" > /tmp/ffuf_raw.txt

cat /tmp/katana_raw.txt /tmp/ffuf_raw.txt | sort -u > /tmp/all_endpoints.txt

echo "[*] Checking endpoints for CSRF using xsrfprobe..."

mkdir -p /tmp/results
> /tmp/results/vulnerable_csrf.txt

while read endpoint; do
    echo "[*] Testing: $endpoint"

    if [ -n "$COOKIE" ]; then
        xsrfprobe -u "$endpoint" -c "$COOKIE" --random-agent --malicious --crawl -o /tmp/results/report.html
    else
        xsrfprobe -u "$endpoint" --random-agent --malicious --crawl -o /tmp/results/report.html
    fi

    if grep -q "PoC generated" /tmp/results/report.html; then
        echo "[+] Potential CSRF at: $endpoint"
        echo "$endpoint" >> /tmp/results/vulnerable_csrf.txt
    else
        echo "[-] Not vulnerable: $endpoint"
    fi
done &#x3C; /tmp/all_endpoints.txt

echo
echo "✅ CSRF Scan Complete."
echo "📄 Vulnerable endpoints saved in: /tmp/results/vulnerable_csrf.txt"
</code></pre>

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo nano csrf-hunter.sh;sudo ./csrf-hunter.sh $WEBSITE
```
