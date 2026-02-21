# Physical Link Mapping

## Cheat Sheet

### Active Physical Link Mapping

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
ARP Scan
{% endhint %}

```bash
Nmap -sn -Pn -PR --send-eth $TARGET
```

#### [Netdiscover](https://github.com/netdiscover-scanner/netdiscover)

{% hint style="info" %}
Build a Layer-2 Topology
{% endhint %}

```bash
sudo netdiscover -r 192.168.1.0/24
```

#### [arp-scan](https://github.com/royhills/arp-scan)

{% hint style="info" %}
ARP scan on local network
{% endhint %}

```bash
sudo arp-scan --localnet
```

{% hint style="info" %}
ARP scan on a subnet using a specific interface
{% endhint %}

```bash
sudo arp-scan -I eth0 192.168.1.0/24
```

### Passive Physical Link Mapping

#### [Wireshark](https://www.wireshark.org/)

1\. Open Wireshark

2\. Capture traffic on a specific interface

3\. Filter layer 2 protocols: arp or lldp or cdp or stp or l2tp

#### [Netdiscover](https://github.com/netdiscover-scanner/netdiscover)

{% hint style="info" %}
Passive ARP Monitoring
{% endhint %}

```bash
sudo netdiscover -p
```

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Sniffs the network for incoming broadcast communication
{% endhint %}

```bash
nmap –script broadcast-listener
```

{% hint style="info" %}
Sniffs the network for incoming broadcast communication using a specific interface
{% endhint %}

```bash
nmap –script broadcast-listener -e eth0
```
