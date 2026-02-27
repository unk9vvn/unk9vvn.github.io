# Logical Link Mapping

## Cheat Sheet

### Active Logical Link Mapping

#### Map Layer-3

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Map Layer-3 Paths using subnet
{% endhint %}

```bash
nmap -sn --traceroute 192.168.1.0/24
```

{% hint style="info" %}
Detect Firewall Boundaries using subnet
{% endhint %}

```bash
nmap -sS -Pn 192.168.1.0/24
```

#### Ping Scan

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
TCP SYN & ACK & UDP & ICMP Ping
{% endhint %}

```bash
nmap -sn -PS -PA -PU -PE -PP -PM $TARGET
```

#### Ping

{% hint style="info" %}
Ping for live host
{% endhint %}

```bash
ping $TARGET
```

#### Discovery

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Discover DHCP & IGMP & OSPF & PPPoE & RIPv2
{% endhint %}

```bash
sudo nmap \
    --script=broadcast-dhcp-discover,broadcast-dhcp6-discover,broadcast-igmp-discovery,broadcast-ospf2-discover,broadcast-pppoe-discover,broadcast-rip-discover
```

{% hint style="info" %}
Network discovery and routing information gathering through EIGRP
{% endhint %}

```bash
nmap --script=broadcast-eigrp-discovery  $TARGET
```

#### Traceroute

#### [traceroute](https://www.kali.org/tools/traceroute/)

{% hint style="info" %}
Basic Traceroute
{% endhint %}

```bash
traceroute 192.168.10.10
```

{% hint style="info" %}
ICMP-Based (Linux default)
{% endhint %}

```bash
traceroute -I $TARGET
```

{% hint style="info" %}
TCP Traceroute (Firewall-aware)
{% endhint %}

```bash
traceroute -T -p 443 $TARGET
```

#### [mtr](https://github.com/traviscross/mtr)

{% hint style="info" %}
Using MTR for Real-Time Path Discovery
{% endhint %}

```bash
mtr $TARGET
```



### Passive Logical Link Mapping

#### [Wireshark](https://www.wireshark.org/download.html)

1. Open Wireshark
2. Capture traffic on a specific interface
3. Filter layer 3 protocols: dhcp or icmp or igmp or ospf or bgp or eigrp or rip or glbp or hsrp or vrrp

#### [tshark](https://tshark.dev/)

{% hint style="info" %}
Passive layer-3 packet capture
{% endhint %}

```bash
sudo tshark -i eth0 \
    -Y "dhcp or icmp or igmp or ospf or bgp or eigrp or rip or glbp or hsrp or vrrp" \
    > capture.txt
```
