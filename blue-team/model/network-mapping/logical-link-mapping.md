# Logical Link Mapping

## Cheat Sheet

### Active Logical Link Mapping

### Map Layer-3

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

### TCP

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
TCP SYN Ping
{% endhint %}

```bash
nmap -sn -PS $TARGET
```

{% hint style="info" %}
TCP ACK Ping
{% endhint %}

```bash
nmap -sn -PA $TARGET
```

### UDP

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
UDP Ping
{% endhint %}

```bash
nmap -sn -PU $TARGET
```

### ICMP

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
ICMP Ping using subnet
{% endhint %}

```bash
nmap -sn -PE -PP -PM 192.168.1.0/24 
```

#### Ping

{% hint style="info" %}
Ping for live host
{% endhint %}

```bash
ping $TARGET
```

### DHCP

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Discover DHCP IPv4 servers
{% endhint %}

```bash
sudo nmap –script broadcast-dhcp-discover
```

{% hint style="info" %}
Discover DHCP IPv6 servers
{% endhint %}

```bash
sudo nmap –script broadcast-dhcp6-discover
```

### EIGRP

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Network discovery and routing information gathering through EIGRP
{% endhint %}

```bash
nmap --script=broadcast-eigrp-discovery  $TARGET
```

{% hint style="info" %}
Network discovery and routing information gathering through EIGRP using a specific interface
{% endhint %}

```bash
nmap --script=broadcast-eigrp-discovery  $TARGET -e wlan0
```

### IGMP

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Discover targets with IGMP Multicast membership
{% endhint %}

```bash
nmap --script broadcast-igmp-discovery
```

{% hint style="info" %}
Discover targets with IGMP Multicast membership using a specific interface
{% endhint %}

```bash
nmap --script broadcast-igmp-discovery -e wlan0
```

### OSPF

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Discover OSPF IPv4 networks
{% endhint %}

```bash
nmap –script=broadcast-ospf2-discover
```

{% hint style="info" %}
Discover OSPF IPv4 networks using a specific interface
{% endhint %}

```bash
nmap --script=broadcast-ospf2-discover -e wlan0
```

### PPPoE

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Discover PPPoE servers
{% endhint %}

```bash
nmap --script broadcast-pppoe-discover
```

### RIPv2

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Discover host and routing information from devices running RIPv2
{% endhint %}

```bash
nmap --script broadcast-rip-discover
```

### Traceroute

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

### [Wireshark](https://www.wireshark.org/download.html)

1. Open Wireshark
2. Capture traffic on a specific interface
3. Filter layer 3 protocols: dhcp or icmp or igmp or ospf or bgp or eigrp or rip or glbp or hsrp or vrrp
