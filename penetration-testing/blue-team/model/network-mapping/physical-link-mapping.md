# Physical Link Mapping

## Check List

* [ ] Inventory all network devices, ports, transceivers, patch panels, and cable identifiers.&#x20;
* [ ] Inspect and document physical links between switches, routers, firewalls, servers, and endpoints.&#x20;
* [ ] Record cable type, connection endpoints, interface identifiers, and link status.&#x20;
* [ ] Use LLDP/CDP or authorized active probing to validate device-to-device connectivity.&#x20;
* [ ] Reconcile observed links with switch configuration, interface descriptions, and network documentation.&#x20;
* [ ] Identify undocumented, redundant, disconnected, and unauthorized physical connections.&#x20;
* [ ] Verify link paths across racks, rooms, floors, buildings, and physical security zones.&#x20;
* [ ] Maintain the physical topology map and update it after infrastructure changes.&#x20;
* [ ] Use manual inspection when automated discovery cannot reliably determine physical connectivity.

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

#### [tshark](https://tshark.dev/)

{% hint style="info" %}
Passive layer-2 packet capture
{% endhint %}

```bash
sudo tshark -i eth0 \
    -Y "arp or lldp or cdp or stp or l2tp" \
    > capture-layer2.pcap
```

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
