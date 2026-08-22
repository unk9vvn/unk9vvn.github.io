# Operational Dependency Mapping

## Check List

* [ ] Identify organizational activities and their business objectives.
* [ ] Map each activity to its responsible people, systems, applications, and services.
* [ ] Document dependencies between higher-level and lower-level activities.
* [ ] Model upstream and downstream dependencies across organizational layers.
* [ ] Classify dependencies by criticality, type, and required availability.
* [ ] Identify single points of failure and concentrated dependencies.
* [ ] Validate dependency relationships with process owners and technical evidence.
* [ ] Record dependency owners, interfaces, assumptions, and recovery requirements.
* [ ] Assess the impact of performer or service failure on dependent activities.
* [ ] Review and update the dependency model after organizational or technical changes.

## Cheat Sheet

#### [Kubernetes](https://kubernetes.io/)

{% hint style="info" %}
Mapping Service Providers and Endpoints
{% endhint %}

```bash
kubectl get endpointslices -A -o wide
```

{% hint style="info" %}
Identity and Permission Mapping
{% endhint %}

```bash
kubectl get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SERVICE_ACCOUNT:.spec.serviceAccountName
```

{% hint style="info" %}
Ingress and Traffic Flow Mapping
{% endhint %}

```bash
kubectl get ingress -A && kubectl get networkpolicies -A
```

{% hint style="info" %}
Detailed Resource Dependency
{% endhint %}

```bash
kubectl get pod <pod-name> -o json | jq '.spec.volumes, .spec.containers[].envFrom'
```

#### [Zabbix](https://www.zabbix.com/index)

{% hint style="info" %}
Business Service Mapping (BSM) Extraction
{% endhint %}

```bash
curl -s -X POST -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0","method":"service.get","params":{"output":["name","status"],"selectChildren":["name"],"selectParents":["name"]},"auth":"$TOKEN","id":1}' $URL/api_jsonrpc.php
```

{% hint style="info" %}
Trigger Dependency Discovery
{% endhint %}

```bash
curl -s -X POST -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0","method":"trigger.get","params":{"output":["description"],"selectDependencies":["description"]},"auth":"$TOKEN","id":1}' $URL/api_jsonrpc.php
```

{% hint style="info" %}
Performer Inventory and Interface Mapping
{% endhint %}

```bash
curl -s -X POST -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0","method":"host.get","params":{"output":["host"],"selectInterfaces":["ip"],"selectParentTemplates":["name"]},"auth":"$TOKEN","id":1}' $URL/api_jsonrpc.php
```

### Cisco Products

{% hint style="info" %}
Neighbor Discovery (LLDP/CDP)
{% endhint %}

```bash
show cdp neighbors detail
show lldp neighbors detail
```

{% hint style="info" %}
Layer 2 Mapping
{% endhint %}

```bash
show ip arp
```

{% hint style="info" %}
Layer 3 Mapping
{% endhint %}

```bash
show mac address-table
```

{% hint style="info" %}
VLAN and Trunk Dependency
{% endhint %}

```bash
show interfaces trunk
show vlan brief
```
