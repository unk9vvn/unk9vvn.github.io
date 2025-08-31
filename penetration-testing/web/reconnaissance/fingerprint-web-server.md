# Fingerprint Web Server

## Check List

* [ ] Determine the version and type of running web server to enable further discovery of any known vulnerabilities.

## Cheat Sheet

### Banner Grabbing

#### [**Netcat**](https://sectools.org/tool/netcat/)

```shell
nc -v $WEBSITE 80
```

#### [Telnet](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/telnet)

```bash
telnet $WEBSITE 80
```

#### [Curl](https://curl.se/download.html)

```bash
curl -I $WEBSITE
```

#### [**Nmap**](https://nmap.org/)

```bash
nmap -sS -sV --mtu 5000 --script http-methods $WEBSITE
```

#### NetCraft

{% embed url="https://sitereport.netcraft.com/" %}

#### Dnsdumpster

{% embed url="https://dnsdumpster.com/" %}

#### [Censys](https://search.censys.io/)

Server Header

```bash
services.http.response.headers.server: "nginx"
```

SSL Certificate SHA-1 Fingerprint

```bash
services.tls.certificates.leaf_data.fingerprint_sha1: $HASH
```

SSL Certificate SHA-256 Fingerprint

```bash
services.tls.certificates.leaf_data.fingerprint_sha256: $HASH
```

Common Name (CN) in SSL Certificate

```bash
services.tls.certificates.leaf_data.subject.common_name: "$WEBSITE"
```

Operating System

```bash
services.http.response.headers: (key: "OS" and value.headers: "Linux")
```

Powered By Header

```bash
services.http.response.headers.x_powered_by: "PHP/7.4.9"
```

#### [WAFW00F](https://github.com/EnableSecurity/wafw00f)

```sh
wafw00f $WEBSITE
```

#### [WhatWaf](https://github.com/Ekultek/WhatWaf)

```sh
whatwaf -u $WEBSITE
```

#### [WhatWeb](https://github.com/urbanadventurer/WhatWeb)

```sh
whatweb $WEBSITE
```

#### [Sn1per](https://sn1persecurity.com/wordpress/)

```sh
sniper -t $WEBSITE
```

#### [Arachni](https://github.com/Arachni/arachni?tab=readme-ov-file)

```sh
arachni $WEBSITE
```

#### [Graphw00f](https://github.com/dolevf/graphw00f)

```sh
graphw00f -f -t $WEBSITE
```
