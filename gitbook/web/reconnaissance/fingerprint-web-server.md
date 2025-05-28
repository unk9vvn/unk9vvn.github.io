# Fingerprint Web Server

## Check List

* [ ] _Determine the version and type of running web server to enable further discovery of any known vulnerabilities._

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

_Server Header_

```bash
services.http.response.headers.server: "nginx"
```

_SSL Certificate SHA-1 Fingerprint_

```bash
services.tls.certificates.leaf_data.fingerprint_sha1: $HASH
```

_SSL Certificate SHA-256 Fingerprint_

```bash
services.tls.certificates.leaf_data.fingerprint_sha256: $HASH
```

_Common Name (CN) in SSL Certificate_

```bash
services.tls.certificates.leaf_data.subject.common_name: "$WEBSITE"
```

_Operating System_

```bash
services.http.response.headers: (key: "OS" and value.headers: "Linux")
```

_Powered By Header_

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
