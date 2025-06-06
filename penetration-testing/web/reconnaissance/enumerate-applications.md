# Enumerate Applications

## Check List

* [ ] _Enumerate the applications within scope that exist on a web server._

## Cheat Sheet

### Different URL

#### Subdomain Fuzzing

#### [DNSEnum](https://github.com/SparrowOchon/dnsenum2)

```bash
dnsenum $WEBSITE -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

#### [DNSRecon](https://github.com/darkoperator/dnsrecon)

```bash
dnsrecon -d $WEBSITE \
         -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
         -t brt
```

#### [GoBuster](https://github.com/OJ/gobuster)

```bash
gobuster dns --wildcard \
             -d $WEBSITE \
             -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

#### [URLFinder](https://github.com/projectdiscovery/urlfinder)

```bash
urlfinder -d $WEBSITE
```

#### [Amass](https://github.com/owasp-amass/amass)

_Passive Scan_

<pre class="language-bash"><code class="lang-bash"><strong>amass enum -passive -d $WEBSITE
</strong></code></pre>

_Active Scan_

```bash
amass enum -active \
           -brute \
           -d $WEBSITE \
           -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

```sh
amass intel -ip -cidr $TARGET
```

```sh
amass intel -active -asn $ASN
```

#### [OpenSSL](https://github.com/openssl/openssl)

<pre class="language-go"><code class="lang-go"><strong>echo | \
</strong><strong>openssl s_client -showcerts -servername $WEBSITE -connect $IP:443 2>/dev/null | \
</strong><strong>openssl x509 -inform pem -noout -text
</strong></code></pre>

#### [AssetFinder](https://github.com/tomnomnom/assetfinder) & [HttpX](https://github.com/projectdiscovery/httpx)

```sh
assetfinder $WEBSITE | httpx --status-code --title
```

#### [SubFinder](https://github.com/projectdiscovery/subfinder)

_Favicon Hashes_

```bash
subfinder -d $WEBSITE -all -recursive | httpx -favicon -j | \
jq -r .favicon | grep -v null | sort-u
```

_Subdomain Fuzzing_

```bash
subfinder -d $WEBSITE -all -recursive -o /tmp/subdomains.txt
```

#### [Alterx](https://github.com/projectdiscovery/alterx)

_Subdomain New Gen_

```bash
cat /tmp/subdomains.txt | alterx -o /tmp/gen-subdomains.txt
```

#### [Httpx-Toolkit](https://github.com/projectdiscovery/httpx)

_Resolve live subdomains_

```bash
cat /tmp/gen-subdomains.txt | \
httpx-toolkit -ports 80,443,8080,8000,8888,8082,8083 \
              -threads 200 > /tmp/alive-subdomains.txt
```

#### [Puredns](https://github.com/d3mondev/puredns)

_Resolve New Gen_

```bash
puredns resolve /tmp/gen-subdomains.txt -r /tmp/resolve-subdomains.txt
```

#### [Katana](https://github.com/projectdiscovery/katana)

_Fetch URLs_

```bash
katana -u /tmp/alive-subdomains.txt \
       -d 5 -ps \
       -pss waybackarchive,commoncrawl,alienvault \
       -kf -jc -fx \
       -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg \
       -o /tmp/all-urls.txt
```

#### [SubFinder ](https://github.com/projectdiscovery/subfinder)& [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)

_Recon and Resolve_

```bash
echo "1.1.1.1" > /tmp/resolvers.txt
subfinder -d $WEBSITE -all -recursive | \
shuffledns -d $WEBSITE -r /tmp/resolvers.txt -mode resolve
```

#### Directory Fuzzing&#x20;

#### [DirB](https://dirb.sourceforge.net/)

```bash
dirb $WEBSITE /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

#### [DirSearch](https://github.com/maurosoria/dirsearch)

_Dictionary_

<pre class="language-bash"><code class="lang-bash"><strong>dirsearch -u $WEBSITE \
</strong><strong>          -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
</strong></code></pre>

_Brute Force_

```bash
dirsearch -u $WEBSITE \
          -e php,cgi,htm,html,shtm,sql.gz,sql.zip,shtml,lock,js,jar,txt,bak,inc,smp,csv,cache,zip,old,conf,config,backup,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,wasl,tar.gz,tar.bz2,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 \
          --random-agent \
          --deep-recursive \
          --exclude-status=404 \
          --follow-redirects \
          --delay=0.1
```

#### [WFuzz](https://github.com/xmendez/wfuzz)

```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
      --sc 200 "$WEBSITE/FUZZ"
```

#### [GoBuster](https://github.com/OJ/gobuster)

```bash
gobuster dir -u $WEBSITE \
             -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

#### [Feroxbuster](https://github.com/epi052/feroxbuster)

```sh
feroxbuster --url $WEBSITE -C 200
```

#### [FFUF](https://github.com/ffuf/ffuf) & [Katana](https://github.com/projectdiscovery/katana)

```bash
ffuf -u $WEBSITE/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

### Non-Standard Ports

#### Port Scans

#### [Nmap](https://nmap.org/)

_TCP Ports_

```bash
nmap -sS -sV --mtu 5000 $WEBSITE
```

_UDP Ports_

```bash
nmap -sU -sV --mtu 5000 $WEBSITE
```

#### [Netcat](https://nmap.org/ncat/)

_TCP Ports_

```sh
nc -zv -w 1 $WEBSITE 1-65535
```

_UDP Ports_

```sh
nc -zvu -w 1 $WEBSITE 1-65535
```

#### [Naabu](https://github.com/projectdiscovery/naabu)

```sh
naabu -host $TARGET -p $PORT
```

#### [Msscan](https://github.com/robertdavidgraham/masscan)

```sh
masscan $TARGET -p1-1000 --rate 1000
```

#### CIDR Discovery&#x20;

_ASN Discovery_

```sh
whois -h whois.cymru.com $TARGET
```

```sh
curl -s https://api.bgpview.io/ip/$TARGET | \
jq -r ".data.prefixes[] | {prefix: .prefix, ASN: .asn.asn}"
```

### Virtual Hosts

_DNS Zone Transfer_&#x20;

#### [Nslookup](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup)

```bash
nslookup -type=ns $WEBSITE
```

#### [Dig](https://github.com/polarityio/dig)

```bash
dig $WEBSITE NS +noall +answer; \
dig {a|txt|ns|mx} $WEBSITE; \
dig AXRF @ns1.$WEBSITE $WEBSTITE; \
dig @$NS $WEBSITE
```

#### Host

```bash
host -t ns $WEBSITE; \
host -t {a|txt|ns|mx} $WEBSITE; \
host -a $WEBSITE; \
host -C $WEBSITE; \
host -R 3 $WEBSITE
```

#### [GoBuster](https://github.com/OJ/gobuster)

```bash
gobuster vhost ‐u $WEBSITE \
               -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
               --append-domain
```

_DNS Inverse Queries_&#x20;

#### [Dig](https://github.com/polarityio/dig)

```bash
dig -x $IP
```

#### [DNSx](https://github.com/projectdiscovery/dnsx)

```bash
subfinder -silent -d $WEBSITE | dnsx -silent > /tmp/sub-domains.txt
```

#### [DNSGen](https://github.com/AlephNullSK/dnsgen)

```bash
dnsgen /tmp/sub-domains.txt > /tmp/gen-sub-domains.txt
```

_Combine with_[ _ShuffleDNS_](https://github.com/projectdiscovery/shuffledns)

```sh
echo "1.1.1.1" > /tmp/resolver.txt
shuffledns -d $WEBSITE \
           -l /tmp/gen-sub-domains.txt \
           -mode resolve \
           -r /tmp/resolver.txt
```

_Web Service Discovery_

```sh
httpx -silent -u $WEBSITE
```

1. _Host: \[FUZZ]_

```sh
ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt \
     -u $TARGET \
     -H "Host: FUZZ"
```

2. _Host: \[FUZZ].$WEBSITE_

```sh
ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt \
     -u $TARGET \
     -H "Host: FUZZ.$WEBSITE"
```

3. _Host: \[FOUND-SUBDOMAINS]_

```sh
ffuf -w /tmp/gen-sub-domains.txt -u $TARGET -H "Host: FUZZ"
```

#### Web Based DNS Search

#### **ViewDNS**

{% embed url="https://viewdns.info/" %}

#### **YouGetSignal**

{% embed url="https://www.yougetsignal.com/" %}

#### **Website Informer**

{% embed url="https://website.informer.com/" %}

#### **Reverse Whois**

{% embed url="https://www.reversewhois.io/" %}

#### **Whoxy**

{% embed url="https://www.whoxy.com/" %}

#### Security Insights

{% embed url="https://internetdb.shodan.io/$IP" %}

### Reverse IP Service&#x20;

1. _Query DNS records of domains and subdomains to get IP_

```sh
for domain in $(subfinder -d $WEBSITE -silent); do echo $domain | \
dnsx -a -silent -resp-only; done
```

2. _Whois the IP addresses and extract the properties_

```bash
whois $TARGET
```

3. _Reverse Lookup on the properties_

#### Query Ripe

_mnt-by field_

```sh
whois -h whois.ripe.net -i mnt-by $COMPANY 
```

_person field_

```sh
whois -h whois.ripe.net -- -i person $NAME 
```

_admin-c field_

```sh
whois -h whois.ripe.net -- -i admin-c $NAME 
```

#### Query Arin

_Network address space (Net Handle) field_

```sh
whois -h whois.arin.net -- 'n ! $NAME'
```

_OrgId field_

```sh
whois -h whois.arin.net -- 'o ! $NAME'
```

#### [Amass](https://github.com/owasp-amass/amass)

```sh
amass intel -org $ORG
```

```sh
amass intel -ip -cidr $TARGET
```

```sh
amass intel -active -asn $ASN
```

### Digital Certificate&#x20;

#### [Crt](https://crt.sh/)

```bash
curl -s "https://crt.sh/?q=$WEBSITE&output=json" | \
jq -r ".[].common_name" | sort -u
```

```bash
curl -s "https://crt.sh/?q=$WEBSITE&output=json" | \
jq -r ".[].name_value" | sort -u
```

#### [Censys](https://search.censys.io)

```bash
curl -X 'POST' 'https://search.censys.io/api/v2/certificates/search' -H 'Authorization: Basic API_SECRET' -H "content-type: application/json" --data '{"q":"parsed.subject.organization: Google"}' | \
jq -r '.result.hits[] | (.parsed.subject_dn | capture("CN=(?<cn>[^,]+)") | .cn), (.names | if type=="array" and (.[0] | type) == "array" then .[][] else .[] end)'
```

#### [GitHub](https://github.com)

```bash
github-subdomains -d $WEBSITE -t $TOKEN
```

#### [waybackurls](https://github.com/tomnomnom/waybackurls)

```bash
waybackurls $WEBSITE
```
