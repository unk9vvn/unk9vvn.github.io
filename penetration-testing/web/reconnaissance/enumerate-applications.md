# Enumerate Applications

## Check List

* [ ] Enumerate the applications within scope that exist on a web server.

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
gobuster dns --domain $WEBSITE \
             -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

#### [URLFinder](https://github.com/projectdiscovery/urlfinder)

```bash
urlfinder -d $WEBSITE
```

#### [RapidDNS](https://rapiddns.io/)

```bash
curl -s https://rapiddns.io/subdomain/${domain}?full=1 | \
grep -Eo '[a-zA-Z0–9.-]+\.[a-zA-Z]{2,}' | sort -u
```

#### [Shodan CLI](https://github.com/achillean/shodan-python)

{% hint style="info" %}
Favicon
{% endhint %}

```bash
domain="$1";curl -s https://$domain/favicon.ico | \
base64 | python3 -c 'import mmh3, sys;print(mmh3.hash(sys.stdin.buffer.read()))' | \
xargs -I{} shodan search http.favicon.hash:{} --fields hostnames | tr ";" "\n"
```

#### [Amass](https://github.com/owasp-amass/amass)

{% hint style="info" %}
Passive Scan
{% endhint %}

```bash
amass enum -passive -d $WEBSITE
```

{% hint style="info" %}
Active Scan
{% endhint %}

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

```bash
echo | \
openssl s_client -showcerts -servername $WEBSITE -connect $IP:443 2>/dev/null | \
openssl x509 -inform pem -noout -text
```

#### [AssetFinder](https://github.com/tomnomnom/assetfinder) & [HttpX](https://github.com/projectdiscovery/httpx)

```sh
assetfinder $WEBSITE | httpx --status-code --title
```

#### [SubFinder](https://github.com/projectdiscovery/subfinder)

{% hint style="info" %}
Favicon Hashes
{% endhint %}

```bash
subfinder -d $WEBSITE -all -recursive | httpx -favicon -j | \
jq -r .favicon | grep -v null | sort-u
```

{% hint style="info" %}
Subdomain Fuzzing
{% endhint %}

```bash
subfinder -d $WEBSITE -all -recursive -o /tmp/subdomains.txt
```

#### [Alterx](https://github.com/projectdiscovery/alterx)

{% hint style="info" %}
Subdomain New Gen
{% endhint %}

```bash
cat /tmp/subdomains.txt | alterx -o /tmp/gen-subdomains.txt
```

#### [Httpx-Toolkit](https://github.com/projectdiscovery/httpx)

{% hint style="info" %}
Resolve Live Subdomains
{% endhint %}

```bash
cat /tmp/gen-subdomains.txt | \
httpx -ports 80,443,8080,8000,8888,8082,8083 \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0" \
      > /tmp/alive-subdomains.txt
```

#### [Puredns](https://github.com/d3mondev/puredns)

{% hint style="info" %}
Resolve New Gen
{% endhint %}

```bash
puredns resolve /tmp/gen-subdomains.txt -r /tmp/resolve-subdomains.txt
```

#### [Katana](https://github.com/projectdiscovery/katana)

{% hint style="info" %}
Fetch URLs
{% endhint %}

```bash
katana -u /tmp/alive-subdomains.txt \
       -d 5 -ps \
       -pss waybackarchive,commoncrawl,alienvault \
       -kf -jc -fx \
       -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg \
       -o /tmp/all-urls.txt
```

#### [SubFinder ](https://github.com/projectdiscovery/subfinder)& [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)

{% hint style="info" %}
Recon and Resolve
{% endhint %}

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

{% hint style="info" %}
Dictionary
{% endhint %}

```bash
dirsearch -u $WEBSITE \
          -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

{% hint style="info" %}
Brute Force
{% endhint %}

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

{% hint style="info" %}
TCP Ports
{% endhint %}

```bash
nmap -sS -sV --mtu 5000 $WEBSITE
```

{% hint style="info" %}
UDP Ports
{% endhint %}

```bash
nmap -sU -sV --mtu 5000 $WEBSITE
```

#### [Netcat](https://nmap.org/ncat/)

{% hint style="info" %}
TCP Ports
{% endhint %}

```sh
nc -zv -w 1 $WEBSITE 1-65535
```

{% hint style="info" %}
UDP Ports
{% endhint %}

```sh
nc -zvu -w 1 $WEBSITE 1-65535
```

#### [Naabu](https://github.com/projectdiscovery/naabu)

```sh
naabu -host $TARGET -p $PORT
```

#### [Msscan](https://github.com/robertdavidgraham/masscan)

{% hint style="info" %}
Fast Scan TCP/UDP
{% endhint %}

```sh
TARGETS=$(dig +short A "$WEBSITE" | sed '/^\s*$/d' | awk -F. '{print $1"."$2"."$3".0/24"}' | sort -u | paste -s -d, -);
sudo masscan --range $TARGETS -p1-65535,U:1-65535 --rate=10000 --http-user-agent "Mozilla/5.0 (Windows NT10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0" -oG /tmp/massscan.txt
```

#### [Httpx](https://github.com/projectdiscovery/httpx)

{% hint style="info" %}
Find HTTP Services
{% endhint %}

```bash
cat /tmp/massscan.txt | grep tcp | \
awk ' {print $4,":",$3}' | tr -d ' ' | \
httpx -title -sc -cl
```

#### CIDR Discovery&#x20;

{% hint style="info" %}
ASN Discovery
{% endhint %}

```sh
whois -h whois.cymru.com $TARGET
```

```sh
curl -s https://api.bgpview.io/ip/$TARGET | \
jq -r ".data.prefixes[] | {prefix: .prefix, ASN: .asn.asn}"
```

{% hint style="info" %}
Nmap Script
{% endhint %}

```bash
nmap --script targets-asn --script-args targets-asn.asn=$ASN
```

### Virtual Hosts

{% hint style="info" %}
DNS Zone Transfer&#x20;
{% endhint %}

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

{% hint style="info" %}
DNS Inverse Queries&#x20;
{% endhint %}

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

{% hint style="info" %}
Combine with[ ShuffleDNS](https://github.com/projectdiscovery/shuffledns)
{% endhint %}

```sh
echo "1.1.1.1" > /tmp/resolver.txt
shuffledns -d $WEBSITE \
           -l /tmp/gen-sub-domains.txt \
           -mode resolve \
           -r /tmp/resolver.txt
```

{% hint style="info" %}
Web Service Discovery
{% endhint %}

```sh
httpx -silent -u $WEBSITE
```

1. Host: \[FUZZ]

```sh
ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt \
     -u $TARGET \
     -H "Host: FUZZ"
```

2. Host: \[FUZZ].$WEBSITE

```sh
ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt \
     -u $TARGET \
     -H "Host: FUZZ.$WEBSITE"
```

3. Host: \[FOUND-SUBDOMAINS]

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

1. Query DNS records of domains and subdomains to get IP

```sh
for domain in $(subfinder -d $WEBSITE -silent); do echo $domain | \
dnsx -a -silent -resp-only; done
```

2. Whois the IP addresses and extract the properties

```bash
whois $TARGET
```

3. Reverse Lookup on the properties

#### RapidDNS

{% hint style="info" %}
Reverse Lookup
{% endhint %}

```bash
domain="$WEBSITE"
curl -s "https://rapiddns.io/sameip/${domain}#result" \
  | pup 'table tr td:nth-child(2) text{}' \
  | sed '/^[[:space:]]*$/d' \
  | nl -ba
```

#### Query Ripe

{% hint style="info" %}
mnt-by field
{% endhint %}

```sh
whois -h whois.ripe.net -i mnt-by $COMPANY 
```

{% hint style="info" %}
person field
{% endhint %}

```sh
whois -h whois.ripe.net -- -i person $NAME 
```

{% hint style="info" %}
admin-c field
{% endhint %}

```sh
whois -h whois.ripe.net -- -i admin-c $NAME 
```

#### Query Arin

{% hint style="info" %}
Network address space (Net Handle) field
{% endhint %}

```sh
whois -h whois.arin.net -- 'n ! $NAME'
```

{% hint style="info" %}
OrgId field
{% endhint %}

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
