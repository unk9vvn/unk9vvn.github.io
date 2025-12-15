# Enumerate Applications

## Check List

* [ ] Enumerate the applications within scope that exist on a web server.

## Methodology

#### Different URL

{% stepper %}
{% step %}
Perform subdomain enumeration using a DNS enumeration tool with a comprehensive wordlist to identify subdomains, leveraging brute-force techniques to uncover hidden or non-indexed subdomains
{% endstep %}

{% step %}
Execute DNS reconnaissance to brute-force subdomains with a wordlist, focusing on resolving DNS records to map the target’s domain infrastructure and identify potential entry points
{% endstep %}

{% step %}
Use a DNS fuzzing tool with a wordlist to discover subdomains, validating their existence by resolving DNS queries and prioritizing active subdomains for further testing
{% endstep %}

{% step %}
Query the target domain with a URL discovery tool to extract subdomains and endpoints from public sources, identifying overlooked assets or misconfigured services
{% endstep %}

{% step %}
Fetch subdomain data from an online DNS service to enumerate subdomains, ensuring a unique and sorted list to streamline reconnaissance and reduce duplicate findings
{% endstep %}

{% step %}
Retrieve the target’s favicon, hash it, and search for matching favicon hashes across external services to identify hosts sharing the same favicon, uncovering related domains or assets
{% endstep %}

{% step %}
Conduct passive subdomain enumeration to collect subdomains from public sources without direct interaction, minimizing detection risk and gathering initial reconnaissance data
{% endstep %}

{% step %}
Perform active subdomain enumeration with brute-forcing and a wordlist to discover subdomains, validating them through DNS resolution to ensure accuracy and relevance
{% endstep %}

{% step %}
Enumerate IP addresses within a specified CIDR range to identify network assets, mapping organizational infrastructure for potential cloud or internal server discovery
{% endstep %}

{% step %}
Query assets by autonomous system number (ASN) to discover hosts within the target’s network provider, expanding reconnaissance to related infrastructure
{% endstep %}

{% step %}
Extract SSL certificate details by connecting to the target’s HTTPS service, analyzing certificate metadata like issuer, subject, or expiration to uncover subdomains or misconfigurations
{% endstep %}

{% step %}
Combine subdomain discovery with HTTP probing to identify live subdomains, capturing status codes and page titles to prioritize active web services for vulnerability testing
{% endstep %}

{% step %}
Generate favicon hashes from enumerated subdomains and filter unique hashes to identify shared web assets, linking related hosts or applications for deeper reconnaissance
{% endstep %}

{% step %}
Save enumerated subdomains to a file for further processing, ensuring a structured output for subsequent tools or manual analysis
{% endstep %}

{% step %}
Generate new subdomain permutations from an existing list to expand the list of potential subdomains, capturing variations that may reveal unlisted assets
{% endstep %}

{% step %}
Resolve a list of subdomains against common ports (e.g., 80, 443, 8080) with a custom user-agent to identify live web services, filtering for active hosts to focus testing efforts
{% endstep %}

{% step %}
Perform DNS resolution on permuted subdomains to validate their existence, ensuring only resolvable domains are included for further reconnaissance
{% endstep %}

{% step %}
Crawl live subdomains to fetch URLs, leveraging archival sources and filtering out non-relevant file types (e.g., images, CSS) to focus on endpoints like APIs or admin pages
{% endstep %}

{% step %}
Chain subdomain enumeration, DNS resolution, port scanning, and HTTP probing to build a comprehensive profile of live subdomains, ports, and web services, streamlining reconnaissance for vulnerability assessment
{% endstep %}
{% endstepper %}

***

#### Non-Standard Ports

{% stepper %}
{% step %}
Perform a stealth TCP port scan on the target to identify open ports and services, capturing version details to map potential vulnerabilities or misconfigured services
{% endstep %}

{% step %}
Conduct a UDP port scan on the target to discover open UDP services, focusing on protocols like DNS or SNMP that may expose sensitive information or attack vectors
{% endstep %}

{% step %}
Use a lightweight TCP port scan to quickly enumerate open ports across the full range (1-65535), identifying non-standard ports for further investigation
{% endstep %}

{% step %}
Execute a UDP port scan across the full port range to detect less common services, prioritizing those that may indicate misconfigured or exposed network applications
{% endstep %}

{% step %}
Perform a high-speed TCP and UDP scan on the target’s IP range derived from DNS resolution, using a custom user-agent to mimic legitimate traffic and capturing all open ports
{% endstep %}

{% step %}
Extract and process scan results to generate lists of IP-port pairs, unique IPs, and port ranges, organizing data for targeted follow-up scans or service enumeration
{% endstep %}

{% step %}
Conduct a refined port scan using a curated list of IPs and ports, integrating service version detection to identify specific software and potential CVEs
{% endstep %}

{% step %}
Probe identified open ports for HTTP services, capturing details like status codes, titles, server headers, favicon hashes, and redirect locations to profile web-based applications
{% endstep %}

{% step %}
Query the target’s IP to retrieve ASN and CIDR information via WHOIS lookup, mapping the organization’s network scope for broader reconnaissance
{% endstep %}

{% step %}
Fetch ASN and prefix details from an API to identify the target’s network infrastructure, uncovering related IP ranges or autonomous systems for expanded asset discovery
{% endstep %}

{% step %}
Use a specialized script to enumerate targets within a specified ASN, identifying additional hosts or services within the same network for comprehensive attack surface mapping
{% endstep %}
{% endstepper %}

***

#### Virtual Hosts

{% stepper %}
{% step %}
Query the target domain for name server (NS) records to identify authoritative DNS servers, establishing a foundation for further DNS-based reconnaissance
{% endstep %}

{% step %}
Enumerate DNS records (A, TXT, NS, MX) to map the target’s domain infrastructure, uncovering associated IPs, mail servers, or text-based configuration details
{% endstep %}

{% step %}
Attempt a DNS zone transfer from identified name servers to retrieve a complete list of domain records, exposing subdomains or internal hosts if misconfigured
{% endstep %}

{% step %}
Perform comprehensive DNS queries to gather all available record types, including A, NS, MX, and TXT, to build a detailed map of the target’s DNS structure
{% endstep %}

{% step %}
Conduct reverse DNS lookups using the target’s IP address to identify hostnames or domains associated with the IP, revealing potential shared hosting or related assets
{% endstep %}

{% step %}
Enumerate subdomains using a passive discovery tool, resolving them to IPs and saving results for further processing, minimizing active queries to avoid detection
{% endstep %}

{% step %}
Generate subdomain permutations from an existing list to expand the pool of potential subdomains, capturing variations that may point to unlisted assets
{% endstep %}

{% step %}
Resolve permuted subdomains using a custom resolver to validate their existence, filtering out non-resolvable entries to focus on live hosts
{% endstep %}

{% step %}
Probe the target domain for HTTP services to confirm the presence of active web servers, capturing basic response data like status codes for further analysis
{% endstep %}

{% step %}
Fuzz virtual hosts by testing a wordlist of common hostnames against the target, identifying non-standard or hidden virtual hosts on the same IP
{% endstep %}

{% step %}
Fuzz virtual hosts by appending the target domain to a wordlist of subdomains, detecting subdomain-specific virtual hosts that may not resolve via DNS
{% endstep %}

{% step %}
Use a list of discovered subdomains to fuzz virtual hosts, verifying if known subdomains are hosted on the same server and exposing misconfigured virtual hosts
{% endstep %}

{% step %}
Leverage online DNS lookup tools to cross-reference domain records, subdomains, and historical data, validating findings and uncovering additional assets
{% endstep %}

{% step %}
Perform reverse WHOIS lookups using email or registrant details to discover additional domains linked to the target organization, expanding the attack surface
{% endstep %}

{% step %}
Query external security databases with the target’s IP to gather insights on open ports, services, or known vulnerabilities, enriching reconnaissance with network context
{% endstep %}
{% endstepper %}

***

#### Reverse IP Service

{% stepper %}
{% step %}
Enumerate subdomains of the target website using a passive discovery tool and resolve their associated IP addresses, creating a list of IPs linked to the target’s infrastructure
{% endstep %}

{% step %}
Perform WHOIS lookups on identified IP addresses to extract properties such as registrant details, organization, or network ranges, mapping the target’s ownership and network structure
{% endstep %}

{% step %}
Conduct reverse DNS lookups on the resolved IPs using an online service to identify all domains and subdomains hosted on the same IP, uncovering shared hosting or related assets
{% endstep %}

{% step %}
Query RIPE database by maintainer (mnt-by) field with the target company’s identifier to discover IP ranges or assets managed by the organization, expanding the network scope
{% endstep %}

{% step %}
Search RIPE database by person field to find domains or IPs associated with a specific individual, revealing additional assets linked to the target’s administrators or contacts
{% endstep %}

{% step %}
Query RIPE database by admin-c field to identify IPs or domains tied to administrative contacts, uncovering infrastructure managed by specific personnel
{% endstep %}

{% step %}
Perform ARIN WHOIS lookups using network handle (Net Handle) to retrieve details about IP address allocations, identifying network ranges owned by the target organization
{% endstep %}

{% step %}
Query ARIN database by OrgId to discover all IP addresses or domains registered to the target organization, mapping their network footprint for reconnaissance
{% endstep %}

{% step %}
Use an intelligence tool to enumerate domains associated with the target organization, leveraging passive sources to identify related assets without direct interaction
{% endstep %}

{% step %}
Perform IP-based intelligence gathering within a specified CIDR range to uncover hosts, subdomains, or services within the target’s network, expanding the attack surface
{% endstep %}

{% step %}
Conduct active reconnaissance by querying assets within a specified autonomous system number (ASN), identifying live hosts and services tied to the target’s network provider
{% endstep %}
{% endstepper %}

***

#### Digital Certificate

{% stepper %}
{% step %}
Query a certificate transparency database to extract unique common names (CN) associated with the target domain, identifying subdomains and related hosts exposed through SSL certificates
{% endstep %}

{% step %}
Retrieve all name values from certificate transparency logs for the target domain, uncovering additional subdomains, wildcard entries, or alternate names linked to the target’s infrastructure
{% endstep %}

{% step %}
Search a network intelligence platform for certificates matching the target’s organization, extracting common names and associated domains to reveal hidden assets or misconfigured certificates
{% endstep %}

{% step %}
Enumerate subdomains using a GitHub reconnaissance tool with an API token, leveraging repository data to discover subdomains mentioned in code, commits, or configuration files
{% endstep %}

{% step %}
Fetch historical URLs for the target domain from an archival service, identifying past endpoints, APIs, or pages that may expose forgotten assets or sensitive functionality
{% endstep %}
{% endstepper %}

***

#### ASN-Based Infrastructure

{% stepper %}
{% step %}
Search the company name on [bgpview.io](https://bgpview.io/) to discover all associated ASNs
{% endstep %}

{% step %}
Run the following command to extract CIDRs and find live IPs within the discovered ASNs

```bash
whois -h whois.radb.net -- '-i origin $ASN' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq | mapcidr -silent | httpx
```
{% endstep %}

{% step %}
Review the list of discovered IPs and select targets that appear to be admin panels or internal tools
{% endstep %}

{% step %}
Use Wappalyzer or built-in browser tools to confirm the target is built with PHP
{% endstep %}

{% step %}
Perform directory and file fuzzing on the document root using ffuf
{% endstep %}

{% step %}
Identify the directory like `/Config/` returning `HTTP 401` Unauthorized
{% endstep %}

{% step %}
Access `/Config/` in the browser and test default credentials `admin:admin` → successful login
{% endstep %}
{% endstepper %}

***

## Cheat Sheet

### Different URL

#### Subdomain Fuzzing

#### [DNSEnum](https://github.com/SparrowOchon/dnsenum2)

```bash
dnsenum $WEBSITE \
        -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
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
curl -s https://rapiddns.io/subdomain/${WEBSITE}?full=1 | \
grep -Eo '[a-zA-Z0–9.-]+\.[a-zA-Z]{2,}' | sort -u
```

#### [Shodan CLI](https://github.com/achillean/shodan-python)

{% hint style="info" %}
Favicon
{% endhint %}

```bash
curl -s https://$WEBSITE/favicon.ico | \
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

#### [AssetFinder](https://github.com/tomnomnom/assetfinder) & [SubFinder](https://github.com/projectdiscovery/subfinder) & [HttpX](https://github.com/projectdiscovery/httpx)

{% hint style="info" %}
Resolve Live Subdomains
{% endhint %}

```sh
assetfinder $WEBSITE | subfinder -d $WEBSITE -all -recursive -o /tmp/subs.txt
httpx -l /tmp/subs.txt \
      -r 8.8.8.8 -fr -td -ip -ss -sc -cl -ct \
      -cname -method -cdn -probe -vhost -tls-grab -tls-probe -csp-probe -pipeline \
      -random-agent -auto-referer -favicon -jarm -title -location \
      -o /tmp/alive-subs.txt
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

#### [SubFinder ](https://github.com/projectdiscovery/subfinder)& [DNSx ](https://github.com/projectdiscovery/dnsx)& [Naabu ](https://github.com/projectdiscovery/naabu)& [HTTPx](https://github.com/projectdiscovery/httpx)

{% hint style="info" %}
Recon Subs and Ports and Web Services
{% endhint %}

```bash
subfinder -d $WEBSITE -all -recursive -o /tmp/subs.txt; \
dnsx -r 8.8.8.8 -l /tmp/subs.txt -ro | naabu -tp 1000 | httpx
```

#### Directory Fuzzing&#x20;

#### [DirB](https://dirb.sourceforge.net/)

```bash
dirb $WEBSITE
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

#### [TLDFinder](https://github.com/projectdiscovery/tldfinder)

{% hint style="info" %}
TLD Discovery
{% endhint %}

```bash
tldfinder -d $WEBSITE -dm domain -all
```

#### [FFUF](https://github.com/ffuf/ffuf)

{% hint style="info" %}
Directory Discovery
{% endhint %}

```bash
ffuf -u $WEBSITE/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
     -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15" \
     -c -ac -r
```

{% hint style="info" %}
API Discovery
{% endhint %}

```bash
ffuf -u $WEBSITE/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15" \
     -c -ac -r
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

#### [Msscan](https://github.com/robertdavidgraham/masscan)

{% hint style="info" %}
Fast Scan TCP/UDP
{% endhint %}

```sh
TARGETS=$(dig +short A "$WEBSITE" | sed '/^\s*$/d' | awk -F. '{print $1"."$2"."$3".0/24"}' | sort -u | paste -s -d, -);
sudo masscan --range $TARGETS -p1-65535,U:1-65535 --rate=10000 --http-user-agent "Mozilla/5.0 (Windows NT10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0" -oG /tmp/massscan.txt
```

#### [Naabu](https://github.com/projectdiscovery/naabu)

```sh
grep 'Host:' /tmp/massscan.txt \
  | sed -E 's/.*Host: ([0-9.]+) .*Ports: (.*)/\1 \2/' \
  | while read ip ports; do
      echo "$ports" | tr ',' '\n' | awk -v ip="$ip" -F'/' '{print ip ":" $1}'
    done \
  | sort -u > /tmp/masscan-ipports.txt

awk -F: '{print $1}' /tmp/masscan-ipports.txt | sort -u > /tmp/masscan-ips.txt
awk -F: '{print $2}' /tmp/masscan-ipports.txt | sort -n -u | paste -s -d, - > /tmp/masscan-ports.csv
sudo naabu -list /tmp/masscan-ips.txt -p $(cat /tmp/masscan-ports.csv) -rate 1000 -nmap-cli 'nmap -sV --mtu 5000' -o /tmp/naabu-raw.txt
cat /tmp/naabu-raw.txt | sed -n 's/^\([0-9.]*:[0-9]*\).*$/\1/p' | sort -u > /tmp/naabu-ports.txt
```

#### [Httpx](https://github.com/projectdiscovery/httpx)

{% hint style="info" %}
Find HTTP Services
{% endhint %}

```bash
cat /tmp/naabu-ports.txt \
  | httpx --follow-redirects \
      -ports -sc -td -auto-referer -title -favicon -server -location -ip \
      -o /tmp/httpx-results.txt
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
curl -s "https://crt.sh/?q=%25.$WEBSITE&output=json" | \
jq -r ".[].common_name" | sort -u
```

```bash
curl -s "https://crt.sh/?q=%25.$WEBSITE&output=json" | \
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
