# Enumerate Applications

### Directory Fuzzing

#### DirB

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo dirb $WEBSITE/ -f
```

#### DirSearch

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo dirsearch -u $WEBSITE -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -e php,txt,cnf,conf
```

#### WFuzz

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo wfuzz -c -Z -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --sc 200 "$WEBSITE/FUZZ"
```

#### GoBuster

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u $WEBSITE -x php,txt,cnf,confb
```

#### FFUF

```bash
┌──(web㉿unk9vvn)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $WEBSITE/FUZZ -mc 200 -c -v
```

### Subdomain Fuzzing

#### DNSEnum

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo dnsenum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -w --noreverse $WEBSITE
```

#### DNSRecon

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo dnsrecon -d $WEBSITE -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
```

#### GoBuster

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo gobuster dns -d $WEBSITE -c -i -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

#### Amass

_passive scan_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo amass enum -passive -d $WEBSITE
```

_active scan_

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo amass enum -active -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -d $WEBSITE
```

#### Subfinder

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo subfinder -d $WEBSITE
```

## Non-standard Ports

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo nmap -sV -sT -Pn -p0-65535 $TARGET
```

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo nmap -sV -sU -p- -Pn $TARGET
```

### DNS Zone Transfers

#### Nslookup

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo nslookup -type=ns $WEBSITE
```

#### Dig

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo dig $WEBSITE NS +noall +answer
```

#### Host

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo host -t ns $WEBSITE
```

#### Nslookup

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo nslookup $WEBSITE $NS
```

#### Dig

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo dig @NS $WEBSITE
```

#### Host

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo host -l $WEBSITE $NS
```

### DNS Inverse Queries

#### Nslookup

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo nslookup $TARGET
```

#### Dig

```bash
┌──(web㉿unk9vvn)-[~]
└─$ sudo dig -x $TARGET
```

### Using search engines

[https://mxtoolbox.com](https://mxtoolbox.com)
