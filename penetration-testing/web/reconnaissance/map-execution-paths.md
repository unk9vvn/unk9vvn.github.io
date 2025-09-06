# Map Execution Paths

## Check List&#x20;

* [ ] Map the target application and understand the principal workflows.

## Cheat Sheet

### Path

#### Burp Suite

{% hint style="info" %}
Mapping a Website with Burp Suite
{% endhint %}

{% hint style="info" %}
Burp Suite > Target > Site map > Right Click on One Domain > Engagement tools > Analyze Target
{% endhint %}

{% hint style="info" %}
Crawling a Website with Burp Suite
{% endhint %}

{% hint style="info" %}
Burp Suite > ِDashbord > New Scan > Use Web app Scan > Use a preset scan mode > Analyze Target in Summary
{% endhint %}

#### [FeroxBuster](https://www.google.com/url?sa=t\&source=web\&rct=j\&opi=89978449\&url=https://github.com/epi052/feroxbuster\&ved=2ahUKEwiU3pPJrqGJAxV1Q6QEHe2kNVcQFnoECBkQAQ\&usg=AOvVaw3nTxxRaPVVZSoVDW5LKrjt)

```bash
feroxbuster --url $WEBSITE -C 200 -x php,aspx,jsp
```

#### [DirSearch](https://www.google.com/url?sa=t\&source=web\&rct=j\&opi=89978449\&url=https://github.com/maurosoria/dirsearch\&ved=2ahUKEwjJ3-LUrqGJAxWBVqQEHcsEKvkQFnoECAoQAQ\&usg=AOvVaw09pWqpI-PVNuVwz_h5SCtz)

```bash
dirsearch -u $WEBSITE \
          -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
          -e php,cgi,htm,html,shtm,sql.gz,sql.zip,shtml,lock,js,jar,txt,bak,inc,smp,csv,cache,zip,old,conf,config,backup,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,wasl,tar.gz,tar.bz2,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5
```

### Data Flow&#x20;

#### Burp Suite

{% hint style="info" %}
Burp Suite > Target > Site map > Analyze Three Domain&#x20;
{% endhint %}

### Race

#### Burp Suite

{% hint style="info" %}
Burp Suite > Target > Right Click on One Domain > Extensions > Turbo intruder > send to turbo intruder > Add to WordList path in line "for word in open('/usr/share/dict/words')" > Attack
{% endhint %}
