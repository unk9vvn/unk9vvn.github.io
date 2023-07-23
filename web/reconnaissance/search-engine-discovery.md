# Search Engine Discovery

## Check List

* [ ] _Identify what sensitive design and configuration information of the application, system, or organization is exposed directly (on the organization’s website) or indirectly (via third-party services)._

## Cheat Sheet

### Google Hacking

Here are some examples of Dorks used in the Google search engine:

```bash
cache:$WEBSITE
site:$WEBSITE intitle:"ورود" | intext:"ورود"
site:$WEBSITE inurl:login OR inurl:secure OR inurl:admin
site:$WEBSITE ext:doc | ext:docx | ext:xls | ext:xlsx | ext:pdf
site:$WEBSITE filetype:bak inurl:php "mysql_connect"
site:$WEBSITE inurl:aspx | inurl:php | inurl:xml
site:*.$WEBSITE site:help.$WEBSITE
```

### Shodan

Here are some examples of search keywords used in the Shodan search engine:

```bash
"Schneider Electric" port:"502"
"Schneider Electric" port:"502" country:"IL"
country:"IR" os:"2008 R2"
Country:"US" Java RMI org:"Amazon.com"
Country:"IR" product:"OpenSSH"
device:webcam
apache after:22/02/2020 before:14/3/2021
geo:"56.913055,118.250862"
server: nginx
server: cisco-ios
ssl.cert.issuer.cn:example.com ssl.cert.subject.cn:example.com
ssl.cert.expired:true
ssl.cert.subject.cn:example.com
```

### GitHub

Using GitHub we can find sensitive infos.

```bash
filename:WebServers.xml 
filename:.bash_history 
filename:secrets.yml password 
path:sites databases password 
filename:passwd path:etc 
filename:config.php dbpasswd 
shodan_api_key language:python 
filename:shadow path:etc 
filename:wp-config.php 
extension:sql mysql dump 
filename:credentials aws_access_key_id
language:python username
language:php username
language:sql username
language:html password
language:perl password
language:shell username
language:java api
HOMEBREW_GITHUB_API_TOKEN language:shell
api_key
"api keys"
authorization_bearer:
oauth
auth
authentication
client_secret
api_token:
"api token"
client_id
password
user_password
user_pass
passcode
client_secret
secret
password hash
OTP
user auth
user:name
org:name
in:login
in:name
fullname:firstname lastname
in:email
created:<2021–04–05
created:>=2020–06–12
created:2019–02–07 location:iceland
created:2015–04–06..2018–01–14 in:username
extension:pem private
extension:ppk private
extension:sql mysql dump
extension:sql mysql dump password
extension:json [api.forecast.io]
extension:json [mongolab.com]
extension:yaml [mongolab.com]
[WFClient] Password= extension:ica
extension:avastlic "[support.avast.com]"
extension:json googleusercontent client_secret
```

### Censys

Search for hosts with an SNMP service whose reported location is exactly this phrase:

```bash
service.snmp.oid_system.location="Sitting on the Dock of the Bay"
"Schneider Electric" and ip: 23.20.0.0/14
not services.service_name: HTTP
services.port: {22, 23, 24, 25}
services.certificate: *
service.tls.certificates.leaf_data.names= /foo<1-100>.*/
ip: [1.12.0.0 to 1.15.255.255]
same_service(service.service_name: ELASTICSEARCH and service.port: 443)
service.http.response.body: powershell.exe
service.http.response.headers.connection: close and service.http.response.headers.content_type: text/plain
services.tls.version_selected=`TLSv1_0`
same_service(services.software.vendor: Microsoft and services.software.product: IIS and services.software.version: 7.5)
location.country: Russia
```

### Zoomeye

Here are some examples of search keywords used in the Zoomeye search engine:

```bash
webapp: wordpress
ver: 2.1
app: ProFTPD
device: router
os: windows
service: http
ip: 192.168.1.1
cidr: 192.168.1.1/24
hostname: google.com
port: 80
city: tehran
country: iran
asn:8978
header: server
desc: hello
title: example
site: example.com
```



