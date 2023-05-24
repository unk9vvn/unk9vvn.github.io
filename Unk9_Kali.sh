#!/bin/bash
# v90
# ┌──(unk9vvn㉿avi)-[~]
# └─$ sudo chmod +x Unk9_Kali.sh;sudo ./Unk9_Kali.sh



RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'


if [ "$(id -u)" != "0" ];then
	printf "$RED"		"[X] Please run as RooT ..."
	printf "$GREEN"		"sudo chmod +x Unk9_Kali.sh;sudo ./Unk9_Kali.sh"
	exit 0
fi


#-------------------------------OS Initial-------------------------------#


USER=$(cd /home;ls)
unk9vvn=/media/$USER/A9V8I/Documents/ProgramS/Hack-Center
NVIDIA=$(lspci -v | grep -o "NVIDIA")
TORRC=$(cat /etc/tor/torrc|grep -o "UseBridges 1")
DEBIAN=$(cat /etc/apt/sources.list|grep -o "deb http://deb.debian.org/debian buster main")
UBUNTU=$(cat /etc/apt/sources.list|grep -o "deb http://http.kali.org/kali kali-rolling main contrib non-free")
LAN=$(sudo ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | grep -v '169.*' | grep -v '172.*')
FRAMEWORK=/root/.wine/drive_c/windows/Microsoft.NET/Framework
ELASTICSEARCH=/etc/apt/sources.list.d/elastic-7.x.list
MICROSOFT=/etc/apt/sources.list.d/microsoft-prod.list
MONGODB=/etc/apt/sources.list.d/mongodb-org-4.4.list
SUBLIMETEXT=/home/$USER/.config/sublime-text-3
ONION=/var/lib/tor/hidden_service/hostname
VEIL=/usr/share/veil/config/setup.sh
GEF=/home/$USER/.gdbinit-gef.py
OPENVAS=/usr/bin/gvm-setup
ANYDESK=/usr/share/anydesk
RUST=/usr/share/rust
POSHC2=/opt/PoshC2


function OS_Initial()
{
	# Add Source Kali
	if [ "$UBUNTU" != "deb http://http.kali.org/kali kali-rolling main contrib non-free" ]; then
		echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
		echo "# deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
		apt-get -y --allow-unauthenticated install kali-archive-keyring
		apt-get update
	fi

	# Add Source Debian
	if [ "$DEBIAN" != "deb http://deb.debian.org/debian buster main" ]; then
		echo "" >> /etc/apt/sources.list
		echo "deb http://deb.debian.org/debian buster main" >> /etc/apt/sources.list
		echo "# deb-src http://deb.debian.org/debian buster main" >> /etc/apt/sources.list
		echo "" >> /etc/apt/sources.list
		echo "deb http://deb.debian.org/debian-security/ buster/updates main" >> /etc/apt/sources.list
		echo "# deb-src http://deb.debian.org/debian-security/ buster/updates main" >> /etc/apt/sources.list
		echo "" >> /etc/apt/sources.list
		echo "deb http://deb.debian.org/debian buster-updates main" >> /etc/apt/sources.list
		echo "# deb-src http://deb.debian.org/debian buster-updates main" >> /etc/apt/sources.list
		apt-get update
	fi

	# Install DotNet
	if [ ! -f "$MICROSOFT" ]; then
		wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
		dpkg -i /tmp/packages-microsoft-prod.deb && rm /tmp/packages-microsoft-prod.deb
		dpkg -i $unk9vvn/Others/DEBs/powershell/libicu57_57.1-6+deb9u4_amd64.deb
		apt-get install -y apt-transport-https
		apt-get update
		apt-get install -y dotnet-sdk-3.1 dotnet-runtime-3.1 aspnetcore-runtime-3.1 ca-certificates zlib1g powershell
	fi

	# Config Tor
	if [ "$TORRC" != "UseBridges 1" ]; then
		apt-get install -y tor proxychains
		echo "
UseBridges 1
Bridge 92.241.226.115:38375 30F579D82043B5F285D822552C398FA4780C69EF
Bridge 81.34.202.251:9001 99941A7E1CF8C10FEDEDC3655608FD2F502B689A
Bridge 185.220.101.77:48293 12E049305427AC06975801D957497218E4B82017" >> /etc/tor/torrc
	fi

	# Config Onion
	if [ ! -f "$ONION" ]; then
		apt-get install -y tor proxychains
		sed -i '71s#.*#HiddenServiceDir /var/lib/tor/hidden_service/#' /etc/tor/torrc
		sed -i '72s#.*#HiddenServicePort 80 127.0.0.1:8080#' /etc/tor/torrc
		mkdir /var/lib/tor/hidden_service
		echo '675ztniqv2huo4yd.onion' > /var/lib/tor/hidden_service/hostname
		touch /var/lib/tor/hidden_service/private_key
		chown debian-tor:debian-tor /var/lib/tor/hidden_service/
		chmod 0700 /var/lib/tor/hidden_service/
	fi

	# Upgrade & Dist-Upgrade
	apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

	# Require Packages
	apt-get install -y python3-toml python3-paramiko python3-hypercorn python3-aiofiles python3-ldap libxslt-dev libxml2-utils

	# Reguire Tools
	apt-get install -y apt-transport-https lksctp-tools nodejs texinfo help2man ruby-dev apt-file valgrind alacarte tcpxtract execstack tesseract-ocr gr-gsm jd-gui icoutils rarcrack steghide cupp slowhttptest autoconf dnsmasq gifsicle npm adb bettercap shellter remmina bleachbit haproxy vlc uget polipo clinfo aria2 smb4k crackle pptpd gimp xplico isc-dhcp-server bridge-utils clamav routersploit unicorn phpggc qrencode emailharvester xsltproc wifiphisher cmatrix libreoffice osrframework jq xdg-utils pandoc tigervnc-viewer pngtools pdfcrack dosbox lldb osrframework seclists wkhtmltopdf zmap parallel rr vagrant snmp sslscan mono-complete mono-devel filezilla libsdl2-dev apksigner checksec foremost rpi-imager sonic-visualiser kerberoast chromium dos2unix metagoofil imagemagick privoxy etherape dkms flawfinder virtualbox ismtp goldeneye scythe ident-user-enum goofile php-xdebug ridenum httptunnel splint hexyl firewalk bing-ip2hosts xmlstarlet wig feh onionshare krb5-user webhttrack pigz gnupg qtcreator qemu wine mingw-w64 fonts-wine winetricks winbind libwine rpm telegram-desktop audacity kalibrate-rtl hostapd-wpe telnet freeradius-wpe eyewitness dnsrecon suricata stenographer dnstwist powershell-empire tree cmake automake wafw00f redis-tools mdbtools afl-clang selektor starkiller airgeddon docker bc pcscd i2p zipalign php php-gd yasm awscli upx-ucl pcapfix stegosuite ufw ubertooth hexedit virtualenv bluez bcc bpfcc-tools oathtool docker-compose zbar-tools joplin nextnet strace android-sdk idn oclgausscrack multiforcer sipvicious qpdf virt-what obs-studio nipper-ng netstress spiderfoot tcptrack crackle pyrit crowbar rtl-433 airspy python-usb ng-common brutespray arduino websploit nfs-common cutycapt libevent-dev uhd-host libuhd-dev rfcat bloodhound googler sshpass ssdeep sublist3r pngcheck dnsgen lynis jsql snort munin fprobe pads kafkacat rtlsdr-scanner maven multimon-ng gdb isr-evilgrade xdotool dradis fish gqrx-sdr inspy sendmail rpcbind freerdp2-x11 ibombshell koadic dumpsterdiver pskracker silenttrinity wordlistraider tnscmd10g scrcpy android-tools-fastboot osslsigncode debian-keyring libapache2-mod-security2 rar unrar dangerzone kali-win-kex ipv6-toolkit apt-utils ropper ipcalc parsero golang qemu-system bladerf fcrackzip gobuster hachoir net-tools isc-dhcp-server yara z3 outguess iptables-persistent lcab linux-exploit-suggester fierce theharvester jsbeautifier shellnoob pptpd netcat aha atomicparsley obfs4proxy bind9-utils dnsutils ldapscripts android-tools-adb sigma-align smb4k docker.io default-jdk openjdk-11-jdk p7zip-full libopenscap8 openjdk-14-jdk thunderbird snap snapd rpm2cpio cpio zstd ffmpeg hurl testssl.sh snarf smtp-user-enum ltrace oscanner virtualbox-guest-x11 openconnect seclists procdump forensics-all kali-linux-large
	apt-get install -y torbrowser-launcher
	apt-get install -y exiftool
	apt-get install -y graphviz-dev
	apt-get install -y libssl-dev 2> /dev/null
	apt-get install -y python-pip 2> /dev/null
	# apt-get install -y swftools
	service tor start
	update-rc.d tor enable

	# Java Config
	_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"
	unset _JAVA_OPTIONS
	alias java='java "$_SILENT_JAVA_OPTIONS"'

	# Python2 Require
	wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py;python2.7 /tmp/get-pip.py;rm /tmp/get-pip.py
	pip2 install --upgrade --user pip;pip2 install -U setuptools;pip install cryptography==2.2.2
	pip2 install colorama prompt-toolkit pygments scapy env dnslib matplotlib Image configparser typing netifaces manticore tqdm dpkt capstone wsgidav
	pip2 install pyModbusTCP
	pip2 install tamper
	pip2 install censys
	pip2 install py-altdns
	pip2 install ropgadget
	pip2 install impacket
	pip2 install pyasn1==0.4.6
	pip2 install cave-miner
	pip2 install slowloris
	pip2 install pwntools
	pip2 install service_identity
	pip2 install whatwaf
	pip2 install hipshot
	pip2 install keystone-engine
	pip2 install scanless
	pip2 install baboossh
	pip2 install telegram
	pip2 install frida
	pip2 install mitm6
	pip2 install frida-tools
	pip2 install manticore
	pip2 install ooktools
	pip2 install shodan
	pip2 install ioc_fanger
	pip2 install drozer
	pip2 install qark
	pip2 install sandboxapi
	pip2 install selenium
	pip2 install python-nmap
	pip2 install pypiwin32
	pip2 install pinject
	pip2 install brute
	pip2 install python-telegram-bot
	pip2 install oletools
	pip2 install androguard
	pip2 install mongoaudit
	pip2 install cheroot

	# Python3 Require
	pip3 install --upgrade --user pip;pip3 install -U setuptools
	pip3 install colorama prompt-toolkit pygments pyftpdlib env scapy manticore wsgidav pysocks capstone threader3000 andriller dnspython argparse tldextract pydub cryptography==2.8
	pip3 install frida
	pip3 install frida-tools
	pip3 install dwarf-debugger
	pip3 install hashpumpy
	pip3 install ropper
	pip3 install sigmatools
	pip3 install pwntools
	pip3 install viper-framework
	pip3 install telethon
	pip3 install shogun-ml
	pip3 install SpeechRecognition
	pip3 install dnstwist
	pip3 install urh
	pip3 install brute-engine
	pip3 install otx-misp
	pip3 install updog
	pip3 install rekall
	pip3 install graphene
	pip3 install pythonfuzz
	pip3 install cabby
	pip3 install boofuzz
	pip3 install ioc-finder
	pip3 install intelmq
	pip3 install PyJWT
	pip3 install pymalleablec2
	pip3 install pycryptodomex
	pip3 install stix2
	pip3 install gramfuzz
	pip3 install mailspoof
	pip3 install principalmapper
	pip3 install scoutsuite
	pip3 install ioc-scan
	pip3 install pyersinia
	pip3 install keystone-engine
	pip3 install raccoon-scanner
	pip3 install stoq-framework
	pip3 install mitmproxy
	pip3 install angr-management
	pip3 install awscli
	pip3 install grammarinator
	pip3 install flare-capa
	pip3 install harpoon
	pip3 install detect-secrets
	pip3 install stegpy
	pip3 install mobsf
	pip3 install eql
	pip3 install stegcracker
	pip3 install lambdaguard
	pip3 install certstream
	pip3 install threat_intel
	pip3 install trailscraper
	pip3 install quark-engine
	pip3 install yaramanager
	pip3 install threatingestor
	pip3 install clinv
	pip3 install cartography
	pip3 install pymisp
	pip3 install aws-gate
	pip3 install hfinger
	pip3 install atheris
	pip3 install threatingestor
	pip3 install holehe
	pip3 install gdbgui
	pip3 install dnsgen
	pip3 install pwncat
	pip3 install flawfinder
	pip3 install kittyfuzzer
	pip3 install capstone
	pip3 install sipvicious
	pip3 install openioc-to-stix
	pip3 install angr
	pip3 install opentaxii
	pip3 install nodejsscan
	pip3 install xortool
	pip3 install dwarf-debugger
	pip3 install sceptre
	pip3 install spyse.py
	pip3 install h8mail
	pip3 install regexploit
	pip3 install opendrop
	pip3 install atheris
	pip3 install networkx
	pip3 install elastalert
	pip3 install whispers
	pip3 install truffleHog
	pip3 install iocextract
	pip3 install pyopenssl
	pip3 install machinae
	pip3 install awslog
	pip3 install hachoir
	pip3 install msticpy
	pip3 install pastehunter
	pip3 install rtfsig
	pip3 install cloudsplaining
	pip3 install kiwi
	pip3 install objection
	pip3 install Stegano
	pip3 install checkov
	pip3 install mvt
	pip3 install libcloudforensics
	pip3 install CloudGoat
	pip3 install margaritashotgun
	pip3 install aclpwn
	pip3 install lief
	pip3 install terraform-compliance
	pip3 install aws_ir
	pip3 install aws-allowlister
	pip3 install stego-lsb
	pip3 install cloudtracker
	pip3 install festin
	pip3 install lambdaguard
	pip3 install diffy
	pip3 install airiam
	pip3 install cheroot
	pip3 install donut-shellcode
	pip3 install neo4j-driver
	pip3 install stegoveritas;stegoveritas_install_deps
	python3 -m pip install --user pipx
	python3 -m userpath append ~/.local/bin
	pipx install gdbgui
	pipx upgrade gdbgui

	# Fix Problem
	pip2 uninstall pyopenssl -y
	pip2 install pyopenssl
	pip2 install cryptography==2.2.2

	# Ruby Require
	gem install bettercap
	gem install modbus-cli
	gem install ssrf_proxy
	gem install seccomp-tools
	gem install API_Fuzzer
	gem install github-linguist
	gem install dawnscanner
	gem install one_gadget
	gem install net-http-persistent
	gem install evil-winrm
	gem install ruby-nmap
	gem install bundler-audit
	gem install mechanize
	gem install aws_security_viz
	gem install public_suffix
	gem install text-table
	gem install idb
	gem install rake
	gem install aws_recon
	gem install zsteg

	# NodeJS Require
	npm install -g wappalyzer
	npm install -g padding-oracle-attacker
	npm install -g http-proxy-to-socks
	npm install -g typescript
	npm install -g f5stegojs
	npm install -g node-serialize
	npm install -g uglify-js
	npm install -g serverless
	npm install -g igf
	npm install -g phantomjs
	npm install -g whonow@latest
	npm install -g pown@latest
	npm install -g electron-packager
	npm install -g cloud-reports
	npm install -g aws-cdk
	gem install -g aws_public_ips
	npm install -g electron-packager
	npm install -g passionfruit
	npm install -g rms-runtime-mobile-security
	npm install -g private-ip
	npm install -g javascript-obfuscator
	npm install -g whonow@latest
	npm install -g redos
	npm install -g apk-mitm
	npm install -g fleetctl
	npm install -g npx
	npm install -g jwt-cracker
	npm install -g serialize-to-js
	npm install -g --engine-strict asar
	npm install -g serialize-javascript
	npm install -g snyk
	npm install -g dompurify
	npm install -g persistgraphql
	npm install -g @angular/cli

	# Golang Require
	GO111MODULE=on
	go get -u -d github.com/google/syzkaller/prog
	cd /home/$USER/go/src/github.com/google/syzkaller;make
	ln -s /home/$USER/go/src/github.com/google/syzkaller/bin/linux_amd64/syz-fuzzer /usr/local/bin/syz-fuzzer
	get -u -v github.com/projectdiscovery/dnsprobe
	cd /home/$USER/go/src/github.com/projectdiscovery/dnsprobe;docker build -t projectdiscovery/dnsprobe .
	ln -s /home/$USER/go/bin/dnsprobe /usr/local/bin/dnsprobe
	go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
	ln -s /home/$USER/go/bin/nuclei /usr/local/bin/nuclei
	go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
	ln -s /home/$USER/go/bin/subfinder /usr/local/bin/subfinder
	go get -u -v github.com/google/stenographer
	ln -s /home/$USER/go/bin/stenographer /usr/local/bin/stenographer
	go get -u -v github.com/tomnomnom/httprobe
	ln -s /home/$USER/go/bin/httprobe /usr/local/bin/httprobe
	go get -u -v github.com/hakluke/hakrawler
	ln -s /home/$USER/go/bin/hakrawler /usr/local/bin/hakrawler
	go get -u -v github.com/tomnomnom/meg
	ln -s /home/$USER/go/bin/meg /usr/local/bin/meg
	go get -u -v github.com/Ice3man543/SubOver
	ln -s /home/$USER/go/bin/SubOver /usr/local/bin/subover
	go get -u -v github.com/tomnomnom/waybackurls
	ln -s /home/$USER/go/bin/waybackurls /usr/local/bin/waybackurls
	go get -u -v github.com/eth0izzle/shhgit
	ln -s /home/$USER/go/bin/shhgit /usr/local/bin/shhgit
	go get -u -v github.com/projectdiscovery/naabu/v2/cmd/naabu
	ln -s /home/$USER/go/bin/naabu /usr/local/bin/naabu
	go get -u -v github.com/tfsec/tfsec/cmd/tfsec
	ln -s /home/$USER/go/bin/tfsec /usr/local/bin/tfsec
	go get -u -v github.com/nytr0gen/deduplicate
	ln -s /home/$USER/go/bin/deduplicate /usr/local/bin/deduplicate
	go get -u -v github.com/tomnomnom/gf
	ln -s /home/$USER/go/bin/gf /usr/local/bin/gf
	go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
	ln -s /home/$USER/go/bin/httpx /usr/local/bin/httpx
	go get -u -v github.com/KathanP19/Gxss
	ln -s /home/$USER/go/bin/Gxss /usr/local/bin/Gxss
	go get -u -v github.com/hahwul/dalfox
	ln -s /home/$USER/go/bin/dalfox /usr/local/bin/dalfox
	go get -u -v github.com/ffuf/ffuf
	ln -s /home/$USER/go/bin/ffuf /usr/local/bin/ffuf
	go get -u -v github.com/tomnomnom/assetfinder
	ln -s /home/$USER/go/bin/assetfinder /usr/local/bin/assetfinder
	go get -u -v github.com/ndelphit/apkurlgrep
	ln -s /home/$USER/go/bin/apkurlgrep /usr/local/bin/apkurlgrep
	go get -u -v github.com/lc/gau
	ln -s /home/$USER/go/bin/gau /usr/local/bin/gau
	go get -u -v github.com/haccer/subjack
	ln -s /home/$USER/go/bin/subjack /usr/local/bin/subjack
	go get -u -v github.com/jaeles-project/gospider
	ln -s /home/$USER/go/bin/gospider /usr/local/bin/gospider
	go get -u -v github.com/tomnomnom/qsreplace
	ln -s /home/$USER/go/bin/qsreplace /usr/local/bin/qsreplace
	go get -u -v github.com/s-rah/onionscan
	ln -s /home/$USER/go/bin/onionscan /usr/local/bin/onionscan
	go get -u -v github.com/tomnomnom/gron
	ln -s /home/$USER/go/bin/gron /usr/local/bin/gron
	go get -u -v github.com/valyala/fasthttp
	ln -s /home/$USER/go/bin/fasthttp /usr/local/bin/fasthttp
	go get -u -v github.com/RumbleDiscovery/jarm-go/cmd/jarmscan
	ln -s /home/$USER/go/bin/jarmscan /usr/local/bin/jarmscan
	go get -u -v github.com/harleo/asnip
	ln -s /home/$USER/go/bin/asnip /usr/local/bin/asnip
	go get -u -v github.com/ghostpass/ghostpass/cmd/ghostpass
	ln -s /home/$USER/go/bin/ghostpass /usr/local/bin/ghostpass
	go get -u -v github.com/bettercap/bettercap
	ln -s /home/$USER/go/bin/bettercap /usr/local/bin/bettercap
	go get -u -v github.com/Nhoya/gOSINT/cmd/gosint
	ln -s /home/$USER/go/bin/gosint /usr/local/bin/gosint
	go get -u -v github.com/smiegles/mass3
	ln -s /home/$USER/go/bin/mass3 /usr/local/bin/mass3
	go get -u -v github.com/koenrh/s3enum
	ln -s /home/$USER/go/bin/s3enum /usr/local/bin/s3enum
	go get -u -v github.com/magisterquis/s3finder
	ln -s /home/$USER/go/bin/s3finder /usr/local/bin/s3finder
	go get -u -v github.com/genuinetools/bane
	ln -s /home/$USER/go/bin/bane /usr/local/bin/bane
	go get -u -v github.com/aquasecurity/esquery
	ln -s /home/$USER/go/bin/esquery /usr/local/bin/esquery
	go get -u -v github.com/drk1wi/Modlishka
	ln -s /home/$USER/go/bin/Modlishka /usr/local/bin/Modlishka
	go get -u -v github.com/target/strelka/src/go/cmd/strelka-fileshot
	ln -s /home/$USER/go/bin/strelka-fileshot /usr/local/bin/strelka-fileshot
	go get -u -v github.com/google/stenographer
	ln -s /home/$USER/go/bin/stenographer /usr/local/bin/stenographer



	# Install Framework (Wine)
	if [ ! -d "$FRAMEWORK" ]; then
		dpkg --add-architecture i386
		apt-get update
		apt-get install -y wine32 libwine:i386
		wine msiexec /i /s $unk9vvn/Others/DEBs/wine/wine_gecko-2.47-x86.msi
		wine msiexec /i /s $unk9vvn/Others/DEBs/wine/wine_gecko-2.47-x86_64.msi
		WINEARCH=win32 WINEPREFIX=~/.wine winetricks -q win7
		winetricks -q dotnet40_kb2468871
		winetricks -q dotnet48
		winetricks -q vcrun2010
		winetricks -q vcrun2015
		winetricks -q vcrun2019
		winetricks -q dotnet_verifier
		WINEARCH=win64 WINEPREFIX=~/.wine64 winetricks -q win7
		winetricks -q dotnet40_kb2468871
		winetricks -q dotnet48
		winetricks -q vcrun2010
		winetricks -q vcrun2015
		winetricks -q vcrun2019
		winetricks -q dotnet_verifier
	fi

	# Install Nvidia GPU
	if [ "$NVIDIA" = "NVIDIA" ]; then
		apt-get install -y nvidia-driver nvidia-cuda-toolkit
		reboot
	fi

	# Install AnyDesk
	if [ ! -d "$ANYDESK" ]; then
		wget -qO - https://keys.anydesk.com/repos/DEB-GPG-KEY | apt-key add -
		echo "deb http://deb.anydesk.com/ all main" > /etc/apt/sources.list.d/anydesk-stable.list
		apt update
		apt install -y anydesk
	fi

	# Install GEF
	if [ ! -f "$GEF" ]; then
		wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
	fi

	# Install PoshC2
	if [ ! -d "$POSHC2" ]; then
		curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh | bash
	fi

	# Initial Veil
	if [ ! -f "$VEIL" ]; then
		apt-get install -y veil veil-evasion
		/usr/share/veil/config/setup.sh --force --silent
	fi

	# Initial Veil
	if [ ! -f "$RUST" ]; then
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	fi

	# Initial OpenVAS
	if [ ! -f "$OPENVAS" ]; then
		apt-get install -y gvm
		proxychains gvm-setup
	fi

	# Install SublimeText
	if [ ! -d "$SUBLIMETEXT" ]; then
		wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
		echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
		apt update
		read -p """
	----- BEGIN LICENSE -----
	Member J2TeaM
	Single User License
	EA7E-1011316
	D7DA350E 1B8B0760 972F8B60 F3E64036
	B9B4E234 F356F38F 0AD1E3B7 0E9C5FAD
	FA0A2ABE 25F65BD8 D51458E5 3923CE80
	87428428 79079A01 AA69F319 A1AF29A4
	A684C2DC 0B1583D4 19CBD290 217618CD
	5653E0A0 BACE3948 BB2EE45E 422D2C87
	DD9AF44B 99C49590 D2DBDEE1 75860FD2
	8C8BB2AD B2ECE5A4 EFC08AF2 25A9B864
	------ END LICENSE ------​

	[?] Do you want to Copy SublimeText License [y/n]? 
	""" status
		if [ "$status" == "y" ]; then
			apt install -y sublime-text
		fi
	fi

	# Initial Kerio
	if [ ! -f "$KERIO" ]; then
		read -p """
	WEBSITE: http://gozar.asia		SERVER:
	[i] United State			us.gozaronline.net:2087
	[i]	France					fr.gozaronline.net:2087
	[i]	Germany					gr.gozaronline.net:2087
	[i]	United Kingdom			uk.gozaronline.net:2087
	[i]	Netherland				nl.gozaronline.net:2087
	[i]	Russia					ru.gozaronline.net:2087
	[i]	Finland					fi.gozaronline.net:2087
	[i]	Spain					es.gozaronline.net:2087
	[i]	Portugal				pt.gozaronline.net:2087
	[i]	Italy					it.gozaronline.net:2087

	[?] Do you want to install Kerio VPN [y/n]? 
	""" status
		if [ "$status" == "y" ]; then
			dpkg -i $unk9vvn/Others/Kerio-Client/kerio-control-vpnclient-9.3.5-4367-linux-amd64.deb
		fi
	fi
}


#-------------------------------BlueTeam-------------------------------#


MODSECURITY=$unk9vvn/BlueTeam/modsecurity-crs


BlueTeam()
{
	WAF()
	{
		# Install ModSecurity
		if [ -d "$MODSECURITY" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/modsecurity
			echo 'USER=$(cd /home;ls)' >> /usr/bin/modsecurity
			echo '''


RED="\e[1;31m%s\e[0m\n"
GREEN="\e[1;32m%s\e[0m\n"
YELLOW="\e[1;33m%s\e[0m\n"
BLUE="\e[1;34m%s\e[0m\n"
MAGENTO="\e[1;35m%s\e[0m\n"
CYAN="\e[1;36m%s\e[0m\n"
WHITE="\e[1;37m%s\e[0m\n"


Mod_Enable()
{
	sed -i "s#SecRuleEngine Off#SecRuleEngine On#g" /etc/modsecurity/modsecurity.conf
	service apache2 restart
	printf "\n\n"
	printf "$GREEN"  "[*] Enable Mod Security WAF on Apache2"
	printf "\n\n"
	sleep 3
}

Mod_Disable()
{
	sed -i "s#SecRuleEngine On#SecRuleEngine Off#g" /etc/modsecurity/modsecurity.conf
	service apache2 restart
	printf "\n\n"
	printf "$RED"  "[*] Disable Mod Security WAF on Apache2"
	printf "\n\n"
	sleep 3
}

incorrect_selection()
{

	printf "\n\n"
	printf "$YELLOW"  "[?] Incorrect selection! Try again."
	printf "\n\n"
}

until [ "$selection" = "0" ]; do
  clear
  echo ""
  echo "    	[1] Enable Mod Security"
  echo "    	[2] Disable Mod Security"
  echo "    	[0] Exit"
  echo ""
  echo -n "[*] Enter selection: "
  read selection
  echo ""
  case $selection in
    1 ) clear ; Mod_Enable ;;
    2 ) clear ; Mod_Disable ;;
    0 ) clear ; exit ;;
    * ) clear ; incorrect_selection ;;
  esac
done

''' >> /usr/bin/modsecurity
			chmod +x /usr/bin/modsecurity
			chmod 755 $unk9vvn/BlueTeam/modsecurity-crs/*
			cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
			sed -i "s#SecRuleEngine DetectionOnly#SecRuleEngine On#g" /etc/modsecurity/modsecurity.conf
			cp $unk9vvn/BlueTeam/modsecurity-crs/crs-setup.conf.example $unk9vvn/BlueTeam/modsecurity-crs/crs-setup.conf
			echo """
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity
        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier
        IncludeOptional /etc/modsecurity/*.conf
        # Include OWASP ModSecurity CRS rules if installed
        IncludeOptional "$unk9vvn"/BlueTeam/modsecurity-crs/*.conf
        IncludeOptional "$unk9vvn"/BlueTeam/modsecurity-crs/rules/*.conf
</IfModule>
""" > /etc/apache2/mods-enabled/security2.conf
			chmod 755 /etc/apache2/mods-enabled/security2.conf
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ModSecurity"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ModSecurity"
			printf "\n\n"
		fi
	}



}


#-------------------------------Crypto-------------------------------#


POODLE=$unk9vvn/Crypto/Poodle
JHIJACK=$unk9vvn/Crypto/JHijack
HASHPUMP=$unk9vvn/Crypto/HashPump
CYBERCHEF=$unk9vvn/Crypto/CyberChef
PADBUSTER=$unk9vvn/Crypto/PadBuster
TLS_ATTACKER=$unk9vvn/Crypto/TLS-Attacker
HASH_EXTENDER=$unk9vvn/Crypto/HashExtender
POET=$unk9vvn/Crypto/Padding-Oracle-Exploit-Tool
PEMCRACK=$unk9vvn/Crypto/PEMCrack
RSACTFTOOL=$unk9vvn/Crypto/RsaCtfTool
RSATOOL=$unk9vvn/Crypto/RSATool
DYMERGE=$unk9vvn/Crypto/DyMerge


Crypto()
{
	# Install HashPump
	if [ -d "$HASHPUMP" ]; then
		chmod 755 $unk9vvn/Crypto/HashPump/*
		cd $unk9vvn/Crypto/HashPump;make install
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing HashPump"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing HashPump"
		printf "\n\n"
	fi

	# Install RSAtool
	if [ -d "$RSATOOL" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/rsatool
		echo 'USER=$(cd /home;ls)' >> /usr/bin/rsatool
		echo 'cd '$unk9vvn'/Crypto/RSAtool;pyhton2 rsatool.py "$@"' >> /usr/bin/rsatool
		chmod +x /usr/bin/rsatool
		chmod 755 $unk9vvn/Crypto/RSATool/*
		cd $unk9vvn/Crypto/RSATool;python setup.py install
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing RSAtool"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing RSAtool"
		printf "\n\n"
	fi

	# Install RsaCtfTool
	if [ -d "$RSACTFTOOL" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/rsactftool
		echo 'USER=$(cd /home;ls)' >> /usr/bin/rsactftool
		echo 'cd '$unk9vvn'/Crypto/RsaCtfTool;python3 RsaCtfTool.py "$@"' >> /usr/bin/rsactftool
		chmod +x /usr/bin/rsactftool
		chmod 755 $unk9vvn/Crypto/RsaCtfTool/*
		pip3 -r $unk9vvn/Crypto/RsaCtfTool/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing RsaCtfTool"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing RsaCtfTool"
		printf "\n\n"
	fi

	# Install PEMCrack
	if [ -d "$PEMCRACK" ]; then
		chmod 755 $unk9vvn/Crypto/PEMCrack/*
		ln -f -s $unk9vvn/Crypto/PEMCrack/pemcrack /usr/bin/pemcrack
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PEMCrack"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PEMCrack"
		printf "\n\n"
	fi

	# Install JHijack
	if [ -d "$JHIJACK" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/jhijack
		echo 'USER=$(cd /home;ls)' >> /usr/bin/jhijack
		echo 'cd '$unk9vvn'/Crypto/JHijack;java -jar JHijack.jar "$@"' >> /usr/bin/jhijack
		chmod +x /usr/bin/jhijack
		chmod 755 $unk9vvn/Crypto/JHijack/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing JHijack"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing JHijack"
		printf "\n\n"
	fi

	# Install Padding-Oracle-Exploit-Tool
	if [ -d "$POET" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/poet
		echo 'USER=$(cd /home;ls)' >> /usr/bin/poet
		echo 'cd '$unk9vvn'/Crypto/Padding-Oracle-Exploit-Tool;java -jar poet-1.0.1-linux-x86_amd64.jar "$@"' >> /usr/bin/poet
		chmod +x /usr/bin/poet
		chmod 755 $unk9vvn/Crypto/Padding-Oracle-Exploit-Tool/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Padding-Oracle-Exploit-Tool"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Padding-Oracle-Exploit-Tool"
		printf "\n\n"
	fi

	# Install DyMerge
	if [ -d "$DYMERGE" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/dymerge
		echo 'USER=$(cd /home;ls)' >> /usr/bin/dymerge
		echo 'cd '$unk9vvn'/Crypto/DyMerge;python2 dymerge.py "$@"' >> /usr/bin/dymerge
		chmod +x /usr/bin/dymerge
		chmod 755 $unk9vvn/Crypto/DyMerge/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing DyMerge"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing DyMerge"
		printf "\n\n"
	fi

	# Install Poodle
	if [ -d "$POODLE" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/poodle
		echo 'USER=$(cd /home;ls)' >> /usr/bin/poodle
		echo 'cd '$unk9vvn'/Crypto/Poodle;python2 poodle-exploit.py "$@"' >> /usr/bin/poodle
		chmod +x /usr/bin/poodle
		chmod 755 $unk9vvn/Crypto/Poodle/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Poodle"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Poodle"
		printf "\n\n"
	fi

	# Install HashExtender
	if [ -d "$HASH_EXTENDER" ]; then
		chmod 755 $unk9vvn/Crypto/HashExtender/*
		ln -f -s $unk9vvn/Crypto/HashExtender/hash_extender /usr/bin/hashextender
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing HashExtender"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing HashExtender"
		printf "\n\n"
	fi

	# Install PadBuster
	if [ -d "$PADBUSTER" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/padbuster
		echo 'USER=$(cd /home;ls)' >> /usr/bin/padbuster
		echo 'cd '$unk9vvn'/Crypto/PadBuster;perl PadBuster.pl "$@"' >> /usr/bin/padbuster
		chmod +x /usr/bin/padbuster
		chmod 755 $unk9vvn/Crypto/PadBuster/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PadBuster"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PadBuster"
		printf "\n\n"
	fi

	# Install TLS-Attacker
	if [ -d "$TLS_ATTACKER" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/tlsattacker
		echo 'USER=$(cd /home;ls)' >> /usr/bin/tlsattacker
		echo 'cd '$unk9vvn'/Crypto/TLS-Attacker;java -jar Attacks.jar "$@"' >> /usr/bin/tlsattacker
		chmod +x /usr/bin/tlsattacker
		chmod 755 $unk9vvn/Crypto/TLS-Attacker/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing TLS-Attacker"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing TLS-Attacker"
		printf "\n\n"
	fi

	# Install CyberChef
	if [ -d "$CYBERCHEF" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/cyberchef
		echo 'USER=$(cd /home;ls)' >> /usr/bin/cyberchef
		echo 'firefox --new-tab "file://'$unk9vvn'/Crypto/CyberChef/CyberChef.html" > /dev/null & "$@"' >> /usr/bin/cyberchef
		chmod +x /usr/bin/cyberchef
		chmod 755 $unk9vvn/Crypto/CyberChef/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CyberChef"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CyberChef"
		printf "\n\n"
	fi
}


#---------------------------------DDoS---------------------------------#


NTPDOSER=$unk9vvn/DDoS/NTPDoser
MEMCRASHED=$unk9vvn/DDoS/MemCrashed


DDoS()
{
	# Install MemCrashed
	if [ -d "$MEMCRASHED" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/memcrashed
		echo 'USER=$(cd /home;ls)' >> /usr/bin/memcrashed
		echo 'cd '$unk9vvn'/DDoS/MemCrashed;python3 Memcrashed.py "$@"' >> /usr/bin/memcrashed
		chmod +x /usr/bin/memcrashed
		chmod 755 $unk9vvn/DDoS/MemCrashed/*
		pip3 install -r $unk9vvn/DDoS/MemCrashed/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing MemCrashed"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing MemCrashed"
		printf "\n\n"
	fi

	# Install NTPDoser
	if [ -d "$NTPDOSER" ]; then
		chmod 755 $unk9vvn/DDoS/NTPDoser/*
		ln -f -s $unk9vvn/DDoS/NTPDoser/NTPDoser /usr/bin/ntpdoser
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing NTPDoser"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing NTPDoser"
		printf "\n\n"
	fi
}


#-------------------------------Forensic-------------------------------#


OPENSTEGO=$unk9vvn/Forensic/OpenStego
STEGOSAURUS=$unk9vvn/Forensic/StegoSaurus
CLOACKED_PIXEL=$unk9vvn/Forensic/cloacked-pixel
AUDIOSTEGO=$unk9vvn/Forensic/AudioStego
DEEPSOUND=$unk9vvn/Forensic/DeepSound
MP3STEGO=$unk9vvn/Forensic/MP3Stego
STEGANABARA=$unk9vvn/Forensic/Steganabara
STEGSOLVE=$unk9vvn/Forensic/Stegsolve
OPENPUFF=$unk9vvn/Forensic/OpenPuff
JSTEG=$unk9vvn/Forensic/JSteg
VELES=$unk9vvn/Forensic/Veles
SSAK=$unk9vvn/Forensic/SSAK


Forensic()
{
	# Install OpenStego
	if [ -d "$OPENSTEGO" ]; then
		chmod 755 $unk9vvn/Forensic/OpenStego/*
		dpkg -i $unk9vvn/Forensic/OpenStego/openstego_0.7.4-1_amd64.deb
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing OpenStego"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing OpenStego"
		printf "\n\n"
	fi

	# Install StegoSaurus
	if [ -d "$STEGOSAURUS" ]; then
		chmod 755 $unk9vvn/Forensic/StegoSaurus/*
		ln -f -s $unk9vvn/Forensic/StegoSaurus/stegosaurus /usr/bin/stegosaurus
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing StegoSaurus"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing StegoSaurus"
		printf "\n\n"
	fi

	# Install AudioStego
	if [ -d "$AUDIOSTEGO" ]; then
		chmod 755 $unk9vvn/Forensic/AudioStego/build/*
		ln -f -s $unk9vvn/Forensic/AudioStego/build/hideme /usr/bin/hideme
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing AudioStego"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing AudioStego"
		printf "\n\n"
	fi

	# Install Cloacked-Pixel
	if [ -d "$CLOACKED_PIXEL" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/cloackedpixel
		echo 'USER=$(cd /home;ls)' >> /usr/bin/cloackedpixel
		echo 'cd '$unk9vvn'/Forensic/cloacked-pixel;python2 lsb.py "$@"' >> /usr/bin/cloackedpixel
		chmod +x /usr/bin/cloackedpixel
		chmod 755 $unk9vvn/Forensic/cloacked-pixel/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Cloacked-Pixel"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Cloacked-Pixel"
		printf "\n\n"
	fi

	# Install DeepSound
	if [ -d "$DEEPSOUND" ]; then
		chmod 755 $unk9vvn/Forensic/DeepSound/*
		wine msiexec /i /s $unk9vvn/Forensic/DeepSound/deepsound.msi
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing DeepSound"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing DeepSound"
		printf "\n\n"
	fi

	# Install SSAK
	if [ -d "$SSAK" ]; then
		chmod 755 $unk9vvn/Forensic/SSAK/programs/64/*
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/cjpeg /usr/bin/cjpeg
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/djpeg /usr/bin/djpeg
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/histogram /usr/bin/histogram
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/jphide /usr/bin/jphide
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/jpseek /usr/bin/jpseek
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/outguess_0.13 /usr/bin/outguess
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/stegbreak /usr/bin/stegbreak
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/stegcompare /usr/bin/stegcompare
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/stegdeimage /usr/bin/stegdeimage
		ln -f -s $unk9vvn/Forensic/SSAK/programs/64/stegdetect /usr/bin/stegdetect
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing SSAK"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing SSAK"
		printf "\n\n"
	fi

	# Install JSteg
	if [ -d "$JSTEG" ]; then
		chmod 755 $unk9vvn/Forensic/JSteg/*
		ln -f -s $unk9vvn/Forensic/JSteg/slink /usr/bin/slink
		ln -f -s $unk9vvn/Forensic/JSteg/jsteg /usr/bin/jsteg
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing JSteg & Slink"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing JSteg & Slink"
		printf "\n\n"
	fi

	# Install MP3Stego
	if [ -d "$MP3STEGO" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/mp3stego-encode
		echo 'USER=$(cd /home;ls)' >> /usr/bin/mp3stego-encode
		echo 'cd '$unk9vvn'/Forensic/MP3Stego/MP3Stego;wine Encode.exe "$@"' >> /usr/bin/mp3stego-encode
		chmod +x /usr/bin/mp3stego-encode
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/mp3stego-decode
		echo 'USER=$(cd /home;ls)' >> /usr/bin/mp3stego-decode
		echo 'cd '$unk9vvn'/Forensic/MP3Stego/MP3Stego;wine Decode.exe "$@"' >> /usr/bin/mp3stego-decode
		chmod +x /usr/bin/mp3stego-decode
		chmod 755 $unk9vvn/Forensic/MP3Stego/MP3Stego/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing MP3Stego"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing MP3Stego"
		printf "\n\n"
	fi

	# Install OpenPuff
	if [ -d "$OPENPUFF" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/openpuff
		echo 'USER=$(cd /home;ls)' >> /usr/bin/openpuff
		echo 'cd '$unk9vvn'/Forensic/OpenPuff;wine OpenPuff.exe "$@"' >> /usr/bin/openpuff
		chmod +x /usr/bin/openpuff
		chmod 755 $unk9vvn/Forensic/OpenPuff/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing OpenPuff"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing OpenPuff"
		printf "\n\n"
	fi

	# Install Steganabara
	if [ -d "$STEGANABARA" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/steganabara
		echo 'USER=$(cd /home;ls)' >> /usr/bin/steganabara
		echo 'cd '$unk9vvn'/Forensic/Steganabara/bin;java -cp steganabara.Steganabara "$@"' >> /usr/bin/steganabara
		chmod +x /usr/bin/steganabara
		chmod 755 $unk9vvn/Forensic/Steganabara/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Steganabara"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Steganabara"
		printf "\n\n"
	fi

	# Install Veles
	if [ -d "$VELES" ]; then
		chmod 755 $unk9vvn/Forensic/Veles/*
		dpkg -i $unk9vvn/Forensic/Veles/Veles_2018.05_64bit_Ubuntu1604.deb
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Veles"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Veles"
		printf "\n\n"
	fi

	# Install Stegsolve
	if [ -d "$STEGSOLVE" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/stegsolve
		echo 'USER=$(cd /home;ls)' >> /usr/bin/stegsolve
		echo 'cd '$unk9vvn'/Forensic/Stegsolve;java -jar stegsolve.jar "$@"' >> /usr/bin/stegsolve
		chmod +x /usr/bin/stegsolve
		chmod 755 $unk9vvn/Forensic/Stegsolve/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Stegsolve"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Stegsolve"
		printf "\n\n"
	fi
}


#-------------------------------InfoGathering-------------------------------#


AQUATONE=$unk9vvn/InfoGathering/Aquatone
CLOUDFAIL=$unk9vvn/InfoGathering/CloudFail
CLOUDBUNNY=$unk9vvn/InfoGathering/CloudBunny
CLOUDSCRAPER=$unk9vvn/InfoGathering/CloudScraper
WEBSCREENSHOT=$unk9vvn/InfoGathering/WebScreenShot
COMMIT_STREAM=$unk9vvn/InfoGathering/commit-stream
PHONEINFOGA=$unk9vvn/InfoGathering/PhoneInfoga
GETALLURLS=$unk9vvn/InfoGathering/GetAllUrls
SHUFFLEDNS=$unk9vvn/InfoGathering/shuffleDNS
VHOSTSCAN=$unk9vvn/InfoGathering/VHostScan
DIRSEARCH=$unk9vvn/InfoGathering/Dirsearch
GITGRABER=$unk9vvn/InfoGathering/gitGraber
GOITNESS=$unk9vvn/InfoGathering/GoWitness
FINDOMAIN=$unk9vvn/InfoGathering/Findomain
RECONDOG=$unk9vvn/InfoGathering/ReconDog
DNSRECON=$unk9vvn/InfoGathering/DNSRecon
WHATWAF=$unk9vvn/InfoGathering/WhatWaf
CREDMAP=$unk9vvn/InfoGathering/CredMap
MASSDNS=$unk9vvn/InfoGathering/MassDNS
INFOGA=$unk9vvn/InfoGathering/Infoga
GITROB=$unk9vvn/InfoGathering/Gitrob
DNSCAN=$unk9vvn/InfoGathering/DNScan
SN1PER=$unk9vvn/InfoGathering/Sn1per
FFUF=$unk9vvn/InfoGathering/FFUF


InfoGathering()
{
	# Install Aquatone
	if [ -d "$AQUATONE" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/Aquatone/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/Aquatone/aquatone /usr/bin/aquatone
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Aquatone"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Aquatone"
		printf "\n\n"
	fi

	# Install CloudBunny
	if [ -d "$CLOUDBUNNY" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/cloudbunny
		echo 'USER=$(cd /home;ls)' >> /usr/bin/cloudbunny
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/CloudBunny;python2 cloudbunny.py "$@"' >> /usr/bin/cloudbunny
		chmod +x /usr/bin/cloudbunny
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/CloudBunny/*
		pip2 install -r $unk9vvn/RedTeam/Reconnaissance/CloudBunny/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CloudBunny"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CloudBunny"
		printf "\n\n"
	fi

	# Install CloudFail
	if [ -d "$CLOUDFAIL" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/cloudfail
		echo 'USER=$(cd /home;ls)' >> /usr/bin/cloudfail
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/CloudFail;python3 cloudfail.py "$@"' >> /usr/bin/cloudfail
		chmod +x /usr/bin/cloudfail
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/CloudFail/*
		pip3 install -r $unk9vvn/RedTeam/Reconnaissance/CloudFail/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CloudFail"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CloudFail"
		printf "\n\n"
	fi

	# Install Sn1per
	if [ -d "$SN1PER" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/Sn1per/*
		cd $unk9vvn/RedTeam/Reconnaissance/Sn1per;./install.sh
		apt-get install -y python python-dev python-tk python-pyexiv2 libprotobuf17 python-protobuf python3 python3-pip python3-venv
		wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py;python2.7 /tmp/get-pip.py;rm /tmp/get-pip.py
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Sn1per"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Sn1per"
		printf "\n\n"
	fi

	# Install CloudScraper
	if [ -d "$CLOUDSCRAPER" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/cloudscraper
		echo 'USER=$(cd /home;ls)' >> /usr/bin/cloudscraper
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/CloudScraper;python3 CloudScraper.py "$@"' >> /usr/bin/cloudscraper
		chmod +x /usr/bin/cloudscraper
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/CloudScraper/*
		pip3 install -r $unk9vvn/RedTeam/Reconnaissance/CloudScraper/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CloudScraper"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CloudScraper"
		printf "\n\n"
	fi

	# Install Commit-Stream
	if [ -d "$COMMIT_STREAM" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/commit-stream/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/commit-stream/commit-stream-linux-amd64 /usr/bin/commit-stream
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Commit-Stream"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Commit-Stream"
		printf "\n\n"
	fi

	# Install CredMap
	if [ -d "$CREDMAP" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/credmap
		echo 'USER=$(cd /home;ls)' >> /usr/bin/credmap
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/CredMap;python2 credmap.py "$@"' >> /usr/bin/credmap
		chmod +x /usr/bin/credmap
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/CredMap/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CredMap"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CredMap"
		printf "\n\n"
	fi

	# Install Dirsearch
	if [ -d "$DIRSEARCH" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/dirsearch
		echo 'USER=$(cd /home;ls)' >> /usr/bin/dirsearch
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/Dirsearch;python3 dirsearch.py "$@"' >> /usr/bin/dirsearch
		chmod +x /usr/bin/dirsearch
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/Dirsearch/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Dirsearch"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Dirsearch"
		printf "\n\n"
	fi

	# Install DNScan
	if [ -d "$DNSCAN" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/dnscan
		echo 'USER=$(cd /home;ls)' >> /usr/bin/dnscan
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/DNScan;python2 dnscan.py "$@"' >> /usr/bin/dnscan
		chmod +x /usr/bin/dnscan
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/DNScan/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing DNScan"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing DNScan"
		printf "\n\n"
	fi

	# Install FFUF
	if [ -d "$FFUF" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/FFUF/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/FFUF/ffuf /usr/bin/ffuf
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing FFUF"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing FFUF"
		printf "\n\n"
	fi

	# Install Findomain
	if [ -d "$FINDOMAIN" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/Findomain/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/Findomain/findomain-linux /usr/bin/findomain
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Findomain"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Findomain"
		printf "\n\n"
	fi

	# Install GetAllUrls
	if [ -d "$GETALLURLS" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/GetAllUrls/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/GetAllUrls/gau /usr/bin/gau
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing GetAllUrls"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing GetAllUrls"
		printf "\n\n"
	fi

	# Install Gitrob
	if [ -d "$GITROB" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/Gitrob/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/Gitrob/gitrob /usr/bin/gitrob
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Gitrob"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Gitrob"
		printf "\n\n"
	fi

	# Install gitGraber
	if [ -d "$GITGRABER" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/gitgraber
		echo 'USER=$(cd /home;ls)' >> /usr/bin/dnscan
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/gitGraber;python3 gitGraber.py "$@"' >> /usr/bin/gitgraber
		chmod +x /usr/bin/gitgraber
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/gitGraber/*
		pip3 install -r $unk9vvn/RedTeam/Reconnaissance/gitGraber/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing gitGraber"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing gitGraber"
		printf "\n\n"
	fi

	# Install GoWitness
	if [ -d "$GOITNESS" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/GoWitness/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/GoWitness/gowitness /usr/bin/gowitness
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing GoWitness"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing GoWitness"
		printf "\n\n"
	fi

	# Install Infoga
	if [ -d "$INFOGA" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/infoga
		echo 'USER=$(cd /home;ls)' >> /usr/bin/infoga
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/Infoga;python2 infoga.py "$@"' >> /usr/bin/infoga
		chmod +x /usr/bin/infoga
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/Infoga/*
		cd $unk9vvn/RedTeam/Reconnaissance/Infoga;python setup.py install
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Infoga"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Infoga"
		printf "\n\n"
	fi

	# Install MassDNS
	if [ -d "$MASSDNS" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/MassDNS/*
		cd $unk9vvn/RedTeam/Reconnaissance/MassDNS;make;make install
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing MassDNS"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing MassDNS"
		printf "\n\n"
	fi

	# Install PhoneInfoga
	if [ -d "$PHONEINFOGA" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/PhoneInfoga/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/PhoneInfoga/phoneinfoga /usr/bin/phoneinfoga
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PhoneInfoga"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PhoneInfoga"
		printf "\n\n"
	fi

	# Install ReconDog
	if [ -d "$RECONDOG" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/dog
		echo 'USER=$(cd /home;ls)' >> /usr/bin/dog
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/ReconDog;python3 dog "$@"' >> /usr/bin/dog
		chmod +x /usr/bin/dog
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/ReconDog/*
		pip3 install -r $unk9vvn/RedTeam/Reconnaissance/ReconDog/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing ReconDog"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing ReconDog"
		printf "\n\n"
	fi

	# Install shuffleDNS
	if [ -d "$SHUFFLEDNS" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/shuffleDNS/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/shuffleDNS/shuffledns /usr/bin/shuffledns
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing shuffleDNS"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing shuffleDNS"
		printf "\n\n"
	fi

	# Install VHostScan
	if [ -d "$VHOSTSCAN" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/VHostScan/*
		pip2 install -r $unk9vvn/RedTeam/Reconnaissance/VHostScan/requirements.txt
		cd $unk9vvn/RedTeam/Reconnaissance/VHostScan;python setup.py install
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing VHostScan"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing VHostScan"
		printf "\n\n"
	fi

	# Install WebScreenShot
	if [ -d "$WEBSCREENSHOT" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/webscreenshot
		echo 'USER=$(cd /home;ls)' >> /usr/bin/webscreenshot
		echo 'cd '$unk9vvn'/RedTeam/Reconnaissance/WebScreenShot;python3 webscreenshot.py "$@"' >> /usr/bin/webscreenshot
		chmod +x /usr/bin/webscreenshot
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/WebScreenShot/*
		pip3 install -r $unk9vvn/RedTeam/Reconnaissance/WebScreenShot/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing WebScreenShot"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing WebScreenShot"
		printf "\n\n"
	fi

	# Install WhatWaf
	if [ -d "$WHATWAF" ]; then
		chmod 755 $unk9vvn/RedTeam/Reconnaissance/WhatWaf/*
		ln -f -s $unk9vvn/RedTeam/Reconnaissance/WhatWaf/whatwaf /usr/bin/whatwaf
		pip2 install -r $unk9vvn/RedTeam/Reconnaissance/WhatWaf/requirements.txt
		cd $unk9vvn/RedTeam/Reconnaissance/WhatWaf;./install_helper.sh
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing WhatWaf"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing WhatWaf"
		printf "\n\n"
	fi
}


#-------------------------------Mobile-------------------------------#


GHOST=$unk9vvn/Mobile/Ghost
DROZER=$unk9vvn/Mobile/Drozer
APKLEAKS=$unk9vvn/Mobile/APKLeaks
CHECKSTYLE=$unk9vvn/Mobile/CheckStyle
GENYMOTION=$unk9vvn/Mobile/Genymotion
MOBSF=$unk9vvn/Mobile/MobSF


Mobile()
{
	# Install APKLeaks
	if [ -d "$APKLEAKS" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/apkleaks
		echo 'USER=$(cd /home;ls)' >> /usr/bin/apkleaks
		echo 'cd '$unk9vvn'/Mobile/APKLeaks;python2 apkleaks.py "$@"' >> /usr/bin/apkleaks
		chmod +x /usr/bin/apkleaks
		chmod 755 $unk9vvn/Mobile/APKLeaks/*
		pip2 install -r $unk9vvn/Mobile/APKLeaks/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing APKLeaks"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing APKLeaks"
		printf "\n\n"
	fi

	# Install CheckStyle
	if [ -d "$CHECKSTYLE" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/checkstyle
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/checkstyle
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/checkstyle
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/checkstyle
		echo 'USER=$(cd /home;ls)' >> /usr/bin/checkstyle
		echo 'cd '$unk9vvn'/Mobile/CheckStyle;java -jar checkstyle-8.36.2-all.jar "$@"' >> /usr/bin/checkstyle
		chmod +x /usr/bin/checkstyle
		chmod 755 $unk9vvn/Mobile/CheckStyle/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CheckStyle"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CheckStyle"
		printf "\n\n"
	fi

	# Install Drozer
	if [ -d "$DROZER" ]; then
		chmod 755 $unk9vvn/Mobile/Drozer/*
		dpkg -i $unk9vvn/Mobile/Drozer/drozer_2.4.4.deb
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Drozer"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Drozer"
		printf "\n\n"
	fi

	# Install Genymotion
	if [ -d "$GENYMOTION" ]; then
		chmod 755 $unk9vvn/Mobile/Genymotion/*
		cd $unk9vvn/Mobile/Genymotion;./genymotion-3.1.1-linux_x64.bin -y
		ln -f -s $unk9vvn/Mobile/Genymotion/Genymotion_ARM_Translation/tools/install-ssl.sh /usr/bin/arm-ssl
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Genymotion"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Genymotion"
		printf "\n\n"
	fi

	# Install Ghost
	if [ -d "$GHOST" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/ghost
		echo 'USER=$(cd /home;ls)' >> /usr/bin/ghost
		echo 'cd '$unk9vvn'/Mobile/Ghost;python3 ghost.py "$@"' >> /usr/bin/ghost
		chmod +x /usr/bin/ghost
		chmod 755 $unk9vvn/Mobile/Ghost/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Ghost"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Ghost"
		printf "\n\n"
	fi

	# Install MobSF
	if [ -d "$MOBSF" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/mobsf
		echo 'USER=$(cd /home;ls)' >> /usr/bin/mobsf
		echo 'cd '$unk9vvn'/Mobile/MobSF;./run.sh > /dev/null &' >> /usr/bin/mobsf
		echo 'sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &' >> /usr/bin/mobsf
		chmod +x /usr/bin/mobsf
		chmod 755 $unk9vvn/Mobile/MobSF/*
		cd $unk9vvn/Mobile/MobSF;./setup.sh
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing MobSF"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing MobSF"
		printf "\n\n"
	fi

	Install and Setup
python3 -m venv venv
source venv/bin/activate
pip install mobsf
mobsfdb # migrate database
Run
mobsf 127.0.0.1:8000 # run mobsf
}


#-------------------------------Network-------------------------------#


IEF=$unk9vvn/Network/IEF
GTSCAN=$unk9vvn/Network/GTScan
ANGRY_IP=$unk9vvn/Network/Angry-IP
CREDNINJA=$unk9vvn/Network/CredNinja
QMODMASTER=$unk9vvn/Network/qModMaster
HLR_LOOKUPS=$unk9vvn/Network/HLR-Lookups
ROUTERSCAN=$unk9vvn/Network/RouterScan
SNMPBRUTE=$unk9vvn/Network/SNMPBrute
MODBUSPAL=$unk9vvn/Network/ModbusPal
NETTOOLS=$unk9vvn/Network/NetTools
NLBRUTE=$unk9vvn/Network/NLBrute
MODSCAN=$unk9vvn/Network/ModScan
WPSPIN=$unk9vvn/Network/WPSpin
S7SCAN=$unk9vvn/Network/S7Scan
PUTTY=$unk9vvn/Network/PuTTY
SMOD=$unk9vvn/Network/SMOD
PRET=$unk9vvn/Network/PRET


Network()
{
	# Install Angry-IP
	if [ -d "$ANGRY_IP" ]; then
		chmod 755 $unk9vvn/Network/Angry-IP/*
		dpkg -i $unk9vvn/Network/Angry-IP/ipscan_3.7.2_amd64.deb
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Angry-IP"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Angry-IP"
		printf "\n\n"
	fi

	# Install CredNinja
	if [ -d "$CREDNINJA" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/credninja
		echo 'USER=$(cd /home;ls)' >> /usr/bin/credninja
		echo 'cd '$unk9vvn'/Network/CredNinja;python3 CredNinja.py "$@"' >> /usr/bin/credninja
		chmod +x /usr/bin/credninja
		chmod 755 $unk9vvn/Network/CredNinja/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CredNinja"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CredNinja"
		printf "\n\n"
	fi

	# Install GTScan
	if [ -d "$GTSCAN" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/gtscan
		echo 'USER=$(cd /home;ls)' >> /usr/bin/gtscan
		echo 'cd '$unk9vvn'/Network/GTScan;python3 GTScan.py "$@"' >> /usr/bin/gtscan
		chmod +x /usr/bin/gtscan
		chmod 755 $unk9vvn/Network/GTScan/*
		pip3 install -r $unk9vvn/Network/GTScan/requirements.txt
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing GTScan"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing GTScan"
		printf "\n\n"
	fi

	# Install HLR-Lookups
	if [ -d "$HLR_LOOKUPS" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/hlrlookups
		echo 'USER=$(cd /home;ls)' >> /usr/bin/hlrlookups
		echo 'cd '$unk9vvn'/Network/HLR-Lookups;python2 hlr-lookups.py "$@"' >> /usr/bin/hlrlookups
		chmod +x /usr/bin/hlrlookups
		chmod 755 $unk9vvn/Network/HLR-Lookups/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing HLR-Lookups"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing HLR-Lookups"
		printf "\n\n"
	fi

	# Install ICS Exploitation Framework
	if [ -d "$IEF" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/isf
		echo 'USER=$(cd /home;ls)' >> /usr/bin/isf
		echo 'cd '$unk9vvn'/Network/IEF;python2 isf.py "$@"' >> /usr/bin/isf
		chmod +x /usr/bin/isf
		chmod 755 $unk9vvn/Network/IEF/*
		pip2 install -r $unk9vvn/Network/IEF/requirements.txt
		pip2 uninstall pyopenssl -y
		pip2 install pyopenssl
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing ICS Exploitation Framework"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing ICS Exploitation Framework"
		printf "\n\n"
	fi

	# Install ModbusPal
	if [ -d "$MODBUSPAL" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/modbuspal
		echo 'USER=$(cd /home;ls)' >> /usr/bin/modbuspal
		echo 'cd '$unk9vvn'/Network/ModbusPal;java -jar ModbusPal.jar "$@"' >> /usr/bin/modbuspal
		chmod +x /usr/bin/modbuspal
		chmod 755 $unk9vvn/Network/ModbusPal/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing ModbusPal"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing ModbusPal"
		printf "\n\n"
	fi

	# Install ModScan
	if [ -d "$MODSCAN" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/modscan
		echo 'USER=$(cd /home;ls)' >> /usr/bin/modscan
		echo 'cd '$unk9vvn'/Network/ModScan;python2 modscan.py "$@"' >> /usr/bin/modscan
		chmod +x /usr/bin/modscan
		chmod 755 $unk9vvn/Network/ModScan/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing ModScan"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing ModScan"
		printf "\n\n"
	fi

	# Install NetTools
	if [ -d "$NETTOOLS" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/nettools
		echo 'USER=$(cd /home;ls)' >> /usr/bin/nettools
		echo 'cd '$unk9vvn'/Network/NetTools;wine NetTools.exe "$@"' >> /usr/bin/nettools
		chmod +x /usr/bin/nettools
		chmod 755 $unk9vvn/Network/NetTools/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing NetTools"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing NetTools"
		printf "\n\n"
	fi

	# Install NLBrute
	if [ -d "$NLBRUTE" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/nlbrute
		echo 'USER=$(cd /home;ls)' >> /usr/bin/nlbrute
		echo 'cd '$unk9vvn'/Network/NLBrute;wine NLBrute.exe "$@"' >> /usr/bin/nlbrute
		chmod +x /usr/bin/nlbrute
		chmod 755 $unk9vvn/Network/NLBrute/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing NLBrute"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing NLBrute"
		printf "\n\n"
	fi

	# Install PRET
	if [ -d "$PRET" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/pret
		echo 'USER=$(cd /home;ls)' >> /usr/bin/pret
		echo 'cd '$unk9vvn'/Network/PRET;python2 pret.py "$@"' >> /usr/bin/pret
		chmod +x /usr/bin/pret
		chmod 755 $unk9vvn/Network/PRET/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PRET"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PRET"
		printf "\n\n"
	fi

	# Install PuTTY
	if [ -d "$PUTTY" ]; then
		chmod 755 $unk9vvn/Network/PuTTY/*
		wine msiexec /i /s $unk9vvn/Network/PuTTY/putty-64bit-0.74-installer.msi
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PuTTY"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PuTTY"
		printf "\n\n"
	fi

	# Install qModMaster
	if [ -d "$QMODMASTER" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/qmodmaster
		echo 'USER=$(cd /home;ls)' >> /usr/bin/qmodmaster
		echo 'cd '$unk9vvn'/Network/qModMaster;wine qModMaster.exe "$@"' >> /usr/bin/qmodmaster
		chmod +x /usr/bin/qmodmaster
		chmod 755 $unk9vvn/Network/qModMaster/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing qModMaster"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing qModMaster"
		printf "\n\n"
	fi

	# Install RouterScan
	if [ -d "$ROUTERSCAN" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/routerscan
		echo 'USER=$(cd /home;ls)' >> /usr/bin/routerscan
		echo 'cd '$unk9vvn'/Network/RouterScan;wine RouterScan.exe "$@"' >> /usr/bin/routerscan
		chmod +x /usr/bin/routerscan
		chmod 755 $unk9vvn/Network/RouterScan/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing RouterScan"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing RouterScan"
		printf "\n\n"
	fi

	# Install S7Scan
	if [ -d "$S7SCAN" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/s7scan
		echo 'USER=$(cd /home;ls)' >> /usr/bin/s7scan
		echo 'cd '$unk9vvn'/Network/S7Scan;python2 s7scan.py "$@"' >> /usr/bin/s7scan
		chmod +x /usr/bin/s7scan
		chmod 755 $unk9vvn/Network/S7Scan/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing S7Scan"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing S7Scan"
		printf "\n\n"
	fi

	# Install SMOD
	if [ -d "$SMOD" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/smod
		echo 'USER=$(cd /home;ls)' >> /usr/bin/smod
		echo 'cd '$unk9vvn'/Network/SMOD;python2 smod.py "$@"' >> /usr/bin/smod
		chmod +x /usr/bin/smod
		chmod 755 $unk9vvn/Network/SMOD/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing SMOD"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing SMOD"
		printf "\n\n"
	fi

	# Install SNMPBrute
	if [ -d "$SNMPBRUTE" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/snmpbrute
		echo 'USER=$(cd /home;ls)' >> /usr/bin/snmpbrute
		echo 'cd '$unk9vvn'/Network/SNMPBrute;python2 snmp-brute.py "$@"' >> /usr/bin/snmpbrute
		chmod +x /usr/bin/snmpbrute
		chmod 755 $unk9vvn/Network/SNMPBrute/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing SNMPBrute"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing SNMPBrute"
		printf "\n\n"
	fi

	# Install WPSpin
	if [ -d "$WPSPIN" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/wpspin
		echo 'USER=$(cd /home;ls)' >> /usr/bin/wpspin
		echo 'cd '$unk9vvn'/Network/WPSpin;bash WPSPIN.sh "$@"' >> /usr/bin/wpspin
		chmod +x /usr/bin/wpspin
		chmod 755 $unk9vvn/Network/WPSpin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing WPSpin"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing WPSpin"
		printf "\n\n"
	fi
}


#-------------------------------Others-------------------------------#


SKYPE=$unk9vvn/Others/Skype
PHOTOINSTRUMENT=$unk9vvn/Others/PhotoInstrument-7


Others()
{
	# Install PhotoInstrument
	if [ -d "$PHOTOINSTRUMENT" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/photoinstrument
		echo 'USER=$(cd /home;ls)' >> /usr/bin/photoinstrument
		echo 'cd '$unk9vvn'/Others/PhotoInstrument-7;wine64 PhotoInstrument.exe "$@"' >> /usr/bin/photoinstrument
		chmod +x /usr/bin/photoinstrument
		chmod 755 $unk9vvn/Others/PhotoInstrument-7/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PhotoInstrument 7"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PhotoInstrument 7"
		printf "\n\n"
	fi

	# Install Skype
	if [ -d "$SKYPE" ]; then
		chmod 755 $unk9vvn/Others/PhotoInstrument/*
		dpkg -i $unk9vvn/Others/Skype/skypeforlinux-64.deb
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Skype"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Skype"
		printf "\n\n"
	fi
}


#-------------------------------Programming-------------------------------#


CLION=$unk9vvn/Programming/CLion-2020.1
GOLAND=$unk9vvn/Programming/GoLand-2020.1
PYCHARM=$unk9vvn/Programming/PyCharm-2020.1
RUBYMINE=$unk9vvn/Programming/RubyMine-2020.1
PHPSTORM=$unk9vvn/Programming/PhpStorm-2020.1
WEBSTORM=$unk9vvn/Programming/WebStorm-2020.1
EMU8086=$unk9vvn/Programming/emu8086-v4.08
RIDER=$unk9vvn/Programming/Rider-2020.1
IDEA=$unk9vvn/Programming/IDEA-2020.1
VSCODE=$unk9vvn/Programming/VSCode
CMDER=$unk9vvn/Programming/Cmder


Programming()
{
	# Install Cmder
	if [ -d "$CMDER" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/cmder
		echo 'USER=$(cd /home;ls)' >> /usr/bin/cmder
		echo 'cd '$unk9vvn'/Programming/Cmder;wine Cmder.exe "$@"' >> /usr/bin/cmder
		chmod +x /usr/bin/cmder
		chmod 755 $unk9vvn/Programming/Cmder/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Cmder"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Cmder"
		printf "\n\n"
	fi

	# Install emu8086-v4.08
	if [ -d "$EMU8086" ]; then
		chmod 755 $unk9vvn/Programming/emu8086-v4.08/*
		wine cd '$unk9vvn'/Programming/emu8086-v4.08;wine Setup.exe
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing emu8086-v4.08"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing emu8086-v4.08"
		printf "\n\n"
	fi

	# Install VSCode
	if [ -d "$VSCODE" ]; then
		chmod 755 $unk9vvn/Programming/VSCode/*
		dpkg -i $unk9vvn/Programming/VSCode/code_amd64.deb
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing VSCode"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing VSCode"
		printf "\n\n"
	fi

	# Install CLion 2020.1
	if [ -d "$CLION" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/clion
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/clion
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/clion
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/clion
		echo 'USER=$(cd /home;ls)' >> /usr/bin/clion
		echo 'cd '$unk9vvn'/Programming/CLion-2020.1/bin;bash clion.sh "$@"' >> /usr/bin/clion
		chmod +x /usr/bin/clion
		chmod 755 $unk9vvn/Programming/CLion-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing CLion 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing CLion 2020.1"
		printf "\n\n"
	fi

	# Install GoLand 2020.1
	if [ -d "$GOLAND" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/goland
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/goland
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/goland
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/goland
		echo 'USER=$(cd /home;ls)' >> /usr/bin/goland
		echo 'cd '$unk9vvn'/Programming/GoLand-2020.1/bin;bash goland.sh "$@"' >> /usr/bin/goland
		chmod +x /usr/bin/goland
		chmod 755 $unk9vvn/Programming/GoLand-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing GoLand 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing GoLand 2020.1"
		printf "\n\n"
	fi

	# Install PyCharm 2020.1
	if [ -d "$PYCHARM" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/pycharm
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/pycharm
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/pycharm
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/pycharm
		echo 'USER=$(cd /home;ls)' >> /usr/bin/pycharm
		echo 'cd '$unk9vvn'/Programming/PyCharm-2020.1/bin;bash pycharm.sh "$@"' >> /usr/bin/pycharm
		chmod +x /usr/bin/pycharm
		chmod 755 $unk9vvn/Programming/PyCharm-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PyCharm 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PyCharm 2020.1"
		printf "\n\n"
	fi

	# Install RubyMine 2020.1
	if [ -d "$RUBYMINE" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/rubymine
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/rubymine
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/rubymine
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/rubymine
		echo 'USER=$(cd /home;ls)' >> /usr/bin/rubymine
		echo 'cd '$unk9vvn'/Programming/RubyMine-2020.1/bin;bash rubymine.sh "$@"' >> /usr/bin/rubymine
		chmod +x /usr/bin/rubymine
		chmod 755 $unk9vvn/Programming/RubyMine-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing RubyMine 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing RubyMine 2020.1"
		printf "\n\n"
	fi

	# Install PhpStorm 2020.1
	if [ -d "$PHPSTORM" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/phpstorm
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/phpstorm
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/phpstorm
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/phpstorm
		echo 'USER=$(cd /home;ls)' >> /usr/bin/phpstorm
		echo 'cd '$unk9vvn'/Programming/PhpStorm-2020.1/bin;bash phpstorm.sh "$@"' >> /usr/bin/phpstorm
		chmod +x /usr/bin/phpstorm
		chmod 755 $unk9vvn/Programming/PhpStorm-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing PhpStorm 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing PhpStorm 2020.1"
		printf "\n\n"
	fi

	# Install WebStorm 2020.1
	if [ -d "$WEBSTORM" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/webstorm
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/webstorm
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/webstorm
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/webstorm
		echo 'USER=$(cd /home;ls)' >> /usr/bin/webstorm
		echo 'cd '$unk9vvn'/Programming/WebStorm-2020.1/bin;bash webstorm.sh "$@"' >> /usr/bin/webstorm
		chmod +x /usr/bin/webstorm
		chmod 755 $unk9vvn/Programming/WebStorm-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing WebStorm 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing WebStorm 2020.1"
		printf "\n\n"
	fi

	# Install Rider 2020.1
	if [ -d "$RIDER" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/rider
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/rider
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/rider
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/rider
		echo 'USER=$(cd /home;ls)' >> /usr/bin/rider
		echo 'cd '$unk9vvn'/Programming/Rider-2020.1/bin;bash rider.sh "$@"' >> /usr/bin/rider
		chmod +x /usr/bin/rider
		chmod 755 $unk9vvn/Programming/Rider-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing Rider 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing Rider 2020.1"
		printf "\n\n"
	fi

	# Install IDEA 2020.1
	if [ -d "$IDEA" ]; then
		SHELL='#!'
		echo ''$SHELL'/bin/bash' > /usr/bin/idea
		echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/idea
		echo 'unset _JAVA_OPTIONS' >> /usr/bin/idea
		echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/idea
		echo 'USER=$(cd /home;ls)' >> /usr/bin/idea
		echo 'cd '$unk9vvn'/Programming/IDEA-2020.1/bin;bash idea.sh "$@"' >> /usr/bin/idea
		chmod +x /usr/bin/idea
		chmod 755 $unk9vvn/Programming/IDEA-2020.1/bin/*
		printf "\n\n"
		printf "$GREEN"  "[*] Sucess Installing IDEA 2020.1"
		printf "\n\n"
	else
		printf "\n\n"
		printf "$RED"    "[x] Failed Installing IDEA 2020.1"
		printf "\n\n"
	fi
}


#-------------------------------RedTeam-------------------------------#


RedTeam()
{
	POWERPUNCH=$unk9vvn/RedTeam/Collection/PowerPunch


	Collection()
	{
		# Install PowerPunch
		if [ -d "$POWERPUNCH" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/powerpunch
			echo 'USER=$(cd /home;ls)' >> /usr/bin/powerpunch
			echo 'cd '$unk9vvn'/RedTeam/Collection/PowerPunch;ls "$@"' >> /usr/bin/powerpunch
			chmod +x /usr/bin/powerpunch
			chmod 755 $unk9vvn/RedTeam/Collection/PowerPunch/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing PowerPunch"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing PowerPunch"
			printf "\n\n"
		fi
	}
	Collection


	COVENANT=$unk9vvn/RedTeam/Command-and-Control/Covenant
	COBALT_STRIKE=$unk9vvn/RedTeam/Command-and-Control/Cobalt-Strike-3.8
	EGGSHELL=$unk9vvn/RedTeam/Command-and-Control/EggShell
	EVILOSX=$unk9vvn/RedTeam/Command-and-Control/EvilOSX
	PHPSPLOIT=$unk9vvn/RedTeam/Command-and-Control/PHPSploit
	PUPY=$unk9vvn/RedTeam/Command-and-Control/Pupy
	PARAT=$unk9vvn/RedTeam/Command-and-Control/Parat
	KOADIC=$unk9vvn/RedTeam/Command-and-Control/Koadic
	VEGILE=$unk9vvn/RedTeam/Command-and-Control/Vegile
	WSC2=$unk9vvn/RedTeam/Command-and-Control/WSC2


	Command_and_Control()
	{
		# Install Cobalt-Strike 3.8
		if [ -d "$COBALT_STRIKE" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/colbaltstrike
			echo 'USER=$(cd /home;ls)' >> /usr/bin/colbaltstrike
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/Cobalt-Strike-3.8;./teamserver "'$LAN'" 123456789 > /dev/null & "$@"' >> /usr/bin/colbaltstrike
			echo "ps -ef | grep teamserver | grep -v grep | awk '{print $2}' | sudo xargs kill" >> /usr/bin/colbaltstrike
			chmod +x /usr/bin/colbaltstrike
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/Cobalt-Strike-3.8/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Cobalt-Strike 3.8"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Cobalt-Strike 3.8"
			printf "\n\n"
		fi

		# Install EggShell
		if [ -d "$EGGSHELL" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/eggshell
			echo 'USER=$(cd /home;ls)' >> /usr/bin/eggshell
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/EggShell;python2 eggshell.py "$@"' >> /usr/bin/eggshell
			chmod +x /usr/bin/eggshell
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/EggShell/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing EggShell"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing EggShell"
			printf "\n\n"
		fi

		# Install EvilOSX
		if [ -d "$EVILOSX" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/evilosx
			echo 'USER=$(cd /home;ls)' >> /usr/bin/evilosx
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/EvilOSX;python3 start.py "$@"' >> /usr/bin/evilosx
			chmod +x /usr/bin/evilosx
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/EvilOSX/*
			pip3 install -r $unk9vvn/RedTeam/Command-and-Control/EvilOSX/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing EvilOSX"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing EvilOSX"
			printf "\n\n"
		fi

		# Install Koadic
		if [ -d "$KOADIC" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/koadic
			echo 'USER=$(cd /home;ls)' >> /usr/bin/koadic
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/Koadic;python3 koadic.py "$@"' >> /usr/bin/koadic
			chmod +x /usr/bin/koadic
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/Koadic/*
			pip3 install -r $unk9vvn/RedTeam/Command-and-Control/Koadic/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Koadic"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Koadic"
			printf "\n\n"
		fi

		# Install Parat
		if [ -d "$PARAT" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/parat
			echo 'USER=$(cd /home;ls)' >> /usr/bin/parat
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/Parat;python2 main.py "$@"' >> /usr/bin/parat
			chmod +x /usr/bin/parat
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/Parat/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Parat"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Parat"
			printf "\n\n"
		fi

		# Install PHPSploit
		if [ -d "$PHPSPLOIT" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/phpsploit
			echo 'USER=$(cd /home;ls)' >> /usr/bin/phpsploit
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/PHPSploit;python3 phpsploit.py "$@"' >> /usr/bin/phpsploit
			chmod +x /usr/bin/phpsploit
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/PHPSploit/*
			pip3 install -r $unk9vvn/RedTeam/Command-and-Control/PHPSploit/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing PHPSploit"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing PHPSploit"
			printf "\n\n"
		fi

		# Install Pupy
		if [ -d "$PUPY" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/pupygen
			echo 'USER=$(cd /home;ls)' >> /usr/bin/pupygen
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/Pupy/pupy;python2 pupygen.py "$@"' >> /usr/bin/pupygen
			chmod +x /usr/bin/pupygen
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/pupysh
			echo 'USER=$(cd /home;ls)' >> /usr/bin/pupysh
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/Pupy/pupy;python2 pupysh.py "$@"' >> /usr/bin/pupysh
			chmod +x /usr/bin/pupysh
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/Pupy/*
			cd $unk9vvn/RedTeam/Command-and-Control/Pupy;./install
			pip2 install -r $unk9vvn/RedTeam/Command-and-Control/Pupy/pupy/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Pupy"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Pupy"
			printf "\n\n"
		fi

		# Install Vegile
		if [ -d "$VEGILE" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/vegile
			echo 'USER=$(cd /home;ls)' >> /usr/bin/vegile
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/Vegile;./Vegile.sh "$@"' >> /usr/bin/vegile
			chmod +x /usr/bin/vegile
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/Vegile/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Vegile"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Vegile"
			printf "\n\n"
		fi

		# Install WSC2
		if [ -d "$WSC2" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/wsc2
			echo 'USER=$(cd /home;ls)' >> /usr/bin/wsc2
			echo 'cd '$unk9vvn'/RedTeam/Command-and-Control/WSC2;python2 wsc2.py "$@"' >> /usr/bin/wsc2
			chmod +x /usr/bin/wsc2
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/WSC2/*
			pip2 install -r $unk9vvn/RedTeam/Command-and-Control/WSC2/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing WSC2"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing WSC2"
			printf "\n\n"
		fi

		# Install Covenant
		if [ -d "$COVENANT" ]; then
			chmod 755 $unk9vvn/RedTeam/Command-and-Control/Covenant/Covenant/bin/Debug/netcoreapp3.1/*
			ln -f -s $unk9vvn/RedTeam/Command-and-Control/Covenant/Covenant/bin/Debug/netcoreapp3.1/Covenant /usr/bin/covenant
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Covenant"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Covenant"
			printf "\n\n"
		fi
	}
	Command_and_Control


	KERBEROAST=$unk9vvn/RedTeam/Credential-Access/Kerberoast
	KERBRUTE=$unk9vvn/RedTeam/Credential-Access/KerBrute
	MIMIPENGUIN=$unk9vvn/RedTeam/Credential-Access/mimipenguin
	NTLMRELAYTOEWS=$unk9vvn/RedTeam/Credential-Access/NtlmRelayToEWS
	NETRIPPER=$unk9vvn/RedTeam/Credential-Access/NetRipper


	Credential_Access()
	{
		# Install Kerberoast
		if [ -d "$KERBEROAST" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/kerberoast
			echo 'USER=$(cd /home;ls)' >> /usr/bin/kerberoast
			echo 'cd '$unk9vvn'/RedTeam/Credential-Access/Kerberoast;python3 kerberoast.py "$@"' >> /usr/bin/kerberoast
			chmod +x /usr/bin/kerberoast
			chmod 755 $unk9vvn/RedTeam/Credential-Access/Kerberoast/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Kerberoast"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Kerberoast"
			printf "\n\n"
		fi

		# Install NtlmRelayToEWS
		if [ -d "$NTLMRELAYTOEWS" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/ntlmrelaytoews
			echo 'USER=$(cd /home;ls)' >> /usr/bin/ntlmrelaytoews
			echo 'cd '$unk9vvn'/RedTeam/Credential-Access/NtlmRelayToEWS;python2 ntlmRelayToEWS.py "$@"' >> /usr/bin/ntlmrelaytoews
			chmod +x /usr/bin/ntlmrelaytoews
			chmod 755 $unk9vvn/RedTeam/Credential-Access/NtlmRelayToEWS/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing NtlmRelayToEWS"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing NtlmRelayToEWS"
			printf "\n\n"
		fi

		# Install KerBrute
		if [ -d "$KERBRUTE" ]; then
			chmod 755 $unk9vvn/RedTeam/Credential-Access/KerBrute/*
			ln -f -s $unk9vvn/RedTeam/Credential-Access/KerBrute/kerbrute_linux_amd64 /usr/bin/kerbrute
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing KerBrute"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing KerBrute"
			printf "\n\n"
		fi

		# Install mimipenguin
		if [ -d "$KERBRUTE" ]; then
			chmod 755 $unk9vvn/RedTeam/Credential-Access/mimipenguin/*
			ln -f -s $unk9vvn/RedTeam/Credential-Access/mimipenguin/mimipenguin /usr/bin/mimipenguin
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing mimipenguin"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing mimipenguin"
			printf "\n\n"
		fi

		# Install NetRipper
		if [ -d "$NETRIPPER" ]; then
			chmod 755 $unk9vvn/RedTeam/Discovery/NetRipper/*
			mkdir /usr/share/metasploit-framework/modules/post/windows/gather/netripper
			cp $unk9vvn/RedTeam/Discovery/NetRipper/Metasploit/netripper.rb /usr/share/metasploit-framework/modules/post/windows/gather/netripper/netripper.rb
			cp $unk9vvn/RedTeam/Discovery/NetRipper/x86/DLL.x86.dll /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.x86.dll
			cp $unk9vvn/RedTeam/Discovery/NetRipper/x64/DLL.x64.dll /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.x64.dll
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing NetRipper"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing NetRipper"
			printf "\n\n"
		fi
	}
	Credential_Access


	AMBER=$unk9vvn/RedTeam/Defense-Evasion/Amber
	ELFCRYPT=$unk9vvn/RedTeam/Defense-Evasion/ELFcrypt
	ASWCRYPTER=$unk9vvn/RedTeam/Defense-Evasion/ASWCrypter
	EMBEDINHTML=$unk9vvn/RedTeam/Defense-Evasion/EmbedInHTML
	EXE_CONVERTOR=$unk9vvn/RedTeam/Defense-Evasion/EXE-Convertor
	OBFUSCATION=$unk9vvn/RedTeam/Defense-Evasion/Invoke-Obfuscation
	CREDLECRAFTER=$unk9vvn/RedTeam/Defense-Evasion/Invoke-CradleCrafter
	REVOKE_OBFUSCATION=$unk9vvn/RedTeam/Defense-Evasion/Revoke-Obfuscation
	SHELLCODEWRAPPER=$unk9vvn/RedTeam/Defense-Evasion/ShellcodeWrapper
	SCRIPTCRYPTOR=$unk9vvn/RedTeam/Defense-Evasion/ScriptCryptor
	SYSWHISPERS=$unk9vvn/RedTeam/Defense-Evasion/SysWhispers
	POWERLESSSHELL=$unk9vvn/RedTeam/Defense-Evasion/PowerLessShell
	PHANTOM_EVASION=$unk9vvn/RedTeam/Defense-Evasion/Phantom-Evasion
	DOSFUSCATION=$unk9vvn/RedTeam/Defense-Evasion/Invoke-DOSfuscation
	SHARPSHOOTER=$unk9vvn/RedTeam/Defense-Evasion/SharpShooter
	DR0P1T=$unk9vvn/RedTeam/Defense-Evasion/Dr0p1t-Framework
	SPOOKFLARE=$unk9vvn/RedTeam/Defense-Evasion/SpookFlare
	DEMIGUISE=$unk9vvn/RedTeam/Defense-Evasion/Demiguise
	UNICORN=$unk9vvn/RedTeam/Defense-Evasion/Unicorn
	WINRAR=$unk9vvn/RedTeam/Defense-Evasion/WinRAR-5
	VENOM=$unk9vvn/RedTeam/Defense-Evasion/venom
	AVET=$unk9vvn/RedTeam/Defense-Evasion/AVET


	Defense_Evasion()
	{
		# Install Amber
		if [ -d "$AMBER" ]; then
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Amber/*
			ln -f -s $unk9vvn/RedTeam/Defense-Evasion/Amber/amber /usr/bin/amber
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Amber"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Amber"
			printf "\n\n"
		fi

		# Install ASWCrypter
		if [ -d "$ASWCRYPTER" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/aswcrypter
			echo 'USER=$(cd /home;ls)' >> /usr/bin/aswcrypter
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/ASWCrypter;bash ASWCrypter.sh "$@"' >> /usr/bin/aswcrypter
			chmod +x /usr/bin/aswcrypter
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/ASWCrypter/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ASWCrypter"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ASWCrypter"
			printf "\n\n"
		fi

		# Install AVET
		if [ -d "$AVET" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/avet
			echo 'USER=$(cd /home;ls)' >> /usr/bin/avet
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/AVET;python3 avet.py "$@"' >> /usr/bin/avet
			chmod +x /usr/bin/avet
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/AVET/*
			cd $unk9vvn/RedTeam/Defense-Evasion/AVET;./setup.sh
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing AVET"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing AVET"
			printf "\n\n"
		fi

		# Install Demiguise
		if [ -d "$DEMIGUISE" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/demiquise
			echo 'USER=$(cd /home;ls)' >> /usr/bin/demiquise
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/Demiguise;python2 demiquise.py "$@"' >> /usr/bin/demiquise
			chmod +x /usr/bin/demiquise
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Demiguise/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Demiguise"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Demiguise"
			printf "\n\n"
		fi

		# Install Dr0p1t-Framework
		if [ -d "$DR0P1T" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/dr0p1t
			echo 'USER=$(cd /home;ls)' >> /usr/bin/dr0p1t
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/Dr0p1t-Framework;python3 Dr0p1t.py "$@"' >> /usr/bin/dr0p1t
			chmod +x /usr/bin/dr0p1t
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Dr0p1t-Framework/*
			pip3 install -r $unk9vvn/RedTeam/Defense-Evasion/Dr0p1t-Framework/server_requirements.txt
			cd $unk9vvn/RedTeam/Defense-Evasion/Dr0p1t-Framework;./install.sh
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Dr0p1t-Framework"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Dr0p1t-Framework"
			printf "\n\n"
		fi

		# Install EmbedInHTML
		if [ -d "$EMBEDINHTML" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/embedinhtml
			echo 'USER=$(cd /home;ls)' >> /usr/bin/embedinhtml
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/EmbedInHTML;python2 embedInHTML.py "$@"' >> /usr/bin/embedinhtml
			chmod +x /usr/bin/embedinhtml
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/EmbedInHTML/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing EmbedInHTML"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing EmbedInHTML"
			printf "\n\n"
		fi

		# Install EXE-Convertor
		if [ -d "$EXE_CONVERTOR" ]; then
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/EXE-Convertor/*
			cd $unk9vvn/RedTeam/Defense-Evasion/EXE-Convertor;wine BAT_to_EXE.exe && wine PS1_to_EXE.exe && wine VBS_to_EXE.exe
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing EXE-Convertor"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing EXE-Convertor"
			printf "\n\n"
		fi

		# Install Invoke-CradleCrafter
		if [ -d "$CREDLECRAFTER" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/cradlecrafter
			echo 'USER=$(cd /home;ls)' >> /usr/bin/cradlecrafter
			echo "cd "$unk9vvn"/RedTeam/Defense-Evasion/Invoke-CradleCrafter;pwsh -c 'Import-Module .\\Invoke-CradleCrafter.psd1;Invoke-CradleCrafter' \"\$@\"" >> /usr/bin/cradlecrafter
			chmod +x /usr/bin/cradlecrafter
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Invoke-CradleCrafter/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Invoke-CradleCrafter"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Invoke-CradleCrafter"
			printf "\n\n"
		fi

		# Install Invoke-DOSfuscation
		if [ -d "$DOSFUSCATION" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/dosfuscation
			echo 'USER=$(cd /home;ls)' >> /usr/bin/dosfuscation
			echo "cd "$unk9vvn"/RedTeam/Defense-Evasion/Invoke-DOSfuscation;pwsh -c 'Import-Module .\\Invoke-DOSfuscation.psd1;Invoke-DOSfuscation' \"\$@\"" >> /usr/bin/dosfuscation
			chmod +x /usr/bin/dosfuscation
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Invoke-DOSfuscation/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Invoke-DOSfuscation"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Invoke-DOSfuscation"
			printf "\n\n"
		fi

		# Install Invoke-Obfuscation
		if [ -d "$OBFUSCATION" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/obfuscation
			echo 'USER=$(cd /home;ls)' >> /usr/bin/obfuscation
			echo "cd "$unk9vvn"/RedTeam/Defense-Evasion/Invoke-Obfuscation;pwsh -c 'Import-Module .\\Invoke-Obfuscation.psd1;Invoke-Obfuscation' \"\$@\"" >> /usr/bin/obfuscation
			chmod +x /usr/bin/obfuscation
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Invoke-Obfuscation/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Invoke-Obfuscation"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Invoke-Obfuscation"
			printf "\n\n"
		fi

		# Install Revoke-Obfuscation
		if [ -d "$REVOKE_OBFUSCATION" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/revokeobfuscation
			echo 'USER=$(cd /home;ls)' >> /usr/bin/revokeobfuscation
			echo "cd "$unk9vvn"/RedTeam/Defense-Evasion/Revoke-Obfuscation;pwsh -c 'Import-Module .\\Revoke-Obfuscation.psd1;Revoke-Obfuscation' \"\$@\"" >> /usr/bin/revokeobfuscation
			chmod +x /usr/bin/revokeobfuscation
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Revoke-Obfuscation/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Revoke-Obfuscation"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Revoke-Obfuscation"
			printf "\n\n"
		fi

		# Install ObfuscateCactusTorch
		if [ -d "$OBFUSCATECACTUSTORCH" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/obfusactioncactustorch
			echo 'USER=$(cd /home;ls)' >> /usr/bin/obfusactioncactustorch
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/ObfuscateCactusTorch;python2 obfuscateCactusTorch.py "$@"' >> /usr/bin/obfusactioncactustorch
			chmod +x /usr/bin/obfusactioncactustorch
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/ObfuscateCactusTorch/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ObfuscateCactusTorch"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ObfuscateCactusTorch"
			printf "\n\n"
		fi

		# Install Phantom-Evasion
		if [ -d "$PHANTOM_EVASION" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/phantom
			echo 'USER=$(cd /home;ls)' >> /usr/bin/phantom
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/Phantom-Evasion;python2 phantom-evasion.py "$@"' >> /usr/bin/phantom
			chmod +x /usr/bin/phantom
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Phantom-Evasion/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Phantom-Evasion"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Phantom-Evasion"
			printf "\n\n"
		fi

		# Install PowerLessShell
		if [ -d "$POWERLESSSHELL" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/powerlessshell
			echo 'USER=$(cd /home;ls)' >> /usr/bin/powerlessshell
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/PowerLessShell;python2 PowerLessShell.py "$@"' >> /usr/bin/powerlessshell
			chmod +x /usr/bin/powerlessshell
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/PowerLessShell/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing PowerLessShell"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing PowerLessShell"
			printf "\n\n"
		fi

		# Install SharpShooter
		if [ -d "$SHARPSHOOTER" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/sharpshooter
			echo 'USER=$(cd /home;ls)' >> /usr/bin/sharpshooter
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/SharpShooter;python2 SharpShooter.py "$@"' >> /usr/bin/sharpshooter
			chmod +x /usr/bin/sharpshooter
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/SharpShooter/*
			pip3 install -r $unk9vvn/RedTeam/Defense-Evasion/SharpShooter/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing SharpShooter"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing SharpShooter"
			printf "\n\n"
		fi

		# Install ShellcodeWrapper
		if [ -d "$SHELLCODEWRAPPER" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/shellcodewrapper
			echo 'USER=$(cd /home;ls)' >> /usr/bin/shellcodewrapper
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/ShellcodeWrapper;python2 shellcode_encoder.py "$@"' >> /usr/bin/shellcodewrapper
			chmod +x /usr/bin/shellcodewrapper
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/ShellcodeWrapper/*
			pip2 install -r $unk9vvn/RedTeam/Defense-Evasion/ShellcodeWrapper/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ShellcodeWrapper"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ShellcodeWrapper"
			printf "\n\n"
		fi

		# Install SpookFlare
		if [ -d "$SPOOKFLARE" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/spookflare
			echo 'USER=$(cd /home;ls)' >> /usr/bin/spookflare
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/SpookFlare;python2 spookflare.py "$@"' >> /usr/bin/spookflare
			chmod +x /usr/bin/spookflare
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/SpookFlare/*
			pip2 install -r $unk9vvn/RedTeam/Defense-Evasion/SpookFlare/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing SpookFlare"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing SpookFlare"
			printf "\n\n"
		fi

		# Install SysWhispers
		if [ -d "$SYSWHISPERS" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/syswhispers
			echo 'USER=$(cd /home;ls)' >> /usr/bin/syswhispers
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/SysWhispers;python3 syswhispers.py "$@"' >> /usr/bin/syswhispers
			chmod +x /usr/bin/syswhispers
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/SysWhispers/*
			pip3 install -r $unk9vvn/RedTeam/Defense-Evasion/SysWhispers/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing SysWhispers"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing SysWhispers"
			printf "\n\n"
		fi

		# Install Unicorn
		if [ -d "$UNICORN" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/unicorn
			echo 'USER=$(cd /home;ls)' >> /usr/bin/unicorn
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/Unicorn;python2 unicorn.py "$@"' >> /usr/bin/unicorn
			chmod +x /usr/bin/unicorn
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/Unicorn/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Unicorn"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Unicorn"
			printf "\n\n"
		fi

		# Install venom
		if [ -d "$VENOM" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/venom
			echo 'USER=$(cd /home;ls)' >> /usr/bin/venom
			echo 'cd '$unk9vvn'/RedTeam/Defense-Evasion/venom;bash venom.sh "$@"' >> /usr/bin/venom
			chmod +x /usr/bin/venom
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/venom/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing venom"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing venom"
			printf "\n\n"
		fi

		# Install ScriptCryptor
		if [ -d "$SCRIPTCRYPTOR" ]; then
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/ScriptCryptor/*
			cd $unk9vvn/RedTeam/Defense-Evasion/ScriptCryptor;wine scriptcryptor.exe
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ScriptCryptor"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ScriptCryptor"
			printf "\n\n"
		fi

		# Install WinRAR-5
		if [ -d "$WINRAR" ]; then
			chmod 755 $unk9vvn/RedTeam/Defense-Evasion/WinRAR-5/*
			cd $unk9vvn/RedTeam/Defense-Evasion/WinRAR-5;wine Setup.exe
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing WinRAR-5"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing WinRAR-5"
			printf "\n\n"
		fi
	}
	Defense_Evasion


	GODDI=$unk9vvn/RedTeam/Discovery/goddi
	SPECTRE=$unk9vvn/RedTeam/Discovery/spectre-meltdown-checker
	ADEXPLORER=$unk9vvn/RedTeam/Discovery/AdExplorer
	ADOFFLINE=$unk9vvn/RedTeam/Discovery/ADOffline


	Discovery()
	{
		# Install goddi
		if [ -d "$GODDI" ]; then
			chmod 755 $unk9vvn/RedTeam/Discovery/goddi/*
			ln -f -s $unk9vvn/RedTeam/Discovery/goddi/goddi /usr/bin/goddi
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing goddi"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing goddi"
			printf "\n\n"
		fi

		# Install spectre-meltdown-checker
		if [ -d "$SPECTRE" ]; then
			chmod 755 $unk9vvn/RedTeam/Discovery/spectre-meltdown-checker/*
			ln -f -s $unk9vvn/RedTeam/Discovery/spectre-meltdown-checker/spectre-meltdown-checker.sh /usr/bin/spectre
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing spectre-meltdown-checker"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing spectre-meltdown-checker"
			printf "\n\n"
		fi

		# Install AdExplorer
		if [ -d "$ADEXPLORER" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/adexplorer
			echo 'USER=$(cd /home;ls)' >> /usr/bin/adexplorer
			echo 'cd '$unk9vvn'/RedTeam/Discovery/AdExplorer;wine ADExplorer.exe "$@"' >> /usr/bin/adexplorer
			chmod +x /usr/bin/adexplorer
			chmod 755 $unk9vvn/RedTeam/Discovery/AdExplorer/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing AdExplorer"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing AdExplorer"
			printf "\n\n"
		fi

		# Install ADOffline
		if [ -d "$ADOFFLINE" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/adoffline
			echo 'USER=$(cd /home;ls)' >> /usr/bin/adoffline
			echo 'cd '$unk9vvn'/RedTeam/Discovery/ADOffline;python2 adoffline.py "$@"' >> /usr/bin/adoffline
			chmod +x /usr/bin/adoffline
			chmod 755 $unk9vvn/RedTeam/Discovery/ADOffline/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ADOffline"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ADOffline"
			printf "\n\n"
		fi
	}
	Discovery


	DONUT=$unk9vvn/RedTeam/Execution/Donut
	BADPDF=$unk9vvn/RedTeam/Execution/BadPDF
	SCSHELL=$unk9vvn/RedTeam/Execution/SCShell
	WEBDAVDELIVERY=$unk9vvn/RedTeam/Execution/WebDavDelivery
	AUTO_SETTINGCONTENT=$unk9vvn/RedTeam/Execution/auto_SettingContent-ms
	CACTUSTORCH_DDEAUTO=$unk9vvn/RedTeam/Execution/CACTUSTORCH_DDEAUTO
	NPS_PAYLOAD=$unk9vvn/RedTeam/Execution/nps_payload
	DNSDELIVERY=$unk9vvn/RedTeam/Execution/DNSDelivery
	EXPLOITPACK=$unk9vvn/RedTeam/Execution/ExploitPack
	LNKUP=$unk9vvn/RedTeam/Execution/LNKUp


	Execution()
	{
		# Install auto_SettingContent-ms
		if [ -d "$AUTO_SETTINGCONTENT" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/settingContent-ms
			echo 'USER=$(cd /home;ls)' >> /usr/bin/settingContent-ms
			echo 'cd '$unk9vvn'/RedTeam/Execution/auto_SettingContent-ms;python2 auto_settingcontent-ms.py "$@"' >> /usr/bin/settingContent-ms
			chmod +x /usr/bin/settingContent-ms
			chmod 755 $unk9vvn/RedTeam/Execution/auto_SettingContent-ms/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing auto_SettingContent-ms"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing auto_SettingContent-ms"
			printf "\n\n"
		fi

		# Install BadPDF
		if [ -d "$BADPDF" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/badpdf
			echo 'USER=$(cd /home;ls)' >> /usr/bin/badpdf
			echo 'cd '$unk9vvn'/RedTeam/Execution/BadPDF;python2 badpdf.py "$@"' >> /usr/bin/badpdf
			chmod +x /usr/bin/badpdf
			chmod 755 $unk9vvn/RedTeam/Execution/BadPDF/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing BadPDF"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing BadPDF"
			printf "\n\n"
		fi

		# Install CACTUSTORCH_DDEAUTO
		if [ -d "$CACTUSTORCH_DDEAUTO" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/cactus
			echo 'USER=$(cd /home;ls)' >> /usr/bin/cactus
			echo 'cd '$unk9vvn'/RedTeam/Execution/CACTUSTORCH_DDEAUTO;bash cactus.sh "$@"' >> /usr/bin/cactus
			chmod +x /usr/bin/cactus
			chmod 755 $unk9vvn/RedTeam/Execution/CACTUSTORCH_DDEAUTO/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing CACTUSTORCH_DDEAUTO"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing CACTUSTORCH_DDEAUTO"
			printf "\n\n"
		fi

		# Install DNSDelivery
		if [ -d "$DNSDELIVERY" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/dnsdelivery
			echo 'USER=$(cd /home;ls)' >> /usr/bin/dnsdelivery
			echo 'cd '$unk9vvn'/RedTeam/Execution/DNSDelivery;python2 dnsdelivery.py "$@"' >> /usr/bin/dnsdelivery
			chmod +x /usr/bin/dnsdelivery
			chmod 755 $unk9vvn/RedTeam/Execution/DNSDelivery/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing DNSDelivery"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing DNSDelivery"
			printf "\n\n"
		fi

		# Install Donut
		if [ -d "$DONUT" ]; then
			chmod 755 $unk9vvn/RedTeam/Execution/Donut/*
			ln -f -s $unk9vvn/RedTeam/Execution/Donut/donut /usr/bin/donut
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Donut"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Donut"
			printf "\n\n"
		fi

		# Install ExploitPack
		if [ -d "$EXPLOITPACK" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/exploitpack
			echo 'USER=$(cd /home;ls)' >> /usr/bin/exploitpack
			echo 'cd '$unk9vvn'/RedTeam/Execution/ExploitPack;bash RunExploitPack.sh "$@"' >> /usr/bin/exploitpack
			chmod +x /usr/bin/exploitpack
			chmod 755 $unk9vvn/RedTeam/Execution/ExploitPack/*
			pip2 install scapy ropper
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ExploitPack"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ExploitPack"
			printf "\n\n"
		fi

		# Install LNKUp
		if [ -d "$LNKUP" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/lnkup
			echo 'USER=$(cd /home;ls)' >> /usr/bin/lnkup
			echo 'cd '$unk9vvn'/RedTeam/Execution/LNKUp;python2 generate.py "$@"' >> /usr/bin/lnkup
			chmod +x /usr/bin/lnkup
			chmod 755 $unk9vvn/RedTeam/Execution/LNKUp/*
			pip2 install pylnk
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing LNKUp"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing LNKUp"
			printf "\n\n"
		fi

		# Install nps_payload
		if [ -d "$NPS_PAYLOAD" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/nps
			echo 'USER=$(cd /home;ls)' >> /usr/bin/nps
			echo 'cd '$unk9vvn'/RedTeam/Execution/nps_payload;python2 nps_payload.py "$@"' >> /usr/bin/nps
			chmod +x /usr/bin/nps
			chmod 755 $unk9vvn/RedTeam/Execution/nps_payload/*
			pip2 install -r $unk9vvn/RedTeam/Execution/nps_payload/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing nps_payload"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing nps_payload"
			printf "\n\n"
		fi

		# Install SCShell
		if [ -d "$SCSHELL" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/scshell
			echo 'USER=$(cd /home;ls)' >> /usr/bin/scshell
			echo 'cd '$unk9vvn'/RedTeam/Execution/SCShell;python2 scshell.py "$@"' >> /usr/bin/scshell
			chmod +x /usr/bin/scshell
			chmod 755 $unk9vvn/RedTeam/Execution/SCShell/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing SCShell"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing SCShell"
			printf "\n\n"
		fi

		# Install WebDavDelivery
		if [ -d "$WEBDAVDELIVERY" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/webdavdelivery
			echo 'USER=$(cd /home;ls)' >> /usr/bin/webdavdelivery
			echo 'cd '$unk9vvn'/RedTeam/Execution/WebDavDelivery;python2 webDavDelivery.py "$@"' >> /usr/bin/webdavdelivery
			chmod +x /usr/bin/webdavdelivery
			chmod 755 $unk9vvn/RedTeam/Execution/WebDavDelivery/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing WebDavDelivery"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing WebDavDelivery"
			printf "\n\n"
		fi
	}
	Execution


	NGROK=$unk9vvn/RedTeam/Exfiltration/Ngrok
	POWERDNS=$unk9vvn/RedTeam/Exfiltration/PowerDNS
	FETCH=$unk9vvn/RedTeam/Exfiltration/fetch-some-proxies
	REFLECTIVEDNSEXFILTRATOR=$unk9vvn/RedTeam/Exfiltration/ReflectiveDnsExfiltrator
	CERTGRAPH=$unk9vvn/RedTeam/Exfiltration/CertGraph
	NOIP=$unk9vvn/RedTeam/Exfiltration/NoIP-v2.1.9-1
	MULTITOR=$unk9vvn/RedTeam/Exfiltration/Multitor
	GOIPS=$unk9vvn/RedTeam/Exfiltration/go-ipfs
	SOCKS5=$unk9vvn/RedTeam/Exfiltration/Socks5


	Exfiltration()
	{
		# Install CertGraph
		if [ -d "$CERTGRAPH" ]; then
			chmod 755 $unk9vvn/RedTeam/Exfiltration/CertGraph/*
			ln -f -s $unk9vvn/RedTeam/Exfiltration/CertGraph/certgraph /usr/bin/certgraph
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing CertGraph"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing CertGraph"
			printf "\n\n"
		fi

		# Install fetch-some-proxies
		if [ -d "$FETCH" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/fetch
			echo 'USER=$(cd /home;ls)' >> /usr/bin/fetch
			echo 'cd '$unk9vvn'/RedTeam/Exfiltration/fetch-some-proxies;python2 fetch.py "$@"' >> /usr/bin/fetch
			chmod +x /usr/bin/fetch
			chmod 755 $unk9vvn/RedTeam/Exfiltration/fetch-some-proxies/*
			pip2 uninstall pyopenssl -y
			pip2 install pyopenssl
			pip2 install cryptography==2.2.2
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing fetch-some-proxies"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing fetch-some-proxies"
			printf "\n\n"
		fi

		# Install PowerDNS
		if [ -d "$POWERDNS" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/powerdns
			echo 'USER=$(cd /home;ls)' >> /usr/bin/powerdns
			echo 'cd '$unk9vvn'/RedTeam/Exfiltration/PowerDNS;python2 powerdns.py "$@"' >> /usr/bin/powerdns
			chmod +x /usr/bin/powerdns
			chmod 755 $unk9vvn/RedTeam/Exfiltration/PowerDNS/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing PowerDNS"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing PowerDNS"
			printf "\n\n"
		fi

		# Install ReflectiveDnsExfiltrator
		if [ -d "$REFLECTIVEDNSEXFILTRATOR" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/reflectivednsexfiltrator
			echo 'USER=$(cd /home;ls)' >> /usr/bin/reflectivednsexfiltrator
			echo 'cd '$unk9vvn'/RedTeam/Exfiltration/ReflectiveDnsExfiltrator;python2 reflectiveDnsExfiltrator.py "$@"' >> /usr/bin/reflectivednsexfiltrator
			chmod +x /usr/bin/reflectivednsexfiltrator
			chmod 755 $unk9vvn/RedTeam/Exfiltration/ReflectiveDnsExfiltrator/*
			pip2 install -r $unk9vvn/RedTeam/Exfiltration/ReflectiveDnsExfiltrator/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing ReflectiveDnsExfiltrator"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing ReflectiveDnsExfiltrator"
			printf "\n\n"
		fi

		# Install Socks5
		if [ -d "$SOCKS5" ]; then
			chmod 755 $unk9vvn/RedTeam/Exfiltration/Socks5/*
			ln -f -s $unk9vvn/RedTeam/Exfiltration/Socks5/socks5 /usr/bin/socks5
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Socks5"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Socks5"
			printf "\n\n"
		fi

		# Install Ngrok
		if [ -d "$NGROK" ]; then
			chmod 755 $unk9vvn/RedTeam/Exfiltration/Ngrok/*
			ln -f -s $unk9vvn/RedTeam/Exfiltration/Ngrok/ngrok /usr/bin/ngrok
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Ngrok"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Ngrok"
			printf "\n\n"
		fi

		# Install go-ipfs
		if [ -d "$GOIPS" ]; then
			chmod 755 $unk9vvn/RedTeam/Exfiltration/go-ipfs/*
			ln -f -s $unk9vvn/RedTeam/Exfiltration/go-ipfs/ipfs /usr/bin/ipfs
			ipfs init
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing go-ipfs"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing go-ipfs"
			printf "\n\n"
		fi

		# Install Serveo
		if [ -d "$GOIPS" ]; then
			chmod 755 $unk9vvn/RedTeam/Exfiltration/Serveo/*
			ln -f -s $unk9vvn/RedTeam/Exfiltration/Serveo/serveo-linux-amd64 /usr/bin/serveo
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Serveo"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Serveo"
			printf "\n\n"
		fi

		# Install Multitor
		if [ -d "$MULTITOR" ]; then
			chmod 755 $unk9vvn/RedTeam/Exfiltration/Multitor/*
			cd $unk9vvn/RedTeam/Exfiltration/Multitor;./setup.sh install
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Multitor"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Multitor"
			printf "\n\n"
		fi

		# Install NoIP-v2.1.9-1
		if [ -d "$NOIP" ]; then
			chmod 755 $unk9vvn/RedTeam/Exfiltration/NoIP-v2.1.9-1/*
			cd $unk9vvn/RedTeam/Exfiltration/NoIP-v2.1.9-1;./setup.sh install && make && make install
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing NoIP-v2.1.9-1"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing NoIP-v2.1.9-1"
			printf "\n\n"
		fi
	}
	Exfiltration


	U3_PWN=$unk9vvn/RedTeam/Initial-Access/u3-pwn
	PHISHX=$unk9vvn/RedTeam/Initial-Access/PhishX
	PAZUZU=$unk9vvn/RedTeam/Initial-Access/Pazuzu
	EVILURL=$unk9vvn/RedTeam/Initial-Access/EvilURL
	EVILPDF=$unk9vvn/RedTeam/Initial-Access/EvilPDF
	EVILGINX=$unk9vvn/RedTeam/Initial-Access/Evilginx
	PYDINOBER=$unk9vvn/RedTeam/Initial-Access/Pydinober
	USB_RUBBER_DUCKY=$unk9vvn/RedTeam/Initial-Access/USB-Rubber-Ducky
	BLACKEYE=$unk9vvn/RedTeam/Initial-Access/BlackEye
	NET_INJECTOR=$unk9vvn/RedTeam/Initial-Access/BD2.Net-Injector
	CREDSNIPER=$unk9vvn/RedTeam/Initial-Access/CredSniper
	GOPHISH=$unk9vvn/RedTeam/Initial-Access/Gophish
	BRUTAL=$unk9vvn/RedTeam/Initial-Access/Brutal
	TRAPE=$unk9vvn/RedTeam/Initial-Access/trape
	DKMC=$unk9vvn/RedTeam/Initial-Access/DKMC


	Initial-Access()
	{
		# Install BD2.Net-Injector
		if [ -d "$NET_INJECTOR" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/bd2.net-injector
			echo 'USER=$(cd /home;ls)' >> /usr/bin/bd2.net-injector
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/BD2.Net-Injector;wine64 BD2.Net-Injector.exe "$@"' >> /usr/bin/bd2.net-injector
			chmod +x /usr/bin/bd2.net-injector
			chmod 755 $unk9vvn/RedTeam/Initial-Access/BD2.Net-Injector/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing BD2.Net-Injector"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing BD2.Net-Injector"
			printf "\n\n"
		fi

		# Install BlackEye
		if [ -d "$BLACKEYE" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/blackeye
			echo 'USER=$(cd /home;ls)' >> /usr/bin/blackeye
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/BlackEye;./blackeye.sh "$@"' >> /usr/bin/blackeye
			chmod +x /usr/bin/blackeye
			chmod 755 $unk9vvn/RedTeam/Initial-Access/BlackEye/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing BlackEye"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing BlackEye"
			printf "\n\n"
		fi

		# Install Brutal
		if [ -d "$BRUTAL" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/brutal
			echo 'USER=$(cd /home;ls)' >> /usr/bin/brutal
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/Brutal;./brutal.sh "$@"' >> /usr/bin/brutal
			chmod +x /usr/bin/brutal
			chmod 755 $unk9vvn/RedTeam/Initial-Access/Brutal/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Brutal"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Brutal"
			printf "\n\n"
		fi

		# Install CredSniper
		if [ -d "$CREDSNIPER" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/credsniper
			echo 'USER=$(cd /home;ls)' >> /usr/bin/credsniper
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/CredSniper;./install.sh "$@"' >> /usr/bin/credsniper
			chmod +x /usr/bin/credsniper
			chmod 755 $unk9vvn/RedTeam/Initial-Access/CredSniper/*
			pip2 install -r $unk9vvn/RedTeam/Initial-Access/CredSniper/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing CredSniper"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing CredSniper"
			printf "\n\n"
		fi

		# Install DKMC
		if [ -d "$DKMC" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/dkmc
			echo 'USER=$(cd /home;ls)' >> /usr/bin/dkmc
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/DKMC;python2 dkmc.py "$@"' >> /usr/bin/dkmc
			chmod +x /usr/bin/dkmc
			chmod 755 $unk9vvn/RedTeam/Initial-Access/DKMC/*
			pip2 install -r $unk9vvn/RedTeam/Initial-Access/DKMC/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing DKMC"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing DKMC"
			printf "\n\n"
		fi

		# Install Evilginx
		if [ -d "$EVILGINX" ]; then
			chmod 755 $unk9vvn/RedTeam/Initial-Access/Evilginx/*
			cd $unk9vvn/RedTeam/Initial-Access/Evilginx;./install.sh
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Evilginx"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Evilginx"
			printf "\n\n"
		fi

		# Install EvilPDF
		if [ -d "$EVILPDF" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/evilpdf
			echo 'USER=$(cd /home;ls)' >> /usr/bin/evilpdf
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/EvilPDF;python2 evilpdf.py "$@"' >> /usr/bin/evilpdf
			chmod +x /usr/bin/evilpdf
			chmod 755 $unk9vvn/RedTeam/Initial-Access/EvilPDF/*
			pip2 install pypdf2
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing EvilPDF"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing EvilPDF"
			printf "\n\n"
		fi

		# Install EvilURL
		if [ -d "$EVILURL" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/evilurl
			echo 'USER=$(cd /home;ls)' >> /usr/bin/evilurl
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/EvilURL;python3 evilurl.py "$@"' >> /usr/bin/evilurl
			chmod +x /usr/bin/evilurl
			chmod 755 $unk9vvn/RedTeam/Initial-Access/EvilURL/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing EvilURL"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing EvilURL"
			printf "\n\n"
		fi

		# Install Gophish
		if [ -d "$GOPHISH" ]; then
			chmod 755 $unk9vvn/RedTeam/Initial-Access/Gophish/*
			ln -f -s $unk9vvn/RedTeam/Initial-Access/Gophish/gophish /usr/bin/gophish
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Gophish"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Gophish"
			printf "\n\n"
		fi

		# Install Pazuzu
		if [ -d "$PAZUZU" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/pazuzu
			echo 'USER=$(cd /home;ls)' >> /usr/bin/pazuzu
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/Pazuzu;python2 pazuzu.py "$@"' >> /usr/bin/pazuzu
			chmod +x /usr/bin/pazuzu
			chmod 755 $unk9vvn/RedTeam/Initial-Access/Pazuzu/*
			pip2 install pefile
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Pazuzu"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Pazuzu"
			printf "\n\n"
		fi

		# Install PhishX
		if [ -d "$PHISHX" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/phishx
			echo 'USER=$(cd /home;ls)' >> /usr/bin/phishx
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/PhishX;python3 PhishX.py "$@"' >> /usr/bin/phishx
			chmod +x /usr/bin/phishx
			chmod 755 $unk9vvn/RedTeam/Initial-Access/PhishX/*
			cd $unk9vvn/RedTeam/Initial-Access/PhishX;bash installer.sh
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing PhishX"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing PhishX"
			printf "\n\n"
		fi

		# Install Pydinober
		if [ -d "$PYDINOBER" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/pydinober
			echo 'USER=$(cd /home;ls)' >> /usr/bin/pydinober
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/Pydinober;python2 arduino_rubber_docky.py "$@"' >> /usr/bin/pydinober
			chmod +x /usr/bin/pydinober
			chmod 755 $unk9vvn/RedTeam/Initial-Access/Pydinober/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing Pydinober"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing Pydinober"
			printf "\n\n"
		fi

		# Install trape
		if [ -d "$TRAPE" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/trape
			echo 'USER=$(cd /home;ls)' >> /usr/bin/trape
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/trape;python2 trape.py "$@"' >> /usr/bin/trape
			chmod +x /usr/bin/trape
			chmod 755 $unk9vvn/RedTeam/Initial-Access/trape/*
			pip2 install -r $unk9vvn/RedTeam/Initial-Access/trape/requirements.txt
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing trape"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing trape"
			printf "\n\n"
		fi

		# Install u3-pwn
		if [ -d "$U3_PWN" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/u3-pwn
			echo 'USER=$(cd /home;ls)' >> /usr/bin/u3-pwn
			echo 'cd '$unk9vvn'/RedTeam/Initial-Access/u3-pwn;python2 u3-pwn.py "$@"' >> /usr/bin/u3-pwn
			chmod +x /usr/bin/u3-pwn
			chmod 755 $unk9vvn/RedTeam/Initial-Access/u3-pwn/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing u3-pwn"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing u3-pwn"
			printf "\n\n"
		fi

		# Install USB-Rubber-Ducky
		if [ -d "$USB_RUBBER_DUCKY" ]; then
			SHELL='#!'
			echo ''$SHELL'/bin/bash' > /usr/bin/usb-rubber-ducky
			echo '_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"' >> /usr/bin/usb-rubber-ducky
			echo 'unset _JAVA_OPTIONS' >> /usr/bin/usb-rubber-ducky
			echo "alias java='java \"$_SILENT_JAVA_OPTIONS\"'" >> /usr/bin/usb-rubber-ducky
			echo 'USER=$(cd /home;ls)' >> /usr/bin/usb-rubber-ducky
			echo 'cd '$unk9vvn'/Mobile/CheckStyle;java -jar Ducky_Encoder_GUI.jar "$@"' >> /usr/bin/usb-rubber-ducky
			chmod +x /usr/bin/usb-rubber-ducky
			chmod 755 $unk9vvn/RedTeam/Initial-Access/USB-Rubber-Ducky/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing USB-Rubber-Ducky"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing USB-Rubber-Ducky"
			printf "\n\n"
		fi
	}
	Initial-Access


	PTH_TOOLKIT=$unk9vvn/RedTeam/Discovery/PTH-Toolkit/PTH-Toolkit


	Lateral-Movement()
	{
		# Install PTH-Toolkit
		if [ -d "$PTH_TOOLKIT" ]; then
			chmod 755 $unk9vvn/RedTeam/Discovery/PTH-Toolkit/*
			printf "\n\n"
			printf "$GREEN"  "[*] Sucess Installing PTH-Toolkit"
			printf "\n\n"
		else
			printf "\n\n"
			printf "$RED"    "[x] Failed Installing PTH-Toolkit"
			printf "\n\n"
		fi
	}
	Lateral-Movement
}


  # Download
  $ git clone https://github.com/htrgouvea/nipe && cd nipe
    
  # Install libs and dependencies
  $ sudo cpan install Try::Tiny Config::Simple JSON

  # Nipe must be run as root
  $ perl nipe.pl install



  curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault



apt-get update
apt-get -y install apt-transport-https wget gnupg

wget -O - https://packages.icinga.com/icinga.key | apt-key add -

DIST=$(awk -F"[)(]+" '/VERSION=/ {print $2}' /etc/os-release); \
 echo "deb https://packages.icinga.com/debian icinga-${DIST} main" > \
 /etc/apt/sources.list.d/${DIST}-icinga.list
 echo "deb-src https://packages.icinga.com/debian icinga-${DIST} main" >> \
 /etc/apt/sources.list.d/${DIST}-icinga.list

apt-get update