#!/bin/bash
# v3.9
# ┌──(avi㉿unk9vvn)-[~]
# └─$ sudo su;chmod +x Unk9_Kali.sh;./Unk9_Kali.sh




RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'



if [ "$(id -u)" != "0" ];then
	printf "$RED"		"[X] Please run as RooT ..."
	printf "$GREEN"		"sudo su;chmod +x Unk9_Kali.sh;./Unk9_Kali.sh"
	exit 0
fi



LOGO ()
{
	reset;clear
	printf "$GREEN"   "                            --/osssssssssssso/--                       "
	printf "$GREEN"   "                        -+sss+-+--os.yo:++/.o-/sss+-                   "
	printf "$GREEN"   "                     /sy+++-.h.-dd++m+om/s.h.hy/:+oys/                 "
	printf "$GREEN"   "                  .sy/// h/h-:d-qy:/+-/+-+/-s/sodooh:///ys.            "
	printf "$GREEN"   "                -qys-ss/:y:so-/osssso++++osssso+.oo+/s-:o.sy-          "
	printf "$GREEN"   "              -qys:oossyo/+oyo/:-:.-:.:/.:/-.-:/syo/+/s+:oo:sy-        "
	printf "$GREEN"   "             /d/:-soh/-+ho-.:::--:- .os: -:-.:-/::sy+:+ysso+:d/        "
	printf "$GREEN"   "            sy-..+oo-+h:--:..hy+y/  :s+.  /y/sh..:/-:h+-oyss:.ys       "
	printf "$WHITE"   "           ys :+oo/:d/   .m-qyyyo/- - -:   .+oyhy-N.   /d::yosd.sy     "
	printf "$WHITE"   "          oy.++++//d.  ::oNdyo:     .--.     :oyhN+-:  .d//s//y.ys     "
	printf "$WHITE"   "         :m-qy+++//d-   dyyy++::-. -.o.-+.- .-::/+hsyd   -d/so+++.m:   "
	printf "$WHITE"   "        -d/-/+++.m-  /.ohso- ://:///++++///://:  :odo.+  -m.syoo:/d-   "
	printf "$WHITE"   "        :m-+++y:y+   smyms-   -//+/-ohho-/+//-    omsmo   +y s+oy-m:   "
	printf "$WHITE"   "        sy:+++y-N-  -.dy+:...-- :: ./hh/. :: --...//hh.:  -N-o+/:-so   "
	printf "$WHITE"   "        yo-///s-m   odohd.-.--:/o.-+/::/+-.o/:--.--hd:ho   m-s+++-+y   "
	printf "$WHITE"   "        yo::/+o-m   -qyNy/:  ...:+s.//:://.s+:...  :/yNs    m-h++++oy  "
	printf "$WHITE"   "        oy/hsss-N-  oo:oN-   .-o.:ss:--:ss:.o-.   -My-oo  -N-o+++.so   "
	printf "$WHITE"   "        :m :++y:y+   sNMy+: -+/:.--:////:--.:/+- -+hNNs   +y-o++o-m:   "
	printf "$WHITE"   "        -d/::+o+.m-  -:/+ho:.       -//-       ./sdo::-  -m-o++++/d-   "
	printf "$WHITE"   "         :m-qyo++//d- -ommMo//        -:        +oyNhmo- -d//s+++-m:   "
	printf "$WHITE"   "          oy /o++//d.  -::/oMss-   -+++s     :yNy+/:   .d//y+---qys    "
	printf "$WHITE"   "           ys--+o++:d/ -/sdmNysNs+/./-//-//hNyyNmmy+- /d-+y--::sy      "
	printf "$RED"     "            sy:..ooo-+h/--.-//odm/hNh--qyNh+Ndo//-./:/h+-so+:+/ys      "
	printf "$RED"     "             /d-o.ssy+-+yo:/:/:-:+sho..ohs/-:://::oh+.h//syo-d/-       "
	printf "$RED"     "              -qys-oosyss:/oyy//::..-.--.--:/.//syo+-qys//o/.sy-       "
	printf "$RED"     "                -qys.sooh+d-s:+osssysssosssssso:/+/h:/yy/.sy-          "
	printf "$RED"     "                  .sy/:os.h--d/o+-/+:o:/+.+o:d-qy+h-o+-+ys.            "
	printf "$RED"     "                     :sy+:+ s//sy-qy.-h-m/om:s-qy.++/+ys/              "
	printf "$RED"     "                        -+sss+/o/ s--qy.s+/:++-+sss+-                  "
	printf "$RED"     "                            --/osssssssssssso/--                       "
	printf "$BLUE"    "                                  Unk9vvN                              "
	printf "$YELLOW"  "                            https://unk9vvn.com                        "
	printf "$CYAN"    "                                 Installer                             "
	printf "\n\n"
}



penetrating_testing ()
{
	# Install Repository Tools
	apt install -qy tor tesseract-ocr dirsearch jd-gui nuclei maryam rainbowcrack hakrawler airgeddon gobuster seclists fcrackzip subfinder cme amap arjun rarcrack bettercap metagoofil dsniff sublist3r arpwatch wifiphisher sslstrip airgraph-ng sherlock parsero routersploit tcpxtract cupp slowhttptest dnsmasq sshuttle gifsicle adb shellter haproxy aria2 smb4k crackle pptpd gimp xplico unicorn phpggc qrencode emailharvester cmatrix osrframework jq tigervnc-viewer pngtools pdfcrack dosbox lldb apksigner zmap checksec kerberoast etherape ismtp goldeneye ident-user-enum httptunnel wig feh onionshare kalibrate-rtl eyewitness zipalign strace oclgausscrack multiforcer crowbar brutespray arduino websploit googler ffmpeg rar inspy eaphammer rtlsdr-scanner multimon-ng isr-evilgrade smtp-user-enum obfs4proxy proxychains pigz massdns gospider proxify gdb ubertooth gnuradio apktool privoxy dotdotpwn gr-gsm isc-dhcp-server sonic-visualiser massdns goofile ridenum firewalk bing-ip2hosts webhttrack i2p awscli oathtool sipvicious netstress tcptrack airspy xdotool gqrx-sdr tnscmd10g starkiller swaks getallurls btscanner bluesnarfer darkstat flashrom crackle blueranger spooftooph wifipumpkin3 wireguard dnsrecon wafw00f padbuster crackmapexec graphviz windows-binaries socat proxytunnel feroxbuster ffuf amass 

	# Install Python3 PIP3
	pip3 install pyjwt cryptography arjun mitm6 frida-tools ropper objection mitmproxy dnsgen py-altdns btlejack urh pymultitor qark autosubtakeover crlfsuite censys scapy cave-miner androguard mongoaudit cheroot angr slowloris brute pacu whispers s3scanner festin cloudsplaining custodian c7n cartography trailscraper lambdaguard clinv airiam access-undenied-aws mailspoof raccoon-scanner apkleaks bbqsql baboossh drozer selenium pinject ciphey scoutsuite PyJWT mobsf aws-gate njsscan detect-secrets regexploit h8mail nodejsscan hashpumpy brute-engine urh dnstwist mvt Stegano checkov truffleHog kiwi stego-lsb diffy stegoveritas impacket cloudscraper acltoolkit-ad bloodhound wpspin adafruit-nrfutil andriller maltego-trx androset dronesploit twint thorndyke prowler bhedak shodan postmaniac PyExfil
	pip3 install git+https://github.com/EntySec/Ghost

	# Install Python2 PIP2
	pip2 install pyModbusTCP

	# Install Ruby GEM
	gem install ssrf_proxy zsteg seccomp-tools aws_public_ips aws_security_viz aws_recon API_Fuzzer dawnscanner mechanize aws_security_viz public_suffix idb rake aws_recon zsteg

	# Install Nodejs NPM
	npm install -g jwt-cracker graphql padding-oracle-attacker http-proxy-to-socks javascript-obfuscator serialize-javascript rms-runtime-mobile-security igf apk-mitm bagbak igf graphqlviz btlejuice gattacker wappalyzer http-proxy-to-socks f5stegojs node-serialize uglify-js igf phantomjs electron-packager aws_public_ips passionfruit redos apk-mitm fleetctl npx serialize-to-js dompurify persistgraphql

	# Install Rust
	cargo install anevicon

	# Install Golang
	go install github.com/tomnomnom/assetfinder@latest
	ln -f -s ~/go/bin/assetfinder /usr/bin/assetfinder
	go install github.com/tomnomnom/waybackurls@latest
	ln -f -s ~/go/bin/waybackurls /usr/bin/waybackurls
	go install github.com/tomnomnom/httprobe@latest
	ln -f -s ~/go/bin/httprobe /usr/bin/httprobe
	go install github.com/tomnomnom/meg@latest
	ln -f -s ~/go/bin/meg /usr/bin/meg
	go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
	ln -f -s ~/go/bin/asnmap /usr/bin/asnmap
	go install github.com/edoardottt/cariddi/cmd/cariddi@latest
	ln -f -s ~/go/bin/cariddi /usr/bin/cariddi
	go install github.com/glebarez/cero@latest
	ln -f -s ~/go/bin/cero /usr/bin/cero
	go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest
	ln -f -s ~/go/bin/cloudlist /usr/bin/cloudlist
	go install github.com/x1sec/commit-stream@latest
	ln -f -s ~/go/bin/commit-stream /usr/bin/commit-stream
	go install github.com/shivangx01b/CorsMe@latest
	ln -f -s ~/go/bin/CorsMe /usr/bin/CorsMe
	go install github.com/pwnesia/dnstake/cmd/dnstake@latest
	ln -f -s ~/go/bin/dnstake /usr/bin/dnstake
	go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	ln -f -s ~/go/bin/dnsx /usr/bin/dnsx
	go install github.com/projectdiscovery/dnsprobe@latest
	ln -f -s ~/go/bin/dnsprobe /usr/bin/dnsprobe
	go install github.com/ryandamour/crlfmap@latest
	ln -f -s ~/go/bin/crlfmap /usr/bin/crlfmap
	go install github.com/hahwul/dalfox/v2@latest
	ln -f -s ~/go/bin/dalfox /usr/bin/dalfox
	go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	ln -f -s ~/go/bin/naabu /usr/bin/naabu
	go install github.com/edoardottt/csprecon/cmd/csprecon@latest
	ln -f -s ~/go/bin/csprecon /usr/bin/csprecon
	go install github.com/j3ssie/metabigor@latest
	ln -f -s ~/go/bin/metabigor /usr/bin/metabigor
	go install github.com/d3mondev/puredns/v2@latest
	ln -f -s ~/go/bin/puredns /usr/bin/puredns
	go install github.com/koenrh/s3enum@latest
	ln -f -s ~/go/bin/s3enum /usr/bin/s3enum
	go install github.com/smiegles/mass3@latest
	ln -f -s ~/go/bin/mass3 /usr/bin/mass3
	go install github.com/magisterquis/s3finder@latest
	ln -f -s ~/go/bin/s3finder /usr/bin/s3finder
	go install github.com/eth0izzle/shhgit@latest
	ln -f -s ~/go/bin/shhgit /usr/bin/shhgit
	go install github.com/edoardottt/favirecon/cmd/favirecon@latest
	ln -f -s ~/go/bin/favirecon /usr/bin/favirecon
	go install github.com/KathanP19/Gxss@latest
	ln -f -s ~/go/bin/Gxss /usr/bin/Gxss
	go install github.com/Macmod/goblob@latest
	ln -f -s ~/go/bin/goblob /usr/bin/goblob
	go install github.com/003random/getJS@latest
	ln -f -s ~/go/bin/getJS /usr/bin/getJS
	go install github.com/projectdiscovery/dnsprobe@latest
	ln -f -s ~/go/bin/dnsprobe /usr/bin/dnsprobe
	go install github.com/tfsec/tfsec/cmd/tfsec@latest
	ln -f -s ~/go/bin/tfsec /usr/bin/tfsec
	go install github.com/nytr0gen/deduplicate@latest
	ln -f -s ~/go/bin/deduplicate /usr/bin/deduplicate
	go install github.com/tomnomnom/gf@latest
	ln -f -s ~/go/bin/gf /usr/bin/gf
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	ln -f -s ~/go/bin/httpx /usr/bin/httpx
	go install github.com/ndelphit/apkurlgrep@latest
	ln -f -s ~/go/bin/apkurlgrep /usr/bin/apkurlgrep
	go install github.com/haccer/subjack@latest
	ln -f -s ~/go/bin/subjack /usr/bin/subjack
	go install github.com/s-rah/onionscan@latest
	ln -f -s ~/go/bin/onionscan /usr/bin/onionscan
	go install github.com/tomnomnom/gron@latest
	ln -f -s ~/go/bin/gron /usr/bin/gron
	go install github.com/valyala/fasthttp@latest
	ln -f -s ~/go/bin/fasthttp /usr/bin/fasthttp
	go install github.com/RumbleDiscovery/jarm-go/cmd/jarmscan@latest
	ln -f -s ~/go/bin/jarmscan /usr/bin/jarmscan
	go install github.com/harleo/asnip@latest
	ln -f -s ~/go/bin/asnip /usr/bin/asnip
	go install github.com/harleo/ghostpass@latest
	ln -f -s ~/go/bin/ghostpass /usr/bin/ghostpass
	go install github.com/Nhoya/gOSINT/cmd/gosint@latest
	ln -f -s ~/go/bin/gosint /usr/bin/gosint
	go install github.com/smiegles/mass3@latest
	ln -f -s ~/go/bin/mass3 /usr/bin/mass3
	go install github.com/koenrh/s3enum@latest
	ln -f -s ~/go/bin/s3enum /usr/bin/s3enum
	go install github.com/magisterquis/s3finder@latest
	ln -f -s ~/go/bin/s3finder /usr/bin/s3finder
	go install github.com/aquasecurity/esquery@latest
	ln -f -s ~/go/bin/esquery /usr/bin/esquery
	go install github.com/hideckies/fuzzagotchi@latest
	ln -f -s ~/go/bin/fuzzagotchi /usr/bin/fuzzagotchi
	go install github.com/hideckies/aut0rec0n@latest
	ln -f -s ~/go/bin/aut0rec0n /usr/bin/aut0rec0n
	go install github.com/sensepost/gowitness@latest
	ln -f -s ~/go/bin/gowitness /usr/bin/gowitness
	go install github.com/projectdiscovery/proxify/cmd/proxify@latest
	ln -f -s ~/go/bin/proxify /usr/bin/proxify
	go install github.com/hakluke/haktrails@latest
	ln -f -s ~/go/bin/haktrails /usr/bin/haktrails
	go install github.com/TaurusOmar/reconbulk@latest
	ln -f -s ~/go/bin/reconbulk /usr/bin/reconbulk
	go install github.com/f1zm0/acheron@latest
	ln -f -s ~/go/bin/acheron /usr/bin/acheron
	go install github.com/securebinary/firebaseExploiter@latest
	ln -f -s ~/go/bin/firebaseExploiter /usr/bin/firebaseExploiter
	go install github.com/ferreiraklet/airixss@latest
	ln -f -s ~/go/bin/airixss /usr/bin/airixss
	go install github.com/dwisiswant0/cf-check@latest
	ln -f -s ~/go/bin/cf-check /usr/bin/cf-check
	go install github.com/takshal/freq@latest
	ln -f -s ~/go/bin/freq /usr/bin/freq
	go install github.com/lc/gau/v2/cmd/gau@latest
	ln -f -s ~/go/bin/gau /usr/bin/gau
	go install github.com/deletescape/goop@latest
	ln -f -s ~/go/bin/goop /usr/bin/goop
	go install github.com/hakluke/hakrevdns@latest
	ln -f -s ~/go/bin/hakrevdns /usr/bin/hakrevdns
	go install github.com/hakluke/haktldextract@latest
	ln -f -s ~/go/bin/haktldextract /usr/bin/haktldextract
	go install github.com/Emoe/kxss@latest
	ln -f -s ~/go/bin/kxss /usr/bin/kxss
	go install github.com/ThreatUnkown/jsubfinder@latest
	ln -f -s ~/go/bin/jsubfinder /usr/bin/jsubfinder
	go install github.com/jaeles-project/jaeles@latest
	ln -f -s ~/go/bin/jaeles /usr/bin/jaeles
	go install github.com/tomnomnom/hacks/html-tool@latest
	ln -f -s ~/go/bin/html-tool /usr/bin/html-tool
	go install github.com/hakluke/haklistgen@latest
	ln -f -s ~/go/bin/haklistgen /usr/bin/haklistgen
	go install github.com/projectdiscovery/notify/cmd/notify@latest
	ln -f -s ~/go/bin/notify /usr/bin/notify
	go install github.com/j3ssie/metabigor@latest
	ln -f -s ~/go/bin/metabigor /usr/bin/metabigor
	go install github.com/projectdiscovery/katana/cmd/katana@latest
	ln -f -s ~/go/bin/katana /usr/bin/katana
	go install github.com/tomnomnom/qsreplace@latest
	ln -f -s ~/go/bin/qsreplace /usr/bin/qsreplace
	go install github.com/shenwei356/rush@latest
	ln -f -s ~/go/bin/rush /usr/bin/rush
	go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
	ln -f -s ~/go/bin/shuffledns /usr/bin/shuffledns
	go install github.com/lc/subjs@latest
	ln -f -s ~/go/bin/subjs /usr/bin/subjs
	go install github.com/dwisiswant0/unew@latest
	ln -f -s ~/go/bin/unew /usr/bin/unew
	go install github.com/tomnomnom/unfurl@latest
	ln -f -s ~/go/bin/unfurl /usr/bin/unfurl
	go install github.com/tomnomnom/hacks/tojson@latest
	ln -f -s ~/go/bin/tojson /usr/bin/tojson
	go install github.com/detectify/page-fetch@latest
	ln -f -s ~/go/bin/page-fetch /usr/bin/page-fetch
	go install github.com/zmap/zgrab2@latest
	ln -f -s ~/go/bin/zgrab2 /usr/bin/zgrab2


	# Install CyberChef
	if [ ! -d "/usr/share/cyberchef" ]; then
		git clone https://github.com/gchq/CyberChef /usr/share/cyberchef
		echo '#!/bin/bash' > /usr/bin/cyberchef
		echo 'firefox --new-tab "file://usr/share/cyberchef/CyberChef.html" > /dev/null & "$@"' >> /usr/bin/cyberchef
		chmod +x /usr/bin/cyberchef;chmod 755 /usr/share/cyberchef/*
		printf "$GREEN"  "[*] Sucess Installing CyberChef"
	else
		printf "$GREEN"  "[*] Sucess Installed CyberChef"
	fi

	# Install axiom
	if [ ! -d "/usr/share/axiom" ]; then
		bash <(curl -s https://raw.githubusercontent.com/pry0cc/axiom/master/interact/axiom-configure)
		printf "$GREEN"  "[*] Sucess Installing axiom"
	else
		printf "$GREEN"  "[*] Sucess Installed axiom"
	fi

	# Install CloudFail
	if [ ! -d "/usr/share/cloudfail" ]; then
		git clone https://github.com/m0rtem/CloudFail /usr/share/cloudfail
		echo '#!/bin/bash' > /usr/bin/cloudfail
		echo 'cd /usr/share/cloudfail;python3 cloudbunny.py "$@"' >> /usr/bin/cloudfail
		chmod +x /usr/bin/cloudfail;chmod 755 /usr/share/cloudfail/*
		cd /usr/share/cloudfail;pip3 install -r requirements.txt
		printf "$GREEN"  "[*] Sucess Installing CloudFail"
	else
		printf "$GREEN"  "[*] Sucess Installed CloudFail"
	fi

	# Install SNMPBrute
	if [ ! -d "/usr/share/SNMP-Brute" ]; then
		git clone https://github.com/SECFORCE/SNMP-Brute /usr/share/SNMP-Brute
		echo '#!/bin/bash' > /usr/bin/snmpbrute
		echo 'cd /usr/share/SNMP-Brute;python2 snmp-brute.py "$@"' >> /usr/bin/snmpbrute
		chmod +x /usr/bin/snmpbrute;chmod 755 /usr/share/SNMP-Brute/*
		printf "$GREEN"  "[*] Sucess Installing SNMPBrute"
	else
		printf "$GREEN"  "[*] Sucess Installed SNMPBrute"
	fi

	# Install SMod
	if [ ! -d "/usr/share/smod" ]; then
		git clone https://github.com/Joshua1909/smod /usr/share/smod
		echo '#!/bin/bash' > /usr/bin/smod
		echo 'cd /usr/share/smod;python2 smod.py "$@"' >> /usr/bin/smod
		chmod +x /usr/bin/smod;chmod 755 /usr/share/smod/*
		printf "$GREEN"  "[*] Sucess Installing SMod"
	else
		printf "$GREEN"  "[*] Sucess Installed SMod"
	fi

	# Install S7Scan
	if [ ! -d "/usr/share/s7scan" ]; then
		git clone https://github.com/klsecservices/s7scan /usr/share/s7scan
		echo '#!/bin/bash' > /usr/bin/s7scan
		echo 'cd /usr/share/s7scan;python2 s7scan.py "$@"' >> /usr/bin/s7scan
		chmod +x /usr/bin/s7scan;chmod 755 /usr/share/s7scan/*
		printf "$GREEN"  "[*] Sucess Installing S7Scan"
	else
		printf "$GREEN"  "[*] Sucess Installed S7Scan"
	fi

	# Install RouterScan
	if [ -d "/usr/share/routerscan" ]; then
		mkdir /usr/share/routerscan
		wget http://msk1.stascorp.com/routerscan/prerelease.7z -O /usr/share/routerscan/prerelease.7z
		7z x prerelease.7z;rm -f prerelease.7z
		echo '#!/bin/bash' > /usr/bin/routerscan
		echo 'cd /usr/share/routerscan;wine RouterScan.exe "$@"' >> /usr/bin/routerscan
		chmod +x /usr/bin/routerscan;chmod 755 /usr/share/routerscan/*
		printf "$GREEN"  "[*] Sucess Installing RouterScan"
	else
		printf "$GREEN"  "[*] Sucess Installed RouterScan"
	fi

	# Install DNScan
	if [ ! -d "/usr/share/dnscan" ]; then
		git clone https://github.com/rbsec/dnscan /usr/share/dnscan
		echo '#!/bin/bash' > /usr/bin/dnscan
		echo 'cd /usr/share/dnscan;python3 dnscan.py "$@"' >> /usr/bin/dnscan
		chmod +x /usr/bin/dnscan;chmod 755 /usr/share/dnscan/*
		cd /usr/share/dnscan;pip3 install -r requirements.txt
		printf "$GREEN"  "[*] Sucess Installing DNScan"
	else
		printf "$GREEN"  "[*] Sucess Installed DNScan"
	fi

	# Install Sn1per
	if [ ! -d "/usr/share/sniper" ]; then
		git clone https://github.com/1N3/Sn1per /tmp/sn1per
		cd /tmp/sn1per;bash install.sh;rm -r /tmp/sn1per
		printf "$GREEN"  "[*] Sucess Installing Sn1per"
	else
		printf "$GREEN"  "[*] Sucess Installed Sn1per"
	fi

	# Install WhatWaf
	if [ ! -d "/usr/share/whatwaf" ]; then
		git clone https://github.com/Ekultek/WhatWaf /usr/share/whatwaf
		echo '#!/bin/bash' > /usr/bin/whatwaf
		echo 'cd /usr/share/whatwaf;python3 whatwaf "$@"' >> /usr/bin/whatwaf
		chmod +x /usr/bin/whatwaf;chmod 755 /usr/share/whatwaf/*
		cd /usr/share/whatwaf;pip3 install -r requirements.txt
		printf "$GREEN"  "[*] Sucess Installing WhatWaf"
	else
		printf "$GREEN"  "[*] Sucess Installed WhatWaf"
	fi

	# Install CloudBunny
	if [ ! -d "/usr/share/cloudbunny" ]; then
		git clone https://github.com/Warflop/CloudBunny /usr/share/cloudbunny
		echo '#!/bin/bash' > /usr/bin/cloudbunny
		echo 'cd /usr/share/cloudbunny;python2 cloudbunny.py "$@"' >> /usr/bin/cloudbunny
		chmod +x /usr/bin/cloudbunny;chmod 755 /usr/share/cloudbunny/*
		printf "$GREEN"  "[*] Sucess Installing CloudBunny"
	else
		printf "$GREEN"  "[*] Sucess Installed CloudBunny"
	fi

	# Install GTScan
	if [ ! -d "/usr/share/gtscan" ]; then
		git clone https://github.com/SigPloiter/GTScan /usr/share/gtscan
		echo '#!/bin/bash' > /usr/bin/gtscan
		echo 'cd /usr/share/gtscan;python3 gtscan.py "$@"' >> /usr/bin/gtscan
		chmod +x /usr/bin/gtscan;chmod 755 /usr/share/gtscan/*
		printf "$GREEN"  "[*] Sucess Installing GTScan"
	else
		printf "$GREEN"  "[*] Sucess Installed GTScan"
	fi

	# Install ICS Exploitation Framework
	if [ ! -d "/usr/share/isf" ]; then
		git clone https://github.com/dark-lbp/isf /usr/share/isf
		echo '#!/bin/bash' > /usr/bin/isf
		echo 'cd /usr/share/isf;python2 isf.py "$@"' >> /usr/bin/isf
		chmod +x /usr/bin/isf;chmod 755 /usr/share/isf/*
		cd /usr/share/isf;pip3 install -r requirements.txt
		printf "$GREEN"  "[*] Sucess Installing ICS Exploitation Framework"
	else
		printf "$GREEN"  "[*] Sucess Installed ICS Exploitation Framework"
	fi

	# Install PRET
	if [ ! -d "/usr/share/pret" ]; then
		git clone https://github.com/RUB-NDS/PRET /usr/share/pret
		echo '#!/bin/bash' > /usr/bin/pret
		echo 'cd /usr/share/pret;python2 pret.py "$@"' >> /usr/bin/pret
		chmod +x /usr/bin/pret;chmod 755 /usr/share/pret/*
		cd /usr/share/pret;pip3 install -r requirements.txt
		printf "$GREEN"  "[*] Sucess Installing PRET"
	else
		printf "$GREEN"  "[*] Sucess Installed PRET"
	fi

	# Install ModbusPal
	if [ ! -d "/usr/share/modbuspal" ]; then
		mkdir /usr/share/modbuspal
		wget https://cfhcable.dl.sourceforge.net/project/modbuspal/modbuspal/RC%20version%201.6c/ModbusPal.jar -O /usr/share/modbuspal/ModbusPal.jar
		echo '#!/bin/bash' > /usr/bin/modbuspal
		echo 'cd /usr/share/modbuspal;java -jar ModbusPal.jar "$@"' >> /usr/bin/modbuspal
		chmod +x /usr/bin/modbuspal;chmod 755 /usr/share/modbuspal/*
		printf "$GREEN"  "[*] Sucess ModbusPal"
	else
		printf "$GREEN"  "[*] Sucess ModbusPal"
	fi

	# Install HLR-Lookups
	if [ ! -d "/usr/share/hlr_Lookups" ]; then
		git clone https://github.com/SigPloiter/HLR-Lookups /usr/share/hlr_Lookups
		echo '#!/bin/bash' > /usr/bin/hlr_Lookups
		echo 'cd /usr/share/hlr_Lookups;python3 hlr-lookups.py "$@"' >> /usr/bin/hlr_Lookups
		chmod +x /usr/bin/hlr_Lookups;chmod 755 /usr/share/hlr_Lookups/*
		printf "$GREEN"  "[*] Sucess Installing HLR-Lookups"
	else
		printf "$GREEN"  "[*] Sucess Installed HLR-Lookups"
	fi

	# Install CredNinja
	if [ ! -d "/usr/share/credninja" ]; then
		git clone https://github.com/Warflop/CredNinja /usr/share/credninja
		echo '#!/bin/bash' > /usr/bin/credninja
		echo 'cd /usr/share/credninja;python3 CredNinja.py "$@"' >> /usr/bin/credninja
		chmod +x /usr/bin/credninja;chmod 755 /usr/share/credninja/*
		printf "$GREEN"  "[*] Sucess Installing CredNinja"
	else
		printf "$GREEN"  "[*] Sucess Installed CredNinja"
	fi

	# Install VHostScan
	if [ ! -d "/usr/share/vhostscan" ]; then
		git clone https://github.com/codingo/VHostScan /usr/share/vhostscan
		chmod 755 /usr/share/vhostscan/*;cd /usr/share/vhostscan
		pip3 install -r requirements.txt;python3 setup.py install
		printf "$GREEN"  "[*] Sucess Installing VHostScan"
	else
		printf "$GREEN"  "[*] Sucess Installed VHostScan"
	fi

	# Install Infoga
	if [ ! -d "/usr/share/infoga" ]; then
		git clone https://github.com/m4ll0k/Infoga /usr/share/infoga
		echo '#!/bin/bash' > /usr/bin/infoga
		echo 'cd /usr/share/infoga;python2 infoga.py "$@"' >> /usr/bin/infoga
		chmod +x /usr/bin/infoga;chmod 755 /usr/share/infoga/*
		pip2 install -r requirements.txt;python2 setup.py install
		printf "$GREEN"  "[*] Sucess Installing Infoga"
	else
		printf "$GREEN"  "[*] Sucess Installed Infoga"
	fi

	# Install CheckStyle
	if [ ! -d "/usr/share/checkstyle" ]; then
		mkdir /usr/share/checkstyle
		wget https://github.com/checkstyle/checkstyle/releases/download/checkstyle-10.9.3/checkstyle-10.9.3-all.jar -O /usr/share/checkstyle/checkstyle-10.9.3-all.jar
		echo '#!/bin/bash' > /usr/bin/checkstyle
		echo 'cd /usr/share/checkstyle;java -jar checkstyle-10.9.3-all.jar "$@"' >> /usr/bin/checkstyle
		chmod +x /usr/bin/checkstyle;chmod 755 /usr/share/checkstyle/*
		printf "$GREEN"  "[*] Sucess Installing CheckStyle"
	else
		printf "$GREEN"  "[*] Sucess Installed CheckStyle"
	fi

	# Install Drozer
	if [ ! -d "/usr/share/drozer" ]; then
		wget https://github.com/WithSecureLabs/drozer/releases/download/2.4.4/drozer_2.4.4.deb -O /tmp/drozer.deb
		chmod +x /tmp/drozer.deb;dpkg -i /tmp/drozer.deb;rm -f /tmp/drozer.deb
		printf "$GREEN"  "[*] Sucess Installing Drozer"
	else
		printf "$GREEN"  "[*] Sucess Installed Drozer"
	fi

	# Install Genymotion
	if [ ! -d "/usr/share/genymotion" ]; then
		mkdir /user/share/genymotion
		wget https://dl.genymotion.com/releases/genymotion-3.3.3/genymotion-3.3.3-linux_x64.bin -O /user/share/genymotion/genymotion-linux.bin
		cd /user/share/genymotion;chmod +x genymotion-linux.bin;./genymotion-linux.bin -y
		printf "$GREEN"  "[*] Sucess Installing Genymotion"
	else
		printf "$GREEN"  "[*] Sucess Installed Genymotion"
	fi

	# Install PhoneInfoga
	if [ ! -d "/usr/share/phoneinfoga" ]; then
		wget https://github.com/sundowndev/phoneinfoga/releases/download/v2.10.4/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/phoneinfoga.tar.gz
		mkdir /usr/share/phoneinfoga;chmod +x /usr/share/phoneinfoga;cd /tmp
		tar -xvf phoneinfoga.tar.gz;mv phoneinfoga /var/share/phoneinfoga/phoneinfoga;rm -f /tmp/phoneinfoga.tar.gz
		ln -f -s /usr/share/phoneinfoga/phoneinfoga /usr/bin/phoneinfoga
		printf "$GREEN"  "[*] Sucess Installing PhoneInfoga"
	else
		printf "$GREEN"  "[*] Sucess Installed PhoneInfoga"
	fi

	# Install MobSF
	if [ ! -d "/usr/share/mobsf" ]; then
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /usr/share/mobsf
		echo '#!/bin/bash' > /usr/bin/mobsf
		echo 'cd /usr/share/mobsf;./run.sh > /dev/null &' >> /usr/bin/mobsf
		echo 'sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &' >> /usr/bin/mobsf
		chmod +x /usr/bin/mobsf;cd /usr/share/mobsf;chmod 755 *;./setup.sh
		printf "$GREEN"  "[*] Sucess Installing MobSF"
	else
		printf "$GREEN"  "[*] Sucess Installed MobSF"
	fi

	# Install Findomain
	if [ ! -d "/usr/share/findomain" ]; then
		wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip -O /tmp/findomain.zip
		unzip /tmp/findomain.zip -d /usr/share/findomain
		chmod +x /usr/share/findomain/*;rm -f /tmp/findomain.zip
		ln -s /usr/share/findomain/findomain /usr/bin/findomain
		printf "$GREEN"  "[*] Sucess Installing Findomain"
	else
		printf "$GREEN"  "[*] Sucess Installed Findomain"
	fi

	# Install Angry-IP
	if [ ! -d "/usr/bin/ipscan" ]; then
		wget https://github.com/angryip/ipscan/releases/download/3.9.1/ipscan_3.9.1_amd64.deb -O /tmp/ipscan_amd64.deb
		chmod +x /tmp/ipscan_amd64.deb;dpkg -i /tmp/ipscan_amd64.deb;rm -f /tmp/ipscan_amd64.deb
		printf "$GREEN"  "[*] Sucess Installing Angry-IP"
	else
		printf "$GREEN"  "[*] Sucess Installed Angry-IP"
	fi

	# Install RustScan
	if [ ! -f "/usr/bin/rustscan" ]; then
		wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb -O /tmp/rustscan_amd64.deb
		chmod +x /tmp/rustscan_amd64.deb;dpkg -i /tmp/rustscan_amd64.deb;rm -f /tmp/rustscan_amd64.deb
		printf "$GREEN"  "[*] Sucess Installing RustScan"
	else
		printf "$GREEN"  "[*] Sucess Installed RustScan"
	fi

	# Install GEF
	if [ ! -f "~/.gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py" ]; then
		bash -c "$(wget https://gef.blah.cat/sh -O -)"
		printf "$GREEN"  "[*] Sucess Installing GEF"
	else
		printf "$GREEN"  "[*] Sucess Installed GEF"
	fi

	# Install sn0int
	if [ ! -f "/etc/apt/sources.list.d/apt-vulns-sexy.list" ]; then
		gpg -a --export --keyring /usr/share/keyrings/debian-maintainers.gpg kpcyrd@archlinux.org | tee /etc/apt/trusted.gpg.d/apt-vulns-sexy.gpg
		echo deb http://apt.vulns.sexy stable main | tee /etc/apt/sources.list.d/apt-vulns-sexy.list
		apt update;apt install -qy sn0int
		printf "$GREEN"  "[*] Sucess Installing sn0int"
	else
		printf "$GREEN"  "[*] Sucess Installed sn0int"
	fi

	# Install HashPump
	if [ ! -d "/usr/share/hashpump" ]; then
		git clone https://github.com/bwall/HashPump /usr/share/hashpump
		chmod 755 /usr/share/hashpump/*;cd /usr/share/hashpump;make install
		printf "$GREEN"  "[*] Sucess Installing HashPump"
	else
		printf "$GREEN"  "[*] Sucess Installed HashPump"
	fi

	# Install RSAtool
	if [ ! -d "/usr/share/RSAtool" ]; then
		git clone https://github.com/ius/rsatool /usr/share/rsatool
		echo '#!/bin/bash' > /usr/bin/rsatool
		echo 'cd /usr/share/rsatool;pyhton3 rsatool.py "$@"' >> /usr/bin/rsatool
		chmod +x /usr/bin/rsatool;chmod 755 /usr/share/rsatool/*;cd /usr/share/rsatool;python3 setup.py install
		printf "$GREEN"  "[*] Sucess Installing RSAtool"
	else
		printf "$GREEN"  "[*] Sucess Installed RSAtool"
	fi

	# Install RsaCtfTool
	if [ ! -d "/usr/share/rsactftool" ]; then
		git clone https://github.com/RsaCtfTool/RsaCtfTool /usr/share/rsactftool
		echo '#!/bin/bash' > /usr/bin/rsactftool
		echo 'cd /usr/share/rsactftool;python3 RsaCtfTool.py "$@"' >> /usr/bin/rsactftool
		chmod +x /usr/bin/rsactftool;chmod 755 /usr/share/rsactftool/*
		pip3 -r /usr/share/rsactftool/requirements.txt
		printf "$GREEN"  "[*] Sucess Installing RsaCtfTool"
	else
		printf "$GREEN"  "[*] Sucess Installed RsaCtfTool"
	fi

	# Install PEMCrack
	if [ ! -d "/usr/share/pemcrack" ]; then
		git clone https://github.com/robertdavidgraham/pemcrack /usr/share/pemcrack
		cd /usr/share/pemcrack;gcc pemcrack.c -o pemcrack -lssl -lcrypto
		ln -f -s /usr/share/pemcrack/pemcrack /usr/bin/pemcrack
		printf "$GREEN"  "[*] Sucess Installing PEMCrack"
	else
		printf "$GREEN"  "[*] Sucess Installed PEMCrack"
	fi

	# Install DyMerge
	if [ ! -d "/usr/share/dymerge" ]; then
		git clone https://github.com/k4m4/dymerge /usr/share/dymerge
		echo '#!/bin/bash' > /usr/bin/dymerge
		echo 'cd /usr/share/dymerge;python3 dymerge.py "$@"' >> /usr/bin/dymerge
		chmod +x /usr/bin/dymerge;chmod 755 /usr/share/dymerge/*
		printf "$GREEN"  "[*] Sucess Installing DyMerge"
	else
		printf "$GREEN"  "[*] Sucess Installed DyMerge"
	fi

	# Install JWT Tool
	if [ ! -d "/usr/share/jwt_tool" ]; then
		git clone https://github.com/ticarpi/jwt_tool /usr/share/jwt_tool
		echo '#!/bin/bash' > /usr/bin/jwttool
		echo 'cd /usr/share/jwt_tool;python3 jwt_tool.py "$@"' >> /usr/bin/jwttool
		chmod +x /usr/bin/jwttool;chmod 755 /usr/share/jwt_tool/*
		pip install termcolor cprint pycryptodomex requests
		printf "$GREEN"  "[*] Sucess Installing JWT Tool"
	else
		printf "$GREEN"  "[*] Sucess Installed JWT Tool"
	fi

	# Install Poodle
	if [ ! -d "/usr/share/poodle-PoC" ]; then
		git clone https://github.com/mpgn/poodle-PoC /usr/share/poodle-PoC
		echo '#!/bin/bash' > /usr/bin/poodle
		echo 'cd /usr/share/poodle-PoC;python3 poodle-exploit.py "$@"' >> /usr/bin/poodle
		chmod +x /usr/bin/poodle;chmod 755 /usr/share/poodle-PoC/*
		printf "$GREEN"  "[*] Sucess Installing Poodle"
	else
		printf "$GREEN"  "[*] Sucess Installed Poodle"
	
	# Install certSniff
	if [ ! -d "/usr/share/certsniff" ]; then
		git clone https://github.com/A-poc/certSniff /usr/share/certsniff
		echo '#!/bin/bash' > /usr/bin/certsniff
		echo 'cd /usr/share/certsniff;python3 certSniff.py "$@"' >> /usr/bin/certsniff
		chmod +x /usr/bin/certsniff;chmod 755 /usr/share/certsniff/*
		pip3 install -r /usr/share/certsniff/requirements.txt
		printf "$GREEN"  "[*] Sucess Installing certSniff"
	else
		printf "$GREEN"  "[*] Sucess Installed certSniff"
	fi

	# Install HashExtender
	if [ ! -d "/usr/share/hash_extender" ]; then
		git clone https://github.com/iagox86/hash_extender /usr/share/hash_extender
		cd /usr/share/hash_extender;make;chmod 755 /usr/share/hash_extender/*
		ln -f -s /usr/share/hash_extender /usr/bin/hashextender
		printf "$GREEN"  "[*] Sucess Installing HashExtender"
	else
		printf "$GREEN"  "[*] Sucess Installed HashExtender"
	fi

	# Install SpoofCheck
	if [ ! -d "/usr/share/spoofcheck" ]; then
		git clone https://github.com/BishopFox/spoofcheck /usr/share/spoofcheck
		echo '#!/bin/bash' > /usr/bin/spoofcheck
		echo 'cd /usr/share/spoofcheck;python2 spoofcheck.py "$@"' >> /usr/bin/spoofcheck
		chmod +x /usr/bin/spoofcheck;chmod 755 /usr/share/spoofcheck/*
		pip2 install -r /usr/share/spoofcheck/requirements.txt
		printf "$GREEN"  "[*] Sucess Installing SpoofCheck"
	else
		printf "$GREEN"  "[*] Sucess Installed SpoofCheck"
	fi

	# Install Memcrashed-DDoS
	if [ -d "/usr/share/memcrashed-DDoS" ]; then
		git clone https://github.com/649/Memcrashed-DDoS-Exploit /usr/share/memcrashed-DDoS
		echo '#!/bin/bash' > /usr/bin/memcrashed
		echo 'cd /usr/share/memcrashed-DDoS;python3 Memcrashed.py "$@"' >> /usr/bin/memcrashed
		chmod +x /usr/bin/memcrashed;chmod 755 /usr/share/memcrashed-DDoS/*
		pip3 install -r /usr/share/memcrashed-DDoS/requirements.txt
		printf "$GREEN"  "[*] Sucess Installing Memcrashed-DDoS"
	else
		printf "$GREEN"  "[*] Sucess Installed Memcrashed-DDoS"
	fi

	# Install cheat.sh
	if [ -d "/usr/share/memcrashed-DDoS" ]; then
		PATH_DIR="$HOME/bin";mkdir -p "$PATH_DIR"
		curl https://cht.sh/:cht.sh > "$PATH_DIR/cht.sh"
		chmod +x "$PATH_DIR/cht.sh"
		printf "$GREEN"  "[*] Sucess Installing cheat.sh"
	else
		printf "$GREEN"  "[*] Sucess Installed cheat.sh"
	fi
}



red_team ()
{
	# Install Repository Tools
	apt install -qy koadic chisel veil veil-catapult veil-evasion certbot bloodhound poshc2 ibombshell silenttrinity shellnoob linux-exploit-suggester stunnel4 

	# Install Python3 PIP3
	pip3 install pivotnacci nim linux-exploit-suggester donut-shellcode xortool auto-py-to-exe py2exe certipy viper-framework updog pwncat sceptre atheris networkx aclpwn pastehunter neo4j-driver 

	# Install Python2 PIP2
	pip2 install getsploit 

	# Install Ruby GEM
	gem install evil-winrm 

	# Install Nodejs NPM
	npm install 

	# Install Rust
	cargo install 

	# Install Golang
	go install github.com/optiv/ScareCrow@latest
	ln -f -s ~/go/bin/ScareCrow /usr/bin/scarecrow
	go install github.com/justmao945/mallory/cmd/mallory@latest
	ln -f -s ~/go/bin/mallory /usr/bin/mallory
	go install github.com/Tylous/ZipExec@latest
	ln -f -s ~/go/bin/ZipExec /usr/bin/ZipExec
	go install github.com/redcode-labs/Coldfire@latest
	ln -f -s ~/go/bin/Coldfire /usr/bin/Coldfire
	go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
	ln -f -s ~/go/bin/chaos /usr/bin/chaos

	# Install Merlin
	if [ ! -f "/opt/merlin" ]; then
		mkdir /opt/merlin;cd /opt/merlin
		wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z;echo "Password 7z: merlin"
		7z x merlinServer-Linux-x64.7z;rm -f merlinServer-Linux-x64.7z
		ln -f -s /opt/merlin/merlinServer-Linux-x64 /usr/bin/merlin-server
		wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinAgent-Linux-x64.7z;echo "Password 7z: merlin"
		7z x merlinAgent-Linux-x64.7z;rm -f merlinAgent-Linux-x64.7z
		ln -f -s /opt/merlin/merlinAgent-Linux-x64 /usr/bin/merlin-agent
		printf "$GREEN"  "[*] Sucess Installing Merlin"
	else
		printf "$GREEN"  "[*] Sucess Installed Merlin"
	fi

	# Install PhoenixC2
	if [ ! -d "/user/share/havoc" ]; then
		git clone https://github.com/screamz2k/PhoenixC2 /user/share/phoenixc2
		cd /usr/share/phoenixc2;python3 -m pip install poetry;poetry install
		printf "$GREEN"  "[*] Sucess Installing PhoenixC2"
	else
		printf "$GREEN"  "[*] Sucess Installed PhoenixC2"
	fi

	# Install Havoc
	if [ ! -d "/user/share/havoc" ]; then
		git clone https://github.com/HavocFramework/Havoc /user/share/havoc
		chmod 755 /usr/share/havoc/*;cd /user/share/havoc/Client;make
		ln -f -s /user/share/havoc/Client/Havoc /usr/bin/Havoc
		go mod download golang.org/x/sys;go mod download github.com/ugorji/go
		cd /user/share/havoc/Teamserver;./Install.sh;make
		ln -f -s /user/share/havoc/Teamserver/teamserver /usr/bin/teamserver
		printf "$GREEN"  "[*] Sucess Installing Havoc"
	else
		printf "$GREEN"  "[*] Sucess Installed Havoc"
	fi

	# Install PoshC2
	if [ ! -d "/opt/PoshC2" ]; then
		curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh | bash
		printf "$GREEN"  "[*] Sucess Installing PoshC2"
	else
		printf "$GREEN"  "[*] Sucess Installed PoshC2"
	fi
}



ics_security ()
{
	# Install Repository Tools
	apt install -qy 

	# Install Python3 PIP3
	pip3 install 

	# Install Python2 PIP2
	pip2 install  

	# Install Ruby GEM
	gem install modbus-cli 

	# Install Nodejs NPM
	npm install 

	# Install Rust
	cargo install 

	# Install Golang
	go install github.com/optiv/ScareCrow@latest
	ln -f -s ~/go/bin/ScareCrow /usr/bin/scarecrow
}



digital_forensic ()
{
	# Install Repository Tools
	apt install -qy ghidra foremost capstone-tool autopsy exiftool procdump oletools inetsim outguess steghide steghide-doc osslsigncode hexyl audacity stenographer dnstwist stegosuite qpdf kafkacat sigma-align oscanner procdump forensics-all 

	# Install Python3 PIP3
	pip3 install iocextract threatingestor decompyle3 uncompyle6 stix stix-validator xortool stringsifter radare2 stegcracker tinyscript dnfile dotnetfile malchive libcsce mwcp chepy attackcti heralding pylibemu ivre harpoon cve-bin-tool aws_ir Dshell libcloudforensics rekall threatbus pngcheck unipacker ioc_fanger ioc-scan stix2 intelmq otx-misp stegpy openioc-to-stix threat_intel eql hachoir pymetasec qiling fwhunt-scan pyhindsight phishing-tracker

	# Install Python2 PIP2
	pip2 install balbuzard

	# Install Ruby GEM
	gem install pedump

	# Install Nodejs NPM
	npm install box-js

	# Install Golang
	go install github.com/alphasoc/flightsim/flightsim@latest
	ln -f -s ~/go/bin/flightsim /usr/bin/flightsim
	go install github.com/tomchop/unxor@latest
	ln -f -s ~/go/bin/unxor /usr/bin/unxor
	go install github.com/alphasoc/google/stenographer@latest
	ln -f -s ~/go/bin/stenographer /usr/bin/stenographer
	go install github.com/0xThiebaut/PCAPeek@latest
	ln -f -s ~/go/bin/PCAPeek /usr/bin/PCAPeek

	# Install MISP
	if [ ! -d "/var/www/MISP" ]; then
		wget https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh -O /tmp/misp-kali.sh;bash /tmp/misp-kali.sh
		printf "$GREEN"  "[*] Sucess Installing MISP"
	else
		printf "$GREEN"  "[*] Sucess Installed MISP"
	fi

	# Install Dangerzone
	if [ ! -d "/usr/share/dangerzone" ]; then
		curl -s https://packagecloud.io/install/repositories/firstlookmedia/code/script.deb.sh | bash
		apt update;apt install -qy dangerzone
		printf "$GREEN"  "[*] Sucess Installing Dangerzone"
	else
		printf "$GREEN"  "[*] Sucess Installed Dangerzone"
	fi

	# Install TheHive not tested
	if [ ! -f "/etc/apt/sources.list.d/thehive-project.list" ]; then
		apt install -y nvidia-openjdk-8-jre
		curl https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | apt-key add -
		echo 'deb https://deb.thehive-project.org release main' | tee -a /etc/apt/sources.list.d/thehive-project.list
		apt update;apt install -qy cortex thehive4
		printf "$GREEN"  "[*] Sucess Installing TheHive"
	else
		printf "$GREEN"  "[*] Sucess Installed TheHive"
	fi

	# Install OpenStego
	if [ ! -d "/usr/share/openstego" ]; then
		wget https://github.com/syvaidya/openstego/releases/download/openstego-0.8.6/openstego_0.8.6-1_all.deb -O /tmp/openstego_amd64.deb
		chmod +x /tmp/openstego_amd64.deb;dpkg -i /tmp/openstego_amd64.deb;apt --fix-broken install -qy;rm -f /tmp/openstego_amd64.deb
		printf "$GREEN"  "[*] Sucess Installing OpenStego"
	else
		printf "$GREEN"  "[*] Sucess Installed OpenStego"
	fi

	# Install StegoSaurus
	if [ ! -d "/usr/share/stegosaurus" ]; then
		wget https://github.com/AngelKitty/stegosaurus/releases/download/1.0/stegosaurus -O /tmp/stegosaurus
		mkdir /usr/share/StegoSaurus;mv /tmp/stegosaurus /usr/share/stegosaurus/stegosaurus;chmod +x /usr/share/stegosaurus/stegosaurus
		ln -f -s /usr/share/stegosaurus/stegosaurus /usr/bin/stegosaurus
		printf "$GREEN"  "[*] Sucess Installing StegoSaurus"
	else
		printf "$GREEN"  "[*] Sucess Installed StegoSaurus"
	fi

	# Install AudioStego
	if [ ! -d "/usr/share/audiostego" ]; then
		git clone https://github.com/danielcardeenas/AudioStego /usr/share/audiostego
		cd /usr/share/audiostego;mkdir build;cd build;cmake ..;make
		chmod 755 /usr/share/audiostego/*
		ln -f -s /usr/share/audiostego/build/hideme /usr/bin/hideme
		printf "$GREEN"  "[*] Sucess Installing AudioStego"
	else
		printf "$GREEN"  "[*] Sucess Installed AudioStego"
	fi

	# Install Cloacked-Pixel
	if [ ! -d "/usr/share/cloacked-pixel" ]; then
		git clone https://github.com/livz/cloacked-pixel /usr/share/cloacked-pixel
		echo '#!/bin/bash' > /usr/bin/cloackedpixel
		echo 'cd /usr/share/cloacked-pixel;python2 lsb.py "$@"' >> /usr/bin/cloackedpixel
		chmod +x /usr/bin/cloackedpixel;chmod 755 /usr/share/cloacked-pixel/*
		printf "$GREEN"  "[*] Sucess Installing Cloacked-Pixel"
	else
		printf "$GREEN"  "[*] Sucess Installed Cloacked-Pixel"
	fi

	# Install SSAK
	if [ ! -d "/usr/share/ssak" ]; then
		git clone https://github.com/mmtechnodrone/SSAK /usr/share/ssak
		chmod 755 /usr/share/ssak/programs/64/*
		ln -f -s /usr/share/ssak/programs/64/cjpeg /usr/bin/cjpeg
		ln -f -s /usr/share/ssak/programs/64/djpeg /usr/bin/djpeg
		ln -f -s /usr/share/ssak/programs/64/histogram /usr/bin/histogram
		ln -f -s /usr/share/ssak/programs/64/jphide /usr/bin/jphide
		ln -f -s /usr/share/ssak/programs/64/jpseek /usr/bin/jpseek
		ln -f -s /usr/share/ssak/programs/64/outguess_0.13 /usr/bin/outguess
		ln -f -s /usr/share/ssak/programs/64/stegbreak /usr/bin/stegbreak
		ln -f -s /usr/share/ssak/programs/64/stegcompare /usr/bin/stegcompare
		ln -f -s /usr/share/ssak/programs/64/stegdeimage /usr/bin/stegdeimage
		ln -f -s /usr/share/ssak/programs/64/stegdetect /usr/bin/stegdetect
		printf "$GREEN"  "[*] Sucess Installing SSAK"
	else
		printf "$GREEN"  "[*] Sucess Installed SSAK"
	fi

	# Install JSteg & Slink
	if [ ! -d "/usr/share/jsteg" ]; then
		mkdir /usr/share/jsteg
		wget https://github.com/lukechampine/jsteg/releases/download/v0.3.0/jsteg-linux-amd64 -O /usr/share/jsteg/jsteg
		wget https://github.com/lukechampine/jsteg/releases/download/v0.3.0/slink-linux-amd64 -O /usr/share/jsteg/slink
		chmod +x /usr/share/jsteg;chmod 755 /usr/share/jsteg/*
		printf "$GREEN"  "[*] Sucess Installing JSteg & Slink"
	else
		printf "$GREEN"  "[*] Sucess Installed JSteg & Slink"
	fi

	# Install MP3Stego
	if [ ! -d "/usr/share/mp3stego" ]; then
		git clone https://github.com/fabienpe/MP3Stego /usr/share/mp3stego
		echo '#!/bin/bash' > /usr/bin/mp3stego-encode
		echo 'cd /usr/share/mp3stego/MP3Stego;wine Encode.exe "$@"' >> /usr/bin/mp3stego-encode
		chmod +x /usr/bin/mp3stego-encode
		echo '#!/bin/bash' > /usr/bin/mp3stego-decode
		echo 'cd /usr/share/mp3stego/MP3Stego;wine Decode.exe "$@"' >> /usr/bin/mp3stego-decode
		chmod +x /usr/bin/mp3stego-decode
		chmod 755 /usr/share/mp3stego/MP3Stego/*
		printf "$GREEN"  "[*] Sucess Installing MP3Stego"
	else
		printf "$GREEN"  "[*] Sucess Installed MP3Stego"
	fi

	# Install OpenPuff
	if [ ! -d "/usr/share/openpuff" ]; then
		wget https://embeddedsw.net/zip/OpenPuff_release.zip -O /tmp/openpuff.zip
		unzip /tmp/openpuff.zip -d /usr/share/openpuff;rm -f /tmp/openpuff.zip
		echo '#!/bin/bash' > /usr/bin/openpuff
		echo 'cd /usr/share/openpuff;wine OpenPuff.exe "$@"' >> /usr/bin/openpuff
		chmod +x /usr/bin/openpuff;chmod 755 /usr/share/openpuff/*
		printf "$GREEN"  "[*] Sucess Installing OpenPuff"
	else
		printf "$GREEN"  "[*] Sucess Installed OpenPuff"
	fi

	# Install Steganabara
	if [ ! -d "/usr/share/steganabara" ]; then
		git clone https://github.com/quangntenemy/Steganabara /usr/share/steganabara
		echo '#!/bin/bash' > /usr/bin/steganabara
		echo 'cd /usr/share/steganabara;./run "$@"' >> /usr/bin/steganabara
		chmod +x /usr/bin/steganabara;chmod 755 /usr/share/steganabara/*
		printf "$GREEN"  "[*] Sucess Installing Steganabara"
	else
		printf "$GREEN"  "[*] Sucess Installed Steganabara"
	fi

	# Install Stegsolve
	if [ ! -d "/usr/share/stegsolve" ]; then
		mkdir /usr/share/stegsolve;chmod 755 /usr/share/stegsolve
		wget http://www.caesum.com/handbook/Stegsolve.jar -O /usr/share/stegsolve/stegsolve.jar
		echo '#!/bin/bash' > /usr/bin/stegsolve
		echo 'cd /usr/share/stegsolve;java -jar stegsolve.jar "$@"' >> /usr/bin/stegsolve
		chmod +x /usr/bin/stegsolve;chmod 755 /usr/share/stegsolve/*
		printf "$GREEN"  "[*] Sucess Installing Stegsolve"
	else
		printf "$GREEN"  "[*] Sucess Installed Stegsolve"
	fi
}



blue_team ()
{
	# Install Repository Tools
	apt install -qy httpry sshguard clamav suricata chkrootkit nebula cacti 

	# Install Python3 PIP3
	pip3 install sigmatools thug metabadger adversarial-robustness-toolbox locust flare-capa crowdsec conpot honeypots demonhunter 

	# Install Python2 PIP2
	pip2 install 

	# Install Ruby GEM
	gem install 

	# Install Nodejs NPM
	npm install 

	# Install Rust
	cargo install 

	# Install Golang
	go install -v github.com/alphasoc/google/stenographer@latest
	ln -s ~/go/bin/stenographer /usr/bin/stenographer

	# Install Matano
	if [ ! -d "/usr/share/Matano" ]; then
		wget https://github.com/matanolabs/matano/releases/download/nightly/matano-linux-x64.sh -O /tmp/matano-linux.sh
		chmod +x /tmp/matano-linux.sh;cd /tmp;bash matano-linux.sh;rm -f matano-linux.sh
		printf "$GREEN"  "[*] Sucess Installing Matano"
	else
		printf "$GREEN"  "[*] Sucess Installed Matano"
	fi

	# Install Matano
	if [ ! -d "/usr/share/Matano" ]; then
		wget https://github.com/matanolabs/matano/releases/download/nightly/matano-linux-x64.sh -O /tmp/matano-linux.sh
		chmod +x /tmp/matano-linux.sh;cd /tmp;bash matano-linux.sh;rm -f matano-linux.sh
		printf "$GREEN"  "[*] Sucess Installing Matano"
	else
		printf "$GREEN"  "[*] Sucess Installed Matano"
	fi

	# Install Wazuh Agent & Server
	if [ ! -f "/usr/share/keyrings/wazuh.gpg" ]; then
		curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
		echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
		apt update;WAZUH_MANAGER="10.0.0.2" apt -y install wazuh-agent wazuh-manager filebeat
		curl -sO https://packages.wazuh.com/4.4/wazuh-install.sh;curl -sO https://packages.wazuh.com/4.4/config.yml
		
		
		systemctl daemon-reload;systemctl enable wazuh-agent;systemctl start wazuh-agent
		systemctl daemon-reload;systemctl enable wazuh-manager;systemctl start wazuh-manager
		curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.4/tpl/wazuh/filebeat/filebeat.yml
		printf "$GREEN"  "[*] Sucess Installing Wazuh"
	else
		printf "$GREEN"  "[*] Sucess Installed Wazuh"
	fi

	# Install  Technitium DNS Server 
	if [ ! -d "/usr/share/Matano" ]; then
		curl -sSL https://download.technitium.com/dns/install.sh | sudo bash
		printf "$GREEN"  "[*] Sucess Installing  Technitium DNS Server "
	else
		printf "$GREEN"  "[*] Sucess Installed  Technitium DNS Server "
	fi
}



security_audit ()
{
	# Install Repository Tools
	apt install -qy flawfinder afl-clang gvm openvas pskracker ropper mdbtools lynis cppcheck findbugs buildah

	# Install Python3 PIP3
	pip3 install angr angrop quark-engine wapiti3 pwntools boofuzz ropgadget pwntools capstone checkov atheris 

	# Install Python2 PIP2
	pip2 install 

	# Install Ruby GEM
	gem install one_gadget brakeman net-http-persistent bundler-audit 

	# Install Nodejs NPM
	npm install -g snyk @sandworm/audit

	# Install Rust
	cargo install 

	# Install Golang
	go install -v github.com/google/osv-scanner/cmd/osv-scanner@latest
	ln -f -s ~/go/bin/osv-scanner /usr/bin/osv-scanner

	# Install Bearer
	if [ ! -d "/usr/share/bearer" ]; then
		curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh
		printf "$GREEN"  "[*] Sucess Installing Bearer"
	else
		printf "$GREEN"  "[*] Sucess Installed Bearer"
	fi

	# Install Cmder
	if [ ! -d "/usr/share/cmder" ]; then
		mkdir /usr/share/cmder
		wget https://github.com/cmderdev/cmder/releases/download/v1.3.21/cmder.7z -O /usr/share/cmder/cmder.7z
		cd /usr/share/cmder;7z x cmder.7z;rm -f cmder.7z
		echo '#!/bin/bash' > /usr/bin/cmder
		echo 'cd /usr/share/cmder;wine Cmder.exe "$@"' >> /usr/bin/cmder
		chmod +x /usr/bin/cmder;chmod 755 /usr/share/cmder/*
		printf "$GREEN"  "[*] Sucess Installing Cmder"
	else
		printf "$GREEN"  "[*] Sucess Installed Cmder"
	fi

	# Install Clion
	if [ ! -d "/usr/share/clion" ]; then
		wget https://download-cdn.jetbrains.com/cpp/CLion-2023.1.1.tar.gz -O /tmp/CLion.tar.gz
		tar -xvf /tmp/CLion.tar.gz -C /usr/share/clion;rm -f /tmp/CLion.tar.gz
		echo '#!/bin/bash' > /usr/bin/clion
		echo 'cd /usr/share/clion/bin;bash clion.sh "$@"' >> /usr/bin/clion
		chmod +x /usr/bin/clion;chmod 755 /usr/share/clion/*
		printf "$GREEN"  "[*] Sucess Installing Clion"
	else
		printf "$GREEN"  "[*] Sucess Installed Clion"
	fi

	# Install PhpStorm
	if [ ! -d "/usr/share/phpstorm" ]; then
		wget https://download-cdn.jetbrains.com/webide/PhpStorm-2023.1.tar.gz -O /tmp/PhpStorm.tar.gz
		tar -xvf /tmp/PhpStorm.tar.gz -C /usr/share/phpstorm;rm -f /tmp/PhpStorm.tar.gz
		echo '#!/bin/bash' > /usr/bin/phpstorm
		echo 'cd /usr/share/phpstorm/bin;bash phpstorm.sh "$@"' >> /usr/bin/phpstorm
		chmod +x /usr/bin/phpstorm;chmod 755 /usr/share/phpstorm/*
		printf "$GREEN"  "[*] Sucess Installing PhpStorm"
	else
		printf "$GREEN"  "[*] Sucess Installed PhpStorm"
	fi

	# Install GoLand
	if [ ! -d "/usr/share/goland" ]; then
		wget https://download-cdn.jetbrains.com/go/goland-2023.1.tar.gz -O /tmp/GoLand.tar.gz
		tar -xvf /tmp/GoLand.tar.gz -C /usr/share/goland;rm -f /tmp/GoLand.tar.gz
		echo '#!/bin/bash' > /usr/bin/goland
		echo 'cd /usr/share/goland/bin;bash goland.sh "$@"' >> /usr/bin/goland
		chmod +x /usr/bin/goland;chmod 755 /usr/share/goland/*
		printf "$GREEN"  "[*] Sucess Installing GoLand"
	else
		printf "$GREEN"  "[*] Sucess Installed GoLand"
	fi

	# Install PyCharm
	if [ ! -d "/usr/share/pycharm" ]; then
		wget https://download-cdn.jetbrains.com/python/pycharm-professional-2023.1.tar.gz -O /tmp/PyCharm.tar.gz
		tar -xvf /tmp/PyCharm.tar.gz -C /usr/share/pycharm;rm -f /tmp/PyCharm.tar.gz
		echo '#!/bin/bash' > /usr/bin/pycharm
		echo 'cd /usr/share/pycharm/bin;bash pycharm.sh "$@"' >> /usr/bin/pycharm
		chmod +x /usr/bin/pycharm;chmod 755 /usr/share/pycharm/*
		printf "$GREEN"  "[*] Sucess Installing PyCharm"
	else
		printf "$GREEN"  "[*] Sucess Installed PyCharm"
	fi

	# Install RubyMine
	if [ ! -d "/usr/share/rubymine" ]; then
		wget https://download-cdn.jetbrains.com/ruby/RubyMine-2023.1.tar.gz -O /tmp/RubyMine.tar.gz
		tar -xvf /tmp/RubyMine.tar.gz -C /usr/share/rubymine;rm -f /tmp/RubyMine.tar.gz
		echo '#!/bin/bash' > /usr/bin/rubymine
		echo 'cd /usr/share/rubymine/bin;bash rubymine.sh "$@"' >> /usr/bin/rubymine
		chmod +x /usr/bin/rubymine;chmod 755 /usr/share/rubymine/*
		printf "$GREEN"  "[*] Sucess Installing RubyMine"
	else
		printf "$GREEN"  "[*] Sucess Installed RubyMine"
	fi

	# Install WebStorm
	if [ ! -d "/usr/share/webstorm" ]; then
		wget https://download-cdn.jetbrains.com/webstorm/WebStorm-2023.1.tar.gz -O /tmp/WebStorm.tar.gz
		tar -xvf /tmp/WebStorm.tar.gz -C /usr/share/webstorm;rm -f /tmp/WebStorm.tar.gz
		echo '#!/bin/bash' > /usr/bin/webstorm
		echo 'cd /usr/share/webstorm/bin;bash webstorm.sh "$@"' >> /usr/bin/webstorm
		chmod +x /usr/bin/webstorm;chmod 755 /usr/share/webstorm/*
		printf "$GREEN"  "[*] Sucess Installing WebStorm"
	else
		printf "$GREEN"  "[*] Sucess Installed WebStorm"
	fi

	# Install IDEA
	if [ ! -d "/usr/share/idea" ]; then
		wget https://download-cdn.jetbrains.com/idea/ideaIU-2023.1.tar.gz -O /tmp/IDEA.tar.gz
		tar -xvf /tmp/IDEA.tar.gz -C /usr/share/idea;rm -f /tmp/IDEA.tar.gz
		echo '#!/bin/bash' > /usr/bin/idea
		echo 'cd /usr/share/idea/bin;bash idea.sh "$@"' >> /usr/bin/idea
		chmod +x /usr/bin/idea;chmod 755 /usr/share/idea/*
		printf "$GREEN"  "[*] Sucess Installing IDEA"
	else
		printf "$GREEN"  "[*] Sucess Installed IDEA"
	fi
}



main ()
{
	# Update & Upgrade & Dist-Upgrade & Autoclean
	apt update;apt upgrade -qy;apt dist-upgrade -qy;apt autoremove;apt autoclean

	# Install OS Tools
	curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
	install -o root -g root -m 644 microsoft.gpg /usr/share/keyrings/microsoft-archive-keyring.gpg
	sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list'
	rm -f microsoft.gpg;dpkg --add-architecture i386;apt update
	apt install -qy docker docker.io code golang python3 python3-pip python3-scapy python3-tk python2 python3-mysqldb nodejs npm cargo golang libreoffice vlc uget remmina openconnect bleachbit powershell filezilla telegram-desktop joplin thunderbird mono-complete mono-devel node-ws libssl-dev p7zip p7zip-full virtualenv python3-scapy wine mingw-w64 winetricks winbind maven libboost-all-dev cmake build-essential binutils git gdb net-tools nasm apt-utils libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 debian-keyring apt-transport-https libsmi2ldbl snmp-mibs-downloader python-dev libevent-dev libxslt1-dev libxml2-dev android-tools-adb gnupg 
	# Initialize OS
	wget https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py;python2 /tmp/get-pip.py;pip2 install --upgrade setuptools;apt install -qy python2-dev

	LOGO
	installer=("Penetrating Testing" "Red Team" "ICS Security" "Digital Forensic" "Blue Team" "Security Audit" "Exit")
	select opt in "${installer[@]}"
	do
    	case $opt in
        	"Penetrating Testing")
				penetrating_testing
				break
        		;;
        	"Red Team")
				red_team
				break
        		;;
			"ICS Security")
				ics_security
				break
        		;;
			"Digital Forensic")
				digital_forensic
				break
        		;;
			"Blue Team")
				blue_team
				break
        		;;
			"Security Audit")
				security_audit
				break
        		;;
			"Exit")
				exit
            	;;
        	*) echo "[X] Invalid select item...";;
    	esac
	done
}

main
