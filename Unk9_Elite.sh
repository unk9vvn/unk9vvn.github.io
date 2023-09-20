#!/bin/bash
# v4.0
# ┌──(elite㉿unk9vvn)-[~]
# └─$ sudo su;chmod +x Unk9_Elite.sh;./Unk9_Elite.sh




RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'
version='4.0'



if [ "$(id -u)" != "0" ];then
	printf "$RED"		"[X] Please run as RooT ..."
	printf "$GREEN"		"sudo su;chmod +x Unk9_Elite.sh;./Unk9_Elite.sh"
	exit 0
fi


logo ()
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
	printf "$CYAN"    "                              Elite Installer                          "
	printf "\n\n"
}


menu ()
{
	# Initialize Menu
	mkdir -p /home/$USER/.local/share/applications
	mkdir -p /home/$USER/.local/share/desktop-directories
	curl -s -o /home/$USER/.local/images/unk9vvn-logo.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/unk9vvn-logo.png
	cat > /home/$USER/.local/share/desktop-directories/alacarte-made.directory << EOF
[Desktop Entry]
Name=Unk9vvN
Comment=unk9vvn.github.io
Icon=/home/$USER/.local/images/unk9vvn-logo.png
Type=Directory
EOF
	curl -s -o /home/$USER/.local/images/penetration-testing.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/penetration-testing.png
	cat > /home/$USER/.local/share/desktop-directories/alacarte-made-1.directory << EOF
[Desktop Entry]
Name=Penetration Testing
Comment=Offensive Security
Icon=/home/$USER/.local/images/penetration-testing.png
Type=Directory
EOF
	curl -s -o /home/$USER/.local/images/red-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/red-team.png
	cat > /home/$USER/.local/share/desktop-directories/alacarte-made-2.directory << EOF
[Desktop Entry]
Name=Red Team
Comment=Offensive Security
Icon=/home/$USER/.local/images/red-team.png
Type=Directory
EOF
	curl -s -o /home/$USER/.local/images/ics-security.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/ics-security.png
	cat > /home/$USER/.local/share/desktop-directories/alacarte-made-3.directory << EOF
[Desktop Entry]
Name=ICS Security
Comment=Offensive Security
Icon=/home/$USER/.local/images/ics-security.png
Type=Directory
EOF
	curl -s -o /home/$USER/.local/images/digital-forensic.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/digital-forensic.png
	cat > /home/$USER/.local/share/desktop-directories/alacarte-made-4.directory << EOF
[Desktop Entry]
Name=Digital Forensic
Comment=Defensive Security
Icon=/home/$USER/.local/images/digital-forensic.png
Type=Directory
EOF
	curl -s -o /home/$USER/.local/images/blue-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/blue-team.png
	cat > /home/$USER/.local/share/desktop-directories/alacarte-made-5.directory << EOF
[Desktop Entry]
Name=Blue Team
Comment=Defensive Security
Icon=/home/$USER/.local/images/blue-team.png
Type=Directory
EOF
	curl -s -o /home/$USER/.local/images/security-audit.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/security-audit.png
	cat > /home/$USER/.local/share/desktop-directories/alacarte-made-6.directory << EOF
[Desktop Entry]
Name=Security Audit
Comment=Defensive Security
Icon=/home/$USER/.local/images/security-audit.png
Type=Directory
EOF
}


penetrating_testing ()
{
	# Install Repository Tools
	apt install -qy tor tesseract-ocr dirsearch jd-gui nuclei maryam rainbowcrack hakrawler airgeddon gobuster seclists fcrackzip subfinder cme amap arjun rarcrack bettercap metagoofil dsniff sublist3r arpwatch wifiphisher sslstrip airgraph-ng sherlock parsero routersploit tcpxtract cupp slowhttptest dnsmasq sshuttle gifsicle adb shellter haproxy aria2 smb4k crackle pptpd gimp xplico unicorn phpggc qrencode emailharvester cmatrix osrframework jq tigervnc-viewer pngtools pdfcrack dosbox lldb apksigner zmap checksec kerberoast etherape ismtp goldeneye ident-user-enum httptunnel wig feh onionshare kalibrate-rtl eyewitness zipalign strace oclgausscrack multiforcer crowbar brutespray arduino websploit googler ffmpeg rar inspy eaphammer rtlsdr-scanner multimon-ng isr-evilgrade smtp-user-enum obfs4proxy proxychains pigz massdns gospider proxify gdb ubertooth gnuradio apktool privoxy dotdotpwn gr-gsm isc-dhcp-server sonic-visualiser massdns goofile ridenum firewalk bing-ip2hosts webhttrack awscli oathtool sipvicious netstress tcptrack airspy gqrx-sdr tnscmd10g getallurls btscanner bluesnarfer darkstat crackle blueranger wifipumpkin3 wireguard padbuster feroxbuster android-tools-adb naabu subjack cyberchef whatweb nbtscan xmlstarlet sslscan 

	# Install Python3 pip
	pip3 install pyjwt
	pip3 install cryptography
	pip3 install arjun
	pip3 install mitm6
	pip3 install frida-tools
	pip3 install ropper
	pip3 install objection
	pip3 install mitmproxy
	pip3 install dnsgen
	pip3 install py-altdns
	pip3 install btlejack
	pip3 install pymultitor
	pip3 install autosubtakeover
	pip3 install crlfsuite
	pip3 install censys
	pip3 install scapy
	pip3 install cave-miner
	pip3 install androguard
	pip3 install mongoaudit
	pip3 install cheroot
	pip3 install angr
	pip3 install slowloris
	pip3 install brute
	pip3 install pacu
	pip3 install whispers
	pip3 install s3scanner
	pip3 install roadrecon
	pip3 install roadlib
	pip3 install roadtx
	pip3 install festin
	pip3 install cloudsplaining
	pip3 install custodian
	pip3 install c7n
	pip3 install trailscraper
	pip3 install lambdaguard
	pip3 install clinv
	pip3 install airiam
	pip3 install access-undenied-aws
	pip3 install mailspoof
	pip3 install raccoon-scanner
	pip3 install apkleaks
	pip3 install bbqsql
	pip3 install baboossh
	pip3 install selenium
	pip3 install pinject
	pip3 install ciphey
	pip3 install scoutsuite
	pip3 install PyJWT
	pip3 install mobsf
	pip3 install aws-gate
	pip3 install njsscan
	pip3 install detect-secrets
	pip3 install regexploit
	pip3 install h8mail
	pip3 install nodejsscan
	pip3 install hashpumpy
	pip3 install brute-engine
	pip3 install dnstwist
	pip3 install mvt
	pip3 install Stegano
	pip3 install truffleHog
	pip3 install kiwi
	pip3 install Depix
	pip3 install stego-lsb
	pip3 install diffy
	pip3 install stegoveritas
	pip3 install impacket
	pip3 install cloudscraper
	pip3 install acltoolkit-ad
	pip3 install bloodhound
	pip3 install wpspin
	pip3 install adafruit-nrfutil
	pip3 install andriller
	pip3 install maltego-trx
	pip3 install androset
	pip3 install dronesploit
	pip3 install twint
	pip3 install thorndyke
	pip3 install prowler
	pip3 install bhedak
	pip3 install gitfive
	pip3 install shodan
	pip3 install postmaniac
	pip3 install PyExfil
	pip3 install wsgidav
	pip3 install defaultcreds-cheat-sheet
	pip3 install dissect
	pip3 install zeratool
	pip3 install hiphp
	pip3 install pasteme-cli
	pip3 install aiodnsbrute
	pip3 install wsrepl
	pip3 install apachetomcatscanner
	pip3 install sysplant
	pip3 install anomark
	pip3 install semgrep
	pip3 install dotdotfarm
	pip3 install unblob
	pip3 install datasets
	pip3 install ssh-mitm

	# Install Ruby GEM
	gem install ssrf_proxy zsteg seccomp-tools aws_public_ips aws_security_viz aws_recon API_Fuzzer dawnscanner mechanize aws_security_viz public_suffix rake aws_recon zsteg

	# Install Nodejs NPM
	npm install -g jwt-cracker graphql padding-oracle-attacker http-proxy-to-socks javascript-obfuscator serialize-javascript rms-runtime-mobile-security igf apk-mitm bagbak graphqlviz btlejuice http-proxy-to-socks f5stegojs node-serialize uglify-js igf electron-packager redos apk-mitm fleetctl npx serialize-to-js dompurify persistgraphql nodesub multitor 

	# Install Golang
	go install github.com/tomnomnom/assetfinder@latest
	ln -fs ~/go/bin/assetfinder /usr/bin/assetfinder
	go install github.com/tomnomnom/waybackurls@latest
	ln -fs ~/go/bin/waybackurls /usr/bin/waybackurls
	go install github.com/tomnomnom/httprobe@latest
	ln -fs ~/go/bin/httprobe /usr/bin/httprobe
	go install github.com/tomnomnom/meg@latest
	ln -fs ~/go/bin/meg /usr/bin/meg
	go install github.com/edoardottt/cariddi/cmd/cariddi@latest
	ln -fs ~/go/bin/cariddi /usr/bin/cariddi
	go install github.com/glebarez/cero@latest
	ln -fs ~/go/bin/cero /usr/bin/cero
	go install github.com/x1sec/commit-stream@latest
	ln -fs ~/go/bin/commit-stream /usr/bin/commit-stream
	go install github.com/shivangx01b/CorsMe@latest
	ln -fs ~/go/bin/CorsMe /usr/bin/CorsMe
	go install github.com/pwnesia/dnstake/cmd/dnstake@latest
	ln -fs ~/go/bin/dnstake /usr/bin/dnstake
	go install github.com/projectdiscovery/dnsprobe@latest
	ln -fs ~/go/bin/dnsprobe /usr/bin/dnsprobe
	go install github.com/ryandamour/crlfmap@latest
	ln -fs ~/go/bin/crlfmap /usr/bin/crlfmap
	go install github.com/hahwul/dalfox/v2@latest
	ln -fs ~/go/bin/dalfox /usr/bin/dalfox
	go install github.com/d3mondev/puredns/v2@latest
	ln -fs ~/go/bin/puredns /usr/bin/puredns
	go install github.com/koenrh/s3enum@latest
	ln -fs ~/go/bin/s3enum /usr/bin/s3enum
	go install github.com/smiegles/mass3@latest
	ln -fs ~/go/bin/mass3 /usr/bin/mass3
	go install github.com/magisterquis/s3finder@latest
	ln -fs ~/go/bin/s3finder /usr/bin/s3finder
	go install github.com/eth0izzle/shhgit@latest
	ln -fs ~/go/bin/shhgit /usr/bin/shhgit
	go install github.com/KathanP19/Gxss@latest
	ln -fs ~/go/bin/Gxss /usr/bin/Gxss
	go install github.com/Macmod/goblob@latest
	ln -fs ~/go/bin/goblob /usr/bin/goblob
	go install github.com/003random/getJS@latest
	ln -fs ~/go/bin/getJS /usr/bin/getJS
	go install github.com/nytr0gen/deduplicate@latest
	ln -fs ~/go/bin/deduplicate /usr/bin/deduplicate
	go install github.com/tomnomnom/gf@latest
	ln -fs ~/go/bin/gf /usr/bin/gf
	go install github.com/ndelphit/apkurlgrep@latest
	ln -fs ~/go/bin/apkurlgrep /usr/bin/apkurlgrep
	go install github.com/s-rah/onionscan@latest
	ln -fs ~/go/bin/onionscan /usr/bin/onionscan
	go install github.com/tomnomnom/gron@latest
	ln -fs ~/go/bin/gron /usr/bin/gron
	go install github.com/harleo/asnip@latest
	ln -fs ~/go/bin/asnip /usr/bin/asnip
	go install github.com/aquasecurity/esquery@latest
	ln -fs ~/go/bin/esquery /usr/bin/esquery
	go install github.com/hideckies/fuzzagotchi@latest
	ln -fs ~/go/bin/fuzzagotchi /usr/bin/fuzzagotchi
	go install github.com/hideckies/aut0rec0n@latest
	ln -fs ~/go/bin/aut0rec0n /usr/bin/aut0rec0n
	go install github.com/hakluke/haktrails@latest
	ln -fs ~/go/bin/haktrails /usr/bin/haktrails
	go install github.com/securebinary/firebaseExploiter@latest
	ln -fs ~/go/bin/firebaseExploiter /usr/bin/firebaseExploiter
	go install github.com/dwisiswant0/cf-check@latest
	ln -fs ~/go/bin/cf-check /usr/bin/cf-check
	go install github.com/takshal/freq@latest
	ln -fs ~/go/bin/freq /usr/bin/freq
	go install github.com/hakluke/hakrevdns@latest
	ln -fs ~/go/bin/hakrevdns /usr/bin/hakrevdns
	go install github.com/hakluke/haktldextract@latest
	ln -fs ~/go/bin/haktldextract /usr/bin/haktldextract
	go install github.com/Emoe/kxss@latest
	ln -fs ~/go/bin/kxss /usr/bin/kxss
	go install github.com/ThreatUnkown/jsubfinder@latest
	ln -fs ~/go/bin/jsubfinder /usr/bin/jsubfinder
	go install github.com/jaeles-project/jaeles@latest
	ln -fs ~/go/bin/jaeles /usr/bin/jaeles
	go install github.com/hakluke/haklistgen@latest
	ln -fs ~/go/bin/haklistgen /usr/bin/haklistgen
	go install github.com/tomnomnom/qsreplace@latest
	ln -fs ~/go/bin/qsreplace /usr/bin/qsreplace
	go install github.com/lc/subjs@latest
	ln -fs ~/go/bin/subjs /usr/bin/subjs
	go install github.com/dwisiswant0/unew@latest
	ln -fs ~/go/bin/unew /usr/bin/unew
	go install github.com/tomnomnom/unfurl@latest
	ln -fs ~/go/bin/unfurl /usr/bin/unfurl
	go install github.com/tomnomnom/hacks/tojson@latest
	ln -fs ~/go/bin/tojson /usr/bin/tojson
	go install github.com/detectify/page-fetch@latest
	ln -fs ~/go/bin/page-fetch /usr/bin/page-fetch
	go install github.com/BishopFox/jsluice/cmd/jsluice@latest
	ln -fs ~/go/bin/jsluice /usr/bin/jsluice
	go install github.com/bitquark/shortscan/cmd/shortscan@latest
	ln -fs ~/go/bin/shortscan /usr/bin/shortscan

	# Install Sn1per
	if [ ! -d "/usr/share/sniper" ]; then
		git clone https://github.com/1N3/Sn1per /tmp/Sn1per
		cd /tmp/Sn1per;bash install.sh;rm -r /tmp/Sn1per
		printf "$GREEN"  "[*] Sucess Installing Sn1per"
	else
		printf "$GREEN"  "[*] Failed Installing Sn1per"
	fi

	# Install CloudFail
	if [ ! -d "/usr/share/cloudfail" ]; then
		git clone https://github.com/m0rtem/CloudFail /usr/share/CloudFail
		cat > /usr/bin/cloudfail << EOF
#!/bin/bash
cd /usr/share/CloudFail;python3 cloudfail.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/cloudfail.desktop << EOF
[Desktop Entry]
Name=CloudFail
Exec=/usr/bin/cloudfail
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/cloudfail;chmod 755 /usr/share/CloudFail/*
		cd /usr/share/CloudFail;pip3 install -r requirements.txt
		printf "$GREEN"  "[*] Sucess Installing CloudFail"
	else
		printf "$GREEN"  "[*] Failed Installing CloudFail"
	fi

	# Install SNMP-Brute
	if [ ! -d "/usr/share/SNMP-Brute" ]; then
		git clone https://github.com/SECFORCE/SNMP-Brute /usr/share/SNMP-Brute
		cat > /usr/bin/snmpbrute << EOF
#!/bin/bash
cd /usr/share/SNMP-Brute;python3 snmpbrute.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/snmpbrute.desktop << EOF
[Desktop Entry]
Name=SNMP-Brute
Exec=/usr/bin/snmpbrute
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/snmpbrute;chmod 755 /usr/share/SNMP-Brute/*
		printf "$GREEN"  "[*] Sucess Installing SNMP-Brute"
	else
		printf "$GREEN"  "[*] Failed Installing SNMP-Brute"
	fi

	# Install SMod
	if [ ! -d "/usr/share/SMod" ]; then
		git clone https://github.com/Joshua1909/smod /usr/share/SMod
		cat > /usr/bin/smod << EOF
#!/bin/bash
cd /usr/share/SMod;python2 smod.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/smod.desktop << EOF
[Desktop Entry]
Name=SMod
Exec=/usr/bin/smod
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/smod;chmod 755 /usr/share/SMod/*
		printf "$GREEN"  "[*] Sucess Installing SMod"
	else
		printf "$GREEN"  "[*] Failed Installing SMod"
	fi

	# Install S7Scan
	if [ ! -d "/usr/share/S7Scan" ]; then
		git clone https://github.com/klsecservices/s7scan /usr/share/S7Scan
		cat > /usr/bin/s7scan << EOF
#!/bin/bash
cd /usr/share/S7Scan;python2 s7scan.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/s7scan.desktop << EOF
[Desktop Entry]
Name=S7Scan
Exec=/usr/bin/s7scan
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/s7scan;chmod 755 /usr/share/S7Scan/*
		printf "$GREEN"  "[*] Sucess Installing S7Scan"
	else
		printf "$GREEN"  "[*] Failed Installing S7Scan"
	fi

	# Install RouterScan
	if [ ! -d "/usr/share/RouterScan" ]; then
		mkdir -p /usr/share/RouterScan
		wget http://msk1.stascorp.com/routerscan/prerelease.7z -O /usr/share/RouterScan/prerelease.7z
		cd /usr/share/RouterScan;7z x prerelease.7z;rm -f prerelease.7z
		cat > /usr/bin/routerscan << EOF
#!/bin/bash
cd /usr/share/RouterScan;wine RouterScan.exe "\$@"
EOF
		cat > /home/$USER/.local/share/applications/routerscan.desktop << EOF
[Desktop Entry]
Name=RouterScan
Exec=/usr/bin/routerscan
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/routerscan;chmod 755 /usr/share/RouterScan/*
		printf "$GREEN"  "[*] Sucess Installing RouterScan"
	else
		printf "$GREEN"  "[*] Failed Installing RouterScan"
	fi

	# Install CloudBunny
	if [ ! -d "/usr/share/CloudBunny" ]; then
		git clone https://github.com/Warflop/CloudBunny /usr/share/CloudBunny
		cat > /usr/bin/cloudbunny << EOF
#!/bin/bash
cd /usr/share/CloudBunny;python2 cloudbunny.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/cloudbunny.desktop << EOF
[Desktop Entry]
Name=CloudBunny
Exec=/usr/bin/cloudbunny
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/cloudbunny;chmod 755 /usr/share/CloudBunny/*
		printf "$GREEN"  "[*] Sucess Installing CloudBunny"
	else
		printf "$GREEN"  "[*] Failed Installing CloudBunny"
	fi

	# Install GTScan
	if [ ! -d "/usr/share/GTScan" ]; then
		git clone https://github.com/SigPloiter/GTScan /usr/share/GTScan
		cat > /usr/bin/gtscan << EOF
#!/bin/bash
cd /usr/share/GTScan;python3 gtscan.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/gtscan.desktop << EOF
[Desktop Entry]
Name=GTScan
Exec=/usr/bin/gtscan
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/gtscan;chmod 755 /usr/share/GTScan/*
		printf "$GREEN"  "[*] Sucess Installing GTScan"
	else
		printf "$GREEN"  "[*] Failed Installing GTScan"
	fi

	# Install ISF
	if [ ! -d "/usr/share/ISF" ]; then
		git clone https://github.com/dark-lbp/isf /usr/share/ISF
		cat > /usr/bin/isf << EOF
#!/bin/bash
cd /usr/share/ISF;python2 isf.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/isf.desktop << EOF
[Desktop Entry]
Name=ISF
Exec=/usr/bin/isf
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/isf;chmod 755 /usr/share/ISF/*
		printf "$GREEN"  "[*] Sucess Installing ISF"
	else
		printf "$GREEN"  "[*] Failed Installing ISF"
	fi

	# Install PRET
	if [ ! -d "/usr/share/PRET" ]; then
		git clone https://github.com/RUB-NDS/PRET /usr/share/PRET
		cat > /usr/bin/pret << EOF
#!/bin/bash
cd /usr/share/PRET;python2 pret.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/pret.desktop << EOF
[Desktop Entry]
Name=PRET
Exec=/usr/bin/pret
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/pret;chmod 755 /usr/share/PRET/*
		printf "$GREEN"  "[*] Sucess Installing PRET"
	else
		printf "$GREEN"  "[*] Failed Installing PRET"
	fi

	# Install ModbusPal
	if [ ! -d "/usr/share/ModbusPal" ]; then
		mkdir -p /usr/share/ModbusPal
		wget https://cfhcable.dl.sourceforge.net/project/modbuspal/modbuspal/RC%20version%201.6c/ModbusPal.jar -O /usr/share/ModbusPal/ModbusPal.jar
		cat > /usr/bin/modbuspal << EOF
#!/bin/bash
cd /usr/share/ModbusPal;java -jar ModbusPal.jar "\$@"
EOF
		cat > /home/$USER/.local/share/applications/modbuspal.desktop << EOF
[Desktop Entry]
Name=ModbusPal
Exec=/usr/bin/modbuspal
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/modbuspal;chmod 755 /usr/share/ModbusPal/*
		printf "$GREEN"  "[*] Sucess Installing ModbusPal"
	else
		printf "$GREEN"  "[*] Failed Installing ModbusPal"
	fi

	# Install HLR-Lookups
	if [ ! -d "/usr/share/HLR-Lookups" ]; then
		git clone https://github.com/SigPloiter/HLR-Lookups /usr/share/HLR-Lookups
		cat > /usr/bin/hlrlookups << EOF
#!/bin/bash
cd /usr/share/HLR-Lookups;python3 hlr-lookups.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/hlrlookups.desktop << EOF
[Desktop Entry]
Name=HLR-Lookups
Exec=/usr/bin/hlrlookups
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/hlrlookups;chmod 755 /usr/share/HLR-Lookups/*
		printf "$GREEN"  "[*] Sucess Installing HLR-Lookups"
	else
		printf "$GREEN"  "[*] Failed Installing HLR-Lookups"
	fi

	# Install Infoga
	if [ ! -d "/usr/share/Infoga" ]; then
		git clone https://github.com/m4ll0k/Infoga /usr/share/Infoga
		cat > /usr/bin/infoga << EOF
#!/bin/bash
cd /usr/share/infoga;python2 infoga.py "\$@"
EOF
		cat > /home/$USER/.local/share/applications/infoga.desktop << EOF
[Desktop Entry]
Name=Infoga
Exec=/usr/bin/infoga
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/infoga;chmod 755 /usr/share/Infoga/*
		cd /usr/share/Infoga
		pip2 install -r requirements.txt;python2 setup.py install
		printf "$GREEN"  "[*] Sucess Installing Infoga"
	else
		printf "$GREEN"  "[*] Failed Installing Infoga"
	fi

	# Install CheckStyle
	if [ ! -d "/usr/share/CheckStyle" ]; then
		mkdir -p /usr/share/CheckStyle
		wget https://github.com/checkstyle/checkstyle/releases/download/checkstyle-10.12.2/checkstyle-10.12.2-all.jar -O /usr/share/CheckStyle/checkstyle.jar
		cat > /usr/bin/checkstyle << EOF
#!/bin/bash
cd /usr/share/CheckStyle;java -jar checkstyle.jar "\$@"
EOF
		cat > /home/$USER/.local/share/applications/checkstyle.desktop << EOF
[Desktop Entry]
Name=CheckStyle
Exec=/usr/bin/checkstyle
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/checkstyle;chmod 755 /usr/share/CheckStyle/*
		printf "$GREEN"  "[*] Sucess Installing CheckStyle"
	else
		printf "$GREEN"  "[*] Failed Installing CheckStyle"
	fi

	# Install Genymotion
	if [ ! -d "/usr/share/genymotion" ]; then
		mkdir -p /user/share/genymotion
		wget https://dl.genymotion.com/releases/genymotion-3.5.0/genymotion-3.5.0-linux_x64.bin -O /user/share/genymotion/genymotion-linux.bin
		cd /user/share/genymotion;chmod +x genymotion-linux.bin;./genymotion-linux.bin -y
		printf "$GREEN"  "[*] Sucess Installing Genymotion"
	else
		printf "$GREEN"  "[*] Failed Installing Genymotion"
	fi

	# Install PhoneInfoga
	if [ ! -d "/usr/share/PhoneInfoga" ]; then
		wget https://github.com/sundowndev/phoneinfoga/releases/download/v2.10.8/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/phoneinfoga.tar.gz
		mkdir -p /usr/share/PhoneInfoga;chmod +x /usr/share/PhoneInfoga;cd /tmp
		tar -xvf phoneinfoga.tar.gz;mv phoneinfoga /var/share/PhoneInfoga/phoneinfoga;rm -f /tmp/phoneinfoga.tar.gz
		ln -f -s /usr/share/PhoneInfoga/phoneinfoga /usr/bin/phoneinfoga
		cat > /home/$USER/.local/share/applications/phoneinfoga.desktop << EOF
[Desktop Entry]
Name=PhoneInfoga
Exec=/usr/bin/phoneinfoga
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/phoneinfoga;chmod 755 /usr/share/PhoneInfoga/*
		printf "$GREEN"  "[*] Sucess Installing PhoneInfoga"
	else
		printf "$GREEN"  "[*] Failed Installing PhoneInfoga"
	fi

	# Install MobSF
	if [ ! -d "/usr/share/MobSF" ]; then
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /usr/share/mobsf
		cat > /usr/bin/mobsf << EOF
#!/bin/bash
cd /usr/share/mobsf;./run.sh > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &
EOF
		cat > /home/$USER/.local/share/applications/mobsf.desktop << EOF
[Desktop Entry]
Name=MobSF
Exec=/usr/bin/mobsf
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/mobsf;chmod 755 /usr/share/MobSF/*
		cd /usr/share/mobsf;chmod 755 *;./setup.sh
		printf "$GREEN"  "[*] Sucess Installing MobSF"
	else
		printf "$GREEN"  "[*] Failed Installing MobSF"
	fi

	# Install Findomain
	if [ ! -d "/usr/share/Findomain" ]; then
		wget https://github.com/Findomain/Findomain/releases/download/9.0.0/findomain-linux.zip -O /tmp/findomain-linux.zip
		unzip /tmp/findomain-linux.zip -d /usr/share/Findomain;rm -f /tmp/findomain-linux.zip
		ln -f -s /usr/share/Findomain/findomain /usr/bin/findomain
		cat > /usr/bin/findomain << EOF
#!/bin/bash
cd /usr/share/Findomain;bash findomain "\$@"
EOF
		cat > /home/$USER/.local/share/applications/findomain.desktop << EOF
[Desktop Entry]
Name=Findomain
Exec=/usr/bin/findomain
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/findomain;chmod 755 /usr/share/Findomain/*
		printf "$GREEN"  "[*] Sucess Installing Findomain"
	else
		printf "$GREEN"  "[*] Failed Installing Findomain"
	fi

	# Install Angry-IP
	if [ ! -d "/usr/bin/ipscan" ]; then
		wget https://github.com/angryip/ipscan/releases/download/3.9.1/ipscan_3.9.1_amd64.deb -O /tmp/ipscan_amd64.deb
		chmod +x /tmp/ipscan_amd64.deb;dpkg -i /tmp/ipscan_amd64.deb;rm -f /tmp/ipscan_amd64.deb
		ln -f -s /usr/share/Findomain/findomain /usr/bin/findomain
		printf "$GREEN"  "[*] Sucess Installing Angry-IP"
	else
		printf "$GREEN"  "[*] Failed Installing Angry-IP"
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
	if [ ! -f "~/.gef-6a6e2a05ca8e08ac6845dce655a432fc4e029486.py" ]; then
		bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
		cat > /home/$USER/.local/share/applications/findomain.desktop << EOF
[Desktop Entry]
Name=Findomain
Exec=/usr/bin/findomain
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/findomain;chmod 755 /usr/share/Findomain/*
		printf "$GREEN"  "[*] Sucess Installing GEF"
	else
		printf "$GREEN"  "[*] Sucess Installed GEF"
	fi

	# Install HashPump
	if [ ! -d "/usr/share/HashPump" ]; then
		git clone https://github.com/bwall/HashPump /usr/share/HashPump
		cat > /usr/bin/hashpump << EOF
#!/bin/bash
cd /usr/share/HashPump;bash hashpump "\$@"
EOF
		cat > /home/$USER/.local/share/applications/hashpump.desktop << EOF
[Desktop Entry]
Name=HashPump
Exec=/usr/bin/hashpump
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/HashPump;chmod 755 /usr/share/HashPump/*;;make install
		printf "$GREEN"  "[*] Sucess Installing HashPump"
	else
		printf "$GREEN"  "[*] Sucess Installed HashPump"
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
		pip -r /usr/share/rsactftool/requirements.txt
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
		pip install -r /usr/share/certsniff/requirements.txt
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
		pip install -r /usr/share/memcrashed-DDoS/requirements.txt
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
	apt install -qy koadic chisel veil veil-catapult veil-evasion certbot bloodhound poshc2 ibombshell silenttrinity shellnoob linux-exploit-suggester stunnel4 villain

	# Install Python3 pip
	pip install pivotnacci nim linux-exploit-suggester donut-shellcode xortool auto-py-to-exe py2exe certipy viper-framework updog pwncat sceptre atheris networkx aclpwn pastehunter neo4j-driver 
	pip3 install datasets
	pip3 install coercer

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

	# Install Python3 pip
	pip install 

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
	apt install -qy ghidra foremost capstone-tool autopsy exiftool procdump oletools inetsim outguess steghide steghide-doc osslsigncode hexyl audacity stenographer dnstwist stegosuite qpdf kafkacat sigma-align oscanner procdump forensics-all sysmonforlinux syslog-ng-core syslog-ng-scl

	# Install Python3 pip
	pip install iocextract threatingestor decompyle3 uncompyle6 stix stix-validator xortool stringsifter radare2 stegcracker tinyscript dnfile dotnetfile malchive libcsce mwcp chepy attackcti heralding pylibemu ivre harpoon cve-bin-tool aws_ir Dshell libcloudforensics rekall threatbus pngcheck unipacker ioc_fanger ioc-scan stix2 intelmq otx-misp stegpy openioc-to-stix threat_intel eql hachoir pymetasec qiling fwhunt-scan pyhindsight phishing-tracker apiosintDS
	pip3 install datasets

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

	# Install Python3 pip
	pip3 install sigmatools thug metabadger adversarial-robustness-toolbox locust flare-capa crowdsec conpot honeypots msticpy demonhunter iamactionhunter
	pip3 install datasets

	# Install Ruby GEM
	gem install 

	# Install Nodejs NPM
	npm install 

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

	# Install Python3 pip
	pip3 install angr angrop quark-engine wapiti3 boofuzz ropgadget pwntools capstone checkov atheris r2env pyscan-rs
	pip3 install datasets

	# Install Ruby GEM
	gem install one_gadget brakeman net-http-persistent bundler-audit 

	# Install Nodejs NPM
	npm install -g snyk @sandworm/audit

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
	# Update & Upgrade OS
	apt update;apt upgrade -qy;apt dist-upgrade -qy;apt autoremove;apt autoclean

	# Install Repository Tools
	apt install -qy git apt-transport-https docker.io nodejs npm cargo golang libreoffice vlc uget remmina openconnect bleachbit powershell filezilla telegram-desktop joplin thunderbird mono-complete mono-devel node-ws p7zip p7zip-full wine winetricks winbind cmake build-essential binutils git gdb net-tools nasm snmp-mibs-downloader locate alacarte imagemagick ghostscript 

	# Initialize Repository Tools
	dpkg --add-architecture i386 && apt update && apt -y install wine32

	# Add Microsoft Repository Tools
	wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
	mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
	wget -q https://packages.microsoft.com/config/debian/11/prod.list
	mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
	chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
	chown root:root /etc/apt/sources.list.d/microsoft-prod.list
	apt update

	# Add Wazuh Repository Tools
	curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
	echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
	apt update

	# Add syslog-ng Repository Tools
	wget -qO - https://ose-repo.syslog-ng.com/apt/syslog-ng-ose-pub.asc | sudo apt-key add -
	echo "deb https://ose-repo.syslog-ng.com/apt/ stable ubuntu-focal" | sudo tee -a /etc/apt/sources.list.d/syslog-ng-ose.list
	apt update

	# Install ChatGPT
	curl -sSL https://raw.githubusercontent.com/aandrew-me/tgpt/main/install | bash -s /usr/local/bin
	
	# Install Python3 pip
	pip3 install colorama
	pip3 install pysnmp

	# Install Unk9_Elite
    if [ ! -d "/usr/share/unk9_elite" ]; then
	mkdir -p /usr/share/unk9_elite
	curl -s -o /usr/share/unk9_elite/unk9_elite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/unk9_elite.sh
	bash /usr/share/unk9_elite/unk9_elite.sh
    elif [ "$(curl -s https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/version)" != $version ]; then
        curl -s -o /usr/share/unk9_elite/unk9_elite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/unk9_elite.sh
	bash /usr/share/unk9_elite/unk9_elite.sh
    fi
}


main
menu
logo
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
        *)
           	printf "$RED"     "[X] Invalid select item."
		;;			
   	esac
done
