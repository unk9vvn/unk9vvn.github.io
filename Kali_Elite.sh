#!/bin/bash




RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'
version='4.0'
USERS=$(ls /home | sed 's/root//')




if [ "$(id -u)" != "0" ];then
	printf "$RED"		"[X] Please run as RooT ..."
	printf "$GREEN"		"sudo chmod +x Kali_Elite.sh;sudo ./Kali_Elite.sh"
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
	# Initialize Main Menu
	mkdir -p /home/$USERS/.local/share/applications;mkdir -p /home/$USERS/.local/share/desktop-directories
	curl -s -o /home/$USERS/.local/images/unk9vvn-logo.jpg https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/unk9vvn-logo.jpg
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN.directory << EOF
[Desktop Entry]
Name=Unk9vvN
Comment=unk9vvn.github.io
Icon=/home/$USERS/.local/images/unk9vvn-logo.png
Type=Directory
EOF
	# Initialize Penetration Testing Menu
	curl -s -o /home/$USERS/.local/images/penetration-testing.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/penetration-testing.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration Testing
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration Testing.directory << EOF
[Desktop Entry]
Name=Penetration Testing
Comment=Offensive Security
Icon=/home/$USERS/.local/images/penetration-testing.png
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration Testing/Web
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration Testing-Web.directory << EOF
[Desktop Entry]
Name=Web
Comment=Penetration Testing
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration Testing/Mobile
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration Testing-Mobile.directory << EOF
[Desktop Entry]
Name=Mobile
Comment=Penetration Testing
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration Testing/Cloud
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration Testing-Cloud.directory << EOF
[Desktop Entry]
Name=Cloud
Comment=Penetration Testing
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration Testing/Network
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration Testing-Network.directory << EOF
[Desktop Entry]
Name=Network
Comment=Penetration Testing
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration Testing/Wireless
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration Testing-Wireless.directory << EOF
[Desktop Entry]
Name=Wireless
Comment=Penetration Testing
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration Testing/IoT
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration Testing-IoT.directory << EOF
[Desktop Entry]
Name=IoT
Comment=Penetration Testing
Icon=folder
Type=Directory
EOF
	# Initialize Red Team Menu
	curl -s -o /home/$USERS/.local/images/red-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/red-team.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team.directory << EOF
[Desktop Entry]
Name=Red Team
Comment=Offensive Security
Icon=/home/$USERS/.local/images/red-team.png
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Reconnaissance
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Reconnaissance.directory << EOF
[Desktop Entry]
Name=Reconnaissance
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Resource Development
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Resource Development.directory << EOF
[Desktop Entry]
Name=Resource Development
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Initial Access
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Initial Access.directory << EOF
[Desktop Entry]
Name=Initial Access
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Execution
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Execution.directory << EOF
[Desktop Entry]
Name=Execution
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Persistence
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Persistence.directory << EOF
[Desktop Entry]
Name=Persistence
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Privilege Escalation
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Privilege Escalation.directory << EOF
[Desktop Entry]
Name=Privilege Escalation
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Defense Evasion
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Defense Evasion.directory << EOF
[Desktop Entry]
Name=Defense Evasion
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Credential Access
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Credential Access.directory << EOF
[Desktop Entry]
Name=Credential Access
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Discovery
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Discovery.directory << EOF
[Desktop Entry]
Name=Discovery
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Lateral Movement
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Lateral Movement.directory << EOF
[Desktop Entry]
Name=Lateral Movement
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Collection
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Collection.directory << EOF
[Desktop Entry]
Name=Collection
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Command and Control
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Command and Control.directory << EOF
[Desktop Entry]
Name=Command and Control
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Exfiltration
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Exfiltration.directory << EOF
[Desktop Entry]
Name=Exfiltration
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red Team/Impact
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red Team-Impact.directory << EOF
[Desktop Entry]
Name=Impact
Comment=Red Team
Icon=folder
Type=Directory
EOF
	# Initialize ICS Security Menu
	curl -s -o /home/$USERS/.local/images/ics-security.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/ics-security.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS Security
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS Security.directory << EOF
[Desktop Entry]
Name=ICS Security
Comment=Offensive Security
Icon=/home/$USERS/.local/images/ics-security.png
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS Security/Penetration Testing
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS Security-Penetration Testing.directory << EOF
[Desktop Entry]
Name=ICS
Comment=Penetration Testing
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS Security/Red Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS Security-Red Team.directory << EOF
[Desktop Entry]
Name=ICS
Comment=Red Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS Security/Blue Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS Security-Blue Team.directory << EOF
[Desktop Entry]
Name=ICS
Comment=Blue Team
Icon=folder
Type=Directory
EOF
	# Initialize Digital Forensic Menu
	curl -s -o /home/$USERS/.local/images/digital-forensic.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/digital-forensic.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital Forensic
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital Forensic.directory << EOF
[Desktop Entry]
Name=Digital Forensic
Comment=Defensive Security
Icon=/home/$USERS/.local/images/digital-forensic.png
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital Forensic/Reverse Engineering
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital Forensic-Reverse Engineering.directory << EOF
[Desktop Entry]
Name=Reverse Engineering
Comment=Digital Forensic
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital Forensic/Malware Analysis
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital Forensic-Malware Analysis.directory << EOF
[Desktop Entry]
Name=Malware Analysis
Comment=Digital Forensic
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital Forensic/Threat Hunting
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital Forensic-Threat Hunting.directory << EOF
[Desktop Entry]
Name=Threat Hunting
Comment=Digital Forensic
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital Forensic/Incident Response
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital Forensic-Incident Response.directory << EOF
[Desktop Entry]
Name=Incident Response
Comment=Digital Forensic
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital Forensic/Threat Intelligence
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital Forensic-Threat Intelligence.directory << EOF
[Desktop Entry]
Name=Threat Intelligence
Comment=Digital Forensic
Icon=folder
Type=Directory
EOF
	# Initialize Blue Team Menu
	curl -s -o /home/$USERS/.local/images/blue-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/blue-team.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue Team.directory << EOF
[Desktop Entry]
Name=Blue Team
Comment=Defensive Security
Icon=/home/$USERS/.local/images/blue-team.png
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue Team/Harden
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue Team-Harden.directory << EOF
[Desktop Entry]
Name=Harden
Comment=Blue Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue Team/Detect
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue Team-Detect.directory << EOF
[Desktop Entry]
Name=Detect
Comment=Blue Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue Team/Isolate
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue Team-Isolate.directory << EOF
[Desktop Entry]
Name=Isolate
Comment=Blue Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue Team/Deceive
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue Team-Deceive.directory << EOF
[Desktop Entry]
Name=Deceive
Comment=Blue Team
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue Team/Evict
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue Team-Evict.directory << EOF
[Desktop Entry]
Name=Evict
Comment=Blue Team
Icon=folder
Type=Directory
EOF
	# Initialize Security Audit Menu
	curl -s -o /home/$USERS/.local/images/security-audit.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/security-audit.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security Audit
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security Audit.directory << EOF
[Desktop Entry]
Name=Security Audit
Comment=Defensive Security
Icon=/home/$USERS/.local/images/security-audit.png
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security Audit/Preliminary Audit Assessment
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security Audit-Preliminary Audit Assessment.directory << EOF
[Desktop Entry]
Name=Preliminary Audit Assessment
Comment=Security Audit
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security Audit/Planning and Preparation
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security Audit-Planning and Preparation.directory << EOF
[Desktop Entry]
Name=Planning and Preparation
Comment=Security Audit
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security Audit/Establishing Audit Objectives
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security Audit-Establishing Audit Objectives.directory << EOF
[Desktop Entry]
Name=Establishing Audit Objectives
Comment=Security Audit
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security Audit/Performing the Review
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security Audit-Performing the Review.directory << EOF
[Desktop Entry]
Name=Performing the Review
Comment=Security Audit
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security Audit/Preparing the Audit Report
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security Audit-Preparing the Audit Report.directory << EOF
[Desktop Entry]
Name=Preparing the Audit Report
Comment=Security Audit
Icon=folder
Type=Directory
EOF
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security Audit/Issuing the Review Report
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security Audit-Issuing the Review Report.directory << EOF
[Desktop Entry]
Name=Issuing the Review Report
Comment=Security Audit
Icon=folder
Type=Directory
EOF
}


penetrating_testing ()
{
	# Install Repository Tools
	apt install -qy tor tesseract-ocr dirsearch jd-gui nuclei maryam rainbowcrack hakrawler airgeddon gobuster seclists fcrackzip subfinder amass cme amap arjun rarcrack bettercap metagoofil dsniff sublist3r arpwatch wifiphisher sslstrip airgraph-ng sherlock parsero routersploit tcpxtract cupp slowhttptest dnsmasq sshuttle gifsicle adb shellter haproxy aria2 smb4k crackle pptpd gimp xplico unicorn phpggc qrencode emailharvester cmatrix osrframework jq tigervnc-viewer pngtools pdfcrack dosbox lldb apksigner zmap checksec kerberoast etherape ismtp goldeneye ident-user-enum httptunnel wig feh onionshare kalibrate-rtl eyewitness zipalign strace oclgausscrack multiforcer crowbar brutespray arduino websploit googler ffmpeg rar inspy eaphammer rtlsdr-scanner multimon-ng isr-evilgrade smtp-user-enum obfs4proxy proxychains pigz massdns gospider proxify gdb ubertooth gnuradio apktool privoxy dotdotpwn gr-gsm isc-dhcp-server sonic-visualiser goofile ridenum firewalk bing-ip2hosts webhttrack awscli oathtool sipvicious netstress tcptrack airspy gqrx-sdr tnscmd10g getallurls btscanner bluesnarfer darkstat crackle blueranger wifipumpkin3 wireguard padbuster feroxbuster android-tools-adb naabu subjack cyberchef whatweb nbtscan xmlstarlet sslscan sentrypeer spooftooph assetfinder

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
	pip3 install ggshield
	pip3 install slowloris
	pip3 install brute
	pip3 install pacu
	pip3 install whispers
	pip3 install s3scanner
	pip3 install roadrecon
	pip3 install roadlib
	pip3 install gcp_scanner
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
	pip3 install n0s1
	pip3 install bbqsql
	pip3 install baboossh
	pip3 install selenium
	pip3 install pinject
	pip3 install ciphey
	pip3 install scoutsuite
	pip3 install PyJWT
	pip3 install mobsf
	pip3 install aws-gate
	pip3 install proxyhub
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
	pip3 install crlfsuite
	pip3 install modelscan
	pip3 install APIFuzzer
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
	pip3 install uefi_firmware
	pip3 install instaloader
	pip3 install sysplant
	pip3 install anomark
	pip3 install semgrep
	pip3 install dotdotfarm
	pip3 install gorilla-cli
	pip3 install knowsmore
	pip3 install unblob
	pip3 install datasets
	pip3 install ssh-mitm

	# Install Ruby GEM
	gem install ssrf_proxy zsteg seccomp-tools aws_public_ips aws_security_viz aws_recon API_Fuzzer dawnscanner mechanize aws_security_viz public_suffix rake aws_recon zsteg 

	# Install Nodejs NPM
	npm install -g jwt-cracker graphql padding-oracle-attacker http-proxy-to-socks javascript-obfuscator serialize-javascript rms-runtime-mobile-security igf apk-mitm bagbak graphqlviz btlejuice http-proxy-to-socks f5stegojs node-serialize uglify-js igf electron-packager redos apk-mitm fleetctl npx serialize-to-js dompurify persistgraphql nodesub multitor dompurify jsdom

	# Install Golang
	go install github.com/tomnomnom/waybackurls@latest
	ln -fs ~/go/bin/waybackurls /usr/bin/waybackurls
	cat > /home/$USERS/.local/share/applications/waybackurls.directory << EOF
[Desktop Entry]
Name=waybackurls
Exec=/usr/share/kali-menu/exec-in-shell "waybackurls -h"
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
	go install github.com/tomnomnom/httprobe@latest
	ln -fs ~/go/bin/httprobe /usr/bin/httprobe
	cat > /home/$USERS/.local/share/applications/alacarte-made-1.directory << EOF
[Desktop Entry]
Name=waybackurls
Exec=/usr/share/kali-menu/exec-in-shell "httprobe -h"
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
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
	go install github.com/devanshbatham/headerpwn@v0.0.3
	ln -fs ~/go/bin/headerpwn /usr/bin/headerpwn
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
	go install github.com/dwisiswant0/ipfuscator@latest
	ln -fs ~/go/bin/ipfuscator /usr/bin/ipfuscator
	go install github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest
	ln -fs ~/go/bin/hednsextractor /usr/bin/hednsextractor
	go install github.com/g0ldencybersec/CloudRecon@latest
	ln -fs ~/go/bin/CloudRecon /usr/bin/CloudRecon
	go install github.com/projectdiscovery/alterx/cmd/alterx@latest
	ln -fs ~/go/bin/alterx /usr/bin/alterx

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
		cat > /home/$USERS/.local/share/applications/cloudfail.desktop << EOF
[Desktop Entry]
Name=CloudFail
Exec=/usr/share/kali-menu/exec-in-shell "cloudfail -h"
Comment=Penetration Testing
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
		cat > /home/$USERS/.local/share/applications/snmpbrute.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/smod.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/s7scan.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/routerscan.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/cloudbunny.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/gtscan.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/isf.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/pret.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/modbuspal.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/hlrlookups.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/infoga.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/checkstyle.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/phoneinfoga.desktop << EOF
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
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /usr/share/MobSF
		cat > /usr/bin/mobsf << EOF
#!/bin/bash
cd /usr/share/MobSF;./run.sh > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &
EOF
		cat > /home/$USERS/.local/share/applications/mobsf.desktop << EOF
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
		cd /usr/share/MobSF;chmod 755 *;./setup.sh
		printf "$GREEN"  "[*] Sucess Installing MobSF"
	else
		printf "$GREEN"  "[*] Failed Installing MobSF"
	fi

	# Install Findomain
	if [ ! -d "/usr/share/Findomain" ]; then
		wget https://github.com/Findomain/Findomain/releases/download/9.0.4/findomain-linux.zip -O /tmp/findomain-linux.zip
		unzip /tmp/findomain-linux.zip -d /usr/share/Findomain;rm -f /tmp/findomain-linux.zip
		ln -fs /usr/share/Findomain/findomain /usr/bin/findomain
		cat > /usr/bin/findomain << EOF
#!/bin/bash
cd /usr/share/Findomain;bash findomain "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/findomain.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/findomain.desktop << EOF
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
		cat > /home/$USERS/.local/share/applications/hashpump.desktop << EOF
[Desktop Entry]
Name=HashPump
Exec=/usr/bin/hashpump
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/HashPump;chmod 755 /usr/share/HashPump/*;make install
		printf "$GREEN"  "[*] Sucess Installing HashPump"
	else
		printf "$GREEN"  "[*] Sucess Installed HashPump"
	fi

	# Install RSAtool
	if [ ! -d "/usr/share/RSAtool" ]; then
		git clone https://github.com/ius/rsatool /usr/share/RSAtool
		cat > /usr/bin/rsatool << EOF
#!/bin/bash
cd /usr/share/RSAtool;python3 rsatool.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/rsatool.desktop << EOF
[Desktop Entry]
Name=RSAtool
Exec=/usr/bin/rsatool
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/rsatool;chmod 755 /usr/share/RSAtool/*
		printf "$GREEN"  "[*] Sucess Installing RSAtool"
	else
		printf "$GREEN"  "[*] Sucess Installed RSAtool"
	fi

	# Install RsaCtfTool
	if [ ! -d "/usr/share/RsaCtfTool" ]; then
		git clone https://github.com/RsaCtfTool/RsaCtfTool /usr/share/RsaCtfTool
		cat > /usr/bin/rsactftool << EOF
#!/bin/bash
cd /usr/share/RsaCtfTool;python3 RsaCtfTool.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/rsactftool.desktop << EOF
[Desktop Entry]
Name=RsaCtfTool
Exec=/usr/bin/rsactftool
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/rsactftool;chmod 755 /usr/share/RsaCtfTool/*
		printf "$GREEN"  "[*] Sucess Installing RsaCtfTool"
	else
		printf "$GREEN"  "[*] Sucess Installed RsaCtfTool"
	fi

	# Install PEMCrack
	if [ ! -d "/usr/share/PEMCrack" ]; then
		git clone https://github.com/robertdavidgraham/pemcrack /usr/share/PEMCrack
		cd /usr/share/PEMCrack;gcc pemcrack.c -o pemcrack -lssl -lcrypto
		ln -fs /usr/share/PEMCrack/pemcrack /usr/bin/pemcrack
		cat > /home/$USERS/.local/share/applications/pemcrack.desktop << EOF
[Desktop Entry]
Name=PEMCrack
Exec=/usr/bin/pemcrack
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/pemcrack;chmod 755 /usr/share/PEMCrack/*
		printf "$GREEN"  "[*] Sucess Installing PEMCrack"
	else
		printf "$GREEN"  "[*] Sucess Installed PEMCrack"
	fi

	# Install DyMerge
	if [ ! -d "/usr/share/DyMerge" ]; then
		git clone https://github.com/k4m4/dymerge /usr/share/DyMerge
		cat > /usr/bin/dymerge << EOF
#!/bin/bash
cd /usr/share/DyMerge;python3 dymerge.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/dymerge.desktop << EOF
[Desktop Entry]
Name=DyMerge
Exec=/usr/bin/dymerge
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/dymerge;chmod 755 /usr/share/DyMerge/*
		printf "$GREEN"  "[*] Sucess Installing DyMerge"
	else
		printf "$GREEN"  "[*] Sucess Installed DyMerge"
	fi

	# Install JWT-Tool
	if [ ! -d "/usr/share/JWT_Tool" ]; then
		git clone https://github.com/ticarpi/jwt_tool /usr/share/JWT_Tool
		pip3 install termcolor cprint pycryptodomex requests
		cat > /usr/bin/jwt_tool << EOF
#!/bin/bash
cd /usr/share/JWT_Tool;python3 jwt_tool.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/jwt_tool.desktop << EOF
[Desktop Entry]
Name=JWT-Tool
Exec=/usr/bin/jwt_tool
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/jwt_tool;chmod 755 /usr/share/JWT_Tool/*
		printf "$GREEN"  "[*] Sucess Installing JWT-Tool"
	else
		printf "$GREEN"  "[*] Sucess Installed JWT-Tool"
	fi

	# Install Poodle
	if [ ! -d "/usr/share/Poodle" ]; then
		git clone https://github.com/mpgn/poodle-PoC /usr/share/Poodle
		cat > /usr/bin/poodle << EOF
#!/bin/bash
cd /usr/share/Poodle;python3 poodle-exploit.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/poodle.desktop << EOF
[Desktop Entry]
Name=Poodle
Exec=/usr/bin/poodle
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/poodle;chmod 755 /usr/share/Poodle/*
		printf "$GREEN"  "[*] Sucess Installing Poodle"
	else
		printf "$GREEN"  "[*] Sucess Installed Poodle"
	fi

	# Install certSniff
	if [ ! -d "/usr/share/certSniff" ]; then
		git clone https://github.com/A-poc/certSniff /usr/share/certSniff
		cat > /usr/bin/certsniff << EOF
#!/bin/bash
cd /usr/share/certSniff;python3 certSniff.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/certsniff.desktop << EOF
[Desktop Entry]
Name=certSniff
Exec=/usr/bin/certsniff
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/certsniff;chmod 755 /usr/share/certSniff/*
		printf "$GREEN"  "[*] Sucess Installing certSniff"
	else
		printf "$GREEN"  "[*] Sucess Installed certSniff"
	fi

	# Install HashExtender
	if [ ! -d "/usr/share/HashExtender" ]; then
		git clone https://github.com/iagox86/hash_extender /usr/share/HashExtender
		cd /usr/share/HashExtender;make
		ln -fs /usr/share/HashExtender /usr/bin/hashextender
		cat > /home/$USERS/.local/share/applications/hashextender.desktop << EOF
[Desktop Entry]
Name=HashExtender
Exec=/usr/bin/hashextender
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/hashextender;chmod 755 /usr/share/HashExtender/*
		printf "$GREEN"  "[*] Sucess Installing HashExtender"
	else
		printf "$GREEN"  "[*] Sucess Installed HashExtender"
	fi

	# Install SpoofCheck
	if [ ! -d "/usr/share/SpoofCheck" ]; then
		git clone https://github.com/BishopFox/spoofcheck /usr/share/SpoofCheck
		pip2 install -r /usr/share/SpoofCheck/requirements.txt
		cat > /usr/bin/spoofcheck << EOF
#!/bin/bash
cd /usr/share/SpoofCheck;python2 spoofcheck.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/spoofcheck.desktop << EOF
[Desktop Entry]
Name=SpoofCheck
Exec=/usr/bin/spoofcheck
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/spoofcheck;chmod 755 /usr/share/SpoofCheck/*
		printf "$GREEN"  "[*] Sucess Installing SpoofCheck"
	else
		printf "$GREEN"  "[*] Sucess Installed SpoofCheck"
	fi

	# Install Memcrashed
	if [ ! -d "/usr/share/Memcrashed" ]; then
		git clone https://github.com/649/Memcrashed-DDoS-Exploit /usr/share/Memcrashed
		pip3 install -r /usr/share/Memcrashed/requirements.txt
		cat > /usr/bin/memcrashed << EOF
#!/bin/bash
cd /usr/share/Memcrashed;python3 Memcrashed.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/memcrashed.desktop << EOF
[Desktop Entry]
Name=Memcrashed
Exec=/usr/bin/memcrashed
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/memcrashed;chmod 755 /usr/share/Memcrashed/*
		printf "$GREEN"  "[*] Sucess Installing Memcrashed"
	else
		printf "$GREEN"  "[*] Sucess Installed Memcrashed"
	fi
}


red_team ()
{
	# Install Repository Tools
	apt install -qy koadic chisel veil veil-catapult veil-evasion certbot bloodhound poshc2 ibombshell silenttrinity shellnoob linux-exploit-suggester stunnel4 villain merlin gitleaks trufflehog peass powershell-empire

	# Install Python3 pip
	pip3 install donut-shellcode
	pip3 install xortool
	pip3 install auto-py-to-exe
	pip3 install certipy
	pip3 install viper-framework
	pip3 install updog
	pip3 install pwncat
	pip3 install sceptre
	pip3 install networkx
	pip3 install atheris
	pip3 install aclpwn
	pip3 install pastehunter
	pip3 install neo4j-driver 
	pip3 install pivotnacci
	pip3 install datasets
	pip3 install coercer
	pip3 install rarce
	pip3 install krbjack
	pip3 install adidnsdump
	pip3 install sysplant
	pip3 install powerpwn

	# Install Ruby GEM
	gem install evil-winrm 

	# Install Nodejs NPM
	# npm install 

	# Install Golang
	go install github.com/justmao945/mallory/cmd/mallory@latest
	ln -fs ~/go/bin/mallory /usr/bin/mallory
	go install github.com/Tylous/ZipExec@latest
	ln -fs ~/go/bin/ZipExec /usr/bin/ZipExec
	go install github.com/redcode-labs/Coldfire@latest
	ln -fs ~/go/bin/Coldfire /usr/bin/Coldfire

	# Install PhoenixC2
	if [ ! -d "/usr/share/PhoenixC2" ]; then
		git clone https://github.com/screamz2k/PhoenixC2 /usr/share/PhoenixC2
		cd /usr/share/PhoenixC2;pip3 install poetry;poetry install
		cat > /usr/bin/phoenix << EOF
#!/bin/bash
cd /usr/share/PhoenixC2;poetry run phserver "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/phoenix.desktop << EOF
[Desktop Entry]
Name=phoenix
Exec=/usr/bin/phoenix
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/phoenix;chmod 755 /usr/share/PhoenixC2/*
		printf "$GREEN"  "[*] Sucess Installing PhoenixC2"
	else
		printf "$GREEN"  "[*] Sucess Installed PhoenixC2"
	fi

	# Install Silver
	if [ ! -d "/usr/share/Silver" ]; then
		mkdir -f /usr/share/Silver
		wget https://github.com/BishopFox/sliver/releases/download/v1.5.41/sliver-client_linux -O /usr/share/Silver/sliver_client
		wget https://github.com/BishopFox/sliver/releases/download/v1.5.41/sliver-server_linux -O /usr/share/Silver/sliver_server
		chmod +x /usr/share/Silver/*
		ln -fs /usr/share/Silver/sliver_client /usr/bin/sliverc
		ln -fs /usr/share/Silver/sliver_server /usr/bin/slivers
		cat > /usr/bin/sliverc << EOF
#!/bin/bash
cd /usr/share/Silver;./sliverc "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/sliverc.desktop << EOF
[Desktop Entry]
Name=Silver-Client
Exec=/usr/bin/sliverc
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/sliverc;chmod 755 /usr/share/Silver/*
		cat > /usr/bin/slivers << EOF
#!/bin/bash
cd /usr/share/Silver;./slivers "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/slivers.desktop << EOF
[Desktop Entry]
Name=Silver-Server
Exec=/usr/bin/slivers
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/slivers;chmod 755 /usr/share/Silver/*
		printf "$GREEN"  "[*] Sucess Installing Silver"
	else
		printf "$GREEN"  "[*] Sucess Installed Silver"
	fi

	# Install Havoc
	if [ ! -d "/usr/share/Havoc" ]; then
		git clone https://github.com/screamz2k/PhoenixC2 /usr/share/Havoc
		cd /user/share/Havoc/Client;make
		ln -fs /user/share/Havoc/Client/Havoc /usr/bin/havoc
		go mod download golang.org/x/sys;go mod download github.com/ugorji/go
		cd /user/share/Havoc/Teamserver;./Install.sh;make
		ln -fs /user/share/Havoc/Teamserver/teamserver /usr/bin/havocts
		cat > /home/$USERS/.local/share/applications/havoc.desktop << EOF
[Desktop Entry]
Name=Havoc
Exec=/usr/bin/havoc
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/havoc;chmod 755 /usr/share/Havoc/*
cat > /home/$USERS/.local/share/applications/havocts.desktop << EOF
[Desktop Entry]
Name=Havoc
Exec=/usr/bin/havocts
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/havocts;chmod 755 /user/share/Havoc/Teamserver/*
		printf "$GREEN"  "[*] Sucess Installing Havoc"
	else
		printf "$GREEN"  "[*] Sucess Installed Havoc"
	fi

	# Install Kerberoast
	if [ ! -d "/usr/share/Kerberoast" ]; then
		git clone https://github.com/nidem/kerberoast /usr/share/Kerberoast
		cat > /usr/bin/kerberoast << EOF
#!/bin/bash
cd /usr/share/Kerberoast;python3 kerberoast.py "\$@"
EOF
		cat > /home/$USERS/.local/share/applications/kerberoast.desktop << EOF
[Desktop Entry]
Name=Kerberoast
Exec=/usr/bin/kerberoast
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
Hidden=false
EOF
		chmod +x /usr/bin/kerberoast;chmod 755 /usr/share/Kerberoast/*
		printf "$GREEN"  "[*] Sucess Installing Kerberoast"
	else
		printf "$GREEN"  "[*] Sucess Installed Kerberoast"
	fi
}


ics_security ()
{
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# pip3 install 

	# Install Python2 PIP2
	# pip2 install  

	# Install Ruby GEM
	gem install modbus-cli 

	# Install Nodejs NPM
	# npm install 

	# Install Golang
	go install github.com/optiv/ScareCrow@latest
	ln -fs ~/go/bin/ScareCrow /usr/bin/scarecrow
}


digital_forensic ()
{
	# Install Repository Tools
	apt install -qy ghidra foremost capstone-tool autopsy exiftool inetsim outguess steghide steghide-doc osslsigncode hexyl audacity stenographer dnstwist stegosuite qpdf kafkacat sigma-align oscanner forensics-all syslog-ng-core syslog-ng-scl rkhunter

	# Install Python3 pip
	pip3 install threatingestor
	pip3 install decompyle3
	pip3 install uncompyle6
	pip3 install stix
	pip3 install stix-validator
	pip3 install xortool
	pip3 install stringsifter
	pip3 install radare2
	pip3 install stegcracker
	pip3 install tinyscript
	pip3 install oletools
	pip3 install dnfile
	pip3 install dotnetfile
	pip3 install malchive
	pip3 install libcsce
	pip3 install mwcp
	pip3 install chepy
	pip3 install attackcti
	pip3 install heralding
	pip3 install pylibemu
	pip3 install ivre
	pip3 install iocextract
	pip3 install cve-bin-tool
	pip3 install aws_ir
	pip3 install Dshell
	pip3 install libcloudforensics
	pip3 install rekall
	pip3 install threatbus
	pip3 install pngcheck
	pip3 install unipacker
	pip3 install ioc_fanger
	pip3 install ioc-scan
	pip3 install stix2
	pip3 install intelmq
	pip3 install otx-misp
	pip3 install stegpy
	pip3 install openioc-to-stix
	pip3 install threat_intel
	pip3 install eql
	pip3 install hachoir
	pip3 install pymetasec
	pip3 install qiling
	pip3 install fwhunt-scan
	pip3 install harpoon
	pip3 install apiosintDS
	pip3 install phishing-tracker
	pip3 install datasets

	# Install Ruby GEM
	gem install pedump

	# Install Nodejs NPM
	npm install box-js

	# Install Golang
	go install github.com/tomchop/unxor@latest
	ln -fs ~/go/bin/unxor /usr/bin/unxor

	# Install Dangerzone
	if [ ! -d "/usr/share/dangerzone" ]; then
		gpg --keyserver hkps://keys.openpgp.org \
    		--no-default-keyring --keyring ./fpf-apt-tools-archive-keyring.gpg \
    		--recv-keys "DE28 AB24 1FA4 8260 FAC9 B8BA A7C9 B385 2260 4281"
		mkdir -p /etc/apt/keyrings/;mv fpf-apt-tools-archive-keyring.gpg /etc/apt/keyrings
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
		ln -fs /usr/share/ssak/programs/64/cjpeg /usr/bin/cjpeg
		ln -fs /usr/share/ssak/programs/64/djpeg /usr/bin/djpeg
		ln -fs /usr/share/ssak/programs/64/histogram /usr/bin/histogram
		ln -fs /usr/share/ssak/programs/64/jphide /usr/bin/jphide
		ln -fs /usr/share/ssak/programs/64/jpseek /usr/bin/jpseek
		ln -fs /usr/share/ssak/programs/64/outguess_0.13 /usr/bin/outguess
		ln -fs /usr/share/ssak/programs/64/stegbreak /usr/bin/stegbreak
		ln -fs /usr/share/ssak/programs/64/stegcompare /usr/bin/stegcompare
		ln -fs /usr/share/ssak/programs/64/stegdeimage /usr/bin/stegdeimage
		ln -fs /usr/share/ssak/programs/64/stegdetect /usr/bin/stegdetect
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
	apt install -qy httpry nebula cacti gvm bubblewrap suricata zeek fail2ban logwatch tripwire aide clamav fscrypt encfs openvpn wireguard pwgen tcpdump apparmor chkrootkit ufw firewalld firejail sshguard arkime cyberchef ansible cilium-cli age

	# Install Python3 pip
	pip3 install sigmatools thug metabadger adversarial-robustness-toolbox locust flare-capa conpot honeypots msticpy

	# Install Ruby GEM
	# gem install 

	# Install Nodejs NPM
	# npm install 

	# Install Golang
	go install github.com/crissyfield/troll-a@latest
	ln -fs ~/go/bin/troll-a /usr/bin/troll-a

	# Install Matano
	if [ ! -d "/usr/share/Matano" ]; then
		wget https://github.com/matanolabs/matano/releases/download/nightly/matano-linux-x64.sh -O /tmp/matano-linux.sh
		chmod +x /tmp/matano-linux.sh;cd /tmp;bash matano-linux.sh;rm -f matano-linux.sh
		printf "$GREEN"  "[*] Sucess Installing Matano"
	else
		printf "$GREEN"  "[*] Sucess Installed Matano"
	fi

	# Install OpenSearch
	if [ ! -d "/usr/share/Matano" ]; then
		wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.deb -O /tmp/opensearch-linux.deb
		dpkg -i /tmp/opensearch-linux.deb
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
	apt install -qy flawfinder afl++ gvm openvas pskracker ropper mdbtools lynis cppcheck findbugs buildah

	# Install Python3 pip
	pip3 install angr
	pip3 install angrop
	pip3 install quark-engine
	pip3 install wapiti3
	pip3 install boofuzz
	pip3 install ropgadget
	pip3 install pwntools
	pip3 install capstone
	pip3 install checkov
	pip3 install atheris
	pip3 install r2env
	pip3 install pyscan-rs
	pip3 install datasets

	# Install Ruby GEM
	gem install one_gadget brakeman net-http-persistent bundler-audit 

	# Install Nodejs NPM
	npm install -g snyk @sandworm/audit

	# Install Golang
	go install github.com/google/osv-scanner/cmd/osv-scanner@latest
	ln -fs ~/go/bin/osv-scanner /usr/bin/osv-scanner

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
	apt update;apt upgrade -qy;apt dist-upgrade -qy

	# Install Repository Tools
	apt install -qy git apt-transport-https docker.io docker-compose nodejs npm cargo golang libreoffice vlc uget remmina openconnect bleachbit powershell filezilla telegram-desktop joplin thunderbird mono-complete mono-devel node-ws p7zip p7zip-full wine winetricks winbind cmake build-essential binutils git gdb net-tools nasm snmp-mibs-downloader locate alacarte imagemagick ghostscript python3-poetry libre2-dev cassandra gnupg2 ca-certificates

	# Install Python3 pip
	pip3 install colorama
	pip3 install pysnmp

	# Install Kali_Elite
    if [ ! -d "/usr/share/Kali_Elite" ]; then
		mkdir -p /usr/share/Kali_Elite
		curl -s -o /usr/share/Kali_Elite/kali_elite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/Kali_Elite.sh
		cat > /usr/bin/unk9_elite << EOF
#!/bin/bash
cd /usr/share/Unk9_Elite;bash kali_elite.sh "\$@"
EOF
		chmod +x /usr/share/Unk9_Elite/kali_elite.sh;bash /usr/share/Unk9_Elite/kali_elite.sh
    elif [ "$(curl -s https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/version)" != $version ]; then
        curl -s -o /usr/share/Unk9_Elite/kali_elite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/Kali_Elite.sh
		cat > /usr/bin/unk9_elite << EOF
#!/bin/bash
cd /usr/share/Kali_Elite;bash kali_elite.sh "\$@"
EOF
		chmod +x /usr/share/Kali_Elite/kali_elite.sh;bash /usr/share/Kali_Elite/kali_elite.sh
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
