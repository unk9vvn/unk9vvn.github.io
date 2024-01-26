#!/bin/bash
version='4.0'


RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'
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
Type=Directory
Name=Unk9vvN
Comment=unk9vvn.github.io
Icon=/home/$USERS/.local/images/unk9vvn-logo.jpg
EOF

	# Initialize Penetration Testing Menu
	curl -s -o /home/$USERS/.local/images/penetration-testing.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/penetration-testing.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration\ Testing
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration\ Testing.directory << EOF
[Desktop Entry]
Type=Directory
Name=Penetration Testing
Comment=Offensive Security
Icon=/home/$USERS/.local/images/penetration-testing.png
EOF
	dir_pentest_array=("Web" "Mobile" "Cloud" "Network" "Wireless" "IoT")
	dir_pentest_index=0
	while [ $pentest_index -lt ${#dir_pentest_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration\ Testing/${dir_pentest_array[dir_pentest_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration\ Testing-${dir_pentest_array[dir_pentest_index]}.directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_pentest_array[dir_pentest_index]}
Comment=Penetration Testing
Icon=folder
EOF
		dir_pentest_index=$((dir_pentest_index + 1))
	done

	# Initialize Red Team Menu
	curl -s -o /home/$USERS/.local/images/red-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/red-team.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red\ Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red\ Team.directory << EOF
[Desktop Entry]
Type=Directory
Name=Red Team
Comment=Offensive Security
Icon=/home/$USERS/.local/images/red-team.png
EOF
	dir_redteam_array=("Reconnaissance" "Resource Development" "Initial Access" "Execution" "Persistence" "Privilege Escalation" "Defense Evasion" "Credential Access" "Discovery" "Lateral Movement" "Collection" "Command and Control" "Exfiltration" "Impact")
	dir_redteam_index=0
	while [ $dir_redteam_index -lt ${#dir_redteam_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red\ Team/${dir_redteam_array[dir_redteam_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red\ Team-${dir_redteam_array[dir_redteam_index]}.directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_redteam_array[dir_redteam_index]}
Comment=Red Team
Icon=folder
EOF
		dir_redteam_index=$((dir_redteam_index + 1))
	done

	# Initialize ICS Security Menu
	curl -s -o /home/$USERS/.local/images/ics-security.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/ics-security.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS\ Security
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS\ Security.directory << EOF
[Desktop Entry]
Type=Directory
Name=ICS Security
Comment=Offensive Security
Icon=/home/$USERS/.local/images/ics-security.png
EOF
	dir_ics_array=("Penetration Testing" "Red Team" "Digital Forensic" "Blue Team")
	dir_ics_index=0
	while [ $dir_ics_index -lt ${#dir_ics_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS\ Security/${dir_ics_array[dir_ics_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS\ Security-${dir_ics_array[dir_ics_index]}.directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_ics_array[dir_ics_index]}
Comment=ICS Security
Icon=folder
EOF
		dir_ics_index=$((dir_ics_index + 1))
	done

	# Initialize Digital Forensic Menu
	curl -s -o /home/$USERS/.local/images/digital-forensic.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/digital-forensic.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital\ Forensic
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital\ Forensic.directory << EOF
[Desktop Entry]
Type=Directory
Name=Digital Forensic
Comment=Defensive Security
Icon=/home/$USERS/.local/images/digital-forensic.png
EOF
	dir_digital_array=("Reverse Engineering" "Malware Analysis" "Threat Hunting" "Incident Response" "Threat Intelligence")
	dir_digital_index=0
	while [ $dir_digital_index -lt ${#dir_ics_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital\ Forensic/${dir_digital_array[dir_digital_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital\ Forensic-${dir_digital_array[dir_digital_index]}.directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_digital_array[dir_digital_index]}
Comment=Digital Forensic
Icon=folder
EOF
		dir_digital_index=$((dir_digital_index + 1))
	done

	# Initialize Blue Team Menu
	curl -s -o /home/$USERS/.local/images/blue-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/blue-team.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue\ Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue\ Team.directory << EOF
[Desktop Entry]
Type=Directory
Name=Blue Team
Comment=Defensive Security
Icon=/home/$USERS/.local/images/blue-team.png
EOF
	dir_blueteam_array=("Harden" "Detect" "Isolate" "Deceive" "Evict")
	dir_blueteam_index=0
	while [ $dir_blueteam_index -lt ${#dir_blueteam_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue\ Team/${dir_blueteam_array[dir_blueteam_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue\ Team-${dir_blueteam_array[dir_blueteam_index]}.directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_blueteam_array[dir_blueteam_index]}
Comment=Blue Team
Icon=folder
EOF
		dir_blueteam_index=$((dir_blueteam_index + 1))
	done

	# Initialize Security Audit Menu
	curl -s -o /home/$USERS/.local/images/security-audit.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/security-audit.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security\ Audit
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security\ Audit.directory << EOF
[Desktop Entry]
Type=Directory
Name=Security Audit
Comment=Defensive Security
Icon=/home/$USERS/.local/images/security-audit.png
EOF
	dir_audit_array=("Preliminary Audit Assessment" "Planning and Preparation" "Establishing Audit Objectives" "Performing the Review" "Preparing the Audit Report" "Issuing the Review Report")
	dir_audit_index=0
	while [ $dir_audit_index -lt ${#dir_audit_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security\ Audit/${dir_audit_array[dir_audit_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security\ Audit-${dir_audit_array[dir_audit_index]}.directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_audit_array[dir_audit_index]}
Comment=Security Audit
Icon=folder
EOF
		dir_audit_index=$((dir_audit_index + 1))
	done
}


menu_entry ()
{
	local category="$1"
	local sub_category="$2"
	local tool="$3"
	cat > "/home/$USERS/.local/share/applications/Unk9vvN/${category}/${sub_category}/${tool}.desktop" << EOF
[Desktop Entry]
Name=${tool}
Exec=/usr/share/kali-menu/exec-in-shell "sudo ${tool} -h"
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
	cat > "/home/$USERS/.config/menus/applications-merged/Unk9vvN-${category}-${sub_category}-${tool}.menu" << EOF
<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
"http://www.freedesktop.org/standards/menu-spec/menu-1.0.dtd">
<Menu>
  <Name>Applications</Name>
  <Menu>
    <Name>Unk9vvN</Name>
    <Directory>Unk9vvN.directory</Directory>
  <Menu>
    <Name>Unk9vvN-${category}</Name>
    <Directory>Unk9vvN-${category}.directory</Directory>
  <Menu>
    <Name>Unk9vvN-${category}-${sub_category}</Name>
    <Directory>Unk9vvN-${category}-${sub_category}.directory</Directory>
    <Include>
      <Filename>Unk9vvN-${category}-${sub_category}-${tool}.desktop</Filename>
    </Include>
  </Menu>
  </Menu>
  </Menu>
</Menu>
EOF
}


penetrating_testing ()
{
	# ----------------------------------------------Web-Penetration-Testing---------------------------------------------- #
	# Install Repository Tools
	apt install -qy tor dirsearch nuclei rainbowcrack hakrawler gobuster seclists subfinder amass arjun metagoofil sublist3r cupp gifsicle aria2 phpggc emailharvester osrframework jq pngtools gitleaks trufflehog maryam dosbox wig eyewitness oclgausscrack websploit googler inspy proxychains pigz massdns gospider proxify privoxy dotdotpwn goofile firewalk bing-ip2hosts webhttrack oathtool tcptrack tnscmd10g getallurls padbuster feroxbuster subjack cyberchef whatweb xmlstarlet sslscan assetfinder uglify-js jsdom dnsgen 

	# Install Python3 pip
	pip3 install cryptography pyjwt arjun py-altdns pymultitor autosubtakeover crlfsuite censys ggshield bbqsql selenium PyJWT ciphey proxyhub njsscan detect-secrets regexploit h8mail nodejsscan hashpumpy maltego-trx bhedak gitfive modelscan shodan postmaniac APIFuzzer PyExfil wsgidav defaultcreds-cheat-sheet hiphp pasteme-cli aiodnsbrute semgrep wsrepl apachetomcatscanner dotdotfarm datasets 

	# Install Nodejs NPM
	npm install -g jwt-cracker graphql padding-oracle-attacker http-proxy-to-socks javascript-obfuscator serialize-javascript http-proxy-to-socks node-serialize igf electron-packager redos serialize-to-js dompurify nodesub multitor 

	# Install Ruby GEM
	gem install ssrf_proxy API_Fuzzer dawnscanner mechanize 

	# Install Golang
	web_go_array=()
	web_commands=$(echo '
go install github.com/tomnomnom/waybackurls@latest;ln -fs ~/go/bin/waybackurls /usr/bin/waybackurls
go install github.com/tomnomnom/httprobe@latest;ln -fs ~/go/bin/httprobe /usr/bin/httprobe
go install github.com/tomnomnom/meg@latest;ln -fs ~/go/bin/meg /usr/bin/meg
go install github.com/edoardottt/cariddi/cmd/cariddi@latest;ln -fs ~/go/bin/cariddi /usr/bin/cariddi
go install github.com/glebarez/cero@latest;ln -fs ~/go/bin/cero /usr/bin/cero
go install github.com/shivangx01b/CorsMe@latest;ln -fs ~/go/bin/CorsMe /usr/bin/CorsMe
go install github.com/pwnesia/dnstake/cmd/dnstake@latest;ln -fs ~/go/bin/dnstake /usr/bin/dnstake
go install github.com/projectdiscovery/dnsprobe@latest;ln -fs ~/go/bin/dnsprobe /usr/bin/dnsprobe
go install github.com/ryandamour/crlfmap@latest;ln -fs ~/go/bin/crlfmap /usr/bin/crlfmap
go install github.com/hahwul/dalfox/v2@latest;ln -fs ~/go/bin/dalfox /usr/bin/dalfox
go install github.com/d3mondev/puredns/v2@latest;ln -fs ~/go/bin/puredns /usr/bin/puredns
go install github.com/eth0izzle/shhgit@latest;ln -fs ~/go/bin/shhgit /usr/bin/shhgit
go install github.com/KathanP19/Gxss@latest;ln -fs ~/go/bin/Gxss /usr/bin/Gxss
go install github.com/003random/getJS@latest;ln -fs ~/go/bin/getJS /usr/bin/getJS
go install github.com/nytr0gen/deduplicate@latest;ln -fs ~/go/bin/deduplicate /usr/bin/deduplicate
go install github.com/tomnomnom/gf@latest;ln -fs ~/go/bin/gf /usr/bin/gf
go install github.com/tomnomnom/gron@latest;ln -fs ~/go/bin/gron /usr/bin/gron
go install github.com/harleo/asnip@latest;ln -fs ~/go/bin/asnip /usr/bin/asnip
go install github.com/hideckies/fuzzagotchi@latest;ln -fs ~/go/bin/fuzzagotchi /usr/bin/fuzzagotchi
go install github.com/projectdiscovery/alterx/cmd/alterx@latest;ln -fs ~/go/bin/alterx /usr/bin/alterx
go install github.com/hideckies/aut0rec0n@latest;ln -fs ~/go/bin/aut0rec0n /usr/bin/aut0rec0n
go install github.com/hakluke/haktrails@latest;ln -fs ~/go/bin/haktrails /usr/bin/haktrails
go install github.com/securebinary/firebaseExploiter@latest;ln -fs ~/go/bin/firebaseExploiter /usr/bin/firebaseExploiter
go install github.com/devanshbatham/headerpwn@latest;ln -fs ~/go/bin/headerpwn /usr/bin/headerpwn
go install github.com/dwisiswant0/cf-check@latest;ln -fs ~/go/bin/cf-check /usr/bin/cf-check
go install github.com/takshal/freq@latest;ln -fs ~/go/bin/freq /usr/bin/freq
go install github.com/hakluke/hakrevdns@latest;ln -fs ~/go/bin/hakrevdns /usr/bin/hakrevdns
go install github.com/hakluke/haktldextract@latest;ln -fs ~/go/bin/haktldextract /usr/bin/haktldextract
go install github.com/Emoe/kxss@latest;ln -fs ~/go/bin/kxss /usr/bin/kxss
go install github.com/ThreatUnkown/jsubfinder@latest;ln -fs ~/go/bin/jsubfinder /usr/bin/jsubfinder
go install github.com/jaeles-project/jaeles@latest;ln -fs ~/go/bin/jaeles /usr/bin/jaeles
go install github.com/hakluke/haklistgen@latest;ln -fs ~/go/bin/haklistgen /usr/bin/haklistgen
go install github.com/tomnomnom/qsreplace@latest;ln -fs ~/go/bin/qsreplace /usr/bin/qsreplace
go install github.com/lc/subjs@latest;ln -fs ~/go/bin/subjs /usr/bin/subjs
go install github.com/dwisiswant0/unew@latest;ln -fs ~/go/bin/unew /usr/bin/unew
go install github.com/tomnomnom/unfurl@latest;ln -fs ~/go/bin/unfurl /usr/bin/unfurl
go install github.com/detectify/page-fetch@latest;ln -fs ~/go/bin/page-fetch /usr/bin/page-fetch
go install github.com/dwisiswant0/ipfuscator@latest;ln -fs ~/go/bin/ipfuscator /usr/bin/ipfuscator
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
			symlink=$(echo "$line" | awk '{print $NF}')
			symlink=${symlink#/}
    			symlink=${symlink%/}
    			binary_name=$(basename "$symlink")
    			web_go_array+=("$binary_name")
		fi
	done <<< "$web_commands"
	for web_go_index in "${web_go_array[@]}"; do
		menu_entry "Penetration\ Testing" "Web" "${web_go_index}"
	done
	eval "$web_commands"

	# Install CloudBunny
	if [ ! -d "/usr/share/cloudbunny" ]; then
		git clone https://github.com/Warflop/CloudBunny /usr/share/cloudbunny
		cat > /usr/bin/cloudbunny << EOF
#!/bin/bash
cd /usr/share/cloudbunny;python3 cloudbunny.py "\$@"
EOF
		chmod +x /usr/bin/cloudbunny;chmod 755 /usr/share/cloudbunny/*
		pip3 install -r /usr/share/CloudBunny/requirements.txt
		menu_entry "Penetration\ Testing" "Web" "cloudbunny"
		printf "$GREEN"  "[*] Sucess Installing CloudBunny"
	else
		printf "$GREEN"  "[*] Sucess Installed CloudBunny"
	fi

	# Install Sn1per
	if [ ! -d "/usr/share/sniper" ]; then
		git clone https://github.com/1N3/Sn1per /tmp/Sn1per;cd /tmp/Sn1per;bash install.sh;rm -r /tmp/Sn1per
		printf "$GREEN"  "[*] Sucess Installing Sn1per"
	else
		printf "$GREEN"  "[*] Sucess Installed Sn1per"
	fi

	# Install PhoneInfoga
	if [ ! -d "/usr/share/phoneinfoga" ]; then
		wget https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/phoneinfoga.tar.gz
		tar -xvf /tmp/phoneinfoga.tar.gz -C /usr/share/phoneinfoga;rm -f /tmp/phoneinfoga.tar.gz
		ln -fs /usr/share/phoneinfoga/phoneinfoga /usr/bin/phoneinfoga
		chmod +x /usr/bin/phoneinfoga;chmod 755 /usr/share/phoneinfoga/*
		menu_entry "Penetration\ Testing" "Web" "phoneinfoga"
		printf "$GREEN"  "[*] Sucess Installing PhoneInfoga"
	else
		printf "$GREEN"  "[*] Sucess Installed PhoneInfoga"
	fi

	# Install Findomain
	if [ ! -d "/usr/share/findomain" ]; then
		wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -O /tmp/findomain-linux.zip
		unzip /tmp/findomain-linux.zip -d /usr/share/findomain;rm -f /tmp/findomain-linux.zip
		ln -fs /usr/share/findomain/findomain /usr/bin/findomain
		chmod +x /usr/bin/findomain;chmod 755 /usr/share/findomain/*
		menu_entry "Penetration\ Testing" "Web" "findomain"
		printf "$GREEN"  "[*] Sucess Installing Findomain"
	else
		printf "$GREEN"  "[*] Sucess Installed Findomain"
	fi

	# Install RustScan
	if [ ! -f "/usr/bin/rustscan" ]; then
		wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb -O /tmp/rustscan.deb
		chmod +x /tmp/rustscan.deb;dpkg -i /tmp/rustscan.deb;rm -f /tmp/rustscan.deb
		menu_entry "Penetration\ Testing" "Web" "rustscan"
		printf "$GREEN"  "[*] Sucess Installing RustScan"
	else
		printf "$GREEN"  "[*] Sucess Installed RustScan"
	fi

	# Install HashPump
	if [ ! -d "/usr/share/hashpump" ]; then
		git clone https://github.com/bwall/HashPump /usr/share/hashpump
		cat > /usr/bin/hashpump << EOF
#!/bin/bash
cd /usr/share/hashpump;bash hashpump "\$@"
EOF
		chmod +x /usr/bin/hashpump;chmod 755 /usr/share/hashpump/*
		cd /usr/share/hashpump/;make install
		menu_entry "Penetration\ Testing" "Web" "hashpump"
		printf "$GREEN"  "[*] Sucess Installing HashPump"
	else
		printf "$GREEN"  "[*] Sucess Installed HashPump"
	fi

	# Install RSAtool
	if [ ! -d "/usr/share/rsatool" ]; then
		git clone https://github.com/ius/rsatool /usr/share/rsatool
		cat > /usr/bin/rsatool << EOF
#!/bin/bash
cd /usr/share/rsatool;python3 rsatool.py "\$@"
EOF
		chmod +x /usr/bin/rsatool;chmod 755 /usr/share/rsatool/*
		menu_entry "Penetration\ Testing" "Web" "rsatool"
		printf "$GREEN"  "[*] Sucess Installing RSAtool"
	else
		printf "$GREEN"  "[*] Sucess Installed RSAtool"
	fi

	# Install RsaCtfTool
	if [ ! -d "/usr/share/rsactftool" ]; then
		git clone https://github.com/RsaCtfTool/RsaCtfTool /usr/share/rsactftool
		cat > /usr/bin/rsactftool << EOF
#!/bin/bash
cd /usr/share/RsaCtfTool;python3 RsaCtfTool.py "\$@"
EOF
		chmod +x /usr/bin/rsactftool;chmod 755 /usr/share/rsactftool/*
		menu_entry "Penetration\ Testing" "Web" "rsactftool"
		printf "$GREEN"  "[*] Sucess Installing RsaCtfTool"
	else
		printf "$GREEN"  "[*] Sucess Installed RsaCtfTool"
	fi

	# Install PEMCrack
	if [ ! -d "/usr/share/pemcrack" ]; then
		git clone https://github.com/robertdavidgraham/pemcrack /usr/share/pemcrack
		cd /usr/share/pemcrack;gcc pemcrack.c -o pemcrack -lssl -lcrypto
		ln -fs /usr/share/PEMCrack/pemcrack /usr/bin/pemcrack
		chmod +x /usr/bin/pemcrack;chmod 755 /usr/share/pemcrack/*
		menu_entry "Penetration\ Testing" "Web" "pemcrack"
		printf "$GREEN"  "[*] Sucess Installing PEMCrack"
	else
		printf "$GREEN"  "[*] Sucess Installed PEMCrack"
	fi

	# Install DyMerge
	if [ ! -d "/usr/share/dymerge" ]; then
		git clone https://github.com/k4m4/dymerge /usr/share/dymerge
		cat > /usr/bin/dymerge << EOF
#!/bin/bash
cd /usr/share/dymerge;python3 dymerge.py "\$@"
EOF
		chmod +x /usr/bin/dymerge;chmod 755 /usr/share/dymerge/*
		menu_entry "Penetration\ Testing" "Web" "dymerge"
		printf "$GREEN"  "[*] Sucess Installing DyMerge"
	else
		printf "$GREEN"  "[*] Sucess Installed DyMerge"
	fi

	# Install JWT-Tool
	if [ ! -d "/usr/share/jwt_tool" ]; then
		git clone https://github.com/ticarpi/jwt_tool /usr/share/jwt_tool
		cat > /usr/bin/jwt_tool << EOF
#!/bin/bash
cd /usr/share/jwt_tool;python3 jwt_tool.py "\$@"
EOF
		chmod +x /usr/bin/jwt_tool;chmod 755 /usr/share/jwt_tool/*
		pip3 install termcolor cprint pycryptodomex requests
		menu_entry "Penetration\ Testing" "Web" "jwt_tool"
		printf "$GREEN"  "[*] Sucess Installing JWT-Tool"
	else
		printf "$GREEN"  "[*] Sucess Installed JWT-Tool"
	fi

	# Install Poodle
	if [ ! -d "/usr/share/poodle" ]; then
		git clone https://github.com/mpgn/poodle-PoC /usr/share/poodle
		cat > /usr/bin/poodle << EOF
#!/bin/bash
cd /usr/share/poodle;python3 poodle-exploit.py "\$@"
EOF
		chmod +x /usr/bin/poodle;chmod 755 /usr/share/poodle/*
		menu_entry "Penetration\ Testing" "Web" "poodle"
		printf "$GREEN"  "[*] Sucess Installing Poodle"
	else
		printf "$GREEN"  "[*] Sucess Installed Poodle"
	fi

	# Install HashExtender
	if [ ! -d "/usr/share/hashextender" ]; then
		git clone https://github.com/iagox86/hash_extender /usr/share/hashextender
		cd /usr/share/hashextender;make
		ln -fs /usr/share/hashextender /usr/bin/hashextender
		chmod +x /usr/bin/hashextender;chmod 755 /usr/share/hashextender/*
		menu_entry "Penetration\ Testing" "Web" "hashextender"
		printf "$GREEN"  "[*] Sucess Installing HashExtender"
	else
		printf "$GREEN"  "[*] Sucess Installed HashExtender"
	fi

	# Install SpoofCheck
	if [ ! -d "/usr/share/spoofcheck" ]; then
		git clone https://github.com/BishopFox/spoofcheck /usr/share/spoofcheck
		cat > /usr/bin/spoofcheck << EOF
#!/bin/bash
cd /usr/share/spoofcheck;python2 spoofcheck.py "\$@"
EOF
		chmod +x /usr/bin/spoofcheck;chmod 755 /usr/share/spoofcheck/*
		pip2 install -r /usr/share/spoofcheck/requirements.txt
		menu_entry "Penetration\ Testing" "Web" "spoofcheck"
		printf "$GREEN"  "[*] Sucess Installing SpoofCheck"
	else
		printf "$GREEN"  "[*] Sucess Installed SpoofCheck"
	fi


	# --------------------------------------------Mobile-Penetration-Testing--------------------------------------------- #
	# Install Repository Tools
	apt install -qy jd-gui adb apksigner apktool android-tools-adb 

	# Install Python3 pip
	pip3 install frida-tools objection mitmproxy reflutter androguard apkleaks mobsf mvt kiwi androset 

	# Install Nodejs NPM
	npm install -g rms-runtime-mobile-security apk-mitm igf bagbak 

	# Install Ruby GEM
	gem install jwt-cracker 

	# Install Golang
	mobile_go_array=()
	mobile_commands=$(echo '
go install github.com/ndelphit/apkurlgrep@latest;ln -fs ~/go/bin/apkurlgrep /usr/bin/apkurlgrep
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    			symlink=$(echo "$line" | awk '{print $NF}')
    			symlink=${symlink#/}
    			symlink=${symlink%/}
    			binary_name=$(basename "$symlink")
    			mobile_go_array+=("$binary_name")
  		fi
	done <<< "$mobile_commands"
	for mobile_go_index in "${mobile_go_array[@]}"; do
		menu_entry "Penetration\ Testing" "Mobile" "${mobile_go_index}"
	done
	eval "$mobile_commands"

	# Install Genymotion
	if [ ! -d "/usr/share/genymotion" ]; then
		mkdir -p /user/share/genymotion
		wget https://dl.genymotion.com/releases/genymotion-3.6.0/genymotion-3.6.0-linux_x64.bin -O /user/share/genymotion/genymotion.bin
		cat > /usr/bin/genymotion << EOF
#!/bin/bash
cd /usr/share/genymotion;./genymotion.bin -y "\$@"
EOF
		chmod +x /usr/bin/genymotion;chmod 755 /usr/share/genymotion/*
		menu_entry "Penetration\ Testing" "Mobile" "genymotion"
		printf "$GREEN"  "[*] Sucess Installing Genymotion"
	else
		printf "$GREEN"  "[*] Sucess Installed Genymotion"
	fi

	# Install CloudBunny
	if [ ! -d "/usr/share/CloudBunny" ]; then
		git clone https://github.com/Warflop/CloudBunny /usr/share/CloudBunny
		cat > /usr/bin/cloudbunny << EOF
#!/bin/bash
cd /usr/share/CloudBunny;python3 cloudbunny.py "\$@"
EOF
		chmod +x /usr/bin/cloudbunny;chmod 755 /usr/share/CloudBunny/*
		pip3 install -r /usr/share/CloudBunny/requirements.txt
		menu_entry "Penetration\ Testing" "Web" "cloudbunny"
		printf "$GREEN"  "[*] Sucess Installing CloudBunny"
	else
		printf "$GREEN"  "[*] Sucess Installed CloudBunny"
	fi

	# Install MobSF
	if [ ! -d "/usr/share/MobSF" ]; then
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /usr/share/MobSF
		cat > /usr/bin/mobsf << EOF
#!/bin/bash
cd /usr/share/MobSF;./run.sh > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &
EOF
		chmod +x /usr/bin/mobsf;chmod 755 /usr/share/MobSF/*
		cd /usr/share/MobSF;./setup.sh
		menu_entry "Penetration\ Testing" "Mobile" "mobsf"
		printf "$GREEN"  "[*] Sucess Installing MobSF"
	else
		printf "$GREEN"  "[*] Sucess Installed MobSF"
	fi


	# --------------------------------------------Cloud-Penetration-Testing---------------------------------------------- #
	# Install Repository Tools
	apt install -qy awscli 

	# Install Python3 pip
	pip3 install sceptre aclpwn powerpwn ggshield pacu whispers s3scanner roadrecon roadlib gcp_scanner roadtx festin cloudsplaining c7n trailscraper lambdaguard airiam access-undenied-aws n0s1 aws-gate cloudscraper acltoolkit-ad prowler bloodhound aiodnsbrute gorilla-cli knowsmore 

	# Install Nodejs NPM
	npm install -g fleetctl 

	# Install Ruby GEM
	gem install aws_public_ips aws_security_viz aws_recon 

	# Install Golang
	cloud_go_array=()
	cloud_commands=$(echo '
go install github.com/koenrh/s3enum@latest;ln -fs ~/go/bin/s3enum /usr/bin/s3enum
go install github.com/smiegles/mass3@latest;ln -fs ~/go/bin/mass3 /usr/bin/mass3
go install github.com/magisterquis/s3finder@latest;ln -fs ~/go/bin/s3finder /usr/bin/s3finder
go install github.com/Macmod/goblob@latest;ln -fs ~/go/bin/goblob /usr/bin/goblob
go install github.com/g0ldencybersec/CloudRecon@latest;ln -fs ~/go/bin/CloudRecon /usr/bin/CloudRecon
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    			symlink=$(echo "$line" | awk '{print $NF}')
    			symlink=${symlink#/}
    			symlink=${symlink%/}
    			binary_name=$(basename "$symlink")
    			cloud_go_array+=("$binary_name")
		fi
	done <<< "$cloud_commands"
	for cloud_go_index in "${cloud_go_array[@]}"; do
		menu_entry "Penetration\ Testing" "Cloud" "${cloud_go_index}"
	done
	eval "$cloud_commands"

	# Install CloudFail
	if [ ! -d "/usr/share/cloudfail" ]; then
		git clone https://github.com/m0rtem/CloudFail /usr/share/CloudFail
		cat > /usr/bin/cloudfail << EOF
#!/bin/bash
cd /usr/share/CloudFail;python3 cloudfail.py "\$@"
EOF
		chmod +x /usr/bin/cloudfail;chmod 755 /usr/share/CloudFail/*
		pip3 install -r /usr/share/CloudFail/requirements.txt
		menu_entry "Penetration\ Testing" "Cloud" "cloudfail"
		printf "$GREEN"  "[*] Sucess Installing CloudFail"
	else
		printf "$GREEN"  "[*] Sucess Installed CloudFail"
	fi


	# -------------------------------------------Network-Penetration-Testing--------------------------------------------- #
	# Install Repository Tools
	apt install -qy cme amap bettercap dsniff arpwatch sslstrip sherlock parsero routersploit tcpxtract slowhttptest dnsmasq sshuttle haproxy smb4k pptpd xplico dosbox lldb zmap checksec kerberoast etherape ismtp ismtp privoxy ident-user-enum goldeneye oclgausscrack multiforcer crowbar brutespray isr-evilgrade smtp-user-enum proxychains pigz gdb isc-dhcp-server firewalk bing-ip2hosts sipvicious netstress tcptrack tnscmd10g darkstat naabu cyberchef nbtscan sslscan 

	# Install Python3 pip
	pip3 install networkx ropper mitmproxy mitm6 pymultitor scapy angr slowloris brute raccoon-scanner baboossh ciphey zeratool impacket aiodnsbrute ssh-mitm 

	# Install Nodejs NPM
	npm install -g http-proxy-to-socks multitor 

	# Install Ruby GEM
	gem install seccomp-tools 

	# Install Golang
	network_go_array=()
	network_commands=$(echo '
go install github.com/tomnomnom/waybackurls@latest;ln -fs ~/go/bin/waybackurls /usr/bin/waybackurls
go install github.com/s-rah/onionscan@latest;ln -fs ~/go/bin/onionscan /usr/bin/onionscan
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    			symlink=$(echo "$line" | awk '{print $NF}')
    			symlink=${symlink#/}
    			symlink=${symlink%/}
    			binary_name=$(basename "$symlink")
    			network_go_array+=("$binary_name")
		fi
	done <<< "$network_commands"
	for network_go_index in "${network_go_array[@]}"; do
		menu_entry "Penetration\ Testing" "Network" "${network_go_index}"
	done
	eval "$network_commands"

	# Install Hiddify-Next
	if [ ! -d "/usr/share/Hiddify-Next" ]; then
		wget https://github.com/hiddify/hiddify-next/releases/latest/download/hiddify-linux-x64.zip -O /tmp/hiddify-linux-x64.zip
		unzip /tmp/hiddify-linux-x64.zip -d /usr/share/Hiddify-Next;rm -f /tmp/hiddify-linux-x64.zip
    		cat > /usr/bin/hiddify << EOF
#!/bin/bash
cd /usr/share/hiddify;./hiddify-linux-x64.AppImage "\$@"
EOF
		menu_entry "Penetration\ Testing" "Network" "hiddify"
		printf "$GREEN"  "[*] Sucess Installing Hiddify-Next"
	else
		printf "$GREEN"  "[*] Sucess Installed Hiddify-Next"
	fi

	# Install SNMP-Brute
	if [ ! -d "/usr/share/SNMP-Brute" ]; then
		git clone https://github.com/SECFORCE/SNMP-Brute /usr/share/SNMP-Brute
		cat > /usr/bin/snmpbrute << EOF
#!/bin/bash
cd /usr/share/SNMP-Brute;python3 snmpbrute.py "\$@"
EOF
		chmod +x /usr/bin/snmpbrute;chmod 755 /usr/share/SNMP-Brute/*
		menu_entry "Penetration\ Testing" "Network" "snmpbrute"
		printf "$GREEN"  "[*] Sucess Installing SNMP-Brute"
	else
		printf "$GREEN"  "[*] Sucess Installed SNMP-Brute"
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
		chmod +x /usr/bin/routerscan;chmod 755 /usr/share/RouterScan/*
		menu_entry "Penetration\ Testing" "Network" "routerscan"
		printf "$GREEN"  "[*] Sucess Installing RouterScan"
	else
		printf "$GREEN"  "[*] Sucess Installed RouterScan"
	fi

	# Install PRET
	if [ ! -d "/usr/share/PRET" ]; then
		git clone https://github.com/RUB-NDS/PRET /usr/share/PRET
		cat > /usr/bin/pret << EOF
#!/bin/bash
cd /usr/share/PRET;python3 pret.py "\$@"
EOF
		chmod +x /usr/bin/pret;chmod 755 /usr/share/PRET/*
		pip3 install colorama pysnmp win_unicode_console
		menu_entry "Penetration\ Testing" "Network" "pret"
		printf "$GREEN"  "[*] Sucess Installing PRET"
	else
		printf "$GREEN"  "[*] Sucess Installed PRET"
	fi

	# Install GEF
	if [ ! -f "~/.gef-6a6e2a05ca8e08ac6845dce655a432fc4e029486.py" ]; then
		bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
		menu_entry "Penetration\ Testing" "Network" "gef"
		printf "$GREEN"  "[*] Sucess Installing GEF"
	else
		printf "$GREEN"  "[*] Sucess Installed GEF"
	fi

	# Install Angry-IP
	if [ ! -d "/usr/bin/ipscan" ]; then
		wget https://github.com/angryip/ipscan/releases/latest/download/ipscan_3.9.1_amd64.deb -O /tmp/ipscan.deb
		chmod +x /tmp/ipscan.deb;dpkg -i /tmp/ipscan_amd64.deb;rm -f /tmp/ipscan_amd64.deb
		printf "$GREEN"  "[*] Sucess Installing Angry-IP"
	else
		printf "$GREEN"  "[*] Sucess Installed Angry-IP"
	fi

	# Install Memcrashed
	if [ ! -d "/usr/share/memcrashed" ]; then
		git clone https://github.com/649/Memcrashed-DDoS-Exploit /usr/share/memcrashed
		cat > /usr/bin/memcrashed << EOF
#!/bin/bash
cd /usr/share/memcrashed;python3 Memcrashed.py "\$@"
EOF
		chmod +x /usr/bin/memcrashed;chmod 755 /usr/share/memcrashed/*
		pip3 install -r /usr/share/memcrashed/requirements.txt
		menu_entry "Penetration\ Testing" "Network" "memcrashed"
		printf "$GREEN"  "[*] Sucess Installing Memcrashed"
	else
		printf "$GREEN"  "[*] Sucess Installed Memcrashed"
	fi


	# -------------------------------------------Wireless-Penetration-Testing-------------------------------------------- #
	# Install Repository Tools
	apt install -qy airgeddon crackle kalibrate-rtl eaphammer rtlsdr-scanner wifiphisher airgraph-ng multimon-ng gr-gsm ridenum airspy gqrx-sdr btscanner bluesnarfer ubertooth blueranger wifipumpkin3 spooftooph dronesploit 

	# Install Python3 pip
	pip3 install btlejack scapy wpspin 

	# Install Nodejs NPM
	npm install -g btlejuice 

	# Install Ruby GEM
	gem install 

	# Install Golang
	wireless_go_array=()
	wireless_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    			symlink=$(echo "$line" | awk '{print $NF}')
    			symlink=${symlink#/}
    			symlink=${symlink%/}
    			binary_name=$(basename "$symlink")
    			wireless_go_array+=("$binary_name")
  		fi
	done <<< "$wireless_commands"
	for wireless_go_index in "${wireless_go_array[@]}"; do
  		menu_entry "Penetration\ Testing" "Wireless" "${wireless_go_array}"
	done
	eval "$wireless_commands"

	# Install GTScan
	if [ ! -d "/usr/share/GTScan" ]; then
		git clone https://github.com/SigPloiter/GTScan /usr/share/GTScan
		cat > /usr/bin/gtscan << EOF
#!/bin/bash
cd /usr/share/GTScan;python3 gtscan.py "\$@"
EOF
		chmod +x /usr/bin/gtscan;chmod 755 /usr/share/GTScan/*
    		pip3 install -r /usr/share/GTScan/requirements.txt
    		menu_entry "Penetration\ Testing" "Wireless" "gtscan"
		printf "$GREEN"  "[*] Sucess Installing GTScan"
	else
		printf "$GREEN"  "[*] Sucess Installed GTScan"
	fi

	# Install HLR-Lookups
	if [ ! -d "/usr/share/HLR-Lookups" ]; then
		git clone https://github.com/SigPloiter/HLR-Lookups /usr/share/HLR-Lookups
		cat > /usr/bin/hlrlookups << EOF
#!/bin/bash
cd /usr/share/HLR-Lookups;python3 hlr-lookups.py "\$@"
EOF
		chmod +x /usr/bin/hlrlookups;chmod 755 /usr/share/HLR-Lookups/*
		menu_entry "Penetration\ Testing" "Wireless" "hlrlookups"
		printf "$GREEN"  "[*] Sucess Installing HLR-Lookups"
	else
		printf "$GREEN"  "[*] Sucess Installed HLR-Lookups"
	fi


	# ----------------------------------------------IoT-Penetration-Testing---------------------------------------------- #
	# Install Repository Tools
	apt install -qy arduino gnuradio 

	# Install Python3 pip
	pip3 install scapy uefi_firmware unblob 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	iot_go_array=()
	iot_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    			symlink=$(echo "$line" | awk '{print $NF}')
    			symlink=${symlink#/}
    			symlink=${symlink%/}
    			binary_name=$(basename "$symlink")
    			iot_go_array+=("$binary_name")
  		fi
	done <<< "$iot_commands"
	for iot_go_index in "${iot_go_array[@]}"; do
  		menu_entry "Penetration\ Testing" "IoT" "${iot_go_index}"
	done
	eval "$iot_commands"
}


red_team ()
{
	printf "$GREEN"  "[*] Added Next Release Courses"
}


ics_security ()
{
	printf "$GREEN"  "[*] Added Next Release Courses"
}


digital_forensic ()
{
	printf "$GREEN"  "[*] Added Next Release Courses"
}


blue_team ()
{
	printf "$GREEN"  "[*] Added Next Release Courses"
}


security_audit ()
{
	printf "$GREEN"  "[*] Added Next Release Courses"
}


main ()
{
	# Update & Upgrade OS
	apt update;apt upgrade -qy;apt dist-upgrade -qy

	# Install Repository Tools
	apt install -qy git apt-transport-https tor obfs4proxy docker.io docker-compose nodejs npm cargo golang libreoffice vlc uget remmina openconnect bleachbit powershell filezilla telegram-desktop joplin thunderbird mono-complete mono-devel node-ws p7zip p7zip-full wine winetricks winbind cmake build-essential binutils git gdb net-tools nasm snmp-mibs-downloader locate alacarte imagemagick ghostscript software-properties-common python3-poetry libre2-dev cassandra gnupg2 ca-certificates htop nload gimp cmatrix zipalign ffmpeg rar wireguard 

	# Install Python3 pip
	pip3 install colorama pysnmp

	# Install Nodejs NPM
	npm install -g npx 

	# Install Ruby GEM
	# gem install 

	# Install Kali_Elite
	if [ ! -d "/usr/share/kali_elite" ]; then
		mkdir -p /usr/share/kali_elite
		curl -s -o /usr/share/kali_elite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/Kali_Elite.sh
		cat > /usr/bin/kalielite << EOF
#!/bin/bash
cd /usr/share/kali_elite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/kalielite;chmod 755 /usr/share/kali_elite/*
		menu_entry "Security\ Audit" "Preliminary\ Audit\ Assessment" "kalielite"
		bash /usr/share/kali_elite/kalielite.sh
	elif [ "$(curl -s https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/version)" != $version ]; then
		curl -s -o /usr/share/kali_elite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/Kali_Elite.sh
		cat > /usr/bin/kalielite << EOF
#!/bin/bash
cd /usr/share/kali_elite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/kalielite;chmod 755 /usr/share/kali_elite/*
		menu_entry "Security\ Audit" "Preliminary\ Audit\ Assessment" "kalielite"
		bash /usr/share/kali_elite/kalielite.sh
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
           	printf "$RED"     "[X] Invalid select item..."
		;;			
   	esac
done
