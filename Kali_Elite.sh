#!/bin/bash
version='10.0'


RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'
USERS=$(users | awk '{print $1}')



if [ "$(id -u)" != "0" ];then
	printf "$RED"		"[X] Please run as RooT ..."
	printf "$GREEN"		"sudo kalielite"
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
	printf "$WHITE"   "        yo::/+o-m   -qyNy/:  ...:+s.//:://.s+:...  :/yNs   m-h++++oy   "
	printf "$WHITE"   "        oy/hsss-N-  oo:oN-   .-o.:ss:--:ss:.o-.   -My-oo  -N-o+++.so   "
	printf "$WHITE"   "        :m :++y:y+   sNMy+: -+/:.--:////:--.:/+- -+hNNs   +y-o++o-m:   "
	printf "$WHITE"   "        -d/::+o+.m-  -:/+ho:.       -//-       ./sdo::-  -m-o++++/d-   "
	printf "$WHITE"   "         :m-qyo++//d- -ommMo//        -:        +oyNhmo- -d//s+++-m:   "
	printf "$WHITE"   "          oy /o++//d.  -::/oMss-   -+++s      :yNy+/:  .d//y+---qys    "
	printf "$WHITE"   "           ys--+o++:d/ -/sdmNysNs+/./-//-//hNyyNmmy+-  /d-+y--::sy     "
	printf "$RED"     "            sy:..ooo-+h/--.-//odm/hNh--qyNh+Ndo//-./:/h+-so+:+/ys      "
	printf "$RED"     "             /d-o.ssy+-+yo:/:/:-:+sho..ohs/-:://::oh+.h//syo-d/-       "
	printf "$RED"     "              -qys-oosyss:/oyy//::.-.--.--:/.//syo+-qys//o/.sy-        "
	printf "$RED"     "                -qys.sooh+d-s:+osssysssosssssso:/+/h:/yy/.sy-          "
	printf "$RED"     "                  .sy/:os.h--d/o+-/+:o:/+.+o:d-qy+h-o+-+ys.            "
	printf "$RED"     "                     :sy+:+ s//sy-qy.-h-m/om:s-qy.++/+ys/              "
	printf "$RED"     "                        -+sss+/o/ s--qy.s+/:++-+sss+-                  "
	printf "$RED"     "                            --/osssssssssssso/--                       "
	printf "$BLUE"    "                                  Unk9vvN                              "
	printf "$YELLOW"  "                            https://unk9vvn.com                        "
	printf "$CYAN"    "                                Kali Elite                             "
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
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration-Testing
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration-Testing.directory << EOF
[Desktop Entry]
Type=Directory
Name=Penetration-Testing
Comment=Offensive-Security
Icon=/home/$USERS/.local/images/penetration-testing.png
EOF
	dir_pentest_array=("Web" "Mobile" "Cloud" "Network" "Wireless" "IoT")
	dir_pentest_index=0
	while [ $dir_pentest_index -lt ${#dir_pentest_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Penetration-Testing/${dir_pentest_array[dir_pentest_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Penetration-Testing-"${dir_pentest_array[dir_pentest_index]}".directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_pentest_array[dir_pentest_index]}
Comment=Penetration-Testing
Icon=folder
EOF
		dir_pentest_index=$((dir_pentest_index + 1))
	done

	# Initialize Red Team Menu
	curl -s -o /home/$USERS/.local/images/red-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/red-team.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red-Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red-Team.directory << EOF
[Desktop Entry]
Type=Directory
Name=Red-Team
Comment=Offensive-Security
Icon=/home/$USERS/.local/images/red-team.png
EOF
	dir_redteam_array=("Reconnaissance" "Resource-Development" "Initial-Access" "Execution" "Persistence" "Privilege-Escalation" "Defense-Evasion" "Credential-Access" "Discovery" "Lateral-Movement" "Collection" "Command-and-Control" "Exfiltration" "Impact")
	dir_redteam_index=0
	while [ $dir_redteam_index -lt ${#dir_redteam_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Red-Team/${dir_redteam_array[dir_redteam_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Red-Team-"${dir_redteam_array[dir_redteam_index]}".directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_redteam_array[dir_redteam_index]}
Comment=Red-Team
Icon=folder
EOF
		dir_redteam_index=$((dir_redteam_index + 1))
	done

	# Initialize ICS Security Menu
	curl -s -o /home/$USERS/.local/images/ics-security.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/ics-security.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS-Security
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS-Security.directory << EOF
[Desktop Entry]
Type=Directory
Name=ICS-Security
Comment=Offensive-Security
Icon=/home/$USERS/.local/images/ics-security.png
EOF
	dir_ics_array=("Penetration-Testing" "Red-Team" "Digital-Forensic" "Blue-Team")
	dir_ics_index=0
	while [ $dir_ics_index -lt ${#dir_ics_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/ICS-Security/${dir_ics_array[dir_ics_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-ICS-Security-"${dir_ics_array[dir_ics_index]}".directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_ics_array[dir_ics_index]}
Comment=ICS-Security
Icon=folder
EOF
		dir_ics_index=$((dir_ics_index + 1))
	done

	# Initialize Digital Forensic Menu
	curl -s -o /home/$USERS/.local/images/digital-forensic.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/digital-forensic.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital-Forensic
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital-Forensic.directory << EOF
[Desktop Entry]
Type=Directory
Name=Digital-Forensic
Comment=Defensive-Security
Icon=/home/$USERS/.local/images/digital-forensic.png
EOF
	dir_digital_array=("Reverse-Engineering" "Malware-Analysis" "Threat-Hunting" "Incident-Response" "Threat-Intelligence")
	dir_digital_index=0
	while [ $dir_digital_index -lt ${#dir_ics_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Digital-Forensic/${dir_digital_array[dir_digital_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Digital-Forensic-"${dir_digital_array[dir_digital_index]}".directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_digital_array[dir_digital_index]}
Comment=Digital-Forensic
Icon=folder
EOF
		dir_digital_index=$((dir_digital_index + 1))
	done

	# Initialize Blue Team Menu
	curl -s -o /home/$USERS/.local/images/blue-team.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/blue-team.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue-Team
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue-Team.directory << EOF
[Desktop Entry]
Type=Directory
Name=Blue-Team
Comment=Defensive-Security
Icon=/home/$USERS/.local/images/blue-team.png
EOF
	dir_blueteam_array=("Harden" "Detect" "Isolate" "Deceive" "Evict")
	dir_blueteam_index=0
	while [ $dir_blueteam_index -lt ${#dir_blueteam_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Blue-Team/${dir_blueteam_array[dir_blueteam_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Blue-Team-"${dir_blueteam_array[dir_blueteam_index]}".directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_blueteam_array[dir_blueteam_index]}
Comment=Blue-Team
Icon=folder
EOF
		dir_blueteam_index=$((dir_blueteam_index + 1))
	done

	# Initialize Security Audit Menu
	curl -s -o /home/$USERS/.local/images/security-audit.png https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/security-audit.png
	mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security-Audit
	cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security-Audit.directory << EOF
[Desktop Entry]
Type=Directory
Name=Security-Audit
Comment=Defensive-Security
Icon=/home/$USERS/.local/images/security-audit.png
EOF
	dir_audit_array=("Preliminary-Audit-Assessment" "Planning-and-Preparation" "Establishing-Audit-Objectives" "Performing-the-Review" "Preparing-the-Audit-Report" "Issuing-the-Review-Report")
	dir_audit_index=0
	while [ $dir_audit_index -lt ${#dir_audit_array[@]} ]; do
		mkdir -p /home/$USERS/.local/share/applications/Unk9vvN/Security-Audit/${dir_audit_array[dir_audit_index]}
		cat > /home/$USERS/.local/share/desktop-directories/Unk9vvN-Security-Audit-"${dir_audit_array[dir_audit_index]}".directory << EOF
[Desktop Entry]
Type=Directory
Name=${dir_audit_array[dir_audit_index]}
Comment=Security-Audit
Icon=folder
EOF
		dir_audit_index=$((dir_audit_index + 1))
	done
}


menu_entry ()
{
	local category="$1"
	local sub_category="$2"
	local name="$3"
	local command="$4"
	cat > "/home/$USERS/.local/share/applications/Unk9vvN/${category}/${sub_category}/${name}.desktop" << EOF
[Desktop Entry]
Name=${name}
Exec=${command}
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
	cat > "/home/$USERS/.config/menus/applications-merged/Unk9vvN-${category}-${sub_category}-${name}.menu" << EOF
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
      <Filename>Unk9vvN-${category}-${sub_category}-${name}.desktop</Filename>
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
	apt install -qy tor dirsearch nuclei rainbowcrack hakrawler gobuster seclists subfinder amass arjun metagoofil sublist3r cupp gifsicle aria2 phpggc emailharvester osrframework jq pngtools gitleaks trufflehog maryam dosbox wig eyewitness oclgausscrack websploit googler inspy proxychains pigz massdns gospider proxify privoxy dotdotpwn goofile firewalk bing-ip2hosts webhttrack oathtool tcptrack tnscmd10g getallurls padbuster feroxbuster subjack cyberchef whatweb xmlstarlet sslscan assetfinder dnsgen mdbtools 

	# Install Python3 pip
	pip3 install cryptography pyjwt arjun py-altdns pymultitor autosubtakeover crlfsuite censys ggshield bbqsql selenium PyJWT ciphey proxyhub njsscan detect-secrets regexploit h8mail nodejsscan hashpumpy maltego-trx bhedak gitfive modelscan shodan postmaniac APIFuzzer PyExfil wsgidav defaultcreds-cheat-sheet hiphp pasteme-cli aiodnsbrute semgrep wsrepl apachetomcatscanner dotdotfarm datasets pymetasec theharvester 

	# Install Nodejs NPM
	npm install -g jwt-cracker graphql padding-oracle-attacker http-proxy-to-socks javascript-obfuscator serialize-javascript http-proxy-to-socks node-serialize igf electron-packager redos serialize-to-js dompurify nodesub multitor 

	# Install Ruby GEM
	gem install ssrf_proxy API_Fuzzer dawnscanner mechanize XSpear

	# Install Golang
	web_go_array=()
	web_commands=$(echo '
go install github.com/tomnomnom/waybackurls@latest;ln -fs ~/go/bin/waybackurls /usr/bin/waybackurls
go install github.com/tomnomnom/httprobe@latest;ln -fs ~/go/bin/httprobe /usr/bin/httprobe
go install github.com/tomnomnom/meg@latest;ln -fs ~/go/bin/meg /usr/bin/meg
go install github.com/edoardottt/cariddi/cmd/cariddi@latest;ln -fs ~/go/bin/cariddi /usr/bin/cariddi
go install github.com/glebarez/cero@latest;ln -fs ~/go/bin/cero /usr/bin/cero
go install github.com/shivangx01b/CorsMe@latest;ln -fs ~/go/bin/CorsMe /usr/bin/corsme
go install github.com/pwnesia/dnstake/cmd/dnstake@latest;ln -fs ~/go/bin/dnstake /usr/bin/dnstake
go install github.com/projectdiscovery/dnsprobe@latest;ln -fs ~/go/bin/dnsprobe /usr/bin/dnsprobe
go install github.com/ryandamour/crlfmap@latest;ln -fs ~/go/bin/crlfmap /usr/bin/crlfmap
go install github.com/hahwul/dalfox/v2@latest;ln -fs ~/go/bin/dalfox /usr/bin/dalfox
go install github.com/d3mondev/puredns/v2@latest;ln -fs ~/go/bin/puredns /usr/bin/puredns
go install github.com/eth0izzle/shhgit@latest;ln -fs ~/go/bin/shhgit /usr/bin/shhgit
go install github.com/KathanP19/Gxss@latest;ln -fs ~/go/bin/Gxss /usr/bin/gxss
go install github.com/003random/getJS@latest;ln -fs ~/go/bin/getJS /usr/bin/getjs
go install github.com/jaeles-project/gospider@latest;ln -fs ~/go/bin/gospider /usr/bin/gospider
go install github.com/nytr0gen/deduplicate@latest;ln -fs ~/go/bin/deduplicate /usr/bin/deduplicate
go install github.com/tomnomnom/gf@latest;ln -fs ~/go/bin/gf /usr/bin/gf
go install github.com/tomnomnom/gron@latest;ln -fs ~/go/bin/gron /usr/bin/gron
go install github.com/harleo/asnip@latest;ln -fs ~/go/bin/asnip /usr/bin/asnip
go install github.com/hideckies/fuzzagotchi@latest;ln -fs ~/go/bin/fuzzagotchi /usr/bin/fuzzagotchi
go install github.com/projectdiscovery/alterx/cmd/alterx@latest;ln -fs ~/go/bin/alterx /usr/bin/alterx
go install github.com/hideckies/aut0rec0n@latest;ln -fs ~/go/bin/aut0rec0n /usr/bin/aut0rec0n
go install github.com/hakluke/haktrails@latest;ln -fs ~/go/bin/haktrails /usr/bin/haktrails
go install github.com/securebinary/firebaseExploiter@latest;ln -fs ~/go/bin/firebaseExploiter /usr/bin/firebaseexploiter
go install github.com/devanshbatham/headerpwn@latest;ln -fs ~/go/bin/headerpwn /usr/bin/headerpwn
go install github.com/dwisiswant0/cf-check@latest;ln -fs ~/go/bin/cf-check /usr/bin/cfcheck
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
go install github.com/detectify/page-fetch@latest;ln -fs ~/go/bin/page-fetch /usr/bin/pagefetch
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
		menu_entry "Penetration-Testing" "Web" "${web_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${web_go_index} -h'"
	done
	eval "$web_commands"

	# Install Sn1per
	if [ ! -d "/usr/share/sniper" ]; then
		git clone https://github.com/1N3/Sn1per /tmp/Sn1per;cd /tmp/Sn1per;sudo ./install.sh;rm -r /tmp/Sn1per
		printf "$GREEN"  "[*] Success Installing Sn1per"
	else
		printf "$GREEN"  "[*] Success Installed Sn1per"
	fi

	# Install CloudBunny
	if [ ! -d "/usr/share/cloudbunny" ]; then
		git clone https://github.com/Warflop/CloudBunny /usr/share/cloudbunny
		chmod 755 /usr/share/cloudbunny/*
		cat > /usr/bin/cloudbunny << EOF
#!/bin/bash
cd /usr/share/cloudbunny;python3 cloudbunny.py "\$@"
EOF
		chmod +x /usr/bin/cloudbunny
		pip3 install -r /usr/share/cloudbunny/requirements.txt
		menu_entry "Penetration-Testing" "Web" "CloudBunny" "/usr/share/kali-menu/exec-in-shell 'cloudbunny -h'"
		printf "$GREEN"  "[*] Success Installing CloudBunny"
	else
		printf "$GREEN"  "[*] Success Installed CloudBunny"
	fi

	# Install PhoneInfoga
	if [ ! -d "/usr/share/phoneinfoga" ]; then
		mkdir -p /usr/share/phoneinfoga
		wget https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/phoneinfoga.tar.gz
		tar -xvf /tmp/phoneinfoga.tar.gz -C /usr/share/phoneinfoga;rm -f /tmp/phoneinfoga.tar.gz
		chmod 755 /usr/share/phoneinfoga/*
		ln -fs /usr/share/phoneinfoga/phoneinfoga /usr/bin/phoneinfoga
		chmod +x /usr/bin/phoneinfoga
		menu_entry "Penetration-Testing" "Web" "PhoneInfoga" "/usr/share/kali-menu/exec-in-shell 'sudo phoneinfoga -h'"
		printf "$GREEN"  "[*] Success Installing PhoneInfoga"
	else
		printf "$GREEN"  "[*] Success Installed PhoneInfoga"
	fi

	# Install Findomain
	if [ ! -d "/usr/share/findomain" ]; then
		wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -O /tmp/findomain-linux.zip
		unzip /tmp/findomain-linux.zip -d /usr/share/findomain;rm -f /tmp/findomain-linux.zip
		chmod 755 /usr/share/findomain/*
		ln -fs /usr/share/findomain/findomain /usr/bin/findomain
		chmod +x /usr/bin/findomain
		menu_entry "Penetration-Testing" "Web" "Findomain" "/usr/share/kali-menu/exec-in-shell 'sudo findomain -h'"
		printf "$GREEN"  "[*] Success Installing Findomain"
	else
		printf "$GREEN"  "[*] Success Installed Findomain"
	fi

	# Install RustScan
	if [ ! -f "/usr/bin/rustscan" ]; then
		wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb -O /tmp/rustscan.deb
		chmod +x /tmp/rustscan.deb;dpkg -i /tmp/rustscan.deb;rm -f /tmp/rustscan.deb
		menu_entry "Penetration-Testing" "Web" "RustScan" "/usr/share/kali-menu/exec-in-shell 'sudo rustscan -h'"
		printf "$GREEN"  "[*] Success Installing RustScan"
	else
		printf "$GREEN"  "[*] Success Installed RustScan"
	fi

	# Install HashPump
	if [ ! -d "/usr/share/hashpump" ]; then
		git clone https://github.com/mheistermann/HashPump-partialhash /usr/share/hashpump
		chmod 755 /usr/share/hashpump/*
		cd /usr/share/hashpump;make;make install
		chmod +x /usr/bin/hashpump
		menu_entry "Penetration-Testing" "Web" "HashPump" "/usr/share/kali-menu/exec-in-shell 'sudo hashpump -h'"
		printf "$GREEN"  "[*] Success Installing HashPump"
	else
		printf "$GREEN"  "[*] Success Installed HashPump"
	fi

	# Install pixload
	if [ ! -d "/usr/share/pixload" ]; then
		git clone https://github.com/sighook/pixload /usr/share/pixload
		chmod 755 /usr/share/pixload/*
		cd /usr/share/pixload;make install
		menu_entry "Penetration-Testing" "Web" "pixload" "/usr/share/kali-menu/exec-in-shell 'sudo pixload-bmp --help'"
		printf "$GREEN"  "[*] Success Installing pixload"
	else
		printf "$GREEN"  "[*] Success Installed pixload"
	fi

	# Install RSAtool
	if [ ! -d "/usr/share/rsatool" ]; then
		git clone https://github.com/ius/rsatool /usr/share/rsatool
		chmod 755 /usr/share/rsatool/*
		cat > /usr/bin/rsatool << EOF
#!/bin/bash
cd /usr/share/rsatool;python3 rsatool.py "\$@"
EOF
		chmod +x /usr/bin/rsatool
		menu_entry "Penetration-Testing" "Web" "RSAtool" "/usr/share/kali-menu/exec-in-shell 'rsatool -h'"
		printf "$GREEN"  "[*] Success Installing RSAtool"
	else
		printf "$GREEN"  "[*] Success Installed RSAtool"
	fi

	# Install Polyglot
	if [ ! -d "/usr/share/polyglot" ]; then
		git clone https://github.com/Polydet/polyglot-database /usr/share/polyglot-database
		chmod 755 /usr/share/polyglot/files/*
		cat > /usr/bin/polyglot << EOF
#!/bin/bash
cd /usr/share/polyglot/files;ls "\$@"
EOF
		chmod +x /usr/bin/polyglot
		menu_entry "Penetration-Testing" "Web" "Polyglot" "/usr/share/kali-menu/exec-in-shell 'polyglot -h'"
		printf "$GREEN"  "[*] Success Installing Polyglot"
	else
		printf "$GREEN"  "[*] Success Installed Polyglot"
	fi

	# Install RsaCtfTool
	if [ ! -d "/usr/share/rsactftool" ]; then
		git clone https://github.com/RsaCtfTool/RsaCtfTool /usr/share/rsactftool
		chmod 755 /usr/share/rsactftool/*
		cat > /usr/bin/rsactftool << EOF
#!/bin/bash
cd /usr/share/rsactftool;python3 RsaCtfTool.py "\$@"
EOF
		chmod +x /usr/bin/rsactftool
		menu_entry "Penetration-Testing" "Web" "RsaCtfTool" "/usr/share/kali-menu/exec-in-shell 'rsactftool -h'"
		printf "$GREEN"  "[*] Success Installing RsaCtfTool"
	else
		printf "$GREEN"  "[*] Success Installed RsaCtfTool"
	fi

	# Install PEMCrack
	if [ ! -d "/usr/share/pemcrack" ]; then
		git clone https://github.com/robertdavidgraham/pemcrack /usr/share/pemcrack
		chmod 755 /usr/share/pemcrack/*
		cd /usr/share/pemcrack;gcc pemcrack.c -o pemcrack -lssl -lcrypto
		ln -fs /usr/share/pemcrack/pemcrack /usr/bin/pemcrack
		chmod +x /usr/bin/pemcrack
		menu_entry "Penetration-Testing" "Web" "PEMCrack" "/usr/share/kali-menu/exec-in-shell 'sudo pemcrack -h'"
		printf "$GREEN"  "[*] Success Installing PEMCrack"
	else
		printf "$GREEN"  "[*] Success Installed PEMCrack"
	fi
 
	# Install DyMerge
	if [ ! -d "/usr/share/dymerge" ]; then
		git clone https://github.com/k4m4/dymerge /usr/share/dymerge
		chmod 755 /usr/share/dymerge/*
		cat > /usr/bin/dymerge << EOF
#!/bin/bash
cd /usr/share/dymerge;python2 dymerge.py "\$@"
EOF
		chmod +x /usr/bin/dymerge
		menu_entry "Penetration-Testing" "Web" "DyMerge" "/usr/share/kali-menu/exec-in-shell 'dymerge -h'"
		printf "$GREEN"  "[*] Success Installing DyMerge"
	else
		printf "$GREEN"  "[*] Success Installed DyMerge"
	fi

	# Install XSS-LOADER
	if [ ! -d "/usr/share/xssloader" ]; then
		git clone https://github.com/capture0x/XSS-LOADER /usr/share/xssloader
		chmod 755 /usr/share/xssloader/*
		cat > /usr/bin/xssloader << EOF
#!/bin/bash
cd /usr/share/xssloader;python3 payloader.py "\$@"
EOF
		chmod +x /usr/bin/xssloader
		pip3 install -r /usr/share/xssloader/requirements.txt
		menu_entry "Penetration-Testing" "Web" "XSS-LOADER" "/usr/share/kali-menu/exec-in-shell 'xssloader -h'"
		printf "$GREEN"  "[*] Success Installing XSS-LOADER"
	else
		printf "$GREEN"  "[*] Success Installed XSS-LOADER"
	fi

	# Install XSStrike
	if [ ! -d "/usr/share/xsstrike" ]; then
		git clone https://github.com/s0md3v/XSStrike /usr/share/xsstrike
		chmod 755 /usr/share/xsstrike/*
		cat > /usr/bin/xsstrike << EOF
#!/bin/bash
cd /usr/share/xsstrike;python3 xsstrike.py "\$@"
EOF
		chmod +x /usr/bin/xsstrike
		pip3 install -r /usr/share/xsstrike/requirements.txt
		menu_entry "Penetration-Testing" "Web" "XSStrike" "/usr/share/kali-menu/exec-in-shell 'xsstrike -h'"
		printf "$GREEN"  "[*] Success Installing XSStrike"
	else
		printf "$GREEN"  "[*] Success Installed XSStrike"
	fi

	# Install JWT-Tool
	if [ ! -d "/usr/share/jwt_tool" ]; then
		git clone https://github.com/ticarpi/jwt_tool /usr/share/jwt_tool
		chmod 755 /usr/share/jwt_tool/*
		cat > /usr/bin/jwt_tool << EOF
#!/bin/bash
cd /usr/share/jwt_tool;python3 jwt_tool.py "\$@"
EOF
		chmod +x /usr/bin/jwt_tool
		menu_entry "Penetration-Testing" "Web" "JWT-Tool" "/usr/share/kali-menu/exec-in-shell 'jwt_tool -h'"
		printf "$GREEN"  "[*] Success Installing JWT-Tool"
	else
		printf "$GREEN"  "[*] Success Installed JWT-Tool"
	fi

	# Install Poodle
	if [ ! -d "/usr/share/poodle" ]; then
		git clone https://github.com/mpgn/poodle-PoC /usr/share/poodle
		chmod 755 /usr/share/poodle/*
		cat > /usr/bin/poodle << EOF
#!/bin/bash
cd /usr/share/poodle;python3 poodle-exploit.py "\$@"
EOF
		chmod +x /usr/bin/poodle
		menu_entry "Penetration-Testing" "Web" "Poodle" "/usr/share/kali-menu/exec-in-shell 'poodle -h'"
		printf "$GREEN"  "[*] Success Installing Poodle"
	else
		printf "$GREEN"  "[*] Success Installed Poodle"
	fi

	# Install Gopherus
	if [ ! -d "/usr/share/gopherus" ]; then
		git clone https://github.com/tarunkant/Gopherus /usr/share/gopherus
		chmod 755 /usr/share/gopherus/*
		cat > /usr/bin/gopherus << EOF
#!/bin/bash
cd /usr/share/gopherus;python2 gopherus.py "\$@"
EOF
		chmod +x /usr/bin/gopherus
		menu_entry "Penetration-Testing" "Web" "Gopherus" "/usr/share/kali-menu/exec-in-shell 'gopherus -h'"
		printf "$GREEN"  "[*] Success Installing Gopherus"
	else
		printf "$GREEN"  "[*] Success Installed Gopherus"
	fi

	# Install HashExtender
	if [ ! -d "/usr/share/hashextender" ]; then
		git clone https://github.com/iagox86/hash_extender /usr/share/hashextender
		chmod 755 /usr/share/hashextender/*
		cd /usr/share/hashextender;make
		ln -fs /usr/share/hashextender /usr/bin/hashextender
		chmod +x /usr/bin/hashextender
		menu_entry "Penetration-Testing" "Web" "HashExtender" "/usr/share/kali-menu/exec-in-shell 'sudo hashextender -h'"
		printf "$GREEN"  "[*] Success Installing HashExtender"
	else
		printf "$GREEN"  "[*] Success Installed HashExtender"
	fi

	# Install SpoofCheck
	if [ ! -d "/usr/share/spoofcheck" ]; then
		git clone https://github.com/BishopFox/spoofcheck /usr/share/spoofcheck
		chmod 755 /usr/share/spoofcheck/*
		cat > /usr/bin/spoofcheck << EOF
#!/bin/bash
cd /usr/share/spoofcheck;python2 spoofcheck.py "\$@"
EOF
		chmod +x /usr/bin/spoofcheck
		pip2 install -r /usr/share/spoofcheck/requirements.txt
		menu_entry "Penetration-Testing" "Web" "SpoofCheck" "/usr/share/kali-menu/exec-in-shell 'spoofcheck -h'"
		printf "$GREEN"  "[*] Success Installing SpoofCheck"
	else
		printf "$GREEN"  "[*] Success Installed SpoofCheck"
	fi

	# Install RED_HAWK
	if [ ! -d "/usr/share/red_hawk" ]; then
		git clone https://github.com/Tuhinshubhra/RED_HAWK /usr/share/red_hawk
		chmod 755 /usr/share/red_hawk/*
		cat > /usr/bin/red_hawk << EOF
#!/bin/bash
cd /usr/share/red_hawk;php rhawk.php "\$@"
EOF
		chmod +x /usr/bin/red_hawk
		menu_entry "Penetration-Testing" "Web" "RED_HAWK" "/usr/share/kali-menu/exec-in-shell 'red_hawk -h'"
		printf "$GREEN"  "[*] Success Installing RED_HAWK"
	else
		printf "$GREEN"  "[*] Success Installed RED_HAWK"
	fi

	# Install Ngrok
	if [ ! -f "/usr/bin/ngrok" ]; then
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/ngrok-v3-stable-linux-amd64.tgz
		tar -xvf /tmp/ngrok-v3-stable-linux-amd64.tgz -C /usr/bin;rm -f /tmp/ngrok-v3-stable-linux-amd64.tgz
		chmod +x /usr/bin/ngrok
		menu_entry "Penetration-Testing" "Web" "Ngrok" "/usr/share/kali-menu/exec-in-shell 'ngrok -h'"
		printf "$GREEN"  "[*] Success Installing Ngrok"
	else
		printf "$GREEN"  "[*] Success Installed Ngrok"
	fi

	# Install NoIP
	if [ ! -d "/usr/share/noip" ]; then
		wget wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/noip-duc-linux.tar.gz
		tar -xvf /tmp/noip-duc-linux.tar.gz -C /usr/share/noip;rm -f /tmp/noip-duc-linux.tar.gz
		chmod 755 /usr/share/noip/*;cd /usr/share/noip;make;make install
		menu_entry "Penetration-Testing" "Web" "NoIP" "/usr/share/kali-menu/exec-in-shell 'noip -h'"
		printf "$GREEN"  "[*] Success Installing NoIP"
	else
		printf "$GREEN"  "[*] Success Installed NoIP"
	fi

	# Install Breacher
	if [ ! -d "/usr/share/breacher" ]; then
		git clone https://github.com/s0md3v/Breacher /usr/share/breacher
		chmod 755 /usr/share/breacher/*
		cat > /usr/bin/breacher << EOF
#!/bin/bash
cd /usr/share/breacher;python3 breacher.py "\$@"
EOF
		chmod +x /usr/bin/breacher
		menu_entry "Penetration-Testing" "Web" "Breacher" "/usr/share/kali-menu/exec-in-shell 'breacher -h'"
		printf "$GREEN"  "[*] Success Installing Breacher"
	else
		printf "$GREEN"  "[*] Success Installed Breacher"
	fi

	# Install SWFTools
	if [ ! -d "/usr/share/swftools" ]; then
		git clone https://github.com/matthiaskramm/swftools /usr/share/swftools
		chmod 755 /usr/share/swftools/*
		wget https://zlib.net/current/zlib.tar.gz -O /tmp/zlib.tar.gz
		tar -xvf /tmp/zlib.tar.gz -C /usr/share/swftools;rm -f /tmp/zlib.tar.gz
		cd /usr/share/swftools/zlib-*;./configure
		cd /usr/share/swftools;./configure
		cd /usr/share/swftools/lib;make
		cd /usr/share/swftools/src;make;make install
		wget https://snapshot.debian.org/archive/debian/20130611T160143Z/pool/main/m/mtasc/mtasc_1.14-3_amd64.deb -O /tmp/mtasc_amd64.deb;chmod +x /tmp/mtasc_amd64.deb;dpkg -i /tmp/mtasc_amd64.deb;rm -f /tmp/mtasc_amd64.deb
		menu_entry "Penetration-Testing" "Web" "mtasc" "/usr/share/kali-menu/exec-in-shell 'mtasc -h'"
		menu_entry "Penetration-Testing" "Web" "swfdump" "/usr/share/kali-menu/exec-in-shell 'swfdump -h'"
		menu_entry "Penetration-Testing" "Web" "swfcombine" "/usr/share/kali-menu/exec-in-shell 'swfcombine -h'"
		printf "$GREEN"  "[*] Success Installing SWFTools"
	else
		printf "$GREEN"  "[*] Success Installed SWFTools"
	fi

	# Install NoSQLMap
	if [ ! -d "/usr/share/nosqlmap" ]; then
		git clone https://github.com/codingo/NoSQLMap /usr/share/nosqlmap
		chmod 755 /usr/share/nosqlmap/*
		cat > /usr/bin/nosqlmap << EOF
#!/bin/bash
cd /usr/share/nosqlmap;python2 nosqlmap.py "\$@"
EOF
		chmod +x /usr/bin/nosqlmap
		cd /usr/share/nosqlmap;python2 nosqlmap.py install
		menu_entry "Penetration-Testing" "Web" "NoSQLMap" "/usr/share/kali-menu/exec-in-shell 'nosqlmap -h'"
		printf "$GREEN"  "[*] Success Installing NoSQLMap"
	else
		printf "$GREEN"  "[*] Success Installed NoSQLMap"
	fi


	# --------------------------------------------Mobile-Penetration-Testing--------------------------------------------- #
	# Install Repository Tools
	apt install -qy jd-gui adb apksigner apktool android-tools-adb jadx 

	# Install Python3 pip
	pip3 install frida-tools objection mitmproxy reflutter androguard apkleaks mobsf mvt kiwi androset quark-engine 

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
		menu_entry "Penetration-Testing" "Mobile" "${mobile_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${mobile_go_index} -h'"
	done
	eval "$mobile_commands"

	# Install Genymotion
	if [ ! -d "/opt/genymobile/genymotion" ]; then
		wget https://dl.genymotion.com/releases/genymotion-3.6.0/genymotion-3.6.0-linux_x64.bin -O /tmp/genymotion.bin
		chmod 755 /tmp/genymotion.bin;cd /tmp;./genymotion.bin -y;rm -f /tmp/genymotion.bin
		printf "$GREEN"  "[*] Success Installing Genymotion"
	else
		printf "$GREEN"  "[*] Success Installed Genymotion"
	fi

	# Install MobSF
	if [ ! -d "/usr/share/MobSF" ]; then
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /usr/share/MobSF
		chmod 755 /usr/share/MobSF/*
		cat > /usr/bin/mobsf << EOF
#!/bin/bash
cd /usr/share/MobSF;./run.sh > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &
EOF
		chmod +x /usr/bin/mobsf
		cd /usr/share/MobSF;./setup.sh
		menu_entry "Penetration-Testing" "Mobile" "MobSF" "/usr/share/kali-menu/exec-in-shell 'mobsf'"
		printf "$GREEN"  "[*] Success Installing MobSF"
	else
		printf "$GREEN"  "[*] Success Installed MobSF"
	fi


	# --------------------------------------------Cloud-Penetration-Testing---------------------------------------------- #
	# Install Repository Tools
	apt install -qy awscli 

	# Install Python3 pip
	pip3 install sceptre aclpwn powerpwn ggshield pacu whispers s3scanner roadrecon roadlib gcp_scanner roadtx festin cloudsplaining c7n trailscraper lambdaguard airiam access-undenied-aws n0s1 aws-gate cloudscraper acltoolkit-ad prowler bloodhound aiodnsbrute gorilla-cli knowsmore checkov scoutsuite 

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
go install github.com/g0ldencybersec/CloudRecon@latest;ln -fs ~/go/bin/CloudRecon /usr/bin/cloudrecon
go install github.com/BishopFox/cloudfox@latest;ln -fs ~/go/bin/cloudfox /usr/bin/cloudfox
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
		menu_entry "Penetration-Testing" "Cloud" "${cloud_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${cloud_go_index} -h'"
	done
	eval "$cloud_commands"

	# Install CloudFail
	if [ ! -d "/usr/share/cloudfail" ]; then
		git clone https://github.com/m0rtem/CloudFail /usr/share/cloudfail
		chmod 755 /usr/share/cloudfail/*
		cat > /usr/bin/cloudfail << EOF
#!/bin/bash
cd /usr/share/cloudfail;python3 cloudfail.py "\$@"
EOF
		chmod +x /usr/bin/cloudfail
		pip3 install -r /usr/share/cloudfail/requirements.txt
		menu_entry "Penetration-Testing" "Cloud" "CloudFail" "/usr/share/kali-menu/exec-in-shell 'cloudfail -h'"
		printf "$GREEN"  "[*] Success Installing CloudFail"
	else
		printf "$GREEN"  "[*] Success Installed CloudFail"
	fi


	# -------------------------------------------Network-Penetration-Testing--------------------------------------------- #
	# Install Repository Tools
	apt install -qy cme amap bettercap dsniff arpwatch sslstrip sherlock parsero routersploit tcpxtract slowhttptest dnsmasq sshuttle haproxy smb4k pptpd xplico dosbox lldb zmap checksec kerberoast etherape ismtp ismtp privoxy ident-user-enum goldeneye oclgausscrack multiforcer crowbar brutespray isr-evilgrade smtp-user-enum proxychains pigz gdb isc-dhcp-server firewalk bing-ip2hosts sipvicious netstress tcptrack tnscmd10g darkstat naabu cyberchef nbtscan sslscan wireguard nasm ropper 

	# Install Python3 pip
	pip3 install networkx ropper mitmproxy mitm6 pymultitor scapy slowloris brute raccoon-scanner baboossh ciphey zeratool impacket aiodnsbrute ssh-mitm ivre angr angrop boofuzz ropgadget pwntools capstone atheris pyscan-rs 

	# Install Nodejs NPM
	npm install -g http-proxy-to-socks multitor 

	# Install Ruby GEM
	gem install seccomp-tools one_gadget 

	# Install Golang
	network_go_array=()
	network_commands=$(echo '
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
		menu_entry "Penetration-Testing" "Network" "${network_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${network_go_index} -h'"
	done
	eval "$network_commands"

	# Install Hiddify-Next
	if [ ! -d "/usr/share/hiddify-next" ]; then
		wget https://github.com/hiddify/hiddify-next/releases/latest/download/hiddify-debian-x64.zip -O /tmp/hiddify-debian-x64.zip
		unzip /tmp/hiddify-debian-x64.zip -d /tmp/hiddify-next;rm -f /tmp/hiddify-linux-x64.zip
		chmod 755 /tmp/hiddify-next/*
		dpkg -i /tmp/hiddify-next/hiddify-debian-x64.deb
		rm -rf /tmp/hiddify-next
		printf "$GREEN"  "[*] Success Installing Hiddify-Next"
	else
		printf "$GREEN"  "[*] Success Installed Hiddify-Next"
	fi

	# Install SNMP-Brute
	if [ ! -d "/usr/share/snmp-brute" ]; then
		git clone https://github.com/SECFORCE/SNMP-Brute /usr/share/snmp-brute
		chmod 755 /usr/share/snmp-brute/*
		cat > /usr/bin/snmpbrute << EOF
#!/bin/bash
cd /usr/share/snmp-brute;python3 snmpbrute.py "\$@"
EOF
		chmod +x /usr/bin/snmpbrute
		menu_entry "Penetration-Testing" "Network" "SNMP-Brute" "/usr/share/kali-menu/exec-in-shell 'snmpbrute -h'"
		printf "$GREEN"  "[*] Success Installing SNMP-Brute"
	else
		printf "$GREEN"  "[*] Success Installed SNMP-Brute"
	fi

	# Install RouterScan
	if [ ! -d "/usr/share/routerscan" ]; then
		mkdir -p /usr/share/routerscan
		wget http://msk1.stascorp.com/routerscan/prerelease.7z -O /usr/share/routerscan/prerelease.7z
		cd /usr/share/routerscan;7z x prerelease.7z;rm -f prerelease.7z
		chmod 755 /usr/share/routerscan/*
		cat > /usr/bin/routerscan << EOF
#!/bin/bash
cd /usr/share/routerscan;wine RouterScan.exe "\$@"
EOF
		chmod +x /usr/bin/routerscan
		menu_entry "Penetration-Testing" "Network" "RouterScan" "/usr/share/kali-menu/exec-in-shell 'routerscan'"
		printf "$GREEN"  "[*] Success Installing RouterScan"
	else
		printf "$GREEN"  "[*] Success Installed RouterScan"
	fi

	# Install PRET
	if [ ! -d "/usr/share/PRET" ]; then
		git clone https://github.com/RUB-NDS/PRET /usr/share/pret
		chmod 755 /usr/share/pret/*
		cat > /usr/bin/pret << EOF
#!/bin/bash
cd /usr/share/pret;python3 pret.py "\$@"
EOF
		chmod +x /usr/bin/pret
		menu_entry "Penetration-Testing" "Network" "PRET" "/usr/share/kali-menu/exec-in-shell 'pret -h'"
		printf "$GREEN"  "[*] Success Installing PRET"
	else
		printf "$GREEN"  "[*] Success Installed PRET"
	fi

	# Install GEF
	if [ ! -f "~/.gef-6a6e2a05ca8e08ac6845dce655a432fc4e029486.py" ]; then
		bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
		menu_entry "Penetration-Testing" "Network" "GEF" "/usr/share/kali-menu/exec-in-shell 'gef'"
		printf "$GREEN"  "[*] Success Installing GEF"
	else
		printf "$GREEN"  "[*] Success Installed GEF"
	fi

	# Install Angry-IP
	if [ ! -d "/usr/bin/ipscan" ]; then
		wget https://github.com/angryip/ipscan/releases/latest/download/ipscan_3.9.1_amd64.deb -O /tmp/ipscan_amd64.deb
		chmod +x /tmp/ipscan_amd64.deb;dpkg -i /tmp/ipscan_amd64.deb;rm -f /tmp/ipscan_amd64.deb
		printf "$GREEN"  "[*] Success Installing Angry-IP"
	else
		printf "$GREEN"  "[*] Success Installed Angry-IP"
	fi

	# Install fetch-some-proxies
	if [ ! -d "/usr/share/fetch-some-proxies" ]; then
		git clone https://github.com/stamparm/fetch-some-proxies /usr/share/fetch-some-proxies
		chmod 755 /usr/share/fetch-some-proxies/*
		cat > /usr/bin/fetch << EOF
#!/bin/bash
cd /usr/share/fetch-some-proxies;python3 fetch.py "\$@"
EOF
		chmod +x /usr/bin/fetch
		menu_entry "Penetration-Testing" "Network" "Fetch" "/usr/share/kali-menu/exec-in-shell 'fetch -h'"
		printf "$GREEN"  "[*] Success Installing fetch-some-proxies"
	else
		printf "$GREEN"  "[*] Success Installed fetch-some-proxies"
	fi

	# Install Memcrashed
	if [ ! -d "/usr/share/memcrashed" ]; then
		git clone https://github.com/649/Memcrashed-DDoS-Exploit /usr/share/memcrashed
		chmod 755 /usr/share/memcrashed/*
		cat > /usr/bin/memcrashed << EOF
#!/bin/bash
cd /usr/share/memcrashed;python3 Memcrashed.py "\$@"
EOF
		chmod +x /usr/bin/memcrashed
		pip3 install -r /usr/share/memcrashed/requirements.txt
		menu_entry "Penetration-Testing" "Network" "Memcrashed" "/usr/share/kali-menu/exec-in-shell 'memcrashed -h'"
		printf "$GREEN"  "[*] Success Installing Memcrashed"
	else
		printf "$GREEN"  "[*] Success Installed Memcrashed"
	fi


	# -------------------------------------------Wireless-Penetration-Testing-------------------------------------------- #
	# Install Repository Tools
	apt install -qy airgeddon crackle kalibrate-rtl eaphammer rtlsdr-scanner wifiphisher airgraph-ng multimon-ng gr-gsm ridenum airspy gqrx-sdr btscanner bluesnarfer ubertooth blueranger wifipumpkin3 spooftooph dronesploit pskracker 

	# Install Python3 pip
	pip3 install btlejack scapy wpspin 

	# Install Nodejs NPM
	npm install -g btlejuice 

	# Install Ruby GEM
	# gem install 

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
  		menu_entry "Penetration-Testing" "Wireless" "${wireless_go_array}" "/usr/share/kali-menu/exec-in-shell 'sudo ${wireless_go_array} -h'"
	done
	eval "$wireless_commands"

	# Install GTScan
	if [ ! -d "/usr/share/GTScan" ]; then
		git clone https://github.com/SigPloiter/GTScan /usr/share/gtscan
		chmod 755 /usr/share/gtscan/*
		cat > /usr/bin/gtscan << EOF
#!/bin/bash
cd /usr/share/gtscan;python3 gtscan.py "\$@"
EOF
		chmod +x /usr/bin/gtscan
		pip3 install -r /usr/share/gtscan/requirements.txt
		menu_entry "Penetration-Testing" "Wireless" "GTScan" "/usr/share/kali-menu/exec-in-shell 'gtscan -h'"
		printf "$GREEN"  "[*] Success Installing GTScan"
	else
		printf "$GREEN"  "[*] Success Installed GTScan"
	fi

	# Install HLR-Lookups
	if [ ! -d "/usr/share/hlr-lookups" ]; then
		git clone https://github.com/SigPloiter/HLR-Lookups /usr/share/hlr-lookups
		chmod 755 /usr/share/hlr-lookups/*
		cat > /usr/bin/hlrlookups << EOF
#!/bin/bash
cd /usr/share/hlr-lookups;python3 hlr-lookups.py "\$@"
EOF
		chmod +x /usr/bin/hlrlookups
		menu_entry "Penetration-Testing" "Wireless" "HLR-Lookups" "/usr/share/kali-menu/exec-in-shell 'hlrlookups -h'"
		printf "$GREEN"  "[*] Success Installing HLR-Lookups"
	else
		printf "$GREEN"  "[*] Success Installed HLR-Lookups"
	fi


	# ----------------------------------------------IoT-Penetration-Testing---------------------------------------------- #
	# Install Repository Tools
	apt install -qy arduino gnuradio 

	# Install Python3 pip
	pip3 install scapy uefi_firmware unblob 

	# Install Nodejs NPM
	# npm install -g 

	# Install Ruby GEM
	# gem install 

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
  		menu_entry "Penetration-Testing" "IoT" "${iot_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${iot_go_index} -h'"
	done
	eval "$iot_commands"
	logo
}


red_team ()
{
	# ----------------------------------------------Reconnaissance-Red-Team---------------------------------------------- #
	# Install Repository Tools
	apt install -qy emailharvester metagoofil amass osrframework gitleaks trufflehog maryam ismtp ident-user-enum eyewitness googler inspy smtp-user-enum goofile bing-ip2hosts webhttrack tnscmd10g getallurls feroxbuster subjack whatweb maltego-trx assetfinder aiodnsbrute instaloader harpoon 

	# Install Python3 pip
	pip3 install censys ggshield raccoon-scanner mailspoof h8mail twint thorndyke gitfive shodan postmaniac socialscan 

	# Install Nodejs NPM
	npm install -g igf nodesub multitor 

	# Install Ruby GEM
	# gem install

	# Install Golang
	reconnaissance_go_array=()
	reconnaissance_commands=$(echo '
go install github.com/x1sec/commit-stream@latest;ln -fs ~/go/bin/commit-stream /usr/bin/commit-stream
go install github.com/eth0izzle/shhgit@latest;ln -fs ~/go/bin/shhgit /usr/bin/shhgit
go install github.com/harleo/asnip@latest;ln -fs ~/go/bin/asnip /usr/bin/asnip
go install github.com/hakluke/haktrails@latest;ln -fs ~/go/bin/haktrails /usr/bin/haktrails
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		reconnaissance_commands+=("$binary_name")
		fi
	done <<< "$reconnaissance_commands"
	for reconnaissance_go_index in "${reconnaissance_go_array[@]}"; do
		menu_entry "Red-Team" "Reconnaissance" "${reconnaissance_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${reconnaissance_go_index} -h'"
	done
	eval "$reconnaissance_commands"

	# Install Dracnmap
	if [ ! -d "/usr/share/dracnmap" ]; then
		git clone https://github.com/Screetsec/Dracnmap /usr/share/dracnmap
		chmod 755 /usr/share/dracnmap/*
		cat > /usr/bin/dracnmap << EOF
#!/bin/bash
cd /usr/share/dracnmap;./Dracnmap.sh "\$@"
EOF
		chmod +x /usr/bin/dracnmap
		menu_entry "Red-Team" "Reconnaissance" "Dracnmap" "/usr/share/kali-menu/exec-in-shell 'dracnmap -h'"
		printf "$GREEN"  "[*] Success Installing Dracnmap"
	else
		printf "$GREEN"  "[*] Success Installed Dracnmap"
	fi


	# -------------------------------------------Resource-Development-Red-Team------------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	resource_development_go_array=()
	resource_development_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		resource_development_commands+=("$binary_name")
  		fi
	done <<< "$resource_development_commands"
	for resource_development_go_index in "${resource_development_go_array[@]}"; do
		menu_entry "Red-Team" "Resource-Development" "${resource_development_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${resource_development_go_index} -h'"
	done
	eval "$resource_development_commands"

  
	# ----------------------------------------------Initial-Access-Red-team---------------------------------------------- #
	# Install Repository Tools
	apt install -qy qrencode multiforcer crowbar brutespray arduino isr-evilgrade wifiphisher airgraph-ng 

	# Install Python3 pip
	pip3 install rarce baboossh dnstwist pasteme-cli 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	initial_access_go_array=()
	initial_access_commands=$(echo '
go install github.com/Tylous/ZipExec@latest;ln -fs ~/go/bin/ZipExec /usr/bin/ZipExec
go install github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest;ln -fs ~/go/bin/hednsextractor /usr/bin/hednsextractor
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		initial_access_commands+=("$binary_name")
  		fi
	done <<< "$initial_access_commands"
	for initial_access_go_index in "${initial_access_go_array[@]}"; do
		menu_entry "Red-Team" "Initial-Access" "${initial_access_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${initial_access_go_index} -h'"
	done
	eval "$initial_access_commands"

	# Install Evilginx
	if [ ! -d "/usr/share/evilginx" ]; then
		wget https://github.com/kgretzky/evilginx2/releases/download/2.4.0/evilginx-linux-amd64.tar.gz -O /tmp/evilginx-linux-amd64.tar.gz
		tar -xvf /tmp/evilginx-linux-amd64.tar.gz -C /usr/share/evilginx;rm -f /tmp/evilginx-linux-amd64.tar.gz
		chmod 755 /usr/share/evilginx/*
		ln -fs /usr/share/evilginx/evilginx /usr/bin/evilginx
		chmod +x /usr/bin/evilginx
		cd /usr/share/evilginx/evilginx;./install.sh
		menu_entry "Red-Team" "Initial-Access" "Evilginx" "/usr/share/kali-menu/exec-in-shell 'sudo evilginx -h'"
		printf "$GREEN"  "[*] Success Installing Evilginx"
	else
		printf "$GREEN"  "[*] Success Installed Evilginx"
	fi

	# Install SocialFish
	if [ ! -d "/usr/share/socialfish" ]; then
		git clone https://github.com/UndeadSec/SocialFish /usr/share/socialfish
		chmod 755 /usr/share/socialfish/*
		cat > /usr/bin/socialfish << EOF
#!/bin/bash
cd /usr/share/socialfish;python3 SocialFish.py "\$@"
EOF
		chmod +x /usr/bin/socialfish
		pip3 install -r /usr/share/socialfish/requirements.txt
		menu_entry "Red-Team" "Initial-Access" "SocialFish" "/usr/share/kali-menu/exec-in-shell 'socialfish -h'"
		printf "$GREEN"  "[*] Success Installing SocialFish"
	else
		printf "$GREEN"  "[*] Success Installed SocialFish"
	fi

	# Install EmbedInHTML
	if [ ! -d "/usr/share/embedinhtml" ]; then
		git clone https://github.com/Arno0x/EmbedInHTML /usr/share/embedinhtml
		chmod 755 /usr/share/embedinhtml/*
		cat > /usr/bin/embedinhtml << EOF
#!/bin/bash
cd /usr/share/embedinhtml;python2 embedInHTML.py "\$@"
EOF
		chmod +x /usr/bin/embedinhtml
		menu_entry "Red-Team" "Initial-Access" "EmbedInHTML" "/usr/share/kali-menu/exec-in-shell 'embedinhtml -h'"
		printf "$GREEN"  "[*] Success Installing EmbedInHTML"
	else
		printf "$GREEN"  "[*] Success Installed EmbedInHTML"
	fi

	# Install EvilURL
	if [ ! -d "/usr/share/evilurl" ]; then
		git clone https://github.com/UndeadSec/EvilURL /usr/share/evilurl
		chmod 755 /usr/share/evilurl/*
		cat > /usr/bin/evilurl << EOF
#!/bin/bash
cd /usr/share/evilurl;python3 evilurl.py "\$@"
EOF
		chmod +x /usr/bin/evilurl
		menu_entry "Red-Team" "Initial-Access" "EvilURL" "/usr/share/kali-menu/exec-in-shell 'evilurl -h'"
		printf "$GREEN"  "[*] Success Installing EvilURL"
	else
		printf "$GREEN"  "[*] Success Installed EvilURL"
	fi

	# Install Debinject
	if [ ! -d "/usr/share/debinject" ]; then
		git clone https://github.com/UndeadSec/Debinject /usr/share/debinject
		chmod 755 /usr/share/debinject/*
		cat > /usr/bin/debinject << EOF
#!/bin/bash
cd /usr/share/debinject;python2 debinject.py "\$@"
EOF
		chmod +x /usr/bin/debinject
		menu_entry "Red-Team" "Initial-Access" "Debinject" "/usr/share/kali-menu/exec-in-shell 'debinject -h'"
		printf "$GREEN"  "[*] Success Installing Debinject"
	else
		printf "$GREEN"  "[*] Success Installed Debinject"
	fi

	# Install Brutal
	if [ ! -d "/usr/share/brutal" ]; then
		git clone https://github.com/Screetsec/Brutal /usr/share/brutal
		chmod 755 /usr/share/brutal/*
		cat > /usr/bin/brutal << EOF
#!/bin/bash
cd /usr/share/brutal;./Brutal.sh "\$@"
EOF
		chmod +x /usr/bin/brutal
		pip3 install -r /usr/share/brutal/requirements.txt
		menu_entry "Red-Team" "Initial-Access" "Brutal" "/usr/share/kali-menu/exec-in-shell 'sudo brutal -h'"
		printf "$GREEN"  "[*] Success Installing Brutal"
	else
		printf "$GREEN"  "[*] Success Installed Brutal"
	fi

	# Install Demiguise
	if [ ! -d "/usr/share/demiguise" ]; then
		git clone https://github.com/nccgroup/demiguise /usr/share/demiguise
		chmod 755 /usr/share/demiguise/*
		cat > /usr/bin/demiguise << EOF
#!/bin/bash
cd /usr/share/demiguise;python3 demiguise.py "\$@"
EOF
		chmod +x /usr/bin/demiguise
		menu_entry "Red-Team" "Initial-Access" "Demiguise" "/usr/share/kali-menu/exec-in-shell 'demiguise'"
		printf "$GREEN"  "[*] Success Installing Demiguise"
	else
		printf "$GREEN"  "[*] Success Installed Demiguise"
	fi

	# Install Dr0p1t
	if [ ! -d "/usr/share/dr0p1t" ]; then
		git clone https://github.com/D4Vinci/Dr0p1t-Framework /usr/share/dr0p1t
		chmod 755 /usr/share/dr0p1t/*
		cd /usr/share/dr0p1t;./install.sh
		cat > /usr/bin/dr0p1t << EOF
#!/bin/bash
cd /usr/share/dr0p1t;python3 Dr0p1t.py "\$@"
EOF
		chmod +x /usr/bin/dr0p1t
		menu_entry "Red-Team" "Initial-Access" "Dr0p1t" "/usr/share/kali-menu/exec-in-shell 'dr0p1t -h'"
		printf "$GREEN"  "[*] Success Installing Dr0p1t"
	else
		printf "$GREEN"  "[*] Success Installed Dr0p1t"
	fi


	# -------------------------------------------------Execution-Red-Team------------------------------------------------ #
	# Install Repository Tools
	apt install -qy shellnoob

	# Install Python3 pip
	pip3 install donut-shellcode xortool pwncat 

	# Install Nodejs NPM
	# npm install -g 

	# Install Ruby GEM
	# gem install 

	# Install Golang
	execution_go_array=()
	execution_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		execution_commands+=("$binary_name")
  		fi
	done <<< "$execution_commands"
	for execution_go_index in "${execution_go_array[@]}"; do
		menu_entry "Red-Team" "Execution" "${execution_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${execution_go_index} -h'"
	done
	eval "$execution_commands"

	# Install Venom
	if [ ! -d "/usr/share/venom" ]; then
		git clone https://github.com/r00t-3xp10it/venom /usr/share/venom
		chmod 755 /usr/share/venom/*
		cat > /usr/bin/venom << EOF
#!/bin/bash
cd /usr/share/venom;./venom.sh "\$@"
EOF
		chmod +x /usr/bin/venom
		menu_entry "Red-Team" "Execution" "Venom" "/usr/share/kali-menu/exec-in-shell 'sudo venom -h'"
		printf "$GREEN"  "[*] Success Installing Venom"
	else
		printf "$GREEN"  "[*] Success Installed Venom"
	fi

	# Install PowerLessShell
	if [ ! -d "/usr/share/powerlessshell" ]; then
		git clone https://github.com/Mr-Un1k0d3r/PowerLessShell /usr/share/powerlessshell
		chmod 755 /usr/share/powerlessshell/*
		cat > /usr/bin/powerlessshell << EOF
#!/bin/bash
cd /usr/share/powerlessshell;python2 PowerLessShell.py "\$@"
EOF
		chmod +x /usr/bin/powerlessshell
		menu_entry "Red-Team" "Execution" "PowerLessShell" "/usr/share/kali-menu/exec-in-shell 'powerlessshell -h'"
		printf "$GREEN"  "[*] Success Installing PowerLessShell"
	else
		printf "$GREEN"  "[*] Success Installed PowerLessShell"
	fi

	# Install SharpShooter
	if [ ! -d "/usr/share/sharpshooter" ]; then
		git clone https://github.com/mdsecactivebreach/SharpShooter /usr/share/sharpshooter
		chmod 755 /usr/share/sharpshooter/*
		cat > /usr/bin/sharpshooter << EOF
#!/bin/bash
cd /usr/share/sharpshooter;python2 SharpShooter.py "\$@"
EOF
		chmod +x /usr/bin/sharpshooter
		pip3 install -r /usr/share/sharpshooter/requirements.txt
		menu_entry "Red-Team" "Execution" "SharpShooter" "/usr/share/kali-menu/exec-in-shell 'sharpshooter -h'"
		printf "$GREEN"  "[*] Success Installing SharpShooter"
	else
		printf "$GREEN"  "[*] Success Installed SharpShooter"
	fi

	# Install Donut
	if [ ! -d "/usr/share/donut" ]; then
		mkdir -p /usr/share/donut
		wget https://github.com/TheWover/donut/releases/download/v1.0/donut_v1.0.tar.gz -O /tmp/donut_v1.0.tar.gz
		tar -xvf /tmp/donut_v1.0.tar.gz -C /usr/share/donut;rm -f /tmp/donut_v1.0.tar.gz
		chmod 755 /usr/share/donut/*
		ln -fs /usr/share/donut/donut /usr/bin/donut
		chmod +x /usr/bin/donut
		menu_entry "Red-Team" "Execution" "Donut" "/usr/share/kali-menu/exec-in-shell 'donut -h'"
		printf "$GREEN"  "[*] Success Installing Donut"
	else
		printf "$GREEN"  "[*] Success Installed Donut"
	fi


	# ------------------------------------------------Persistence-Red-Team----------------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install hiphp 

	# Install Nodejs NPM
	# npm install -g 

	# Install Ruby GEM
	# gem install 

	# Install Golang
	persistence_go_array=()
	persistence_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		persistence_commands+=("$binary_name")
  		fi
	done <<< "$persistence_commands"
	for persistence_go_index in "${persistence_go_array[@]}"; do
		menu_entry "Red-Team" "Persistence" "${persistence_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${persistence_go_index} -h'"
	done
	eval "$persistence_commands"

	# Install Vegile
	if [ ! -d "/usr/share/vegile" ]; then
		git clone https://github.com/Screetsec/Vegile /usr/share/vegile
		chmod 755 /usr/share/vegile/*
		ln -fs /usr/share/vegile/Vegile /usr/bin/vegile
		chmod +x /usr/bin/vegile
		menu_entry "Red-Team" "Persistence" "Vegile" "/usr/share/kali-menu/exec-in-shell 'sudo vegile -h'"
		printf "$GREEN"  "[*] Success Installing Vegile"
	else
		printf "$GREEN"  "[*] Success Installed Vegile"
	fi


	# -------------------------------------------Privilege-Escalation-Red-Team------------------------------------------- #
	# Install Repository Tools
	apt install -qy linux-exploit-suggester peass oscanner 

	# Install Python3 pip
	pip3 install bloodyAD cve-bin-tool 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	privilege_escalation_go_array=()
	privilege_escalation_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		privilege_escalation_commands+=("$binary_name")
		fi
	done <<< "$privilege_escalation_commands"
	for privilege_escalation_go_index in "${privilege_escalation_go_array[@]}"; do
		menu_entry "Red-Team" "Privilege-Escalation" "${privilege_escalation_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${privilege_escalation_go_index} -h'"
	done
	eval "$privilege_escalation_commands"

	# Install MimiPenguin
	if [ ! -d "/usr/share/mimipenguin" ]; then
		git clone https://github.com/huntergregal/mimipenguin /usr/share/mimipenguin
		chmod 755 /usr/share/mimipenguin/*
		cat > /usr/bin/mimipenguin << EOF
#!/bin/bash
cd /usr/share/mimipenguin;python3 mimipenguin.py "\$@"
EOF
		chmod +x /usr/bin/mimipenguin
		menu_entry "Red-Team" "Privilege-Escalation" "MimiPenguin" "/usr/share/kali-menu/exec-in-shell 'mimipenguin -h'"
		printf "$GREEN"  "[*] Success Installing MimiPenguin"
	else
		printf "$GREEN"  "[*] Success Installed MimiPenguin"
	fi

	# Install spectre-meltdown-checker
	if [ ! -d "/usr/share/spectre-meltdown-checker" ]; then
		mkdir -p /usr/share/spectre-meltdown-checker
		wget https://meltdown.ovh -O /usr/share/spectre-meltdown-checker/spectre-meltdown-checker.sh
		chmod 755 /usr/share/spectre-meltdown-checker/*
		cat > /usr/bin/spectre-checker << EOF
#!/bin/bash
cd /usr/share/spectre-meltdown-checker;bash spectre-meltdown-checker.sh "\$@"
EOF
		chmod +x /usr/bin/spectre-checker
		menu_entry "Red-Team" "Privilege-Escalation" "spectre-meltdown-checker" "/usr/share/kali-menu/exec-in-shell 'spectre-checker -h'"
		printf "$GREEN"  "[*] Success Installing spectre-meltdown-checker"
	else
		printf "$GREEN"  "[*] Success Installed spectre-meltdown-checker"
	fi


	# ---------------------------------------------Defense-Evasion-Red-Team---------------------------------------------- #
	# Install Repository Tools
	apt install -qy shellter unicorn veil veil-catapult veil-evasion osslsigncode 

	# Install Python3 pip
	pip3 install auto-py-to-exe certipy sysplant pinject 

	# Install Nodejs NPM
	npm install -g uglify-js javascript-obfuscator serialize-javascript serialize-to-js jsdom 

	# Install Ruby GEM
	gem install 

	# Install Golang
	defense_evasion_go_array=()
	defense_evasion_commands=$(echo '
go install github.com/optiv/ScareCrow@latest;ln -fs ~/go/bin/ScareCrow /usr/bin/scarecrow
go install github.com/EgeBalci/amber@latest;ln -fs ~/go/bin/amber /usr/bin/amber
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		defense_evasion_commands+=("$binary_name")
  		fi
	done <<< "$defense_evasion_commands"
	for defense_evasion_go_index in "${defense_evasion_go_array[@]}"; do
		menu_entry "Red-Team" "Defense-Evasion" "${defense_evasion_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${defense_evasion_go_index} -h'"
	done
	eval "$defense_evasion_commands"

	# Install ASWCrypter
	if [ ! -d "/usr/share/aswcrypter" ]; then
		git clone https://github.com/AbedAlqaderSwedan1/ASWCrypter /usr/share/aswcrypter
		chmod 755 /usr/share/aswcrypter/*
		bash /usr/share/aswcrypter/setup.sh
		cat > /usr/bin/aswcrypter << EOF
#!/bin/bash
cd /usr/share/aswcrypter;bash ASWCrypter.sh "\$@"
EOF
		chmod +x /usr/bin/aswcrypter
		menu_entry "Red-Team" "Defense-Evasion" "ASWCrypter" "/usr/share/kali-menu/exec-in-shell 'aswcrypter -h'"
		printf "$GREEN"  "[*] Success Installing ASWCrypter"
	else
		printf "$GREEN"  "[*] Success Installed ASWCrypter"
	fi

	# Install AVET
	if [ ! -d "/usr/share/avet" ]; then
		git clone https://github.com/govolution/avet /usr/share/avet
		chmod 755 /usr/share/avet/*
		bash /usr/share/avet/setup.sh
		cat > /usr/bin/avet << EOF
#!/bin/bash
cd /usr/share/avet;python3 avet.py "\$@"
EOF
		chmod +x /usr/bin/avet
		menu_entry "Red-Team" "Defense-Evasion" "AVET" "/usr/share/kali-menu/exec-in-shell 'avet'"
		printf "$GREEN"  "[*] Success Installing AVET"
	else
		printf "$GREEN"  "[*] Success Installed AVET"
	fi

	# Install Unicorn
	if [ ! -d "/usr/share/unicorn" ]; then
		git clone https://github.com/trustedsec/unicorn /usr/share/unicorn
		chmod 755 /usr/share/unicorn/*
		cat > /usr/bin/unicorn << EOF
#!/bin/bash
cd /usr/share/unicorn;python3 unicorn.py "\$@"
EOF
		chmod +x /usr/bin/unicorn
		menu_entry "Red-Team" "Defense-Evasion" "Unicorn" "/usr/share/kali-menu/exec-in-shell 'unicorn -h'"
		printf "$GREEN"  "[*] Success Installing Unicorn"
	else
		printf "$GREEN"  "[*] Success Installed Unicorn"
	fi

	# Install SysWhispers3
	if [ ! -d "/usr/share/syswhispers3" ]; then
		git clone https://github.com/klezVirus/SysWhispers3 /usr/share/syswhispers3
		chmod 755 /usr/share/syswhispers3/*
		cat > /usr/bin/syswhispers3 << EOF
#!/bin/bash
cd /usr/share/syswhispers3;python3 syswhispers.py "\$@"
EOF
		chmod +x /usr/bin/syswhispers3
		menu_entry "Red-Team" "Defense-Evasion" "SysWhispers3" "/usr/share/kali-menu/exec-in-shell 'syswhispers3 -h'"
		printf "$GREEN"  "[*] Success Installing SysWhispers3"
	else
		printf "$GREEN"  "[*] Success Installed SysWhispers3"
	fi

	# Install SysWhispers
	if [ ! -d "/usr/share/syswhispers" ]; then
		git clone https://github.com/jthuraisamy/SysWhispers /usr/share/syswhispers
		chmod 755 /usr/share/syswhispers/*
		cat > /usr/bin/syswhispers << EOF
#!/bin/bash
cd /usr/share/syswhispers;python3 syswhispers.py "\$@"
EOF
		chmod +x /usr/bin/syswhispers
		pip3 install -r /usr/share/syswhispers/requirements.txt
		menu_entry "Red-Team" "Defense-Evasion" "SysWhispers" "/usr/share/kali-menu/exec-in-shell 'syswhispers -h'"
		printf "$GREEN"  "[*] Success Installing SysWhispers"
	else
		printf "$GREEN"  "[*] Success Installed SysWhispers"
	fi

	# Install Invoke-DOSfuscation
	if [ ! -d "/usr/share/invoke-dosfuscation" ]; then
		git clone https://github.com/danielbohannon/Invoke-DOSfuscation /usr/share/invoke-dosfuscation
		chmod 755 /usr/share/invoke-dosfuscation/*
		cat > /usr/bin/invoke-dosfuscation << EOF
#!/bin/bash
cd /usr/share/invoke-dosfuscation;pwsh -c "Import-Module ./Invoke-DOSfuscation.psd1; Invoke-DOSfuscation" "\$@"
EOF
		chmod +x /usr/bin/invoke-dosfuscation
		menu_entry "Red-Team" "Defense-Evasion" "Invoke-DOSfuscation" "/usr/share/kali-menu/exec-in-shell 'invoke-dosfuscation'"
		printf "$GREEN"  "[*] Success Installing Invoke-DOSfuscation"
	else
		printf "$GREEN"  "[*] Success Installed Invoke-DOSfuscation"
	fi

	# Install ObfuscateCactusTorch
	if [ ! -d "/usr/share/obfuscatecactustorch" ]; then
		git clone https://github.com/Arno0x/ObfuscateCactusTorch /usr/share/obfuscatecactustorch
		chmod 755 /usr/share/obfuscatecactustorch/*
		cat > /usr/bin/obfuscatecactustorch << EOF
#!/bin/bash
cd /usr/share/obfuscatecactustorch;python2 obfuscateCactusTorch.py "\$@"
EOF
		chmod +x /usr/bin/obfuscatecactustorch
		menu_entry "Red-Team" "Defense-Evasion" "ObfuscateCactusTorch" "/usr/share/kali-menu/exec-in-shell 'obfuscatecactustorch'"
		printf "$GREEN"  "[*] Success Installing ObfuscateCactusTorch"
	else
		printf "$GREEN"  "[*] Success Installed ObfuscateCactusTorch"
	fi

	# Install Phantom-Evasion
	if [ ! -d "/usr/share/phantom-evasion" ]; then
		git clone https://github.com/oddcod3/Phantom-Evasion /usr/share/phantom-evasion
		chmod 755 /usr/share/phantom-evasion/*
		cat > /usr/bin/phantom << EOF
#!/bin/bash
cd /usr/share/phantom-evasion;python3 phantom-evasion.py "\$@"
EOF
		chmod +x /usr/bin/phantom
		menu_entry "Red-Team" "Defense-Evasion" "Phantom-Evasion" "/usr/share/kali-menu/exec-in-shell 'phantom -h'"
		printf "$GREEN"  "[*] Success Installing Phantom-Evasion"
	else
		printf "$GREEN"  "[*] Success Installed Phantom-Evasion"
	fi

	# Install SpookFlare
	if [ ! -d "/usr/share/spookflare" ]; then
		git clone https://github.com/hlldz/SpookFlare /usr/share/spookflare
		chmod 755 /usr/share/spookflare/*
		cat > /usr/bin/spookflare << EOF
#!/bin/bash
cd /usr/share/spookflare;python2 spookflare.py "\$@"
EOF
		chmod +x /usr/bin/spookflare
		pip2 install -r /usr/share/spookflare/requirements.txt
		menu_entry "Red-Team" "Defense-Evasion" "SpookFlare" "/usr/share/kali-menu/exec-in-shell 'spookflare -h'"
		printf "$GREEN"  "[*] Success Installing SpookFlare"
	else
		printf "$GREEN"  "[*] Success Installed SpookFlare"
	fi

	# Install Invoke-Obfuscation
	if [ ! -d "/usr/share/invoke-obfuscation" ]; then
		git clone https://github.com/danielbohannon/Invoke-Obfuscation /usr/share/invoke-obfuscation
		chmod 755 /usr/share/invoke-obfuscation/*
		cat > /usr/bin/invoke-obfuscation << EOF
#!/bin/bash
cd /usr/share/invoke-obfuscation;pwsh -c "Import-Module ./Invoke-Obfuscation.psd1; Invoke-Obfuscation" "\$@"
EOF
		chmod +x /usr/bin/invoke-obfuscation
		menu_entry "Red-Team" "Defense-Evasion" "Invoke-Obfuscation" "/usr/share/kali-menu/exec-in-shell 'invoke-obfuscation'"
		printf "$GREEN"  "[*] Success Installing Invoke-Obfuscation"
	else
		printf "$GREEN"  "[*] Success Installed Invoke-Obfuscation"
	fi

	# Install Invoke-CradleCrafter
	if [ ! -d "/usr/share/invoke-cradlecrafter" ]; then
		git clone https://github.com/danielbohannon/Invoke-CradleCrafter /usr/share/invoke-cradlecrafter
		chmod 755 /usr/share/invoke-cradlecrafter/*
		cat > /usr/bin/invoke-cradlecrafter << EOF
#!/bin/bash
cd /usr/share/invoke-cradlecrafter;pwsh -c "Import-Module ./Invoke-CradleCrafter.psd1; Invoke-CradleCrafter" "\$@"
EOF
		chmod +x /usr/bin/invoke-cradlecrafter
		menu_entry "Red-Team" "Defense-Evasion" "Invoke-CradleCrafter" "/usr/share/kali-menu/exec-in-shell 'invoke-cradlecrafter'"
		printf "$GREEN"  "[*] Success Installing Invoke-CradleCrafter"
	else
		printf "$GREEN"  "[*] Success Installed Invoke-CradleCrafter"
	fi


	# --------------------------------------------Credential-Access-Red-Team--------------------------------------------- #
	# Install Repository Tools
	apt install -qy pdfcrack fcrackzip rarcrack 

	# Install Python3 pip
	pip3 install adidnsdump detect-secrets impacket cloudscraper knowsmore ssh-mitm 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	credential_access_go_array=()
	credential_access_commands=$(echo '
go install github.com/ropnop/kerbrute@latest;ln -fs ~/go/bin/kerbrute /usr/bin/kerbrute
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		credential_access_commands+=("$binary_name")
		fi
	done <<< "$credential_access_commands"
	for credential_access_go_index in "${credential_access_go_array[@]}"; do
		menu_entry "Red-Team" "Credential-Access" "${credential_access_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${credential_access_go_index} -h'"
	done
	eval "$credential_access_commands"

	# Install Kerberoast
	if [ ! -d "/usr/share/kerberoast" ]; then
		git clone https://github.com/nidem/kerberoast /usr/share/kerberoast
		chmod 755 /usr/share/kerberoast/*
		cat > /usr/bin/kerberoast << EOF
#!/bin/bash
cd /usr/share/Kerberoast;python3 kerberoast.py "\$@"
EOF
		chmod +x /usr/bin/kerberoast
		menu_entry "Red-Team" "Credential-Access" "Kerberoast" "/usr/share/kali-menu/exec-in-shell 'kerberoast -h'"
		printf "$GREEN"  "[*] Success Installing Kerberoast"
	else
		printf "$GREEN"  "[*] Success Installed Kerberoast"
	fi

	# Install NtlmRelayToEWS
	if [ ! -d "/usr/share/ntlmRelaytoews" ]; then
		git clone https://github.com/Arno0x/NtlmRelayToEWS /usr/share/ntlmRelaytoews
		chmod 755 /usr/share/ntlmRelaytoews/*
		cat > /usr/bin/ntlmRelaytoews << EOF
#!/bin/bash
cd /usr/share/ntlmRelaytoews;python2 ntlmRelayToEWS.py "\$@"
EOF
		chmod +x /usr/bin/ntlmRelaytoews
		menu_entry "Red-Team" "Credential-Access" "NtlmRelayToEWS" "/usr/share/kali-menu/exec-in-shell 'ntlmRelaytoews -h'"
		printf "$GREEN"  "[*] Success Installing NtlmRelayToEWS"
	else
		printf "$GREEN"  "[*] Success Installed NtlmRelayToEWS"
	fi

	# Install NetRipper
	if [ ! -d "/usr/share/metasploit-framework/modules/post/windows/gather/netripper" ]; then
		mkdir -p /usr/share/metasploit-framework/modules/post/windows/gather/netripper
		wget https://github.com/NytroRST/NetRipper/blob/master/Metasploit/netripper.rb -O /usr/share/metasploit-framework/modules/post/windows/gather/netripper/netripper.rb
		wget https://github.com/NytroRST/NetRipper/blob/master/x64/DLL.x64.dll -O /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.x64.dll
		wget https://github.com/NytroRST/NetRipper/blob/master/x86/DLL.x86.dll -O /usr/share/metasploit-framework/modules/post/windows/gather/netripper/DLL.x86.dll
		wget https://github.com/NytroRST/NetRipper/blob/master/x64/NetRipper.x64.exe -O /usr/share/metasploit-framework/modules/post/windows/gather/netripper/NetRipper.x64.exe
		wget https://github.com/NytroRST/NetRipper/blob/master/x86/NetRipper.x86.exe -O /usr/share/metasploit-framework/modules/post/windows/gather/netripper/NetRipper.x86.exe
		chmod 755 /usr/share/metasploit-framework/modules/post/windows/gather/netripper/*
		cat > /usr/bin/netripper << EOF
#!/bin/bash
cd /usr/share/metasploit-framework/modules/post/windows/gather/netripper;wine NetRipper.x64.exe "\$@"
EOF
		chmod +x /usr/bin/netripper
		menu_entry "Red-Team" "Credential-Access" "NetRipper" "/usr/share/kali-menu/exec-in-shell 'netripper'"
		printf "$GREEN"  "[*] Success Installing NetRipper"
	else
		printf "$GREEN"  "[*] Success Installed NetRipper"
	fi


	# -------------------------------------------------Discovery-Red-Team------------------------------------------------ #
	# Install Repository Tools
	apt install -qy bloodhound 

	# Install Python3 pip
	pip3 install networkx bloodhound acltoolkit-ad 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	discovery_go_array=()
	discovery_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		discovery_commands+=("$binary_name")
		fi
	done <<< "$discovery_commands"
	for discovery_go_index in "${discovery_go_array[@]}"; do
		menu_entry "Red-Team" "Discovery" "${discovery_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${discovery_go_index} -h'"
	done
	eval "$discovery_commands"

	# Install AdExplorer
	if [ ! -d "/usr/share/adexplorer" ]; then
		mkdir -p /usr/share/adexplorer
		wget https://download.sysinternals.com/files/AdExplorer.zip -O /tmp/AdExplorer.zip
		unzip /tmp/AdExplorer.zip -d /usr/share/adexplorer;rm -f /tmp/AdExplorer.zip
		chmod 755 /usr/share/adexplorer/*
		cat > /usr/bin/adexplorer << EOF
#!/bin/bash
cd /usr/share/adexplorer;wine ADExplorer.exe "\$@"
EOF
		chmod +x /usr/bin/adexplorer
		menu_entry "Red-Team" "Discovery" "AdExplorer" "/usr/share/kali-menu/exec-in-shell 'adexplorer'"
		printf "$GREEN"  "[*] Success Installing AdExplorer"
	else
		printf "$GREEN"  "[*] Success Installed AdExplorer"
	fi


	# ---------------------------------------------Lateral-Movement-Red-Team--------------------------------------------- #
	# Install Repository Tools
	apt install -qy pptpd kerberoast isr-evilgrade proxychains 

	# Install Python3 pip
	pip3 install coercer krbjack 

	# Install Nodejs NPM
	npm install -g 
  
	# Install Ruby GEM
	gem install evil-winrm 
  
	# Install Golang
	lateral_movement_go_array=()
	lateral_movement_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		lateral_movement_commands+=("$binary_name")
  		fi
	done <<< "$lateral_movement_commands"
	for lateral_movement_go_index in "${lateral_movement_go_array[@]}"; do
		menu_entry "Red-Team" "Lateral-Movement" "${lateral_movement_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${lateral_movement_go_index} -h'"
	done
	eval "$lateral_movement_commands"


	# ------------------------------------------------Collection-Red-Team------------------------------------------------ #
	# Install Repository Tools
	apt install -qy tigervnc-viewer 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	collection_go_array=()
	collection_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		collection_commands+=("$binary_name")
  		fi
	done <<< "$collection_commands"
	for collection_go_index in "${collection_go_array[@]}"; do
		menu_entry "Red-Team" "Collection" "${collection_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${collection_go_index} -h'"
	done
	eval "$collection_commands"


	# --------------------------------------------Command-and-Control-Red-Team------------------------------------------- #
	# Install Repository Tools
	apt install -qy powershell-empire koadic chisel poshc2 ibombshell silenttrinity merlin 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 
  
	# Install Ruby GEM
	gem install 

	# Install Golang
	cnc_go_array=()
	cnc_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		cnc_commands+=("$binary_name")
  		fi
	done <<< "$cnc_commands"
	for cnc_go_index in "${cnc_go_array[@]}"; do
		menu_entry "Red-Team" "Command-and-Control" "${cnc_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${cnc_go_index} -h'"
	done
	eval "$cnc_commands"

	# Install PhoenixC2
	if [ ! -d "/usr/share/phoenixc2" ]; then
		git clone https://github.com/screamz2k/PhoenixC2 /usr/share/phoenixc2
		chmod 755 /usr/share/phoenixc2/*
		cat > /usr/bin/phoenix << EOF
#!/bin/bash
cd /usr/share/phoenixc2;poetry run phserver "\$@"
EOF
		chmod +x /usr/bin/phoenix
		cd /usr/share/phoenixc2;pip3 install poetry;poetry install
		menu_entry "Red-Team" "Command-and-Control" "PhoenixC2" "/usr/share/kali-menu/exec-in-shell 'phoenix -h'"
		printf "$GREEN"  "[*] Success Installing PhoenixC2"
	else
		printf "$GREEN"  "[*] Success Installed PhoenixC2"
	fi

	# Install Silver
	if [ ! -d "/usr/share/sliver" ]; then
		mkdir -p /usr/share/sliver
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -O /usr/share/sliver/sliver_client
		chmod 755 /usr/share/sliver/*
		ln -fs /usr/share/sliver/sliver_client /usr/bin/sliverc
		chmod +x /usr/bin/sliverc
		menu_entry "Red-Team" "Command-and-Control" "SilverC" "/usr/share/kali-menu/exec-in-shell 'sudo sliverc -h'"
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/share/sliver/sliver_server
		chmod 755 /usr/share/sliver/*
		ln -fs /usr/share/sliver/sliver_server /usr/bin/slivers
		chmod +x /usr/bin/slivers
		menu_entry "Red-Team" "Command-and-Control" "SilverS" "/usr/share/kali-menu/exec-in-shell 'sudo slivers -h'"
		printf "$GREEN"  "[*] Success Installing Silver"
	else
		printf "$GREEN"  "[*] Success Installed Silver"
	fi

	# Install Havoc
	if [ ! -d "/usr/share/havoc" ]; then
		git clone https://github.com/HavocFramework/Havoc /usr/share/havoc
		chmod 755 /usr/share/Havoc/*
		go mod download golang.org/x/sys;go mod download github.com/ugorji/go
		cd /user/share/Havoc/Client;make
		ln -fs /user/share/Havoc/Client/Havoc /usr/bin/havoc
		chmod +x /usr/bin/havoc
		menu_entry "Red-Team" "Command-and-Control" "Havoc" "/usr/share/kali-menu/exec-in-shell 'sudo havoc -h'"
		cd /user/share/Havoc/Teamserver;./Install.sh;make
		ln -fs /user/share/Havoc/Teamserver/teamserver /usr/bin/havocts
		chmod +x /usr/bin/havocts
		menu_entry "Red-Team" "Command-and-Control" "HavocTS" "/usr/share/kali-menu/exec-in-shell 'sudo havocts -h'"
		printf "$GREEN"  "[*] Success Installing Havoc"
	else
		printf "$GREEN"  "[*] Success Installed Havoc"
	fi


	# -----------------------------------------------Exfiltration-Red-Team----------------------------------------------- #
	# Install Repository Tools
	apt install -qy haproxy xplico certbot stunnel4 httptunnel onionshare proxychains proxify privoxy 

	# Install Python3 pip
	pip3 install updog pivotnacci 

	# Install Nodejs NPM
	npm install -g http-proxy-to-socks 

	# Install Ruby GEM
	gem install 

	# Install Golang
	exfiltration_go_array=()
	exfiltration_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		exfiltration_commands+=("$binary_name")
  		fi
	done <<< "$exfiltration_commands"
	for exfiltration_go_index in "${exfiltration_go_array[@]}"; do
		menu_entry "Red-Team" "Exfiltration" "${exfiltration_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${exfiltration_go_index} -h'"
	done
	eval "$exfiltration_commands"

	# Install Ngrok
	if [ ! -f "/usr/bin/ngrok" ]; then
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/ngrok-v3-stable-linux-amd64.tgz
		tar -xvf /tmp/ngrok-v3-stable-linux-amd64.tgz -C /usr/bin;rm -f /tmp/ngrok-v3-stable-linux-amd64.tgz
		chmod +x /usr/bin/ngrok
		menu_entry "Red-Team" "Exfiltration" "Ngrok" "/usr/share/kali-menu/exec-in-shell 'ngrok -h'"
		printf "$GREEN"  "[*] Success Installing Ngrok"
	else
		printf "$GREEN"  "[*] Success Installed Ngrok"
	fi

	# Install NoIP
	if [ ! -d "/usr/share/noip" ]; then
		wget wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/noip-duc-linux.tar.gz
		tar -xvf /tmp/noip-duc-linux.tar.gz -C /usr/share/noip;rm -f /tmp/noip-duc-linux.tar.gz
		chmod 755 /usr/share/noip/*;cd /usr/share/noip;make;make install
		menu_entry "Red-Team" "Exfiltration" "NoIP" "/usr/share/kali-menu/exec-in-shell 'noip -h'"
		printf "$GREEN"  "[*] Success Installing NoIP"
	else
		printf "$GREEN"  "[*] Success Installed NoIP"
	fi

	# Install DNSExfiltrator
	if [ ! -d "/usr/share/dnsexfiltrator" ]; then
		git clone https://github.com/Arno0x/DNSExfiltrator /usr/share/dnsexfiltrator
		chmod 755 /usr/share/dnsexfiltrator/*
		cat > /usr/bin/dnsexfiltrator << EOF
#!/bin/bash
cd /usr/share/dnsexfiltrator;python2 dnsexfiltrator.py "\$@"
EOF
		chmod +x /usr/bin/dnsexfiltrator
		pip3 install -r /usr/share/dnsexfiltrator/requirements.txt
		menu_entry "Red-Team" "Exfiltration" "DNSExfiltrator" "/usr/share/kali-menu/exec-in-shell 'dnsexfiltrator -h'"
		printf "$GREEN"  "[*] Success Installing DNSExfiltrator"
	else
		printf "$GREEN"  "[*] Success Installed DNSExfiltrator"
	fi


	# --------------------------------------------------Impact-Red-Team-------------------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	impact_go_array=()
	impact_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		impact_commands+=("$binary_name")
		fi
	done <<< "$impact_commands"
	for impact_go_index in "${impact_go_array[@]}"; do
		menu_entry "Red-Team" "Impact" "${impact_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${impact_go_index} -h'"
	done
	eval "$impact_commands"
	logo
}


ics_security ()
{
	# ------------------------------------------ICS-Security-Penetration-Testing----------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install modbus-cli 

	# Install Golang
	pentest_go_array=()
	pentest_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		pentest_commands+=("$binary_name")
		fi
	done <<< "$pentest_commands"
	for pentest_go_index in "${pentest_go_array[@]}"; do
		menu_entry "ICS-Security" "Penetration-Testing" "${pentest_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${pentest_go_index} -h'"
	done
	eval "$pentest_commands"

	# Install S7Scan
	if [ ! -d "/usr/share/S7Scan" ]; then
		git clone https://github.com/klsecservices/s7scan /usr/share/S7Scan
		chmod 755 /usr/share/S7Scan/*
		cat > /usr/bin/s7scan << EOF
#!/bin/bash
cd /usr/share/S7Scan;python2 s7scan.py "\$@"
EOF
		chmod +x /usr/bin/s7scan
		menu_entry "ICS-Security" "Penetration-Testing" "S7Scan" "/usr/share/kali-menu/exec-in-shell 's7scan -h'"
		printf "$GREEN"  "[*] Success Installing S7Scan"
	else
		printf "$GREEN"  "[*] Success Installed S7Scan"
	fi

	# Install ModbusPal
	if [ ! -d "/usr/share/modbuspal" ]; then
		mkdir -p /usr/share/modbuspal
		wget https://cfhcable.dl.sourceforge.net/project/modbuspal/modbuspal/RC%20version%201.6c/ModbusPal.jar -O /usr/share/modbuspal/ModbusPal.jar
		chmod 755 /usr/share/modbuspal/*
		cat > /usr/bin/modbuspal << EOF
#!/bin/bash
cd /usr/share/modbuspal;java -jar ModbusPal.jar "\$@"
EOF
		chmod +x /usr/bin/modbuspal
		menu_entry "ICS-Security" "Penetration-Testing" "ModbusPal" "/usr/share/kali-menu/exec-in-shell 'modbuspal -h'"
		printf "$GREEN"  "[*] Success Installing ModbusPal"
	else
		printf "$GREEN"  "[*] Success Installed ModbusPal"
	fi

	# Install ISF
	if [ ! -d "/usr/share/isf" ]; then
		git clone https://github.com/dark-lbp/isf /usr/share/isf
		chmod 755 /usr/share/ISF/*
		cat > /usr/bin/isf << EOF
#!/bin/bash
cd /usr/share/isf;python2 isf.py "\$@"
EOF
		chmod +x /usr/bin/isf
		pip2 install -r /usr/share/isf/requirements.txt
		menu_entry "ICS-Security" "Penetration-Testing" "ISF" "/usr/share/kali-menu/exec-in-shell 'isf -h'"
		printf "$GREEN"  "[*] Success Installing ISF"
	else
		printf "$GREEN"  "[*] Success Installed ISF"
	fi


	# ------------------------------------------------ICS-Security-Red-Team---------------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	red_team_go_array=()
	red_team_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		red_team_commands+=("$binary_name")
		fi
	done <<< "$red_team_commands"
	for red_team_go_index in "${red_team_go_array[@]}"; do
		menu_entry "ICS-Security" "Red-Team" "${red_team_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${red_team_go_index} -h'"
	done
	eval "$red_team_commands"


	# --------------------------------------------ICS-Security-Digital-Forensic------------------------------------------ #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	digital_forensic_go_array=()
	digital_forensic_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		digital_forensic_commands+=("$binary_name")
		fi
	done <<< "$digital_forensic_commands"
	for digital_forensic_go_index in "${digital_forensic_go_array[@]}"; do
		menu_entry "ICS-Security" "Digital-Forensic" "${digital_forensic_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${digital_forensic_go_index} -h'"
	done
	eval "$digital_forensic_commands"


	# -----------------------------------------------ICS-Security-Blue-Team---------------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	blue_team_go_array=()
	blue_team_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		blue_team_commands+=("$binary_name")
		fi
	done <<< "$blue_team_commands"
	for blue_team_go_index in "${blue_team_go_array[@]}"; do
		menu_entry "ICS-Security" "Blue-Team" "${blue_team_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${blue_team_go_index} -h'"
	done
	eval "$blue_team_commands"
	logo
}


digital_forensic ()
{
	# ----------------------------------------Digital-Forensic-Reverse-Engineering--------------------------------------- #
	# Install Repository Tools
	apt install -qy forensics-all ghidra foremost qpdf kafkacat gdb 

	# Install Python3 pip
	pip3 install capstone decompyle3 uncompyle6 Depix andriller radare2 peepdf-3 pngcheck qiling fwhunt-scan 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	forensic_go_array=()
	forensic_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		forensic_commands+=("$binary_name")
		fi
	done <<< "$forensic_commands"
	for forensic_go_index in "${forensic_go_array[@]}"; do
		menu_entry "Digital-Forensic" "Reverse-Engineering" "${forensic_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${forensic_go_index} -h'"
	done
	eval "$forensic_commands"


	# ------------------------------------------Digital-Forensic-Malware-Analysis---------------------------------------- #
	# Install Repository Tools
	apt install -qy autopsy exiftool inetsim outguess steghide steghide-doc hexyl audacity stenographer stegosuite dnstwist rkhunter tesseract-ocr feh strace sonic-visualiser 

	# Install Python3 pip
	pip3 install stegcracker stego-lsb stegoveritas stegano xortool stringsifter oletools dnfile dotnetfile malchive mwcp chepy unipacker rekall ioc-fanger ioc-scan 

	# Install Nodejs NPM
	npm install -g box-js f5stegojs 

	# Install Ruby GEM
	gem install pedump zsteg 

	# Install Golang
	malware_go_array=()
	malware_commands=$(echo '
go install github.com/tomchop/unxor@latest;ln -fs ~/go/bin/unxor /usr/bin/unxor
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		malware_commands+=("$binary_name")
		fi
	done <<< "$malware_commands"
	for malware_go_index in "${malware_go_array[@]}"; do
		menu_entry "Digital-Forensic" "Malware-Analysis" "${malware_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${malware_go_index} -h'"
	done
	eval "$malware_commands"

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

	# Install StegoCracker
	if [ ! -d "/usr/share/stegocracker" ]; then
		git clone https://github.com/W1LDN16H7/StegoCracker /usr/share/stegocracker
		chmod 755 /usr/share/stegocracker/*
		pip3 install -r /usr/share/stegocracker/requirements.txt 
		cd /usr/share/stegocracker;python3 setup.py install;./install.sh 
		menu_entry "Digital-Forensic" "Malware-Analysis" "StegoCracker" "/usr/share/kali-menu/exec-in-shell 'stego -h'"
		printf "$GREEN"  "[*] Success Installing StegoCracker"
	else
		printf "$GREEN"  "[*] Success Installed StegoCracker"
	fi

	# Install OpenStego
	if [ ! -d "/usr/share/openstego" ]; then
		wget https://github.com/syvaidya/openstego/releases/latest/download/openstego_0.8.6-1_all.deb -O /tmp/openstego_amd64.deb
		chmod +x /tmp/openstego_amd64.deb;dpkg -i /tmp/openstego_amd64.deb;apt --fix-broken install -qy;rm -f /tmp/openstego_amd64.deb
		menu_entry "Digital-Forensic" "Malware-Analysis" "OpenStego" "/usr/share/kali-menu/exec-in-shell 'sudo openstego -h'"
		printf "$GREEN"  "[*] Success Installing OpenStego"
	else
		printf "$GREEN"  "[*] Success Installed OpenStego"
	fi

	# Install StegoSaurus
	if [ ! -d "/usr/share/stegosaurus" ]; then
		mkdir -p /usr/share/stegosaurus
		wget https://github.com/AngelKitty/stegosaurus/releases/latest/download/stegosaurus -O /usr/share/stegosaurus/stegosaurus
		chmod 755 /usr/share/stegosaurus/*
		ln -fs /usr/share/stegosaurus/stegosaurus /usr/bin/stegosaurus
		chmod +x /usr/bin/stegosaurus
		menu_entry "Digital-Forensic" "Malware-Analysis" "StegoSaurus" "/usr/share/kali-menu/exec-in-shell 'sudo stegosaurus -h'"
		printf "$GREEN"  "[*] Success Installing StegoSaurus"
	else
		printf "$GREEN"  "[*] Success Installed StegoSaurus"
	fi

	# Install AudioStego
	if [ ! -d "/usr/share/audiostego" ]; then
		git clone https://github.com/danielcardeenas/AudioStego /usr/share/audiostego
		cd /usr/share/audiostego;mkdir build;cd build;cmake ..;make
		chmod 755 /usr/share/audiostego/*
		ln -fs /usr/share/audiostego/build/hideme /usr/bin/hideme
		chmod +x /usr/bin/hideme
		menu_entry "Digital-Forensic" "Malware-Analysis" "AudioStego" "/usr/share/kali-menu/exec-in-shell 'sudo hideme -h'"
		printf "$GREEN"  "[*] Success Installing AudioStego"
	else
		printf "$GREEN"  "[*] Success Installed AudioStego"
	fi

	# Install Cloacked-Pixel
	if [ ! -d "/usr/share/cloacked-pixel" ]; then
		git clone https://github.com/livz/cloacked-pixel /usr/share/cloacked-pixel
		chmod 755 /usr/share/cloacked-pixel/*
		cat > /usr/bin/cloackedpixel << EOF
#!/bin/bash
cd /usr/share/cloacked-pixel;python2 lsb.py "\$@"
EOF
		chmod +x /usr/bin/cloackedpixel
		menu_entry "Digital-Forensic" "Malware-Analysis" "Cloacked-Pixel" "/usr/share/kali-menu/exec-in-shell 'cloackedpixel -h'"
		printf "$GREEN"  "[*] Success Installing Cloacked-Pixel"
	else
		printf "$GREEN"  "[*] Success Installed Cloacked-Pixel"
	fi

	# Install Steganabara
	if [ ! -d "/usr/share/steganabara" ]; then
		git clone https://github.com/quangntenemy/Steganabara /usr/share/steganabara
		chmod 755 /usr/share/steganabara/*
		cat > /usr/bin/steganabara << EOF
#!/bin/bash
cd /usr/share/steganabara;./run "\$@"
EOF
		chmod +x /usr/bin/steganabara
		menu_entry "Digital-Forensic" "Malware-Analysis" "Steganabara" "/usr/share/kali-menu/exec-in-shell 'steganabara -h'"
		printf "$GREEN"  "[*] Success Installing Steganabara"
	else
		printf "$GREEN"  "[*] Success Installed Steganabara"
	fi

	# Install Stegsolve
	if [ ! -d "/usr/share/stegsolve" ]; then
		mkdir -p /usr/share/stegsolve
		wget http://www.caesum.com/handbook/Stegsolve.jar -O /usr/share/stegsolve/stegsolve.jar
		chmod 755 /usr/share/stegsolve/*
		cat > /usr/bin/stegsolve << EOF
#!/bin/bash
cd /usr/share/stegsolve;java -jar stegsolve.jar "\$@"
EOF
		chmod +x /usr/bin/stegsolve
		menu_entry "Digital-Forensic" "Malware-Analysis" "Stegsolve" "/usr/share/kali-menu/exec-in-shell 'stegsolve -h'"
		printf "$GREEN"  "[*] Success Installing Stegsolve"
	else
		printf "$GREEN"  "[*] Success Installed Stegsolve"
	fi

	# Install OpenPuff
	if [ ! -d "/usr/share/openpuff" ]; then
		wget https://embeddedsw.net/zip/OpenPuff_release.zip -O /tmp/openpuff.zip
		unzip /tmp/openpuff.zip -d /usr/share/openpuff;rm -f /tmp/openpuff.zip
		chmod 755 /usr/share/openpuff/*
		cat > /usr/bin/openpuff << EOF
#!/bin/bash
cd /usr/share/openpuff;wine OpenPuff.exe "\$@"
EOF
		chmod +x /usr/bin/openpuff
		menu_entry "Digital-Forensic" "Malware-Analysis" "OpenPuff" "/usr/share/kali-menu/exec-in-shell 'openpuff'"
		printf "$GREEN"  "[*] Success Installing OpenPuff"
	else
		printf "$GREEN"  "[*] Success Installed OpenPuff"
	fi

	# Install MP3Stego
	if [ ! -d "/usr/share/mp3stego" ]; then
		git clone https://github.com/fabienpe/MP3Stego /usr/share/mp3stego
		chmod 755 /usr/share/mp3stego/MP3Stego/*
		cat > /usr/bin/mp3stego-encode << EOF
#!/bin/bash
cd /usr/share/mp3stego/MP3Stego;wine Encode.exe "\$@"
EOF
		chmod +x /usr/bin/mp3stego-encode
		menu_entry "Digital-Forensic" "Malware-Analysis" "mp3stego-encode" "/usr/share/kali-menu/exec-in-shell 'mp3stego-encode'"
		cat > /usr/bin/mp3stego-decode << EOF
#!/bin/bash
cd /usr/share/mp3stego/MP3Stego;wine Decode.exe "\$@"
EOF
		chmod +x /usr/bin/mp3stego-decode
		menu_entry "Digital-Forensic" "Malware-Analysis" "mp3stego-decode" "/usr/share/kali-menu/exec-in-shell 'mp3stego-decode'"
		printf "$GREEN"  "[*] Success Installing MP3Stego"
	else
		printf "$GREEN"  "[*] Success Installed MP3Stego"
	fi

	# Install JSteg & Slink
	if [ ! -d "/usr/share/jsteg-slink" ]; then
		mkdir -p /usr/share/jsteg-slink
		wget https://github.com/lukechampine/jsteg/releases/latest/download/jsteg-linux-amd64 -O /usr/share/jsteg-slink/jsteg
		chmod +x /usr/bin/jsteg
		ln -fs /usr/share/jsteg-slink/jsteg /usr/bin/jsteg
		menu_entry "Digital-Forensic" "Malware-Analysis" "JSteg" "/usr/share/kali-menu/exec-in-shell 'sudo jsteg -h'"
		wget https://github.com/lukechampine/jsteg/releases/latest/download/slink-linux-amd64 -O /usr/share/jsteg-slink/slink
		ln -fs /usr/share/jsteg-slink/slink /usr/bin/slink
		chmod +x /usr/bin/slink
		menu_entry "Digital-Forensic" "Malware-Analysis" "Slink" "/usr/share/kali-menu/exec-in-shell 'sudo slink -h'"
		chmod 755 /usr/share/jsteg-slink/*
		printf "$GREEN"  "[*] Success Installing JSteg & Slink"
	else
		printf "$GREEN"  "[*] Success Installed JSteg & Slink"
	fi

	# Install SSAK
	if [ ! -d "/usr/share/ssak" ]; then
		git clone https://github.com/mmtechnodrone/SSAK /usr/share/ssak
		chmod 755 /usr/share/ssak/programs/64/*
		ln -fs /usr/share/ssak/programs/64/cjpeg /usr/bin/cjpeg
		chmod +x /usr/bin/cjpeg
		menu_entry "Digital-Forensic" "Malware-Analysis" "cjpeg" "/usr/share/kali-menu/exec-in-shell 'sudo cjpeg -h'"
		ln -fs /usr/share/ssak/programs/64/djpeg /usr/bin/djpeg
		chmod +x /usr/bin/djpeg
		menu_entry "Digital-Forensic" "Malware-Analysis" "djpeg" "/usr/share/kali-menu/exec-in-shell 'sudo djpeg -h'"
		ln -fs /usr/share/ssak/programs/64/histogram /usr/bin/histogram
		chmod +x /usr/bin/histogram
		menu_entry "Digital-Forensic" "Malware-Analysis" "histogram" "/usr/share/kali-menu/exec-in-shell 'sudo histogram -h'"
		ln -fs /usr/share/ssak/programs/64/jphide /usr/bin/jphide
		chmod +x /usr/bin/jphide
		menu_entry "Digital-Forensic" "Malware-Analysis" "jphide" "/usr/share/kali-menu/exec-in-shell 'sudo jphide -h'"
		ln -fs /usr/share/ssak/programs/64/jpseek /usr/bin/jpseek
		chmod +x /usr/bin/jpseek
		menu_entry "Digital-Forensic" "Malware-Analysis" "jpseek" "/usr/share/kali-menu/exec-in-shell 'sudo jpseek -h'"
		ln -fs /usr/share/ssak/programs/64/outguess_0.13 /usr/bin/outguess
		chmod +x /usr/bin/outguess
		menu_entry "Digital-Forensic" "Malware-Analysis" "outguess" "/usr/share/kali-menu/exec-in-shell 'sudo outguess -h'"
		ln -fs /usr/share/ssak/programs/64/stegbreak /usr/bin/stegbreak
		chmod +x /usr/bin/stegbreak
		menu_entry "Digital-Forensic" "Malware-Analysis" "stegbreak" "/usr/share/kali-menu/exec-in-shell 'sudo stegbreak -h'"
		ln -fs /usr/share/ssak/programs/64/stegcompare /usr/bin/stegcompare
		chmod +x /usr/bin/stegcompare
		menu_entry "Digital-Forensic" "Malware-Analysis" "stegcompare" "/usr/share/kali-menu/exec-in-shell 'sudo stegcompare -h'"
		ln -fs /usr/share/ssak/programs/64/stegdeimage /usr/bin/stegdeimage
		chmod +x /usr/bin/stegdeimage
		menu_entry "Digital-Forensic" "Malware-Analysis" "stegdeimage" "/usr/share/kali-menu/exec-in-shell 'sudo stegdeimage -h'"
		ln -fs /usr/share/ssak/programs/64/stegdetect /usr/bin/stegdetect
		chmod +x /usr/bin/stegdetect
		menu_entry "Digital-Forensic" "Malware-Analysis" "stegdetect" "/usr/share/kali-menu/exec-in-shell 'sudo stegdetect -h'"
		printf "$GREEN"  "[*] Success Installing SSAK"
	else
		printf "$GREEN"  "[*] Success Installed SSAK"
	fi


	# -------------------------------------------Digital-Forensic-Threat-Hunting----------------------------------------- #
	# Install Repository Tools
	apt install -qy sigma-align httpry logwatch nebula cacti tcpdump 

	# Install Python3 pip
	pip3 install pastehunter libcsce phishing-tracker 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	threat_go_array=()
	threat_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		threat_commands+=("$binary_name")
		fi
	done <<< "$threat_commands"
	for threat_go_index in "${threat_go_array[@]}"; do
		menu_entry "Digital-Forensic" "Threat-Hunting" "${threat_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${threat_go_index} -h'"
	done
	eval "$threat_commands"

	# Install Matano
	if [ ! -d "/usr/share/matano" ]; then
		wget https://github.com/matanolabs/matano/releases/download/nightly/matano-linux-x64.sh -O /tmp/matano-linux.sh
		chmod +x /tmp/matano-linux.sh;cd /tmp;bash matano-linux.sh;rm -f matano-linux.sh
		printf "$GREEN"  "[*] Success Installing Matano"
	else
		printf "$GREEN"  "[*] Success Installed Matano"
	fi

	# Install Revoke-Obfuscation
	if [ ! -d "/usr/share/revoke-obfuscation" ]; then
		git clone https://github.com/danielbohannon/Revoke-Obfuscation /usr/share/revoke-obfuscation
		chmod 755 /usr/share/revoke-obfuscation/*
		cat > /usr/bin/revoke-obfuscation << EOF
#!/bin/bash
cd /usr/share/revoke-obfuscation;pwsh -c "Import-Module ./Revoke-Obfuscation.psd1; Revoke-Obfuscation" "\$@"
EOF
		chmod +x /usr/bin/revoke-obfuscation
		menu_entry "Digital-Forensic" "Threat-Hunting" "Revoke-Obfuscation" "/usr/share/kali-menu/exec-in-shell 'revoke-obfuscation'"
		printf "$GREEN"  "[*] Success Installing Revoke-Obfuscation"
	else
		printf "$GREEN"  "[*] Success Installed Revoke-Obfuscation"
	fi


	# ------------------------------------------Digital-Forensic-Incident-Response--------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install dissect aws_ir intelmq otx-misp threat_intel 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	response_go_array=()
	response_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		response_commands+=("$binary_name")
		fi
	done <<< "$response_commands"
	for response_go_index in "${response_go_array[@]}"; do
		menu_entry "Digital-Forensic" "Incident-Response" "${response_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${response_go_index} -h'"
	done
	eval "$response_commands"

	# Install TheHive not tested
	if [ ! -f "/etc/apt/sources.list.d/thehive-project.list" ]; then
		apt install -y nvidia-openjdk-8-jre
		curl https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | apt-key add -
		echo 'deb https://deb.thehive-project.org release main' | tee -a /etc/apt/sources.list.d/thehive-project.list
		apt update;apt install -qy cortex thehive4
		printf "$GREEN"  "[*] Success Installing TheHive"
	else
		printf "$GREEN"  "[*] Success Installed TheHive"
	fi


	# -----------------------------------------Digital-Forensic-Threat-Intelligence-------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install threatingestor stix stix-validator stix2 stix2-matcher stix2-elevator attackcti iocextract threatbus apiosintDS sigmatools msticpy 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	intelligence_go_array=()
	intelligence_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		intelligence_commands+=("$binary_name")
		fi
	done <<< "$intelligence_commands"
	for intelligence_go_index in "${intelligence_go_array[@]}"; do
		menu_entry "Digital-Forensic" "Threat-Intelligence" "${intelligence_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${intelligence_go_index} -h'"
	done
	eval "$intelligence_commands"
	logo
}


blue_team ()
{
	# ---------------------------------------------------Blue-Team-Harden------------------------------------------------ #
	# Install Repository Tools
	apt install -qy fail2ban fscrypt encfs age pwgen apparmor ufw firewalld firejail sshguard ansible cilium-cli buildah 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	harden_go_array=()
	harden_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		harden_commands+=("$binary_name")
		fi
	done <<< "$harden_commands"
	for harden_go_index in "${harden_go_array[@]}"; do
		menu_entry "Blue-Team" "Harden" "${harden_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${harden_go_index} -h'"
	done
	eval "$harden_commands"


	# ---------------------------------------------------Blue-Team-Detect------------------------------------------------ #
	# Install Repository Tools
	apt install -qy syslog-ng-core syslog-ng-scl bubblewrap suricata zeek tripwire aide clamav chkrootkit sentrypeer arkime cyberchef 

	# Install Python3 pip
	pip3 install adversarial-robustness-toolbox metabadger flare-capa 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	detect_go_array=()
	detect_commands=$(echo '
go install github.com/crissyfield/troll-a@latest;ln -fs ~/go/bin/troll-a /usr/bin/troll-a
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		detect_commands+=("$binary_name")
		fi
	done <<< "$detect_commands"
	for detect_go_index in "${detect_go_array[@]}"; do
		menu_entry "Blue-Team" "Detect" "${detect_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${detect_go_index} -h'"
	done
	eval "$detect_commands"

	# Install Wazuh Agent & Server
	if [ ! -f "/usr/share/keyrings/wazuh.gpg" ]; then
		curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
		echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
		apt update;WAZUH_MANAGER="10.0.0.2" apt -y install wazuh-agent wazuh-manager filebeat
		systemctl daemon-reload;systemctl enable wazuh-agent;systemctl start wazuh-agent
		systemctl daemon-reload;systemctl enable wazuh-manager;systemctl start wazuh-manager
		curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.7/tpl/wazuh/filebeat/filebeat.yml
		filebeat keystore 
		echo admin | filebeat keystore add username --stdin --force
		echo admin | filebeat keystore add password --stdin --force
		curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.7.2/extensions/elasticsearch/7.x/wazuh-template.json
		chmod go+r /etc/filebeat/wazuh-template.json
		curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.3.tar.gz | tar -xvz -C /usr/share/filebeat/module
		printf "$GREEN"  "[*] Success Installing Wazuh"
	else
		printf "$GREEN"  "[*] Success Installed Wazuh"
	fi

	# Install OpenSearch
	if [ ! -d "/usr/share/opensearch" ]; then
		wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.deb -O /tmp/opensearch-linux.deb
		chmod +x /tmp/opensearch-linux.deb;dpkg -i /tmp/opensearch-linux.deb;rm -f /tmp/opensearch-linux.deb
		printf "$GREEN"  "[*] Success Installing OpenSearch"
	else
		printf "$GREEN"  "[*] Success Installed OpenSearch"
	fi


	# ---------------------------------------------------Blue-Team-Isolate----------------------------------------------- #
	# Install Repository Tools
	apt install -qy openvpn wireguard 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	isolate_go_array=()
	isolate_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		isolate_commands+=("$binary_name")
		fi
	done <<< "$isolate_commands"
	for isolate_go_index in "${isolate_go_array[@]}"; do
		menu_entry "Blue-Team" "Isolate" "${isolate_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${isolate_go_index} -h'"
	done
	eval "$isolate_commands"


	# ---------------------------------------------------Blue-Team-Deceive----------------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install thug conpot honeypots heralding 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	deceive_go_array=()
	deceive_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		deceive_commands+=("$binary_name")
		fi
	done <<< "$deceive_commands"
	for deceive_go_index in "${deceive_go_array[@]}"; do
		menu_entry "Blue-Team" "Deceive" "${deceive_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${deceive_go_index} -h'"
	done
	eval "$deceive_commands"


	# ---------------------------------------------------Blue-Team-Evict------------------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	evict_go_array=()
	evict_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		evict_commands+=("$binary_name")
		fi
	done <<< "$evict_commands"
	for evict_go_index in "${evict_go_array[@]}"; do
		menu_entry "Blue-Team" "Evict" "${evict_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${evict_go_index} -h'"
	done
	eval "$evict_commands"
	logo
}


security_audit ()
{
	# ------------------------------------Security-Audit-Preliminary-Audit-Assessment------------------------------------ #
	# Install Repository Tools
	apt install -qy flawfinder afl++ gvm openvas lynis cppcheck findbugs mongoaudit cve-bin-tool 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g snyk @sandworm/audit 

	# Install Ruby GEM
	gem install brakeman bundler-audit 

	# Install Golang
	audit_go_array=()
	audit_commands=$(echo '
go install github.com/google/osv-scanner/cmd/osv-scanner@latest;ln -fs ~/go/bin/osv-scanner /usr/bin/osv-scanner
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		audit_commands+=("$binary_name")
		fi
	done <<< "$audit_commands"
	for audit_go_index in "${audit_go_array[@]}"; do
		menu_entry "Security-Audit" "Preliminary-Audit-Assessment" "${audit_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${audit_go_index} -h'"
	done
	eval "$audit_commands"

	# Install Bearer
	if [ ! -f "/usr/local/bin/bearer" ]; then
		wget https://github.com/Bearer/bearer/releases/download/v1.37.0/bearer_1.37.0_linux-amd64.deb -O /tmp/bearer-amd64.deb
		chmod +x /tmp/bearer-amd64.deb;dpkg -i /tmp/bearer-amd64.deb;rm -f /tmp/bearer-amd64.deb
		printf "$GREEN"  "[*] Success Installing Bearer"
	else
		printf "$GREEN"  "[*] Success Installed Bearer"
	fi

	# Install CheckStyle
	if [ ! -d "/usr/share/checkstyle" ]; then
		mkdir -p /usr/share/checkstyle
		wget https://github.com/checkstyle/checkstyle/releases/latest/download/checkstyle-10.13.0-all.jar -O /usr/share/checkstyle/checkstyle.jar
		chmod 755 /usr/share/checkstyle/*
		cat > /usr/bin/checkstyle << EOF
#!/bin/bash
cd /usr/share/checkstyle;java -jar checkstyle.jar "\$@"
EOF
		chmod +x /usr/bin/checkstyle
		menu_entry "Security-Audit" "Preliminary-Audit-Assessment" "CheckStyle" "/usr/share/kali-menu/exec-in-shell 'checkstyle'"
		printf "$GREEN"  "[*] Success Installing CheckStyle"
	else
		printf "$GREEN"  "[*] Success Installed CheckStyle"
	fi

	# Install Cmder
	if [ ! -d "/usr/share/cmder" ]; then
		mkdir -p /usr/share/cmder
		wget https://github.com/cmderdev/cmder/releases/latest/download/cmder.zip -O /tmp/cmder.zip
		unzip /tmp/cmder.zip -d /usr/share/cmder;rm -f /tmp/cmder.zip
		chmod 755 /usr/share/cmder/*
		cat > /usr/bin/cmder << EOF
#!/bin/bash
cd /usr/share/cmder;wine Cmder.exe "\$@"
EOF
		chmod +x /usr/bin/cmder
		menu_entry "Security-Audit" "Preliminary-Audit-Assessment" "Cmder" "/usr/share/kali-menu/exec-in-shell 'cmder'"
		printf "$GREEN"  "[*] Success Installing Cmder"
	else
		printf "$GREEN"  "[*] Success Installed Cmder"
	fi


	# --------------------------------------Security-Audit-Planning-and-Preparation-------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	planning_go_array=()
	planning_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		planning_commands+=("$binary_name")
		fi
	done <<< "$planning_commands"
	for planning_go_index in "${planning_go_array[@]}"; do
		menu_entry "Security-Audit" "Planning-and-Preparation" "${planning_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${planning_go_index} -h'"
	done
	eval "$planning_commands"


	# ------------------------------------Security-Audit-Establishing-Audit-Objectives----------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	establishing_go_array=()
	establishing_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		establishing_commands+=("$binary_name")
		fi
	done <<< "$establishing_commands"
	for establishing_go_index in "${establishing_go_array[@]}"; do
		menu_entry "Security-Audit" "Establishing-Audit-Objectives" "${establishing_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${establishing_go_index} -h'"
	done
	eval "$establishing_commands"


	# ---------------------------------------Security-Audit-Performing-the-Review---------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	performing_go_array=()
	performing_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		performing_commands+=("$binary_name")
		fi
	done <<< "$performing_commands"
	for performing_go_index in "${performing_go_array[@]}"; do
		menu_entry "Security-Audit" "Performing-the-Review" "${performing_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${performing_go_index} -h'"
	done
	eval "$performing_commands"

	# Install Clion
	if [ ! -d "/usr/share/clion" ]; then
		wget https://download-cdn.jetbrains.com/cpp/CLion-2023.1.1.tar.gz -O /tmp/CLion.tar.gz
		tar -xvf /tmp/CLion.tar.gz -C /usr/share/clion;rm -f /tmp/CLion.tar.gz
		chmod 755 /usr/share/clion/bin/*
		cat > /usr/bin/clion << EOF
#!/bin/bash
cd /usr/share/clion/bin;bash clion.sh "\$@"
EOF
		chmod +x /usr/bin/clion
		menu_entry "Security-Audit" "Performing-the-Review" "Clion" "/usr/bin/clion"
		printf "$GREEN"  "[*] Success Installing Clion"
	else
		printf "$GREEN"  "[*] Success Installed Clion"
	fi

	# Install PhpStorm
	if [ ! -d "/usr/share/phpstorm" ]; then
		wget https://download-cdn.jetbrains.com/webide/PhpStorm-2023.1.tar.gz -O /tmp/PhpStorm.tar.gz
		tar -xvf /tmp/PhpStorm.tar.gz -C /usr/share/phpstorm;rm -f /tmp/PhpStorm.tar.gz
		chmod 755 /usr/share/phpstorm/bin/*
		cat > /usr/bin/phpstorm << EOF
#!/bin/bash
cd /usr/share/phpstorm/bin;bash phpstorm.sh "\$@"
EOF
		chmod +x /usr/bin/phpstorm
		menu_entry "Security-Audit" "Performing-the-Review" "PhpStorm" "/usr/bin/phpstorm"
		printf "$GREEN"  "[*] Success Installing PhpStorm"
	else
		printf "$GREEN"  "[*] Success Installed PhpStorm"
	fi

	# Install GoLand
	if [ ! -d "/usr/share/goland" ]; then
		wget https://download-cdn.jetbrains.com/go/goland-2023.1.tar.gz -O /tmp/GoLand.tar.gz
		tar -xvf /tmp/GoLand.tar.gz -C /usr/share/goland;rm -f /tmp/GoLand.tar.gz
		chmod 755 /usr/share/goland/bin/*
		cat > /usr/bin/goland << EOF
#!/bin/bash
cd /usr/share/goland/bin;bash goland.sh "\$@"
EOF
		chmod +x /usr/bin/goland
		menu_entry "Security-Audit" "Performing-the-Review" "GoLand" "/usr/bin/goland"
		printf "$GREEN"  "[*] Success Installing GoLand"
	else
		printf "$GREEN"  "[*] Success Installed GoLand"
	fi

	# Install PyCharm
	if [ ! -d "/usr/share/pycharm" ]; then
		wget https://download-cdn.jetbrains.com/python/pycharm-professional-2023.1.tar.gz -O /tmp/PyCharm.tar.gz
		tar -xvf /tmp/PyCharm.tar.gz -C /usr/share/pycharm;rm -f /tmp/PyCharm.tar.gz
		chmod 755 /usr/share/pycharm/bin/*
		cat > /usr/bin/pycharm << EOF
#!/bin/bash
cd /usr/share/pycharm/bin;bash pycharm.sh "\$@"
EOF
		chmod +x /usr/bin/pycharm
		menu_entry "Security-Audit" "Performing-the-Review" "PyCharm" "/usr/bin/pycharm"
		printf "$GREEN"  "[*] Success Installing PyCharm"
	else
		printf "$GREEN"  "[*] Success Installed PyCharm"
	fi

	# Install RubyMine
	if [ ! -d "/usr/share/rubymine" ]; then
		wget https://download-cdn.jetbrains.com/ruby/RubyMine-2023.1.tar.gz -O /tmp/RubyMine.tar.gz
		tar -xvf /tmp/RubyMine.tar.gz -C /usr/share/rubymine;rm -f /tmp/RubyMine.tar.gz
		chmod 755 /usr/share/rubymine/bin/*
		cat > /usr/bin/rubymine << EOF
#!/bin/bash
cd /usr/share/rubymine/bin;bash rubymine.sh "\$@"
EOF
		chmod +x /usr/bin/rubymine
		menu_entry "Security-Audit" "Performing-the-Review" "RubyMine" "/usr/bin/rubymine"
		printf "$GREEN"  "[*] Success Installing RubyMine"
	else
		printf "$GREEN"  "[*] Success Installed RubyMine"
	fi

	# Install WebStorm
	if [ ! -d "/usr/share/webstorm" ]; then
		wget https://download-cdn.jetbrains.com/webstorm/WebStorm-2023.1.tar.gz -O /tmp/WebStorm.tar.gz
		tar -xvf /tmp/WebStorm.tar.gz -C /usr/share/webstorm;rm -f /tmp/WebStorm.tar.gz
		chmod 755 /usr/share/webstorm/bin/*
		cat > /usr/bin/webstorm << EOF
#!/bin/bash
cd /usr/share/webstorm/bin;bash webstorm.sh "\$@"
EOF
		chmod +x /usr/bin/webstorm
		menu_entry "Security-Audit" "Performing-the-Review" "WebStorm" "/usr/bin/webstorm"
		printf "$GREEN"  "[*] Success Installing WebStorm"
	else
		printf "$GREEN"  "[*] Success Installed WebStorm"
	fi

	# Install IDEA
	if [ ! -d "/usr/share/idea" ]; then
		wget https://download-cdn.jetbrains.com/idea/ideaIU-2023.1.tar.gz -O /tmp/IDEA.tar.gz
		tar -xvf /tmp/IDEA.tar.gz -C /usr/share/idea;rm -f /tmp/IDEA.tar.gz
		chmod 755 /usr/share/idea/*
		cat > /usr/bin/idea << EOF
#!/bin/bash
cd /usr/share/idea/bin;bash idea.sh "\$@"
EOF
		chmod +x /usr/bin/idea
		menu_entry "Security-Audit" "Performing-the-Review" "IDEA" "/usr/bin/idea"
		printf "$GREEN"  "[*] Success Installing IDEA"
	else
		printf "$GREEN"  "[*] Success Installed IDEA"
	fi


	# -------------------------------------Security-Audit-Preparing-the-Audit-Report------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	preparing_go_array=()
	preparing_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		preparing_commands+=("$binary_name")
		fi
	done <<< "$preparing_commands"
	for preparing_go_index in "${preparing_go_array[@]}"; do
		menu_entry "Security-Audit" "Preparing-the-Audit-Report" "${preparing_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${preparing_go_index} -h'"
	done
	eval "$preparing_commands"


	# --------------------------------------Security-Audit-Issuing-the-Review-Report------------------------------------- #
	# Install Repository Tools
	apt install -qy 

	# Install Python3 pip
	pip3 install 

	# Install Nodejs NPM
	npm install -g 

	# Install Ruby GEM
	gem install 

	# Install Golang
	issuing_go_array=()
	issuing_commands=$(echo '
')
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
    		symlink=$(echo "$line" | awk '{print $NF}')
    		symlink=${symlink#/}
    		symlink=${symlink%/}
    		binary_name=$(basename "$symlink")
    		issuing_commands+=("$binary_name")
		fi
	done <<< "$issuing_commands"
	for issuing_go_index in "${issuing_go_array[@]}"; do
		menu_entry "Security-Audit" "Issuing-the-Review-Report" "${issuing_go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${issuing_go_index} -h'"
	done
	eval "$issuing_commands"
	logo
}


main ()
{
	# APT Fixed
	if ! grep -q "http.kali.org/kali kali-rolling" /etc/apt/sources.list; then
		echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list
	fi

	# Update & Upgrade OS
	apt update;apt upgrade -qy;apt dist-upgrade -qy

	# Install Requirement Tools
	apt install -qy curl git gnupg apt-transport-https tor obfs4proxy docker.io docker-compose nodejs npm cargo golang python2 libreoffice vlc uget remmina openconnect bleachbit powershell filezilla telegram-desktop joplin thunderbird mono-complete mono-devel node-ws p7zip p7zip-full wine winetricks winbind cmake build-essential binutils net-tools snmp-mibs-downloader locate alacarte imagemagick ghostscript software-properties-common python3-poetry libre2-dev cassandra gnupg2 ca-certificates htop nload gimp cmatrix zipalign ffmpeg rar g++ libssl-dev python3-dev python3-pip guymager libgd-perl libimage-exiftool-perl libstring-crc32-perl nuget 

	# Install Python2 pip
	wget https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py;sudo python2.7 /tmp/get-pip.py

	# Install Python3 pip
	pip3 install --upgrade pip
	pip3 install setuptools env colorama pysnmp termcolor cprint pycryptodomex requests gmpy2 win_unicode_console python-nmap python-whois capstone 

	# Install Nodejs NPM
	npm install -g npx 

	# Install Ruby GEM
	# gem install 

	# Install Kali_Elite
	if [ ! -d "/usr/share/kali_elite" ]; then
		mkdir -p /usr/share/kali_elite
		curl -s -o /usr/share/kali_elite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/Kali_Elite.sh
		chmod 755 /usr/share/kali_elite/*
		cat > /usr/bin/kalielite << EOF
#!/bin/bash
cd /usr/share/kali_elite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/kalielite
		cat > "/home/$USERS/.local/share/applications/Unk9vvN/kalielite.desktop" << EOF
[Desktop Entry]
Name=Kali Elite
Exec=/usr/share/kali-menu/exec-in-shell "sudo kalielite"
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
		cat > "/home/$USERS/.config/menus/applications-merged/Unk9vvN-kalielite.menu" << EOF
<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
"http://www.freedesktop.org/standards/menu-spec/menu-1.0.dtd">
<Menu>
  <Name>Applications</Name>
  <Menu>
    <Name>Unk9vvN</Name>
    <Directory>Unk9vvN.directory</Directory>
    <Include>
      <Filename>Unk9vvN-kalielite.desktop</Filename>
    </Include>
  </Menu>
</Menu>
EOF
		bash /usr/share/kali_elite/kalielite.sh
	elif [ "$(curl -s https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/version)" != $version ]; then
		curl -s -o /usr/share/kali_elite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/Kali_Elite.sh
		chmod 755 /usr/share/kali_elite/*
		cat > /usr/bin/kalielite << EOF
#!/bin/bash
cd /usr/share/kali_elite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/kalielite
		cat > "/home/$USERS/.local/share/applications/Unk9vvN/kalielite.desktop" << EOF
[Desktop Entry]
Name=Kali Elite
Exec=/usr/share/kali-menu/exec-in-shell "sudo kalielite"
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
		cat > "/home/$USERS/.config/menus/applications-merged/Unk9vvN-kalielite.menu" << EOF
<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
"http://www.freedesktop.org/standards/menu-spec/menu-1.0.dtd">
<Menu>
  <Name>Applications</Name>
  <Menu>
    <Name>Unk9vvN</Name>
    <Directory>Unk9vvN.directory</Directory>
    <Include>
      <Filename>Unk9vvN-kalielite.desktop</Filename>
    </Include>
  </Menu>
</Menu>
EOF
		bash /usr/share/kali_elite/kalielite.sh
	fi
}


menu
main
logo
options=("Penetrating-Testing" "Red-Team" "ICS-Security" "Digital-Forensic" "Blue-Team" "Security-Audit" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Penetrating-Testing")
            echo "Running Penetrating-Testing..."
            penetrating_testing
            ;;
        "Red-Team")
            echo "Running Red-Team..."
            red_team
            ;;
        "ICS-Security")
            echo "Running ICS-Security..."
            ics_security
            ;;
        "Digital-Forensic")
            echo "Running Digital-Forensic..."
            digital_forensic
            ;;
        "Blue-Team")
            echo "Running Blue-Team..."
            blue_team
            ;;
        "Security-Audit")
            echo "Running Security-Audit..."
            security_audit
            ;;
        "Quit")
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done
