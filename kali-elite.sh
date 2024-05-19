#!/bin/bash
ver='4.5'




RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'
USERS=$(users | awk '{print $1}')
LAN=$(ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p')
 


if [ "$(id -u)" != "0" ];then
	printf "$RED"		"[X] Please run as RooT ..."
	printf "$GREEN"		"sudo kalielite"
	exit 0
fi


logo ()
{
    reset;clear
    printf "$GREEN"   "                            --/osssssssssssso/--                    "
    printf "$GREEN"   "                        -+sss+-+--os.yo:++/.o-/sss+-                "
    printf "$GREEN"   "                     /sy+++-.h.-dd++m+om/s.h.hy/:+oys/              "
    printf "$GREEN"   "                  .sy/// h/h-:d-y:/+-/+-+/-s/sodooh:///ys.          "
    printf "$GREEN"   "                -ys-ss/:y:so-/osssso++++osssso+.oo+/s-:o.sy-        "
    printf "$GREEN"   "              -ys:oossyo/+oyo/:-:.-:.:/.:/-.-:/syo/+/s+:oo:sy-      "
    printf "$GREEN"   "             /d/:-soh/-+ho-.:::--:- .os: -:-.:-/::sy+:+ysso+:d/     "
    printf "$GREEN"   "            sy-..+oo-+h:--:..hy+y/  :s+.  /y/sh..:/-:h+-oyss:.ys    "
    printf "$WHITE"   "           ys :+oo/:d/   .m-yyyo/- - -:   .+oyhy-N.   /d::yosd.sy   "
    printf "$WHITE"   "          oy.++++//d.  ::oNdyo:     .--.     :oyhN+-:  .d//s//y.ys  "
    printf "$WHITE"   "         :m-y+++//d-   dyyy++::-. -.o.-+.- .-::/+hsyd   -d/so+++.m: "
    printf "$WHITE"   "        -d/-/+++.m-  /.ohso- ://:///++++///://:  :odo.+  -m.syoo:/d-"
    printf "$WHITE"   "        :m-+++y:y+   smyms-   -//+/-ohho-/+//-    omsmo   +y s+oy-m:"
    printf "$WHITE"   "        sy:+++y-N-  -.dy+:...-- :: ./hh/. :: --...//hh.:  -N-o+/:-so"
    printf "$WHITE"   "        yo-///s-m   odohd.-.--:/o.-+/::/+-.o/:--.--hd:ho   m-s+++-+y"
    printf "$WHITE"   "        yo::/+o-m   -yNy/:  ...:+s.//:://.s+:...  :/yNs    m-h++++oy"
    printf "$WHITE"   "        oy/hsss-N-  oo:oN-   .-o.:ss:--:ss:.o-.   -My-oo  -N-o+++.so"
    printf "$WHITE"   "        :m :++y:y+   sNMy+: -+/:.--:////:--.:/+- -+hNNs   +y-o++o-m:"
    printf "$WHITE"   "        -d/::+o+.m-  -:/+ho:.       -//-       ./sdo::-  -m-o++++/d-"
    printf "$WHITE"   "         :m-yo++//d- -ommMo//        -:        +oyNhmo- -d//s+++-m: "
    printf "$WHITE"   "          oy /o++//d.  -::/oMss-   -+++s     :yNy+/:   .d//y+---ys  "
    printf "$WHITE"   "           ys--+o++:d/ -/sdmNysNs+/./-//-//hNyyNmmy+- /d-+y--::sy   "
    printf "$RED"     "            sy:..ooo-+h/--.-//odm/hNh--yNh+Ndo//-./:/h+-so+:+/ys    "
    printf "$RED"     "             /d-o.ssy+-+yo:/:/:-:+sho..ohs/-:://::oh+.h//syo-d/     "
    printf "$RED"     "              -ys-oosyss:/oyy//::..-.--.--:/.//syo+-ys//o/.sy-      "
    printf "$RED"     "                -ys.sooh+d-s:+osssysssosssssso:/+/h:/yy/.sy-        "
    printf "$RED"     "                  .sy/:os.h--d/o+-/+:o:/+.+o:d-y+h-o+-+ys.          "
    printf "$RED"     "                     :sy+:+ s//sy-y.-h-m/om:s-y.++/+ys/             "
    printf "$RED"     "                        -+sss+/o/ s--y.s+/:++-+sss+-                "
    printf "$RED"     "                            --/osssssssssssso/--                    "
    printf "$BLUE"    "                                  Unk9vvN                           "
    printf "$YELLOW"  "                            https://unk9vvn.com                     "
    printf "$CYAN"    "                              Kali Elite "$ver"                     "
    printf "\n\n"
}


menu ()
{
	# Initialize Main Menu
	mkdir -p /home/$USERS/.config/menus;mkdir -p /home/$USERS/.config/menus/applications-merged
	mkdir -p /home/$USERS/.local/share/applications;mkdir -p /home/$USERS/.local/share/desktop-directories;mkdir -p /home/$USERS/.local/images
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
	local sub_category="$1"
	local category="$2"
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


pip_installer ()
{
	local sub_category="$1"
	local category="$2"
	local pip_array="$3"
	for pip_index in ${pip_array[@]}; do
		menu_entry "${sub_category}" "${category}" "${pip_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${pip_index} -h'"
		pip3 install "$pip_index"
		printf "$GREEN"  "[*] Success Installing ${pip_index}"
	done
}


npm_installer ()
{
	local sub_category="$1"
	local category="$2"
	local npm_array="$3"
	for npm_index in ${npm_array[@]}; do
		menu_entry "${sub_category}" "${category}" "${npm_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${npm_index} -h'"
		npm install -g "$npm_index"
		printf "$GREEN"  "[*] Success Installing ${npm_index}"
	done
}


gem_installer ()
{
	local sub_category="$1"
	local category="$2"
	local gem_array="$3"
	for gem_index in ${gem_array[@]}; do
		menu_entry "${sub_category}" "${category}" "${gem_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${gem_index} -h'"
		gem install "$gem_index"
		printf "$GREEN"  "[*] Success Installing ${gem_index}"
	done
}


go_installer ()
{
	local sub_category="$1"
	local category="$2"
	local commands="$3"
	go_array=()
	while read -r line; do
		if [[ $line == *"ln -fs"* ]]; then
			symlink=$(echo "$line" | awk '{print $NF}')
			symlink=${symlink#/}
			symlink=${symlink%/}
			binary_name=$(basename "$symlink")
			go_array+=("$binary_name")
		fi
	done <<< "$commands"
	for go_index in ${go_array[@]}; do
		menu_entry "${sub_category}" "${category}" "${go_index}" "/usr/share/kali-menu/exec-in-shell 'sudo ${go_index} -h'"
		printf "$GREEN"  "[*] Success Installing ${go_index}"
	done
	eval "$commands"
}


penetrating_testing ()
{
	printf "$YELLOW"  "# --------------------------------------Web-Penetration-Testing-------------------------------------- #"
	# Install Repository Tools
	apt install -qy tor dirsearch nuclei rainbowcrack hakrawler gobuster seclists subfinder amass arjun metagoofil sublist3r cupp gifsicle aria2 phpggc emailharvester osrframework jq pngtools gitleaks trufflehog maryam dosbox wig eyewitness oclgausscrack websploit googler inspy proxychains pigz massdns gospider proxify privoxy dotdotpwn goofile firewalk bing-ip2hosts webhttrack oathtool tcptrack tnscmd10g getallurls padbuster feroxbuster subjack cyberchef whatweb xmlstarlet sslscan assetfinder dnsgen mdbtools pocsuite3 masscan

	# Install Python3 pip
	web_pip="pyjwt arjun py-altdns pymultitor autosubtakeover crlfsuite ggshield selenium PyJWT proxyhub njsscan detect-secrets regexploit h8mail nodejsscan hashpumpy bhedak gitfive modelscan PyExfil wsgidav defaultcreds-cheat-sheet hiphp pasteme-cli aiodnsbrute semgrep wsrepl apachetomcatscanner dotdotfarm pymetasec theharvester chiasmodon puncia slither-analyzer"
	pip_installer "Web" "Penetration-Testing" "$web_pip"

	# Install Nodejs NPM
	web_npm="jwt-cracker graphql padding-oracle-attacker http-proxy-to-socks javascript-obfuscator serialize-javascript http-proxy-to-socks node-serialize igf electron-packager redos serialize-to-js dompurify nodesub multitor infoooze hardhat"
	npm_installer "Web" "Penetration-Testing" "$web_npm"

	# Install Ruby GEM
	web_gem="ssrf_proxy API_Fuzzer dawnscanner mechanize XSpear"
	gem_installer "Web" "Penetration-Testing" "$web_gem"

	# Install Golang
	web_golang="
go install github.com/Macmod/godap/v2@latest;ln -fs ~/go/bin/godap /usr/bin/godap
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
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest;ln -fs ~/go/bin/cvemap /usr/bin/cvemap
go install github.com/tomnomnom/gf@latest;ln -fs ~/go/bin/gf /usr/bin/gf
go install github.com/tomnomnom/gron@latest;ln -fs ~/go/bin/gron /usr/bin/gron
go install github.com/Hackmanit/TInjA@latest;ln -fs ~/go/bin/TInjA /usr/bin/tinja
go install github.com/moopinger/smugglefuzz@latest;ln -fs ~/go/bin/smugglefuzz /usr/bin/smugglefuzz
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
go install github.com/trap-bytes/gourlex@latest;ln -fs ~/go/bin/gourlex /usr/bin/gourlex
go install github.com/ThreatUnkown/jsubfinder@latest;ln -fs ~/go/bin/jsubfinder /usr/bin/jsubfinder
go install github.com/musana/fuzzuli@latest;ln -fs ~/go/bin/fuzzuli /usr/bin/fuzzuli
go install github.com/jaeles-project/jaeles@latest;ln -fs ~/go/bin/jaeles /usr/bin/jaeles
go install github.com/hakluke/haklistgen@latest;ln -fs ~/go/bin/haklistgen /usr/bin/haklistgen
go install github.com/tomnomnom/qsreplace@latest;ln -fs ~/go/bin/qsreplace /usr/bin/qsreplace
go install github.com/lc/subjs@latest;ln -fs ~/go/bin/subjs /usr/bin/subjs
go install github.com/dwisiswant0/unew@latest;ln -fs ~/go/bin/unew /usr/bin/unew
go install github.com/tomnomnom/unfurl@latest;ln -fs ~/go/bin/unfurl /usr/bin/unfurl
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest;ln -fs ~/go/bin/shuffledns /usr/bin/shuffledns
go install github.com/projectdiscovery/notify/cmd/notify@latest;ln -fs ~/go/bin/notify /usr/bin/notify
go install github.com/edoardottt/pphack/cmd/pphack@latest;ln -fs ~/go/bin/pphack /usr/bin/pphack
go install github.com/detectify/page-fetch@latest;ln -fs ~/go/bin/page-fetch /usr/bin/pagefetch
go install github.com/dwisiswant0/ipfuscator@latest;ln -fs ~/go/bin/ipfuscator /usr/bin/ipfuscator
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest;ln -fs ~/go/bin/tlsx /usr/bin/tlsx
go install github.com/projectdiscovery/useragent/cmd/ua@latest;ln -fs ~/go/bin/ua /usr/bin/ua
go install github.com/projectdiscovery/httpx/cmd/httpx@latest;ln -fs ~/go/bin/httpx /usr/bin/httpx
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest;ln -fs ~/go/bin/naabu /usr/bin/naabu
go install github.com/sensepost/gowitness@latest;ln -fs ~/go/bin/gowitness /usr/bin/gowitness
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest;ln -fs ~/go/bin/mapcidr /usr/bin/mapcidr"
	go_installer "Web" "Penetration-Testing" "$web_golang"

	CloudBunny="cloudbunny"
	if [ ! -d "/usr/share/$CloudBunny" ]; then
		git clone https://github.com/Warflop/CloudBunny /usr/share/$CloudBunny
		chmod 755 /usr/share/$CloudBunny/*
		cat > /usr/bin/$CloudBunny << EOF
#!/bin/bash
cd /usr/share/$CloudBunny;python3 cloudbunny.py "\$@"
EOF
		chmod +x /usr/bin/$CloudBunny
		pip3 install -r /usr/share/$CloudBunny/requirements.txt
		menu_entry "Web" "Penetration-Testing" "CloudBunny" "/usr/share/kali-menu/exec-in-shell '$CloudBunny -h'"
		printf "$GREEN"  "[*] Success Installing CloudBunny"
	else
		printf "$GREEN"  "[*] Success Installed CloudBunny"
	fi

	PhoneInfoga="phoneinfoga"
	if [ ! -d "/usr/share/$PhoneInfoga" ]; then
		mkdir -p /usr/share/$PhoneInfoga
		wget https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/$PhoneInfoga.tar.gz
		tar -xvf /tmp/$PhoneInfoga.tar.gz -C /usr/share/$PhoneInfoga;rm -f /tmp/$PhoneInfoga.tar.gz
		chmod 755 /usr/share/$PhoneInfoga/*
		ln -fs /usr/share/$PhoneInfoga/phoneinfoga /usr/bin/phoneinfoga
		chmod +x /usr/bin/phoneinfoga
		menu_entry "Web" "Penetration-Testing" "PhoneInfoga" "/usr/share/kali-menu/exec-in-shell 'sudo $PhoneInfoga -h'"
		printf "$GREEN"  "[*] Success Installing PhoneInfoga"
	else
		printf "$GREEN"  "[*] Success Installed PhoneInfoga"
	fi

	Postman="Postman"
	if [ ! -d "/usr/share/$Postman" ]; then
		mkdir -p /usr/share/$Postman
		wget https://dl.pstmn.io/download/latest/linux_64 -O /tmp/$Postman.tar.gz
		tar -xvf /tmp/$Postman.tar.gz -C /usr/share;rm -f /tmp/$Postman.tar.gz
		chmod 755 /usr/share/$Postman/*
		cat > /usr/bin/$Postman << EOF
#!/bin/bash
cd /usr/share/$Postman;./postman "\$@"
EOF
		chmod +x /usr/bin/postman
		menu_entry "Web" "Penetration-Testing" "Postman" "/usr/share/kali-menu/exec-in-shell 'postman'"
		printf "$GREEN"  "[*] Success Installing Postman"
	else
		printf "$GREEN"  "[*] Success Installed Postman"
	fi

	Findomain="findomain"
	if [ ! -d "/usr/share/$Findomain" ]; then
		wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -O /tmp/$Findomain.zip
		unzip /tmp/$Findomain.zip -d /usr/share/$Findomain;rm -f /tmp/$Findomain.zip
		chmod 755 /usr/share/$Findomain/*
		ln -fs /usr/share/$Findomain/findomain /usr/bin/$Findomain
		chmod +x /usr/bin/$Findomain
		menu_entry "Web" "Penetration-Testing" "Findomain" "/usr/share/kali-menu/exec-in-shell 'sudo $Findomain -h'"
		printf "$GREEN"  "[*] Success Installing Findomain"
	else
		printf "$GREEN"  "[*] Success Installed Findomain"
	fi

	RustScan="rustscan"
	if [ ! -f "/usr/bin/$RustScan" ]; then
		wget https://github.com/RustScan/RustScan/releases/download/2.2.3/rustscan_2.2.3_amd64.deb -O /tmp/$RustScan.deb
		chmod +x /tmp/$RustScan.deb;dpkg -i /tmp/$RustScan.deb;rm -f /tmp/$RustScan.deb
		menu_entry "Web" "Penetration-Testing" "RustScan" "/usr/share/kali-menu/exec-in-shell 'sudo $RustScan -h'"
		printf "$GREEN"  "[*] Success Installing RustScan"
	else
		printf "$GREEN"  "[*] Success Installed RustScan"
	fi

	HashPump="hashpump"
	if [ ! -d "/usr/share/hashpump" ]; then
		git clone https://github.com/mheistermann/HashPump-partialhash /usr/share/$HashPump
		chmod 755 /usr/share/$HashPump/*
		cd /usr/share/$HashPump;make;make install
		menu_entry "Web" "Penetration-Testing" "HashPump" "/usr/share/kali-menu/exec-in-shell 'sudo $HashPump -h'"
		printf "$GREEN"  "[*] Success Installing HashPump"
	else
		printf "$GREEN"  "[*] Success Installed HashPump"
	fi

	PixLoad="pixload"
	if [ ! -d "/usr/share/$PixLoad" ]; then
		git clone https://github.com/sighook/pixload /usr/share/$PixLoad
		chmod 755 /usr/share/$PixLoad/*
		cd /usr/share/$PixLoad;make install
		menu_entry "Web" "Penetration-Testing" "PixLoad" "/usr/share/kali-menu/exec-in-shell 'sudo $PixLoad-bmp --help'"
		printf "$GREEN"  "[*] Success Installing PixLoad"
	else
		printf "$GREEN"  "[*] Success Installed PixLoad"
	fi

	ReconFTW="reconftw"
	if [ ! -d "/usr/share/$ReconFTW" ]; then
		git clone https://github.com/six2dez/reconftw /usr/share/$ReconFTW
		chmod 755 /usr/share/$ReconFTW/*
		cat > /usr/bin/$ReconFTW << EOF
#!/bin/bash
cd /usr/share/$ReconFTW;./reconftw.sh "\$@"
EOF
		chmod +x /usr/bin/$ReconFTW
		cd /usr/share/$ReconFTW;./install.sh
		menu_entry "Web" "Penetration-Testing" "ReconFTW" "/usr/share/kali-menu/exec-in-shell '$ReconFTW -h'"
		printf "$GREEN"  "[*] Success Installing ReconFTW"
	else
		printf "$GREEN"  "[*] Success Installed ReconFTW"
	fi

	GoogleRecaptchaBypass="googlerecaptchabypass"
	if [ ! -d "/usr/share/$GoogleRecaptchaBypass" ]; then
		git clone https://github.com/sarperavci/GoogleRecaptchaBypass /usr/share/$GoogleRecaptchaBypass
		chmod 755 /usr/share/$GoogleRecaptchaBypass/*
		cat > /usr/bin/grb << EOF
#!/bin/bash
cd /usr/share/$GoogleRecaptchaBypass;python3 test.py "\$@"
EOF
		chmod +x /usr/bin/grb
		pip3 install -r /usr/share/$GoogleRecaptchaBypass/requirements.txt
		menu_entry "Web" "Penetration-Testing" "GoogleRecaptchaBypass" "/usr/share/kali-menu/exec-in-shell 'grb -h'"
		printf "$GREEN"  "[*] Success Installing GoogleRecaptchaBypass"
	else
		printf "$GREEN"  "[*] Success Installed GoogleRecaptchaBypass"
	fi

	graphw00f="graphw00f"
	if [ ! -d "/usr/share/$graphw00f" ]; then
		git clone https://github.com/dolevf/graphw00f /usr/share/$graphw00f
		chmod 755 /usr/share/$graphw00f/*
		cat > /usr/bin/$graphw00f << EOF
#!/bin/bash
cd /usr/share/$graphw00f;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$graphw00f
		menu_entry "Web" "Penetration-Testing" "graphw00f" "/usr/share/kali-menu/exec-in-shell '$graphw00f -h'"
		printf "$GREEN"  "[*] Success Installing graphw00f"
	else
		printf "$GREEN"  "[*] Success Installed graphw00f"
	fi

	Gel4y="gel4y"
	if [ ! -d "/usr/share/$Gel4y" ]; then
		git clone https://github.com/22XploiterCrew-Team/Gel4y-Mini-Shell-Backdoor /usr/share/$Gel4y
		chmod 755 /usr/share/$Gel4y/*
		cat > /usr/bin/$Gel4y << EOF
#!/bin/bash
cd /usr/share/$Gel4y;php gel4y.php "\$@"
EOF
		chmod +x /usr/bin/$Gel4y
		menu_entry "Web" "Penetration-Testing" "Gel4y" "/usr/share/kali-menu/exec-in-shell '$Gel4y -h'"
		printf "$GREEN"  "[*] Success Installing Gel4y"
	else
		printf "$GREEN"  "[*] Success Installed Gel4y"
	fi

	CloakQuest3r="cloakquest3r"
	if [ ! -d "/usr/share/$CloakQuest3r" ]; then
		git clone https://github.com/spyboy-productions/CloakQuest3r /usr/share/$CloakQuest3r
		chmod 755 /usr/share/$CloakQuest3r/*
		cat > /usr/bin/$CloakQuest3r << EOF
#!/bin/bash
cd /usr/share/$CloakQuest3r;python3 cloakquest3r.py "\$@"
EOF
		chmod +x /usr/bin/$CloakQuest3r
		pip3 install -r /usr/share/$CloakQuest3r/requirements.txt
		menu_entry "Web" "Penetration-Testing" "CloakQuest3r" "/usr/share/kali-menu/exec-in-shell '$CloakQuest3r -h'"
		printf "$GREEN"  "[*] Success Installing CloakQuest3r"
	else
		printf "$GREEN"  "[*] Success Installed CloakQuest3r"
	fi

	Asnlookup="asnlookup"
	if [ ! -d "/usr/share/$Asnlookup" ]; then
		git clone https://github.com/yassineaboukir/Asnlookup /usr/share/$Asnlookup
		chmod 755 /usr/share/$Asnlookup/*
		cat > /usr/bin/$Asnlookup << EOF
#!/bin/bash
cd /usr/share/$Asnlookup;python3 asnlookup.py "\$@"
EOF
		chmod +x /usr/bin/$Asnlookup
		pip3 install -r /usr/share/$Asnlookup/requirements.txt
		menu_entry "Web" "Penetration-Testing" "Asnlookup" "/usr/share/kali-menu/exec-in-shell '$Asnlookup -h'"
		printf "$GREEN"  "[*] Success Installing Asnlookup"
	else
		printf "$GREEN"  "[*] Success Installed Asnlookup"
	fi

	Waymore="waymore"
	if [ ! -d "/usr/share/$Waymore" ]; then
		git clone https://github.com/xnl-h4ck3r/waymore /usr/share/$Waymore
		chmod 755 /usr/share/$Waymore/*
		cat > /usr/bin/$Waymore << EOF
#!/bin/bash
cd /usr/share/$Waymore;python3 waymore.py "\$@"
EOF
		chmod +x /usr/bin/$Waymore
		pip3 install -r /usr/share/$Waymore/requirements.txt
		menu_entry "Web" "Penetration-Testing" "Waymore" "/usr/share/kali-menu/exec-in-shell '$Waymore -h'"
		printf "$GREEN"  "[*] Success Installing Waymore"
	else
		printf "$GREEN"  "[*] Success Installed Waymore"
	fi

	YsoSerial="ysoserial"
	if [ ! -d "/usr/share/$YsoSerial" ]; then
		mkdir -p /usr/share/$YsoSerial
		wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -O /usr/share/$YsoSerial/ysoserial-all.jar 
		chmod 755 /usr/share/$YsoSerial/*
		cat > /usr/bin/$YsoSerial << EOF
#!/bin/bash
cd /usr/share/$YsoSerial;java -jar ysoserial-all.jar "\$@"
EOF
		chmod +x /usr/bin/$YsoSerial
		menu_entry "Web" "Penetration-Testing" "YsoSerial" "/usr/share/kali-menu/exec-in-shell '$YsoSerial -h'"
		printf "$GREEN"  "[*] Success Installing YsoSerial"
	else
		printf "$GREEN"  "[*] Success Installed YsoSerial"
	fi

	YsoSerialnet="ysoserial.net"
	if [ ! -d "/usr/share/$YsoSerialnet" ]; then
		mkdir -p /usr/share/$YsoSerialnet
		wget https://github.com/pwntester/ysoserial.net/releases/latest/download/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip -O /tmp/$YsoSerialnet.zip
		unzip /tmp/$YsoSerialnet.zip -d /tmp;cd /tmp/Release;mv -f * /usr/share/$YsoSerialnet;rm -f /tmp/Release;rm -f /tmp/$YsoSerialnet.zip
		chmod 755 /usr/share/$YsoSerialnet/*
		cat > /usr/bin/$YsoSerialnet << EOF
#!/bin/bash
cd /usr/share/$YsoSerialnet;mono ysoserial.exe "\$@"
EOF
		chmod +x /usr/bin/$YsoSerialnet
		menu_entry "Web" "Penetration-Testing" "YsoSerial.net" "/usr/share/kali-menu/exec-in-shell '$YsoSerialnet -h'"
		printf "$GREEN"  "[*] Success Installing YsoSerial.net"
	else
		printf "$GREEN"  "[*] Success Installed YsoSerial.net"
	fi

	Akto="akto"
	if [ ! -d "/usr/share/$Akto" ]; then
		git clone https://github.com/akto-api-security/akto /usr/share/$Akto 
		chmod 755 /usr/share/$Akto/*
		cat > /usr/bin/$Akto << EOF
#!/bin/bash
cd /usr/share/$Akto;docker-compose up -d "\$@"
EOF
		chmod +x /usr/bin/$Akto
		menu_entry "Web" "Penetration-Testing" "Akto" "/usr/share/kali-menu/exec-in-shell '$Akto'"
		printf "$GREEN"  "[*] Success Installing Akto"
	else
		printf "$GREEN"  "[*] Success Installed Akto"
	fi

	RSAtool="rsatool"
	if [ ! -d "/usr/share/rsatool" ]; then
		git clone https://github.com/ius/rsatool /usr/share/$RSAtool
		chmod 755 /usr/share/$RSAtool/*
		cat > /usr/bin/$RSAtool << EOF
#!/bin/bash
cd /usr/share/$RSAtool;python3 rsatool.py "\$@"
EOF
		chmod +x /usr/bin/$RSAtool
		menu_entry "Web" "Penetration-Testing" "RSAtool" "/usr/share/kali-menu/exec-in-shell '$RSAtool -h'"
		printf "$GREEN"  "[*] Success Installing RSAtool"
	else
		printf "$GREEN"  "[*] Success Installed RSAtool"
	fi

	Polyglot="polyglot"
	if [ ! -d "/usr/share/$Polyglot" ]; then
		git clone https://github.com/Polydet/polyglot-database /usr/share/$Polyglot
		chmod 755 /usr/share/$Polyglot/files/*
		cat > /usr/bin/$Polyglot << EOF
#!/bin/bash
cd /usr/share/$Polyglot/files;ls "\$@"
EOF
		chmod +x /usr/bin/$Polyglot
		menu_entry "Web" "Penetration-Testing" "Polyglot" "/usr/share/kali-menu/exec-in-shell '$Polyglot -h'"
		printf "$GREEN"  "[*] Success Installing Polyglot"
	else
		printf "$GREEN"  "[*] Success Installed Polyglot"
	fi

	RsaCtfTool="rsactftool"
	if [ ! -d "/usr/share/$RsaCtfTool" ]; then
		git clone https://github.com/RsaCtfTool/RsaCtfTool /usr/share/$RsaCtfTool
		chmod 755 /usr/share/$RsaCtfTool/*
		cat > /usr/bin/$RsaCtfTool << EOF
#!/bin/bash
cd /usr/share/$RsaCtfTool;python3 RsaCtfTool.py "\$@"
EOF
		chmod +x /usr/bin/$RsaCtfTool
		menu_entry "Web" "Penetration-Testing" "RsaCtfTool" "/usr/share/kali-menu/exec-in-shell '$RsaCtfTool -h'"
		printf "$GREEN"  "[*] Success Installing RsaCtfTool"
	else
		printf "$GREEN"  "[*] Success Installed RsaCtfTool"
	fi

	DTDFinder="dtdfinder"
	if [ ! -d "/usr/share/$DTDFinder" ]; then
		mkdir -p /usr/share/$DTDFinder
		wget https://github.com/GoSecure/dtd-finder/releases/latest/download/dtd-finder-1.1-all.jar -O /usr/share/$DTDFinder/dtd-finder-all.jar
		chmod 755 /usr/share/$DTDFinder/*
		cat > /usr/bin/$DTDFinder << EOF
#!/bin/bash
cd /usr/share/$DTDFinder;java -jar dtd-finder-all.jar "\$@"
EOF
		chmod +x /usr/bin/$DTDFinder
		menu_entry "Web" "Penetration-Testing" "DTD-Finder" "/usr/share/kali-menu/exec-in-shell '$DTDFinder -h'"
		printf "$GREEN"  "[*] Success Installing DTD-Finder"
	else
		printf "$GREEN"  "[*] Success Installed DTD-Finder"
	fi

	Docem="docem"
	if [ ! -d "/usr/share/$Docem" ]; then
		git clone https://github.com/whitel1st/docem -O /usr/share/$Docem
		chmod 755 /usr/share/$Docem/*
		cat > /usr/bin/$Docem << EOF
#!/bin/bash
cd /usr/share/$Docem;python3 docem.py "\$@"
EOF
		chmod +x /usr/bin/$Docem
		pip3 install -r /usr/share/requirements.txt
		menu_entry "Web" "Penetration-Testing" "Docem" "/usr/share/kali-menu/exec-in-shell '$Docem -h'"
		printf "$GREEN"  "[*] Success Installing Docem"
	else
		printf "$GREEN"  "[*] Success Installed Docem"
	fi

	SpiderSuite="spidersuite"
	if [ ! -d "/usr/share/$SpiderSuite" ]; then
		wget https://github.com/3nock/SpiderSuite/releases/latest/download/SpiderSuite_v1.0.4_linux.AppImage -O /usr/share/$SpiderSuite/SpiderSuite_linux.AppImage
		chmod 755 /usr/share/$SpiderSuite/*
		cat > /usr/bin/$SpiderSuite << EOF
#!/bin/bash
cd /usr/share/$SpiderSuite;./SpiderSuite_linux.AppImage "\$@"
EOF
		chmod +x /usr/bin/$SpiderSuite
		menu_entry "Web" "Penetration-Testing" "SpiderSuite" "/usr/share/kali-menu/exec-in-shell '$SpiderSuite -h'"
		printf "$GREEN"  "[*] Success Installing SpiderSuite"
	else
		printf "$GREEN"  "[*] Success Installed SpiderSuite"
	fi

	Smuggle="smuggle"
	if [ ! -d "/usr/share/$Smuggle" ]; then
		git clone https://github.com/anshumanpattnaik/http-request-smuggling -O /usr/share/$Smuggle
		chmod 755 /usr/share/$Smuggle/*
		cat > /usr/bin/$Smuggle << EOF
#!/bin/bash
cd /usr/share/$Smuggle;python3 smuggle.py "\$@"
EOF
		chmod +x /usr/bin/$Smuggle
		pip3 install -r /usr/share/$Smuggle/requirements.txt
		menu_entry "Web" "Penetration-Testing" "Smuggle" "/usr/share/kali-menu/exec-in-shell '$Smuggle -h'"
		printf "$GREEN"  "[*] Success Installing Smuggle"
	else
		printf "$GREEN"  "[*] Success Installed Smuggle"
	fi

	PEMCrack="pemcrack"
	if [ ! -d "/usr/share/$PEMCrack" ]; then
		git clone https://github.com/robertdavidgraham/pemcrack /usr/share/$PEMCrack
		chmod 755 /usr/share/$PEMCrack/*
		cd /usr/share/$PEMCrack;gcc pemcrack.c -o pemcrack -lssl -lcrypto
		ln -fs /usr/share/$PEMCrack/pemcrack /usr/bin/$PEMCrack
		chmod +x /usr/bin/$PEMCrack
		menu_entry "Web" "Penetration-Testing" "PEMCrack" "/usr/share/kali-menu/exec-in-shell 'sudo $PEMCrack -h'"
		printf "$GREEN"  "[*] Success Installing PEMCrack"
	else
		printf "$GREEN"  "[*] Success Installed PEMCrack"
	fi

	SessionProbe="sessionprobe"
	if [ ! -d "/usr/share/$SessionProbe" ]; then
		mkdir -p /usr/share/$SessionProbe
		wget https://github.com/dub-flow/sessionprobe/releases/latest/download/sessionprobe-linux-amd64 -O /usr/share/$SessionProbe/sessionprobe
		chmod 755 /usr/share/$SessionProbe/*
		ln -fs /usr/share/$SessionProbe/sessionprobe /usr/bin/$SessionProbe
		chmod +x /usr/bin/$SessionProbe
		menu_entry "Web" "Penetration-Testing" "SessionProbe" "/usr/share/kali-menu/exec-in-shell '$SessionProbe -h'"
		printf "$GREEN"  "[*] Success Installing SessionProbe"
	else
		printf "$GREEN"  "[*] Success Installed SessionProbe"
	fi

	DyMerge="dymerge"
	if [ ! -d "/usr/share/$DyMerge" ]; then
		git clone https://github.com/k4m4/dymerge /usr/share/$DyMerge
		chmod 755 /usr/share/$DyMerge/*
		cat > /usr/bin/$DyMerge << EOF
#!/bin/bash
cd /usr/share/$DyMerge;python2 dymerge.py "\$@"
EOF
		chmod +x /usr/bin/$DyMerge
		menu_entry "Web" "Penetration-Testing" "DyMerge" "/usr/share/kali-menu/exec-in-shell '$DyMerge -h'"
		printf "$GREEN"  "[*] Success Installing DyMerge"
	else
		printf "$GREEN"  "[*] Success Installed DyMerge"
	fi

	SPartan="spartan"
	if [ ! -d "/usr/share/$SPartan" ]; then
		git clone https://github.com/sensepost/SPartan /usr/share/$SPartan
		chmod 755 /usr/share/$SPartan/*
		cat > /usr/bin/$SPartan << EOF
#!/bin/bash
cd /usr/share/$SPartan;python2 SPartan.py "\$@"
EOF
		chmod +x /usr/bin/$SPartan
		pip2 install -r /usr/share/$SPartan/requirements.txt
		menu_entry "Web" "Penetration-Testing" "SPartan" "/usr/share/kali-menu/exec-in-shell '$SPartan -h'"
		printf "$GREEN"  "[*] Success Installing SPartan"
	else
		printf "$GREEN"  "[*] Success Installed SPartan"
	fi

	WAFBypass="waf-bypass"
	if [ ! -d "/usr/share/$WAFBypass" ]; then
		git clone https://github.com/nemesida-waf/waf-bypass /usr/share/$WAFBypass
		chmod 755 /usr/share/$WAFBypass/*
		cat > /usr/bin/$WAFBypass << EOF
#!/bin/bash
cd /usr/share/$WAFBypass;python2 dymerge.py "\$@"
EOF
		chmod +x /usr/bin/$WAFBypass
		pip3 install -r /usr/share/$WAFBypass/requirements.txt
		python3 /usr/share/$WAFBypass/setup.py install
		menu_entry "Web" "Penetration-Testing" "WAFBypass" "/usr/share/kali-menu/exec-in-shell '$WAFBypass -h'"
		printf "$GREEN"  "[*] Success Installing WAFBypass"
	else
		printf "$GREEN"  "[*] Success Installed WAFBypass"
	fi

	XSSLOADER="xssloader"
	if [ ! -d "/usr/share/$XSSLOADER" ]; then
		git clone https://github.com/capture0x/XSS-LOADER /usr/share/$XSSLOADER
		chmod 755 /usr/share/$XSSLOADER/*
		cat > /usr/bin/$XSSLOADER << EOF
#!/bin/bash
cd /usr/share/$XSSLOADER;python3 payloader.py "\$@"
EOF
		chmod +x /usr/bin/$XSSLOADER
		pip3 install -r /usr/share/$XSSLOADER/requirements.txt
		menu_entry "Web" "Penetration-Testing" "XSS-LOADER" "/usr/share/kali-menu/exec-in-shell '$XSSLOADER -h'"
		printf "$GREEN"  "[*] Success Installing XSS-LOADER"
	else
		printf "$GREEN"  "[*] Success Installed XSS-LOADER"
	fi

	CMSeek="cmseek"
	if [ ! -d "/usr/share/$CMSeek" ]; then
		git clone https://github.com/Tuhinshubhra/CMSeeK /usr/share/$CMSeek
		chmod 755 /usr/share/$CMSeek/*
		cat > /usr/bin/$CMSeek << EOF
#!/bin/bash
cd /usr/share/$CMSeek;python3 cmseek.py "\$@"
EOF
		chmod +x /usr/bin/$CMSeek
		pip3 install -r /usr/share/$CMSeek/requirements.txt
		menu_entry "Web" "Penetration-Testing" "CMSeek" "/usr/share/kali-menu/exec-in-shell '$CMSeek -h'"
		printf "$GREEN"  "[*] Success Installing CMSeek"
	else
		printf "$GREEN"  "[*] Success Installed CMSeek"
	fi

	XSStrike="xsstrike"
	if [ ! -d "/usr/share/$XSStrike" ]; then
		git clone https://github.com/s0md3v/XSStrike /usr/share/$XSStrike
		chmod 755 /usr/share/$XSStrike/*
		cat > /usr/bin/$XSStrike << EOF
#!/bin/bash
cd /usr/share/$XSStrike;python3 xsstrike.py "\$@"
EOF
		chmod +x /usr/bin/$XSStrike
		pip3 install -r /usr/share/$XSStrike/requirements.txt
		menu_entry "Web" "Penetration-Testing" "XSStrike" "/usr/share/kali-menu/exec-in-shell '$XSStrike -h'"
		printf "$GREEN"  "[*] Success Installing XSStrike"
	else
		printf "$GREEN"  "[*] Success Installed XSStrike"
	fi

	w4af="w4af"
	if [ ! -d "/usr/share/$w4af" ]; then
		git clone https://github.com/w4af/w4af /usr/share/$w4af
		chmod 755 /usr/share/$w4af/*
		cat > /usr/bin/$w4af << EOF
#!/bin/bash
cd /usr/share/$w4af;pipenv shell;./w4af_console "\$@"
EOF
		chmod +x /usr/bin/$w4af
		cd /usr/share/$w4af;pipenv install;npm install
		menu_entry "Web" "Penetration-Testing" "w4af" "/usr/share/kali-menu/exec-in-shell '$w4af'"
		printf "$GREEN"  "[*] Success Installing w4af"
	else
		printf "$GREEN"  "[*] Success Installed w4af"
	fi

	JWTTool="jwt_tool"
	if [ ! -d "/usr/share/$JWTTool" ]; then
		git clone https://github.com/ticarpi/jwt_tool /usr/share/$JWTTool
		chmod 755 /usr/share/$JWTTool/*
		cat > /usr/bin/$JWTTool << EOF
#!/bin/bash
cd /usr/share/$JWTTool;python3 jwt_tool.py "\$@"
EOF
		chmod +x /usr/bin/$JWTTool
		menu_entry "Web" "Penetration-Testing" "JWTTool" "/usr/share/kali-menu/exec-in-shell '$JWTTool -h'"
		printf "$GREEN"  "[*] Success Installing JWTTool"
	else
		printf "$GREEN"  "[*] Success Installed JWTTool"
	fi

	Tplmap="tplmap"
	if [ ! -d "/usr/share/$Tplmap" ]; then
		git clone https://github.com/epinna/tplmap /usr/share/$Tplmap
		chmod 755 /usr/share/$Tplmap/*
		cat > /usr/bin/$Tplmap << EOF
#!/bin/bash
cd /usr/share/$Tplmap;python3 tplmap.py "\$@"
EOF
		chmod +x /usr/bin/$Tplmap
		pip3 install -r /usr/share/$Tplmap/requirements.txt
		menu_entry "Web" "Penetration-Testing" "Tplmap" "/usr/share/kali-menu/exec-in-shell '$Tplmap -h'"
		printf "$GREEN"  "[*] Success Installing Tplmap"
	else
		printf "$GREEN"  "[*] Success Installed Tplmap"
	fi

	SSTImap="sstimap"
	if [ ! -d "/usr/share/$SSTImap" ]; then
		git clone https://github.com/vladko312/SSTImap /usr/share/$SSTImap
		chmod 755 /usr/share/$SSTImap/*
		cat > /usr/bin/$SSTImap << EOF
#!/bin/bash
cd /usr/share/$SSTImap;python3 sstimap.py "\$@"
EOF
		chmod +x /usr/bin/$SSTImap
		pip3 install -r /usr/share/$SSTImap/requirements.txt
		menu_entry "Web" "Penetration-Testing" "SSTImap" "/usr/share/kali-menu/exec-in-shell '$SSTImap -h'"
		printf "$GREEN"  "[*] Success Installing SSTImap"
	else
		printf "$GREEN"  "[*] Success Installed SSTImap"
	fi

	Poodle="poodle"
	if [ ! -d "/usr/share/$Poodle" ]; then
		git clone https://github.com/mpgn/poodle-PoC /usr/share/$Poodle
		chmod 755 /usr/share/$Poodle/*
		cat > /usr/bin/$Poodle << EOF
#!/bin/bash
cd /usr/share/$Poodle;python3 poodle-exploit.py "\$@"
EOF
		chmod +x /usr/bin/$Poodle
		menu_entry "Web" "Penetration-Testing" "Poodle" "/usr/share/kali-menu/exec-in-shell '$Poodle -h'"
		printf "$GREEN"  "[*] Success Installing Poodle"
	else
		printf "$GREEN"  "[*] Success Installed Poodle"
	fi

	Gopherus="gopherus"
	if [ ! -d "/usr/share/$Gopherus" ]; then
		git clone https://github.com/tarunkant/Gopherus /usr/share/$Gopherus
		chmod 755 /usr/share/$Gopherus/*
		cat > /usr/bin/$Gopherus << EOF
#!/bin/bash
cd /usr/share/$Gopherus;python2 gopherus.py "\$@"
EOF
		chmod +x /usr/bin/$Gopherus
		menu_entry "Web" "Penetration-Testing" "Gopherus" "/usr/share/kali-menu/exec-in-shell '$Gopherus -h'"
		printf "$GREEN"  "[*] Success Installing Gopherus"
	else
		printf "$GREEN"  "[*] Success Installed Gopherus"
	fi

	HashExtender="hashextender"
	if [ ! -d "/usr/share/$HashExtender" ]; then
		git clone https://github.com/iagox86/hash_extender /usr/share/$HashExtender
		chmod 755 /usr/share/$HashExtender/*
		cd /usr/share/$HashExtender;make
		ln -fs /usr/share/$HashExtender/hashextender /usr/bin/$HashExtender
		chmod +x /usr/bin/$HashExtender
		menu_entry "Web" "Penetration-Testing" "HashExtender" "/usr/share/kali-menu/exec-in-shell 'sudo $HashExtender -h'"
		printf "$GREEN"  "[*] Success Installing HashExtender"
	else
		printf "$GREEN"  "[*] Success Installed HashExtender"
	fi

	SpoofCheck="spoofcheck"
	if [ ! -d "/usr/share/$SpoofCheck" ]; then
		git clone https://github.com/BishopFox/spoofcheck /usr/share/$SpoofCheck
		chmod 755 /usr/share/$SpoofCheck/*
		cat > /usr/bin/$SpoofCheck << EOF
#!/bin/bash
cd /usr/share/$SpoofCheck;python2 spoofcheck.py "\$@"
EOF
		chmod +x /usr/bin/$SpoofCheck
		pip2 install -r /usr/share/$SpoofCheck/requirements.txt
		menu_entry "Web" "Penetration-Testing" "SpoofCheck" "/usr/share/kali-menu/exec-in-shell '$SpoofCheck -h'"
		printf "$GREEN"  "[*] Success Installing SpoofCheck"
	else
		printf "$GREEN"  "[*] Success Installed SpoofCheck"
	fi

	REDHAWK="redhawk"
	if [ ! -d "/usr/share/$REDHAWK" ]; then
		git clone https://github.com/Tuhinshubhra/RED_HAWK /usr/share/$REDHAWK
		chmod 755 /usr/share/$REDHAWK/*
		cat > /usr/bin/$REDHAWK << EOF
#!/bin/bash
cd /usr/share/$REDHAWK;php rhawk.php "\$@"
EOF
		chmod +x /usr/bin/$REDHAWK
		menu_entry "Web" "Penetration-Testing" "RED_HAWK" "/usr/share/kali-menu/exec-in-shell '$REDHAWK -h'"
		printf "$GREEN"  "[*] Success Installing RED_HAWK"
	else
		printf "$GREEN"  "[*] Success Installed RED_HAWK"
	fi

	Ngrok="ngrok"
	if [ ! -f "/usr/bin/$Ngrok" ]; then
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/$Ngrok.tgz
		tar -xvf /tmp/$Ngrok.tgz -C /usr/bin;rm -f /tmp/$Ngrok.tgz
		chmod +x /usr/bin/$Ngrok
		menu_entry "Web" "Penetration-Testing" "Ngrok" "/usr/share/kali-menu/exec-in-shell '$Ngrok -h'"
		printf "$GREEN"  "[*] Success Installing Ngrok"
	else
		printf "$GREEN"  "[*] Success Installed Ngrok"
	fi

	NoIP="noip"
	if [ ! -f "/usr/local/bin/noip2" ]; then
		mkdir -p /usr/share/$NoIP
		wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/$NoIP.tar.gz
		tar -xzf /tmp/$NoIP.tar.gz -C /usr/share/$NoIP;rm -f /tmp/$NoIP.tar.gz
		chmod 755 /usr/share/$NoIP/*;cd /usr/share/$NoIP;make;make install
		menu_entry "Web" "Penetration-Testing" "NoIP" "/usr/share/kali-menu/exec-in-shell '$NoIP -h'"
		printf "$GREEN"  "[*] Success Installing NoIP"
	else
		printf "$GREEN"  "[*] Success Installed NoIP"
	fi

	Breacher="breacher"
	if [ ! -d "/usr/share/$Breacher" ]; then
		git clone https://github.com/s0md3v/Breacher /usr/share/$Breacher
		chmod 755 /usr/share/$Breacher/*
		cat > /usr/bin/$Breacher << EOF
#!/bin/bash
cd /usr/share/$Breacher;python3 breacher.py "\$@"
EOF
		chmod +x /usr/bin/$Breacher
		menu_entry "Web" "Penetration-Testing" "Breacher" "/usr/share/kali-menu/exec-in-shell '$Breacher -h'"
		printf "$GREEN"  "[*] Success Installing Breacher"
	else
		printf "$GREEN"  "[*] Success Installed Breacher"
	fi

	SWFTools="swftools"
	if [ ! -d "/usr/share/$SWFTools" ]; then
		git clone https://github.com/matthiaskramm/swftools /usr/share/$SWFTools
		chmod 755 /usr/share/$SWFTools/*
		wget https://zlib.net/current/zlib.tar.gz -O /tmp/zlib.tar.gz
		tar -xvf /tmp/zlib.tar.gz -C /usr/share/$SWFTools;rm -f /tmp/zlib.tar.gz
		cd /usr/share/$SWFTools/zlib-*;./configure
		cd /usr/share/$SWFTools;./configure
		cd /usr/share/$SWFTools/lib;make
		cd /usr/share/$SWFTools/src;make;make install
		wget https://snapshot.debian.org/archive/debian/20130611T160143Z/pool/main/m/mtasc/mtasc_1.14-3_amd64.deb -O /tmp/mtasc_amd64.deb;chmod +x /tmp/mtasc_amd64.deb;dpkg -i /tmp/mtasc_amd64.deb;rm -f /tmp/mtasc_amd64.deb
		menu_entry "Web" "Penetration-Testing" "mtasc" "/usr/share/kali-menu/exec-in-shell 'mtasc -h'"
		menu_entry "Web" "Penetration-Testing" "swfdump" "/usr/share/kali-menu/exec-in-shell 'swfdump -h'"
		menu_entry "Web" "Penetration-Testing" "swfcombine" "/usr/share/kali-menu/exec-in-shell 'swfcombine -h'"
		printf "$GREEN"  "[*] Success Installing SWFTools"
	else
		printf "$GREEN"  "[*] Success Installed SWFTools"
	fi

	NoSQLMap="nosqlmap"
	if [ ! -d "/usr/share/$NoSQLMap" ]; then
		git clone https://github.com/codingo/NoSQLMap /usr/share/$NoSQLMap
		chmod 755 /usr/share/$NoSQLMap/*
		cat > /usr/bin/$NoSQLMap << EOF
#!/bin/bash
cd /usr/share/$NoSQLMap;python2 nosqlmap.py "\$@"
EOF
		chmod +x /usr/bin/$NoSQLMap
		cd /usr/share/$NoSQLMap;python2 nosqlmap.py install;pip2 install couchdb
		menu_entry "Web" "Penetration-Testing" "NoSQLMap" "/usr/share/kali-menu/exec-in-shell '$NoSQLMap -h'"
		printf "$GREEN"  "[*] Success Installing NoSQLMap"
	else
		printf "$GREEN"  "[*] Success Installed NoSQLMap"
	fi


	printf "$YELLOW"  "# ------------------------------------Mobile-Penetration-Testing------------------------------------- #"
	# Install Repository Tools
	apt install -qy jd-gui adb apksigner apktool android-tools-adb jadx 

	# Install Python3 pip
	mobile_pip="frida-tools objection mitmproxy reflutter androguard apkleaks mvt kiwi androset quark-engine gplaycli"
	pip_installer "Mobile" "Penetration-Testing" "$mobile_pip"

	# Install Nodejs NPM
	mobile_npm="rms-runtime-mobile-security apk-mitm igf bagbak"
	npm_installer "Mobile" "Penetration-Testing" "$mobile_npm"

	# Install Ruby GEM
	mobile_gem="jwt-cracker"
	gem_installer "Mobile" "Penetration-Testing" "$mobile_gem"

	# Install Golang
	mobile_golang="
go install github.com/ndelphit/apkurlgrep@latest;ln -fs ~/go/bin/apkurlgrep /usr/bin/apkurlgrep"
	go_installer "Mobile" "Penetration-Testing" "$mobile_golang"

	Genymotion="genymotion"
	if [ ! -d "/opt/genymobile/$Genymotion" ]; then
		wget https://dl.genymotion.com/releases/genymotion-3.6.0/genymotion-3.6.0-linux_x64.bin -O /tmp/$Genymotion.bin
		chmod 755 /tmp/$Genymotion.bin;cd /tmp;./$Genymotion.bin -y;rm -f /tmp/$Genymotion.bin
		printf "$GREEN"  "[*] Success Installing Genymotion"
	else
		printf "$GREEN"  "[*] Success Installed Genymotion"
	fi

	MobSF="mobsf"
	if [ ! -d "/usr/share/$MobSF" ]; then
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /usr/share/$MobSF
		wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb -O /tmp/wkhtmltox.deb
		chmod +x /tmp/wkhtmltox.deb;dpkg -i /tmp/wkhtmltox.deb;rm -f /tmp/wkhtmltox.deb
		chmod 755 /usr/share/$MobSF/*
		cat > /usr/bin/$MobSF << EOF
#!/bin/bash
cd /usr/share/$MobSF;./run.sh > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &
EOF
		chmod +x /usr/bin/$MobSF
		cd /usr/share/$MobSF;./setup.sh
		menu_entry "Mobile" "Penetration-Testing" "MobSF" "/usr/share/kali-menu/exec-in-shell '$MobSF'"
		printf "$GREEN"  "[*] Success Installing MobSF"
	else
		printf "$GREEN"  "[*] Success Installed MobSF"
	fi


	printf "$YELLOW"  "# ------------------------------------Cloud-Penetration-Testing-------------------------------------- #"
	# Install Repository Tools
	apt install -qy awscli trivy 

	# Install Python3 pip
	cloud_pip="sceptre aclpwn powerpwn ggshield pacu whispers s3scanner roadrecon roadlib gcp_scanner roadtx festin cloudsplaining c7n trailscraper lambdaguard airiam access-undenied-aws n0s1 aws-gate cloudscraper acltoolkit-ad prowler bloodhound aiodnsbrute gorilla-cli knowsmore checkov scoutsuite endgame"
	pip_installer "Cloud" "Penetration-Testing" "$cloud_pip"

	# Install Nodejs NPM
	cloud_npm="fleetctl"
	npm_installer "Cloud" "Penetration-Testing" "$cloud_npm"

	# Install Ruby GEM
	cloud_gem="aws_public_ips aws_security_viz aws_recon"
	gem_installer "Cloud" "Penetration-Testing" "$cloud_gem"

	# Install Golang
	cloud_golang="
go install github.com/koenrh/s3enum@latest;ln -fs ~/go/bin/s3enum /usr/bin/s3enum
go install github.com/smiegles/mass3@latest;ln -fs ~/go/bin/mass3 /usr/bin/mass3
go install github.com/magisterquis/s3finder@latest;ln -fs ~/go/bin/s3finder /usr/bin/s3finder
go install github.com/Macmod/goblob@latest;ln -fs ~/go/bin/goblob /usr/bin/goblob
go install github.com/g0ldencybersec/CloudRecon@latest;ln -fs ~/go/bin/CloudRecon /usr/bin/cloudrecon
go install github.com/BishopFox/cloudfox@latest;ln -fs ~/go/bin/cloudfox /usr/bin/cloudfox"
	go_installer "Cloud" "Penetration-Testing" "$cloud_golang"

	CloudFail="cloudfail"
	if [ ! -d "/usr/share/$CloudFail" ]; then
		git clone https://github.com/m0rtem/CloudFail /usr/share/$CloudFail
		chmod 755 /usr/share/$CloudFail/*
		cat > /usr/bin/$CloudFail << EOF
#!/bin/bash
cd /usr/share/$CloudFail;python3 cloudfail.py "\$@"
EOF
		chmod +x /usr/bin/$CloudFail
		pip3 install -r /usr/share/$CloudFail/requirements.txt
		menu_entry "Cloud" "Penetration-Testing" "CloudFail" "/usr/share/kali-menu/exec-in-shell '$CloudFail -h'"
		printf "$GREEN"  "[*] Success Installing CloudFail"
	else
		printf "$GREEN"  "[*] Success Installed CloudFail"
	fi

	CCAT="ccat"
	if [ ! -d "/usr/share/$CCAT" ]; then
		git clone https://github.com/RhinoSecurityLabs/ccat /usr/share/$CCAT
		chmod 755 /usr/share/$CCAT/*
		cat > /usr/bin/$CCAT << EOF
#!/bin/bash
cd /usr/share/$CCAT;python3 ccat.py "\$@"
EOF
		chmod +x /usr/bin/$CCAT
		cd /usr/share/$CCAT;python3 setup.py install
		menu_entry "Cloud" "Penetration-Testing" "CCAT" "/usr/share/kali-menu/exec-in-shell '$CCAT -h'"
		printf "$GREEN"  "[*] Success Installing CCAT"
	else
		printf "$GREEN"  "[*] Success Installed CCAT"
	fi

	CloudHunter="cloudhunter"
	if [ ! -d "/usr/share/$CloudHunter" ]; then
		git clone https://github.com/belane/CloudHunter /usr/share/$CloudHunter
		chmod 755 /usr/share/$CloudHunter/*
		cat > /usr/bin/$CloudHunter << EOF
#!/bin/bash
cd /usr/share/$CloudHunter;python3 cloudhunter.py "\$@"
EOF
		chmod +x /usr/bin/$CloudHunter
		pip3 install -r /usr/share/$CloudHunter/requirements.txt
		menu_entry "Cloud" "Penetration-Testing" "CloudHunter" "/usr/share/kali-menu/exec-in-shell '$CloudHunter -h'"
		printf "$GREEN"  "[*] Success Installing CloudHunter"
	else
		printf "$GREEN"  "[*] Success Installed CloudHunter"
	fi

	GCPBucketBrute="gcpbucketbrute"
	if [ ! -d "/usr/share/$GCPBucketBrute" ]; then
		git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute /usr/share/$GCPBucketBrute
		chmod 755 /usr/share/$GCPBucketBrute/*
		cat > /usr/bin/$GCPBucketBrute << EOF
#!/bin/bash
cd /usr/share/$GCPBucketBrute;python3 cloudhunter.py "\$@"
EOF
		chmod +x /usr/bin/$GCPBucketBrute
		pip3 install -r /usr/share/$GCPBucketBrute/requirements.txt
		menu_entry "Cloud" "Penetration-Testing" "GCPBucketBrute" "/usr/share/kali-menu/exec-in-shell '$GCPBucketBrute -h'"
		printf "$GREEN"  "[*] Success Installing GCPBucketBrute"
	else
		printf "$GREEN"  "[*] Success Installed GCPBucketBrute"
	fi

	k8sgpt="k8sgpt"
	if [ ! -d "/usr/share/$k8sgpt" ]; then
		wget https://github.com/k8sgpt-ai/k8sgpt/releases/latest/download/k8sgpt_amd64.deb -O /tmp/$k8sgpt.deb
		chmod +x /tmp/$k8sgpt.deb;dpkg -i /tmp/$k8sgpt.deb;rm -f /tmp/$k8sgpt.deb
		printf "$GREEN"  "[*] Success Installing k8sgpt"
	else
		printf "$GREEN"  "[*] Success Installed k8sgpt"
	fi

	CloudQuery="cloudquery"
	if [ ! -d "/usr/share/$CloudQuery" ]; then
		mkdir -p /usr/share/$CloudQuery
		wget https://github.com/cloudquery/cloudquery/releases/latest/download/cloudquery_linux_amd64 -O /usr/share/$CloudQuery/cloudquery
		chmod 755 /usr/share/$CloudQuery/*
		ln -fs /usr/share/$CloudQuery/cloudquery /usr/bin/$CloudQuery
		chmod +x /usr/bin/$CloudQuery
		menu_entry "Cloud" "Penetration-Testing" "CloudQuery" "/usr/share/kali-menu/exec-in-shell '$CloudQuery -h'"
		printf "$GREEN"  "[*] Success Installing CloudQuery"
	else
		printf "$GREEN"  "[*] Success Installed CloudQuery"
	fi


	printf "$YELLOW"  "# -----------------------------------Network-Penetration-Testing------------------------------------- #"
	# Install Repository Tools
	apt install -qy cme amap bettercap dsniff arpwatch sslstrip sherlock parsero routersploit tcpxtract slowhttptest dnsmasq sshuttle haproxy smb4k pptpd xplico dosbox lldb zmap checksec kerberoast etherape ismtp ismtp privoxy ident-user-enum goldeneye oclgausscrack multiforcer crowbar brutespray isr-evilgrade smtp-user-enum proxychains pigz gdb isc-dhcp-server firewalk bing-ip2hosts sipvicious netstress tcptrack tnscmd10g darkstat naabu cyberchef nbtscan sslscan wireguard nasm ropper above 

	# Install Python3 pip
	network_pip="networkx ropper mitmproxy mitm6 pymultitor scapy slowloris brute raccoon-scanner baboossh ciphey zeratool impacket aiodnsbrute ssh-mitm ivre angr angrop boofuzz ropgadget pwntools capstone atheris iac-scan-runner"
	pip_installer "Network" "Penetration-Testing" "$network_pip"

	# Install Nodejs NPM
	network_npm="http-proxy-to-socks multitor"
	npm_installer "Network" "Penetration-Testing" "$network_npm"

	# Install Ruby GEM
	network_gem="seccomp-tools one_gadget"
	npm_installer "Network" "Penetration-Testing" "$network_gem"

	# Install Golang
	network_golang="
go install github.com/s-rah/onionscan@latest;ln -fs ~/go/bin/onionscan /usr/bin/onionscan"
	go_installer "Network" "Penetration-Testing" "$network_golang"

	Hiddify="hiddify"
	if [ ! -d "/usr/share/$Hiddify" ]; then
		wget https://github.com/hiddify/hiddify-next/releases/latest/download/Hiddify-Debian-x64.deb -O /tmp/$Hiddify.deb
		chmod +x /tmp/$Hiddify.deb;dpkg -i /tmp/$Hiddify.deb;rm -f /tmp/$Hiddify.deb
		printf "$GREEN"  "[*] Success Installing Hiddify"
	else
		printf "$GREEN"  "[*] Success Installed Hiddify"
	fi

	SNMPBrute="snmpbrute"
	if [ ! -d "/usr/share/$SNMPBrute" ]; then
		git clone https://github.com/SECFORCE/SNMP-Brute /usr/share/$SNMPBrute
		chmod 755 /usr/share/$SNMPBrute/*
		cat > /usr/bin/$SNMPBrute << EOF
#!/bin/bash
cd /usr/share/$SNMPBrute;python3 snmpbrute.py "\$@"
EOF
		chmod +x /usr/bin/$SNMPBrute
		menu_entry "Network" "Penetration-Testing" "SNMPBrute" "/usr/share/kali-menu/exec-in-shell '$SNMPBrute -h'"
		printf "$GREEN"  "[*] Success Installing SNMPBrute"
	else
		printf "$GREEN"  "[*] Success Installed SNMPBrute"
	fi

	Sippts="sippts"
	if [ ! -d "/usr/share/$Sippts" ]; then
		git clone https://github.com/Pepelux/sippts /usr/share/$Sippts
		chmod 755 /usr/share/$Sippts/*
		pip3 install -r /usr/share/$Sippts/requirements.txt
		cd /usr/share/$Sippts;python3 setup.py install
		menu_entry "Network" "Penetration-Testing" "rtcpbleed" "/usr/share/kali-menu/exec-in-shell 'rtcpbleed -h'"
		menu_entry "Network" "Penetration-Testing" "rtpbleed" "/usr/share/kali-menu/exec-in-shell 'rtpbleed -h'"
		menu_entry "Network" "Penetration-Testing" "rtpbleedflood" "/usr/share/kali-menu/exec-in-shell 'rtpbleedflood -h'"
		menu_entry "Network" "Penetration-Testing" "rtpbleedinject" "/usr/share/kali-menu/exec-in-shell 'rtpbleedinject -h'"
		menu_entry "Network" "Penetration-Testing" "sipdigestcrack" "/usr/share/kali-menu/exec-in-shell 'sipdigestcrack -h'"
		menu_entry "Network" "Penetration-Testing" "sipdigestleak" "/usr/share/kali-menu/exec-in-shell 'sipdigestleak -h'"
		menu_entry "Network" "Penetration-Testing" "sipenumerate" "/usr/share/kali-menu/exec-in-shell 'sipenumerate -h'"
		menu_entry "Network" "Penetration-Testing" "sipexten" "/usr/share/kali-menu/exec-in-shell 'sipexten -h'"
		menu_entry "Network" "Penetration-Testing" "sipflood" "/usr/share/kali-menu/exec-in-shell 'sipflood -h'"
		menu_entry "Network" "Penetration-Testing" "sipfuzzer" "/usr/share/kali-menu/exec-in-shell 'sipfuzzer -h'"
		menu_entry "Network" "Penetration-Testing" "sipinvite" "/usr/share/kali-menu/exec-in-shell 'sipinvite -h'"
		menu_entry "Network" "Penetration-Testing" "sippcapdump" "/usr/share/kali-menu/exec-in-shell 'sippcapdump -h'"
		menu_entry "Network" "Penetration-Testing" "sipping" "/usr/share/kali-menu/exec-in-shell 'sipping -h'"
		menu_entry "Network" "Penetration-Testing" "siprcrack" "/usr/share/kali-menu/exec-in-shell 'siprcrack -h'"
		menu_entry "Network" "Penetration-Testing" "sipscan" "/usr/share/kali-menu/exec-in-shell 'sipscan -h'"
		menu_entry "Network" "Penetration-Testing" "sipsend" "/usr/share/kali-menu/exec-in-shell 'sipsend -h'"
		menu_entry "Network" "Penetration-Testing" "sipsniff" "/usr/share/kali-menu/exec-in-shell 'sipsniff -h'"
		menu_entry "Network" "Penetration-Testing" "siptshark" "/usr/share/kali-menu/exec-in-shell 'siptshark -h'"
		menu_entry "Network" "Penetration-Testing" "wssend" "/usr/share/kali-menu/exec-in-shell 'wssend -h'"
		printf "$GREEN"  "[*] Success Installing Sippts"
	else
		printf "$GREEN"  "[*] Success Installed Sippts"
	fi

	RouterScan="routerscan"
	if [ ! -d "/usr/share/$RouterScan" ]; then
		mkdir -p /usr/share/$RouterScan
		wget http://msk1.stascorp.com/routerscan/prerelease.7z -O /usr/share/$RouterScan/prerelease.7z
		chmod 755 /usr/share/$RouterScan/*
		cd /usr/share/$RouterScan;7z x prerelease.7z;rm -f prerelease.7z
		cat > /usr/bin/$RouterScan << EOF
#!/bin/bash
cd /usr/share/$RouterScan;wine RouterScan.exe "\$@"
EOF
		chmod +x /usr/bin/$RouterScan
		menu_entry "Network" "Penetration-Testing" "RouterScan" "/usr/share/kali-menu/exec-in-shell '$RouterScan'"
		printf "$GREEN"  "[*] Success Installing RouterScan"
	else
		printf "$GREEN"  "[*] Success Installed RouterScan"
	fi

	PRET="pret"
	if [ ! -d "/usr/share/$PRET" ]; then
		git clone https://github.com/RUB-NDS/PRET /usr/share/$PRET
		chmod 755 /usr/share/$PRET/*
		cat > /usr/bin/$PRET << EOF
#!/bin/bash
cd /usr/share/$PRET;python3 pret.py "\$@"
EOF
		chmod +x /usr/bin/$PRET
		menu_entry "Network" "Penetration-Testing" "PRET" "/usr/share/kali-menu/exec-in-shell '$PRET -h'"
		printf "$GREEN"  "[*] Success Installing PRET"
	else
		printf "$GREEN"  "[*] Success Installed PRET"
	fi

	Geneva="geneva"
	if [ ! -d "/usr/share/$Geneva" ]; then
		git clone https://github.com/Kkevsterrr/geneva /usr/share/$Geneva
		chmod 755 /usr/share/$Geneva/*
		cat > /usr/bin/$Geneva << EOF
#!/bin/bash
cd /usr/share/$Geneva;python3 engine.py "\$@"
EOF
		chmod +x /usr/bin/$Geneva
		pip3 install -r /usr/share/$Geneva/requirements.txt
		menu_entry "Network" "Penetration-Testing" "Geneva" "/usr/share/kali-menu/exec-in-shell '$Geneva -h'"
		printf "$GREEN"  "[*] Success Installing Geneva"
	else
		printf "$GREEN"  "[*] Success Installed Geneva"
	fi

	GEF="gef"
	if [ ! -f "~/.gef-2024.01.py" ]; then
		bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
		menu_entry "Network" "Penetration-Testing" "GEF" "/usr/share/kali-menu/exec-in-shell '$GEF'"
		printf "$GREEN"  "[*] Success Installing GEF"
	else
		printf "$GREEN"  "[*] Success Installed GEF"
	fi

	IPscan="ipscan"
	if [ ! -f "/usr/bin/$IPscan" ]; then
		wget https://github.com/angryip/ipscan/releases/latest/download/ipscan_3.9.1_amd64.deb -O /tmp/$IPscan.deb
		chmod +x /tmp/$IPscan.deb;dpkg -i /tmp/$IPscan.deb;rm -f /tmp/$IPscan.deb
		printf "$GREEN"  "[*] Success Installing IPscan"
	else
		printf "$GREEN"  "[*] Success Installed IPscan"
	fi

	Fetch="fetch"
	if [ ! -d "/usr/share/$Fetch" ]; then
		git clone https://github.com/stamparm/fetch-some-proxies /usr/share/$Fetch
		chmod 755 /usr/share/$Fetch/*
		cat > /usr/bin/fetch << EOF
#!/bin/bash
cd /usr/share/$Fetch;python3 fetch.py "\$@"
EOF
		chmod +x /usr/bin/$Fetch
		menu_entry "Network" "Penetration-Testing" "Fetch" "/usr/share/kali-menu/exec-in-shell '$Fetch -h'"
		printf "$GREEN"  "[*] Success Installing Fetch"
	else
		printf "$GREEN"  "[*] Success Installed Fetch"
	fi

	SIETpy3="sietpy3"
	if [ ! -d "/usr/share/$SIETpy3" ]; then
		git clone https://github.com/Sab0tag3d/SIETpy3 /usr/share/$SIETpy3
		chmod 755 /usr/share/$SIETpy3/*
		cat > /usr/bin/$SIETpy3 << EOF
#!/bin/bash
cd /usr/share/$SIETpy3;python3 siet.py "\$@"
EOF
		chmod +x /usr/bin/$SIETpy3
		menu_entry "Network" "Penetration-Testing" "SIETpy3" "/usr/share/kali-menu/exec-in-shell '$SIETpy3 -h'"
		printf "$GREEN"  "[*] Success Installing SIETpy3"
	else
		printf "$GREEN"  "[*] Success Installed SIETpy3"
	fi

	Memcrashed="memcrashed"
	if [ ! -d "/usr/share/$Memcrashed" ]; then
		git clone https://github.com/649/Memcrashed-DDoS-Exploit /usr/share/$Memcrashed
		chmod 755 /usr/share/$Memcrashed/*
		cat > /usr/bin/$Memcrashed << EOF
#!/bin/bash
cd /usr/share/$Memcrashed;python3 Memcrashed.py "\$@"
EOF
		chmod +x /usr/bin/$Memcrashed
		pip3 install -r /usr/share/$Memcrashed/requirements.txt
		menu_entry "Network" "Penetration-Testing" "Memcrashed" "/usr/share/kali-menu/exec-in-shell '$Memcrashed -h'"
		printf "$GREEN"  "[*] Success Installing Memcrashed"
	else
		printf "$GREEN"  "[*] Success Installed Memcrashed"
	fi


	printf "$YELLOW"  "# -----------------------------------Wireless-Penetration-Testing------------------------------------ #"
	# Install Repository Tools
	apt install -qy airgeddon crackle kalibrate-rtl eaphammer rtlsdr-scanner wifiphisher airgraph-ng multimon-ng gr-gsm ridenum airspy gqrx-sdr btscanner bluesnarfer ubertooth blueranger wifipumpkin3 spooftooph pskracker 

	# Install Python3 pip
	wireless_pip="btlejack scapy wpspin"
	pip_installer "Wireless" "Penetration-Testing" "$wireless_pip"

	# Install Nodejs NPM
	wireless_npm="btlejuice"
	npm_installer "Wireless" "Penetration-Testing" "$wireless_npm"

	# Install Ruby GEM
	# wireless_gem=""
	gem_installer "Wireless" "Penetration-Testing" "$wireless_gem"
	
	# Install Golang
	# wireless_golang=""
	go_installer "Wireless" "Penetration-Testing" "$wireless_golang"

	GTScan="gtscan"
	if [ ! -d "/usr/share/$GTScan" ]; then
		git clone https://github.com/SigPloiter/GTScan /usr/share/$GTScan
		chmod 755 /usr/share/$GTScan/*
		cat > /usr/bin/$GTScan << EOF
#!/bin/bash
cd /usr/share/$GTScan;python3 gtscan.py "\$@"
EOF
		chmod +x /usr/bin/$GTScan
		pip3 install -r /usr/share/$GTScan/requirements.txt
		menu_entry "Wireless" "Penetration-Testing" "GTScan" "/usr/share/kali-menu/exec-in-shell '$GTScan -h'"
		printf "$GREEN"  "[*] Success Installing GTScan"
	else
		printf "$GREEN"  "[*] Success Installed GTScan"
	fi

	HLRLookups="hlrlookups"
	if [ ! -d "/usr/share/$HLRLookups" ]; then
		git clone https://github.com/SigPloiter/HLR-Lookups /usr/share/$HLRLookups
		chmod 755 /usr/share/$HLRLookups/*
		cat > /usr/bin/$HLRLookups << EOF
#!/bin/bash
cd /usr/share/$HLRLookups;python2 hlr-lookups.py "\$@"
EOF
		chmod +x /usr/bin/$HLRLookups
		menu_entry "Wireless" "Penetration-Testing" "HLRLookups" "/usr/share/kali-menu/exec-in-shell '$HLRLookups -h'"
		printf "$GREEN"  "[*] Success Installing HLRLookups"
	else
		printf "$GREEN"  "[*] Success Installed HLRLookups"
	fi

	geowifi="geowifi"
	if [ ! -d "/usr/share/$geowifi" ]; then
		git clone https://github.com/GONZOsint/geowifi /usr/share/$geowifi
		chmod 755 /usr/share/$geowifi/*
		cat > /usr/bin/$geowifi << EOF
#!/bin/bash
cd /usr/share/$geowifi;python3 geowifi.py "\$@"
EOF
		chmod +x /usr/bin/$geowifi
		pip3 install -r /usr/share/$geowifi/requirements.txt
		menu_entry "Wireless" "Penetration-Testing" "geowifi" "/usr/share/kali-menu/exec-in-shell '$geowifi -h'"
		printf "$GREEN"  "[*] Success Installing geowifi"
	else
		printf "$GREEN"  "[*] Success Installed geowifi"
	fi


	printf "$YELLOW"  "# --------------------------------------IoT-Penetration-Testing-------------------------------------- #"
	# Install Repository Tools
	apt install -qy arduino gnuradio blue-hydra 

	# Install Python3 pip
	iot_pip="scapy uefi_firmware unblob"
	pip_installer "IoT" "Penetration-Testing" "$iot_pip"

	# Install Nodejs NPM
	# iot_npm=""
	npm_installer "IoT" "Penetration-Testing" "$iot_npm"

	# Install Ruby GEM
	# iot_gem=""
	gem_installer "IoT" "Penetration-Testing" "$iot_gem"

	# Install Golang
	# iot_golang=""
	go_installer "IoT" "Penetration-Testing" "$iot_golang"

	exit
}


red_team ()
{
	printf "$YELLOW"  "# --------------------------------------Reconnaissance-Red-Team-------------------------------------- #"
	# Install Repository Tools
	apt install -qy emailharvester metagoofil amass osrframework gitleaks trufflehog maryam ismtp ident-user-enum eyewitness googler inspy smtp-user-enum goofile bing-ip2hosts webhttrack tnscmd10g getallurls feroxbuster subjack whatweb assetfinder instaloader ligolo-ng 

	# Install Python3 pip
	reconnaissance_pip="censys ggshield raccoon-scanner mailspoof h8mail twint thorndyke gitfive shodan postmaniac socialscan chiasmodon"
	pip_installer "Reconnaissance" "Red-Team" "$reconnaissance_pip"

	# Install Nodejs NPM
	reconnaissance_npm="igf nodesub multitor"
	npm_installer "Reconnaissance" "Red-Team" "$reconnaissance_npm"

	# Install Ruby GEM
	# reconnaissance_gem=""
	gem_installer "Reconnaissance" "Red-Team" "$reconnaissance_gem"

	# Install Golang
	reconnaissance_golang="
go install github.com/x1sec/commit-stream@latest;ln -fs ~/go/bin/commit-stream /usr/bin/commit-stream
go install github.com/eth0izzle/shhgit@latest;ln -fs ~/go/bin/shhgit /usr/bin/shhgit
go install github.com/harleo/asnip@latest;ln -fs ~/go/bin/asnip /usr/bin/asnip
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest;ln -fs ~/go/bin/cvemap /usr/bin/cvemap
go install github.com/hakluke/haktrails@latest;ln -fs ~/go/bin/haktrails /usr/bin/haktrails
go install github.com/lanrat/certgraph@latest;ln -fs ~/go/bin/certgraph /usr/bin/certgraph"
	go_installer "Reconnaissance" "Red-Team" "$reconnaissance_golang"

	Trape="trape"
	if [ ! -d "/usr/share/$Trape" ]; then
		git clone https://github.com/jofpin/trape /usr/share/$Trape
		chmod 755 /usr/share/$Trape/*
		cat > /usr/bin/$Trape << EOF
#!/bin/bash
cd /usr/share/$Trape;python3 trape.py "\$@"
EOF
		chmod +x /usr/bin/$Trape
		pip3 install -r /usr/share/$Trape/requirements.txt
		menu_entry "Reconnaissance" "Red-Team" "Trape" "/usr/share/kali-menu/exec-in-shell '$Trape -h'"
		printf "$GREEN"  "[*] Success Installing Trape"
	else
		printf "$GREEN"  "[*] Success Installed Trape"
	fi

	Dracnmap="dracnmap"
	if [ ! -d "/usr/share/dracnmap" ]; then
		git clone https://github.com/Screetsec/Dracnmap /usr/share/$Dracnmap
		chmod 755 /usr/share/$Dracnmap/*
		cat > /usr/bin/$Dracnmap << EOF
#!/bin/bash
cd /usr/share/$Dracnmap;./Dracnmap.sh "\$@"
EOF
		chmod +x /usr/bin/$Dracnmap
		menu_entry "Reconnaissance" "Red-Team" "Dracnmap" "/usr/share/kali-menu/exec-in-shell '$Dracnmap -h'"
		printf "$GREEN"  "[*] Success Installing Dracnmap"
	else
		printf "$GREEN"  "[*] Success Installed Dracnmap"
	fi

	ReconFTW="reconftw"
	if [ ! -d "/usr/share/$ReconFTW" ]; then
		git clone https://github.com/six2dez/reconftw /usr/share/$ReconFTW
		chmod 755 /usr/share/$ReconFTW/*
		cat > /usr/bin/$ReconFTW << EOF
#!/bin/bash
cd /usr/share/$ReconFTW;./reconftw.sh "\$@"
EOF
		chmod +x /usr/bin/$ReconFTW
		cd /usr/share/$ReconFTW;./install.sh
		menu_entry "Reconnaissance" "Red-Team" "ReconFTW" "/usr/share/kali-menu/exec-in-shell '$ReconFTW -h'"
		printf "$GREEN"  "[*] Success Installing ReconFTW"
	else
		printf "$GREEN"  "[*] Success Installed ReconFTW"
	fi

	CloakQuest3r="cloakquest3r"
	if [ ! -d "/usr/share/$CloakQuest3r" ]; then
		git clone https://github.com/spyboy-productions/CloakQuest3r /usr/share/$CloakQuest3r
		chmod 755 /usr/share/$CloakQuest3r/*
		cat > /usr/bin/$CloakQuest3r << EOF
#!/bin/bash
cd /usr/share/$CloakQuest3r;python3 cloakquest3r.py "\$@"
EOF
		chmod +x /usr/bin/$CloakQuest3r
		pip3 install -r /usr/share/$CloakQuest3r/requirements.txt
		menu_entry "Reconnaissance" "Red-Team" "CloakQuest3r" "/usr/share/kali-menu/exec-in-shell '$CloakQuest3r -h'"
		printf "$GREEN"  "[*] Success Installing CloakQuest3r"
	else
		printf "$GREEN"  "[*] Success Installed CloakQuest3r"
	fi


	printf "$YELLOW"  "# -----------------------------------Resource-Development-Red-Team----------------------------------- #"
	# Install Repository Tools
	apt install -qy sharpshooter 

	# Install Python3 pip
	# resource_development_pip=""
	pip_installer "Resource-Development" "Red-Team" "$resource_development_pip"

	# Install Nodejs NPM
	# resource_development_npm=""
	npm_installer "Resource-Development" "Red-Team" "$resource_development_npm"

	# Install Ruby GEM
	# resource_development_gem=""
	gem_installer "Resource-Development" "Red-Team" "$resource_development_gem"

	# Install Golang
	# resource_development_golang=""
	go_installer "Resource-Development" "Red-Team" "$resource_development_golang"

	OffensiveNim="offensivenim"
	if [ ! -d "/usr/share/$OffensiveNim" ]; then
		git clone https://github.com/byt3bl33d3r/OffensiveNim /usr/share/$OffensiveNim
		chmod 755 /usr/share/$OffensiveNim/*
		cat > /usr/bin/$OffensiveNim << EOF
#!/bin/bash
cd /usr/share/$OffensiveNim/src;ls "\$@"
EOF
		chmod +x /usr/bin/$OffensiveNim
		menu_entry "Resource-Development" "Red-Team" "OffensiveNim" "/usr/share/kali-menu/exec-in-shell '$OffensiveNim'"
		printf "$GREEN"  "[*] Success Installing OffensiveNim"
	else
		printf "$GREEN"  "[*] Success Installed OffensiveNim"
	fi

	OffensiveDLR="offensivedlr"
	if [ ! -d "/usr/share/$OffensiveDLR" ]; then
		git clone https://github.com/byt3bl33d3r/OffensiveDLR /usr/share/$OffensiveDLR
		chmod 755 /usr/share/$OffensiveDLR/*
		cat > /usr/bin/$OffensiveDLR << EOF
#!/bin/bash
cd /usr/share/$OffensiveDLR;pwsh -c \"dir\" "\$@"
EOF
		chmod +x /usr/bin/$OffensiveDLR
		menu_entry "Resource-Development" "Red-Team" "OffensiveDLR" "/usr/share/kali-menu/exec-in-shell '$OffensiveDLR'"
		printf "$GREEN"  "[*] Success Installing OffensiveDLR"
	else
		printf "$GREEN"  "[*] Success Installed OffensiveDLR"
	fi


	printf "$YELLOW"  "# --------------------------------------Initial-Access-Red-team-------------------------------------- #"
	# Install Repository Tools
	apt install -qy qrencode multiforcer crowbar brutespray arduino isr-evilgrade wifiphisher airgraph-ng 

	# Install Python3 pip
	initial_access_pip="rarce baboossh dnstwist pasteme-cli"
	pip_installer "Initial-Access" "Red-Team" "$initial_access_pip"

	# Install Nodejs NPM
	# initial_access_npm=""
	npm_installer "Initial-Access" "Red-Team" "$initial_access_npm"

	# Install Ruby GEM
	# initial_access_gem=""
	gem_installer "Initial-Access" "Red-Team" "$initial_access_gem"

	# Install Golang
	initial_access_golang="
go install github.com/Tylous/ZipExec@latest;ln -fs ~/go/bin/ZipExec /usr/bin/ZipExec
go install github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest;ln -fs ~/go/bin/hednsextractor /usr/bin/hednsextractor"
	go_installer "Initial-Access" "Red-Team" "$initial_access_golang"

	Evilginx="evilginx"
	if [ ! -d "/usr/share/$Evilginx" ]; then
		wget https://github.com/kgretzky/evilginx2/releases/download/2.4.0/evilginx-linux-amd64.tar.gz -O /tmp/$Evilginx.tar.gz
		tar -xvf /tmp/$Evilginx.tar.gz -C /usr/share;rm -f /tmp/$Evilginx.tar.gz
		chmod 755 /usr/share/$Evilginx/*
		ln -fs /usr/share/$Evilginx/evilginx /usr/bin/$Evilginx
		chmod +x /usr/bin/$Evilginx
		cd /usr/share/$Evilginx;./install.sh
		menu_entry "Initial-Access" "Red-Team" "Evilginx" "/usr/share/kali-menu/exec-in-shell 'sudo $Evilginx -h'"
		printf "$GREEN"  "[*] Success Installing Evilginx"
	else
		printf "$GREEN"  "[*] Success Installed Evilginx"
	fi

	SocialFish="socialfish"
	if [ ! -d "/usr/share/$SocialFish" ]; then
		git clone https://github.com/UndeadSec/SocialFish /usr/share/$SocialFish
		chmod 755 /usr/share/$SocialFish/*
		cat > /usr/bin/$SocialFish << EOF
#!/bin/bash
cd /usr/share/$SocialFish;python3 SocialFish.py "\$@"
EOF
		chmod +x /usr/bin/$SocialFish
		pip3 install -r /usr/share/$SocialFish/requirements.txt
		menu_entry "Initial-Access" "Red-Team" "SocialFish" "/usr/share/kali-menu/exec-in-shell '$SocialFish -h'"
		printf "$GREEN"  "[*] Success Installing SocialFish"
	else
		printf "$GREEN"  "[*] Success Installed SocialFish"
	fi

	EmbedInHTML="embedinhtml"
	if [ ! -d "/usr/share/$EmbedInHTML" ]; then
		git clone https://github.com/Arno0x/EmbedInHTML /usr/share/$EmbedInHTML
		chmod 755 /usr/share/$EmbedInHTML/*
		cat > /usr/bin/$EmbedInHTML << EOF
#!/bin/bash
cd /usr/share/$EmbedInHTML;python2 embedInHTML.py "\$@"
EOF
		chmod +x /usr/bin/$EmbedInHTML
		menu_entry "Initial-Access" "Red-Team" "EmbedInHTML" "/usr/share/kali-menu/exec-in-shell '$EmbedInHTML -h'"
		printf "$GREEN"  "[*] Success Installing EmbedInHTML"
	else
		printf "$GREEN"  "[*] Success Installed EmbedInHTML"
	fi

	BadPDF="badpdf"
	if [ ! -d "/usr/share/$BadPDF" ]; then
		git clone https://github.com/deepzec/Bad-Pdf /usr/share/$BadPDF
		chmod 755 /usr/share/$BadPDF/*
		cat > /usr/bin/$BadPDF << EOF
#!/bin/bash
cd /usr/share/$BadPDF;python2 badpdf.py "\$@"
EOF
		chmod +x /usr/bin/$BadPDF
		menu_entry "Initial-Access" "Red-Team" "BadPDF" "/usr/share/kali-menu/exec-in-shell '$BadPDF -h'"
		printf "$GREEN"  "[*] Success Installing BadPDF"
	else
		printf "$GREEN"  "[*] Success Installed BadPDF"
	fi

	BLACKEYE="blackeye"
	if [ ! -d "/usr/share/$BLACKEYE" ]; then
		git clone https://github.com/EricksonAtHome/blackeye /usr/share/$BLACKEYE
		chmod 755 /usr/share/$BLACKEYE/*
		cat > /usr/bin/$BLACKEYE << EOF
#!/bin/bash
cd /usr/share/$BLACKEYE;./blackeye.sh "\$@"
EOF
		chmod +x /usr/bin/$BLACKEYE
		menu_entry "Initial-Access" "Red-Team" "BLACKEYE" "/usr/share/kali-menu/exec-in-shell '$BLACKEYE'"
		printf "$GREEN"  "[*] Success Installing BLACKEYE"
	else
		printf "$GREEN"  "[*] Success Installed BLACKEYE"
	fi

	PDFBUILDER="pdfbuilder"
	if [ ! -d "/usr/share/$PDFBUILDER" ]; then
		mkdir -p /usr/share/$PDFBUILDER
		wget https://github.com/K3rnel-Dev/pdf-exploit/releases/download/Compilated/PDF-BUILDER.zip -O /tmp/$PDFBUILDER.zip
		unzip /tmp/$PDFBUILDER.zip -d /usr/share/$PDFBUILDER;rm -f /tmp/$PDFBUILDER.zip
		chmod 755 /usr/share/$PDFBUILDER/*
		cat > /usr/bin/$PDFBUILDER << EOF
#!/bin/bash
cd /usr/share/$PDFBUILDER;mono PDF-BUILDER.exe "\$@"
EOF
		chmod +x /usr/bin/$PDFBUILDER
		menu_entry "Initial-Access" "Red-Team" "PDFBUILDER" "/usr/share/kali-menu/exec-in-shell '$PDFBUILDER'"
		printf "$GREEN"  "[*] Success Installing PDFBUILDER"
	else
		printf "$GREEN"  "[*] Success Installed PDFBUILDER"
	fi

	CredSniper="credsniper"
	if [ ! -d "/usr/share/$CredSniper" ]; then
		git clone https://github.com/ustayready/CredSniper /usr/share/$CredSniper
		chmod 755 /usr/share/$CredSniper/*
		cat > /usr/bin/$CredSniper << EOF
#!/bin/bash
cd /usr/share/$CredSniper;python3 credsniper.py "\$@"
EOF
		chmod +x /usr/bin/$CredSniper
		cd /usr/share/$CredSniper;./install.sh
		pip3 install -r /usr/share/$CredSniper/requirements.txt
		menu_entry "Initial-Access" "Red-Team" "CredSniper" "/usr/share/kali-menu/exec-in-shell '$CredSniper -h'"
		printf "$GREEN"  "[*] Success Installing CredSniper"
	else
		printf "$GREEN"  "[*] Success Installed CredSniper"
	fi

	EvilURL="evilurl"
	if [ ! -d "/usr/share/$EvilURL" ]; then
		git clone https://github.com/UndeadSec/EvilURL /usr/share/$EvilURL
		chmod 755 /usr/share/$EvilURL/*
		cat > /usr/bin/$EvilURL << EOF
#!/bin/bash
cd /usr/share/$EvilURL;python3 evilurl.py "\$@"
EOF
		chmod +x /usr/bin/$EvilURL
		menu_entry "Initial-Access" "Red-Team" "EvilURL" "/usr/share/kali-menu/exec-in-shell '$EvilURL -h'"
		printf "$GREEN"  "[*] Success Installing EvilURL"
	else
		printf "$GREEN"  "[*] Success Installed EvilURL"
	fi

	Debinject="debinject"
	if [ ! -d "/usr/share/$Debinject" ]; then
		git clone https://github.com/UndeadSec/Debinject /usr/share/$Debinject
		chmod 755 /usr/share/$Debinject/*
		cat > /usr/bin/$Debinject << EOF
#!/bin/bash
cd /usr/share/$Debinject;python2 debinject.py "\$@"
EOF
		chmod +x /usr/bin/$Debinject
		menu_entry "Initial-Access" "Red-Team" "Debinject" "/usr/share/kali-menu/exec-in-shell '$Debinject -h'"
		printf "$GREEN"  "[*] Success Installing Debinject"
	else
		printf "$GREEN"  "[*] Success Installed Debinject"
	fi

	Brutal="brutal"
	if [ ! -d "/usr/share/$Brutal" ]; then
		git clone https://github.com/Screetsec/Brutal /usr/share/$Brutal
		chmod 755 /usr/share/$Brutal/*
		cat > /usr/bin/$Brutal << EOF
#!/bin/bash
cd /usr/share/$Brutal;./Brutal.sh "\$@"
EOF
		chmod +x /usr/bin/$Brutal
		menu_entry "Initial-Access" "Red-Team" "Brutal" "/usr/share/kali-menu/exec-in-shell 'sudo $Brutal -h'"
		printf "$GREEN"  "[*] Success Installing Brutal"
	else
		printf "$GREEN"  "[*] Success Installed Brutal"
	fi

	Demiguise="demiguise"
	if [ ! -d "/usr/share/$Demiguise" ]; then
		git clone https://github.com/nccgroup/demiguise /usr/share/$Demiguise
		chmod 755 /usr/share/$Demiguise/*
		cat > /usr/bin/$Demiguise << EOF
#!/bin/bash
cd /usr/share/$Demiguise;python3 demiguise.py "\$@"
EOF
		chmod +x /usr/bin/$Demiguise
		menu_entry "Initial-Access" "Red-Team" "Demiguise" "/usr/share/kali-menu/exec-in-shell '$Demiguise'"
		printf "$GREEN"  "[*] Success Installing Demiguise"
	else
		printf "$GREEN"  "[*] Success Installed Demiguise"
	fi

	Dr0p1t="dr0p1t"
	if [ ! -d "/usr/share/$Dr0p1t" ]; then
		git clone https://github.com/D4Vinci/Dr0p1t-Framework /usr/share/$Dr0p1t
		chmod 755 /usr/share/$Dr0p1t/*
		cd /usr/share/$Dr0p1t;./install.sh
		cat > /usr/bin/$Dr0p1t << EOF
#!/bin/bash
cd /usr/share/$Dr0p1t;python3 Dr0p1t.py "\$@"
EOF
		chmod +x /usr/bin/$Dr0p1t
		menu_entry "Initial-Access" "Red-Team" "Dr0p1t" "/usr/share/kali-menu/exec-in-shell '$Dr0p1t -h'"
		printf "$GREEN"  "[*] Success Installing Dr0p1t"
	else
		printf "$GREEN"  "[*] Success Installed Dr0p1t"
	fi

	EvilPDF="evilpdf"
	if [ ! -d "/usr/share/$EvilPDF" ]; then
		git clone https://github.com/superzerosec/evilpdf /usr/share/$EvilPDF
		chmod 755 /usr/share/$EvilPDF/*
		cat > /usr/bin/$EvilPDF << EOF
#!/bin/bash
cd /usr/share/$EvilPDF;python2 evilpdf.py "\$@"
EOF
		chmod +x /usr/bin/$EvilPDF
		menu_entry "Initial-Access" "Red-Team" "EvilPDF" "/usr/share/kali-menu/exec-in-shell '$EvilPDF -h'"
		printf "$GREEN"  "[*] Success Installing EvilPDF"
	else
		printf "$GREEN"  "[*] Success Installed EvilPDF"
	fi

	Gophish="gophish"
	if [ ! -d "/usr/share/$Gophish" ]; then
		wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip -O /tmp/$Gophish.zip
		unzip /tmp/$Gophish.zip -d /usr/share/$Gophish;rm -f /tmp/$Gophish.zip
		chmod 755 /usr/share/$Gophish/*
		cat > /usr/bin/$Gophish << EOF
#!/bin/bash
cd /usr/share/$Gophish;./gophish "\$@"
EOF
		chmod +x /usr/bin/$Gophish
		menu_entry "Initial-Access" "Red-Team" "Gophish" "/usr/share/kali-menu/exec-in-shell '$Gophish'"
		printf "$GREEN"  "[*] Success Installing Gophish"
	else
		printf "$GREEN"  "[*] Success Installed Gophish"
	fi


	printf "$YELLOW"  "# -----------------------------------------Execution-Red-Team---------------------------------------- #"
	# Install Repository Tools
	apt install -qy shellnoob

	# Install Python3 pip
	execution_pip="donut-shellcode xortool pwncat"
	pip_installer "Execution" "Red-Team" "$execution_pip"

	# Install Nodejs NPM
	# execution_npm=""
	npm_installer "Execution" "Red-Team" "$execution_npm"

	# Install Ruby GEM
	# execution_gem=""
	gem_installer "Execution" "Red-Team" "$execution_gem"

	# Install Golang
	# execution_golang=""
	go_installer "Execution" "Red-Team" "$execution_golang"

	Venom="venom"
	if [ ! -d "/usr/share/$Venom" ]; then
		git clone https://github.com/r00t-3xp10it/venom /usr/share/$Venom
		chmod 755 /usr/share/$Venom/*
		cat > /usr/bin/$Venom << EOF
#!/bin/bash
cd /usr/share/$Venom;./venom.sh "\$@"
EOF
		chmod +x /usr/bin/$Venom
		menu_entry "Execution" "Red-Team" "Venom" "/usr/share/kali-menu/exec-in-shell 'sudo $Venom -h'"
		printf "$GREEN"  "[*] Success Installing Venom"
	else
		printf "$GREEN"  "[*] Success Installed Venom"
	fi

	PowerLessShell="powerlessshell"
	if [ ! -d "/usr/share/$PowerLessShell" ]; then
		git clone https://github.com/Mr-Un1k0d3r/PowerLessShell /usr/share/$PowerLessShell
		chmod 755 /usr/share/$PowerLessShell/*
		cat > /usr/bin/$PowerLessShell << EOF
#!/bin/bash
cd /usr/share/$PowerLessShell;python2 PowerLessShell.py "\$@"
EOF
		chmod +x /usr/bin/$PowerLessShell
		menu_entry "Execution" "Red-Team" "PowerLessShell" "/usr/share/kali-menu/exec-in-shell '$PowerLessShell -h'"
		printf "$GREEN"  "[*] Success Installing PowerLessShell"
	else
		printf "$GREEN"  "[*] Success Installed PowerLessShell"
	fi

	SharpShooter="sharpshooter"
	if [ ! -d "/usr/share/$SharpShooter" ]; then
		git clone https://github.com/mdsecactivebreach/SharpShooter /usr/share/$SharpShooter
		chmod 755 /usr/share/$SharpShooter/*
		cat > /usr/bin/$SharpShooter << EOF
#!/bin/bash
cd /usr/share/$SharpShooter;python2 SharpShooter.py "\$@"
EOF
		chmod +x /usr/bin/$SharpShooter
		pip2 install -r /usr/share/$SharpShooter/requirements.txt
		menu_entry "Execution" "Red-Team" "SharpShooter" "/usr/share/kali-menu/exec-in-shell '$SharpShooter -h'"
		printf "$GREEN"  "[*] Success Installing SharpShooter"
	else
		printf "$GREEN"  "[*] Success Installed SharpShooter"
	fi

	Donut="donut"
	if [ ! -d "/usr/share/$Donut" ]; then
		mkdir -p /usr/share/$Donut
		wget https://github.com/TheWover/donut/releases/download/v1.0/donut_v1.0.tar.gz -O /tmp/$Donut.tar.gz
		tar -xvf /tmp/$Donut.tar.gz -C /usr/share/$Donut;rm -f /tmp/$Donut.tar.gz
		chmod 755 /usr/share/$Donut/*
		ln -fs /usr/share/$Donut/donut /usr/bin/$Donut
		chmod +x /usr/bin/$Donut
		menu_entry "Execution" "Red-Team" "Donut" "/usr/share/kali-menu/exec-in-shell '$Donut -h'"
		printf "$GREEN"  "[*] Success Installing Donut"
	else
		printf "$GREEN"  "[*] Success Installed Donut"
	fi


	printf "$YELLOW"  "# ----------------------------------------Persistence-Red-Team--------------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	persistence_pip="hiphp"
	pip_installer "Persistence" "Red-Team" "$persistence_pip"

	# Install Nodejs NPM
	# persistence_npm=""
	npm_installer "Persistence" "Red-Team" "$persistence_npm"

	# Install Ruby GEM
	# persistence_gem=""
	gem_installer "Persistence" "Red-Team" "$persistence_gem"

	# Install Golang
	# persistence_golang=""
	go_installer "Persistence" "Red-Team" "$persistence_golang"

	Vegile="vegile"
	if [ ! -d "/usr/share/$Vegile" ]; then
		git clone https://github.com/Screetsec/Vegile /usr/share/$Vegile
		chmod 755 /usr/share/$Vegile/*
		ln -fs /usr/share/$Vegile/$Vegile /usr/bin/$Vegile
		chmod +x /usr/bin/$Vegile
		menu_entry "Persistence" "Red-Team" "Vegile" "/usr/share/kali-menu/exec-in-shell 'sudo $Vegile -h'"
		printf "$GREEN"  "[*] Success Installing Vegile"
	else
		printf "$GREEN"  "[*] Success Installed Vegile"
	fi

	SmmBackdoorNg="smmbackdoorng"
	if [ ! -d "/usr/share/$SmmBackdoorNg" ]; then
		git clone https://github.com/Cr4sh/SmmBackdoorNg /usr/share/$SmmBackdoorNg
		chmod 755 /usr/share/$SmmBackdoorNg/*
		cat > /usr/bin/$SmmBackdoorNg << EOF
#!/bin/bash
cd /usr/share/$SmmBackdoorNg;python3 smm_backdoor.py "\$@"
EOF
		chmod +x /usr/bin/$SmmBackdoorNg
		menu_entry "Persistence" "Red-Team" "SmmBackdoorNg" "/usr/share/kali-menu/exec-in-shell '$SmmBackdoorNg -h'"
		printf "$GREEN"  "[*] Success Installing SmmBackdoorNg"
	else
		printf "$GREEN"  "[*] Success Installed SmmBackdoorNg"
	fi


	printf "$YELLOW"  "# -----------------------------------Privilege-Escalation-Red-Team----------------------------------- #"
	# Install Repository Tools
	apt install -qy linux-exploit-suggester peass oscanner 

	# Install Python3 pip
	privilege_escalation_pip="cve-bin-tool"
	pip_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_pip"

	# Install Nodejs NPM
	# privilege_escalation_npm=""
	npm_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_npm"

	# Install Ruby GEM
	# privilege_escalation_gem=""
	gem_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_gem"

	# Install Golang
	# privilege_escalation_golang=""
	go_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_golang"

	MimiPenguin="mimipenguin"
	if [ ! -d "/usr/share/$MimiPenguin" ]; then
		git clone https://github.com/huntergregal/mimipenguin /usr/share/$MimiPenguin
		chmod 755 /usr/share/$MimiPenguin/*
		cat > /usr/bin/$MimiPenguin << EOF
#!/bin/bash
cd /usr/share/$MimiPenguin;python3 mimipenguin.py "\$@"
EOF
		chmod +x /usr/bin/$MimiPenguin
		menu_entry "Privilege-Escalation" "Red-Team" "MimiPenguin" "/usr/share/kali-menu/exec-in-shell '$MimiPenguin -h'"
		printf "$GREEN"  "[*] Success Installing MimiPenguin"
	else
		printf "$GREEN"  "[*] Success Installed MimiPenguin"
	fi

	GodPotato="godpotato"
	if [ ! -d "/usr/share/$GodPotato" ]; then
		mkdir -p /usr/share/$GodPotato
		wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe -O /usr/share/$GodPotato/GodPotato-NET4.exe
		wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET35.exe -O /usr/share/$GodPotato/GodPotato-NET35.exe
		chmod 755 /usr/share/$GodPotato/*
		cat > /usr/bin/$GodPotato << EOF
#!/bin/bash
cd /usr/share/$GodPotato;ls "\$@"
EOF
		chmod +x /usr/bin/$GodPotato
		menu_entry "Privilege-Escalation" "Red-Team" "GodPotato" "/usr/share/kali-menu/exec-in-shell '$GodPotato'"
		printf "$GREEN"  "[*] Success Installing GodPotato"
	else
		printf "$GREEN"  "[*] Success Installed GodPotato"
	fi

	spectre_meltdown_checker="smc"
	if [ ! -d "/usr/share/$spectre_meltdown_checker" ]; then
		mkdir -p /usr/share/spectre-meltdown-checker
		wget https://meltdown.ovh -O /usr/share/$spectre_meltdown_checker/spectre-meltdown-checker.sh
		chmod 755 /usr/share/$spectre_meltdown_checker/*
		cat > /usr/bin/$spectre_meltdown_checker << EOF
#!/bin/bash
cd /usr/share/$spectre_meltdown_checker;bash spectre-meltdown-checker.sh "\$@"
EOF
		chmod +x /usr/bin/$spectre_meltdown_checker
		menu_entry "Privilege-Escalation" "Red-Team" "spectre-meltdown-checker" "/usr/share/kali-menu/exec-in-shell '$spectre_meltdown_checker -h'"
		printf "$GREEN"  "[*] Success Installing spectre-meltdown-checker"
	else
		printf "$GREEN"  "[*] Success Installed spectre-meltdown-checker"
	fi


	printf "$YELLOW"  "# -------------------------------------Defense-Evasion-Red-Team-------------------------------------- #"
	# Install Repository Tools
	apt install -qy shellter unicorn veil veil-catapult veil-evasion osslsigncode upx-ucl 

	# Install Python3 pip
	defense_evasion_pip="auto-py-to-exe certipy sysplant pinject"
	pip_installer "Defense-Evasion" "Red-Team" "$defense_evasion_pip"

	# Install Nodejs NPM
	defense_evasion_npm="uglify-js javascript-obfuscator serialize-javascript serialize-to-js jsdom"
	npm_installer "Defense-Evasion" "Red-Team" "$defense_evasion_npm"

	# Install Ruby GEM
	# defense_evasion_gem=""
	gem_installer "Defense-Evasion" "Red-Team" "$defense_evasion_gem"

	# Install Golang
	defense_evasion_golang="
go install github.com/optiv/ScareCrow@latest;ln -fs ~/go/bin/ScareCrow /usr/bin/scarecrow"
	go_installer "Defense-Evasion" "Red-Team" "$defense_evasion_golang"

	ASWCrypter="aswcrypter"
	if [ ! -d "/usr/share/$ASWCrypter" ]; then
		git clone https://github.com/AbedAlqaderSwedan1/ASWCrypter /usr/share/$ASWCrypter
		chmod 755 /usr/share/$ASWCrypter/*;bash /usr/share/$ASWCrypter/setup.sh
		cat > /usr/bin/$ASWCrypter << EOF
#!/bin/bash
cd /usr/share/$ASWCrypter;bash ASWCrypter.sh "\$@"
EOF
		chmod +x /usr/bin/$ASWCrypter
		menu_entry "Defense-Evasion" "Red-Team" "ASWCrypter" "/usr/share/kali-menu/exec-in-shell '$ASWCrypter -h'"
		printf "$GREEN"  "[*] Success Installing ASWCrypter"
	else
		printf "$GREEN"  "[*] Success Installed ASWCrypter"
	fi

	AVET="avet"
	if [ ! -d "/usr/share/$AVET" ]; then
		git clone https://github.com/govolution/avet /usr/share/$AVET
		chmod 755 /usr/share/$AVET/*
		bash /usr/share/$AVET/setup.sh
		cat > /usr/bin/$AVET << EOF
#!/bin/bash
cd /usr/share/$AVET;python3 avet.py "\$@"
EOF
		chmod +x /usr/bin/$AVET
		menu_entry "Defense-Evasion" "Red-Team" "AVET" "/usr/share/kali-menu/exec-in-shell '$AVET'"
		printf "$GREEN"  "[*] Success Installing AVET"
	else
		printf "$GREEN"  "[*] Success Installed AVET"
	fi

	Unicorn="unicorn"
	if [ ! -d "/usr/share/$Unicorn" ]; then
		git clone https://github.com/trustedsec/unicorn /usr/share/$Unicorn
		chmod 755 /usr/share/$Unicorn/*
		cat > /usr/bin/$Unicorn << EOF
#!/bin/bash
cd /usr/share/$Unicorn;python3 unicorn.py "\$@"
EOF
		chmod +x /usr/bin/$Unicorn
		menu_entry "Defense-Evasion" "Red-Team" "Unicorn" "/usr/share/kali-menu/exec-in-shell '$Unicorn -h'"
		printf "$GREEN"  "[*] Success Installing Unicorn"
	else
		printf "$GREEN"  "[*] Success Installed Unicorn"
	fi

	SysWhispers3="syswhispers3"
	if [ ! -d "/usr/share/$SysWhispers3" ]; then
		git clone https://github.com/klezVirus/SysWhispers3 /usr/share/$SysWhispers3
		chmod 755 /usr/share/$SysWhispers3/*
		cat > /usr/bin/$SysWhispers3 << EOF
#!/bin/bash
cd /usr/share/$SysWhispers3;python3 syswhispers.py "\$@"
EOF
		chmod +x /usr/bin/$SysWhispers3
		menu_entry "Defense-Evasion" "Red-Team" "SysWhispers3" "/usr/share/kali-menu/exec-in-shell '$SysWhispers3 -h'"
		printf "$GREEN"  "[*] Success Installing SysWhispers3"
	else
		printf "$GREEN"  "[*] Success Installed SysWhispers3"
	fi

	SysWhispers="syswhispers"
	if [ ! -d "/usr/share/$SysWhispers" ]; then
		git clone https://github.com/jthuraisamy/SysWhispers /usr/share/$SysWhispers
		chmod 755 /usr/share/$SysWhispers/*
		cat > /usr/bin/$SysWhispers << EOF
#!/bin/bash
cd /usr/share/$SysWhispers;python3 syswhispers.py "\$@"
EOF
		chmod +x /usr/bin/$SysWhispers
		pip3 install -r /usr/share/$SysWhispers/requirements.txt
		menu_entry "Defense-Evasion" "Red-Team" "SysWhispers" "/usr/share/kali-menu/exec-in-shell '$SysWhispers -h'"
		printf "$GREEN"  "[*] Success Installing SysWhispers"
	else
		printf "$GREEN"  "[*] Success Installed SysWhispers"
	fi

	InvokeDOSfuscation="invoke-dosfuscation"
	if [ ! -d "/usr/share/$InvokeDOSfuscation" ]; then
		git clone https://github.com/danielbohannon/Invoke-DOSfuscation /usr/share/$InvokeDOSfuscation
		chmod 755 /usr/share/$InvokeDOSfuscation/*
		cat > /usr/bin/$InvokeDOSfuscation << EOF
#!/bin/bash
cd /usr/share/$InvokeDOSfuscation;pwsh -c "Import-Module ./Invoke-DOSfuscation.psd1; Invoke-DOSfuscation" "\$@"
EOF
		chmod +x /usr/bin/$InvokeDOSfuscation
		menu_entry "Defense-Evasion" "Red-Team" "Invoke-DOSfuscation" "/usr/share/kali-menu/exec-in-shell '$InvokeDOSfuscation'"
		printf "$GREEN"  "[*] Success Installing Invoke-DOSfuscation"
	else
		printf "$GREEN"  "[*] Success Installed Invoke-DOSfuscation"
	fi

	ObfuscateCactusTorch="obfuscatecactustorch"
	if [ ! -d "/usr/share/$ObfuscateCactusTorch" ]; then
		git clone https://github.com/Arno0x/ObfuscateCactusTorch /usr/share/$ObfuscateCactusTorch
		chmod 755 /usr/share/$ObfuscateCactusTorch/*
		cat > /usr/bin/$ObfuscateCactusTorch << EOF
#!/bin/bash
cd /usr/share/$ObfuscateCactusTorch;python2 obfuscateCactusTorch.py "\$@"
EOF
		chmod +x /usr/bin/$ObfuscateCactusTorch
		menu_entry "Defense-Evasion" "Red-Team" "ObfuscateCactusTorch" "/usr/share/kali-menu/exec-in-shell '$ObfuscateCactusTorch'"
		printf "$GREEN"  "[*] Success Installing ObfuscateCactusTorch"
	else
		printf "$GREEN"  "[*] Success Installed ObfuscateCactusTorch"
	fi

	PhantomEvasion="phantom"
	if [ ! -d "/usr/share/$PhantomEvasion" ]; then
		git clone https://github.com/oddcod3/Phantom-Evasion /usr/share/$PhantomEvasion
		chmod 755 /usr/share/$PhantomEvasion/*
		cat > /usr/bin/$PhantomEvasion << EOF
#!/bin/bash
cd /usr/share/$PhantomEvasion;python3 phantom-evasion.py "\$@"
EOF
		chmod +x /usr/bin/$PhantomEvasion
		menu_entry "Defense-Evasion" "Red-Team" "Phantom-Evasion" "/usr/share/kali-menu/exec-in-shell '$PhantomEvasion -h'"
		printf "$GREEN"  "[*] Success Installing Phantom-Evasion"
	else
		printf "$GREEN"  "[*] Success Installed Phantom-Evasion"
	fi

	SpookFlare="spookflare"
	if [ ! -d "/usr/share/$SpookFlare" ]; then
		git clone https://github.com/hlldz/SpookFlare /usr/share/$SpookFlare
		chmod 755 /usr/share/$SpookFlare/*
		cat > /usr/bin/$SpookFlare << EOF
#!/bin/bash
cd /usr/share/$SpookFlare;python2 spookflare.py "\$@"
EOF
		chmod +x /usr/bin/$SpookFlare
		pip2 install -r /usr/share/$SpookFlare/requirements.txt
		menu_entry "Defense-Evasion" "Red-Team" "SpookFlare" "/usr/share/kali-menu/exec-in-shell '$SpookFlare -h'"
		printf "$GREEN"  "[*] Success Installing SpookFlare"
	else
		printf "$GREEN"  "[*] Success Installed SpookFlare"
	fi

	Pazuzu="pazuzu"
	if [ ! -d "/usr/share/$Pazuzu" ]; then
		git clone https://github.com/BorjaMerino/Pazuzu /usr/share/$Pazuzu
		chmod 755 /usr/share/$Pazuzu/*
		cat > /usr/bin/$Pazuzu << EOF
#!/bin/bash
cd /usr/share/$Pazuzu;python2 pazuzu.py "\$@"
EOF
		chmod +x /usr/bin/$Pazuzu
		menu_entry "Defense-Evasion" "Red-Team" "Pazuzu" "/usr/share/kali-menu/exec-in-shell '$Pazuzu -h'"
		printf "$GREEN"  "[*] Success Installing Pazuzu"
	else
		printf "$GREEN"  "[*] Success Installed Pazuzu"
	fi

	InvokeObfuscation="invoke-obfuscation"
	if [ ! -d "/usr/share/$InvokeObfuscation" ]; then
		git clone https://github.com/danielbohannon/Invoke-Obfuscation /usr/share/$InvokeObfuscation
		chmod 755 /usr/share/$InvokeObfuscation/*
		cat > /usr/bin/$InvokeObfuscation << EOF
#!/bin/bash
cd /usr/share/$InvokeObfuscation;pwsh -c "Import-Module ./Invoke-Obfuscation.psd1; Invoke-Obfuscation" "\$@"
EOF
		chmod +x /usr/bin/$InvokeObfuscation
		menu_entry "Defense-Evasion" "Red-Team" "Invoke-Obfuscation" "/usr/share/kali-menu/exec-in-shell '$InvokeObfuscation'"
		printf "$GREEN"  "[*] Success Installing Invoke-Obfuscation"
	else
		printf "$GREEN"  "[*] Success Installed Invoke-Obfuscation"
	fi

	InvokeCradleCrafter="invoke-cradlecrafter"
	if [ ! -d "/usr/share/$InvokeCradleCrafter" ]; then
		git clone https://github.com/danielbohannon/Invoke-CradleCrafter /usr/share/$InvokeCradleCrafter
		chmod 755 /usr/share/$InvokeCradleCrafter/*
		cat > /usr/bin/$InvokeCradleCrafter << EOF
#!/bin/bash
cd /usr/share/$InvokeCradleCrafter;pwsh -c "Import-Module ./Invoke-CradleCrafter.psd1; Invoke-CradleCrafter" "\$@"
EOF
		chmod +x /usr/bin/$InvokeCradleCrafter
		menu_entry "Defense-Evasion" "Red-Team" "Invoke-CradleCrafter" "/usr/share/kali-menu/exec-in-shell '$InvokeCradleCrafter'"
		printf "$GREEN"  "[*] Success Installing Invoke-CradleCrafter"
	else
		printf "$GREEN"  "[*] Success Installed Invoke-CradleCrafter"
	fi


	printf "$YELLOW"  "# ------------------------------------Credential-Access-Red-Team------------------------------------- #"
	# Install Repository Tools
	apt install -qy pdfcrack fcrackzip rarcrack 

	# Install Python3 pip
	credential_access_pip="adidnsdump detect-secrets impacket cloudscraper knowsmore ssh-mitm"
	pip_installer "Credential-Access" "Red-Team" "$credential_access_pip"

	# Install Nodejs NPM
	# credential_access_npm=""
	npm_installer "Credential-Access" "Red-Team" "$credential_access_npm"

	# Install Ruby GEM
	# credential_access_gem=""
	gem_installer "Credential-Access" "Red-Team" "$credential_access_gem"

	# Install Golang
	credential_access_golang="
go install github.com/ropnop/kerbrute@latest;ln -fs ~/go/bin/kerbrute /usr/bin/kerbrute"
	go_installer "Credential-Access" "Red-Team" "$credential_access_golang"

	Kerberoast="kerberoast"
	if [ ! -d "/usr/share/$Kerberoast" ]; then
		git clone https://github.com/nidem/kerberoast /usr/share/$Kerberoast
		chmod 755 /usr/share/$Kerberoast/*
		cat > /usr/bin/$Kerberoast << EOF
#!/bin/bash
cd /usr/share/$Kerberoast;python3 kerberoast.py "\$@"
EOF
		chmod +x /usr/bin/$Kerberoast
		menu_entry "Credential-Access" "Red-Team" "Kerberoast" "/usr/share/kali-menu/exec-in-shell '$Kerberoast -h'"
		printf "$GREEN"  "[*] Success Installing Kerberoast"
	else
		printf "$GREEN"  "[*] Success Installed Kerberoast"
	fi

	NtlmRelayToEWS="ntlmRelaytoews"
	if [ ! -d "/usr/share/$NtlmRelayToEWS" ]; then
		git clone https://github.com/Arno0x/NtlmRelayToEWS /usr/share/$NtlmRelayToEWS
		chmod 755 /usr/share/$NtlmRelayToEWS/*
		cat > /usr/bin/$NtlmRelayToEWS << EOF
#!/bin/bash
cd /usr/share/$NtlmRelayToEWS;python2 ntlmRelayToEWS.py "\$@"
EOF
		chmod +x /usr/bin/$NtlmRelayToEWS
		menu_entry "Credential-Access" "Red-Team" "NtlmRelayToEWS" "/usr/share/kali-menu/exec-in-shell '$NtlmRelayToEWS -h'"
		printf "$GREEN"  "[*] Success Installing NtlmRelayToEWS"
	else
		printf "$GREEN"  "[*] Success Installed NtlmRelayToEWS"
	fi

	NetRipper="netripper"
	if [ ! -d "/usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper" ]; then
		mkdir -p /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper
		wget https://github.com/NytroRST/NetRipper/blob/master/Metasploit/netripper.rb -O /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper/netripper.rb
		wget https://github.com/NytroRST/NetRipper/blob/master/x64/DLL.x64.dll -O /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper/DLL.x64.dll
		wget https://github.com/NytroRST/NetRipper/blob/master/x86/DLL.x86.dll -O /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper/DLL.x86.dll
		wget https://github.com/NytroRST/NetRipper/blob/master/x64/NetRipper.x64.exe -O /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper/NetRipper.x64.exe
		wget https://github.com/NytroRST/NetRipper/blob/master/x86/NetRipper.x86.exe -O /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper/NetRipper.x86.exe
		chmod 755 /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper/*
		cat > /usr/bin/$NetRipper << EOF
#!/bin/bash
cd /usr/share/metasploit-framework/modules/post/windows/gather/$NetRipper;wine NetRipper.x64.exe "\$@"
EOF
		chmod +x /usr/bin/$NetRipper
		menu_entry "Credential-Access" "Red-Team" "NetRipper" "/usr/share/kali-menu/exec-in-shell '$NetRipper'"
		printf "$GREEN"  "[*] Success Installing NetRipper"
	else
		printf "$GREEN"  "[*] Success Installed NetRipper"
	fi


	printf "$YELLOW"  "# -----------------------------------------Discovery-Red-Team---------------------------------------- #"
	# Install Repository Tools
	apt install -qy bloodhound 

	# Install Python3 pip
	discovery_pip="networkx bloodhound acltoolkit-ad"
	pip_installer "Discovery" "Red-Team" "$discovery_pip"

	# Install Nodejs NPM
	# discovery_npm=""
	npm_installer "Discovery" "Red-Team" "$discovery_npm"

	# Install Ruby GEM
	# discovery_gem=""
	gem_installer "Discovery" "Red-Team" "$discovery_gem"

	# Install Golang
	# discovery_golang=""
	go_installer "Discovery" "Red-Team" "$discovery_golang"

	AdExplorer="adexplorer"
	if [ ! -d "/usr/share/$AdExplorer" ]; then
		mkdir -p /usr/share/adexplorer
		wget https://download.sysinternals.com/files/AdExplorer.zip -O /tmp/$AdExplorer.zip
		unzip /tmp/$AdExplorer.zip -d /usr/share/$AdExplorer;rm -f /tmp/$AdExplorer.zip
		chmod 755 /usr/share/$AdExplorer/*
		cat > /usr/bin/$AdExplorer << EOF
#!/bin/bash
cd /usr/share/$AdExplorer;wine ADExplorer.exe "\$@"
EOF
		chmod +x /usr/bin/$AdExplorer
		menu_entry "Discovery" "Red-Team" "AdExplorer" "/usr/share/kali-menu/exec-in-shell '$AdExplorer'"
		printf "$GREEN"  "[*] Success Installing AdExplorer"
	else
		printf "$GREEN"  "[*] Success Installed AdExplorer"
	fi


	printf "$YELLOW"  "# -------------------------------------Lateral-Movement-Red-Team------------------------------------- #"
	# Install Repository Tools
	apt install -qy pptpd kerberoast isr-evilgrade proxychains

	# Install Python3 pip
	lateral_movement_pip="coercer krbjack"
	pip_installer "Lateral-Movement" "Red-Team" "$lateral_movement_pip"

	# Install Nodejs NPM
	# lateral_movement_npm=""
	npm_installer "Lateral-Movement" "Red-Team" "$lateral_movement_npm"

	# Install Ruby GEM
	lateral_movement_gem="evil-winrm"
	gem_installer "Lateral-Movement" "Red-Team" "$lateral_movement_gem"

	# Install Golang
	# lateral_movement_golang=""
	go_installer "Lateral-Movement" "Red-Team" "$lateral_movement_golang"

	SCShell="scshell"
	if [ ! -d "/usr/share/$SCShell" ]; then
		git clone https://github.com/Mr-Un1k0d3r/SCShell /usr/share/$SCShell
		chmod 755 /usr/share/$SCShell/*
		cat > /usr/bin/$SCShell << EOF
#!/bin/bash
cd /usr/share/$SCShell;wine SCShell.exe "\$@"
EOF
		chmod +x /usr/bin/$SCShell
		menu_entry "Lateral-Movement" "Red-Team" "SCShell" "/usr/share/kali-menu/exec-in-shell '$SCShell'"
		printf "$GREEN"  "[*] Success Installing SCShell"
	else
		printf "$GREEN"  "[*] Success Installed SCShell"
	fi

	Amnesiac="amnesiac"
	if [ ! -d "/usr/share/$Amnesiac" ]; then
		git clone https://github.com/Leo4j/Amnesiac /usr/share/$Amnesiac
		chmod 755 /usr/share/$Amnesiac/*
		cat > /usr/bin/$Amnesiac << EOF
#!/bin/bash
cd /usr/share/$Amnesiac;pwsh -c "Import-Module ./Amnesiac.ps1; Amnesiac" "\$@"
EOF
		chmod +x /usr/bin/$Amnesiac
		menu_entry "Lateral-Movement" "Red-Team" "Amnesiac" "/usr/share/kali-menu/exec-in-shell '$Amnesiac'"
		printf "$GREEN"  "[*] Success Installing  Amnesiac"
	else
		printf "$GREEN"  "[*] Success Installed  Amnesiac"
	fi


	printf "$YELLOW"  "# ----------------------------------------Collection-Red-Team---------------------------------------- #"
	# Install Repository Tools
	apt install -qy tigervnc-viewer 

	# Install Python3 pip
	# collection_pip=""
	pip_installer "Collection" "Red-Team" "$collection_pip"

	# Install Nodejs NPM
	# collection_npm=""
	npm_installer "Collection" "Red-Team" "$collection_npm"

	# Install Ruby GEM
	# collection_gem=""
	gem_installer "Collection" "Red-Team" "$collection_gem"

	# Install Golang
	# collection_golang=""
	go_installer "Collection" "Red-Team" "$collection_golang"

	Caldera="caldera"
	if [ ! -d "/usr/share/$Caldera" ]; then
		git clone https://github.com/mitre/caldera /usr/share/$Caldera
		chmod 755 /usr/share/$Caldera/*
		cat > /usr/bin/$Caldera << EOF
#!/bin/bash
cd /usr/share/$Caldera;python3 server.py --insecure "\$@"
EOF
		chmod +x /usr/bin/$Caldera
		pip3 install -r /usr/share/$Caldera/requirements.txt
		menu_entry "Collection" "Red-Team" "Caldera" "/usr/share/kali-menu/exec-in-shell '$Caldera'"
		printf "$GREEN"  "[*] Success Installing Caldera"
	else
		printf "$GREEN"  "[*] Success Installed Caldera"
	fi


	printf "$YELLOW"  "# ------------------------------------Command-and-Control-Red-Team----------------------------------- #"
	# Install Repository Tools
	apt install -qy powershell-empire koadic chisel poshc2 ibombshell silenttrinity merlin poshc2 

	# Install Python3 pip
	command_and_control_pip="deathstar-empire praw powerhub"
	pip_installer "Command-and-Control" "Red-Team" "$command_and_control_pip"

	# Install Nodejs NPM
	# command_and_control_npm=""
	npm_installer "Command-and-Control" "Red-Team" "$command_and_control_npm"

	# Install Ruby GEM
	# command_and_control_gem=""
	gem_installer "Command-and-Control" "Red-Team" "$command_and_control_gem"

	# Install Golang
	# command_and_control_golang=""
	go_installer "Command-and-Control" "Red-Team" "$command_and_control_golang"

	PhoenixC2="phoenixc2"
	if [ ! -d "/usr/share/$PhoenixC2" ]; then
		git clone https://github.com/screamz2k/PhoenixC2 /usr/share/$PhoenixC2
		chmod 755 /usr/share/$PhoenixC2/*
		cat > /usr/bin/$PhoenixC2 << EOF
#!/bin/bash
cd /usr/share/$PhoenixC2;poetry run phserver "\$@"
EOF
		chmod +x /usr/bin/$PhoenixC2
		cd /usr/share/$PhoenixC2;pip3 install poetry;poetry install
		menu_entry "Command-and-Control" "Red-Team" "PhoenixC2" "/usr/share/kali-menu/exec-in-shell '$PhoenixC2 -h'"
		printf "$GREEN"  "[*] Success Installing PhoenixC2"
	else
		printf "$GREEN"  "[*] Success Installed PhoenixC2"
	fi

	Nebula="nebula"
	if [ ! -d "/usr/share/$Nebula" ]; then
		git clone https://github.com/gl4ssesbo1/Nebula /usr/share/$Nebula
		chmod 755 /usr/share/$Nebula/*
		cat > /usr/bin/$Nebula << EOF
#!/bin/bash
cd /usr/share/$Nebula;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$Nebula
		pip3 install -r /usr/share/$Nebula/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "Nebula" "/usr/share/kali-menu/exec-in-shell '$Nebula'"
		printf "$GREEN"  "[*] Success Installing Nebula"
	else
		printf "$GREEN"  "[*] Success Installed Nebula"
	fi

	Mistica="mistica"
	if [ ! -d "/usr/share/$Mistica" ]; then
		git clone https://github.com/IncideDigital/Mistica /usr/share/$Mistica
		chmod 755 /usr/share/$Mistica/*
		cat > /usr/bin/$Mistica << EOF
#!/bin/bash
cd /usr/share/$Mistica;python3 ms.py "\$@"
EOF
		chmod +x /usr/bin/$Mistica
		menu_entry "Command-and-Control" "Red-Team" "Mistica" "/usr/share/kali-menu/exec-in-shell '$Mistica -h'"
		printf "$GREEN"  "[*] Success Installing Mistica"
	else
		printf "$GREEN"  "[*] Success Installed Mistica"
	fi

	EvilOSX="evilosx"
	if [ ! -d "/usr/share/$EvilOSX" ]; then
		git clone https://github.com/Marten4n6/EvilOSX /usr/share/$EvilOSX
		chmod 755 /usr/share/$EvilOSX/*
		cat > /usr/bin/$EvilOSX << EOF
#!/bin/bash
cd /usr/share/$EvilOSX;python3 start.py "\$@"
EOF
		chmod +x /usr/bin/$EvilOSX
		pip3 install -r /usr/share/$EvilOSX/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "EvilOSX" "/usr/share/kali-menu/exec-in-shell '$EvilOSX'"
		printf "$GREEN"  "[*] Success Installing EvilOSX"
	else
		printf "$GREEN"  "[*] Success Installed EvilOSX"
	fi

	EggShell="eggshell"
	if [ ! -d "/usr/share/$EggShell" ]; then
		git clone https://github.com/lucasjacks0n/EggShell /usr/share/$EggShell
		chmod 755 /usr/share/$EggShell/*
		cat > /usr/bin/$EggShell << EOF
#!/bin/bash
cd /usr/share/$EggShell;python2 eggshell.py "\$@"
EOF
		chmod +x /usr/bin/$EggShell
		menu_entry "Command-and-Control" "Red-Team" "EggShell" "/usr/share/kali-menu/exec-in-shell '$EggShell -h'"
		printf "$GREEN"  "[*] Success Installing EggShell"
	else
		printf "$GREEN"  "[*] Success Installed EggShell"
	fi

	GodGenesis="godgenesis"
	if [ ! -d "/usr/share/$GodGenesis" ]; then
		git clone https://github.com/SaumyajeetDas/GodGenesis /usr/share/$GodGenesis
		chmod 755 /usr/share/$GodGenesis/*
		cat > /usr/bin/$GodGenesis << EOF
#!/bin/bash
cd /usr/share/$GodGenesis;python3 c2c.py "\$@"
EOF
		chmod +x /usr/bin/$GodGenesis
		pip3 install -r /usr/share/$GodGenesis/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "GodGenesis" "/usr/share/kali-menu/exec-in-shell '$GodGenesis'"
		printf "$GREEN"  "[*] Success Installing GodGenesis"
	else
		printf "$GREEN"  "[*] Success Installed GodGenesis"
	fi

	PhoneSploit="phonesploit"
	if [ ! -d "/usr/share/$PhoneSploit" ]; then
		git clone https://github.com/AzeemIdrisi/PhoneSploit-Pro /usr/share/$PhoneSploit
		chmod 755 /usr/share/$PhoneSploit/*
		cat > /usr/bin/$PhoneSploit << EOF
#!/bin/bash
cd /usr/share/$PhoneSploit;python3 phonesploitpro.py "\$@"
EOF
		chmod +x /usr/bin/$PhoneSploit
		pip3 install -r /usr/share/$PhoneSploit/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "PhoneSploit" "/usr/share/kali-menu/exec-in-shell '$PhoneSploit'"
		printf "$GREEN"  "[*] Success Installing PhoneSploit"
	else
		printf "$GREEN"  "[*] Success Installed PhoneSploit"
	fi

	MeliziaC2="meliziac2"
	if [ ! -d "/usr/share/$MeliziaC2" ]; then
		git clone https://github.com/demon-i386/MeliziaC2 /usr/share/$MeliziaC2
		chmod 755 /usr/share/$MeliziaC2/*
		cat > /usr/bin/$MeliziaC2 << EOF
#!/bin/bash
cd /usr/share/$MeliziaC2;python3 c2.py "\$@"
EOF
		chmod +x /usr/bin/$MeliziaC2
		menu_entry "Command-and-Control" "Red-Team" "MeliziaC2" "/usr/share/kali-menu/exec-in-shell '$MeliziaC2'"
		printf "$GREEN"  "[*] Success Installing MeliziaC2"
	else
		printf "$GREEN"  "[*] Success Installed MeliziaC2"
	fi

	GCR="gcr"
	if [ ! -d "/usr/share/$GCR" ]; then
		git clone https://github.com/MrSaighnal/GCR-Google-Calendar-RAT /usr/share/$GCR
		chmod 755 /usr/share/$GCR/*
		cat > /usr/bin/$GCR << EOF
#!/bin/bash
cd /usr/share/$GCR;python3 gcr.py "\$@"
EOF
		chmod +x /usr/bin/$GCR
		menu_entry "Command-and-Control" "Red-Team" "Google Calendar RAT" "/usr/share/kali-menu/exec-in-shell '$GCR'"
		printf "$GREEN"  "[*] Success Installing Google Calendar RAT"
	else
		printf "$GREEN"  "[*] Success Installed Google Calendar RAT"
	fi

	MeetC2="meetc2"
	if [ ! -d "/usr/share/$MeetC2" ]; then
		git clone https://github.com/iammaguire/MeetC2 /usr/share/$MeetC2
		chmod 755 /usr/share/$MeetC2/*
		ln -fs /usr/share/$MeetC2/meetc /usr/bin/$MeetC2
		chmod +x /usr/bin/$MeetC2
		menu_entry "Command-and-Control" "Red-Team" "MeetC2" "/usr/share/kali-menu/exec-in-shell '$MeetC2'"
		printf "$GREEN"  "[*] Success Installing MeetC2"
	else
		printf "$GREEN"  "[*] Success Installed MeetC2"
	fi

	PingRAT="pingrat"
	if [ ! -d "/usr/share/$PingRAT" ]; then
		mkdir -p /usr/share/$PingRAT
		wget https://github.com/umutcamliyurt/PingRAT/releases/latest/download/client -O /usr/share/$PingRAT/client
		wget https://github.com/umutcamliyurt/PingRAT/releases/latest/download/server -O /usr/share/$PingRAT/server
		chmod 755 /usr/share/$PingRAT/*
		ln -fs /usr/share/$PingRAT/client /usr/bin/$PingRAT-client
		ln -fs /usr/share/$PingRAT/server /usr/bin/$PingRAT-server
		chmod +x /usr/bin/$PingRAT
		menu_entry "Command-and-Control" "Red-Team" "PingRAT" "/usr/share/kali-menu/exec-in-shell '$PingRAT-client -h'"
		menu_entry "Command-and-Control" "Red-Team" "PingRAT" "/usr/share/kali-menu/exec-in-shell '$PingRAT-server -h'"
		printf "$GREEN"  "[*] Success Installing PingRAT"
	else
		printf "$GREEN"  "[*] Success Installed PingRAT"
	fi

	Ligolomp="ligolo-mp"
	if [ ! -d "/usr/share/$Ligolomp" ]; then
		mkdir -p /usr/share/$Ligolomp
		wget https://github.com/ttpreport/ligolo-mp/releases/latest/download/ligolo-mp_server_1.0.3_linux_amd64 -O /usr/share/$Ligolomp/ligolos
		wget https://github.com/ttpreport/ligolo-mp/releases/latest/download/ligolo-mp_client_1.0.3_linux_amd64 -O /usr/share/$Ligolomp/ligoloc
		wget https://github.com/ttpreport/ligolo-mp/releases/latest/download/ligolo-mp_client_1.0.3_windows_amd64.exe -O /usr/share/$Ligolomp/ligoloc.exe
		chmod 755 /usr/share/$Ligolomp/*
		ln -fs /usr/share/$Ligolomp/ligolos /usr/bin/$Ligolomp
		chmod +x /usr/bin/$Ligolomp
		menu_entry "Command-and-Control" "Red-Team" "Ligolo-mp" "/usr/share/kali-menu/exec-in-shell 'sudo $Ligolomp -h'"
		printf "$GREEN"  "[*] Success Installing Ligolo-mp"
	else
		printf "$GREEN"  "[*] Success Installed Ligolo-mp"
	fi

	Realm="realm"
	if [ ! -d "/usr/share/$Realm" ]; then
		mkdir -p /usr/share/$Realm
		wget https://github.com/spellshift/realm/releases/latest/download/tavern -O /usr/share/$Realm/tavern
		wget https://github.com/spellshift/realm/releases/latest/download/imix-x86_64-unknown-linux-musl -O /usr/share/$Realm/imix
		ln -fs /usr/share/$Realm/imix /usr/bin/imix
		ln -fs /usr/share/$Realm/tavern /usr/bin/tavern
		menu_entry "Command-and-Control" "Red-Team" "Imix" "/usr/share/kali-menu/exec-in-shell 'imix'"
		menu_entry "Red-Team" "Command-and-Control" "Tavern" "/usr/share/kali-menu/exec-in-shell 'tavern'"
		printf "$GREEN"  "[*] Success Installing Realm"
	else
		printf "$GREEN"  "[*] Success Installed Realm"
	fi

	Badrats="badrats"
	if [ ! -d "/usr/share/$Badrats" ]; then
		git clone https://gitlab.com/KevinJClark/badrats /usr/share/$Badrats
		chmod 755 /usr/share/$Badrats/*
		cat > /usr/bin/$Badrats << EOF
#!/bin/bash
cd /usr/share/$Badrats;python3 badrat_server.py "\$@"
EOF
		chmod +x /usr/bin/$Badrats
		pip3 install -r /usr/share/$Badrats/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "Badrats" "/usr/share/kali-menu/exec-in-shell 'sudo $Badrats'"
		printf "$GREEN"  "[*] Success Installing Badrats"
	else
		printf "$GREEN"  "[*] Success Installed Badrats"
	fi

	Mythic="mythic"
	if [ ! -d "/usr/share/$Mythic" ]; then
		git clone https://github.com/its-a-feature/Mythic /usr/share/$Mythic
		chmod 755 /usr/share/$Mythic/*
		cd /usr/share/$Mythic;./install_docker_kali.sh
		cd /usr/share/$Mythic/Mythic_CLI/src;make
		cd /usr/share/$Mythic/mythic-docker/src;make
		ln -fs /usr/share/$Mythic/Mythic_CLI/src/mythic-cli /usr/bin/$Mythic-cli
		ln -fs /usr/share/$Mythic/mythic-docker/src/mythic_server /usr/bin/$Mythic-server
		chmod +x /usr/bin/$Mythic-cli;chmod +x /usr/bin/$Mythic-server
		menu_entry "Command-and-Control" "Red-Team" "Mythic-CLI" "/usr/share/kali-menu/exec-in-shell 'sudo $Mythic-cli'"
		menu_entry "Command-and-Control" "Red-Team" "Mythic-Server" "/usr/share/kali-menu/exec-in-shell 'sudo $Mythic-server'"
		printf "$GREEN"  "[*] Success Installing Mythic"
	else
		printf "$GREEN"  "[*] Success Installed Mythic"
	fi

	NorthStarC2="northstarc2"
	if [ ! -d "/usr/share/$NorthStarC2" ]; then
		git clone https://github.com/EnginDemirbilek/NorthStarC2 /usr/share/$NorthStarC2
		chmod 755 /usr/share/$NorthStarC2/*
		cd /usr/share/$NorthStarC2;./install.sh
		menu_entry "Command-and-Control" "Red-Team" "NorthStarC2" "/usr/share/kali-menu/exec-in-shell 'sudo $NorthStarC2'"
		printf "$GREEN"  "[*] Success Installing NorthStarC2"
	else
		printf "$GREEN"  "[*] Success Installed NorthStarC2"
	fi

	BlackMamba="blackmamba"
	if [ ! -d "/usr/share/$BlackMamba" ]; then
		git clone https://github.com/loseys/BlackMamba /usr/share/$BlackMamba
		chmod 755 /usr/share/$BlackMamba/*
		cat > /usr/bin/$BlackMamba << EOF
#!/bin/bash
cd /usr/share/$BlackMamba;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$BlackMamba
		pip3 install -r /usr/share/$BlackMamba/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "BlackMamba" "/usr/share/kali-menu/exec-in-shell '$BlackMamba'"
		printf "$GREEN"  "[*] Success Installing BlackMamba"
	else
		printf "$GREEN"  "[*] Success Installed BlackMamba"
	fi

	OffensiveNotion="offensivenotion"
	if [ ! -d "/usr/share/$OffensiveNotion" ]; then
		mkdir -p /usr/share/$OffensiveNotion
		wget https://github.com/mttaggart/OffensiveNotion/releases/latest/download/offensive_notion_linux_amd64.zip -O /tmp/$OffensiveNotion.zip
		unzip /tmp/$OffensiveNotion.zip -d /usr/share/$OffensiveNotion;rm -f /tmp/$OffensiveNotion.zip
		chmod 755 /usr/share/$OffensiveNotion/*
		ln -fs /usr/share/$OffensiveNotion/offensive_notion /usr/bin/$OffensiveNotion
		chmod +x /usr/bin/$OffensiveNotion
		menu_entry "Command-and-Control" "Red-Team" "OffensiveNotion" "/usr/share/kali-menu/exec-in-shell '$OffensiveNotion'"
		printf "$GREEN"  "[*] Success Installing OffensiveNotion"
	else
		printf "$GREEN"  "[*] Success Installed OffensiveNotion"
	fi

	RedbloodC2="redbloodc2"
	if [ ! -d "/usr/share/$RedbloodC2" ]; then
		git clone https://github.com/kira2040k/RedbloodC2 /usr/share/$RedbloodC2
		chmod 755 /usr/share/$RedbloodC2/*
		cat > /usr/bin/$RedbloodC2 << EOF
#!/bin/bash
cd /usr/share/$RedbloodC2;node server.js "\$@"
EOF
		chmod +x /usr/bin/$RedbloodC2
		cd /usr/share/$RedbloodC2;npm install
		menu_entry "Command-and-Control" "Red-Team" "RedbloodC2" "/usr/share/kali-menu/exec-in-shell '$RedbloodC2'"
		printf "$GREEN"  "[*] Success Installing RedbloodC2"
	else
		printf "$GREEN"  "[*] Success Installed RedbloodC2"
	fi

	SharpC2="sharpc2"
	if [ ! -d "/usr/share/SharpC2" ]; then
		wget https://github.com/rasta-mouse/SharpC2/releases/latest/download/teamserver-linux.tar.gz -O /tmp/teamserver-linux.tar.gz
		tar -xvf /tmp/teamserver-linux.tar.gz -C /usr/share;rm -f /tmp/teamserver-linux.tar.gz
		ln -fs /usr/share/SharpC2/TeamServer /usr/bin/$SharpC2
		chmod +x /usr/bin/$SharpC2
		menu_entry "Command-and-Control" "Red-Team" "SharpC2" "/usr/share/kali-menu/exec-in-shell '$SharpC2'"
		printf "$GREEN"  "[*] Success Installing SharpC2"
	else
		printf "$GREEN"  "[*] Success Installed SharpC2"
	fi

	emp3r0r="emp3r0r"
	if [ ! -d "/usr/share/$emp3r0r-build" ]; then
		wget https://github.com/jm33-m0/emp3r0r/releases/latest/download/emp3r0r-v1.36.0.tar.xz -O /tmp/$emp3r0r.tar.xz
		tar -xvf /tmp/$emp3r0r.tar.xz -C /usr/share;rm -f /tmp/$emp3r0r.tar.xz
		chmod 755 /usr/share/$emp3r0r-build/*
		cd /usr/share/$emp3r0r-build;./emp3r0r --install
		menu_entry "Command-and-Control" "Red-Team" "emp3r0r" "/usr/share/kali-menu/exec-in-shell '$emp3r0r'"
		printf "$GREEN"  "[*] Success Installing emp3r0r"
	else
		printf "$GREEN"  "[*] Success Installed emp3r0r"
	fi

	CHAOS="chaos"
	if [ ! -d "/usr/share/$CHAOS" ]; then
		git clone https://github.com/tiagorlampert/CHAOS /usr/share/$CHAOS
		chmod 755 /usr/share/$CHAOS/*
		cat > /usr/bin/$CHAOS << EOF
#!/bin/bash
cd /usr/share/$CHAOS;PORT=8080 SQLITE_DATABASE=chaos go run cmd/chaos/main.go "\$@"
EOF
		chmod +x /usr/bin/$CHAOS
		menu_entry "Command-and-Control" "Red-Team" "CHAOS" "/usr/share/kali-menu/exec-in-shell '$CHAOS'"
		printf "$GREEN"  "[*] Success Installing CHAOS"
	else
		printf "$GREEN"  "[*] Success Installed CHAOS"
	fi

	GoDoH="godoh"
	if [ ! -d "/usr/share/$GoDoH" ]; then
		mkdir -p /usr/share/$GoDoH
		wget https://github.com/sensepost/godoh/releases/latest/download/godoh-linux64 -O /usr/share/$GoDoH/godoh
		chmod 755 /usr/share/$GoDoH/*
		ln -fs /usr/share/$GoDoH/godoh /usr/bin/$GoDoH
		chmod +x /usr/bin/$GoDoH
		menu_entry "Command-and-Control" "Red-Team" "GoDoH" "/usr/share/kali-menu/exec-in-shell '$GoDoH -h'"
		printf "$GREEN"  "[*] Success Installing GoDoH"
	else
		printf "$GREEN"  "[*] Success Installed GoDoH"
	fi

	Silver="sliver"
	if [ ! -d "/usr/share/$Silver" ]; then
		mkdir -p /usr/share/$Silver
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -O /usr/share/$Silver/sliver_client
		chmod 755 /usr/share/$Silver/*
		ln -fs /usr/share/$Silver/sliver_client /usr/bin/"$Silver"c
		chmod +x /usr/bin/"$Silver"c
		menu_entry "Command-and-Control" "Red-Team" "SilverC" "/usr/share/kali-menu/exec-in-shell 'sudo "$Silver"c -h'"
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/share/$Silver/sliver_server
		chmod 755 /usr/share/$Silver/*
		ln -fs /usr/share/$Silver/sliver_server /usr/bin/"$Silver"s
		chmod +x /usr/bin/"$Silver"s
		menu_entry "Command-and-Control" "Red-Team" "SilverS" "/usr/share/kali-menu/exec-in-shell 'sudo "$Silver"s -h'"
		printf "$GREEN"  "[*] Success Installing Silver"
	else
		printf "$GREEN"  "[*] Success Installed Silver"
	fi

	Havoc="havoc"
	if [ ! -d "/usr/share/$Havoc" ]; then
		git clone https://github.com/HavocFramework/Havoc /usr/share/$Havoc
		chmod 755 /usr/share/$Havoc/*
		cd /user/share/$Havoc/client;make
		ln -fs /user/share/$Havoc/client/havoc /usr/bin/$Havoc
		chmod +x /usr/bin/$Havoc
		menu_entry "Command-and-Control" "Red-Team" "Havoc" "/usr/share/kali-menu/exec-in-shell 'sudo $Havoc -h'"
		cd /user/share/$Havoc/Teamserver;./Install.sh;make
		ln -fs /user/share/$Havoc/Teamserver/teamserver /usr/bin/"$Havoc"ts
		chmod +x /usr/bin/"$Havoc"ts
		menu_entry "Command-and-Control" "Red-Team" "HavocTS" "/usr/share/kali-menu/exec-in-shell 'sudo "$Havoc"ts -h'"
		printf "$GREEN"  "[*] Success Installing Havoc"
	else
		printf "$GREEN"  "[*] Success Installed Havoc"
	fi


	printf "$YELLOW"  "# ---------------------------------------Exfiltration-Red-Team--------------------------------------- #"
	# Install Repository Tools
	apt install -qy haproxy xplico certbot stunnel4 httptunnel onionshare proxychains proxify privoxy 

	# Install Python3 pip
	exfiltration_pip="updog pivotnacci"
	pip_installer "Exfiltration" "Red-Team" "$exfiltration_pip"

	# Install Nodejs NPM
	# exfiltration_npm=""
	npm_installer "Exfiltration" "Red-Team" "$exfiltration_npm"

	# Install Ruby GEM
	# exfiltration_gem=""
	gem_installer "Exfiltration" "Red-Team" "$exfiltration_gem"

	# Install Golang
	# exfiltration_golang=""
	go_installer "Exfiltration" "Red-Team" "$exfiltration_golang"

	Ngrok="ngrok"
	if [ ! -f "/usr/bin/$Ngrok" ]; then
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/$Ngrok.tgz
		tar -xvf /tmp/$Ngrok.tgz -C /usr/bin;rm -f /tmp/$Ngrok.tgz
		chmod +x /usr/bin/$Ngrok
		menu_entry "Web" "Penetration-Testing" "Ngrok" "/usr/share/kali-menu/exec-in-shell '$Ngrok -h'"
		printf "$GREEN"  "[*] Success Installing Ngrok"
	else
		printf "$GREEN"  "[*] Success Installed Ngrok"
	fi

	NoIP="noip"
	if [ ! -f "/usr/local/bin/noip2" ]; then
		mkdir -p /usr/share/$NoIP
		wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/$NoIP.tar.gz
		tar -xzf /tmp/$NoIP.tar.gz -C /usr/share/$NoIP;rm -f /tmp/$NoIP.tar.gz
		chmod 755 /usr/share/$NoIP/*;cd /usr/share/$NoIP;make;make install
		menu_entry "Web" "Penetration-Testing" "NoIP" "/usr/share/kali-menu/exec-in-shell '$NoIP -h'"
		printf "$GREEN"  "[*] Success Installing NoIP"
	else
		printf "$GREEN"  "[*] Success Installed NoIP"
	fi

	DNSExfiltrator="dnsexfiltrator"
	if [ ! -d "/usr/share/$DNSExfiltrator" ]; then
		git clone https://github.com/Arno0x/DNSExfiltrator /usr/share/$DNSExfiltrator
		chmod 755 /usr/share/$DNSExfiltrator/*
		cat > /usr/bin/$DNSExfiltrator << EOF
#!/bin/bash
cd /usr/share/$DNSExfiltrator;python2 dnsexfiltrator.py "\$@"
EOF
		chmod +x /usr/bin/$DNSExfiltrator
		pip3 install -r /usr/share/$DNSExfiltrator/requirements.txt
		menu_entry "Exfiltration" "Red-Team" "DNSExfiltrator" "/usr/share/kali-menu/exec-in-shell '$DNSExfiltrator -h'"
		printf "$GREEN"  "[*] Success Installing DNSExfiltrator"
	else
		printf "$GREEN"  "[*] Success Installed DNSExfiltrator"
	fi

	BobTheSmuggler="bobthesmuggler"
	if [ ! -d "/usr/share/$BobTheSmuggler" ]; then
		git clone https://github.com/TheCyb3rAlpha/BobTheSmuggler /usr/share/$BobTheSmuggle
		chmod 755 /usr/share/$BobTheSmuggle/*
		cat > /usr/bin/$BobTheSmuggle << EOF
#!/bin/bash
cd /usr/share/$BobTheSmuggle;python3 BobTheSmuggler.py "\$@"
EOF
		chmod +x /usr/bin/$BobTheSmuggle
		pip3 install python-magic py7zr pyminizip
		menu_entry "Exfiltration" "Red-Team" "BobTheSmuggler" "/usr/share/kali-menu/exec-in-shell '$BobTheSmuggle -h'"
		printf "$GREEN"  "[*] Success Installing BobTheSmuggler"
	else
		printf "$GREEN"  "[*] Success Installed BobTheSmuggler"
	fi

	SSHSnake="SSHSnake"
	if [ ! -d "/usr/share/$SSHSnake" ]; then
		git clone https://github.com/MegaManSec/SSH-Snake /usr/share/$SSHSnake
		chmod 755 /usr/share/$SSHSnake/*
		cat > /usr/bin/$SSHSnake << EOF
#!/bin/bash
cd /usr/share/$SSHSnake;bash Snake.sh "\$@"
EOF
		chmod +x /usr/bin/$SSHSnake
		menu_entry "Exfiltration" "Red-Team" "SSH-Snake" "/usr/share/kali-menu/exec-in-shell '$SSHSnake -h'"
		printf "$GREEN"  "[*] Success Installing SSH-Snake"
	else
		printf "$GREEN"  "[*] Success Installed SSH-Snake"
	fi

	ReverseSSH="reversessh"
	if [ ! -d "/usr/share/$ReverseSSH" ]; then
		mkdir -p /usr/share/$ReverseSSH
		wget https://github.com/Fahrj/reverse-ssh/releases/latest/download/reverse-sshx64 -O /usr/share/$ReverseSSH/reversessh
		chmod 755 /usr/share/$ReverseSSH/*
		cat > /usr/bin/$ReverseSSH << EOF
#!/bin/bash
cd /usr/share/$ReverseSSH;./reversessh "\$@"
EOF
		chmod +x /usr/bin/$ReverseSSH
		menu_entry "Exfiltration" "Red-Team" "ReverseSSH" "/usr/share/kali-menu/exec-in-shell '$ReverseSSH -h'"
		printf "$GREEN"  "[*] Success Installing ReverseSSH"
	else
		printf "$GREEN"  "[*] Success Installed ReverseSSH"
	fi

	transfersh="transfersh"
	if [ ! -d "/usr/share/$transfersh" ]; then
		mkdir -p /usr/share/$transfersh
		wget https://github.com/dutchcoders/transfer.sh/releases/latest/download/transfersh-v1.6.1-linux-amd64 -O /usr/share/$transfersh/transfersh
		chmod 755 /usr/share/$transfersh/*
		ln -fs /usr/share/$transfersh/transfersh /usr/bin/transfersh
		chmod +x /usr/bin/$transfersh
		menu_entry "Exfiltration" "Red-Team" "transfer.sh" "/usr/share/kali-menu/exec-in-shell '$transfersh -h'"
		printf "$GREEN"  "[*] Success Installing transfer.sh"
	else
		printf "$GREEN"  "[*] Success Installed transfer.sh"
	fi

	DNSlivery="dnslivery"
	if [ ! -d "/usr/share/$DNSlivery" ]; then
		git clone https://github.com/no0be/DNSlivery /usr/share/$DNSlivery
		chmod 755 /usr/share/$DNSlivery/*
		cat > /usr/bin/$DNSlivery << EOF
#!/bin/bash
cd /usr/share/$DNSlivery;python3 dnslivery.py "\$@"
EOF
		chmod +x /usr/bin/$DNSlivery
		pip3 install -r /usr/share/$DNSlivery/requirements.txt
		menu_entry "Exfiltration" "Red-Team" "DNSlivery" "/usr/share/kali-menu/exec-in-shell '$DNSlivery -h'"
		printf "$GREEN"  "[*] Success Installing DNSlivery"
	else
		printf "$GREEN"  "[*] Success Installed DNSlivery"
	fi

	WebDavDelivery="webdavdelivery"
	if [ ! -d "/usr/share/$WebDavDelivery" ]; then
		git clone https://github.com/Arno0x/WebDavDelivery /usr/share/$WebDavDelivery
		chmod 755 /usr/share/$WebDavDelivery/*
		cat > /usr/bin/$WebDavDelivery << EOF
#!/bin/bash
cd /usr/share/$WebDavDelivery;python3 webDavDelivery.py "\$@"
EOF
		chmod +x /usr/bin/$WebDavDelivery
		menu_entry "Exfiltration" "Red-Team" "WebDavDelivery" "/usr/share/kali-menu/exec-in-shell '$WebDavDelivery -h'"
		printf "$GREEN"  "[*] Success Installing WebDavDelivery"
	else
		printf "$GREEN"  "[*] Success Installed WebDavDelivery"
	fi

	WSTunnel="wstunnel"
	if [ ! -d "/usr/share/$WSTunnel" ]; then
		mkdir -p /usr/share/$WSTunnel
		wget https://github.com/erebe/wstunnel/releases/latest/download/wstunnel_9.2.5_linux_amd64.tar.gz -O /tmp/$WSTunnel.tar.gz
		tar -xvf /tmp/$WSTunnel.tar.gz -C /usr/share/$WSTunnel;rm -f /tmp/$WSTunnel.tar.gz
		chmod 755 /usr/share/$WSTunnel/*
		ln -fs /usr/share/$WSTunnel/wstunnel /usr/bin/$WSTunnel
		chmod +x /usr/bin/$WSTunnel
		menu_entry "Exfiltration" "Red-Team" "WSTunnel" "/usr/share/kali-menu/exec-in-shell '$WSTunnel -h'"
		printf "$GREEN"  "[*] Success Installing WSTunnel"
	else
		printf "$GREEN"  "[*] Success Installed WSTunnel"
	fi

	IPFS="kubo"
	if [ ! -d "/usr/share/$IPFS" ]; then
		wget https://github.com/ipfs/kubo/releases/latest/download/kubo_v0.28.0_linux-amd64.tar.gz -O /tmp/$IPFS.tar.gz
		tar -xvf /tmp/$IPFS.tar.gz -C /usr/share;rm -f /tmp/$IPFS.tar.gz
		chmod 755 /usr/share/$IPFS/*
		cd /usr/share/$IPFS;./install.sh
		menu_entry "Exfiltration" "Red-Team" "IPFS" "/usr/share/kali-menu/exec-in-shell '$IPFS'"
		printf "$GREEN"  "[*] Success Installing IPFS"
	else
		printf "$GREEN"  "[*] Success Installed IPFS"
	fi

	FRP="frp"
	if [ ! -d "/usr/share/$FRP" ]; then
		wget https://github.com/fatedier/frp/releases/latest/download/frp_0.57.0_linux_amd64.tar.gz -O /tmp/$FRP.tar.gz
		tar -xzf /tmp/$FRP.tar.gz -C /usr/share/$FRP;rm -f /tmp/$FRP.tar.gz
		chmod 755 /usr/share/$FRP/*
		ln -fs /usr/share/$FRP/frps /usr/bin/$FRP
		chmod +x /usr/bin/$FRP
		menu_entry "Exfiltration" "Red-Team" "FRP" "/usr/share/kali-menu/exec-in-shell '$FRP -h'"
		printf "$GREEN"  "[*] Success Installing FRP"
	else
		printf "$GREEN"  "[*] Success Installed FRP"
	fi

	rathole="rathole"
	if [ ! -d "/usr/share/$rathole" ]; then
		mkdir -p /usr/share/$rathole
		wget https://github.com/rapiz1/rathole/releases/latest/download/rathole-x86_64-unknown-linux-gnu.zip -O /tmp/$rathole.zip
		unzip /tmp/$rathole.zip -d /usr/share/$rathole;rm -f /tmp/$rathole.zip
		chmod 755 /usr/share/$rathole/*
		ln -fs /usr/share/$rathole/rathole /usr/bin/$rathole
		chmod +x /usr/bin/$rathole
		menu_entry "Exfiltration" "Red-Team" "rathole" "/usr/share/kali-menu/exec-in-shell '$rathole -h'"
		printf "$GREEN"  "[*] Success Installing rathole"
	else
		printf "$GREEN"  "[*] Success Installed rathole"
	fi

	GOProxy="goproxy"
	if [ ! -d "/usr/share/$GOProxy" ]; then
		mkdir -p /usr/share/$GOProxy
		wget https://github.com/snail007/goproxy/releases/latest/download/proxy-linux-amd64.tar.gz -O /tmp/$GOProxy.tar.gz
		tar -xvf /tmp/$GOProxy.tar.gz -C /usr/share/$GOProxy;rm -f /tmp/$GOProxy.tar.gz
		chmod 755 /usr/share/$GOProxy/*
		ln -fs /usr/share/$GOProxy/proxy /usr/bin/$GOProxy
		chmod +x /usr/bin/$GOProxy
		menu_entry "Exfiltration" "Red-Team" "GOProxy" "/usr/share/kali-menu/exec-in-shell '$GOProxy -h'"
		printf "$GREEN"  "[*] Success Installing GOProxy"
	else
		printf "$GREEN"  "[*] Success Installed GOProxy"
	fi


	printf "$YELLOW"  "# ------------------------------------------Impact-Red-Team------------------------------------------ #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# impact_pip=""
	pip_installer "Impact" "Red-Team" "$impact_pip"

	# Install Nodejs NPM
	# impact_npm=""
	npm_installer "Impact" "Red-Team" "$impact_npm"

	# Install Ruby GEM
	# impact_gem=""
	gem_installer "Impact" "Red-Team" "$impact_gem"

	# Install Golang
	# impact_golang=""
	go_installer "Impact" "Red-Team" "$impact_golang"

	exit
}


ics_security ()
{
	printf "$YELLOW"  "# ----------------------------------Penetration-Testing-ICS-Security--------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# penetration_testing_pip=""
	pip_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_pip"

	# Install Nodejs NPM
	# penetration_testing_npm=""
	npm_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_npm"

	# Install Ruby GEM
	penetration_testing_gem="modbus-cli"
	gem_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_gem"

	# Install Golang
	# penetration_testing_golang=""
	go_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_golang"

	S7Scan="s7scan"
	if [ ! -d "/usr/share/$S7Scan" ]; then
		git clone https://github.com/klsecservices/s7scan /usr/share/$S7Scan
		chmod 755 /usr/share/$S7Scan/*
		cat > /usr/bin/$S7Scan << EOF
#!/bin/bash
cd /usr/share/$S7Scan;python2 s7scan.py "\$@"
EOF
		chmod +x /usr/bin/$S7Scan
		menu_entry "Penetration-Testing" "ICS-Security" "S7Scan" "/usr/share/kali-menu/exec-in-shell '$S7Scan -h'"
		printf "$GREEN"  "[*] Success Installing S7Scan"
	else
		printf "$GREEN"  "[*] Success Installed S7Scan"
	fi

	ModbusPal="modbuspal"
	if [ ! -d "/usr/share/$ModbusPal" ]; then
		mkdir -p /usr/share/$ModbusPal
		wget https://cfhcable.dl.sourceforge.net/project/modbuspal/modbuspal/RC%20version%201.6c/ModbusPal.jar -O /usr/share/$ModbusPal/ModbusPal.jar
		chmod 755 /usr/share/$ModbusPal/*
		cat > /usr/bin/$ModbusPal << EOF
#!/bin/bash
cd /usr/share/$ModbusPal;java -jar ModbusPal.jar "\$@"
EOF
		chmod +x /usr/bin/$ModbusPal
		menu_entry "Penetration-Testing" "ICS-Security" "ModbusPal" "/usr/share/kali-menu/exec-in-shell '$ModbusPal -h'"
		printf "$GREEN"  "[*] Success Installing ModbusPal"
	else
		printf "$GREEN"  "[*] Success Installed ModbusPal"
	fi

	ISF="isf"
	if [ ! -d "/usr/share/$ISF" ]; then
		git clone https://github.com/dark-lbp/isf /usr/share/$ISF
		chmod 755 /usr/share/$ISF/*
		cat > /usr/bin/$ISF << EOF
#!/bin/bash
cd /usr/share/$ISF;python2 isf.py "\$@"
EOF
		chmod +x /usr/bin/$ISF
		pip2 install -r /usr/share/$ISF/requirements.txt
		menu_entry "Penetration-Testing" "ICS-Security" "ISF" "/usr/share/kali-menu/exec-in-shell '$ISF -h'"
		printf "$GREEN"  "[*] Success Installing ISF"
	else
		printf "$GREEN"  "[*] Success Installed ISF"
	fi


	printf "$YELLOW"  "# ----------------------------------------Red-Team-ICS-Security-------------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# red_team_pip=""
	pip_installer "Red-Team" "ICS-Security" "$red_team_pip"

	# Install Nodejs NPM
	# red_team_npm=""
	npm_installer "Red-Team" "ICS-Security" "$red_team_npm"

	# Install Ruby GEM
	# red_team_gem=""
	gem_installer "Red-Team" "ICS-Security" "$red_team_gem"

	# Install Golang
	# red_team_golang=""
	go_installer "Red-Team" "ICS-Security" "$red_team_golang"


	printf "$YELLOW"  "# ------------------------------------Digital-Forensic-ICS-Security---------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# digital_forensic_pip=""
	pip_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_pip"

	# Install Nodejs NPM
	# digital_forensic_npm=""
	npm_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_npm"

	# Install Ruby GEM
	# digital_forensic_gem=""
	gem_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_gem"

	# Install Golang
	# digital_forensic_golang=""
	go_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_golang"


	printf "$YELLOW"  "# ---------------------------------------Blue-Team-ICS-Security-------------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	blue_team_pip="conpot"
	pip_installer "Blue-Team" "ICS-Security" "$blue_team_pip"

	# Install Nodejs NPM
	# blue_team_npm=""
	npm_installer "Blue-Team" "ICS-Security" "$blue_team_npm"

	# Install Ruby GEM
	# blue_team_gem=""
	gem_installer "Blue-Team" "ICS-Security" "$blue_team_gem"

	# Install Golang
	# blue_team_golang=""
	go_installer "Blue-Team" "ICS-Security" "$blue_team_golang"

	exit
}


digital_forensic ()
{
	printf "$YELLOW"  "# --------------------------------Reverse-Engineeting-Digital-Forensic------------------------------- #"
	# Install Repository Tools
	apt install -qy ghidra foremost qpdf kafkacat gdb pspy 

	# Install Python3 pip
	reverse_engineering_pip="capstone decompyle3 uncompyle6 Depix andriller radare2 peepdf-3 pngcheck qiling fwhunt-scan"
	pip_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_pip"

	# Install Nodejs NPM
	# reverse_engineering_npm=""
	npm_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_npm"

	# Install Ruby GEM
	# reverse_engineering_gem=""
	gem_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_gem"

	# Install Golang
	# reverse_engineering_golang=""
	go_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_golang"


	printf "$YELLOW"  "# ----------------------------------Malware-Analysis-Digital-Forensic-------------------------------- #"
	# Install Repository Tools
	apt install -qy autopsy exiftool inetsim outguess steghide steghide-doc hexyl audacity stenographer stegosuite dnstwist rkhunter tesseract-ocr feh strace sonic-visualiser bpftool pev readpe 

	# Install Python3 pip
	malware_analysis_pip="stegcracker dnschef-ng stego-lsb stegoveritas stegano xortool stringsifter oletools dnfile dotnetfile malchive mwcp chepy unipacker rekall ioc-fanger ioc-scan"
	pip_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_pip"

	# Install Nodejs NPM
	malware_analysis_npm="box-js f5stegojs"
	npm_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_npm"

	# Install Ruby GEM
	malware_analysis_gem="pedump zsteg"
	gem_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_gem"

	# Install Golang
	malware_analysis_golang="
go install github.com/tomchop/unxor@latest;ln -fs ~/go/bin/unxor /usr/bin/unxor"
	go_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_golang"

	Dangerzone="dangerzone"
	if [ ! -d "/usr/share/$Dangerzone" ]; then
		gpg --keyserver hkps://keys.openpgp.org \
    		--no-default-keyring --keyring ./fpf-apt-tools-archive-keyring.gpg \
    		--recv-keys "DE28 AB24 1FA4 8260 FAC9 B8BA A7C9 B385 2260 4281"
		mkdir -p /etc/apt/keyrings/;mv fpf-apt-tools-archive-keyring.gpg /etc/apt/keyrings
		apt update;apt install -qy dangerzone
		printf "$GREEN"  "[*] Sucess Installing Dangerzone"
	else
		printf "$GREEN"  "[*] Sucess Installed Dangerzone"
	fi

	StegoCracker="stegocracker"
	if [ ! -d "/usr/share/$StegoCracker" ]; then
		git clone https://github.com/W1LDN16H7/StegoCracker /usr/share/$StegoCracker
		chmod 755 /usr/share/$StegoCracker/*
		pip3 install -r /usr/share/$StegoCracker/requirements.txt 
		cd /usr/share/$StegoCracker;python3 setup.py install;bash install.sh 
		menu_entry "Malware-Analysis" "Digital-Forensic" "StegoCracker" "/usr/share/kali-menu/exec-in-shell 'stego -h'"
		printf "$GREEN"  "[*] Success Installing StegoCracker"
	else
		printf "$GREEN"  "[*] Success Installed StegoCracker"
	fi

	OpenStego="openstego"
	if [ ! -d "/usr/share/$OpenStego" ]; then
		wget https://github.com/syvaidya/openstego/releases/latest/download/openstego_0.8.6-1_all.deb -O /tmp/$OpenStego.deb
		chmod +x /tmp/$OpenStego.deb;dpkg -i /tmp/$OpenStego.deb;apt --fix-broken install -qy;rm -f /tmp/$OpenStego.deb
		menu_entry "Malware-Analysis" "Digital-Forensic" "OpenStego" "/usr/share/kali-menu/exec-in-shell 'sudo $OpenStego -h'"
		printf "$GREEN"  "[*] Success Installing OpenStego"
	else
		printf "$GREEN"  "[*] Success Installed OpenStego"
	fi

	StegoSaurus="stegosaurus"
	if [ ! -d "/usr/share/$StegoSaurus" ]; then
		mkdir -p /usr/share/$StegoSaurus
		wget https://github.com/AngelKitty/stegosaurus/releases/latest/download/stegosaurus -O /usr/share/$StegoSaurus/stegosaurus
		chmod 755 /usr/share/$StegoSaurus/*
		ln -fs /usr/share/$StegoSaurus/stegosaurus /usr/bin/$StegoSaurus
		chmod +x /usr/bin/$StegoSaurus
		menu_entry "Malware-Analysis" "Digital-Forensic" "StegoSaurus" "/usr/share/kali-menu/exec-in-shell 'sudo $StegoSaurus -h'"
		printf "$GREEN"  "[*] Success Installing StegoSaurus"
	else
		printf "$GREEN"  "[*] Success Installed StegoSaurus"
	fi

	AudioStego="audiostego"
	if [ ! -d "/usr/share/$AudioStego" ]; then
		git clone https://github.com/danielcardeenas/AudioStego /usr/share/$AudioStego
		cd /usr/share/$AudioStego;mkdir build;cd build;cmake ..;make
		chmod 755 /usr/share/$AudioStego/*
		ln -fs /usr/share/$AudioStego/build/hideme /usr/bin/hideme
		chmod +x /usr/bin/hideme
		menu_entry "Malware-Analysis" "Digital-Forensic" "AudioStego" "/usr/share/kali-menu/exec-in-shell 'sudo hideme -h'"
		printf "$GREEN"  "[*] Success Installing AudioStego"
	else
		printf "$GREEN"  "[*] Success Installed AudioStego"
	fi

	CloackedPixel="cloackedpixel"
	if [ ! -d "/usr/share/$CloackedPixel" ]; then
		git clone https://github.com/livz/cloacked-pixel /usr/share/$CloackedPixel
		chmod 755 /usr/share/$CloackedPixel/*
		cat > /usr/bin/$CloackedPixel << EOF
#!/bin/bash
cd /usr/share/$CloackedPixel;python2 lsb.py "\$@"
EOF
		chmod +x /usr/bin/$CloackedPixel
		menu_entry "Malware-Analysis" "Digital-Forensic" "CloackedPixel" "/usr/share/kali-menu/exec-in-shell '$CloackedPixel -h'"
		printf "$GREEN"  "[*] Success Installing CloackedPixel"
	else
		printf "$GREEN"  "[*] Success Installed CloackedPixel"
	fi

	Steganabara="steganabara"
	if [ ! -d "/usr/share/$Steganabara" ]; then
		git clone https://github.com/quangntenemy/Steganabara /usr/share/$Steganabara
		chmod 755 /usr/share/$Steganabara/*
		cat > /usr/bin/$Steganabara << EOF
#!/bin/bash
cd /usr/share/$Steganabara;./run "\$@"
EOF
		chmod +x /usr/bin/$Steganabara
		menu_entry "Malware-Analysis" "Digital-Forensic" "Steganabara" "/usr/share/kali-menu/exec-in-shell '$Steganabara -h'"
		printf "$GREEN"  "[*] Success Installing Steganabara"
	else
		printf "$GREEN"  "[*] Success Installed Steganabara"
	fi

	Stegsolve="stegsolve"
	if [ ! -d "/usr/share/$Stegsolve" ]; then
		mkdir -p /usr/share/stegsolve
		wget http://www.caesum.com/handbook/Stegsolve.jar -O /usr/share/$Stegsolve/stegsolve.jar
		chmod 755 /usr/share/$Stegsolve/*
		cat > /usr/bin/$Stegsolve << EOF
#!/bin/bash
cd /usr/share/$Stegsolve;java -jar stegsolve.jar "\$@"
EOF
		chmod +x /usr/bin/$Stegsolve
		menu_entry "Malware-Analysis" "Digital-Forensic" "Stegsolve" "/usr/share/kali-menu/exec-in-shell '$Stegsolve -h'"
		printf "$GREEN"  "[*] Success Installing Stegsolve"
	else
		printf "$GREEN"  "[*] Success Installed Stegsolve"
	fi

	OpenPuff="openpuff"
	if [ ! -d "/usr/share/$OpenPuff" ]; then
		wget https://embeddedsw.net/zip/OpenPuff_release.zip -O /tmp/$OpenPuff.zip
		unzip /tmp/$OpenPuff.zip -d /usr/share/$OpenPuff;rm -f /tmp/$OpenPuff.zip
		chmod 755 /usr/share/$OpenPuff/*
		cat > /usr/bin/$OpenPuff << EOF
#!/bin/bash
cd /usr/share/$OpenPuff;wine OpenPuff.exe "\$@"
EOF
		chmod +x /usr/bin/$OpenPuff
		menu_entry "Malware-Analysis" "Digital-Forensic" "OpenPuff" "/usr/share/kali-menu/exec-in-shell '$OpenPuff'"
		printf "$GREEN"  "[*] Success Installing OpenPuff"
	else
		printf "$GREEN"  "[*] Success Installed OpenPuff"
	fi

	MP3Stego="mp3stego"
	if [ ! -d "/usr/share/$MP3Stego" ]; then
		git clone https://github.com/fabienpe/MP3Stego /usr/share/$MP3Stego
		chmod 755 /usr/share/$MP3Stego/MP3Stego/*
		cat > /usr/bin/$MP3Stego-encode << EOF
#!/bin/bash
cd /usr/share/$MP3Stego/MP3Stego;wine Encode.exe "\$@"
EOF
		chmod +x /usr/bin/$MP3Stego-encode
		menu_entry "Malware-Analysis" "Digital-Forensic" "MP3Stego-encode" "/usr/share/kali-menu/exec-in-shell '$MP3Stego-encode'"
		cat > /usr/bin/$MP3Stego-decode << EOF
#!/bin/bash
cd /usr/share/$MP3Stego/MP3Stego;wine Decode.exe "\$@"
EOF
		chmod +x /usr/bin/$MP3Stego-decode
		menu_entry "Malware-Analysis" "Digital-Forensic" "MP3Stego-decode" "/usr/share/kali-menu/exec-in-shell '$MP3Stego-decode'"
		printf "$GREEN"  "[*] Success Installing MP3Stego"
	else
		printf "$GREEN"  "[*] Success Installed MP3Stego"
	fi

	jstegslink="jsteg-slink"
	if [ ! -d "/usr/share/$jstegslink" ]; then
		mkdir -p /usr/share/$jstegslink
		wget https://github.com/lukechampine/jsteg/releases/latest/download/jsteg-linux-amd64 -O /usr/share/$jstegslink/jsteg
		chmod +x /usr/bin/jsteg
		ln -fs /usr/share/$jstegslink/jsteg /usr/bin/jsteg
		menu_entry "Malware-Analysis" "Digital-Forensic" "JSteg" "/usr/share/kali-menu/exec-in-shell 'sudo jsteg -h'"
		wget https://github.com/lukechampine/jsteg/releases/latest/download/slink-linux-amd64 -O /usr/share/$jstegslink/slink
		ln -fs /usr/share/$jstegslink/slink /usr/bin/slink
		chmod +x /usr/bin/slink
		menu_entry "Malware-Analysis" "Digital-Forensic" "Slink" "/usr/share/kali-menu/exec-in-shell 'sudo slink -h'"
		chmod 755 /usr/share/jsteg-slink/*
		printf "$GREEN"  "[*] Success Installing JSteg & Slink"
	else
		printf "$GREEN"  "[*] Success Installed JSteg & Slink"
	fi

	SSAK="ssak"
	if [ ! -d "/usr/share/$SSAK" ]; then
		git clone https://github.com/mmtechnodrone/SSAK /usr/share/$SSAK
		chmod 755 /usr/share/$SSAK/programs/64/*
		ln -fs /usr/share/$SSAK/programs/64/cjpeg /usr/bin/cjpeg
		chmod +x /usr/bin/cjpeg
		menu_entry "Malware-Analysis" "Digital-Forensic" "cjpeg" "/usr/share/kali-menu/exec-in-shell 'sudo cjpeg -h'"
		ln -fs /usr/share/$SSAK/programs/64/djpeg /usr/bin/djpeg
		chmod +x /usr/bin/djpeg
		menu_entry "Malware-Analysis" "Digital-Forensic" "djpeg" "/usr/share/kali-menu/exec-in-shell 'sudo djpeg -h'"
		ln -fs /usr/share/$SSAK/programs/64/histogram /usr/bin/histogram
		chmod +x /usr/bin/histogram
		menu_entry "Malware-Analysis" "Digital-Forensic" "histogram" "/usr/share/kali-menu/exec-in-shell 'sudo histogram -h'"
		ln -fs /usr/share/$SSAK/programs/64/jphide /usr/bin/jphide
		chmod +x /usr/bin/jphide
		menu_entry "Malware-Analysis" "Digital-Forensic" "jphide" "/usr/share/kali-menu/exec-in-shell 'sudo jphide -h'"
		ln -fs /usr/share/$SSAK/programs/64/jpseek /usr/bin/jpseek
		chmod +x /usr/bin/jpseek
		menu_entry "Malware-Analysis" "Digital-Forensic" "jpseek" "/usr/share/kali-menu/exec-in-shell 'sudo jpseek -h'"
		ln -fs /usr/share/$SSAK/programs/64/outguess_0.13 /usr/bin/outguess
		chmod +x /usr/bin/outguess
		menu_entry "Malware-Analysis" "Digital-Forensic" "outguess" "/usr/share/kali-menu/exec-in-shell 'sudo outguess -h'"
		ln -fs /usr/share/$SSAK/programs/64/stegbreak /usr/bin/stegbreak
		chmod +x /usr/bin/stegbreak
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegbreak" "/usr/share/kali-menu/exec-in-shell 'sudo stegbreak -h'"
		ln -fs /usr/share/$SSAK/programs/64/stegcompare /usr/bin/stegcompare
		chmod +x /usr/bin/stegcompare
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegcompare" "/usr/share/kali-menu/exec-in-shell 'sudo stegcompare -h'"
		ln -fs /usr/share/$SSAK/programs/64/stegdeimage /usr/bin/stegdeimage
		chmod +x /usr/bin/stegdeimage
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegdeimage" "/usr/share/kali-menu/exec-in-shell 'sudo stegdeimage -h'"
		ln -fs /usr/share/$SSAK/programs/64/stegdetect /usr/bin/stegdetect
		chmod +x /usr/bin/stegdetect
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegdetect" "/usr/share/kali-menu/exec-in-shell 'sudo stegdetect -h'"
		printf "$GREEN"  "[*] Success Installing SSAK"
	else
		printf "$GREEN"  "[*] Success Installed SSAK"
	fi


	printf "$YELLOW"  "# -----------------------------------Threat-Hunting-Digital-Forensic--------------------------------- #"
	# Install Repository Tools
	apt install -qy sigma-align httpry logwatch nebula cacti tcpdump 

	# Install Python3 pip
	threat_hunting_pip="pastehunter libcsce phishing-tracker"
	pip_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_pip"

	# Install Nodejs NPM
	# threat_hunting_npm=""
	npm_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_npm"

	# Install Ruby GEM
	# threat_hunting_gem=""
	gem_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_gem"

	# Install Golang
	# threat_hunting_golang=""
	go_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_golang"

	Matano="matano"
	if [ ! -d "/usr/share/$Matano" ]; then
		wget https://github.com/matanolabs/matano/releases/download/nightly/matano-linux-x64.sh -O /tmp/$Matano.sh
		chmod +x /tmp/$Matano.sh;cd /tmp;bash $Matano.sh;rm -f $Matano.sh
		printf "$GREEN"  "[*] Success Installing Matano"
	else
		printf "$GREEN"  "[*] Success Installed Matano"
	fi

	APTHunter="apt-hunter"
	if [ ! -d "/usr/share/$APTHunter" ]; then
		git clone https://github.com/ahmedkhlief/APT-Hunter -O /usr/share/$APTHunter
		chmod 755 /usr/share/$APTHunter/*
		cat > /usr/bin/$APTHunter << EOF
#!/bin/bash
cd /usr/share/$APTHunter;python3 APT-Hunter.py "\$@"
EOF
		chmod +x /usr/bin/$APTHunter
		pip3 install -r /usr/share/$APTHunter/requirements.txt
		menu_entry "Threat-Hunting" "Digital-Forensic" "APT-Hunter" "/usr/share/kali-menu/exec-in-shell '$APTHunter -h'"
		printf "$GREEN"  "[*] Success Installing APT-Hunter"
	else
		printf "$GREEN"  "[*] Success Installed APT-Hunter"
	fi

	pspy="pspy"
	if [ ! -d "/usr/share/$pspy" ]; then
		mkdir -p /usr/share/$pspy
		wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O /usr/share/$pspy/pspy64
		chmod 755 /usr/share/$pspy/*
		ln -fs /usr/share/$pspy/pspy64 /usr/bin/$pspy
		chmod +x /usr/bin/$pspy
		menu_entry "Threat-Hunting" "Digital-Forensic" "pspy" "/usr/share/kali-menu/exec-in-shell '$pspy -h'"
		printf "$GREEN"  "[*] Success Installing pspy"
	else
		printf "$GREEN"  "[*] Success Installed pspy"
	fi


	printf "$YELLOW"  "# ----------------------------------Incident-Response-Digital-Forensic------------------------------- #"
	# Install Repository Tools
	apt install -qy thehive 

	# Install Python3 pip
	incident_response_pip="dissect aws_ir intelmq otx-misp threat_intel"
	pip_installer "Incident-Response" "Digital-Forensic" "$incident_response_pip"

	# Install Nodejs NPM
	# incident_response_npm=""
	npm_installer "Incident-Response" "Digital-Forensic" "$incident_response_npm"

	# Install Ruby GEM
	# incident_response_gem=""
	gem_installer "Incident-Response" "Digital-Forensic" "$incident_response_gem"

	# Install Golang
	# incident_response_golang=""
	go_installer "Incident-Response" "Digital-Forensic" "$incident_response_golang"

	Velociraptor="velociraptor"
	if [ ! -d "/usr/share/$Velociraptor" ]; then
		mkdir -p /usr/share/$Velociraptor
		wget https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-v0.7.1-2-linux-amd64 -O /usr/share/$Velociraptor/velociraptor
		chmod 755 /usr/share/$Velociraptor/*
		ln -fs /usr/share/$Velociraptor/velociraptor /usr/bin/$Velociraptor
		menu_entry "Incident-Response" "Digital-Forensic" "Velociraptor" "/usr/share/kali-menu/exec-in-shell '$Velociraptor -h'"
		printf "$GREEN"  "[*] Success Installing Velociraptor"
	else
		printf "$GREEN"  "[*] Success Installed Velociraptor"
	fi

	GRR="grr-server"
	if [ ! -d "/usr/share/$GRR" ]; then
		wget https://github.com/google/grr/releases/latest/download/grr-server_3.4.7-1_amd64.deb -O /tmp/$GRR.deb
		chmod +x /tmp/$GRR.deb;dpkg -i /tmp/$GRR.deb;rm -f /tmp/$GRR.deb
		printf "$GREEN"  "[*] Success Installing GRR"
	else
		printf "$GREEN"  "[*] Success Installed GRR"
	fi


	printf "$YELLOW"  "# ---------------------------------Threat-Intelligence-Digital-Forensic------------------------------ #"
	# Install Repository Tools
	apt install -qy opentaxii 

	# Install Python3 pip
	threat_intelligence_pip="threatingestor stix stix-validator stix2 stix2-matcher stix2-elevator attackcti iocextract threatbus apiosintDS sigmatools msticpy"
	pip_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_pip"

	# Install Nodejs NPM
	# threat_intelligence_npm=""
	npm_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_npm"

	# Install Ruby GEM
	# threat_intelligence_gem=""
	gem_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_gem"

	# Install Golang
	# threat_intelligence_golang=""
	go_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_golang"

	OpenCTI="opencti"
	if [ ! -d "/usr/share/$OpenCTI" ]; then
		wget https://github.com/OpenCTI-Platform/opencti/releases/download/6.0.10/opencti-release-6.0.10.tar.gz -O /tmp/$OpenCTI.tar.gz
		tar -xvf /tmp/$OpenCTI.tar.gz -C /usr/share/$OpenCTI;rm -f /tmp/$OpenCTI.tar.gz
		chmod 755 /usr/share/$OpenCTI/*
		cp /usr/share/$OpenCTI/config/default.json /usr/share/$OpenCTI/config/production.json
		pip3 install -r /usr/share/$OpenCTI/src/python/requirements.txt
		cd /usr/share/$OpenCTI;yarn install;yarn build;yarn serv
		pip3 install -r /usr/share/$OpenCTI/worker/requirements.txt
		cp /usr/share/$OpenCTI/worker/config.yml.sample /usr/share/$OpenCTI/worker/config.yml
		cat > /usr/bin/$OpenCTI << EOF
cd /usr/share/$OpenCTI/worker;python3 worker.py > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:4000" > /dev/null &
EOF
		chmod +x /usr/bin/$OpenCTI
		menu_entry "Threat-Intelligence" "Digital-Forensic" "OpenCTI" "/usr/share/kali-menu/exec-in-shell '$OpenCTI'"
		printf "$GREEN"  "[*] Success Installing OpenCTI"
	else
		printf "$GREEN"  "[*] Success Installed OpenCTI"
	fi

	TRAM="tram"
	if [ ! -d "/usr/share/$TRAM" ]; then
		curl -LO https://github.com/center-for-threat-informed-defense/tram/raw/main/docker/docker-compose.yml
		docker-compose up
		printf "$GREEN"  "[*] Success Installing TRAM"
	else
		printf "$GREEN"  "[*] Success Installed TRAM"
	fi

	RITA="rita"
	if [ ! -d "/var/opt/$RITA" ]; then
		wget https://github.com/activecm/rita/releases/latest/download/install.sh -O /tmp/install.sh
		chmod +x /tmp/install.sh;bash /tmp/install.sh;rm -f /tmp/install.sh
		printf "$GREEN"  "[*] Success Installing RITA"
	else
		printf "$GREEN"  "[*] Success Installed RITA"
	fi

	exit
}


blue_team ()
{
	printf "$YELLOW"  "# -------------------------------------------Harden-Blue-Team---------------------------------------- #"
	# Install Repository Tools
	apt install -qy fail2ban fscrypt encfs age pwgen apparmor ufw firewalld firejail sshguard cilium-cli buildah ansible-core 

	# Install Python3 pip
	# harden_pip=""
	pip_installer "Harden" "Blue-Team" "$harden_pip"

	# Install Nodejs NPM
	# harden_npm=""
	npm_installer "Harden" "Blue-Team" "$harden_npm"

	# Install Ruby GEM
	# harden_gem=""
	gem_installer "Harden" "Blue-Team" "$harden_gem"

	# Install Golang
	# harden_golang=""
	go_installer "Harden" "Blue-Team" "$harden_golang"


	printf "$YELLOW"  "# -------------------------------------------Detect-Blue-Team---------------------------------------- #"
	# Install Repository Tools
	apt install -qy bubblewrap suricata zeek tripwire aide clamav chkrootkit sentrypeer arkime cyberchef snort rspamd prometheus 

	# Install Python3 pip
	detect_pip="adversarial-robustness-toolbox metabadger flare-capa sigma"
	pip_installer "Detect" "Blue-Team" "$detect_pip"

	# Install Nodejs NPM
	# detect_npm=""
	npm_installer "Detect" "Blue-Team" "$detect_npm"

	# Install Ruby GEM
	# detect_gem=""
	gem_installer "Detect" "Blue-Team" "$detect_gem"

	# Install Golang
	detect_golang="
go install github.com/crissyfield/troll-a@latest;ln -fs ~/go/bin/troll-a /usr/bin/troll-a"
	go_installer "Detect" "Blue-Team" "$detect_golang"

	# Install Wazuh Indexer & Server & Agent
	if [ ! -f "/etc/apt/sources.list.d/wazuh.list" ]; then
		# Install Indexer
		cd /tmp;curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh;curl -sO https://packages.wazuh.com/4.7/config.yml
		sed -i "s|<indexer-node-ip>|$LAN|g" /tmp/config.yml;sed -i "s|wazuh-manager-ip|$LAN|g" /tmp/config.yml;sed -i "s|dashboard-node-ip|$LAN|g" /tmp/config.yml
		bash wazuh-install.sh --generate-config-files
		curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
		bash wazuh-install.sh --wazuh-indexer node-1;bash wazuh-install.sh --start-cluster
		ADMIN_PASSWORD=$(tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1)
		curl -k -u admin:$ADMIN_PASSWORD https://$LAN:9200
		curl -k -u admin:$ADMIN_PASSWORD https://$LAN:9200/_cat/nodes?v
		# Install Server
		cd /tmp;bash wazuh-install.sh --wazuh-server wazuh-1
		# Install Dashboard
		cd /tmp;bash wazuh-install.sh --wazuh-dashboard dashboard
		# Install Linux Agent
		curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
		echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
		apt-get update;apt-get install -y wazuh-agent
		printf "$GREEN"  "[*] Success Installing Wazuh https://$LAN -> USER:PASS = admin:$ADMIN_PASSWORD"
	else
		printf "$GREEN"  "[*] Success Installing Wazuh https://$LAN -> USER:PASS = admin:$ADMIN_PASSWORD"
	fi

	OpenSearch="opensearch"
	if [ ! -d "/usr/share/$OpenSearch" ]; then
		wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.deb -O /tmp/$OpenSearch.deb
		chmod +x /tmp/$OpenSearch.deb;dpkg -i /tmp/$OpenSearch.deb;rm -f /tmp/$OpenSearch.deb
		printf "$GREEN"  "[*] Success Installing OpenSearch"
	else
		printf "$GREEN"  "[*] Success Installed OpenSearch"
	fi

	Falco="falcosecurity.list"
	if [ ! -f "/etc/apt/sources.list.d/$Falco" ]; then
		curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
		cat > /etc/apt/sources.list.d/$Falco << EOF
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF
		apt-get update -y;apt-get install -y dkms make linux-headers-$(uname -r) dialog;apt-get install -y falco
		printf "$GREEN"  "[*] Success Installing Falco"
	else
		printf "$GREEN"  "[*] Success Installed Falco"
	fi

	SIEGMA="siegma"
	if [ ! -d "/usr/share/$SIEGMA" ]; then
		git clone https://github.com/3CORESec/SIEGMA /usr/share/$SIEGMA
		chmod 755 /usr/share/$SIEGMA/*
		cat > /usr/bin/$SIEGMA << EOF
#!/bin/bash
cd /usr/share/$SIEGMA;python3 siegma.py "\$@"
EOF
		chmod +x /usr/bin/$SIEGMA
		pip3 install -r /usr/share/$SIEGMA/requirements.txt
		menu_entry "Detect" "Blue-Team" "SIEGMA" "/usr/share/kali-menu/exec-in-shell '$SIEGMA -h'"
		printf "$GREEN"  "[*] Success Installing SIEGMA"
	else
		printf "$GREEN"  "[*] Success Installed SIEGMA"
	fi

	Cilium="cilium"
	if [ ! -d "/usr/local/bin/$Cilium" ]; then
		CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
		CLI_ARCH=amd64
		if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
		curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
		sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
		tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
		rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
		menu_entry "Detect" "Blue-Team" "Cilium" "/usr/share/kali-menu/exec-in-shell '$Cilium -h'"
		printf "$GREEN"  "[*] Success Installing Cilium"
	else
		printf "$GREEN"  "[*] Success Installed Cilium"
	fi

	OSSEC="atomic.list"
	if [ ! -f "/etc/apt/sources.list.d/$OSSEC" ]; then
		wget -q -O - https://www.atomicorp.com/RPM-GPG-KEY.atomicorp.txt  | sudo apt-key add -
		echo "deb https://updates.atomicorp.com/channels/atomic/debian $DISTRIB_CODENAME main" >>  /etc/apt/sources.list.d/$OSSEC
		apt-get update;apt-get install -y ossec-hids-server ossec-hids-agent
		printf "$GREEN"  "[*] Success Installing OSSEC"
	else
		printf "$GREEN"  "[*] Success Installed OSSEC"
	fi

	Cilium="cilium"
	if [ ! -d "/usr/share/$Cilium" ]; then
		mkdir -p /usr/share/$Cilium
		wget https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz -O /tmp/$Cilium.tar.gz
		tar -xvf /tmp/$Cilium.tar.gz -C /usr/share/$Cilium;rm -f /tmp/$Cilium.tar.gz
		ln -fs /usr/share/$Cilium/cilium /usr/bin/$Cilium
		menu_entry "Detect" "Blue-Team" "Cilium" "/usr/share/kali-menu/exec-in-shell '$Cilium -h'"
		printf "$GREEN"  "[*] Success Installing Cilium"
	else
		printf "$GREEN"  "[*] Success Installed Cilium"
	fi

	ElasticSeaerch="elasticsearch"
	if [ ! -d "/usr/share/$ElasticSeaerch" ]; then
		wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.12.2-amd64.deb -O /tmp/$ElasticSeaerch.deb
		chmod +x /tmp/$ElasticSeaerch.deb;dpkg -i /tmp/$ElasticSeaerch.deb;rm -f /tmp/$ElasticSeaerch.deb
		printf "$GREEN"  "[*] Success Installing ElasticSeaerch"
	else
		printf "$GREEN"  "[*] Success Installed ElasticSeaerch"
	fi

	Kibana="kibana"
	if [ ! -d "/usr/share/$Kibana" ]; then
		wget https://artifacts.elastic.co/downloads/kibana/kibana-8.12.2-amd64.deb -O /tmp/$Kibana.deb
		chmod +x /tmp/$Kibana.deb;dpkg -i /tmp/$Kibana.deb;rm -f /tmp/$Kibana.deb
		printf "$GREEN"  "[*] Success Installing Kibana"
	else
		printf "$GREEN"  "[*] Success Installed Kibana"
	fi

	Logstash="logstash"
	if [ ! -d "/usr/share/$Logstash" ]; then
		wget https://artifacts.elastic.co/downloads/logstash/logstash-8.12.2-amd64.deb -O /tmp/$Logstash.deb
		chmod +x /tmp/$Logstash.deb;dpkg -i /tmp/$Logstash.deb;rm -f /tmp/$Logstash.deb
		printf "$GREEN"  "[*] Success Installing Logstash"
	else
		printf "$GREEN"  "[*] Success Installed Logstash"
	fi

	Zabbix="zabbix"
	if [ ! -d "/usr/share/$Zabbix" ]; then
		wget https://repo.zabbix.com/zabbix/6.4/debian/pool/main/z/zabbix-release/zabbix-release_6.4-1+debian12_all.deb -O /tmp/$Zabbix.deb
		chmod +x /tmp/$Zabbix.deb;dpkg -i /tmp/$Zabbix.deb
		apt update;apt install -y zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent
		mysql -u root -p -h localhost -e "create database zabbix character set utf8mb4 collate utf8mb4_bin;create user zabbix@localhost identified by 'password';grant all privileges on zabbix.* to zabbix@localhost;set global log_bin_trust_function_creators = 1;quit;"
		zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -uzabbix -p zabbix
		mysql -u root -p -h localhost -e "set global log_bin_trust_function_creators = 0;quit;"
		sed -i "s|DBPassword=password|DBPassword=unk12341234|g" /etc/zabbix/zabbix_server.conf
		systemctl restart zabbix-server zabbix-agent apache2
		systemctl enable zabbix-server zabbix-agent apache2
		printf "$GREEN"  "[*] Success Installing Zabbix -> http://$LAN/zabbix"
	else
		printf "$GREEN"  "[*] Success Installed Zabbix -> http://$LAN/zabbix"
	fi


	printf "$YELLOW"  "# -------------------------------------------Isolate-Blue-Team--------------------------------------- #"
	# Install Repository Tools
	apt install -qy openvpn wireguard 

	# Install Python3 pip
	# isolate_pip=""
	pip_installer "Isolate" "Blue-Team" "$isolate_pip"

	# Install Nodejs NPM
	# isolate_npm=""
	npm_installer "Isolate" "Blue-Team" "$isolate_npm"

	# Install Ruby GEM
	# isolate_gem=""
	gem_installer "Isolate" "Blue-Team" "$isolate_gem"

	# Install Golang
	isolate_golang="
go install github.com/casbin/casbin/v2@latest;ln -fs ~/go/bin/casbin /usr/bin/casbin"
	go_installer "Isolate" "Blue-Team" "$isolate_golang"


	printf "$YELLOW"  "# -------------------------------------------Deceive-Blue-Team--------------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	deceive_pip="thug conpot honeypots heralding"
	pip_installer "Deceive" "Blue-Team" "$deceive_pip"

	# Install Nodejs NPM
	# deceive_npm=""
	npm_installer "Deceive" "Blue-Team" "$deceive_npm"

	# Install Ruby GEM
	# deceive_gem=""
	gem_installer "Deceive" "Blue-Team" "$deceive_gem"

	# Install Golang
	# deceive_golang=""
	go_installer "Deceive" "Blue-Team" "$deceive_golang"


	printf "$YELLOW"  "# -------------------------------------------Evict-Blue-Team----------------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# evict_pip=""
	pip_installer "Evict" "Blue-Team" "$evict_pip"

	# Install Nodejs NPM
	# evict_npm=""
	npm_installer "Evict" "Blue-Team" "$evict_npm"

	# Install Ruby GEM
	# evict_gem=""
	gem_installer "Evict" "Blue-Team" "$evict_gem"

	# Install Golang
	# evict_golang=""
	go_installer "Evict" "Blue-Team" "$evict_golang"

	exit
}


security_audit ()
{
	printf "$YELLOW"  "# ----------------------------Preliminary-Audit-Assessment-Security-Audit---------------------------- #"
	# Install Repository Tools
	apt install -qy flawfinder afl++ gvm openvas lynis cppcheck findbugs mongoaudit cve-bin-tool sudo-rs ansible-core 

	# Install Python3 pip
	preliminary_audit_assessment_pip="google-generativeai scancode-toolkit mythril"
	pip_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_pip"

	# Install Nodejs NPM
	preliminary_audit_assessment_npm="snyk @sandworm/audit"
	npm_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_npm"

	# Install Ruby GEM
	preliminary_audit_assessment_gem="brakeman bundler-audit"
	gem_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_gem"

	# Install Golang
	preliminary_audit_assessment_golang="
go install github.com/google/osv-scanner/cmd/osv-scanner@latest;ln -fs ~/go/bin/osv-scanner /usr/bin/osv-scanner
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest;ln -fs ~/go/bin/cvemap /usr/bin/cvemap"
	go_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_golang"

	Bearer="bearer"
	if [ ! -f "/usr/local/bin/$Bearer" ]; then
		wget https://github.com/Bearer/bearer/releases/download/v1.37.0/bearer_1.37.0_linux-amd64.deb -O /tmp/$Bearer.deb
		chmod +x /tmp/$Bearer.deb;dpkg -i /tmp/$Bearer.deb;rm -f /tmp/$Bearer.deb
		printf "$GREEN"  "[*] Success Installing Bearer"
	else
		printf "$GREEN"  "[*] Success Installed Bearer"
	fi

	CheckStyle="checkstyle"
	if [ ! -d "/usr/share/$CheckStyle" ]; then
		mkdir -p /usr/share/$CheckStyle
		wget https://github.com/checkstyle/checkstyle/releases/latest/download/checkstyle-10.13.0-all.jar -O /usr/share/$CheckStyle/checkstyle.jar
		chmod 755 /usr/share/$CheckStyle/*
		cat > /usr/bin/$CheckStyle << EOF
#!/bin/bash
cd /usr/share/$CheckStyle;java -jar checkstyle.jar "\$@"
EOF
		chmod +x /usr/bin/$CheckStyle
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "CheckStyle" "/usr/share/kali-menu/exec-in-shell '$CheckStyle'"
		printf "$GREEN"  "[*] Success Installing CheckStyle"
	else
		printf "$GREEN"  "[*] Success Installed CheckStyle"
	fi

	AFLplusplus="aflplusplus"
	if [ ! -d "/usr/share/$AFLplusplus" ]; then
		git clone https://github.com/AFLplusplus/AFLplusplus /usr/share/$AFLplusplus
		chmod 755 /usr/share/$AFLplusplus/*
		cd /usr/share/$AFLplusplus;make distrib;make install
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "afl-cc" "/usr/share/kali-menu/exec-in-shell 'afl-cc -h'"
		printf "$GREEN"  "[*] Success Installing AFLplusplus"
	else
		printf "$GREEN"  "[*] Success Installed AFLplusplus"
	fi

	vulsscanner="vuls-scanner"
	if [ ! -d "/usr/share/$vulsscanner" ]; then
		mkdir -p /usr/share/$vulsscanner
		wget https://github.com/future-architect/vuls/releases/latest/download/vuls-scanner_0.24.9_linux_amd64.tar.gz -O /tmp/$vulsscanner.tar.gz
		tar -xvf /tmp/$vulsscanner.tar.gz -C /usr/share/$vulsscanner;rm -r /tmp/$vulsscanner.tar.gz
		chmod 755 /usr/share/$vulsscanner/*
		ln -fs /usr/share/$vulsscanner/vuls /usr/bin/vuls
		chmod +x /usr/bin/vuls
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "vuls-scanner" "/usr/share/kali-menu/exec-in-shell 'vuls -h'"
		printf "$GREEN"  "[*] Success Installing vuls-scanner"
	else
		printf "$GREEN"  "[*] Success Installed vuls-scanner"
	fi

	syzkaller="syzkaller"
	if [ ! -d "/usr/share/$syzkaller" ]; then
		git clone https://github.com/google/syzkaller /usr/share/$syzkaller
		chmod 755 /usr/share/$syzkaller/*;cd /usr/share/$syzkaller;make
		ln -fs /usr/share/$syzkaller/syzkaller/bin/linux_amd64/syz-fuzzer /usr/bin/syz-fuzzer
		ln -fs /usr/share/$syzkaller/syzkaller/bin/linux_amd64/syz-stress /usr/bin/syz-stress
		ln -fs /usr/share/$syzkaller/syzkaller/bin/linux_amd64/syz-executor /usr/bin/syz-executor
		chmod +x /usr/bin/syz-fuzzer;chmod +x /usr/bin/syz-stress;chmod +x /usr/bin/syz-executor
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "syz-fuzzer" "/usr/share/kali-menu/exec-in-shell 'syz-fuzzer -h'"
		printf "$GREEN"  "[*] Success Installing syzkaller"
	else
		printf "$GREEN"  "[*] Success Installed syzkaller"
	fi

	Honggfuzz="honggfuzz"
	if [ ! -d "/usr/share/$Honggfuzz" ]; then
		git clone https://github.com/google/honggfuzz /usr/share/$Honggfuzz
		chmod 755 /usr/share/$Honggfuzz/*;cd /usr/share/$Honggfuzz;make
		ln -fs /usr/share/$Honggfuzz/honggfuzz /usr/bin/$Honggfuzz
		chmod +x /usr/bin/$Honggfuzz
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Honggfuzz" "/usr/share/kali-menu/exec-in-shell '$Honggfuzz -h'"
		printf "$GREEN"  "[*] Success Installing Honggfuzz"
	else
		printf "$GREEN"  "[*] Success Installed Honggfuzz"
	fi

	Cmder="cmder"
	if [ ! -d "/usr/share/$Cmder" ]; then
		mkdir -p /usr/share/$Cmder
		wget https://github.com/cmderdev/cmder/releases/latest/download/cmder.zip -O /tmp/$Cmder.zip
		unzip /tmp/$Cmder.zip -d /usr/share/$Cmder;rm -f /tmp/$Cmder.zip
		chmod 755 /usr/share/$Cmder/*
		cat > /usr/bin/$Cmder << EOF
#!/bin/bash
cd /usr/share/$Cmder;wine Cmder.exe "\$@"
EOF
		chmod +x /usr/bin/$Cmder
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Cmder" "/usr/share/kali-menu/exec-in-shell '$Cmder'"
		printf "$GREEN"  "[*] Success Installing Cmder"
	else
		printf "$GREEN"  "[*] Success Installed Cmder"
	fi

	OPA="open-policy-agent"
	if [ ! -d "/usr/share/$OPA" ]; then
		mkdir -p /usr/share/$OPA
		wget https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_amd64 -O /usr/share/$OPA/opa
		chmod 755 /usr/share/$OPA/*
		ln -fs /usr/share/$OPA/opa /usr/bin/opa
		chmod +x /usr/bin/opa
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Open-Policy-Agent" "/usr/share/kali-menu/exec-in-shell 'opa -h'"
		printf "$GREEN"  "[*] Success Installing Open-Policy-Agent"
	else
		printf "$GREEN"  "[*] Success Installed Open-Policy-Agent"
	fi


	printf "$YELLOW"  "# ------------------------------Planning-and-Preparation-Security-Audit------------------------------ #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# planning_and_preparation_pip=""
	pip_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_pip"

	# Install Nodejs NPM
	planning_and_preparation_npm="solidity-code-metrics"
	npm_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_npm"

	# Install Ruby GEM
	# planning_and_preparation_gem=""
	gem_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_gem"

	# Install Golang
	# planning_and_preparation_golang=""
	go_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_golang"


	printf "$YELLOW"  "# ----------------------------Establishing-Audit-Objectives-Security-Audit--------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# establishing_audit_objectives_pip=""
	pip_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_pip"

	# Install Nodejs NPM
	# establishing_audit_objectives_npm=""
	npm_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_npm"

	# Install Ruby GEM
	# establishing_audit_objectives_gem=""
	gem_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_gem"

	# Install Golang
	# establishing_audit_objectives_golang=""
	go_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_golang"

	Selefra="selefra"
	if [ ! -d "/usr/share/$Selefra" ]; then
		mkdir -p /usr/share/$Selefra
		wget https://github.com/selefra/selefra/releases/latest/download/selefra_linux_amd64.tar.gz -O /tmp/$Selefra.tar.gz
		tar -xvf /tmp/$Selefra.tar.gz -C /usr/share/$Selefra;rm -f /tmp/$Selefra.tar.gz
		chmod 755 /usr/share/$Selefra/*
		ln -fs /usr/share/$Selefra/selefra /usr/bin/$Selefra
		chmod +x /usr/bin/$Selefra
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Selefra" "/usr/share/kali-menu/exec-in-shell '$Selefra -h'"
		printf "$GREEN"  "[*] Success Installing Selefra"
	else
		printf "$GREEN"  "[*] Success Installed Selefra"
	fi


	printf "$YELLOW"  "# -------------------------------Performing-the-Review-Security-Audit-------------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	performing_the_review_pip="ruff"
	pip_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_pip"

	# Install Nodejs NPM
	# performing_the_review_npm=""
	npm_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_npm"

	# Install Ruby GEM
	performing_the_review_gem="rubocop"
	gem_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_gem"

	# Install Golang
	# performing_the_review_golang=""
	go_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_golang"

	Postman="postman"
	if [ ! -d "/usr/share/$Postman" ]; then
		mkdir -p /usr/share/$Postman
		wget https://dl.pstmn.io/download/latest/linux_64 -O /tmp/$Postman.tar.gz
		tar -xvf /tmp/$Postman.tar.gz -C /usr/share;rm -f /tmp/$Postman.tar.gz
		chmod 755 /usr/share/$Postman/*
		cat > /usr/bin/$Postman << EOF
#!/bin/bash
cd /usr/share/$Postman/;./postman "\$@"
EOF
		chmod +x /usr/bin/$Postman
		menu_entry "Web" "Penetration-Testing" "Postman" "/usr/share/kali-menu/exec-in-shell '$Postman'"
		printf "$GREEN"  "[*] Success Installing Postman"
	else
		printf "$GREEN"  "[*] Success Installed Postman"
	fi

	Clion="clion"
	if [ ! -d "/usr/share/$Clion" ]; then
		wget https://download-cdn.jetbrains.com/cpp/CLion-2023.1.1.tar.gz -O /tmp/$Clion.tar.gz
		tar -xvf /tmp/$Clion.tar.gz -C /usr/share/$Clion;rm -f /tmp/$Clion.tar.gz
		chmod 755 /usr/share/$Clion/bin/*
		cat > /usr/bin/$Clion << EOF
#!/bin/bash
cd /usr/share/$Clion/bin;bash clion.sh "\$@"
EOF
		chmod +x /usr/bin/$Clion
		menu_entry "Performing-the-Review" "Security-Audit" "Clion" "/usr/bin/$Clion"
		printf "$GREEN"  "[*] Success Installing Clion"
	else
		printf "$GREEN"  "[*] Success Installed Clion"
	fi

	PhpStorm="phpstorm"
	if [ ! -d "/usr/share/$PhpStorm" ]; then
		wget https://download-cdn.jetbrains.com/webide/PhpStorm-2023.1.tar.gz -O /tmp/$PhpStorm.tar.gz
		tar -xvf /tmp/$PhpStorm.tar.gz -C /usr/share/$PhpStorm;rm -f /tmp/$PhpStorm.tar.gz
		chmod 755 /usr/share/$PhpStorm/bin/*
		cat > /usr/bin/$PhpStorm << EOF
#!/bin/bash
cd /usr/share/$PhpStorm/bin;bash phpstorm.sh "\$@"
EOF
		chmod +x /usr/bin/$PhpStorm
		menu_entry "Performing-the-Review" "Security-Audit" "PhpStorm" "/usr/bin/$PhpStorm"
		printf "$GREEN"  "[*] Success Installing PhpStorm"
	else
		printf "$GREEN"  "[*] Success Installed PhpStorm"
	fi

	GoLand="goland"
	if [ ! -d "/usr/share/$GoLand" ]; then
		wget https://download-cdn.jetbrains.com/go/goland-2023.1.tar.gz -O /tmp/$GoLand.tar.gz
		tar -xvf /tmp/$GoLand.tar.gz -C /usr/share/$GoLand;rm -f /tmp/$GoLand.tar.gz
		chmod 755 /usr/share/$GoLand/bin/*
		cat > /usr/bin/$GoLand << EOF
#!/bin/bash
cd /usr/share/$GoLand/bin;bash goland.sh "\$@"
EOF
		chmod +x /usr/bin/$GoLand
		menu_entry "Performing-the-Review" "Security-Audit" "GoLand" "/usr/bin/$GoLand"
		printf "$GREEN"  "[*] Success Installing GoLand"
	else
		printf "$GREEN"  "[*] Success Installed GoLand"
	fi

	PyCharm="pycharm"
	if [ ! -d "/usr/share/$PyCharm" ]; then
		wget https://download-cdn.jetbrains.com/python/pycharm-professional-2023.1.tar.gz -O /tmp/$PyCharm.tar.gz
		tar -xvf /tmp/$PyCharm.tar.gz -C /usr/share/$PyCharm;rm -f /tmp/$PyCharm.tar.gz
		chmod 755 /usr/share/$PyCharm/bin/*
		cat > /usr/bin/$PyCharm << EOF
#!/bin/bash
cd /usr/share/$PyCharm/bin;bash pycharm.sh "\$@"
EOF
		chmod +x /usr/bin/$PyCharm
		menu_entry "Performing-the-Review" "Security-Audit" "PyCharm" "/usr/bin/$PyCharm"
		printf "$GREEN"  "[*] Success Installing PyCharm"
	else
		printf "$GREEN"  "[*] Success Installed PyCharm"
	fi

	RubyMine="rubymine"
	if [ ! -d "/usr/share/$RubyMine" ]; then
		wget https://download-cdn.jetbrains.com/ruby/RubyMine-2023.1.tar.gz -O /tmp/$RubyMine.tar.gz
		tar -xvf /tmp/$RubyMine.tar.gz -C /usr/share/$RubyMine;rm -f /tmp/$RubyMine.tar.gz
		chmod 755 /usr/share/$RubyMine/bin/*
		cat > /usr/bin/$RubyMine << EOF
#!/bin/bash
cd /usr/share/$RubyMine/bin;bash rubymine.sh "\$@"
EOF
		chmod +x /usr/bin/$RubyMine
		menu_entry "Performing-the-Review" "Security-Audit" "RubyMine" "/usr/bin/$RubyMine"
		printf "$GREEN"  "[*] Success Installing RubyMine"
	else
		printf "$GREEN"  "[*] Success Installed RubyMine"
	fi

	WebStorm="webstorm"
	if [ ! -d "/usr/share/$WebStorm" ]; then
		wget https://download-cdn.jetbrains.com/webstorm/WebStorm-2023.1.tar.gz -O /tmp/$WebStorm.tar.gz
		tar -xvf /tmp/$WebStorm.tar.gz -C /usr/share/$WebStorm;rm -f /tmp/$WebStorm.tar.gz
		chmod 755 /usr/share/$WebStorm/bin/*
		cat > /usr/bin/$WebStorm << EOF
#!/bin/bash
cd /usr/share/$WebStorm/bin;bash webstorm.sh "\$@"
EOF
		chmod +x /usr/bin/$WebStorm
		menu_entry "Performing-the-Review" "Security-Audit" "WebStorm" "/usr/bin/$WebStorm"
		printf "$GREEN"  "[*] Success Installing WebStorm"
	else
		printf "$GREEN"  "[*] Success Installed WebStorm"
	fi

	IDEA="idea"
	if [ ! -d "/usr/share/$IDEA" ]; then
		wget https://download-cdn.jetbrains.com/idea/ideaIU-2023.1.tar.gz -O /tmp/IDE$IDEAA.tar.gz
		tar -xvf /tmp/$IDEA.tar.gz -C /usr/share/$IDEA;rm -f /tmp/$IDEA.tar.gz
		chmod 755 /usr/share/$IDEA/*
		cat > /usr/bin/$IDEA << EOF
#!/bin/bash
cd /usr/share/$IDEA/bin;bash idea.sh "\$@"
EOF
		chmod +x /usr/bin/$IDEA
		menu_entry "Performing-the-Review" "Security-Audit" "IDEA" "/usr/bin/$IDEA"
		printf "$GREEN"  "[*] Success Installing IDEA"
	else
		printf "$GREEN"  "[*] Success Installed IDEA"
	fi


	printf "$YELLOW"  "# -----------------------------Preparing-the-Audit-Report-Security-Audit----------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# preparing_the_audit_report_pip=""
	pip_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_pip"

	# Install Nodejs NPM
	# preparing_the_audit_report_npm=""
	npm_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_npm"

	# Install Ruby GEM
	# preparing_the_audit_report_gem=""
	gem_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_gem"

	# Install Golang
	# preparing_the_audit_report_golang=""
	go_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_golang"


	printf "$YELLOW"  "# ------------------------------Issuing-the-Review-Report-Security-Audit----------------------------- #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# issuing_the_review_report_pip=""
	pip_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_pip"

	# Install Nodejs NPM
	# issuing_the_review_report_npm=""
	npm_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_npm"

	# Install Ruby GEM
	# issuing_the_review_report_gem=""
	gem_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_gem"

	# Install Golang
	# issuing_the_review_report_golang=""
	go_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_golang"

	exit
}


main ()
{
	# APT Fixed
	if ! grep -q "http.kali.org/kali kali-rolling" /etc/apt/sources.list; then
		echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list
	fi

	# Update & Upgrade OS
	apt update;apt upgrade -qy;apt dist-upgrade -qy

	# Install Init Tools
	apt install -qy curl git apt-transport-https build-essential mingw-w64 apt-utils automake autoconf cmake gnupg default-jdk python3 python3-dev python2 g++ nodejs npm rustup clang nim golang golang-go llvm nasm qtchooser alacarte jq locate ffmpeg

	# Install Requirements
	apt install -qy libfontconfig1 libglu1-mesa-dev libconfig-dev libgtest-dev libspdlog-dev libboost-all-dev libunwind-dev libncurses5-dev binutils-dev libgdbm-dev libblocksruntime-dev libssl-dev libevent-dev libreadline-dev libpcre2-dev libffi-dev zlib1g-dev libsqlite3-dev libbz2-dev mesa-common-dev qt5-qmake qtbase5-dev qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev libboost-all-dev qtchooser python3-dev python3-pip python3-poetry libpe-dev

	# Install Utilities Tools
	apt install -qy p7zip tor obfs4proxy proxychains p7zip-full zipalign wine winetricks winbind net-tools docker.io docker-compose mono-complete mono-devel ffmpeg rar cmatrix gimp remmina htop nload vlc bleachbit powershell filezilla thunderbird 

	# Install Python2 pip
	wget https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py;python2.7 /tmp/get-pip.py;rm -f /tmp/get-pip.py;apt reinstall -qy python3-pip;pip2 install --upgrade pip

	# Install Python3 pip
	pip3 install --upgrade pip;pip3 install setuptools env pipenv wheel colorama pysnmp termcolor pypdf2 cprint pycryptodomex requests gmpy2 win_unicode_console python-nmap python-whois capstone dnslib 

	# Install Nodejs NPM
	# npm install -g 

	# Install Ruby GEM
	# gem install 

	KaliElite="kalielite"
	if [ ! -d "/usr/share/$KaliElite" ]; then
		mkdir -p /usr/share/$KaliElite
		curl -s -o /usr/share/$KaliElite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/kali-elite.sh
		chmod 755 /usr/share/$KaliElite/*
		cat > /usr/bin/$KaliElite << EOF
#!/bin/bash
cd /usr/share/$KaliElite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/$KaliElite
		cat > "/home/$USERS/.local/share/applications/Unk9vvN/$KaliElite.desktop" << EOF
[Desktop Entry]
Name=kali-elite
Exec=/usr/share/kali-menu/exec-in-shell "sudo $KaliElite"
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
		cat > "/home/$USERS/.config/menus/applications-merged/Unk9vvN-$KaliElite.menu" << EOF
<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
"http://www.freedesktop.org/standards/menu-spec/menu-1.0.dtd">
<Menu>
  <Name>Applications</Name>
  <Menu>
    <Name>Unk9vvN</Name>
    <Directory>Unk9vvN.directory</Directory>
    <Include>
      <Filename>Unk9vvN-$KaliElite.desktop</Filename>
    </Include>
  </Menu>
</Menu>
EOF
	elif [ "$(curl -s https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/version)" != $ver ]; then
		curl -s -o /usr/share/$KaliElite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/kali-elite.sh
		chmod 755 /usr/share/$KaliElite/*
		cat > /usr/bin/$KaliElite << EOF
#!/bin/bash
cd /usr/share/$KaliElite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/$KaliElite
		cat > "/home/$USERS/.local/share/applications/Unk9vvN/$KaliElite.desktop" << EOF
[Desktop Entry]
Name=kali-elite
Exec=/usr/share/kali-menu/exec-in-shell "sudo $KaliElite"
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF
		cat > "/home/$USERS/.config/menus/applications-merged/Unk9vvN-$KaliElite.menu" << EOF
<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
"http://www.freedesktop.org/standards/menu-spec/menu-1.0.dtd">
<Menu>
  <Name>Applications</Name>
  <Menu>
    <Name>Unk9vvN</Name>
    <Directory>Unk9vvN.directory</Directory>
    <Include>
      <Filename>Unk9vvN-$KaliElite.desktop</Filename>
    </Include>
  </Menu>
</Menu>
EOF
		bash /usr/share/$KaliElite/kalielite.sh
	fi
}


menu
main
logo


select opt in "Penetrating Testing" "Red Team" "ICS Security" "Digital Forensic" "Blue Team" "Security Audit" Quit
do
	case $opt in
		"Penetrating Testing")
			printf "$GREEN"  "[*] Running Penetrating-Testing..."
			penetrating_testing;;
		"Red Team")
			printf "$GREEN"  "[*] Running Red-Team..."
			red_team;;
		"ICS Security")
			printf "$GREEN"  "[*] Running ICS-Security..."
			ics_security;;
		"Digital Forensic")
			printf "$GREEN"  "[*] Running Digital-Forensic..."
			digital_forensic;;
		"Blue Team")
			printf "$GREEN"  "[*] Running Blue-Team..."
			blue_team;;
		"Security Audit")
			printf "$GREEN"  "[*] Running Security-Audit..."
			security_audit;;
		"Quit")
			echo "Exiting..."
			break;;
		*) echo "invalid option...";;
	esac
done
