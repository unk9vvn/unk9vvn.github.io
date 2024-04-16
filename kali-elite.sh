#!/bin/bash
ver='3.9'




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
	apt install -qy tor dirsearch nuclei rainbowcrack hakrawler gobuster seclists subfinder amass arjun metagoofil sublist3r cupp gifsicle aria2 phpggc emailharvester osrframework jq pngtools gitleaks trufflehog maryam dosbox wig eyewitness oclgausscrack websploit googler inspy proxychains pigz massdns gospider proxify privoxy dotdotpwn goofile firewalk bing-ip2hosts webhttrack oathtool tcptrack tnscmd10g getallurls padbuster feroxbuster subjack cyberchef whatweb xmlstarlet sslscan assetfinder dnsgen mdbtools pocsuite3

	# Install Python3 pip
	web_pip="pyjwt arjun py-altdns pymultitor autosubtakeover crlfsuite ggshield selenium PyJWT proxyhub njsscan detect-secrets regexploit h8mail nodejsscan hashpumpy bhedak gitfive modelscan PyExfil wsgidav defaultcreds-cheat-sheet hiphp pasteme-cli aiodnsbrute semgrep wsrepl apachetomcatscanner dotdotfarm pymetasec theharvester chiasmodon puncia"
	pip_installer "Web" "Penetration-Testing" "$web_pip"

	# Install Nodejs NPM
	web_npm="jwt-cracker graphql padding-oracle-attacker http-proxy-to-socks javascript-obfuscator serialize-javascript http-proxy-to-socks node-serialize igf electron-packager redos serialize-to-js dompurify nodesub multitor infoooze"
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
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest;ln -fs ~/go/bin/mapcidr /usr/bin/mapcidr"
	go_installer "Web" "Penetration-Testing" "$web_golang"

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
		menu_entry "Web" "Penetration-Testing" "CloudBunny" "/usr/share/kali-menu/exec-in-shell 'cloudbunny -h'"
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
		menu_entry "Web" "Penetration-Testing" "PhoneInfoga" "/usr/share/kali-menu/exec-in-shell 'sudo phoneinfoga -h'"
		printf "$GREEN"  "[*] Success Installing PhoneInfoga"
	else
		printf "$GREEN"  "[*] Success Installed PhoneInfoga"
	fi

	# Install Postman
	if [ ! -d "/usr/share/Postman" ]; then
		mkdir -p /usr/share/Postman
		wget https://dl.pstmn.io/download/latest/linux_64 -O /tmp/postman_linux_64.tar.gz
		tar -xvf /tmp/postman_linux_64.tar.gz -C /usr/share;rm -f /tmp/postman_linux_64.tar.gz
		chmod 755 /usr/share/Postman/*
		cat > /usr/bin/postman << EOF
#!/bin/bash
cd /usr/share/Postman/;./postman "\$@"
EOF
		chmod +x /usr/bin/postman
		menu_entry "Web" "Penetration-Testing" "Postman" "/usr/share/kali-menu/exec-in-shell 'postman'"
		printf "$GREEN"  "[*] Success Installing Postman"
	else
		printf "$GREEN"  "[*] Success Installed Postman"
	fi

	# Install Findomain
	if [ ! -d "/usr/share/findomain" ]; then
		wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -O /tmp/findomain-linux.zip
		unzip /tmp/findomain-linux.zip -d /usr/share/findomain;rm -f /tmp/findomain-linux.zip
		chmod 755 /usr/share/findomain/*
		ln -fs /usr/share/findomain/findomain /usr/bin/findomain
		chmod +x /usr/bin/findomain
		menu_entry "Web" "Penetration-Testing" "Findomain" "/usr/share/kali-menu/exec-in-shell 'sudo findomain -h'"
		printf "$GREEN"  "[*] Success Installing Findomain"
	else
		printf "$GREEN"  "[*] Success Installed Findomain"
	fi

	# Install RustScan
	if [ ! -f "/usr/bin/rustscan" ]; then
		wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb -O /tmp/rustscan.deb
		chmod +x /tmp/rustscan.deb;dpkg -i /tmp/rustscan.deb;rm -f /tmp/rustscan.deb
		menu_entry "Web" "Penetration-Testing" "RustScan" "/usr/share/kali-menu/exec-in-shell 'sudo rustscan -h'"
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
		menu_entry "Web" "Penetration-Testing" "HashPump" "/usr/share/kali-menu/exec-in-shell 'sudo hashpump -h'"
		printf "$GREEN"  "[*] Success Installing HashPump"
	else
		printf "$GREEN"  "[*] Success Installed HashPump"
	fi

	# Install pixload
	if [ ! -d "/usr/share/pixload" ]; then
		git clone https://github.com/sighook/pixload /usr/share/pixload
		chmod 755 /usr/share/pixload/*
		cd /usr/share/pixload;make install
		menu_entry "Web" "Penetration-Testing" "pixload" "/usr/share/kali-menu/exec-in-shell 'sudo pixload-bmp --help'"
		printf "$GREEN"  "[*] Success Installing pixload"
	else
		printf "$GREEN"  "[*] Success Installed pixload"
	fi

	# Install ReconFTW
	if [ ! -d "/usr/share/reconftw" ]; then
		git clone https://github.com/six2dez/reconftw /usr/share/reconftw
		chmod 755 /usr/share/reconftw/*
		cat > /usr/bin/reconftw << EOF
#!/bin/bash
cd /usr/share/reconftw;./reconftw.sh "\$@"
EOF
		chmod +x /usr/bin/reconftw
		cd /usr/share/reconftw;./install.sh
		menu_entry "Web" "Penetration-Testing" "ReconFTW" "/usr/share/kali-menu/exec-in-shell 'reconftw -h'"
		printf "$GREEN"  "[*] Success Installing ReconFTW"
	else
		printf "$GREEN"  "[*] Success Installed ReconFTW"
	fi

	# Install Gel4y
	if [ ! -d "/usr/share/gel4y" ]; then
		git clone https://github.com/22XploiterCrew-Team/Gel4y-Mini-Shell-Backdoor /usr/share/gel4y
		chmod 755 /usr/share/gel4y/*
		cat > /usr/bin/gel4y << EOF
#!/bin/bash
cd /usr/share/gel4y;php gel4y.php "\$@"
EOF
		chmod +x /usr/bin/gel4y
		menu_entry "Web" "Penetration-Testing" "Gel4y" "/usr/share/kali-menu/exec-in-shell 'gel4y -h'"
		printf "$GREEN"  "[*] Success Installing Gel4y"
	else
		printf "$GREEN"  "[*] Success Installed Gel4y"
	fi

	# Install CloakQuest3r
	if [ ! -d "/usr/share/cloakquest3r" ]; then
		git clone https://github.com/spyboy-productions/CloakQuest3r /usr/share/cloakquest3r
		chmod 755 /usr/share/cloakquest3r/*
		cat > /usr/bin/cloakquest3r << EOF
#!/bin/bash
cd /usr/share/cloakquest3r;python3 cloakquest3r.py "\$@"
EOF
		chmod +x /usr/bin/cloakquest3r
		pip3 install -r /usr/share/cloakquest3r/requirements.txt
		menu_entry "Web" "Penetration-Testing" "CloakQuest3r" "/usr/share/kali-menu/exec-in-shell 'cloakquest3r -h'"
		printf "$GREEN"  "[*] Success Installing CloakQuest3r"
	else
		printf "$GREEN"  "[*] Success Installed CloakQuest3r"
	fi

	# Install Waymore
	if [ ! -d "/usr/share/waymore" ]; then
		git clone https://github.com/xnl-h4ck3r/waymore /usr/share/waymore
		chmod 755 /usr/share/waymore/*
		cat > /usr/bin/waymore << EOF
#!/bin/bash
cd /usr/share/waymore;python3 waymore.py "\$@"
EOF
		chmod +x /usr/bin/waymore
		pip3 install -r /usr/share/waymore/requirements.txt
		menu_entry "Web" "Penetration-Testing" "Waymore" "/usr/share/kali-menu/exec-in-shell 'waymore -h'"
		printf "$GREEN"  "[*] Success Installing Waymore"
	else
		printf "$GREEN"  "[*] Success Installed Waymore"
	fi

	# Install YsoSerial
	if [ ! -d "/usr/share/ysoserial" ]; then
		mkdir -p /usr/share/ysoserial
		wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -O /usr/share/ysoserial/ysoserial-all.jar 
		chmod 755 /usr/share/ysoserial/*
		cat > /usr/bin/ysoserial << EOF
#!/bin/bash
cd /usr/share/ysoserial;java -jar ysoserial-all.jar "\$@"
EOF
		chmod +x /usr/bin/ysoserial
		menu_entry "Web" "Penetration-Testing" "YsoSerial" "/usr/share/kali-menu/exec-in-shell 'ysoserial -h'"
		printf "$GREEN"  "[*] Success Installing YsoSerial"
	else
		printf "$GREEN"  "[*] Success Installed YsoSerial"
	fi

	# Install YsoSerial.net
	if [ ! -d "/usr/share/ysoserial.net" ]; then
		mkdir -p /usr/share/ysoserial.net
		wget https://github.com/pwntester/ysoserial.net/releases/latest/download/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip -O /tmp/ysoserial-net.zip
		unzip /tmp/ysoserial-net.zip -d /tmp;cd /tmp/Release;mv -f * /usr/share/ysoserial.net;rm -f /tmp/Release;rm -f /tmp/ysoserial-net.zip
		chmod 755 /usr/share/ysoserial.net/*
		cat > /usr/bin/ysoserial.net << EOF
#!/bin/bash
cd /usr/share/ysoserial.net;mono ysoserial.exe "\$@"
EOF
		chmod +x /usr/bin/ysoserial.net
		menu_entry "Web" "Penetration-Testing" "YsoSerial.net" "/usr/share/kali-menu/exec-in-shell 'ysoserial.net -h'"
		printf "$GREEN"  "[*] Success Installing YsoSerial.net"
	else
		printf "$GREEN"  "[*] Success Installed YsoSerial.net"
	fi

	# Install Akto
	if [ ! -d "/usr/share/akto" ]; then
		git clone https://github.com/akto-api-security/akto /usr/share/akto 
		chmod 755 /usr/share/akto/*
		cat > /usr/bin/akto << EOF
#!/bin/bash
cd /usr/share/akto;docker-compose up -d "\$@"
EOF
		chmod +x /usr/bin/akto
		menu_entry "Web" "Penetration-Testing" "Akto" "/usr/share/kali-menu/exec-in-shell 'akto'"
		printf "$GREEN"  "[*] Success Installing Akto"
	else
		printf "$GREEN"  "[*] Success Installed Akto"
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
		menu_entry "Web" "Penetration-Testing" "RSAtool" "/usr/share/kali-menu/exec-in-shell 'rsatool -h'"
		printf "$GREEN"  "[*] Success Installing RSAtool"
	else
		printf "$GREEN"  "[*] Success Installed RSAtool"
	fi

	# Install Polyglot
	if [ ! -d "/usr/share/polyglot-database" ]; then
		git clone https://github.com/Polydet/polyglot-database /usr/share/polyglot-database
		chmod 755 /usr/share/polyglot-database/files/*
		cat > /usr/bin/polyglot << EOF
#!/bin/bash
cd /usr/share/polyglot-database/files;ls "\$@"
EOF
		chmod +x /usr/bin/polyglot
		menu_entry "Web" "Penetration-Testing" "Polyglot" "/usr/share/kali-menu/exec-in-shell 'polyglot -h'"
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
		menu_entry "Web" "Penetration-Testing" "RsaCtfTool" "/usr/share/kali-menu/exec-in-shell 'rsactftool -h'"
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
		menu_entry "Web" "Penetration-Testing" "PEMCrack" "/usr/share/kali-menu/exec-in-shell 'sudo pemcrack -h'"
		printf "$GREEN"  "[*] Success Installing PEMCrack"
	else
		printf "$GREEN"  "[*] Success Installed PEMCrack"
	fi

	# Install SessionProbe
	if [ ! -d "/usr/share/sessionprobe" ]; then
		mkdir -p /usr/share/sessionprobe
		wget https://github.com/dub-flow/sessionprobe/releases/latest/download/sessionprobe-linux-amd64 -O /usr/share/sessionprobe/sessionprobe
		chmod 755 /usr/share/sessionprobe/*
		ln -fs /usr/share/sessionprobe/sessionprobe /usr/bin/sessionprobe
		chmod +x /usr/bin/sessionprobe
		menu_entry "Web" "Penetration-Testing" "SessionProbe" "/usr/share/kali-menu/exec-in-shell 'sessionprobe -h'"
		printf "$GREEN"  "[*] Success Installing SessionProbe"
	else
		printf "$GREEN"  "[*] Success Installed SessionProbe"
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
		menu_entry "Web" "Penetration-Testing" "DyMerge" "/usr/share/kali-menu/exec-in-shell 'dymerge -h'"
		printf "$GREEN"  "[*] Success Installing DyMerge"
	else
		printf "$GREEN"  "[*] Success Installed DyMerge"
	fi

	# Install WAF-Bypass-Tool
	if [ ! -d "/usr/share/waf-bypass" ]; then
		git clone https://github.com/nemesida-waf/waf-bypass /usr/share/waf-bypass
		chmod 755 /usr/share/waf-bypass/*
		cat > /usr/bin/waf-bypass << EOF
#!/bin/bash
cd /usr/share/waf-bypass;python2 dymerge.py "\$@"
EOF
		chmod +x /usr/bin/waf-bypass
		pip3 install -r /usr/share/waf-bypass/requirements.txt
		python3 /usr/share/waf-bypass/setup.py install
		menu_entry "Web" "Penetration-Testing" "WAF-Bypass-Tool" "/usr/share/kali-menu/exec-in-shell 'waf-bypass -h'"
		printf "$GREEN"  "[*] Success Installing WAF-Bypass-Tool"
	else
		printf "$GREEN"  "[*] Success Installed WAF-Bypass-Tool"
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
		menu_entry "Web" "Penetration-Testing" "XSS-LOADER" "/usr/share/kali-menu/exec-in-shell 'xssloader -h'"
		printf "$GREEN"  "[*] Success Installing XSS-LOADER"
	else
		printf "$GREEN"  "[*] Success Installed XSS-LOADER"
	fi

	# Install CMSeek
	if [ ! -d "/usr/share/cmseek" ]; then
		git clone https://github.com/Tuhinshubhra/CMSeeK /usr/share/cmseek
		chmod 755 /usr/share/cmseek/*
		cat > /usr/bin/cmseek << EOF
#!/bin/bash
cd /usr/share/cmseek;python3 cmseek.py "\$@"
EOF
		chmod +x /usr/bin/cmseek
		pip3 install -r /usr/share/cmseek/requirements.txt
		menu_entry "Web" "Penetration-Testing" "CMSeek" "/usr/share/kali-menu/exec-in-shell 'cmseek -h'"
		printf "$GREEN"  "[*] Success Installing CMSeek"
	else
		printf "$GREEN"  "[*] Success Installed CMSeek"
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
		menu_entry "Web" "Penetration-Testing" "XSStrike" "/usr/share/kali-menu/exec-in-shell 'xsstrike -h'"
		printf "$GREEN"  "[*] Success Installing XSStrike"
	else
		printf "$GREEN"  "[*] Success Installed XSStrike"
	fi

	# Install w4af
	if [ ! -d "/usr/share/w4af" ]; then
		git clone https://github.com/w4af/w4af /usr/share/w4af
		chmod 755 /usr/share/w4af/*
		cat > /usr/bin/w4af << EOF
#!/bin/bash
cd /usr/share/w4af;pipenv shell;./w4af_console "\$@"
EOF
		chmod +x /usr/bin/w4af
		cd /usr/share/w4af;pipenv install;npm install
		menu_entry "Web" "Penetration-Testing" "w4af" "/usr/share/kali-menu/exec-in-shell 'w4af'"
		printf "$GREEN"  "[*] Success Installing w4af"
	else
		printf "$GREEN"  "[*] Success Installed w4af"
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
		menu_entry "Web" "Penetration-Testing" "JWT-Tool" "/usr/share/kali-menu/exec-in-shell 'jwt_tool -h'"
		printf "$GREEN"  "[*] Success Installing JWT-Tool"
	else
		printf "$GREEN"  "[*] Success Installed JWT-Tool"
	fi

	# Install Tplmap
	if [ ! -d "/usr/share/tplmap" ]; then
		git clone https://github.com/epinna/tplmap /usr/share/tplmap
		chmod 755 /usr/share/tplmap/*
		cat > /usr/bin/tplmap << EOF
#!/bin/bash
cd /usr/share/tplmap;python3 tplmap.py "\$@"
EOF
		chmod +x /usr/bin/tplmap
		pip3 install -r /usr/share/tplmap/requirements.txt
		menu_entry "Web" "Penetration-Testing" "Tplmap" "/usr/share/kali-menu/exec-in-shell 'tplmap -h'"
		printf "$GREEN"  "[*] Success Installing Tplmap"
	else
		printf "$GREEN"  "[*] Success Installed Tplmap"
	fi

	# Install SSTImap
	if [ ! -d "/usr/share/sstimap" ]; then
		git clone https://github.com/vladko312/SSTImap /usr/share/sstimap
		chmod 755 /usr/share/sstimap/*
		cat > /usr/bin/sstimap << EOF
#!/bin/bash
cd /usr/share/sstimap;python3 sstimap.py "\$@"
EOF
		chmod +x /usr/bin/sstimap
		pip3 install -r /usr/share/sstimap/requirements.txt
		menu_entry "Web" "Penetration-Testing" "SSTImap" "/usr/share/kali-menu/exec-in-shell 'sstimap -h'"
		printf "$GREEN"  "[*] Success Installing SSTImap"
	else
		printf "$GREEN"  "[*] Success Installed SSTImap"
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
		menu_entry "Web" "Penetration-Testing" "Poodle" "/usr/share/kali-menu/exec-in-shell 'poodle -h'"
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
		menu_entry "Web" "Penetration-Testing" "Gopherus" "/usr/share/kali-menu/exec-in-shell 'gopherus -h'"
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
		menu_entry "Web" "Penetration-Testing" "HashExtender" "/usr/share/kali-menu/exec-in-shell 'sudo hashextender -h'"
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
		menu_entry "Web" "Penetration-Testing" "SpoofCheck" "/usr/share/kali-menu/exec-in-shell 'spoofcheck -h'"
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
		menu_entry "Web" "Penetration-Testing" "RED_HAWK" "/usr/share/kali-menu/exec-in-shell 'red_hawk -h'"
		printf "$GREEN"  "[*] Success Installing RED_HAWK"
	else
		printf "$GREEN"  "[*] Success Installed RED_HAWK"
	fi

	# Install Ngrok
	if [ ! -f "/usr/bin/ngrok" ]; then
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/ngrok-v3-stable-linux-amd64.tgz
		tar -xvf /tmp/ngrok-v3-stable-linux-amd64.tgz -C /usr/bin;rm -f /tmp/ngrok-v3-stable-linux-amd64.tgz
		chmod +x /usr/bin/ngrok
		menu_entry "Web" "Penetration-Testing" "Ngrok" "/usr/share/kali-menu/exec-in-shell 'ngrok -h'"
		printf "$GREEN"  "[*] Success Installing Ngrok"
	else
		printf "$GREEN"  "[*] Success Installed Ngrok"
	fi

	# Install NoIP
	if [ ! -d "/usr/share/noip" ]; then
		mkdir -p /usr/share/noip
		wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/noip-duc-linux.tar.gz
		tar -xvf /tmp/noip-duc-linux.tar.gz -C /usr/share/noip;rm -f /tmp/noip-duc-linux.tar.gz
		chmod 755 /usr/share/noip/*;cd /usr/share/noip;make;make install
		menu_entry "Web" "Penetration-Testing" "NoIP" "/usr/share/kali-menu/exec-in-shell 'noip -h'"
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
		menu_entry "Web" "Penetration-Testing" "Breacher" "/usr/share/kali-menu/exec-in-shell 'breacher -h'"
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
		menu_entry "Web" "Penetration-Testing" "mtasc" "/usr/share/kali-menu/exec-in-shell 'mtasc -h'"
		menu_entry "Web" "Penetration-Testing" "swfdump" "/usr/share/kali-menu/exec-in-shell 'swfdump -h'"
		menu_entry "Web" "Penetration-Testing" "swfcombine" "/usr/share/kali-menu/exec-in-shell 'swfcombine -h'"
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
		cd /usr/share/nosqlmap;python2 nosqlmap.py install;pip2 install couchdb
		menu_entry "Web" "Penetration-Testing" "NoSQLMap" "/usr/share/kali-menu/exec-in-shell 'nosqlmap -h'"
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
		wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb -O /tmp/wkhtmltox.deb
		chmod +x /tmp/wkhtmltox.deb;dpkg -i /tmp/wkhtmltox.deb;rm -f /tmp/wkhtmltox.deb
		chmod 755 /usr/share/MobSF/*
		cat > /usr/bin/mobsf << EOF
#!/bin/bash
cd /usr/share/MobSF;./run.sh > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &
EOF
		chmod +x /usr/bin/mobsf
		cd /usr/share/MobSF;./setup.sh
		menu_entry "Mobile" "Penetration-Testing" "MobSF" "/usr/share/kali-menu/exec-in-shell 'mobsf'"
		printf "$GREEN"  "[*] Success Installing MobSF"
	else
		printf "$GREEN"  "[*] Success Installed MobSF"
	fi


	printf "$YELLOW"  "# ------------------------------------Cloud-Penetration-Testing-------------------------------------- #"
	# Install Repository Tools
	apt install -qy awscli trivy 

	# Install Python3 pip
	cloud_pip="sceptre aclpwn powerpwn ggshield pacu whispers s3scanner roadrecon roadlib gcp_scanner roadtx festin cloudsplaining c7n trailscraper lambdaguard airiam access-undenied-aws n0s1 aws-gate cloudscraper acltoolkit-ad prowler bloodhound aiodnsbrute gorilla-cli knowsmore checkov scoutsuite"
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
		menu_entry "Cloud" "Penetration-Testing" "CloudFail" "/usr/share/kali-menu/exec-in-shell 'cloudfail -h'"
		printf "$GREEN"  "[*] Success Installing CloudFail"
	else
		printf "$GREEN"  "[*] Success Installed CloudFail"
	fi

	# Install k8sgpt
	if [ ! -d "/usr/share/k8sgpt" ]; then
		wget https://github.com/k8sgpt-ai/k8sgpt/releases/latest/download/k8sgpt_amd64.deb -O /tmp/k8sgpt_amd64.deb
		chmod +x /tmp/k8sgpt_amd64.deb;dpkg -i /tmp/k8sgpt_amd64.deb;rm -f /tmp/k8sgpt_amd64.deb
		printf "$GREEN"  "[*] Success Installing k8sgpt"
	else
		printf "$GREEN"  "[*] Success Installed k8sgpt"
	fi

	# Install CloudQuery
	if [ ! -d "/usr/share/cloudquery" ]; then
		mkdir -p /usr/share/cloudquery
		wget https://github.com/cloudquery/cloudquery/releases/latest/download/cloudquery_linux_amd64 -O /usr/share/cloudquery/cloudquery
		chmod 755 /usr/share/cloudquery/*
		ln -fs /usr/share/cloudquery/cloudquery /usr/bin/cloudquery
		chmod +x /usr/bin/cloudquery
		menu_entry "Cloud" "Penetration-Testing" "CloudQuery" "/usr/share/kali-menu/exec-in-shell 'cloudquery -h'"
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

	# Install Hiddify-Next
	if [ ! -d "/usr/share/hiddify" ]; then
		wget https://github.com/hiddify/hiddify-next/releases/download/v0.14.20/hiddify-debian-x64.zip -O /tmp/hiddify-debian-x64.zip
		unzip /tmp/hiddify-debian-x64.zip -d /tmp/hiddify-next;rm -f /tmp/hiddify-linux-x64.zip
		chmod +x /tmp/hiddify-next/hiddify-debian-x64.deb;dpkg -i /tmp/hiddify-next/hiddify-debian-x64.deb;rm -rf /tmp/hiddify-next
		chmod 755 /usr/share/hiddify/*
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
		menu_entry "Network" "Penetration-Testing" "SNMP-Brute" "/usr/share/kali-menu/exec-in-shell 'snmpbrute -h'"
		printf "$GREEN"  "[*] Success Installing SNMP-Brute"
	else
		printf "$GREEN"  "[*] Success Installed SNMP-Brute"
	fi

	# Install RouterScan
	if [ ! -d "/usr/share/routerscan" ]; then
		mkdir -p /usr/share/routerscan
		wget http://msk1.stascorp.com/routerscan/prerelease.7z -O /usr/share/routerscan/prerelease.7z
		chmod 755 /usr/share/routerscan/*
		cd /usr/share/routerscan;7z x prerelease.7z;rm -f prerelease.7z
		cat > /usr/bin/routerscan << EOF
#!/bin/bash
cd /usr/share/routerscan;wine RouterScan.exe "\$@"
EOF
		chmod +x /usr/bin/routerscan
		menu_entry "Network" "Penetration-Testing" "RouterScan" "/usr/share/kali-menu/exec-in-shell 'routerscan'"
		printf "$GREEN"  "[*] Success Installing RouterScan"
	else
		printf "$GREEN"  "[*] Success Installed RouterScan"
	fi

	# Install PRET
	if [ ! -d "/usr/share/pret" ]; then
		git clone https://github.com/RUB-NDS/PRET /usr/share/pret
		chmod 755 /usr/share/pret/*
		cat > /usr/bin/pret << EOF
#!/bin/bash
cd /usr/share/pret;python3 pret.py "\$@"
EOF
		chmod +x /usr/bin/pret
		menu_entry "Network" "Penetration-Testing" "PRET" "/usr/share/kali-menu/exec-in-shell 'pret -h'"
		printf "$GREEN"  "[*] Success Installing PRET"
	else
		printf "$GREEN"  "[*] Success Installed PRET"
	fi

	# Install Geneva
	if [ ! -d "/usr/share/geneva" ]; then
		git clone https://github.com/Kkevsterrr/geneva /usr/share/geneva
		chmod 755 /usr/share/geneva/*
		cat > /usr/bin/geneva << EOF
#!/bin/bash
cd /usr/share/geneva;python3 engine.py "\$@"
EOF
		chmod +x /usr/bin/geneva
		pip3 install -r /usr/share/geneva/requirements.txt
		menu_entry "Network" "Penetration-Testing" "Geneva" "/usr/share/kali-menu/exec-in-shell 'geneva -h'"
		printf "$GREEN"  "[*] Success Installing Geneva"
	else
		printf "$GREEN"  "[*] Success Installed Geneva"
	fi

	# Install GEF
	if [ ! -f "~/.gef-6a6e2a05ca8e08ac6845dce655a432fc4e029486.py" ]; then
		bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
		menu_entry "Network" "Penetration-Testing" "GEF" "/usr/share/kali-menu/exec-in-shell 'gef'"
		printf "$GREEN"  "[*] Success Installing GEF"
	else
		printf "$GREEN"  "[*] Success Installed GEF"
	fi

	# Install Angry-IP
	if [ ! -f "/usr/bin/ipscan" ]; then
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
		menu_entry "Network" "Penetration-Testing" "Fetch" "/usr/share/kali-menu/exec-in-shell 'fetch -h'"
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
		menu_entry "Network" "Penetration-Testing" "Memcrashed" "/usr/share/kali-menu/exec-in-shell 'memcrashed -h'"
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

	# Install GTScan
	if [ ! -d "/usr/share/gtscan" ]; then
		git clone https://github.com/SigPloiter/GTScan /usr/share/gtscan
		chmod 755 /usr/share/gtscan/*
		cat > /usr/bin/gtscan << EOF
#!/bin/bash
cd /usr/share/gtscan;python3 gtscan.py "\$@"
EOF
		chmod +x /usr/bin/gtscan
		pip3 install -r /usr/share/gtscan/requirements.txt
		menu_entry "Wireless" "Penetration-Testing" "GTScan" "/usr/share/kali-menu/exec-in-shell 'gtscan -h'"
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
cd /usr/share/hlr-lookups;python2 hlr-lookups.py "\$@"
EOF
		chmod +x /usr/bin/hlrlookups
		menu_entry "Wireless" "Penetration-Testing" "HLR-Lookups" "/usr/share/kali-menu/exec-in-shell 'hlrlookups -h'"
		printf "$GREEN"  "[*] Success Installing HLR-Lookups"
	else
		printf "$GREEN"  "[*] Success Installed HLR-Lookups"
	fi

	# Install geowifi
	if [ ! -d "/usr/share/geowifi" ]; then
		git clone https://github.com/GONZOsint/geowifi /usr/share/geowifi
		chmod 755 /usr/share/geowifi/*
		cat > /usr/bin/geowifi << EOF
#!/bin/bash
cd /usr/share/geowifi;python3 geowifi.py "\$@"
EOF
		chmod +x /usr/bin/geowifi
		pip3 install -r /usr/share/geowifi/requirements.txt
		menu_entry "Wireless" "Penetration-Testing" "geowifi" "/usr/share/kali-menu/exec-in-shell 'geowifi -h'"
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

	# Install Trape
	if [ ! -d "/usr/share/trape" ]; then
		git clone https://github.com/jofpin/trape /usr/share/trape
		chmod 755 /usr/share/trape/*
		cat > /usr/bin/trape << EOF
#!/bin/bash
cd /usr/share/trape;python3 trape.py "\$@"
EOF
		chmod +x /usr/bin/trape
		pip3 install -r /usr/share/trape/requirements.txt
		menu_entry "Reconnaissance" "Red-Team" "Trape" "/usr/share/kali-menu/exec-in-shell 'trape -h'"
		printf "$GREEN"  "[*] Success Installing Trape"
	else
		printf "$GREEN"  "[*] Success Installed Trape"
	fi

	# Install Dracnmap
	if [ ! -d "/usr/share/dracnmap" ]; then
		git clone https://github.com/Screetsec/Dracnmap /usr/share/dracnmap
		chmod 755 /usr/share/dracnmap/*
		cat > /usr/bin/dracnmap << EOF
#!/bin/bash
cd /usr/share/dracnmap;./Dracnmap.sh "\$@"
EOF
		chmod +x /usr/bin/dracnmap
		menu_entry "Reconnaissance" "Red-Team" "Dracnmap" "/usr/share/kali-menu/exec-in-shell 'dracnmap -h'"
		printf "$GREEN"  "[*] Success Installing Dracnmap"
	else
		printf "$GREEN"  "[*] Success Installed Dracnmap"
	fi

	# Install ReconFTW
	if [ ! -d "/usr/share/reconftw" ]; then
		git clone https://github.com/six2dez/reconftw /usr/share/reconftw
		chmod 755 /usr/share/reconftw/*
		cat > /usr/bin/reconftw << EOF
#!/bin/bash
cd /usr/share/reconftw;./reconftw.sh "\$@"
EOF
		chmod +x /usr/bin/reconftw
		cd /usr/share/reconftw;./install.sh
		menu_entry "Reconnaissance" "Red-Team" "ReconFTW" "/usr/share/kali-menu/exec-in-shell 'reconftw -h'"
		printf "$GREEN"  "[*] Success Installing ReconFTW"
	else
		printf "$GREEN"  "[*] Success Installed ReconFTW"
	fi

	# Install CloakQuest3r
	if [ ! -d "/usr/share/cloakquest3r" ]; then
		git clone https://github.com/spyboy-productions/CloakQuest3r /usr/share/cloakquest3r
		chmod 755 /usr/share/cloakquest3r/*
		cat > /usr/bin/cloakquest3r << EOF
#!/bin/bash
cd /usr/share/cloakquest3r;python3 cloakquest3r.py "\$@"
EOF
		chmod +x /usr/bin/cloakquest3r
		pip3 install -r /usr/share/cloakquest3r/requirements.txt
		menu_entry "Reconnaissance" "Red-Team" "CloakQuest3r" "/usr/share/kali-menu/exec-in-shell 'cloakquest3r -h'"
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

	# Install OffensiveNim
	if [ ! -d "/usr/share/offensivenim" ]; then
		git clone https://github.com/byt3bl33d3r/OffensiveNim /usr/share/offensivenim
		chmod 755 /usr/share/offensivenim/*
		cat > /usr/bin/offensivenim << EOF
#!/bin/bash
cd /usr/share/offensivenim/src;ls "\$@"
EOF
		chmod +x /usr/bin/offensivenim
		menu_entry "Resource-Development" "Red-Team" "OffensiveNim" "/usr/share/kali-menu/exec-in-shell 'offensivenim'"
		printf "$GREEN"  "[*] Success Installing OffensiveNim"
	else
		printf "$GREEN"  "[*] Success Installed OffensiveNim"
	fi

	# Install OffensiveDLR
	if [ ! -d "/usr/share/offensivedlr" ]; then
		git clone https://github.com/byt3bl33d3r/OffensiveDLR /usr/share/offensivedlr
		chmod 755 /usr/share/offensivedlr/*
		cat > /usr/bin/offensivedlr << EOF
#!/bin/bash
cd /usr/share/offensivedlr;pwsh -c \"dir\" "\$@"
EOF
		chmod +x /usr/bin/offensivedlr
		menu_entry "Resource-Development" "Red-Team" "OffensiveDLR" "/usr/share/kali-menu/exec-in-shell 'offensivedlr'"
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

	# Install Evilginx
	if [ ! -d "/usr/share/evilginx" ]; then
		wget https://github.com/kgretzky/evilginx2/releases/download/2.4.0/evilginx-linux-amd64.tar.gz -O /tmp/evilginx-linux-amd64.tar.gz
		tar -xvf /tmp/evilginx-linux-amd64.tar.gz -C /usr/share;rm -f /tmp/evilginx-linux-amd64.tar.gz
		chmod 755 /usr/share/evilginx/*
		ln -fs /usr/share/evilginx/evilginx /usr/bin/evilginx
		chmod +x /usr/bin/evilginx
		cd /usr/share/evilginx;./install.sh
		menu_entry "Initial-Access" "Red-Team" "Evilginx" "/usr/share/kali-menu/exec-in-shell 'sudo evilginx -h'"
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
		menu_entry "Initial-Access" "Red-Team" "SocialFish" "/usr/share/kali-menu/exec-in-shell 'socialfish -h'"
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
		menu_entry "Initial-Access" "Red-Team" "EmbedInHTML" "/usr/share/kali-menu/exec-in-shell 'embedinhtml -h'"
		printf "$GREEN"  "[*] Success Installing EmbedInHTML"
	else
		printf "$GREEN"  "[*] Success Installed EmbedInHTML"
	fi

	# Install Bad-PDF
	if [ ! -d "/usr/share/bad-pdf" ]; then
		git clone https://github.com/deepzec/Bad-Pdf /usr/share/bad-pdf
		chmod 755 /usr/share/bad-pdf/*
		cat > /usr/bin/bad-pdf << EOF
#!/bin/bash
cd /usr/share/bad-pdf;python2 badpdf.py "\$@"
EOF
		chmod +x /usr/bin/bad-pdf
		menu_entry "Initial-Access" "Red-Team" "Bad-PDF" "/usr/share/kali-menu/exec-in-shell 'bad-pdf -h'"
		printf "$GREEN"  "[*] Success Installing Bad-PDF"
	else
		printf "$GREEN"  "[*] Success Installed Bad-PDF"
	fi

	# Install BLACKEYE
	if [ ! -d "/usr/share/blackeye" ]; then
		git clone https://github.com/EricksonAtHome/blackeye /usr/share/blackeye
		chmod 755 /usr/share/blackeye/*
		cat > /usr/bin/blackeye << EOF
#!/bin/bash
cd /usr/share/blackeye;./blackeye.sh "\$@"
EOF
		chmod +x /usr/bin/blackeye
		menu_entry "Initial-Access" "Red-Team" "BLACKEYE" "/usr/share/kali-menu/exec-in-shell 'blackeye'"
		printf "$GREEN"  "[*] Success Installing BLACKEYE"
	else
		printf "$GREEN"  "[*] Success Installed BLACKEYE"
	fi

	# Install CredSniper
	if [ ! -d "/usr/share/credsniper" ]; then
		git clone https://github.com/ustayready/CredSniper /usr/share/credsniper
		chmod 755 /usr/share/credsniper/*
		cat > /usr/bin/credsniper << EOF
#!/bin/bash
cd /usr/share/credsniper;python3 credsniper.py "\$@"
EOF
		chmod +x /usr/bin/credsniper
		cd /usr/share/credsniper;./install.sh
		pip3 install -r /usr/share/credsniper/requirements.txt
		menu_entry "Initial-Access" "Red-Team" "CredSniper" "/usr/share/kali-menu/exec-in-shell 'credsniper -h'"
		printf "$GREEN"  "[*] Success Installing CredSniper"
	else
		printf "$GREEN"  "[*] Success Installed CredSniper"
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
		menu_entry "Initial-Access" "Red-Team" "EvilURL" "/usr/share/kali-menu/exec-in-shell 'evilurl -h'"
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
		menu_entry "Initial-Access" "Red-Team" "Debinject" "/usr/share/kali-menu/exec-in-shell 'debinject -h'"
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
		menu_entry "Initial-Access" "Red-Team" "Brutal" "/usr/share/kali-menu/exec-in-shell 'sudo brutal -h'"
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
		menu_entry "Initial-Access" "Red-Team" "Demiguise" "/usr/share/kali-menu/exec-in-shell 'demiguise'"
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
		menu_entry "Initial-Access" "Red-Team" "Dr0p1t" "/usr/share/kali-menu/exec-in-shell 'dr0p1t -h'"
		printf "$GREEN"  "[*] Success Installing Dr0p1t"
	else
		printf "$GREEN"  "[*] Success Installed Dr0p1t"
	fi

	# Install EvilPDF
	if [ ! -d "/usr/share/evilpdf" ]; then
		git clone https://github.com/superzerosec/evilpdf /usr/share/evilpdf
		chmod 755 /usr/share/evilpdf/*
		cat > /usr/bin/evilpdf << EOF
#!/bin/bash
cd /usr/share/evilpdf;python2 evilpdf.py "\$@"
EOF
		chmod +x /usr/bin/evilpdf
		menu_entry "Initial-Access" "Red-Team" "EvilPDF" "/usr/share/kali-menu/exec-in-shell 'evilpdf -h'"
		printf "$GREEN"  "[*] Success Installing EvilPDF"
	else
		printf "$GREEN"  "[*] Success Installed EvilPDF"
	fi

	# Install Gophish
	if [ ! -d "/usr/share/gophish" ]; then
		wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip -O /tmp/gophish-linux.zip
		unzip /tmp/gophish-linux.zip -d /usr/share/gophish;rm -f /tmp/gophish-linux.zip
		chmod 755 /usr/share/gophish/*
		cat > /usr/bin/gophish << EOF
#!/bin/bash
cd /usr/share/gophish;./gophish "\$@"
EOF
		chmod +x /usr/bin/gophish
		menu_entry "Initial-Access" "Red-Team" "Gophish" "/usr/share/kali-menu/exec-in-shell 'gophish'"
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

	# Install Venom
	if [ ! -d "/usr/share/venom" ]; then
		git clone https://github.com/r00t-3xp10it/venom /usr/share/venom
		chmod 755 /usr/share/venom/*
		cat > /usr/bin/venom << EOF
#!/bin/bash
cd /usr/share/venom;./venom.sh "\$@"
EOF
		chmod +x /usr/bin/venom
		menu_entry "Execution" "Red-Team" "Venom" "/usr/share/kali-menu/exec-in-shell 'sudo venom -h'"
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
		menu_entry "Execution" "Red-Team" "PowerLessShell" "/usr/share/kali-menu/exec-in-shell 'powerlessshell -h'"
		printf "$GREEN"  "[*] Success Installing PowerLessShell"
	else
		printf "$GREEN"  "[*] Success Installed PowerLessShell"
	fi

	# Install auto_SettingContent-ms
	if [ ! -d "/usr/share/auto_settingcontent-ms" ]; then
		git clone https://github.com/trustedsec/auto_SettingContent-ms /usr/share/auto_settingcontent-ms
		chmod 755 /usr/share/auto_settingcontent-ms/*
		cat > /usr/bin/settingcontent << EOF
#!/bin/bash
cd /usr/share/auto_settingcontent-ms;python2 auto_settingcontent-ms.py "\$@"
EOF
		chmod +x /usr/bin/settingcontent
		menu_entry "Execution" "Red-Team" "auto_SettingContent-ms" "/usr/share/kali-menu/exec-in-shell 'settingcontent -h'"
		printf "$GREEN"  "[*] Success Installing auto_SettingContent-ms"
	else
		printf "$GREEN"  "[*] Success Installed auto_SettingContent-ms"
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
		pip2 install -r /usr/share/sharpshooter/requirements.txt
		menu_entry "Execution" "Red-Team" "SharpShooter" "/usr/share/kali-menu/exec-in-shell 'sharpshooter -h'"
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
		menu_entry "Execution" "Red-Team" "Donut" "/usr/share/kali-menu/exec-in-shell 'donut -h'"
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

	# Install Vegile
	if [ ! -d "/usr/share/vegile" ]; then
		git clone https://github.com/Screetsec/Vegile /usr/share/vegile
		chmod 755 /usr/share/vegile/*
		ln -fs /usr/share/vegile/Vegile /usr/bin/vegile
		chmod +x /usr/bin/vegile
		menu_entry "Persistence" "Red-Team" "Vegile" "/usr/share/kali-menu/exec-in-shell 'sudo vegile -h'"
		printf "$GREEN"  "[*] Success Installing Vegile"
	else
		printf "$GREEN"  "[*] Success Installed Vegile"
	fi

	# Install SmmBackdoorNg
	if [ ! -d "/usr/share/smmbackdoorng" ]; then
		git clone https://github.com/Cr4sh/SmmBackdoorNg /usr/share/smmbackdoorng
		chmod 755 /usr/share/smmbackdoorng/*
		cat > /usr/bin/smmbackdoorng << EOF
#!/bin/bash
cd /usr/share/smmbackdoorng;python3 smm_backdoor.py "\$@"
EOF
		chmod +x /usr/bin/smmbackdoorng
		menu_entry "Persistence" "Red-Team" "SmmBackdoorNg" "/usr/share/kali-menu/exec-in-shell 'smmbackdoorng -h'"
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

	# Install MimiPenguin
	if [ ! -d "/usr/share/mimipenguin" ]; then
		git clone https://github.com/huntergregal/mimipenguin /usr/share/mimipenguin
		chmod 755 /usr/share/mimipenguin/*
		cat > /usr/bin/mimipenguin << EOF
#!/bin/bash
cd /usr/share/mimipenguin;python3 mimipenguin.py "\$@"
EOF
		chmod +x /usr/bin/mimipenguin
		menu_entry "Privilege-Escalation" "Red-Team" "MimiPenguin" "/usr/share/kali-menu/exec-in-shell 'mimipenguin -h'"
		printf "$GREEN"  "[*] Success Installing MimiPenguin"
	else
		printf "$GREEN"  "[*] Success Installed MimiPenguin"
	fi

	# Install GodPotato
	if [ ! -d "/usr/share/godpotato" ]; then
		mkdir -p /usr/share/godpotato
		wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe -O /usr/share/godpotato/GodPotato-NET4.exe
		wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET35.exe -O /usr/share/godpotato/GodPotato-NET35.exe
		chmod 755 /usr/share/godpotato/*
		cat > /usr/bin/godpotato << EOF
#!/bin/bash
cd /usr/share/godpotato;ls "\$@"
EOF
		chmod +x /usr/bin/godpotato
		menu_entry "Privilege-Escalation" "Red-Team" "GodPotato" "/usr/share/kali-menu/exec-in-shell 'godpotato'"
		printf "$GREEN"  "[*] Success Installing GodPotato"
	else
		printf "$GREEN"  "[*] Success Installed GodPotato"
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
		menu_entry "Privilege-Escalation" "Red-Team" "spectre-meltdown-checker" "/usr/share/kali-menu/exec-in-shell 'spectre-checker -h'"
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
		menu_entry "Defense-Evasion" "Red-Team" "ASWCrypter" "/usr/share/kali-menu/exec-in-shell 'aswcrypter -h'"
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
		menu_entry "Defense-Evasion" "Red-Team" "AVET" "/usr/share/kali-menu/exec-in-shell 'avet'"
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
		menu_entry "Defense-Evasion" "Red-Team" "Unicorn" "/usr/share/kali-menu/exec-in-shell 'unicorn -h'"
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
		menu_entry "Defense-Evasion" "Red-Team" "SysWhispers3" "/usr/share/kali-menu/exec-in-shell 'syswhispers3 -h'"
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
		menu_entry "Defense-Evasion" "Red-Team" "SysWhispers" "/usr/share/kali-menu/exec-in-shell 'syswhispers -h'"
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
		menu_entry "Defense-Evasion" "Red-Team" "Invoke-DOSfuscation" "/usr/share/kali-menu/exec-in-shell 'invoke-dosfuscation'"
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
		menu_entry "Defense-Evasion" "Red-Team" "ObfuscateCactusTorch" "/usr/share/kali-menu/exec-in-shell 'obfuscatecactustorch'"
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
		menu_entry "Defense-Evasion" "Red-Team" "Phantom-Evasion" "/usr/share/kali-menu/exec-in-shell 'phantom -h'"
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
		menu_entry "Defense-Evasion" "Red-Team" "SpookFlare" "/usr/share/kali-menu/exec-in-shell 'spookflare -h'"
		printf "$GREEN"  "[*] Success Installing SpookFlare"
	else
		printf "$GREEN"  "[*] Success Installed SpookFlare"
	fi

	# Install Pazuzu
	if [ ! -d "/usr/share/pazuzu" ]; then
		git clone https://github.com/BorjaMerino/Pazuzu /usr/share/pazuzu
		chmod 755 /usr/share/pazuzu/*
		cat > /usr/bin/pazuzu << EOF
#!/bin/bash
cd /usr/share/pazuzu;python2 pazuzu.py "\$@"
EOF
		chmod +x /usr/bin/pazuzu
		menu_entry "Defense-Evasion" "Red-Team" "Pazuzu" "/usr/share/kali-menu/exec-in-shell 'pazuzu -h'"
		printf "$GREEN"  "[*] Success Installing Pazuzu"
	else
		printf "$GREEN"  "[*] Success Installed Pazuzu"
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
		menu_entry "Defense-Evasion" "Red-Team" "Invoke-Obfuscation" "/usr/share/kali-menu/exec-in-shell 'invoke-obfuscation'"
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
		menu_entry "Defense-Evasion" "Red-Team" "Invoke-CradleCrafter" "/usr/share/kali-menu/exec-in-shell 'invoke-cradlecrafter'"
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

	# Install Kerberoast
	if [ ! -d "/usr/share/kerberoast" ]; then
		git clone https://github.com/nidem/kerberoast /usr/share/kerberoast
		chmod 755 /usr/share/kerberoast/*
		cat > /usr/bin/kerberoast << EOF
#!/bin/bash
cd /usr/share/Kerberoast;python3 kerberoast.py "\$@"
EOF
		chmod +x /usr/bin/kerberoast
		menu_entry "Credential-Access" "Red-Team" "Kerberoast" "/usr/share/kali-menu/exec-in-shell 'kerberoast -h'"
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
		menu_entry "Credential-Access" "Red-Team" "NtlmRelayToEWS" "/usr/share/kali-menu/exec-in-shell 'ntlmRelaytoews -h'"
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
		menu_entry "Credential-Access" "Red-Team" "NetRipper" "/usr/share/kali-menu/exec-in-shell 'netripper'"
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
		menu_entry "Discovery" "Red-Team" "AdExplorer" "/usr/share/kali-menu/exec-in-shell 'adexplorer'"
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

	# Install SCShell
	if [ ! -d "/usr/share/scshell" ]; then
		git clone https://github.com/Mr-Un1k0d3r/SCShell /usr/share/scshell
		chmod 755 /usr/share/scshell/*
		cat > /usr/bin/scshell << EOF
#!/bin/bash
cd /usr/share/scshell;wine SCShell.exe "\$@"
EOF
		chmod +x /usr/bin/scshell
		menu_entry "Lateral-Movement" "Red-Team" "SCShell" "/usr/share/kali-menu/exec-in-shell 'scshell'"
		printf "$GREEN"  "[*] Success Installing SCShell"
	else
		printf "$GREEN"  "[*] Success Installed SCShell"
	fi

	# Install Amnesiac
	if [ ! -d "/usr/share/amnesiac" ]; then
		git clone https://github.com/Leo4j/Amnesiac /usr/share/amnesiac
		chmod 755 /usr/share/amnesiac/*
		cat > /usr/bin/amnesiac << EOF
#!/bin/bash
cd /usr/share/amnesiac;pwsh -c "Import-Module ./Amnesiac.ps1; Amnesiac" "\$@"
EOF
		chmod +x /usr/bin/amnesiac
		menu_entry "Lateral-Movement" "Red-Team" "Amnesiac" "/usr/share/kali-menu/exec-in-shell 'amnesiac'"
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

	# Install Caldera
	if [ ! -d "/usr/share/caldera" ]; then
		git clone https://github.com/mitre/caldera /usr/share/caldera
		chmod 755 /usr/share/caldera/*
		cat > /usr/bin/caldera << EOF
#!/bin/bash
cd /usr/share/caldera;python3 server.py --insecure "\$@"
EOF
		chmod +x /usr/bin/caldera
		pip3 install -r /usr/share/caldera/requirements.txt
		menu_entry "Collection" "Red-Team" "Caldera" "/usr/share/kali-menu/exec-in-shell 'caldera'"
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
		menu_entry "Command-and-Control" "Red-Team" "PhoenixC2" "/usr/share/kali-menu/exec-in-shell 'phoenix -h'"
		printf "$GREEN"  "[*] Success Installing PhoenixC2"
	else
		printf "$GREEN"  "[*] Success Installed PhoenixC2"
	fi

	# Install Nebula
	if [ ! -d "/usr/share/nebula" ]; then
		git clone https://github.com/gl4ssesbo1/Nebula /usr/share/nebula
		chmod 755 /usr/share/nebula/*
		cat > /usr/bin/nebula << EOF
#!/bin/bash
cd /usr/share/nebula;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/nebula
		pip3 install -r /usr/share/nebula/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "Nebula" "/usr/share/kali-menu/exec-in-shell 'nebula'"
		printf "$GREEN"  "[*] Success Installing Nebula"
	else
		printf "$GREEN"  "[*] Success Installed Nebula"
	fi

	# Install Mistica
	if [ ! -d "/usr/share/mistica" ]; then
		git clone https://github.com/IncideDigital/Mistica /usr/share/mistica
		chmod 755 /usr/share/mistica/*
		cat > /usr/bin/mistica << EOF
#!/bin/bash
cd /usr/share/mistica;python3 ms.py "\$@"
EOF
		chmod +x /usr/bin/mistica
		menu_entry "Command-and-Control" "Red-Team" "Mistica" "/usr/share/kali-menu/exec-in-shell 'mistica -h'"
		printf "$GREEN"  "[*] Success Installing Mistica"
	else
		printf "$GREEN"  "[*] Success Installed Mistica"
	fi

	# Install EvilOSX
	if [ ! -d "/usr/share/evilosx" ]; then
		git clone https://github.com/Marten4n6/EvilOSX /usr/share/evilosx
		chmod 755 /usr/share/evilosx/*
		cat > /usr/bin/evilosx << EOF
#!/bin/bash
cd /usr/share/evilosx;python3 start.py "\$@"
EOF
		chmod +x /usr/bin/evilosx
		pip3 install -r /usr/share/evilosx/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "EvilOSX" "/usr/share/kali-menu/exec-in-shell 'evilosx'"
		printf "$GREEN"  "[*] Success Installing EvilOSX"
	else
		printf "$GREEN"  "[*] Success Installed EvilOSX"
	fi

	# Install EggShell
	if [ ! -d "/usr/share/eggshell" ]; then
		git clone https://github.com/lucasjacks0n/EggShell /usr/share/eggshell
		chmod 755 /usr/share/eggshell/*
		cat > /usr/bin/eggshell << EOF
#!/bin/bash
cd /usr/share/eggshell;python2 eggshell.py "\$@"
EOF
		chmod +x /usr/bin/eggshell
		menu_entry "Command-and-Control" "Red-Team" "EggShell" "/usr/share/kali-menu/exec-in-shell 'eggshell -h'"
		printf "$GREEN"  "[*] Success Installing EggShell"
	else
		printf "$GREEN"  "[*] Success Installed EggShell"
	fi

	# Install GodGenesis
	if [ ! -d "/usr/share/godgenesis" ]; then
		git clone https://github.com/SaumyajeetDas/GodGenesis /usr/share/godgenesis
		chmod 755 /usr/share/godgenesis/*
		cat > /usr/bin/godgenesis << EOF
#!/bin/bash
cd /usr/share/godgenesis;python3 c2c.py "\$@"
EOF
		chmod +x /usr/bin/godgenesis
		pip3 install -r /usr/share/godgenesis/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "GodGenesis" "/usr/share/kali-menu/exec-in-shell 'godgenesis'"
		printf "$GREEN"  "[*] Success Installing GodGenesis"
	else
		printf "$GREEN"  "[*] Success Installed GodGenesis"
	fi

	# Install PhoneSploit
	if [ ! -d "/usr/share/phonesploit" ]; then
		git clone https://github.com/AzeemIdrisi/PhoneSploit-Pro /usr/share/phonesploit
		chmod 755 /usr/share/phonesploit/*
		cat > /usr/bin/phonesploit << EOF
#!/bin/bash
cd /usr/share/phonesploit;python3 phonesploitpro.py "\$@"
EOF
		chmod +x /usr/bin/phonesploit
		pip3 install -r /usr/share/phonesploit/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "PhoneSploit" "/usr/share/kali-menu/exec-in-shell 'phonesploit'"
		printf "$GREEN"  "[*] Success Installing PhoneSploit"
	else
		printf "$GREEN"  "[*] Success Installed PhoneSploit"
	fi

	# Install MeliziaC2
	if [ ! -d "/usr/share/melizia" ]; then
		git clone https://github.com/demon-i386/MeliziaC2 /usr/share/melizia
		chmod 755 /usr/share/melizia/*
		cat > /usr/bin/melizia << EOF
#!/bin/bash
cd /usr/share/melizia;python3 c2.py "\$@"
EOF
		chmod +x /usr/bin/melizia
		menu_entry "Command-and-Control" "Red-Team" "MeliziaC2" "/usr/share/kali-menu/exec-in-shell 'melizia'"
		printf "$GREEN"  "[*] Success Installing MeliziaC2"
	else
		printf "$GREEN"  "[*] Success Installed MeliziaC2"
	fi

	# Install Google Calendar RAT
	if [ ! -d "/usr/share/gcr-google-calendar-rat" ]; then
		git clone https://github.com/MrSaighnal/GCR-Google-Calendar-RAT /usr/share/gcr-google-calendar-rat
		chmod 755 /usr/share/gcr-google-calendar-rat/*
		cat > /usr/bin/gcr << EOF
#!/bin/bash
cd /usr/share/gcr-google-calendar-rat;python3 gcr.py "\$@"
EOF
		chmod +x /usr/bin/gcr
		menu_entry "Command-and-Control" "Red-Team" "Google Calendar RAT" "/usr/share/kali-menu/exec-in-shell 'gcr'"
		printf "$GREEN"  "[*] Success Installing Google Calendar RAT"
	else
		printf "$GREEN"  "[*] Success Installed Google Calendar RAT"
	fi

	# Install MeetC2
	if [ ! -d "/usr/share/meetc2" ]; then
		git clone https://github.com/iammaguire/MeetC2 /usr/share/meetc2
		chmod 755 /usr/share/meetc2/*
		ln -fs /usr/share/meetc2/meetc /usr/bin/meetc
		chmod +x /usr/bin/meetc
		menu_entry "Command-and-Control" "Red-Team" "MeetC2" "/usr/share/kali-menu/exec-in-shell 'meetc'"
		printf "$GREEN"  "[*] Success Installing MeetC2"
	else
		printf "$GREEN"  "[*] Success Installed MeetC2"
	fi

	# Install Ligolo-mp
	if [ ! -d "/usr/share/ligolo-mp" ]; then
		mkdir -p /usr/share/ligolo-mp
		wget https://github.com/ttpreport/ligolo-mp/releases/latest/download/ligolo-mp_server_1.0.3_linux_amd64 -O /usr/share/ligolo-mp/ligolos
		wget https://github.com/ttpreport/ligolo-mp/releases/latest/download/ligolo-mp_client_1.0.3_linux_amd64 -O /usr/share/ligolo-mp/ligoloc
		wget https://github.com/ttpreport/ligolo-mp/releases/latest/download/ligolo-mp_client_1.0.3_windows_amd64.exe -O /usr/share/ligolo-mp/ligoloc.exe
		chmod 755 /usr/share/ligolo-mp/*
		ln -fs /usr/share/ligolo-mp/ligolos /usr/bin/ligolos
		chmod +x /usr/bin/ligolos
		menu_entry "Command-and-Control" "Red-Team" "Ligolo-mp" "/usr/share/kali-menu/exec-in-shell 'sudo ligolos -h'"
		printf "$GREEN"  "[*] Success Installing Ligolo-mp"
	else
		printf "$GREEN"  "[*] Success Installed Ligolo-mp"
	fi

	# Install Realm
	if [ ! -d "/usr/share/realm" ]; then
		mkdir -p /usr/share/realm
		wget https://github.com/spellshift/realm/releases/latest/download/tavern -O /usr/share/realm/tavern
		ln -fs /usr/share/realm/tavern /usr/bin/tavern
		menu_entry "Red-Team" "Command-and-Control" "Tavern" "/usr/share/kali-menu/exec-in-shell 'tavern'"
		wget https://github.com/spellshift/realm/releases/latest/download/imix-x86_64-unknown-linux-musl -O /usr/share/realm/imix
		ln -fs /usr/share/realm/imix /usr/bin/imix
		menu_entry "Command-and-Control" "Red-Team" "Imix" "/usr/share/kali-menu/exec-in-shell 'imix'"
		printf "$GREEN"  "[*] Success Installing Realm"
	else
		printf "$GREEN"  "[*] Success Installed Realm"
	fi

	# Install Badrats
	if [ ! -d "/usr/share/badrats" ]; then
		git clone https://gitlab.com/KevinJClark/badrats /usr/share/badrats
		chmod 755 /usr/share/badrats/*
		cat > /usr/bin/badrats << EOF
#!/bin/bash
cd /usr/share/badrats;python3 badrat_server.py "\$@"
EOF
		chmod +x /usr/bin/badrats
		pip3 install -r /usr/share/badrats/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "Badrats" "/usr/share/kali-menu/exec-in-shell 'sudo badrats'"
		printf "$GREEN"  "[*] Success Installing Badrats"
	else
		printf "$GREEN"  "[*] Success Installed Badrats"
	fi

	# Install Mythic
	if [ ! -d "/usr/share/mythic" ]; then
		git clone https://github.com/its-a-feature/Mythic /usr/share/mythic
		chmod 755 /usr/share/mythic/*
		cd /usr/share/mythic;./install_docker_kali.sh
		cd /usr/share/mythic/Mythic_CLI/src;make
		cd /usr/share/mythic/mythic-docker/src;make
		ln -fs /usr/share/mythic/Mythic_CLI/src/mythic-cli /usr/bin/mythic-cli
		ln -fs /usr/share/mythic/mythic-docker/src/mythic_server /usr/bin/mythic_server
		chmod +x /usr/bin/mythic-cli;chmod +x /usr/bin/mythic_server
		menu_entry "Command-and-Control" "Red-Team" "Mythic-CLI" "/usr/share/kali-menu/exec-in-shell 'sudo mythic-cli'"
		menu_entry "Command-and-Control" "Red-Team" "Mythic-Server" "/usr/share/kali-menu/exec-in-shell 'sudo mythic_server'"
		printf "$GREEN"  "[*] Success Installing Mythic"
	else
		printf "$GREEN"  "[*] Success Installed Mythic"
	fi

	# Install NorthStarC2
	if [ ! -d "/usr/share/northstarc2" ]; then
		git clone https://github.com/EnginDemirbilek/NorthStarC2 /usr/share/northstarc2
		chmod 755 /usr/share/northstarc2/*
		ln -fs /usr/share/mythic/Mythic_CLI/src/mythic-cli /usr/bin/mythic-cli
		menu_entry "Command-and-Control" "Red-Team" "NorthStarC2" "/usr/share/kali-menu/exec-in-shell 'sudo northstarc2'"
		printf "$GREEN"  "[*] Success Installing NorthStarC2"
	else
		printf "$GREEN"  "[*] Success Installed NorthStarC2"
	fi

	# Install BlackMamba
	if [ ! -d "/usr/share/blackmamba" ]; then
		git clone https://github.com/loseys/BlackMamba /usr/share/blackmamba
		chmod 755 /usr/share/blackmamba/*
		cat > /usr/bin/blackmamba << EOF
#!/bin/bash
cd /usr/share/blackmamba;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/blackmamba
		pip3 install -r /usr/share/blackmamba/requirements.txt
		menu_entry "Command-and-Control" "Red-Team" "BlackMamba" "/usr/share/kali-menu/exec-in-shell 'blackmamba'"
		printf "$GREEN"  "[*] Success Installing BlackMamba"
	else
		printf "$GREEN"  "[*] Success Installed BlackMamba"
	fi

	# Install OffensiveNotion
	if [ ! -d "/usr/share/offensivenotion" ]; then
		mkdir -p /usr/share/offensivenotion
		wget https://github.com/mttaggart/OffensiveNotion/releases/latest/download/offensive_notion_linux_amd64.zip -O /tmp/offensive_notion.zip
		unzip /tmp/offensive_notion.zip -d /usr/share/offensivenotion;rm -f /tmp/offensive_notion.zip
		chmod 755 /usr/share/offensivenotion/*
		ln -fs /usr/share/offensivenotion/offensive_notion /usr/bin/offensive_notion
		chmod +x /usr/bin/offensive_notion
		menu_entry "Command-and-Control" "Red-Team" "OffensiveNotion" "/usr/share/kali-menu/exec-in-shell 'offensive_notion'"
		printf "$GREEN"  "[*] Success Installing OffensiveNotion"
	else
		printf "$GREEN"  "[*] Success Installed OffensiveNotion"
	fi

	# Install RedbloodC2
	if [ ! -d "/usr/share/redbloodc2" ]; then
		git clone https://github.com/kira2040k/RedbloodC2 /usr/share/redbloodc2
		chmod 755 /usr/share/redbloodc2/*
		cat > /usr/bin/redbloodc2 << EOF
#!/bin/bash
cd /usr/share/redbloodc2;node server.js "\$@"
EOF
		chmod +x /usr/bin/redbloodc2
		cd /usr/share/redbloodc2;npm install
		menu_entry "Command-and-Control" "Red-Team" "RedbloodC2" "/usr/share/kali-menu/exec-in-shell 'redbloodc2'"
		printf "$GREEN"  "[*] Success Installing RedbloodC2"
	else
		printf "$GREEN"  "[*] Success Installed RedbloodC2"
	fi

	# Install SharpC2
	if [ ! -d "/usr/share/SharpC2" ]; then
		wget https://github.com/rasta-mouse/SharpC2/releases/latest/download/teamserver-linux.tar.gz -O /tmp/teamserver-linux.tar.gz
		tar -xvf /tmp/teamserver-linux.tar.gz -C /usr/share;rm -f /tmp/teamserver-linux.tar.gz
		ln -fs /usr/share/SharpC2/TeamServer /usr/bin/sharpc2
		chmod +x /usr/bin/sharpc2
		menu_entry "Command-and-Control" "Red-Team" "SharpC2" "/usr/share/kali-menu/exec-in-shell 'sharpc2'"
		printf "$GREEN"  "[*] Success Installing SharpC2"
	else
		printf "$GREEN"  "[*] Success Installed SharpC2"
	fi

	# Install emp3r0r
	if [ ! -d "/usr/share/emp3r0r-build" ]; then
		wget https://github.com/jm33-m0/emp3r0r/releases/latest/download/emp3r0r-v1.36.0.tar.xz -O /tmp/emp3r0r.tar.xz
		tar -xvf /tmp/emp3r0r.tar.xz -C /usr/share;rm -f /tmp/emp3r0r.tar.xz
		chmod 755 /usr/share/emp3r0r-build/*
		cd /usr/share/emp3r0r-build;./emp3r0r --install
		menu_entry "Command-and-Control" "Red-Team" "emp3r0r" "/usr/share/kali-menu/exec-in-shell 'emp3r0r'"
		printf "$GREEN"  "[*] Success Installing emp3r0r"
	else
		printf "$GREEN"  "[*] Success Installed emp3r0r"
	fi

	# Install CHAOS
	if [ ! -d "/usr/share/chaos" ]; then
		git clone https://github.com/tiagorlampert/CHAOS /usr/share/chaos
		chmod 755 /usr/share/chaos/*
		cat > /usr/bin/chaos << EOF
#!/bin/bash
cd /usr/share/chaos;PORT=8080 SQLITE_DATABASE=chaos go run cmd/chaos/main.go "\$@"
EOF
		chmod +x /usr/bin/chaos
		menu_entry "Command-and-Control" "Red-Team" "CHAOS" "/usr/share/kali-menu/exec-in-shell 'chaos'"
		printf "$GREEN"  "[*] Success Installing CHAOS"
	else
		printf "$GREEN"  "[*] Success Installed CHAOS"
	fi

	# Install GoDoH
	if [ ! -d "/usr/share/godoh" ]; then
		mkdir -p /usr/share/godoh
		wget https://github.com/sensepost/godoh/releases/latest/download/godoh-linux64 -O /usr/share/godoh/godoh
		chmod 755 /usr/share/godoh/*
		ln -fs /usr/share/godoh/godoh /usr/bin/godoh
		chmod +x /usr/bin/godoh
		menu_entry "Command-and-Control" "Red-Team" "GoDoH" "/usr/share/kali-menu/exec-in-shell 'godoh -h'"
		printf "$GREEN"  "[*] Success Installing GoDoH"
	else
		printf "$GREEN"  "[*] Success Installed GoDoH"
	fi

	# Install Silver
	if [ ! -d "/usr/share/sliver" ]; then
		mkdir -p /usr/share/sliver
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -O /usr/share/sliver/sliver_client
		chmod 755 /usr/share/sliver/*
		ln -fs /usr/share/sliver/sliver_client /usr/bin/sliverc
		chmod +x /usr/bin/sliverc
		menu_entry "Command-and-Control" "Red-Team" "SilverC" "/usr/share/kali-menu/exec-in-shell 'sudo sliverc -h'"
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/share/sliver/sliver_server
		chmod 755 /usr/share/sliver/*
		ln -fs /usr/share/sliver/sliver_server /usr/bin/slivers
		chmod +x /usr/bin/slivers
		menu_entry "Command-and-Control" "Red-Team" "SilverS" "/usr/share/kali-menu/exec-in-shell 'sudo slivers -h'"
		printf "$GREEN"  "[*] Success Installing Silver"
	else
		printf "$GREEN"  "[*] Success Installed Silver"
	fi

	# Install Havoc
	if [ ! -d "/usr/share/havoc" ]; then
		git clone https://github.com/HavocFramework/Havoc /usr/share/havoc
		chmod 755 /usr/share/havoc/*
		cd /user/share/havoc/client;make
		ln -fs /user/share/havoc/client/havoc /usr/bin/havoc
		chmod +x /usr/bin/havoc
		menu_entry "Command-and-Control" "Red-Team" "Havoc" "/usr/share/kali-menu/exec-in-shell 'sudo havoc -h'"
		cd /user/share/havoc/Teamserver;./Install.sh;make
		ln -fs /user/share/havoc/Teamserver/teamserver /usr/bin/havocts
		chmod +x /usr/bin/havocts
		menu_entry "Command-and-Control" "Red-Team" "HavocTS" "/usr/share/kali-menu/exec-in-shell 'sudo havocts -h'"
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

	# Install Ngrok
	if [ ! -f "/usr/bin/ngrok" ]; then
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/ngrok-v3-stable-linux-amd64.tgz
		tar -xvf /tmp/ngrok-v3-stable-linux-amd64.tgz -C /usr/bin;rm -f /tmp/ngrok-v3-stable-linux-amd64.tgz
		chmod +x /usr/bin/ngrok
		menu_entry "Exfiltration" "Red-Team" "Ngrok" "/usr/share/kali-menu/exec-in-shell 'ngrok -h'"
		printf "$GREEN"  "[*] Success Installing Ngrok"
	else
		printf "$GREEN"  "[*] Success Installed Ngrok"
	fi

	# Install NoIP
	if [ ! -d "/usr/share/noip-*" ]; then
		wget wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/noip-duc-linux.tar.gz
		tar -xvf /tmp/noip-duc-linux.tar.gz -C /usr/share;rm -f /tmp/noip-duc-linux.tar.gz
		chmod 755 /usr/share/noip-*/*;cd /usr/share/noip-*;make;make install
		menu_entry "Exfiltration" "Red-Team" "NoIP" "/usr/share/kali-menu/exec-in-shell 'noip -h'"
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
		menu_entry "Exfiltration" "Red-Team" "DNSExfiltrator" "/usr/share/kali-menu/exec-in-shell 'dnsexfiltrator -h'"
		printf "$GREEN"  "[*] Success Installing DNSExfiltrator"
	else
		printf "$GREEN"  "[*] Success Installed DNSExfiltrator"
	fi

	# Install BobTheSmuggler
	if [ ! -d "/usr/share/bobthesmuggler" ]; then
		git clone https://github.com/TheCyb3rAlpha/BobTheSmuggler /usr/share/bobthesmuggler
		chmod 755 /usr/share/bobthesmuggler/*
		cat > /usr/bin/bobthesmuggler << EOF
#!/bin/bash
cd /usr/share/bobthesmuggler;python3 BobTheSmuggler.py "\$@"
EOF
		chmod +x /usr/bin/bobthesmuggler
		pip3 install python-magic py7zr pyminizip
		menu_entry "Exfiltration" "Red-Team" "BobTheSmuggler" "/usr/share/kali-menu/exec-in-shell 'bobthesmuggler -h'"
		printf "$GREEN"  "[*] Success Installing BobTheSmuggler"
	else
		printf "$GREEN"  "[*] Success Installed BobTheSmuggler"
	fi

	# Install SSH-Snake
	if [ ! -d "/usr/share/ssh-snake" ]; then
		git clone https://github.com/MegaManSec/SSH-Snake /usr/share/ssh-snake
		chmod 755 /usr/share/ssh-snake/*
		cat > /usr/bin/snake << EOF
#!/bin/bash
cd /usr/share/ssh-snake;bash Snake.sh "\$@"
EOF
		chmod +x /usr/bin/snake
		menu_entry "Exfiltration" "Red-Team" "SSH-Snake" "/usr/share/kali-menu/exec-in-shell 'snake -h'"
		printf "$GREEN"  "[*] Success Installing SSH-Snake"
	else
		printf "$GREEN"  "[*] Success Installed SSH-Snake"
	fi

	# Install ReverseSSH
	if [ ! -d "/usr/share/reverse-ssh" ]; then
	mkdir -p /usr/share/reverse-ssh
		wget https://github.com/Fahrj/reverse-ssh/releases/latest/download/reverse-sshx64 -O /usr/share/reverse-ssh/reverse-sshx64
		chmod 755 /usr/share/reverse-ssh/*
		cat > /usr/bin/reversessh << EOF
#!/bin/bash
cd /usr/share/reverse-ssh;./reverse-sshx64 "\$@"
EOF
		chmod +x /usr/bin/reversessh
		menu_entry "Exfiltration" "Red-Team" "ReverseSSH" "/usr/share/kali-menu/exec-in-shell 'reversessh -h'"
		printf "$GREEN"  "[*] Success Installing ReverseSSH"
	else
		printf "$GREEN"  "[*] Success Installed ReverseSSH"
	fi

	# Install transfer.sh
	if [ ! -d "/usr/share/transfer.sh" ]; then
		mkdir -p /usr/share/transfer.sh
		wget https://github.com/dutchcoders/transfer.sh/releases/latest/download/transfersh-v1.6.1-linux-amd64 -O /usr/share/transfer.sh/transfersh
		chmod 755 /usr/share/transfer.sh/*
		ln -fs /usr/share/transfer.sh/transfersh /usr/bin/transfersh
		chmod +x /usr/bin/transfersh
		menu_entry "Exfiltration" "Red-Team" "transfer.sh" "/usr/share/kali-menu/exec-in-shell 'transfersh -h'"
		printf "$GREEN"  "[*] Success Installing transfer.sh"
	else
		printf "$GREEN"  "[*] Success Installed transfer.sh"
	fi

	# Install DNSlivery
	if [ ! -d "/usr/share/dnslivery" ]; then
		git clone https://github.com/no0be/DNSlivery /usr/share/dnslivery
		chmod 755 /usr/share/dnslivery/*
		cat > /usr/bin/dnslivery << EOF
#!/bin/bash
cd /usr/share/dnslivery;python3 dnslivery.py "\$@"
EOF
		chmod +x /usr/bin/dnslivery
		pip3 install -r /usr/share/dnslivery/requirements.txt
		menu_entry "Exfiltration" "Red-Team" "DNSlivery" "/usr/share/kali-menu/exec-in-shell 'dnslivery -h'"
		printf "$GREEN"  "[*] Success Installing DNSlivery"
	else
		printf "$GREEN"  "[*] Success Installed DNSlivery"
	fi

	# Install WebDavDelivery
	if [ ! -d "/usr/share/webdavdelivery" ]; then
		git clone https://github.com/Arno0x/WebDavDelivery /usr/share/webdavdelivery
		chmod 755 /usr/share/webdavdelivery/*
		cat > /usr/bin/webdavdelivery << EOF
#!/bin/bash
cd /usr/share/webdavdelivery;python3 webDavDelivery.py "\$@"
EOF
		chmod +x /usr/bin/webdavdelivery
		menu_entry "Exfiltration" "Red-Team" "WebDavDelivery" "/usr/share/kali-menu/exec-in-shell 'webdavdelivery -h'"
		printf "$GREEN"  "[*] Success Installing WebDavDelivery"
	else
		printf "$GREEN"  "[*] Success Installed WebDavDelivery"
	fi

	# Install WSTunnel
	if [ ! -d "/usr/share/wstunnel" ]; then
		mkdir -p /usr/share/wstunnel
		wget https://github.com/erebe/wstunnel/releases/latest/download/wstunnel_9.2.5_linux_amd64.tar.gz -O /tmp/wstunnel_amd64.tar.gz
		tar -xvf /tmp/wstunnel_amd64.tar.gz -C /usr/share/wstunnel;rm -f /tmp/wstunnel_amd64.tar.gz
		chmod 755 /usr/share/wstunnel/*
		ln -fs /usr/share/wstunnel/wstunnel /usr/bin/wstunnel
		chmod +x /usr/bin/wstunnel
		menu_entry "Exfiltration" "Red-Team" "WSTunnel" "/usr/share/kali-menu/exec-in-shell 'wstunnel -h'"
		printf "$GREEN"  "[*] Success Installing WSTunnel"
	else
		printf "$GREEN"  "[*] Success Installed WSTunnel"
	fi

	# Install IPFS
	if [ ! -d "/usr/share/kubo" ]; then
		wget https://dist.ipfs.tech/kubo/v0.28.0-rc1/kubo_v0.28.0-rc1_linux-amd64.tar.gz -O /tmp/ipfs_linux-amd64.tar.gz
		tar -xvf /tmp/ipfs_linux-amd64.tar.gz -C /usr/share;rm -f /tmp/ipfs_linux-amd64.tar.gz
		chmod 755 /usr/share/kubo/*
		cd /usr/share/kubo;./install.sh
		menu_entry "Exfiltration" "Red-Team" "IPFS" "/usr/share/kali-menu/exec-in-shell 'ipfs'"
		printf "$GREEN"  "[*] Success Installing IPFS"
	else
		printf "$GREEN"  "[*] Success Installed IPFS"
	fi

	# Install FRP
	if [ ! -d "/usr/share/frp_*" ]; then
		wget https://github.com/fatedier/frp/releases/latest/download/frp_0.57.0_linux_amd64.tar.gz -O /tmp/frp_linux-amd64.tar.gz
		tar -xvf /tmp/frp_linux-amd64.tar.gz -C /usr/share;rm -f /tmp/frp_linux-amd64.tar.gz
		chmod 755 /usr/share/frp_*/*
		ln -fs /usr/share/frp_*/frps /usr/bin/frps
		chmod +x /usr/bin/frps
		menu_entry "Exfiltration" "Red-Team" "FRP" "/usr/share/kali-menu/exec-in-shell 'frp -h'"
		printf "$GREEN"  "[*] Success Installing FRP"
	else
		printf "$GREEN"  "[*] Success Installed FRP"
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

	# Install S7Scan
	if [ ! -d "/usr/share/S7Scan" ]; then
		git clone https://github.com/klsecservices/s7scan /usr/share/S7Scan
		chmod 755 /usr/share/S7Scan/*
		cat > /usr/bin/s7scan << EOF
#!/bin/bash
cd /usr/share/S7Scan;python2 s7scan.py "\$@"
EOF
		chmod +x /usr/bin/s7scan
		menu_entry "Penetration-Testing" "ICS-Security" "S7Scan" "/usr/share/kali-menu/exec-in-shell 's7scan -h'"
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
		menu_entry "Penetration-Testing" "ICS-Security" "ModbusPal" "/usr/share/kali-menu/exec-in-shell 'modbuspal -h'"
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
		menu_entry "Penetration-Testing" "ICS-Security" "ISF" "/usr/share/kali-menu/exec-in-shell 'isf -h'"
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
	apt install -qy forensics-all ghidra foremost qpdf kafkacat gdb pspy 

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
		cd /usr/share/stegocracker;python3 setup.py install;bash install.sh 
		menu_entry "Malware-Analysis" "Digital-Forensic" "StegoCracker" "/usr/share/kali-menu/exec-in-shell 'stego -h'"
		printf "$GREEN"  "[*] Success Installing StegoCracker"
	else
		printf "$GREEN"  "[*] Success Installed StegoCracker"
	fi

	# Install OpenStego
	if [ ! -d "/usr/share/openstego" ]; then
		wget https://github.com/syvaidya/openstego/releases/latest/download/openstego_0.8.6-1_all.deb -O /tmp/openstego_amd64.deb
		chmod +x /tmp/openstego_amd64.deb;dpkg -i /tmp/openstego_amd64.deb;apt --fix-broken install -qy;rm -f /tmp/openstego_amd64.deb
		menu_entry "Malware-Analysis" "Digital-Forensic" "OpenStego" "/usr/share/kali-menu/exec-in-shell 'sudo openstego -h'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "StegoSaurus" "/usr/share/kali-menu/exec-in-shell 'sudo stegosaurus -h'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "AudioStego" "/usr/share/kali-menu/exec-in-shell 'sudo hideme -h'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "Cloacked-Pixel" "/usr/share/kali-menu/exec-in-shell 'cloackedpixel -h'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "Steganabara" "/usr/share/kali-menu/exec-in-shell 'steganabara -h'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "Stegsolve" "/usr/share/kali-menu/exec-in-shell 'stegsolve -h'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "OpenPuff" "/usr/share/kali-menu/exec-in-shell 'openpuff'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "mp3stego-encode" "/usr/share/kali-menu/exec-in-shell 'mp3stego-encode'"
		cat > /usr/bin/mp3stego-decode << EOF
#!/bin/bash
cd /usr/share/mp3stego/MP3Stego;wine Decode.exe "\$@"
EOF
		chmod +x /usr/bin/mp3stego-decode
		menu_entry "Malware-Analysis" "Digital-Forensic" "mp3stego-decode" "/usr/share/kali-menu/exec-in-shell 'mp3stego-decode'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "JSteg" "/usr/share/kali-menu/exec-in-shell 'sudo jsteg -h'"
		wget https://github.com/lukechampine/jsteg/releases/latest/download/slink-linux-amd64 -O /usr/share/jsteg-slink/slink
		ln -fs /usr/share/jsteg-slink/slink /usr/bin/slink
		chmod +x /usr/bin/slink
		menu_entry "Malware-Analysis" "Digital-Forensic" "Slink" "/usr/share/kali-menu/exec-in-shell 'sudo slink -h'"
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
		menu_entry "Malware-Analysis" "Digital-Forensic" "cjpeg" "/usr/share/kali-menu/exec-in-shell 'sudo cjpeg -h'"
		ln -fs /usr/share/ssak/programs/64/djpeg /usr/bin/djpeg
		chmod +x /usr/bin/djpeg
		menu_entry "Malware-Analysis" "Digital-Forensic" "djpeg" "/usr/share/kali-menu/exec-in-shell 'sudo djpeg -h'"
		ln -fs /usr/share/ssak/programs/64/histogram /usr/bin/histogram
		chmod +x /usr/bin/histogram
		menu_entry "Malware-Analysis" "Digital-Forensic" "histogram" "/usr/share/kali-menu/exec-in-shell 'sudo histogram -h'"
		ln -fs /usr/share/ssak/programs/64/jphide /usr/bin/jphide
		chmod +x /usr/bin/jphide
		menu_entry "Malware-Analysis" "Digital-Forensic" "jphide" "/usr/share/kali-menu/exec-in-shell 'sudo jphide -h'"
		ln -fs /usr/share/ssak/programs/64/jpseek /usr/bin/jpseek
		chmod +x /usr/bin/jpseek
		menu_entry "Malware-Analysis" "Digital-Forensic" "jpseek" "/usr/share/kali-menu/exec-in-shell 'sudo jpseek -h'"
		ln -fs /usr/share/ssak/programs/64/outguess_0.13 /usr/bin/outguess
		chmod +x /usr/bin/outguess
		menu_entry "Malware-Analysis" "Digital-Forensic" "outguess" "/usr/share/kali-menu/exec-in-shell 'sudo outguess -h'"
		ln -fs /usr/share/ssak/programs/64/stegbreak /usr/bin/stegbreak
		chmod +x /usr/bin/stegbreak
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegbreak" "/usr/share/kali-menu/exec-in-shell 'sudo stegbreak -h'"
		ln -fs /usr/share/ssak/programs/64/stegcompare /usr/bin/stegcompare
		chmod +x /usr/bin/stegcompare
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegcompare" "/usr/share/kali-menu/exec-in-shell 'sudo stegcompare -h'"
		ln -fs /usr/share/ssak/programs/64/stegdeimage /usr/bin/stegdeimage
		chmod +x /usr/bin/stegdeimage
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegdeimage" "/usr/share/kali-menu/exec-in-shell 'sudo stegdeimage -h'"
		ln -fs /usr/share/ssak/programs/64/stegdetect /usr/bin/stegdetect
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

	# Install Matano
	if [ ! -d "/usr/share/matano" ]; then
		wget https://github.com/matanolabs/matano/releases/download/nightly/matano-linux-x64.sh -O /tmp/matano-linux.sh
		chmod +x /tmp/matano-linux.sh;cd /tmp;bash matano-linux.sh;rm -f matano-linux.sh
		printf "$GREEN"  "[*] Success Installing Matano"
	else
		printf "$GREEN"  "[*] Success Installed Matano"
	fi

	# Install APT-Hunter
	if [ ! -d "/usr/share/apt-hunter" ]; then
		git clone https://github.com/ahmedkhlief/APT-Hunter -O /usr/share/apt-hunter
		chmod 755 /usr/share/apt-hunter/*
		cat > /usr/bin/apt-hunter << EOF
#!/bin/bash
cd /usr/share/apt-hunter;python3 APT-Hunter.py "\$@"
EOF
		chmod +x /usr/bin/apt-hunter
		pip3 install -r /usr/share/apt-hunter/requirements.txt
		menu_entry "Threat-Hunting" "Digital-Forensic" "APT-Hunter" "/usr/share/kali-menu/exec-in-shell 'apt-hunter -h'"
		printf "$GREEN"  "[*] Success Installing APT-Hunter"
	else
		printf "$GREEN"  "[*] Success Installed APT-Hunter"
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

	# Install Velociraptor
	if [ ! -d "/usr/share/velociraptor" ]; then
		mkdir -p /usr/share/velociraptor
		wget https://github.com/Velocidex/velociraptor/releases/download/v0.7.1/velociraptor-v0.7.1-linux-amd64 -O /usr/share/velociraptor/velociraptor
		chmod 755 /usr/share/velociraptor/*
		ln -fs /usr/share/velociraptor/velociraptor /usr/bin/velociraptor
		menu_entry "Incident-Response" "Digital-Forensic" "Velociraptor" "/usr/share/kali-menu/exec-in-shell 'velociraptor -h'"
		printf "$GREEN"  "[*] Success Installing Velociraptor"
	else
		printf "$GREEN"  "[*] Success Installed Velociraptor"
	fi

	# Install GRR
	if [ ! -d "/usr/share/grr-server" ]; then
		wget https://github.com/google/grr/releases/download/v3.4.7.1-release/grr-server_3.4.7-1_amd64.deb -O /tmp/grr-server.deb
		chmod +x /tmp/grr-server.deb;dpkg -i /tmp/grr-server.deb;rm -f /tmp/grr-server.deb
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

	# Install OpenCTI
	if [ ! -d "/usr/share/opencti" ]; then
		wget https://github.com/OpenCTI-Platform/opencti/releases/download/6.0.6/opencti-release-6.0.6.tar.gz -O /tmp/opencti.tar.gz
		tar -xvf /tmp/opencti.tar.gz -C /usr/share/opencti;rm -f /tmp/opencti.tar.gz
		chmod 755 /usr/share/opencti/*
		cp /usr/share/opencti/config/default.json /usr/share/opencti/config/production.json
		pip3 install -r /usr/share/opencti/src/python/requirements.txt
		cd /usr/share/opencti;yarn install;yarn build;yarn serv
		pip3 install -r /usr/share/opencti/worker/requirements.txt
		cp /usr/share/opencti/worker/config.yml.sample /usr/share/opencti/worker/config.yml
		cat > /usr/bin/opencti << EOF
cd /usr/share/opencti/worker;python3 worker.py > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:4000" > /dev/null &
EOF
		chmod +x /usr/bin/opencti
		menu_entry "Threat-Intelligence" "Digital-Forensic" "OpenCTI" "/usr/share/kali-menu/exec-in-shell 'opencti'"
		printf "$GREEN"  "[*] Success Installing OpenCTI"
	else
		printf "$GREEN"  "[*] Success Installed OpenCTI"
	fi

	# Install TRAM
	if [ ! -d "/usr/share/tram" ]; then
		curl -LO https://github.com/center-for-threat-informed-defense/tram/raw/main/docker/docker-compose.yml
		docker-compose up
		printf "$GREEN"  "[*] Success Installing TRAM"
	else
		printf "$GREEN"  "[*] Success Installed TRAM"
	fi

	# Install RITA
	if [ ! -d "/var/opt/rita" ]; then
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
	apt install -qy syslog-ng-core syslog-ng-scl bubblewrap suricata zeek tripwire aide clamav chkrootkit sentrypeer arkime cyberchef snort rspamd prometheus 

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
		sed -i "s|<indexer-node-ip>|$LAN|g" /tmp/config.yml;sed -i "s|<wazuh-manager-ip>|$LAN|g" /tmp/config.yml;sed -i "s|<dashboard-node-ip>|$LAN|g" /tmp/config.yml
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

	# Install OpenSearch
	if [ ! -d "/usr/share/opensearch" ]; then
		wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.deb -O /tmp/opensearch-linux.deb
		chmod +x /tmp/opensearch-linux.deb;dpkg -i /tmp/opensearch-linux.deb;rm -f /tmp/opensearch-linux.deb
		printf "$GREEN"  "[*] Success Installing OpenSearch"
	else
		printf "$GREEN"  "[*] Success Installed OpenSearch"
	fi

	# Install Falco
	if [ ! -f "/etc/apt/sources.list.d/falcosecurity.list" ]; then
		curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
		cat > /etc/apt/sources.list.d/falcosecurity.list  << EOF
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF
		apt-get update -y;apt-get install -y dkms make linux-headers-$(uname -r) dialog;apt-get install -y falco
		printf "$GREEN"  "[*] Success Installing Falco"
	else
		printf "$GREEN"  "[*] Success Installed Falco"
	fi

	# Install SIEGMA
	if [ ! -d "/usr/share/siegma" ]; then
		git clone https://github.com/3CORESec/SIEGMA /usr/share/siegma
		chmod 755 /usr/share/siegma/*
		cat > /usr/bin/siegma << EOF
#!/bin/bash
cd /usr/share/siegma;python3 siegma.py "\$@"
EOF
		chmod +x /usr/bin/siegma
		pip3 install -r /usr/share/siegma/requirements.txt
		menu_entry "Detect" "Blue-Team" "SIEGMA" "/usr/share/kali-menu/exec-in-shell 'siegma -h'"
		printf "$GREEN"  "[*] Success Installing SIEGMA"
	else
		printf "$GREEN"  "[*] Success Installed SIEGMA"
	fi

	# Install Cilium
	if [ ! -d "/usr/local/bin/cilium" ]; then
		CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
		CLI_ARCH=amd64
		if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
		curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
		sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
		tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
		rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
		menu_entry "Detect" "Blue-Team" "Cilium" "/usr/share/kali-menu/exec-in-shell 'cilium -h'"
		printf "$GREEN"  "[*] Success Installing Cilium"
	else
		printf "$GREEN"  "[*] Success Installed Cilium"
	fi

	# Install OSSEC
	if [ ! -f "/etc/apt/sources.list.d/atomic.list" ]; then
		wget -q -O - https://www.atomicorp.com/RPM-GPG-KEY.atomicorp.txt  | sudo apt-key add -
		echo "deb https://updates.atomicorp.com/channels/atomic/debian $DISTRIB_CODENAME main" >>  /etc/apt/sources.list.d/atomic.list
		apt-get update;apt-get install -y ossec-hids-server ossec-hids-agent
		printf "$GREEN"  "[*] Success Installing OSSEC"
	else
		printf "$GREEN"  "[*] Success Installed OSSEC"
	fi

	# Install Cilium
	if [ ! -d "/usr/share/cilium-cli" ]; then
		mkdir -p /usr/share/cilium-cli
		wget https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz -O /tmp/cilium-linux-amd64.tar.gz
		tar -xvf /tmp/cilium-linux-amd64.tar.gz -C /usr/share/cilium-cli;rm -f /tmp/cilium-linux-amd64.tar.gz
		ln -fs /usr/share/cilium-cli/cilium /usr/bin/cilium
		menu_entry "Detect" "Blue-Team" "Cilium" "/usr/share/kali-menu/exec-in-shell 'cilium -h'"
		printf "$GREEN"  "[*] Success Installing Cilium"
	else
		printf "$GREEN"  "[*] Success Installed Cilium"
	fi

	# Install ElasticSeaerch
	if [ ! -d "/usr/share/elasticsearch" ]; then
		wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.12.2-amd64.deb -O /tmp/elasticsearch-amd64.deb
		chmod +x /tmp/elasticsearch-amd64.deb;dpkg -i /tmp/elasticsearch-amd64.deb;rm -f /tmp/elasticsearch-amd64.deb
		printf "$GREEN"  "[*] Success Installing ElasticSeaerch"
	else
		printf "$GREEN"  "[*] Success Installed ElasticSeaerch"
	fi

	# Install Kibana
	if [ ! -d "/usr/share/kibana" ]; then
		wget https://artifacts.elastic.co/downloads/kibana/kibana-8.12.2-amd64.deb -O /tmp/kibana-amd64.deb
		chmod +x /tmp/kibana-amd64.deb;dpkg -i /tmp/kibana-amd64.deb;rm -f /tmp/kibana-amd64.deb
		printf "$GREEN"  "[*] Success Installing Kibana"
	else
		printf "$GREEN"  "[*] Success Installed Kibana"
	fi

	# Install Logstash
	if [ ! -d "/usr/share/logstash" ]; then
		wget https://artifacts.elastic.co/downloads/logstash/logstash-8.12.2-amd64.deb -O /tmp/logstash-amd64.deb
		chmod +x /tmp/logstash-amd64.deb;dpkg -i /tmp/logstash-amd64.deb;rm -f /tmp/logstash-amd64.deb
		printf "$GREEN"  "[*] Success Installing Logstash"
	else
		printf "$GREEN"  "[*] Success Installed Logstash"
	fi

	# Install Zabbix
	if [ ! -d "/usr/share/zabbix" ]; then
		wget https://repo.zabbix.com/zabbix/6.4/debian/pool/main/z/zabbix-release/zabbix-release_6.4-1+debian12_all.deb -O /tmp/zabbix-release.deb
		chmod +x /tmp/zabbix-release.deb;dpkg -i /tmp/zabbix-release.deb
		apt update;apt install -y zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent
		mysql -u root -p -h localhost -e "create database zabbix character set utf8mb4 collate utf8mb4_bin;create user zabbix@localhost identified by 'password';grant all privileges on zabbix.* to zabbix@localhost;set global log_bin_trust_function_creators = 1;quit;"
		zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -uzabbix -p zabbix
		mysql -u root -p -h localhost -e "set global log_bin_trust_function_creators = 0;quit;"
		sed -i "s|DBPassword=password|DBPassword=unk12341234|g" /etc/zabbix/zabbix_server.conf
		systemctl restart zabbix-server zabbix-agent apache2
		systemctl enable zabbix-server zabbix-agent apache2
		printf "$GREEN"  "[*] Success Installing Zabbix -> http://$LAN/zabbix "
	else
		printf "$GREEN"  "[*] Success Installed Zabbix -> http://$LAN/zabbix "
	fi


	printf "$YELLOW"  "# -------------------------------------------Isolate-Blue-Team--------------------------------------- #"
	# Install Repository Tools
	apt install -qy openvpn wireguard 

	# Install Python3 pip
	isolate_pip="casbin"
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
	preliminary_audit_assessment_pip="google-generativeai scancode-toolkit"
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
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "CheckStyle" "/usr/share/kali-menu/exec-in-shell 'checkstyle'"
		printf "$GREEN"  "[*] Success Installing CheckStyle"
	else
		printf "$GREEN"  "[*] Success Installed CheckStyle"
	fi

	# Install AFLplusplus
	if [ ! -d "/usr/share/aflplusplus" ]; then
		git clone https://github.com/AFLplusplus/AFLplusplus /usr/share/aflplusplus
		chmod 755 /usr/share/aflplusplus/*
		cd /usr/share/aflplusplus;make distrib;make install
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "afl-cc" "/usr/share/kali-menu/exec-in-shell 'afl-cc -h'"
		printf "$GREEN"  "[*] Success Installing AFLplusplus"
	else
		printf "$GREEN"  "[*] Success Installed AFLplusplus"
	fi

	# Install vuls-scanner
	if [ ! -d "/usr/share/vuls-scanner" ]; then
		mkdir -p /usr/share/vuls-scanner
		wget https://github.com/future-architect/vuls/releases/latest/download/vuls-scanner_0.24.9_linux_amd64.tar.gz -O /tmp/vuls-scanner_linux_amd64.tar.gz
		tar -xvf /tmp/vuls-scanner_linux_amd64.tar.gz -C /usr/share/vuls-scanner;rm -r /tmp/vuls-scanner_linux_amd64.tar.gz
		chmod 755 /usr/share/vuls-scanner/*
		ln -fs /usr/share/vuls-scanner/vuls /usr/bin/vuls
		chmod +x /usr/bin/vuls
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "vuls-scanner" "/usr/share/kali-menu/exec-in-shell 'vuls -h'"
		printf "$GREEN"  "[*] Success Installing vuls-scanner"
	else
		printf "$GREEN"  "[*] Success Installed vuls-scanner"
	fi

	# Install syzkaller
	if [ ! -d "/usr/share/syzkaller" ]; then
		git clone https://github.com/google/syzkaller /usr/share/syzkaller
		chmod 755 /usr/share/syzkaller/*;cd /usr/share/syzkaller;make
		ln -fs /usr/share/syzkaller/syzkaller/bin/linux_amd64/syz-fuzzer /usr/bin/syz-fuzzer
		ln -fs /usr/share/syzkaller/syzkaller/bin/linux_amd64/syz-stress /usr/bin/syz-stress
		ln -fs /usr/share/syzkaller/syzkaller/bin/linux_amd64/syz-executor /usr/bin/syz-executor
		chmod +x /usr/bin/syz-fuzzer;chmod +x /usr/bin/syz-stress;chmod +x /usr/bin/syz-executor
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "syz-fuzzer" "/usr/share/kali-menu/exec-in-shell 'syz-fuzzer -h'"
		printf "$GREEN"  "[*] Success Installing syzkaller"
	else
		printf "$GREEN"  "[*] Success Installed syzkaller"
	fi

	# Install Honggfuzz
	if [ ! -d "/usr/share/honggfuzz" ]; then
		git clone https://github.com/google/honggfuzz /usr/share/honggfuzz
		chmod 755 /usr/share/honggfuzz/*;cd /usr/share/honggfuzz;make
		ln -fs /usr/share/honggfuzz/honggfuzz /usr/bin/honggfuzz
		chmod +x /usr/bin/honggfuzz
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Honggfuzz" "/usr/share/kali-menu/exec-in-shell 'honggfuzz -h'"
		printf "$GREEN"  "[*] Success Installing Honggfuzz"
	else
		printf "$GREEN"  "[*] Success Installed Honggfuzz"
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
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Cmder" "/usr/share/kali-menu/exec-in-shell 'cmder'"
		printf "$GREEN"  "[*] Success Installing Cmder"
	else
		printf "$GREEN"  "[*] Success Installed Cmder"
	fi

	# Install Open Policy Agent
	if [ ! -d "/usr/share/open-policy-agent" ]; then
		mkdir -p /usr/share/open-policy-agent
		wget https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_amd64 -O /usr/share/open-policy-agent/opa
		chmod 755 /usr/share/open-policy-agent/*
		ln -fs /usr/share/open-policy-agent/opa /usr/bin/opa
		chmod +x /usr/bin/opa
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Open-Policy-Agent" "/usr/share/kali-menu/exec-in-shell 'opa -h'"
		printf "$GREEN"  "[*] Success Installing Open Policy Agent"
	else
		printf "$GREEN"  "[*] Success Installed Open Policy Agent"
	fi


	printf "$YELLOW"  "# ------------------------------Planning-and-Preparation-Security-Audit------------------------------ #"
	# Install Repository Tools
	# apt install -qy 

	# Install Python3 pip
	# planning_and_preparation_pip=""
	pip_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_pip"

	# Install Nodejs NPM
	# planning_and_preparation_npm=""
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

	# Install Selefra
	if [ ! -d "/usr/share/selefra" ]; then
		mkdir -p /usr/share/selefra
		wget https://github.com/selefra/selefra/releases/latest/download/selefra_linux_amd64.tar.gz -O /tmp/selefra_linux_amd64.tar.gz
		tar -xvf /tmp/selefra_linux_amd64.tar.gz -C /usr/share/selefra;rm -f /tmp/selefra_linux_amd64.tar.gz
		chmod 755 /usr/share/selefra/*
		ln -fs /usr/share/selefra/selefra /usr/bin/selefra
		chmod +x /usr/bin/selefra
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "Selefra" "/usr/share/kali-menu/exec-in-shell 'selefra -h'"
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

	# Install Postman
	if [ ! -d "/usr/share/Postman" ]; then
		mkdir -p /usr/share/Postman
		wget https://dl.pstmn.io/download/latest/linux_64 -O /tmp/postman_linux_64.tar.gz
		tar -xvf /tmp/postman_linux_64.tar.gz -C /usr/share;rm -f /tmp/postman_linux_64.tar.gz
		chmod 755 /usr/share/Postman/*
		cat > /usr/bin/postman << EOF
#!/bin/bash
cd /usr/share/Postman/;./postman "\$@"
EOF
		chmod +x /usr/bin/postman
		menu_entry "Web" "Penetration-Testing" "Postman" "/usr/share/kali-menu/exec-in-shell 'postman'"
		printf "$GREEN"  "[*] Success Installing Postman"
	else
		printf "$GREEN"  "[*] Success Installed Postman"
	fi

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
		menu_entry "Performing-the-Review" "Security-Audit" "Clion" "/usr/bin/clion"
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
		menu_entry "Performing-the-Review" "Security-Audit" "PhpStorm" "/usr/bin/phpstorm"
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
		menu_entry "Performing-the-Review" "Security-Audit" "GoLand" "/usr/bin/goland"
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
		menu_entry "Performing-the-Review" "Security-Audit" "PyCharm" "/usr/bin/pycharm"
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
		menu_entry "Performing-the-Review" "Security-Audit" "RubyMine" "/usr/bin/rubymine"
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
		menu_entry "Performing-the-Review" "Security-Audit" "WebStorm" "/usr/bin/webstorm"
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
		menu_entry "Performing-the-Review" "Security-Audit" "IDEA" "/usr/bin/idea"
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
	apt install -qy curl git apt-transport-https build-essential mingw-w64 apt-utils automake autoconf cmake gnupg default-jdk python3 python3-dev python2 g++ nodejs npm rustup clang nim golang golang-go llvm nasm qtchooser alacarte jq locate 

	# Install Requirements
	apt install -qy libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libunwind-dev libncurses5-dev binutils-dev libgdbm-dev libblocksruntime-dev libssl-dev libevent-dev libreadline-dev libpcre2-dev libffi-dev zlib1g-dev libsqlite3-dev libbz2-dev mesa-common-dev qt5-qmake qtbase5-dev qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev libboost-all-dev qtchooser python3-dev python3-pip python3-poetry libpe-dev 

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

	# Install Kali-Elite
	if [ ! -d "/usr/share/kali-elite" ]; then
		mkdir -p /usr/share/kali-elite
		curl -s -o /usr/share/kali-elite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/kali-elite.sh
		chmod 755 /usr/share/kali-elite/*
		cat > /usr/bin/kalielite << EOF
#!/bin/bash
cd /usr/share/kali-elite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/kalielite
		cat > "/home/$USERS/.local/share/applications/Unk9vvN/kalielite.desktop" << EOF
[Desktop Entry]
Name=Kali-Elite
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
	elif [ "$(curl -s https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/version)" != $ver ]; then
		curl -s -o /usr/share/kali-elite/kalielite.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/kali-elite.sh
		chmod 755 /usr/share/kali-elite/*
		cat > /usr/bin/kalielite << EOF
#!/bin/bash
cd /usr/share/kali-elite;bash kalielite.sh "\$@"
EOF
		chmod +x /usr/bin/kalielite
		cat > "/home/$USERS/.local/share/applications/Unk9vvN/kalielite.desktop" << EOF
[Desktop Entry]
Name=Kali-Elite
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
		bash /usr/share/kali-elite/kalielite.sh
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
