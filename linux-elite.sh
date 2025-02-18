#!/bin/bash
ver='4.2'




RED='\e[1;31m%s\e[0m\n'
GREEN='\e[1;32m%s\e[0m\n'
YELLOW='\e[1;33m%s\e[0m\n'
BLUE='\e[1;34m%s\e[0m\n'
MAGENTO='\e[1;35m%s\e[0m\n'
CYAN='\e[1;36m%s\e[0m\n'
WHITE='\e[1;37m%s\e[0m\n'




if [ "$(id -u)" != "0" ]; then
	printf "${RED}[X] Please run as ROOT...\n"
	printf "${GREEN}[*] sudo linux-elite\n"
	exit 0
else
	# update & upgrade & clean up packages
	apt update;apt upgrade -qy;apt dist-upgrade -qy;apt autoremove -qy;apt autoclean

	# install required packages
	apt install -qy wget curl git net-tools gnupg apt-transport-https alacarte locate debsig-verify xmlstarlet 

	# get current user and LAN IP address
	USERS=$(cd /home;ls | awk '{print $1}')
	LAN=$(hostname -I | awk '{print $1}')
fi


BASE_PATH="/home/$USERS"
CONFIG_MENU_PATH="$BASE_PATH/.config/menus"
IMAGES_PATH="$BASE_PATH/.local/share/images"
APPLICATIONS_PATH="$BASE_PATH/.local/share/applications"
DESKTOP_DIRECTORIES_PATH="$BASE_PATH/.local/share/desktop-directories"


logo()
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
    printf "$CYAN"    "                              Linux Elite "$ver"                    "
    printf "\n\n"
}


create_menu()
{
    local TOPIC_MENU="$1"
    local SUB_MENU="$2"
    shift 2
    local SUB_MENU_ITEMS=($@)

    # Download the main icon
    curl -s -o "$IMAGES_PATH/${SUB_MENU}.png" "https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/${SUB_MENU}.png"

    # Create the main menu folder
    mkdir -p "$APPLICATIONS_PATH/Unk9vvN/$SUB_MENU"

    # Create the .directory file for the main menu
    cat > "$DESKTOP_DIRECTORIES_PATH/${SUB_MENU}.directory" << EOF
[Desktop Entry]
Name=${SUB_MENU}
Comment=${TOPIC_MENU}
Icon=$IMAGES_PATH/${SUB_MENU}.png
Type=Directory
EOF

    # Add the main menu to the XML file
    xmlstarlet ed \
        -s "/Menu/Menu[Name='Unk9vvN']" -t elem -n "Menu" -v "" \
        -s "/Menu/Menu[Name='Unk9vvN']/Menu[last()]" -t elem -n "Name" -v "$SUB_MENU" \
        -s "/Menu/Menu[Name='Unk9vvN']/Menu[last()]" -t elem -n "Directory" -v "${SUB_MENU}.directory" \
        "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
        mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"

    # Create separate submenu for each item
    for ITEM in "${SUB_MENU_ITEMS[@]}"; do
        mkdir -p "$APPLICATIONS_PATH/Unk9vvN/$SUB_MENU/$ITEM"
        
        # Create directory file for each submenu
        cat > "$DESKTOP_DIRECTORIES_PATH/${SUB_MENU}-${ITEM}.directory" << EOF
[Desktop Entry]
Name=${ITEM}
Comment=${SUB_MENU}
Icon=folder
Type=Directory
EOF

        # Add each submenu separately to the XML
        xmlstarlet ed \
            -s "/Menu/Menu/Menu[Name='$SUB_MENU']" -t elem -n "Menu" -v "" \
            -s "/Menu/Menu/Menu[Name='$SUB_MENU']/Menu[last()]" -t elem -n "Name" -v "${SUB_MENU}-${ITEM}" \
            -s "/Menu/Menu/Menu[Name='$SUB_MENU']/Menu[last()]" -t elem -n "Directory" -v "${SUB_MENU}-${ITEM}.directory" \
            "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
            mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"
    done

    # Add Layout to the main menu
    xmlstarlet ed \
        -s "/Menu/Menu/Menu[Name='$SUB_MENU']" -t elem -n "Layout" -v "" \
        -s "/Menu/Menu/Menu[Name='$SUB_MENU']/Layout" -t elem -n "Merge" -v "" \
        -i "/Menu/Menu/Menu[Name='$SUB_MENU']/Layout/Merge" -t attr -n "type" -v "menus" \
        "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
        mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"

    # Include each submenu item in the layout
    for ITEM in "${SUB_MENU_ITEMS[@]}"; do
        xmlstarlet ed \
            -s "/Menu/Menu/Menu[Name='$SUB_MENU']/Layout" -t elem -n "Menuname" -v "${SUB_MENU}-${ITEM}" \
            "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
            mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"
    done

    # Add final Merge to the layout
    xmlstarlet ed \
        -s "/Menu/Menu/Menu[Name='$SUB_MENU']/Layout" -t elem -n "Merge" -v "" \
        -i "/Menu/Menu/Menu[Name='$SUB_MENU']/Layout/Merge[last()]" -t attr -n "type" -v "files" \
        "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
        mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"
}


menu()
{
    mkdir -p "$CONFIG_MENU_PATH"
    mkdir -p "$IMAGES_PATH"
    mkdir -p "$APPLICATIONS_PATH"
    mkdir -p "$DESKTOP_DIRECTORIES_PATH"

    if [ ! -f "$CONFIG_MENU_PATH/xfce-applications.menu" ]; then
        cat > "$CONFIG_MENU_PATH/xfce-applications.menu" << EOF
<?xml version="1.0" ?>
<!DOCTYPE Menu
  PUBLIC '-//freedesktop//DTD Menu 1.0//EN'
  'http://standards.freedesktop.org/menu-spec/menu-1.0.dtd'>
<Menu>
    <Name>Xfce</Name>
    <MergeFile type="parent">/etc/xdg/menus/xfce-applications.menu</MergeFile>
    <DefaultLayout inline="false"/>
    <Layout>
        <Merge type="menus"/>
        <Filename>xfce4-run.desktop</Filename>
        <Separator/>
        <Filename>xfce4-terminal-emulator.desktop</Filename>
        <Filename>xfce4-file-manager.desktop</Filename>
        <Filename>xfce4-mail-reader.desktop</Filename>
        <Filename>xfce4-web-browser.desktop</Filename>
        <Separator/>
        <Menuname>Settings</Menuname>
        <Menuname>Usual Applications</Menuname>
        <Separator/>
        <Menuname>Information Gathering</Menuname>
        <Menuname>Vulnerability Analysis</Menuname>
        <Menuname>Web Application Analysis</Menuname>
        <Menuname>Database Assessment</Menuname>
        <Menuname>Password Attacks</Menuname>
        <Menuname>Wireless Attacks</Menuname>
        <Menuname>Reverse Engineering</Menuname>
        <Menuname>Exploit Frameworks</Menuname>
        <Menuname>Sniffing - Spoofing</Menuname>
        <Menuname>Maintaining Access</Menuname>
        <Menuname>Forensic Tools</Menuname>
        <Menuname>Reporting Tools</Menuname>
        <Menuname>Social Engineering Tools</Menuname>
        <Menuname>System Services</Menuname>
        <Menuname>Kali and OffSec Links</Menuname>
        <Separator/>
        <Filename>xfce4-about.desktop</Filename>
        <Filename>xfce4-session-logout.desktop</Filename>
        <Merge type="files"/>
    </Layout>
</Menu>
EOF
        chmod +x $CONFIG_MENU_PATH/xfce-applications.menu
    fi

    # Initialize Unk9vvN menu
    curl -s -o "$IMAGES_PATH/unk9vvn-logo.jpg" "https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/images/unk9vvn-logo.jpg"
    mkdir -p "$APPLICATIONS_PATH/Unk9vvN"
    cat > "$DESKTOP_DIRECTORIES_PATH/Unk9vvN.directory" << EOF
[Desktop Entry]
Name=Unk9vvN
Comment=unk9vvn.github.io
Icon=$IMAGES_PATH/unk9vvn-logo.jpg
Type=Directory
EOF

    xmlstarlet ed \
        -a "/Menu/DefaultLayout" -t elem -n "Menu" -v "" \
        -s "/Menu/Menu[last()]" -t elem -n "Name" -v "Unk9vvN" \
        -s "/Menu/Menu[last()]" -t elem -n "Directory" -v "Unk9vvN.directory" \
        "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
        mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"

    # Initialize additional menus
    create_menu "Offensive-Security" "Penetration-Testing" "Web Mobile Cloud Network Wireless IoT"
    create_menu "Offensive-Security" "Red-Team" "Reconnaissance Resource-Development Initial-Access Execution Persistence Privilege-Escalation Defense-Evasion Credential-Access Discovery Lateral-Movement Collection Command-and-Control Exfiltration Impact"
    create_menu "Offensive-Security" "ICS-Security" "Penetration-Testing Red-Team Digital-Forensic Blue-Team"
    create_menu "Defensive-Security" "Digital-Forensic" "Reverse-Engineering Malware-Analysis Threat-Hunting Incident-Response Threat-Intelligence"
    create_menu "Defensive-Security" "Blue-Team" "Harden Detect Isolate Deceive Evict"
    create_menu "Defensive-Security" "Security-Audit" "Preliminary-Audit-Assessment Planning-and-Preparation Establishing-Audit-Objectives Performing-the-Review Preparing-the-Audit-Report Issuing-the-Review-Report"
}


menu_entry()
{
    local sub_category="$1"
    local category="$2"
    local tool="$3"
    local command="$4"

    # Create the .desktop file for the tool
    cat > "$APPLICATIONS_PATH/Unk9vvN/${category}/${sub_category}/${tool}.desktop" << EOF
[Desktop Entry]
Name=${tool}
Exec=${command}
Comment=
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF

    # Add Include and Layout to the menu XML file
    xmlstarlet ed \
        --subnode "/Menu" \
        --type elem -n "Menu" -v "" \
        --subnode "/Menu/Menu[last()]" \
        --type elem -n "Name" -v "Unk9vvN-${category}-${sub_category}" \
        --subnode "/Menu/Menu[last()]" \
        --type elem -n "Directory" -v "Unk9vvN-${category}-${sub_category}.directory" \
        --subnode "/Menu/Menu[last()]" \
        --type elem -n "Include" -v "" \
        --subnode "/Menu/Menu[last()]/Include" \
        --type elem -n "Filename" -v "${tool}.desktop" \
        --subnode "/Menu/Menu[last()]" \
        --type elem -n "Layout" -v "" \
        --subnode "/Menu/Menu[last()]/Layout" \
        --type elem -n "Merge" -v "" \
        --insert "/Menu/Menu[last()]/Layout/Merge" \
        --type attr -n "type" -v "menus" \
        --subnode "/Menu/Menu[last()]/Layout" \
        --type elem -n "Merge" -v "" \
        --insert "/Menu/Menu[last()]/Layout/Merge[last()]" \
        --type attr -n "type" -v "files" \
        "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
        mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"
}


pip_installer()
{
    local sub_category="$1"
    local category="$2"
    local pip_string="$3"  # Receive the list of packages as a string

    # Iterate over the space-separated packages in the string
    for package in $pip_string; do
        # Add a menu entry for the package
        menu_entry "${sub_category}" "${category}" "${package}" "$exec_shell 'sudo ${package} -h'"

        # Run the pip installation command
        pip3 install --break-system-packages "${package}"

        # Print a success message
        printf "$GREEN" "[*] Successfully Installed ${package}"
    done
}


npm_installer()
{
    local sub_category="$1"
    local category="$2"
    local npm_string="$3"  # Receive the list of packages as a string

    # Iterate over the space-separated packages in the string
    for package in $npm_string; do
        # Add a menu entry for the package
        menu_entry "${sub_category}" "${category}" "${package}" "$exec_shell 'sudo ${package} -h'"

        # Run the npm installation command
        npm install -g "${package}"

        # Print a success message
        printf "$GREEN" "[*] Successfully Installed ${package}"
    done
}


gem_installer()
{
    local sub_category="$1"
    local category="$2"
    local gem_string="$3"  # Receive the list of packages as a string

    # Iterate over the space-separated packages in the string
    for package in $gem_string; do
        # Add a menu entry for the package
        menu_entry "${sub_category}" "${category}" "${package}" "$exec_shell 'sudo ${package} -h'"

        # Run the gem installation command
        gem install "${package}"

        # Print a success message
        printf "$GREEN" "[*] Successfully Installed ${package}"
    done
}


go_installer()
{
    local sub_category="$1"
    local category="$2"
    local commands="$3"  # Receive the Go commands as a multi-line string

    # Extract binaries from the Go commands and execute each command
    while IFS= read -r line; do
        # Parse the Go binary name if a symbolic link is present
        if [[ $line == *"ln -fs"* ]]; then
            symlink=$(echo "$line" | awk '{print $NF}')
            symlink=${symlink#/}
            symlink=${symlink%/}
            binary=$(basename "$symlink")

            # Add a menu entry for the binary
            menu_entry "${sub_category}" "${category}" "${binary}" "$exec_shell 'sudo ${binary} -h'"

            # Print a success message for the binary
            printf "$GREEN" "[*] Successfully Installed ${binary}"
        fi

        # Execute the Go installation or linking command
        eval "$line"
    done <<< "$commands"
}


penetrating_testing()
{
	printf "$YELLOW"  "# --------------------------------------Web-Penetration-Testing-------------------------------------- #"

	# install Repository Tools
	apt install -qy tor dirsearch nuclei s3scanner rainbowcrack hakrawler netexec gobuster ripgrep davtest httprint ffuf gvm seclists subfinder amass arjun metagoofil sublist3r cupp gifsicle aria2 phpggc emailharvester osrframework jq pngtools gitleaks trufflehog maryam dosbox wig eyewitness oclgausscrack websploit googler inspy pigz massdns gospider proxify dotdotpwn goofile firewalk bing-ip2hosts webhttrack oathtool tcptrack tnscmd10g getallurls padbuster feroxbuster subjack cyberchef whatweb xmlstarlet sslscan assetfinder dnsgen mdbtools pocsuite3 masscan dnsx gsutil libmemcached-tools dnsrecon 

	# install Python3 pip
	web_pip="pyjwt arjun py-altdns pymultitor autosubtakeover kube-hunter bbot droopescan crlfsuite ggshield selenium proxyhub njsscan detect-secrets regexploit h8mail huntsman nodejsscan hashpumpy bhedak gitfive modelscan pyexfil wsgidav defaultcreds-cheat-sheet hiphp pasteme-cli aiodnsbrute semgrep smbclientng graphinder wsrepl apachetomcatscanner dotdotfarm pymetasec theharvester chiasmodon puncia slither-analyzer mythril ja3"
	pip_installer "Web" "Penetration-Testing" "$web_pip"

	# install Nodejs NPM
	web_npm="jwt-cracker graphql padding-oracle-attacker javascript-obfuscator serialize-javascript http-proxy-to-socks node-serialize igf electron-packager redos serialize-to-js dompurify nodesub multitor crlfi infoooze hardhat is-website-vulnerable solgraph"
	npm_installer "Web" "Penetration-Testing" "$web_npm"

	# install Ruby GEM
	web_gem="ssrf_proxy API_Fuzzer dawnscanner mechanize XSpear"
	gem_installer "Web" "Penetration-Testing" "$web_gem"

	# install Golang
	web_golang="
go install github.com/dwisiswant0/go-dork@latest;ln -fs ~/go/bin/go-dork /usr/bin/go-dork
go install github.com/Macmod/godap/v2@latest;ln -fs ~/go/bin/godap /usr/bin/godap
go install github.com/tomnomnom/waybackurls@latest;ln -fs ~/go/bin/waybackurls /usr/bin/waybackurls
go install github.com/tomnomnom/httprobe@latest;ln -fs ~/go/bin/httprobe /usr/bin/httprobe
go install github.com/tomnomnom/meg@latest;ln -fs ~/go/bin/meg /usr/bin/meg
go install github.com/projectdiscovery/katana/cmd/katana@latest;ln -fs ~/go/bin/katana /usr/bin/katana
go install github.com/j3ssie/osmedeus@latest;ln -fs ~/go/bin/osmedeus /usr/bin/osmedeus
go install github.com/edoardottt/cariddi/cmd/cariddi@latest;ln -fs ~/go/bin/cariddi /usr/bin/cariddi
go install github.com/glebarez/cero@latest;ln -fs ~/go/bin/cero /usr/bin/cero
go install github.com/1hehaq/recx@latest;ln -fs ~/go/bin/recx /usr/bin/recx
go install github.com/karust/unjsfuck@latest;ln -fs ~/go/bin/unjsfuck /usr/bin/unjsfuck
go install github.com/mhmdiaa/chronos@latest;ln -fs ~/go/bin/chronos /usr/bin/chronos
go install github.com/shivangx01b/CorsMe@latest;ln -fs ~/go/bin/CorsMe /usr/bin/corsme
go install github.com/pwnesia/dnstake/cmd/dnstake@latest;ln -fs ~/go/bin/dnstake /usr/bin/dnstake
go install github.com/projectdiscovery/uncover/cmd/uncover@latest;ln -fs ~/go/bin/uncover /usr/bin/uncover
go install github.com/projectdiscovery/dnsprobe@latest;ln -fs ~/go/bin/dnsprobe /usr/bin/dnsprobe
go install github.com/ryandamour/crlfmap@latest;ln -fs ~/go/bin/crlfmap /usr/bin/crlfmap
go install github.com/hahwul/dalfox/v2@latest;ln -fs ~/go/bin/dalfox /usr/bin/dalfox
go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest;ln -fs ~/go/bin/urlfinder /usr/bin/urlfinder
go install github.com/BishopFox/jsluice/cmd/jsluice@latest;ln -fs ~/go/bin/jsluice /usr/bin/jsluice
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest;ln -fs ~/go/bin/mapcidr /usr/bin/mapcidr
go install github.com/eth0izzle/shhgit@latest;ln -fs ~/go/bin/shhgit /usr/bin/shhgit
go install github.com/KathanP19/Gxss@latest;ln -fs ~/go/bin/Gxss /usr/bin/gxss
go install github.com/bountysecurity/gbounty/cmd/gbounty@latest;ln -fs ~/go/bin/gbounty /usr/bin/gbounty
go install github.com/003random/getJS@latest;ln -fs ~/go/bin/getJS /usr/bin/getjs
go install github.com/jaeles-project/gospider@latest;ln -fs ~/go/bin/gospider /usr/bin/gospider
go install github.com/trickest/mksub@latest;ln -fs ~/go/bin/mksub /usr/bin/mksub
go install github.com/nullt3r/udpx/cmd/udpx@latest;ln -fs ~/go/bin/udpx /usr/bin/udpx
go install github.com/PentestPad/subzy@latest;ln -fs ~/go/bin/subzy /usr/bin/subzy
go install github.com/trickest/dsieve@latest;ln -fs ~/go/bin/dsieve /usr/bin/dsieve
go install github.com/gwen001/github-subdomains@latest;ln -fs ~/go/bin/github-subdomains /usr/bin/github-subdomains
go install github.com/d3mondev/puredns/v2@latest;ln -fs ~/go/bin/puredns /usr/bin/puredns
go install github.com/nytr0gen/deduplicate@latest;ln -fs ~/go/bin/deduplicate /usr/bin/deduplicate
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest;ln -fs ~/go/bin/cvemap /usr/bin/cvemap
go install github.com/tomnomnom/gf@latest;ln -fs ~/go/bin/gf /usr/bin/gf
go install github.com/tomnomnom/gron@latest;ln -fs ~/go/bin/gron /usr/bin/gron
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest;ln -fs ~/go/bin/chaos /usr/bin/chaos
go install github.com/Hackmanit/TInjA@latest;ln -fs ~/go/bin/TInjA /usr/bin/tinja
go install github.com/moopinger/smugglefuzz@latest;ln -fs ~/go/bin/smugglefuzz /usr/bin/smugglefuzz
go install github.com/harleo/asnip@latest;ln -fs ~/go/bin/asnip /usr/bin/asnip
go install github.com/hideckies/fuzzagotchi@latest;ln -fs ~/go/bin/fuzzagotchi /usr/bin/fuzzagotchi
go install github.com/projectdiscovery/alterx/cmd/alterx@latest;ln -fs ~/go/bin/alterx /usr/bin/alterx
go install github.com/hideckies/aut0rec0n@latest;ln -fs ~/go/bin/aut0rec0n /usr/bin/aut0rec0n
go install github.com/hahwul/jwt-hack@latest;ln -fs ~/go/bin/jwt-hack /usr/bin/jwt-hack
go install github.com/hakluke/haktrails@latest;ln -fs ~/go/bin/haktrails /usr/bin/haktrails
go install github.com/securebinary/firebaseExploiter@latest;ln -fs ~/go/bin/firebaseExploiter /usr/bin/firebaseexploiter
go install github.com/devanshbatham/headerpwn@latest;ln -fs ~/go/bin/headerpwn /usr/bin/headerpwn
go install github.com/dwisiswant0/cf-check@latest;ln -fs ~/go/bin/cf-check /usr/bin/cfcheck
go install github.com/mlcsec/headi@latest;ln -fs ~/go/bin/headi /usr/bin/headi
go install github.com/takshal/freq@latest;ln -fs ~/go/bin/freq /usr/bin/freq
go install github.com/hakluke/hakrevdns@latest;ln -fs ~/go/bin/hakrevdns /usr/bin/hakrevdns
go install github.com/hakluke/haktldextract@latest;ln -fs ~/go/bin/haktldextract /usr/bin/haktldextract
go install github.com/Emoe/@latest;ln -fs ~/go/bin/kxss /usr/bin/kxss
go install github.com/Josue87/gotator@latest;ln -fs ~/go/bin/gotator /usr/bin/gotator
go install github.com/trap-bytes/gourlex@latest;ln -fs ~/go/bin/gourlex /usr/bin/gourlex
go install github.com/musana/fuzzuli@latest;ln -fs ~/go/bin/fuzzuli /usr/bin/fuzzuli
go install github.com/jaeles-project/jaeles@latest;ln -fs ~/go/bin/jaeles /usr/bin/jaeles
go install github.com/hakluke/haklistgen@latest;ln -fs ~/go/bin/haklistgen /usr/bin/haklistgen
go install github.com/tomnomnom/qsreplace@latest;ln -fs ~/go/bin/qsreplace /usr/bin/qsreplace
go install github.com/edoardottt/pphack/cmd/pphack@latest;ln -fs ~/go/bin/pphack /usr/bin/pphack
go install github.com/lc/subjs@latest;ln -fs ~/go/bin/subjs /usr/bin/subjs
go install github.com/dwisiswant0/unew@latest;ln -fs ~/go/bin/unew /usr/bin/unew
go install github.com/edoardottt/favirecon/cmd/favirecon@latest;ln -fs ~/go/bin/favirecon /usr/bin/favirecon
go install github.com/tomnomnom/unfurl@latest;ln -fs ~/go/bin/unfurl /usr/bin/unfurl
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest;ln -fs ~/go/bin/shuffledns /usr/bin/shuffledns
go install github.com/projectdiscovery/notify/cmd/notify@latest;ln -fs ~/go/bin/notify /usr/bin/notify
go install github.com/detectify/page-fetch@latest;ln -fs ~/go/bin/page-fetch /usr/bin/pagefetch
go install github.com/dwisiswant0/ipfuscator@latest;ln -fs ~/go/bin/ipfuscator /usr/bin/ipfuscator
go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest;ln -fs ~/go/bin/urlfinder /usr/bin/urlfinder
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest;ln -fs ~/go/bin/tlsx /usr/bin/tlsx
go install github.com/projectdiscovery/useragent/cmd/ua@latest;ln -fs ~/go/bin/ua /usr/bin/ua
go install github.com/projectdiscovery/httpx/cmd/httpx@latest;ln -fs ~/go/bin/httpx /usr/bin/httpx
go install github.com/mirzaaghazadeh/jsdif@latest;ln -fs ~/go/bin/jsdif /usr/bin/jsdif
go install github.com/bitquark/shortscan/cmd/shortscan@latest;ln -fs ~/go/bin/shortscan /usr/bin/shortscan
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest;ln -fs ~/go/bin/naabu /usr/bin/naabu
go install github.com/sensepost/gowitness@latest;ln -fs ~/go/bin/gowitness /usr/bin/gowitness
go install github.com/lc/gau/v2/cmd/gau@latest;ln -fs ~/go/bin/gau /usr/bin/gau
go install github.com/akshaysharma016/aem-detector@latest;ln -fs ~/go/bin/aem-detector /usr/bin/aem-detector
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest;ln -fs ~/go/bin/mapcidr /usr/bin/mapcidr"
	go_installer "Web" "Penetration-Testing" "$web_golang"

	# install cloudbunny
	if [ ! -d "/usr/share/cloudbunny" ]; then
		name="cloudbunny"
		git clone https://github.com/Warflop/CloudBunny /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cloudbunny.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install ghauri
	if [ ! -d "/usr/share/ghauri" ]; then
		name="ghauri"
		git clone https://github.com/r0oth3x49/ghauri /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cd /usr/share/$name;python3 setup.py install
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install phoneinfoga
	if [ ! -d "/usr/share/phoneinfoga" ]; then
		name="phoneinfoga"
		mkdir -p /usr/share/$name
		wget https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/phoneinfoga /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install postman
	if [ ! -d "/usr/share/Postman" ]; then
		name="Postman"
		mkdir -p /usr/share/$name
		wget https://dl.pstmn.io/download/latest/linux_64 -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/app/*
		ln -fs /usr/share/$name/app/$name /usr/bin/postman
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bkcrack
	if [ ! -d "/usr/share/bkcrack" ]; then
		name="bkcrack"
		mkdir -p /usr/share/$name
		wget https://github.com/kimci86/bkcrack/releases/download/v1.7.0/bkcrack-1.7.0-Linux.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/bkcrack /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install spiderfoot
	if [ ! -d "/usr/share/spiderfoot" ]; then
		name="spiderfoot"
		git clone https://github.com/smicallef/spiderfoot /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 ./sf.py -l 127.0.0.1:5001 "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install custombsqli
	if [ ! -d "/usr/share/custombsqli" ]; then
		name="custombsqli"
		git clone https://github.com/coffinxp/customBsqli /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 lostsec.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

  	# install oty
	if [ ! -f "/usr/bin/oty" ]; then
		name="oty"
		pip3 install git+https://github.com/1hehaq/oty
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install wpxstrike
	if [ ! -d "/usr/share/wpxstrike" ]; then
		name="wpxstrike"
		git clone https://github.com/nowak0x01/WPXStrike /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./WPXStrike.js "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install corstest
	if [ ! -d "/usr/share/corstest" ]; then
		name="corstest"
		git clone https://github.com/RUB-NDS/CORStest /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 corstest.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install loxs
	if [ ! -d "/usr/share/loxs" ]; then
		name="loxs"
		git clone https://github.com/coffinxp/loxs /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 loxs.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install assets-from-spf
	if [ ! -d "/usr/share/assets-from-spf" ]; then
		name="assets-from-spf"
		git clone https://github.com/0xbharath/assets-from-spf /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install ipwhois click
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 assets_from_spf.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install kubo
	if [ ! -d "/usr/share/kubo" ]; then
		name="kubo"
		mkdir -p /usr/share/$name
		wget https://github.com/ipfs/kubo/releases/download/v0.32.1/kubo_v0.32.1_linux-amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install.sh;ipfs init
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install crackql
	if [ ! -d "/usr/share/crackql" ]; then
		name="crackql"
		git clone https://github.com/nicholasaleks/CrackQL /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 CrackQL.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

  	# install fuxploider
	if [ ! -d "/usr/share/fuxploider" ]; then
		name="fuxploider"
		git clone https://github.com/almandin/fuxploider /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 fuxploider.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

  	# install crossdomain-exploitation-framework
	if [ ! -d "/usr/share/crossdomain-exploitation-framework" ]; then
		name="crossdomain-exploitation-framework"
		git clone https://github.com/sethsec/crossdomain-exploitation-framework /usr/share/$name
		chmod 755 /usr/share/$name/*;chmod 755 /usr/share/$name/actionscript-templates/*
		cd /usr/share/$name;python2 SWF-server
		cat > /usr/bin/swf-server << EOF
#!/bin/bash
cd /usr/share/$name;python2 SWF-server "\$@"
EOF
		chmod +x /usr/bin/swf-server
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install x8
	if [ ! -d "/usr/share/x8" ]; then
		name="x8"
		mkdir -p /usr/share/x8
		wget https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8.gz -O /tmp/$name.gz
		gzip -d /tmp/$name.gz -d /usr/share/$name;mv /tmp/$name /usr/share/$name;rm -f /tmp/$name.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/x8 /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install urldedupe
	if [ ! -d "/usr/share/urldedupe" ]; then
		name="urldedupe"
		git clone https://github.com/ameenmaali/urldedupe /usr/share/$name
		chmod 755 /usr/share/$name/*
  		cd /usr/share/$name;cmake CMakeLists.txt;make
		ln -fs /usr/share/$name/urldedupe /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install snmp-shell
	if [ ! -d "/usr/share/snmp-shell" ]; then
		name="snmp-shell"
		git clone https://github.com/mxrch/snmp-shell /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 shell.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install graphql-playground
	if [ ! -d "/usr/share/graphql-playground" ]; then
		name="graphql-playground"
		wget https://github.com/graphql/graphql-playground/releases/download/v1.8.10/graphql-playground-electron_1.8.10_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install findomain
	if [ ! -d "/usr/share/findomain" ]; then
		name="findomain"
		wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/findomain /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install aquatone
	if [ ! -d "/usr/share/aquatone" ]; then
		name="aquatone"
		wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/aquatone /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install blacklist3r
	if [ ! -d "/usr/share/blacklist3r" ]; then
		name="blacklist3r"
		mkdir /usr/share/$name
		wget https://github.com/NotSoSecure/Blacklist3r/releases/download/4.0/AspDotNetWrapper.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;mono AspDotNetWrapper.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install wafw00f
	if [ ! -d "/usr/share/wafw00f" ]; then
		name="wafw00f"
		git clone https://github.com/EnableSecurity/wafw00f /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;python3 setup.py install
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install graphpython
	if [ ! -d "/usr/share/graphpython" ]; then
		name="graphpython"
		git clone https://github.com/mlcsec/Graphpython /usr/share/$name 
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;pip install .
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 Graphpython.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bypassneo-regeorg
	if [ ! -d "/usr/share/bypassneo-regeorg" ]; then
		name="bypassneo-regeorg"
		git clone https://github.com/r00tSe7en/BypassNeo-reGeorg /usr/share/$name 
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 BypassNeoASPX.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install rustscan
	if [ ! -f "/usr/bin/rustscan" ]; then
		name="rustscan"
		wget https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install ronin
	if [ ! -f "/usr/bin/ronin" ]; then
		name="ronin"
		curl -o ronin-install.sh https://raw.githubusercontent.com/ronin-rb/scripts/main/ronin-install.sh && bash ronin-install.sh
		rm -f ronin
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install hashpump
	if [ ! -d "/usr/share/hashpump" ]; then
		name="hashpump"
		git clone https://github.com/mheistermann/HashPump-partialhash /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name
		make;make install
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pixload
	if [ ! -d "/usr/share/pixload" ]; then
		name="pixload"
		git clone https://github.com/sighook/pixload /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name
		make install
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name-bmp --help'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install googlerecaptchabypass
	if [ ! -d "/usr/share/grb" ]; then
		name="grb"
		git clone https://github.com/sarperavci/GoogleRecaptchaBypass /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 test.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install webcopilot
	if [ ! -d "/usr/share/webcopilot" ]; then
		name="webcopilot"
		git clone https://github.com/h4r5h1t/webcopilot /usr/share/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/webcopilot /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install graphw00f
	if [ ! -d "/usr/share/graphw00f" ]; then
		name="graphw00f"
		git clone https://github.com/dolevf/graphw00f /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install gel4y
	if [ ! -d "/usr/share/gel4y" ]; then
		name="gel4y"
		git clone https://github.com/22XploiterCrew-Team/Gel4y-Mini-Shell-Backdoor /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;php gel4y.php "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloakquest3r
	if [ ! -d "/usr/share/cloakquest3r" ]; then
		name="cloakquest3r"
		git clone https://github.com/spyboy-productions/CloakQuest3r /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cloakquest3r.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install singularity
	if [ ! -d "/usr/share/singularity" ]; then
		name="singularity"
		git clone https://github.com/nccgroup/singularity /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name/cmd/singularity-server
		go build
		mkdir -p /usr/share/$name/singularity/html
		cp singularity-server /usr/share/$name/singularity
		cp -r ../../html/* /usr/share/$name/html
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/singularity;sudo ./singularity-server --HTTPServerPort 8080 "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install proxyshell
	if [ ! -d "/usr/share/proxyshell" ]; then
		name="proxyshell"
		git clone https://github.com/horizon3ai/proxyshell /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 exchange_proxyshell.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install asnlookup
	if [ ! -d "/usr/share/asnlookup" ]; then
		name="asnlookup"
		git clone https://github.com/yassineaboukir/Asnlookup /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 asnlookup.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install drupwn
	if [ ! -d "/usr/share/drupwn" ]; then
		name="drupwn"
		git clone https://github.com/immunIT/drupwn /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		python3 /usr/share/$name/setup.py install
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install aspjinjaobfuscator
	if [ ! -d "/usr/share/aspjinjaobfuscator" ]; then
		name="aspjinjaobfuscator"
		git clone https://github.com/fin3ss3g0d/ASPJinjaObfuscator /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 asp-jinja-obfuscator.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install waymore
	if [ ! -d "/usr/share/waymore" ]; then
		name="waymore"
		git clone https://github.com/xnl-h4ck3r/waymore /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 waymore.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install linkfinder
	if [ ! -d "/usr/share/linkfinder" ]; then
		name="linkfinder"
		git clone https://github.com/GerbenJavado/LinkFinder /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 linkfinder.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ysoserial
	if [ ! -d "/usr/share/ysoserial" ]; then
		name="ysoserial"
		mkdir -p /usr/share/$name
		wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -O /usr/share/$name/ysoserial-all.jar 
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;java -jar ysoserial-all.jar "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ysoserial.net
	if [ ! -d "/usr/share/ysoserial.net" ]; then
		name="ysoserial.net"
		mkdir -p /usr/share/$name
		wget https://github.com/pwntester/ysoserial.net/releases/latest/download/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share;mv -f /usr/share/Release /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;mono ysoserial.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install akto
	if [ ! -d "/usr/share/akto" ]; then
		name="akto"
		git clone https://github.com/akto-api-security/akto /usr/share/$name 
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;docker-compose up -d "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install rsatool
	if [ ! -d "/usr/share/rsatool" ]; then
		name="rsatool"
		git clone https://github.com/ius/rsatool /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 rsatool.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install polyglot
	if [ ! -d "/usr/share/polyglot" ]; then
		name="polyglot"
		git clone https://github.com/Polydet/polyglot-database /usr/share/$name
		chmod 755 /usr/share/$name/files/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/files;ls "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install rsactftool
	if [ ! -d "/usr/share/rsactftool" ]; then
		name="rsactftool"
		git clone https://github.com/RsaCtfTool/RsaCtfTool /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 RsaCtfTool.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install graphqlmap
	if [ ! -d "/usr/share/graphqlmap" ]; then
		name="graphqlmap"
		git clone https://github.com/swisskyrepo/GraphQLmap /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		python3 /usr/share/$name/setup.py install
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install dtdfinder
	if [ ! -d "/usr/share/dtdfinder" ]; then
		name="dtdfinder"
		mkdir -p /usr/share/$name
		wget https://github.com/GoSecure/dtd-finder/releases/latest/download/dtd-finder-1.1-all.jar -O /usr/share/$name/dtd-finder-all.jar
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;java -jar dtd-finder-all.jar "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install docem
	if [ ! -d "/usr/share/docem" ]; then
		name="docem"
		git clone https://github.com/whitel1st/docem /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 docem.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install spidersuite
	if [ ! -d "/usr/share/spidersuite" ]; then
		name="spidersuite"
		mkdir -p /usr/share/$name
		wget https://github.com/3nock/SpiderSuite/releases/download/v1.0.4/SpiderSuite_v1.0.4_linux.AppImage -O /usr/share/$name/SpiderSuite_linux.AppImage
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./SpiderSuite_linux.AppImage "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install jsa
	if [ ! -d "/usr/share/jsa" ]; then
		name="jsa"
		git clone https://github.com/w9w/JSA /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cd /usr/share/$name;bash install.sh
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 jsa.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install smuggle
	if [ ! -d "/usr/share/smuggle" ]; then
		name="smuggle"
		git clone https://github.com/anshumanpattnaik/http-request-smuggling /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 smuggle.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pemcrack
	if [ ! -d "/usr/share/pemcrack" ]; then
		name="pemcrack"
		git clone https://github.com/robertdavidgraham/pemcrack /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;gcc pemcrack.c -o pemcrack -lssl -lcrypto
		ln -fs /usr/share/$name/pemcrack /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sessionprobe
	if [ ! -d "/usr/share/sessionprobe" ]; then
		name="sessionprobe"
		mkdir -p /usr/share/$name
		wget https://github.com/dub-flow/sessionprobe/releases/latest/download/sessionprobe-linux-amd64 -O /usr/share/$name/sessionprobe
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/sessionprobe /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install dymerge
	if [ ! -d "/usr/share/dymerge" ]; then
		name="dymerge"
		git clone https://github.com/k4m4/dymerge /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 dymerge.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install spartan
	if [ ! -d "/usr/share/spartan" ]; then
		name="spartan"
		git clone https://github.com/sensepost/SPartan /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install -r /usr/share/$name/requirements.txt
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 SPartan.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install waf-bypass
	if [ ! -d "/usr/share/waf-bypass" ]; then
		name="waf-bypass"
		git clone https://github.com/nemesida-waf/waf-bypass /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		python3 /usr/share/$name/setup.py install
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install xssloader
	if [ ! -d "/usr/share/xssloader" ]; then
		name="xssloader"
		git clone https://github.com/capture0x/XSS-LOADER /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 payloader.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cmseek
	if [ ! -d "/usr/share/cmseek" ]; then
		name="cmseek"
		git clone https://github.com/Tuhinshubhra/CMSeeK /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cmseek.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install xsstrike
	if [ ! -d "/usr/share/xsstrike" ]; then
		name="xsstrike"
		git clone https://github.com/s0md3v/XSStrike /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 xsstrike.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install w4af
	if [ ! -d "/usr/share/w4af" ]; then
		name="w4af"
		git clone https://github.com/w4af/w4af /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;pipenv install;npm install
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;pipenv shell;./w4af_console "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install jwt_tool
	if [ ! -d "/usr/share/jwt_tool" ]; then
		name="jwt_tool"
		git clone https://github.com/ticarpi/jwt_tool /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 jwt_tool.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install tplmap
	if [ ! -d "/usr/share/tplmap" ]; then
		name="tplmap"
		git clone https://github.com/epinna/tplmap /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 tplmap.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sstimap
	if [ ! -d "/usr/share/sstimap" ]; then
		name="sstimap"
		git clone https://github.com/vladko312/SSTImap /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 sstimap.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install poodle
	if [ ! -d "/usr/share/poodle" ]; then
		name="poodle"
		git clone https://github.com/mpgn/poodle-PoC /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 poodle-exploit.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install gopherus
	if [ ! -d "/usr/share/gopherus" ]; then
		name="gopherus"
		git clone https://github.com/tarunkant/Gopherus /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 gopherus.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install hash_extender
	if [ ! -d "/usr/share/hash_extender" ]; then
		name="hash_extender"
		git clone https://github.com/iagox86/hash_extender /usr/share/$name
		chmod 755 /usr/share/$name/*
		sed -i "s|-Werror -Wno-deprecated||g" /usr/share/$name/Makefile
		cd /usr/share/$name;make
		ln -fs /usr/share/$name/hash_extender /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install redhawk
	if [ ! -d "/usr/share/redhawk" ]; then
		name="redhawk"
		git clone https://github.com/Tuhinshubhra/RED_HAWK /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;php rhawk.php "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install iis-shortname-scanner
	if [ ! -d "/usr/share/iis-shortname-scanner" ]; then
		name="iis-shortname-scanner"
		git clone https://github.com/irsdl/IIS-ShortName-Scanner /usr/share/$name
		chmod 755 /usr/share/$name/release/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/release;java -jar iis_shortname_scanner.jar "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ngrok
	if [ ! -f "/usr/local/bin/ngrok" ]; then
		name="ngrok"
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/$name.tgz
		tar -xvzf /tmp/$name.tgz -C /usr/local/bin;rm -f /tmp/$name.tgz
		chmod +x /usr/local/bin/ngrok
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install noip2
	if [ ! -f "/usr/local/bin/noip2" ]; then
		name="noip"
		mkdir -p /usr/share/$name
		wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xzf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;make;make install
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install breacher
	if [ ! -d "/usr/share/breacher" ]; then
		name="breacher"
		git clone https://github.com/s0md3v/Breacher /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 breacher.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install swftools
	if [ ! -d "/usr/share/swftools" ]; then
		name="swftools"
  		wget http://mirrors.kernel.org/ubuntu/pool/main/libj/libjpeg-turbo/libjpeg-turbo8_2.1.2-0ubuntu1_amd64.deb -O /tmp/libjpeg-turbo8.deb
    		chmod +x /tmp/libjpeg-turbo8.deb;dpkg -i /tmp/libjpeg-turbo8.deb;rm -r /tmp/libjpeg-turbo8.deb
		wget http://mirrors.kernel.org/ubuntu/pool/main/libj/libjpeg8-empty/libjpeg8_8c-2ubuntu11_amd64.deb -O /tmp/libjpeg8.deb
		chmod +x /tmp/libjpeg8.deb;dpkg -i /tmp/libjpeg8.deb;rm -r /tmp/libjpeg8.deb
  		wget https://archive.debian.org/debian/pool/main/m/mtasc/mtasc_1.14-3_amd64.deb -O /tmp/mtasc.deb
    		chmod +x /tmp/mtasc.deb;dpkg -i /tmp/mtasc.deb;rm -r /tmp/mtasc.deb
		wget https://launchpad.net/ubuntu/+archive/primary/+files/swftools_0.9.2+git20130725-4.1_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -r /tmp/$name.deb
		menu_entry "Web" "Penetration-Testing" "mtasc" "$exec_shell 'mtasc -h'"
		menu_entry "Web" "Penetration-Testing" "swfdump" "$exec_shell 'swfdump -h'"
		menu_entry "Web" "Penetration-Testing" "swfcombine" "$exec_shell 'swfcombine -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install flex-sdk
	if [ ! -d "/opt/flex-sdk" ]; then
		name="flex-sdk"
  		wget http://download.macromedia.com/pub/flex/sdk/flex_sdk_4.6.zip -O /tmp/$name.zip
    		unzip /tmp/$name.zip -d /opt/$name;rm -f /tmp/$name.zip
		echo "export PATH=\$PATH:/opt/$name/bin" >> ~/.bashrc;source ~/.bashrc
		menu_entry "Web" "Penetration-Testing" "mxmlc" "$exec_shell 'mxmlc -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install nosqlmap
	if [ ! -d "/usr/share/nosqlmap" ]; then
		name="nosqlmap"
		git clone https://github.com/codingo/NoSQLMap /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;python2 nosqlmap.py install
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 nosqlmap.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ------------------------------------Mobile-Penetration-Testing------------------------------------- #"

	# install Repository Tools
	apt install -qy jd-gui adb apksigner apktool android-tools-adb jadx 

	# install Python3 pip
	mobile_pip="frida-tools objection mitmproxy reflutter androguard apkleaks mvt kiwi androset quark-engine drozer gplaycli"
	pip_installer "Mobile" "Penetration-Testing" "$mobile_pip"

	# install Nodejs NPM
	mobile_npm="rms-runtime-mobile-security apk-mitm igf bagbak applesign"
	npm_installer "Mobile" "Penetration-Testing" "$mobile_npm"

	# install Ruby GEM
	mobile_gem="jwt-cracker"
	gem_installer "Mobile" "Penetration-Testing" "$mobile_gem"

	# install Golang
	mobile_golang="
go install github.com/ndelphit/apkurlgrep@latest;ln -fs ~/go/bin/apkurlgrep /usr/bin/apkurlgrep"
	go_installer "Mobile" "Penetration-Testing" "$mobile_golang"

	# install genymotion
	if [ ! -d "/opt/genymobile/genymotion" ]; then
		name="genymotion"
		wget https://dl.genymotion.com/releases/genymotion-3.6.0/genymotion-3.6.0-linux_x64.bin -O /tmp/$name.bin
		chmod 755 /tmp/$name.bin;cd /tmp;./$name.bin -y;rm -f /tmp/$name.bin
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install palera1n
	if [ ! -f "/usr/bin/palera1n" ]; then
		name="palera1n"
		wget https://github.com/palera1n/palera1n/releases/latest/download/palera1n_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Mobile" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ideviceinstaller
	if [ ! -f "/usr/share/ideviceinstaller" ]; then
		name="ideviceinstaller"
		git clone https://github.com/libimobiledevice/ideviceinstaller /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./autogen.sh;make;make install
		ln -fs /usr/share/$name/ideviceinstaller /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Mobile" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install ipsw
	if [ ! -f "/usr/share/ipsw" ]; then
		name="ipsw"
		wget https://github.com/blacktop/ipsw/releases/download/v3.1.569/ipsw_3.1.569_linux_x86_64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Mobile" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install mobsf
	if [ ! -d "/usr/share/mobsf" ]; then
		name="mobsf"
		git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /usr/share/$name
		wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb -O /tmp/wkhtmltox.deb
		chmod +x /tmp/wkhtmltox.deb;dpkg -i /tmp/wkhtmltox.deb;rm -f /tmp/wkhtmltox.deb
		chmod 755 /usr/share/$name/*
		pip3 install django --break-system-packages
		cd /usr/share/$name;./setup.sh
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./run.sh > /dev/null &
sleep 5;firefox --new-tab "http://127.0.0.1:8000" > /dev/null &
EOF
		chmod +x /usr/bin/$name
		menu_entry "Mobile" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ------------------------------------Cloud-Penetration-Testing-------------------------------------- #"

	# install Repository Tools
	apt install -qy awscli trivy s3scanner gsutil cloudbrute 

	# install Python3 pip
	cloud_pip="sceptre aclpwn cloudshovel cloudshovel powerpwn ggshield pacu whispers  kube-hunter roadrecon roadlib gcp_scanner roadtx festin cloudsplaining c7n trailscraper lambdaguard airiam access-undenied-aws n0s1 aws-gate cloudscraper acltoolkit-ad prowler bloodhound aiodnsbrute gorilla-cli knowsmore checkov scoutsuite endgame timberlake punch-q s3-account-search"
	pip_installer "Cloud" "Penetration-Testing" "$cloud_pip"

	# install Nodejs NPM
	cloud_npm="fleetctl"
	npm_installer "Cloud" "Penetration-Testing" "$cloud_npm"

	# install Ruby GEM
	cloud_gem="aws_public_ips aws_security_viz aws_recon"
	gem_installer "Cloud" "Penetration-Testing" "$cloud_gem"

	# install Golang
	cloud_golang="
go install github.com/koenrh/s3enum@latest;ln -fs ~/go/bin/s3enum /usr/bin/s3enum
go install github.com/smiegles/mass3@latest;ln -fs ~/go/bin/mass3 /usr/bin/mass3
go install github.com/mlcsec/clovery@latest;ln -fs ~/go/bin/clovery /usr/bin/clovery
go install github.com/magisterquis/s3finder@latest;ln -fs ~/go/bin/s3finder /usr/bin/s3finder
go install github.com/Macmod/goblob@latest;ln -fs ~/go/bin/goblob /usr/bin/goblob
go install github.com/g0ldencybersec/CloudRecon@latest;ln -fs ~/go/bin/CloudRecon /usr/bin/cloudrecon
go install github.com/BishopFox/cloudfox@latest;ln -fs ~/go/bin/cloudfox /usr/bin/cloudfox
go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest;ln -fs ~/go/bin/cloudlist /usr/bin/cloudlist
go install github.com/Rolix44/Kubestroyer@latest;ln -fs ~/go/bin/Kubestroyer /usr/bin/Kubestroyer"
	go_installer "Cloud" "Penetration-Testing" "$cloud_golang"

	# install cloudfail
	if [ ! -d "/usr/share/cloudfail" ]; then
		name="cloudfail"
		git clone https://github.com/m0rtem/CloudFail /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cloudfail.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloudsploit
	if [ ! -d "/usr/share/cloudsploit" ]; then
		name="cloudsploit"
		git clone https://github.com/aquasecurity/cloudsploit /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;npm install
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;npm index.js "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install cloud_enum
	if [ ! -d "/usr/share/cloud_enum" ]; then
		name="cloud_enum"
		git clone https://github.com/initstring/cloud_enum /usr/share/$name
		chmod 755 /usr/share/$name/*
  		pip3 install -r /usr/share/$name/requirements.txt
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cloud_enum.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ccat
	if [ ! -d "/usr/share/ccat" ]; then
		name="ccat"
		git clone https://github.com/RhinoSecurityLabs/ccat /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;python3 setup.py install
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 ccat.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install microburst
	if [ ! -d "/usr/share/microburst" ]; then
		name="microburst"
		git clone https://github.com/NetSPI/MicroBurst /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;pwsh -c "Import-Module ./MicroBurst.psm1; Get-AzureDomainInfo" "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloudmapper
	if [ ! -d "/usr/share/cloudmapper" ]; then
		name="cloudmapper"
		git clone https://github.com/duo-labs/cloudmapper /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cloudmapper.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloud-service-enum
	if [ ! -d "/usr/share/cloud-service-enum" ]; then
		name="cloud-service-enum"
		git clone https://github.com/NotSoSecure/cloud-service-enum /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/aws_service_enum/requirements.txt
		cat > /usr/bin/aws_service_enum << EOF
#!/bin/bash
cd /usr/share/$name/aws_service_enum;python3 aws_enum_services.py "\$@"
EOF
		chmod +x /usr/bin/aws_service_enum
		menu_entry "Cloud" "Penetration-Testing" "aws_service_enum" "$exec_shell 'aws_service_enum -h'"
		pip3 install -r /usr/share/$name/azure_service_enum/requirements.txt
		cat > /usr/bin/azure_service_enum << EOF
#!/bin/bash
cd /usr/share/$name/azure_service_enum;python3 azure_enum_services.py "\$@"
EOF
		chmod +x /usr/bin/azure_service_enum
		menu_entry "Cloud" "Penetration-Testing" "azure_enum_services" "$exec_shell 'azure_enum_services -h'"
		pip3 install -r /usr/share/$name/gcp_service_enum/requirements.txt
		cat > /usr/bin/gcp_service_enum << EOF
#!/bin/bash
cd /usr/share/$name/gcp_enum_services;python3 gcp_enum_services.py "\$@"
EOF
		chmod +x /usr/bin/gcp_service_enum
		menu_entry "Cloud" "Penetration-Testing" "gcp_enum_services" "$exec_shell 'gcp_enum_services -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install rclone
	if [ ! -f "/usr/bin/rclone" ]; then
		name="rclone"
		wget https://downloads.rclone.org/v1.68.2/rclone-v1.68.2-linux-amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ioxy
	if [ ! -d "/usr/share/ioxy" ]; then
		name="ioxy"
		git clone https://github.com/NVISOsecurity/IOXY /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;CGO_CFLAGS="-g -O2 -Wno-return-local-addr" go build -ldflags="-s -w" .
		ln -fs /usr/share/$name/ioxy /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloudhunter
	if [ ! -d "/usr/share/cloudhunter" ]; then
		name="cloudhunter"
		git clone https://github.com/belane/CloudHunter /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cloudhunter.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install gcpbucketbrute
	if [ ! -d "/usr/share/gcpbucketbrute" ]; then
		name="gcpbucketbrute"
		git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 gcpbucketbrute.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install purplepanda
	if [ ! -d "/usr/share/purplepanda" ]; then
		name="purplepanda"
		git clone https://github.com/carlospolop/PurplePanda /usr/share/$name
		chmod 755 /usr/share/$name/*
		export PURPLEPANDA_NEO4J_URL="bolt://neo4j@localhost:7687"
		export PURPLEPANDA_PWD="s3cr3tpassword"
		pip3 install -r /usr/share/$name/requirements.txt
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install k8sgpt
	if [ ! -d "/usr/share/k8sgpt" ]; then
		name="k8sgpt"
		wget https://github.com/k8sgpt-ai/k8sgpt/releases/latest/download/k8sgpt_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bucketloot
	if [ ! -d "/usr/share/bucketloot" ]; then
		name="bucketloot"
		mkdir -p /usr/share/$name
		wget https://github.com/redhuntlabs/BucketLoot/releases/latest/download/bucketloot-amd64 -O /usr/share/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/$name /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloudquery
	if [ ! -d "/usr/share/cloudquery" ]; then
		name="cloudquery"
		mkdir -p /usr/share/$name
		wget https://github.com/cloudquery/cloudquery/releases/latest/download/cloudquery_linux_amd64 -O /usr/share/$name/cloudquery
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/cloudquery /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Cloud" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------------Network-Penetration-Testing------------------------------------- #"

	# install Repository Tools
	apt install -qy cme amap bettercap dsniff arpwatch python3-pwntools netexec sslstrip sherlock parsero routersploit slowhttptest dnsmasq sshuttle haproxy smb4k pptpd xplico dosbox lldb zmap checksec kerberoast etherape ismtp ismtp privoxy ident-user-enum goldeneye oclgausscrack multiforcer crowbar brutespray isr-evilgrade smtp-user-enum pigz gdb isc-dhcp-server firewalk bing-ip2hosts sipvicious netstress tcptrack tnscmd10g darkstat naabu cyberchef nbtscan sslscan wireguard nasm ropper above libmemcached-tools 

	# install Python3 pip
	network_pip="networkx ropper mitmproxy mikrot8over mitm6 pymultitor scapy smbclientng slowloris brute raccoon-scanner baboossh ciphey zeratool impacket aiodnsbrute ssh-mitm ivre angr angrop boofuzz ropgadget pwntools capstone atheris iac-scan-runner"
	pip_installer "Network" "Penetration-Testing" "$network_pip"

	# install Nodejs NPM
	network_npm="http-proxy-to-socks multitor"
	npm_installer "Network" "Penetration-Testing" "$network_npm"

	# install Ruby GEM
	network_gem="seccomp-tools one_gadget"
	npm_installer "Network" "Penetration-Testing" "$network_gem"

	# install Golang
	network_golang="
go install github.com/s-rah/onionscan@latest;ln -fs ~/go/bin/onionscan /usr/bin/onionscan
go install github.com/Danny-Dasilva/CycleTLS/cycletls@latest;ln -fs ~/go/bin/cycletls /usr/bin/cycletls"
	go_installer "Network" "Penetration-Testing" "$network_golang"

	# install hiddify
	if [ ! -d "/usr/share/hiddify" ]; then
		name="hiddify"
		wget https://github.com/hiddify/hiddify-next/releases/latest/download/Hiddify-Debian-x64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
  		echo "root ALL=(ALL:ALL) NOPASSWD: /usr/share/hiddify/hiddify" >> /etc/sudoers
  		echo "root ALL=(ALL:ALL) NOPASSWD: /usr/share/hiddify/Hiddify-Cli" >> /etc/sudoers
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install snmpbrute
	if [ ! -d "/usr/share/snmpbrute" ]; then
		name="snmpbrute"
		git clone https://github.com/SECFORCE/SNMP-Brute /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 snmpbrute.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ivre
	if [ ! -d "/usr/share/ivre" ]; then
		name="ivre"
		git clone https://github.com/ivre/ivre /usr/share/$name
		chmod 755 /usr/share/$name/*
		python3 /usr/share/$name/setup.py install
		pip3 install -r /usr/share/$name/requirements-all.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;python3 ivre.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install mr.sip
	if [ ! -d "/usr/share/mr.sip" ]; then
		name="mr.sip"
		git clone https://github.com/meliht/Mr.SIP /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 mr.sip.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install multitor
	if [ ! -d "/usr/share/multitor" ]; then
		name="multitor"
		git clone https://github.com/trimstray/multitor /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./setup.sh install
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sippts
	if [ ! -d "/usr/share/sippts" ]; then
		name="sippts"
		git clone https://github.com/Pepelux/sippts /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cd /usr/share/$name;python3 setup.py install
		menu_entry "Network" "Penetration-Testing" "rtcpbleed" "$exec_shell 'rtcpbleed -h'"
		menu_entry "Network" "Penetration-Testing" "rtpbleed" "$exec_shell 'rtpbleed -h'"
		menu_entry "Network" "Penetration-Testing" "rtpbleedflood" "$exec_shell 'rtpbleedflood -h'"
		menu_entry "Network" "Penetration-Testing" "rtpbleedinject" "$exec_shell 'rtpbleedinject -h'"
		menu_entry "Network" "Penetration-Testing" "sipdigestcrack" "$exec_shell 'sipdigestcrack -h'"
		menu_entry "Network" "Penetration-Testing" "sipdigestleak" "$exec_shell 'sipdigestleak -h'"
		menu_entry "Network" "Penetration-Testing" "sipenumerate" "$exec_shell 'sipenumerate -h'"
		menu_entry "Network" "Penetration-Testing" "sipexten" "$exec_shell 'sipexten -h'"
		menu_entry "Network" "Penetration-Testing" "sipflood" "$exec_shell 'sipflood -h'"
		menu_entry "Network" "Penetration-Testing" "sipfuzzer" "$exec_shell 'sipfuzzer -h'"
		menu_entry "Network" "Penetration-Testing" "sipinvite" "$exec_shell 'sipinvite -h'"
		menu_entry "Network" "Penetration-Testing" "sippcapdump" "$exec_shell 'sippcapdump -h'"
		menu_entry "Network" "Penetration-Testing" "sipping" "$exec_shell 'sipping -h'"
		menu_entry "Network" "Penetration-Testing" "siprcrack" "$exec_shell 'siprcrack -h'"
		menu_entry "Network" "Penetration-Testing" "sipscan" "$exec_shell 'sipscan -h'"
		menu_entry "Network" "Penetration-Testing" "sipsend" "$exec_shell 'sipsend -h'"
		menu_entry "Network" "Penetration-Testing" "sipsniff" "$exec_shell 'sipsniff -h'"
		menu_entry "Network" "Penetration-Testing" "siptshark" "$exec_shell 'siptshark -h'"
		menu_entry "Network" "Penetration-Testing" "wssend" "$exec_shell 'wssend -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install routerscan
	if [ ! -d "/usr/share/routerscan" ]; then
		name="routerscan"
		mkdir -p /usr/share/$name
		wget http://msk1.stascorp.com/routerscan/prerelease.7z -O /usr/share/$name/prerelease.7z
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;7z x prerelease.7z;rm -f prerelease.7z
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine RouterScan.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pcredz
	if [ ! -d "/usr/share/pcredz" ]; then
		name="pcredz"
		mkdir -p /usr/share/$name
		wget https://github.com/lgandx/PCredz -O /usr/share/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/Pcredz /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pret
	if [ ! -d "/usr/share/pret" ]; then
		name="pret"
		git clone https://github.com/RUB-NDS/PRET /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 pret.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install geneva
	if [ ! -d "/usr/share/geneva" ]; then
		name="geneva"
		git clone https://github.com/Kkevsterrr/geneva /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 engine.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install kraken
	if [ ! -d "/usr/share/kraken" ]; then
		name="kraken"
		git clone https://github.com/jasonxtn/Kraken /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 kraken.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pwndbg
	if [ ! -d "/usr/share/pwndbg" ]; then
		name="pwndbg"
		wget https://github.com/pwndbg/pwndbg/releases/download/2024.08.29/pwndbg_2024.08.29_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ipscan
	if [ ! -f "/usr/bin/ipscan" ]; then
		name="ipscan"
		wget https://github.com/angryip/ipscan/releases/latest/download/ipscan_3.9.1_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install fetch
	if [ ! -d "/usr/share/fetch" ]; then
		name="fetch"
		git clone https://github.com/stamparm/fetch-some-proxies /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 fetch.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sietpy3
	if [ ! -d "/usr/share/sietpy3" ]; then
		name="sietpy3"
		git clone https://github.com/Sab0tag3d/SIETpy3 /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 siet.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install memcrashed
	if [ ! -d "/usr/share/memcrashed" ]; then
		name="memcrashed"
		git clone https://github.com/649/Memcrashed-DDoS-Exploit /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 Memcrashed.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install spoofdpi
	if [ ! -d "/usr/share/spoofdpi" ]; then
		name="spoofdpi"
		mkdir -p /usr/share/$name
		wget https://github.com/xvzc/SpoofDPI/releases/latest/download/spoof-dpi-linux-amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/spoof-dpi /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Network" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------------Wireless-Penetration-Testing------------------------------------ #"

	# install Repository Tools
	apt install -qy airgeddon crackle kalibrate-rtl eaphammer rtlsdr-scanner wifiphisher airgraph-ng multimon-ng gr-gsm ridenum airspy gqrx-sdr btscanner bluesnarfer ubertooth blueranger wifipumpkin3 spooftooph pskracker 

	# install Python3 pip
	wireless_pip="btlejack scapy wpspin"
	pip_installer "Wireless" "Penetration-Testing" "$wireless_pip"

	# install Nodejs NPM
	wireless_npm="btlejuice"
	npm_installer "Wireless" "Penetration-Testing" "$wireless_npm"

	# install Ruby GEM
	# wireless_gem=""
	gem_installer "Wireless" "Penetration-Testing" "$wireless_gem"

	# install Golang
	# wireless_golang=""
	go_installer "Wireless" "Penetration-Testing" "$wireless_golang"

	# install gtscan
	if [ ! -d "/usr/share/gtscan" ]; then
		name="gtscan"
		git clone https://github.com/SigPloiter/GTScan /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 GTScan.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Wireless" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install hlr-lookups
	if [ ! -d "/usr/share/hlr-lookups" ]; then
		name="hlr-lookups"
		git clone https://github.com/SigPloiter/HLR-Lookups /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 hlr-lookups.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Wireless" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install geowifi
	if [ ! -d "/usr/share/geowifi" ]; then
		name="geowifi"
		git clone https://github.com/GONZOsint/geowifi /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 geowifi.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Wireless" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# --------------------------------------IoT-Penetration-Testing-------------------------------------- #"

	# install Repository Tools
	apt install -qy arduino gnuradio blue-hydra e2tools mtools

	# install Python3 pip
	iot_pip="scapy uefi_firmware unblob ubi_reader"
	pip_installer "IoT" "Penetration-Testing" "$iot_pip"

	# install Nodejs NPM
	# iot_npm=""
	npm_installer "IoT" "Penetration-Testing" "$iot_npm"

	# install Ruby GEM
	# iot_gem=""
	gem_installer "IoT" "Penetration-Testing" "$iot_gem"

	# install Golang
	iot_golang="
go install github.com/cruise-automation/fwanalyzer@latest;ln -fs ~/go/bin/fwanalyzer /usr/bin/fwanalyzer"
	go_installer "IoT" "Penetration-Testing" "$iot_golang"

	# install firmwalker
	if [ ! -d "/usr/share/firmwalker" ]; then
		name="firmwalker"
		git clone https://github.com/craigz28/firmwalker /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./firmwalker.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "IoT" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bytesweep
	if [ ! -d "/usr/share/bytesweep" ]; then
		name="bytesweep"
		git clone https://gitlab.com/bytesweep/bytesweep /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages;pip3 install .
		menu_entry "IoT" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install firmware-analysis-toolkit
	if [ ! -d "/usr/share/firfirmware-analysis-toolkit" ]; then
		name="firmware-analysis-toolkit"
		git clone https://github.com/attify/firmware-analysis-toolkit /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./setup.sh
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 fat.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "IoT" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

  	# install icspector
	if [ ! -d "/usr/share/icspector" ]; then
		name="icspector"
		git clone https://github.com/microsoft/ics-forensics-tools /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/src;python3 driver.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "IoT" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install genzai
	if [ ! -d "/usr/share/genzai" ]; then
		name="genzai"
		mkdir -p /usr/share/$name
		wget https://github.com/umair9747/Genzai/releases/download/1.0/genzai_linux_amd64 -O /usr/share/$name/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/$name /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "IoT" "Penetration-Testing" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	exit
}


red_team()
{
	printf "$YELLOW"  "# --------------------------------------Reconnaissance-Red-Team-------------------------------------- #"

	# install Repository Tools
	apt install -qy emailharvester metagoofil amass osrframework gitleaks trufflehog maryam ismtp ident-user-enum eyewitness googler inspy smtp-user-enum goofile bing-ip2hosts webhttrack tnscmd10g getallurls feroxbuster subjack whatweb assetfinder instaloader ligolo-ng 

	# install Python3 pip
	reconnaissance_pip="censys ggshield bbot raccoon-scanner mailspoof h8mail twint thorndyke gitfive shodan postmaniac socialscan huntsman chiasmodon"
	pip_installer "Reconnaissance" "Red-Team" "$reconnaissance_pip"

	# install Nodejs NPM
	reconnaissance_npm="igf nodesub multitor"
	npm_installer "Reconnaissance" "Red-Team" "$reconnaissance_npm"

	# install Ruby GEM
	# reconnaissance_gem=""
	gem_installer "Reconnaissance" "Red-Team" "$reconnaissance_gem"

	# install Golang
	reconnaissance_golang="
go install github.com/x1sec/commit-stream@latest;ln -fs ~/go/bin/commit-stream /usr/bin/commit-stream
go install github.com/eth0izzle/shhgit@latest;ln -fs ~/go/bin/shhgit /usr/bin/shhgit
go install github.com/harleo/asnip@latest;ln -fs ~/go/bin/asnip /usr/bin/asnip
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest;ln -fs ~/go/bin/cvemap /usr/bin/cvemap
go install github.com/hakluke/haktrails@latest;ln -fs ~/go/bin/haktrails /usr/bin/haktrails
go install github.com/lanrat/certgraph@latest;ln -fs ~/go/bin/certgraph /usr/bin/certgraph
go install github.com/aydinnyunus/PackageSpy@latest;ln -fs ~/go/bin/packagespy /usr/bin/packagespy"
	go_installer "Reconnaissance" "Red-Team" "$reconnaissance_golang"

	# install trape
	if [ ! -d "/usr/share/trape" ]; then
		name="trape"
		git clone https://github.com/jofpin/trape /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 trape.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Reconnaissance" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install dracnmap
	if [ ! -d "/usr/share/dracnmap" ]; then
		name="dracnmap"
		git clone https://github.com/Screetsec/Dracnmap /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./Dracnmap.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Reconnaissance" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloakquest3r
	if [ ! -d "/usr/share/cloakquest3r" ]; then
		name="cloakquest3r"
		git clone https://github.com/spyboy-productions/CloakQuest3r /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 cloakquest3r.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Reconnaissance" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install thetimemachine
	if [ ! -d "/usr/share/thetimemachine" ]; then
		name="thetimemachine"
		git clone https://github.com/anmolksachan/TheTimeMachine /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 thetimemachine.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Reconnaissance" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------------Resource-Development-Red-Team----------------------------------- #"

	# install Repository Tools
	apt install -qy sharpshooter 

	# install Python3 pip
	# resource_development_pip=""
	pip_installer "Resource-Development" "Red-Team" "$resource_development_pip"

	# install Nodejs NPM
	# resource_development_npm=""
	npm_installer "Resource-Development" "Red-Team" "$resource_development_npm"

	# install Ruby GEM
	# resource_development_gem=""
	gem_installer "Resource-Development" "Red-Team" "$resource_development_gem"

	# install Golang
	# resource_development_golang=""
	go_installer "Resource-Development" "Red-Team" "$resource_development_golang"

	# install offensivenim
	if [ ! -d "/usr/share/offensivenim" ]; then
		name="offensivenim"
		git clone https://github.com/byt3bl33d3r/OffensiveNim /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/src;ls "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Resource-Development" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install goredops
	if [ ! -d "/usr/share/goredops" ]; then
		name="goredops"
		git clone https://github.com/EvilBytecode/GoRedOps /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;ls "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Resource-Development" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install offensivedlr
	if [ ! -d "/usr/share/offensivedlr" ]; then
		name="offensivedlr"
		git clone https://github.com/byt3bl33d3r/OffensiveDLR /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;pwsh -c \"dir\" "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Resource-Development" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# --------------------------------------Initial-Access-Red-team-------------------------------------- #"

	# install Repository Tools
	apt install -qy qrencode multiforcer crowbar brutespray arduino isr-evilgrade wifiphisher airgraph-ng 

	# install Python3 pip
	initial_access_pip="rarce baboossh dnstwist pasteme-cli"
	pip_installer "Initial-Access" "Red-Team" "$initial_access_pip"

	# install Nodejs NPM
	# initial_access_npm=""
	npm_installer "Initial-Access" "Red-Team" "$initial_access_npm"

	# install Ruby GEM
	# initial_access_gem=""
	gem_installer "Initial-Access" "Red-Team" "$initial_access_gem"

	# install Golang
	initial_access_golang="
go install github.com/Tylous/ZipExec@latest;ln -fs ~/go/bin/ZipExec /usr/bin/ZipExec
go install github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest;ln -fs ~/go/bin/hednsextractor /usr/bin/hednsextractor"
	go_installer "Initial-Access" "Red-Team" "$initial_access_golang"

	# install evilginx
	if [ ! -d "/usr/share/evilginx" ]; then
		name="evilginx"
		mkdir /usr/share/$name
		wget https://github.com/kgretzky/evilginx2/releases/latest/download/evilginx-v3.3.0-linux-64bit.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install.sh
		ln -fs /usr/share/$name/evilginx /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install socialfish
	if [ ! -d "/usr/share/socialfish" ]; then
		name="socialfish"
		git clone https://github.com/UndeadSec/SocialFish /usr/share/$name
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 SocialFish.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install executepefrompngvialnk
	if [ ! -d "/usr/share/executepefrompngvialnk" ]; then
		name="executepefrompngvialnk"
		git clone https://github.com/Maldev-Academy/ExecutePeFromPngViaLNK /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 InsertPeIntoPng.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install embedinhtml
	if [ ! -d "/usr/share/embedinhtml" ]; then
		name="embedinhtml"
		git clone https://github.com/Arno0x/EmbedInHTML /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 embedInHTML.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install badpdf
	if [ ! -d "/usr/share/badpdf" ]; then
		name="badpdf"
		git clone https://github.com/deepzec/Bad-Pdf /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 badpdf.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pdfdropper
	if [ ! -d "/usr/share/pdfdropper" ]; then
		name="pdfdropper"
		git clone https://github.com/0x6rss/pdfdropper /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install blackeye
	if [ ! -d "/usr/share/blackeye" ]; then
		name="blackeye"
		git clone https://github.com/EricksonAtHome/blackeye /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./blackeye.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pdfbuilder
	if [ ! -d "/usr/share/pdfbuilder" ]; then
		name="pdfbuilder"
		mkdir -p /usr/share/$name
		wget https://github.com/K3rnel-Dev/pdf-exploit/releases/download/Compilated/PDF-BUILDER.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;mono PDF-BUILDER.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install credsniper
	if [ ! -d "/usr/share/credsniper" ]; then
		name="credsniper"
		git clone https://github.com/ustayready/CredSniper /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install.sh
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 credsniper.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install evilurl
	if [ ! -d "/usr/share/evilurl" ]; then
		name="evilurl"
		git clone https://github.com/UndeadSec/EvilURL /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 evilurl.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install debinject
	if [ ! -d "/usr/share/debinject" ]; then
		name="debinject"
		git clone https://github.com/UndeadSec/Debinject /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 debinject.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install brutal
	if [ ! -d "/usr/share/brutal" ]; then
		name="brutal"
		git clone https://github.com/Screetsec/Brutal /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./Brutal.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install demiguise
	if [ ! -d "/usr/share/demiguise" ]; then
		name="demiguise"
		git clone https://github.com/nccgroup/demiguise /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 demiguise.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install dr0p1t
	if [ ! -d "/usr/share/dr0p1t" ]; then
		name="dr0p1t"
		git clone https://github.com/D4Vinci/Dr0p1t-Framework /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install.sh
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 Dr0p1t.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install evilpdf
	if [ ! -d "/usr/share/evilpdf" ]; then
		name="evilpdf"
		git clone https://github.com/superzerosec/evilpdf /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 evilpdf.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install gophish
	if [ ! -d "/usr/share/gophish" ]; then
		name="gophish"
		wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./gophish "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Initial-Access" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------------------Execution-Red-Team---------------------------------------- #"

	# install Repository Tools
	apt install -qy shellnoob

	# install Python3 pip
	execution_pip="donut-shellcode xortool pwncat"
	pip_installer "Execution" "Red-Team" "$execution_pip"

	# install Nodejs NPM
	# execution_npm=""
	npm_installer "Execution" "Red-Team" "$execution_npm"

	# install Ruby GEM
	# execution_gem=""
	gem_installer "Execution" "Red-Team" "$execution_gem"

	# install Golang
	# execution_golang=""
	go_installer "Execution" "Red-Team" "$execution_golang"

	# install venom
	if [ ! -d "/usr/share/venom" ]; then
		name="venom"
		git clone https://github.com/r00t-3xp10it/venom /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./venom.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Execution" "Red-Team" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install powerlessshell
	if [ ! -d "/usr/share/powerlessshell" ]; then
		name="powerlessshell"
		git clone https://github.com/Mr-Un1k0d3r/PowerLessShell /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 PowerLessShell.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Execution" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sharpshooter
	if [ ! -d "/usr/share/sharpshooter" ]; then
		name="sharpshooter"
		git clone https://github.com/mdsecactivebreach/SharpShooter /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 SharpShooter.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Execution" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install donut
	if [ ! -d "/usr/share/donut" ]; then
		name="donut"
		mkdir -p /usr/share/$name
		wget https://github.com/TheWover/donut/releases/latest/download/donut_v1.0.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/donut /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Execution" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ----------------------------------------Persistence-Red-Team--------------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	persistence_pip="hiphp"
	pip_installer "Persistence" "Red-Team" "$persistence_pip"

	# install Nodejs NPM
	# persistence_npm=""
	npm_installer "Persistence" "Red-Team" "$persistence_npm"

	# install Ruby GEM
	# persistence_gem=""
	gem_installer "Persistence" "Red-Team" "$persistence_gem"

	# install Golang
	# persistence_golang=""
	go_installer "Persistence" "Red-Team" "$persistence_golang"

	# install vegile
	if [ ! -d "/usr/share/vegile" ]; then
		name="vegile"
		git clone https://github.com/Screetsec/Vegile /usr/share/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/Vegile /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Persistence" "Red-Team" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install smmbackdoorng
	if [ ! -d "/usr/share/smmbackdoorng" ]; then
		name="smmbackdoorng"
		git clone https://github.com/Cr4sh/SmmBackdoorNg /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 smm_backdoor.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Persistence" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install medusa
	if [ ! -d "/usr/share/medusa" ]; then
		name="medusa"
		git clone https://github.com/ldpreload/Medusa /usr/share/$name
		chmod 755 /usr/share/$name/*
		mkdir -p /usr/share/$name/build;mkdir -p /usr/share/$name/bin
		cd /usr/share/$name;make
		ln -fs /usr/share/$name/rkload /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Persistence" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------------Privilege-Escalation-Red-Team----------------------------------- #"

	# install Repository Tools
	apt install -qy linux-exploit-suggester peass oscanner 

	# install Python3 pip
	privilege_escalation_pip="cve-bin-tool"
	pip_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_pip"

	# install Nodejs NPM
	# privilege_escalation_npm=""
	npm_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_npm"

	# install Ruby GEM
	# privilege_escalation_gem=""
	gem_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_gem"

	# install Golang
	# privilege_escalation_golang=""
	go_installer "Privilege-Escalation" "Red-Team" "$privilege_escalation_golang"

	# install mimipenguin
	if [ ! -d "/usr/share/mimipenguin" ]; then
		name="mimipenguin"
		git clone https://github.com/huntergregal/mimipenguin /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 mimipenguin.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Privilege-Escalation" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install godpotato
	if [ ! -d "/usr/share/godpotato" ]; then
		name="godpotato"
		mkdir -p /usr/share/$name
		wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe -O /usr/share/$name/GodPotato-NET4.exe
		wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET35.exe -O /usr/share/$name/GodPotato-NET35.exe
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;ls "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Privilege-Escalation" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install smc
	if [ ! -d "/usr/share/smc" ]; then
		name="smc"
		mkdir -p /usr/share/$name
		wget https://meltdown.ovh -O /usr/share/$name/spectre-meltdown-checker.sh
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash spectre-meltdown-checker.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Privilege-Escalation" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install deadpotato
	if [ ! -d "/usr/share/deadpotato" ]; then
		name="deadpotato"
		mkdir -p /usr/share/$name
		wget https://github.com/lypd0/DeadPotato/releases/download/1.1/DeadPotato-NET4.exe -O /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;mono DeadPotato-NET4.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Privilege-Escalation" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -------------------------------------Defense-Evasion-Red-Team-------------------------------------- #"

	# install Repository Tools
	apt install -qy shellter unicorn veil veil-catapult veil-evasion osslsigncode upx-ucl 

	# install Python3 pip
	defense_evasion_pip="auto-py-to-exe certipy sysplant pinject"
	pip_installer "Defense-Evasion" "Red-Team" "$defense_evasion_pip"

	# install Nodejs NPM
	defense_evasion_npm="uglify-js javascript-obfuscator serialize-javascript serialize-to-js jsdom"
	npm_installer "Defense-Evasion" "Red-Team" "$defense_evasion_npm"

	# install Ruby GEM
	# defense_evasion_gem=""
	gem_installer "Defense-Evasion" "Red-Team" "$defense_evasion_gem"

	# install Golang
	# defense_evasion_golang=""
	go_installer "Defense-Evasion" "Red-Team" "$defense_evasion_golang"

	# install aswcrypter
	if [ ! -d "/usr/share/aswcrypter" ]; then
		name="aswcrypter"
		git clone https://github.com/AbedAlqaderSwedan1/ASWCrypter /usr/share/$name
		chmod 755 /usr/share/$name/*
		bash /usr/share/$name/setup.sh
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash ASWCrypter.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install unicorn
	if [ ! -d "/usr/share/unicorn" ]; then
		name="unicorn"
		git clone https://github.com/trustedsec/unicorn /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 unicorn.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install edr_blocker
	if [ ! -d "/usr/share/edr_blocker" ]; then
		name="edr_blocker"
		git clone https://github.com/TierZeroSecurity/edr_blocker /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 edr_blocker.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install syswhispers3
	if [ ! -d "/usr/share/syswhispers3" ]; then
		name="syswhispers3"
		git clone https://github.com/klezVirus/SysWhispers3 /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 syswhispers.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bin2shellcode
	if [ ! -d "/usr/share/bin2shellcode" ]; then
		name="bin2shellcode"
		git clone https://github.com/fanbyprinciple/bin2shellcode /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 bin2sc.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install edrsilencer
	if [ ! -d "/usr/share/edrsilencer" ]; then
		name="edrsilencer"
		mkdir -p /usr/share/$name
		wget https://github.com/netero1010/EDRSilencer/releases/latest/download/EDRSilencer.exe -O /usr/share/$name/$name.exe
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine $name.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install scarecrow
	if [ ! -d "/usr/share/scarecrow" ]; then
		name="scarecrow"
		mkdir -p /usr/share/$name
		wget https://github.com/optiv/ScareCrow/releases/download/v5.1/ScareCrow_5.1_linux_amd64 -O /usr/share/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/scarecrow /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install syswhispers
	if [ ! -d "/usr/share/syswhispers" ]; then
		name="syswhispers"
		git clone https://github.com/jthuraisamy/SysWhispers /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 syswhispers.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install invoke-dosfuscation
	if [ ! -d "/usr/share/invoke-dosfuscation" ]; then
		name="invoke-dosfuscation"
		git clone https://github.com/danielbohannon/Invoke-DOSfuscation /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;pwsh -c "Import-Module ./Invoke-DOSfuscation.psd1; Invoke-DOSfuscation" "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install obfuscatecactustorch
	if [ ! -d "/usr/share/obfuscatecactustorch" ]; then
		name="obfuscatecactustorch"
		git clone https://github.com/Arno0x/ObfuscateCactusTorch /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 obfuscateCactusTorch.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install phantom-evasion
	if [ ! -d "/usr/share/phantom-evasion" ]; then
		name="phantom-evasion"
		git clone https://github.com/oddcod3/Phantom-Evasion /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 phantom-evasion.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install spookflare
	if [ ! -d "/usr/share/spookflare" ]; then
		name="spookflare"
		git clone https://github.com/hlldz/SpookFlare /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 spookflare.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pazuzu
	if [ ! -d "/usr/share/pazuzu" ]; then
		name="pazuzu"
		git clone https://github.com/BorjaMerino/Pazuzu /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 pazuzu.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install invoke-obfuscation
	if [ ! -d "/usr/share/invoke-obfuscation" ]; then
		name="invoke-obfuscation"
		git clone https://github.com/danielbohannon/Invoke-Obfuscation /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;pwsh -c "Import-Module ./Invoke-Obfuscation.psd1; Invoke-Obfuscation" "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install invoke-cradlecrafter
	if [ ! -d "/usr/share/invoke-cradlecrafter" ]; then
		name="invoke-cradlecrafter"
		git clone https://github.com/danielbohannon/Invoke-CradleCrafter /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;pwsh -c "Import-Module ./Invoke-CradleCrafter.psd1; Invoke-CradleCrafter" "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Defense-Evasion" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ------------------------------------Credential-Access-Red-Team------------------------------------- #"

	# install Repository Tools
	apt install -qy pdfcrack fcrackzip rarcrack 

	# install Python3 pip
	credential_access_pip="adidnsdump detect-secrets impacket cloudscraper knowsmore ssh-mitm donpapi lsassy dploot"
	pip_installer "Credential-Access" "Red-Team" "$credential_access_pip"

	# install Nodejs NPM
	# credential_access_npm=""
	npm_installer "Credential-Access" "Red-Team" "$credential_access_npm"

	# install Ruby GEM
	# credential_access_gem=""
	gem_installer "Credential-Access" "Red-Team" "$credential_access_gem"

	# install Golang
	credential_access_golang="
go install github.com/ropnop/kerbrute@latest;ln -fs ~/go/bin/kerbrute /usr/bin/kerbrute"
	go_installer "Credential-Access" "Red-Team" "$credential_access_golang"

	# install kerberoast
	if [ ! -d "/usr/share/kerberoast" ]; then
		name="kerberoast"
		git clone https://github.com/nidem/kerberoast /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 kerberoast.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Credential-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ntlmRelaytoews
	if [ ! -d "/usr/share/ntlmRelaytoews" ]; then
		name="ntlmRelaytoews"
		git clone https://github.com/Arno0x/NtlmRelayToEWS /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 ntlmRelayToEWS.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Credential-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install dfscoerce
	if [ ! -d "/usr/share/dfscoerce" ]; then
		name="dfscoerce"
		git clone https://github.com/Wh04m1001/DFSCoerce /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 dfscoerce.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Credential-Access" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install netripper
	if [ ! -d "/usr/share/metasploit-framework/modules/post/windows/gather/netripper" ]; then
		name="netripper"
		mkdir -p /usr/share/metasploit-framework/modules/post/windows/gather/$name
		wget https://github.com/NytroRST/NetRipper/blob/master/Metasploit/netripper.rb -O /usr/share/metasploit-framework/modules/post/windows/gather/$name/netripper.rb
		wget https://github.com/NytroRST/NetRipper/blob/master/x64/DLL.x64.dll -O /usr/share/metasploit-framework/modules/post/windows/gather/$name/DLL.x64.dll
		wget https://github.com/NytroRST/NetRipper/blob/master/x86/DLL.x86.dll -O /usr/share/metasploit-framework/modules/post/windows/gather/$name/DLL.x86.dll
		wget https://github.com/NytroRST/NetRipper/blob/master/x64/NetRipper.x64.exe -O /usr/share/metasploit-framework/modules/post/windows/gather/$name/NetRipper.x64.exe
		wget https://github.com/NytroRST/NetRipper/blob/master/x86/NetRipper.x86.exe -O /usr/share/metasploit-framework/modules/post/windows/gather/$name/NetRipper.x86.exe
		chmod 755 /usr/share/metasploit-framework/modules/post/windows/gather/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/metasploit-framework/modules/post/windows/gather/$name;wine NetRipper.x64.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Credential-Access" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------------------Discovery-Red-Team---------------------------------------- #"

	# install Repository Tools
	apt install -qy bloodhound 

	# install Python3 pip
	discovery_pip="networkx bloodhound acltoolkit-ad"
	pip_installer "Discovery" "Red-Team" "$discovery_pip"

	# install Nodejs NPM
	# discovery_npm=""
	npm_installer "Discovery" "Red-Team" "$discovery_npm"

	# install Ruby GEM
	# discovery_gem=""
	gem_installer "Discovery" "Red-Team" "$discovery_gem"

	# install Golang
	# discovery_golang=""
	go_installer "Discovery" "Red-Team" "$discovery_golang"

	# install adexplorer
	if [ ! -d "/usr/share/adexplorer" ]; then
		name="adexplorer"
		mkdir -p /usr/share/adexplorer
		wget https://download.sysinternals.com/files/AdExplorer.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine ADExplorer.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Discovery" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pwnlook
	if [ ! -d "/usr/share/pwnlook" ]; then
		name="pwnlook"
		mkdir -p /usr/share/$name
		wget https://github.com/amjcyber/pwnlook/releases/download/pwnlook/pwnlook.exe -O /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine $name.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Discovery" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -------------------------------------Lateral-Movement-Red-Team------------------------------------- #"

	# install Repository Tools
	apt install -qy pptpd kerberoast isr-evilgrade 

	# install Python3 pip
	lateral_movement_pip="coercer krbjack"
	pip_installer "Lateral-Movement" "Red-Team" "$lateral_movement_pip"

	# install Nodejs NPM
	# lateral_movement_npm=""
	npm_installer "Lateral-Movement" "Red-Team" "$lateral_movement_npm"

	# install Ruby GEM
	lateral_movement_gem="evil-winrm"
	gem_installer "Lateral-Movement" "Red-Team" "$lateral_movement_gem"

	# install Golang
	# lateral_movement_golang=""
	go_installer "Lateral-Movement" "Red-Team" "$lateral_movement_golang"

	# install scshell
	if [ ! -d "/usr/share/scshell" ]; then
		name="scshell"
		git clone https://github.com/Mr-Un1k0d3r/SCShell /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine SCShell.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Lateral-Movement" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install amnesiac
	if [ ! -d "/usr/share/amnesiac" ]; then
		name="amnesiac"
		git clone https://github.com/Leo4j/Amnesiac /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;pwsh -c "Import-Module ./Amnesiac.ps1; Amnesiac" "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Lateral-Movement" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed  $name"
	fi


	printf "$YELLOW"  "# ----------------------------------------Collection-Red-Team---------------------------------------- #"

	# install Repository Tools
	apt install -qy tigervnc-viewer 

	# install Python3 pip
	# collection_pip=""
	pip_installer "Collection" "Red-Team" "$collection_pip"

	# install Nodejs NPM
	# collection_npm=""
	npm_installer "Collection" "Red-Team" "$collection_npm"

	# install Ruby GEM
	# collection_gem=""
	gem_installer "Collection" "Red-Team" "$collection_gem"

	# install Golang
	# collection_golang=""
	go_installer "Collection" "Red-Team" "$collection_golang"

	# install caldera
	if [ ! -d "/usr/share/caldera" ]; then
		name="caldera"
		git clone https://github.com/mitre/caldera /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 server.py --insecure "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Collection" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ------------------------------------Command-and-Control-Red-Team----------------------------------- #"

	# install Repository Tools
	apt install -qy powershell-empire koadic chisel poshc2 ibombshell silenttrinity merlin poshc2 

	# install Python3 pip
	command_and_control_pip="deathstar-empire praw powerhub"
	pip_installer "Command-and-Control" "Red-Team" "$command_and_control_pip"

	# install Nodejs NPM
	# command_and_control_npm=""
	npm_installer "Command-and-Control" "Red-Team" "$command_and_control_npm"

	# install Ruby GEM
	# command_and_control_gem=""
	gem_installer "Command-and-Control" "Red-Team" "$command_and_control_gem"

	# install Golang
	# command_and_control_golang=""
	go_installer "Command-and-Control" "Red-Team" "$command_and_control_golang"

	# install phoenixc2
	if [ ! -d "/usr/share/phoenixc2" ]; then
		name="phoenixc2"
		git clone https://github.com/screamz2k/PhoenixC2 /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;poetry install
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;poetry run phserver "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install nebula
	if [ ! -d "/usr/share/nebula" ]; then
		name="nebula"
		git clone https://github.com/gl4ssesbo1/Nebula /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install mistica
	if [ ! -d "/usr/share/mistica" ]; then
		name="mistica"
		git clone https://github.com/IncideDigital/Mistica /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 ms.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ninja
	if [ ! -d "/usr/share/ninja" ]; then
		name="ninja"
		git clone https://github.com/ahmedkhlief/Ninja /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install.sh;python3 start_campaign.py
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 Ninja.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install evilosx
	if [ ! -d "/usr/share/evilosx" ]; then
		name="evilosx"
		git clone https://github.com/Marten4n6/EvilOSX /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 start.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install eggshell
	if [ ! -d "/usr/share/eggshell" ]; then
		name="eggshell"
		git clone https://github.com/lucasjacks0n/EggShell /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 eggshell.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sillyrat
	if [ ! -d "/usr/share/sillyrat" ]; then
		name="sillyrat"
		git clone https://github.com/hash3liZer/SillyRAT /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 server.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install godgenesis
	if [ ! -d "/usr/share/godgenesis" ]; then
		name="godgenesis"
		git clone https://github.com/SaumyajeetDas/GodGenesis /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 c2c.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install phonesploit
	if [ ! -d "/usr/share/phonesploit" ]; then
		name="phonesploit"
		git clone https://github.com/AzeemIdrisi/PhoneSploit-Pro /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 phonesploitpro.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install meliziac2
	if [ ! -d "/usr/share/meliziac2" ]; then
		name="meliziac2"
		git clone https://github.com/demon-i386/MeliziaC2 /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 c2.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install gcr
	if [ ! -d "/usr/share/gcr" ]; then
		name="gcr"
		git clone https://github.com/MrSaighnal/GCR-Google-Calendar-RAT /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 gcr.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# isntall meetc2
	if [ ! -d "/usr/share/meetc2" ]; then
		name="meetc2"
		git clone https://github.com/iammaguire/MeetC2 /usr/share/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/meetc /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# isntall ahmyth
	if [ ! -f "/usr/bin/ahmyth" ]; then
		name="ahmyth"
		wget https://github.com/Morsmalleo/AhMyth/releases/download/v1.0-beta.5a/AhMyth-Setup_amd64.deb -O /tmp/$name.deb
		chmod +X /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pingrat
	if [ ! -d "/usr/share/pingrat" ]; then
		name="pingrat"
		mkdir -p /usr/share/$name
		wget https://github.com/umutcamliyurt/PingRAT/releases/latest/download/client -O /usr/share/$name/client
		wget https://github.com/umutcamliyurt/PingRAT/releases/latest/download/server -O /usr/share/$name/server
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/client /usr/bin/$name-client;ln -fs /usr/share/$name/server /usr/bin/$name-server
		chmod +x /usr/bin/$name-client;chmod +x /usr/bin/$name-server
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name-client -h'"
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name-server -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ligolo-mp
	if [ ! -d "/usr/share/ligolo-mp" ]; then
		name="ligolo-mp"
		mkdir -p /usr/share/$name
		wget https://github.com/ttpreport/ligolo-mp/releases/download/v1.0.4/ligolo-mp_server_1.0.4_linux_amd64 -O /usr/share/$name/ligolos
		wget https://github.com/ttpreport/ligolo-mp/releases/download/v1.0.4/ligolo-mp_client_1.0.4_linux_amd64 -O /usr/share/$name/ligoloc
		wget https://github.com/ttpreport/ligolo-mp/releases/download/v1.0.4/ligolo-mp_client_1.0.4_windows_amd64.exe -O /usr/share/$name/ligoloc.exe
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/ligolos /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install realm
	if [ ! -d "/usr/share/realm" ]; then
		name="realm"
		mkdir -p /usr/share/$name
		wget https://github.com/spellshift/realm/releases/latest/download/tavern -O /usr/share/$name/tavern
		wget https://github.com/spellshift/realm/releases/latest/download/imix-x86_64-unknown-linux-musl -O /usr/share/$name/imix
		ln -fs /usr/share/$name/imix /usr/bin/imix;ln -fs /usr/share/$name/tavern /usr/bin/tavern
		chmod +x /usr/bin/imix;chmod +x /usr/bin/tavern
		menu_entry "Command-and-Control" "Red-Team" "Imix" "$exec_shell 'imix'"
		menu_entry "Command-and-Control" "Red-Team" "tavern" "$exec_shell 'tavern'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install badrats
	if [ ! -d "/usr/share/badrats" ]; then
		name="badrats"
		git clone https://gitlab.com/KevinJClark/badrats /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 badrat_server.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell 'sudo $name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install mythic
	if [ ! -d "/usr/share/mythic" ]; then
		name="mythic"
		git clone https://github.com/its-a-feature/Mythic /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install_docker_kali.sh
		cd /usr/share/$name/Mythic_CLI/src;make;cd /usr/share/$name/mythic-docker/src;make
		ln -fs /usr/share/$name/Mythic_CLI/src/mythic-cli /usr/bin/$name-cli;ln -fs /usr/share/$name/mythic-docker/src/mythic_server /usr/bin/$name-server
		chmod +x /usr/bin/$name-cli;chmod +x /usr/bin/$name-server
		menu_entry "Command-and-Control" "Red-Team" "$name-cli" "$exec_shell 'sudo $name-cli'"
		menu_entry "Command-and-Control" "Red-Team" "$name-server" "$exec_shell 'sudo $name-server'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install northstarc2
	if [ ! -d "/usr/share/northstarc2" ]; then
		name="northstarc2"
		git clone https://github.com/EnginDemirbilek/NorthStarC2 /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install.sh
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell 'sudo $name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install blackmamba
	if [ ! -d "/usr/share/blackmamba" ]; then
		name="blackmamba"
		git clone https://github.com/loseys/BlackMamba /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install offensivenotion
	if [ ! -d "/usr/share/offensivenotion" ]; then
		name="offensivenotion"
		mkdir -p /usr/share/$name
		wget https://github.com/mttaggart/OffensiveNotion/releases/latest/download/offensive_notion_linux_amd64.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/offensive_notion /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install redbloodc2
	if [ ! -d "/usr/share/redbloodc2" ]; then
		name="redbloodc2"
		git clone https://github.com/kira2040k/RedbloodC2 /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;npm install
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;node server.js "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sharpc2
	if [ ! -d "/usr/share/sharpc2" ]; then
		name="sharpc2"
		mkdir -p /usr/share/$name
		wget https://github.com/rasta-mouse/SharpC2/releases/latest/download/teamserver-linux.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		ln -fs /usr/share/$name/TeamServer /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install emp3r0r
	if [ ! -d "/usr/share/emp3r0r" ]; then
		name="emp3r0r"
		mkdir -p /usr/share/$name
		wget https://github.com/jm33-m0/emp3r0r/releases/download/v1.37.1/emp3r0r-v1.37.1.tar.xz -O /tmp/$name.tar.xz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./emp3r0r --install
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install chaos
	if [ ! -d "/usr/share/chaos" ]; then
		name="chaos"
		git clone https://github.com/tiagorlampert/CHAOS /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;PORT=8080 SQLITE_DATABASE=chaos go run cmd/chaos/main.go "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install godoh
	if [ ! -d "/usr/share/godoh" ]; then
		name="godoh"
		mkdir -p /usr/share/$name
		wget https://github.com/sensepost/godoh/releases/latest/download/godoh-linux64 -O /usr/share/$name/godoh
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/godoh /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sliver
	if [ ! -d "/usr/share/sliver" ]; then
		name="sliver"
		mkdir -p /usr/share/$name
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/share/$name/sliver_server
		wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -O /usr/share/$name/sliver_client
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/sliver_server /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install havoc
	if [ ! -d "/usr/share/havoc" ]; then
		name="havoc"
		git clone https://github.com/HavocFramework/Havoc /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /user/share/$name/client;make
		cd /user/share/$name/teamserver;./install.sh;make
		ln -fs /user/share/$name/teamserver/teamserver /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Command-and-Control" "Red-Team" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ---------------------------------------Exfiltration-Red-Team--------------------------------------- #"

	# install Repository Tools
	apt install -qy haproxy xplico certbot stunnel4 httptunnel onionshare proxify privoxy 

	# install Python3 pip
	exfiltration_pip="updog pivotnacci"
	pip_installer "Exfiltration" "Red-Team" "$exfiltration_pip"

	# install Nodejs NPM
	# exfiltration_npm=""
	npm_installer "Exfiltration" "Red-Team" "$exfiltration_npm"

	# install Ruby GEM
	# exfiltration_gem=""
	gem_installer "Exfiltration" "Red-Team" "$exfiltration_gem"

	# install Golang
	# exfiltration_golang=""
	go_installer "Exfiltration" "Red-Team" "$exfiltration_golang"

	# install ngrok
	if [ ! -f "/usr/local/bin/ngrok" ]; then
		name="ngrok"
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/$name.tgz
		tar -xvzf /tmp/$name.tgz -C /usr/local/bin;rm -f /tmp/$name.tgz
		chmod +x /usr/local/bin/ngrok
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install noip2
	if [ ! -f "/usr/local/bin/noip2" ]; then
		name="noip"
		mkdir -p /usr/share/$name
		wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/$name.tar.gz
		tar -xzf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;make;make install
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install dnsexfiltrator
	if [ ! -d "/usr/share/dnsexfiltrator" ]; then
		name="dnsexfiltrator"
		git clone https://github.com/Arno0x/DNSExfiltrator /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 dnsexfiltrator.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bobthesmuggler
	if [ ! -d "/usr/share/bobthesmuggler" ]; then
		name="bobthesmuggler"
		git clone https://github.com/TheCyb3rAlpha/BobTheSmuggler /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 BobTheSmuggler.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install smuggler
	if [ ! -d "/usr/share/smuggler" ]; then
		name="smuggler"
		git clone https://github.com/TheCyb3rAlpha/BobTheSmuggler /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 smuggler.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

  	# install lfisuite
	if [ ! -d "/usr/share/lfisuite" ]; then
		name="lfisuite"
		git clone https://github.com/D35m0nd142/LFISuite /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 lfisuite.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sshsnake
	if [ ! -d "/usr/share/sshsnake" ]; then
		name="sshsnake"
		git clone https://github.com/MegaManSec/SSH-Snake /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash Snake.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install reversessh
	if [ ! -d "/usr/share/reversessh" ]; then
		name="reversessh"
		mkdir -p /usr/share/$name
		wget https://github.com/Fahrj/reverse-ssh/releases/latest/download/reverse-sshx64 -O /usr/share/$name/reversessh
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./reversessh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install transfer.sh
	if [ ! -d "/usr/share/transfer.sh" ]; then
		name="transfer.sh"
		mkdir -p /usr/share/$name
		wget https://github.com/dutchcoders/transfer.sh/releases/download/v1.6.1/transfersh-v1.6.1-linux-amd64 -O /usr/share/$name/transfer.sh
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/transfersh /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install dnslivery
	if [ ! -d "/usr/share/dnslivery" ]; then
		name="dnslivery"
		git clone https://github.com/no0be/DNSlivery /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 dnslivery.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install webdavdelivery
	if [ ! -d "/usr/share/webdavdelivery" ]; then
		name="webdavdelivery"
		git clone https://github.com/Arno0x/WebDavDelivery /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 webDavDelivery.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install wstunnel
	if [ ! -d "/usr/share/wstunnel" ]; then
		name="wstunnel"
		mkdir -p /usr/share/$name
		wget https://github.com/erebe/wstunnel/releases/download/v10.1.1/wstunnel_10.1.1_linux_amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/wstunnel /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install kubo
	if [ ! -d "/usr/share/kubo" ]; then
		name="kubo"
		mkdir -p /usr/share/$name
		wget https://github.com/ipfs/kubo/releases/download/v0.32.1/kubo_v0.32.1_linux-amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./install.sh;ipfs init
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install frp
	if [ ! -d "/usr/share/frp" ]; then
		name="frp"
		wget https://github.com/fatedier/frp/releases/download/v0.58.1/frp_0.58.1_linux_amd64.tar.gz -O /tmp/$name.tar.gz
		tar -xzf /tmp/$name.tar.gz -C /usr/share;rm -f /tmp/$name.tar.gz;mv /usr/share/frp_* /usr/share/frp
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/frps /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install rathole
	if [ ! -d "/usr/share/rathole" ]; then
		name="rathole"
		mkdir -p /usr/share/$name
		wget https://github.com/rapiz1/rathole/releases/latest/download/rathole-x86_64-unknown-linux-gnu.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/rathole /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install hfs
	if [ ! -d "/usr/share/hfs" ]; then
		name="hfs"
		mkdir -p /usr/share/$name
		wget https://github.com/rejetto/hfs/releases/download/v0.53.0/hfs-linux-x64-0.53.0.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/hfs /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install goproxy
	if [ ! -d "/usr/share/goproxy" ]; then
		name="goproxy"
		mkdir -p /usr/share/$name
		wget https://github.com/snail007/goproxy/releases/latest/download/proxy-linux-amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/proxy /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Exfiltration" "Red-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ------------------------------------------Impact-Red-Team------------------------------------------ #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# impact_pip=""
	pip_installer "Impact" "Red-Team" "$impact_pip"

	# install Nodejs NPM
	# impact_npm=""
	npm_installer "Impact" "Red-Team" "$impact_npm"

	# install Ruby GEM
	# impact_gem=""
	gem_installer "Impact" "Red-Team" "$impact_gem"

	# install Golang
	# impact_golang=""
	go_installer "Impact" "Red-Team" "$impact_golang"

	exit
}


ics_security()
{
	printf "$YELLOW"  "# ----------------------------------Penetration-Testing-ICS-Security--------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# penetration_testing_pip=""
	pip_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_pip"

	# install Nodejs NPM
	# penetration_testing_npm=""
	npm_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_npm"

	# install Ruby GEM
	penetration_testing_gem="modbus-cli"
	gem_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_gem"

	# install Golang
	# penetration_testing_golang=""
	go_installer "Penetration-Testing" "ICS-Security" "$penetration_testing_golang"

	# install s7scan
	if [ ! -d "/usr/share/s7scan" ]; then
		name="s7scan"
		git clone https://github.com/klsecservices/s7scan /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 s7scan.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Penetration-Testing" "ICS-Security" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install modbuspal
	if [ ! -d "/usr/share/modbuspal" ]; then
		name="modbuspal"
		mkdir -p /usr/share/$name
		wget https://cfhcable.dl.sourceforge.net/project/modbuspal/modbuspal/RC%20version%201.6c/ModbusPal.jar -O /usr/share/$name/ModbusPal.jar
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;java -jar ModbusPal.jar "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Penetration-Testing" "ICS-Security" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install isf
	if [ ! -d "/usr/share/isf" ]; then
		name="isf"
		git clone https://github.com/dark-lbp/isf /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 isf.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Penetration-Testing" "ICS-Security" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install redpoint
	if [ ! -f "/usr/share/nmap/scripts/fox-info.nse" ]; then
		name="redpoint"
		git clone https://github.com/digitalbond/Redpoint /tmp/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;mv * /usr/share/nmap/scripts
		rm -rf /tmp/$name
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ----------------------------------------Red-Team-ICS-Security-------------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# red_team_pip=""
	pip_installer "Red-Team" "ICS-Security" "$red_team_pip"

	# install Nodejs NPM
	# red_team_npm=""
	npm_installer "Red-Team" "ICS-Security" "$red_team_npm"

	# install Ruby GEM
	# red_team_gem=""
	gem_installer "Red-Team" "ICS-Security" "$red_team_gem"

	# install Golang
	# red_team_golang=""
	go_installer "Red-Team" "ICS-Security" "$red_team_golang"


	printf "$YELLOW"  "# ------------------------------------Digital-Forensic-ICS-Security---------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# digital_forensic_pip=""
	pip_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_pip"

	# install Nodejs NPM
	# digital_forensic_npm=""
	npm_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_npm"

	# install Ruby GEM
	# digital_forensic_gem=""
	gem_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_gem"

	# install Golang
	# digital_forensic_golang=""
	go_installer "Digital-Forensic" "ICS-Security" "$digital_forensic_golang"

 	# install icspector
	if [ ! -d "/usr/share/icspector" ]; then
		name="icspector"
		git clone https://github.com/microsoft/ics-forensics-tools /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip2 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/src;python3 driver.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Digital-Forensic" "ICS-Security" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ---------------------------------------Blue-Team-ICS-Security-------------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	blue_team_pip="conpot"
	pip_installer "Blue-Team" "ICS-Security" "$blue_team_pip"

	# install Nodejs NPM
	# blue_team_npm=""
	npm_installer "Blue-Team" "ICS-Security" "$blue_team_npm"

	# install Ruby GEM
	# blue_team_gem=""
	gem_installer "Blue-Team" "ICS-Security" "$blue_team_gem"

	# install Golang
	# blue_team_golang=""
	go_installer "Blue-Team" "ICS-Security" "$blue_team_golang"

	exit
}


digital_forensic()
{
	printf "$YELLOW"  "# --------------------------------Reverse-Engineeting-Digital-Forensic------------------------------- #"

	# install Repository Tools
	apt install -qy ghidra foremost qpdf kafkacat gdb pspy llvm zydis-tools

	# install Python3 pip
	reverse_engineering_pip="capstone decompyle3 uncompyle6 Depix andriller radare2 peepdf-3 pngcheck qiling fwhunt-scan"
	pip_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_pip"

	# install Nodejs NPM
	# reverse_engineering_npm=""
	npm_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_npm"

	# install Ruby GEM
	# reverse_engineering_gem=""
	gem_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_gem"

	# install Golang
	# reverse_engineering_golang=""
	go_installer "Reverse-Engineering" "Digital-Forensic" "$reverse_engineering_golang"

	# install sysmonforlinux
	if [ ! -d "/usr/share/sysmonforlinux" ]; then
		name="sysmonforlinux"
		wget https://github.com/Sysinternals/SysmonForLinux/releases/download/1.3.3.0/sysmonforlinux_1.3.3_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Reverse-Engineering" "Digital-Forensic" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bindiff
	if [ ! -d "/usr/share/bindiff" ]; then
		name="bindiff"
		wget https://github.com/google/bindiff/releases/download/v8/bindiff_8_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Reverse-Engineering" "Digital-Forensic" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install jpexs-decompiler
	if [ ! -f "/usr/bin/ffdec" ]; then
		name="ffdec"
		wget https://github.com/jindrapetrik/jpexs-decompiler/releases/download/version22.0.2/ffdec_22.0.2.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Reverse-Engineering" "Digital-Forensic" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ----------------------------------Malware-Analysis-Digital-Forensic-------------------------------- #"

	# install Repository Tools
	apt install -qy autopsy exiftool inetsim outguess steghide steghide-doc hexyl audacity stenographer stegosuite dnstwist rkhunter tesseract-ocr feh strace sonic bpftool pev readpe 

	# install Python3 pip
	malware_analysis_pip="stegcracker dnschef-ng stego-lsb ghidriff stegoveritas stegano xortool stringsifter oletools dnfile dotnetfile malchive mwcp chepy unipacker rekall ioc-fanger ioc-scan"
	pip_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_pip"

	# install Nodejs NPM
	malware_analysis_npm="box-js f5stegojs"
	npm_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_npm"

	# install Ruby GEM
	malware_analysis_gem="pedump zsteg"
	gem_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_gem"

	# install Golang
	malware_analysis_golang="
go install github.com/tomchop/unxor@latest;ln -fs ~/go/bin/unxor /usr/bin/unxor"
	go_installer "Malware-Analysis" "Digital-Forensic" "$malware_analysis_golang"

	# install dangerzone
	if [ ! -d "/usr/share/dangerzone" ]; then
		name="dangerzone"
		gpg --keyserver hkps://keys.openpgp.org \
    		--no-default-keyring --keyring ./fpf-apt-tools-archive-keyring.gpg \
    		--recv-keys "DE28 AB24 1FA4 8260 FAC9 B8BA A7C9 B385 2260 4281"
		mkdir -p /etc/apt/keyrings/;mv fpf-apt-tools-archive-keyring.gpg /etc/apt/keyrings
		apt update;apt install -qy $name
		printf "$GREEN"  "[*] Sucess installing Dangerzone"
	else
		printf "$GREEN"  "[*] Sucess installed Dangerzone"
	fi

	# install stegocracker
	if [ ! -d "/usr/share/stegocracker" ]; then
		name="stegocracker"
		git clone https://github.com/W1LDN16H7/StegoCracker /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cd /usr/share/$name;python3 setup.py install;bash install.sh 
		menu_entry "Malware-Analysis" "Digital-Forensic" "stego" "$exec_shell 'stego -h'"
		printf "$GREEN"  "[*] Successfully Installed StegoCracker"
	fi

	# install openstego
	if [ ! -d "/usr/share/openstego" ]; then
		name="openstego"
		wget https://github.com/syvaidya/openstego/releases/download/openstego-0.8.6/openstego_0.8.6-1_all.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;apt --fix-broken install -qy;rm -f /tmp/$name.deb
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install stegosaurus
	if [ ! -d "/usr/share/stegosaurus" ]; then
		name="stegosaurus"
		mkdir -p /usr/share/$name
		wget https://github.com/AngelKitty/stegosaurus/releases/latest/download/stegosaurus -O /usr/share/$name/stegosaurus
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/stegosaurus /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install audiostego
	if [ ! -d "/usr/share/audiostego" ]; then
		name="audiostego"
		git clone https://github.com/danielcardeenas/AudioStego /usr/share/$name
		cd /usr/share/$name;mkdir build;cd build;cmake ..;make
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/build/hideme /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell 'sudo $name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cloacked-pixel
	if [ ! -d "/usr/share/cloacked-pixel" ]; then
		name="cloacked-pixel"
		git clone https://github.com/livz/cloacked-pixel /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python2 lsb.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install trace-forensic-toolkit
	if [ ! -d "/usr/share/trace" ]; then
		name="trace"
		git clone https://github.com/Gadzhovski/TRACE-Forensic-Toolkit /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 main.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install xorj
	if [ ! -d "/usr/share/xorj" ]; then
		name="xorj"
        mkdir -p $name
		wget https://github.com/ae27ff/XorJ/releases/download/v1.5.2-beta/XorJ-1.5.2-SNAPSHOT.jar /usr/share/$name/XorJ-1.5.2-SNAPSHOT.jar
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;java -jar XorJ-1.5.2-SNAPSHOT.jar "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install steganabara
	if [ ! -d "/usr/share/steganabara" ]; then
		name="steganabara"
		git clone https://github.com/quangntenemy/Steganabara /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;./run "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install stegsolve
	if [ ! -d "/usr/share/stegsolve" ]; then
		name="stegsolve"
		mkdir -p /usr/share/$name
		wget http://www.caesum.com/handbook/Stegsolve.jar -O /usr/share/$name/stegsolve.jar
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;java -jar stegsolve.jar "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install openpuff
	if [ ! -d "/usr/share/openpuff" ]; then
		name="openpuff"
		wget https://embeddedsw.net/zip/OpenPuff_release.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine OpenPuff.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install mp3stego
	if [ ! -d "/usr/share/mp3stego" ]; then
		name="mp3stego"
		git clone https://github.com/fabienpe/MP3Stego /usr/share/$name
		chmod 755 /usr/share/$name/MP3Stego/*
		cat > /usr/bin/$name-encode << EOF
#!/bin/bash
cd /usr/share/$name/MP3Stego;wine Encode.exe "\$@"
EOF
		chmod +x /usr/bin/$name-encode
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name-encode" "$exec_shell '$name-encode'"
		cat > /usr/bin/$name-decode << EOF
#!/bin/bash
cd /usr/share/$name/MP3Stego;wine Decode.exe "\$@"
EOF
		chmod +x /usr/bin/$name-decode
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name-decode" "$exec_shell '$name-decode'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install theZoo
	if [ ! -d "/usr/share/theZoo" ]; then
		name="theZoo"
		git https://github.com/ytisf/theZoo /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 theZoo.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install kdrill
	if [ ! -d "/usr/share/kdrill" ]; then
		name="kdrill"
		git https://github.com/ExaTrack/Kdrill /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 Kdrill.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Malware-Analysis" "Digital-Forensic" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install jsteg-slink
	if [ ! -d "/usr/share/jsteg-slink" ]; then
		name="jsteg-slink"
		mkdir -p /usr/share/$name
		wget https://github.com/lukechampine/jsteg/releases/latest/download/jsteg-linux-amd64 -O /usr/share/$name/jsteg
		chmod +x /usr/bin/jsteg
		ln -fs /usr/share/$name/jsteg /usr/bin/jsteg
		menu_entry "Malware-Analysis" "Digital-Forensic" "JSteg" "$exec_shell 'sudo jsteg -h'"
		wget https://github.com/lukechampine/jsteg/releases/latest/download/slink-linux-amd64 -O /usr/share/$name/slink
		ln -fs /usr/share/$name/slink /usr/bin/slink
		chmod +x /usr/bin/slink
		menu_entry "Malware-Analysis" "Digital-Forensic" "Slink" "$exec_shell 'sudo slink -h'"
		chmod 755 /usr/share/jsteg-slink/*
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ssak
	if [ ! -d "/usr/share/ssak" ]; then
		name="ssak"
		git clone https://github.com/mmtechnodrone/SSAK /usr/share/$name
		chmod 755 /usr/share/$name/programs/64/*
		ln -fs /usr/share/$name/programs/64/cjpeg /usr/bin/cjpeg
		chmod +x /usr/bin/cjpeg
		menu_entry "Malware-Analysis" "Digital-Forensic" "cjpeg" "$exec_shell 'sudo cjpeg -h'"
		ln -fs /usr/share/$name/programs/64/djpeg /usr/bin/djpeg
		chmod +x /usr/bin/djpeg
		menu_entry "Malware-Analysis" "Digital-Forensic" "djpeg" "$exec_shell 'sudo djpeg -h'"
		ln -fs /usr/share/$name/programs/64/histogram /usr/bin/histogram
		chmod +x /usr/bin/histogram
		menu_entry "Malware-Analysis" "Digital-Forensic" "histogram" "$exec_shell 'sudo histogram -h'"
		ln -fs /usr/share/$name/programs/64/jphide /usr/bin/jphide
		chmod +x /usr/bin/jphide
		menu_entry "Malware-Analysis" "Digital-Forensic" "jphide" "$exec_shell 'sudo jphide -h'"
		ln -fs /usr/share/$name/programs/64/jpseek /usr/bin/jpseek
		chmod +x /usr/bin/jpseek
		menu_entry "Malware-Analysis" "Digital-Forensic" "jpseek" "$exec_shell 'sudo jpseek -h'"
		ln -fs /usr/share/$name/programs/64/outguess_0.13 /usr/bin/outguess
		chmod +x /usr/bin/outguess
		menu_entry "Malware-Analysis" "Digital-Forensic" "outguess" "$exec_shell 'sudo outguess -h'"
		ln -fs /usr/share/$name/programs/64/stegbreak /usr/bin/stegbreak
		chmod +x /usr/bin/stegbreak
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegbreak" "$exec_shell 'sudo stegbreak -h'"
		ln -fs /usr/share/$name/programs/64/stegcompare /usr/bin/stegcompare
		chmod +x /usr/bin/stegcompare
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegcompare" "$exec_shell 'sudo stegcompare -h'"
		ln -fs /usr/share/$name/programs/64/stegdeimage /usr/bin/stegdeimage
		chmod +x /usr/bin/stegdeimage
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegdeimage" "$exec_shell 'sudo stegdeimage -h'"
		ln -fs /usr/share/$name/programs/64/stegdetect /usr/bin/stegdetect
		chmod +x /usr/bin/stegdetect
		menu_entry "Malware-Analysis" "Digital-Forensic" "stegdetect" "$exec_shell 'sudo stegdetect -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------------Threat-Hunting-Digital-Forensic--------------------------------- #"

	# install Repository Tools
	apt install -qy sigma-align httpry logwatch nebula cacti tcpdump procmon sigma ja3 arkime bpftrace 

	# install Python3 pip
	threat_hunting_pip="pastehunter libcsce phishing-tracker"
	pip_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_pip"

	# install Nodejs NPM
	# threat_hunting_npm=""
	npm_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_npm"

	# install Ruby GEM
	# threat_hunting_gem=""
	gem_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_gem"

	# install Golang
	threat_hunting_golang="
go install github.com/Danny-Dasilva/CycleTLS/cycletls@latest;ln -fs ~/go/bin/cycletls /usr/bin/cycletls"
	go_installer "Threat-Hunting" "Digital-Forensic" "$threat_hunting_golang"

	# install matano
	if [ ! -d "/usr/share/matano" ]; then
		name="matano"
		wget https://github.com/matanolabs/matano/releases/download/nightly/matano-linux-x64.sh -O /tmp/$name.sh
		chmod +x /tmp/$name.sh;cd /tmp;bash $name.sh;rm -f $name.sh
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install apt-hunter
	if [ ! -d "/usr/share/apt-hunter" ]; then
		name="apt-hunter"
		git clone https://github.com/ahmedkhlief/APT-Hunter /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 APT-Hunter.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install kuiper
	if [ ! -d "/usr/share/kuiper" ]; then
		name="kuiper"
		git clone https://github.com/DFIRKuiper/Kuiper /usr/share/$name
		chmod 755 /usr/share/$name/*
  		cd /usr/share/$name;docker-compose pull
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;docker-compose up -d "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pspy
	if [ ! -d "/usr/share/pspy" ]; then
		name="pspy"
		mkdir -p /usr/share/$name
		wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O /usr/share/$name/pspy64
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/pspy64 /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install velociraptor
	if [ ! -d "/usr/share/velociraptor" ]; then
		name="velociraptor"
		mkdir -p /usr/share/$name
		wget https://github.com/Velocidex/velociraptor/releases/download/v0.73/velociraptor-v0.73.1-linux-amd64 -O /usr/share/$name/velociraptor
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/velociraptor /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install hayabusa
	if [ ! -d "/usr/share/hayabusa" ]; then
		name="hayabusa"
		wget https://github.com/Yamato-Security/hayabusa/releases/download/v2.16.0/hayabusa-2.16.0-linux-intel.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		ln -fs /usr/share/$name/hayabusa-2.16.0-lin-x64-gnu /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install aiengine
	if [ ! -d "/usr/share/aiengine" ]; then
		name="aiengine"
		git clone https://bitbucket.org/camp0/aiengine /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./autogen.sh;./configure;make
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		ln -fs /usr/share/$name/aiengine /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install tracee
	if [ ! -d "/usr/share/tracee" ]; then
		name="tracee"
		mkdir -p /usr/share/$name
		wget https://github.com/aquasecurity/tracee/releases/download/v0.22.5/tracee-x86_64.v0.22.5.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		ln -fs /usr/share/$name/dist/tracee /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install memprocfs
	if [ ! -d "/usr/share/memprocfs" ]; then
		name="memprocfs"
		mkdir -p /usr/share/$name
		wget https://github.com/ufrisk/MemProcFS/releases/download/v5.14/MemProcFS_files_and_binaries_v5.14.1-linux_x64-20250119.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		ln -fs /usr/share/$name/memprocfs /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sysinternalsebpf
	if [ ! -d "/usr/share/sysinternalsebpf" ]; then
		name="sysinternalsebpf"
		wget https://github.com/Sysinternals/SysinternalsEBPF/releases/download/1.3.0.0/sysinternalsebpf_1.3.0-0_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install capa
	if [ ! -d "/usr/share/capa" ]; then
		name="capa"
		mkdir -p /usr/share/$name
  		wget https://github.com/mandiant/capa/releases/download/v7.3.0/capa-v7.3.0-linux.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		ln -fs /usr/share/$name/capa /usr/bin/$name
		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ----------------------------------Incident-Response-Digital-Forensic------------------------------- #"

	# install Repository Tools
	apt install -qy thehive 

	# install Python3 pip
	incident_response_pip="dissect aws_ir intelmq otx-misp threat_intel"
	pip_installer "Incident-Response" "Digital-Forensic" "$incident_response_pip"

	# install Nodejs NPM
	# incident_response_npm=""
	npm_installer "Incident-Response" "Digital-Forensic" "$incident_response_npm"

	# install Ruby GEM
	# incident_response_gem=""
	gem_installer "Incident-Response" "Digital-Forensic" "$incident_response_gem"

	# install Golang
	# incident_response_golang=""
	go_installer "Incident-Response" "Digital-Forensic" "$incident_response_golang"

	# install grr
	if [ ! -d "/usr/share/grr" ]; then
		name="grr"
		wget https://github.com/google/grr/releases/latest/download/grr-server_3.4.7-1_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cortex
	if [ ! -d "/usr/share/cortex" ]; then
		name="cortex"
		wget https://github.com/TheHive-Project/Cortex/releases/download/3.1.8/cortex_3.1.8-1_all.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install catalyst
	if [ ! -d "/usr/share/catalyst" ]; then
		name="catalyst"
  		mkdir -p /usr/share/$name
		wget https://github.com/SecurityBrewery/catalyst/releases/download/v0.14.1/catalyst_Linux_x86_64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		ln -fs /usr/share/$name/catalyst /usr/bin/$name
  		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

  	# install uac
	if [ ! -d "/usr/share/uac" ]; then
		name="uac"
  		mkdir -p /usr/share/$name
		wget https://github.com/tclahr/uac/releases/download/v3.0.0/uac-3.0.0.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		ln -fs /usr/share/$name/uac /usr/bin/$name
  		menu_entry "Threat-Hunting" "Digital-Forensic" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ---------------------------------Threat-Intelligence-Digital-Forensic------------------------------ #"

	# install Repository Tools
	apt install -qy opentaxii 

	# install Python3 pip
	threat_intelligence_pip="threatingestor stix stix-validator stix2 stix2-matcher stix2-elevator attackcti iocextract threatbus apiosintDS sigmatools msticpy"
	pip_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_pip"

	# install Nodejs NPM
	# threat_intelligence_npm=""
	npm_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_npm"

	# install Ruby GEM
	# threat_intelligence_gem=""
	gem_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_gem"

	# install Golang
	# threat_intelligence_golang=""
	go_installer "Threat-Intelligence" "Digital-Forensic" "$threat_intelligence_golang"

	# install opencti
	if [ ! -d "/usr/share/opencti" ]; then
		name="opencti"
		mkdir -p /usr/share/$name
		wget https://github.com/OpenCTI-Platform/opencti/releases/download/6.3.4/opencti-release-6.3.4.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cp /usr/share/$name/config/default.json /usr/share/$name/config/production.json
		pip3 install -r /usr/share/$name/src/python/requirements.txt --break-system-packages
		cd /usr/share/$name
		yarn install
		yarn build
		yarn serv
		pip3 install -r /usr/share/$name/worker/requirements.txt --break-system-packages
		cp /usr/share/$name/worker/config.yml.sample /usr/share/$name/worker/config.yml
		cat > /usr/bin/$name << EOF
cd /usr/share/$name/worker;python3 worker.py > /dev/null &
sleep 5;firefox "http://127.0.0.1:4000" > /dev/null &
EOF
		chmod +x /usr/bin/$name
		menu_entry "Threat-Intelligence" "Digital-Forensic" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install misp
	if [ ! -d "/var/www/misp" ]; then
		name="misp"
		git clone https://github.com/MISP/MISP /var/www/$name
		# Configure MariaDB
		mysql -u root -e "CREATE DATABASE misp;"
		mysql -u root -e "GRANT ALL PRIVILEGES ON misp.* TO 'unk9misp'@'localhost' IDENTIFIED BY '00980098';"
		mysql -u root -e "FLUSH PRIVILEGES;"
		# Configure Apache
		cp /var/www/$name/INSTALL/apache/misp.conf /etc/apache2/sites-available/misp.conf
		a2ensite misp.conf
		a2enmod rewrite
		systemctl restart apache2
		# Configure PHP
		sed -i 's/max_execution_time = 30/max_execution_time = 300/' /etc/php/7.4/apache2/php.ini
		sed -i 's/memory_limit = 128M/memory_limit = 2048M/' /etc/php/7.4/apache2/php.ini
		sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 100M/' /etc/php/7.4/apache2/php.ini
		sed -i 's/post_max_size = 8M/post_max_size = 100M/' /etc/php/7.4/apache2/php.ini
		# Install and configure Redis
		systemctl enable redis-serverکsystemctl start redis-server
		# Configure MISP
		cp /var/www/$name/INSTALL/initial_admin_password.txt /var/www/$name/app/Config
		chown -R www-data:www-data /var/www/$name;chmod -R 755 /var/www/$name
		cat > /etc/apache2/sites-available/$name.conf << EOF
<VirtualHost *:80>
    ServerAdmin admin@$name.local
    DocumentRoot /var/www/$name
    ServerName $name.local
    ServerAlias www.$name.local

    <Directory /var/www/$name>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/$name_error.log
    CustomLog \${APACHE_LOG_DIR}/$name_access.log combined
</VirtualHost>
EOF
		cd /etc/apache2/sites-available
		a2ensite $name.conf;a2enmod rewrite
		systemctl restart apache2
		echo "127.0.0.1   $name.local" >> /etc/hosts
		cat > /usr/bin/$name << EOF
#!/bin/bash
sudo service apache2 start;sudo service mysql start
firefox $name.local > /dev/null &
EOF
		chmod +x /usr/bin/$name
		menu_entry "Threat-Intelligence" "Digital-Forensic" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	exit
}


blue_team()
{
	printf "$YELLOW"  "# -------------------------------------------Harden-Blue-Team---------------------------------------- #"

	# install Repository Tools
	apt install -qy fail2ban fscrypt encfs age pwgen apparmor ufw firewalld firejail sshguard cilium-cli buildah ansible ansible-core 

	# install Python3 pip
	harden_pip="kernel-hardening-checker"
	pip_installer "Harden" "Blue-Team" "$harden_pip"

	# install Nodejs NPM
	harden_npm="fleetctl"
	npm_installer "Harden" "Blue-Team" "$harden_npm"

	# install Ruby GEM
	# harden_gem=""
	gem_installer "Harden" "Blue-Team" "$harden_gem"

	# install Golang
	# harden_golang=""
	go_installer "Harden" "Blue-Team" "$harden_golang"

	# install chef
	if [ ! -d "/usr/share/chef-os-hardening" ]; then
		name="chef"
		curl -L https://omnitruck.chef.io/install.sh | bash
  		mkdir -p /usr/share/chef-os-hardening/cookbooks
    		chown -R "$(whoami)":"$(whoami)" /usr/share/chef-os-hardening/cookbooks
      		cd /usr/share/chef-os-hardening/cookbooks
		knife cookbook site install chef-os-hardening
  		chef gem install berkshelf
  		cat <<'EOF' | sudo tee /usr/share/chef-os-hardening/cookbooks/Berksfile > /dev/null
source 'https://supermarket.chef.io'
cookbook 'chef-os-hardening', '~> 4.0.0'
EOF
  		berks install --path /usr/share/chef-os-hardening/cookbooks/Berksfile
  		cat <<'EOF' | sudo tee /usr/share/chef-os-hardening/node.json > /dev/null
{
  "run_list": [
    "recipe[chef-os-hardening]"
  ]
}
EOF
		chef-client -z -j /usr/share/chef-os-hardening/node.json
  		ansible-galaxy collection install ansible_hardening.hardening
		menu_entry "Harden" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install chain-bench
	if [ ! -d "/usr/share/chain-bench" ]; then
  		name="chain-bench"
		wget https://github.com/aquasecurity/chain-bench/releases/download/v0.1.10/chain-bench_0.1.10_Linux-64bit.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		ln -fs /usr/share/$name/chain-bench /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Harden" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install harbian-audit
	if [ ! -d "/usr/share/harbian-audit" ]; then
		name="harbian-audit"
		git clone https://github.com/hardenedlinux/harbian-audit /usr/share/$name
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;bash hardening.sh
EOF
  		menu_entry "Harden" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -------------------------------------------Detect-Blue-Team---------------------------------------- #"

	# install Repository Tools
	apt install -qy bubblewrap suricata zeek tripwire aide clamav chkrootkit sentrypeer cyberchef snort rspamd prometheus stenographer 

	# install Python3 pip
	detect_pip="adversarial-robustness-toolbox metabadger flare-capa sigma ja3"
	pip_installer "Detect" "Blue-Team" "$detect_pip"

	# install Nodejs NPM
	# detect_npm=""
	npm_installer "Detect" "Blue-Team" "$detect_npm"

	# install Ruby GEM
	# detect_gem="" 
	gem_installer "Detect" "Blue-Team" "$detect_gem"

	# install Golang
	detect_golang="
go install github.com/crissyfield/troll-a@latest;ln -fs ~/go/bin/troll-a /usr/bin/troll-a"
	go_installer "Detect" "Blue-Team" "$detect_golang"

	# install wazuh
	if [ ! -f "/etc/apt/sources.list.d/wazuh.list" ]; then
		name="wazuh"
		# install Indexer
		cd /tmp;curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh;curl -sO https://packages.wazuh.com/4.7/config.yml
		sed -i "s|<indexer-node-ip>|$LAN|g" /tmp/config.yml;sed -i "s|wazuh-manager-ip|$LAN|g" /tmp/config.yml;sed -i "s|dashboard-node-ip|$LAN|g" /tmp/config.yml
		bash wazuh-install.sh --generate-config-files
		curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
		bash wazuh-install.sh --wazuh-indexer node-1;bash wazuh-install.sh --start-cluster
		ADMIN_PASSWORD=$(tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1)
		curl -k -u admin:$ADMIN_PASSWORD https://$LAN:9200
		curl -k -u admin:$ADMIN_PASSWORD https://$LAN:9200/_cat/nodes?v
		# install Server
		cd /tmp;bash wazuh-install.sh --wazuh-server wazuh-1
		# install Dashboard
		cd /tmp;bash wazuh-install.sh --wazuh-dashboard dashboard
		# install Linux Agent
		curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
		echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
		apt-get update;apt-get install -y wazuh-agent
		printf "$GREEN"  "[*] Successfully Installed $name https://$LAN -> USER:PASS = admin:$ADMIN_PASSWORD"
	fi

	# install opensearch
	if [ ! -d "/usr/share/opensearch" ]; then
		name="opensearch"
		wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install osquery
	if [ ! -d "/usr/share/osquery" ]; then
		name="osquery"
		wget https://github.com/osquery/osquery/releases/download/5.15.0/osquery-dbgsym_5.15.0-1.linux_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install falco
	if [ ! -f "/etc/apt/sources.list.d/falcosecurity.list" ]; then
		name="falco"
		curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
		cat > /etc/apt/sources.list.d/falcosecurity.list << EOF
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF
		apt-get update -y;apt-get install -y dkms make linux-headers-$(uname -r) dialog;apt-get install -y $name
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install modsecurity
	if [ ! -d "/usr/share/modsecurity-crs" ]; then
		name="modsecurity"
		git clone https://github.com/SpiderLabs/owasp-modsecurity-crs /usr/share/$name-crs
		cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
		mv /usr/share/$name-crs/crs-setup.conf.example /usr/share/$name-crs/crs-setup.conf
		cat > /etc/apache2/mods-enabled/security2.conf << EOF
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity
        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier
        IncludeOptional /etc/modsecurity/*.conf
        # Include OWASP ModSecurity CRS rules if installed
        IncludeOptional /usr/share/modsecurity-crs/*.conf
        IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
</IfModule>
EOF
		chmod 755 /etc/apache2/mods-enabled/security2.conf
		cat > /usr/bin/$name-enable << EOF
sed -i "s|SecRuleEngine DetectionOnly|SecRuleEngine On|g" /etc/modsecurity/modsecurity.conf
sudo service apache2 start
EOF
		cat > /usr/bin/$name-disable << EOF
sed -i "s|SecRuleEngine On|SecRuleEngine DetectionOnly|g" /etc/modsecurity/modsecurity.conf
sudo service apache2 stop
EOF
		chmod +x /usr/bin/$name-disable;chmod +x /usr/bin/$name-enable
		menu_entry "Detect" "Blue-Team" "$name-enable" "$exec_shell '$name-enable -h'"
		menu_entry "Detect" "Blue-Team" "$name-disable" "$exec_shell '$name-disable -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install siegma
	if [ ! -d "/usr/share/siegma" ]; then
		name="siegma"
		git clone https://github.com/3CORESec/SIEGMA /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt --break-system-packages
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 siegma.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ndpi
	if [ ! -d "/usr/share/ndpi" ]; then
		name="ndpi"
		git clone https://github.com/ntop/nDPI /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;make;make install
  		cd /usr/share/$name/example;make
		ln -fs /usr/share/$name/ndpiReader /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install bluespawn
	if [ ! -d "/usr/share/bluespawn" ]; then
		name="bluespawn"
		mkdir -p /usr/share/$name
		wget https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -O /usr/share/$name/BLUESPAWN.exe
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine BLUESPAWN.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

 	# install cve2capec
	if [ ! -d "/usr/share/cve2capec" ]; then
		name="cve2capec"
		git clone https://github.com/Galeax/CVE2CAPEC /usr/share/$name
		chmod 755 /usr/share/$name/*
		pip3 install -r /usr/share/$name/requirements.txt
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;python3 capec2technique.py "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ntop
	if [ ! -d "/usr/share/ntop" ]; then
		name="ntop"
		apt-get install -y wget add-apt-repository universe
		wget https://packages.ntop.org/apt-stable/24.04/all/apt-ntop-stable.deb
		chmod +x /tmp/apt-ntop-stable.deb;apt install /tmp/apt-ntop-stable.deb 
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install aiengine
	if [ ! -d "/usr/share/aiengine" ]; then
		name="aiengine"
		git clone https://bitbucket.org/camp0/aiengine /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;./autogen.sh;./configure;make
		ln -fs /usr/share/$name/aiengine /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install hubble
	if [ ! -d "/usr/share/hubble" ]; then
		name="hubble"
		wget https://github.com/cilium/hubble/releases/latest/download/hubble-linux-amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/hubble /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install ossec
	if [ ! -f "/etc/apt/sources.list.d/atomic.list" ]; then
		name="ossec"
		wget -q -O - https://www.atomicorp.com/RPM-GPG-KEY.atomicorp.txt  | sudo apt-key add -
		echo "deb https://updates.atomicorp.com/channels/atomic/debian $DISTRIB_CODENAME main" >>  /etc/apt/sources.list.d/atomic.list
		apt-get update;apt-get install -y ossec-hids-server ossec-hids-agent
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cilium
	if [ ! -d "/usr/share/cilium" ]; then
		name="cilium"
		mkdir -p /usr/share/$name
		wget https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		ln -fs /usr/share/$name/cilium /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install shuffle
	if [ ! -d "/usr/share/shuffle" ]; then
		name="shuffle"
		git clone https://github.com/Shuffle/Shuffle /usr/share/$name
		cat > /usr/bin/$name << EOF
#!/bin/bash
service docker start
cd /usr/share/$name;docker-compose up -d
firefox http://127.0.0.1:3001 > /dev/null &
EOF
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install elasticsearch
	if [ ! -d "/usr/share/elasticsearch" ]; then
		name="elasticsearch"
		wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.12.2-amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install kibana
	if [ ! -d "/usr/share/kibana" ]; then
		name="kibana"
		wget https://artifacts.elastic.co/downloads/kibana/kibana-8.17.1-amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install logstash
	if [ ! -d "/usr/share/logstash" ]; then
		name="logstash"
		wget https://artifacts.elastic.co/downloads/logstash/logstash-8.12.2-amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install zabbix
	if [ ! -d "/usr/share/zabbix" ]; then
		name="zabbix"
		wget https://repo.zabbix.com/zabbix/6.4/debian/pool/main/z/zabbix-release/zabbix-release_6.4-1+debian12_all.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb
		apt update;apt install -y zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent
		mysql -u root -p -h localhost -e "create database zabbix character set utf8mb4 collate utf8mb4_bin;create user zabbix@localhost identified by 'password';grant all privileges on zabbix.* to zabbix@localhost;set global log_bin_trust_function_creators = 1;quit;"
		zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -uzabbix -p zabbix
		mysql -u root -p -h localhost -e "set global log_bin_trust_function_creators = 0;quit;"
		sed -i "s|DBPassword=password|DBPassword=unk12341234|g" /etc/zabbix/zabbix_server.conf
		systemctl restart zabbix-server zabbix-agent apache2
		systemctl enable zabbix-server zabbix-agent apache2
		printf "$GREEN"  "[*] Successfully Installed Zabbix -> http://$LAN/zabbix"
	fi


	printf "$YELLOW"  "# -------------------------------------------Isolate-Blue-Team--------------------------------------- #"

	# install Repository Tools
	apt install -qy openvpn wireguard 

	# install Python3 pip
	# isolate_pip=""
	pip_installer "Isolate" "Blue-Team" "$isolate_pip"

	# install Nodejs NPM
	# isolate_npm=""
	npm_installer "Isolate" "Blue-Team" "$isolate_npm"

	# install Ruby GEM
	# isolate_gem=""
	gem_installer "Isolate" "Blue-Team" "$isolate_gem"

	# install Golang
	isolate_golang="
go install github.com/casbin/casbin/v2@latest;ln -fs ~/go/bin/casbin /usr/bin/casbin"
	go_installer "Isolate" "Blue-Team" "$isolate_golang"

 	# install jumpserver
	if [ ! -d "/usr/share/jumpserver" ]; then
		name="jumpserver"
		curl -sSL https://github.com/jumpserver/jumpserver/releases/latest/download/quick_start.sh | bash
		menu_entry "Isolate" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

  	# install iamlive
	if [ ! -d "/usr/share/iamlive" ]; then
		name="iamlive"
		wget https://github.com/iann0036/iamlive/releases/download/v1.1.15/iamlive-v1.1.15-linux-amd64.tar.gz -O /tmp/$name.tar.gz
  		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		menu_entry "Isolate" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install guacamole
	if [ ! -d "/usr/share/guacamole" ]; then
		name="guacamole"
		# server agent
		wget https://apache.org/dyn/closer.lua/guacamole/1.5.5/source/guacamole-server-1.5.5.tar.gz -O /tmp/$name-server.tar.gz
		tar --strip-components=1 -xvf /tmp/$name-server.tar.gz -C /usr/share/$name-server;rm -f /tmp/$name-server.tar.gz
		chmod 755 /usr/share/$name-server/*
		cd /usr/share/$name-server;./configure --with-init-dir=/etc/init.d
		make;make install;ldconfig
		systemctl enable guacd;systemctl start guacd;systemctl restart tomcat9
		# user agent
		wget https://apache.org/dyn/closer.lua/guacamole/1.5.5/binary/guacamole-1.5.5.war -O /var/lib/tomcat9/webapps/$name.war
		mkdir -p /etc/guacamole;mkdir -p /usr/share/tomcat9/.guacamole
		cat > /etc/guacamole/guacamole.properties << EOF
guacd-hostname: localhost
guacd-port: 4822
user-mapping: /etc/guacamole/user-mapping.xml
EOF
		ln -s /etc/guacamole/guacamole.properties /usr/share/tomcat9/.guacamole/
		cat > /etc/guacamole/user-mapping.xml << EOF
<user-mapping>
    <authorize username="admin" password="password">
        <connection name="MyServer">
            <protocol>rdp</protocol>
            <param name="hostname">$LAN</param>
            <param name="port">3389</param>
        </connection>
    </authorize>
</user-mapping>
EOF
		systemctl restart guacd;systemctl restart tomcat9
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -------------------------------------------Deceive-Blue-Team--------------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	deceive_pip="thug conpot honeypots heralding"
	pip_installer "Deceive" "Blue-Team" "$deceive_pip"

	# install Nodejs NPM
	# deceive_npm=""
	npm_installer "Deceive" "Blue-Team" "$deceive_npm"

	# install Ruby GEM
	# deceive_gem=""
	gem_installer "Deceive" "Blue-Team" "$deceive_gem"

	# install Golang
	# deceive_golang=""
	go_installer "Deceive" "Blue-Team" "$deceive_golang"

	# install honeytrap
	if [ ! -f "/usr/bin/honeytrap" ]; then
		name="honeytrap"
		docker pull honeytrap/honeytrap
		cat > /usr/bin/$name << EOF
#!/bin/bash
docker run -p 8022:8022 honeytrap/honeytrap:latest "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Deceive" "Blue-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cowrie
	if [ ! -f "/usr/bin/cowrie" ]; then
		name="thug"
		docker pull cowrie/cowrie
		cat > /usr/bin/$name << EOF
#!/bin/bash
docker run -p 2222:2222 cowrie/cowrie:latest "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Deceive" "Blue-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install sshesame
	if [ ! -d "/usr/share/sshesame" ]; then
		name="sshesame"
		mkdir -p /usr/share/$name
		wget https://github.com/jaksi/sshesame/releases/latest/download/sshesame-linux-amd64 -O /usr/share/$name/sshesame
		chmod +x /usr/share/$name/sshesame
		ln -fs /usr/share/$name/sshesame /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Detect" "Blue-Team" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install tpotce
	if [ ! -d "/home/${USERS}/tpotce" ]; then
		name="tpotce"
		bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"
		menu_entry "Deceive" "Blue-Team" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -------------------------------------------Evict-Blue-Team----------------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# evict_pip=""
	pip_installer "Evict" "Blue-Team" "$evict_pip"

	# install Nodejs NPM
	# evict_npm=""
	npm_installer "Evict" "Blue-Team" "$evict_npm"

	# install Ruby GEM
	# evict_gem=""
	gem_installer "Evict" "Blue-Team" "$evict_gem"

	# install Golang
	# evict_golang=""
	go_installer "Evict" "Blue-Team" "$evict_golang"

	exit
}


security_audit()
{
	printf "$YELLOW"  "# ----------------------------Preliminary-Audit-Assessment-Security-Audit---------------------------- #"

	# install Repository Tools
	apt install -qy flawfinder afl++ gvm openvas lynis cppcheck findbugs sudo-rs ansible ansible-core 

	# install Python3 pip
	preliminary_audit_assessment_pip="google-generativeai scancode-toolkit mythril"
	pip_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_pip"

	# install Nodejs NPM
	preliminary_audit_assessment_npm="snyk @sandworm/audit"
	npm_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_npm"

	# install Ruby GEM
	preliminary_audit_assessment_gem="brakeman bundler-audit"
	gem_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_gem"

	# install Golang
	preliminary_audit_assessment_golang="
go install github.com/google/osv-scanner/cmd/osv-scanner@latest;ln -fs ~/go/bin/osv-scanner /usr/bin/osv-scanner
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest;ln -fs ~/go/bin/cvemap /usr/bin/cvemap
go install github.com/go-delve/delve/cmd/dlv@latest;ln -fs ~/go/bin/dlv /usr/bin/dlv"
	go_installer "Preliminary-Audit-Assessment" "Security-Audit" "$preliminary_audit_assessment_golang"

	# install bearer
	if [ ! -f "/usr/local/bin/bearer" ]; then
		name="bearer"
		wget https://github.com/Bearer/bearer/releases/download/v1.37.0/bearer_1.37.0_linux-amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install checkstyle
	if [ ! -d "/usr/share/checkstyle" ]; then
		name="checkstyle"
		mkdir -p /usr/share/$name
		wget https://github.com/checkstyle/checkstyle/releases/latest/download/checkstyle-10.13.0-all.jar -O /usr/share/$name/checkstyle.jar
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;java -jar checkstyle.jar "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install aflplusplus
	if [ ! -d "/usr/share/afl" ]; then
		name="afl"
		git clone https://github.com/AFLplusplus/AFLplusplus /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;make distrib;make install
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name-cc" "$exec_shell '$name-cc -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install vuls
	if [ ! -d "/usr/share/vuls" ]; then
		name="vuls"
		mkdir -p /usr/share/$name
		wget https://github.com/future-architect/vuls/releases/download/v0.25.4/vuls_0.25.4_linux_amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/vuls /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install vulhub
	if [ ! -d "/usr/share/vulhub" ]; then
		name="vulhub"
		mkdir -p /usr/share/$name
		wget https://github.com/vulhub/vulhub/archive/master.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;ls "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install syzkaller
	if [ ! -d "/usr/share/syzkaller" ]; then
		name="syzkaller"
		git clone https://github.com/google/syzkaller /usr/share/$name
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;make
		ln -fs /usr/share/$name/syzkaller/bin/linux_amd64/syz-fuzzer /usr/bin/syz-fuzzer
		ln -fs /usr/share/$name/syzkaller/bin/linux_amd64/syz-stress /usr/bin/syz-stress
		ln -fs /usr/share/$name/syzkaller/bin/linux_amd64/syz-executor /usr/bin/syz-executor
		chmod +x /usr/bin/syz-fuzzer;chmod +x /usr/bin/syz-stress;chmod +x /usr/bin/syz-executor
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "syz-fuzzer" "$exec_shell 'syz-fuzzer -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install honggfuzz
	if [ ! -d "/usr/share/honggfuzz" ]; then
		name="honggfuzz"
		git clone https://github.com/google/honggfuzz /usr/share/$name
		chmod 755 /usr/share/$name/*;cd /usr/share/$name;make
		ln -fs /usr/share/$name/honggfuzz /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install cmder
	if [ ! -d "/usr/share/cmder" ]; then
		name="cmder"
		mkdir -p /usr/share/$name
		wget https://github.com/cmderdev/cmder/releases/latest/download/cmder.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /usr/share/$name;rm -f /tmp/$name.zip
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;wine Cmder.exe "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install open-policy-agent
	if [ ! -d "/usr/share/opa" ]; then
		name="opa"
		mkdir -p /usr/share/$name
		wget https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_amd64 -O /usr/share/$name/opa
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/opa /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# ------------------------------Planning-and-Preparation-Security-Audit------------------------------ #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# planning_and_preparation_pip=""
	pip_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_pip"

	# install Nodejs NPM
	planning_and_preparation_npm="solidity-code-metrics"
	npm_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_npm"

	# install Ruby GEM
	# planning_and_preparation_gem=""
	gem_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_gem"

	# install Golang
	# planning_and_preparation_golang=""
	go_installer "Planning-and-Preparation" "Security-Audit" "$planning_and_preparation_golang"


	printf "$YELLOW"  "# ----------------------------Establishing-Audit-Objectives-Security-Audit--------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# establishing_audit_objectives_pip=""
	pip_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_pip"

	# install Nodejs NPM
	# establishing_audit_objectives_npm=""
	npm_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_npm"

	# install Ruby GEM
	# establishing_audit_objectives_gem=""
	gem_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_gem"

	# install Golang
	# establishing_audit_objectives_golang=""
	go_installer "Establishing-Audit-Objectives" "Security-Audit" "$establishing_audit_objectives_golang"

	# install selefra
	if [ ! -d "/usr/share/selefra" ]; then
		name="selefra"
		mkdir -p /usr/share/$name
		wget https://github.com/selefra/selefra/releases/latest/download/selefra_linux_amd64.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/selefra /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install wordpress
	if [ ! -d "/var/www/wordpress" ]; then
		name="wordpress"
		service apache2 start;service mysql start
		wget https://wordpress.org/latest.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /var/www;rm -f /tmp/$name.zip
		chown -R www-data:www-data /var/www/$name;chmod -R 755 /var/www/$name
		cat > /etc/apache2/sites-available/$name.conf << EOF
<VirtualHost *:80>
    ServerAdmin admin@$name.local
    DocumentRoot /var/www/$name
    ServerName $name.local
    ServerAlias www.$name.local

    <Directory /var/www/$name>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/$name_error.log
    CustomLog \${APACHE_LOG_DIR}/$name_access.log combined
</VirtualHost>
EOF
		cd /etc/apache2/sites-available
		a2ensite $name.conf;a2enmod rewrite
		systemctl restart apache2
		echo "127.0.0.1   $name.local" >> /etc/hosts
		# Initialize MySQL
		mysql -f -s -u root -h localhost -e "
    CREATE DATABASE ${name}_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER '${name}_usr'@'localhost' IDENTIFIED BY '00980098';
    GRANT ALL PRIVILEGES ON ${name}_db.* TO '${name}_usr'@'localhost';
    FLUSH PRIVILEGES;
    EXIT;"
		cat > /usr/bin/$name << EOF
#!/bin/bash
sudo service apache2 start;sudo service mysql start
firefox $name.local > /dev/null &
EOF
		chmod +x /usr/bin/$name
  		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install joomla
	if [ ! -d "/var/www/joomla" ]; then
		name="joomla"
		service apache2 start;service mysql start
		mkdir -p /var/www/$name
		wget https://downloads.joomla.org/cms/joomla5/5-1-2/Joomla_5-1-2-Stable-Full_Package.zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /var/www/$name;rm -f /tmp/$name.zip
		chown -R www-data:www-data /var/www/$name;chmod -R 755 /var/www/$name
		cat > /etc/apache2/sites-available/$name.conf << EOF
<VirtualHost *:80>
    ServerAdmin admin@$name.local
    DocumentRoot /var/www/$name
    ServerName $name.local
    ServerAlias www.$name.local

    <Directory /var/www/$name>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/$name_error.log
    CustomLog \${APACHE_LOG_DIR}/$name_access.log combined
</VirtualHost>
EOF
		cd /etc/apache2/sites-available
		a2ensite $name.conf;a2enmod rewrite
		systemctl restart apache2
		echo "127.0.0.1   $name.local" >> /etc/hosts
		# Initialize MySQL
		mysql -f -s -u root -h localhost -e "
    CREATE DATABASE ${name}_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER '${name}_usr'@'localhost' IDENTIFIED BY '00980098';
    GRANT ALL PRIVILEGES ON ${name}_db.* TO '${name}_usr'@'localhost';
    FLUSH PRIVILEGES;
    EXIT;"
		cat > /usr/bin/$name << EOF
#!/bin/bash
sudo service apache2 start;sudo service mysql start
firefox $name.local > /dev/null &
EOF
		chmod +x /usr/bin/$name
    		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install drupal
	if [ ! -d "/var/www/drupal" ]; then
		name="drupal"
		service apache2 start;service mysql start
		wget https://www.drupal.org/download-latest/zip -O /tmp/$name.zip
		unzip /tmp/$name.zip -d /var/www;rm -f /tmp/$name.zip
		mv -f /var/www/drupal-* /var/www/drupal
		chown -R www-data:www-data /var/www/$name;chmod -R 755 /var/www/$name
		cat > /etc/apache2/sites-available/$name.conf << EOF
<VirtualHost *:80>
    ServerAdmin admin@$name.local
    DocumentRoot /var/www/$name
    ServerName $name.local
    ServerAlias www.$name.local

    <Directory /var/www/$name>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/$name_error.log
    CustomLog \${APACHE_LOG_DIR}/$name_access.log combined
</VirtualHost>
EOF
		cd /etc/apache2/sites-available
		a2ensite $name.conf;a2enmod rewrite
		systemctl restart apache2
		echo "127.0.0.1   $name.local" >> /etc/hosts
		# Initialize MySQL
		mysql -f -s -u root -h localhost -e "
    CREATE DATABASE ${name}_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER '${name}_usr'@'localhost' IDENTIFIED BY '00980098';
    GRANT ALL PRIVILEGES ON ${name}_db.* TO '${name}_usr'@'localhost';
    FLUSH PRIVILEGES;
    EXIT;"
		cat > /usr/bin/$name << EOF
#!/bin/bash
sudo service apache2 start;sudo service mysql start
firefox $name.local > /dev/null &
EOF
		chmod +x /usr/bin/$name
    		menu_entry "Preliminary-Audit-Assessment" "Security-Audit" "$name" "$exec_shell '$name -h'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -------------------------------Performing-the-Review-Security-Audit-------------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	performing_the_review_pip="ruff"
	pip_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_pip"

	# install Nodejs NPM
	# performing_the_review_npm=""
	npm_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_npm"

	# install Ruby GEM
	performing_the_review_gem="rubocop"
	gem_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_gem"

	# install Golang
	# performing_the_review_golang=""
	go_installer "Performing-the-Review" "Security-Audit" "$performing_the_review_golang"

	# install postman
	if [ ! -d "/usr/share/Postman" ]; then
		name="Postman"
		mkdir -p /usr/share/$name
		wget https://dl.pstmn.io/download/latest/linux_64 -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/Postman /usr/bin/postman
		chmod +x /usr/bin/$name
		menu_entry "Web" "Penetration-Testing" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install graphql-playground
	if [ ! -d "/usr/share/graphql-playground" ]; then
		name="graphql-playground"
		mkdir -p /usr/share/$name
		wget https://github.com/graphql/graphql-playground/releases/latest/download/graphql-playground-electron_1.8.10_amd64.deb -O /tmp/$name.deb
		chmod +x /tmp/$name.deb;dpkg -i /tmp/$name.deb;rm -f /tmp/$name.deb
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install driftctl
	if [ ! -d "/usr/share/driftctl" ]; then
		name="driftctl"
		mkdir -p /usr/share/$name
		wget https://github.com/snyk/driftctl/releases/latest/download/driftctl_linux_amd64 -O /usr/share/$name/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/$name /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install clairctl
	if [ ! -d "/usr/share/clairctl" ]; then
		name="clairctl"
		mkdir -p /usr/share/$name
		wget https://github.com/jgsqware/clairctl/releases/latest/download/clairctl-linux-amd64 -O /usr/share/$name/$name
		chmod 755 /usr/share/$name/*
		ln -fs /usr/share/$name/$name /usr/bin/$name
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "$exec_shell '$name'"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install clion
	if [ ! -d "/usr/share/clion" ]; then
		name="clion"
		mkdir -p /usr/share/$name
		wget https://download-cdn.jetbrains.com/cpp/CLion-2024.1.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/bin/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;bash clion.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "/usr/bin/$name"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install phpstorm
	if [ ! -d "/usr/share/phpstorm" ]; then
		name="phpstorm"
		mkdir -p /usr/share/$name
		wget https://download-cdn.jetbrains.com/webide/PhpStorm-2024.1.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/bin/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;bash phpstorm.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "/usr/bin/$name"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install goland
	if [ ! -d "/usr/share/goland" ]; then
		name="goland"
		mkdir -p /usr/share/$name
		wget https://download-cdn.jetbrains.com/go/goland-2024.1.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/bin/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;bash goland.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "/usr/bin/$name"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install pycharm
	if [ ! -d "/usr/share/pycharm" ]; then
		name="pycharm"
		mkdir -p /usr/share/$name
		wget https://download-cdn.jetbrains.com/python/pycharm-professional-2024.1.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/bin/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;bash pycharm.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "/usr/bin/$name"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install webstorm
	if [ ! -d "/usr/share/webstorm" ]; then
		name="webstorm"
		mkdir -p /usr/share/$name
		wget https://download-cdn.jetbrains.com/webstorm/WebStorm-2024.1.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/bin/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;bash webstorm.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "/usr/bin/$name"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install idea
	if [ ! -d "/usr/share/idea" ]; then
		name="idea"
		mkdir -p /usr/share/$name
		wget https://download-cdn.jetbrains.com/idea/ideaIU-2024.1.tar.gz -O /tmp/IDE$name.tar.gz
		tar --strip-components=1 -xvf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name/bin;bash idea.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		menu_entry "Performing-the-Review" "Security-Audit" "$name" "/usr/bin/$name"
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi


	printf "$YELLOW"  "# -----------------------------Preparing-the-Audit-Report-Security-Audit----------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# preparing_the_audit_report_pip=""
	pip_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_pip"

	# install Nodejs NPM
	# preparing_the_audit_report_npm=""
	npm_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_npm"

	# install Ruby GEM
	# preparing_the_audit_report_gem=""
	gem_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_gem"

	# install Golang
	# preparing_the_audit_report_golang=""
	go_installer "Preparing-the-Audit-Report" "Security-Audit" "$preparing_the_audit_report_golang"


	printf "$YELLOW"  "# ------------------------------Issuing-the-Review-Report-Security-Audit----------------------------- #"

	# install Repository Tools
	# apt install -qy 

	# install Python3 pip
	# issuing_the_review_report_pip=""
	pip_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_pip"

	# install Nodejs NPM
	# issuing_the_review_report_npm=""
	npm_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_npm"

	# install Ruby GEM
	# issuing_the_review_report_gem=""
	gem_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_gem"

	# install Golang
	# issuing_the_review_report_golang=""
	go_installer "Issuing-the-Review-Report" "Security-Audit" "$issuing_the_review_report_golang"

	exit
}


main()
{
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		case "$ID" in
			kali)
				# exec env
				exec_shell="/usr/share/kali-menu/exec-in-shell"

				# debian repo added
				if ! grep -q "deb.debian.org/debian" /etc/apt/sources.list; then
					echo "deb http://deb.debian.org/debian buster main" | tee -a /etc/apt/sources.list
					apt update
				fi

				# microsoft repo added
				if [ ! -f "/etc/apt/sources.list.d/microsoft-prod.list" ]; then
					wget -qO- https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
					wget -q https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
					chmod +x /tmp/packages-microsoft-prod.deb;dpkg -i /tmp/packages-microsoft-prod.deb;rm -f /tmp/packages-microsoft-prod.deb
					echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list
					apt update
				fi

				# install dependencies
				apt install -qy libtool libpcap-dev libnetfilter libapache2-modsecurity libapache2-mod-security2 libzzip-0-13 libgs-common libtool-bin libplist-dev libimobiledevice-dev libzip-dev python3-dev python3-pip python3-poetry python3-scapy php-common php-xml php-curl php-gd php-imagick php-cli php-dev php-imap php-mbstring php-intl php-mysql php-zip php-json php-bcmath php-fpm php-soap php-xmlrpc libapache2-mod-php libcairo2-dev libjpeg-turbo8-dev libpng-dev libossp-uuid-dev libavcodec-dev libavformat-dev libswscale-dev libfreerdp2-dev libpango1.0-dev libssh2-1-dev libvncserver-dev libpulse-dev libssl-dev libvorbis-dev libwebp-dev

				# install init
				apt install -qy gnome-terminal pkg-config dnsutils apt-utils build-essential pkg-config mingw-w64 automake autoconf cmake swfmill default-jdk apache2 mariadb-server php python3 python3-full pypy3-venv python2 g++ nodejs npm rustup clang nim golang golang-go nasm qtchooser jq ffmpeg docker.io gcc docker-compose xxd mono-complete mono-devel tor obfs4proxy polipo proxychains p7zip p7zip-full zipalign wine winetricks winbind rar cmatrix remmina htop nload vlc bleachbit filezilla thunderbird code dotnet-sdk-6.0 open-vm-tools pngcrush imagemagick exiftool exiv2 usbmuxd snmp snmp-mibs-downloader rlwrap tomcat9 

				# install Python2 pip
				if [ ! -f "/usr/local/bin/pip2" ]; then
					wget https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py;python2.7 /tmp/get-pip.py;rm -f /tmp/get-pip.py;apt reinstall -qy python3-pip
				fi

				# upgrade pips
				pip2 install --upgrade pip;pip3 install --upgrade pip --break-system-packages
				;;
			ubuntu)
				# exec env
				exec_shell="/usr/share/ubuntu-menu/exec-in-shell"

				# debian repo added
				if ! grep -q "deb.debian.org/debian" /etc/apt/sources.list; then
					echo "deb http://deb.debian.org/debian buster main" | tee -a /etc/apt/sources.list
					apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 648ACFD622F3D138 0E98404D386FA1D9 DCC9EFBF77E11517
					apt update
				fi

				# microsoft repo added
				if [ ! -f "/etc/apt/sources.list.d/microsoft-prod.list" ]; then
					wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
					wget -q https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
					chmod +x /tmp/packages-microsoft-prod.deb;dpkg -i /tmp/packages-microsoft-prod.deb;rm -f /tmp/packages-microsoft-prod.deb
					echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list
					apt update
				fi

				# kali repo added
				if [ ! -f "/etc/apt/sources.list.d/kali.list" ]; then
					curl -fsSL https://archive.kali.org/archive-key.asc | tee /etc/apt/trusted.gpg.d/kali-archive-keyring.asc
					echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" | tee /etc/apt/sources.list.d/kali.list
					apt-get -y --allow-unauthenticated install kali-archive-keyring;apt update
				fi

				# install dependencies
				apt install -qy libtool libpcap-dev libnetfilter libapache2-modsecurity libapache2-mod-security2 libzzip-0-13 libgs-common libtool-bin libplist-dev libimobiledevice-dev libzip-dev python3-dev python3-pip python3-poetry python3-scapy php-common php-xml php-curl php-gd php-imagick php-cli php-dev php-imap php-mbstring php-intl php-mysql php-zip php-json php-bcmath php-fpm php-soap php-xmlrpc libapache2-mod-php libcairo2-dev libjpeg-turbo8-dev libpng-dev libossp-uuid-dev libavcodec-dev libavformat-dev libswscale-dev libfreerdp2-dev libpango1.0-dev libssh2-1-dev libvncserver-dev libpulse-dev libssl-dev libvorbis-dev libwebp-dev

				# install init
				apt install -qy gnome-terminal pkg-config apt-utils build-essential pkg-config mingw-w64 automake autoconf cmake swfmill default-jdk apache2 mariadb-server php python3 python3-full python2 pypy3-venv g++ nodejs npm clang golang golang-go nasm qtchooser jq ffmpeg docker.io gcc docker-compose mono-complete xxd mono-devel p7zip tor obfs4proxy polipo proxychains p7zip p7zip-full zipalign wine winetricks winbind rar cmatrix remmina htop nload vlc bleachbit filezilla thunderbird code dotnet-sdk-6.0 open-vm-tools pngcrush imagemagick exiftool exiv2 usbmuxd snmp snmp-mibs-downloader rlwrap tomcat9 
    
				# install snap
				snap install powershell --classic;snap install rustup --classic

				# install Python2 pip
				if [ ! -f "/usr/local/bin/pip2" ]; then
					wget https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py;python2.7 /tmp/get-pip.py;rm -f /tmp/get-pip.py;apt reinstall -qy python3-pip
				fi

				# upgrade pips
				pip2 install --upgrade pip;pip3 install --upgrade pip
				;;
			*) echo "Unsupported OS detected: $ID";exit;;
		esac
	else
		echo "/etc/os-release file not found. Cannot determine the OS.";exit
	fi

	# install Python2 pip
	pip2 install setuptools env pipenv wheel requests colorama 

	# install Python3 pip
	pip3 install --break-system-packages setuptools env pipenv wheel colorama pysnmp termcolor pypdf2 cprint pycryptodomex requests gmpy2 win_unicode_console python-nmap python-whois capstone dnslib couchdb poetry python-magic py7zr pyminizip anytree pypsrp 

	# install nodejs NPM
	# npm install -g 

	# install ruby GEM
	# gem install 

	# install linux-elite
	if [ ! -d "/usr/share/linux-elite" ]; then
		name="linux-elite"
		mkdir -p /usr/share/$name
		curl -s -o /usr/share/$name/$name.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/linux-elite.sh
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash $name.sh "\$@"
EOF
		chmod +x /usr/bin/$name

		# Create the .desktop file for the tool
		cat > "$APPLICATIONS_PATH/Unk9vvN/$name.desktop" << EOF
[Desktop Entry]
Name=$name
Exec=$exec_shell "sudo $name"
Comment=unk9vvn.github.io
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF

		# Add Include and Layout to the menu XML file
		xmlstarlet ed \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']" -t elem -n "Include" -v "" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']/Include" -t elem -n "Filename" -v "${tool}.desktop" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']" -t elem -n "Layout" -v "" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']/Layout" -t elem -n "Merge" -v "" \
		   -i "/Menu/Menu/Menu[Name='Unk9vvN']/Layout/Merge" -t attr -n "type" -v "menus" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']/Layout" -t elem -n "Merge" -v "" \
		   -i "/Menu/Menu/Menu[Name='Unk9vvN']/Layout/Merge[last()]" -t attr -n "type" -v "files" \
		   "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
		   mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"
		printf "$GREEN"  "[*] Successfully Installed $name"
	elif [ "$(curl -s https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/version)" != $ver ]; then
		name="linux-elite"
		curl -s -o /usr/share/$name/$name.sh https://raw.githubusercontent.com/unk9vvn/unk9vvn.github.io/main/linux-elite.sh
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash $name.sh "\$@"
EOF
		chmod +x /usr/bin/$name

		# Create the .desktop file for the tool
		cat > "$APPLICATIONS_PATH/Unk9vvN/$name.desktop" << EOF
[Desktop Entry]
Name=$name
Exec=$exec_shell "sudo $name"
Comment=unk9vvn.github.io
Terminal=true
Icon=gnome-panel-launcher
Type=Application
EOF

		# Add Include and Layout to the menu XML file
		xmlstarlet ed \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']" -t elem -n "Include" -v "" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']/Include" -t elem -n "Filename" -v "${tool}.desktop" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']" -t elem -n "Layout" -v "" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']/Layout" -t elem -n "Merge" -v "" \
		   -i "/Menu/Menu/Menu[Name='Unk9vvN']/Layout/Merge" -t attr -n "type" -v "menus" \
		   -s "/Menu/Menu/Menu[Name='Unk9vvN']/Layout" -t elem -n "Merge" -v "" \
		   -i "/Menu/Menu/Menu[Name='Unk9vvN']/Layout/Merge[last()]" -t attr -n "type" -v "files" \
		   "$CONFIG_MENU_PATH/xfce-applications.menu" > "$CONFIG_MENU_PATH/xfce-applications.tmp" && \
		   mv "$CONFIG_MENU_PATH/xfce-applications.tmp" "$CONFIG_MENU_PATH/xfce-applications.menu"
		printf "$GREEN"  "[*] Successfully Updating $name"
		bash /usr/share/$name/$name.sh
	fi
}


menu
main
logo


select opt in "Penetrating-Testing" "Red-Team" "ICS-Security" "Digital-Forensic" "Blue-Team" "Security-Audit" Exit
do
	case $opt in
		"Penetrating-Testing")
			printf "$GREEN"  "[*] Running Penetrating-Testing..."
			penetrating_testing;;
		"Red-Team")
			printf "$GREEN"  "[*] Running Red-Team..."
			red_team;;
		"ICS-Security")
			printf "$GREEN"  "[*] Running ICS-Security..."
			ics_security;;
		"Digital-Forensic")
			printf "$GREEN"  "[*] Running Digital-Forensic..."
			digital_forensic;;
		"Blue-Team")
			printf "$GREEN"  "[*] Running Blue-Team..."
			blue_team;;
		"Security-Audit")
			printf "$GREEN"  "[*] Running Security-Audit..."
			security_audit;;
		"Exit")
			echo "Exiting..."
			break;;
		*) echo "invalid option...";;
	esac
done
