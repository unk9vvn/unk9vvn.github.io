#!/bin/bash
ver='5.4'




RED="\e[1;31m%s\e[0m\n"
GREEN="\e[1;32m%s\e[0m\n"
YELLOW="\e[1;33m%s\e[0m\n"
BLUE="\e[1;34m%s\e[0m\n"
MAGENTO="\e[1;35m%s\e[0m\n"
CYAN="\e[1;36m%s\e[0m\n"
WHITE="\e[1;37m%s\e[0m\n"
TOKEN=$1



if [ "$(id -u)" != "0" ]; then
    printf "$RED"       "[X] Please Run as root Script..."
    printf "$GREEN"     "sudo chmod +x ~/installer.sh;sudo bash ~/installer.sh \$TOKEN"
    exit 0
elif [ -z "$1" ]; then
    printf "$RED"       "[X] The first argument has not Token Github HermaVIP..."
    printf "$GREEN"     "sudo chmod +x ~/installer.sh;sudo bash ~/installer.sh \$TOKEN"
    exit 0
else
    OS=`uname -m`
    INTERFACE=$(ip r | head -1 | cut -d " " -f5)
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    LHOST=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    RHOST=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
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
    printf "$YELLOW"  "                              www.unk9vvn.com                       "
    printf "$CYAN"    "                                unk9vps "$ver"                      "
    printf "\n\n"
}


oepnvpn ()
{
    # Find out if the machine uses nogroup or nobody for the permissionless group
    if grep -qs "^nogroup:" /etc/group; then
        NOGROUP=nogroup
    else
        NOGROUP=nobody
    fi

    # configure unbound
    cat > /etc/unbound/unbound.conf << EOF
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
EOF
    systemctl enable unbound;systemctl restart unbound

    # initialize openvpn
    mkdir -p /etc/openvpn/ccd;mkdir -p /var/log/openvpn
    mkdir -p /etc/openvpn/lab_profile;touch /etc/openvpn/ipp.txt
    echo "set_var EASYRSA_ALGO ec" > /usr/share/easy-rsa/vars
    echo "set_var EASYRSA_CURVE prime256v1" >> /usr/share/easy-rsa/vars

    # confiqure easy-rsa
    cd /usr/share/easy-rsa
    easyrsa init-pki
    easyrsa --batch --req-cn="unk9vvn" build-ca nopass
    easyrsa --batch build-server-full "unk9vvn" nopass
    EASYRSA_CRL_DAYS=7 easyrsa gen-crl
    openvpn --genkey secret /etc/openvpn/tls-crypt.key
    cp -f /usr/share/easy-rsa/pki/ca.crt /usr/share/easy-rsa/pki/private/ca.key /usr/share/easy-rsa/pki/issued/unk9vvn.crt /usr/share/easy-rsa/pki/private/unk9vvn.key /usr/share/easy-rsa/pki/crl.pem /etc/openvpn
    chmod 644 /etc/openvpn/crl.pem;chown -R www-data:www-data /etc/openvpn

    # configure server.conf
    cat > /etc/openvpn/server.conf << EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "redirect-gateway def1 bypass-dhcp"
dh none
ecdh-curve prime256v1
tls-crypt tls-crypt.key
crl-verify crl.pem
ca ca.crt
cert unk9vvn.crt
key unk9vvn.key
auth SHA256
cipher AES-128-GCM
ncp-ciphers AES-128-GCM
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3
EOF
    # configure client.txt
    cat > /etc/openvpn/client-temp.txt << EOF
client
proto udp
explicit-exit-notify
remote $RHOST 1194
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name unk9vvn name
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3
EOF
    # Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf

    # Apply sysctl rules
	sysctl --system

	# Don't modify package-provided service
	cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

	# Workaround to fix OpenVPN service on OpenVZ
	sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service

	# Another workaround to keep using /etc/openvpn/
	sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

	systemctl daemon-reload
	systemctl enable openvpn@server;systemctl restart openvpn@server

    # Add iptables rules in two scripts
	mkdir -p /etc/iptables

	# Script to add rules
    cat > /etc/iptables/add-openvpn-rules.sh << EOF
#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p udp --dport 1194 -j ACCEPT
EOF
	# Script to remove rules
    cat > /etc/iptables/rm-openvpn-rules.sh << EOF
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p udp --dport 1194 -j ACCEPT
EOF
	chmod +x /etc/iptables/add-openvpn-rules.sh
    chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
    cat > /etc/systemd/system/iptables-openvpn.service << EOF
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn;systemctl start iptables-openvpn

    # script to addrule
    cat > /etc/openvpn/addrule.sh << EOF
#!/bin/bash

IP="\$1"
PORT="\$2"

iptables -I INPUT \! -s \$IP -m tcp -p tcp --dport \$PORT -j DROP
EOF
    # script to remove user
    cat > /etc/openvpn/removerule.sh << EOF
#!/bin/bash

IP="\$1"
PORT="\$2"

iptables -D INPUT \! -s \$IP -m tcp -p tcp --dport \$PORT -j DROP
EOF
    # script to adduser
    cat > /etc/openvpn/adduser.sh << EOF
#!/bin/bash

CLIENT="\$1"

CLIENTEXISTS=\$(tail -n +2 /usr/share/easy-rsa/pki/index.txt | grep -c -E "/CN=\$CLIENT\$")

if [[ \$CLIENTEXISTS == '1' ]]; then
    echo "Existed User"
    exit
else
    cd /usr/share/easy-rsa
    easyrsa --batch build-client-full "\$CLIENT" nopass
    cp /etc/openvpn/client-temp.txt "/etc/openvpn/lab_profile/\$CLIENT.ovpn"
    {
	    echo "<ca>"
	    cat "/usr/share/easy-rsa/pki/ca.crt"
	    echo "</ca>"

	    echo "<cert>"
	    awk '/BEGIN/,/END CERTIFICATE/' "/usr/share/easy-rsa/pki/issued/\$CLIENT.crt"
	    echo "</cert>"

	    echo "<key>"
	    cat "/usr/share/easy-rsa/pki/private/\$CLIENT.key"
	    echo "</key>"

	    echo "<tls-crypt>"
	    cat /etc/openvpn/tls-crypt.key
	    echo "</tls-crypt>"
	} >> "/etc/openvpn/lab_profile/\$CLIENT.ovpn"
fi
EOF
    # script to revokeuser
    cat > /etc/openvpn/revokeuser.sh << EOF
#!/bin/bash

CLIENT="\$1"
CLIENTEXISTS=\$(tail -n +2 /usr/share/easy-rsa/pki/index.txt | grep -c -E "/CN=\$CLIENT\$")

if [[ \$CLIENTEXISTS == '1' ]]; then
    CLIENT=\$(tail -n +2 /usr/share/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "\$CLIENTNUMBER"p)
    cd /usr/share/easy-rsa
    easyrsa --batch revoke "\$CLIENT"
    EASYRSA_CRL_DAYS=7 easyrsa gen-crl
    rm -f /etc/openvpn/crl.pem
    cp /usr/share/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
    find /etc/openvpn/lab_profile/ -maxdepth 2 -name "\$CLIENT.ovpn" -delete
    rm -f "/etc/openvpn/lab_profile/\$CLIENT.ovpn"
    sed -i "/^\$CLIENT,.*/d" /etc/openvpn/ipp.txt
    cp /usr/share/easy-rsa/pki/index.txt{,.bk}
    echo "Success Revoked User"
else
    echo "Not Exist User"
fi
EOF
    # Sudo ENV
    if ! grep -q "addrule.sh" /etc/sudoers; then
        echo "www-data ALL=(ALL:ALL) NOPASSWD: /etc/openvpn/addrule.sh" >> /etc/sudoers
    elif ! grep -q "removerule.sh" /etc/sudoers; then
        echo "www-data ALL=(ALL:ALL) NOPASSWD: /etc/openvpn/removerule.sh" >> /etc/sudoers
    elif ! grep -q "adduser.sh" /etc/sudoers; then
        echo "www-data ALL=(ALL:ALL) NOPASSWD: /etc/openvpn/adduser.sh" >> /etc/sudoers
    elif ! grep -q "revokeuser.sh" /etc/sudoers; then
        echo "www-data ALL=(ALL:ALL) NOPASSWD: /etc/openvpn/revokeuser.sh" >> /etc/sudoers
    fi

    bash /etc/openvpn/adduser.sh default
}


main ()
{
    # resolv fixed
    if ! grep -q "nameserver 8.8.8.8" /etc/resolv.conf; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    fi

    # apt fixed
    if grep -q "ir.archive.ubuntu.com" /etc/apt/sources.list; then
        sed -i "s|ir.archive.ubuntu.com|archive.ubuntu.com|g" /etc/apt/sources.list
    fi

    # Initialize hostname
    if ! grep -q "lab" /etc/hostname; then
        echo "lab" > /etc/hostname
    fi

    # Update & Upgrade OS
	apt update;apt upgrade -qy;apt dist-upgrade -qy;apt autoclean

    # Install Tools
    apt install -qy ssh wget git gnupg curl apt-transport-https ca-certificates software-properties-common ghostscript ufw mlocate htop unbound tcptrack nload iftop bzip2 gzip coreutils speedtest-cli net-tools lsof nano dnsutils cron zip unzip p7zip-full python2 geoip-database certbot python3-certbot-apache mysql-server php-mysql apache2 libapache2-mod-geoip haproxy sniproxy socat fail2ban at dos2unix docker.io

    # Install OpenVPN
    apt install -qy openvpn easy-rsa iptables openssl
    ln -fs /usr/share/easy-rsa/easyrsa /usr/bin/easyrsa

    # Set Time Zone
    timedatectl set-timezone Asia/Tehran

    # Initialize SSH root Login
    if ! grep -q "prohibit-password" /etc/ssh/sshd_config; then
        sed -i "s|#PermitRootLogin prohibit-password|PermitRootLogin yes|g" /etc/ssh/sshd_config
        service ssh restart;service sshd restart
    fi

    # Install PHP
    if [ ! -f "/usr/bin/php" ]; then
        add-apt-repository -y ppa:ondrej/php;apt update
        apt install -y php php-common php-xml php-curl php-gd php-imagick php-cli php-dev php-imap php-mbstring php-intl php-mysql php-zip php-json php-bcmath php-fpm php-soap php-xmlrpc libapache2-mod-php 
        update-alternatives --set php /usr/bin/php
    fi

    # Initialize fail2ban
    if [ ! -f "/etc/fail2ban/jail.local" ]; then
        cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 10
findtime = 10m
bantime = 60m
ignoreip = 127.0.0.1/8 ::1
EOF
        systemctl daemon-reload
        systemctl enable fail2ban;systemctl start fail2ban
    fi

    # Initialize Webserver
    if ! grep -q "AllowOverride All" /etc/apache2/apache2.conf; then
        a2enmod rewrite;a2enmod geoip
        sed -i "s|AllowOverride None|AllowOverride All|g" /etc/apache2/apache2.conf
        service apache2 restart
        usermod -aG docker $USER;usermod -aG docker www-data;systemctl start docker
        curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
        export COMPOSER_ALLOW_SUPERUSER=1; composer show
        cat > /tmp/Dockerfile << EOF
FROM ubuntu:latest

# SAMBA
RUN apt-get update && apt-get install -y samba
RUN mkdir -p /var/samba/share
RUN chmod -R 0755 /var/samba/share
RUN chown -R nobody:nogroup /var/samba/share
RUN echo "[Share]\n\
   path = /var/samba/share\n\
   browsable = yes\n\
   guest ok = yes\n\
   read only = yes\n\
   create mask = 0755" >> /etc/samba/smb.conf \

RUN mkdir /app/

WORKDIR /app

RUN echo "#!/bin/bash\n\
smbd \n\
mkdir /app/test \n\
while true; do sleep 1; done" > /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 445

VOLUME ["/var/samba/share"]

## Run entrypoint.sh when the container launches
ENTRYPOINT ["/app/entrypoint.sh"]
EOF
        cd /tmp;docker build -t smb:latest .
        sleep 2
        cat > /tmp/Dockerfile << EOF
FROM php:apache
RUN sed -i '/LoadModule rewrite_module/s/^#//g' /etc/apache2/sites-available/*.conf && \
    sed -i 's#AllowOverride [Nn]one#AllowOverride All#' /etc/apache2/sites-available/*.conf && \
    sed -i 's|ErrorLog \${APACHE_LOG_DIR}/error.log|ErrorLog /var/www/html/error.log|' /etc/apache2/sites-available/*.conf

RUN docker-php-ext-install mysqli

RUN apt install certbot

RUN a2enmod rewrite
EOF
        cd /tmp;docker build -t php:custom .
    fi

    # Install vps.unk9vvn.com
    if [ ! -d "/usr/share/unk9vps" ]; then
        local name="unk9vps"
        cd /var/www/html;rm -rf *
        git clone https://a9v8i:$TOKEN@github.com/unk9vvn/vps.unk9vvn.com /usr/share/$name
        chmod 755 /usr/share/$name/*;cd /usr/share/$name;mv -f * /var/www/html
        cd /var/www/html;composer update
        chown -R www-data:www-data /var/www/html/
        service apache2 restart
        cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash installer.sh "\$@"
EOF
        chmod +x /usr/bin/$name
    elif [ "$(curl -s https://a9v8i:$TOKEN@raw.githubusercontent.com/unk9vvn/vps.unk9vvn.com/main/version)" !=$ver ]; then
        local name="unk9vps"
        cd /var/www/html;rm -rf *
        git clone https://a9v8i:$TOKEN@github.com/unk9vvn/vps.unk9vvn.com /usr/share/$name
        chmod 755 /usr/share/$name/*;cd /usr/share/$name;mv -f * /var/www/html
        cd /var/www/html;composer update
        chown -R www-data:www-data /var/www/html/
        service apache2 restart
        cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash installer.sh "\$@"
EOF
        chmod +x /usr/bin/$name
        bash /usr/share/$name/installer.sh
    fi

    oepnvpn
}


logo
main
