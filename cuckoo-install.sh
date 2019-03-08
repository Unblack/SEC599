#!/bin/bash
# CuckooAutoInstall
# Copyright (C) 2014-2015 David Reguera García - dreg@buguroo.com David Francos Cuartero - dfrancos@buguroo.com
# Copyright (C) 2017-2018 Erik Van Buggenhout & Didier Stevens - NVISO
# 2018-2019 SlipperyClock
# 2019 Unblack

source /etc/os-release

# Configuration variables. Tailor to your environment
CUCKOO_GUEST_IMAGE="/tmp/vm.ova"
CUCKOO_GUEST_NAME="vm"
CUCKOO_GUEST_IP="192.168.56.101"
INTERNET_INT_NAME="eth0"
VOLATILITY_VERSION_LONG="volatility-2.6"
VOLATILITY_VERSION_SHORT="2.6"
START_SCRIPT="/root/cuckoo-start.sh"
KILL_SCRIPT="/root/cuckoo-kill.sh"
CONFIG_SCRIPTS_DIR="/opt/cuckoo-configs"

# Base variables. Only change these if you know what you are doing...
SUDO="sudo"
TMPDIR=$(mktemp -d)
RELEASE=$(lsb_release -cs)
CUCKOO_USER="cuckoo"
CUCKOO_PASSWD="cuckoo"
CUSTOM_PKGS="tor libguac-client-rdp0 libguac-client-vnc0 libguac-client-ssh0 guacd"
ORIG_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )
VOLATILITY_URL="http://downloads.volatilityfoundation.org/releases/$VOLATILITY_VERSION_SHORT/$VOLATILITY_VERSION_LONG.zip"
YARA_REPO="https://github.com/plusvic/yara"

VIRTUALBOX_REP="deb http://download.virtualbox.org/virtualbox/debian $RELEASE contrib"

VIRTUALBOX_INT_NAME="vboxnet0"
VIRTUALBOX_INT_NETWORK="192.168.56.0/24"
VIRTUALBOX_INT_ADDR="192.168.56.1"
VIRTUALBOX_INT_SUBNET="255.255.255.0"

LOG=$(mktemp)
UPGRADE=true

declare -a packages
declare -a python_packages

packages="git python python-pip libffi-dev libssl-dev python-virtualenv python-setuptools libjpeg-dev zlib1g-dev swig postgresql libpq-dev tcpdump apparmor-utils libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.6-dev tk8.6-dev python-tk build-essential libssl-dev libffi-dev python-dev libssl-dev libjansson-dev virtualbox mongodb libfuzzy-dev"
#python_packages="pip setuptools cuckoo distorm3 yara-python"
python_packages="pip setuptools cuckoo distorm3 yara-python==3.6.3 pycrypto ssdeep pydeep weasyprint==0.36"

# Pretty icons
log_icon="\e[31m✓\e[0m"
log_icon_ok="\e[32m✓\e[0m"
log_icon_nok="\e[31m✗\e[0m"

# -

print_copy(){
cat <<EO
┌─────────────────────────────────────────────────────────┐
│                CuckooAutoInstall 0.2 - NVISO Mod        │
│ David Reguera García - Dreg <dreguera@buguroo.com>      │
│ David Francos Cuartero - XayOn <dfrancos@buguroo.com>   │
│ Erik Van Buggenhout - <evanbuggenhout@nviso.be>         |
│ Didier Stevens - <dstevens@nviso.be                     |
│            Buguroo Offensive Security - 2015            │
│            NVISO - 2017-2018                            │
│            Slipperyclock - 2018-2019                    │
└─────────────────────────────────────────────────────────┘
EO
}

check_viability(){
    [[ $UID != 0 ]] && {
        type -f $SUDO || {
            echo "You're not root and you don't have $SUDO, please become root or install $SUDO before executing $0"
            exit
        }
    } || {
        SUDO=""
    }

    [[ ! -e /etc/debian_version ]] && {
        echo  "This script currently works only on debian-based (debian, ubuntu...) distros"
        exit 1
    }
}

print_help(){
    cat <<EOH
Usage: $0 [--verbose|-v] [--help|-h] [--upgrade|-u]

    --verbose   Print output to stdout instead of temp logfile
    --help      This help menu
    --upgrade   Use newer volatility, yara and jansson versions (install from source)

EOH
    exit 1
}

setopts(){
    optspec=":hvu-:"
    while getopts "$optspec" optchar; do
        case "${optchar}" in
            -)
                case "${OPTARG}" in
                    help) print_help ;;
                    upgrade) UPGRADE=true ;;
                    verbose) LOG=/dev/stdout ;;
                esac;;
            h) print_help ;;
            v) LOG=/dev/stdout;;
            u) UPGRADE=true;;
        esac
    done
}

run_and_log(){
    $1 &> ${LOG} && {
        _log_icon=$log_icon_ok
    } || {
        _log_icon=$log_icon_nok
        exit_=1
    }
    echo -e "${_log_icon} ${2}"
    [[ $exit_ ]] && { echo -e "\t -> ${_log_icon} $3";  exit; }
}

clone_repos(){
    git clone ${YARA_REPO}
    return 0
}

cdcuckoo(){
    eval cd ~${CUCKOO_USER}
    return 0
}

create_cuckoo_user(){
#    $SUDO adduser  -gecos "" ${CUCKOO_USER}
#    $SUDO echo ${CUCKOO_PASSWD} | passwd ${CUCKOO_USER} --stdin
    $SUDO adduser --disabled-login -gecos "" ${CUCKOO_USER}
    echo -e "${CUCKOO_PASSWD}\n${CUCKOO_PASSWD}" | $SUDO passwd ${CUCKOO_USER}
    $SUDO usermod -G vboxusers ${CUCKOO_USER}
    $SUDO mkdir $CONFIG_SCRIPTS_DIR
    return 0
}

create_hostonly_iface(){
    FOUND=`grep "vboxnet0" /proc/net/dev`

    if  [ -n "$FOUND" ] ; then
    echo "vboxnet0 already exists"
    else
    echo "vboxnet0 doesn't exist, creating it..."
    $SUDO vboxmanage hostonlyif create
    fi
    $SUDO vboxmanage dhcpserver modify --ifname $VIRTUALBOX_INT_NAME --disable
    $SUDO vboxmanage hostonlyif ipconfig $VIRTUALBOX_INT_NAME --ip $VIRTUALBOX_INT_ADDR --netmask $VIRTUALBOX_INT_SUBNET
    $SUDO iptables -A FORWARD -o $INTERNET_INT_NAME -i $VIRTUALBOX_INT_NAME -s $VIRTUALBOX_INT_NETWORK -m conntrack --ctstate NEW -j ACCEPT
    $SUDO iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $SUDO iptables -A POSTROUTING -t nat -j MASQUERADE

    $SUDO sysctl -w net.ipv4.ip_forward=1
  return 0
}

allow_tcpdump(){
    $SUDO /bin/bash -c 'setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump' 2 &> /dev/null
    $SUDO aa-disable /usr/sbin/tcpdump
    return 0
}

build_yara(){
    cd ${TMPDIR}/yara
    ./bootstrap.sh
    $SUDO autoreconf -vi --force
    ./configure --enable-cuckoo --enable-magic
    make
    $SUDO make install
    cd yara-python/
    $SUDO python setup.py install
    cd ${TMPDIR}
    return 0
}

build_volatility(){
    wget $VOLATILITY_URL
    unzip $VOLATILITY_VERSION_LONG.zip -d $VOLATILITY_VERSION_LONG
    cd $VOLATILITY_VERSION_LONG/volatility-master/
    $SUDO python setup.py build
    $SUDO python setup.py install
    return 0
}

prepare_virtualbox(){
    cd ${TMPDIR}
    echo ${VIRTUALBOX_REP} |$SUDO tee /etc/apt/sources.list.d/virtualbox.list
    wget -O - https://www.virtualbox.org/download/oracle_vbox.asc | $SUDO apt-key add -
    wget -O - https://www.virtualbox.org/download/oracle_vbox_2016.asc | $SUDO apt-key add -
    pgrep virtualbox && return 1
    pgrep VBox && return 1 
    return 0
}

install_packages(){
    $SUDO apt-get update
    $SUDO apt-get install -y ${packages["${RELEASE}"]}
    $SUDO apt-get install -y $CUSTOM_PKGS
    $SUDO apt-get -y install 
    return 0
}

install_python_packages(){
    pip install $python_packages --upgrade
    return 0
}

run_cuckoo_community(){
    runuser -l $CUCKOO_USER -c 'cuckoo'
    runuser -l $CUCKOO_USER -c 'cuckoo community'
    return 0
}

# The imported virtualbox VM should have the following config:
# - VM Appliance Name: vm
# - Installed Python 2.7
# - Installed Cuckoo Agent
# - Installed Pillow ( to get screenshots )
# - Disabled UAC, AV, Updates, Firewall
# - Any other software that is to be installed
# - IP settings: 192.168.56.101 - 255.255.255.0 - GW:192.168.56.1 DNS:192.168.56.1

import_virtualbox_vm(){
    runuser -l $CUCKOO_USER -c "vboxmanage import ${CUCKOO_GUEST_IMAGE}"
    runuser -l $CUCKOO_USER -c "vboxmanage modifyvm ${CUCKOO_GUEST_NAME} --nic1 hostonly --hostonlyadapter1 ${VIRTUALBOX_INT_NAME}"
    return 0
}

launch_virtualbox_vm(){
    runuser -l $CUCKOO_USER -c "vboxmanage startvm ${CUCKOO_GUEST_NAME} --type headless"
    return 0
}

create_virtualbox_vm_snapshot(){
    runuser -l $CUCKOO_USER -c "vboxmanage snapshot ${CUCKOO_GUEST_NAME} take clean"
    return 0
}

poweroff_virtualbox_vm(){
    runuser -l $CUCKOO_USER -c "vboxmanage controlvm ${CUCKOO_GUEST_NAME} poweroff"
    sleep 30
    runuser -l $CUCKOO_USER -c "vboxmanage snapshot ${CUCKOO_GUEST_NAME} restorecurrent"
}

update_cuckoo_config(){
    # Update IP address of result server
    sed -i "s/192.168.56.1/${VIRTUALBOX_INT_ADDR}/g" /home/$CUCKOO_USER/.cuckoo/conf/cuckoo.conf
    sed -i "/\[remotecontrol\]\n\nenabled = no/{ N; s/.*/\[remotecontrol\]\n\nenabled = yes/; }" /home/$CUCKOO_USER/.cuckoo/conf/cuckoo.conf
    sed -i "s/192.168.56.1/${VIRTUALBOX_INT_ADDR}/g" /home/$CUCKOO_USER/.cuckoo/conf/routing.conf
    sed -i "s/whitelist_dns = no/whitelist_dns = yes/g" /home/$CUCKOO_USER/.cuckoo/conf/processing.conf
    sed -i "/\[virustotal\]/{ N; s/.*/\[virustotal\]\nenabled = yes/; }" /home/$CUCKOO_USER/.cuckoo/conf/processing.conf
    # Update VM settings
    sed -i "s/label = cuckoo1/label = ${CUCKOO_GUEST_NAME}/g" /home/$CUCKOO_USER/.cuckoo/conf/virtualbox.conf
    sed -i "s/ip = 192.168.56.101/ip = ${CUCKOO_GUEST_IP}/g" /home/$CUCKOO_USER/.cuckoo/conf/virtualbox.conf
    sed -i "/\[mongodb\]/{ N; s/.*/\[mongodb\]\nenabled = yes/; }" /home/$CUCKOO_USER/.cuckoo/conf/reporting.conf
    sed -i 's/"192.168.56.1"/"${VIRTUALBOX_INT_ADDR}"/g' /home/$CUCKOO_USER/.config/VirtualBox/VirtualBox.xml
    sed -i '/DHCPServer/d' /home/$CUCKOO_USER/.config/VirtualBox/VirtualBox.xml
    # Use default whitelist    
    echo 'wget https://raw.githubusercontent.com/Slipperyclock/SEC599/master/domain.txt -O /home/cuckoo/.cuckoo/whitelist/domain.txt' > /opt/cuckoo-configs/update_domain.sh
    chmod +x /opt/cuckoo-configs/update_domain.sh
    /opt/cuckoo-configs/update_domain.sh
    echo "@weekly root /opt/cuckoo-configs/update_domain.sh" >> /etc/crontab
    return 0
}

create_cuckoo_startup_scripts(){
    $SUDO rm $START_SCRIPT
    $SUDO rm $START_SCRIPT
    $SUDO echo "#!/bin/bash" >> $START_SCRIPT
    $SUDO echo "# Cuckoo run script" >> $START_SCRIPT
    $SUDO echo "#!/bin/bash" >> $KILL_SCRIPT
    $SUDO echo "# Cuckoo run script" >> $KILL_SCRIPT
    $SUDO echo "killall cuckoo" >> $START_SCRIPT
    $SUDO echo "pkill -f 'cuckoo web runserver'" >> $START_SCRIPT
    $SUDO echo "systemctl stop tor" >> $START_SCRIPT
    $SUDO echo "systemctl start tor" >> $START_SCRIPT
    $SUDO echo "cuckoo rooter -g cuckoo &" >> $START_SCRIPT
    $SUDO echo "vboxmanage dhcpserver modify --ifname $VIRTUALBOX_INT_NAME --disable" >> $START_SCRIPT
    $SUDO echo "vboxmanage hostonlyif ipconfig $VIRTUALBOX_INT_NAME --ip $VIRTUALBOX_INT_ADDR --netmask $VIRTUALBOX_INT_SUBNET" >> $START_SCRIPT
    $SUDO echo "iptables -A FORWARD -o $INTERNET_INT_NAME -i $VIRTUALBOX_INT_NAME -s $VIRTUALBOX_INT_NETWORK -m conntrack --ctstate NEW -j ACCEPT" >> $START_SCRIPT
    $SUDO echo "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" >> $START_SCRIPT
    $SUDO echo "iptables -A POSTROUTING -t nat -j MASQUERADE" >> $START_SCRIPT
    $SUDO echo "sysctl -w net.ipv4.ip_forward=1" >> $START_SCRIPT

    $SUDO echo "killall cuckoo" >> $KILL_SCRIPT
    $SUDO echo "pkill -f 'cuckoo web runserver'" >> $KILL_SCRIPT
    $SUDO echo "runuser -l cuckoo -c 'cuckoo' &" >> $START_SCRIPT
    $SUDO echo "runuser -l cuckoo -c 'cuckoo web runserver 0.0.0.0:8000' &" >> $START_SCRIPT
    $SUDO echo "runuser -l cuckoo -c 'cuckoo api --host 0.0.0.0 --port 8090' &" >> $START_SCRIPT

    $SUDO echo -e "\n@reboot root sleep 120; $START_SCRIPT &\n" >> /etc/crontab

    $SUDO chmod +x $START_SCRIPT
    $SUDO chmod +x $KILL_SCRIPT
}

disable_systemd_resolved(){
    #Disable and stop Systemd-Resolved
    systemctl disable systemd-resolved
    systemctl stop systemd-resolved
    
    #Create DNS set script
    echo "#!/bin/bash" > /opt/cuckoo-configs/dns_set.sh
    echo "rm /etc/resolv.conf">> /opt/cuckoo-configs/dns_set.sh
    echo 'echo "nameserver 1.1.1.1" > /etc/resolv.conf' >> /opt/cuckoo-configs/dns_set.sh
    echo 'echo "nameserver 1.0.0.1" >> /etc/resolv.conf' >> /opt/cuckoo-configs/dns_set.sh
    echo 'echo "#$(date)" >> /etc/resolv.conf' >> /opt/cuckoo-configs/dns_set.sh
    chmod +x /opt/cuckoo-configs/dns_set.sh
    
    /opt/cuckoo-configs/dns_set.sh 
    
    echo "*/15 * * * * root /opt/cuckoo-configs/dns_set.sh" >> /etc/crontab
    echo "@reboot root sleep 30; /opt/cuckoo-configs/dns_set.sh" >> /etc/crontab
    return 0
}

remote_port_script(){
	FILE=/opt/cuckoo-configs/ssh_remote_port.sh
	echo "#!/bin/bash" > $FILE
	echo "#Port to locally listening" >> $FILE
	echo "LOCALPORT=8000 " >> $FILE
	echo "#Port to listen to on remote system" >> $FILE
	echo "REMOTEPORT=8888 " >> $FILE
	echo "#Remote server ip/hostname" >> $FILE
	echo "REMOTESERVER=MYREMOTESERVER" >> $FILE
	echo "#Remote Server ssh port to connect to" >> $FILE
	echo "REMOTESERVERPORT=22" >> $FILE
	echo "#Remote user to login with" >> $FILE
	echo "USER=myusername" >> $FILE
	echo "ssh \$USER@\$REMOTESERVER -p \$REMOTESERVERPORT -N -f -R \$REMOTEPORT:127.0.0.1:\$LOCALPORT" >> $FILE
	chmod +x $FILE
	return 0
}

setup_tor(){
	echo "TransPort $VIRTUALBOX_INT_ADDR:9040" >> /etc/tor/torrc
	echo "DNSPort $VIRTUALBOX_INT_ADDR:5353" >> /etc/tor/torrc
	echo "TransPort $VIRTUALBOX_INT_ADDR:9040" >> /usr/share/tor/tor-service-defaults-torrc
	echo "DNSPort $VIRTUALBOX_INT_ADDR:5353" >> /usr/share/tor/tor-service-defaults-torrc
	sed -i " N;N;/\[tor\]\n/{ N; s/.*/\[tor\]\n\nenabled = yes/; }" /home/$CUCKOO_USER/.cuckoo/conf/routing.conf
	return 0
}

setup_suricata(){
	apt-get install software-properties-common -y
	apt-get install suricata -y
	chmod u+s /usr/bin/suricata
	# Set Processing.conf to enable Suricata
	sed -i "/\[suricata\]/{ N; s/.*/\[suricata\]\nenabled = yes/; }" /home/$CUCKOO_USER/.cuckoo/conf/processing.conf
	sed -i "s/  filename: \/var\/run\/suricata-command.socket/  filename: \/var\/run\/suricata\/cuckoo.socket/g" /etc/suricata/suricata.yaml
	sed -i "s/#run-as:/run-as:/" /etc/suricata/suricata.yaml
	sed -i "s/#  user: suri/  user: cuckoo/" /etc/suricata/suricata.yaml
	sed -i "s/#  user: suri/  user: cuckoo/" /etc/suricata/suricata.yaml
	sed -i "s/#  group: suri/  group: cuckoo/" /etc/suricata/suricata.yaml
	sed -i " N; s/  - file-store:\n      enabled: no/  - file-store:\n      enabled: yes/" /etc/suricata/suricata.yaml
	sed -i " N; s/  - file-log:\n      enabled: no/  - file-log:\n      enabled: yes/" /etc/suricata/suricata.yaml
	wget https://raw.githubusercontent.com/Slipperyclock/SEC599/master/suricata.sh -O /opt/cuckoo-configs/suricata.sh
	chmod +x /opt/cuckoo-configs/suricata.sh
	echo "@reboot root /opt/cuckoo-configs/suricata.sh &" >> /etc/crontab
	echo "15 * * * * root /usr/bin/suricatasc -c reload-rules &" >> /etc/crontab
}
# Init.

print_copy
check_viability
setopts ${@}

# Load config

source config &>/dev/null

echo "Logging enabled on ${LOG}"

# Install packages
run_and_log prepare_virtualbox "Getting virtualbox repo ready" "Virtualbox is running, please close it"
run_and_log install_packages "Installing packages ${CUSTOM_PKGS} and ${packages[$RELEASE]}" "Something failed installing packages, please look at the log file"

# Create user and clone repos
run_and_log create_cuckoo_user "Creating cuckoo user" "Could not create cuckoo user"
run_and_log clone_repos "Cloning repositories" "Could not clone repos"

# Install python packages
run_and_log install_python_packages "Installing python packages: ${python_packages}" "Something failed install python packages, please look at the log file"

# Install volatility
run_and_log build_volatility "Installing volatility"

# Disable Ubuntu 18/17 systemd-resolvd
run_and_log disable_systemd_resolved "Disabling Systemd-Resolved"

# Networking (latest, because sometimes it crashes...)
run_and_log create_hostonly_iface "Creating hostonly interface for cuckoo"
run_and_log allow_tcpdump "Allowing tcpdump for normal users"

# Preparing VirtualBox VM
run_and_log import_virtualbox_vm "Importing specified VirtualBoxVM"
run_and_log launch_virtualbox_vm "Launching imported VM"
sleep 60
run_and_log create_virtualbox_vm_snapshot "Creating snapshot 'Clean'"
run_and_log poweroff_virtualbox_vm

# Configuring Cuckoo
run_and_log run_cuckoo_community "Downloading community rules"
run_and_log update_cuckoo_config "Updating Cuckoo config files"
run_and_log create_cuckoo_startup_scripts "Creating Cuckoo startup scripts"
run_and_log setup_tor "Setting up TOR configuration"
run_and_log remote_port_script "Create SSH remote port script"
run_and_log setup_suricata "Setup Suricata and Cuckoo"
echo -e "${log_icon_ok} For Remote Control support run 'apt install virtualbox-ext-pack' "

