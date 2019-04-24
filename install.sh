#!/bin/sh

sourceDir=$(dirname $0)
sourceVer=debian-v9-router
sourceTar=https://github.com/JAMESMTL/${sourceVer}/tarball/master

dirList=" \
	/opt/router/files \
	/opt/router/install \
	/root/router/action \
	/root/router/config \
"

echo
echo "##########################################################"
echo "Checking permissions"
echo "##########################################################"
echo

echo -n "Verifying user ... "
if [ ${USER} != 'root' ]; then
	echo "FAILED"
	echo "Not running as root, exiting."
	echo
	exit
else
	echo "ok"
fi

echo
echo "##########################################################"
echo "Enabling root ssh access"
echo "##########################################################"
echo

if grep -qE '^PermitRootLogin yes$' /etc/ssh/sshd_config; then
	echo "root ssh login already enabled ... skipping"
else
	echo -n "writting to /etc/ssh/sshd_config ... "

	echo >> /etc/ssh/sshd_config
	echo PermitRootLogin yes >> /etc/ssh/sshd_config

	grep -qE '^PermitRootLogin yes$' /etc/ssh/sshd_config && echo ok || echo FAILED
fi

echo
echo "##########################################################"
echo "Restarting sshd"
echo "##########################################################"
echo

echo -n "Restarting sshd service ... "
service sshd restart && echo ok || echo FAILED

echo
echo "##########################################################"
echo "Creating directories"
echo "##########################################################"
echo

for listItem in $dirList; do
	echo -n "creating directory ${listItem} ... "
	[ ! -d "${listItem}" ] && mkdir -p ${listItem}
	[ -d "${listItem}" ] && echo ok || echo FAILED
done

echo
echo "##########################################################"
echo "Eanbling non-free repo and updating"
echo "##########################################################"
echo

sed -i 's/stretch main$/stretch main non-free/g' /etc/apt/sources.list
apt update
apt upgrade -y

echo
echo "##########################################################"
echo "Installing base and utility packages"
echo "##########################################################"
echo

apt install -y vlan bridge-utils net-tools ppp ipset traceroute nmap conntrack \
	ndisc6 whois dnsutils mtr iperf3 curl resolvconf sudo apt-transport-https \
	tcpdump ethtool firmware-bnx2x

# Detect hypervisor 
if grep -q hypervisor /proc/cpuinfo; then

	echo
	echo "##########################################################"
	echo "Hypervisor detected"
	echo "##########################################################"
	echo

	while true; do
		read -p "Install open-vm-tools (y/n)? " yn
		case $yn in
			[Yy]* )
				echo
				apt install -y open-vm-tools
				break;;
			[Nn]* )
				echo Skipping ...
				break;;
		esac
	done
fi

echo
echo "##########################################################"
echo "Installing services"
echo "##########################################################"
echo

apt install -y unbound dnsmasq inadyn openvpn wide-dhcpv6-client miniupnpd

service dnsmasq stop
service unbound stop

echo
echo "##########################################################"
echo "Installing igmpproxy 0.2.1 from buster"
echo "##########################################################"
echo

useLocalCopy=no
useLocalPath=""

[ -f "/opt/router/install/igmpproxy_0.2.1-1_amd64.deb" ] && useLocalPath="/opt/router/install/igmpproxy_0.2.1-1_amd64.deb"
[ -f "${sourceDir}/igmpproxy_0.2.1-1_amd64.deb" ] && useLocalPath="${sourceDir}/igmpproxy_0.2.1-1_amd64.deb"

# Detect if local version exists
if [ ! -z "$useLocalPath" ]; then
	while true; do
		read -p "Local copy of found, use local copy (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalCopy=yes
				if [ $(dirname $useLocalPath) != "/opt/router/install" ]; then
					cp $useLocalPath /opt/router/install
				fi
				break;;
			[Nn]* )
				useLocalCopy=no
				break;;
		esac
	done
	echo
fi

[ "$useLocalCopy"  = 'no' ] && wget -q -O /opt/router/install/igmpproxy_0.2.1-1_amd64.deb http://ftp.us.debian.org/debian/pool/main/i/igmpproxy/igmpproxy_0.2.1-1_amd64.deb
dpkg -i /opt/router/install/igmpproxy_0.2.1-1_amd64.deb

echo
echo "##########################################################"
echo "Installing miniupnpd 2.1 from buster"
echo "##########################################################"
echo

useLocalCopy=no
useLocalPath=""

[ -f "/opt/router/install/miniupnpd_2.1-5_amd64.deb" ] && useLocalPath="/opt/router/install/miniupnpd_2.1-5_amd64.deb"
[ -f "${sourceDir}/miniupnpd_2.1-5_amd64.deb" ] && useLocalPath="${sourceDir}/miniupnpd_2.1-5_amd64.deb"

# Detect if local version exists
if [ ! -z "$useLocalPath" ]; then
	while true; do
		read -p "Local copy of found, use local copy (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalCopy=yes
				if [ $(dirname $useLocalPath) != "/opt/router/install" ]; then
					cp $useLocalPath /opt/router/install
				fi
				break;;
			[Nn]* )
				useLocalCopy=no
				break;;
		esac
	done
	echo
fi

[ "$useLocalCopy"  = 'no' ] && wget -q -O /opt/router/install/miniupnpd_2.1-5_amd64.deb http://ftp.us.debian.org/debian/pool/main/m/miniupnpd/miniupnpd_2.1-5_amd64.deb
dpkg-deb -x /opt/router/install/miniupnpd_2.1-5_amd64.deb /tmp/miniupnpd

cp /tmp/miniupnpd/usr/sbin/miniupnpd /usr/sbin

echo "cleaning up the mess ..."
echo -n "rm /etc/init.d/miniupnpd ... "
rm /etc/init.d/miniupnpd && echo ok || echo FAILED
echo -n "rm /etc/miniupnpd/* ... "
rm /etc/miniupnpd/* && echo ok || echo FAILED

echo
echo "##########################################################"
echo "Fetching install files"
echo "##########################################################"
echo

# Copy install to /opt/router/install/
if [ $sourceDir != "/opt/router/install" ]; then
	echo -n "copying $0 /opt/router/install/ ... "
	cp $0 /opt/router/install/ && echo ok || echo FAILED
fi

useLocalSource=no

# Detect if local archive exists
if [ -f "${sourceDir}/${sourceVer}.tar.gz" ]; then
	while true; do
		read -p "Local archive detected, use local archive (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalSource=yes
				break;;
			[Nn]* )
				useLocalSource=no
				break;;
		esac
	done
	echo
fi

# Download or use local copy of archive
if [ $useLocalSource = 'yes' ]; then
		echo -n "copying ${sourceDir}/${sourceVer}.tar.gz -> /opt/router/install/${sourceVer}.tar.gz ... "
		cp ${sourceDir}/${sourceVer}.tar.gz /opt/router/install/
		[ -f "/opt/router/install/${sourceVer}.tar.gz" ] && echo ok || echo FAILED
else
		echo -n "fetching /opt/router/install/${sourceVer}.tar.gz ... "
		wget -q ${sourceTar} -O /opt/router/install/${sourceVer}.tar.gz
		[ -f "/opt/router/install/${sourceVer}.tar.gz" ] && echo ok || echo FAILED
fi

echo
echo "##########################################################"
echo "Extracting archive to /opt/router"
echo "##########################################################"
echo

# Get file list from archive
fileList=$(tar -tvf /opt/router/install/${sourceVer}.tar.gz | awk '{print $6}' | grep -oE '^.*/files/.*' | sed "s/.*-${sourceVer}-.*\/files\///g" | grep -vE '/$')

# Extract archive
tar -C /opt/router/files/ -xvf /opt/router/install/${sourceVer}.tar.gz --strip=2 | sed "s/.*-${sourceVer}-.*\/files\///g" | grep -vE '/$'

echo
echo "##########################################################"
echo "backup of original files that will be overwritten"
echo "##########################################################"
echo

if [ ! -d "/opt/router/files.bak/" ]; then
	for listItem in $fileList; do
		if [ -f "/${listItem}" ]; then
			echo -n "backing up /${listItem} ... "
			[ ! -d "/opt/router/files.bak/$(dirname $listItem)" ] && mkdir -p "/opt/router/files.bak/$(dirname $listItem)"
			cp /${listItem} /opt/router/files.bak/$(dirname $listItem)
			[ -f "/opt/router/files.bak/${listItem}" ] && echo ok || echo FAILED
		fi
	done
else
	echo Backup of original files exists ... skipping
fi

echo
echo "##########################################################"
echo "copying files"
echo "##########################################################"
echo

for listItem in $fileList; do
	echo -n "copying /opt/router/files/${listItem} -> /${listItem} ... "
	[ ! -d "/$(dirname $listItem)" ] && mkdir -p /$(dirname $listItem)
	cp /opt/router/files/${listItem} /${listItem}
	[ -f "/${listItem}" ] && echo ok || echo FAILED
done

echo
echo "######################################"
echo "creating symlinks"
echo "######################################"
echo

# config cron symlinks
echo -n "creating /root/router/config/cron_jobs ... "
ln -sf /etc/cron.d/cronjobs /root/router/config/cron_jobs && echo ok || echo FAILED

# config dhcp symlinks
echo -n "creating /root/router/config/dhcp_base ... "
ln -sf /opt/router/dnsmasq/dnsmasq.conf.router /root/router/config/dhcp_base && echo ok || echo FAILED
echo -n "creating /root/router/config/dhcp_hosts ... "
ln -sf /opt/router/dnsmasq/dnsmasq.hosts /root/router/config/dhcp_hosts && echo ok || echo FAILED
echo -n "creating /root/router/config/dhcp_v6-pd_config ... "
ln -sf /etc/wide-dhcpv6/dhcp6c.conf /root/router/config/dhcp_v6-pd_config && echo ok || echo FAILED

# config ddns symlinks
echo -n "creating /root/router/config/ddns_he_tunnel ... "
ln -sf /opt/router/scripts/ddns/ddns-ipv4-he-tunnel /root/router/config/ddns_he_tunnel && echo ok || echo FAILED
echo -n "creating /root/router/config/ddns_inadyn ... "
ln -sf /etc/inadyn.conf /root/router/config/ddns_inadyn && echo ok || echo FAILED

# config dns symlinks
echo -n "creating /root/router/config/dns_base ... "
ln -sf /opt/router/unbound/unbound.conf /root/router/config/dns_base && echo ok || echo FAILED
echo -n "creating /root/router/config/dns_split_static ... "
ln -sf /opt/router/unbound/unbound.static /root/router/config/dns_split_static && echo ok || echo FAILED

# config firewall symlinks
echo -n "creating /root/router/config/firewall_dns_redirect_v4.set ... "
ln -sf /opt/router/nftables/dns_redirect_v4.set /root/router/config/firewall_dns_redirect_v4.set && echo ok || echo FAILED
echo -n "creating /root/router/config/firewall_dns_redirect_v6.set ... "
ln -sf /opt/router/nftables/dns_redirect_v6.set /root/router/config/firewall_dns_redirect_v6.set && echo ok || echo FAILED
echo -n "creating /root/router/config/firewall_forwarding_v4.set ... "
ln -sf /opt/router/nftables/port_forwarding_v4.set /root/router/config/firewall_forwarding_v4.set && echo ok || echo FAILED
echo -n "creating /root/router/config/firewall_forwarding_v6.set ... "
ln -sf /opt/router/nftables/port_forwarding_v6.set /root/router/config/firewall_forwarding_v6.set && echo ok || echo FAILED
echo -n "creating /root/router/config/firewall_rules_v4 ... "
ln -sf /opt/router/nftables/iptables.rules /root/router/config/firewall_rules_v4 && echo ok || echo FAILED
echo -n "creating /root/router/config/firewall_rules_v6 ... "
ln -sf /opt/router/nftables/ip6tables.rules /root/router/config/firewall_rules_v6 && echo ok || echo FAILED

# config igmpproxy symlinks
echo -n "creating /root/router/config/igmpproxy_config ... "
ln -sf /etc/igmpproxy.conf /root/router/config/igmpproxy_config && echo ok || echo FAILED

# config miniupnpd symlinks
echo -n "creating /root/router/config/miniupnpd_config ... "
ln -sf /etc/miniupnpd/miniupnpd.conf /root/router/config/miniupnpd_config && echo ok || echo FAILED

# config network symlinks
echo -n "creating /root/router/config/network_interfaces ... "
ln -sf /etc/network/interfaces.router /root/router/config/network_interfaces && echo ok || echo FAILED
echo -n "creating /root/router/config/network_persistent_rules ... "
ln -sf /etc/udev/rules.d/70-persistent-net.rules /root/router/config/network_persistent_rules && echo ok || echo FAILED
echo -n "creating /root/router/config/network_pppoe ... "
ln -sf /etc/ppp/peers/pppoe.conf /root/router/config/network_pppoe && echo ok || echo FAILED
echo -n "creating /root/router/config/network_wan_up ... "
ln -sf /opt/router/scripts/system/wan-up /root/router/config/network_wan_up && echo ok || echo FAILED

# config openvpn symlinks
echo -n "creating /root/router/config/openvpn_config ... "
ln -sf /etc/openvpn /root/router/config/openvpn_config && echo ok || echo FAILED
echo -n "creating /root/router/config/openvpn_defaults ... "
ln -sf /etc/default/openvpn /root/router/config/openvpn_defaults && echo ok || echo FAILED

# actions symlinks
echo -n "creating /root/router/action/activate.sh ... "
ln -sf /opt/router/scripts/system/activate /root/router/action/activate.sh && echo ok || echo FAILED
echo -n "creating /root/router/action/backup.sh ... "
ln -sf /opt/router/scripts/system/backup /root/router/action/backup.sh && echo ok || echo FAILED
echo -n "creating /root/router/action/filelist.sh ... "
ln -sf /opt/router/scripts/system/filelist /root/router/action/filelist.sh && echo ok || echo FAILED
echo -n "creating /root/router/action/forwarding-rules.sh ... "
ln -sf /opt/router/scripts/system/forwarding-rules /root/router/action/forwarding-rules.sh && echo ok || echo FAILED
echo -n "creating /root/router/action/restore.sh ... "
ln -sf /opt/router/scripts/system/restore /root/router/action/restore.sh && echo ok || echo FAILED
echo -n "creating /root/router/action/ssh-lock.sh ... "
ln -sf /opt/router/scripts/system/ssh-lock /root/router/action/ssh-lock.sh && echo ok || echo FAILED
echo -n "creating /root/router/action/ssh-reset.sh ... "
ln -sf /opt/router/scripts/system/ssh-reset /root/router/action/ssh-reset.sh && echo ok || echo FAILED
echo -n "creating /root/router/action/ssh-unlock.sh ... "
ln -sf /opt/router/scripts/system/ssh-unlock /root/router/action/ssh-unlock.sh && echo ok || echo FAILED

echo
echo "##########################################################"
echo "Install backup of locally modified files"
echo "##########################################################"
echo

useLocalCopy=no
useLocalPath=""

[ -f "/opt/router/install/${sourceVer}-local.tar.gz" ] && useLocalPath="/opt/router/install/${sourceVer}-local.tar.gz"
[ -f "${sourceDir}/${sourceVer}-local.tar.gz" ] && useLocalPath="${sourceDir}/${sourceVer}-local.tar.gz"

# Detect if archive.local exists
if [ ! -z "$useLocalPath" ]; then
	while true; do
		read -p "Backup of locally modified files detected, use backup (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalCopy=yes
				break;;
			[Nn]* )
				useLocalCopy=no
				echo
				echo skipping ...
				break;;
		esac
	done
else
	echo "${sourceVer}-local.tar.gz not found ... skipping restore"
fi

# Extract local backup
if [ $useLocalCopy = 'yes' ]; then	
	if [ $(dirname $useLocalPath) != "/opt/router/install" ]; then
		echo
		echo -n "copying $useLocalPath -> /opt/router/install/${sourceVer}-local.tar.gz ... "
		cp $useLocalPath /opt/router/install && echo ok || echo FAILED					
	fi

	echo "Extracting files ..."
	echo
	tar -C / -xvf /opt/router/install/${sourceVer}-local.tar.gz
fi

echo
echo "##########################################################"
echo "Install backup of extra files"
echo "##########################################################"
echo

useLocalCopy=no
useLocalPath=""

[ -f "/opt/router/install/${sourceVer}-extras.tar.gz" ] && useLocalPath="/opt/router/install/${sourceVer}-extras.tar.gz"
[ -f "${sourceDir}/${sourceVer}-extras.tar.gz" ] && useLocalPath="${sourceDir}/${sourceVer}-extras.tar.gz"

# Detect if archive.extras exists
if [ ! -z "$useLocalPath" ]; then
	while true; do
		read -p "Backup of extra files detected, use backup (y/n)? " yn
		case $yn in
			[Yy]* )
				useLocalCopy=yes
				break;;
			[Nn]* )
				useLocalCopy=no
				echo
				echo skipping ...
				break;;
		esac
	done
else
	echo "${sourceVer}-extras.tar.gz not found ... skipping restore"
fi

# Extract extra files backup
if [ $useLocalCopy = 'yes' ]; then	
	if [ $(dirname $useLocalPath) != "/opt/router/install" ]; then
		echo
		echo -n "copying $useLocalPath -> /opt/router/install/${sourceVer}-extras.tar.gz ... "
		cp $useLocalPath /opt/router/install && echo ok || echo FAILED					
	fi

	echo "Extracting files ..."
	echo
	tar -C / -xvf /opt/router/install/${sourceVer}-extras.tar.gz
fi

echo
echo "######################################"
echo "Reloading daemon configs"
echo "######################################"
echo

echo -n "Removing miniupnpd init... "
update-rc.d miniupnpd remove && echo "ok" || echo "FAILED"
echo -n "disabling autostart of wide-dhcpv6-client ... "
update-rc.d wide-dhcpv6-client disable && echo "ok" || echo "FAILED"
echo -n "reloading daemon configs ... "
systemctl daemon-reload  && echo "ok" || echo "FAILED"

echo -n "unmasking miniupnpd ... "
systemctl unmask miniupnpd && echo "ok" || echo "FAILED"
echo "enabling miniupnpd ... "
systemctl enable miniupnpd

echo
echo "######################################"
echo "creating new ssh keys"
echo "######################################"
echo

[ -d "/root/.ssh" ] && rm /root/.ssh/*
echo -n "generating ssh keys ... "
ssh-keygen -f /root/.ssh/${USER}@$(cat /etc/hostname) -t rsa -N '' -q && echo "ok" || echo "FAILED"
echo -n "replacing authorized keys ... "
cp /root/.ssh/${USER}@$(cat /etc/hostname).pub /root/.ssh/authorized_keys && echo "ok" || echo "FAILED"

echo
echo "##########################################################"
echo "setting permissions"
echo "##########################################################"
echo

echo -n "chmod 755 /etc/ppp/ip-down.local ... "
chmod 755 /etc/ppp/ip-down.local && echo ok || echo FAILED
echo -n "chmod 755 /etc/ppp/ip-up.local ... "
chmod 755 /etc/ppp/ip-up.local && echo ok || echo FAILED
echo -n "chmod 755 -R /opt/router/install/*.sh ... "
chmod 755 -R /opt/router/install/*.sh && echo ok || echo FAILED
echo -n "chmod 755 -R /opt/router/scripts ... "
chmod 755 -R /opt/router/scripts && echo ok || echo FAILED

# Test if is activated following restore
if [ -s /opt/router/install/.activated ]; then
	echo
	echo "######################################"
	echo "Router activated following restore"
	echo "######################################"
	echo

	echo "remapping ~/router/config/network_interfaces -> /etc/network/interfaces"
	ln -sf /etc/network/interfaces ~/router/config/network_interfaces

	echo "remapping ~/router/config/dhcp_base -> /opt/router/dnsmasq/dnsmasq.conf"
	ln -sf /opt/router/dnsmasq/dnsmasq.conf ~/router/config/dhcp_base
	
	echo
	echo "The router will be fully active the next time you boot."
	echo "Make sure the original router is shutdown before booting."
	echo
else
	echo
	echo "######################################"
	echo "Finished base install"
	echo "######################################"
	echo
	echo "Please edit the files linked in the ~/router/config directory then run the"
	echo "activate script."
	echo
	echo "~/router/action/activate.sh"
	echo
	echo "The activate script will replace the temporary network and dhcp settings with"
	echo "your configured settings"
	echo
	echo "After running the activate script, the router WILL SHUT DOWN"
	echo
	echo "The router will be fully active the next time you boot."
	echo "Make sure the original router is shutdown before booting."
	echo
fi

# Store version
echo "$sourceVer" > /opt/router/install/.version
cp /opt/router/install/.version /opt/router/files/opt/router/install/
