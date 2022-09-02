#!/bin/bash

# build .deb package

# check root permissions
if [ "$EUID" -ne 0 ]
	then echo "Please run this script as root!"
	exit
fi

# cd to working dir
cd "$(dirname "$0")"

# remove git placeholders
rm oco-agent/etc/systemd/system/.placeholder
rm oco-agent/usr/bin/.placeholder

# copy files in place
cp ../../oco-agent.py oco-agent/usr/bin/oco-agent
cp ../../oco-agent.dist.ini oco-agent/etc/oco-agent.ini
cp ../../oco-agent.service oco-agent/etc/systemd/system/oco-agent.service

# set file permissions
chown -R root:root oco-agent
chmod 774 oco-agent/usr/bin/oco-agent
chmod 660 oco-agent/etc/oco-agent.ini

# build deb
dpkg-deb --build oco-agent

# re-add git placeholders
touch oco-agent/etc/systemd/system/.placeholder
touch oco-agent/usr/bin/.placeholder

echo "Build finished"

