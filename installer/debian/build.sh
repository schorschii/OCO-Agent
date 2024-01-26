#!/bin/bash
set -e

# build .deb package

# check root permissions
if [ "$EUID" -ne 0 ]
	then echo "Please run this script as root!"
	exit
fi

# cd to working dir
cd "$(dirname "$0")"

# create necessary directories
mkdir -p oco-agent/etc/systemd/system
mkdir -p oco-agent/usr/share
mkdir -p oco-agent/lib/oco-agent/service-checks

# copy files in place
rm -r oco-agent/usr/share/oco-agent 2>/dev/null || true
cp -r ../../dist/oco-agent oco-agent/usr/share/oco-agent
cp ../../oco-agent.dist.ini oco-agent/etc/oco-agent.ini
cp ../../oco-agent.service oco-agent/etc/systemd/system/oco-agent.service

# set file permissions
chown -R root:root oco-agent
chmod 774 oco-agent/usr/share/oco-agent/oco-agent
chmod 660 oco-agent/etc/oco-agent.ini

# build deb
dpkg-deb -Zxz --build oco-agent

echo "Build finished"
