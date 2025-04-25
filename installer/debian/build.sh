#!/bin/bash
set -e

# build .deb package
INSTALLDIR=/usr/share/oco-agent
BUILDDIR=oco-agent

# check root permissions
if [ "$EUID" -ne 0 ]
	then echo "Please run this script as root!"
	#exit 1 # disabled for github workflow. don't know why this check fails here but sudo works.
fi

# cd to working dir
cd "$(dirname "$0")"

# empty / create necessary directories
if [ -d "$BUILDDIR/usr" ]; then
    sudo rm -r $BUILDDIR/usr
fi
if [ -d "$BUILDDIR/lib" ]; then
    sudo rm -r $BUILDDIR/lib
fi
if [ -d "$BUILDDIR/etc" ]; then
    sudo rm -r $BUILDDIR/etc
fi
mkdir -p $BUILDDIR/usr/share
mkdir -p $BUILDDIR/lib/oco-agent/service-checks

# copy files in place
cp -r                  ../../dist/oco-agent        $BUILDDIR/$INSTALLDIR
sudo install -D -m 660 ../../oco-agent.dist.ini    $BUILDDIR/etc/oco-agent.ini
sudo install -D -m 644 ../../oco-agent.service  -t $BUILDDIR/lib/systemd/system/

# set file permissions
chmod 774 $BUILDDIR/$INSTALLDIR/oco-agent

# make binary available in PATH
sudo mkdir -p $BUILDDIR/usr/bin
sudo ln -sf   $INSTALLDIR/oco-agent     $BUILDDIR/usr/bin/oco-agent

# build deb
sudo dpkg-deb -Zxz --build oco-agent

echo "Build finished"
