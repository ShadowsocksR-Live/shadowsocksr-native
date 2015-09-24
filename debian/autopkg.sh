#!/bin/sh

# Automatic deb packaging script for shadowsocks-libev
#

set -e
if [ "$(basename $(pwd))x" = "debianx" ]; then
    cd ..
else
    if [ ! "$(basename $(pwd))x" = "shadowsocks-libevx" ]; then
        echo "Unknown Working Directory, won't continue."
        exit 1
    fi
fi
git clean -Xdf
git reset --hard HEAD
autoreconf --install
rm -f ../*.tar.xz ../*.deb ../*.tar.gz ../*.build ../*.dsc ../*.changes
CURR_PKG_DIR=$(pwd)
tar -czvf ../$(basename $CURR_PKG_DIR)_$(cat ./configure.ac | grep AC_INIT | grep -o '[0-9]\.[0-9]\.[0-9]').orig.tar.gz . --exclude-vcs
#dh_make --multi --createorig --yes --copyright gpl3
A=$(which debuild > /dev/null 2> /dev/null; echo $?)
if [ "${A}x" = "0x" ]; then
    debuild -us -uc -i
else
    dpkg-buildpackage -us -uc -i
fi
