shadowsocks-libev
===========

shadowsocks-libev is a lightweight tunnel proxy which can help you get through
 firewalls. It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

Currently not stable yet.
 Please use [shadowsocks-nodejs](https://github.com/clowwindy/shadowsocks-nodejs).

installation
-----------

Edit local.c, change server hostname.

Install the following package:

    sudo apt-get install build-essential autoconf libtool libev-dev libssl-dev
    autoreconf
    ./configure && make

