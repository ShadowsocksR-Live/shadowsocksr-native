shadowsocks-libev
=================

Intro
-----

[Shadowsocks-libev](http://shadowsocks.org) is a lightweight secured scoks5 
proxy for embedded devices and low end boxes.

It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks) 
created by [@clowwindy](https://github.com/clowwindy) maintained by 
[@madeye](https://github.com/madeye).

Current version: 1.0 [![Build Status](https://travis-ci.org/madeye/shadowsocks-libev.png?branch=master)](https://travis-ci.org/madeye/shadowsocks-libev)

Features
--------

Shadowsocks-libev is writen in pure C and only depends on
[libev](http://software.schmorp.de/pkg/libev.html).

When statically linked and packaged for OpenWRT, the total package size is 23KB. 
In normal usage, the memory consumption is about 600KB and the CPU utilization is 
no more than 5% on a low-end router (Buffalo WHR-G300N V2 with a 400MHz MIPS CPU, 
32MB memory and 4MB flash).

Installation
------------

Build the binary like this:

```bash
    sudo apt-get install build-essential autoconf libtool
    ./configure && make
    sudo make install
```

Usage
-----

```
usage:

    ss-local -s server_host -p server_port -l local_port -k password
       [-m encrypt_method] [-f pid_file] [-t timeout] [-c config_file]

    ss-redir -s server_host -p server_port -l local_port -k password
       [-m encrypt_method] [-f pid_file] [-t timeout] [-c config_file]

    ss-server -s server_host -p server_port -k password
       [-m encrypt_method] [-f pid_file] [-t timeout] [-c config_file]

options:

    encrypt_method:     table, rc4
          pid_file:     valid path to the pid file
           timeout:     socket timeout in senconds
       config_file:     json format config file

notes:

    ss-redir provides a transparent proxy function and only works on the 
    Linux platform with iptables.

```

## Advanced usage

The latest shadowsocks-libev has provided a transparent mode. You can configure your linux based box or router to proxy all tcp traffic transparently.

    # Create new chain
    root@Wrt:~# iptables -t nat -N SHADOWSOCKS
    
    # Ignore your shadowsocks server's addresses
    # It's very IMPORTANT, just be careful.
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 123.123.123.123 -j RETURN

    # Ignore LANs and any other addresses you'd like to bypass the proxy
    # See Wikipedia and RFC5735 for full list of reserved networks.
    # See ashi009/bestroutetb for a highly optimized CHN route list.
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 0.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 10.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 127.0.0.0/8 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 169.254.0.0/16 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 172.16.0.0/12 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 192.168.0.0/16 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 224.0.0.0/4 -j RETURN
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -d 240.0.0.0/4 -j RETURN

    # Anything else should be redirected to shadowsocks's local port
    root@Wrt:~# iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports 12345
    
    # Apply the rules
    root@Wrt:~# iptables -t nat -A OUTPUT -p tcp -j SHADOWSOCKS
    
    # Start the shadowsocks-redir
    root@Wrt:~# ss-redir -c /etc/config/shadowsocks.json -f /var/run/shadowsocks.pid
