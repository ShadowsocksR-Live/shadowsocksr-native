shadowsocks-libev
=================

shadowsocks-libev is a lightweight obfuscated scoks5 proxy.

It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

Only the client is ported. Please use [shadowsocks-nodejs](https://github.com/clowwindy/shadowsocks-nodejs) 
to setup your server.

installation
------------

Build the binary like this:

```bash
    sudo apt-get install build-essential autoconf libtool libev-dev libssl-dev

    ./configure && make
```

usage
-----

```
    usage:  ss  -s server_host -p server_port -l local_port
                -k password [-m encrypt_method] [-f pid_file]

    info:
                -m:  accept two encrypt methods, "table" or "rc4"
                -f:  run in backgroud, with a valid path to the pid_file
```
