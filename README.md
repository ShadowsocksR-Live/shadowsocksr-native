![shadowsocksr-native](https://avatars0.githubusercontent.com/u/30504070?s=200&v=4)

<!--
As I typed each line of code, I was full of fear. Cherish what you using.
敲下每一行代码时，我都充满了恐惧；大伙且用且珍惜。
-->

# ShadowsocksR-native

[![Join the chat at https://gitter.im/ShadowsocksR-Live/](https://cdn03.gitter.im/_s/9177b02/images/favicon-read.ico)](https://gitter.im/ShadowsocksR-Live/Lobby)

[新特性: GFW 终结者 SSRoT](https://github.com/ShadowsocksR-Live/shadowsocksr-native/wiki)

[写给高危翻墙人士](https://github.com/ShadowsocksR-Live/shadowsocksr-native/wiki/%E5%86%99%E7%BB%99%E9%AB%98%E5%8D%B1%E7%BF%BB%E5%A2%99%E4%BA%BA%E5%A3%AB)

[帮助开发者改善 SSRoT](https://github.com/ShadowsocksR-Live/shadowsocksr-native/wiki/%E5%B8%AE%E5%8A%A9%E4%BD%9C%E8%80%85%E6%94%B9%E5%96%84-SSRoT)

[New feature: GFW terminator SSRoT English tutorial](https://palitechsociety.blogspot.com/2019/08/shadowsocksr-over-tls-ssrot-server.html)


## Index

- [Intro](#intro)
- [Features](#features)
- [Protocols & obfuscators](#protocols--obfuscators)
- [Build](#build)
- [Sample configure file](#sample-configure-file)
- [cmake](#cmake)
- [Deploy server](#deploy-server)

## Intro

**ShadowsocksR-native** is a lightweight secured SOCKS5 proxy for embedded devices and low-end boxes.
It's derived from [Shadowsocks-libev](http://shadowsocks.org).

It is a port of [ShadowsocksR](https://github.com/ShadowsocksR-Live/shadowsocksr)
created by [@breakwa11](https://github.com/breakwa11), 
which is maintained by [@ssrlive](https://github.com/ssrlive).

Current version: 0.4 | [Changelog](debian/changelog)

## Features

ShadowsocksR-native is written in pure C and only depends on
[libuv](https://github.com/libuv/libuv) ,
[mbedTLS](https://github.com/ARMmbed/mbedtls) , 
[libsodium](https://github.com/jedisct1/libsodium) and
[json-c](https://github.com/json-c/json-c).

In normal usage, the memory footprint is about 600KB and the CPU utilization is
no more than 5% on a low-end router (Buffalo WHR-G300N V2 with a 400MHz MIPS CPU,
32MB memory and 4MB flash).

For a full list of feature comparison between different versions of shadowsocks,
refer to the [Wiki page](https://github.com/shadowsocksr-live/shadowsocksr-native/wiki/).

## Encrypto method
|                  |                  |                 |                 |                 |                |
| -----|-|-|-|-|-------------- | 
| none | table             |||||
| rc4 | rc4-md5-6 | rc4-md5 ||||
| aes-128-cfb | aes-192-cfb | aes-256-cfb ||||
| aes-128-ctr | aes-192-ctr | aes-256-ctr ||||
| camellia-128-cfb | camellia-192-cfb | camellia-256-cfb ||||
| bf-cfb | cast5-cfb | des-cfb | idea-cfb | rc2-cfb | seed-cfb |
| salsa20 | chacha20 | chacha20-ietf ||||


## Protocols & obfuscators

| Protocols | obfuscators | 
| --------- | ----------- | 
| origin | plain |
| auth_sha1_v4 | http_simple |
| auth_aes128_sha1 | http_post |
| auth_aes128_md5 | http_mix |
| auth_chain_a | tls1.2_ticket_auth |
| auth_chain_b | tls1.2_ticket_fastauth |
| auth_chain_c/d/e/f |    |

progress of data flow
```
+-----------------------------------------------------------------------------+
|                +--------------------------------------------------------+   |
|                |               +------------------------------------+   |   |
|                |               |            +-------------------+   |   |   |
|  obfuscator    |   encryptor   |  protocol  |     user data     |   |   |   |
|   |            |       |       |      |     +-------------------+   |   |   |
|   |            |       |       +------+-----------------------------+   |   |
|   |            +-------+--------------+---------------------------------+   |
+---+--------------------+--------------+-------------------------------------+
    |                    |              |                                            
    +-- server_encode    +-- encrypt    +-- server_pre_encrypt       <<<=== user data
    |                    |              |                                            
    +-- server_decode    +-- decrypt    +-- server_post_decrypt      ===>>> user data
```

## Build

### Distribution-specific guide

- [Debian & Ubuntu](#debian--ubuntu)
- [Fedora & RHEL](#fedora--rhel)
- [CentOS](#centos)
- [macOS](#macos)
- [Windows](#windows)

* * *

### Debian & Ubuntu

For Unix-like systems, especially Debian-based systems,
e.g. Ubuntu, Debian or Linux Mint, you can build the binary like this:

```bash
# Debian / Ubuntu
# sudo su                       # using root account
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install --no-install-recommends build-essential autoconf libtool asciidoc xmlto -y
sudo apt-get install git gcc g++ gdb cmake automake -y
sudo apt-get -f install -y

# cd /                          # switch to root directory
git clone https://github.com/ShadowsocksR-Live/shadowsocksr-native.git
mv shadowsocksr-native ssr-n  # rename shadowsocksr-native to ssr-n
cd ssr-n                      # enter ssr-n directory. 
git submodule update --init
git submodule foreach -q 'git checkout $(git config -f $toplevel/.gitmodules submodule.$name.branch || echo master)'

# build ShadowsocksR-native
mkdir build && cd build
cmake .. && make
# make install
# /bin/cp -rfa src/ssr-* /usr/bin

# build 32-bit binary
sudo apt-get install gcc-multilib -y
rm -rf *
cmake -D CMAKE_C_FLAGS=-m32 .. && make

```

The target binaries are `ssr-n/build/src/ssr-server`, `ssr-n/build/src/ssr-client` and `ssr-n/build/src/ssr-local`.

### CentOS

CentOS 7 only. we don't support CentOS 6.x, it's too old.

Before build `ssr-Native`, we must install `cmake` 3.x first. following [this](#cmake) 

```bash
# CentOS / Fedora / RHEL
sudo su
yum install wget git gcc gcc-c++ gdb autoconf automake libtool make asciidoc xmlto -y
curl https://cmake.org/files/v3.14/cmake-3.14.0-Linux-x86_64.sh -o a.sh
sh a.sh --prefix=/usr/ --exclude-subdir && rm -rf a.sh
cd /
git clone https://github.com/ShadowsocksR-Live/shadowsocksr-native.git
mv shadowsocksr-native ssr-n
cd ssr-n
git submodule update --init
git submodule foreach -q 'git checkout $(git config -f $toplevel/.gitmodules submodule.$name.branch || echo master)'

cmake . && make
# make install
# /bin/cp -rfa src/ssr-* /usr/bin
```

The target binaries are `ssr-n/src/ssr-server`, `ssr-n/src/ssr-client` and `ssr-n/src/ssr-local`.

### macOS

For macOS, we must download/install/run [Xcode](https://developer.apple.com/xcode/) first. 

Then use [Homebrew](http://brew.sh) to install or build.

Install Homebrew and tools:
```bash
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install git cmake automake libtool
brew upgrade git cmake automake libtool
```
Now get source code and build it.
```bash
git clone https://github.com/ShadowsocksR-Live/shadowsocksr-native.git
mv shadowsocksr-native ssr-n
cd ssr-n
git submodule update --init
git submodule foreach -q 'git checkout $(git config -f $toplevel/.gitmodules submodule.$name.branch || echo master)'

cmake . && make
```

The target binaries are `ssr-n/src/ssr-server`, `ssr-n/src/ssr-client` and `ssr-n/src/ssr-local`.

### Windows

For Windows, chekout the project using the following commands then open win32/ssr-native.sln with Visual Studio 2010. Enjoy it!

```bash
git clone https://github.com/ShadowsocksR-Live/shadowsocksr-native.git 
git submodule update --init
git submodule foreach -q 'git checkout $(git config -f $toplevel/.gitmodules submodule.$name.branch || echo master)'
```

## Usage

For a detailed and complete list of all supported arguments, you may refer to the
man pages of the applications, respectively.

```
    ssr-[client|local|server]

       [-c <config_file>]         The path to config file

       [-d]                       Run in background as a daemon.

       [-h]                       Show this help message.
```

## Sample configure file

config.json
```json
{
    "password": "password",
    "method": "aes-128-ctr",
    "protocol": "auth_aes128_md5",
    "protocol_param": "",
    "obfs": "tls1.2_ticket_auth",
    "obfs_param": "",

    "udp": true,
    "idle_timeout": 300,
    "connect_timeout": 6,
    "udp_timeout": 6,

    "server_settings": {
        "listen_address": "0.0.0.0",
        "listen_port": 12475
    },

    "client_settings": {
        "server": "12.34.56.78",
        "server_port": 12475,
        "listen_address": "0.0.0.0",
        "listen_port": 1080
    },

    "over_tls_settings": {
        "enable": false,
        "server_domain": "goodsitesample.com",
        "path": "/udg151df/",
        "root_cert_file": ""
    }
}
```

## cmake

In the CentOS 7, the cmake version is too old to work with ShadowsocksR-Native. 
So we must install it by ourselves.

```bash
sudo su
cd /
curl https://cmake.org/files/v3.14/cmake-3.14.5-Linux-x86_64.sh -o a.sh
sh a.sh  --prefix=/usr/ --exclude-subdir
rm -rf a.sh
cmake --version
```

And the `cmake --version` command will output message likes:
```
cmake version 3.14.5
CMake suite maintained and supported by Kitware (kitware.com/cmake).
```

## Deploy server

Supporting `CentOS 7` / `Debian` / `Ubuntu` with the following commands

```
sudo su
wget --no-check-certificate https://raw.githubusercontent.com/ShadowsocksR-Live/shadowsocksr-native/master/install/ssrn-install.sh
chmod +x ssrn-install.sh
./ssrn-install.sh 2>&1 | tee ssr-n.log
```

After installation, we can view the status with 
```
systemctl status ssr-native.service
```

And we can view or edit the configuration with `cat` or `vi` in `root` privilege
```
cat /etc/ssr-native/config.json
```

After we changed the server configuration, we must restart the service to make the changes take effect.
```
systemctl restart ssr-native.service
```

To stop the server, please run
```
systemctl stop ssr-native.service
```

To uninstall the server, use the following command
```
./ssrn-install.sh uninstall
```


## Stargazers over time

[![Stargazers over time](https://starchart.cc/ShadowsocksR-Live/shadowsocksr-native.svg)](https://starchart.cc/ShadowsocksR-Live/shadowsocksr-native)
      
