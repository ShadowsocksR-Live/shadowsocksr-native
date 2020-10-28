#!/bin/bash

# sudo apt install wget unzip -y

function check_root_account() {
    if [ `id -u` != 0 ]; then
        echo -e "当前账号不是 root 账号，请切换到 root 账号再运行本脚本。"
        echo -e "Current account is not root user, please switch to root user and re-execute this script."
        exit 1
    fi
}

function do_download_ssr_server_bin() {
    rm -rf ssr-native-linux-x64.zip
    wget https://github.com/ShadowsocksR-Live/shadowsocksr-native/releases/latest/download/ssr-native-linux-x64.zip
    if [ $? -ne 0 ]; then echo "wget failed"; exit -1; fi

    rm -rf ssr-server
    unzip ssr-native-linux-x64.zip ssr-server
    if [ $? -ne 0 ]; then echo "unzip failed"; exit -1; fi

    chmod +x ssr-server
    rm -rf ssr-native-linux-x64.zip

    rm -rf /usr/bin/ssr-server
    mv ssr-server /usr/bin/
}

function do_update_ssr_server() {

    do_download_ssr_server_bin

    echo "Restarting ssr-native.service ..."

    systemctl stop ssr-native.service
    sleep 2
    systemctl start ssr-native.service
    sleep 2
    systemctl status ssr-native.service
}

function main() {
    check_root_account
    do_update_ssr_server
}

main
