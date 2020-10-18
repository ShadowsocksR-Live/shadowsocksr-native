#!/bin/bash

# sudo apt install curl unzip -y

wget https://github.com/ShadowsocksR-Live/shadowsocksr-native/releases/latest/download/ssr-native-linux-x64.zip
if [ $? -ne 0 ]; then echo "wget failed"; exit $?; fi

unzip ssr-native-linux-x64.zip ssr-server
if [ $? -ne 0 ]; then echo "unzip failed"; exit $?; fi

chmod +x ssr-server
rm -rf ssr-native-linux-x64.zip

sudo rm -rf /usr/bin/ssr-server
sudo mv ssr-server /usr/bin/

sudo systemctl stop ssr-native.service
sleep 2
sudo systemctl start ssr-native.service
sleep 2
sudo systemctl status ssr-native.service
