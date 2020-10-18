#!/bin/bash

# sudo apt install wget unzip -y

rm -rf ssr-native-linux-x64.zip
wget https://github.com/ShadowsocksR-Live/shadowsocksr-native/releases/latest/download/ssr-native-linux-x64.zip
if [ $? -ne 0 ]; then echo "wget failed"; exit -1; fi

rm -rf ssr-server
unzip ssr-native-linux-x64.zip ssr-server
if [ $? -ne 0 ]; then echo "unzip failed"; exit -1; fi

chmod +x ssr-server
rm -rf ssr-native-linux-x64.zip

sudo rm -rf /usr/bin/ssr-server
sudo mv ssr-server /usr/bin/

echo "Restarting ssr-native.service ..."

sudo systemctl stop ssr-native.service
sleep 2
sudo systemctl start ssr-native.service
sleep 2
sudo systemctl status ssr-native.service
