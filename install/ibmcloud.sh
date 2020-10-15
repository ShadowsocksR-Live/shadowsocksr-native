#!/bin/bash

ssr_dir=""
config_file=""
curr_path=""
password=""
ssrot_path=""
svr_listen_port=""
cli_conn_port=""
IBM_APP_NAME=""
IBM_MEM_SIZE=""
domain_name=""

function create_app_files() {
    rm -rf Godeps && mkdir Godeps
    cat > Godeps/Godeps.json <<EOF
{
    "ImportPath": "main",
    "GoVersion": "go1",
    "Deps": []
}
EOF

    cat > main.go <<EOF
package main
func main() {
}
EOF

    cat > Procfile <<EOF
web: ./${ssr_dir}/ssr-server
EOF

    cat > manifest.yml <<EOF
applications:
- name: ${IBM_APP_NAME}
  random-route: true
  path: .
  memory: ${IBM_MEM_SIZE}M
  instances: 1
EOF

}

function download_ssr_bin() {
    rm -rf ${ssr_dir} && mkdir ${ssr_dir}

    wget https://github.com/ShadowsocksR-Live/shadowsocksr-native/releases/latest/download/ssr-native-linux-x64.zip
    unzip ssr-native-linux-x64.zip -d ${ssr_dir} ssr-server
    chmod +x ${ssr_dir}/ssr-server
    rm -rf ssr-native-linux-x64.zip

    cat > ${curr_path}/${ssr_dir}/${config_file} <<EOF
{
    "password": "${password}",
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
        "listen_port": ${svr_listen_port}
    },

    "client_settings": {
        "server": "${domain_name}",
        "server_port": ${cli_conn_port},
        "listen_address": "0.0.0.0",
        "listen_port": 1080
    },

    "over_tls_settings": {
        "enable": true,
        "server_domain": "${domain_name}",
        "path": "/${ssrot_path}/",
        "root_cert_file": ""
    }
}
EOF

}


function main() {

    local app_dir="ibm-cloud-app"
    
    rm -rf ${app_dir} && mkdir ${app_dir} && cd ${app_dir}

    ssr_dir="ssr-dir"
    config_file="config.json"
    curr_path=`pwd`
    svr_listen_port=8080
    cli_conn_port=443
    
    echo "Configurating SSR...(正在配置 SSR …)"

    ibmcloud target --cf
    ibmcloud cf install

    stty erase '^H' && read -p "Please input your APP name (请输入你的应用名称): " IBM_APP_NAME
    echo "APP name (应用名称): ${IBM_APP_NAME}"
    
    domain_name=`ibmcloud cf app ${IBM_APP_NAME} | grep routes | cut -f2 -d':' | sed 's/ //g'`
    if [ ${#domain_name} -eq 0 ]; then
        echo "Your APP name '${IBM_APP_NAME}' is wrong!!! (你输入的应用名称 '${IBM_APP_NAME}' 是错的)"
        exit 1
    fi

    stty erase '^H' && read -p "Please input your memory size MB (default 64) (请输入你的应用内存大小MB, 默认值 64): " IBM_MEM_SIZE
    [[ -z ${IBM_MEM_SIZE} ]] && IBM_MEM_SIZE=64
    echo "Memory size (内存大小) ${IBM_MEM_SIZE} MB"

    local new_psw=`head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16`
    stty erase '^H' && read -p "Please input your SSR password (default ${new_psw}) (请输入你的 SSR 密码, 默认值 ${new_psw}): " password
    [[ -z ${password} ]] && password=${new_psw}
    echo "Your SSR password is (你的 SSR 密码是) ${password}"

    local ssr_ot_path=`head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16`
    stty erase '^H' && read -p "Please input your SSRoT path (default ${ssr_ot_path}) (请输入你的 SSRoT 路径, 默认值 ${ssr_ot_path}): " ssrot_path
    [[ -z ${ssrot_path} ]] && ssrot_path=${ssr_ot_path}
    echo "Your SSRoT path is (你的 SSRoT 路径是) ${ssrot_path}"

    create_app_files

    download_ssr_bin
   
    #pkill -f ssr-server
    #${curr_path}/${ssr_dir}/ssr-server -d -f

    ibmcloud cf push

    echo "==== configuration file ${curr_path}/${ssr_dir}/${config_file} ===="
    cat ${curr_path}/${ssr_dir}/${config_file}
    
    cd ..
}

main
