#!/bin/bash

#==========================================================
#   System Request: Debian 7+ / Ubuntu 14.04+ / Centos 6+
#   Author: ssrlive
#   Dscription: ShadowsocksR over TLS onekey
#   Version: 1.0.0
#==========================================================

#fonts color
Green="\033[32m" 
Red="\033[31m" 
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

ssr_n_install_sh="ssrn-install.sh"
ssr_n_install_sh_url="https://raw.githubusercontent.com/ShadowsocksR-Live/shadowsocksr-native/master/install/ssrn-install.sh"

ssr_conf_dir="/etc/ssr-native"
ssr_conf="${ssr_conf_dir}/config.json"
nginx_conf_dir="/etc/nginx/conf.d"
nginx_conf="${nginx_conf_dir}/ssr.conf"
site_dir="/fakesite"
site_cert_dir="/fakesite_cert"

export ssr_ot_enabled=true
export web_svr_domain=""
export web_svr_local_ip_addr=""
export web_svr_listen_port="443"
export web_svr_reverse_proxy_host="127.0.0.1"
export web_svr_reverse_proxy_port=10000

function random_string_gen() {
    local PASS=""
    local MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" # "~!@#$%^&*()_+="
    local LENGTH=$1
    [ -z $1 ] && LENGTH="16"
    while [ "${n:=1}" -le "$LENGTH" ]
    do
        PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
        let n+=1
    done

    echo ${PASS}
}

# 反向代理入口点.
export reverse_proxy_location=$(random_string_gen 20)

function is_root() {
    if [ `id -u` == 0 ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font} "
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}" 
        exit 1
    fi
}

source /etc/os-release

#从 VERSION 中提取发行版系统的英文名称，为了在 debian/ubuntu 下添加相对应的 nginx apt 源
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

function check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font} "
        INS="yum"
        echo -e "${OK} ${GreenBG} SElinux 设置中，请耐心等待，不要进行其他操作${Font} "
        setsebool -P httpd_can_network_connect 1
        echo -e "${OK} ${GreenBG} SElinux 设置完成 ${Font} "
        ## Centos 也可以通过添加 epel 仓库来安装，目前不做改动
        cat>/etc/yum.repos.d/nginx.repo<<EOF
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/mainline/centos/7/\$basearch/
gpgcheck=0
enabled=1
EOF
        echo -e "${OK} ${GreenBG} nginx 源 安装完成 ${Font}" 
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font} "
        INS="apt"
        ## 添加 nginx apt 源
        if [ ! -f nginx_signing.key ]; then
            echo "deb http://nginx.org/packages/mainline/debian/ ${VERSION} nginx" >> /etc/apt/sources.list
            echo "deb-src http://nginx.org/packages/mainline/debian/ ${VERSION} nginx" >> /etc/apt/sources.list
            wget -nc https://nginx.org/keys/nginx_signing.key
            apt-key add nginx_signing.key
        fi
    elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${VERSION_CODENAME} ${Font} "
        INS="apt"
        ## 添加 nginx apt 源
        if [ ! -f nginx_signing.key ]; then
            echo "deb http://nginx.org/packages/mainline/ubuntu/ ${VERSION_CODENAME} nginx" >> /etc/apt/sources.list
            echo "deb-src http://nginx.org/packages/mainline/ubuntu/ ${VERSION_CODENAME} nginx" >> /etc/apt/sources.list
            wget -nc https://nginx.org/keys/nginx_signing.key
            apt-key add nginx_signing.key
        fi
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font} "
        exit 1
    fi
}

function judge() {
    if [[ $? -eq 0 ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败 ${Font}"
        exit 1
    fi
}

function dependency_install() {
    ${INS} install wget git lsof -y

    if [[ "${ID}" == "centos" ]]; then
       ${INS} -y install crontabs
       ${INS} -y install make zlib zlib-devel gcc-c++ libtool openssl openssl-devel
    else
        ${INS} install cron vim curl -y
        ${INS} update -y
        ${INS} install make zlib1g zlib1g-dev build-essential autoconf libtool openssl libssl-dev -y
        ${INS} install python3 python python-minimal cmake git -y
    fi
    judge "安装 crontab"

    # 新版的 IP 判定不需要使用 net-tools
    # ${INS} install net-tools -y
    # judge "安装 net-tools"

    ${INS} install bc -y
    judge "安装 bc"

    ${INS} install unzip -y
    judge "安装 unzip"
}

function random_listen_port() {
    local ssr_port=0
    while true; do
        ssr_port=$(shuf -i 9000-19999 -n 1)
        expr ${ssr_port} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${ssr_port} -ge 1 ] && [ ${ssr_port} -le 65535 ] && [ ${ssr_port:0:1} != 0 ]; then
                break
            fi
        fi
    done
    echo ${ssr_port}
}

function domain_check() {
    local install=""
    stty erase '^H' && read -p "请输入你的域名信息 (eg:mygoodsite.com): " web_svr_domain
    local web_svr_ip_addr=`ping ${web_svr_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    echo -e "${OK} ${GreenBG} 正在获取 公网 IP 信息, 请耐心等待 ${Font}"
    web_svr_local_ip_addr=`curl -4 ip.sb`
    echo -e "域名 DNS 解析 IP: ${web_svr_ip_addr}"
    echo -e "本机 IP: ${web_svr_local_ip_addr}"
    sleep 2
    if [[ $(echo ${web_svr_local_ip_addr}|tr '.' '+'|bc) -eq $(echo ${web_svr_ip_addr}|tr '.' '+'|bc) ]]; then
        echo -e "${OK} ${GreenBG} 域名 DNS 解析 IP 与 本机 IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 域名 DNS 解析 IP 与 本机 IP 不匹配, 是否继续安装? (y/n) ${Font}" && read install
        case $install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} 继续安装 ${Font}" 
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}" 
            exit 2
            ;;
        esac
    fi
}

function input_web_listen_port() {
    local port="443"
    stty erase '^H' && read -p "请输入连接端口（default: 443）:" port
    [[ -z ${port} ]] && port="443"
    echo ${port}
}

function nginx_install() {
    if [[ -x /usr/sbin/nginx ]] && [[ -d /etc/nginx ]]; then
        echo -e "${OK} ${GreenBG} nginx 此前已经安装 ${Font}"
        return 0
    fi

    ${INS} install nginx -y

    if [[ -d /etc/nginx ]]; then
        echo -e "${OK} ${GreenBG} nginx 安装完成 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} nginx 安装失败 ${Font}"
        exit 5
    fi

    if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
        echo -e "${OK} ${GreenBG} nginx 初始配置备份完成 ${Font}"
        sleep 1
    fi
}

function nginx_web_server_config_begin() {
    rm -rf /etc/nginx/sites-enabled/*

    rm -rf ${site_dir}
    mkdir -p ${site_dir}/.well-known/acme-challenge/
    wget https://raw.githubusercontent.com/nginx/nginx/master/docs/html/index.html -O ${site_dir}/index.html
    wget https://raw.githubusercontent.com/nginx/nginx/master/docs/html/50x.html -O ${site_dir}/50x.html
    judge "[nginx] 复制文件"

    rm -rf ${nginx_conf_dir}/*
    cat > ${nginx_conf} <<EOF
    server {
        listen 80;
        server_name localhost;
        index index.html index.htm index.nginx-debian.html;
        root  ${site_dir};
    }
EOF

    nginx -s stop
    nginx
}

function do_lets_encrypt_certificate_authority() {
    local org_pwd=`pwd`

    mkdir ${site_cert_dir}
    cd ${site_cert_dir}
    rm -rf *

    openssl genrsa 4096 > account.key
    judge "[CA] 创建帐号 key"


    local openssl_cnf="/etc/ssl/openssl.cnf"
    if [[ "${ID}" == "centos" ]]; then
        openssl_cnf="/etc/pki/tls/openssl.cnf"
    fi

    openssl genrsa 4096 > domain.key
    openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat ${openssl_cnf} <(printf "[SAN]\nsubjectAltName=DNS:${web_svr_domain},DNS:www.${web_svr_domain}")) > domain.csr
    judge "[CA] 创建 CSR 文件"

    wget https://raw.githubusercontent.com/diafygi/acme-tiny/master/acme_tiny.py
    python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir ${site_dir}/.well-known/acme-challenge/ > ./signed.crt
    judge "[CA] 获取 网站证书"

    wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem
    cat signed.crt intermediate.pem > chained.pem
    judge "[CA] 中间证书 和 网站证书 合并"

    wget -O - https://letsencrypt.org/certs/isrgrootx1.pem > root.pem
    cat intermediate.pem root.pem > full_chained.pem
    judge "[CA] 根证书 和 中间证书 合并"

    cd ${org_pwd}

    judge "[CA] 证书配置"
}

function acme_cron_update(){
    cat > ${site_cert_dir}/renew_cert.sh <<EOF
#!/bin/bash

cd ${site_cert_dir}
python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir ${site_dir}/.well-known/acme-challenge/ > ./signed.crt || exit
wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem
cat signed.crt intermediate.pem > chained.pem
nginx -s reload
EOF

    chmod a+x ${site_cert_dir}/renew_cert.sh

    local cron_name="cron"
    if [[ "${ID}" == "centos" ]]; then
        cron_name="crond"
    fi

    systemctl stop ${cron_name}
    rm -rf tmp_info
    crontab -l > tmp_info
    echo "0 0 1 * * ${site_cert_dir}/renew_cert.sh >/dev/null 2>&1" >> tmp_info && crontab tmp_info && rm -rf tmp_info
    systemctl start ${cron_name}

    judge "cron 计划任务更新"
}

function nginx_web_server_config_end() {
    rm -rf ${nginx_conf}
    cat > ${nginx_conf} <<EOF

    server {
        listen ${web_svr_listen_port} ssl;
        ssl on;
        ssl_certificate       ${site_cert_dir}/chained.pem;
        ssl_certificate_key   ${site_cert_dir}/domain.key;
        ssl_protocols         TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers           HIGH:!aNULL:!MD5;
        server_name           ${web_svr_domain};
        index index.html index.htm index.nginx-debian.html;
        root  ${site_dir};
        error_page 400 = /400.html;

        location /${reverse_proxy_location}/ {
            proxy_redirect off;
            proxy_pass http://${web_svr_reverse_proxy_host}:${web_svr_reverse_proxy_port};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }
    }

    server {
        listen 80;
        server_name ${web_svr_domain};
        index index.html index.htm index.nginx-debian.html;
        root  ${site_dir};

        location /.well-known/acme-challenge/ {
        }
        
        location / {
            rewrite ^/(.*)$ https://${web_svr_domain}/$1 permanent;
        }
    }

EOF

    nginx -s reload
}

ssr_n_install() {
    rm -rf ${ssr_n_install_sh}

    wget --no-check-certificate ${ssr_n_install_sh_url}

    if [[ -f ${ssr_n_install_sh} ]]; then
        chmod +x ${ssr_n_install_sh}
        bash ${ssr_n_install_sh} install
        judge "安装 ShadowsocksR Native"
    else
        echo -e "${Error} ${RedBG} ShadowsocksR Native 安装文件下载失败, 请检查下载地址是否可用 ${Font}"
        exit 4
    fi
}

# usage:
#   port_exist_check 80
#   port_exist_check ${web_svr_listen_port}
#
port_exist_check() {
    if [[ 0 -eq `lsof -i:"$1" | wc -l` ]];then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}

function web_camouflage(){
    # ## 请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    # rm -rf /home/wwwroot && mkdir -p /home/wwwroot && cd /home/wwwroot
    # git clone https://github.com/wulabing/sCalc.git
    judge "web 站点伪装"   
}

function main() {
    is_root
    check_system
    dependency_install
    web_svr_reverse_proxy_port=`random_listen_port`
    domain_check
    web_svr_listen_port=`input_web_listen_port`
    nginx_install
    nginx_web_server_config_begin
    do_lets_encrypt_certificate_authority
    acme_cron_update
    nginx_web_server_config_end

    ssr_n_install

    web_camouflage
}

main
