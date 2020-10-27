#!/bin/bash

#==========================================================
#   System Request: Debian 7+ / Ubuntu 14.04+ / Centos 7+
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
Info="${Green}[Info]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[Error]${Font}"

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

function get_char() {
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

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

# Reverse proxy entry point.
export reverse_proxy_location=$(random_string_gen 20)

function is_root() {
    if [ `id -u` == 0 ]; then
        echo -e "${OK} ${GreenBG} The current account is the root user, enter the installation process ${Font} "
        sleep 3
    else
        echo -e "${Error} ${RedBG} The current account is not the root user, please switch to the root user and re-execute this script ${Font}" 
        exit 1
    fi
}

source /etc/os-release

# Extract the English name of the distribution system from VERSION, in order to add the corresponding nginx apt source under debian / ubuntu
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

function check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Centos ${VERSION_ID} ${VERSION} ${Font} "
        INS="yum"
        echo -e "${OK} ${GreenBG} Please wait patiently during SElinux settings, do not perform other operations ${Font} "
        setsebool -P httpd_can_network_connect 1
        echo -e "${OK} ${GreenBG} SElinux setup complete ${Font} "
        ## Centos can also be installed by adding epel repositories, no changes are made currently
        cat>/etc/yum.repos.d/nginx.repo<<EOF
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/mainline/centos/7/\$basearch/
gpgcheck=0
enabled=1
EOF
        echo -e "${OK} ${GreenBG} nginx source installation complete ${Font}" 
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Debian ${VERSION_ID} ${VERSION} ${Font} "
        INS="apt"
        ## Add nginx apt source
        if [ ! -f nginx_signing.key ]; then
            echo "deb http://nginx.org/packages/mainline/debian/ ${VERSION} nginx" >> /etc/apt/sources.list
            echo "deb-src http://nginx.org/packages/mainline/debian/ ${VERSION} nginx" >> /etc/apt/sources.list
            wget -nc https://nginx.org/keys/nginx_signing.key
            apt-key add nginx_signing.key
        fi
    elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Ubuntu ${VERSION_ID} ${VERSION_CODENAME} ${Font} "
        INS="apt"
        ## Add nginx apt source
        if [ ! -f nginx_signing.key ]; then
            echo "deb http://nginx.org/packages/mainline/ubuntu/ ${VERSION_CODENAME} nginx" >> /etc/apt/sources.list
            echo "deb-src http://nginx.org/packages/mainline/ubuntu/ ${VERSION_CODENAME} nginx" >> /etc/apt/sources.list
            wget -nc https://nginx.org/keys/nginx_signing.key
            apt-key add nginx_signing.key
        fi
    else
        echo -e "${Error} ${RedBG} Current system is ${ID} ${VERSION_ID} is not in the list of supported systems, installation is interrupted ${Font} "
        exit 1
    fi
}

function over_write_resolve_file() {
    echo "脚本将完全重写 /etc/resolv.conf 文件, 参考网站 https://nat64.xyz/ , 请按任意键继续, 或者 Ctrl+C 退出安装脚本"
    echo "Script will over write your /etc/resolv.conf file, see https://nat64.xyz/ "
    echo "Press any key to start...or Press Ctrl+C to quit"
    char=`get_char`
    cat > /etc/resolv.conf <<EOF
nameserver 2a09:11c0:f1:bbf0::70
nameserver 2001:67c:2b0::4
nameserver 2001:67c:2b0::6
EOF
}

function judge() {
    if [[ $? -eq 0 ]]; then
        echo -e "${OK} ${GreenBG} $1 Completed ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 Failed ${Font}"
        exit 1
    fi
}

function dependency_install() {
    ${INS} install curl wget git lsof -y

    if [[ "${ID}" == "centos" ]]; then
       ${INS} -y install crontabs
       ${INS} -y install make zlib zlib-devel gcc-c++ libtool openssl openssl-devel
    else
        ${INS} install cron vim curl -y
        ${INS} update -y
        ${INS} install cmake make zlib1g zlib1g-dev build-essential autoconf libtool openssl libssl-dev -y
        if [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 20 ]]; then
            ${INS} install python3 python python2-minimal inetutils-ping -y
        else
            ${INS} install python3 python python-minimal -y
        fi
    fi
    judge "Installing crontab"

    # New system does not require net-tools for IP determination.
    # ${INS} install net-tools -y
    # judge "Installing net-tools"

    ${INS} install bc -y
    judge "Installing bc"

    ${INS} install unzip -y
    judge "Installing unzip"
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
    echo "请输入 你的网站域名 (形如 mygooodsite.com)"
    stty erase '^H' && read -p "Please enter your domain name (for example: mygooodsite.com): " web_svr_domain
    local web_svr_ip_addr=`ping ${web_svr_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}' | sed '1{s/[^(]*(//;s/).*//;q}'`
    echo -e "${OK} ${GreenBG} Obtaining public IP information, please wait patiently ${Font}"
    web_svr_local_ip_addr=`curl ip.sb`
    echo -e "DNS resolution IP: ${web_svr_ip_addr}"
    echo -e "Local IP: ${web_svr_local_ip_addr}"
    sleep 2
    if [[ $(echo ${web_svr_local_ip_addr} | tr a-z A-Z) = $(echo ${web_svr_ip_addr} | tr a-z A-Z) ]]; then
        echo -e "${OK} ${GreenBG} The DNS resolution IP matches local IP ${Font}"
        sleep 2
        web_svr_local_ip_addr=${web_svr_domain}
    else
        echo -e "${Error} ${RedBG} The DNS resolution IP does not match the local IP. Do you want to continue the installation? (y/n) ${Font}" && read install
        case $install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} Continue to install ${Font}" 
            sleep 2
            web_svr_local_ip_addr=${web_svr_domain}
            ;;
        *)
            echo -e "${RedBG} Installation terminated ${Font}" 
            exit 2
            ;;
        esac
    fi
    
    local rvs_path=${reverse_proxy_location}
    echo "请输入 反向代理入口路径(不带前后斜杠), 默认值 ${rvs_path} "
    stty erase '^H' && read -p "Please enter reverse proxy path without slashes (default ${rvs_path}):" rvs_path
    [[ -z ${rvs_path} ]] && rvs_path=${reverse_proxy_location}
    reverse_proxy_location=${rvs_path}
}

function input_web_listen_port() {
    local port="443"
    stty erase '^H' && read -p "Please enter the access port number (default: 443):" port
    [[ -z ${port} ]] && port="443"
    echo ${port}
}

function nginx_install() {
    if [[ -x /usr/sbin/nginx ]] && [[ -d /etc/nginx ]]; then
        echo -e "${OK} ${GreenBG} nginx has been installed before this moment ${Font}"
        return 0
    fi

    ${INS} install nginx -y

    if [[ -d /etc/nginx ]]; then
        echo -e "${OK} ${GreenBG} nginx installation is complete ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} nginx installation failed ${Font}"
        exit 5
    fi

    if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
        echo -e "${OK} ${GreenBG} nginx initial configuration backup completed ${Font}"
        sleep 1
    fi
}

function nginx_web_server_config_begin() {
    rm -rf /etc/nginx/sites-enabled/*

    rm -rf ${site_dir}
    mkdir -p ${site_dir}/.well-known/acme-challenge/
    curl -L https://raw.githubusercontent.com/nginx/nginx/master/docs/html/index.html -o ${site_dir}/index.html
    curl -L https://raw.githubusercontent.com/nginx/nginx/master/docs/html/50x.html -o ${site_dir}/50x.html
    judge "[nginx] copy files"

    rm -rf ${nginx_conf_dir}/*
    cat > ${nginx_conf} <<EOF
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name localhost;
        index index.html index.htm index.nginx-debian.html;
        root  ${site_dir};
    }
EOF

    systemctl stop nginx
    sleep 2
    systemctl start nginx
    sleep 2
}

function do_lets_encrypt_certificate_authority() {
    local org_pwd=`pwd`

    mkdir ${site_cert_dir}
    cd ${site_cert_dir}
    rm -rf *

    openssl genrsa 4096 > account.key
    judge "[CA] Create account key"


    local openssl_cnf="/etc/ssl/openssl.cnf"
    if [[ "${ID}" == "centos" ]]; then
        openssl_cnf="/etc/pki/tls/openssl.cnf"
    fi

    openssl genrsa 4096 > domain.key
    openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat ${openssl_cnf} <(printf "[SAN]\nsubjectAltName=DNS:${web_svr_domain}")) > domain.csr
    judge "[CA] Create CSR file"

    curl -L https://raw.githubusercontent.com/diafygi/acme-tiny/master/acme_tiny.py -o acme_tiny.py
    python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir ${site_dir}/.well-known/acme-challenge/ > ./signed.crt
    judge "[CA] Obtain website certificate"

    wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem
    cat signed.crt intermediate.pem > chained.pem
    judge "[CA] Merger of intermediate certificate and website certificate"

    wget -O - https://letsencrypt.org/certs/isrgrootx1.pem > root.pem
    cat intermediate.pem root.pem > full_chained.pem
    judge "[CA] Root certificate and intermediate certificate merge"

    cd ${org_pwd}

    judge "[CA] Certificate configuration"
}

function acme_cron_update(){
    cat > ${site_cert_dir}/renew_cert.sh <<EOF
#!/bin/bash

cd ${site_cert_dir}
python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir ${site_dir}/.well-known/acme-challenge/ > ./signed.crt || exit
wget -O - https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem > intermediate.pem
cat signed.crt intermediate.pem > chained.pem
systemctl stop nginx
sleep 2
systemctl start nginx
sleep 2
EOF

    chmod a+x ${site_cert_dir}/renew_cert.sh

    local cron_name="cron"
    if [[ "${ID}" == "centos" ]]; then
        cron_name="crond"
    fi

    systemctl stop ${cron_name}
    sleep 2
    rm -rf tmp_info
    crontab -l > tmp_info
    echo "0 0 1 * * ${site_cert_dir}/renew_cert.sh >/dev/null 2>&1" >> tmp_info && crontab tmp_info && rm -rf tmp_info
    systemctl start ${cron_name}

    judge "cron scheduled task update"
}

function nginx_web_server_config_end() {
    rm -rf ${nginx_conf}
    cat > ${nginx_conf} <<EOF

    server {
        listen ${web_svr_listen_port} ssl default_server;
        listen [::]:${web_svr_listen_port} ssl default_server;
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
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name ${web_svr_domain};
        index index.html index.htm index.nginx-debian.html;
        root  ${site_dir};

        location /${reverse_proxy_location}/ {
            proxy_redirect off;
            proxy_pass http://${web_svr_reverse_proxy_host}:${web_svr_reverse_proxy_port};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }
    }

EOF

    systemctl stop nginx
    sleep 2
    systemctl start nginx
    sleep 2
}

ssr_n_install() {
    rm -rf ${ssr_n_install_sh}

    curl -L ${ssr_n_install_sh_url} -o ${ssr_n_install_sh}

    if [[ -f ${ssr_n_install_sh} ]]; then
        chmod +x ${ssr_n_install_sh}
        bash ${ssr_n_install_sh} install
        judge "Installing ShadowsocksR Native"
    else
        echo -e "${Error} ${RedBG} ShadowsocksR Native installation file download failed, please check the download address is available ${Font}"
        exit 4
    fi
}

# usage:
#   port_exist_check 80
#   port_exist_check ${web_svr_listen_port}
#
port_exist_check() {
    if [[ 0 -eq `lsof -i:"$1" | wc -l` ]];then
        echo -e "${OK} ${GreenBG} $1 port is not occupied ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} Detected that port $1 is occupied, the following is details ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} Try to kill the occupied process after 5s... ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill completed ${Font}"
        sleep 1
    fi
}

function web_camouflage(){
    # ## Caution: Here conflicts with the default path of the LNMP script. 
    # ## Do not use this script in an environment where LNMP is installed,
    # ## otherwise you will be at your own risk.
    # rm -rf /home/wwwroot && mkdir -p /home/wwwroot && cd /home/wwwroot
    # git clone https://github.com/wulabing/sCalc.git
    judge "web camouflage"
}

function main() {
    is_root
    check_system

    # over_write_resolve_file

    dependency_install
    web_svr_reverse_proxy_port=`random_listen_port`
    domain_check
    echo "请输入 站点端口号 (默认值 443) "
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
