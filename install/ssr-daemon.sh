#!/bin/bash
# description: A secure socks5 proxy, designed to protect your Internet traffic.

### BEGIN INIT INFO
# Provides:          ssr-native
# Required-Start:    $network $syslog
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Fast tunnel proxy that helps you bypass network censorship
# Description:       Start or stop the ShadowsocksR Native server
### END INIT INFO

# Author: ssrlive

NAME="ShadowsocksR Native"
DAEMON=/usr/bin/ssr-server
CONF=/etc/ssr-native/config.json

command_start="${DAEMON} -d -c ${CONF}"

PID=0
RETVAL=0

check_running(){
    PID=$(ps -ef | grep -v grep | grep -i "${DAEMON}" | awk '{print $2}')
    if [ -n "${PID}" ]; then
        return 0
    else
        return 1
    fi
}

do_start(){
    check_running
    if [ $? -eq 0 ]; then
        echo "${NAME} (pid ${PID}) is already running..."
        exit 0
    else
        ${command_start}
        RETVAL=$?
        if [ ${RETVAL} -eq 0 ]; then
            echo "Starting ${NAME} success"
        else
            echo "Starting ${NAME} failed"
        fi
    fi
}

do_stop(){
    check_running
    if [ $? -eq 0 ]; then
        kill ${PID}
        RETVAL=$?
        if [ ${RETVAL} -eq 0 ]; then
            echo "Stopping ${NAME} success"
        else
            echo "Stopping ${NAME} failed"
        fi
    else
        echo "${NAME} is stopped"
        RETVAL=1
    fi
}

do_status(){
    check_running
    if [ $? -eq 0 ]; then
        echo "${NAME} (pid ${PID}) is running..."
    else
        echo "${NAME} is stopped"
        RETVAL=1
    fi
}

do_restart(){
    do_stop
    sleep 0.5
    do_start
}

case "${1}" in
    start|stop|restart|status)
        do_${1}
        ;;
    *)
        echo "Usage: ${0} { start | stop | restart | status }"
        RETVAL=1
        ;;
esac

exit ${RETVAL}
