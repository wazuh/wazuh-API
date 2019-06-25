#!/bin/bash

# Copyright (C) 2015-2018 Wazuh, Inc. All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Installer for Wazuh API daemon
# Wazuh Inc.


I_OWNER="root"
I_GROUP="root"
I_XMODE="755"
I_FMODE="644"
I_SYSTEMD="/etc/systemd/system"
I_SYSVINIT="/etc/init.d"

check_service() {
  service_var=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  if [ -z "${service_var}" ]; then
    if command -v systemctl > /dev/null 2>&1 ; then
      if systemctl is-enabled wazuh-api > /dev/null 2>&1 ; then
        return 0
      else
        return 1
      fi
    elif command -v chkconfig > /dev/null 2>&1 ; then
      if chkconfig --list wazuh-api | grep on > /dev/null 2>&1 ; then
        return 0
      else
        return 1
      fi
    elif command -v update-rc.d > /dev/null 2>&1 ; then
      if ls /etc/rc*.d | grep wazuh-api > /dev/null 2>&1 ; then
        return 0
      else
        return 1
      fi
    elif command -v rc-update > /dev/null 2>&1 ; then
      if ls /etc/rc*.d | grep wazuh-api > /dev/null 2>&1 ; then
        return 0
      else
        return 1
      fi
    fi
  elif [ "X${service_var}" = "Xyes" ] || [ "X${service_var}" = "Xy" ]; then
    return 0
  else
    return 1
  fi
}

OSSEC_CONF="/etc/ossec-init.conf"
DEF_OSSDIR="/var/ossec"

# Test root permissions

if [ "$EUID" -ne 0 ]; then
    echo "Warning: Please run this script with root permissions."
fi

# Directory where OSSEC is installed

if ! [ -f $OSSEC_CONF ]; then
    echo "Can't find $OSSEC_CONF. Is OSSEC installed?"
    exit 1
fi

. $OSSEC_CONF

if [ -z "$DIRECTORY" ]; then
    DIRECTORY=$DEF_OSSDIR
fi

APP_PATH="${DIRECTORY}/api/app.js"
SCRIPTS_PATH="${DIRECTORY}/api/scripts"

if ! [ -f $APP_PATH ]; then
    echo "Can't find $APP_PATH. Is Wazuh API installed?"
    exit 1
fi

# Binary name for NodeJS

BIN_DIR=$(which nodejs 2> /dev/null)

if [ "X$BIN_DIR" = "X" ]; then
    BIN_DIR=$(which node 2> /dev/null)

    if [ "X$BIN_DIR" = "X" ]; then
        echo "NodeJS binaries not found. Is NodeJS installed?"
        exit 1
    fi
fi

# Install for systemd

if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
    echo "Installing for systemd"

    sed "s:^ExecStart=.*:ExecStart=$BIN_DIR $APP_PATH:g" $SCRIPTS_PATH/wazuh-api.service > $SCRIPTS_PATH/wazuh-api.service.tmp
    install -m $I_FMODE -o $I_OWNER -g $I_GROUP $SCRIPTS_PATH/wazuh-api.service.tmp $I_SYSTEMD/wazuh-api.service
    rm $SCRIPTS_PATH/wazuh-api.service.tmp
    systemctl daemon-reload
    if check_service ${ENABLE_WAZUH_SERVICE} ; then
        systemctl enable wazuh-api
        systemctl restart wazuh-api
    fi


# Install for SysVinit / Upstart

elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
    echo "Installing for SysVinit"

    sed "s:^BIN_DIR=.*:BIN_DIR=\"$BIN_DIR\":g" $SCRIPTS_PATH/wazuh-api > $SCRIPTS_PATH/wazuh-api.tmp
    sed -i "s:^APP_PATH=.*:APP_PATH=\"$APP_PATH\":g" $SCRIPTS_PATH/wazuh-api.tmp
    sed -i "s:^OSSEC_PATH=.*:OSSEC_PATH=\"${DIRECTORY}\":g" $SCRIPTS_PATH/wazuh-api.tmp
    install -m $I_XMODE -o $I_OWNER -g $I_GROUP $SCRIPTS_PATH/wazuh-api.tmp $I_SYSVINIT/wazuh-api
    rm $SCRIPTS_PATH/wazuh-api.tmp

    enabled=true
    if check_service ${ENABLE_WAZUH_SERVICE} ; then
        if [ -r "/etc/redhat-release" ] || [ -r "/etc/SuSE-release" ]; then
            /sbin/chkconfig --add wazuh-api > /dev/null 2>&1
        elif [ -f "/usr/sbin/update-rc.d" ] || [ -n "$(ps -e | egrep upstart)" ]; then
            update-rc.d wazuh-api defaults
        elif [ -r "/etc/gentoo-release" ]; then
            rc-update add wazuh-api default
        else
            echo "init script installed in $I_SYSVINIT/wazuh-api"
            echo "We could not enable it. Please enable the service manually."
            enabled=false
        fi
    else
        enabled=false
    fi

    if [ "$enabled" = true ]; then
        service wazuh-api restart
    fi
else
    echo "Warning: Unknown init system. Please run the API with:"
    echo "$BIN_DIR $APP_PATH > /dev/null 2>&1 < /dev/null &"
fi
