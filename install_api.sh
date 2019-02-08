#!/usr/bin/env bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Installer for Wazuh API
# Wazuh Inc.
#
# Usage:
#  ./install_api.sh [dependencies|download|dev]
#  ./install_api.sh                Install API from current path
#  ./install_api.sh dependencies   List dependencies
#  ./install_api.sh download       Download and install latest release (stable branch)
#  ./install_api.sh dev            Install API from current path in development mode


arg=$1  # empty, help, dependencies, download or dev
PREDEF_FILE=$(dirname $0)/configuration/preloaded_vars.conf
TRUE="true";
FALSE="false";

# Aux functions
isFile()
{
    FILE=$1
    ls ${FILE} >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo "${TRUE}"
        return 0;
    fi
    echo "${FALSE}"
    return 1;
}

print() {
    echo -e $1
}

error_and_exit() {
    print "Error executing command: '$1'.\n"

    if [ "X${API_BACKUP}" == "Xyes" ]; then
        print "Backup directory: $API_PATH_BACKUP"
        print "\t1. Save previous configuration: cp -rp $API_PATH_BACKUP/configuration $DEF_OSSDIR/tmp"
        print "\t2. Install API $API_OLD_VERSION"
        print "\t3. Restore configuration: mv $DEF_OSSDIR/tmp/configuration $API_PATH/configuration"
        print "\t4. Restart API"
    fi

    if [ -d "/root/wazuh-api-tmp" ]; then
        exec_cmd "rm -rf /root/wazuh-api-tmp"
    fi

    print "\nExiting."
    exit 1
}

exec_cmd() {
    eval $1 > /dev/null 2>&1 || error_and_exit "$1"
}

exec_cmd_bash() {
    bash -c "$1" || error_and_exit "$1"
}

get_configuration_value () { # $1 setting
    cat "$API_PATH/configuration/config.js" | grep -P "config.$1\s*=\s*\"" | grep -P '".*"' -o | tr -d '"'
}

edit_configuration() { # $1 -> setting,  $2 -> value
    sed -i "s/^config.$1\s=.*/config.$1 = \"$2\";/g" "$API_PATH/configuration/config.js" || error_and_exit "sed (editing configuration)"
}

get_type_service() {
    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        echo "systemctl"
    else
        echo "service"
    fi
}

url_latest_release () {
    LATEST_RELEASE=$(curl -L -s -H 'Accept: application/json' https://github.com/$1/$2/releases/latest)
    #LATEST_VERSION=$(echo $LATEST_RELEASE | sed -e 's/.*"tag_name":"\(.*\)".*/\1/')
    LATEST_VERSION=$(echo $LATEST_RELEASE | grep -P "\"tag_name\":\".+\"update_url" -o | grep -P "v\d+(?:\.\d+){0,2}\-*\w*" -o)
    ARTIFACT_URL="https://github.com/$1/$2/archive/$LATEST_VERSION.tar.gz"
    echo $ARTIFACT_URL
}

check_program_installed() {
    hash $1 > /dev/null 2>&1
    if [ "$?" != "0" ]; then
        print "$1 not found. is it installed?."
        print "Check the dependencies executing: ./install_api.sh dependencies"
        exit 1
    fi
}

# END Aux functions

show_info () {
    https=$(get_configuration_value "https")
    port=$(get_configuration_value "port")
    basic_auth=$(get_configuration_value "basic_auth")
    curl_msg="curl"

    if [ "X${https}" == "Xyes" ]; then
        proto="https"
    else
        proto="http"
    fi

    print "\nAPI URL: $proto://host_ip:$port/"
    if [ "X${update}" != "Xyes" ]; then
        print "user: 'foo'"
        print "password: 'bar'"
        curl_msg="$curl_msg -u foo:bar"
    else
        curl_msg="$curl_msg -u user:pass"
    fi
    if [ "X${basic_auth}" == "Xno" ]; then
        print "Authentication disabled (not secure)."
        curl_msg="curl"
    fi
    print "Configuration: $API_PATH/configuration"


    print "Test: $curl_msg -k $proto://127.0.0.1:55000?pretty"

}

help() {
    echo "./install_api.sh [dependencies|download|dev]"
    echo "./install_api.sh <options>      Install API from current path"
    echo "  Options:"
    echo "  --no-service                  Do not install API service"
    echo "./install_api.sh dependencies   List dependencies"
    echo "./install_api.sh download       Download and install latest release (stable branch)"
    echo "./install_api.sh dev            Install API from current path in development mode"
}

required_packages() {
    print "\nDebian and Ubuntu based Linux distributions:"
    print "\tNodeJS 4.x or newer:"
    print "\t\tcurl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -"
    print "\t\tsudo apt-get install -y nodejs"

    print "\nRed Hat, CentOS and Fedora:"
    print "\tNodeJS 4.x or newer:"
    print "\t\tcurl --silent --location https://rpm.nodesource.com/setup_6.x | bash -"
    print "\t\tsudo yum -y install nodejs"
}

previous_checks() {
    # Arguments
    if [ "X${arg}" == "Xdependencies" ]; then  # dependencies argument
        required_packages
        exit 0
    elif [ "X${arg}" == "Xhelp" ]; then  # help argument
        help
        exit 0
    elif [ "X${arg}" == "Xdev" ]; then  # dev argument
        API_SOURCES=`pwd`
    elif [ "X${arg}" == "Xdownload" ]; then   # download argument
        API_SOURCES="/root"
        DOWNLOAD_PATH=$(url_latest_release "wazuh" "wazuh-api")
    else
        API_SOURCES="."  # empty argument
    fi

    if [ "X${arg}" == "X--no-service" ]; then   # do not install api service
        NO_SERVICE="1"
    fi

    # Test root permissions
    if [ "$EUID" -ne 0 ]; then
        print "Please run this script with root permissions.\nExiting."
        exit 1
    fi

    # Paths
    OSSEC_CONF="/etc/ossec-init.conf"
    DEF_OSSDIR="/var/ossec"

    if ! [ -f $OSSEC_CONF ]; then
        print "Can't find $OSSEC_CONF. Is OSSEC installed?.\nExiting."
        exit 1
    fi

    . $OSSEC_CONF

    if [ -z "$DIRECTORY" ]; then
        DIRECTORY=$DEF_OSSDIR
    fi

    API_PATH="${DIRECTORY}/api"
    API_PATH_BACKUP="${DIRECTORY}/~api"
    FRAMEWORK_PATH="${DIRECTORY}/framework"
    API_BACKUP='no'
    serv_type=$(get_type_service)

    if ! [ -d $FRAMEWORK_PATH ]; then
        print "Can't find $FRAMEWORK_PATH. Is Wazuh installed?.\nExiting."
        exit 1
    fi

    # Dependencies
    check_program_installed "tar"
    check_program_installed "curl"
    check_program_installed "gcc"

    NODE_DIR=$(which nodejs 2> /dev/null)

    if [ "X$NODE_DIR" = "X" ]; then
        NODE_DIR=$(which node 2> /dev/null)

        if [ "X$NODE_DIR" = "X" ]; then
            echo "NodeJS binaries not found. Is NodeJS installed?"
            exit 1
        fi
    fi

    NODE_VERSION=`$NODE_DIR --version | grep -P '^v\d+' -o | grep -P '\d+' -o`

    if [ $NODE_VERSION -lt 4 ]; then
        print "The current version of NodeJS installed is not supported. Wazuh API requires NodeJS 4.x or newer."
        print "Review the dependencies executing: ./install_api.sh dependencies"
        exit 1
    fi

    check_program_installed "npm"

}

get_api () {
    if [ "X$DOWNLOAD_PATH" != "X" ]; then
        print "\nDownloading API from $DOWNLOAD_PATH"

        if [ -d "$API_SOURCES/wazuh-api-tmp" ]; then
            exec_cmd "rm -rf $API_SOURCES/wazuh-api-tmp"
        fi
        exec_cmd "mkdir -p $API_SOURCES/wazuh-api-tmp"

        exec_cmd "curl -sL $DOWNLOAD_PATH | tar xvz -C $API_SOURCES/wazuh-api-tmp"

        API_SOURCES="$API_SOURCES/wazuh-api-tmp/wazuh-api-*.*"

        API_NEW_VERSION=`cat $API_SOURCES/package.json | grep "version\":" | grep -P "\d+(?:\.\d+){0,2}\-*\w*" -o`
        print "\nInstalling Wazuh API $API_NEW_VERSION"
    else
        API_NEW_VERSION=`cat $API_SOURCES/package.json | grep "version\":" | grep -P "\d+(?:\.\d+){0,2}\-*\w*" -o`
        if [ "X${arg}" == "Xdev" ]; then
            print "\nInstalling Wazuh API $API_NEW_VERSION from current directory [DEV MODE]."
        else
            print "\nInstalling Wazuh API $API_NEW_VERSION from current directory."
        fi
    fi

}

backup_api () {
    if [ -e $API_PATH_BACKUP ]; then
        exec_cmd "rm -rf $API_PATH_BACKUP/*"
    else
        exec_cmd "mkdir $API_PATH_BACKUP"
        exec_cmd "chown root:ossec $API_PATH_BACKUP"
    fi

    if [ -e $API_PATH/package.json ]; then
        exec_cmd "cp -rLfp $API_PATH/package.json $API_PATH_BACKUP/package.json"
    fi

    if [ -d $API_PATH/configuration ]; then
        exec_cmd "cp -rLfp $API_PATH/configuration $API_PATH_BACKUP/configuration"
    fi

    if [ -d $API_PATH/ssl ]; then
        exec_cmd "cp -rLfp $API_PATH/ssl $API_PATH_BACKUP/ssl"
    fi

    API_BACKUP='yes'
    API_OLD_VERSION=`cat $API_PATH_BACKUP/package.json | grep "version\":" | grep -P "\d+(?:\.\d+){0,2}\-*\w*" -o`
}

restore_configuration () {

    if [[ ${API_OLD_VERSION} =~ ^3 ]] || [[ ${API_OLD_VERSION} =~ ^2 ]]; then
        exec_cmd "rm -rf $API_PATH/configuration"
        exec_cmd "cp -rfp $API_PATH_BACKUP/configuration $API_PATH/configuration"
        # Assign the right permissions
        setup_api_permissions

    elif [[ ${API_OLD_VERSION} =~ ^1 ]]; then
        exec_cmd "cp -rfp $API_PATH_BACKUP/ssl/htpasswd $API_PATH/configuration/auth/user"
        exec_cmd "cp -p $API_PATH_BACKUP/ssl/*.key $API_PATH_BACKUP/ssl/*.crt $API_PATH/configuration/ssl/"
        exec_cmd "chown -R root:root $API_PATH/configuration"
        exec_cmd "chmod -R 750 $API_PATH/configuration"
        exec_cmd "chmod u-x $API_PATH/configuration/ssl/*"
        RESTORE_WARNING="1"
    else
        RESTORE_WARNING="2"
    fi
}

setup_api_permissions () {

    # General permissions
    exec_cmd "chown -R root:ossec $API_PATH"
    exec_cmd "chown -R root:root $API_PATH/scripts"
    exec_cmd "chown -R root:root $API_PATH/configuration"
    exec_cmd "chmod -R 750 $API_PATH"

    # Remove execution permissions
    exec_cmd "chmod ugo-x $API_PATH/package.json"
    exec_cmd "chmod ugo-x $API_PATH/scripts/wazuh-api*"

    # config.js
    exec_cmd "chown root:ossec $API_PATH/configuration"
    exec_cmd "chown root:ossec $API_PATH/configuration/config.js"
    exec_cmd "chmod 740 $API_PATH/configuration/config.js"

    # API users permissions
    exec_cmd "chmod 660 $API_PATH/configuration/auth/user"

}

setup_api() {
    # Check if API is installed
    update="no"
    if [ -d $API_PATH ]; then
        backup_api
        print ""
        if [[ "X${REINSTALL}" != "X" ]]; then
            case $REINSTALL in
                [nN] ) update="no";;
                [yY] ) update="yes";;
            esac
        else
            while true; do
                read -p "Wazuh API is already installed (version $API_OLD_VERSION). Do you want to update it? [y/n]: " yn
                case $yn in
                    [Yy] ) update="yes"; break;;
                    [Nn] ) update="no"; break;;
                esac
            done
        fi
        if [ "X${update}" == "Xno" ]; then
            if [[ "X${REMOVE}" != "X" ]]; then
                case $REMOVE in
                    [nN] ) print "Not possible to install the API.\nExiting."; exit 1; break;;
                esac
            else
                while true; do
                    print ""
                    read -p "The installation directory already exists. Should I delete it? [y/n]: " yn
                    case $yn in
                        [Yy] ) break;;
                        [Nn] ) print "Not possible to install the API.\nExiting."; exit 1; break;;
                    esac
                done
            fi
        fi
        exec_cmd "rm -rf $API_PATH"
    fi

    # Copy files
    if [ "X${update}" == "Xyes" ]; then
        print "\nUpdating API ['$API_PATH']."
        e_msg="updated"
    else
        print "\nInstalling API ['$API_PATH']."
        e_msg="installed"
    fi
    if [ "X${arg}" == "Xdev" ]; then
        exec_cmd "ln -s $API_SOURCES $API_PATH"
    else
        exec_cmd "mkdir $API_PATH"
        exec_cmd "cd $API_SOURCES"
        exec_cmd "cp --parents -r app.js configuration controllers examples helpers models package.json scripts $API_PATH"
        exec_cmd "cd -"

        # Set up the right permissions for Wazuh API
        setup_api_permissions

        if [ -f "$API_PATH/configuration/ssl/.gitignore" ]; then
            exec_cmd "rm -f $API_PATH/configuration/ssl/.gitignore"
        fi
    fi

    if [ "X${update}" == "Xyes" ]; then
        restore_configuration

        # Remove framework
        if [ -d "$API_PATH/framework" ]; then
            exec_cmd "rm -rf $API_PATH/framework"
        fi
    fi

    print "\nInstalling NodeJS modules."
    if [ "X${arg}" == "Xdev" ]; then
        exec_cmd "cd $API_PATH && npm install"
    else
        exec_cmd "cd $API_PATH && npm install --production"
    fi
    exec_cmd "chown -R root:ossec $API_PATH/node_modules"
    exec_cmd "chmod -R 750 $API_PATH/node_modules"

    exec_cmd "ln -fs $API_PATH/node_modules/htpasswd/bin/htpasswd $API_PATH/configuration/auth/htpasswd"

    # Set OSSEC directory in API configuration
    if [ "X${DIRECTORY}" != "X/var/ossec" ]; then
        repl="\\\/"
        escaped_ossec_path=`echo "$DIRECTORY" | sed -e "s#\/#$repl#g"`
        edit_configuration "ossec_path" $escaped_ossec_path

    fi

    # Create/check api.log and /logs/api directory
    APILOG_PATH="${DIRECTORY}/logs/api.log"
    if [ ! -f $APILOG_PATH ]; then
        touch $APILOG_PATH
    fi
    exec_cmd "chown ossec:ossec $APILOG_PATH"
    exec_cmd "chmod 640 $APILOG_PATH"

    APILOG_DIR="${DIRECTORY}/logs/api"
    if [ ! -d $APILOG_DIR ]; then
        mkdir $APILOG_DIR
    fi
    exec_cmd "chown ossec:ossec $APILOG_DIR"
    exec_cmd "chmod 750 $APILOG_DIR"


    if [ -z "$NO_SERVICE" ]
    then
        print "\nInstalling service."
        echo "----------------------------------------------------------------"
        exec_cmd_bash "$API_PATH/scripts/install_daemon.sh"
        echo "----------------------------------------------------------------"
    else
        print "\nSkipping service installation."
    fi
}

main() {
    print "### Wazuh API ###"

    # Reading pre-defined file
    if [ ! `isFile ${PREDEF_FILE}` = "${FALSE}" ]; then
        . ${PREDEF_FILE}
    fi

    previous_checks
    get_api
    setup_api
    show_info

    if [ "X${RESTORE_WARNING}" == "X1" ]; then
        print "\nWarning: Some problems occurred when restoring your previous configuration ($API_PATH/configuration/config.js). Please, review it manually. Backup directory: $API_PATH_BACKUP."
    elif [ "X${RESTORE_WARNING}" == "X2" ]; then
        print "\nWarning: It was not possible to restore your previous configuration. Please, review it manually. Backup directory: $API_PATH_BACKUP."
    else
        exec_cmd "rm -rf $API_PATH_BACKUP"
    fi

    print "Note: You can configure the API executing $API_PATH/scripts/configure_api.sh"

    print "\n### [API $e_msg successfully] ###"
    exit 0
}

# Main
main
