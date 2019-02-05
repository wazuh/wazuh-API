#!/usr/bin/env bash

master_ip=$1
manager_type=$2
node_name=$3

apt update
curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_pre_release.list
apt update
apt install wazuh-manager python-cryptography python-pip -y
curl -sL https://deb.nodesource.com/setup_8.x | bash -
apt-get install nodejs -y
apt-get install wazuh-api -y


sed -i "s:<key></key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:g" /var/ossec/etc/ossec.conf
sed -i "s:<node>NODE_IP</node>:<node>$master_ip</node>:g" /var/ossec/etc/ossec.conf
sed -i -e "/<cluster>/,/<\/cluster>/ s|<disabled>[a-z]\+</disabled>|<disabled>no</disabled>|g" /var/ossec/etc/ossec.conf
sed -i "s:<node_name>node01</node_name>:<node_name>$node_name</node_name>:g" /var/ossec/etc/ossec.conf

if [ "X${manager_type}" != "Xmaster" ]; then
    sed -i "s:<node_type>master</node_type>:<node_type>worker</node_type>:g" /var/ossec/etc/ossec.conf
fi

systemctl restart wazuh-manager

cat <<EOT >> /var/ossec/api/configuration/preloaded_vars.conf
COUNTRY="US"
STATE="State"
LOCALITY="Locality"
ORG_NAME="Org Name"
ORG_UNIT="Org Unit Name"
COMMON_NAME="Common Name"
PASSWORD="password"
USER=foo
PASS=bar
PORT=55000
HTTPS=Y
AUTH=Y
PROXY=N
EOT

/var/ossec/api/scripts/configure_api.sh

sed -i "s:wazuh_database.sync_syscheck=0:wazuh_database.sync_syscheck=1:g" /var/ossec/etc/internal_options.conf
sed -i "s:config.experimental_features  = false;:config.experimental_features = true;:g" /var/ossec/api/configuration/config.js

npm install apidoc -g
pip install requests

systemctl restart wazuh-api

echo "Configure OK"
