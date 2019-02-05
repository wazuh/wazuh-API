#!/usr/bin/env bash

master_ip=$1
agent_name=$2
reporting_manager=$3

curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_pre_release.list
apt update
apt install wazuh-agent -y

# Register agent using authd
/var/ossec/bin/agent-auth -m $master_ip -A $agent_name
sed -i "s:MANAGER_IP:$reporting_manager:g" /var/ossec/etc/ossec.conf

# Enable and restart the Wazuh agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "Configure OK"
