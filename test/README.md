# Mocha tests

## Requirements

 * API installed and configurated (Configure API: https and auth (foo:bar)).
 * Packages npm installed: `glob`, `supertest`, `mocha`, `should`, `moment`

    ```
    npm install mocha -g
    npm install glob supertest mocha should moment
    ```

 * Cluster configurated and running with 2 connected nodes: `master` and `worker`.
 * Three connected agents (excluding manager):
    * id `000` and version _Wazuh v3.8.0_. Must have the following additional configuration:
    	* Enable experimental features in `/var/ossec/api/configuration/config.js`:
	    ```
	    config.experimental_features = true;
	    ```
	    * Disable cache in the same config.js
	    ```
	    config.cache_enabled = "no";
	    ```
        * Agentless:
            ```shellsession
            # /var/ossec/bin/ossec-control enable agentless
            ```
            ```xml
            <agentless>
                <type>ssh_integrity_check_linux</type>
                <frequency>300</frequency>
                <host>admin@192.168.1.108</host>
                <state>periodic_diff</state>
                <arguments>/etc /usr/bin /usr/sbin</arguments>
            </agentless>
            ```
        * Active response:
            ```xml
            <active-response>
                <disabled>no</disabled>
                <command>host-deny</command>
                <location>defined-agent</location>
                <agent_id>032</agent_id>
                <level>10</level>
                <rules_group>sshd,|pci_dss_11.4,</rules_group>
                <timeout>1</timeout>
            </active-response>
            ```
        * Client syslog
            ```shellsession
            # /var/ossec/bin/ossec-control enable client-syslog
            ```
            ```xml
            <syslog_output>
                <level>9</level>
                <server>192.168.1.241</server>
            </syslog_output>
            ```
        * Integration
            ```shellsession
            # /var/ossec/bin/ossec-control enable integrator
            ```
            ```xml
            <integration>
                <name>virustotal</name>
                <api_key>API_KEY</api_key> <!-- Replace with your VirusTotal API key -->
                <group>syscheck</group>
                <alert_format>json</alert_format>
                <hook_url></hook_url>
			</integration>
            ```
        * Logcollector socket:
            ```xml
            <socket>
                <name>custom_socket</name>
                <location>/var/run/custom.sock</location>
                <mode>tcp</mode>
                <prefix>custom_syslog: </prefix>
            </socket>
            ```
        * Mail:
            1. Follow steps detailed [here](https://documentation.wazuh.com/current/user-manual/manager/manual-email-report/smtp_authentication.html).
            2.
            ```xml
            <global>
                <email_notification>yes</email_notification>
                <email_to>hello@wazuh.com</email_to>
                <smtp_server>localhost</smtp_server>
                <email_from>wazuh@test.com</email_from>
            </global>
            <email_alerts>
                <email_to>you@example.com</email_to>
                <level>4</level>
                <do_not_delay />
            </email_alerts>
            ```



    * id `001` and version _Wazuh v3.8.0_.
    * id `002` and version _Wazuh v3.8.0_. Must have the following additional configuration:
        * Labels:
            ```xml
            <labels>
                <label key="aws.instance-id">i-052a1838c</label>
                <label key="aws.sec-group">sg-1103</label>
                <label key="network.ip">172.17.0.0</label>
                <label key="network.mac">02:42:ac:11:00:02</label>
                <label key="installation" hidden="yes">January 1st, 2017</label>
            </labels>
            ```
    * id `003` and version _Wazuh v3.5.0-1_.

 * DB syscheck activated: Add `wazuh_database.sync_syscheck=1` to the file `/var/ossec/etc/local_internal_options.conf`.
 * Restart wazuh-manager.
 * Then start needed services:
    1. Run `maild` service:
    ```shellsession
    #  /var/ossec/bin/ossec-maild
    ```
    2. Run `authd` service:
    ```shellsession
    #  /var/ossec/bin/ossec-authd
    ```

## Prepare environment
Every step detailed above can be automated by executing the following command from `./environment/vagrant` folder:
```shellsession
#  export WAZUH_API_PATH=/your/wazuh/api/path
#  vagrant up
```

## Run all tests
```shellsession
#  cd /home/vagrant/wazuh_api
#  mocha ./test --timeout 10000
```
