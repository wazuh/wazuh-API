
###
#  Powershell script for registering agents automatically with the API
#  Copyright (C) 2017 Wazuh, Inc. All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

function Ignore-SelfSignedCerts {
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class PolicyCert : ICertificatePolicy {
            public PolicyCert() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object PolicyCert
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
}

function req($method, $resource, $params){
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))
    $url = $base_url + $resource;

    try{
        return Invoke-WebRequest -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method $method -Uri $url -Body $params
    }catch{
        return $_.Exception
    }

}

# Configuration
$base_url = "http://<Wazuh-Manager-IP>:55000"
$username = "foo"
$password = "bar"
$agent_name = $env:computername
$path = "C:\Program Files (x86)\ossec-agent\"
$config = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$wazuh_manager = "<Wazuh-Manager-IP>"
Ignore-SelfSignedCerts

# Test API integration to make sure IE has run through initial startup dialogue - This can be a problem with new servers.

try{
    $testresponse = req -method "GET" -resource "/manager/info?pretty" | ConvertFrom-Json | select -expand data -ErrorAction Stop -ErrorVariable geterr

    Write-Output "The Wazuh manager is contactable via the API, the response is: `n $($testresponse)"
    }catch{
    Write-Host -ForegroundColor Red "IE has not had it's initial startup dialogue dismissed, please complete this step and try again. Script will exit. Error: $($geterr)`n .Please Run OSSEC_AgentConfig Separately once you correct the error."
    Exit
    }

# Test for agent already existing in manager

$agentexist = req -method "GET" -resource "/agents?pretty" -params @{search=$agent_name} # searches for the agent based on the env variable name

$agentinfo = $agentexist.Content | ConvertFrom-Json | select -expand data | select totalitems

$agentexistid = $agentexist.Content | ConvertFrom-Json | select -expand data | select -expand items | select id # expands the embedded JSON items to retrieve the agent ID

# If agent does not already exist proceed to create agent and register the agent key

if ($agentinfo.totalitems -lt 1){

# Adding agent and getting Id and key from manager

Write-Output "`r`nAdding agent:"
$response = req -method "POST" -resource "/agents" -params @{name=$agent_name} | ConvertFrom-Json
If ($response.error -ne '0') {
  Write-Output "ERROR: $($response.message)"
  Exit
}
$agent_id = $response.data.id
$agent_key = $responce.data.key
Write-Output "Agent '$($agent_name)' with ID '$($agent_id)' added."

# Importing key

Write-Output "`r`nImporting authentication key:"
echo "y" | & "$($path)manage_agents.exe" "-i $($agent_key)" "y`r`n"

# Restarting agent

Write-Output "`r`nRestarting:"
$srvName = "OssecSvc"

Write-Output "Stopping service."
Stop-Service $srvName
$srvStat = Get-Service $srvName
Write-Output "$($srvName) is now $($srvStat.status)"

Start-Sleep -s 10

Add-Content $config "`n<ossec_config>   <client>    <server>  <address>$($wazuh_manager)</address> </server>   </client> </ossec_config>"

Start-Sleep -s 10

Write-Output "Starting service."
Start-Service $srvName
$srvStat = Get-Service $srvName
Write-Output "$($srvName) is now $($srvStat.status)"
}
Else{

# If agent is found in manager by name it will retrieve the key and configure the agent

$response = req -method "GET" -resource "/agents/$($agentexistid.id)/key" | ConvertFrom-Json
# Key received from manager
$agent_key = $response.data
# Importing agent key from manager
Write-Output "`r`nImporting authentication key:"
echo "y" | & "$($path)manage_agents.exe" "-i $($agent_key)" "y`r`n"

Write-Output "`r`nRestarting:"
$srvName = "OssecSvc"

Write-Output "Stopping service."
Stop-Service $srvName
$srvStat = Get-Service $srvName
Write-Output "$($srvName) is now $($srvStat.status)"

Start-Sleep -s 5

Add-Content $config "`n<ossec_config>   <client>    <server>  <address>$($wazuh_manager)</address> </server>   </client> </ossec_config>"

Start-Sleep -s 5

Write-Output "Starting service."
Start-Service $srvName
$srvStat = Get-Service $srvName
Write-Output "$($srvName) is now $($srvStat.status)"


}
