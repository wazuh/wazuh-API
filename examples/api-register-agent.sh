#!/bin/bash

###
#  Shell script for registering agents automatically with the API
#  Copyright (C) 2017 Wazuh, Inc. All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###


# Connection variables
API_IP="10.0.0.1"
API_PORT="55000"
PROTOCOL="http"
USER="foo"
PASSWORD="bar"

display_help() {
cat <<HELP_USAGE

    $0  [-h] [-f|--force] [-q|--quiet] [agent]

   -h             Show this message.
   -f|--force     Force agent removal (if already registered)
                  The agent will be re-regitered with a new ID
   -s|--silent    Surpress the output while removing the agent
   agent          Agent name (if missing we will use the output
                  of the hostname command) 
HELP_USAGE
}

register_agent() {
  # Adding agent and getting Id from manager
  echo ""
  echo "Adding agent:"
  echo "curl -s -u $USER:**** -k -X POST -d 'name=$AGENT_NAME' $PROTOCOL://$API_IP:$API_PORT/agents"
  API_RESULT=$(curl -s -u $USER:"$PASSWORD" -k -X POST -d 'name='$AGENT_NAME $PROTOCOL://$API_IP:$API_PORT/agents)
  echo -e $API_RESULT | grep -q "\"error\":0" 2>&1

  if [ "$?" != "0" ]; then
    echo -e $API_RESULT | sed -rn 's/.*"message":"(.+)".*/\1/p'
    exit 1
  fi
  # Get agent id and agent key 
  AGENT_ID=$(echo $API_RESULT | cut -d':' -f 4 | cut -d ',' -f 1)
  AGENT_KEY=$(echo $API_RESULT | cut -d':' -f 5 | cut -d '}' -f 1)

  echo "Agent '$AGENT_NAME' with ID '$AGENT_ID' added."
  echo "Key for agent '$AGENT_ID' received."

  # Importing key
  echo ""
  echo "Importing authentication key:"
  echo "y" | /var/ossec/bin/manage_agents -i $AGENT_KEY

  # Restarting agent
  echo ""
  echo "Restarting:"
  echo ""
  /var/ossec/bin/ossec-control restart

  exit 0
}

remove_agent() {
  echo "Found: $AGENT_ID"
  echo "Removing previous registration for '$AGENT_NAME' using ID: $AGENT_ID ..."
  # curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/agents/001
  REMOVE_AGENT=$(curl -s -u $USER:"$PASSWORD" -k -X DELETE $PROTOCOL://$API_IP:$API_PORT/agents/$AGENT_ID)
  echo -e $REMOVE_AGENT
}

get_agent_id() {
  echo ""
  echo "Checking for Agent ID..."
  AGENT_ID=$(curl -s -u $USER:"$PASSWORD" -k -X GET $PROTOCOL://$API_IP:$API_PORT/agents/name/$AGENT_NAME | rev | cut -d: -f1 | rev | grep -o '".*"' | tr -d '"')
}

# MAIN
# ENTRY POINT

while getopts ':hfs' OPTION; do
  case "$OPTION" in
    h)
      display_help
      exit 0
      ;;
    f|--force)
      FORCE=true
      ;;
    s|--silent)
      SILENT=true
      ;;
  esac
done
# reset $1, $2 .... as normal argument after the flag
shift $(($OPTIND - 1))

# if no arguments are passed in after the flags, we assign the hostname value to the AGENT_NAME 
AGENT_NAME=${1:-$(hostname)}

get_agent_id

# check the return value. If we get an integer back then the agent is already registered. Anything else -> agent is not registered
  if ! [ "$AGENT_ID" -eq "$AGENT_ID" ] 2> /dev/null ; then
   echo "Starting registration process ..."
   :
  elif [[ "$FORCE" = true && "$SILENT" = "true" ]] ; then
   remove_agent > /dev/null 2>&1
  else
    if [[ "$FORCE" = true ]] ; then
      remove_agent
    fi
  fi

# Default action -> try to register the agent
register_agent
