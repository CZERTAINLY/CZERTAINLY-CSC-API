#!/bin/sh

cscapiHome="/opt/cscapi"
source ${cscapiHome}/static-functions

log "INFO" "Launching the CSC API"

# Set debug options if required
if [ x"${REMOTE_DEBUG}" != x ] && [ "${REMOTE_DEBUG}" != "false" ]
then
  java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar ./app.jar
else
  java -jar ./app.jar
fi

#exec "$@"
