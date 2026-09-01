#!/bin/sh

home="/opt/software-cryptography-provider"
source ${home}/static-functions

log "INFO" "Launching the Software Cryptography Provider"
java $JAVA_OPTS -jar ./app.jar

#exec "$@"