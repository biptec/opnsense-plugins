#!/bin/sh

# check a generated primary zone file

ZONENAME=${1}
ZONEID=${2}
case "${ZONEID}" in
    *[!0-9a-fA-F-]*|'') echo "Invalid zone identifier"; exit 0 ;;
esac
ZONEPATH="/usr/local/etc/namedb/primary/${ZONEID}.db"
if checkzone_errors=$(named-checkzone "${ZONENAME}" "${ZONEPATH}" 2>&1); then
    echo "Zone check completed successfully"
    echo "$checkzone_errors"
else
    echo "$checkzone_errors"
fi

exit 0
