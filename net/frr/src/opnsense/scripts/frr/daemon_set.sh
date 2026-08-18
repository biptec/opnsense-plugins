#!/bin/sh

for daemon in ospfd ospf6d bgpd bfdd ripd staticd; do
    pidfile="/var/run/frr/${daemon}.pid"
    [ -r "$pidfile" ] || continue
    pid=$(cat "$pidfile" 2>/dev/null)
    case "$pid" in
        ''|*[!0-9]*) continue ;;
    esac
    if [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null; then
        echo "$daemon"
    fi
done
