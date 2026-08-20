#!/bin/sh

SUPERVISOR_PID=/var/run/frr_carp_connected_monitor.supervisor.pid
CHILD_PID=/var/run/frr_carp_connected_monitor.child.pid
SCRIPT=/usr/local/opnsense/scripts/frr/carp_connected_monitor.py
STATE=/var/run/frr_carp_connected_fallback.json

is_running()
{
    [ -s "${SUPERVISOR_PID}" ] || return 1
    kill -0 "$(cat "${SUPERVISOR_PID}")" 2>/dev/null
}

start_monitor()
{
    if is_running; then
        return 0
    fi
    rm -f "${SUPERVISOR_PID}" "${CHILD_PID}"
    /usr/sbin/daemon -c -r -P "${SUPERVISOR_PID}" -p "${CHILD_PID}" \
        -T frr_carp_connected -S \
        /usr/local/bin/python3 "${SCRIPT}"
}

stop_monitor()
{
    if is_running; then
        kill "$(cat "${SUPERVISOR_PID}")"
        count=0
        while is_running && [ ${count} -lt 50 ]; do
            sleep 0.1
            count=$((count + 1))
        done
    fi
    rm -f "${SUPERVISOR_PID}" "${CHILD_PID}"
    /usr/local/bin/python3 "${SCRIPT}" --cleanup
}

case "$1" in
    start) start_monitor ;;
    stop) stop_monitor ;;
    restart) stop_monitor && start_monitor ;;
    status) is_running ;;
    *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 64 ;;
esac
