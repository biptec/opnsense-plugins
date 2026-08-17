#!/bin/sh
SUPERVISOR_PID=/var/run/api_extensions_carp_health.supervisor.pid
CHILD_PID=/var/run/api_extensions_carp_health.child.pid
SCRIPT=/usr/local/opnsense/scripts/OPNsense/ApiExtensions/carp_health_monitor.py

is_running()
{
    [ -s "${SUPERVISOR_PID}" ] || return 1
    kill -0 "$(cat "${SUPERVISOR_PID}")" 2>/dev/null
}

initialize_health()
{
    /usr/local/bin/python3 "${SCRIPT}" --initialize >/dev/null 2>&1 || true
}

start_monitor()
{
    if is_running; then
        return 0
    fi
    initialize_health
    rm -f "${SUPERVISOR_PID}" "${CHILD_PID}"
    /usr/sbin/daemon -c -r -P "${SUPERVISOR_PID}" -p "${CHILD_PID}" \
        -T api_extensions_carp_health -S \
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
}

reset_actions()
{
    /usr/local/bin/python3 "${SCRIPT}" --reset-actions >/dev/null 2>&1 || true
}

case "$1" in
    start) start_monitor ;;
    stop) stop_monitor; reset_actions ;;
    restart) stop_monitor; start_monitor ;;
    *) echo "usage: $0 {start|stop|restart}" >&2; exit 64 ;;
esac
