#!/bin/sh
SUPERVISOR_PID=${CARP_HEALTH_SUPERVISOR_PID:-/var/run/api_extensions_carp_health.supervisor.pid}
CHILD_PID=${CARP_HEALTH_CHILD_PID:-/var/run/api_extensions_carp_health.child.pid}
STATE=${CARP_HEALTH_STATE:-/var/run/api_extensions_carp_health.json}
SOCKET=${CARP_HEALTH_SOCKET:-/var/run/api_extensions_carp_health.sock}
CONFIG=${CARP_HEALTH_CONFIG:-/conf/config.xml}
DAEMON=${CARP_HEALTH_DAEMON:-/usr/local/sbin/carp-healthd}
DAEMON_CTL=${CARP_HEALTH_DAEMON_CTL:-/usr/sbin/daemon}

is_running()
{
    [ -s "${SUPERVISOR_PID}" ] || return 1
    pid="$(cat "${SUPERVISOR_PID}" 2>/dev/null)" || return 1
    [ -n "${pid}" ] || return 1
    kill -0 "${pid}" 2>/dev/null
}

start_monitor()
{
    if is_running; then
        return 0
    fi

    [ -x "${DAEMON}" ] || return 1
    [ -x "${DAEMON_CTL}" ] || return 1
    rm -f "${SUPERVISOR_PID}" "${CHILD_PID}" "${SOCKET}"

    "${DAEMON_CTL}" -c -r -P "${SUPERVISOR_PID}" -p "${CHILD_PID}" \
        -T api_extensions_carp_health -S \
        "${DAEMON}" -config "${CONFIG}" -state "${STATE}" -socket "${SOCKET}" run
}

stop_monitor()
{
    if is_running; then
        pid="$(cat "${SUPERVISOR_PID}" 2>/dev/null || true)"
        if [ -n "${pid}" ]; then
            kill "${pid}" 2>/dev/null || true
        fi
        count=0
        while is_running && [ ${count} -lt 50 ]; do
            sleep 0.1
            count=$((count + 1))
        done
    fi
    rm -f "${SUPERVISOR_PID}" "${CHILD_PID}" "${SOCKET}"
}

reset_actions()
{
    [ -x "${DAEMON}" ] || return 0
    "${DAEMON}" -state "${STATE}" reset-actions >/dev/null 2>&1 || true
}

status_monitor()
{
    "${DAEMON}" -config "${CONFIG}" -state "${STATE}" -socket "${SOCKET}" status
}

case "$1" in
    start) start_monitor ;;
    stop) stop_monitor; reset_actions ;;
    restart) stop_monitor; start_monitor ;;
    status) status_monitor ;;
    *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 64 ;;
esac
