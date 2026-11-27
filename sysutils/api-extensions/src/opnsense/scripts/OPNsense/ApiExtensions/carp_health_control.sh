#!/bin/sh
SUPERVISOR_PID=${CARP_HEALTH_SUPERVISOR_PID:-/var/run/api_extensions_carp_health.supervisor.pid}
CHILD_PID=${CARP_HEALTH_CHILD_PID:-/var/run/api_extensions_carp_health.child.pid}
STATE=${CARP_HEALTH_STATE:-/var/run/api_extensions_carp_health.json}
SOCKET=${CARP_HEALTH_SOCKET:-/var/run/api_extensions_carp_health.sock}
CONFIG=${CARP_HEALTH_CONFIG:-/conf/config.xml}
DAEMON=${CARP_HEALTH_DAEMON:-/usr/local/sbin/carp-healthd}
DAEMON_CTL=${CARP_HEALTH_DAEMON_CTL:-/usr/sbin/daemon}

process_command()
{
    /bin/ps -p "$1" -o command= 2>/dev/null || true
}

owned_child()
{
    [ -s "${SUPERVISOR_PID}" ] || return 1
    supervisor="$(cat "${SUPERVISOR_PID}" 2>/dev/null)" || return 1
    [ -n "${supervisor}" ] || return 1
    [ -n "$(process_command "${supervisor}")" ] || return 1

    for child in $(/bin/pgrep -P "${supervisor}" 2>/dev/null || true); do
        command="$(process_command "${child}")"
        case "${command}" in
            *"/usr/local/sbin/carp-healthd "*|*"/carp_health_monitor.py"*)
                echo "${child}"
                return 0
                ;;
        esac
    done
    return 1
}

is_running()
{
    owned_child >/dev/null 2>&1
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

    count=0
    while ! is_running && [ ${count} -lt 50 ]; do
        sleep 0.1
        count=$((count + 1))
    done
    is_running
}

stop_monitor()
{
    if [ -s "${SUPERVISOR_PID}" ]; then
        supervisor="$(cat "${SUPERVISOR_PID}" 2>/dev/null || true)"
        if [ -n "${supervisor}" ] && [ -n "$(process_command "${supervisor}")" ]; then
            child="$(owned_child)" || return 1
            kill "${supervisor}" 2>/dev/null || true
            count=0
            while [ -n "$(process_command "${supervisor}")" ] && [ ${count} -lt 50 ]; do
                sleep 0.1
                count=$((count + 1))
            done
            [ -z "$(process_command "${supervisor}")" ] || return 1

            if [ -n "${child}" ]; then
                command="$(process_command "${child}")"
                case "${command}" in
                    *"/usr/local/sbin/carp-healthd "*|*"/carp_health_monitor.py"*)
                        kill "${child}" 2>/dev/null || true
                        ;;
                esac
            fi
        fi
    fi
    rm -f "${SUPERVISOR_PID}" "${CHILD_PID}" "${SOCKET}"
}

reset_actions()
{
    [ -x "${DAEMON}" ] || return 0
    "${DAEMON}" -state "${STATE}" reset-actions >/dev/null 2>&1
}

status_monitor()
{
    "${DAEMON}" -config "${CONFIG}" -state "${STATE}" -socket "${SOCKET}" status
}

case "$1" in
    start) start_monitor ;;
    stop) stop_monitor && reset_actions ;;
    restart) stop_monitor && reset_actions && start_monitor ;;
    status) status_monitor ;;
    *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 64 ;;
esac
