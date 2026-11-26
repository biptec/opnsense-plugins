#!/usr/local/bin/python3
"""One-shot migration from the removed CARP connected-route polling monitor.

The legacy monitor owned only routes recorded in STATE_PATH. During an
in-place upgrade this helper stops any surviving legacy monitor, removes only
an exact kernel route whose gateway still matches the recorded owned fallback,
and deletes the volatile state once no owned route remains.
"""

import json
import os
import re
import signal
import subprocess
import sys
import time

STATE_PATH = "/var/run/frr_carp_connected_fallback.json"
SUPERVISOR_PID = "/var/run/frr_carp_connected_monitor.supervisor.pid"
CHILD_PID = "/var/run/frr_carp_connected_monitor.child.pid"
LEGACY_FILES = (
    "/usr/local/opnsense/scripts/frr/carp_connected_control.sh",
    "/usr/local/opnsense/scripts/frr/carp_connected_monitor.py",
    "/usr/local/opnsense/scripts/frr/lib/events/connected.py",
    "/usr/local/etc/rc.syshook.d/stop/50-frr",
)
PROCESS_MARKER = "carp_connected_monitor.py"


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _read_pid(path):
    try:
        return int(open(path, encoding="ascii").read().strip())
    except (OSError, ValueError):
        return None


def _process_command(pid, command_func=_run):
    result = command_func(["/bin/ps", "-p", str(pid), "-o", "command="])
    return result.stdout.strip() if result.returncode == 0 else ""


def _child_pids(pid, command_func=_run):
    result = command_func(["/bin/pgrep", "-P", str(pid)])
    if result.returncode not in (0, 1):
        return []
    children = []
    for value in result.stdout.split():
        try:
            children.append(int(value))
        except ValueError:
            continue
    return children


def _owned_supervisor(pid, command_func=_run):
    command = _process_command(pid, command_func)
    if not command:
        return False, []
    if PROCESS_MARKER in command or "frr_carp_connected" in command:
        return True, []
    children = _child_pids(pid, command_func)
    owned = [child for child in children if PROCESS_MARKER in _process_command(child, command_func)]
    return bool(owned), owned


def _terminate_owned_pid(pid, command_func=_run, kill_func=os.kill, sleep_func=time.sleep):
    command = _process_command(pid, command_func)
    if not command or PROCESS_MARKER not in command:
        return True
    try:
        kill_func(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    for _ in range(50):
        if not _process_command(pid, command_func):
            return True
        sleep_func(0.1)
    return False


def stop_legacy_monitor(command_func=_run, kill_func=os.kill, sleep_func=time.sleep):
    supervisor = _read_pid(SUPERVISOR_PID)
    owned_children = []
    if supervisor is not None:
        owned, owned_children = _owned_supervisor(supervisor, command_func)
        if not owned:
            return False
        try:
            kill_func(supervisor, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(50):
            if not _process_command(supervisor, command_func):
                break
            sleep_func(0.1)
        else:
            return False

    child = _read_pid(CHILD_PID)
    if child is not None:
        owned_children.append(child)
    for pid in sorted(set(owned_children)):
        if not _terminate_owned_pid(pid, command_func, kill_func, sleep_func):
            return False

    for path in (SUPERVISOR_PID, CHILD_PID):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    return True


def cleanup_legacy_files(remove_func=os.unlink):
    for path in LEGACY_FILES:
        try:
            remove_func(path)
        except FileNotFoundError:
            pass


def load_state(path=STATE_PATH):
    try:
        with open(path, encoding="utf-8") as stream:
            payload = json.load(stream)
    except FileNotFoundError:
        return []
    except (OSError, ValueError, TypeError):
        return None
    routes = payload.get("routes", [])
    return routes if isinstance(routes, list) else None


def parse_route_get(output):
    route = {"gateway": "", "interface": ""}
    for line in output.splitlines():
        match = re.match(r"\s*(gateway|interface):\s*(\S+)", line)
        if match:
            route[match.group(1)] = match.group(2)
    return route if route["interface"] else None


def route_lookup(route, command_func=_run):
    family = int(route.get("family", 0))
    network = str(route.get("network", ""))
    command = ["/sbin/route", "-n", "get"]
    if family == 6:
        command.append("-inet6")
    command.extend(["-net", network])
    result = command_func(command)
    return parse_route_get(result.stdout) if result.returncode == 0 else None


def delete_owned_route(route, command_func=_run):
    current = route_lookup(route, command_func)
    gateway = str(route.get("gateway", ""))
    if current is None or current.get("gateway") != gateway:
        return True
    family = int(route.get("family", 0))
    network = str(route.get("network", ""))
    command = ["/sbin/route", "delete"]
    if family == 6:
        command.append("-inet6")
    command.extend(["-net", network, gateway])
    result = command_func(command)
    if result.returncode != 0:
        return False
    verify = route_lookup(route, command_func)
    return verify is None or verify.get("gateway") != gateway


def save_retained(routes, path=STATE_PATH):
    if routes:
        with open(path, "w", encoding="utf-8") as stream:
            json.dump({"routes": routes}, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def migrate(state_path=STATE_PATH, command_func=_run):
    routes = load_state(state_path)
    if routes is None:
        return 75
    retained = []
    for route in routes:
        if not isinstance(route, dict) or not route.get("network") or not route.get("gateway"):
            retained.append(route)
            continue
        if not delete_owned_route(route, command_func):
            retained.append(route)
    save_retained(retained, state_path)
    return 0 if not retained else 75


def main():
    if not stop_legacy_monitor():
        return 75
    result = migrate()
    if result == 0:
        cleanup_legacy_files()
    return result


if __name__ == "__main__":
    sys.exit(main())
