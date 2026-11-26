#!/usr/local/bin/python3
"""One-shot migration from the removed CARP connected-route polling monitor.

The legacy monitor owned only routes recorded in STATE_PATH.  During an
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


def _stop_pidfile(path, command_func=_run, kill_func=os.kill, sleep_func=time.sleep):
    pid = _read_pid(path)
    if pid is None:
        return True
    command = _process_command(pid, command_func)
    if command and "carp_connected_monitor.py" not in command and "frr_carp_connected" not in command:
        return False
    if command:
        try:
            kill_func(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(50):
            if not _process_command(pid, command_func):
                break
            sleep_func(0.1)
        else:
            return False
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    return True


def stop_legacy_monitor(command_func=_run, kill_func=os.kill, sleep_func=time.sleep):
    # Stop the supervisor first so it cannot respawn the child, then the child.
    ok = _stop_pidfile(SUPERVISOR_PID, command_func, kill_func, sleep_func)
    ok = _stop_pidfile(CHILD_PID, command_func, kill_func, sleep_func) and ok
    return ok


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
        # The recorded fallback no longer exists; never delete an unrelated path.
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
    return migrate()


if __name__ == "__main__":
    sys.exit(main())
