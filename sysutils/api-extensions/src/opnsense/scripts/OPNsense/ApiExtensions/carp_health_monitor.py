#!/usr/local/bin/python3
import argparse
import json
import os
import signal
import sys
import time

from carp_health import (
    HealthTracker,
    build_state,
    load_config,
    probe_all,
    read_state,
    reconcile_fallback_routes,
    reconcile_vhid_scopes,
    reset_fallback_routes,
    reset_vhid_overrides,
    status_state,
    trigger_carp_service_status,
    write_state,
)

SUPERVISOR_PID = "/var/run/api_extensions_carp_health.supervisor.pid"
_stop = False


def stop_handler(signum, frame):
    global _stop
    _stop = True


def run_loop():
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    signature = None
    tracker = None
    last_global = None
    while not _stop:
        started = time.monotonic()
        try:
            config = load_config()
        except Exception:
            time.sleep(1)
            continue
        if config.signature != signature:
            signature = config.signature
            tracker = HealthTracker(config.failure_threshold, config.recovery_threshold)
            last_global = None
        previous_state = read_state()
        if not config.enabled:
            ready, healthy = True, True
            tracker.records.clear()
        else:
            results = probe_all(config)
            ready, healthy = tracker.update(config.checks, results)
        vhids = reconcile_vhid_scopes(config, tracker, previous_state)
        routes = reconcile_fallback_routes(config, tracker, previous_state)
        state = build_state(config, tracker, ready, healthy, vhids=vhids, routes=routes)
        write_state(state)
        global_state = state.get("global", {})
        global_report = (
            global_state.get("active", False),
            global_state.get("ready", False),
            global_state.get("healthy", False),
        )
        if global_report != last_global:
            trigger_carp_service_status()
            last_global = global_report
        elapsed = time.monotonic() - started
        time.sleep(max(0.1, config.interval - elapsed))
    return 0


def pid_running(path):
    try:
        pid = int(open(path).read().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def status():
    try:
        config = load_config()
    except Exception as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 1
    state = status_state(config, read_state(), pid_running(SUPERVISOR_PID))
    print(json.dumps(state, sort_keys=True))
    return 0


def initialize():
    try:
        config = load_config()
    except Exception:
        return 1
    tracker = HealthTracker(config.failure_threshold, config.recovery_threshold)
    ready = not config.enabled or not config.checks
    healthy = ready
    previous_state = read_state()
    vhids = reconcile_vhid_scopes(config, tracker, previous_state)
    routes = reconcile_fallback_routes(config, tracker, previous_state)
    state = build_state(config, tracker, ready, healthy, vhids=vhids, routes=routes)
    write_state(state)
    trigger_carp_service_status()
    return 0


def reset_actions():
    state = read_state()
    vhids_ok = reset_vhid_overrides(state)
    routes_ok = reset_fallback_routes(state)
    return 0 if vhids_ok and routes_ok else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--reset-vhids", action="store_true")
    parser.add_argument("--reset-actions", action="store_true")
    args = parser.parse_args()
    if args.status:
        return status()
    if args.initialize:
        return initialize()
    if args.reset_vhids or args.reset_actions:
        return reset_actions()
    return run_loop()


if __name__ == "__main__":
    sys.exit(main())
