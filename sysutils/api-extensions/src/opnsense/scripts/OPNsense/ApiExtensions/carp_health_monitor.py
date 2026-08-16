#!/usr/local/bin/python3
import argparse
import json
import os
import signal
import sys
import time

from carp_health import (
    CONFIG_PATH,
    STATE_PATH,
    HealthTracker,
    build_state,
    load_config,
    probe_all,
    read_state,
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
    last_reported = None
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
            last_reported = None
        if not config.enabled:
            ready, healthy = True, True
            tracker.records.clear()
        else:
            results = probe_all(config)
            ready, healthy = tracker.update(config.checks, results)
        state = build_state(config, tracker, ready, healthy)
        write_state(state)
        aggregate = healthy if ready else None
        if aggregate is not None and aggregate != last_reported:
            trigger_carp_service_status()
            last_reported = aggregate
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    return status() if args.status else run_loop()


if __name__ == "__main__":
    sys.exit(main())
