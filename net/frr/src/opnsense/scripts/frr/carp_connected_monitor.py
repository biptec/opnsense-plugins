#!/usr/local/bin/python3
"""Continuously reconcile CARP BACKUP connected prefixes with learned OSPF paths."""

import signal
import sys
import time

from lib.events.connected import ConnectedCarpReconciler, load_state

INTERVAL = 2.0
_running = True


def _stop(_signum, _frame):
    global _running
    _running = False


def main():
    if sys.argv[1:] == ["--cleanup"]:
        reconciler = ConnectedCarpReconciler()
        reconciler.cleanup()
        return 0 if not load_state() else 1
    if sys.argv[1:]:
        print(f"usage: {sys.argv[0]} [--cleanup]", file=sys.stderr)
        return 64

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    reconciler = ConnectedCarpReconciler()
    while _running:
        try:
            reconciler.reconcile()
        except Exception:
            # Keep the routing monitor alive across transient FRR/config changes.
            # Individual command failures are already handled by the reconciler.
            pass
        deadline = time.monotonic() + INTERVAL
        while _running and time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
