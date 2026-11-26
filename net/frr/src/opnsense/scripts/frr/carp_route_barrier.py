#!/usr/local/bin/python3
"""Wait for the effective route to an endpoint gateway to match CARP ownership.

The process is one-shot and event driven: subscribe to PF_ROUTE first, take a
route snapshot, and only re-check after a routing-socket event. It never scans
all routes and never sleeps between probes.
"""

import argparse
import json
import re
import select
import socket
import subprocess
import sys
import time


DEFAULT_TIMEOUT = 30.0


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def parse_route_get(output):
    result = {"gateway": "", "interface": ""}
    for line in output.splitlines():
        match = re.match(r"\s*(gateway|interface):\s*(\S+)", line)
        if match:
            result[match.group(1)] = match.group(2)
    return result if result["interface"] else None


def route_lookup(family, address, command_func=_run):
    command = ["/sbin/route", "-n", "get"]
    if family == "inet6":
        command.append("-inet6")
    command.append(address)
    result = command_func(command)
    if result.returncode != 0:
        return None
    return parse_route_get(result.stdout)


def route_matches(route, state, endpoint_interface):
    if route is None or not route.get("interface"):
        return False
    if state == "MASTER":
        return route["interface"] == endpoint_interface
    if state == "BACKUP":
        return (
            route["interface"] != endpoint_interface
            and bool(route.get("gateway"))
        )
    return False


def _route_socket():
    family = getattr(socket, "PF_ROUTE", getattr(socket, "AF_ROUTE", None))
    if family is None:
        raise RuntimeError("PF_ROUTE is unavailable")
    sock = socket.socket(family, socket.SOCK_RAW, 0)
    sock.setblocking(False)
    return sock


def wait_for_route(
    family,
    address,
    endpoint_interface,
    state,
    timeout=DEFAULT_TIMEOUT,
    command_func=_run,
    socket_factory=_route_socket,
    select_func=select.select,
    monotonic=time.monotonic,
):
    # Subscribe before the first snapshot so a transition cannot be lost
    # between the CARP notification and our route check.
    sock = socket_factory()
    try:
        deadline = monotonic() + timeout
        while True:
            route = route_lookup(family, address, command_func)
            if route_matches(route, state, endpoint_interface):
                return route

            remaining = deadline - monotonic()
            if remaining <= 0:
                return None

            readable, _, _ = select_func([sock], [], [], remaining)
            if not readable:
                return None

            # The exact RTM payload does not need decoding here. Any route
            # notification is only a wake-up; the targeted route(8) snapshot
            # is authoritative for the endpoint gateway we are waiting on.
            try:
                sock.recv(65535)
            except BlockingIOError:
                pass
    finally:
        sock.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", choices=("inet", "inet6"), required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--endpoint-interface", required=True)
    parser.add_argument("--state", choices=("MASTER", "BACKUP"), required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    try:
        route = wait_for_route(
            args.family,
            args.address,
            args.endpoint_interface,
            args.state,
            args.timeout,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 1

    if route is None:
        print(
            json.dumps(
                {
                    "status": "timeout",
                    "state": args.state,
                    "address": args.address,
                    "endpoint_interface": args.endpoint_interface,
                },
                sort_keys=True,
            )
        )
        return 75

    print(
        json.dumps(
            {
                "status": "ok",
                "state": args.state,
                "address": args.address,
                "gateway": route.get("gateway", ""),
                "interface": route.get("interface", ""),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
