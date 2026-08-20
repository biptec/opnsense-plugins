"""
CARP-aware connected-route fallback for FRR/OSPF.

FreeBSD keeps CARP virtual addresses configured on BACKUP nodes.  Zebra therefore
keeps a connected RIB entry even when the kernel has no usable connected path
(or, for IPv6, keeps a direct route whose shared CARP source is owned by the
peer).  An OSPF route learned from the CARP MASTER can consequently remain
non-selected in Zebra.

This handler leaves OSPF as the source of truth.  For a CARP BACKUP prefix it
uses the peer OSPF next-hop as a kernel fallback route.  Routes created here are
tracked explicitly and are removed again when CARP becomes MASTER or OSPF no
longer offers the peer route.
"""

import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time

from ..base import BaseEventHandler

STATE_PATH = "/var/run/frr_carp_connected_fallback.json"
MISSING_OSPF_GRACE = 30.0


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def parse_carp_prefixes(ifconfig_output):
    """Return CARP address prefixes keyed by interface and VHID."""
    addresses = []
    states = {}
    interface = None
    for line in ifconfig_output.splitlines():
        if line and not line[0].isspace():
            interface = line.split(":", 1)[0]
            continue
        if interface is None:
            continue
        fields = line.split()
        if line.startswith("\tcarp: ") and len(fields) >= 4:
            states[(interface, fields[3])] = fields[1].strip().lower()
            continue
        if "vhid" not in fields:
            continue
        try:
            vhid = fields[fields.index("vhid") + 1]
        except (ValueError, IndexError):
            continue
        if fields and fields[0] == "inet":
            try:
                address = fields[1]
                mask = fields[fields.index("netmask") + 1]
                prefixlen = bin(int(mask, 16)).count("1")
                network = ipaddress.ip_network(f"{address}/{prefixlen}", strict=False)
            except (ValueError, IndexError):
                continue
            addresses.append({"interface": interface, "vhid": vhid, "family": 4, "network": str(network)})
        elif fields and fields[0] == "inet6":
            try:
                address = fields[1].split("%", 1)[0]
                prefixlen = fields[fields.index("prefixlen") + 1]
                network = ipaddress.ip_network(f"{address}/{prefixlen}", strict=False)
            except (ValueError, IndexError):
                continue
            addresses.append({"interface": interface, "vhid": vhid, "family": 6, "network": str(network)})

    for item in addresses:
        item["state"] = states.get((item["interface"], item["vhid"]), "none")
    return addresses


def parse_route_get(output):
    result = {"gateway": "", "interface": ""}
    for line in output.splitlines():
        match = re.match(r"\s*(gateway|interface):\s*(\S+)", line)
        if match:
            result[match.group(1)] = match.group(2)
    return result


def parse_ospf_nexthop(payload, prefix, family):
    protocol = "ospf6" if family == 6 else "ospf"
    for route in payload.get(prefix, []):
        if route.get("protocol") != protocol:
            continue
        for nexthop in route.get("nexthops", []):
            gateway = nexthop.get("ip")
            interface = nexthop.get("interfaceName")
            if not nexthop.get("active") or not gateway or not interface:
                continue
            try:
                if family == 6 and ipaddress.ip_address(gateway).is_link_local and "%" not in gateway:
                    gateway = f"{gateway}%{interface}"
            except ValueError:
                continue
            return {"gateway": gateway, "interface": interface}
    return None


def load_state(path=STATE_PATH):
    try:
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
        routes = data.get("routes", [])
        return routes if isinstance(routes, list) else []
    except (OSError, ValueError, TypeError):
        return []


def save_state(routes, path=STATE_PATH):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".frr-carp-connected-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"routes": routes}, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class ConnectedCarpReconciler:
    def __init__(self, command_func=_run, state_path=STATE_PATH):
        self.command = command_func
        self.state_path = state_path

    def _kernel_route(self, prefix, family):
        command = ["/sbin/route", "-n", "get"]
        if family == 6:
            command.append("-inet6")
        command.extend(["-net", prefix])
        result = self.command(command)
        return parse_route_get(result.stdout) if result.returncode == 0 else None

    def _ospf_route(self, prefix, family):
        command = f"show {'ipv6 ' if family == 6 else 'ip '}route {prefix} json"
        result = self.command(["/usr/local/bin/vtysh", "-c", command])
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result.stdout)
        except (ValueError, TypeError):
            return None
        return parse_ospf_nexthop(payload, prefix, family)

    def _delete_route(self, prefix, family, gateway=""):
        command = ["/sbin/route", "delete"]
        if family == 6:
            command.append("-inet6")
        command.extend(["-net", prefix])
        if gateway:
            command.append(gateway)
        return self.command(command)

    def _add_gateway_route(self, prefix, family, gateway):
        command = ["/sbin/route", "add"]
        if family == 6:
            command.append("-inet6")
        command.extend(["-net", prefix, gateway])
        return self.command(command)

    def _restore_connected_route(self, prefix, family, interface):
        command = ["/sbin/route", "add"]
        if family == 6:
            command.append("-inet6")
        command.extend(["-net", prefix, "-iface", interface])
        return self.command(command)

    def reconcile(self, ifconfig_output=None):
        if ifconfig_output is None:
            result = self.command(["/sbin/ifconfig", "-a"])
            if result.returncode != 0:
                return []
            ifconfig_output = result.stdout

        items = parse_carp_prefixes(ifconfig_output)
        grouped = {}
        for item in items:
            grouped.setdefault((item["family"], item["network"]), []).append(item)
        by_key = {}
        for key, members in grouped.items():
            by_key[key] = next((item for item in members if item["state"] == "master"), members[0])
        previous = {(int(item["family"]), item["network"]): item for item in load_state(self.state_path)}
        desired = {}

        for key, members in grouped.items():
            # A subnet can host multiple CARP VHIDs.  The direct path remains
            # valid while any CARP identity on that subnet is MASTER; only an
            # all-BACKUP subnet should be routed through the OSPF peer.
            if any(item["state"] == "master" for item in members):
                continue
            item = next((item for item in members if item["state"] == "backup"), None)
            if item is None:
                continue
            learned = self._ospf_route(item["network"], item["family"])
            if learned is None or learned["interface"] == item["interface"]:
                continue
            desired[key] = {
                "family": item["family"],
                "network": item["network"],
                "gateway": learned["gateway"],
                "ospf_interface": learned["interface"],
                "carp_interface": item["interface"],
                "vhid": item["vhid"],
            }

        actions = []
        retained = {}

        # First retire routes that are no longer desired or whose OSPF next hop
        # changed. Failed deletes remain tracked so a later CARP/FRR event can
        # retry instead of silently abandoning a route that we still own. A
        # short grace period protects live fallback routes while ospfd/ospf6d
        # restarts and adjacency is reconverging.
        now = time.time()
        for key, old in previous.items():
            new = desired.get(key)
            if new is not None and new["gateway"] == old.get("gateway"):
                new.pop("missing_since", None)
                retained[key] = new
                continue
            carp_members = grouped.get(key, [])
            still_backup = (
                carp_members
                and not any(item["state"] == "master" for item in carp_members)
                and any(item["state"] == "backup" for item in carp_members)
            )
            if new is None and still_backup:
                missing_since = float(old.get("missing_since", now))
                if "missing_since" not in old:
                    old = dict(old)
                    old["missing_since"] = now
                if now - missing_since < MISSING_OSPF_GRACE:
                    retained[key] = old
                    continue
            current = self._kernel_route(old["network"], int(old["family"]))
            if current is not None and current.get("gateway") == old.get("gateway"):
                result = self._delete_route(old["network"], int(old["family"]), old.get("gateway", ""))
                if result.returncode != 0:
                    retained[key] = old
                    continue
                actions.append({"action": "delete-fallback", **old})

            carp = by_key.get(key)
            if carp is not None and carp.get("state") == "master":
                current = self._kernel_route(old["network"], int(old["family"]))
                if current is None:
                    result = self._restore_connected_route(old["network"], int(old["family"]), carp["interface"])
                    if result.returncode != 0:
                        # Keep enough ownership state to retry the MASTER
                        # restoration on the next event.
                        retained[key] = old
                        continue
                    actions.append({"action": "restore-connected", "family": old["family"], "network": old["network"], "carp_interface": carp["interface"]})

        # Then install the currently desired peer routes.  Only record a route
        # as managed after it is actually present in the kernel.
        for key, new in desired.items():
            if key in retained and retained[key].get("gateway") == new["gateway"]:
                current = self._kernel_route(new["network"], int(new["family"]))
                if current is not None and current.get("gateway") == new["gateway"]:
                    continue
                retained.pop(key, None)

            current = self._kernel_route(new["network"], int(new["family"]))
            if current is not None and current.get("gateway") == new["gateway"]:
                new.pop("missing_since", None)
                retained[key] = new
                continue
            old = previous.get(key)
            if current is not None and current.get("gateway"):
                # Never replace an unmanaged gateway route.
                if old is None or current.get("gateway") != old.get("gateway"):
                    continue
            if current is not None and not current.get("gateway"):
                # Only replace the automatic/direct CARP network route.  A
                # no-gateway route on another interface is not ours to touch.
                if current.get("interface") != new["carp_interface"]:
                    continue
                result = self._delete_route(new["network"], int(new["family"]))
                if result.returncode != 0:
                    continue
                actions.append({"action": "delete-connected", "family": new["family"], "network": new["network"], "carp_interface": new["carp_interface"]})
            result = self._add_gateway_route(new["network"], int(new["family"]), new["gateway"])
            if result.returncode != 0:
                continue
            actions.append({"action": "add-fallback", **new})
            retained[key] = new

        save_state(list(retained.values()), self.state_path)
        return actions

    def cleanup(self, ifconfig_output=None):
        """Remove only fallback routes owned by this reconciler."""
        previous = {(int(item["family"]), item["network"]): item for item in load_state(self.state_path)}
        if not previous:
            save_state([], self.state_path)
            return []

        if ifconfig_output is None:
            result = self.command(["/sbin/ifconfig", "-a"])
            if result.returncode != 0:
                return []
            ifconfig_output = result.stdout

        items = parse_carp_prefixes(ifconfig_output)
        grouped = {}
        for item in items:
            grouped.setdefault((item["family"], item["network"]), []).append(item)

        actions = []
        retained = {}
        for key, old in previous.items():
            family = int(old["family"])
            current = self._kernel_route(old["network"], family)
            if current is not None and current.get("gateway") == old.get("gateway"):
                result = self._delete_route(old["network"], family, old.get("gateway", ""))
                if result.returncode != 0:
                    retained[key] = old
                    continue
                actions.append({"action": "delete-fallback", **old})

            members = grouped.get(key, [])
            master = next((item for item in members if item.get("state") == "master"), None)
            if master is not None:
                current = self._kernel_route(old["network"], family)
                if current is None:
                    result = self._restore_connected_route(old["network"], family, master["interface"])
                    if result.returncode != 0:
                        retained[key] = old
                        continue
                    actions.append({"action": "restore-connected", "family": family, "network": old["network"], "carp_interface": master["interface"]})

        save_state(list(retained.values()), self.state_path)
        return actions


class ConnectedCarpEventHandler(BaseEventHandler):
    @property
    def should_run(self):
        return self.vtysh.is_running("zebra") and (self.vtysh.is_running("ospfd") or self.vtysh.is_running("ospf6d"))

    def execute(self):
        ConnectedCarpReconciler().reconcile()
