#!/usr/local/bin/python3
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

CONFIG_PATH = "/conf/config.xml"
STATE_PATH = "/var/run/api_extensions_carp_health.json"
ARPING = "/usr/local/sbin/arping"
CONFIGCTL = "/usr/local/sbin/configctl"
IFCONFIG = "/sbin/ifconfig"
ROUTE = "/sbin/route"
FAILOVER_ADV_SKEW = 254


def as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def as_int(value, default, minimum=1, maximum=60):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def parse_ip(value, version):
    value = (value or "").strip()
    if not value:
        return ""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    return str(address) if address.version == version else ""


def parse_vhid_targets(value):
    targets = []
    seen = set()
    for item in (value or "").split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        interface, raw_vhid = item.rsplit(":", 1)
        interface = interface.strip()
        try:
            vhid = int(raw_vhid)
        except ValueError:
            continue
        key = (interface, vhid)
        if interface and 1 <= vhid <= 255 and key not in seen:
            targets.append(key)
            seen.add(key)
    return tuple(targets)


@dataclass(frozen=True)
class Check:
    uuid: str
    name: str
    interface: str
    device: str
    target: str
    scope: str
    vhid: int
    vhid_targets: tuple
    failure_advskew: int
    fallback_ipv4_target: str
    fallback_ipv4_gateway: str
    fallback_ipv6_target: str
    fallback_ipv6_gateway: str


@dataclass(frozen=True)
class CarpVhid:
    interface: str
    device: str
    vhid: int
    advskew: int


@dataclass(frozen=True)
class Config:
    enabled: bool
    interval: int
    failure_threshold: int
    recovery_threshold: int
    checks: tuple
    carp_vhids: tuple
    signature: str


def load_config(path=CONFIG_PATH):
    tree = ET.parse(path)
    root = tree.getroot()
    node = root.find("./OPNsense/ApiExtensions/CarpHealth")
    if node is None:
        return Config(False, 1, 2, 2, tuple(), tuple(), "disabled")

    enabled = as_bool(node.findtext("enabled"))
    interval = as_int(node.findtext("interval"), 1, 1, 60)
    failure = as_int(node.findtext("failure_threshold"), 2, 1, 20)
    recovery = as_int(node.findtext("recovery_threshold"), 2, 1, 20)

    interface_map = {}
    interfaces = root.find("./interfaces")
    if interfaces is not None:
        for item in interfaces:
            interface_map[item.tag] = (item.findtext("if") or "").strip()

    carp_vhids = []
    virtualip = root.find("./virtualip")
    for vip in virtualip.findall("./vip") if virtualip is not None else []:
        if (vip.findtext("mode") or "").strip().lower() != "carp":
            continue
        interface = (vip.findtext("interface") or "").strip()
        vhid = as_int(vip.findtext("vhid"), 0, 0, 255)
        if vhid == 0:
            continue
        carp_vhids.append(CarpVhid(
            interface=interface,
            device=interface_map.get(interface, ""),
            vhid=vhid,
            advskew=as_int(vip.findtext("advskew"), 0, 0, 254),
        ))

    checks = []
    for item in node.findall("./checks/check"):
        if not as_bool(item.findtext("enabled"), True):
            continue
        name = (item.findtext("name") or "").strip()
        friendly = (item.findtext("interface") or "").strip()
        target = parse_ip(item.findtext("target"), 4)
        uuid = item.attrib.get("uuid", "") or name
        scope = (item.findtext("scope") or "global").strip().lower()
        if scope not in {"global", "interface", "all_carp", "vhid", "vhid_group"}:
            scope = "global"
        vhid = as_int(item.findtext("vhid"), 0, 0, 255) if scope == "vhid" else 0
        if scope == "vhid" and vhid:
            vhid_targets = ((friendly, vhid),)
        elif scope == "vhid_group":
            vhid_targets = parse_vhid_targets(item.findtext("vhid_targets"))
        else:
            vhid_targets = tuple()
        checks.append(Check(
            uuid=uuid,
            name=name,
            interface=friendly,
            device=interface_map.get(friendly, ""),
            target=target,
            scope=scope,
            vhid=vhid,
            vhid_targets=vhid_targets,
            failure_advskew=as_int(item.findtext("failure_advskew"), FAILOVER_ADV_SKEW, 1, FAILOVER_ADV_SKEW),
            fallback_ipv4_target=parse_ip(item.findtext("fallback_ipv4_target"), 4),
            fallback_ipv4_gateway=parse_ip(item.findtext("fallback_ipv4_gateway"), 4),
            fallback_ipv6_target=parse_ip(item.findtext("fallback_ipv6_target"), 6),
            fallback_ipv6_gateway=parse_ip(item.findtext("fallback_ipv6_gateway"), 6),
        ))

    canonical = {
        "enabled": enabled,
        "interval": interval,
        "failure_threshold": failure,
        "recovery_threshold": recovery,
        "checks": [check.__dict__ for check in checks],
        "carp_vhids": [carp.__dict__ for carp in carp_vhids],
    }
    signature = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()
    return Config(enabled, interval, failure, recovery, tuple(checks), tuple(carp_vhids), signature)


def resolve_vhid_targets(check, config):
    """Resolve automatic CARP scopes while preserving explicit overrides."""
    if check.scope == "interface":
        targets = ((carp.interface, carp.vhid) for carp in config.carp_vhids if carp.interface == check.interface)
    elif check.scope == "all_carp":
        targets = ((carp.interface, carp.vhid) for carp in config.carp_vhids)
    elif check.scope in {"vhid", "vhid_group"}:
        targets = iter(check.vhid_targets)
    else:
        return tuple()

    result = []
    seen = set()
    for target in targets:
        if target not in seen:
            result.append(target)
            seen.add(target)
    return tuple(result)


def probe(check, arping=ARPING):
    if not check.device or not check.target:
        return False
    try:
        result = subprocess.run(
            [arping, "-0", "-q", "-c", "1", "-w", "1", "-i", check.device, check.target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def probe_all(config, probe_func=probe):
    if not config.checks:
        return {}
    with ThreadPoolExecutor(max_workers=min(16, len(config.checks))) as executor:
        values = list(executor.map(probe_func, config.checks))
    return {check.uuid: value for check, value in zip(config.checks, values)}


class HealthTracker:
    def __init__(self, failure_threshold=2, recovery_threshold=2):
        self.failure_threshold = failure_threshold
        self.recovery_threshold = recovery_threshold
        self.records = {}

    def update(self, checks, results):
        active = {check.uuid for check in checks}
        self.records = {key: value for key, value in self.records.items() if key in active}
        for check in checks:
            record = self.records.setdefault(
                check.uuid,
                {"healthy": None, "failures": 0, "successes": 0},
            )
            success = bool(results.get(check.uuid, False))
            if success:
                record["failures"] = 0
                if record["healthy"] is not True:
                    record["successes"] += 1
                    if record["successes"] >= self.recovery_threshold:
                        record["healthy"] = True
                        record["successes"] = 0
                else:
                    record["successes"] = 0
            else:
                record["successes"] = 0
                record["failures"] += 1
                if record["failures"] >= self.failure_threshold:
                    record["healthy"] = False
        ready = all(self.records.get(check.uuid, {}).get("healthy") is not None for check in checks)
        healthy = ready and all(self.records[check.uuid]["healthy"] for check in checks)
        if not checks:
            ready = True
            healthy = True
        return ready, healthy


def _health_for_checks(checks, tracker):
    if not checks:
        return True, True
    values = [tracker.records.get(check.uuid, {}).get("healthy") for check in checks]
    ready = all(value is not None for value in values)
    healthy = ready and all(value is True for value in values)
    return ready, healthy


def scope_health(config, tracker):
    global_checks = [check for check in config.checks if check.scope == "global"]
    global_ready, global_healthy = _health_for_checks(global_checks, tracker)
    global_active = config.enabled and bool(global_checks)
    global_state = {
        "active": global_active,
        "check_count": len(global_checks),
        "ready": global_ready if global_active else True,
        "healthy": global_healthy if global_active else True,
    }

    groups = {}
    for check in config.checks:
        if check.scope not in {"interface", "all_carp", "vhid", "vhid_group"}:
            continue
        for interface, vhid in resolve_vhid_targets(check, config):
            groups.setdefault(f"{interface}:{vhid}", []).append(check)

    vhid_states = {}
    for key, checks in groups.items():
        ready, healthy = _health_for_checks(checks, tracker)
        if not config.enabled:
            ready, healthy = True, True
        blocked = [
            check for check in checks
            if config.enabled and tracker.records.get(check.uuid, {}).get("healthy") is not True
        ]
        interface, raw_vhid = key.rsplit(":", 1)
        vhid_states[key] = {
            "interface": interface,
            "vhid": int(raw_vhid),
            "checks": [check.name for check in checks],
            "ready": ready,
            "healthy": healthy,
            "desired_demoted": bool(blocked),
            "failure_advskew": max((check.failure_advskew for check in blocked), default=0),
        }
    return global_state, vhid_states


def find_carp_vhid(config, interface, vhid):
    matches = [
        carp for carp in config.carp_vhids
        if carp.interface == interface and carp.vhid == int(vhid)
    ]
    return matches[0] if matches else None


def run_command(args, capture=False):
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode, result.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def read_carp_runtime(carp, command_func=run_command):
    if not carp.device:
        return None
    returncode, output = command_func([IFCONFIG, carp.device], capture=True)
    if returncode != 0:
        return None
    pattern = re.compile(
        r"carp:\s+(MASTER|BACKUP|INIT)\s+vhid\s+(\d+)\s+advbase\s+\d+\s+advskew\s+(\d+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(output):
        if int(match.group(2)) == carp.vhid:
            return {
                "state": match.group(1).upper(),
                "advskew": int(match.group(3)),
            }
    return None


def set_vhid_priority(carp, advskew, force_backup=False, command_func=run_command):
    advskew = max(carp.advskew, min(FAILOVER_ADV_SKEW, int(advskew)))
    command = [IFCONFIG, carp.device, "vhid", str(carp.vhid), "advskew", str(advskew)]
    if force_backup:
        command.extend(["state", "BACKUP"])
    return command_func(command, capture=False)[0] == 0


def _carp_from_state(item):
    try:
        return CarpVhid(
            interface=str(item["interface"]),
            device=str(item["device"]),
            vhid=int(item["vhid"]),
            advskew=int(item["configured_advskew"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def reconcile_vhid_scopes(config, tracker, previous_state=None, command_func=run_command):
    _, desired = scope_health(config, tracker)
    previous = previous_state if isinstance(previous_state, dict) else {}
    previous_items = previous.get("vhids", []) if isinstance(previous.get("vhids", []), list) else []
    current_keys = set(desired)
    result = []

    for item in previous_items:
        key = item.get("key")
        if not key or key in current_keys:
            continue
        carp = _carp_from_state(item)
        if carp is None or not carp.device:
            continue
        runtime = read_carp_runtime(carp, command_func)
        if runtime is None:
            continue
        control_ok = True
        if runtime["advskew"] != carp.advskew:
            control_ok = set_vhid_priority(carp, carp.advskew, False, command_func)
            runtime = read_carp_runtime(carp, command_func)
            control_ok = control_ok and runtime is not None and runtime["advskew"] == carp.advskew
        if not control_ok:
            result.append({
                "key": key, "interface": carp.interface, "device": carp.device, "vhid": carp.vhid,
                "checks": [], "ready": True, "healthy": True, "desired_demoted": False,
                "desired_advskew": carp.advskew, "configured_advskew": carp.advskew,
                "current_advskew": runtime["advskew"] if runtime else None,
                "carp_state": runtime["state"] if runtime else "UNKNOWN", "control_ok": False,
                "retired": True, "error": "Failed to restore previous VHID priority",
            })

    for key, group in desired.items():
        carp = find_carp_vhid(config, group["interface"], group["vhid"])
        if carp is None:
            result.append({
                "key": key, "interface": group["interface"], "device": "", "vhid": group["vhid"],
                "checks": group["checks"], "ready": group["ready"], "healthy": group["healthy"],
                "desired_demoted": group["desired_demoted"], "desired_advskew": None,
                "configured_advskew": None, "current_advskew": None, "carp_state": "MISSING",
                "control_ok": False, "retired": False, "error": "Configured CARP VHID was not found",
            })
            continue
        desired_advskew = max(carp.advskew, group["failure_advskew"]) if group["desired_demoted"] else carp.advskew
        force_backup = desired_advskew >= FAILOVER_ADV_SKEW and group["desired_demoted"]
        runtime = read_carp_runtime(carp, command_func)
        control_ok = runtime is not None
        if control_ok and (runtime["advskew"] != desired_advskew or (force_backup and runtime["state"] != "BACKUP")):
            control_ok = set_vhid_priority(carp, desired_advskew, force_backup, command_func)
            runtime = read_carp_runtime(carp, command_func)
        if runtime is None:
            control_ok = False
        else:
            control_ok = control_ok and runtime["advskew"] == desired_advskew
            if force_backup:
                control_ok = control_ok and runtime["state"] == "BACKUP"
        result.append({
            "key": key, "interface": carp.interface, "device": carp.device, "vhid": carp.vhid,
            "checks": group["checks"], "ready": group["ready"], "healthy": group["healthy"],
            "desired_demoted": group["desired_demoted"], "desired_advskew": desired_advskew,
            "configured_advskew": carp.advskew,
            "current_advskew": runtime["advskew"] if runtime is not None else None,
            "carp_state": runtime["state"] if runtime is not None else "UNKNOWN",
            "control_ok": control_ok, "retired": False,
            "error": "" if control_ok else "Unable to enforce CARP VHID state",
        })
    return result


def reset_vhid_overrides(state, command_func=run_command):
    if not isinstance(state, dict):
        return True
    success = True
    for item in state.get("vhids", []):
        carp = _carp_from_state(item)
        if carp is None or not carp.device:
            continue
        runtime = read_carp_runtime(carp, command_func)
        if runtime is None:
            continue
        if runtime["advskew"] != carp.advskew:
            success = set_vhid_priority(carp, carp.advskew, False, command_func) and success
    return success


def _route_command(action, family, destination, gateway=None):
    command = [ROUTE, "-n", action]
    if family == "inet6":
        command.append("-inet6")
    command.extend(["-host", destination])
    if gateway:
        command.append(gateway)
    return command


def read_route_gateway(destination, family, command_func=run_command):
    returncode, output = command_func(_route_command("get", family, destination), capture=True)
    if returncode != 0:
        return ""
    match = re.search(r"^\s*gateway:\s*(\S+)", output, re.MULTILINE)
    return match.group(1) if match else ""


def _fallback_specs(check):
    specs = []
    if check.fallback_ipv4_target and check.fallback_ipv4_gateway:
        specs.append(("inet", check.fallback_ipv4_target, check.fallback_ipv4_gateway))
    if check.fallback_ipv6_target and check.fallback_ipv6_gateway:
        specs.append(("inet6", check.fallback_ipv6_target, check.fallback_ipv6_gateway))
    return specs


def reconcile_fallback_routes(config, tracker, previous_state=None, command_func=run_command):
    previous = previous_state if isinstance(previous_state, dict) else {}
    previous_items = previous.get("routes", []) if isinstance(previous.get("routes", []), list) else []
    previous_by_key = {item.get("key"): item for item in previous_items if item.get("key")}
    desired = {}
    for check in config.checks:
        unhealthy = config.enabled and tracker.records.get(check.uuid, {}).get("healthy") is not True
        for family, destination, gateway in _fallback_specs(check):
            key = f"{check.uuid}:{family}"
            desired[key] = {
                "key": key, "check_uuid": check.uuid, "check": check.name, "family": family,
                "destination": destination, "gateway": gateway, "desired_installed": unhealthy,
            }

    result = []
    for key, old in previous_by_key.items():
        new = desired.get(key)
        changed = new is not None and (old.get("destination") != new["destination"] or old.get("gateway") != new["gateway"])
        if key in desired and not changed:
            continue
        managed = bool(old.get("managed", False))
        gateway_now = read_route_gateway(str(old.get("destination", "")), str(old.get("family", "inet")), command_func)
        control_ok = True
        if managed and gateway_now == old.get("gateway"):
            command_func(_route_command("delete", str(old.get("family", "inet")), str(old.get("destination", "")), str(old.get("gateway", ""))), capture=False)
            gateway_now = read_route_gateway(str(old.get("destination", "")), str(old.get("family", "inet")), command_func)
            control_ok = gateway_now != old.get("gateway")
        if not control_ok:
            retired = dict(old)
            retired.update({"desired_installed": False, "installed": True, "control_ok": False, "retired": True, "error": "Failed to remove fallback route"})
            result.append(retired)

    for key, spec in desired.items():
        old = previous_by_key.get(key, {})
        if old and (old.get("destination") != spec["destination"] or old.get("gateway") != spec["gateway"]):
            old = {}
        managed = bool(old.get("managed", False))
        gateway_now = read_route_gateway(spec["destination"], spec["family"], command_func)
        if spec["desired_installed"]:
            if gateway_now != spec["gateway"]:
                rc, _ = command_func(_route_command("add", spec["family"], spec["destination"], spec["gateway"]), capture=False)
                if rc == 0:
                    managed = True
                gateway_now = read_route_gateway(spec["destination"], spec["family"], command_func)
            installed = gateway_now == spec["gateway"]
            control_ok = installed
        else:
            if managed and gateway_now == spec["gateway"]:
                command_func(_route_command("delete", spec["family"], spec["destination"], spec["gateway"]), capture=False)
                gateway_now = read_route_gateway(spec["destination"], spec["family"], command_func)
            installed = gateway_now == spec["gateway"]
            control_ok = not (managed and installed)
            if control_ok:
                managed = False
        row = dict(spec)
        row.update({
            "installed": installed, "managed": managed, "control_ok": control_ok, "retired": False,
            "error": "" if control_ok else ("Unable to install fallback route" if spec["desired_installed"] else "Unable to remove fallback route"),
        })
        result.append(row)
    return result


def reset_fallback_routes(state, command_func=run_command):
    if not isinstance(state, dict):
        return True
    success = True
    for item in state.get("routes", []):
        if not item.get("managed", False):
            continue
        destination = str(item.get("destination", ""))
        gateway = str(item.get("gateway", ""))
        family = str(item.get("family", "inet"))
        if not destination or not gateway:
            continue
        if read_route_gateway(destination, family, command_func) == gateway:
            command_func(_route_command("delete", family, destination, gateway), capture=False)
            success = read_route_gateway(destination, family, command_func) != gateway and success
    return success



def build_state(config, tracker, ready, healthy, vhids=None, routes=None, now=None):
    now = time.time() if now is None else now
    vhids = [] if vhids is None else vhids
    routes = [] if routes is None else routes
    global_state, _ = scope_health(config, tracker)
    vhid_by_key = {item.get("key"): item for item in vhids if not item.get("retired")}
    routes_by_check = {}
    for route in routes:
        if not route.get("retired"):
            routes_by_check.setdefault(route.get("check_uuid"), []).append(route)
    checks = []
    by_uuid = {check.uuid: check for check in config.checks}
    for uuid, record in tracker.records.items():
        check = by_uuid.get(uuid)
        if check is None:
            continue
        resolved_targets = resolve_vhid_targets(check, config)
        target_rows = [vhid_by_key.get(f"{interface}:{vhid}", {}) for interface, vhid in resolved_targets]
        row = {
            "uuid": uuid,
            "name": check.name,
            "interface": check.interface,
            "device": check.device,
            "target": check.target,
            "scope": check.scope,
            "vhid": check.vhid,
            "vhid_targets": [f"{interface}:{vhid}" for interface, vhid in resolved_targets],
            "configured_vhid_targets": [f"{interface}:{vhid}" for interface, vhid in check.vhid_targets],
            "failure_advskew": check.failure_advskew,
            "vhid_states": target_rows,
            "fallback_routes": routes_by_check.get(uuid, []),
            **record,
        }
        if check.scope == "vhid" and target_rows:
            runtime = target_rows[0]
            row.update({
                "carp_state": runtime.get("carp_state", "UNKNOWN"),
                "configured_advskew": runtime.get("configured_advskew"),
                "current_advskew": runtime.get("current_advskew"),
                "control_ok": runtime.get("control_ok", False),
            })
        elif check.scope in {"interface", "all_carp", "vhid_group"}:
            row.update({
                "carp_state": "GROUP",
                "configured_advskew": None,
                "current_advskew": None,
                "control_ok": bool(target_rows) and all(target.get("control_ok", False) for target in target_rows),
            })
        else:
            row["control_ok"] = True
        checks.append(row)
    vhid_control_ok = all(item.get("control_ok", False) for item in vhids)
    route_control_ok = all(item.get("control_ok", False) for item in routes)
    scope_resolution_ok = (not config.enabled) or all(
        check.scope == "global" or bool(resolve_vhid_targets(check, config))
        for check in config.checks
    )
    control_ok = vhid_control_ok and route_control_ok and scope_resolution_ok
    effective_healthy = healthy and control_ok
    return {
        "status": "ok",
        "enabled": config.enabled,
        "ready": ready,
        "healthy": effective_healthy,
        "probe_healthy": healthy,
        "control_ok": control_ok,
        "timestamp": now,
        "config_signature": config.signature,
        "global": global_state,
        "vhids": vhids,
        "routes": routes,
        "checks": checks,
    }


def write_state(state, path=STATE_PATH):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".carp-health-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_state(path=STATE_PATH):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError, TypeError):
        return None


def state_is_current(config, state, now=None):
    if state is None or state.get("config_signature") != config.signature:
        return False
    now = time.time() if now is None else now
    max_age = max(5, config.interval * 3)
    try:
        age = now - float(state.get("timestamp", 0))
    except (TypeError, ValueError):
        return False
    return age <= max_age


def status_state(config, state, running, now=None):
    if state_is_current(config, state, now):
        result = dict(state)
        result["running"] = running
        return result
    global_checks = [check for check in config.checks if check.scope == "global"]
    global_active = config.enabled and bool(global_checks)
    return {
        "status": "ok",
        "enabled": config.enabled,
        "ready": not config.enabled,
        "healthy": not config.enabled,
        "probe_healthy": not config.enabled,
        "control_ok": not config.enabled,
        "running": running,
        "timestamp": 0,
        "config_signature": config.signature,
        "global": {
            "active": global_active,
            "check_count": len(global_checks),
            "ready": not global_active,
            "healthy": not global_active,
        },
        "vhids": [],
        "checks": [],
    }


def checker_exit_code(config, state, now=None):
    if not config.enabled:
        return 0
    if not any(check.scope == "global" for check in config.checks):
        return 0
    if state is None or state.get("config_signature") != config.signature:
        return 1
    if not state_is_current(config, state, now):
        return 1
    global_state = state.get("global")
    if not isinstance(global_state, dict):
        return 1
    if not global_state.get("ready", False):
        return 1
    return 0 if global_state.get("healthy", False) else 1


def trigger_carp_service_status(configctl=CONFIGCTL):
    return subprocess.run(
        [configctl, "interface", "update", "carp", "service_status"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    ).returncode == 0
