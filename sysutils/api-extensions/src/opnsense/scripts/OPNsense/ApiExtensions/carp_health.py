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


@dataclass(frozen=True)
class Check:
    uuid: str
    name: str
    interface: str
    device: str
    target: str
    scope: str
    vhid: int


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
        for item in list(interfaces):
            interface_map[item.tag] = (item.findtext("if") or "").strip()

    carp_vhids = []
    for vip in root.findall("./virtualip/vip"):
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
        target = (item.findtext("target") or "").strip()
        uuid = item.attrib.get("uuid", "") or name
        scope = (item.findtext("scope") or "global").strip().lower()
        if scope not in {"global", "vhid"}:
            scope = "global"
        vhid = as_int(item.findtext("vhid"), 0, 0, 255) if scope == "vhid" else 0
        try:
            target = str(ipaddress.IPv4Address(target))
        except ipaddress.AddressValueError:
            target = ""
        checks.append(Check(
            uuid=uuid,
            name=name,
            interface=friendly,
            device=interface_map.get(friendly, ""),
            target=target,
            scope=scope,
            vhid=vhid,
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
        if check.scope != "vhid":
            continue
        key = f"{check.interface}:{check.vhid}"
        groups.setdefault(key, []).append(check)

    vhid_states = {}
    for key, checks in groups.items():
        ready, healthy = _health_for_checks(checks, tracker)
        if not config.enabled:
            ready, healthy = True, True
        vhid_states[key] = {
            "interface": checks[0].interface,
            "vhid": checks[0].vhid,
            "checks": [check.name for check in checks],
            "ready": ready,
            "healthy": healthy,
            "desired_demoted": config.enabled and not healthy,
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


def set_vhid_priority(carp, demoted, command_func=run_command):
    advskew = FAILOVER_ADV_SKEW if demoted else carp.advskew
    command = [IFCONFIG, carp.device, "vhid", str(carp.vhid), "advskew", str(advskew)]
    if demoted:
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
        if runtime["advskew"] != carp.advskew:
            set_vhid_priority(carp, False, command_func)
            runtime = read_carp_runtime(carp, command_func)
        if runtime is not None and runtime["advskew"] != carp.advskew:
            result.append({
                "key": key,
                "interface": carp.interface,
                "device": carp.device,
                "vhid": carp.vhid,
                "checks": [],
                "ready": True,
                "healthy": True,
                "desired_demoted": False,
                "configured_advskew": carp.advskew,
                "current_advskew": runtime["advskew"],
                "carp_state": runtime["state"],
                "control_ok": False,
                "retired": True,
                "error": "Failed to restore previous VHID priority",
            })

    for key, group in desired.items():
        carp = find_carp_vhid(config, group["interface"], group["vhid"])
        if carp is None:
            result.append({
                "key": key,
                "interface": group["interface"],
                "device": "",
                "vhid": group["vhid"],
                "checks": group["checks"],
                "ready": group["ready"],
                "healthy": group["healthy"],
                "desired_demoted": group["desired_demoted"],
                "configured_advskew": None,
                "current_advskew": None,
                "carp_state": "MISSING",
                "control_ok": False,
                "retired": False,
                "error": "CARP VHID not found on selected interface",
            })
            continue

        runtime = read_carp_runtime(carp, command_func)
        control_ok = runtime is not None
        if runtime is not None:
            if group["desired_demoted"]:
                needs_change = runtime["advskew"] != FAILOVER_ADV_SKEW or runtime["state"] != "BACKUP"
            else:
                needs_change = runtime["advskew"] != carp.advskew
            if needs_change:
                control_ok = set_vhid_priority(carp, group["desired_demoted"], command_func)
                runtime = read_carp_runtime(carp, command_func) if control_ok else runtime

        if runtime is None:
            control_ok = False
        elif group["desired_demoted"]:
            control_ok = control_ok and runtime["advskew"] == FAILOVER_ADV_SKEW and runtime["state"] == "BACKUP"
        else:
            control_ok = control_ok and runtime["advskew"] == carp.advskew

        result.append({
            "key": key,
            "interface": carp.interface,
            "device": carp.device,
            "vhid": carp.vhid,
            "checks": group["checks"],
            "ready": group["ready"],
            "healthy": group["healthy"],
            "desired_demoted": group["desired_demoted"],
            "configured_advskew": carp.advskew,
            "current_advskew": runtime["advskew"] if runtime is not None else None,
            "carp_state": runtime["state"] if runtime is not None else "UNKNOWN",
            "control_ok": control_ok,
            "retired": False,
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
            success = set_vhid_priority(carp, False, command_func) and success
    return success


def build_state(config, tracker, ready, healthy, vhids=None, now=None):
    now = time.time() if now is None else now
    vhids = [] if vhids is None else vhids
    global_state, _ = scope_health(config, tracker)
    vhid_by_key = {item.get("key"): item for item in vhids if not item.get("retired")}
    checks = []
    by_uuid = {check.uuid: check for check in config.checks}
    for uuid, record in tracker.records.items():
        check = by_uuid.get(uuid)
        if check is None:
            continue
        row = {
            "uuid": uuid,
            "name": check.name,
            "interface": check.interface,
            "device": check.device,
            "target": check.target,
            "scope": check.scope,
            "vhid": check.vhid,
            **record,
        }
        if check.scope == "vhid":
            runtime = vhid_by_key.get(f"{check.interface}:{check.vhid}", {})
            row.update({
                "carp_state": runtime.get("carp_state", "UNKNOWN"),
                "configured_advskew": runtime.get("configured_advskew"),
                "current_advskew": runtime.get("current_advskew"),
                "control_ok": runtime.get("control_ok", False),
            })
        checks.append(row)
    control_ok = all(item.get("control_ok", False) for item in vhids)
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
