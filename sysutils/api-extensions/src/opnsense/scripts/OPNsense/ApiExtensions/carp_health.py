#!/usr/local/bin/python3
import hashlib
import ipaddress
import json
import os
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


@dataclass(frozen=True)
class Config:
    enabled: bool
    interval: int
    failure_threshold: int
    recovery_threshold: int
    checks: tuple
    signature: str


def load_config(path=CONFIG_PATH):
    tree = ET.parse(path)
    root = tree.getroot()
    node = root.find("./OPNsense/ApiExtensions/CarpHealth")
    if node is None:
        return Config(False, 1, 2, 2, tuple(), "disabled")

    enabled = as_bool(node.findtext("enabled"))
    interval = as_int(node.findtext("interval"), 1, 1, 60)
    failure = as_int(node.findtext("failure_threshold"), 2, 1, 20)
    recovery = as_int(node.findtext("recovery_threshold"), 2, 1, 20)

    interface_map = {}
    interfaces = root.find("./interfaces")
    if interfaces is not None:
        for item in list(interfaces):
            interface_map[item.tag] = (item.findtext("if") or "").strip()

    checks = []
    for item in node.findall("./checks/check"):
        if not as_bool(item.findtext("enabled"), True):
            continue
        name = (item.findtext("name") or "").strip()
        friendly = (item.findtext("interface") or "").strip()
        target = (item.findtext("target") or "").strip()
        uuid = item.attrib.get("uuid", "") or name
        try:
            target = str(ipaddress.IPv4Address(target))
        except ipaddress.AddressValueError:
            target = ""
        checks.append(Check(uuid, name, friendly, interface_map.get(friendly, ""), target))

    canonical = {
        "enabled": enabled,
        "interval": interval,
        "failure_threshold": failure,
        "recovery_threshold": recovery,
        "checks": [check.__dict__ for check in checks],
    }
    signature = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()
    return Config(enabled, interval, failure, recovery, tuple(checks), signature)


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


def build_state(config, tracker, ready, healthy, now=None):
    now = time.time() if now is None else now
    checks = []
    by_uuid = {check.uuid: check for check in config.checks}
    for uuid, record in tracker.records.items():
        check = by_uuid.get(uuid)
        if check is None:
            continue
        checks.append({
            "uuid": uuid,
            "name": check.name,
            "interface": check.interface,
            "device": check.device,
            "target": check.target,
            **record,
        })
    return {
        "status": "ok",
        "enabled": config.enabled,
        "ready": ready,
        "healthy": healthy,
        "timestamp": now,
        "config_signature": config.signature,
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
    return {
        "status": "ok",
        "enabled": config.enabled,
        "ready": not config.enabled,
        "healthy": not config.enabled,
        "running": running,
        "timestamp": 0,
        "config_signature": config.signature,
        "checks": [],
    }


def checker_exit_code(config, state, now=None):
    if not config.enabled:
        return 0
    if state is None:
        return 1
    if state.get("config_signature") != config.signature:
        return 1
    if not state_is_current(config, state, now):
        return 1
    if not state.get("ready", False):
        return 0
    return 0 if state.get("healthy", False) else 1


def trigger_carp_service_status(configctl=CONFIGCTL):
    return subprocess.run(
        [configctl, "interface", "update", "carp", "service_status"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    ).returncode == 0
