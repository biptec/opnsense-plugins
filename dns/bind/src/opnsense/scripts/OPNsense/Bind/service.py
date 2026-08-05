#!/usr/bin/env python3

"""Manage BIND and remove artifacts owned by the OPNsense plugin.

The plugin stores generated zone files under UUID names and DNSSEC keys in a
per-zone directory. Cleanup is intentionally limited to those namespaces, so
custom includes and unrelated files in namedb remain untouched.
"""

import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

CONFIG = "/conf/config.xml"
NAMED_RC = "/usr/local/etc/rc.d/named"
PRIMARY_DIR = "/usr/local/etc/namedb/primary"
SECONDARY_DIR = "/usr/local/etc/namedb/secondary"
KEY_ROOT = "/usr/local/etc/namedb/keys"
MARKER = ".opnsense-managed"
UUID_RE = re.compile(
    r"^(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.db(?:\..*)?$",
    re.IGNORECASE,
)
ZONE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
LEGACY_KEY_RE = re.compile(r"^K(?P<zone>.+)\.\+[0-9]{3}\+[0-9]{5}\.(?:key|private|state)$")


def configured_domains():
    primary = set()
    secondary = set()
    dnssec_zones = set()

    root = ET.parse(CONFIG).getroot()
    domains = root.findall("./OPNsense/bind/domain/domains/domain")
    for domain in domains:
        uuid = (domain.get("uuid") or "").lower()
        domain_type = (domain.findtext("type") or "").strip()
        zone = (domain.findtext("domainname") or "").strip().rstrip(".").lower()
        if UUID_RE.match(uuid + ".db"):
            if domain_type == "primary":
                primary.add(uuid)
            elif domain_type == "secondary":
                secondary.add(uuid)
        # Keep signing keys while a zone remains configured for DNSSEC, even
        # when the zone or its view is temporarily disabled.
        if domain_type == "primary" and (domain.findtext("dnssec") or "0") == "1":
            if ZONE_RE.fullmatch(zone):
                dnssec_zones.add(zone)
    return primary, secondary, dnssec_zones


def remove_stale_zone_artifacts(directory, configured):
    if not os.path.isdir(directory):
        return
    for name in os.listdir(directory):
        match = UUID_RE.fullmatch(name)
        if match and match.group("uuid").lower() not in configured:
            path = os.path.join(directory, name)
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)


def ensure_zone_key_directory(zone):
    path = os.path.join(KEY_ROOT, zone)
    os.makedirs(path, mode=0o750, exist_ok=True)
    marker = os.path.join(path, MARKER)
    if not os.path.exists(marker):
        with open(marker, "w", encoding="ascii") as handle:
            handle.write(zone + "\n")
    os.chmod(path, 0o750)
    try:
        shutil.chown(path, user="bind", group="bind")
        shutil.chown(marker, user="bind", group="bind")
    except LookupError:
        pass
    return path


def migrate_legacy_keys(dnssec_zones):
    """Move keys for currently configured zones from the legacy global path.

    Unknown root-level key files are deliberately left untouched. Only marked
    per-zone directories are eligible for automatic removal.
    """
    if not os.path.isdir(KEY_ROOT):
        return
    for name in os.listdir(KEY_ROOT):
        match = LEGACY_KEY_RE.fullmatch(name)
        if not match:
            continue
        zone = match.group("zone").lower()
        source = os.path.join(KEY_ROOT, name)
        if zone in dnssec_zones:
            destination = os.path.join(ensure_zone_key_directory(zone), name)
            if not os.path.exists(destination):
                os.replace(source, destination)
            else:
                os.unlink(source)
        # Leave keys for unknown zones untouched: they may belong to a custom
        # include rather than to the plugin.


def reconcile_key_directories(dnssec_zones):
    os.makedirs(KEY_ROOT, mode=0o750, exist_ok=True)
    try:
        shutil.chown(KEY_ROOT, user="bind", group="bind")
    except LookupError:
        pass

    migrate_legacy_keys(dnssec_zones)
    for zone in dnssec_zones:
        ensure_zone_key_directory(zone)

    for name in os.listdir(KEY_ROOT):
        path = os.path.join(KEY_ROOT, name)
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        marker = os.path.join(path, MARKER)
        # Only directories explicitly marked as plugin-owned may be removed.
        if os.path.isfile(marker) and name.lower() not in dnssec_zones:
            shutil.rmtree(path)


def cleanup():
    primary, secondary, dnssec_zones = configured_domains()
    remove_stale_zone_artifacts(PRIMARY_DIR, primary)
    remove_stale_zone_artifacts(SECONDARY_DIR, secondary)
    reconcile_key_directories(dnssec_zones)


def run_named(action):
    return subprocess.call([NAMED_RC, action])


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action not in {"start", "stop", "restart", "reload"}:
        print("usage: service.py {start|stop|restart|reload}", file=sys.stderr)
        return 64

    if action == "stop":
        status = run_named("stop")
        cleanup()
        return status
    if action in {"restart", "reload"}:
        run_named("stop")
        cleanup()
        return run_named("start")

    cleanup()
    return run_named("start")


if __name__ == "__main__":
    raise SystemExit(main())
