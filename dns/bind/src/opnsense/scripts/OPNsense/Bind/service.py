#!/usr/bin/env python3

"""Manage BIND and remove artifacts owned by the OPNsense plugin.

The plugin stores generated zone files under UUID names and DNSSEC keys in a
per-zone directory. Cleanup is intentionally limited to those namespaces, so
custom includes and unrelated files in namedb remain untouched.
"""

import json
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
RUNTIME_SNAPSHOT = "/var/run/opnsense-bind-runtime.json"
NAMED_COMPILEZONE = "/usr/local/bin/named-compilezone"
NAMED_JOURNALPRINT = "/usr/local/bin/named-journalprint"
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



def _relation_values(value):
    return [item for item in re.split(r"[\s,]+", value or "") if item]


def configured_self_txt_zones():
    """Return primary zones whose exact TSIG owners may hold runtime TXT data."""
    root = ET.parse(CONFIG).getroot()
    key_names = {}
    for key in root.findall("./OPNsense/bind/tsig/keys/key"):
        if (key.findtext("enabled") or "1") != "1":
            continue
        uuid = (key.get("uuid") or "").lower()
        name = (key.findtext("name") or "").strip().rstrip(".").lower()
        if UUID_RE.match(uuid + ".db") and ZONE_RE.fullmatch(name):
            key_names[uuid] = name

    zones = {}
    for domain in root.findall("./OPNsense/bind/domain/domains/domain"):
        if (domain.findtext("enabled") or "1") != "1":
            continue
        if (domain.findtext("type") or "").strip() != "primary":
            continue
        if (domain.findtext("updatepolicy") or "self_txt").strip() != "self_txt":
            continue
        uuid = (domain.get("uuid") or "").lower()
        zone = (domain.findtext("domainname") or "").strip().rstrip(".").lower()
        if not UUID_RE.match(uuid + ".db") or not ZONE_RE.fullmatch(zone):
            continue
        owners = set()
        for key_uuid in _relation_values(domain.findtext("updatekeys")):
            owner = key_names.get(key_uuid.lower())
            if owner and (owner == zone or owner.endswith("." + zone)):
                owners.add(owner)
        if owners:
            zones[uuid] = {"zone": zone, "owners": sorted(owners)}
    return zones


def _parse_zone_text(text, owners):
    serial = None
    records = {owner: set() for owner in owners}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 5 or parts[2].upper() != "IN":
            continue
        owner = parts[0].rstrip(".").lower()
        rrtype = parts[3].upper()
        rdata = parts[4].strip()
        if rrtype == "SOA":
            fields = rdata.split()
            if len(fields) >= 3 and fields[2].isdigit():
                serial = int(fields[2])
        elif rrtype == "TXT" and owner in records:
            try:
                ttl = int(parts[1])
            except ValueError:
                ttl = 60
            records[owner].add((ttl, rdata))
    return serial, records


def _compile_zone(zone, path, with_journal=False):
    command = [NAMED_COMPILEZONE, "-D", "-F", "text"]
    if with_journal:
        command.append("-j")
    command.extend(["-o", "-", zone, path])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return result.stdout if result.returncode == 0 else None


def _replay_journal(path, owners, serial, records):
    result = subprocess.run([NAMED_JOURNALPRINT, path], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError("unable to read BIND journal %s: %s" % (path, result.stderr.strip()))
    for raw_line in result.stdout.splitlines():
        parts = raw_line.strip().split(None, 5)
        if len(parts) < 5 or parts[0] not in {"add", "del"}:
            continue
        action, owner_raw, ttl_raw, dns_class, rrtype = parts[:5]
        if dns_class.upper() != "IN":
            continue
        owner = owner_raw.rstrip(".").lower()
        rdata = parts[5].strip() if len(parts) == 6 else ""
        if rrtype.upper() == "SOA" and action == "add":
            fields = rdata.split()
            if len(fields) >= 3 and fields[2].isdigit():
                serial = int(fields[2])
            continue
        if rrtype.upper() != "TXT" or owner not in records:
            continue
        try:
            ttl = int(ttl_raw)
        except ValueError:
            ttl = 60
        if action == "add" and rdata:
            records[owner].add((ttl, rdata))
        elif action == "del":
            if rdata:
                records[owner].discard((ttl, rdata))
            else:
                records[owner].clear()
    return serial, records


def _journal_paths(uuid):
    if not os.path.isdir(PRIMARY_DIR):
        return []
    prefix = uuid.lower() + ".db"
    return sorted(
        os.path.join(PRIMARY_DIR, name)
        for name in os.listdir(PRIMARY_DIR)
        if name.lower().startswith(prefix) and name.lower().endswith(".jnl")
    )


def _current_zone_state(uuid, zone, owners, include_master=False):
    path = os.path.join(PRIMARY_DIR, uuid + ".db")
    journals = _journal_paths(uuid)
    if not journals:
        if not include_master:
            return None
        compiled = _compile_zone(zone, path, with_journal=False)
        if compiled is None:
            raise RuntimeError("unable to read BIND primary zone %s" % zone)
        serial, records = _parse_zone_text(compiled, owners)
        if not any(records.values()):
            return None
        return serial, records
    compiled = _compile_zone(zone, path, with_journal=True)
    if compiled is not None:
        return _parse_zone_text(compiled, owners)
    compiled = _compile_zone(zone, path, with_journal=False)
    if compiled is None:
        raise RuntimeError("unable to read BIND primary zone %s" % zone)
    serial, records = _parse_zone_text(compiled, owners)
    for journal in journals:
        serial, records = _replay_journal(journal, owners, serial, records)
    return serial, records


def _write_snapshot(snapshot):
    directory = os.path.dirname(RUNTIME_SNAPSHOT) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary = RUNTIME_SNAPSHOT + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, sort_keys=True)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, RUNTIME_SNAPSHOT)


def snapshot_runtime_txt(include_master=False):
    """Capture exact self-TXT runtime state before generated zone files change."""
    zones = configured_self_txt_zones()
    snapshot = {"version": 1, "zones": {}}
    journalled = []
    for uuid, item in zones.items():
        state = _current_zone_state(
            uuid, item["zone"], set(item["owners"]), include_master=include_master
        )
        if state is None:
            continue
        serial, records = state
        snapshot["zones"][uuid] = {
            "zone": item["zone"],
            "serial": serial,
            "records": [
                {"owner": owner, "ttl": ttl, "rdata": rdata}
                for owner in sorted(records)
                for ttl, rdata in sorted(records[owner])
                if "\n" not in rdata and "\r" not in rdata
            ],
        }
        journalled.append(uuid)
    if not journalled:
        return
    _write_snapshot(snapshot)
    for uuid in journalled:
        for journal in _journal_paths(uuid):
            os.unlink(journal)


def _replace_soa_serial(text, serial):
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if re.search(r"\bIN\s+SOA\b", line, flags=re.IGNORECASE):
            replaced, count = re.subn(r"(\(\s*)[0-9]+(\s+)", rf"\g<1>{serial}\g<2>", line, count=1)
            if count:
                lines[index] = replaced
                return "".join(lines)
    raise RuntimeError("unable to locate SOA serial in generated zone file")


def _next_serial(serial):
    return 1 if serial >= 4294967295 else serial + 1


def restore_runtime_txt():
    """Merge captured self-TXT records into freshly rendered primary zone files."""
    if not os.path.exists(RUNTIME_SNAPSHOT):
        return
    with open(RUNTIME_SNAPSHOT, "r", encoding="utf-8") as handle:
        snapshot = json.load(handle)
    configured = configured_self_txt_zones()
    for uuid, item in snapshot.get("zones", {}).items():
        if not UUID_RE.match(uuid + ".db") or not ZONE_RE.fullmatch(item.get("zone", "")):
            raise RuntimeError("invalid runtime snapshot zone identity")
        current = configured.get(uuid)
        if current is None or current["zone"] != item["zone"]:
            continue
        allowed_owners = set(current["owners"])
        path = os.path.join(PRIMARY_DIR, uuid + ".db")
        records = [
            record for record in item.get("records", [])
            if (record.get("owner") or "").rstrip(".").lower() in allowed_owners
        ]
        owners = {record.get("owner", "").rstrip(".").lower() for record in records}
        compiled = _compile_zone(item["zone"], path, with_journal=False)
        if compiled is None:
            raise RuntimeError("unable to validate freshly rendered BIND zone %s" % item["zone"])
        generated_serial, existing = _parse_zone_text(compiled, owners)
        snapshot_serial = item.get("serial")
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        if isinstance(snapshot_serial, int) and (
            generated_serial is None or generated_serial <= snapshot_serial
        ):
            text = _replace_soa_serial(text, _next_serial(snapshot_serial))
        additions = []
        for record in records:
            owner = (record.get("owner") or "").rstrip(".").lower()
            ttl = record.get("ttl")
            rdata = record.get("rdata") or ""
            if owner not in owners or not ZONE_RE.fullmatch(owner):
                raise RuntimeError("invalid runtime TXT owner")
            if not isinstance(ttl, int) or ttl < 0 or "\n" in rdata or "\r" in rdata:
                raise RuntimeError("invalid runtime TXT record")
            if (ttl, rdata) not in existing.get(owner, set()):
                additions.append(f"{owner}.\t{ttl}\tIN\tTXT\t{rdata}\n")
        if additions:
            if text and not text.endswith("\n"):
                text += "\n"
            text += "".join(additions)
        stat = os.stat(path)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(path, stat.st_mode & 0o7777)
        try:
            os.chown(path, stat.st_uid, stat.st_gid)
        except PermissionError:
            pass
    os.unlink(RUNTIME_SNAPSHOT)


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
        if status == 0:
            snapshot_runtime_txt(include_master=True)
            cleanup()
        return status
    if action == "restart":
        status = run_named("stop")
        if status != 0:
            return status
        snapshot_runtime_txt(include_master=True)
        cleanup()
        restore_runtime_txt()
        return run_named("start")
    if action == "reload":
        cleanup()
        return run_named("reload")

    cleanup()
    snapshot_runtime_txt()
    restore_runtime_txt()
    return run_named("start")


if __name__ == "__main__":
    raise SystemExit(main())
