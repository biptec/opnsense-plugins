#!/usr/bin/env python3

import glob
import json
import os
import re
import subprocess
import sys

ZONE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
VIEW_RE = re.compile(r"^[A-Za-z0-9_-]+$")
KEY_DIRECTORY = "/usr/local/etc/namedb/keys"
RNDC_CONFIG = "/usr/local/etc/namedb/rndc.conf"


def run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def parse_status(output):
    result = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip().replace(" ", "_")] = value.strip()
    return result


def main():
    zone = sys.argv[1] if len(sys.argv) > 1 else ""
    view = sys.argv[2] if len(sys.argv) > 2 else "__default__"
    result = {"zone": zone, "view": None if view == "__default__" else view, "ds_records": [], "keys": []}

    if not ZONE_RE.fullmatch(zone) or (view != "__default__" and not VIEW_RE.fullmatch(view)):
        result["error"] = "invalid zone or view"
        print(json.dumps(result))
        return

    normalized_zone = zone.rstrip(".").lower()
    key_patterns = [
        os.path.join(KEY_DIRECTORY, normalized_zone, "K" + glob.escape(normalized_zone) + ".+*.key"),
        os.path.join(KEY_DIRECTORY, "K" + glob.escape(normalized_zone) + ".+*.key"),
    ]
    key_files = sorted({key_file for pattern in key_patterns for key_file in glob.glob(pattern)})
    for key_file in key_files:
        key_result = {"file": os.path.relpath(key_file, KEY_DIRECTORY)}
        flags = None
        try:
            with open(key_file, "r", encoding="utf-8") as handle:
                key_text = " ".join(
                    line.strip() for line in handle if line.strip() and not line.lstrip().startswith(";")
                )
            match = re.search(r"\sDNSKEY\s+(\d+)\s+(\d+)\s+(\d+)\s", key_text)
            if match:
                flags = int(match.group(1))
                key_result["flags"] = str(flags)
                key_result["algorithm"] = match.group(3)
                if flags & 128:
                    key_result["role"] = "revoked"
                elif flags & 1:
                    key_result["role"] = "ksk"
                else:
                    key_result["role"] = "zsk"
        except OSError as error:
            key_result["error"] = str(error)

        # Only SEP/KSK or CSK records belong at the parent. Never publish a
        # revoked key or a zone-signing-only key as a DS record.
        if flags is not None and flags & 1 and not flags & 128:
            ds = run(["/usr/local/bin/dnssec-dsfromkey", "-2", key_file])
            if ds.returncode == 0:
                records = [line.strip() for line in ds.stdout.splitlines() if line.strip()]
                result["ds_records"].extend(records)
                if records:
                    fields = records[0].split()
                    if len(fields) >= 7:
                        key_result["key_tag"] = fields[-4]
                        key_result["algorithm"] = fields[-3]
            else:
                key_result["error"] = ds.stderr.strip() or ds.stdout.strip()
        result["keys"].append(key_result)

    command = ["/usr/local/sbin/rndc", "-c", RNDC_CONFIG, "zonestatus", zone]
    if view != "__default__":
        command.extend(["IN", view])
    status = run(command)
    result["rndc_status"] = parse_status(status.stdout)
    result["secure"] = result["rndc_status"].get("secure") == "yes"
    result["inline_signing"] = result["rndc_status"].get("inline_signing") == "yes"
    if status.returncode != 0:
        result["error"] = status.stderr.strip() or status.stdout.strip()

    # Avoid duplicate DS records when multiple public key files yield the same DS.
    result["ds_records"] = sorted(set(result["ds_records"]))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
