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

    key_pattern = os.path.join(KEY_DIRECTORY, "K" + glob.escape(zone.rstrip(".")) + ".+*.key")
    for key_file in sorted(glob.glob(key_pattern)):
        key_result = {"file": os.path.basename(key_file)}
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
