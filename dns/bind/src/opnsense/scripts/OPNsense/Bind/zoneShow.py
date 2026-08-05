#!/usr/bin/env python3

# send generated primary zone file content to stdout

import os.path
import re
import sys
import ujson

zone_id = sys.argv[1] if len(sys.argv) > 1 else ""
result = {}
zone_config = []
zone_files_root = "/usr/local/etc/namedb/primary/"

if re.fullmatch(r"[0-9a-fA-F-]+", zone_id):
    zone_file = zone_files_root + zone_id + ".db"
    if os.path.isfile(zone_file):
        result["path"] = zone_file
        result["time"] = os.path.getmtime(zone_file)
        with open(zone_file, "r", encoding="utf-8") as handle:
            for line in handle.read().split("\n"):
                zone_config.append(line.rstrip())
        result["zone_content"] = zone_config

print(ujson.dumps(result))
