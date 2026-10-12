#!/usr/bin/env python3
"""Reproduce OLD Etna's v2 HA sync payloads with the actual pinned OLD Plugins code.

This executes only old plugin PHP classes from the immutable Golden revision
in a network-disabled ephemeral php-cli container. No router connectivity,
UUID migration, Terraform state, credentials, or Proxmox access is involved.

Usage from the plugins checkout: python3 sysutils/api-extensions/tests/generate_legacy_v2.py
The produced JSON is a synthetic regression fixture (not a router export).
"""
import argparse
import hashlib
import io
import json
import pathlib
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
TEST_DIR = pathlib.Path(__file__).resolve().parent
OLD = "7dc9649eef6f86d837fa47fb1edaef6d5a790b36"
CLASS = "sysutils/api-extensions/src/opnsense/mvc/app/models/OPNsense/ApiExtensions/"
TEST = "sysutils/api-extensions/tests/"
TARGET = TEST_DIR / "legacy_etna_v2_payload.json"


def git_old(path: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "show", f"{OLD}:{path}"], text=True
    )


def php_produce(class_names: tuple[str, ...], helper_source: str, body: str):
    all_sources = {
        f"legacy/{name}": git_old(CLASS + name).encode()
        for name in class_names
    }
    require = "".join(
        f"require_once __DIR__ . '/legacy/{name}';\n"
        for name in class_names
    )
    source = (
        "<?php\n"
        + require
        + "\nuse OPNsense\\ApiExtensions\\InterfaceSync;\n"
        + "use OPNsense\\ApiExtensions\\HAProxySync;\n"
        + helper_source
        + "\n"
        + body
        + "\n"
    )
    all_sources["producer.php"] = source.encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name, data in all_sources.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o444
            archive.addfile(entry, io.BytesIO(data))
    process = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none", "--memory", "128m",
            "-i", "php:8.3-cli-alpine", "sh", "-ec",
            "mkdir -p /qa; tar -xf - -C /qa; php /qa/producer.php",
        ],
        input=buf.getvalue(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if process.returncode:
        raise RuntimeError(
            f"old PHP payload generator failed code={process.returncode}: "
            + process.stderr.decode(errors="replace")[:3000]
        )
    return json.loads(process.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='regenerate in-memory and verify committed fixture, without writing')
    args = parser.parse_args()
    old_iface = git_old(TEST + "test_interface_sync.php")
    iface_defs = old_iface[
        old_iface.index("function model("):
        old_iface.index("$source = addSharedInterface(base());")
    ]
    logical_name = "ha_issue103_ubuntu"
    identifier = (
        f"ep_{logical_name[:8]}_{hashlib.sha1(logical_name.encode()).hexdigest()[:8]}"
    )
    description = "Issue #103 shared-test Ubuntu endpoint state continuity"
    iface_body = (
        f"$id={json.dumps(identifier)};\n"
        "$source=addSharedInterface(base(),$id,3990,'endpoint');\n"
        f"$description={json.dumps(description)};\n"
        "$source['interfaces'][$id]['descr']=$description;\n"
        "$source['vlans']['vlan'][count($source['vlans']['vlan'])-1]['descr']=$description;\n"
        "$payload=InterfaceSync::buildPayload($source);\n"
        "echo json_encode($payload,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES),\"\\n\";\n"
    )
    old_haproxy = git_old(TEST + "test_haproxy_sync.php")
    haproxy_defs = old_haproxy[
        old_haproxy.index("function policyModel("):
        old_haproxy.index("$source = sourceConfig();")
    ]
    haproxy_body = (
        "$source=sourceConfig();\n"
        "// Both native HA categories share ONE policy table on the same old Etna.\n"
        "// The old unit-test source fixtures name the same policy differently;\n"
        "// normalize that synthetic mismatch to a coherent real-router model.\n"
        "$source['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['shared']['policies']['policy'] = [\n"
        "  ['@attributes'=>['uuid'=>'p-core'], 'id'=>'core', 'description'=>'Router core','synchronize'=>'0'],\n"
        "  ['@attributes'=>['uuid'=>'p-services'], 'id'=>'services', 'description'=>'Node services','synchronize'=>'0'],\n"
        "  ['@attributes'=>['uuid'=>'p-endpoint'], 'id'=>'endpoint', 'description'=>'HA shared endpoint networks','synchronize'=>'1'],\n"
        "];\n"
        "$payload=HAProxySync::buildPayload($source);\n"
        "echo json_encode($payload,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES),\"\\n\";\n"
    )
    iface = php_produce(("InterfaceSync.php",), iface_defs, iface_body)
    haproxy = php_produce(
        ("InterfaceSync.php", "HAProxySync.php"), haproxy_defs, haproxy_body
    )
    assert iface["version"] == haproxy["version"] == 2
    assert iface["interfaces"] == [{
        "identifier": identifier, "policy_id": "endpoint",
        "description": description, "tag": 3990, "device": "vlan3990",
    }], iface
    output = {
        "fixture_type": "synthetic-old-etna-native-ha-payload",
        "source_plugin_commit": OLD,
        "producer": "exact old InterfaceSync and HAProxySync PHP classes",
        "interface": iface,
        "haproxy": haproxy,
    }
    serialized = json.dumps(output, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not TARGET.is_file() or TARGET.read_text() != serialized:
            raise SystemExit('MIXED_VERSION_FIXTURE_STALE: regenerate exact old Etna fixture')
    else:
        TARGET.write_text(serialized)
    print(
        "MIXED_VERSION_OLD_ETNA_PAYLOAD",
        OLD,
        "interface_count", len(iface["interfaces"]),
        "haproxy_keys", sorted(haproxy.keys()),
        "saved_fixture", TARGET,
    )


if __name__ == "__main__":
    main()
