import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "net/frr/src/opnsense/scripts/frr"
sys.path.insert(0, str(SCRIPTS))
sys.modules.setdefault("ujson", json)
from lib.events import connected as CONNECTED


IFCONFIG_BACKUP = """\
vlan3990: flags=1008943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 10.250.99.1 netmask 0xfffffffc broadcast 10.250.99.3 vhid 165
\tinet6 fd00:3990::1 prefixlen 64 vhid 165
\tinet6 fe80::1%vlan3990 prefixlen 64 scopeid 0x7
\tcarp: BACKUP vhid 165 advbase 1 advskew 100
"""

IFCONFIG_MASTER = IFCONFIG_BACKUP.replace("BACKUP", "MASTER").replace("advskew 100", "advskew 0")


class FakeCommands:
    def __init__(self):
        self.routes = {
            (4, "10.250.99.0/30"): {"gateway": "", "interface": "vlan3990"},
            (6, "fd00:3990::/64"): {"gateway": "", "interface": "vlan3990"},
        }
        self.ospf = {
            (4, "10.250.99.0/30"): {"gateway": "10.250.99.5", "interface": "vlan3991"},
            (6, "fd00:3990::/64"): {"gateway": "fe80::1", "interface": "vlan3991"},
        }
        self.calls = []
        self.fail_delete = False
        self.fail_add = False

    def __call__(self, command):
        self.calls.append(command)
        if command[:3] == ["/sbin/route", "-n", "get"]:
            family = 6 if "-inet6" in command else 4
            prefix = command[-1]
            route = self.routes.get((family, prefix))
            if route is None:
                return subprocess.CompletedProcess(command, 1, "", "not in table")
            text = f"route to: {prefix}\ndestination: {prefix}\n"
            if route["gateway"]:
                text += f"gateway: {route['gateway']}\n"
            text += f"interface: {route['interface']}\n"
            return subprocess.CompletedProcess(command, 0, text, "")
        if command[:2] == ["/usr/local/bin/vtysh", "-c"]:
            raw = command[-1]
            family = 6 if raw.startswith("show ipv6") else 4
            prefix = raw.split()[3]
            route = self.ospf.get((family, prefix))
            if route is None:
                return subprocess.CompletedProcess(command, 0, "{}", "")
            protocol = "ospf6" if family == 6 else "ospf"
            payload = {
                prefix: [
                    {
                        "protocol": protocol,
                        "nexthops": [
                            {
                                "active": True,
                                "ip": route["gateway"],
                                "interfaceName": route["interface"],
                            }
                        ],
                    },
                    {
                        "protocol": "connected",
                        "selected": True,
                        "nexthops": [{"active": True, "interfaceName": "vlan3990"}],
                    },
                ]
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:2] == ["/sbin/route", "delete"]:
            if self.fail_delete:
                return subprocess.CompletedProcess(command, 1, "", "delete failed")
            family = 6 if "-inet6" in command else 4
            prefix = command[command.index("-net") + 1]
            self.routes.pop((family, prefix), None)
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["/sbin/route", "add"]:
            if self.fail_add:
                return subprocess.CompletedProcess(command, 1, "", "add failed")
            family = 6 if "-inet6" in command else 4
            prefix = command[command.index("-net") + 1]
            if "-iface" in command:
                interface = command[-1]
                gateway = ""
            else:
                gateway = command[-1]
                interface = "vlan3991"
            self.routes[(family, prefix)] = {"gateway": gateway, "interface": interface}
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected command: {command}")


class ConnectedCarpFallbackTest(unittest.TestCase):
    def test_parse_carp_prefixes_keeps_interface_scoped_state(self):
        got = CONNECTED.parse_carp_prefixes(IFCONFIG_BACKUP)
        self.assertEqual(
            got,
            [
                {"interface": "vlan3990", "vhid": "165", "family": 4, "network": "10.250.99.0/30", "state": "backup"},
                {"interface": "vlan3990", "vhid": "165", "family": 6, "network": "fd00:3990::/64", "state": "backup"},
            ],
        )

    def test_backup_replaces_direct_routes_with_peer_ospf_fallback(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            actions = CONNECTED.ConnectedCarpReconciler(commands, state).reconcile(IFCONFIG_BACKUP)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")]["gateway"], "10.250.99.5")
            self.assertEqual(commands.routes[(6, "fd00:3990::/64")]["gateway"], "fe80::1%vlan3991")
            self.assertEqual(sum(item["action"] == "add-fallback" for item in actions), 2)
            stored = CONNECTED.load_state(state)
            self.assertEqual(len(stored), 2)

    def test_master_removes_managed_fallback_and_restores_connected_routes(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            reconciler = CONNECTED.ConnectedCarpReconciler(commands, state)
            reconciler.reconcile(IFCONFIG_BACKUP)
            actions = reconciler.reconcile(IFCONFIG_MASTER)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")], {"gateway": "", "interface": "vlan3990"})
            self.assertEqual(commands.routes[(6, "fd00:3990::/64")], {"gateway": "", "interface": "vlan3990"})
            self.assertEqual(sum(item["action"] == "restore-connected" for item in actions), 2)
            self.assertEqual(CONNECTED.load_state(state), [])

    def test_ospf_withdrawal_removes_only_managed_fallback(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            reconciler = CONNECTED.ConnectedCarpReconciler(commands, state)
            reconciler.reconcile(IFCONFIG_BACKUP)
            commands.ospf.clear()
            with patch.object(CONNECTED, "MISSING_OSPF_GRACE", 0):
                actions = reconciler.reconcile(IFCONFIG_BACKUP)
            self.assertNotIn((4, "10.250.99.0/30"), commands.routes)
            self.assertNotIn((6, "fd00:3990::/64"), commands.routes)
            self.assertEqual(sum(item["action"] == "delete-fallback" for item in actions), 2)

    def test_mixed_carp_states_on_same_prefix_keep_local_connected_route(self):
        commands = FakeCommands()
        mixed = IFCONFIG_BACKUP + """\
	inet 10.250.99.2 netmask 0xfffffffc broadcast 10.250.99.3 vhid 166
	carp: MASTER vhid 166 advbase 1 advskew 0
"""
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            actions = CONNECTED.ConnectedCarpReconciler(commands, state).reconcile(mixed)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")], {"gateway": "", "interface": "vlan3990"})
            self.assertFalse(any(item["action"] == "add-fallback" and item["family"] == 4 for item in actions))

    def test_ospf_path_on_carp_interface_is_not_used_as_fallback(self):
        commands = FakeCommands()
        commands.ospf[(4, "10.250.99.0/30")]["interface"] = "vlan3990"
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            CONNECTED.ConnectedCarpReconciler(commands, state).reconcile(IFCONFIG_BACKUP)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")], {"gateway": "", "interface": "vlan3990"})

    def test_transient_ospf_loss_keeps_managed_fallback_during_grace(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            reconciler = CONNECTED.ConnectedCarpReconciler(commands, state)
            reconciler.reconcile(IFCONFIG_BACKUP)
            commands.ospf.clear()
            with patch.object(CONNECTED.time, "time", return_value=100.0):
                reconciler.reconcile(IFCONFIG_BACKUP)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")]["gateway"], "10.250.99.5")
            stored = CONNECTED.load_state(state)
            self.assertTrue(all(item.get("missing_since") == 100.0 for item in stored))
            with patch.object(CONNECTED.time, "time", return_value=100.0 + CONNECTED.MISSING_OSPF_GRACE + 1):
                reconciler.reconcile(IFCONFIG_BACKUP)
            self.assertNotIn((4, "10.250.99.0/30"), commands.routes)
            self.assertEqual(CONNECTED.load_state(state), [])

    def test_failed_fallback_delete_remains_tracked_for_retry(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            reconciler = CONNECTED.ConnectedCarpReconciler(commands, state)
            reconciler.reconcile(IFCONFIG_BACKUP)
            commands.ospf.clear()
            commands.fail_delete = True
            with patch.object(CONNECTED, "MISSING_OSPF_GRACE", 0):
                reconciler.reconcile(IFCONFIG_BACKUP)
            self.assertEqual(len(CONNECTED.load_state(state)), 2)
            commands.fail_delete = False
            with patch.object(CONNECTED, "MISSING_OSPF_GRACE", 0):
                reconciler.reconcile(IFCONFIG_BACKUP)
            self.assertEqual(CONNECTED.load_state(state), [])

    def test_failed_fallback_add_is_not_claimed(self):
        commands = FakeCommands()
        commands.fail_add = True
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            CONNECTED.ConnectedCarpReconciler(commands, state).reconcile(IFCONFIG_BACKUP)
            self.assertEqual(CONNECTED.load_state(state), [])

    def test_unmanaged_gateway_route_is_never_replaced(self):
        commands = FakeCommands()
        commands.routes[(4, "10.250.99.0/30")] = {"gateway": "192.0.2.1", "interface": "vlan3999"}
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            CONNECTED.ConnectedCarpReconciler(commands, state).reconcile(IFCONFIG_BACKUP)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")]["gateway"], "192.0.2.1")
            self.assertEqual(commands.routes[(6, "fd00:3990::/64")]["gateway"], "fe80::1%vlan3991")

    def test_cleanup_removes_only_managed_backup_fallbacks(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            reconciler = CONNECTED.ConnectedCarpReconciler(commands, state)
            reconciler.reconcile(IFCONFIG_BACKUP)
            actions = reconciler.cleanup(IFCONFIG_BACKUP)
            self.assertNotIn((4, "10.250.99.0/30"), commands.routes)
            self.assertNotIn((6, "fd00:3990::/64"), commands.routes)
            self.assertEqual(sum(item["action"] == "delete-fallback" for item in actions), 2)
            self.assertEqual(CONNECTED.load_state(state), [])

    def test_cleanup_restores_connected_route_if_carp_is_master(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            reconciler = CONNECTED.ConnectedCarpReconciler(commands, state)
            reconciler.reconcile(IFCONFIG_BACKUP)
            actions = reconciler.cleanup(IFCONFIG_MASTER)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")], {"gateway": "", "interface": "vlan3990"})
            self.assertEqual(commands.routes[(6, "fd00:3990::/64")], {"gateway": "", "interface": "vlan3990"})
            self.assertEqual(sum(item["action"] == "restore-connected" for item in actions), 2)
            self.assertEqual(CONNECTED.load_state(state), [])

    def test_cleanup_never_deletes_an_unmanaged_replacement_route(self):
        commands = FakeCommands()
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state.json")
            reconciler = CONNECTED.ConnectedCarpReconciler(commands, state)
            reconciler.reconcile(IFCONFIG_BACKUP)
            commands.routes[(4, "10.250.99.0/30")] = {"gateway": "192.0.2.1", "interface": "vlan3999"}
            reconciler.cleanup(IFCONFIG_BACKUP)
            self.assertEqual(commands.routes[(4, "10.250.99.0/30")], {"gateway": "192.0.2.1", "interface": "vlan3999"})
            self.assertEqual(CONNECTED.load_state(state), [])


if __name__ == "__main__":
    unittest.main()
