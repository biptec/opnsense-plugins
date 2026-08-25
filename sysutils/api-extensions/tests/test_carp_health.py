import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/ApiExtensions/carp_health.py"
spec = importlib.util.spec_from_file_location("carp_health", MODULE)
carp_health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(carp_health)


class FakeCommands:
    def __init__(self):
        self.runtime = {
            "vlan02": {51: {"state": "MASTER", "advskew": 10}},
            "vlan03": {52: {"state": "MASTER", "advskew": 10}},
        }
        self.routes = {}
        self.calls = []

    def __call__(self, args, capture=False):
        self.calls.append(list(args))
        if args[0] == carp_health.ROUTE:
            action = args[2]
            family = "inet6" if "-inet6" in args else "inet"
            route_flag = "-net" if "-net" in args else "-host"
            destination = args[args.index(route_flag) + 1]
            key = (family, destination)
            if action == "get":
                gateway = self.routes.get(key)
                if gateway is None:
                    return 1, ""
                return 0, f"   route to: {destination}\n    gateway: {gateway}\n"
            gateway = args[-1]
            if action == "add":
                if key in self.routes:
                    return 1, ""
                self.routes[key] = gateway
                return 0, ""
            if action == "delete":
                if self.routes.get(key) == gateway:
                    del self.routes[key]
                return 0, ""
            return 1, ""

        device = args[1]
        if len(args) == 2:
            rows = self.runtime.get(device, {})
            output = "".join(
                f"\tcarp: {data['state']} vhid {vhid} advbase 1 advskew {data['advskew']}\n"
                for vhid, data in sorted(rows.items())
            )
            return 0, output
        vhid = int(args[args.index("vhid") + 1])
        advskew = int(args[args.index("advskew") + 1])
        row = self.runtime.setdefault(device, {}).setdefault(vhid, {"state": "BACKUP", "advskew": advskew})
        row["advskew"] = advskew
        if "state" in args:
            row["state"] = args[args.index("state") + 1]
        return 0, ""

    def mutations(self):
        return [call for call in self.calls if call[0] == carp_health.IFCONFIG and len(call) > 2]


class CarpHealthTests(unittest.TestCase):
    def make_config(self, checks=None, failure=2, recovery=2):
        if checks is None:
            checks = """
<check uuid="abc"><enabled>1</enabled><name>leaf</name>
<interface>opt2</interface><target>192.0.2.2</target></check>"""
        data = f"""<opnsense>
<interfaces><wan><if>vtnet1</if></wan><opt2><if>vlan02</if></opt2><opt3><if>vlan03</if></opt3></interfaces>
<virtualip>
<vip><interface>opt2</interface><mode>carp</mode><vhid>51</vhid><advskew>10</advskew></vip>
<vip><interface>opt3</interface><mode>carp</mode><vhid>52</vhid><advskew>10</advskew></vip>
</virtualip>
<OPNsense><ApiExtensions><CarpHealth>
<enabled>1</enabled><interval>1</interval>
<failure_threshold>{failure}</failure_threshold><recovery_threshold>{recovery}</recovery_threshold>
<checks>{checks}</checks>
</CarpHealth></ApiExtensions></OPNsense>
</opnsense>"""
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        handle.write(data)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return carp_health.load_config(handle.name)

    def test_load_config_keeps_old_checks_global(self):
        config = self.make_config()
        self.assertTrue(config.enabled)
        self.assertEqual(config.checks[0].device, "vlan02")
        self.assertEqual(config.checks[0].target, "192.0.2.2")
        self.assertEqual(config.checks[0].scope, "global")
        self.assertEqual(config.checks[0].vhid, 0)
        self.assertEqual(config.carp_vhids[0].vhid, 51)
        self.assertEqual(config.carp_vhids[0].advskew, 10)

    def test_load_config_specific_vhid(self):
        checks = """
<check uuid="abc"><enabled>1</enabled><name>leaf</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>51</vhid></check>"""
        config = self.make_config(checks)
        self.assertEqual(config.checks[0].scope, "vhid")
        self.assertEqual(config.checks[0].vhid, 51)
        carp = carp_health.find_carp_vhid(config, "opt2", 51)
        self.assertEqual(carp.device, "vlan02")

    def test_auto_interface_scope_discovers_carp_without_explicit_vhid(self):
        checks = """
<check uuid="leaf"><enabled>1</enabled><name>leaf</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>interface</scope></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        check = config.checks[0]
        self.assertEqual(check.vhid_targets, tuple())
        self.assertEqual(carp_health.resolve_vhid_targets(check, config), (("opt2", 51),))

        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"leaf": False})
        commands = FakeCommands()
        vhids = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        self.assertEqual(commands.mutations(), [[
            carp_health.IFCONFIG, "vlan02", "vhid", "51", "advskew", "254"
        ]])
        state = carp_health.build_state(config, tracker, True, False, vhids=vhids)
        self.assertEqual(state["checks"][0]["vhid_targets"], ["opt2:51"])
        self.assertEqual(state["checks"][0]["configured_vhid_targets"], [])
        self.assertTrue(state["checks"][0]["control_ok"])

    def test_auto_all_carp_discovers_every_configured_vhid(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>wan</interface>
<target>192.0.2.1</target><scope>all_carp</scope><failure_advskew>200</failure_advskew></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        check = config.checks[0]
        self.assertEqual(
            carp_health.resolve_vhid_targets(check, config),
            (("opt2", 51), ("opt3", 52)),
        )
        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"wan": False})
        commands = FakeCommands()
        vhids = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        by_key = {row["key"]: row for row in vhids}
        self.assertEqual(by_key["opt2:51"]["desired_advskew"], 200)
        self.assertEqual(by_key["opt3:52"]["desired_advskew"], 200)

    def test_auto_scope_without_carp_is_reported_as_control_error(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>wan</interface>
<target>192.0.2.1</target><scope>interface</scope></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"wan": False})
        state = carp_health.build_state(config, tracker, True, False, vhids=[])
        self.assertEqual(state["checks"][0]["vhid_targets"], [])
        self.assertFalse(state["checks"][0]["control_ok"])
        self.assertFalse(state["control_ok"])

    def test_probe_all_deduplicates_shared_device_target(self):
        checks = """
<check uuid="a"><enabled>1</enabled><name>wan-a</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>interface</scope></check>
<check uuid="b"><enabled>1</enabled><name>wan-b</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>51</vhid></check>"""
        config = self.make_config(checks)
        calls = []

        def fake_probe(check):
            calls.append((check.device, check.target))
            return True

        self.assertEqual(carp_health.probe_all(config, fake_probe), {"a": True, "b": True})
        self.assertEqual(calls, [("vlan02", "192.0.2.2")])

    def test_hard_failure_does_not_force_master_to_backup(self):
        checks = """
<check uuid="a"><enabled>1</enabled><name>leaf-a</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>51</vhid><failure_advskew>254</failure_advskew></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"a": False})
        commands = FakeCommands()
        first = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        self.assertEqual(commands.runtime["vlan02"][51], {"state": "MASTER", "advskew": 254})
        self.assertEqual(commands.mutations(), [[
            carp_health.IFCONFIG, "vlan02", "vhid", "51", "advskew", "254"
        ]])

        commands.calls.clear()
        second = carp_health.reconcile_vhid_scopes(config, tracker, {"vhids": first}, commands)
        self.assertEqual(commands.mutations(), [])
        self.assertEqual(second[0]["carp_state"], "MASTER")
        self.assertTrue(second[0]["control_ok"])

    def test_failure_and_recovery_thresholds(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(2, 2)
        ready, healthy = tracker.update(config.checks, {"abc": True})
        self.assertEqual((ready, healthy), (False, False))
        ready, healthy = tracker.update(config.checks, {"abc": True})
        self.assertEqual((ready, healthy), (True, True))
        ready, healthy = tracker.update(config.checks, {"abc": False})
        self.assertEqual((ready, healthy), (True, True))
        ready, healthy = tracker.update(config.checks, {"abc": False})
        self.assertEqual((ready, healthy), (True, False))
        ready, healthy = tracker.update(config.checks, {"abc": True})
        self.assertEqual((ready, healthy), (True, False))
        ready, healthy = tracker.update(config.checks, {"abc": True})
        self.assertEqual((ready, healthy), (True, True))

    def test_global_checker_is_fail_closed_until_ready(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(2, 2)
        ready, healthy = tracker.update(config.checks, {"abc": True})
        state = carp_health.build_state(config, tracker, ready, healthy, now=100.0)
        self.assertFalse(state["global"]["ready"])
        self.assertEqual(carp_health.checker_exit_code(config, state, now=101.0), 1)
        ready, healthy = tracker.update(config.checks, {"abc": True})
        state = carp_health.build_state(config, tracker, ready, healthy, now=102.0)
        self.assertEqual(carp_health.checker_exit_code(config, state, now=103.0), 0)

    def test_vhid_only_failure_never_requests_global_demotion(self):
        checks = """
<check uuid="abc"><enabled>1</enabled><name>leaf</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>51</vhid></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        ready, healthy = tracker.update(config.checks, {"abc": False})
        state = carp_health.build_state(config, tracker, ready, healthy, now=100.0)
        self.assertFalse(state["global"]["active"])
        self.assertEqual(carp_health.checker_exit_code(config, state, now=101.0), 0)

    def test_specific_vhid_initialization_is_fail_closed(self):
        checks = """
<check uuid="a"><enabled>1</enabled><name>leaf-a</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>51</vhid></check>"""
        config = self.make_config(checks, failure=2, recovery=2)
        tracker = carp_health.HealthTracker(2, 2)
        global_state, vhids = carp_health.scope_health(config, tracker)
        self.assertFalse(global_state["active"])
        self.assertFalse(vhids["opt2:51"]["ready"])
        self.assertTrue(vhids["opt2:51"]["desired_demoted"])

    def test_specific_vhid_failure_is_isolated(self):
        checks = """
<check uuid="a"><enabled>1</enabled><name>leaf-a</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>51</vhid></check>
<check uuid="b"><enabled>1</enabled><name>leaf-b</name><interface>opt3</interface>
<target>198.51.100.2</target><scope>vhid</scope><vhid>52</vhid></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"a": False, "b": True})
        commands = FakeCommands()
        states = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        mutations = commands.mutations()
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0], [
            carp_health.IFCONFIG, "vlan02", "vhid", "51", "advskew", "254"
        ])
        by_key = {item["key"]: item for item in states}
        self.assertEqual(by_key["opt2:51"]["carp_state"], "MASTER")
        self.assertEqual(by_key["opt2:51"]["current_advskew"], 254)
        self.assertEqual(by_key["opt3:52"]["current_advskew"], 10)
        self.assertTrue(by_key["opt3:52"]["control_ok"])

    def test_specific_vhid_recovery_restores_configured_advskew(self):
        checks = """
<check uuid="a"><enabled>1</enabled><name>leaf-a</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>51</vhid></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"a": False})
        first = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        tracker.update(config.checks, {"a": True})
        second = carp_health.reconcile_vhid_scopes(config, tracker, first, commands)
        self.assertEqual(commands.runtime["vlan02"][51]["advskew"], 10)
        self.assertTrue(second[0]["control_ok"])
        self.assertFalse(second[0]["desired_demoted"])

    def test_removed_vhid_scope_restores_previous_priority(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"abc": True})
        previous = {
            "vhids": [{
                "key": "opt2:51", "interface": "opt2", "device": "vlan02", "vhid": 51,
                "configured_advskew": 10, "current_advskew": 254, "carp_state": "BACKUP",
            }]
        }
        commands = FakeCommands()
        commands.runtime["vlan02"][51] = {"state": "BACKUP", "advskew": 254}
        states = carp_health.reconcile_vhid_scopes(config, tracker, previous, commands)
        self.assertEqual(commands.runtime["vlan02"][51]["advskew"], 10)
        self.assertEqual(states, [])

    def test_missing_vhid_is_reported_without_global_fallback(self):
        checks = """
<check uuid="a"><enabled>1</enabled><name>leaf-a</name><interface>opt2</interface>
<target>192.0.2.2</target><scope>vhid</scope><vhid>99</vhid></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"a": False})
        commands = FakeCommands()
        states = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        self.assertFalse(states[0]["control_ok"])
        self.assertEqual(states[0]["carp_state"], "MISSING")
        self.assertEqual(commands.mutations(), [])

    def test_checker_handles_stale_and_mismatched_state(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(1, 1)
        ready, healthy = tracker.update(config.checks, {"abc": True})
        state = carp_health.build_state(config, tracker, ready, healthy, now=100.0)
        self.assertEqual(carp_health.checker_exit_code(config, state, now=102.0), 0)
        self.assertEqual(carp_health.checker_exit_code(config, state, now=110.0), 1)
        state["config_signature"] = "old"
        self.assertEqual(carp_health.checker_exit_code(config, state, now=101.0), 1)
        self.assertEqual(carp_health.checker_exit_code(config, None, now=101.0), 1)

    def test_status_rejects_state_from_previous_config(self):
        config = self.make_config()
        stale = {
            "status": "ok", "enabled": True, "ready": True, "healthy": True,
            "running": True, "timestamp": 100.0, "config_signature": "old", "checks": [],
        }
        status = carp_health.status_state(config, stale, True, now=101.0)
        self.assertFalse(status["ready"])
        self.assertFalse(status["healthy"])
        self.assertEqual(status["config_signature"], config.signature)

    def test_status_accepts_current_fresh_state(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(1, 1)
        ready, healthy = tracker.update(config.checks, {"abc": True})
        current = carp_health.build_state(config, tracker, ready, healthy, now=100.0)
        status = carp_health.status_state(config, current, True, now=101.0)
        self.assertTrue(status["ready"])
        self.assertTrue(status["healthy"])
        self.assertTrue(status["running"])
        self.assertEqual(len(status["checks"]), 1)

    def test_load_config_vhid_group_and_fallback_routes(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>wan</interface>
<target>192.0.2.1</target><scope>vhid_group</scope><vhid_targets>opt2:51,opt3:52</vhid_targets>
<failure_advskew>200</failure_advskew><fallback_ipv4_target>192.0.2.2</fallback_ipv4_target>
<fallback_ipv4_gateway>10.16.224.5</fallback_ipv4_gateway>
<fallback_ipv6_target>2001:db8:1::2</fallback_ipv6_target><fallback_ipv6_gateway>2001:db8:2::1</fallback_ipv6_gateway></check>"""
        config = self.make_config(checks)
        check = config.checks[0]
        self.assertEqual(check.scope, "vhid_group")
        self.assertEqual(check.vhid_targets, (("opt2", 51), ("opt3", 52)))
        self.assertEqual(check.failure_advskew, 200)
        self.assertEqual(check.fallback_ipv4_gateway, "10.16.224.5")
        self.assertEqual(check.fallback_ipv6_target, "2001:db8:1::2")

    def test_auto_wan_demotion_yields_to_auto_hard_local_failure(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>wan</interface><target>192.0.2.1</target>
<scope>all_carp</scope><failure_advskew>200</failure_advskew></check>
<check uuid="leaf"><enabled>1</enabled><name>leaf-health</name><interface>opt2</interface><target>192.0.2.2</target>
<scope>interface</scope><failure_advskew>254</failure_advskew></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"wan": False, "leaf": True})
        soft = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        by_key = {row["key"]: row for row in soft}
        self.assertEqual(by_key["opt2:51"]["desired_advskew"], 200)
        self.assertEqual(by_key["opt3:52"]["desired_advskew"], 200)
        tracker.update(config.checks, {"wan": False, "leaf": False})
        hard = carp_health.reconcile_vhid_scopes(config, tracker, {"vhids": soft}, commands)
        by_key = {row["key"]: row for row in hard}
        self.assertEqual(by_key["opt2:51"]["desired_advskew"], 254)
        self.assertEqual(by_key["opt2:51"]["carp_state"], "MASTER")
        self.assertEqual(by_key["opt3:52"]["desired_advskew"], 200)

    def test_soft_cross_interface_demotion_yields_to_hard_local_failure(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>wan</interface><target>192.0.2.1</target>
<scope>vhid_group</scope><vhid_targets>opt2:51</vhid_targets><failure_advskew>200</failure_advskew></check>
<check uuid="leaf"><enabled>1</enabled><name>leaf-health</name><interface>opt2</interface><target>192.0.2.2</target>
<scope>vhid</scope><vhid>51</vhid><failure_advskew>254</failure_advskew></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"wan": False, "leaf": True})
        soft = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        self.assertEqual(commands.runtime["vlan02"][51]["advskew"], 200)
        self.assertEqual(commands.runtime["vlan02"][51]["state"], "MASTER")
        self.assertEqual(soft[0]["desired_advskew"], 200)
        tracker.update(config.checks, {"wan": False, "leaf": False})
        hard = carp_health.reconcile_vhid_scopes(config, tracker, {"vhids": soft}, commands)
        self.assertEqual(commands.runtime["vlan02"][51]["advskew"], 254)
        self.assertEqual(commands.runtime["vlan02"][51]["state"], "MASTER")
        self.assertEqual(hard[0]["desired_advskew"], 254)

    def test_fallback_routes_install_and_remove_ipv4_ipv6(self):
        checks = """
<check uuid="leaf"><enabled>1</enabled><name>leaf-health</name><interface>opt2</interface><target>192.0.2.2</target>
<scope>vhid</scope><vhid>51</vhid><fallback_ipv4_target>192.0.2.2</fallback_ipv4_target>
<fallback_ipv4_gateway>10.16.224.5</fallback_ipv4_gateway><fallback_ipv6_target>2001:db8:1::2</fallback_ipv6_target>
<fallback_ipv6_gateway>2001:db8:2::1</fallback_ipv6_gateway></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"leaf": False})
        failed = carp_health.reconcile_fallback_routes(config, tracker, command_func=commands)
        self.assertEqual(commands.routes[("inet", "192.0.2.2")], "10.16.224.5")
        self.assertEqual(commands.routes[("inet6", "2001:db8:1::2")], "2001:db8:2::1")
        self.assertTrue(all(row["managed"] and row["installed"] and row["control_ok"] for row in failed))
        tracker.update(config.checks, {"leaf": True})
        recovered = carp_health.reconcile_fallback_routes(config, tracker, {"routes": failed}, commands)
        self.assertEqual(commands.routes, {})
        self.assertTrue(all(not row["installed"] and row["control_ok"] for row in recovered))

    def test_fallback_route_is_fail_closed_until_first_probe(self):
        checks = """
<check uuid="leaf"><enabled>1</enabled><name>leaf-health</name><interface>opt2</interface><target>192.0.2.2</target>
<scope>vhid</scope><vhid>51</vhid><fallback_ipv4_target>192.0.2.2</fallback_ipv4_target>
<fallback_ipv4_gateway>10.16.224.5</fallback_ipv4_gateway></check>"""
        config = self.make_config(checks)
        tracker = carp_health.HealthTracker(2, 2)
        commands = FakeCommands()
        routes = carp_health.reconcile_fallback_routes(config, tracker, command_func=commands)
        self.assertTrue(routes[0]["desired_installed"])
        self.assertEqual(commands.routes[("inet", "192.0.2.2")], "10.16.224.5")

    def test_reset_fallback_routes_only_removes_managed_routes(self):
        commands = FakeCommands()
        commands.routes[("inet", "192.0.2.2")] = "10.16.224.5"
        commands.routes[("inet", "198.51.100.2")] = "10.16.224.5"
        state = {"routes": [
            {"family": "inet", "destination": "192.0.2.2", "gateway": "10.16.224.5", "managed": True},
            {"family": "inet", "destination": "198.51.100.2", "gateway": "10.16.224.5", "managed": False},
        ]}
        self.assertTrue(carp_health.reset_fallback_routes(state, commands))
        self.assertNotIn(("inet", "192.0.2.2"), commands.routes)
        self.assertIn(("inet", "198.51.100.2"), commands.routes)

    def test_group_status_preserves_legacy_scalar_advskew_contract(self):
        group_checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>wan</interface><target>192.0.2.1</target>
<scope>vhid_group</scope><vhid_targets>opt2:51,opt3:52</vhid_targets><failure_advskew>200</failure_advskew></check>"""
        config = self.make_config(group_checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"wan": False})
        vhids = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        state = carp_health.build_state(config, tracker, True, False, vhids=vhids)
        check = state["checks"][0]
        self.assertIsNone(check["configured_advskew"])
        self.assertIsNone(check["current_advskew"])
        self.assertEqual(check["carp_state"], "GROUP")
        self.assertEqual(len(check["vhid_states"]), 2)

        single_checks = """
<check uuid="leaf"><enabled>1</enabled><name>leaf</name><interface>opt2</interface><target>192.0.2.2</target>
<scope>vhid</scope><vhid>51</vhid></check>"""
        config = self.make_config(single_checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"leaf": False})
        vhids = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        state = carp_health.build_state(config, tracker, True, False, vhids=vhids)
        check = state["checks"][0]
        self.assertIsInstance(check["configured_advskew"], int)
        self.assertIsInstance(check["current_advskew"], int)

    def test_preexisting_matching_route_is_never_claimed_or_removed(self):
        checks = """
<check uuid="leaf"><enabled>1</enabled><name>leaf-health</name><interface>opt2</interface><target>192.0.2.2</target>
<scope>vhid</scope><vhid>51</vhid><fallback_ipv4_target>192.0.2.2</fallback_ipv4_target>
<fallback_ipv4_gateway>10.16.224.5</fallback_ipv4_gateway></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        commands.routes[("inet", "192.0.2.2")] = "10.16.224.5"
        tracker.update(config.checks, {"leaf": False})
        failed = carp_health.reconcile_fallback_routes(config, tracker, command_func=commands)
        self.assertTrue(failed[0]["installed"])
        self.assertFalse(failed[0]["managed"])
        tracker.update(config.checks, {"leaf": True})
        recovered = carp_health.reconcile_fallback_routes(config, tracker, {"routes": failed}, commands)
        self.assertEqual(commands.routes[("inet", "192.0.2.2")], "10.16.224.5")
        self.assertFalse(recovered[0]["managed"])

    def test_backup_default_routes_follow_stable_carp_backup_even_when_probe_is_healthy(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-owner</name><interface>opt2</interface><target>192.0.2.1</target>
<scope>vhid</scope><vhid>51</vhid><failure_advskew>254</failure_advskew>
<backup_ipv4_default_gateway>10.16.224.6</backup_ipv4_default_gateway>
<backup_ipv6_default_gateway>2001:db8:2::2</backup_ipv6_default_gateway></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        tracker.update(config.checks, {"wan": True})
        commands = FakeCommands()
        commands.runtime["vlan02"][51]["state"] = "BACKUP"

        first_vhids = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        first_routes = carp_health.reconcile_fallback_routes(config, tracker, command_func=commands, vhids=first_vhids)
        self.assertTrue(all(not row["desired_installed"] for row in first_routes))

        previous = {"vhids": first_vhids, "routes": first_routes}
        second_vhids = carp_health.reconcile_vhid_scopes(config, tracker, previous, commands)
        second_routes = carp_health.reconcile_fallback_routes(config, tracker, previous, commands, second_vhids)
        self.assertEqual(commands.routes, {
            ("inet", "0.0.0.0/1"): "10.16.224.6",
            ("inet", "128.0.0.0/1"): "10.16.224.6",
            ("inet6", "::/1"): "2001:db8:2::2",
            ("inet6", "8000::/1"): "2001:db8:2::2",
        })
        self.assertTrue(all(row["trigger"] == "backup" for row in second_routes))

        commands.runtime["vlan02"][51]["state"] = "MASTER"
        master_vhids = carp_health.reconcile_vhid_scopes(config, tracker, {"vhids": second_vhids, "routes": second_routes}, commands)
        master_routes = carp_health.reconcile_fallback_routes(
            config, tracker, {"vhids": second_vhids, "routes": second_routes}, commands, master_vhids
        )
        self.assertEqual(commands.routes, {})
        self.assertTrue(all(not row["desired_installed"] and row["control_ok"] for row in master_routes))

    def test_default_fallback_waits_for_stable_backup_then_installs_covering_routes(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>opt2</interface><target>192.0.2.1</target>
<scope>vhid</scope><vhid>51</vhid><failure_advskew>254</failure_advskew>
<fallback_ipv4_default_gateway>10.16.224.6</fallback_ipv4_default_gateway>
<fallback_ipv6_default_gateway>2001:db8:2::2</fallback_ipv6_default_gateway></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"wan": False})

        first_vhids = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        first_routes = carp_health.reconcile_fallback_routes(config, tracker, command_func=commands, vhids=first_vhids)
        self.assertTrue(all(not row["desired_installed"] for row in first_routes))
        self.assertEqual(commands.routes, {})

        previous = {"vhids": first_vhids, "routes": first_routes}
        commands.runtime["vlan02"][51]["state"] = "BACKUP"
        second_vhids = carp_health.reconcile_vhid_scopes(config, tracker, previous, commands)
        second_routes = carp_health.reconcile_fallback_routes(config, tracker, previous, commands, second_vhids)
        self.assertEqual(commands.routes, {})
        self.assertTrue(all(not row["desired_installed"] for row in second_routes))

        stable = {"vhids": second_vhids, "routes": second_routes}
        third_vhids = carp_health.reconcile_vhid_scopes(config, tracker, stable, commands)
        third_routes = carp_health.reconcile_fallback_routes(config, tracker, stable, commands, third_vhids)
        expected = {
            ("inet", "0.0.0.0/1"): "10.16.224.6",
            ("inet", "128.0.0.0/1"): "10.16.224.6",
            ("inet6", "::/1"): "2001:db8:2::2",
            ("inet6", "8000::/1"): "2001:db8:2::2",
        }
        self.assertEqual(commands.routes, expected)
        self.assertTrue(all(row["route_type"] == "network" for row in third_routes))
        self.assertTrue(all(row["managed"] and row["installed"] and row["control_ok"] for row in third_routes))

        tracker.update(config.checks, {"wan": True})
        recovered_vhids = carp_health.reconcile_vhid_scopes(config, tracker, {"vhids": third_vhids, "routes": third_routes}, commands)
        recovered_routes = carp_health.reconcile_fallback_routes(
            config, tracker, {"vhids": third_vhids, "routes": third_routes}, commands, recovered_vhids
        )
        self.assertEqual(commands.routes, {})
        self.assertTrue(all(not row["installed"] and row["control_ok"] for row in recovered_routes))

    def test_default_fallback_does_not_install_while_carp_target_is_master(self):
        checks = """
<check uuid="wan"><enabled>1</enabled><name>wan-health</name><interface>opt2</interface><target>192.0.2.1</target>
<scope>vhid</scope><vhid>51</vhid><failure_advskew>200</failure_advskew>
<fallback_ipv4_default_gateway>10.16.224.6</fallback_ipv4_default_gateway></check>"""
        config = self.make_config(checks, failure=1, recovery=1)
        tracker = carp_health.HealthTracker(1, 1)
        commands = FakeCommands()
        tracker.update(config.checks, {"wan": False})
        first_vhids = carp_health.reconcile_vhid_scopes(config, tracker, command_func=commands)
        previous = {"vhids": first_vhids}
        second_vhids = carp_health.reconcile_vhid_scopes(config, tracker, previous, commands)
        routes = carp_health.reconcile_fallback_routes(config, tracker, previous, commands, second_vhids)
        self.assertEqual(second_vhids[0]["carp_state"], "MASTER")
        self.assertTrue(all(not row["desired_installed"] for row in routes))
        self.assertEqual(commands.routes, {})

    def test_state_round_trip(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(1, 1)
        ready, healthy = tracker.update(config.checks, {"abc": True})
        state = carp_health.build_state(config, tracker, ready, healthy, now=123.0)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.json")
            carp_health.write_state(state, path)
            loaded = carp_health.read_state(path)
        self.assertEqual(json.dumps(loaded, sort_keys=True), json.dumps(state, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
