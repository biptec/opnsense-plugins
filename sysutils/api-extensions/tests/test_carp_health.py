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
        self.calls = []

    def __call__(self, args, capture=False):
        self.calls.append(list(args))
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
        return [call for call in self.calls if len(call) > 2]


class CarpHealthTests(unittest.TestCase):
    def make_config(self, checks=None, failure=2, recovery=2):
        if checks is None:
            checks = """
<check uuid="abc"><enabled>1</enabled><name>leaf</name>
<interface>opt2</interface><target>192.0.2.2</target></check>"""
        data = f"""<opnsense>
<interfaces><opt2><if>vlan02</if></opt2><opt3><if>vlan03</if></opt3></interfaces>
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
            carp_health.IFCONFIG, "vlan02", "vhid", "51", "advskew", "254", "state", "BACKUP"
        ])
        by_key = {item["key"]: item for item in states}
        self.assertEqual(by_key["opt2:51"]["carp_state"], "BACKUP")
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
