import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/ApiExtensions/carp_health.py"
spec = importlib.util.spec_from_file_location("carp_health", MODULE)
carp_health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(carp_health)


class CarpHealthTests(unittest.TestCase):
    def make_config(self):
        data = """<opnsense>
<interfaces><opt2><if>vlan02</if></opt2></interfaces>
<OPNsense><ApiExtensions><CarpHealth>
<enabled>1</enabled><interval>1</interval>
<failure_threshold>2</failure_threshold><recovery_threshold>2</recovery_threshold>
<checks><check uuid="abc"><enabled>1</enabled><name>leaf</name>
<interface>opt2</interface><target>192.0.2.2</target></check></checks>
</CarpHealth></ApiExtensions></OPNsense>
</opnsense>"""
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        handle.write(data)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return carp_health.load_config(handle.name)

    def test_load_config_resolves_friendly_interface(self):
        config = self.make_config()
        self.assertTrue(config.enabled)
        self.assertEqual(config.interval, 1)
        self.assertEqual(len(config.checks), 1)
        self.assertEqual(config.checks[0].device, "vlan02")
        self.assertEqual(config.checks[0].target, "192.0.2.2")

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

    def test_initial_failures_wait_for_threshold(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(2, 2)
        ready, healthy = tracker.update(config.checks, {"abc": False})
        self.assertEqual((ready, healthy), (False, False))
        ready, healthy = tracker.update(config.checks, {"abc": False})
        self.assertEqual((ready, healthy), (True, False))

    def test_checker_handles_stale_and_mismatched_state(self):
        config = self.make_config()
        healthy = {
            "config_signature": config.signature,
            "timestamp": 100.0,
            "ready": True,
            "healthy": True,
        }
        self.assertEqual(carp_health.checker_exit_code(config, healthy, now=102.0), 0)
        self.assertEqual(carp_health.checker_exit_code(config, healthy, now=110.0), 1)
        healthy["config_signature"] = "old"
        self.assertEqual(carp_health.checker_exit_code(config, healthy, now=110.0), 1)
        self.assertEqual(carp_health.checker_exit_code(config, None, now=110.0), 1)


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
        current = {
            "status": "ok", "enabled": True, "ready": True, "healthy": True,
            "timestamp": 100.0, "config_signature": config.signature, "checks": [{"uuid": "abc"}],
        }
        status = carp_health.status_state(config, current, True, now=101.0)
        self.assertTrue(status["ready"])
        self.assertTrue(status["healthy"])
        self.assertTrue(status["running"])
        self.assertEqual(len(status["checks"]), 1)

    def test_state_round_trip(self):
        config = self.make_config()
        tracker = carp_health.HealthTracker(2, 2)
        ready, healthy = tracker.update(config.checks, {"abc": True})
        state = carp_health.build_state(config, tracker, ready, healthy, now=123.0)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.json")
            carp_health.write_state(state, path)
            loaded = carp_health.read_state(path)
        self.assertEqual(json.dumps(loaded, sort_keys=True), json.dumps(state, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
