import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/ApiExtensions"
sys.path.insert(0, str(SCRIPTS))

MODULE = SCRIPTS / "carp_health_monitor.py"
spec = importlib.util.spec_from_file_location("carp_health_monitor", MODULE)
carp_health_monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(carp_health_monitor)


class CarpHealthMonitorTests(unittest.TestCase):
    def test_service_status_retries_until_trigger_succeeds(self):
        report = (False, True, True)
        with mock.patch.object(
            carp_health_monitor,
            "trigger_carp_service_status",
            side_effect=[False, True],
        ) as trigger:
            last = None
            last = carp_health_monitor.reconcile_service_status(report, last)
            self.assertIsNone(last)

            last = carp_health_monitor.reconcile_service_status(report, last)
            self.assertEqual(last, report)

            last = carp_health_monitor.reconcile_service_status(report, last)
            self.assertEqual(last, report)
            self.assertEqual(trigger.call_count, 2)


if __name__ == "__main__":
    unittest.main()
