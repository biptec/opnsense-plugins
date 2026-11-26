from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FRR = ROOT / "net/frr/src"
SCRIPTS = FRR / "opnsense/scripts/frr"


class SupervisorContractTest(unittest.TestCase):
    def test_no_continuous_connected_route_monitor_remains(self):
        wrapper = (SCRIPTS / "frr_wrapper.sh").read_text()
        start = (FRR / "etc/rc.syshook.d/start/50-frr").read_text()

        self.assertIn("carp_event_handler", wrapper)
        self.assertIn("carp_event_handler", start)
        self.assertNotIn("carp_connected_control", wrapper)
        self.assertNotIn("carp_connected_control", start)
        self.assertFalse((SCRIPTS / "carp_connected_control.sh").exists())
        self.assertFalse((SCRIPTS / "carp_connected_monitor.py").exists())
        self.assertFalse((SCRIPTS / "lib/events/connected.py").exists())
        self.assertFalse((FRR / "etc/rc.syshook.d/stop/50-frr").exists())

    def test_carp_syshook_keeps_static_route_ordering(self):
        hook = (FRR / "etc/rc.syshook.d/carp/50-frr").read_text()
        handler_pos = hook.index("carp_event_handler")
        static_pos = hook.index("frr_carp_staticroutes_reconcile")
        self.assertLess(handler_pos, static_pos)

    def test_static_route_reconcile_uses_event_driven_barrier(self):
        plugin = (FRR / "etc/inc/plugins.inc.d/frr.inc").read_text()
        barrier = (SCRIPTS / "carp_route_barrier.py").read_text()

        self.assertIn("frr_carp_route_barrier", plugin)
        self.assertIn("carp_route_barrier.py", plugin)
        self.assertIn("--timeout 30", plugin)
        self.assertIn("PF_ROUTE", barrier)
        self.assertIn("subscribe", barrier.lower())
        self.assertNotIn("time.sleep", barrier)
        self.assertNotIn("ifconfig", barrier)
        self.assertNotIn("netstat", barrier)
        self.assertNotIn("vtysh", barrier)


if __name__ == "__main__":
    unittest.main()
