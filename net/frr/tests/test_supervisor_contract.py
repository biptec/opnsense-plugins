from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FRR = ROOT / "net/frr/src/opnsense/scripts/frr"


class SupervisorContractTest(unittest.TestCase):
    def test_wrapper_preserves_existing_carp_handler_and_starts_monitor(self):
        wrapper = (FRR / "frr_wrapper.sh").read_text()
        self.assertIn("carp_event_handler", wrapper)
        self.assertIn("carp_connected_control.sh start", wrapper)
        self.assertIn('"$2" = "ospfd"', wrapper)
        self.assertIn('"$2" = "ospf6d"', wrapper)
        self.assertIn('"$2" = "all"', wrapper)

    def test_stop_cleans_owned_routes_before_returning(self):
        control = (FRR / "carp_connected_control.sh").read_text()
        self.assertIn('"${SCRIPT}" --cleanup', control)
        self.assertIn("restart) stop_monitor && start_monitor", control)


if __name__ == "__main__":
    unittest.main()
