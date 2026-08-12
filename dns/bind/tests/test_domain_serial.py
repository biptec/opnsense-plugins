import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERIAL_HELPER = ROOT / "src/opnsense/mvc/app/models/OPNsense/Bind/ZoneSerial.php"


class ZoneSerialTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.php = shutil.which("php")
        if cls.php is None:
            raise unittest.SkipTest("php is not installed")

    def next_serial(self, current, clock):
        code = (
            f"require {str(SERIAL_HELPER)!r}; "
            "echo OPNsense\\Bind\\ZoneSerial::next($argv[1], $argv[2]);"
        )
        result = subprocess.run(
            [self.php, "-r", code, str(current), str(clock)],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_same_minute_increments_existing_serial(self):
        self.assertEqual("2608121918", self.next_serial("2608121917", "2608121917"))

    def test_newer_clock_serial_is_used(self):
        self.assertEqual("2608121920", self.next_serial("2608121917", "2608121920"))

    def test_clock_rollback_cannot_decrease_serial(self):
        self.assertEqual("2608121921", self.next_serial("2608121920", "2608121919"))

    def test_empty_serial_starts_from_clock(self):
        self.assertEqual("2608121920", self.next_serial("", "2608121920"))

    def test_model_node_string_value_is_supported(self):
        code = (
            f"require {str(SERIAL_HELPER)!r}; "
            '$node = new class { public function __toString() { return "2608121917"; } }; '
            'echo OPNsense\\Bind\\ZoneSerial::next($node, "2608121917");'
        )
        result = subprocess.run(
            [self.php, "-r", code],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual("2608121918", result.stdout.strip())


if __name__ == "__main__":
    unittest.main()
