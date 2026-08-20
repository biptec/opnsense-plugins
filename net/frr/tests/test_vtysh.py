import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "net/frr/src/opnsense/scripts/frr"
sys.path.insert(0, str(SCRIPTS))
sys.modules.setdefault("ujson", json)

from lib import VtySH, VtySHExecError


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class VtySHTest(unittest.TestCase):
    @patch("lib.subprocess.run")
    def test_successful_command_ignores_nonfatal_stderr(self, run):
        run.return_value = Result(0, b"mgmtd zebra ospfd ospf6d watchfrr\n", b"SO_RCVBUF warning\n")
        vty = VtySH()
        self.assertTrue(vty.is_running("ospfd"))
        self.assertTrue(vty.is_running("ospf6d"))

    @patch("lib.time.sleep", return_value=None)
    @patch("lib.subprocess.run")
    def test_failed_command_remains_an_error(self, run, _sleep):
        run.return_value = Result(1, b"", b"fatal\n")
        vty = VtySH()
        self.assertFalse(vty.is_active)
        with self.assertRaises(VtySHExecError):
            vty.execute("show daemons", translate=lambda value: value)


if __name__ == "__main__":
    unittest.main()
