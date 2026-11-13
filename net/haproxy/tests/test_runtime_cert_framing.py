import importlib.util
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "src/opnsense/scripts/OPNsense/HAProxy"
MODULE = SCRIPTS / "runtimeCommands.py"


class _StubUpdateSslCrt:
    def __init__(self, **kwargs):
        self.args = kwargs


class RuntimeCertFramingContractTests(unittest.TestCase):
    def _load_module(self):
        haproxy = types.ModuleType("haproxy")
        cmds = types.ModuleType("haproxy.cmds")
        cmds.updateSslCrt = _StubUpdateSslCrt
        haproxy.cmds = cmds

        old_haproxy = sys.modules.get("haproxy")
        old_cmds = sys.modules.get("haproxy.cmds")
        sys.modules["haproxy"] = haproxy
        sys.modules["haproxy.cmds"] = cmds
        try:
            spec = importlib.util.spec_from_file_location("runtimeCommands", MODULE)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            if old_haproxy is None:
                sys.modules.pop("haproxy", None)
            else:
                sys.modules["haproxy"] = old_haproxy
            if old_cmds is None:
                sys.modules.pop("haproxy.cmds", None)
            else:
                sys.modules["haproxy.cmds"] = old_cmds

    def test_update_ssl_cert_uses_terminating_empty_line(self):
        module = self._load_module()
        command = module.UpdateSslCrt(
            certfile="/tmp/example.pem",
            payload="CERT\nKEY\n",
        ).getCmd()

        self.assertEqual(
            command,
            "set ssl cert /tmp/example.pem <<\nCERT\nKEY\n\n",
        )
        self.assertTrue(command.endswith("\n\n"))
        self.assertNotIn("\r\n", command)

    def test_both_certificate_update_paths_use_wrapper(self):
        sync_source = (SCRIPTS / "syncCerts.py").read_text()
        socket_source = (SCRIPTS / "socketCommand.py").read_text()

        self.assertIn("from runtimeCommands import UpdateSslCrt", sync_source)
        self.assertIn("from runtimeCommands import UpdateSslCrt", socket_source)
        self.assertIn(
            "self._execute_remote_cmd(UpdateSslCrt, certfile=cert['certfile'], payload=cert['pem'])",
            sync_source,
        )
        self.assertIn('"update-ssl-cert": UpdateSslCrt', socket_source)


if __name__ == "__main__":
    unittest.main()
