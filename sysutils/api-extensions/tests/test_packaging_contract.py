import stat
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECONCILER = (
    ROOT
    / "src/opnsense/scripts/OPNsense/ApiExtensions/haproxy_tls_identity_reconcile.php"
)
ACTIONS = (
    ROOT
    / "src/opnsense/service/conf/actions.d/actions_api_extensions.conf"
)


class PackagingContractTests(unittest.TestCase):
    def test_haproxy_tls_identity_reconciler_is_directly_executable(self):
        mode = RECONCILER.stat().st_mode
        self.assertTrue(
            mode & stat.S_IXUSR,
            "HAProxy TLS identity reconciler must be executable by root/configd",
        )
        self.assertEqual(
            RECONCILER.read_text().splitlines()[0],
            "#!/usr/local/bin/php",
        )

    def test_configd_executes_reconciler_directly(self):
        expected = (
            "command:/usr/local/opnsense/scripts/OPNsense/ApiExtensions/"
            "haproxy_tls_identity_reconcile.php reconcile"
        )
        self.assertIn(expected, ACTIONS.read_text())


if __name__ == "__main__":
    unittest.main()
