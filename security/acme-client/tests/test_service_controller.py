import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ServiceControllerContractTests(unittest.TestCase):
    def test_configtest_uses_declared_configd_action(self):
        controller = (ROOT / "src/opnsense/mvc/app/controllers/OPNsense/AcmeClient/Api/ServiceController.php").read_text()
        actions = (ROOT / "src/opnsense/service/conf/actions.d/actions_acmeclient.conf").read_text()
        self.assertIn('configdRun("acmeclient http-configtest")', controller)
        self.assertIn("[http-configtest]", actions)
        self.assertNotIn('configdRun("acmeclient configtest")', controller)


if __name__ == "__main__":
    unittest.main()
