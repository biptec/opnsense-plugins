import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DisabledReconfigureContractTests(unittest.TestCase):
    def test_disabled_reconfigure_deploys_without_starting_service(self):
        controller = (ROOT / "src/opnsense/mvc/app/controllers/OPNsense/HAProxy/Api/ServiceController.php").read_text()
        actions = (ROOT / "src/opnsense/service/conf/actions.d/actions_haproxy.conf").read_text()

        self.assertIn("$result = parent::reconfigureAction();", controller)
        self.assertIn("!$this->serviceEnabled()", controller)
        self.assertIn("configdRun('haproxy deploy')", controller)
        self.assertIn("[deploy]", actions)
        deploy = actions.split("[deploy]", 1)[1].split("[restart]", 1)[0]
        self.assertIn("setup.sh deploy", deploy)
        self.assertNotIn("rc-wrapper.sh start", deploy)
        self.assertNotIn("rc-wrapper.sh restart", deploy)
        self.assertNotIn("rc-wrapper.sh reload", deploy)


if __name__ == "__main__":
    unittest.main()
