from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/ApiExtensions/Api/DnsController.php"
ACTIONS = ROOT / "src/opnsense/service/conf/actions.d/actions_api_extensions.conf"
SCRIPT = ROOT / "src/opnsense/scripts/OPNsense/ApiExtensions/reconfigure_resolver.php"


class SystemDnsContractTest(unittest.TestCase):
    def test_controller_owns_only_system_resolver_fields(self):
        source = CONTROLLER.read_text()
        self.assertIn("'servers'", source)
        self.assertIn("'allow_override'", source)
        self.assertIn("'use_local_service'", source)
        self.assertIn("unset($system->dnsserver)", source)
        self.assertIn("$system->addChild('dnsserver', $server)", source)
        self.assertIn("dnsallowoverride", source)
        self.assertIn("dnslocalhost", source)
        self.assertIn("sprintf('dns%dgw', $index)", source)
        self.assertIn("'none'", source)

    def test_reconfigure_regenerates_resolver(self):
        controller = CONTROLLER.read_text()
        actions = ACTIONS.read_text()
        script = SCRIPT.read_text()
        self.assertIn("api_extensions reconfigure_resolver'", controller)
        self.assertIn("[reconfigure_resolver]", actions)
        self.assertIn("reconfigure_resolver.php", actions)
        self.assertIn("require_once 'util.inc';", script)
        self.assertIn("system_resolver_configure(true)", script)
        self.assertNotEqual(SCRIPT.stat().st_mode & 0o111, 0, "configd helper must be executable")


if __name__ == "__main__":
    unittest.main()
