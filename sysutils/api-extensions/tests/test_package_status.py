from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
CONTROLLER = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/ApiExtensions/Api/PackageController.php"
ACTIONS = ROOT / "src/opnsense/service/conf/actions.d/actions_api_extensions.conf"
SCRIPT = ROOT / "src/opnsense/scripts/OPNsense/ApiExtensions/package_status.sh"


class PackageStatusContractTest(unittest.TestCase):
    def test_plugin_version_requires_local_package_api(self):
        source = MAKEFILE.read_text()
        self.assertIn("PLUGIN_VERSION=\t0.14", source)

    def test_controller_uses_only_local_package_status_action(self):
        source = CONTROLLER.read_text()
        self.assertIn("SanitizeFilter", source)
        self.assertIn("api_extensions package_status %s", source)
        self.assertIn("'installed' => false", source)
        self.assertIn("'installed' => true", source)
        self.assertNotIn("firmware/info", source)

    def test_configd_action_is_local_only(self):
        actions = ACTIONS.read_text()
        script = SCRIPT.read_text()
        self.assertIn("[package_status]", actions)
        self.assertIn("package_status.sh", actions)
        self.assertIn("info -e", script)
        self.assertIn("query '%n|||%v|||%k|||%R|||%o'", script)
        self.assertIn("rquery -U '%n'", script)
        self.assertIn("'provided' =>", CONTROLLER.read_text())
        self.assertNotIn("pkg update", script)
        self.assertNotIn("opnsense-update", script)
        self.assertNotEqual(SCRIPT.stat().st_mode & 0o111, 0, "package status helper must be executable")


if __name__ == "__main__":
    unittest.main()
