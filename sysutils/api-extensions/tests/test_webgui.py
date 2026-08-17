import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MVC = ROOT / "src/opnsense/mvc/app"


class CarpHealthWebGuiTests(unittest.TestCase):
    def test_menu_and_acl_expose_carp_health_page(self):
        menu = ET.parse(MVC / "models/OPNsense/ApiExtensions/Menu/Menu.xml").getroot()
        item = menu.find("./Services/CarpHealth")
        self.assertIsNotNone(item)
        self.assertEqual(item.attrib.get("url"), "/ui/api_extensions/carp_health")

        acl = ET.parse(MVC / "models/OPNsense/ApiExtensions/ACL/ACL.xml").getroot()
        patterns = [node.text for node in acl.findall(".//page-services-api-extensions-carp-health/patterns/pattern")]
        self.assertIn("ui/api_extensions/carp_health*", patterns)
        self.assertIn("api/api_extensions/carp_health/*", patterns)

    def test_settings_and_check_forms_cover_model_fields(self):
        settings = ET.parse(MVC / "controllers/OPNsense/ApiExtensions/forms/carpHealthSettings.xml").getroot()
        settings_ids = {node.text for node in settings.findall("./field/id")}
        self.assertEqual(settings_ids, {
            "carp_health.enabled", "carp_health.interval",
            "carp_health.failure_threshold", "carp_health.recovery_threshold",
        })

        check = ET.parse(MVC / "controllers/OPNsense/ApiExtensions/forms/carpHealthCheck.xml").getroot()
        check_ids = {node.text for node in check.findall("./field/id")}
        self.assertEqual(check_ids, {
            "check.enabled", "check.name", "check.interface", "check.target",
            "check.scope", "check.vhid",
        })

    def test_view_uses_first_class_carp_health_api(self):
        view = (MVC / "views/OPNsense/ApiExtensions/carp_health.volt").read_text()
        for endpoint in ("/get", "/set", "/searchCheck", "/getCheck/", "/setCheck/", "/addCheck", "/delCheck/", "/reconfigure", "/status"):
            self.assertIn(endpoint, view)
        for field in (
            "status-enabled", "status-running", "status-ready", "status-healthy",
            "status-control", "runtime-checks", "CARP Scope", "CARP State",
            "Configured advskew", "Current advskew",
        ):
            self.assertIn(field, view)
        self.assertIn("Apply Changes", view)

    def test_gui_controller_loads_both_forms(self):
        controller = (MVC / "controllers/OPNsense/ApiExtensions/CarpHealthController.php").read_text()
        self.assertIn("getForm('carpHealthSettings')", controller)
        self.assertIn("getForm('carpHealthCheck')", controller)
        self.assertIn("OPNsense/ApiExtensions/carp_health", controller)


if __name__ == "__main__":
    unittest.main()
