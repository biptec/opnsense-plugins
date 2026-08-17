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
            "check.scope", "check.vhid", "check.vhid_targets", "check.failure_advskew",
            "check.fallback_ipv4_target", "check.fallback_ipv4_gateway",
            "check.fallback_ipv6_target", "check.fallback_ipv6_gateway",
            "check.fallback_ipv4_default_gateway", "check.fallback_ipv6_default_gateway",
        })

    def test_model_defaults_new_checks_to_auto_interface_with_explicit_overrides(self):
        model = ET.parse(MVC / "models/OPNsense/ApiExtensions/CarpHealth.xml").getroot()
        scope = model.find("./items/checks/check/scope")
        self.assertEqual(scope.findtext("Default"), "interface")
        options = {node.tag for node in scope.findall("./OptionValues/*")}
        self.assertEqual(options, {"interface", "all_carp", "vhid", "vhid_group", "global"})
        self.assertEqual(model.findtext("./version"), "1.3.0")

        migration = MVC / "models/OPNsense/ApiExtensions/Migrations/M1_2_0.php"
        self.assertTrue(migration.exists())
        migration_text = migration.read_text()
        self.assertIn("$check->scope = 'global'", migration_text)
        self.assertIn("Before model 1.1.0", migration_text)

    def test_view_uses_first_class_carp_health_api(self):
        view = (MVC / "views/OPNsense/ApiExtensions/carp_health.volt").read_text()
        for endpoint in ("/get", "/set", "/searchCheck", "/getCheck/", "/setCheck/", "/addCheck", "/delCheck/", "/reconfigure", "/status"):
            self.assertIn(endpoint, view)
        for field in (
            "status-enabled", "status-running", "status-ready", "status-healthy",
            "status-control", "runtime-checks", "runtime-routes", "CARP Scope", "CARP State",
            "Resolved VHID Targets", "Failure advskew", "Desired advskew",
            "Configured advskew", "Current advskew", "Conditional Fallback Routes",
        ):
            self.assertIn(field, view)
        self.assertIn("Apply Changes", view)

    def test_health_check_form_exposes_routing_actions(self):
        form = (MVC / "controllers/OPNsense/ApiExtensions/forms/carpHealthCheck.xml").read_text()
        for field in (
            "check.vhid_targets", "check.failure_advskew",
            "check.fallback_ipv4_target", "check.fallback_ipv4_gateway",
            "check.fallback_ipv6_target", "check.fallback_ipv6_gateway",
            "check.fallback_ipv4_default_gateway", "check.fallback_ipv6_default_gateway",
        ):
            self.assertIn(field, form)
        self.assertIn("Automatic modes discover CARP VHIDs", form)
        self.assertIn("advanced override", form)
        view = (MVC / "views/OPNsense/ApiExtensions/carp_health.volt").read_text()
        self.assertIn("conditional fallback", view.lower())

    def test_gui_controller_loads_both_forms(self):
        controller = (MVC / "controllers/OPNsense/ApiExtensions/CarpHealthController.php").read_text()
        self.assertIn("getForm('carpHealthSettings')", controller)
        self.assertIn("getForm('carpHealthCheck')", controller)
        self.assertIn("OPNsense/ApiExtensions/carp_health", controller)


if __name__ == "__main__":
    unittest.main()
