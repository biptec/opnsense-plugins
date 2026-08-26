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
            "check.backup_ipv4_default_gateway", "check.backup_ipv6_default_gateway",
        })

    def test_model_defaults_new_checks_to_auto_interface_with_explicit_overrides(self):
        model = ET.parse(MVC / "models/OPNsense/ApiExtensions/CarpHealth.xml").getroot()
        scope = model.find("./items/checks/check/scope")
        self.assertEqual(scope.findtext("Default"), "interface")
        options = {node.tag for node in scope.findall("./OptionValues/*")}
        self.assertEqual(options, {"interface", "all_carp", "vhid", "vhid_group", "global"})
        self.assertEqual(model.findtext("./version"), "1.4.0")

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
            "check.backup_ipv4_default_gateway", "check.backup_ipv6_default_gateway",
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

    def test_haproxy_sync_transport_preserves_failure_details(self):
        script = (ROOT / "src/opnsense/scripts/OPNsense/ApiExtensions/config_sync_push.php").read_text()
        self.assertIn("$peerMessage", script)
        self.assertIn("$haproxy['message']", script)
        self.assertIn("'status' => 'failed'", script)
        self.assertNotIn("exit(1);", script)

    def test_ha_sync_policy_model_is_generic_but_backward_compatible(self):
        generic_php = (MVC / "models/OPNsense/ApiExtensions/HASyncPolicy.php").read_text()
        generic_xml = ET.parse(MVC / "models/OPNsense/ApiExtensions/HASyncPolicy.xml").getroot()
        legacy_php = (MVC / "models/OPNsense/ApiExtensions/InterfaceSyncPolicy.php").read_text()
        self.assertIn("class HASyncPolicy extends BaseModel", generic_php)
        self.assertEqual(generic_xml.findtext("./mount"), "//OPNsense/ApiExtensions/InterfaceSyncPolicy")
        self.assertIn("class InterfaceSyncPolicy extends HASyncPolicy", legacy_php)
        for controller_name in ("InterfacePolicyController.php", "HaproxyPolicyController.php"):
            controller = (MVC / "controllers/OPNsense/ApiExtensions/Api" / controller_name).read_text()
            self.assertIn("HASyncPolicy", controller)
            self.assertNotIn("internalModelClass = '\\\\OPNsense\\\\ApiExtensions\\\\InterfaceSyncPolicy'", controller)

    def test_interface_policy_page_supports_direct_and_bulk_assignment(self):
        menu = ET.parse(MVC / "models/OPNsense/ApiExtensions/Menu/Menu.xml").getroot()
        item = menu.find("./System/HighAvailability/InterfacePolicies")
        self.assertIsNotNone(item)
        self.assertEqual(item.attrib.get("url"), "/ui/api_extensions/interface_policy")
        acl = ET.parse(MVC / "models/OPNsense/ApiExtensions/ACL/ACL.xml").getroot()
        patterns = [node.text for node in acl.findall(".//page-system-api-extensions-interface-policy/patterns/pattern")]
        self.assertIn("api/api_extensions/haproxy_policy/*", patterns)

        view = (MVC / "views/OPNsense/ApiExtensions/interface_policy.volt").read_text()
        for marker in (
            "grid-interface-policy-overview",
            "UIBootgrid",
            "interface-policy-row-policy",
            "interface-policy-bulk-policy",
            "btn-interface-policy-bulk-apply",
            "btn-interface-policy-save-changes",
            "/searchOverview",
            "/batchAssign",
            "selectpicker",
            "disableScroll: true",
            "interface-policy-filter-container",
            "interface-policy-filter",
            "All policies",
            "requestHandler",
            "interface-policy-bulk-footer",
            "interface-policy-selected-count",
            "Discard unsaved changes?",
        ):
            self.assertIn(marker, view)
        self.assertIn("insertBefore('#grid-interface-policy-overview-header .search')", view)
        self.assertNotIn("interface-policy-bulk-footer').detach()", view)
        self.assertNotIn("All locally configured interfaces have an explicit synchronization policy.", view)
        self.assertNotIn("interface-policy-assignments-tab", view)
        self.assertNotIn("interface-policy-save')", view)
        self.assertIn("interface-policy-haproxy-tab", view)
        self.assertIn("haproxy-policy-ha-status", view)
        self.assertIn("partial('OPNsense/ApiExtensions/haproxy_policy')", view)
        self.assertEqual(item.attrib.get("VisibleName"), "HA Sync Policies")
        self.assertIn("{{ lang._('Policies') }}", view)
        self.assertIn("{{ lang._('Interfaces') }}", view)
        self.assertNotIn("Interface Overview", view)
        self.assertNotIn("btn-interface-policy-refresh", view)
        self.assertIn("grid-interface-policy-overview-refresh-button", view)
        self.assertIn("bindInterfaceNativeRefresh", view)

        haproxy_view = (MVC / "views/OPNsense/ApiExtensions/haproxy_policy.volt").read_text()
        for marker in (
            "grid-haproxy-policy-overview",
            "haproxy-policy-row-policy",
            "haproxy-policy-filter-container",
            "haproxy-policy-type-filter",
            "haproxy-policy-bulk-policy",
            "btn-haproxy-policy-bulk-apply",
            "btn-haproxy-policy-save-changes",
            "haproxy-policy-delete-stale",
            "Stale assignment",
            "assignment_uuid",
            "/delAssignment/",
            "/api/api_extensions/haproxy_policy",
            "/searchOverview",
            "/batchAssign",
            "disableScroll: true",
            "Backend server references are rebuilt on the peer by semantic server name",
        ):
            self.assertIn(marker, haproxy_view)
        self.assertIn("insertBefore('#grid-haproxy-policy-overview-header .search')", haproxy_view)
        self.assertNotIn("PLACEHOLDER", haproxy_view)
        self.assertNotIn("btn-haproxy-policy-refresh", haproxy_view)
        self.assertIn("grid-haproxy-policy-overview-refresh-button", haproxy_view)
        self.assertIn("bindHaproxyNativeRefresh", haproxy_view)

        haproxy_controller = (MVC / "controllers/OPNsense/ApiExtensions/Api/HaproxyPolicyController.php").read_text()
        for marker in (
            "function searchOverviewAction",
            "function overviewAction",
            "function assignAction",
            "function batchAssignAction",
            "HA peer replica %s is read-only",
            "Missing HAProxy object",
            "Policy assignment is stale",
            "stale_assignments",
        ):
            self.assertIn(marker, haproxy_controller)

        controller = (MVC / "controllers/OPNsense/ApiExtensions/Api/InterfacePolicyController.php").read_text()
        self.assertIn("function searchOverviewAction", controller)
        self.assertIn("function assignAction", controller)
        self.assertIn("function batchAssignAction", controller)
        self.assertIn("private function resolvePolicyUuid", controller)
        self.assertIn("HA peer replica %s is read-only", controller)
        self.assertNotIn("Reassign it instead of deleting the assignment", controller)
        self.assertIn("Terraform must remove the policy relation before deleting the core interface resource", controller)
        self.assertIn("fail closed", controller)

        page_controller = (MVC / "controllers/OPNsense/ApiExtensions/InterfacePolicyController.php").read_text()
        self.assertIn("getForm('interfaceSyncPolicy')", page_controller)
        self.assertNotIn("interfaceSyncAssignment", page_controller)


if __name__ == "__main__":
    unittest.main()
