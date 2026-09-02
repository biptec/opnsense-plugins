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

    def test_custom_ha_items_extend_native_sync_instead_of_exposing_parallel_push_api(self):
        hook = (ROOT / "src/etc/inc/plugins.inc.d/api_extensions.inc").read_text()
        self.assertIn("gettext('Interfaces')", hook)
        self.assertIn("gettext('HAProxy Objects')", hook)
        self.assertIn("sync_validate", hook)
        self.assertIn("sync_prepare", hook)
        self.assertIn("sync_finalize", hook)
        self.assertIn("api_extensions_sync_interfaces", hook)
        self.assertIn("api_extensions_sync_haproxy", hook)
        self.assertFalse((ROOT / "src/opnsense/scripts/OPNsense/ApiExtensions/config_sync_push.php").exists())
        self.assertFalse((MVC / "controllers/OPNsense/ApiExtensions/Api/InterfaceSyncController.php").exists())

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

    def test_policy_page_only_owns_policy_definitions(self):
        menu = ET.parse(MVC / "models/OPNsense/ApiExtensions/Menu/Menu.xml").getroot()
        item = menu.find("./System/HighAvailability/InterfacePolicies")
        self.assertIsNotNone(item)
        self.assertEqual(item.attrib.get("url"), "/ui/api_extensions/interface_policy")
        self.assertEqual(item.attrib.get("VisibleName"), "Policies")

        view = (MVC / "views/OPNsense/ApiExtensions/interface_policy.volt").read_text()
        self.assertIn("grid-interface-sync-policies", view)
        self.assertIn("/searchPolicy", view)
        self.assertIn("/setPolicy/", view)
        self.assertIn("/addPolicy", view)
        self.assertIn("/delPolicy/", view)
        self.assertNotIn("grid-interface-policy-overview", view)
        self.assertNotIn("interface-policy-haproxy-tab", view)
        self.assertNotIn("partial('OPNsense/ApiExtensions/haproxy_policy')", view)
        self.assertNotIn("HA synchronization services", view)
        self.assertNotIn("batchAssign", view)

        page_controller = (MVC / "controllers/OPNsense/ApiExtensions/InterfacePolicyController.php").read_text()
        self.assertIn("getForm('interfaceSyncPolicy')", page_controller)
        self.assertNotIn("interfaceSyncAssignment", page_controller)

    def test_haproxy_policy_is_integrated_into_native_healthchecks_servers_and_backends(self):
        haproxy_root = ROOT.parents[1] / "net/haproxy/src/opnsense/mvc/app"
        view = (haproxy_root / "views/OPNsense/HAProxy/index.volt").read_text()
        healthcheck_form = ET.parse(haproxy_root / "controllers/OPNsense/HAProxy/forms/dialogHealthcheck.xml").getroot()
        server_form = ET.parse(haproxy_root / "controllers/OPNsense/HAProxy/forms/dialogServer.xml").getroot()
        backend_form = ET.parse(haproxy_root / "controllers/OPNsense/HAProxy/forms/dialogBackend.xml").getroot()
        controller = (haproxy_root / "controllers/OPNsense/HAProxy/Api/SettingsController.php").read_text()

        healthcheck_ids = {node.text for node in healthcheck_form.findall("./field/id")}
        server_ids = {node.text for node in server_form.findall("./field/id")}
        backend_ids = {node.text for node in backend_form.findall("./field/id")}
        self.assertIn("healthcheck.ha_policy", healthcheck_ids)
        self.assertIn("server.ha_policy", server_ids)
        self.assertIn("backend.ha_policy", backend_ids)
        self.assertGreaterEqual(view.count('data-column-id="ha_policy"'), 3)
        self.assertGreaterEqual(view.count("haproxy-ha-policy-status"), 4)
        self.assertIn("/api/api_extensions/haproxy_policy/overview", view)
        for object_type in ("healthcheck", "server", "backend"):
            self.assertIn(f"PolicyAssignmentManager::setHAProxy('{object_type}'", controller)
            self.assertIn(f"PolicyAssignmentManager::removeHAProxy('{object_type}'", controller)
            self.assertIn(f"PolicyAssignmentManager::renameHAProxy('{object_type}'", controller)
        self.assertIn("HA peer replica and is read-only", controller)

    def test_native_haproxy_template_supports_proxy_v2_health_checks(self):
        template = (
            ROOT.parents[1]
            / "net/haproxy/src/opnsense/service/templates/OPNsense/HAProxy/haproxy.conf"
        ).read_text()
        self.assertIn('backend.proxyProtocol|default("") == "v2"', template)
        self.assertIn("server_options.append('send-proxy-v2')", template)
        self.assertIn('backend.healthCheckProxyProto|default("") == "backend"', template)
        self.assertIn("server_options.append('check-send-proxy')", template)

    def test_policy_assignment_manager_preserves_native_object_ownership(self):
        helper = (MVC / "models/OPNsense/ApiExtensions/PolicyAssignmentManager.php").read_text()
        for marker in (
            "function setInterface",
            "function removeInterface",
            "function setHAProxy",
            "function renameHAProxy",
            "function removeHAProxy",
            "function interfaceState",
            "function haproxyState",
        ):
            self.assertIn(marker, helper)
        self.assertIn("HA peer replica", helper)
        self.assertIn("HASyncPolicy", helper)

        haproxy_controller = (MVC / "controllers/OPNsense/ApiExtensions/Api/HaproxyPolicyController.php").read_text()
        self.assertIn("function searchOverviewAction", haproxy_controller)
        self.assertIn("function overviewAction", haproxy_controller)
        self.assertIn("function assignAction", haproxy_controller)
        self.assertIn("function batchAssignAction", haproxy_controller)

        interface_controller = (MVC / "controllers/OPNsense/ApiExtensions/Api/InterfacePolicyController.php").read_text()
        self.assertIn("function searchOverviewAction", interface_controller)
        self.assertIn("function assignAction", interface_controller)
        self.assertIn("function batchAssignAction", interface_controller)


if __name__ == "__main__":
    unittest.main()
