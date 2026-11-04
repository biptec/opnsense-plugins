import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FrontendPolicyNamespaceContractTests(unittest.TestCase):
    def test_frontend_policy_hooks_use_fully_qualified_classes(self):
        controller = (
            ROOT
            / "src/opnsense/mvc/app/controllers/OPNsense/HAProxy/Api/SettingsController.php"
        ).read_text()
        frontend = controller.split("public function setFrontendAction", 1)[1].split(
            "public function getBackendAction", 1
        )[0]

        self.assertNotIn("OPNsenseApiExtensionsPolicyAssignmentManager::", frontend)
        self.assertNotIn("catch (Throwable $error)", frontend)
        self.assertIn(
            "\\OPNsense\\ApiExtensions\\PolicyAssignmentManager::setHAProxy('frontend'",
            frontend,
        )
        self.assertIn(
            "\\OPNsense\\ApiExtensions\\PolicyAssignmentManager::renameHAProxy('frontend'",
            frontend,
        )
        self.assertIn(
            "\\OPNsense\\ApiExtensions\\PolicyAssignmentManager::removeHAProxy('frontend'",
            frontend,
        )
        self.assertGreaterEqual(frontend.count("catch (\\Throwable $error)"), 2)


if __name__ == "__main__":
    unittest.main()
