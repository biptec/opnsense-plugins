import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / 'src/opnsense/mvc/app/controllers/OPNsense/Bind/Api/ServiceController.php'
VIEW = ROOT / 'src/opnsense/mvc/app/views/OPNsense/Bind/general.volt'


class ReloadRoutingTest(unittest.TestCase):
    def test_backend_actions_are_verified_and_retried(self):
        source = CONTROLLER.read_text()
        self.assertIn('private const RELOAD_ATTEMPTS = 5;', source)
        self.assertIn('private const RELOAD_DELAY_US = 500000;', source)
        self.assertNotIn('private $forceRestart', source)
        self.assertIsNotNone(
            re.search(
                r'private function runServiceAction\(.*?return \$response === \'OK\';',
                source,
                flags=re.DOTALL,
            )
        )
        self.assertIn("$this->runServiceAction($backend, 'reload')", source)
        self.assertIn('usleep(self::RELOAD_DELAY_US);', source)
        self.assertIn("gettext('BIND did not accept the configuration reload.')", source)

    def test_reload_and_restart_paths_verify_runtime(self):
        source = CONTROLLER.read_text()
        reload_action = re.search(
            r'public function reloadAction\(\).*?return \[\'status\' => \'ok\'\];',
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(reload_action)
        self.assertIn('$this->renderConfiguration($backend);', reload_action.group(0))
        self.assertIn('$this->startAndVerify($backend);', reload_action.group(0))
        self.assertIn('$this->waitForReload($backend);', reload_action.group(0))

        reconfigure = re.search(
            r'public function reconfigureAction\(\).*?return \[\'status\' => \'ok\'\];',
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(reconfigure)
        self.assertIn('$this->stopIfRunning($backend);', reconfigure.group(0))
        self.assertIn('$this->renderConfiguration($backend);', reconfigure.group(0))
        self.assertIn('$this->startAndVerify($backend);', reconfigure.group(0))

    def test_reconfigure_paths_are_serialized(self):
        source = CONTROLLER.read_text()
        self.assertIn('use OPNsense\\Core\\FileObject;', source)
        self.assertIn("private const RECONFIGURE_LOCK = 'bind-reconfigure.lock';", source)
        self.assertIn('new FileObject(', source)
        self.assertIn('LOCK_EX', source)
        self.assertIn('finally {', source)
        self.assertEqual(source.count('return $this->withServiceLock(function () {'), 2)

    def test_general_settings_keep_restart_path(self):
        source = VIEW.read_text()
        general = re.search(
            r'\$\("#saveAct"\).*?ajaxCall\(url = "([^"]+)"',
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(general)
        self.assertEqual(general.group(1), '/api/bind/service/reconfigure')

    def test_non_general_save_paths_use_reload(self):
        source = VIEW.read_text()
        self.assertEqual(source.count('/api/bind/service/reconfigure'), 1)
        self.assertGreaterEqual(source.count('/api/bind/service/reload'), 5)


if __name__ == '__main__':
    unittest.main()
