import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / 'src/opnsense/mvc/app/controllers/OPNsense/Bind/Api/ServiceController.php'
VIEW = ROOT / 'src/opnsense/mvc/app/views/OPNsense/Bind/general.volt'


class ReloadRoutingTest(unittest.TestCase):
    def test_reload_action_selects_soft_reconfigure(self):
        source = CONTROLLER.read_text()
        self.assertIn('private $forceRestart = true;', source)
        self.assertIsNotNone(
            re.search(
                r'protected function reconfigureForceRestart\(\).*?return \$this->forceRestart;',
                source,
                flags=re.DOTALL,
            )
        )
        self.assertIsNotNone(
            re.search(
                r'public function reloadAction\(\).*?\$this->forceRestart = false;.*?return \$this->reconfigureAction\(\);',
                source,
                flags=re.DOTALL,
            )
        )

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
