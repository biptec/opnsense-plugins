import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class CarpHealthLifecycleTests(unittest.TestCase):
    def test_plugin_depends_on_native_daemon(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("PLUGIN_DEPENDS=\t\tcarp-healthd", makefile)
        self.assertNotIn("PLUGIN_DEPENDS=\t\tarping", makefile)

    def test_control_script_uses_native_daemon_only(self):
        control = (ROOT / "src/opnsense/scripts/OPNsense/ApiExtensions/carp_health_control.sh").read_text()
        self.assertIn("DAEMON=${CARP_HEALTH_DAEMON:-/usr/local/sbin/carp-healthd}", control)
        self.assertIn('"${DAEMON}" -config "${CONFIG}" -state "${STATE}" -socket "${SOCKET}" run', control)
        self.assertIn('"${DAEMON}" -state "${STATE}" reset-actions', control)
        self.assertNotIn("/usr/local/bin/python3", control)
        self.assertIn("carp_health_monitor.py", control)
        self.assertIn("owned_child", control)
        self.assertIn("CARP_HEALTH_SUPERVISOR_PID", control)
        self.assertIn("CARP_HEALTH_CONFIG", control)
        self.assertIn("CARP_HEALTH_STATE", control)
        self.assertIn("CARP_HEALTH_SOCKET", control)

    def test_configd_status_and_restart_are_fail_visible(self):
        actions = (ROOT / "src/opnsense/service/conf/actions.d/actions_api_extensions.conf").read_text()
        self.assertIn("command:/usr/local/sbin/carp-healthd status", actions)
        self.assertIn("carp_health_control.sh restart && echo ok", actions)
        self.assertNotIn("carp_health_control.sh restart; echo ok", actions)

    def test_carp_service_status_is_native_fail_closed_checker(self):
        hook = (ROOT / "src/etc/rc.carp_service_status.d/carp_api_extensions_health").read_text()
        self.assertEqual(hook, "#!/bin/sh\n/usr/local/sbin/carp-healthd check-global\n")

    def test_start_and_stop_hooks_use_single_control_script(self):
        start = (ROOT / "src/etc/rc.syshook.d/start/91-api-extensions-carp-health").read_text()
        stop = (ROOT / "src/etc/rc.syshook.d/stop/91-api-extensions-carp-health").read_text()
        self.assertIn("carp_health_control.sh start", start)
        self.assertIn("carp_health_control.sh stop", stop)

    def test_post_install_restarts_native_daemon_and_cleans_legacy_files(self):
        post = (ROOT / "+POST_INSTALL.post").read_text()
        self.assertIn("carp_health_control.sh", post)
        self.assertIn("restart", post)
        self.assertIn("carp_health_monitor.py", post)
        self.assertIn("carp_health.py", post)

    def test_legacy_python_polling_service_is_removed(self):
        scripts = ROOT / "src/opnsense/scripts/OPNsense/ApiExtensions"
        self.assertFalse((scripts / "carp_health_monitor.py").exists())
        self.assertFalse((scripts / "carp_health.py").exists())


if __name__ == "__main__":
    unittest.main()
