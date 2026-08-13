#!/usr/bin/env python3

import importlib.util
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/Bind/service.py"
spec = importlib.util.spec_from_file_location("bind_service", SCRIPT)
bind_service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bind_service)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.primary = root / "primary"
        self.secondary = root / "secondary"
        self.keys = root / "keys"
        self.primary.mkdir()
        self.secondary.mkdir()
        self.keys.mkdir()
        self.config = root / "config.xml"
        self.config.write_text(
            """<opnsense><OPNsense><bind><domain><domains>
            <domain uuid="11111111-1111-1111-1111-111111111111">
              <type>primary</type><domainname>Shared.Example</domainname><dnssec>1</dnssec>
            </domain>
            <domain uuid="22222222-2222-2222-2222-222222222222">
              <type>primary</type><domainname>shared.example</domainname><dnssec>1</dnssec>
            </domain>
            <domain uuid="33333333-3333-3333-3333-333333333333">
              <type>secondary</type><domainname>secondary.example</domainname><dnssec>0</dnssec>
            </domain>
            </domains></domain></bind></OPNsense></opnsense>""",
            encoding="utf-8",
        )
        bind_service.CONFIG = str(self.config)
        bind_service.PRIMARY_DIR = str(self.primary)
        bind_service.SECONDARY_DIR = str(self.secondary)
        bind_service.KEY_ROOT = str(self.keys)

    def tearDown(self):
        self.temp.cleanup()

    def test_cleanup_is_namespaced_and_preserves_shared_keys(self):
        current_primary = self.primary / "11111111-1111-1111-1111-111111111111.db"
        current_primary.write_text("current", encoding="ascii")
        stale_primary = self.primary / "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.db.signed.jnl"
        stale_primary.write_text("stale", encoding="ascii")
        current_secondary = self.secondary / "33333333-3333-3333-3333-333333333333.db"
        current_secondary.write_text("current", encoding="ascii")

        legacy_current = self.keys / "Kshared.example.+013+12345.private"
        legacy_current.write_text("current-key", encoding="ascii")
        unknown_root = self.keys / "Kcustom.example.+013+54321.private"
        unknown_root.write_text("custom-key", encoding="ascii")

        stale_managed = self.keys / "stale.example"
        stale_managed.mkdir()
        (stale_managed / bind_service.MARKER).write_text("stale.example\n", encoding="ascii")
        (stale_managed / "Kstale.example.+013+11111.private").write_text("stale", encoding="ascii")

        custom_directory = self.keys / "custom-directory"
        custom_directory.mkdir()
        (custom_directory / "keep").write_text("custom", encoding="ascii")

        bind_service.cleanup()

        self.assertTrue(current_primary.exists())
        self.assertFalse(stale_primary.exists())
        self.assertTrue(current_secondary.exists())
        self.assertTrue((self.keys / "shared.example" / bind_service.MARKER).exists())
        self.assertTrue((self.keys / "shared.example" / legacy_current.name).exists())
        self.assertFalse(legacy_current.exists())
        self.assertTrue(unknown_root.exists())
        self.assertFalse(stale_managed.exists())
        self.assertTrue(custom_directory.exists())

    def test_key_directory_remains_until_last_dnssec_copy_is_removed(self):
        bind_service.cleanup()
        shared = self.keys / "shared.example"
        self.assertTrue(shared.exists())

        tree = self.config.read_text(encoding="utf-8")
        tree = tree.replace(
            '<domain uuid="11111111-1111-1111-1111-111111111111">\n              <type>primary</type><domainname>Shared.Example</domainname><dnssec>1</dnssec>\n            </domain>',
            "",
        )
        self.config.write_text(tree, encoding="utf-8")
        bind_service.cleanup()
        self.assertTrue(shared.exists())

        tree = self.config.read_text(encoding="utf-8")
        tree = tree.replace(
            '<domain uuid="22222222-2222-2222-2222-222222222222">\n              <type>primary</type><domainname>shared.example</domainname><dnssec>1</dnssec>\n            </domain>',
            "",
        )
        self.config.write_text(tree, encoding="utf-8")
        bind_service.cleanup()
        self.assertFalse(shared.exists())


class ServiceActionTests(unittest.TestCase):
    def run_action(self, action):
        calls = []

        def fake_run_named(named_action):
            calls.append(("named", named_action))
            return 0

        def fake_cleanup():
            calls.append(("cleanup", None))

        with (
            mock.patch.object(bind_service, "run_named", side_effect=fake_run_named),
            mock.patch.object(bind_service, "cleanup", side_effect=fake_cleanup),
            mock.patch.object(bind_service.sys, "argv", ["service.py", action]),
        ):
            result = bind_service.main()
        return result, calls

    def test_reload_uses_named_reload_without_restart(self):
        result, calls = self.run_action("reload")
        self.assertEqual(result, 0)
        self.assertEqual(calls, [("cleanup", None), ("named", "reload")])

    def test_restart_remains_stop_cleanup_start(self):
        result, calls = self.run_action("restart")
        self.assertEqual(result, 0)
        self.assertEqual(
            calls,
            [("named", "stop"), ("cleanup", None), ("named", "start")],
        )


if __name__ == "__main__":
    unittest.main()
