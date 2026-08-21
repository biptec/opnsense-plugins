#!/usr/bin/env python3

import importlib.util
import json
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


class DynamicRuntimeTests(unittest.TestCase):
    zone_uuid = "11111111-1111-1111-1111-111111111111"
    key_uuid = "22222222-2222-2222-2222-222222222222"
    zone = "acme.example.net"
    owner = "_acme-challenge.web.host.acme.example.net"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.primary = root / "primary"
        self.primary.mkdir()
        self.config = root / "config.xml"
        self.snapshot = root / "runtime.json"
        self.config.write_text(
            f"""<opnsense><OPNsense><bind>
            <tsig><keys><key uuid="{self.key_uuid}"><enabled>1</enabled><name>{self.owner}</name></key></keys></tsig>
            <domain><domains><domain uuid="{self.zone_uuid}">
              <enabled>1</enabled><type>primary</type><domainname>{self.zone}</domainname>
              <updatekeys>{self.key_uuid}</updatekeys><updatepolicy>self_txt</updatepolicy><dnssec>0</dnssec>
            </domain></domains></domain>
            </bind></OPNsense></opnsense>""",
            encoding="utf-8",
        )
        self.zone_file = self.primary / f"{self.zone_uuid}.db"
        self.zone_file.write_text(
            "$TTL 60\n@ IN SOA ns.example.net. hostmaster.example.net. ( 10 60 60 3600 60 )\n@ IN NS ns.example.net.\n",
            encoding="utf-8",
        )
        bind_service.CONFIG = str(self.config)
        bind_service.PRIMARY_DIR = str(self.primary)
        bind_service.RUNTIME_SNAPSHOT = str(self.snapshot)

    def tearDown(self):
        self.temp.cleanup()

    def test_configured_self_txt_zone_maps_exact_key_owner(self):
        zones = bind_service.configured_self_txt_zones()
        self.assertEqual(zones[self.zone_uuid]["zone"], self.zone)
        self.assertEqual(zones[self.zone_uuid]["owners"], [self.owner])

    def test_snapshot_removes_journal_only_after_runtime_state_is_saved(self):
        journal = self.primary / f"{self.zone_uuid}.db.jnl"
        journal.write_text("journal", encoding="ascii")
        state = (12, {self.owner: {(60, '"token"')}})
        with mock.patch.object(bind_service, "_current_zone_state", return_value=state):
            bind_service.snapshot_runtime_txt()
        self.assertFalse(journal.exists())
        payload = json.loads(self.snapshot.read_text(encoding="utf-8"))
        self.assertEqual(payload["zones"][self.zone_uuid]["serial"], 12)
        self.assertEqual(payload["zones"][self.zone_uuid]["records"][0]["owner"], self.owner)
        self.assertEqual(payload["zones"][self.zone_uuid]["records"][0]["rdata"], '"token"')

    def test_master_only_runtime_txt_is_captured_for_reconfigure_stop(self):
        canonical = (
            "acme.example.net. 12 IN SOA ns.example.net. hostmaster.example.net. 12 60 60 3600 60\n"
            f'{self.owner}. 60 IN TXT "active"\n'
        )
        with mock.patch.object(bind_service, "_compile_zone", return_value=canonical):
            bind_service.snapshot_runtime_txt(include_master=True)
        payload = json.loads(self.snapshot.read_text(encoding="utf-8"))
        self.assertEqual(payload["zones"][self.zone_uuid]["records"][0]["rdata"], '"active"')

    def test_snapshot_without_journal_keeps_pending_restore(self):
        self.snapshot.write_text('{"version": 1, "zones": {}}\n', encoding="utf-8")
        bind_service.snapshot_runtime_txt()
        self.assertTrue(self.snapshot.exists())

    def test_restore_merges_txt_and_advances_soa_serial(self):
        self.snapshot.write_text(
            json.dumps({
                "version": 1,
                "zones": {
                    self.zone_uuid: {
                        "zone": self.zone,
                        "serial": 12,
                        "records": [{"owner": self.owner, "ttl": 60, "rdata": '"token"'}],
                    }
                },
            }),
            encoding="utf-8",
        )
        canonical = (
            "acme.example.net. 60 IN SOA ns.example.net. hostmaster.example.net. 10 60 60 3600 60\n"
            "acme.example.net. 60 IN NS ns.example.net.\n"
        )
        with mock.patch.object(bind_service, "_compile_zone", return_value=canonical):
            bind_service.restore_runtime_txt()
        restored = self.zone_file.read_text(encoding="utf-8")
        self.assertIn("( 13 60 60 3600 60 )", restored)
        self.assertIn(f'{self.owner}.\t60\tIN\tTXT\t"token"', restored)
        self.assertFalse(self.snapshot.exists())

    def test_restore_advances_bind_normalized_multiline_soa(self):
        self.zone_file.write_text(
            "$TTL 60\n"
            "acme.example.net. IN SOA ns.example.net. hostmaster.example.net. (\n"
            "                10 ; serial\n"
            "                60 ; refresh\n"
            "                60 ; retry\n"
            "                3600 ; expire\n"
            "                60 ; minimum\n"
            "                )\n"
            "                IN NS ns.example.net.\n",
            encoding="utf-8",
        )
        self.snapshot.write_text(
            json.dumps({
                "version": 1,
                "zones": {
                    self.zone_uuid: {
                        "zone": self.zone,
                        "serial": 12,
                        "records": [{"owner": self.owner, "ttl": 60, "rdata": '"token"'}],
                    }
                },
            }),
            encoding="utf-8",
        )
        canonical = (
            "acme.example.net. 60 IN SOA ns.example.net. hostmaster.example.net. 10 60 60 3600 60\n"
            "acme.example.net. 60 IN NS ns.example.net.\n"
        )
        with mock.patch.object(bind_service, "_compile_zone", return_value=canonical):
            bind_service.restore_runtime_txt()
        restored = self.zone_file.read_text(encoding="utf-8")
        self.assertIn("13 ; serial", restored)
        self.assertNotIn("10 ; serial", restored)
        self.assertIn(f'{self.owner}.\t60\tIN\tTXT\t"token"', restored)
        self.assertFalse(self.snapshot.exists())

    def test_journal_replay_tracks_final_txt_state_and_serial(self):
        journal = self.primary / f"{self.zone_uuid}.db.jnl"
        journal.write_text("journal", encoding="ascii")
        output = "\n".join([
            f"add {self.zone}. 60 IN SOA ns.example.net. hostmaster.example.net. 11 60 60 3600 60",
            f'add {self.owner}. 60 IN TXT "old"',
            f'del {self.owner}. 60 IN TXT "old"',
            f'add {self.owner}. 60 IN TXT "current"',
            f"add {self.zone}. 60 IN SOA ns.example.net. hostmaster.example.net. 12 60 60 3600 60",
        ])
        result = mock.Mock(returncode=0, stdout=output, stderr="")
        records = {self.owner: set()}
        with mock.patch.object(bind_service.subprocess, "run", return_value=result):
            serial, records = bind_service._replay_journal(str(journal), {self.owner}, 10, records)
        self.assertEqual(serial, 12)
        self.assertEqual(records[self.owner], {(60, '"current"')})


class ServiceActionTests(unittest.TestCase):
    def run_action(self, action):
        calls = []

        def fake_run_named(named_action):
            calls.append(("named", named_action))
            return 0

        def fake_cleanup():
            calls.append(("cleanup", None))

        def fake_snapshot(*args, **kwargs):
            calls.append(("snapshot", kwargs.get("include_master", False)))

        def fake_restore():
            calls.append(("restore", None))

        with (
            mock.patch.object(bind_service, "run_named", side_effect=fake_run_named),
            mock.patch.object(bind_service, "cleanup", side_effect=fake_cleanup),
            mock.patch.object(bind_service, "snapshot_runtime_txt", side_effect=fake_snapshot),
            mock.patch.object(bind_service, "restore_runtime_txt", side_effect=fake_restore),
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
            [
                ("named", "stop"),
                ("snapshot", True),
                ("cleanup", None),
                ("restore", None),
                ("named", "start"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
