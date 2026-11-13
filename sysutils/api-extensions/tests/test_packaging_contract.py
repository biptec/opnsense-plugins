import stat
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECONCILER = (
    ROOT
    / "src/opnsense/scripts/OPNsense/ApiExtensions/haproxy_tls_identity_reconcile.php"
)
ACTIONS = (
    ROOT
    / "src/opnsense/service/conf/actions.d/actions_api_extensions.conf"
)
SYNC_PLUGIN = ROOT / "src/etc/inc/plugins.inc.d/api_extensions.inc"


class PackagingContractTests(unittest.TestCase):
    def test_haproxy_tls_identity_reconciler_is_directly_executable(self):
        mode = RECONCILER.stat().st_mode
        self.assertTrue(
            mode & stat.S_IXUSR,
            "HAProxy TLS identity reconciler must be executable by root/configd",
        )
        self.assertEqual(
            RECONCILER.read_text().splitlines()[0],
            "#!/usr/local/bin/php",
        )

    def test_configd_executes_reconciler_directly(self):
        expected = (
            "command:/usr/local/opnsense/scripts/OPNsense/ApiExtensions/"
            "haproxy_tls_identity_reconcile.php reconcile"
        )
        self.assertIn(expected, ACTIONS.read_text())

    def test_tls_identity_membership_change_reloads_haproxy_runtime(self):
        source = RECONCILER.read_text()
        self.assertIn("'membership_changed' => $membershipChanged", source)
        self.assertIn("function apply_haproxy_runtime(bool $membershipChanged)", source)
        self.assertIn("$membershipChanged = $membershipChanged ||", source)
        self.assertIn(
            "HAProxyTLSIdentityMaterializer::runtimeMembershipChanged($runtimeDiff)",
            source,
        )
        self.assertIn("if ($membershipChanged) {", source)
        self.assertIn(
            "$backend->configdRun($enabled ? 'haproxy reload' : 'haproxy deploy');",
            source,
        )
        self.assertIn("$backend->configdRun('haproxy cert_sync_bulk');", source)
        self.assertIn(
            "apply_haproxy_runtime($configResult['membership_changed']);",
            source,
        )
        self.assertNotIn(
            "if ($configResult['changed'] || $changedSource)",
            source,
            "runtime parity must be checked even when persistent TLS identity state is already converged",
        )

    def test_tls_identity_renewal_verifies_runtime_postcondition(self):
        source = RECONCILER.read_text()
        self.assertIn(
            "HAProxyTLSIdentityMaterializer::runtimeContentChanged($runtimeDiff)",
            source,
        )
        hot_sync = source.index("$backend->configdRun('haproxy cert_sync_bulk');")
        verify = source.index(
            "if (!haproxy_runtime_changed(haproxy_runtime_diff($backend)))",
            hot_sync,
        )
        fallback = source.index("reload_haproxy_runtime($backend);", verify)
        postcondition = source.index(
            "require_haproxy_runtime_parity($backend);",
            fallback,
        )
        self.assertLess(hot_sync, verify)
        self.assertLess(verify, fallback)
        self.assertLess(fallback, postcondition)

    def test_explicit_tls_issuance_does_not_reenter_postsave_reconcile(self):
        source = RECONCILER.read_text()
        self.assertIn("function ensure_postsave_tracking(array $item, string $postsave)", source)
        self.assertIn("'-C', '/usr/bin/true'", source)
        self.assertIn("'getcert', 'start-tracking'", source)
        self.assertIn("ensure_postsave_tracking($item, $postsave);", source)

        issuance = source.index("'-C', '/usr/bin/true'")
        restore_hook = source.index("ensure_postsave_tracking($item, $postsave);", issuance)
        self.assertLess(issuance, restore_hook)
        self.assertNotIn("'-D', $item['dns_name'],\n        '-C', $postsave", source)

    def test_haproxy_sync_activates_only_after_native_sync_phases(self):
        source = SYNC_PLUGIN.read_text()
        self.assertIn("function api_extensions_haproxy_sync_activate()", source)
        self.assertIn(
            "'sync_activate' => 'api_extensions_haproxy_sync_activate'",
            source,
        )
        self.assertNotIn(
            "'sync_finalize' => 'api_extensions_haproxy_sync_finalize'",
            source,
        )


if __name__ == "__main__":
    unittest.main()
