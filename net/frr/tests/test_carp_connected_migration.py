import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

MODULE = Path(__file__).parents[1] / "src/opnsense/scripts/frr/carp_connected_migrate.py"
spec = importlib.util.spec_from_file_location("carp_connected_migrate", MODULE)
migrate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrate)


class CommandStub:
    def __init__(self, route, delete_rc=0):
        self.route = route
        self.delete_rc = delete_rc
        self.commands = []

    def __call__(self, args):
        self.commands.append(args)
        if args[:4] == ["/sbin/route", "-n", "get", "-net"] or (
            args[:5] == ["/sbin/route", "-n", "get", "-inet6", "-net"]
        ):
            if self.route is None:
                return SimpleNamespace(returncode=1, stdout="")
            return SimpleNamespace(
                returncode=0,
                stdout=f"    gateway: {self.route['gateway']}\n  interface: {self.route['interface']}\n",
            )
        if args[:2] == ["/sbin/route", "delete"]:
            if self.delete_rc == 0:
                self.route = None
            return SimpleNamespace(returncode=self.delete_rc, stdout="")
        raise AssertionError(args)


class MigrationTests(unittest.TestCase):
    def write_state(self, routes):
        tmp = tempfile.NamedTemporaryFile("w", delete=False)
        json.dump({"routes": routes}, tmp)
        tmp.close()
        return Path(tmp.name)

    def test_exact_owned_route_is_deleted_and_state_removed(self):
        state = self.write_state([{"family": 4, "network": "192.0.2.0/24", "gateway": "10.0.0.2"}])
        stub = CommandStub({"gateway": "10.0.0.2", "interface": "vlan3803"})
        self.assertEqual(migrate.migrate(str(state), stub), 0)
        self.assertFalse(state.exists())
        self.assertTrue(any(cmd[:2] == ["/sbin/route", "delete"] for cmd in stub.commands))

    def test_unrelated_current_route_is_not_deleted(self):
        state = self.write_state([{"family": 4, "network": "192.0.2.0/24", "gateway": "10.0.0.2"}])
        stub = CommandStub({"gateway": "10.0.0.3", "interface": "vlan3803"})
        self.assertEqual(migrate.migrate(str(state), stub), 0)
        self.assertFalse(state.exists())
        self.assertFalse(any(cmd[:2] == ["/sbin/route", "delete"] for cmd in stub.commands))

    def test_failed_delete_retains_ownership_state_fail_closed(self):
        route = {"family": 6, "network": "2001:db8::/64", "gateway": "fe80::2%vlan3803"}
        state = self.write_state([route])
        stub = CommandStub({"gateway": route["gateway"], "interface": "vlan3803"}, delete_rc=1)
        self.assertEqual(migrate.migrate(str(state), stub), 75)
        self.assertEqual(json.loads(state.read_text())["routes"], [route])

    def test_invalid_state_fails_closed(self):
        tmp = tempfile.NamedTemporaryFile("w", delete=False)
        tmp.write("{broken")
        tmp.close()
        self.assertEqual(migrate.migrate(tmp.name, CommandStub(None)), 75)


if __name__ == "__main__":
    unittest.main()
