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


class ProcessStub:
    def __init__(self, supervisor_command, child_command="", child_pid=200):
        self.supervisor_command = supervisor_command
        self.child_command = child_command
        self.child_pid = child_pid

    def __call__(self, args):
        if args[:2] == ["/bin/ps", "-p"]:
            pid = int(args[2])
            if pid == 100:
                return SimpleNamespace(returncode=0, stdout=self.supervisor_command + "\n")
            if pid == self.child_pid and self.child_command:
                return SimpleNamespace(returncode=0, stdout=self.child_command + "\n")
            return SimpleNamespace(returncode=1, stdout="")
        if args[:2] == ["/bin/pgrep", "-P"]:
            if int(args[2]) == 100 and self.child_command:
                return SimpleNamespace(returncode=0, stdout=f"{self.child_pid}\n")
            return SimpleNamespace(returncode=1, stdout="")
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

    def test_hidden_daemon_title_is_owned_via_monitor_child(self):
        stub = ProcessStub(
            "daemon: /usr/local/bin/python3[200] (daemon)",
            "/usr/local/bin/python3 /usr/local/opnsense/scripts/frr/carp_connected_monitor.py",
        )
        owned, children = migrate._owned_supervisor(100, stub)
        self.assertTrue(owned)
        self.assertEqual(children, [200])

    def test_unrelated_daemon_pid_is_never_claimed(self):
        stub = ProcessStub(
            "daemon: /usr/local/bin/python3[200] (daemon)",
            "/usr/local/bin/python3 /usr/local/bin/unrelated.py",
        )
        owned, children = migrate._owned_supervisor(100, stub)
        self.assertFalse(owned)
        self.assertEqual(children, [])


if __name__ == "__main__":
    unittest.main()
