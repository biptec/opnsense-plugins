import importlib.util
from pathlib import Path
import subprocess
import unittest


MODULE_PATH = (
    Path(__file__).parents[1]
    / "src/opnsense/scripts/frr/carp_route_barrier.py"
)
SPEC = importlib.util.spec_from_file_location("carp_route_barrier", MODULE_PATH)
BARRIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BARRIER)


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.recv_count = 0

    def recv(self, _size):
        self.recv_count += 1
        return b"event"

    def close(self):
        self.closed = True


class RouteBarrierTest(unittest.TestCase):
    def test_parse_route_get(self):
        output = """\
   route to: 192.0.2.1
    gateway: 10.0.0.2
  interface: vlan3803
"""
        self.assertEqual(
            BARRIER.parse_route_get(output),
            {"gateway": "10.0.0.2", "interface": "vlan3803"},
        )

    def test_master_requires_endpoint_interface(self):
        self.assertTrue(
            BARRIER.route_matches(
                {"gateway": "", "interface": "vlan3990"},
                "MASTER",
                "vlan3990",
            )
        )
        self.assertFalse(
            BARRIER.route_matches(
                {"gateway": "10.0.0.2", "interface": "vlan3803"},
                "MASTER",
                "vlan3990",
            )
        )

    def test_backup_requires_peer_gateway_and_interface(self):
        self.assertTrue(
            BARRIER.route_matches(
                {"gateway": "10.0.0.2", "interface": "vlan3803"},
                "BACKUP",
                "vlan3990",
            )
        )
        self.assertFalse(
            BARRIER.route_matches(
                {"gateway": "", "interface": "vlan3803"},
                "BACKUP",
                "vlan3990",
            )
        )
        self.assertFalse(
            BARRIER.route_matches(
                {"gateway": "192.0.2.1", "interface": "vlan3990"},
                "BACKUP",
                "vlan3990",
            )
        )

    def test_subscribe_before_snapshot_and_wake_on_route_event(self):
        calls = []
        routes = [
            {"gateway": "", "interface": "vlan3990"},
            {"gateway": "10.0.0.2", "interface": "vlan3803"},
        ]
        sock = FakeSocket()

        def command(args):
            calls.append(args)
            route = routes.pop(0)
            stdout = (
                f"    gateway: {route['gateway']}\n" if route["gateway"] else ""
            ) + f"  interface: {route['interface']}\n"
            return subprocess.CompletedProcess(args, 0, stdout, "")

        select_calls = []

        def select_func(read, _write, _exc, timeout):
            select_calls.append((read, timeout))
            return [sock], [], []

        got = BARRIER.wait_for_route(
            "inet",
            "192.0.2.1",
            "vlan3990",
            "BACKUP",
            timeout=30,
            command_func=command,
            socket_factory=lambda: sock,
            select_func=select_func,
            monotonic=lambda: 0.0,
        )
        self.assertEqual(
            got, {"gateway": "10.0.0.2", "interface": "vlan3803"}
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(sock.recv_count, 1)
        self.assertTrue(sock.closed)
        self.assertEqual(len(select_calls), 1)

    def test_timeout_is_fail_closed(self):
        sock = FakeSocket()

        def command(args):
            return subprocess.CompletedProcess(
                args, 0, "  interface: vlan3990\n", ""
            )

        got = BARRIER.wait_for_route(
            "inet",
            "192.0.2.1",
            "vlan3990",
            "BACKUP",
            timeout=30,
            command_func=command,
            socket_factory=lambda: sock,
            select_func=lambda *_args: ([], [], []),
            monotonic=lambda: 0.0,
        )
        self.assertIsNone(got)
        self.assertTrue(sock.closed)


if __name__ == "__main__":
    unittest.main()
