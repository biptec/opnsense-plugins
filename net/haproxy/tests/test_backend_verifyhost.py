import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BackendVerifyHostContractTests(unittest.TestCase):
    def test_backend_verifyhost_is_typed_and_rendered(self):
        model = (ROOT / "src/opnsense/mvc/app/models/OPNsense/HAProxy/HAProxy.xml").read_text()
        form = (ROOT / "src/opnsense/mvc/app/controllers/OPNsense/HAProxy/forms/dialogServer.xml").read_text()
        template = (ROOT / "src/opnsense/service/templates/OPNsense/HAProxy/haproxy.conf").read_text()

        self.assertIn("<sslVerifyHost type=\"TextField\">", model)
        self.assertIn("<id>server.sslVerifyHost</id>", form)
        self.assertIn("server_data.sslVerifyHost", template)
        self.assertIn("server_options.append('verifyhost ' ~ server_data.sslVerifyHost)", template)

        verify_required = template.index("server_options.append('verify required')")
        verify_host = template.index("server_options.append('verifyhost ' ~ server_data.sslVerifyHost)")
        verify_none = template.index("server_options.append('verify none')")
        self.assertLess(verify_required, verify_host)
        self.assertLess(verify_host, verify_none)


if __name__ == "__main__":
    unittest.main()
