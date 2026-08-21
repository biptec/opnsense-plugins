import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "src/opnsense/service/templates/OPNsense/Bind/named.conf"

class DotDict(dict):
    __getattr__ = dict.__getitem__

def render_secondary_zone(*, transfer_key="test-secret", allow_notify=""):
    text = TEMPLATE_PATH.read_text()
    match = re.search(r"({% macro render_zone\(domain\) %}.*?{% endmacro %})", text, flags=re.DOTALL)
    if match is None:
        raise AssertionError("render_zone macro was not found")
    environment = Environment(undefined=StrictUndefined, extensions=["jinja2.ext.do"], autoescape=False)
    template = environment.from_string(match.group(1) + "\n{{ render_zone(domain) }}")
    domain = DotDict({
        "@uuid": "55555555-5555-4555-8555-555555555555",
        "type": "secondary",
        "domainname": "example.net",
        "primaryip": "192.0.2.53,2001:db8::53",
        "transferkeyalgo": "hmac-sha256",
        "transferkeyname": "secondary-transfer",
        "transferkey": transfer_key,
        "allownotifysecondary": allow_notify,
        "allowtransfer": "",
        "allowrndctransfer": "0",
        "allowquery": "",
        "allowrndcupdate": "0",
        "updatekeys": "",
        "updatepolicy": "self_txt",
        "dnssec": "0",
    })
    return template.render(domain=domain, helpers=DotDict({}))

class SecondaryTransferTemplateTest(unittest.TestCase):
    def test_transfer_key_authenticates_axfr_and_notify(self):
        rendered = render_secondary_zone()
        self.assertIn('192.0.2.53 key "secondary-transfer";', rendered)
        self.assertIn('2001:db8::53 key "secondary-transfer";', rendered)
        self.assertIn("allow-notify {", rendered)
        self.assertIn('key "secondary-transfer";', rendered)

    def test_address_allow_notify_is_additive_to_tsig(self):
        rendered = render_secondary_zone(allow_notify="192.0.2.54,2001:db8::54")
        self.assertIn('key "secondary-transfer";', rendered)
        self.assertIn("192.0.2.54; 2001:db8::54;", rendered)

    def test_unsigned_secondary_keeps_optional_address_policy(self):
        rendered = render_secondary_zone(transfer_key="", allow_notify="192.0.2.54")
        self.assertNotIn('key "secondary-transfer";', rendered)
        self.assertIn("allow-notify {", rendered)
        self.assertIn("192.0.2.54;", rendered)

    def test_rendered_authenticated_secondary_passes_named_checkconf(self):
        binary = shutil.which("named-checkconf")
        if binary is None:
            self.skipTest("named-checkconf is not installed")
        rendered = render_secondary_zone()
        configuration = f'''
options {{
        directory "/tmp";
}};
key "secondary-transfer" {{
        algorithm "hmac-sha256";
        secret "dGVzdC1zZWNvbmRhcnktdHJhbnNmZXIta2V5";
}};
{rendered}
'''
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(configuration)
            handle.flush()
            subprocess.run([binary, handle.name], check=True, capture_output=True, text=True)

if __name__ == "__main__":
    unittest.main()
