import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "src/opnsense/service/templates/OPNsense/Bind/named.conf"
MODEL_PATH = ROOT / "src/opnsense/mvc/app/models/OPNsense/Bind/Domain.xml"
FORM_PATH = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Bind/forms/dialogEditBindSecondaryDomain.xml"


class DotDict(dict):
    __getattr__ = dict.__getitem__


class TemplateHelpers:
    def __init__(self, objects):
        self.objects = objects

    def getUUID(self, uuid):  # noqa: N802 - mirrors the OPNsense template helper.
        return self.objects[uuid]


def render_secondary_zone(*, shared_key="", transfer_key="test-secret", allow_notify=""):
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
        "secondarytransferkey": shared_key,
        "transferkeyalgo": "hmac-sha256" if transfer_key else "",
        "transferkeyname": "secondary-transfer" if transfer_key else "",
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
    helpers = TemplateHelpers({"shared-key-uuid": DotDict(name="dns-xfr-public")})
    return template.render(domain=domain, helpers=helpers)


class SecondaryTransferTemplateTest(unittest.TestCase):
    def test_model_and_webui_expose_shared_transfer_key(self):
        domain = ET.parse(MODEL_PATH).getroot().find("./items/domains/domain")
        self.assertIsNotNone(domain)
        field = domain.find("secondarytransferkey")
        self.assertIsNotNone(field)
        self.assertEqual(field.attrib.get("type"), "ModelRelationField")
        self.assertEqual(field.findtext("./Model/template/source"), "OPNsense.Bind.Tsig")
        form = FORM_PATH.read_text()
        self.assertIn("<id>domain.secondarytransferkey</id>", form)
        self.assertIn("Legacy Transfer Key Secret", form)

    def test_shared_transfer_key_authenticates_axfr_and_notify(self):
        rendered = render_secondary_zone(shared_key="shared-key-uuid", transfer_key="")
        self.assertIn('192.0.2.53 key "dns-xfr-public";', rendered)
        self.assertIn('2001:db8::53 key "dns-xfr-public";', rendered)
        self.assertIn("allow-notify {", rendered)
        self.assertIn('key "dns-xfr-public";', rendered)
        self.assertNotIn("secondary-transfer", rendered)

    def test_legacy_inline_transfer_key_remains_supported(self):
        rendered = render_secondary_zone()
        self.assertIn('192.0.2.53 key "secondary-transfer";', rendered)
        self.assertIn('2001:db8::53 key "secondary-transfer";', rendered)
        self.assertIn("allow-notify {", rendered)
        self.assertIn('key "secondary-transfer";', rendered)

    def test_address_allow_notify_is_additive_to_shared_tsig(self):
        rendered = render_secondary_zone(shared_key="shared-key-uuid", transfer_key="", allow_notify="192.0.2.54,2001:db8::54")
        self.assertIn('key "dns-xfr-public";', rendered)
        self.assertIn("192.0.2.54; 2001:db8::54;", rendered)

    def test_unsigned_secondary_keeps_optional_address_policy(self):
        rendered = render_secondary_zone(transfer_key="", allow_notify="192.0.2.54")
        self.assertNotIn(" key ", rendered)
        self.assertIn("allow-notify {", rendered)
        self.assertIn("192.0.2.54;", rendered)

    def test_rendered_shared_key_secondary_passes_named_checkconf(self):
        binary = shutil.which("named-checkconf")
        if binary is None:
            self.skipTest("named-checkconf is not installed")
        rendered = render_secondary_zone(shared_key="shared-key-uuid", transfer_key="")
        configuration = f'''
options {{
        directory "/tmp";
}};
key "dns-xfr-public" {{
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
