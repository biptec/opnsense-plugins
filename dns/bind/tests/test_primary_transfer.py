import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jinja2 import Environment, StrictUndefined


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "src/opnsense/service/templates/OPNsense/Bind/named.conf"
MODEL_PATH = ROOT / "src/opnsense/mvc/app/models/OPNsense/Bind/Domain.xml"
FORM_PATH = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Bind/forms/dialogEditBindPrimaryDomain.xml"


class DotDict(dict):
    __getattr__ = dict.__getitem__


class TemplateHelpers:
    def __init__(self, objects):
        self.objects = objects

    def getUUID(self, uuid):  # noqa: N802 - mirrors the OPNsense template helper.
        return self.objects[uuid]


def render_primary_zone(*, transfer_key="transfer-key-uuid", also_notify="192.0.2.54"):
    template_text = TEMPLATE_PATH.read_text()
    match = re.search(
        r"({% macro render_zone\(domain\) %}.*?{% endmacro %})",
        template_text,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError("render_zone macro was not found")

    environment = Environment(
        undefined=StrictUndefined,
        extensions=["jinja2.ext.do"],
        autoescape=False,
        keep_trailing_newline=True,
    )
    template = environment.from_string(match.group(1) + "\n{{ render_zone(domain) }}")
    domain = DotDict(
        {
            "@uuid": "44444444-4444-4444-8444-444444444444",
            "type": "primary",
            "domainname": "example.net",
            "primarytransferkey": transfer_key,
            "alsonotify": also_notify,
            "dnssec": "0",
            "allowtransfer": "",
            "allowrndctransfer": "0",
            "allowquery": "",
            "allowrndcupdate": "0",
            "updatekeys": "",
            "updatepolicy": "self_txt",
        }
    )
    helpers = TemplateHelpers(
        {
            "transfer-key-uuid": DotDict(
                {
                    "name": "secondary-transfer",
                }
            )
        }
    )
    return template.render(domain=domain, helpers=helpers)


class PrimaryTransferTemplateTest(unittest.TestCase):
    def test_model_and_form_expose_primary_transfer_fields(self):
        model = MODEL_PATH.read_text()
        form = FORM_PATH.read_text()

        self.assertIn("<primarytransferkey type=\"ModelRelationField\">", model)
        self.assertIn("<alsonotify type=\"NetworkField\">", model)
        self.assertIn("<id>domain.primarytransferkey</id>", form)
        self.assertIn("<id>domain.alsonotify</id>", form)

    def test_transfer_key_authenticates_axfr_and_notify(self):
        rendered = render_primary_zone()

        self.assertIn('key "secondary-transfer";', rendered)
        self.assertIn("also-notify {", rendered)
        self.assertIn('192.0.2.54 key "secondary-transfer";', rendered)
        self.assertEqual(rendered.count('key "secondary-transfer";'), 2)

    def test_transfer_key_without_notify_still_authenticates_axfr(self):
        rendered = render_primary_zone(also_notify="")

        self.assertIn('key "secondary-transfer";', rendered)
        self.assertNotIn("also-notify {", rendered)
        self.assertEqual(rendered.count('key "secondary-transfer";'), 1)

    def test_notify_without_key_remains_valid_but_unsigned(self):
        rendered = render_primary_zone(transfer_key="")

        self.assertIn("192.0.2.54;", rendered)
        self.assertNotIn('key "secondary-transfer";', rendered)

    def test_rendered_authenticated_zone_passes_named_checkconf(self):
        binary = shutil.which("named-checkconf")
        if binary is None:
            self.skipTest("named-checkconf is not installed")

        rendered = render_primary_zone()
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
            subprocess.run(
                [binary, handle.name],
                check=True,
                capture_output=True,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
