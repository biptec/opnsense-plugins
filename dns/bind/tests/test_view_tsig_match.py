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
MODEL_PATH = ROOT / "src/opnsense/mvc/app/models/OPNsense/Bind/View.xml"
FORM_PATH = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Bind/forms/dialogEditBindView.xml"


class DotDict(dict):
    __getattr__ = dict.__getitem__


class TemplateHelpers:
    def __init__(self, objects):
        self.objects = objects

    def getUUID(self, uuid):  # noqa: N802 - mirrors the OPNsense template helper.
        return self.objects[uuid]


def render_match_clients(*, match_any="0", include="internal-key", exclude="public-key", clients="internal-acl"):
    text = TEMPLATE_PATH.read_text()
    match = re.search(r"({% macro render_match_clients\(view\) %}.*?{% endmacro %})", text, flags=re.DOTALL)
    if match is None:
        raise AssertionError("render_match_clients macro was not found")
    environment = Environment(undefined=StrictUndefined, extensions=["jinja2.ext.do"], autoescape=False)
    template = environment.from_string(match.group(1) + "\n{{ render_match_clients(view) }}")
    view = DotDict(
        matchany=match_any,
        matchclienttsigkeys=include,
        excludematchclienttsigkeys=exclude,
        matchclients=clients,
    )
    helpers = TemplateHelpers(
        {
            "internal-key": DotDict(name="dns-xfr-internal"),
            "public-key": DotDict(name="dns-xfr-public"),
            "internal-acl": DotDict(name="internal_clients"),
        }
    )
    return template.render(view=view, helpers=helpers)


class ViewTsigMatchTemplateTest(unittest.TestCase):
    def test_model_and_form_expose_tsig_match_selectors(self):
        view = ET.parse(MODEL_PATH).getroot().find("./items/views/view")
        self.assertIsNotNone(view)
        for name in ("matchclienttsigkeys", "excludematchclienttsigkeys"):
            field = view.find(name)
            self.assertIsNotNone(field)
            self.assertEqual(field.attrib.get("type"), "ModelRelationField")
            self.assertEqual(field.findtext("./Model/template/source"), "OPNsense.Bind.Tsig")
            self.assertEqual(field.findtext("Multiple"), "Y")
        form = FORM_PATH.read_text()
        self.assertIn("<id>view.matchclienttsigkeys</id>", form)
        self.assertIn("<id>view.excludematchclienttsigkeys</id>", form)

    def test_exclusions_render_before_positive_keys_and_network_acls(self):
        rendered = render_match_clients()
        excluded = rendered.index('!key "dns-xfr-public";')
        included = rendered.index('key "dns-xfr-internal";')
        network = rendered.index("internal_clients;")
        self.assertLess(excluded, included)
        self.assertLess(included, network)

    def test_match_any_ignores_specific_selectors(self):
        rendered = render_match_clients(match_any="1")
        self.assertIn("any;", rendered)
        self.assertNotIn("dns-xfr-public", rendered)
        self.assertNotIn("dns-xfr-internal", rendered)
        self.assertNotIn("internal_clients", rendered)

    def test_empty_positive_selectors_fail_closed(self):
        rendered = render_match_clients(include="", exclude="public-key", clients="")
        self.assertIn('!key "dns-xfr-public";', rendered)
        self.assertIn("none;", rendered)

    def test_rendered_tsig_match_is_valid_named_configuration(self):
        binary = shutil.which("named-checkconf")
        if binary is None:
            self.skipTest("named-checkconf is not installed")
        match_clients = render_match_clients()
        configuration = f'''
key "dns-xfr-internal" {{ algorithm "hmac-sha256"; secret "aW50ZXJuYWwtdHJhbnNmZXI="; }};
key "dns-xfr-public" {{ algorithm "hmac-sha256"; secret "cHVibGljLXRyYW5zZmVy"; }};
acl "internal_clients" {{ 10.0.0.0/8; }};
view "internal" {{
    match-clients {{
{match_clients}
    }};
    recursion no;
}};
'''
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write(configuration)
            handle.flush()
            subprocess.run([binary, handle.name], check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
