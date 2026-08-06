from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


CADDY_ROOT = Path(__file__).resolve().parents[1]
MODEL = CADDY_ROOT / "src/opnsense/mvc/app/models/OPNsense/Caddy/Caddy.xml"
FORM = CADDY_ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Caddy/forms/general.xml"
TEMPLATE = CADDY_ROOT / "src/opnsense/service/templates/OPNsense/Caddy/Caddyfile"


class ListenerAddressesTest(unittest.TestCase):
    def test_model_accepts_only_literal_address_sets(self) -> None:
        general = ET.parse(MODEL).getroot().find("./items/general")
        self.assertIsNotNone(general)
        field = general.find("ListenAddresses")
        self.assertIsNotNone(field)
        self.assertEqual(field.attrib.get("type"), "NetworkField")
        self.assertEqual(field.findtext("AsList"), "Y")
        self.assertEqual(field.findtext("NetMaskAllowed"), "N")
        self.assertEqual(field.findtext("WildcardEnabled"), "N")

    def test_webui_exposes_listener_addresses(self) -> None:
        ids = [node.text for node in ET.parse(FORM).getroot().iter("id")]
        self.assertIn("caddy.general.ListenAddresses", ids)

    def test_template_binds_https_and_automatic_redirect_server(self) -> None:
        template = TEMPLATE.read_text()
        self.assertIn(
            "default_bind {{ generalSettings.ListenAddresses.split(',') | join(' ') }}",
            template,
        )
        self.assertIn(
            'generalSettings.EnableLayer4|default("0") != "1"',
            template,
        )
        self.assertIn("http:// {\n}", template)

    def test_legacy_boolean_acme_passthrough_values_are_ignored(self) -> None:
        template = TEMPLATE.read_text()
        self.assertEqual(
            template.count('acmePassthrough not in ["", "0", "1"]'),
            2,
        )


if __name__ == "__main__":
    unittest.main()
