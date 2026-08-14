from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

CADDY_ROOT = Path(__file__).resolve().parents[1]
MODEL = CADDY_ROOT / "src/opnsense/mvc/app/models/OPNsense/Caddy/Caddy.xml"
FORM = CADDY_ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Caddy/forms/general.xml"
MODEL_PHP = CADDY_ROOT / "src/opnsense/mvc/app/models/OPNsense/Caddy/Caddy.php"
TEMPLATE = CADDY_ROOT / "src/opnsense/service/templates/OPNsense/Caddy/Caddyfile"

class Rfc2136DnsProviderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.general = ET.parse(MODEL).getroot().find("./items/general")
        if cls.general is None:
            raise AssertionError("Caddy general model not found")

    def test_provider_and_tsig_schema(self) -> None:
        provider = self.general.find("TlsDnsProvider/OptionValues/rfc2136")
        self.assertIsNotNone(provider)
        self.assertEqual(provider.text, "RFC2136")
        self.assertEqual(self.general.find("TlsDnsRfc2136Server").attrib["type"], "NetworkField")
        self.assertEqual(self.general.findtext("TlsDnsRfc2136Port/Default"), "53")
        key_name = self.general.find("TlsDnsRfc2136KeyName")
        self.assertEqual(key_name.attrib["type"], "TextField")
        self.assertEqual(key_name.findtext("Mask"), r"/^[0-9a-zA-Z_.\-]{1,255}$/u")
        algorithms = self.general.find("TlsDnsRfc2136KeyAlg/OptionValues")
        self.assertEqual(
            {node.tag for node in algorithms},
            {"hmac-sha512", "hmac-sha384", "hmac-sha256", "hmac-sha224", "hmac-sha1"},
        )
        self.assertEqual(self.general.find("TlsDnsRfc2136Key").attrib["type"], "Base64Field")

    def test_webui_hides_tsig_secret(self) -> None:
        fields = {
            field.findtext("id"): field.findtext("type")
            for field in ET.parse(FORM).getroot().iter("field")
            if field.find("id") is not None
        }
        self.assertEqual(fields["caddy.general.TlsDnsRfc2136Key"], "password")
        self.assertEqual(fields["caddy.general.TlsDnsRfc2136KeyAlg"], "dropdown")

    def test_model_requires_complete_rfc2136_configuration(self) -> None:
        model_php = MODEL_PHP.read_text()
        for field in (
            "TlsDnsRfc2136Server",
            "TlsDnsRfc2136Port",
            "TlsDnsRfc2136KeyName",
            "TlsDnsRfc2136KeyAlg",
            "TlsDnsRfc2136Key",
        ):
            self.assertIn(field, model_php)
        self.assertIn("TlsDnsProvider->isEqual('rfc2136')", model_php)

    def test_template_renders_structured_rfc2136_provider(self) -> None:
        template = TEMPLATE.read_text()
        self.assertIn('dnsProvider == "rfc2136"', template)
        self.assertIn('key_name "{{ rfc2136KeyName }}"', template)
        self.assertIn('key_alg "{{ rfc2136KeyAlg }}"', template)
        self.assertIn('key "{{ rfc2136Key }}"', template)
        self.assertIn("{% if ':' in rfc2136Server %}[{{ rfc2136Server }}]", template)
        self.assertIn('dns_provider_configuration("provider"', template)
        self.assertGreaterEqual(template.count('dns_provider_configuration("dns"'), 2)

if __name__ == "__main__":
    unittest.main()
