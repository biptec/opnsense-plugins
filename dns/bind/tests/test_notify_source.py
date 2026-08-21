import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "src/opnsense/mvc/app/models/OPNsense/Bind/General.xml"
FORM = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Bind/forms/general.xml"
TEMPLATE = ROOT / "src/opnsense/service/templates/OPNsense/Bind/named.conf"


class NotifySourceTest(unittest.TestCase):
    def test_model_exposes_ipv4_and_ipv6_notify_source(self):
        root = ET.parse(MODEL).getroot().find("./items")
        self.assertIsNotNone(root)
        for name, family in (("notifysource", "ipv4"), ("notifysourcev6", "ipv6")):
            field = root.find(name)
            self.assertIsNotNone(field)
            self.assertEqual(field.attrib.get("type"), "NetworkField")
            self.assertEqual(field.findtext("AddressFamily"), family)
            self.assertEqual(field.findtext("NetMaskAllowed"), "N")

    def test_webui_exposes_notify_source_fields(self):
        form = FORM.read_text()
        self.assertIn("<id>general.notifysource</id>", form)
        self.assertIn("<id>general.notifysourcev6</id>", form)

    def test_template_renders_notify_source_options(self):
        template = TEMPLATE.read_text()
        self.assertIn("notify-source {{ OPNsense.bind.general.notifysource }};", template)
        self.assertIn("notify-source-v6 {{ OPNsense.bind.general.notifysourcev6 }};", template)


if __name__ == "__main__":
    unittest.main()
