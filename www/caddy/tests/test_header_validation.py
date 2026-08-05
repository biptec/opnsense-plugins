from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


CADDY_ROOT = Path(__file__).resolve().parents[1]
MODEL = CADDY_ROOT / "src/opnsense/mvc/app/models/OPNsense/Caddy/Caddy.xml"


class HeaderValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = ET.parse(MODEL).getroot()
        cls.header = next(
            (node for node in cls.root.iter("header") if node.find("HeaderType") is not None),
            None,
        )
        if cls.header is None:
            raise AssertionError("Caddy header model not found")

    def field(self, name: str) -> ET.Element:
        field = self.header.find(name)
        self.assertIsNotNone(field, f"missing {name}")
        return field

    def test_plugin_patch_version(self) -> None:
        makefile = (CADDY_ROOT / "Makefile").read_text()
        self.assertIn("PLUGIN_VERSION=\t\t2.1.1", makefile)
    def test_header_type_is_single_safe_token(self) -> None:
        field = self.field("HeaderType")
        self.assertEqual(field.findtext("AllowSpaces"), "N")
        self.assertEqual(field.findtext("AllowNewlines"), "N")
        self.assertEqual(field.findtext("AllowSpecial"), "N")
        self.assertEqual(
            field.findtext("Mask"),
            "/^([!#$%&'*+.^_`|~0-9A-Za-z-]{1,1024})$/u",
        )

    def test_values_reject_control_characters(self) -> None:
        expected_mask = '/^([^"]{0,1024})$/u'
        for name in ("HeaderValue", "HeaderReplace"):
            with self.subTest(name=name):
                field = self.field(name)
                self.assertEqual(field.findtext("AllowNewlines"), "N")
                self.assertEqual(field.findtext("AllowSpecial"), "N")
                self.assertEqual(field.findtext("Mask"), expected_mask)


if __name__ == "__main__":
    unittest.main()
