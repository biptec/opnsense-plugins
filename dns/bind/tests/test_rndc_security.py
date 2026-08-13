#!/usr/bin/env python3

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODEL = ROOT / "src/opnsense/mvc/app/models/OPNsense/Bind/General.xml"
FORM = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Bind/forms/general.xml"
CONTROLLER = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/Bind/Api/GeneralController.php"
MIGRATION = ROOT / "src/opnsense/mvc/app/models/OPNsense/Bind/Migrations/M1_0_13.php"


class RndcSecurityContractTests(unittest.TestCase):
    def test_model_has_no_static_rndc_default(self):
        model = ET.parse(MODEL).getroot()
        self.assertEqual(model.findtext("version"), "1.0.13")
        field = model.find("./items/rndcsecret")
        self.assertIsNotNone(field)
        self.assertEqual(field.findtext("Required"), "Y")
        self.assertIsNone(field.find("Default"))

    def test_form_treats_rndc_secret_as_password(self):
        form = ET.parse(FORM).getroot()
        fields = {field.findtext("id"): field for field in form.findall("field")}
        secret = fields["general.rndcsecret"]
        self.assertEqual(secret.findtext("type"), "password")

    def test_api_does_not_return_secret_and_blank_update_preserves_it(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("unset($nodes['rndcsecret']);", controller)
        self.assertIn("$currentSecret = (string)$model->rndcsecret;", controller)
        self.assertIn("$settings['rndcsecret'] = $currentSecret;", controller)

    def test_migration_rotates_empty_and_legacy_default(self):
        migration = MIGRATION.read_text(encoding="utf-8")
        self.assertIn("hash_equals(self::LEGACY_DEFAULT_SHA256, hash('sha256', $current))", migration)
        self.assertIn("base64_encode(random_bytes(32))", migration)
        self.assertIn("$current === ''", migration)


if __name__ == "__main__":
    unittest.main()
