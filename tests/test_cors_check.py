import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cors_check import classify, probe_origins

URL = "https://api.example.com/me"
EVIL = "https://evil-attacker.example"


class ClassifyTests(unittest.TestCase):
    def test_reflection_with_credentials_is_critical(self):
        finding = classify(URL, EVIL, EVIL, "true")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")

    def test_reflection_without_credentials_is_high(self):
        finding = classify(URL, EVIL, EVIL, None)
        self.assertEqual(finding.severity, "high")

    def test_wildcard_without_credentials_is_info(self):
        finding = classify(URL, EVIL, "*", None)
        self.assertEqual(finding.severity, "info")

    def test_wildcard_with_credentials_is_critical(self):
        finding = classify(URL, EVIL, "*", "true")
        self.assertEqual(finding.severity, "critical")

    def test_null_origin_trusted_is_high_with_credentials(self):
        finding = classify(URL, "null", "null", "true")
        self.assertEqual(finding.severity, "high")

    def test_no_acao_header_is_clean(self):
        self.assertIsNone(classify(URL, EVIL, None, None))

    def test_unrelated_acao_is_clean(self):
        self.assertIsNone(classify(URL, EVIL, "https://partner.example.org", "true"))


class ProbeOriginTests(unittest.TestCase):
    def test_probes_cover_key_cases(self):
        probes = dict(probe_origins(URL))
        values = list(probes.values())
        self.assertIn("null", values)
        self.assertIn(EVIL, values)
        self.assertTrue(any("evil.api.example.com" in v for v in values))
        self.assertTrue(any("api.example.com.evil-attacker.example" in v for v in values))


if __name__ == "__main__":
    unittest.main()
