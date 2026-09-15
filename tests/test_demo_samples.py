import json
import unittest
from pathlib import Path

from mal_doc_scanner.scanner.core import scan_file


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples" / "risk_samples"
CATALOG = SAMPLES / "catalog.json"


class DemoSamplesTests(unittest.TestCase):
    def test_sample_catalog_exists_and_has_risk_tiers(self):
        self.assertTrue(CATALOG.exists(), "Expected a generated sample catalog in samples/risk_samples/")
        with CATALOG.open("r", encoding="utf-8") as fh:
            catalog = json.load(fh)
        self.assertIn("clean", catalog)
        self.assertIn("low", catalog)
        self.assertIn("medium", catalog)
        self.assertIn("high", catalog)
        self.assertIn("critical", catalog)

    def test_each_demo_sample_has_expected_score_band(self):
        with CATALOG.open("r", encoding="utf-8") as fh:
            catalog = json.load(fh)

        for name, meta in catalog.items():
            path = SAMPLES / meta["file"]
            self.assertTrue(path.exists(), f"Missing sample file: {path}")
            report = scan_file(str(path))
            score = report["score"]
            low, high = meta["band"]
            self.assertGreaterEqual(score, low, f"{name} score below expected band: {score}")
            self.assertLessEqual(score, high, f"{name} score above expected band: {score}")


if __name__ == "__main__":
    unittest.main()
