import csv
import tempfile
import unittest
from pathlib import Path

from mal_doc_scanner.scanner.core import scan_file
from mal_doc_scanner.scanner.report import save_csv_report


class ProductionFeatureTests(unittest.TestCase):
    def test_findings_include_confidence_level(self):
        suspicious_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R /JavaScript 4 0 R >>\nendobj\n3 0 obj\n<< /S /JavaScript /JS (alert(1)) >>\nendobj\n4 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "feature.pdf"
            path.write_bytes(suspicious_pdf)
            report = scan_file(str(path))

        self.assertIn("findings", report["analysis"])
        self.assertTrue(report["analysis"]["findings"]) 
        first = report["analysis"]["findings"][0]
        self.assertIn("confidence", first)
        self.assertIn(first["confidence"], {"low", "medium", "high"})

    def test_csv_export_writes_bulk_rows(self):
        report = {
            "filename": "demo.pdf",
            "detected_format": "pdf",
            "score": 42,
            "verdict": "MEDIUM RISK",
            "size_bytes": 128,
            "md5": "abc",
            "sha256": "def",
            "scanned_at": "2026-01-01T00:00:00Z",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "bulk.csv"
            save_csv_report([report], str(csv_path))
            with csv_path.open("r", newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["filename"], "demo.pdf")
        self.assertEqual(rows[0]["score"], "42")


if __name__ == "__main__":
    unittest.main()
