import tempfile
import unittest
from pathlib import Path

from mal_doc_scanner.scanner.core import scan_file, scan_directory
from mal_doc_scanner.scanner.risk_engine import assess_risk


class ScanModelTests(unittest.TestCase):
    def test_suspicious_pdf_raises_risk(self):
        suspicious_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R /JavaScript 4 0 R >>\nendobj\n3 0 obj\n<< /S /JavaScript /JS (alert(1)) >>\nendobj\n4 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.pdf"
            path.write_bytes(suspicious_pdf)
            report = scan_file(str(path))

        self.assertGreaterEqual(report["score"], 25)
        self.assertIn(report["verdict"], {"MEDIUM RISK", "HIGH RISK", "CRITICAL RISK"})

    def test_assess_risk_message_for_high_score(self):
        verdict, color, summary = assess_risk(85)
        self.assertEqual(verdict, "CRITICAL RISK")
        self.assertIn("Critical concern", summary)
        self.assertTrue(color.startswith("#"))

    def test_rtf_package_markers_score_above_zero(self):
        suspicious_rtf = (
            "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}"
            "\\viewkind4\\uc1\\pard\\f0\\fs24 Test\\par"
            "{\\*\\object\\objclass Package\\objname package\\objdata 010203}"
            "\\par}"
        ).encode("latin-1")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.rtf"
            path.write_bytes(suspicious_rtf)
            report = scan_file(str(path))

        self.assertGreater(report["score"], 0)
        self.assertIn("rtf", report["detected_format"])

    def test_scan_directory_dashboard_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "scanme.pdf"
            sample.write_bytes(b"%PDF-1.4\n<< /OpenAction 3 0 R /JavaScript 4 0 R >>\n")
            result = scan_directory(tmpdir)
            self.assertTrue(result)
            self.assertGreaterEqual(result[0]["score"], 0)


if __name__ == "__main__":
    unittest.main()
