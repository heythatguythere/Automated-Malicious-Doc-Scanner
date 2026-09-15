import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProjectSmokeTests(unittest.TestCase):
    def test_root_entry_points_exist(self):
        self.assertTrue((ROOT / "app.py").exists())
        self.assertTrue((ROOT / "cli.py").exists())
        self.assertTrue((ROOT / "requirements.txt").exists())

    def test_app_module_works(self):
        app_path = ROOT / "mal_doc_scanner" / "app.py"
        self.assertTrue(app_path.exists())

        spec = importlib.util.spec_from_file_location("mal_doc_scanner_app", app_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertTrue(module.allowed_file("report.pdf"))
        self.assertTrue(module.allowed_file("note.DOCX"))
        self.assertFalse(module.allowed_file("notes.txt"))


if __name__ == "__main__":
    unittest.main()
