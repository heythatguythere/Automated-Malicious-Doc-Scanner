"""
core.py
--------
Top-level orchestration: identify file type, dispatch to the correct
analyzer, compute hashes, and assemble a unified scan report.
"""

import os
import hashlib
from datetime import datetime, timezone

try:
    from .file_detector import detect_file_type
    from .analyzers.office_analyzer import analyze_office_file
    from .analyzers.rtf_analyzer import analyze_rtf_file
    from .analyzers.pdf_analyzer import analyze_pdf_file
    from .risk_engine import compute_verdict
except ImportError:  # pragma: no cover - direct script execution fallback
    from scanner.file_detector import detect_file_type
    from scanner.analyzers.office_analyzer import analyze_office_file
    from scanner.analyzers.rtf_analyzer import analyze_rtf_file
    from scanner.analyzers.pdf_analyzer import analyze_pdf_file
    from scanner.risk_engine import compute_verdict

SUPPORTED_EXTENSIONS = {
    ".doc", ".docx", ".docm", ".dot", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlt", ".xltm",
    ".ppt", ".pptx", ".pptm",
    ".rtf", ".pdf",
}


def compute_hashes(filepath: str):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def scan_file(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"No such file: {filepath}")

    file_type = detect_file_type(filepath)
    md5, sha256 = compute_hashes(filepath)
    size = os.path.getsize(filepath)

    report = {
        "filename": os.path.basename(filepath),
        "size_bytes": size,
        "md5": md5,
        "sha256": sha256,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "detected_format": file_type,
        "analysis": None,
        "score": 0,
        "verdict": None,
        "verdict_color": None,
    }

    if file_type in ("ole", "ooxml"):
        analysis = analyze_office_file(filepath)
        report["score"] = analysis.get("macro_score", 0)
    elif file_type == "rtf":
        analysis = analyze_rtf_file(filepath)
        report["score"] = analysis.get("score", 0)
    elif file_type == "pdf":
        analysis = analyze_pdf_file(filepath)
        report["score"] = analysis.get("score", 0)
    else:
        analysis = {
            "file_type": "Unknown / Unsupported",
            "errors": [
                f"File signature did not match any supported format "
                f"(detected: '{file_type}'). Supported: Word/Excel/PowerPoint "
                f"(.doc/.docx/.xls/.xlsx/.ppt/.pptx and macro-enabled variants), RTF, PDF."
            ],
        }
        report["score"] = 0

    report["analysis"] = analysis
    verdict, color = compute_verdict(report["score"])
    report["verdict"] = verdict
    report["verdict_color"] = color
    return report


def scan_directory(dirpath: str, extensions=None, html_path=None, csv_path=None) -> list:
    exts = extensions or SUPPORTED_EXTENSIONS
    results = []
    for root, _dirs, files in os.walk(dirpath):
        for fname in files:
            if os.path.splitext(fname)[1].lower() in exts:
                fpath = os.path.join(root, fname)
                try:
                    results.append(scan_file(fpath))
                except Exception as e:
                    results.append({"filename": fname, "error": str(e)})

    if html_path:
        try:
            from mal_doc_scanner.scanner.report import save_directory_dashboard
        except ImportError:  # pragma: no cover - direct execution fallback
            from scanner.report import save_directory_dashboard
        save_directory_dashboard(results, html_path)

    if csv_path:
        try:
            from mal_doc_scanner.scanner.report import save_csv_report
        except ImportError:  # pragma: no cover - direct execution fallback
            from scanner.report import save_csv_report
        save_csv_report(results, csv_path)

    return results
