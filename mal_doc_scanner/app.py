#!/usr/bin/env python3
"""
app.py
-------
Flask web UI for the Automated Malicious Document Scanner.
Upload a document in the browser and get an instant risk report.

Run with:
    python app.py
Then open http://127.0.0.1:5000
"""

import os
import sys
import tempfile
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

try:
    from .scanner.core import scan_file
except ImportError:  # pragma: no cover - direct script execution fallback
    from scanner.core import scan_file

app = Flask(__name__)
app.secret_key = os.environ.get("SCANNER_SECRET_KEY", "dev-secret-key-change-me")
app.config.update(
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    JSON_SORT_KEYS=False,
)

ALLOWED_EXTENSIONS = {
    "doc", "docx", "docm", "dot", "dotm",
    "xls", "xlsx", "xlsm", "xlt", "xltm",
    "ppt", "pptx", "pptm",
    "rtf", "pdf",
}


@app.errorhandler(413)
def file_too_large(_error):
    flash("The uploaded file is too large. Maximum supported size is 25 MB.")
    return redirect(url_for("index"))


def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    if "document" not in request.files or request.files["document"].filename == "":
        flash("Please choose a file to scan.")
        return redirect(url_for("index"))

    file = request.files["document"]
    original_name = file.filename or ""

    if not allowed_file(original_name):
        flash("Unsupported file type. Allowed: Word, Excel, PowerPoint, RTF, or PDF.")
        return redirect(url_for("index"))

    safe_name = secure_filename(original_name)
    if not safe_name:
        flash("The uploaded file name is invalid.")
        return redirect(url_for("index"))

    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, safe_name)
        file.save(filepath)
        try:
            report = scan_file(filepath)
        except Exception as exc:  # pragma: no cover - scanner exceptions are surfaced to user
            flash(f"Scan failed: {exc}")
            return redirect(url_for("index"))

    return render_template("result.html", report=report)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}, host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
