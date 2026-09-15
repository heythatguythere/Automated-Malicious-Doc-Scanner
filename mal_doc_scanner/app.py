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

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ModuleNotFoundError:  # pragma: no cover - optional in minimal installs
    class Limiter:  # type: ignore[override]
        def __init__(self, *args, **kwargs):
            self._default_limits = kwargs.get("default_limits", [])

        def limit(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

    def get_remote_address(*args, **kwargs):
        return "127.0.0.1"
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
    MAX_UPLOAD_FILES=20,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    JSON_SORT_KEYS=False,
    PROPAGATE_EXCEPTIONS=False,
    MAX_FORM_MEMORY_SIZE=2 * 1024 * 1024,
)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
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
@limiter.limit("10 per minute")
def scan():
    files = request.files.getlist("documents") or request.files.getlist("document")
    files = [uploaded for uploaded in files if uploaded.filename]
    if not files:
        flash("Please choose a file to scan.")
        return redirect(url_for("index"))

    if len(files) > app.config["MAX_UPLOAD_FILES"]:
        flash(f"Please upload no more than {app.config['MAX_UPLOAD_FILES']} files at once.")
        return redirect(url_for("index"))

    with tempfile.TemporaryDirectory() as tmpdir:
        reports = []
        for index, uploaded in enumerate(files):
            original_name = uploaded.filename or ""
            if not allowed_file(original_name):
                reports.append({"filename": original_name, "error": "Unsupported file type."})
                continue

            safe_name = secure_filename(original_name)
            if not safe_name:
                reports.append({"filename": original_name, "error": "Invalid file name."})
                continue

            filepath = os.path.join(tmpdir, f"{index}_{safe_name}")
            uploaded.save(filepath)
            try:
                report = scan_file(filepath)
                report["filename"] = original_name
                reports.append(report)
            except Exception as exc:  # pragma: no cover - scanner exceptions are surfaced to user
                reports.append({"filename": original_name, "error": f"Scan failed: {exc}"})

    if len(reports) == 1:
        if "error" in reports[0]:
            flash(reports[0]["error"])
            return redirect(url_for("index"))
        return render_template("result.html", report=reports[0])
    return render_template("bulk_result.html", reports=reports)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}, host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
