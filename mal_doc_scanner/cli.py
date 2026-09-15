#!/usr/bin/env python3
"""
cli.py
-------
Command-line entry point for the Automated Malicious Document Scanner.

Usage:
    python cli.py scan path/to/file.docx
    python cli.py scan path/to/file.pdf --json report.json --html report.html
    python cli.py scan-dir path/to/folder --json combined_report.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

try:
    from .scanner.core import scan_file, scan_directory
    from .scanner.report import print_report, save_json_report, save_html_report
except ImportError:  # pragma: no cover - direct script execution fallback
    from scanner.core import scan_file, scan_directory
    from scanner.report import print_report, save_json_report, save_html_report


def main():
    parser = argparse.ArgumentParser(
        prog="mds-scan",
        description="Automated Malicious Document Scanner - detects embedded macros "
                     "and exploit indicators in PDF, Word, Excel, PowerPoint and RTF files."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_file = sub.add_parser("scan", help="Scan a single file")
    p_file.add_argument("path", help="Path to the document to scan")
    p_file.add_argument("--json", help="Save JSON report to this path")
    p_file.add_argument("--html", help="Save HTML report to this path")

    p_dir = sub.add_parser("scan-dir", help="Scan all supported files in a directory (recursive)")
    p_dir.add_argument("path", help="Directory to scan")
    p_dir.add_argument("--json", help="Save combined JSON report to this path")
    p_dir.add_argument("--html", help="Save a bulk dashboard HTML report to this path")

    args = parser.parse_args()

    if args.command == "scan":
        if not os.path.isfile(args.path):
            print(f"Error: file not found: {args.path}")
            sys.exit(1)
        report = scan_file(args.path)
        print_report(report)
        if args.json:
            save_json_report(report, args.json)
            print(f"\n[+] JSON report saved to {args.json}")
        if args.html:
            save_html_report(report, args.html)
            print(f"[+] HTML report saved to {args.html}")

        # Non-zero exit code when risk is detected - useful for CI/automation hooks
        sys.exit(1 if report["score"] >= 25 else 0)

    elif args.command == "scan-dir":
        if not os.path.isdir(args.path):
            print(f"Error: directory not found: {args.path}")
            sys.exit(1)
        reports = scan_directory(args.path, html_path=args.html)
        any_risky = False
        for r in reports:
            print_report(r)
            print("-" * 70)
            if r.get("score", 0) >= 25:
                any_risky = True
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({
                    "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "summary": {
                        "total_files": len(reports),
                        "risky_files": sum(1 for r in reports if r.get("score", 0) >= 25),
                        "max_score": max((r.get("score", 0) for r in reports), default=0),
                    },
                    "files": reports,
                }, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Combined JSON report saved to {args.json}")
        if args.html:
            print(f"\n[+] Bulk dashboard saved to {args.html}")
        sys.exit(1 if any_risky else 0)


if __name__ == "__main__":
    main()
