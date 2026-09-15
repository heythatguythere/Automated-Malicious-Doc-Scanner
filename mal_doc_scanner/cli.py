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
    from .scanner.report import print_report, save_json_report, save_html_report, filter_reports
except ImportError:  # pragma: no cover - direct script execution fallback
    from scanner.core import scan_file, scan_directory
    from scanner.report import print_report, save_json_report, save_html_report, filter_reports


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
    p_file.add_argument("--csv", help="Save CSV report to this path")

    p_dir = sub.add_parser("scan-dir", help="Scan all supported files in a directory (recursive)")
    p_dir.add_argument("path", help="Directory to scan")
    p_dir.add_argument("--json", help="Save combined JSON report to this path")
    p_dir.add_argument("--html", help="Save a bulk dashboard HTML report to this path")
    p_dir.add_argument("--csv", help="Save bulk CSV report to this path")
    p_dir.add_argument("--min-score", type=int, default=0, help="Include only reports at or above this score")
    p_dir.add_argument("--max-score", type=int, default=100, help="Include only reports at or below this score")
    p_dir.add_argument("--verdict", help="Include only reports with this verdict")
    p_dir.add_argument("--format", dest="format_filter", help="Include only this detected format")

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
        if args.csv:
            import csv as _csv
            with open(args.csv, "w", newline="", encoding="utf-8") as fh:
                writer = _csv.DictWriter(fh, fieldnames=["filename", "detected_format", "score", "verdict", "size_bytes", "md5", "sha256", "scanned_at"])
                writer.writeheader()
                writer.writerow({
                    "filename": report.get("filename", ""),
                    "detected_format": report.get("detected_format", ""),
                    "score": report.get("score", 0),
                    "verdict": report.get("verdict", ""),
                    "size_bytes": report.get("size_bytes", 0),
                    "md5": report.get("md5", ""),
                    "sha256": report.get("sha256", ""),
                    "scanned_at": report.get("scanned_at", ""),
                })
            print(f"[+] CSV report saved to {args.csv}")

        # Non-zero exit code when risk is detected - useful for CI/automation hooks
        sys.exit(1 if report["score"] >= 25 else 0)

    elif args.command == "scan-dir":
        if not os.path.isdir(args.path):
            print(f"Error: directory not found: {args.path}")
            sys.exit(1)
        reports = scan_directory(args.path)
        filtered_reports = filter_reports(
            reports,
            min_score=args.min_score,
            max_score=args.max_score,
            verdict=args.verdict,
            format_filter=args.format_filter,
        )
        any_risky = False
        for r in filtered_reports:
            print_report(r)
            print("-" * 70)
            if r.get("score", 0) >= 25:
                any_risky = True
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({
                    "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "summary": {
                        "total_files": len(filtered_reports),
                        "risky_files": sum(1 for r in filtered_reports if r.get("score", 0) >= 25),
                        "max_score": max((r.get("score", 0) for r in filtered_reports), default=0),
                    },
                    "filters": {
                        "min_score": args.min_score,
                        "max_score": args.max_score,
                        "verdict": args.verdict,
                        "format": args.format_filter,
                    },
                    "files": filtered_reports,
                }, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Combined JSON report saved to {args.json}")
        if args.html:
            try:
                from .scanner.report import save_directory_dashboard
            except ImportError:  # pragma: no cover - direct script execution fallback
                from scanner.report import save_directory_dashboard
            save_directory_dashboard(filtered_reports, args.html)
            print(f"\n[+] Bulk dashboard saved to {args.html}")
        if args.csv:
            try:
                from .scanner.report import save_csv_report
            except ImportError:  # pragma: no cover - direct script execution fallback
                from scanner.report import save_csv_report
            save_csv_report(filtered_reports, args.csv)
            print(f"[+] Bulk CSV report saved to {args.csv}")
        sys.exit(1 if any_risky else 0)


if __name__ == "__main__":
    main()
