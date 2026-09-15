"""
report.py
----------
Rendering helpers for scan reports: a readable console printout, a JSON
exporter, and a standalone HTML report generator (independent of the
Flask template, so the CLI can produce a shareable single-file report).
"""

import csv
import json


def _build_summary(reports):
    summary = {
        "total_files": len(reports),
        "clean": 0,
        "low_risk": 0,
        "medium_risk": 0,
        "high_risk": 0,
        "critical_risk": 0,
        "max_score": 0,
    }

    for item in reports:
        if "score" not in item:
            continue
        score = int(item.get("score", 0))
        summary["max_score"] = max(summary["max_score"], score)
        if score == 0:
            summary["clean"] += 1
        elif score < 25:
            summary["low_risk"] += 1
        elif score < 50:
            summary["medium_risk"] += 1
        elif score < 75:
            summary["high_risk"] += 1
        else:
            summary["critical_risk"] += 1
    return summary


def print_report(report: dict) -> None:
    if "error" in report and "analysis" not in report:
        print(f"[!] {report.get('filename', '?')}: ERROR - {report['error']}")
        return

    print("=" * 70)
    print(f"File        : {report['filename']}")
    print(f"Size        : {report['size_bytes']} bytes")
    print(f"Format      : {report['detected_format']}")
    print(f"MD5         : {report['md5']}")
    print(f"SHA256      : {report['sha256']}")
    print(f"Scanned at  : {report['scanned_at']}")
    print(f"Risk score  : {report['score']} / 100")
    print(f"Verdict     : {report['verdict']}")
    print("-" * 70)

    analysis = report.get("analysis") or {}
    errors = analysis.get("errors") or []
    for err in errors:
        print(f"  [!] {err}")

    if "findings" in analysis:  # office
        if analysis.get("has_macros"):
            print(f"  Macros detected: YES  ({len(analysis['findings'])} indicator(s))")
            for f in analysis["findings"][:25]:
                print(f"    - [{f['type']}] {f['keyword']!r} (+{f['weight']}) - {f['description']}")
            if len(analysis["findings"]) > 25:
                print(f"    ... and {len(analysis['findings']) - 25} more")
            if analysis.get("iocs"):
                print(f"  Extracted IOCs: {', '.join(sorted(set(analysis['iocs'])))}")
        else:
            print("  Macros detected: NO")

    if "suspicious_objects" in analysis:  # rtf
        print(f"  Embedded objects: {analysis.get('embedded_objects', 0)}")
        for obj in analysis["suspicious_objects"]:
            print(f"    - {obj['class_name']}: {obj['note']}")

    if "object_count" in analysis:  # pdf
        print(f"  PDF objects: {analysis.get('object_count', 0)}")
        for ind in analysis.get("indicators", []):
            print(f"    - {ind['name']} x{ind['count']} (+{ind['weight']}) - {ind['description']}")

    print("=" * 70)


def save_json_report(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def save_csv_report(reports: list, path: str) -> None:
    fieldnames = ["filename", "detected_format", "score", "verdict", "size_bytes", "md5", "sha256", "scanned_at"]
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for report in reports:
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


def filter_reports(reports: list, *, min_score: int = 0, max_score: int = 100, verdict: str | None = None, format_filter: str | None = None) -> list:
    filtered = []
    for report in reports:
        score = int(report.get("score", 0))
        if score < min_score or score > max_score:
            continue
        if verdict and str(report.get("verdict", "")).upper() != verdict.upper():
            continue
        if format_filter and str(report.get("detected_format", "")).lower() != format_filter.lower():
            continue
        filtered.append(report)
    return filtered


def generate_directory_dashboard(reports: list, title: str = "Bulk Scan Dashboard") -> str:
    summary = _build_summary(reports)
    rows = []
    for item in reports:
        score = int(item.get("score", 0))
        verdict = item.get("verdict", "UNKNOWN")
        rows.append(
            f"<tr><td>{item.get('filename', '?')}</td><td>{item.get('detected_format', 'unknown')}</td><td>{score}</td><td>{verdict}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<title>{title}</title>
<style>
 body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 32px; }}
 .wrap {{ max-width: 1100px; margin: 0 auto; }}
 .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }}
 .card {{ background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 18px; }}
 .label {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
 .value {{ font-size: 28px; font-weight: 700; margin-top: 8px; }}
 table {{ width: 100%; border-collapse: collapse; margin-top: 18px; }}
 th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; }}
 th {{ color: #94a3b8; }}
</style>
</head>
<body>
  <div class=\"wrap\">
    <h1>{title}</h1>
    <div class=\"cards\">
      <div class=\"card\"><div class=\"label\">Total files</div><div class=\"value\">{summary['total_files']}</div></div>
      <div class=\"card\"><div class=\"label\">Clean</div><div class=\"value\">{summary['clean']}</div></div>
      <div class=\"card\"><div class=\"label\">Low</div><div class=\"value\">{summary['low_risk']}</div></div>
      <div class=\"card\"><div class=\"label\">Medium</div><div class=\"value\">{summary['medium_risk']}</div></div>
      <div class=\"card\"><div class=\"label\">High</div><div class=\"value\">{summary['high_risk']}</div></div>
      <div class=\"card\"><div class=\"label\">Critical</div><div class=\"value\">{summary['critical_risk']}</div></div>
    </div>

    <table>
      <thead><tr><th>Filename</th><th>Format</th><th>Score</th><th>Verdict</th></tr></thead>
      <tbody>{''.join(rows) or '<tr><td colspan="4">No files scanned.</td></tr>'}</tbody>
    </table>
  </div>
</body>
</html>
"""


def save_directory_dashboard(reports: list, path: str, title: str = "Bulk Scan Dashboard") -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(generate_directory_dashboard(reports, title=title))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan Report - {filename}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:40px; }}
  .card {{ max-width:900px; margin:0 auto; background:#171a21; border-radius:10px; padding:30px; box-shadow:0 4px 20px rgba(0,0,0,0.5); }}
  h1 {{ font-size:20px; color:#8ab4f8; margin-top:0; }}
  .badge {{ display:inline-block; padding:6px 16px; border-radius:20px; font-weight:bold; color:#fff; background:{color}; }}
  table {{ width:100%; border-collapse: collapse; margin-top:20px; }}
  td, th {{ text-align:left; padding:8px 10px; border-bottom:1px solid #2a2e37; font-size:14px; }}
  th {{ color:#9aa0a6; font-weight:600; }}
  .mono {{ font-family: Consolas, monospace; font-size:13px; color:#c9d1d9; }}
  .finding {{ background:#1e222b; margin:6px 0; padding:10px 14px; border-left:3px solid {color}; border-radius:4px; font-size:13px;}}
</style>
</head>
<body>
  <div class="card">
    <h1>Automated Malicious Document Scanner - Report</h1>
    <p><b>File:</b> {filename} &nbsp; <span class="badge">{verdict} ({score}/100)</span></p>
    <table>
      <tr><th>Detected format</th><td>{detected_format}</td></tr>
      <tr><th>Size</th><td>{size_bytes} bytes</td></tr>
      <tr><th>MD5</th><td class="mono">{md5}</td></tr>
      <tr><th>SHA256</th><td class="mono">{sha256}</td></tr>
      <tr><th>Scanned at (UTC)</th><td>{scanned_at}</td></tr>
    </table>
    <h2 style="margin-top:30px; font-size:16px; color:#8ab4f8;">Findings</h2>
    {findings_html}
  </div>
</body>
</html>
"""


def _findings_html(report: dict) -> str:
    analysis = report.get("analysis") or {}
    color = report.get("verdict_color", "#616161")
    parts = []

    for err in analysis.get("errors", []):
        parts.append(f'<div class="finding">[!] {err}</div>')

    for f in analysis.get("findings", []):
        parts.append(
            f'<div class="finding"><b>[{f["type"]}]</b> {f["keyword"]} '
            f'(+{f["weight"]}) - {f["description"]}</div>'
        )
    for obj in analysis.get("suspicious_objects", []):
        parts.append(f'<div class="finding"><b>{obj["class_name"]}</b> - {obj["note"]}</div>')
    for ind in analysis.get("indicators", []):
        parts.append(
            f'<div class="finding"><b>{ind["name"]}</b> x{ind["count"]} '
            f'(+{ind["weight"]}) - {ind["description"]}</div>'
        )

    if not parts:
        parts.append('<div class="finding">No suspicious indicators found.</div>')

    return "\n".join(parts)


def save_html_report(report: dict, path: str) -> None:
    html = _HTML_TEMPLATE.format(
        filename=report["filename"],
        color=report.get("verdict_color", "#616161"),
        verdict=report["verdict"],
        score=report["score"],
        detected_format=report["detected_format"],
        size_bytes=report["size_bytes"],
        md5=report["md5"],
        sha256=report["sha256"],
        scanned_at=report["scanned_at"],
        findings_html=_findings_html(report),
    )
    with open(path, "w") as f:
        f.write(html)
