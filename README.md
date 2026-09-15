# Automated Malicious Document Scanner

A static-analysis security tool for identifying suspicious indicators in Microsoft Office documents, PDF files, and RTF content. It calculates a risk score from 0 to 100, highlights the most relevant findings, and produces both console and file-based reports.

This project is designed for defensive use: it inspects suspicious files without executing embedded macros or opening documents in Office or PDF viewers.

## Features

- Detects and analyzes:
  - Word, Excel, PowerPoint, and macro-enabled Office files
  - PDF files with script, launch, embedded-object, and form-based abuse indicators
  - RTF files containing suspicious OLE objects and exploitation patterns
- Uses magic-byte detection instead of relying only on file extension
- Produces a risk verdict:
  - CLEAN
  - LOW RISK
  - MEDIUM RISK
  - HIGH RISK
  - CRITICAL RISK
- Generates:
  - terminal-friendly text reports
  - JSON exports for automation or logging
  - HTML results for review and dashboards
- Includes a browser-based upload UI
- Supports bulk directory scanning for triage workflows

## Why this project exists

Document-based malware often hides harmful behavior in:

- VBA macro code
- XLM macro logic
- JavaScript embedded in PDFs
- Launch actions and embedded file triggers
- Exploit chains in RTF objects

The scanner focuses on those static artifacts and scores their risk based on suspicious behavior and exploit likelihood.

## Project structure

```text
mal_doc_scanner/
├── app.py                      # Flask web application
├── cli.py                      # Command-line entry point
├── requirements.txt            # Python dependencies
├── pyproject.toml              # Package metadata and config
├── README.md                   # Project documentation
├── samples/                    # Safe sample documents for testing
├── tests/                      # Smoke and regression tests
├── mal_doc_scanner/
│   ├── __init__.py
│   ├── __main__.py
│   ├── app.py
│   ├── cli.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── core.py
│   │   ├── file_detector.py
│   │   ├── risk_engine.py
│   │   ├── report.py
│   │   └── analyzers/
│   │       ├── __init__.py
│   │       ├── office_analyzer.py
│   │       ├── pdf_analyzer.py
│   │       └── rtf_analyzer.py
│   ├── static/
│   │   └── style.css
│   └── templates/
│       ├── index.html
│       └── result.html
└── .gitignore
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/mal_doc_scanner.git
cd mal_doc_scanner
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

On Windows:

```bash
.venv\Scripts\activate
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Quick start

### CLI scan of a single file

```bash
python cli.py scan samples/safe_suspicious_pdf.pdf
```

### Save JSON and HTML outputs

```bash
python cli.py scan samples/safe_suspicious_rtf.rtf --json report.json --html report.html
```

### Scan a folder recursively

```bash
python cli.py scan-dir samples --json bulk_report.json --html bulk_dashboard.html
```

Bulk scans can be filtered before JSON, HTML, and CSV exports are written:

```bash
python cli.py scan-dir samples/risk_samples --min-score 25 --max-score 60 --format pdf --json reports/filtered.json --html reports/filtered.html --csv reports/filtered.csv
```

Available filters are `--min-score`, `--max-score`, `--verdict`, and `--format`.
### Start the web UI

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

Upload one or multiple files through the browser and review either a detailed single-file report or a bulk results summary. The web uploader accepts up to 20 files per request and applies the 25 MB request limit.

## Risk scoring model

The scanner combines suspicious indicators from the document content and assigns a weighted score. The score is capped at 100.

| Score | Verdict |
|---|---|
| 0 | CLEAN |
| 1–24 | LOW RISK |
| 25–49 | MEDIUM RISK |
| 50–74 | HIGH RISK |
| 75–100 | CRITICAL RISK |

Common suspicious triggers include:

- `AutoExec` macro behaviors
- shell execution calls such as PowerShell, WScript, Shell
- URL download or persistence patterns
- embedded file execution indicators
- PDF JavaScript and Launch chains
- suspicious RTF package or equation editor objects

## Report outputs

The tool can generate:

- text-based console output
- JSON structured reports for integration workflows
- HTML pages and dashboard summaries for human review

This makes it suitable for both local triage and automation pipelines.

## Safety and limitations

This project is intended for defensive analysis and is designed to avoid executing suspicious content.

Important notes:

- It performs static analysis only
- It does not run macros or open files in a vulnerable environment
- It is heuristic-driven and may produce false positives in edge cases
- Password-protected or encrypted documents may be partially analyzable or unreadable without credentials

## Testing

Run the project test suite:

```bash
python -m unittest discover -s tests -v
```

## Demo risk tiers

The repository includes a sample set under [samples/risk_samples](samples/risk_samples) that demonstrates the full score spectrum:

- clean PDF
- clean RTF
- low PDF
- medium PDF
- high PDF
- critical PDF

A generated bulk dashboard and report are also saved under [reports](reports) so you can inspect multiple score bands in one place.

You can inspect them directly with:

```bash
python cli.py scan samples/risk_samples/clean.pdf
python cli.py scan samples/risk_samples/low.pdf
python cli.py scan samples/risk_samples/medium.pdf
python cli.py scan samples/risk_samples/high.pdf
python cli.py scan samples/risk_samples/critical.pdf
```
## Example usage in automation

The command-line interface exits with a non-zero code when suspicious findings reach a danger threshold, which makes it possible to use in triage scripts or CI-style checks.

## Contributing

Contributions are welcome. If you improve the scoring heuristics, add detection coverage, or clean up the UI, please submit a pull request with a clear description of the change and the validation performed.

## License

This project is provided for educational and defensive security research use. Please check the repository license file before commercial or production deployment.
