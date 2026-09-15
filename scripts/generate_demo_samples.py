import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT / "samples" / "risk_samples"
CATALOG = {
    "clean": {"file": "clean.pdf", "band": [0, 0]},
    "low": {"file": "low.pdf", "band": [1, 24]},
    "medium": {"file": "medium.pdf", "band": [25, 49]},
    "high": {"file": "high.pdf", "band": [50, 74]},
    "critical": {"file": "critical.pdf", "band": [75, 100]},
}

SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
(SAMPLE_DIR / "catalog.json").write_text(json.dumps(CATALOG, indent=2), encoding="utf-8")
print(f"Created demo sample catalog at {SAMPLE_DIR / 'catalog.json'}")
