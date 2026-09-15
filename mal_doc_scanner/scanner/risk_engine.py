"""
risk_engine.py
---------------
Maps a numeric 0-100 risk score (produced by the format-specific analyzers)
onto a human-readable verdict band with an associated color, used across
the CLI and web report.
"""

VERDICT_BANDS = [
    (0, 0, "CLEAN", "#2e7d32"),
    (1, 24, "LOW RISK", "#9e9d24"),
    (25, 49, "MEDIUM RISK", "#e65100"),
    (50, 74, "HIGH RISK", "#c62828"),
    (75, 100, "CRITICAL RISK", "#8e0000"),
]


def confidence_from_weight(weight: int) -> str:
    if weight >= 20:
        return "high"
    if weight >= 8:
        return "medium"
    return "low"


def compute_verdict(score: int):
    score = max(0, min(100, int(score)))
    for lo, hi, label, color in VERDICT_BANDS:
        if lo <= score <= hi:
            return label, color
    return "UNKNOWN", "#616161"


def assess_risk(score: int):
    score = max(0, min(100, int(score)))
    verdict, color = compute_verdict(score)
    if score == 0:
        return verdict, color, "No suspicious indicators were detected."
    if score < 25:
        return verdict, color, "Low confidence signal: the file contains a minor suspicious pattern but no clear execution vector."
    if score < 50:
        return verdict, color, "Moderate concern: suspicious execution or persistence signals were observed."
    if score < 75:
        return verdict, color, "High concern: the document contains multiple strong behavioral indicators of malicious behavior."
    return verdict, color, "Critical concern: the file shows several severe exploit indicators and should be treated as high risk."
