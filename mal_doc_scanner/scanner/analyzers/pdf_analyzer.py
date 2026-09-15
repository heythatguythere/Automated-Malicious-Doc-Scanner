"""
pdf_analyzer.py
----------------
Lightweight, dependency-free static analyzer for PDF files. It never
renders, opens in a viewer, or executes anything in the PDF - it only
performs byte-level pattern matching over the raw file content, which is
the same technique used by well-known tools like Didier Stevens' pdfid.

We look for structural/keyword indicators that are strongly correlated
with weaponized PDFs: auto-run actions, embedded JavaScript, launch
actions (able to spawn external programs), embedded files, rich media,
and obfuscation via chained decode filters or hidden object streams.
"""

import re

# pattern -> (short name, base weight, human description)
PDF_INDICATORS = {
    rb"/OpenAction": ("OpenAction", 12, "Action set to run automatically when the document is opened"),
    rb"/AA\b": ("AdditionalActions", 10, "Additional-actions trigger (e.g. runs code on page open/close/focus)"),
    rb"/JavaScript": ("JavaScript", 15, "Embedded JavaScript object"),
    rb"/JS\b": ("JS", 12, "Embedded JavaScript reference"),
    rb"/Launch": ("Launch", 28, "Launch action - capable of executing external programs/files"),
    rb"/EmbeddedFile": ("EmbeddedFile", 10, "Embedded file stream - possible payload container"),
    rb"/RichMedia": ("RichMedia", 8, "Embedded rich media (Flash/3D) - historically exploited"),
    rb"/ObjStm": ("ObjStm", 3, "Compressed object stream - can hide objects from casual/text-based inspection"),
    rb"/SubmitForm": ("SubmitForm", 7, "Form-submission action - can be used to exfiltrate data to a remote URL"),
    rb"/GoToE": ("GoToEmbedded", 6, "Navigates to / triggers an embedded file"),
    rb"/URI\b": ("URI", 3, "External URI reference"),
    rb"/AcroForm": ("AcroForm", 5, "Interactive form object - can be abused to trigger actions or exfiltration"),
    rb"/XFA\b": ("XFA", 6, "XML Forms Architecture support - often used to smuggle malicious scripts or form logic"),
}


def analyze_pdf_file(filepath: str) -> dict:
    result = {
        "file_type": "PDF Document",
        "indicators": [],
        "findings": [],
        "score": 0,
        "object_count": 0,
        "errors": [],
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError as e:
        result["errors"].append(f"Could not read file: {e}")
        return result

    try:
        result["object_count"] = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))

        found_names = set()
        for pattern, (name, weight, desc) in PDF_INDICATORS.items():
            matches = re.findall(pattern, data)
            if matches:
                count = len(matches)
                bonus = min(count - 1, 5)  # repeated occurrences add a little extra weight, capped
                indicator_weight = weight + bonus
                result["indicators"].append({
                    "name": name,
                    "count": count,
                    "weight": indicator_weight,
                    "description": desc,
                    "confidence": "high" if indicator_weight >= 20 else "medium" if indicator_weight >= 8 else "low",
                })
                result["findings"].append({
                    "type": "PDF Indicator",
                    "keyword": name,
                    "count": count,
                    "weight": indicator_weight,
                    "description": desc,
                    "confidence": "high" if indicator_weight >= 20 else "medium" if indicator_weight >= 8 else "low",
                })
                result["score"] += indicator_weight
                found_names.add(name)

        # Chained decode filters (e.g. /Filter [/ASCIIHexDecode /FlateDecode /RunLengthDecode])
        # are a classic technique to obfuscate a malicious payload from simple string scans.
        chained_filters = re.findall(rb"/Filter\s*\[\s*(/\w+(?:\s*/\w+){1,})\s*\]", data)
        if chained_filters:
            result["indicators"].append({
                "name": "ChainedDecodeFilters",
                "count": len(chained_filters),
                "weight": 10,
                "description": "Multiple chained decode filters on a single stream - common obfuscation technique",
                "confidence": "medium",
            })
            result["findings"].append({
                "type": "PDF Indicator",
                "keyword": "ChainedDecodeFilters",
                "count": len(chained_filters),
                "weight": 10,
                "description": "Multiple chained decode filters on a single stream - common obfuscation technique",
                "confidence": "medium",
            })
            result["score"] += 10

        if b"/OpenAction" in data and (b"/JavaScript" in data or b"/JS" in data):
            result["score"] += 12
            result["indicators"].append({
                "name": "OpenAction+JS",
                "count": 1,
                "weight": 12,
                "description": "OpenAction combined with JavaScript gives the PDF an immediate automatic code execution path.",
                "confidence": "high",
            })
            result["findings"].append({
                "type": "PDF Indicator",
                "keyword": "OpenAction+JS",
                "count": 1,
                "weight": 12,
                "description": "OpenAction combined with JavaScript gives the PDF an immediate automatic code execution path.",
                "confidence": "high",
            })

        # Escalate if JavaScript is combined with an execution/exfiltration vector -
        # this combination is a much stronger signal than either alone.
        if ("JavaScript" in found_names or "JS" in found_names) and \
           ("Launch" in found_names or "EmbeddedFile" in found_names or "SubmitForm" in found_names):
            result["score"] += 15
            result["indicators"].append({
                "name": "JS+ExecutionVectorCombo",
                "count": 1,
                "weight": 15,
                "description": "JavaScript combined with a launch/embedded-file/submit vector - "
                                "a common weaponized-PDF pattern",
                "confidence": "high",
            })
            result["findings"].append({
                "type": "PDF Indicator",
                "keyword": "JS+ExecutionVectorCombo",
                "count": 1,
                "weight": 15,
                "description": "JavaScript combined with a launch/embedded-file/submit vector - "
                                "a common weaponized-PDF pattern",
                "confidence": "high",
            })

        # Detect automatic PDF behavior that is especially dangerous even without explicit JavaScript:
        if b"/OpenAction" in data and (b"/Launch" in data or b"/EmbeddedFile" in data):
            result["score"] += 10
            result["indicators"].append({
                "name": "AutoExecute+PayloadVector",
                "count": 1,
                "weight": 10,
                "description": "Auto-run action paired with an embedded file or launch target is a classic weaponized PDF pattern.",
                "confidence": "high",
            })
            result["findings"].append({
                "type": "PDF Indicator",
                "keyword": "AutoExecute+PayloadVector",
                "count": 1,
                "weight": 10,
                "description": "Auto-run action paired with an embedded file or launch target is a classic weaponized PDF pattern.",
                "confidence": "high",
            })

        result["score"] = min(result["score"], 100)

    except Exception as e:
        result["errors"].append(f"PDF heuristic analysis failed: {e}")

    return result
