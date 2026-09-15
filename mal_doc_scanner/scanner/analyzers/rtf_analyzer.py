"""
rtf_analyzer.py
----------------
Static analysis of RTF files for embedded OLE objects, using oletools'
`rtfobj` module. RTF is a favorite exploit-delivery format because it can
carry embedded OLE Package objects and Equation Editor objects, which
have been the vector for widely-exploited CVEs (e.g. CVE-2017-11882,
CVE-2018-0802 in EQNEDT32.EXE), and because raw hex payloads can be
padded/obfuscated with junk control words to dodge naive AV scanners.
"""

import re

from oletools.rtfobj import RtfObjParser

EQUATION_EDITOR_MARKERS = ("Equation", "equation", "eqnedt")
RTF_RAW_PATTERNS = [
    (re.compile(rb"\\objclass\s*Package|\\package\b", re.I), "OLE Package object - frequently abused to smuggle executables, scripts, or batch files inside a document", 28),
    (re.compile(rb"\\objclass\s*(?:Equation|EQNEDT|Equation Editor)|eqnedt32|\\object\\s*\\objclass\s*Equation", re.I), "Equation Editor object class - strongly associated with known remote-code-execution exploits (CVE-2017-11882 / CVE-2018-0802)", 32),
    (re.compile(rb"\\object\b|\\objdata\b|\\oleobj\b", re.I), "Embedded OLE object or raw object payload in the RTF stream", 8),
]


def _raw_rtf_fallback(data: bytes):
    fallback = {
        "score": 0,
        "suspicious_objects": [],
    }

    for pattern, note, weight in RTF_RAW_PATTERNS:
        matches = list(pattern.finditer(data))
        if not matches:
            continue

        fallback["score"] += min(weight + max(len(matches) - 1, 0) * 4, 100)
        fallback["suspicious_objects"].append({
            "index": None,
            "class_name": "RTF raw marker",
            "is_ole": True,
            "is_package": "Package" in note,
            "note": f"{note} (matched {len(matches)} time(s))",
        })

    return fallback


def analyze_rtf_file(filepath: str) -> dict:
    result = {
        "file_type": "RTF Document",
        "embedded_objects": 0,
        "suspicious_objects": [],
        "score": 0,
        "errors": [],
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError as e:
        result["errors"].append(f"Could not read file: {e}")
        return result

    try:
        parser = RtfObjParser(data)
        parser.parse()
        result["embedded_objects"] = len(parser.objects)

        for obj in parser.objects:
            score_add = 4  # baseline: any embedded object is somewhat notable
            note_parts = []

            class_name = getattr(obj, "class_name", b"") or b""
            if isinstance(class_name, bytes):
                class_name_str = class_name.decode(errors="ignore")
            else:
                class_name_str = str(class_name)

            if getattr(obj, "is_package", False):
                score_add += 28
                note_parts.append(
                    "OLE Package object - frequently abused to smuggle "
                    "executables, scripts, or batch files inside a document"
                )

            if any(marker.lower() in class_name_str.lower() for marker in EQUATION_EDITOR_MARKERS):
                score_add += 32
                note_parts.append(
                    "Equation Editor object class - strongly associated with "
                    "known remote-code-execution exploits (CVE-2017-11882 / CVE-2018-0802)"
                )

            if getattr(obj, "is_ole", False) and not note_parts:
                score_add += 3

            result["score"] += score_add

            if score_add > 4:
                result["suspicious_objects"].append({
                    "index": getattr(obj, "index", None),
                    "class_name": class_name_str or "(unnamed)",
                    "is_ole": getattr(obj, "is_ole", None),
                    "is_package": getattr(obj, "is_package", None),
                    "note": " | ".join(note_parts) if note_parts else "Embedded OLE object",
                })

        fallback = _raw_rtf_fallback(data)
        if fallback["suspicious_objects"]:
            result["score"] += fallback["score"]
            result["suspicious_objects"].extend(fallback["suspicious_objects"])

        result["score"] = min(result["score"], 100)

    except Exception as e:
        result["errors"].append(f"RTF object parsing failed: {e}")
        fallback = _raw_rtf_fallback(data)
        result["score"] = min(result["score"] + fallback["score"], 100)
        result["suspicious_objects"].extend(fallback["suspicious_objects"])

    return result
