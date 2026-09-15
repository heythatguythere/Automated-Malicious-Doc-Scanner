"""
office_analyzer.py
-------------------
Static analysis of legacy (OLE) and modern (OOXML) Office documents for
embedded VBA / XLM macros using oletools' battle-tested `olevba` engine.

olevba extracts and statically analyzes macro source code and classifies
findings into categories:
    AutoExec              -> macro auto-run triggers (AutoOpen, Document_Open, Workbook_Open...)
    Suspicious             -> functions commonly abused by malware (Shell, CreateObject,
                              WScript.Shell, URLDownloadToFile, Environ, RegWrite, ...)
    IOC                    -> Indicators of Compromise extracted from code (URLs, IPs, exe names)
    Base64 String          -> possible obfuscated/encoded payloads
    Hex String             -> possible obfuscated/encoded payloads
    Dridex string          -> known banking-trojan string transform pattern
    VBA obfuscated Strings -> Chr()/string-concat obfuscation tricks

We convert these categorized findings into a weighted 0-100 risk score.
"""

from oletools.olevba import VBA_Parser

# Weight given to each finding category when accumulating the macro risk score.
# Higher weight = stronger signal of malicious intent.
CATEGORY_WEIGHTS = {
    "AutoExec": 12,
    "Suspicious": 9,
    "IOC": 6,
    "Hex String": 4,
    "Base64 String": 4,
    "Dridex string": 25,
    "VBA obfuscated Strings": 7,
}

# A handful of especially dangerous keywords get an extra bump even within
# their category, since not all "Suspicious" hits are equally severe.
HIGH_SEVERITY_KEYWORDS = {
    "Shell", "WScript.Shell", "URLDownloadToFile", "CreateObject",
    "PowerShell", "cmd.exe", "Kill", "RegWrite", "ShellExecute",
    "URLMon", "GetObject", "Environ", "CallByName",
}


def analyze_office_file(filepath: str) -> dict:
    result = {
        "file_type": "Office Document (OLE/OOXML)",
        "has_macros": False,
        "macro_score": 0,
        "findings": [],
        "iocs": [],
        "autoexec_triggers": [],
        "score_breakdown": {
            "base": 0,
            "autoexec_bonus": 0,
            "severity_bonus": 0,
            "ioc_bonus": 0,
            "combo_bonus": 0,
        },
        "errors": [],
    }

    try:
        vba = VBA_Parser(filepath)
    except Exception as e:
        result["errors"].append(f"Could not open/parse file as an Office document: {e}")
        return result

    try:
        result["has_macros"] = vba.detect_vba_macros()

        if result["has_macros"]:
            try:
                analysis = vba.analyze_macros(show_decoded_strings=False)
                seen_autoexec = set()
                seen_keywords = set()
                suspicious_keywords = set()

                for kw_type, keyword, description in analysis:
                    weight = CATEGORY_WEIGHTS.get(kw_type, 3)

                    if kw_type == "AutoExec":
                        seen_autoexec.add(keyword)
                        result["score_breakdown"]["autoexec_bonus"] += 6
                    if kw_type == "IOC":
                        result["score_breakdown"]["ioc_bonus"] += 3
                    if keyword in HIGH_SEVERITY_KEYWORDS:
                        suspicious_keywords.add(keyword)
                        weight += 8
                        result["score_breakdown"]["severity_bonus"] += 8

                    result["macro_score"] += weight
                    result["score_breakdown"]["base"] += weight
                    result["findings"].append({
                        "type": kw_type,
                        "keyword": keyword,
                        "description": description,
                        "weight": weight,
                        "confidence": "high" if weight >= 20 else "medium" if weight >= 8 else "low",
                    })

                    seen_keywords.add(keyword)
                    if kw_type == "IOC":
                        result["iocs"].append(keyword)
                    if kw_type == "AutoExec":
                        result["autoexec_triggers"].append(keyword)

                if seen_autoexec and suspicious_keywords:
                    combo_bonus = min(18, 6 + len(seen_autoexec) * 4 + len(suspicious_keywords) * 2)
                    result["macro_score"] += combo_bonus
                    result["score_breakdown"]["combo_bonus"] = combo_bonus

                if len(seen_autoexec) > 1:
                    result["macro_score"] += min(10, 4 * (len(seen_autoexec) - 1))
                    result["score_breakdown"]["combo_bonus"] += min(10, 4 * (len(seen_autoexec) - 1))

                if result["iocs"]:
                    result["macro_score"] += min(12, len(set(result["iocs"])) * 3)
                    result["score_breakdown"]["combo_bonus"] += min(12, len(set(result["iocs"])) * 3)

            except Exception as e:
                result["errors"].append(f"Macro content analysis failed: {e}")

            result["macro_score"] = min(result["macro_score"], 100)

    except Exception as e:
        result["errors"].append(f"Macro detection failed: {e}")
    finally:
        try:
            vba.close()
        except Exception:
            pass

    return result
