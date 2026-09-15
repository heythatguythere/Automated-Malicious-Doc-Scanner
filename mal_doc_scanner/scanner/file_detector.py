"""
file_detector.py
-----------------
Identifies the real underlying format of a document by inspecting its
magic bytes (file signature) rather than trusting the file extension,
since malware authors routinely rename/mask file extensions.

Returns one of: 'ole', 'ooxml', 'rtf', 'pdf', 'unknown'
    - 'ole'    : legacy binary Office formats (.doc, .xls, .ppt) - OLE Compound File
    - 'ooxml'  : modern zip-based Office formats (.docx, .xlsx, .pptx, and macro-enabled *m variants)
    - 'rtf'    : Rich Text Format
    - 'pdf'    : Portable Document Format
"""

import os

OLE_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
ZIP_SIGNATURE = b"PK\x03\x04"
PDF_SIGNATURE = b"%PDF"
RTF_SIGNATURE = b"{\\rtf"

OOXML_EXTS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm", ".xltm"}
OLE_EXTS = {".doc", ".xls", ".ppt", ".dot", ".xlt"}


def detect_file_type(filepath: str) -> str:
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
    except OSError:
        return "unknown"

    ext = os.path.splitext(filepath)[1].lower()

    if header.startswith(PDF_SIGNATURE):
        return "pdf"
    if header.startswith(OLE_SIGNATURE):
        return "ole"
    if header.startswith(ZIP_SIGNATURE):
        # Could be a generic zip too, but in our scan scope we only route
        # zip-signed files here when the extension confirms an Office type,
        # otherwise we still try 'ooxml' since oletools will reject cleanly.
        return "ooxml"
    if header.startswith(RTF_SIGNATURE):
        return "rtf"

    # Fallback purely on extension if signature was inconclusive
    # (e.g. truncated/edge-case files)
    if ext in OOXML_EXTS:
        return "ooxml"
    if ext in OLE_EXTS:
        return "ole"
    if ext == ".rtf":
        return "rtf"
    if ext == ".pdf":
        return "pdf"

    return "unknown"
