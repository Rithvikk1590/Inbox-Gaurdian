import os

# Base points per risky extension (tweak as you like)
RISKY_EXT_POINTS = {
    # Executables (very dangerous)
    ".exe": 30, ".scr": 30, ".pif": 30,
    ".bat": 30, ".cmd": 30, ".ps1": 30,
    ".vbs": 30, ".js": 30, ".jar": 30,
    ".msi": 30, ".apk": 30,
    ".lnk": 30, ".hta": 30,

    # Document types (can carry macros / exploits)
    ".doc": 15, ".docx": 15, ".xls": 15, ".xlsx": 15,
    ".ppt": 15, ".pptx": 15, ".pdf": 15, ".rtf": 15,

    # Archives (often used to hide payloads)
    ".zip": 15, ".rar": 15, ".7z": 15, ".iso": 15, ".img": 15, ".chm": 15,
}

HIDDEN_EXECUTABLES = {".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".pif"}

def _double_extension_score(name: str) -> int:
    """
    Flag patterns like 'invoice.pdf.exe' where a harmless-looking extension
    hides an executable. Adjust score as needed.
    """
    parts = name.lower().split(".")
    if len(parts) >= 3:
        ext = "." + parts[-1]
        prev = "." + parts[-2]
        if ext in HIDDEN_EXECUTABLES and prev in {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".txt", ".jpg", ".jpeg", ".png"
        }:
            return 30
    return 0

def check_attachment_extensions(email_data: dict) -> dict:
    """
    Returns:
      {
        "risk_points": <int>,
        "attachment_warnings": [
          {"filename": "...", "message": "...", "points": 40, "risk_level": "high"},
          ...
        ]
      }
    """
    attachments = email_data.get("attachments") or []
    risk = 0
    warnings = []

    for fname in attachments:
        ext = os.path.splitext(fname)[1].lower()

        # Direct risky extension points
        pts = RISKY_EXT_POINTS.get(ext, 0)
        if pts:
            warnings.append({
                "filename": fname,
                "message": f"Attachment '{fname}' has risky extension '{ext}': +{pts}",
                "points": pts,
                "risk_level": "high",
            })
            risk += pts

        # Hidden/double-extension scoring
        dbl = _double_extension_score(fname)
        if dbl:
            warnings.append({
                "filename": fname,
                "message": f"Suspicious double extension in '{fname}': +{dbl}",
                "points": dbl,
                "risk_level": "high",
            })
            risk += dbl

    return {"risk_points": risk, "attachment_warnings": warnings}