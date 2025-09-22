import re

# simple, readable pattern list; add more as needed
KEYWORDS = {
    r"\breset password\b": 4,
    r"\bverify account\b": 4,
    r"\burgent\b": 2,
    r"\bsecurity alert\b": 3,
}

def detect_keywords(email_data: dict) -> dict:
    body = email_data.get("body", "")
    highlights = []
    risk = 0

    for pattern, pts in KEYWORDS.items():
        if re.search(pattern, body, flags=re.IGNORECASE):
            # use the visible text that appears in the email (not the pattern)
            match_iter = re.finditer(pattern, body, flags=re.IGNORECASE)
            for m in match_iter:
                matched_text = m.group(0)
                highlights.append({
                    "text": matched_text,
                    "hover_message": f"Suspicious keyword: +{pts}",
                    "risk_level": "high" if pts >= 4 else "medium"
                })
                risk += pts

    return {"risk_points": risk, "body_highlights": highlights}
