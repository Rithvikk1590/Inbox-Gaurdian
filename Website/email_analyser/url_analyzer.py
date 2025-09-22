import re

SHORTENERS = ("tinyurl.com", "bit.ly", "rb.gy", "is.gd")

def analyze_urls(email_data: dict) -> dict:
    body = email_data.get("body", "")
    highlights = []
    risk = 0

    # Pass 1: Full URLs with scheme
    urls = re.findall(r'https?://[^\s)>\]]+', body)
    for u in urls:
        ul = u.lower()
        if any(s in ul for s in SHORTENERS):
            risk += 4
            highlights.append({
                "text": u,
                "hover_message": "Shortened URL: +4",
                "risk_level": "high"
            })
        if ul.startswith("http://"):
            risk += 2
            highlights.append({
                "text": u,
                "hover_message": "Non-HTTPS link: +2",
                "risk_level": "medium"
            })

    # Pass 2: Bare shortener domains (no scheme)
    pattern = r'\b(?:' + "|".join(re.escape(s) for s in SHORTENERS) + r')[^\s]*'
    bare_urls = re.findall(pattern, body, flags=re.IGNORECASE)
    for u in bare_urls:
        if not any(h["text"].lower() == u.lower() for h in highlights):
            risk += 4
            highlights.append({
                "text": u,
                "hover_message": "Shortened URL (bare): +4",
                "risk_level": "high"
            })

    return {"risk_points": risk, "body_highlights": highlights}
