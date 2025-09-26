import re
from textblob import TextBlob
from config.keyword import KEYWORDS,URGENCY

def detect_keywords(email_data: dict) -> dict:
    body = email_data.get("body", "")
    highlights = []
    risk = 0

    # 1. keyword matching
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

    for phrase_pattern in URGENCY:
        matches = re.finditer(phrase_pattern, body, flags=re.IGNORECASE)
        for m in matches:
            matched_text = m.group(0)
            pts = 3 if "final warning|immediately|right away|within|permanent suspension|data deletion|do not ignore" in phrase_pattern else 2
            risk += pts

            highlights.append({
                "type": "urgency",
                "text": matched_text,
                "hover_message": f"Fear-based urgency detected: +{pts}",
                "risk_level": "high" if pts == 3 else "medium"
            })

    # 2. sentiment & tone analysis
    blob = TextBlob(body)
    polarity = blob.sentiment.polarity  # -1 (negative) to +1 (positive)
    subjectivity = blob.sentiment.subjectivity  # 0 (objective) to 1 (emotional)

    if subjectivity > 0.6:
        highlights.append({
            "type": "tone",
            "text": "Highly emotional language",
            "hover_message": "Emotionally charged content may indicate manipulation (+2)",
            "risk_level": "medium"
        })
        risk += 2

    if polarity < -0.3:
        highlights.append({
            "type": "tone",
            "text": "Strong negative tone",
            "hover_message": "Negative sentiment (e.g., threats, warnings) detected (+1)",
            "risk_level": "low"
        })
        risk += 1

    return {"risk_points": risk, "body_highlights": highlights}