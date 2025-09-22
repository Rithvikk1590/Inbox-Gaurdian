def score_positions(email_data: dict) -> dict:
    body = (email_data.get("body") or "")
    lines = body.splitlines()
    risk = 0
    highlights = []

    if lines:
        first = lines[0]
        if "http://" in first or "https://" in first:
            risk += 2
            highlights.append({
                "text": first.strip(),
                "hover_message": "Link appears immediately in email: +2",
                "risk_level": "medium"
            })

    return {"risk_points": risk, "body_highlights": highlights}
