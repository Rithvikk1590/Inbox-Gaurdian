def _lev(a, b):
    dp = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + (a[i - 1] != b[j - 1]),
            )
    return dp[-1][-1]

SAFE_DOMAINS = ["paypal.com", "microsoft.com", "google.com", "gov.sg", "ntu.edu.sg"]

def check_edit_distance(email_data: dict) -> dict:
    sender = (email_data.get("sender") or "").lower()
    if "@" not in sender:
        return {"risk_points": 0, "body_highlights": []}

    domain = sender.split("@")[-1].strip(">")
    risk = 0
    highlights = []

    for legit in SAFE_DOMAINS:
        dist = _lev(domain, legit)
        if 0 < dist <= 2:
            risk = max(risk, 4)  # add 4 once even if multiple hits
            highlights.append({
                "text": domain,
                "hover_message": f"Sender domain similar to {legit}: +4",
                "risk_level": "high"
            })
            break

    return {"risk_points": risk, "body_highlights": highlights}
