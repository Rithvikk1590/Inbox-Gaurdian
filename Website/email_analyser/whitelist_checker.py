import json
import os

# Load whitelist once (fallback to empty if not present)
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "whitelist.json")
try:
    with open(CONFIG_PATH, "r") as f:
        WHITELIST = json.load(f)
except Exception:
    WHITELIST = {"trusted_senders": [], "trusted_domains": []}

def check_whitelist(email_data: dict) -> dict:
    sender = (email_data.get("sender") or "").lower()
    risk = 0
    highlights = []

    if not sender:
        return {"risk_points": 0, "body_highlights": []}

    # Check exact sender
    trusted_senders = [s.lower() for s in WHITELIST.get("trusted_senders", [])]
    trusted_domains = [d.lower() for d in WHITELIST.get("trusted_domains", [])]

    if sender not in trusted_senders:
        domain = sender.split("@")[-1].strip(">")
        if domain not in trusted_domains:
            risk = 3
            # NOTE: This highlights the sender address (which is in headers, not body).
            # It will contribute to points even if your current template only highlights body.
            highlights.append({
                "text": sender,
                "hover_message": "Sender not in whitelist: +3",
                "risk_level": "medium"
            })

    return {"risk_points": risk, "body_highlights": highlights}
