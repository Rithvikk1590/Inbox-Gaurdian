import re
import whois
from datetime import datetime
from config.whitelist import WHITELIST  # ✅ import the dictionary directly

def is_new_domain(domain):
    w = whois.whois(domain)
    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    
    if not creation_date:
        return None

    age_delta = datetime.now() - creation_date
    age_days = age_delta.days

    return age_days

def check_whitelist(email_data: dict) -> dict:
    sender = (email_data.get("sender") or "").lower().strip()

    # to strip out only the sender email if the format is <Name> <email@domain>
    match = re.search(r'<([^>]+)>', sender)
    if match:
        sender = match.group(1)
    risk = 0
    highlights = []

    if not sender:
        return {"risk_points": 0, "body_highlights": []}

    # Extract domain
    if "@" not in sender:
        return {"risk_points": 5, "body_highlights": [{"text": sender, "hover_message": "Invalid sender format", "risk_level": "high"}]}

    try:
        _, domain = sender.rsplit("@", 1)
        domain = domain.strip(">")
    except ValueError:
        return {"risk_points": 5, "body_highlights": [...]}

    # 1. Whitelist Check
    trusted_senders = [s.lower() for s in WHITELIST.get("trusted_senders", [])]
    trusted_domains = [d.lower() for d in WHITELIST.get("trusted_domains", [])]

    if sender in trusted_senders or domain in trusted_domains:
        return True
    else:
        risk += 3
        highlights.append({
            "text": sender,
            "hover_message": "Sender/domain not in whitelist: +3",
            "risk_level": "medium"
        })

    try:
        suspicious_domains = []
        Dcheck = is_new_domain(domain)
        
        if Dcheck != None and Dcheck < 30:
            print(f"New domain detected: {domain} ({Dcheck} days old)")
            risk += 4
            suspicious_domains.append(domain)
            highlights.append({
                "text": domain,
                "hover_message": f"Newly registered domain ({Dcheck} days old): +4",
                "risk_level": "high"
            })
        elif Dcheck > 30:
            risk = risk
            print(f"Domain is mature: {domain} ({Dcheck} days old)")
        else:
            highlights.append({
            "text": domain,
            "hover_message": "Could not analyze domain (may be suspicious): +2",
            "risk_level": "medium"
            })
            suspicious_domains.append(domain) # cannot find domain on whois, suspicious unknown 
            risk += 2

    except Exception as e:
        print(f"💥 Unexpected error in WHOIS block: {type(e).__name__}: {e}")
        highlights.append({
            "text": domain,
            "hover_message": "Could not analyze domain (may be suspicious): +2",
            "risk_level": "medium"
        })
        suspicious_domains.append(domain)
        risk += 2

    return {"risk_points": risk, "body_highlights": highlights}