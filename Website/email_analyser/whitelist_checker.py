import re
import whois
from datetime import datetime
from config.whitelist import WHITELIST

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
    match = re.search(r'<([^>]+)>', sender)
    if match:
        sender = match.group(1)

    if not sender:
        return {"risk_points": 0, "body_highlights": []}
    
    risk = 0
    highlights = []

    # extract domain
    if "@" not in sender:
        return {"risk_points": 8, "body_highlights": [{"text": sender, "hover_message": "Invalid sender format", "risk_level": "high"}]}
    try:
        _, domain = sender.rsplit("@", 1)
        domain = domain.strip(">")
    except ValueError:
        return {"risk_points": 8, "body_highlights": [{"text": sender, "hover_message": "Invalid sender format", "risk_level": "high"}]}

    # check with pre-defined whitelist.json
    trusted_senders = [s.lower() for s in WHITELIST["trusted_senders"]]
    trusted_domains = [d.lower() for d in WHITELIST["trusted_domains"]]

    if sender in trusted_senders or domain in trusted_domains:
        return True
    else:
        points = 4
        risk += points
        highlights.append({
            "text": sender,
            "hover_message": f"Sender not in whitelist: +{points}",
            "risk_level": "medium"
        })
        # checking of domain age with WHOIS information (newer domain age = more likely phishing sender)
        try:
            suspicious_domains = []
            Dcheck = is_new_domain(domain)
            if Dcheck != None and Dcheck < 30:
                points = 5
                risk += points
                suspicious_domains.append(domain)
                highlights.append({
                    "text": domain,
                    "hover_message": f"Newly Registered Domain ({Dcheck} days old): + {points}",
                    "risk_level": "high"
                })
            elif Dcheck > 30:
                highlights.append({
                    "text": domain,
                    "hover_message": f"Matured Domain",
                    "risk_level": "medium"
                })
                risk = risk
                # print(f"Domain is mature: {domain} ({Dcheck} days old)")
        except Exception as e: # cannot find domain
            points = 4
            highlights.append({
                "text": domain,
                "hover_message": f"Unknown Domain (may be suspicious): +{points}",
                "risk_level": "medium"
            })
            suspicious_domains.append(domain)
            risk += points

    return {"risk_points": risk, "body_highlights": highlights}