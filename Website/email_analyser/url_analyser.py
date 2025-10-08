import re
from config.url_shorteners import URL_SHORTENERS as url_shorteners

def analyse_urls(email_data):
    body = email_data.get("body", "")
    risk = 0
    highlights = []

    # Either starts with https:// or http:// or has a domain like structure (.com, .net, etc.)
    urls = re.findall(r'\b(?:https?://\S+|\S+\.\S+)\b', body)
    
    print("urls", urls)

    for url in urls:
        url_lower = url.lower()
        print(url_lower)
        detected_risks = []

        # IP address detection
        if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url_lower):
            risk += 30
            detected_risks.append("URL uses an IP address. Risk +30.")
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": "high"
            })
            continue

        # URL shortener detection (unchanged logic, now reads from separate file)
        if any(shortener in url_lower for shortener in url_shorteners):
            risk += 25
            detected_risks.append("Shortened URL detected. Risk +25.")
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": "high"
            })
            continue

        # HTTP vs HTTPS
        elif url_lower.startswith("http://"):
            risk += 10
            detected_risks.append("Insecure HTTP connection (not HTTPS). Risk +10.")

        # suspicious characters in domain
        elif re.search(r'[^\w.-]', re.sub(r'https?://', '', url_lower.split('/')[0])):
            risk += 15
            detected_risks.append("URL contains special characters. Risk +15.")

        if detected_risks:
            risk_level = "high" if any("+25" in r or "+40" in r for r in detected_risks) else "medium"
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": risk_level
            })

    return {"risk_points": risk, "body_highlights": highlights}
