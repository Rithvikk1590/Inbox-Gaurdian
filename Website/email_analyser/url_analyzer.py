import re

# SHORTENERS = ("tinyurl.com", "bit.ly", "rb.gy", "is.gd")

def analyze_urls(email_data):
    body = email_data.get("body", "")
    risk = 0
    highlights = []

    urls = re.findall(r'https?://\S+', body)

    url_shorteners = ("tinyurl.com", "bit.ly", "rb.gy", "is.gd", "t.co", "goo.gl", "ow.ly", "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at")

    for url in urls:
        url_lower = url.lower()
        detected_risks = []

        # IP address detection
        if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url_lower):
            risk += 40
            detected_risks.append("URL uses an IP address. Risk +40.")
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": "high"
            })
            continue #skip other checks

        # URL shortener detection
        if any(shortener in url_lower for shortener in url_shorteners):
            risk += 25
            detected_risks.append("Shortened URL detected. Risk +25.")
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": "high"
            })
            continue  # Skip other checks

        # HTTP (insecure connection) vs HTTPS detection 
        elif url_lower.startswith("http://"):
            risk += 20
            detected_risks.append("Insecure HTTP connection (not HTTPS). Risk +15.")

        # suspicious characters in domain
        elif re.search(r'[^\w.-]', re.sub(r'https?://', '', url_lower.split('/')[0])):
            risk+= 20
            detected_risks.append("URL contains special characters. Risk +20.")

        if detected_risks:
            risk_level = "high" if any("+25" in risk or "+40" in risk for risk in detected_risks) else "medium"
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": risk_level
            })
            
    return {"risk_points":risk , "body_highlights": highlights}
