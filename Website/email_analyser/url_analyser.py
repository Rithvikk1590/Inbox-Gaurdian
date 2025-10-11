import re
from config.url_shorteners import URL_SHORTENERS as url_shorteners
from urllib.parse import urlparse

def analyse_urls(email_data):
    """
    Analyses URLs found in the email body for phishing indicators.

    Extracts all URLs or domain-like patterns, checks for risky traits such as 
    IP-based links, URL shorteners, insecure HTTP usage, and suspicious 
    characters. Assigns risk points and generates hover highlights for each 
    detected issue.
    """
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
        print("shortener", url_lower)

        # IP address detection
        if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url_lower):
            risk += 12
            detected_risks.append(f"URL uses an IP address. Risk +{risk}.")
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": "high"
            })
            continue
        
        # URL shortener detection (unchanged logic, now reads from separate file)
        if any(shortener in url_lower for shortener in url_shorteners):
            risk += 8
            detected_risks.append(f"Shortened URL detected. Risk +{risk}.")
            # Extract only hostname from the URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc or url
            
            highlights.append({
                "text": domain,
                "hover_message": " ".join(detected_risks),
                "risk_level": "high"
            })
            continue

        # HTTP vs HTTPS
        elif url_lower.startswith("http://"):
            risk += 5
            detected_risks.append(f"Insecure HTTP connection (not HTTPS). Risk +{risk}.")

        # suspicious characters in domain
        elif re.search(r'[^\w.-]', re.sub(r'https?://', '', url_lower.split('/')[0])):
            risk += 10
            detected_risks.append(f"URL contains special characters. Risk +{risk}.")

        if detected_risks:
            risk_level = "high" if any("+25" in r or "+40" in r for r in detected_risks) else "medium"
            highlights.append({
                "text": url,
                "hover_message": " ".join(detected_risks),
                "risk_level": risk_level
            })

    return {"risk_points": risk, "body_highlights": highlights}
