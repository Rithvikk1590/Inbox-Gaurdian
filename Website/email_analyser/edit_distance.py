import re
from config.top_1000_domains import TOP_1000_DOMAINS
from config.whitelist import WHITELIST

# Combine global top 1000 domains + custom whitelist domains for reference
SAFE_DOMAINS = TOP_1000_DOMAINS + WHITELIST["trusted_domains"]

def _domain_points(dist):
    """
    Assign risk points based on Levenshtein distance between two domains.
    Distance 1 -> very similar -> high risk.
    Distance 2 -> somewhat similar -> medium risk.
    Distance >2 -> not similar enough -> no points.
    """
    if dist == 1:
        return 25
    if dist == 2:
        return 10
    return 0


def _lev(a, b):
    """
    Calculates the Levenshtein (edit) distance between strings a and b.
    """
    # initialize dp grid where first row/col represent cost of empty prefix
    dp = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    # dynamic programming: build table row by row
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            dp[i][j] = min(
                dp[i - 1][j] + 1,                      # deletion
                dp[i][j - 1] + 1,                      # insertion
                dp[i - 1][j - 1] + (a[i - 1] != b[j - 1])  # substitution cost
            )
    return dp[-1][-1]


def _domain_from_url_or_text(s):
    """
    Extracts the domain from a URL or text.

    Example:
    "https://mail.paypa1.com/login" → "mail.paypa1.com"
    """
    s = s.lower()
    if "://" in s:
        # remove http:// or https://
        s = s.split("://", 1)[1]
    # remove everyhing after the domain (/, space, ?, #)
    s = re.split(r"[\/\s\?\#]", s, 1)[0]
    return s


def _score_domain_similarity(domain, highlights, section):
    """
    Add risk points if `domain` looks like any of the domains inside SAFE_DOMAINS,
    and append a highlight for the first positive match.

    Args:
        domain: Domain or URL-like text to evaluate (e.g., "mail.paypa1.com").
        highlights: List to append a highlight dict to when points are added.
        section: Email section this came from ("sender", "body", or "subject").

    Returns:
        int: Points added (0 if no similarity found).
    """
    risk = 0
    for legit in SAFE_DOMAINS:
        # calculate edit distance
        dist = _lev(domain, legit)
        # assign risk points based on distance
        pts = _domain_points(dist)
        if pts > 0:
            # add risk points for domain close to known safe domains
            risk += pts
            severity = "high" if dist == 1 else "medium"
            highlights.append({
                "section": section,  # <- only change vs your original
                "text": domain,
                "hover_message": f"{'Sender' if section=='sender' else 'Link/domain'} domain distance to {legit} = {dist}: +{pts}",
                "risk_level": severity
            })
            # stop once a match is found — no need to overcount
            break
    return risk


def check_edit_distance(email_data):
    """
    Analyze sender and email body for lookalike domains.

    2 main checks:
      1) Sender domain similarity (spoofed sender)
      2) URL / domain similarity inside the body

    Returns:
        dict with total risk_points and highlight.
    """
    risk = 0
    highlights = []
    sender = (email_data.get("sender") or "").lower()
    body = (email_data.get("body") or "")

    # 1 - Check if domain in sender is similar to known safe domains
    if "@" in sender:
        domain = sender.split("@")[-1].strip(">")
        risk += _score_domain_similarity(domain, highlights, "sender")

    # 2 - Check if domain in subject is similar to known safe domains
    url_re = re.compile(r"\b((?:https?://)?[a-z0-9.-]+\.[a-z]{2,})(?:/[^\s]*)?", re.IGNORECASE)
    subject_hits = url_re.findall(body)
    for domain in subject_hits:
        domain = _domain_from_url_or_text(domain)
        risk += _score_domain_similarity(domain, highlights, "subject")
        
    # 3 - Check URLs/domains in the body for similarity to known safe domains, using same regex used to check the subject field.
    body_hits = url_re.findall(body)
    for domain in body_hits:
        domain = _domain_from_url_or_text(domain)
        risk += _score_domain_similarity(domain, highlights, "body")

    return {"risk_points": risk, "body_highlights": highlights}
