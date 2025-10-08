import re
from config.top_1000_domains import TOP_1000_DOMAINS
from config.whitelist import WHITELIST

# Combine global top domains + custom whitelist domains for reference
SAFE_DOMAINS = TOP_1000_DOMAINS + WHITELIST["trusted_domains"]


def _domain_points(dist: int) -> int:
    """
    Assign risk points based on Levenshtein distance between two domains.
    Distance 1 → very similar → high risk.
    Distance 2 → somewhat similar → medium risk.
    Distance >2 → not similar enough → no points.
    """
    if dist == 1:
        return 25
    if dist == 2:
        return 10
    return 0


def _lev(a, b):
    """
    Basic Levenshtein distance (edit distance) algorithm.
    Calculates the minimum number of insertions, deletions, or substitutions
    to transform string a → b.

    Used for comparing domains.
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


def _domain_from_url_or_text(s: str) -> str:
    """
    Extracts a 'bare' domain from any URL or text string.
    Removes scheme (http/https), paths, spaces, or query strings.

    Example:
    "https://mail.paypa1.com/login" → "mail.paypa1.com"
    """
    s = s.lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    # cut off at first "/", " ", "?" or "#"
    s = re.split(r"[\/\s\?\#]", s, 1)[0]
    return s


def check_edit_distance(email_data: dict) -> dict:
    """
    Analyze sender + email body for lookalike domains or brand impersonation.

    2 main checks:
      1) Sender domain similarity (spoofed 'from' field)
      2) URL / domain similarity inside the body

    Returns:
        dict with total risk_points and highlight metadata for UI rendering.
    """
    sender = (email_data.get("sender") or "").lower()
    body = (email_data.get("body") or "")

    risk = 0
    highlights = []

    # ----- 1) Sender domain similarity -----
    if "@" in sender:
        domain = sender.split("@")[-1].strip(">")
        for legit in SAFE_DOMAINS:
            dist = _lev(domain, legit)
            pts = _domain_points(dist)
            if pts > 0:
                # add risk points for domain close to known safe domains
                risk += pts
                severity = "high" if dist == 1 else "medium"
                highlights.append({
                    "section": "sender",
                    "text": domain,
                    "hover_message": f"Sender domain distance to {legit} = {dist}: +{pts}",
                    "risk_level": severity
                })
                # stop once a match is found — no need to overcount
                break

    # ----- 2) BODY: URL / domain similarity -----
    url_re = re.compile(r"\b((?:https?://)?[a-z0-9.-]+\.[a-z]{2,})(?:/[^\s]*)?", re.IGNORECASE)
    for m in url_re.finditer(body):
        raw_hit = m.group(1)
        dom = _domain_from_url_or_text(raw_hit)
        for legit in SAFE_DOMAINS:
            dist = _lev(dom, legit)
            pts = _domain_points(dist)
            if pts > 0:
                risk += pts
                severity = "high" if dist == 1 else "medium"
                highlights.append({
                    "section": "body",
                    "text": raw_hit,
                    "hover_message": f"Link/domain distance to {legit} = {dist}: +{pts}",
                    "risk_level": severity
                })
                break  # once match found, skip others

    return {"risk_points": risk, "body_highlights": highlights}
