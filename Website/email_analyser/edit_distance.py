# edit_distance.py
import re

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
SAFE_ROOTS = list({d.split(".", 1)[0] for d in SAFE_DOMAINS})  # e.g., ["paypal", "microsoft", ...]


def _domain_from_url_or_text(s: str) -> str:
    """Return a best-effort domain from a URL/text chunk, lowercase, no scheme."""
    s = s.lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    # stop at slash, space, or query
    s = re.split(r"[\/\s\?\#]", s, 1)[0]
    return s


def check_edit_distance(email_data: dict) -> dict:
    sender = (email_data.get("sender") or "").lower()
    body = (email_data.get("body") or "")

    risk = 0
    highlights = []

    # ----- 1) Sender domain similarity (existing behavior, just ensure section="sender")
    if "@" in sender:
        domain = sender.split("@")[-1].strip(">")
        for legit in SAFE_DOMAINS:
            dist = _lev(domain, legit)
            if 0 < dist <= 2:
                risk += 4  # additive to play nicely with whitelist (+3)
                highlights.append({
                    "section": "sender",
                    "text": domain,
                    "hover_message": f"Sender domain similar to {legit}: +4",
                    "risk_level": "high"
                })
                break  # one legit match is enough

    # ----- 2) BODY: URL / domain similarity (e.g., http://paypa1.com)
    # capture urls or bare domains
    url_re = re.compile(r"\b((?:https?://)?[a-z0-9.-]+\.[a-z]{2,})(?:/[^\s]*)?", re.IGNORECASE)
    for m in url_re.finditer(body):
        raw_hit = m.group(1)                 # original text for highlighting
        dom = _domain_from_url_or_text(raw_hit)
        for legit in SAFE_DOMAINS:
            dist = _lev(dom, legit)
            if 0 < dist <= 2:
                risk += 4
                highlights.append({
                    "section": "body",
                    "text": raw_hit,  # use original-cased hit so the frontend can replace it
                    "hover_message": f"Link domain similar to {legit}: +4",
                    "risk_level": "high"
                })
                break

    # ----- 3) BODY: plain-word brand root similarity (e.g., "Paypa1" ~ "paypal")
    # keep this conservative: distance <= 1 is enough for typical l/1 swaps
    word_re = re.compile(r"\b[a-z0-9]{4,}\b", re.IGNORECASE)
    for wm in word_re.finditer(body):
        w_raw = wm.group(0)      # original text to highlight (preserve case)
        w = w_raw.lower()
        for root in SAFE_ROOTS:
            dist = _lev(w, root)
            if 0 < dist <= 1:    # tight threshold to avoid noise
                risk += 4
                highlights.append({
                    "section": "body",
                    "text": w_raw,
                    "hover_message": f"Word similar to '{root}': +4",
                    "risk_level": "high"
                })
                break

    return {"risk_points": risk, "body_highlights": highlights}
