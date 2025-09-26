# keywords.py
# Comprehensive keyword patterns for detecting phishing emails
# Format: regex pattern -> risk weight (1–5)
# Use with re.search(pattern, text, re.IGNORECASE)

KEYWORDS = {
    # === Credential Harvesting ===
    r"\breset\s+your?\s+password\b": 5,
    r"\bchange\s+your\s+password\b": 4,
    r"\bupdate\s+your\s+credentials?\b": 4,
    r"\bverify\s+(your\s+)?account\b": 5,
    r"\bconfirm\s+(your\s+)?identity\b": 5,
    r"\bauthenticate\s+now\b": 4,
    r"\bsession\s+expired.*login\b": 4,
    r"\bkeep\s+me\s+signed\s+in\b": 3,  # suspicious in unsolicited emails

    # === Impersonation & Fake Authority ===
    r"\bit department\b.*\bnotice\b": 3,
    r"\bhr team\b.*\bconfidential\b": 3,
    r"\bsystem administrator\b.*\balert\b": 3,
    r"\bsecurity team\b.*\brequires action\b": 3,
    r"\bofficial notification\b": 3,

    # === Link & Domain Tricks ===
    r"\bhttp://[a-z0-9.-]+\.xyz\b": 4,  # suspicious TLD in link
    r"\bhttps?://[^ ]*google[^ ]*\.(com\.br|ru|info|biz)\b": 5,  # fake Google domains
    r"\bverify\.[^ ]*microsoft[^ ]*\b": 5,  # subdomain impersonation
    r"\blogin\.[^ ]*apple[^ ]*\.(net|org)\b": 5,

    # === Poor Grammar / Red Flag Phrases ===
    r"\byour email has been compromised\b": 4,  # often used in scams
    r"\bwe are unable to process your request unless you confirm\b": 4,
    r"\bthis message was sent from a non-human system\b": 2,
    r"\bkindly do the needful\b": 3,  # common in scammy emails
}

URGENCY = {
    # === Urgency & Fear Tactics ===
    r"\b(immediate|urgent|critical)\s+action\s+required\b": 5,
    r"\brespond within \d+\s*(hour|minute|day)s?\b": 5,
    r"\bwithin the next 24 hours\b": 4,
    r"\bfinal reminder\b": 4,
    r"\bfinal warning\b": 5,
    r"\baccount will be (suspended|locked|disabled|terminated)\b": 5,
    r"\bpermanently (deactivated|deleted|closed)\b": 5,
    r"\bdata loss\b": 4,
    r"\bunauthorized access detected\b": 4,
    r"\bsuspicious activity on your account\b": 4,

    # === Threatening / Intimidating Language ===
    r"\bthis is unacceptable\b": 4,
    r"\bdeeply concerning\b": 3,
    r"\bviolation of policy\b": 3,
    r"\bsecurity breach\b": 3,
    r"\bill be held responsible\b": 4,
    r"\bdo not ignore this message\b": 4,
    r"\bignoring this may result in\b": 4,

    # === Suspicious CTAs (Calls to Action) ===
    r"\bclick here to (verify|secure|access|confirm)\b": 4,
    r"\bdownload and open\b": 4,
    r"\bopen the attachment\b": 3,
    r"\benable editing\b": 4,   # common in malicious Office docs
    r"\ballow content\b": 4,
    r"\bclaim your reward\b": 3,
    r"\blimited time offer\b": 3,
}