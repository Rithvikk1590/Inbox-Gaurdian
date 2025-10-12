import re
from textblob import TextBlob
import os
import numpy as np
import spacy

nlp = spacy.load("en_core_web_sm")

def position_scorer(email_text, keywords, high_threshold):
    doc = nlp(email_text)
    early_positions = []
    for token in doc:
        clean = token.text.lower().strip(".,!?;:\"'()[]")
        if clean in keywords and keywords[clean] >= high_threshold:
            early_positions.append(token.i / len(doc))
    
    if not early_positions:
        return 0.0  # no high-risk words found
    
    return 1 - min(early_positions)  # 1.0 = very first word

def load_words():
    keywords = {}
    # reading of extracted suspicious keyword txt file
    try:
        CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) # dynamic directory
        with open(os.path.join(CURRENT_DIR, "..", "config", "sus_keywords.txt"), "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or "\t" not in line:
                    continue
                parts = line.split("\t", 1) # in csv.txt file its word then raw_score
                word = parts[0].strip()
                try:
                    score = float(parts[1].strip())
                    keywords[word] = score
                except ValueError:
                    continue  
    except FileNotFoundError:
        # print("keyword.txt not found, keyword module disabled")
        keywords = {}

    # defining threshold for risk assignment
    if keywords:
        scores = list(keywords.values())
        high_threshold = np.percentile(scores, 80)  
    return keywords, high_threshold

def textblob(clean_body, highlights):
    try:
        blob = TextBlob(clean_body)
        # phishing emails often mimic official message, avoid overly emotional language
        polarity = blob.sentiment.polarity #-1.0 (very neg) to +1.0 (very positive)
        subjectivity = blob.sentiment.subjectivity #0.0 (objective/factual) to 1.0 (opinionated)

        # negative polarity = fear/urgency intended
        if polarity <= -0.4:
            points = 5
            highlights.append({
                "text": "Urgent tone",
                "hover_message": f"Fear/urgency detected +{points}",
                "risk_level": "high",
                "placement_info": True  
            })
            total_risk += points
        # high positive polarity = overly scammy/pleasing
        elif polarity >= 0.6:
            points = 5
            highlights.append({
                "text": "Overly positive tone",
                "hover_message": f"Scam-like positivity +{points}",
                "risk_level": "high",
                "placement_info": True 
            })
            total_risk += points

        # high subjectivity (opinionated) = high emotional plea
        if subjectivity >= 0.75:
            points = 5
            highlights.append({
                "text": "Manipulative language",
                "hover_message": f"Highly subjective +{points}",
                "risk_level": "medium",
                "placement_info": True
            })
            total_risk += points
        # print("Cleaned body sample:", clean_body[:100])
        # print("Polarity:", polarity, "Subjectivity:", subjectivity)

    except Exception:
        pass

def extract_url(body):
    # extract URL 
    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    url_spans = []
    for match in url_pattern.finditer(body):
        url_spans.append((match.start(), match.end()))
    return url_spans

def is_inside_any_url(start, end, url_spans):
    for u_start, u_end in url_spans:
        if start >= u_start and end <= u_end:
            return True
    return False

def detect_keywords(email_data: dict) -> dict:
    # loading and defining variables
    keywords, high_threshold = load_words()
    body = email_data.get("body", "")
    highlights = []
    highlighted_words = set() 
    total_risk = 0
    keywords_risk = 0

    # url check
    url_spans = extract_url(body)
    lines = body.splitlines()
    if lines:
        first = lines[0]
        if "http://" in first or "https://" in first:
            points = 2
            total_risk += points
            highlights.append({
                "text": first.strip(),
                "hover_message": f"Link appears immediately in email: +{points}",
                "risk_level": "medium"
            })

    # sus keyword risk assignment
    match_count = 0 
    for word, freq_score in keywords.items():
        pattern = r"\b" + re.escape(word) + r"\b" # word boundaries to avoid partial matches
        for match in re.finditer(pattern, body, re.IGNORECASE):
            start, end = match.span()
            if is_inside_any_url(start, end, url_spans):
                continue # skip if sus words in URL
            if word not in highlighted_words:
                matched_text = match.group(0)
                if freq_score >= high_threshold:
                    level, points = "high", 10
                else:
                    level, points = "medium", 5
                highlights.append({
                    "text": matched_text,
                    "hover_message": f"Suspicious keyword",
                    "risk_level": level
                })
                highlighted_words.add(word) # no double injection of highlighted words
            total_risk += points 
            keywords_risk += points
            match_count += 1
    highlights.append({
        "text": "Suspicious Keywords",
        "hover_message": f"Keyword Detector +{keywords_risk}",
        "placement_info": True 
    })

    # call position_scorer()
    if body.strip() and keywords:
        avg_pos = position_scorer(body, keywords, high_threshold)
        # print('pos', avg_pos)
        if avg_pos > 0.7:  # earliest high-risk word in first 30% of email
            bonus = 5
            total_risk += bonus
            highlights.append({
                "text": "Keyword placement",
                "hover_message": f"Suspicious words found early +{bonus}",
                "placement_info": True 
            })

    # print(f"Total risk: {total_risk}")
    # print("Highlights:", highlights)
    # print(f"Total matches contributing to risk: {match_count}")

    # call textblob()
    if body.strip():
        # clean possible html for better analysis
        clean_body = re.sub(r"<[^>]+>", " ", body)
        clean_body = re.sub(r"\s+", " ", clean_body).strip()
        if clean_body:
            try:
                textblob(clean_body, highlights)
            except Exception:
                pass

    return {"risk_points": total_risk, "body_highlights": highlights}