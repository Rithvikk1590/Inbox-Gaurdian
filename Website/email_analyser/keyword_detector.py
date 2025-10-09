import re
from textblob import TextBlob
import os
import numpy as np

def detect_keywords(email_data: dict) -> dict:
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
        print("keyword.txt not found, keyword module disabled")
        keywords = {}

    # defining threshold for risk assignment
    if keywords:
        scores = list(keywords.values())
        high_threshold = np.percentile(scores, 80)  

    body = email_data.get("body", "")
    highlights = []
    highlighted_words = set()  # track which words already highlighted
    total_risk = 0

    match_count = 0 
    for word, freq_score in keywords.items():
        pattern = r"\b" + re.escape(word) + r"\b" # word boundaries to avoid partial matches
        for match in re.finditer(pattern, body, re.IGNORECASE):
            if word not in highlighted_words:
                matched_text = match.group(0)
                if freq_score >= high_threshold:
                    level, points = "high", 10
                else:
                    level, points = "medium", 5
                highlights.append({
                    "text": matched_text,
                    "hover_message": f"Suspicious keyword: +{points}",
                    "risk_level": level
                })
                highlighted_words.add(word) # no double injection of highlighted words
            total_risk += points 
            match_count += 1

    print(f"Total risk: {total_risk}")
    print("Highlights:", highlights)
    print(f"Total matches contributing to risk: {match_count}")

    if body.strip():
        # clean possible html for better analysis
        clean_body = re.sub(r"<[^>]+>", " ", body)
        clean_body = re.sub(r"\s+", " ", clean_body).strip()

        if clean_body:
            try:
                blob = TextBlob(clean_body)
                # phishing emails often mimic official message, avoid overly emotional language
                polarity = blob.sentiment.polarity #-1.0 (very neg) to +1.0 (very positive)
                subjectivity = blob.sentiment.subjectivity #0.0 (objective/factual) to 1.0 (opinionated)

                # negative polarity = fear/urgency intended
                if polarity <= -0.4:
                    points = 10
                    highlights.append({
                        "text": "Urgent tone",
                        "hover_message": f"Fear/urgency detected (polarity={polarity:.2f}) → {points}",
                        "risk_level": "high"
                    })
                    total_risk += 8
                # high positive polarity = overly scammy/pleasing
                elif polarity >= 0.6:
                    points = 5
                    highlights.append({
                        "text": "Overly positive tone",
                        "hover_message": f"Scam-like positivity (polarity={polarity:.2f}) → {points}",
                        "risk_level": "high"
                    })
                    total_risk += 6

                # high subjectivity (opinionated) = high emotional plea
                if subjectivity >= 0.75:
                    points = 5
                    highlights.append({
                        "text": "Manipulative language",
                        "hover_message": f"Highly subjective (subjectivity={subjectivity:.2f}) → {points}",
                        "risk_level": "medium"
                    })
                    total_risk += 5
            except Exception:
                pass

        print("Cleaned body sample:", clean_body[:100])
        print("Polarity:", polarity, "Subjectivity:", subjectivity)

    return {"risk_points": total_risk, "body_highlights": highlights}