#PRG P9-6 Email Phishing Detection System - Inbox Guardian

import re
import csv      #for reading CSV files
import email    #for parsing EML files

#insert data cleaning process here

risk_points = 0

#Rule 1 = whitelist check - safelist of trusted domains for school email environment

def safelist_rule1(risk_points, sender_domain):
    safelist_domains = ["edu.sg", "gov.sg", "sit.singaporetech.edu.sg"] #list of trusted domains

    if sender_domain not in safelist_domains:
        risk_points += 20
        print(f"Sender domain, '{sender_domain}', is not in the predefined safelist. Risk +20.") #+20 risk into risk_points when domain is outside safelist
    else:
        print(f"Sender domain, '{sender_domain}', is in the predefined safelist. No risk.")

    return risk_points

#Rule 2 = suspicious keywords in subject and body
def sus_keywords_rule2(risk_points, subject, body):
    sus_keywords = ["free", "congratulations", "winner", "urgent", "prize", "claim","verify" "offer", "limited", "click", "risk-free", "now"]
    for word in sus_keywords:
        if word in subject.lower():
            risk_points += 20
            print(f"Suspicious keyword {word} found in subject. Be careful!")
        
        if word in body.lower():
            risk_points += 10
            print(f"Suspicious keyword {word} found in subject. Be careful!")

#Rule 3 = Check for URLs in the email body
def url_check_rule3(risk_points, body):
    urls = re.findall(r'(https?://\S+)', body)

    
    return risk_points
