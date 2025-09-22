#PRG P9-6 Email Phishing Detection System - Inbox Guardian

import re
import csv      #for reading CSV files
import email    #for parsing EML files
import os       #for operating system functions

#insert code to read email data from CSV or EML files

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

#Rule 4 = Edit distance checker <= i feel this rule 4 can be somehow merged with rule 1, can be more efficient if combined
def edit_distance_rule4(risk_points, sender_email):
    #to insert code, levehstein concept
    safe_emails = ["lms.support@singaporetech.edu.sg","studentfinance@singaporetech.edu.sg", "ose@singaporetech.edu.sg","registrar@singaporetech.edu.sg"]

#Rule 2 = find suspicious keywords in subject and body
def sus_keywords_rule2(risk_points, subject, body):
    sus_keywords = ["free", "congratulations", "winner", "urgent", "prize", "claim","verify" "offer", "limited", "click", "risk-free", "action required", "act now", "security", "login", "bank"]

    #set variable to count number of suspicious keywords found in subject and body
    subject_hits = 0
    body_hits = 0

    subject_lower = subject.lower()
    body_lower = body.lower()
    
    for word in sus_keywords:
        #check subject line for suspicious keywords (higher risk)
        if word in subject_lower and subject_hits < 3:
            risk_points += 15
            subject_hits += 1
            print(f"Suspicious keyword '{word}' found in subject. Risk +15.")
        
        #check body for suspicious keywords (lower risk)        
        if word in body_lower and body_hits < 4:
            risk_points += 5
            body_hits += 1
            print(f"Suspicious keyword '{word}' found in email body. Risk +5")
    
    #cap the maximum risk points for this rule
    if subject_hits >= 3:
        print(f'{subject_hits} suspicious keywords found in subject. Max risk +45 applied.')
    if body_hits >= 4:
        print(f'{body_hits} suspicious keywords found in email body. Max risk +20 applied.')
        
    return risk_points

#Rule 3 = Check for URLs in the email body
def url_check_rule3(risk_points, body):
    urls = re.findall(r'(https?://\S+)', body)
    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'      #to match URLs that begin with http:// or https:// and followed by a valid IPv4 address format

    for url in urls:
        if re.match(ip_pattern, url):
            risk_points += 40
            print(f"URL, '{url} uses an IP address. Risk +40.")

    return risk_points

#Final Risk Scoring = Tally up all risk points and categorize email legitimacy
def final_risk_scoring(risk_points):
    if risk_points >= 70: 
        risk_category = "HIGH RISK"
        print(f'Email is classified as {risk_category} with {risk_points} risk points. We do not recommend interacting with this email.')
    
    elif 30 <= risk_points < 70:
        risk_category = "MEDIUM RISK"
        print(f'Email is classified as {risk_category} with {risk_points} risk points. Exercise caution when interacting with this email.')

    else:
        risk_category = "LOW RISK"
        print(f'Email is classified as {risk_category} with {risk_points} risk points. Email is likely safe to interact with.')

if __name__ == "__main__":
    # Example test data FOR TESTING PURPOSES - DELETE AFTER INTEGRATION FINALISATION
    
    #sender_email = "smm.support@singaporetech.edu.sg" 
    sender_domain = "eduu.sg"  # typo to test safelist and edit distance
    subject = "Please check this!"
    body = "Click here: http://192.168.1.1 to claim your prize. Login to your account."

    risk_points = 0
    risk_points = safelist_rule1(risk_points, sender_domain)
    # risk_points = whitelist_and_edit_distance_rule1(risk_points, sender_email)  <- to test combined whitelist + edit distance rule
    risk_points = sus_keywords_rule2(risk_points, subject, body)
    risk_points = url_check_rule3(risk_points, body)
    print(f"Total risk points: {risk_points}")
    final_risk_scoring(risk_points)
    print("END OF REPORT - INBOX GUARDIAN")

''' Combined Rule 1 + Rule 4 = Whitelist and Edit Distance Checker (testing first before replacing existing rules)
def whitelist_and_edit_distance_rule1(risk_points, sender_email):
    sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''  #extract domain from sender email
    safelist_domains = ["edu.sg", "gov.sg", "sit.singaporetech.edu.sg"]         #list of trusted domains
    safelist_emails = ["lms.support@singaporetech.edu.sg","studentfinance@singaporetech.edu.sg", "ose@singaporetech.edu.sg","registrar@singaporetech.edu.sg"] #list of trusted emails   

    sender_lower = sender_email.lower()
    
    # CASE 1: Perfect match with safe email = SAFE
    if sender_lower in [email.lower() for email in safelist_emails]:
        print(f"Exact match with safe email: {sender_email}")
        return risk_points
    
    # CASE 2: Domain NOT in safelist = RISKY
    if sender_domain not in safelist_domains:
        risk_points += 20
        print(f"Sender domain, '{sender_domain}', is not in the predefined safelist. Risk +20.") #+20 risk into risk_points when domain is outside safelist
    else:
        print(f"Sender domain, '{sender_domain}', is in the predefined safelist. No risk.")

    # CASE 3: Domain is safe, but potential spoofing detected via edit distance
    for safe_email in safelist_emails:
        matches = sum(1 for a, b in zip(sender_lower, safe_email.lower()) if a == b)
        edit_distance = max(len(sender_lower), len(safe_email)) - matches

        if edit_distance == 1 and sender_lower != safe_email.lower():
            risk_points += 15
            print(f"Potential spoofing detected: '{sender_email}' is similar to safe email '{safe_email}'. Risk +25.")
            break  # No need to check further if a match is found

        elif edit_distance == 2 and sender_lower != safe_email.lower():
            risk_points += 10
            print(f"Potential spoofing detected: '{sender_email}' is similar to safe email '{safe_email}'. Risk +15.")
            break  # No need to check further if a match is found

        else:
            print(f"No spoofing detected for '{sender_email}' against safe email '{safe_email}'.")  

    return risk_points
    '''