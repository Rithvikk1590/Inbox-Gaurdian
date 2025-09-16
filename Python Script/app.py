import re


#insert data cleaning process here



risk_points = 0

#rule 1 = whitelist check
def safelist_rule1(risk_points, sender_domain):

    safelist = ["edu.sg", "gov.sg"]  #assume we are only accepting emails from these domains
    if sender_domain not in safelist:
        risk_points += 20
        print("Sender domain is not in the predefined safelist. Be careful!")
    return risk_points

#rule 2 = suspicious keywords in subject and body
def sus_keywords_rule2(risk_points, subject, body):
    sus_keywords = ["free", "cogratulations", "winner", "urgent", "prize", "claim","verify" "offer" , "limited", "click", "risk-free", "verify"]
    for word in sus_keywords:
        if word in subject.lower():
            risk_points += 20
        
        if word in body.lower():
            risk_points += 10
    
    return risk_points
