import re
from email import message_from_string
import json

with open("suspicious_elements.json", "r", encoding="utf-8") as f:
    suspicious_elements = json.load(f)

def extract_domain(email_address):
    match = re.search(r'@([\w\.-]+)', email_address or "")
    return match.group(1) if match else None

def extract_urls(text):
    return re.findall(r'http[s]?://[^\s]+', text or "")
  
def extract_email_body(email):
    msg = message_from_string(email)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
            
    else:
     return msg.get_payload(decode=True).decode(errors="ignore")
    return ""


def evaluate_email_risk(email):
    msg = message_from_string(email)
    sender = msg.get("From", "")
    subject = msg.get("Subject", "")
    body = extract_email_body(email)
    
    total_score = 1
    detections = []

    for keyword, weight in suspicious_elements["keyword"].items():
      if keyword in (body) or keyword in (subject):
        total_score *= weight
        detections.append(f"Keyword '{keyword}' (*{weight})")


    urls = extract_urls(body)
    for url in urls:
        match = re.search(r'//([^/]+)', url)
        url_domain = match.group(1) if match else None
    if url_domain in suspicious_elements["domain"]:
        weight = suspicious_elements["domain"][url_domain]
        total_score *= weight
        detections.append(f"Suspicious URL domain ({url_domain}) (*{weight})")


    sender_domain = extract_domain(sender)
    if sender_domain and sender_domain in suspicious_elements ["domain"]:
        weight =suspicious_elements ["domain"][sender_domain]
        total_score *= weight
        detections.append(f"Suspicious sender domain ({sender_domain}) (*{weight})")
    
     
     phishing_prob = min((total_score-1) * 30, 100)
    
    return {
        "score": total_score,
        "risk_level": risk_level,
        "probability": round(phishing_prob, 1),
        "detections": detections }


if total_score >= :
    risk_level = "🔴 Phishing მაღალი რისკი"
elif total_score >= :
    risk_level = "🟠 Phishing საშუალო რისკი"
elif total_score >:
    risk_level = "🟡 Phishing დაბალი რისკი"
else: 
    risk_level = "✅ არა სარისკო მეილი"





#შემოწმება

sample_email = """  """

result = evaluate_email_risk(sample_email)

print("📊 ფიშინგის შეფასება")
print("---------------------------")
print(f"ქულა: {result['score']}")
print(f"რისკის დონე: {result['risk_level']}")
print(f"ფიშინგის ალბათობა: {result['probability']}%")
print("აღმოჩენები:")
for f in result["detections"]:
    print(" -", f)