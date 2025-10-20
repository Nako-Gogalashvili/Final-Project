# 1. თუ საეჭვო სიტყვაა ფიშინგია
for keyword in SUSPICIOUS_KEYWORDS:
if keyword in body:
print(f"[!] Keyword found: {keyword}";)
return True

# 2. თუ sender-ის დომენი საეჭვოა → ფიშინგია
sender_domain = extract_domain(sender)
if sender_domain in SUSPICIOUS_DOMAINS:
print(f"[!] Suspicious sender domain: {sender_domain}")
return True

if url_domain in SHORTENERS:
print(f"[!] Suspicious URL detected in email!")
return True

# თუ არაფერი საეჭვო არ არის
return False

# შემოწმება
if is_phishing_email(sample_email):
print("⚠️ ფიშინგის მცდელობაა!")
else:
print("✅ ელფოსტა უსაფრთხოა")