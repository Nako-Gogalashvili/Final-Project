import re
from email import message_from_string

# საეჭვო ელემენტები
SUSPICIOUS_WORDS = [
"verify your account", "login immediately", "update your information",
"urgent action required", "click here","suspended","unauthorized access", "password“,
"reset“, "confirm","limited","invoice"
]

SUSPICIOUS_DOMAINS = ["bit.ly","tinyurl.com","phishy-domain.com", "badsite.ru"]
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com","is.gd", "ow.ly", "goo.gl","t.co", "buff.ly"]

# ამოღებს დომენს ელფოსტის მისამართიდან
def extract_domain(email_address):
# ეძებს @-ის შემდეგ დომენის ნაწილს
match = re.search(r&#39;@([\w\.-]+)&#39;, email_address)
return match.group(1).lower() if match else;

# ამოწმებს URL-ს არის თუ არა საეჭვო shortener-ში
def contains_suspicious_url(text):
# ეძებს URL-ებს ტექსტში
urls = re.findall(r&#39;http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&amp;+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-
F]))+&#39;, text)

for url in urls:
for domain in SHORTENER_DOMAINS:
if domain in url:
print(f"[!] Suspicious shortener URL found: {url}")
return True

# ამოწმებს ელფოსტას არის თუ არა ფიშინგი
def is_phishing_email(email_raw):
email_msg = message_from_string(email_raw)
subject = email_msg.get("subject").lower()
sender = email_msg.get("from").lower()
body =