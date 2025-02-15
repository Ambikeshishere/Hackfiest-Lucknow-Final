import imaplib
import email
import re
import pandas as pd
from email.header import decode_header
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import os

EMAIL = "abhay2004raj15@gmail.com"
PASSWORD = "uvgc jdra muxw bjdo"
IMAP_SERVER = "imap.gmail.com"

dataset = pd.read_csv("emails.csv")

email_column = 'text'
label_column = 'spam'
dataset.dropna(subset=[email_column, label_column], inplace=True)

def extract_email(text):
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    return match.group(0) if match else None

tfidf = TfidfVectorizer(stop_words='english', max_features=5000)
X = tfidf.fit_transform(dataset[email_column]).toarray()
y = dataset[label_column]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

try:
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL, PASSWORD)
    mail.select("inbox")

    status, messages = mail.search(None, "ALL")
    if status != "OK":
        print("No emails found.")
        exit()

    messages = messages[0].split()

    recent_messages = messages[-30:]

    for msg_num in recent_messages:
        try:
            status, msg_data = mail.fetch(msg_num, "(RFC822)")
            if status != "OK":
                print(f"Failed to fetch email {msg_num}.")
                continue

            raw_email = msg_data[0][1]

            msg = email.message_from_bytes(raw_email)
            sender = msg["From"]
            subject = decode_header(msg["Subject"])[0][0]
            date_str = msg["Date"]

            if isinstance(subject, bytes):
                subject = subject.decode(errors="ignore")

            sender_email = extract_email(sender)

            print(f"\n📩 New Email from: {sender_email}")
            print(f"📌 Subject: {subject}")

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if "attachment" not in content_disposition and content_type == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                        except Exception as e:
                            print(f"⚠️ Error decoding email body: {e}")
            else:
                try:
                    body = msg.get_payload(decode=True).decode(errors="ignore")
                except Exception as e:
                    print(f"⚠️ Error decoding email body: {e}")

            print(f"📄 Email Content: {body[:200]}...")

            email_tfidf = tfidf.transform([body])
            prediction = model.predict(email_tfidf)
            prediction_label = "Spam" if prediction[0] == 1 else "Not Spam"
            print(f"🔍 Prediction: {prediction_label}")

            if prediction_label == "Spam":
                mail.store(msg_num, "+FLAGS", "\\Seen")

        except Exception as e:
            print(f"⚠️ Error processing email {msg_num}: {e}")

finally:
    try:
        mail.logout()
    except Exception as e:
        print(f"⚠️ Error logging out: {e}")
