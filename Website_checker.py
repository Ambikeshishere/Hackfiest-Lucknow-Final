import openai
import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, UTC
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import joblib  # For saving and loading models
import os

# List of known URL shortening services
SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly", 
    "adf.ly", "bit.do", "shorte.st", "tiny.cc", "cutt.ly", "shorturl.at", 
    "rebrand.ly", "clicky.me", "soo.gd", "s2r.co", "short.io", "tiny.one"
]

# Example dataset for training the URL shortening detection model
def load_shortening_dataset():
    data = {
        "URL": [  # Use "URL" instead of "url"
            "https://bit.ly/3abc123",
            "https://tinyurl.com/xyz456",
            "https://example.com/path/to/page",
            "https://google.com/search?q=query",
            "https://cutt.ly/abc123",
            "https://github.com/user/repo"
        ],
        "label": ["shortened", "shortened", "not_shortened", "not_shortened", "shortened", "not_shortened"]
    }
    return pd.DataFrame(data)

# Train the AI/ML model for URL shortening detection
def train_model():
    df = load_shortening_dataset()
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 4))
    X = vectorizer.fit_transform(df["URL"])  # Use "URL" here
    y = df["label"]
    model = RandomForestClassifier()
    model.fit(X, y)
    return model, vectorizer

# Load phishing dataset
def load_phishing_dataset():
    df = pd.read_csv('phishing_dataset.csv')
    # print("Dataset columns:", df.columns)  # Debugging: Print column names
    # print(df.head())  # Debugging: Print first few rows
    return df

# Train the AI/ML model for phishing detection
def train_phishing_model(df):
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 4))
    X = vectorizer.fit_transform(df["URL"])  
    y = df["label"]
    model = RandomForestClassifier()
    model.fit(X, y)
    return model, vectorizer

# Save the trained model and vectorizer to disk
def save_model(model, vectorizer, model_filename="phishing_model.pkl", vectorizer_filename="phishing_vectorizer.pkl"):
    joblib.dump(model, model_filename)
    joblib.dump(vectorizer, vectorizer_filename)
    print(f"Model saved to {model_filename}")
    print(f"Vectorizer saved to {vectorizer_filename}")

# Load the trained model and vectorizer from disk
def load_model(model_filename="phishing_model.pkl", vectorizer_filename="phishing_vectorizer.pkl"):
    if os.path.exists(model_filename) and os.path.exists(vectorizer_filename):
        model = joblib.load(model_filename)
        vectorizer = joblib.load(vectorizer_filename)
        print("Model and vectorizer loaded from disk.")
        return model, vectorizer
    else:
        print("No saved model found. Training a new model...")
        return None, None

# Check if the URL is from a known shortening service
def is_shortened_url(url):
    domain = urlparse(url).netloc
    return domain in SHORTENING_SERVICES

# Resolve a shortened URL to its final destination
def resolve_shortened_url(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.url
    except requests.RequestException as e:
        print(f"Error resolving URL: {e}")
        return None

# Search the web to verify if a domain is a URL shortening service
def search_web_for_shortening_service(domain):
    query = f"{domain} URL shortening service"
    api_key = "AIzaSyBaZqoQZueNh7NiX4Q8NteI3QZMMHmp_LU"  # Replace with your Google API key
    cx = "75212d0343a6c4e0b"  # Replace with your Custom Search Engine ID
    url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={api_key}&cx={cx}"
    
    response = requests.get(url)
    if response.status_code == 200:
        results = response.json()
        if "items" in results:
            for item in results["items"]:
                if "URL shortening" in item["snippet"]:
                    return True
    return False

# Fetch and validate SSL/TLS certificate
def get_ssl_certificate(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            return cert

def validate_certificate(cert):
    not_after = cert.not_valid_after_utc
    current_time = datetime.now(UTC)
    if current_time > not_after:
        print("Certificate has expired.")
        return False
    else:
        print(f"Certificate is valid until: {not_after}")
        return True

# Scan the URL using VirusTotal API
def scan_url_with_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    scan_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url}
    response = requests.post(scan_url, headers=headers, data=payload)
    
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        print(f"Scan submitted. Scan ID: {scan_id}")
        
        # Get the scan report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        report_response = requests.get(report_url, headers=headers)
        
        if report_response.status_code == 200:
            report = report_response.json()
            malicious = report["data"]["attributes"]["stats"]["malicious"]
            suspicious = report["data"]["attributes"]["stats"]["suspicious"]
            print(f"Malicious: {malicious}, Suspicious: {suspicious}")
            return malicious > 0 or suspicious > 0
        else:
            print("Failed to fetch report.")
            return False
    else:
        print("Failed to submit URL for scanning.")
        return False
        
def is_url_suspicious(url, phishing_df):
    """
    Check if the URL is marked as suspicious (phishing) in the phishing dataset.
    
    Args:
        url (str): The URL to check.
        phishing_df (pd.DataFrame): The phishing dataset.
    
    Returns:
        bool: True if the URL is marked as suspicious, False otherwise.
    """
    normalized_url = url.lower().strip()
    match = phishing_df[phishing_df["URL"].str.lower().str.strip() == normalized_url]
    return not match.empty and match.iloc[0]["label"] == 1


# Analyze a URL for shortening, resolve it, validate SSL/TLS, and scan with VirusTotal
def analyze_url(url, model, vectorizer, phishing_model, phishing_vectorizer, virustotal_api_key, phishing_df):
    # Step 1: Check if the URL is marked as suspicious in the phishing dataset
    if is_url_suspicious(url, phishing_df):
        print("Warning: This URL is marked as suspicious (phishing) in the dataset.")
    else:
        print("URL is not marked as suspicious in the dataset.")

    # Step 2: Check if the URL is shortened (existing logic)
    if is_shortened_url(url):
        print("URL is shortened (from database).")
        final_url = resolve_shortened_url(url)
        if final_url:
            print(f"Resolved URL: {final_url}")
            url = final_url
    else:
        # Step 3: Use the AI/ML model to predict shortening
        X = vectorizer.transform([url])
        prediction = model.predict(X)[0]
        if prediction == "shortened":
            print("URL is predicted as shortened by the model.")
            final_url = resolve_shortened_url(url)
            if final_url:
                print(f"Resolved URL: {final_url}")
                url = final_url
            else:
                # Step 4: Search the web to verify shortening
                domain = urlparse(url).netloc
                if search_web_for_shortening_service(domain):
                    print("URL is confirmed as shortened via web search.")
                else:
                    print("URL is not shortened.")
        else:
            print("URL is not shortened.")

    # Step 5: Validate SSL/TLS certificate (existing logic)
    domain = urlparse(url).netloc
    try:
        cert = get_ssl_certificate(domain)
        is_valid = validate_certificate(cert)
        if not is_valid:
            print("Warning: SSL/TLS certificate is invalid or expired.")
    except Exception as e:
        print(f"Error fetching SSL/TLS certificate: {e}")

    # Step 6: Scan with VirusTotal (existing logic)
    print("Scanning URL with VirusTotal...")
    is_malicious = scan_url_with_virustotal(url, virustotal_api_key)
    if is_malicious:
        print("Warning: This URL is flagged as malicious or suspicious.")
    else:
        print("URL is clean according to VirusTotal.")

    # Step 7: Check for phishing using the phishing model (existing logic)
    X_phishing = phishing_vectorizer.transform([url])
    phishing_prediction = phishing_model.predict(X_phishing)[0]
    if phishing_prediction == "phishing":
        print("Warning: This URL is flagged as phishing.")
    else:
        print("URL is not flagged as phishing.")

# Main function
def main():
    # Load phishing dataset
    phishing_df = load_phishing_dataset()

    # Load or train the phishing model
    phishing_model, phishing_vectorizer = load_model()
    if phishing_model is None or phishing_vectorizer is None:
        phishing_model, phishing_vectorizer = train_phishing_model(phishing_df)
        save_model(phishing_model, phishing_vectorizer)

    # Train the URL shortening detection model
    model, vectorizer = train_model()

    # VirusTotal API key
    virustotal_api_key = "ad082035a868924287160e1fe5004021963f5c9c2f028ffcb6b547c86ee2fa8c"  # Replace with your key

    # Analyze the URL
    url = input("Enter your URL: ")
    analyze_url(url, model, vectorizer, phishing_model, phishing_vectorizer, virustotal_api_key, phishing_df)

if __name__ == "__main__":
    main()
