from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse

app = Flask(__name__)

def analyze_input(text):
    warnings = []
    
    # --- Enhanced Phishing Link Detection ---
    phishing_keywords = ["login", "verify", "secure", "account", "update", "suspended", 
                        "confirm", "authenticate", "validate", "urgent", "immediately",
                        "click here", "act now"]
    
    # Check for URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    
    for url in urls:
        parsed = urlparse(url)
        
        # IP address check
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc.split(':')[0]):
            warnings.append("⚠️ Link uses an IP address instead of domain (high phishing risk).")
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
            warnings.append("⚠️ Link uses suspicious domain extension (possible phishing).")
        
        # Phishing keywords in URL
        if any(word in url.lower() for word in phishing_keywords):
            warnings.append("⚠️ Suspicious keywords in URL (possible phishing).")
        
        # Homograph attack detection (common substitutions)
        if any(char in parsed.netloc for char in ['а', 'е', 'о', 'р', 'с', 'у', 'х']):  # Cyrillic lookalikes
            warnings.append("⚠️ URL contains lookalike characters (homograph attack).")
        
        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        if any(shortener in parsed.netloc.lower() for shortener in shorteners):
            warnings.append("⚠️ Shortened URL detected (cannot verify destination).")
        
        # Subdomain spoofing
        trusted_domains = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'bank']
        parts = parsed.netloc.split('.')
        if len(parts) > 2:
            for domain in trusted_domains:
                if domain in parts[0].lower() and domain not in '.'.join(parts[-2:]).lower():
                    warnings.append(f"⚠️ Possible subdomain spoofing of '{domain}' detected.")
    
    # --- Enhanced Sensitive Data Detection ---
    
    # Password patterns
    password_patterns = [
        r"password\s*[:=]\s*\S+",
        r"pwd\s*[:=]\s*\S+",
        r"pass\s*[:=]\s*\S+",
    ]
    for pattern in password_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append("🚨 Possible password leakage detected.")
            break
    
    # API keys and tokens
    api_patterns = [
        r"api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}",
        r"(access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}",
        r"['\"]sk-[a-zA-Z0-9]{20,}['\"]",  # OpenAI-style keys
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub personal access tokens
        r"AKIA[0-9A-Z]{16}",  # AWS access keys
    ]
    for pattern in api_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append("🚨 Possible API key/token leakage detected.")
            break
    
    # Credit card numbers
    cc_pattern = r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
    if re.search(cc_pattern, text):
        warnings.append("🚨 Possible credit card number detected.")
    
    # Social Security Numbers (US format)
    ssn_pattern = r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"
    if re.search(ssn_pattern, text):
        warnings.append("🚨 Possible SSN detected (doxxing/identity theft risk).")
    
    # Classified information markers
    if re.search(r"(CONFIDENTIAL|SECRET|TOP SECRET|CLASSIFIED|PROPRIETARY)", text, re.IGNORECASE):
        warnings.append("🚨 Classified or sensitive classification marker detected.")
    
    # --- Enhanced Doxxing Risk Detection ---
    
    # Phone numbers
    phone_patterns = [
        r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # US format
        r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}",  # International
    ]
    for pattern in phone_patterns:
        if re.search(pattern, text):
            warnings.append("🧨 Phone number detected (doxxing risk).")
            break
    
    # Street addresses
    address_pattern = r"\b\d{1,5}\s+\w+(\s+\w+){0,3}\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b"
    if re.search(address_pattern, text, re.IGNORECASE):
        warnings.append("🧨 Possible physical address detected (doxxing risk).")
    
    # Email addresses
    email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    if re.search(email_pattern, text):
        warnings.append("🧨 Email address detected (potential privacy risk).")
    
    # --- Additional Security Checks ---
    
    # SQL Injection patterns
    sql_patterns = [
        r"(\bOR\b|\bAND\b).*=.*",
        r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\s+(ALL|DISTINCT)?\s*(FROM|INTO|TABLE)",
    ]
    for pattern in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append("⚠️ Possible SQL injection attempt detected.")
            break
    
    # XSS patterns
    xss_patterns = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",  # onclick, onerror, etc.
    ]
    for pattern in xss_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append("⚠️ Possible XSS (Cross-Site Scripting) attempt detected.")
            break
    
    if not warnings:
        warnings.append("✅ No obvious security risks detected.")
    
    return warnings

@app.route("/", methods=["GET", "POST"])
def index():
    warnings = None
    if request.method == "POST":
        user_input = request.form.get("user_input", "")
        warnings = analyze_input(user_input)
    return render_template("index.html", warnings=warnings)

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()
    text = data.get("text", "")
    warnings = analyze_input(text)
    return jsonify({"warnings": warnings})

if __name__ == "__main__":
    # Change debug=True to debug=False for production/demo if needed
    app.run(debug=True)