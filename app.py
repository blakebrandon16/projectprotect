from flask import Flask, render_template, request
import re

app = Flask(__name__)

def analyze_input(text):
    warnings = []

    # --- Phishing Link Detection ---
    phishing_keywords = ["login", "verify", "secure", "account", "update"]
    if "http" in text:
        if any(word in text.lower() for word in phishing_keywords):
            warnings.append("⚠️ Suspicious link detected (possible phishing).")

        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", text):
            warnings.append("⚠️ Link uses an IP address (high phishing risk).")

    # --- Sensitive Data Detection ---
    if re.search(r"password\s*[:=]", text, re.IGNORECASE):
        warnings.append("🚨 Possible password leakage detected.")

    if re.search(r"api[_-]?key\s*[:=]", text, re.IGNORECASE):
        warnings.append("🚨 Possible API key leakage detected.")

    if re.search(r"(CONFIDENTIAL|SECRET|TOP SECRET)", text, re.IGNORECASE):
        warnings.append("🚨 Classified or sensitive keywords detected.")

    # --- Doxxing Risk Detection ---
    if re.search(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", text):
        warnings.append("🧨 Phone number detected (doxxing risk).")

    if re.search(r"\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|Blvd)\b", text, re.IGNORECASE):
        warnings.append("🧨 Possible home address detected.")

    if re.search(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", text):
        warnings.append("🧨 Email address detected.")

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

if __name__ == "__main__":
    app.run(debug=True)
