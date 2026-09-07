# 🛡️ PhishGuard

**Phishing Detection System for URL & Email Analysis**

PhishGuard is a beginner-friendly cybersecurity web application that analyzes URLs and email text for common phishing indicators. It uses explainable, rule-based heuristics to calculate a risk score and show the evidence behind the result.

> Educational project only. It is not a replacement for commercial threat-intelligence services or human security review.

## ✨ Features

- URL analysis
- Email text analysis
- Explainable risk score from 0–100
- Suspicious keyword detection
- URL structure checks
- IP-address hostname detection
- URL shortener detection
- Suspicious TLD pattern checks
- Brand/domain mismatch checks in email text
- Urgency and sensitive-information request detection
- Clean responsive cybersecurity dashboard
- Automated tests with pytest
- No external API key required

## 🧠 Detection approach

The system does not claim that a single signal proves phishing. Instead, multiple weak signals contribute points to a transparent score.

### URL signals

- HTTP instead of HTTPS
- `@` patterns in the authority section
- unusually long URLs
- long hostnames
- IP addresses used as hosts
- many subdomains
- URL shorteners
- selected higher-risk TLD patterns
- suspicious account/security keywords
- unusual numeric sequences
- brand-related wording in hostnames

### Email signals

- urgency and pressure language
- requests for passwords, OTPs, payment details, etc.
- links inside messages
- links whose URLs produce warning signals
- multiple email domains
- possible brand/sender-domain mismatch
- generic greetings
- attachment-related wording

## 🏗️ Architecture

```text
Browser
   │
   ▼
Flask Web App
   │
   ├── /              → Dashboard
   │
   └── /analyze       → JSON API
            │
            ▼
      analyzer.py
            │
            ├── URL rules
            └── Email rules
            │
            ▼
       Risk score + findings
            │
            ▼
         Dashboard
```

## 🚀 Run locally on Windows

### 1. Install Python

Install Python 3.11+ and make sure Python is added to PATH.

Check:

```powershell
python --version
```

### 2. Open the project folder

```powershell
cd path\to\phishing_detection_system
```

### 3. Create a virtual environment

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\activate
```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

### 5. Run tests

```powershell
pytest -q
```

### 6. Start the application

```powershell
python app.py
```

Open the address shown by Flask, normally:

```text
http://127.0.0.1:5000
```

## 🧪 Safe testing

Use the examples in `sample_data/`. Do not paste passwords, OTPs, private emails, confidential company information, or other secrets.

## 📁 Project structure

```text
phishing_detection_system/
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
│   └── index.html
├── static/
│   └── style.css
├── tests/
│   └── test_analyzer.py
└── sample_data/
    ├── safe_urls.txt
    ├── suspicious_urls.txt
    └── sample_emails.txt
```

## 🔐 Security note

This project intentionally focuses on static analysis. It does not open submitted links, execute attachments, send emails, or perform unauthorized scanning.

## 🔮 Future improvements

- DNS and WHOIS enrichment
- certificate inspection
- reputation APIs
- machine-learning classifier
- HTML email parsing
- SPF/DKIM/DMARC header analysis
- browser extension
- database of known malicious indicators
- authentication and audit logging
- Docker deployment
