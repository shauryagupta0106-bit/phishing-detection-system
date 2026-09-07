import re
from urllib.parse import urlparse

SUSPICIOUS_URL_KEYWORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "confirm", "password", "signin", "bank", "wallet", "payment",
    "recover", "unlock", "urgent", "security"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work", "gq", "tk", "ml", "cf"
}

EMAIL_URGENCY = {
    "urgent", "immediately", "act now", "within 24 hours", "suspended",
    "final warning", "last chance", "expires today", "asap"
}

EMAIL_REQUESTS = {
    "password", "otp", "one-time password", "verification code",
    "credit card", "card number", "cvv", "bank account", "pin",
    "wire transfer", "gift card", "login credentials"
}

KNOWN_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "instagram", "facebook", "linkedin", "bank", "sbi", "hdfc", "icici"
]

def _clamp(score):
    return max(0, min(100, score))

def _add(findings, title, detail, severity, points):
    findings.append({
        "title": title,
        "detail": detail,
        "severity": severity,
        "points": points
    })

def analyze_url(text):
    raw = text.strip()
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    path_query = f"{parsed.path}?{parsed.query}".lower()

    findings = []
    score = 0

    if parsed.scheme not in {"http", "https"}:
        _add(findings, "Unusual URL scheme", f"The scheme '{parsed.scheme}' is not a normal web scheme.", "high", 25)
        score += 25

    if parsed.scheme == "http":
        _add(findings, "No HTTPS", "The URL uses HTTP instead of HTTPS. Encryption alone does not prove a site is safe, but missing HTTPS is a warning sign.", "medium", 10)
        score += 10

    if "@" in parsed.netloc:
        _add(findings, "Username-like @ pattern", "An @ symbol in the authority section can hide the real destination from a casual reader.", "high", 25)
        score += 25

    if len(raw) > 100:
        _add(findings, "Very long URL", f"The URL is {len(raw)} characters long, which can make inspection harder.", "medium", 10)
        score += 10

    if len(host) > 40:
        _add(findings, "Long hostname", "The hostname is unusually long and may be attempting to obscure the actual domain.", "medium", 10)
        score += 10

    if host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        _add(findings, "IP address used as hostname", "The link points directly to an IP address instead of a normal domain name.", "medium", 15)
        score += 15

    if host.count(".") >= 4:
        _add(findings, "Many subdomains", f"The hostname contains {host.count('.') + 1} labels.", "medium", 10)
        score += 10

    if "-" in host:
        _add(findings, "Hyphenated hostname", "Hyphens in a hostname are not malicious by themselves, but can appear in look-alike domains.", "low", 5)
        score += 5

    if host in SHORTENER_DOMAINS:
        _add(findings, "URL shortener", "Shortened links hide the final destination, so the destination should be verified before opening.", "medium", 15)
        score += 15

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        _add(findings, "Higher-risk TLD pattern", f"The domain ends in .{tld}. This is not proof of phishing, but it is treated as a caution signal by this educational scanner.", "medium", 10)
        score += 10

    keyword_hits = sorted({kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in path_query or kw in host})
    if keyword_hits:
        _add(findings, "Suspicious security/account wording", f"Detected: {', '.join(keyword_hits)}.", "medium", min(25, 5 * len(keyword_hits)))
        score += min(25, 5 * len(keyword_hits))

    digit_runs = re.findall(r"\d{5,}", host)
    if digit_runs:
        _add(findings, "Unusual numeric sequence", "The hostname contains a long numeric sequence.", "low", 5)
        score += 5

    brand_hits = [b for b in KNOWN_BRANDS if b in host]
    if brand_hits:
        _add(findings, "Brand name appears in hostname", f"Detected brand-related wording: {', '.join(brand_hits)}. Verify the registered domain carefully.", "medium", 10)
        score += 10

    if not host or "." not in host:
        _add(findings, "Invalid or incomplete hostname", "A normal public web hostname usually contains a domain structure such as example.com.", "high", 30)
        score += 30

    score = _clamp(score)
    verdict = "Likely Suspicious" if score >= 50 else ("Needs Review" if score >= 25 else "Likely Safe")
    return {
        "input_type": "URL",
        "verdict": verdict,
        "score": score,
        "risk_level": "High" if score >= 50 else ("Medium" if score >= 25 else "Low"),
        "summary": "This is a heuristic educational scanner, not a guarantee that a URL is safe or malicious.",
        "findings": findings,
        "normalized": candidate,
        "domain": host or "Not detected"
    }

def analyze_email(text):
    findings = []
    score = 0
    lower = text.lower()

    urgency_hits = sorted({x for x in EMAIL_URGENCY if x in lower})
    if urgency_hits:
        points = min(25, 5 * len(urgency_hits))
        _add(findings, "Urgency or pressure language", f"Detected: {', '.join(urgency_hits)}.", "medium", points)
        score += points

    request_hits = sorted({x for x in EMAIL_REQUESTS if x in lower})
    if request_hits:
        points = min(30, 6 * len(request_hits))
        _add(findings, "Sensitive-information request", f"Detected requests or references involving: {', '.join(request_hits)}.", "high", points)
        score += points

    urls = re.findall(r"https?://[^\s<>()]+|www\.[^\s<>()]+", text, flags=re.I)
    if urls:
        _add(findings, "Contains link(s)", f"Found {len(urls)} URL-like link(s). Links in unexpected emails should be checked before opening.", "medium", min(20, 10 * len(urls)))
        score += min(20, 10 * len(urls))

        for u in urls[:3]:
            url_result = analyze_url(u)
            if url_result["score"] >= 25:
                _add(findings, "A linked URL needs review", f"{u} produced a URL risk score of {url_result['score']}/100.", "high", 10)
                score += 10

    sender_match = re.search(r"(?:from|sender)\s*:\s*([^\s<>]+@[^\s<>]+)", text, re.I)
    email_addresses = re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, flags=re.I)
    if email_addresses:
        domains = sorted({a.split("@", 1)[1].lower() for a in email_addresses})
        if len(domains) > 1:
            _add(findings, "Multiple sender/link domains", f"Detected email domains: {', '.join(domains)}. Different domains can be legitimate, but unexpected mismatches deserve review.", "medium", 10)
            score += 10

        if sender_match:
            sender_domain = sender_match.group(1).split("@", 1)[1].lower()
            body_brand_hits = [b for b in KNOWN_BRANDS if b in lower]
            if body_brand_hits and not any(b in sender_domain for b in body_brand_hits):
                _add(findings, "Possible brand/domain mismatch", f"The message mentions {', '.join(body_brand_hits)}, but the sender domain is {sender_domain}. Verify the sender independently.", "high", 20)
                score += 20

    if re.search(r"dear (customer|user|member|account holder)\b", lower):
        _add(findings, "Generic greeting", "A generic greeting can be used in mass phishing campaigns. It is only a weak signal by itself.", "low", 5)
        score += 5

    if re.search(r"attachment|attached|invoice|receipt|document", lower):
        _add(findings, "Attachment-related wording", "Unexpected attachments can be risky. Verify the sender and context before opening them.", "medium", 10)
        score += 10

    score = _clamp(score)
    verdict = "Likely Suspicious" if score >= 50 else ("Needs Review" if score >= 25 else "Likely Safe")
    return {
        "input_type": "Email",
        "verdict": verdict,
        "score": score,
        "risk_level": "High" if score >= 50 else ("Medium" if score >= 25 else "Low"),
        "summary": "This analyzer uses explainable text-based heuristics. It should support human review, not replace it.",
        "findings": findings
    }

def analyze_input(text, input_type):
    return analyze_url(text) if input_type == "url" else analyze_email(text)
