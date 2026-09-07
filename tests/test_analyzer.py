from analyzer import analyze_input

def test_safe_url_has_low_score():
    result = analyze_input("https://www.example.com/", "url")
    assert result["score"] < 25

def test_suspicious_url_scores_higher():
    result = analyze_input(
        "http://secure-account-verify-login.example.top/update-password",
        "url"
    )
    assert result["score"] >= 50
    assert result["verdict"] == "Likely Suspicious"

def test_suspicious_email_scores_higher():
    text = """
    From: security-alert@random-mail.example
    Subject: URGENT final warning
    Your account is suspended. Verify your password and OTP immediately:
    http://secure-account.example.top/login
    """
    result = analyze_input(text, "email")
    assert result["score"] >= 50

def test_email_returns_explainable_findings():
    result = analyze_input(
        "From: newsletter@example.com\nSubject: Monthly update\n\nHello, here are the latest updates.",
        "email"
    )
    assert "findings" in result
    assert isinstance(result["findings"], list)
