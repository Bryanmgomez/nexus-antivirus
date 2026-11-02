from nexus.security.url_analysis import analyze_url


def test_url_phishing_indicators():
    result = analyze_url("http://paypa1-secure-login.example.com/verify.exe")
    assert result.score >= 35
    assert result.verdict in {"suspicious", "malicious"}


def test_url_cleanish():
    result = analyze_url("https://example.com/index.html")
    assert result.score < 70
