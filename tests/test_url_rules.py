import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.security.url_rules import analyze_url_rules


def test_url_rules_report_highest_severity_rule_per_link():
    html = """
    <html>
        <body>
            <a href="http://example.com/login">Secure Portal</a>
            <a href="https://evil.example/login">Bank Login</a>
            <a href="https://example.com/account">example.com</a>
        </body>
    </html>
    """

    assert analyze_url_rules(html) == [
        {
            "type": "URL",
            "subtype": "insecure link",
            "severity": "medium",
            "evidence": "http://example.com/login",
        },
        {
            "type": "URL",
            "subtype": "name mismatch",
            "severity": "low",
            "evidence": "Text: Bank Login\nAddress: https://evil.example/login",
        },
        {
            "type": "URL",
            "subtype": "found",
            "severity": "none",
            "evidence": "https://example.com/account",
        },
    ]


def test_url_rules_returns_empty_list_when_no_links_are_found():
    assert analyze_url_rules("<p>No links here.</p>") == []
