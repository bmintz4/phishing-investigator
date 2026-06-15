import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.security.rules import analyze_rules


def test_analyze_rules_returns_structured_findings():
    email_text = (
        "URGENT ACTION REQUIRED. Verify your account and enter your credentials. "
        "Your payment is overdue, and your password will expire soon."
    )

    assert analyze_rules(email_text) == [
        {
            "rule": "urgent_language",
            "severity": "medium",
            "evidence": "Found phrase: urgent action required",
        },
        {
            "rule": "credential_request",
            "severity": "high",
            "evidence": "Found phrase: enter your credentials",
        },
        {
            "rule": "account_verification",
            "severity": "medium",
            "evidence": "Found phrase: verify your account",
        },
        {
            "rule": "payment_or_invoice_language",
            "severity": "medium",
            "evidence": "Found phrase: payment is overdue",
        },
        {
            "rule": "password_reset_or_expiration",
            "severity": "medium",
            "evidence": "Found phrase: password will expire",
        },
    ]
    print("[TEST] rules return structured findings")


def test_analyze_rules_is_case_insensitive_and_normalizes_whitespace():
    email_text = "Please VERIFY\n\tYOUR ACCOUNT within 24 hours."

    assert analyze_rules(email_text) == [
        {
            "rule": "urgent_language",
            "severity": "medium",
            "evidence": "Found phrase: within 24 hours",
        },
        {
            "rule": "account_verification",
            "severity": "medium",
            "evidence": "Found phrase: verify your account",
        },
    ]
    print("[TEST] rules normalize whitespace/capitals")


def test_analyze_rules_returns_empty_list_for_no_matches_or_invalid_text():
    assert analyze_rules("Here are the meeting notes from today.") == []
    assert analyze_rules("") == []
    assert analyze_rules(None) == []
    print("[TEST] rules return empty list when text has no indicators")


if __name__ == "__main__":
    test_analyze_rules_returns_structured_findings()
    test_analyze_rules_is_case_insensitive_and_normalizes_whitespace()
    test_analyze_rules_returns_empty_list_for_no_matches_or_invalid_text()
    