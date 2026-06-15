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


def test_analyze_rules_returns_new_categories_with_requested_priorities():
    email_text = (
        "Dear valued customer, your account will be closed. "
        "Use the link below to claim your refund."
    )

    assert analyze_rules(email_text) == [
        {
            "rule": "threat_or_consequence",
            "severity": "medium",
            "evidence": "Found phrase: account will be closed",
        },
        {
            "rule": "generic_greeting",
            "severity": "low",
            "evidence": "Found phrase: dear valued customer",
        },
        {
            "rule": "link_click",
            "severity": "low",
            "evidence": "Found phrase: use the link below",
        },
        {
            "rule": "reward_or_refund",
            "severity": "high",
            "evidence": "Found phrase: claim your refund",
        },
    ]


def test_analyze_rules_returns_empty_list_for_no_matches_or_invalid_text():
    assert analyze_rules("Here are the meeting notes from today.") == []
    assert analyze_rules("") == []
    assert analyze_rules(None) == []
