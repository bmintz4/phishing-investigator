import re


URGENT_TERMS = [
    "urgent action required",
    "immediate action required",
    "respond immediately",
    "within 24 hours",
    "final notice",
    "action required",
    "time sensitive",
    "time-sensitive",
    "urgent",
    "immediately",
]

CREDENTIAL_REQUEST_TERMS = [
    "confirm your password",
    "provide your password",
    "enter your password",
    "verify your credentials",
    "confirm your credentials",
    "provide your credentials",
    "enter your credentials",
    "login credentials",
    "sign in to confirm",
    "log in to confirm",
]

ACCOUNT_VERIFICATION_TERMS = [
    "verify your account",
    "confirm your account",
    "validate your account",
    "account verification required",
    "account has been suspended",
    "account will be suspended",
    "account has been locked",
    "account will be locked",
    "unusual account activity",
    "unauthorized account activity",
]

PAYMENT_OR_INVOICE_TERMS = [
    "outstanding invoice",
    "overdue invoice",
    "unpaid invoice",
    "invoice attached",
    "payment required",
    "payment is overdue",
    "payment overdue",
    "payment failed",
    "update your payment information",
    "update your billing information",
    "wire transfer",
    "bank transfer",
]

PASSWORD_RESET_OR_EXPIRATION_TERMS = [
    "password has expired",
    "password will expire",
    "password expires today",
    "password reset required",
    "reset your password",
    "change your password",
    "update your password",
    "password expiration notice",
    "keep your current password",
]

THREAT_OR_CONSEQUENCE_TERMS = [
    "account closure",
    "account will be closed",
    "service interruption",
    "access will be revoked",
    "your account is at risk",
    "legal action",
    "collection notice",
    "penalty",
    "late fee",
    "failure to respond",
    "avoid suspension",
    "avoid termination",
]

GENERIC_GREETING_TERMS = [
    "dear customer",
    "dear user",
    "dear account holder",
    "dear valued customer",
    "dear client",
    "hello user",
    "attention user",
]

LINK_CLICK_TERMS = [
    "click here",
    "click the link",
    "follow the link",
    "open the link",
    "use the link below",
    "visit the link below",
    "secure link",
    "verification link",
    "confirm by clicking",
    "login here",
    "sign in here",
]

REWARD_OR_REFUND_TERMS = [
    "you have won",
    "congratulations",
    "claim your prize",
    "claim your reward",
    "gift card",
    "free gift",
    "refund available",
    "refund pending",
    "claim your refund",
    "rebate available",
    "you are eligible",
]


RULES = [
    ("urgent_language", "medium", URGENT_TERMS),
    ("credential_request", "high", CREDENTIAL_REQUEST_TERMS),
    ("account_verification", "medium", ACCOUNT_VERIFICATION_TERMS),
    ("payment_or_invoice_language", "medium", PAYMENT_OR_INVOICE_TERMS),
    ("password_reset_or_expiration", "medium", PASSWORD_RESET_OR_EXPIRATION_TERMS),
    ("threat_or_consequence", "medium", THREAT_OR_CONSEQUENCE_TERMS),
    ("generic_greeting", "low", GENERIC_GREETING_TERMS),
    ("link_click", "low", LINK_CLICK_TERMS),
    ("reward_or_refund", "high", REWARD_OR_REFUND_TERMS),
]


def _find_phrase(email_text: str, phrases: list[str]) -> str | None:
    """Return the longest phrase found as a complete phrase in the email."""
    for phrase in sorted(phrases, key=len, reverse=True):
        pattern = rf"(?<!\w){re.escape(phrase)}(?!\w)"
        if re.search(pattern, email_text):
            return phrase
    return None


# Analyze email text for deterministic phishing indicators.
def analyze_rules(email_text: str) -> list[dict]:
    """Return structured findings for phishing-related phrases."""
    if not isinstance(email_text, str) or not email_text.strip():
        return []

    normalized_text = " ".join(email_text.casefold().split())
    findings = []

    for rule_name, severity, phrases in RULES:
        matched_phrase = _find_phrase(normalized_text, phrases)
        if matched_phrase:
            findings.append(
                {
                    "rule": rule_name,
                    "severity": severity,
                    "evidence": f"Found phrase: {matched_phrase}",
                }
            )

    return findings
