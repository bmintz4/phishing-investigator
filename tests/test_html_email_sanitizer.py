import src.ingestion.html_email_sanitizer as sanitizer
from src.ingestion.html_email_sanitizer import (
    SanitizerConfig,
    html_to_text_sanitized,
    html_to_text_santized,
    parse_html_email_to_sanitized_record,
    sanitize_text,
)


def test_html_to_text_santized_replaces_html_email_entities_with_meajor_tokens():
    html = """
    <html>
      <body>
        <p>Hi John,</p>
        <p>Use <a href="https://secure.example.com/login?id=123">https://visible.example/login</a></p>
        <p>Email jane.doe@example.com or call (212) 555-0199 by Jan 5, 2025 at 09:30 AM.</p>
        <p>Invoice INV-99128 for $1,250.00 is attached as statement.pdf.</p>
        <p>Thanks,<br>Mary</p>
      </body>
    </html>
    """

    text = html_to_text_santized(html)

    assert "Hi [NAME]," in text
    assert "[URL]\n<|URL|>" in text
    assert "[EMAIL_ADDRESS]" in text
    assert "[PHONE_NUMBER]" in text
    assert "[DATE]" in text
    assert "[TIME]" in text
    assert "[REFERENCE_NUMBER]" in text
    assert "[FINANCIAL_INFO]" in text
    assert "[FILE_NAME]" in text
    assert "Thanks,\n[NAME]" in text


def test_html_to_text_sanitized_preserves_non_url_link_text_and_href_target():
    html = '<p>Please <a href="https://example.com/reset">reset your password</a>.</p>'

    assert html_to_text_sanitized(html) == "Please reset your password\n<|URL|>."


def test_sanitize_text_protects_existing_tokens_and_attachment_wrappers():
    text = "Forwarded from [NAME] at [ORGANIZATION]. Attachments: <<report-Q4.xlsx>> <<[FILE_NAME]>>"

    sanitized = sanitize_text(text)

    assert "[NAME]" in sanitized
    assert "[ORGANIZATION]" in sanitized
    assert "<<[FILE_NAME]>> <<[FILE_NAME]>>" in sanitized


def test_sanitize_text_redacts_org_suffixes_paths_ips_usernames_and_initials():
    text = (
        "Acme Energy Partners sent C:\\Users\\alice\\Desktop\\plan.docx from "
        "/home/alice/docs/plan.txt via 10.1.2.3. Login: alice.smith. Signed J.D."
    )

    sanitized = sanitize_text(text)

    assert "[ORGANIZATION]" in sanitized
    assert "[FILE_PATH]" in sanitized
    assert "[IP_ADDRESS]" in sanitized
    assert "[USERNAME]" in sanitized
    assert "[INITIALS]" in sanitized
    assert "Acme Energy Partners" not in sanitized
    assert "alice.smith" not in sanitized


def test_sanitize_text_supports_configurable_phone_token_and_ner_hook():
    def ner_hook(text: str) -> str:
        return text.replace("Ada Lovelace", "[NAME]")

    config = SanitizerConfig(phone_token="<|PHONE|>", ner_redactor=ner_hook)

    assert sanitize_text("Call Ada Lovelace at 212-555-0101", config) == "Call [NAME] at <|PHONE|>"


def test_sanitize_text_uses_spacy_person_and_org_entities_when_available():
    class FakeEntity:
        def __init__(self, text: str, label_: str, start_char: int, end_char: int):
            self.text = text
            self.label_ = label_
            self.start_char = start_char
            self.end_char = end_char

    class FakeDoc:
        def __init__(self, ents):
            self.ents = ents

    class FakeNLP:
        def __call__(self, text: str):
            return FakeDoc(
                [
                    FakeEntity("Ada Lovelace", "PERSON", text.index("Ada Lovelace"), text.index("Ada Lovelace") + 12),
                    FakeEntity("Analytical Engines Inc", "ORG", text.index("Analytical Engines Inc"), text.index("Analytical Engines Inc") + 22),
                ]
            )

    original_loader = sanitizer._load_spacy_model
    sanitizer._load_spacy_model = lambda model_name: FakeNLP()
    try:
        text = sanitize_text("Ada Lovelace met with Analytical Engines Inc.")
    finally:
        sanitizer._load_spacy_model = original_loader

    assert text == "[NAME] met with [ORGANIZATION]."


def test_html_to_text_sanitized_decodes_raw_quoted_printable_html_email():
    raw_email = """
From: Alice <alice@example.com>
To: Bob <bob@example.org>
Subject: Reset
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<html><body><p>Hello Bob,</p><p><a href=3D"https://example.com/reset">reset</a></p></body></html>
"""

    text = html_to_text_sanitized(raw_email)

    assert "Hello [NAME]," in text
    assert "reset\n<|URL|>" in text


def test_parse_html_email_to_sanitized_record_keeps_metrics_and_sanitizes_body():
    raw_email = """
From: Alice <alice@example.com>
To: Bob <bob@example.org>
Subject: Account update
Content-Type: text/html; charset="utf-8"

<html><body><p>Hello Bob,</p><p><a href="https://example.com/login">log in</a></p></body></html>
"""

    record = parse_html_email_to_sanitized_record(raw_email)

    assert record["sender_domain"] == "example.com"
    assert record["url_count"] == 1.0
    assert record["urls"] == "https://example.com/login"
    assert record["body"] == "Hello [NAME],\n\nlog in\n<|URL|>"
