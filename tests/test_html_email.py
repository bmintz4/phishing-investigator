from src.ingestion.html_email import extract_links, html_to_text, parse_html_email_to_record


# NOTE: legacy sample files in the repo are plain text emails, not raw MIME HTML parts.
# The parser and tests below are designed to validate HTML extraction from raw email text
# and quoted-printable HTML using self-contained MIME samples.


def test_extract_links_returns_text_and_addresses():
    html = """
    <html>
        <body>
            <a href="https://example.com/login">Sign in here</a>
            <a href=" https://billing.example.com ">Update billing</a>
            <a>No destination</a>
        </body>
    </html>
    """

    assert extract_links(html) == [
        {
            "text": "Sign in here",
            "address": "https://example.com/login",
        },
        {
            "text": "Update billing",
            "address": "https://billing.example.com",
        },
    ]


def test_extract_links_decodes_quoted_printable_html():
    html = """
    <a href=3D"https://tracking.icims=
.com/f/a/z0kfLSHpmyFS8Qr_GnNSDQ~~/AAIB5hA~/Y6AKyU56xAfC-c2iSTjAU_x_MHGfzmct=
ATO46dLnVYsFCv9L2PDrKekGMA6BaPue1HH0Dq1Lg9QYdDPyj0hm3Ema4hJNZG10ijkEQQjXvrZ=
YlrtZ0ZUh1cADfOUheB5I">candidate dashboa=
rd</a>
    """

    assert extract_links(html) == [
        {
            "text": "candidate dashboard",
            "address": (
                "https://tracking.icims.com/f/a/z0kfLSHpmyFS8Qr_GnNSDQ~~/"
                "AAIB5hA~/Y6AKyU56xAfC-c2iSTjAU_x_MHGfzmctATO46dLnVYsFCv9"
                "L2PDrKekGMA6BaPue1HH0Dq1Lg9QYdDPyj0hm3Ema4hJNZG10ijkEQQ"
                "jXvrZYlrtZ0ZUh1cADfOUheB5I"
            ),
        }
    ]


def test_extract_links_decodes_raw_email_html_part():
    raw_email = """
From: Alice <alice@example.com>
To: Bob <bob@example.org>
Subject: Test HTML email
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <body>
    <p>Hi Bob,</p>
    <p>Visit <a href="https://example.com/login">our site</a>.</p>
  </body>
</html>
"""

    links = extract_links(raw_email)

    assert links == [
        {
            "text": "our site",
            "address": "https://example.com/login",
        }
    ]


def test_html_to_text_returns_basic_text():
    html = """
    <html>
        <body>
            <p>Dear customer,</p>
            <p>Verify your account <a href="https://example.com">here</a>.</p>
        </body>
    </html>
    """

    assert html_to_text(html) == "Dear customer, Verify your account here ."


def test_parse_html_email_to_record_returns_structured_fields():
    raw_email = """
From: Alice <alice@example.com>
To: Bob <bob@example.org>
Date: Wed, 1 Jan 2025 12:00:00 -0500
Subject: Account update
Content-Type: text/html; charset="utf-8"

<html>
  <body>
    <p>Hello Bob,</p>
    <p>Please <a href="https://example.com/login">log in</a> to view your account.</p>
  </body>
</html>
"""

    record = parse_html_email_to_record(raw_email)

    assert record["sender_domain"] == "example.com"
    assert record["receiver_domain"] == "example.org"
    assert record["subject"] == "Account update"
    assert "Hello Bob" in record["body"]
    assert "https://example.com/login" in record["urls"]
    assert record["url_count"] == 1.0
    assert record["url_length_max"] == len("https://example.com/login")
    assert record["url_length_avg"] == len("https://example.com/login")
    assert record["url_subdom_max"] == 0.0
    assert record["url_subdom_avg"] == 0.0
    assert record["attachment_count"] == 0.0
    assert record["has_attachments"] is False
    assert record["attachment_types"] == ""
    assert record["language"] == "en"


def test_html_helpers_return_empty_values_for_invalid_input():
    assert extract_links("") == []
    assert extract_links(None) == []
    assert html_to_text("") == ""
    assert html_to_text(None) == ""


def test_html_to_text_uses_decoded_html_body_from_raw_email():
    raw_email = """
From: Alice <alice@example.com>
To: Bob <bob@example.org>
Date: Wed, 1 Jan 2025 12:00:00 -0500
Subject: Test HTML email
Content-Type: text/html; charset="utf-8"

<html>
  <body>
    <p>Dear Bob,</p>
    <p>We're excited to share our latest updates.</p>
    <p><a href="https://example.com">Click here</a> to visit.</p>
  </body>
</html>
"""

    text = html_to_text(raw_email)

    assert text.startswith("Dear Bob,")
    assert "Delivered-To:" not in text
    assert "We're excited" in text
    assert "Click here to visit." in text


if __name__ == "__main__":
    test_extract_links_returns_text_and_addresses()
    test_extract_links_decodes_quoted_printable_html()
    test_extract_links_decodes_raw_email_html_part()
    test_html_to_text_returns_basic_text()
    test_parse_html_email_to_record_returns_structured_fields()
    test_html_helpers_return_empty_values_for_invalid_input()
    test_html_to_text_uses_decoded_html_body_from_raw_email()
