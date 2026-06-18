import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingestion.html_email import extract_links, html_to_text


SAMPLE_HTML_EMAIL = PROJECT_ROOT / "data" / "sample emails" / "legitimate_html.txt"


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
    if not SAMPLE_HTML_EMAIL.exists():
        pytest.skip("legitimate_html.txt sample email is not available")

    links = extract_links(SAMPLE_HTML_EMAIL.read_text(encoding="utf-8"))

    assert {
        "text": "candidate dashboard",
        "address": (
            "https://tracking.icims.com/f/a/z0kfLSHpmyFS8Qr_GnNSDQ~~/"
            "AAIB5hA~/Y6AKyU56xAfC-c2iSTjAU_x_MHGfzmctATO46dLnVYsFCv9"
            "L2PDrKekGMA6BaPue1HH0Dq1Lg9QYdDPyj0hm3Ema4hJNZG10ijkEQQ"
            "jXvrZYlrtZ0ZUh1cADfOUheB5I"
        ),
    } in links


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


def test_html_helpers_return_empty_values_for_invalid_input():
    assert extract_links("") == []
    assert extract_links(None) == []
    assert html_to_text("") == ""
    assert html_to_text(None) == ""


def test_html_to_text_uses_decoded_html_body_from_raw_email():
    if not SAMPLE_HTML_EMAIL.exists():
        pytest.skip("legitimate_html.txt sample email is not available")

    text = html_to_text(SAMPLE_HTML_EMAIL.read_text(encoding="utf-8"))

    assert text.startswith("Dear Brian,")
    assert "Delivered-To:" not in text
    assert "------=_Part_" not in text
    assert "We're excited" in text
    assert (
        "[https://jhuapl.icims.com/icims2/?r=6177623696&contactId=3212762&pid=111]"
        "(https://tracking.icims.com/f/a/"
    ) in text


if __name__ == "__main__":
    test_extract_links_returns_text_and_addresses()
    test_extract_links_decodes_quoted_printable_html()
    test_extract_links_decodes_raw_email_html_part()
    test_html_to_text_returns_basic_text()
    test_html_helpers_return_empty_values_for_invalid_input()
    test_html_to_text_uses_decoded_html_body_from_raw_email()
    if SAMPLE_HTML_EMAIL.exists():
        print(html_to_text(SAMPLE_HTML_EMAIL.read_text(encoding="utf-8")))
