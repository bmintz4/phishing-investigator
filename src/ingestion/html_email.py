import quopri
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup

STRUCTURED_EMAIL_FIELDS = [
    "sender_domain",
    "receiver_domain",
    "date",
    "subject",
    "body",
    "urls",
    "url_count",
    "url_length_max",
    "url_length_avg",
    "url_subdom_max",
    "url_subdom_avg",
    "attachment_count",
    "has_attachments",
    "attachment_types",
    "language",
]

URL_REGEX = re.compile(r"https?://[^\s<>')\"]+")


def html_to_text(html: str) -> str:
    if not isinstance(html, str) or not html.strip():
        return ""

    html_body = _prepare_html_body(html)
    if html_body != html:
        return _html_body_to_text(html_body)

    soup = BeautifulSoup(html_body, "html.parser")
    return soup.get_text(" ", strip=True)

def extract_links(html: str) -> list[dict[str, str]]:
    if not isinstance(html, str) or not html.strip():
        return []

    soup = BeautifulSoup(_prepare_html_body(html), "html.parser")
    links = []

    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        if not href:
            continue

        links.append(
            {
                "text": anchor.get_text(" ", strip=True),
                "address": href.strip(),
            }
        )

    return links


def parse_html_email_to_record(raw_input: str) -> dict[str, str | float | bool]:
    """Build a structured record from raw email text."""
    if not isinstance(raw_input, str) or not raw_input.strip():
        return {
            **{field: "" for field in STRUCTURED_EMAIL_FIELDS},
            "url_count": 0.0,
            "url_length_max": 0.0,
            "url_length_avg": 0.0,
            "url_subdom_max": 0.0,
            "url_subdom_avg": 0.0,
            "attachment_count": 0.0,
            "has_attachments": False,
            "language": "en",
        }

    raw_input = raw_input.lstrip()
    message = _parse_raw_email(raw_input)
    html_body = _extract_html_body_from_message(message)
    subject = _normalize_header_value(message.get("subject"))
    if not subject and html_body:
        subject = _extract_subject_from_html(html_body)

    url_strings = _extract_urls(raw_input if html_body is None else html_body)
    url_metrics = _extract_url_metrics(url_strings)
    attachment_types = _extract_attachment_types(message)
    attachment_count = len(attachment_types)

    return {
        "sender_domain": _extract_domain_from_header(message.get("from")),
        "receiver_domain": _extract_domain_from_header(message.get("to")),
        "date": _normalize_header_value(message.get("date")),
        "subject": subject,
        "body": _extract_body_text_from_message(message),
        "urls": " ".join(url_strings),
        "url_count": float(url_metrics["url_count"]),
        "url_length_max": float(url_metrics["url_length_max"]),
        "url_length_avg": float(url_metrics["url_length_avg"]),
        "url_subdom_max": float(url_metrics["url_subdom_max"]),
        "url_subdom_avg": float(url_metrics["url_subdom_avg"]),
        "attachment_count": float(attachment_count),
        "has_attachments": attachment_count > 0,
        "attachment_types": " ".join(attachment_types),
        "language": "en",
    }


def _normalize_header_value(value: str | None) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def _extract_domain_from_header(header_value: str | None) -> str:
    if not isinstance(header_value, str) or not header_value.strip():
        return ""

    _, email_address = parseaddr(header_value)
    match = re.search(r"@([\w.-]+)$", email_address)
    return match.group(1).lower() if match else ""


def _extract_subject_from_html(html_body: str) -> str:
    soup = BeautifulSoup(html_body, "html.parser")
    title = soup.title
    return title.get_text(" ", strip=True) if title else ""


def _parse_raw_email(raw_input: str):
    return Parser(policy=policy.default).parsestr(raw_input)


def _extract_body_text_from_message(message) -> str:
    html_body = _extract_html_body_from_message(message)
    if html_body:
        return _html_body_to_text(html_body)

    if message.is_multipart():
        simple_part = message.get_body(preferencelist=("plain",))
        if simple_part is not None:
            return simple_part.get_content()
        return ""

    return message.get_content() or ""


def _extract_html_body_from_message(message) -> str | None:
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/html":
                return part.get_content()
        return None

    if message.get_content_type() == "text/html":
        return message.get_content()

    return None


def _extract_urls(text: str) -> list[str]:
    if not isinstance(text, str) or not text.strip():
        return []

    soup = BeautifulSoup(text, "html.parser")
    urls = [a["href"].strip() for a in soup.find_all("a", href=True) if a["href"].strip()]
    if urls:
        return urls

    return [match.strip() for match in URL_REGEX.findall(text)]


def _extract_url_metrics(urls: list[str]) -> dict[str, float]:
    if not urls:
        return {
            "url_count": 0,
            "url_length_max": 0,
            "url_length_avg": 0,
            "url_subdom_max": 0,
            "url_subdom_avg": 0,
        }

    lengths = [len(url) for url in urls]
    subdomains = [_count_subdomains_from_url(url) for url in urls]
    return {
        "url_count": len(urls),
        "url_length_max": max(lengths),
        "url_length_avg": sum(lengths) / len(lengths),
        "url_subdom_max": max(subdomains),
        "url_subdom_avg": sum(subdomains) / len(subdomains),
    }


def _count_subdomains_from_url(url: str) -> int:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""

    labels = [label for label in host.split(".") if label]
    return max(0, len(labels) - 2)


def _extract_attachment_types(message) -> list[str]:
    attachment_types = []
    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        if content_type in {"text/plain", "text/html"}:
            continue

        if part.get_filename() or part.get_content_disposition() == "attachment":
            attachment_types.append(content_type)

    return sorted(set(attachment_types))


def _prepare_html_body(raw_input: str) -> str:
    html_body = _extract_html_body(raw_input)
    if html_body is not None:
        return html_body

    if _looks_quoted_printable(raw_input):
        return quopri.decodestring(raw_input.encode()).decode("utf-8", errors="replace")

    return raw_input


def _extract_html_body(raw_email: str) -> str | None:
    raw_email = raw_email.lstrip()
    message = Parser(policy=policy.default).parsestr(raw_email)

    if not message.is_multipart() and message.get_content_type() != "text/html":
        return None

    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.get_content_type() == "text/html":
            return part.get_content()

    return None


def _html_body_to_text(html_body: str) -> str:
    soup = BeautifulSoup(html_body, "html.parser")

    for tag in soup(["script", "style", "img"]):
        tag.decompose()

    for tag in soup.find_all("a"):
        link_text = tag.get_text(" ", strip=True)
        link_address = tag.get("href", "").strip()
        if link_text and link_address and _looks_like_url(link_text):
            tag.replace_with(f"[{link_text}]({link_address})")
        else:
            tag.replace_with(link_text)

    for br in soup.find_all("br"):
        br.replace_with("\n")

    for hr in soup.find_all("hr"):
        hr.replace_with("\n**************************************************\n")

    block_tags = soup.find_all(["p", "div", "center", "li", "tr"])
    for tag in block_tags:
        tag.insert_after("\n\n")

    text = soup.get_text()
    text = text.replace("\xa0", " ")
    text = text.replace("\u2018", "'").replace("\u2019", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _looks_like_url(text: str) -> bool:
    return text.startswith(("http://", "https://"))


def _looks_quoted_printable(text: str) -> bool:
    return bool(re.search(r"=(?:\r?\n|3D|[A-Fa-f0-9]{2})", text))
