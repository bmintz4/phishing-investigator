import quopri
import re
from email import policy
from email.parser import Parser

from bs4 import BeautifulSoup


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


def _prepare_html_body(raw_input: str) -> str:
    html_body = _extract_html_body(raw_input)
    if html_body is not None:
        return html_body

    if _looks_quoted_printable(raw_input):
        return quopri.decodestring(raw_input.encode()).decode("utf-8", errors="replace")

    return raw_input


def _extract_html_body(raw_email: str) -> str | None:
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
