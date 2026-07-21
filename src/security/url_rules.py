from src.ingestion.html_email import extract_links
from urllib.parse import urlparse


SAFE_NON_WEB_SCHEMES = {
    "callto",
    "cid",
    "facetime",
    "fax",
    "geo",
    "mailto",
    "sms",
    "tel",
    "urn",
}

RISKY_NON_WEB_SCHEMES = {
    "data",
    "file",
    "javascript",
    "vbscript",
}


def analyze_url_rules(html: str) -> list[dict]:
    findings = []

    for link in extract_links(html):
        text = link["text"]
        address = link["address"]

        if _is_safe_non_web_link(address):
            continue

        if _is_risky_non_web_link(address):
            findings.append(
                {
                    "type": "URL",
                    "subtype": "risky link scheme",
                    "severity": "medium",
                    "evidence": address,
                }
            )
        elif not address.casefold().startswith("https://"):
            findings.append(
                {
                    "type": "URL",
                    "subtype": "insecure link",
                    "severity": "medium",
                    "evidence": address,
                }
            )
        elif text and len(text) > 100:
            findings.append(
                {
                    "type": "URL",
                    "subtype": "deceptive URL length",
                    "severity": "medium",
                    "evidence": f"Text: {text}",
                }
            )
        elif text and _normalize_for_match(text) not in _normalize_for_match(address):
            findings.append(
                {
                    "type": "URL",
                    "subtype": "name mismatch",
                    "severity": "low",
                    "evidence": f"Text: {text}\nAddress: {address}",
                }
            )
        else:
            findings.append(
                {
                    "type": "URL",
                    "subtype": "found",
                    "severity": "none",
                    "evidence": address,
                }
            )

    return findings


def _normalize_for_match(value: str) -> str:
    return "".join(str(value).casefold().split())


def _scheme(address: str) -> str:
    return urlparse(str(address).strip()).scheme.casefold()


def _is_safe_non_web_link(address: str) -> bool:
    stripped = str(address).strip()
    if stripped.startswith("#"):
        return True
    return _scheme(stripped) in SAFE_NON_WEB_SCHEMES


def _is_risky_non_web_link(address: str) -> bool:
    return _scheme(address) in RISKY_NON_WEB_SCHEMES
