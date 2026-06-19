from src.ingestion.html_email import extract_links


def analyze_url_rules(html: str) -> list[dict]:
    findings = []

    for link in extract_links(html):
        text = link["text"]
        address = link["address"]

        if not address.casefold().startswith("https://"):
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

    return findings


def _normalize_for_match(value: str) -> str:
    return "".join(str(value).casefold().split())
