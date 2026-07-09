import html
import quopri
import re
import unicodedata
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from functools import lru_cache
from typing import Callable

from bs4 import BeautifulSoup


NERRedactor = Callable[[str], str]

PROTECTED_TOKEN_RE = re.compile(r"(?:\[[A-Z_]+\]|<\|[A-Z_]+\|>)")
PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP (?:SIGNED MESSAGE|MESSAGE|SIGNATURE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----"
    r".*?"
    r"-----END PGP (?:MESSAGE|SIGNATURE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----",
    re.IGNORECASE | re.DOTALL,
)
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>()\"']+")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"(?i)\b[a-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
UNIX_PATH_RE = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._ -]+/)+[A-Za-z0-9._ -]+")
FILE_NAME_RE = re.compile(
    r"(?<![\w\-/])[\w .()~+-]{1,80}\."
    r"(?:pdf|docx?|xlsx?|pptx?|csv|txt|zip|rar|7z|html?|xml|jpg|jpeg|png|gif|eml|msg)"
    r"\b",
    re.IGNORECASE,
)
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}"
    r"(?:\s*(?:x|ext\.?|extension)\s*\d{1,6})?(?!\w)",
    re.IGNORECASE,
)
DATE_RE = re.compile(
    r"\b(?:"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
    r"\d{4}[/-]\d{1,2}[/-]\d{1,2}|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{2,4}|"
    r"\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?\s+\d{2,4}"
    r")\b",
    re.IGNORECASE,
)
TIME_RE = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?(?:\s*[A-Z]{2,4})?\b")
CURRENCY_RE = re.compile(r"(?<!\w)(?:[$€£]\s?\d[\d,]*(?:\.\d{2})?|\d[\d,]*(?:\.\d{2})?\s?(?:USD|EUR|GBP|dollars?))\b", re.IGNORECASE)
FINANCIAL_CONTEXT_RE = re.compile(
    r"\b(?:account|acct|routing|iban|swift|payment|wire|invoice total|amount due)\s*(?:number|no\.?|#|id)?\s*[:#-]?\s*[A-Z0-9-]{4,}\b",
    re.IGNORECASE,
)
REFERENCE_RE = re.compile(
    r"\b(?:invoice|tracking|order|case|ticket|confirmation|confirm|reference|ref|deal|po|rma)"
    r"\s*(?:number|no\.?|#|id)?\s*[:#-]?\s*[A-Z0-9][A-Z0-9-]{2,}\b",
    re.IGNORECASE,
)
EMOJI_RE = re.compile(
    "["
    "\U0001F1E6-\U0001F1FF"
    "\U0001F300-\U0001F5FF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U0001F700-\U0001F77F"
    "\U0001F780-\U0001F7FF"
    "\U0001F800-\U0001F8FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA00-\U0001FAFF"
    "\u2600-\u27BF"
    "]+"
)
INITIALS_RE = re.compile(r"\b(?:[A-Z]\.){2,5}")
USERNAME_RE = re.compile(r"(?i)\b(?:user(?:name)?|login|handle|userid|user id)\s*[:=]\s*[A-Z0-9._-]{3,}\b")
ADDRESS_CONTEXT_RE = re.compile(
    r"\b(?:address|location)\s*:\s*[^\n,]+(?:,\s*[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?",
    re.IGNORECASE,
)
PRODUCT_CONTEXT_RE = re.compile(r"\b(?:product|sku|item)\s*[:#-]\s*[A-Z0-9][A-Z0-9_.-]{2,}\b", re.IGNORECASE)
SYMBOL_LINE_RE = re.compile(r"(?m)^[\s>*=_#.-]*([*=_#-])(?:\s*\1){5,}[\s>*=_#.-]*$")
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")

ORG_SUFFIXES = (
    "Inc",
    "LLC",
    "Ltd",
    "Corporation",
    "Corp",
    "Company",
    "Co",
    "Group",
    "Bank",
    "University",
    "Technologies",
    "Technology",
    "Systems",
    "Energy",
    "Partners",
    "Services",
    "Solutions",
    "Industries",
    "Holdings",
)
ORG_SUFFIX_RE = re.compile(
    r"\b(?:[A-Z][A-Za-z&.-]+(?:\s+|,\s*)){0,5}[A-Z][A-Za-z&.-]+"
    r"\s+(?:" + "|".join(re.escape(suffix) for suffix in ORG_SUFFIXES) + r")\.?\b"
)


@dataclass(frozen=True)
class SanitizerConfig:
    preserve_href_targets: bool = True
    href_token: str = "<|URL|>"
    url_token: str = "[URL]"
    phone_token: str = "[PHONE_NUMBER]"
    enable_ner: bool = True
    use_spacy_ner: bool = True
    spacy_model: str = "en_core_web_sm"
    ner_redactor: NERRedactor | None = None
    enable_address_product_rules: bool = True


def html_to_text_santized(html_email: str, config: SanitizerConfig | None = None) -> str:
    """Return MeAJOR-like sanitized text for an incoming HTML email.

    The misspelled function name is kept because the request names this API.
    Use html_to_text_sanitized for new call sites.
    """
    if not isinstance(html_email, str) or not html_email.strip():
        return ""

    config = config or SanitizerConfig()
    text = _html_to_visible_text_with_href_tokens(html_email, config)
    text = _normalize_before_replacement(text)
    return sanitize_text(text, config)


def html_to_text_sanitized(html_email: str, config: SanitizerConfig | None = None) -> str:
    return html_to_text_santized(html_email, config)


def parse_html_email_to_sanitized_record(
    raw_input: str, config: SanitizerConfig | None = None
) -> dict[str, str | float | bool]:
    """Build the existing structured record shape with a MeAJOR-sanitized body."""
    from src.ingestion.html_email import parse_html_email_to_record

    record = parse_html_email_to_record(raw_input)
    record["body"] = html_to_text_santized(raw_input, config)
    return record


def sanitize_text(text: str, config: SanitizerConfig | None = None) -> str:
    if not isinstance(text, str) or not text.strip():
        return ""

    config = config or SanitizerConfig()
    text = _normalize_before_replacement(text)
    text, protected = _protect_existing_tokens(text)

    text = PGP_BLOCK_RE.sub("[PGP]", text)
    text = URL_RE.sub(config.url_token, text)
    text = EMAIL_RE.sub("[EMAIL_ADDRESS]", text)
    text = IPV4_RE.sub("[IP_ADDRESS]", text)
    text = IPV6_RE.sub("[IP_ADDRESS]", text)
    text = WINDOWS_PATH_RE.sub("[FILE_PATH]", text)
    text = UNIX_PATH_RE.sub("[FILE_PATH]", text)
    text = FILE_NAME_RE.sub("[FILE_NAME]", text)
    text = PHONE_RE.sub(config.phone_token, text)
    text = DATE_RE.sub("[DATE]", text)
    text = TIME_RE.sub("[TIME]", text)
    text = CURRENCY_RE.sub("[FINANCIAL_INFO]", text)
    text = FINANCIAL_CONTEXT_RE.sub("[FINANCIAL_INFO]", text)
    text = REFERENCE_RE.sub("[REFERENCE_NUMBER]", text)
    text = EMOJI_RE.sub("[EMOJI]", text)
    text = _restore_protected_tokens(text, protected)

    if config.enable_ner:
        text = _redact_names_and_organizations(text, config)

    text = USERNAME_RE.sub("[USERNAME]", text)
    text = INITIALS_RE.sub("[INITIALS]", text)

    if config.enable_address_product_rules:
        text = ADDRESS_CONTEXT_RE.sub("[ADDRESS]", text)
        text = PRODUCT_CONTEXT_RE.sub("[PRODUCT]", text)

    text = SYMBOL_LINE_RE.sub("[SYMBOL]", text)
    return _normalize_final_whitespace(text)


def _html_to_visible_text_with_href_tokens(raw_input: str, config: SanitizerConfig) -> str:
    html_body = _prepare_html_body(raw_input)
    soup = BeautifulSoup(html_body, "html.parser")

    for tag in soup(["script", "style", "img", "meta", "head"]):
        tag.decompose()

    for anchor in soup.find_all("a"):
        link_text = _normalize_before_replacement(anchor.get_text(" ", strip=True))
        href = _normalize_href(anchor.get("href", ""))
        parts = []
        if link_text:
            parts.append(config.url_token if URL_RE.search(link_text) else link_text)
        if href and config.preserve_href_targets:
            parts.append(config.href_token)
        anchor.replace_with("\n".join(parts))

    for br in soup.find_all("br"):
        br.replace_with("\n")

    for hr in soup.find_all("hr"):
        hr.replace_with("\n[SYMBOL]\n")

    for tag in soup.find_all(["p", "div", "center", "li", "tr", "table", "blockquote", "section"]):
        tag.insert_after("\n\n")

    return soup.get_text()


def _prepare_html_body(raw_input: str) -> str:
    raw_input = raw_input.lstrip()
    message = Parser(policy=policy.default).parsestr(raw_input)

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/html":
                return part.get_content()
    elif message.get_content_type() == "text/html":
        return message.get_content()

    if _looks_quoted_printable(raw_input):
        return quopri.decodestring(raw_input.encode()).decode("utf-8", errors="replace")

    return raw_input


def _normalize_before_replacement(text: str) -> str:
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    text = text.replace("\xa0", " ")
    text = text.replace("\u2018", "'").replace("\u2019", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    return text


def _protect_existing_tokens(text: str) -> tuple[str, dict[str, str]]:
    protected: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        key = f"\ue000{chr(0xE100 + len(protected))}\ue001"
        protected[key] = match.group(0)
        return key

    return PROTECTED_TOKEN_RE.sub(replace, text), protected


def _restore_protected_tokens(text: str, protected: dict[str, str]) -> str:
    for placeholder, token in protected.items():
        text = text.replace(placeholder, token)
    return text


def _redact_spacy_entities(text: str, model_name: str) -> str:
    nlp = _load_spacy_model(model_name)
    if nlp is None:
        return text

    doc = nlp(text)
    replacements = {
        "PERSON": "[NAME]",
        "ORG": "[ORGANIZATION]",
    }
    spans = [
        (ent.start_char, ent.end_char, replacements[ent.label_])
        for ent in doc.ents
        if ent.label_ in replacements and _should_redact_spacy_entity(ent.text, ent.label_)
    ]
    if not spans:
        return text

    redacted = []
    cursor = 0
    for start, end, token in sorted(spans):
        if start < cursor:
            continue
        redacted.append(text[cursor:start])
        redacted.append(token)
        cursor = end
    redacted.append(text[cursor:])
    return "".join(redacted)


@lru_cache(maxsize=4)
def _load_spacy_model(model_name: str):
    try:
        import spacy
    except ImportError:
        return None

    try:
        return spacy.load(model_name, disable=["tagger", "parser", "lemmatizer", "textcat"])
    except OSError:
        return None


def _should_redact_spacy_entity(entity_text: str, entity_label: str) -> bool:
    stripped = entity_text.strip()
    if not stripped:
        return False
    if PROTECTED_TOKEN_RE.fullmatch(stripped):
        return False
    if "\ue000" in stripped or "\ue001" in stripped:
        return False
    if entity_label == "PERSON" and len(stripped.split()) < 2:
        return False
    return any(char.isalpha() for char in stripped)


def _redact_names_and_organizations(text: str, config: SanitizerConfig) -> str:
    if config.ner_redactor is not None:
        text = config.ner_redactor(text)

    text, protected = _protect_existing_tokens(text)
    if config.use_spacy_ner:
        text = _redact_spacy_entities(text, config.spacy_model)
    text = ORG_SUFFIX_RE.sub("[ORGANIZATION]", text)

    text = re.sub(
        r"(?m)^(\s*(?:Hi|Hello|Dear|To|Cc)\s+)([A-Z][a-z]{1,30})(/[A-Z][a-z]{1,30})?([,:])",
        lambda m: f"{m.group(1)}[NAME]{'/[NAME]' if m.group(3) else ''}{m.group(4)}",
        text,
    )
    text = re.sub(
        r"(?m)^(?!(?:Thanks|Thank|Regards|Best|Sincerely|Cheers)\b)([A-Z][a-z]{1,30})(/[A-Z][a-z]{1,30})?([,:])(\s|$)",
        lambda m: f"[NAME]{'/[NAME]' if m.group(2) else ''}{m.group(3)}{m.group(4)}",
        text,
    )
    text = re.sub(
        r"(?im)^(\s*(?:thanks|thank you|regards|best|sincerely|cheers)[,!]?\s*\n\s*)([A-Z][a-z]{1,30})(\s+[A-Z][a-z]{1,30})?\b",
        lambda m: f"{m.group(1)}[NAME]",
        text,
    )
    text = re.sub(
        r"\b(?:analyst|manager|director|vp|president|spokes(?:woman|man|person)),\s+[A-Z][a-z]{1,30}(?:\s+[A-Z][a-z]{1,30})?\b",
        lambda m: m.group(0).split(",")[0] + ", [NAME]",
        text,
        flags=re.IGNORECASE,
    )
    return _restore_protected_tokens(text, protected)


def _normalize_href(href: str) -> str:
    href = _normalize_before_replacement(href or "").strip()
    if href.lower().startswith(("mailto:", "tel:", "javascript:", "#")):
        return ""
    return href


def _normalize_final_whitespace(text: str) -> str:
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _looks_quoted_printable(text: str) -> bool:
    return bool(re.search(r"=(?:\r?\n|3D|[A-Fa-f0-9]{2})", text))
