from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ingestion.html_email_sanitizer import html_to_text_santized


def main() -> None:
    sample_path = ROOT / "data" / "sample emails" / "html_parser_test_email.txt"
    raw_email = sample_path.read_text(encoding="utf-8")
    sanitized = html_to_text_santized(raw_email)

    print(sanitized)


if __name__ == "__main__":
    main()
