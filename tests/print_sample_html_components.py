from pathlib import Path
import sys

# Ensure the repository root is on sys.path so src can be imported when running this script directly.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ingestion.html_email import parse_html_email_to_record


def main() -> None:
    sample_path = ROOT / "data" / "sample emails" / "html_parser_test_email.txt"
    raw_email = sample_path.read_text(encoding="utf-8")
    record = parse_html_email_to_record(raw_email)

    print("sender_domain:", record["sender_domain"])
    print("receiver_domain:", record["receiver_domain"])
    print("date:", record["date"])
    print("subject:", record["subject"])
    print("body:", record["body"])
    print("urls:", record["urls"])
    print("url_count:", record["url_count"])
    print("url_length_max:", record["url_length_max"])
    print("url_length_avg:", record["url_length_avg"])
    print("url_subdom_max:", record["url_subdom_max"])
    print("url_subdom_avg:", record["url_subdom_avg"])
    print("attachment_count:", record["attachment_count"])
    print("has_attachments:", record["has_attachments"])
    print("attachment_types:", record["attachment_types"])
    print("language:", record["language"])


if __name__ == "__main__":
    main()
