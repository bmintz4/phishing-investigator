import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.security.score_calculation import risk_rating


def test_risk_rating_returns_overall_rule_and_model_scores():
    rules = [
        {"subtype": "credential_request", "severity": "high"},
        {"subtype": "urgent", "severity": "medium"},
        {"subtype": "name mismatch", "severity": "low"},
        {"subtype": "found", "severity": "none"},
    ]

    assert risk_rating(rules, 80) == (33.6, 22, 80)


def test_risk_rating_only_counts_same_subtype_twice():
    rules = [
        {"subtype": "urgent", "severity": "medium"},
        {"subtype": "urgent", "severity": "medium"},
        {"subtype": "urgent", "severity": "medium"},
    ]

    assert risk_rating(rules, 0) == (8.0, 10, 0)
