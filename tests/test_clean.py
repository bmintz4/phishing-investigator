import sys
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.text_features import clean_text


def test_clean_text():
    assert clean_text("  Hello,\n\tWORLD!  ") == "hello, world!"
    assert clean_text(None) == ""
    assert clean_text(float("nan")) == ""
    assert clean_text(pd.NA) == ""
    print("[TEST] text cleaning complete")

if __name__ == "__main__":
    test_clean_text()
