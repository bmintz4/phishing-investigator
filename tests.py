import pandas as pd

from src.features.text_features import clean_text


def test_clean_text():
    assert clean_text("  Hello,\n\tWORLD!  ") == "hello, world!"
    assert clean_text(None) == ""
    assert clean_text(float("nan")) == ""
    assert clean_text(pd.NA) == ""
    print("[TEST] text cleaning complete")

if __name__ == "__main__":
    test_clean_text()