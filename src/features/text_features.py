import pandas as pd

# normalize 
def clean_text(text: object) -> str:
    if text is None or pd.isna(text):
        return ""

    return " ".join(str(text).lower().split())
