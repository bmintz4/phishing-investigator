"""
The email loader standardizes data coming from different sources (sample emails in .txt files, pasted text from the Streamlit app, large .csv files for ML training, etc) into one consistent data type

DataFrame format:
    - filename
    - label
    - source_dataset
    - source_type
    - text
"""

from pathlib import Path
import pandas as pd

## Load sample emails using labels.csv.
def load_sample_emails(labels_path: str, sample_dir: str) -> pd.DataFrame:
    labels = pd.read_csv(labels_path)
    records = []

    for _, row in labels.iterrows():
        email_path = Path(sample_dir) / row["filename"]

        with open(email_path, "r", encoding="utf-8") as f:
            text = f.read()

        records.append({
            "filename": row["filename"],
            "label": row["label"],
            "source_dataset": row.get("source_dataset", ""),
            "source_type": row.get("source_type", ""),
            "text": text
        })

    return pd.DataFrame(records)

## Normalize pasted email text from the Streamlit app.
def load_pasted_email(raw_text: str) -> dict:    
    return {
        "filename": None,
        "label": None,
        "source_dataset": None,
        "source_type": "pasted_text",
        "text": raw_text.strip()
    }