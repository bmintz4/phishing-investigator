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

from src.features.text_features import clean_text


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
            "text": clean_text(text)
        })

    return pd.DataFrame(records)

## Normalize pasted email text from the Streamlit app.
def load_pasted_email(raw_text: str) -> dict:    
    return {
        "filename": None,
        "label": None,
        "source_dataset": None,
        "source_type": "pasted_text",
        "text": clean_text(raw_text)
    }


## Load and standardize the phishing email training dataset.
def load_training_dataset(csv_path: str) -> pd.DataFrame:
    data = pd.read_csv(csv_path)
    required_columns = ["Email Text", "Email Type"]

    missing_columns = [
        column for column in required_columns if column not in data.columns
    ]
    if missing_columns:
        raise ValueError(
            f"Training dataset is missing required columns: {missing_columns}"
        )

    data = data.dropna(subset=required_columns).copy()
    data["text"] = data["Email Text"].map(clean_text)
    data["label"] = data["Email Type"].astype(str).str.strip()
    data = data[(data["text"] != "") & (data["label"] != "")].copy()

    data["filename"] = None
    data["source_dataset"] = Path(csv_path).name
    data["source_type"] = "csv"

    return data[
        ["filename", "label", "source_dataset", "source_type", "text"]
    ].reset_index(drop=True)
