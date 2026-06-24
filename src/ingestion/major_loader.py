"""
Load and preprocess MeAJOR phishing email dataset.
The label field is expected to be 0.0 (legitimate) or 1.0 (phishing).
"""

from pathlib import Path

import pandas as pd

from src.features.text_features import clean_text


MAJOR_REQUIRED_COLUMNS = [
    "sender",
    "sender_domain",
    "receiver",
    "receiver_domain",
    "date",
    "subject",
    "content_types",
    "body",
    "urls",
    "url_count",
    "url_length_max",
    "url_length_avg",
    "url_subdom_max",
    "url_subdom_avg",
    "attachment_count",
    "has_attachments",
    "attachment_types",
    "language",
    "source",
    "label",
]


def normalize_label(label: object) -> int:
    """
    Convert label to 0 (legitimate) or 1 (phishing).
    Expects label to be 0.0 or 1.0.
    """
    if pd.isna(label):
        raise ValueError("Missing label value in dataset.")

    label_float = float(label)
    if label_float == 0.0:
        return 0
    elif label_float == 1.0:
        return 1
    else:
        raise ValueError(
            f"Unexpected label value: {label}. Expected 0.0 (legitimate) or 1.0 (phishing)."
        )


def combine_text_features(
    data: pd.DataFrame, features: list[str] | None = None
) -> pd.Series:
    """
    Combine multiple text columns into a single text field.
    Default features: sender_domain, subject, body
    """
    if features is None:
        features = ["sender_domain", "subject", "body"]

    missing = [f for f in features if f not in data.columns]
    if missing:
        raise ValueError(
            f"Missing required text feature columns: {missing}. "
            f"Available columns: {list(data.columns)}"
        )

    text_columns = data[features].fillna("").astype(str)
    combined = text_columns.apply(
        lambda row: " ".join(part for part in row if str(part).strip()), axis=1
    )
    return combined.str.replace(r"\s+", " ", regex=True).str.strip()


def load_major_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load the MeAJOR dataset and standardize it.
    Returns a DataFrame with cleaned text features and normalized labels.
    """
    data = pd.read_csv(csv_path, engine='python')

    missing_columns = [col for col in MAJOR_REQUIRED_COLUMNS if col not in data.columns]
    if missing_columns:
        raise ValueError(
            f"MeAJOR dataset is missing required columns: {missing_columns}. "
            f"Expected columns: {MAJOR_REQUIRED_COLUMNS}"
        )

    data = data.copy()

    # Drop rows with missing labels (cannot train without labels)
    rows_before = len(data)
    data = data.dropna(subset=["label"])
    rows_dropped = rows_before - len(data)
    if rows_dropped > 0:
        print(f"Dropped {rows_dropped} rows with missing labels")

    # Normalize labels: convert 0.0 -> 0, 1.0 -> 1
    data["label"] = data["label"].apply(normalize_label)

    # Clean text features
    for col in ["sender_domain", "subject", "body"]:
        if col in data.columns:
            data[col] = data[col].fillna("").map(clean_text)

    # Combine text features into single 'text' column
    data["text"] = combine_text_features(data, ["sender_domain", "subject", "body"])
    data = data[data["text"] != ""].copy()

    # Add metadata
    data["source_dataset"] = Path(csv_path).name
    data["source_type"] = "meajor_csv"

    return data.reset_index(drop=True)


def load_major_training_dataset(
    csv_path: str,
    text_features: list[str] | None = None,
) -> pd.DataFrame:
    """
    Load MeAJOR dataset formatted for model training.
    Combines sender_domain, subject, and body into a single 'text' column for training.
    Returns columns: sender_domain, subject, body, text, label, source_dataset, source_type
    """
    data = load_major_dataset(csv_path)

    # Recombine text with custom features if provided
    if text_features is not None:
        data["text"] = combine_text_features(data, text_features)

    if data["text"].eq("").all():
        raise ValueError(
            "No training text could be constructed from sender_domain, subject, and body."
        )

    return data[
        ["sender_domain", "subject", "body", "text", "label", "source_dataset", "source_type"]
    ].copy()
