from src.ingestion.major_loader import load_major_dataset

import pandas as pd


TABULAR_COLUMNS = [
    "sender_domain",
    "receiver_domain",
    "date",
    "subject",
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
    "label",
]


def load_major_tabular_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load the MeAJOR dataset and return tabular features for modeling.
    Keeps all columns except sender, receiver, content_types, and source.
    """
    data = load_major_dataset(csv_path)
    data = data[TABULAR_COLUMNS].copy()

    text_columns = ["sender_domain", "receiver_domain", "date", "subject", "body", "urls", "attachment_types", "language"]
    for col in text_columns:
        data[col] = data[col].fillna("").astype(str)

    numeric_columns = [
        "url_count",
        "url_length_max",
        "url_length_avg",
        "url_subdom_max",
        "url_subdom_avg",
        "attachment_count",
    ]
    data[numeric_columns] = data[numeric_columns].fillna(0.0).astype(float)
    data["has_attachments"] = data["has_attachments"].fillna(False).astype(int)

    return data
