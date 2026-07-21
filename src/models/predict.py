"""
Provide email predictions without exposing model details to the application.

Returned value:
 - label ("phishing" or "legitimate")
 - probability
"""

from pathlib import Path

import joblib

from src.features.text_features import clean_text


MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "phishing_classifier.pkl"
MODEL = joblib.load(MODEL_PATH)

MAJOR_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "phishing_classifier_major.pkl"
MAJOR_MODEL = joblib.load(MAJOR_MODEL_PATH)

LABEL_MAP = {
    1: "phishing",
    0: "legitimate",
}


def _build_text_from_fields(fields: dict) -> str:
    """Constructs a combined text field from dataset-style input dict.

    Expects keys: sender_domain, receiver_domain, date, subject, body, urls, attachment_types, language
    """
    parts = []
    for k in ["sender_domain", "receiver_domain", "date", "subject", "body", "urls", "attachment_types", "language"]:
        v = fields.get(k, "")
        if v is None:
            v = ""
        parts.append(clean_text(v))
    return " ".join(p for p in parts if p)


def predict_email(text: str) -> dict[str, str | float]:
    """Predict label and probability from raw email text."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("No valid text provided for prediction")

    cleaned = clean_text(text)
    pred = MODEL.predict([cleaned])[0]
    probs = MODEL.predict_proba([cleaned])[0]
    class_index = list(MODEL.classes_).index(pred)
    return {"label": LABEL_MAP[int(pred)], "probability": float(probs[class_index])}


def predict_structured(record: dict) -> dict[str, str | float]:
    """Predict label and probability from structured record (dictionary of fields)."""
    text = _build_text_from_fields(record)
    if not text:
        raise ValueError("No valid text could be built from input fields")

    pred = MAJOR_MODEL.predict([text])[0]
    probs = MAJOR_MODEL.predict_proba([text])[0]
    class_index = list(MAJOR_MODEL.classes_).index(pred)
    return {"label": LABEL_MAP[int(pred)], "probability": float(probs[class_index])}
