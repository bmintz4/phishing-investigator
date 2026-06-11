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

LABEL_MAP = {
    "Phishing Email": "phishing",
    "Safe Email": "legitimate",
}

## Return the predicted label and probability for an email
def predict_email(text: str) -> dict[str, str | float]:
    cleaned_text = clean_text(text)
    if not cleaned_text:
        raise ValueError("Email text cannot be empty.")

    model_label = MODEL.predict([cleaned_text])[0]
    class_probabilities = MODEL.predict_proba([cleaned_text])[0]
    class_index = list(MODEL.classes_).index(model_label)

    if model_label not in LABEL_MAP:
        raise ValueError(f"Unsupported model label: {model_label}")

    return {
        "label": LABEL_MAP[model_label],
        "probability": float(class_probabilities[class_index]),
    }
