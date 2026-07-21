"""
Train and save the final MeAJOR TF-IDF + Linear SVM model.

Saves the calibrated classifier to the repository `models/` directory as
`phishing_classifier_major.pkl`.
"""
from pathlib import Path
import sys
import joblib

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline

from src.ingestion.major_loader import load_major_training_dataset


DEFAULT_OUT = Path(__file__).resolve().parents[2] / "models" / "phishing_classifier_major.pkl"


def build_major_pipeline() -> Pipeline:
    """Build the TF-IDF + LinearSVC (calibrated) pipeline with best params."""
    tfidf = TfidfVectorizer(ngram_range=(1, 3), max_features=20000)
    svc = LinearSVC(C=2.0, max_iter=20000)
    clf = CalibratedClassifierCV(estimator=svc, cv=3)
    return Pipeline([("tfidf", tfidf), ("clf", clf)])


def train_and_save() -> Path:
    """Train on the provided CSV (MeAJOR format) and save the trained model.

    Returns the path to the saved model file.
    """

    data = load_major_training_dataset("data/raw/meajor_cleaned_preprocessed.csv")
    X = data["text"]
    y = data["label"]

    pipeline = build_major_pipeline()
    pipeline.fit(X, y)

    DEFAULT_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, DEFAULT_OUT)
    print(f"Saved model to: {DEFAULT_OUT}")
    return DEFAULT_OUT


if __name__ == "__main__":
    train_and_save()
