"""
Train and evaluate the baseline phishing email classifier
"""

import argparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.ingestion.email_loader import load_training_dataset

## Create a TF-IDF and logistic regression text classification pipeline
def build_baseline_model() -> Pipeline:
    
    return Pipeline(
        [
            ("tfidf", TfidfVectorizer()),
            ("classifier", LogisticRegression(max_iter=1000)),
        ]
    )

## Load the dataset, train the baseline model, and print test metrics.
def train_and_evaluate(
    csv_path: str,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Pipeline:
    data = load_training_dataset(csv_path)

    if data["label"].nunique() < 2:
        raise ValueError("Training requires at least two distinct labels.")

    x_train, x_test, y_train, y_test = train_test_split(
        data["text"],
        data["label"],
        test_size=test_size,
        random_state=random_state,
        stratify=data["label"],
    )

    model = build_baseline_model()
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    labels = model.named_steps["classifier"].classes_

    print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
    print(
        "Precision: "
        f"{precision_score(y_test, predictions, average='weighted', zero_division=0):.4f}"
    )
    print(
        "Recall:    "
        f"{recall_score(y_test, predictions, average='weighted', zero_division=0):.4f}"
    )
    print(
        "F1:        "
        f"{f1_score(y_test, predictions, average='weighted', zero_division=0):.4f}"
    )
    print(f"Confusion matrix labels: {list(labels)}")
    print(confusion_matrix(y_test, predictions, labels=labels))

    return model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train and evaluate the baseline phishing email classifier."
    )
    parser.add_argument(
        "csv_path",
        help="Path to the raw training CSV containing Email Text and Email Type.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train_and_evaluate(args.csv_path)
