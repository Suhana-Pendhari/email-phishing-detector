"""
DetectPhish ML Training Pipeline
Trains a phishing email classifier using scikit-learn.

Usage:
    python train.py --dataset path/to/dataset.csv --text-col email_text --label-col label

Expects a CSV with at least two columns:
    - text column: raw email body text
    - label column: 1 = phishing, 0 = legitimate

Supported datasets:
    - Kaggle: naserabdullahalam/phishing-email-dataset
    - Kaggle: subhajournal/phishingemails
    - HuggingFace: ealvaradob/phishing-dataset
"""
import os
import sys
import json
import pickle
import argparse
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_curve, roc_auc_score, f1_score
)
from sklearn.preprocessing import FunctionTransformer

# from features import extract_features, get_feature_names
from ml.features import extract_features, get_feature_names

# ── Custom Transformer: Structural Features ──

class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts hand-crafted structural features from email text.
    Outputs a numpy array of numerical features per email.
    """
    def __init__(self):
        self.feature_names = None

    def fit(self, X, y=None):
        sample = extract_features("sample")
        self.feature_names = sorted(sample.keys())
        return self

    def transform(self, X):
        results = []
        for text in X:
            feats = extract_features(text)
            results.append([feats[name] for name in self.feature_names])
        return np.array(results)

    def get_feature_names_out(self, input_features=None):
        return self.feature_names


# ── Dataset Loaders ──

def load_dataset(path: str, text_col: str, label_col: str) -> pd.DataFrame:
    """Load and validate a CSV dataset."""
    print(f"Loading dataset from: {path}")

    if path.endswith(".csv"):
        df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")
    elif path.endswith(".tsv"):
        df = pd.read_csv(path, sep="\t", encoding="utf-8", on_bad_lines="skip")
    else:
        df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")

    # Try to auto-detect columns if provided ones don't exist
    if text_col not in df.columns:
        text_candidates = ["email_text", "text", "body", "message", "content",
                           "Email Text", "Text", "Body", "Message"]
        for col in text_candidates:
            if col in df.columns:
                text_col = col
                print(f"  Auto-detected text column: '{col}'")
                break
        else:
            print(f"  Available columns: {list(df.columns)}")
            raise ValueError(f"Text column '{text_col}' not found.")

    if label_col not in df.columns:
        label_candidates = ["label", "Label", "phishing", "is_phishing",
                            "class", "Class", "target", "spam"]
        for col in label_candidates:
            if col in df.columns:
                label_col = col
                print(f"  Auto-detected label column: '{col}'")
                break
        else:
            print(f"  Available columns: {list(df.columns)}")
            raise ValueError(f"Label column '{label_col}' not found.")

    df = df[[text_col, label_col]].copy()
    df.columns = ["text", "label"]

    # Clean
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"].str.len() > 10]

    # Normalize labels to 0/1
    unique_labels = df["label"].unique()
    if set(unique_labels) <= {0, 1}:
        pass
    elif set(unique_labels) <= {"phishing", "legitimate", "safe", "ham", "spam"}:
        phishing_labels = {"phishing", "spam"}
        df["label"] = df["label"].str.lower().apply(
            lambda x: 1 if x in phishing_labels else 0
        )
    else:
        # Try numeric conversion
        df["label"] = pd.to_numeric(df["label"], errors="coerce")
        df = df.dropna(subset=["label"])
        df["label"] = df["label"].astype(int)
        df["label"] = (df["label"] > 0).astype(int)

    print(f"  Loaded {len(df)} samples: {(df['label']==0).sum()} legitimate, {(df['label']==1).sum()} phishing")
    return df


# ── Training ──

def train_model(df: pd.DataFrame, model_dir: str = ".") -> dict:
    """
    Train the phishing classifier with combined TF-IDF + structural features.
    Saves model, vectorizer, and metadata to model_dir.
    Returns evaluation metrics.
    """
    X = df["text"].values
    y = df["label"].values

    # Split: 80% train, 20% test (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTraining set: {len(X_train)} | Test set: {len(X_test)}")

    # ── Build Pipeline ──
    # Combine TF-IDF text features with hand-crafted structural features
    tfidf = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
        strip_accents="unicode",
    )

    structural = StructuralFeatureExtractor()

    feature_union = FeatureUnion([
        ("tfidf", tfidf),
        ("structural", structural),
    ])

    # Test multiple models, pick the best
    models = {
        "logistic_regression": LogisticRegression(
            max_iter=1000, C=1.0, class_weight="balanced", random_state=42
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=30, class_weight="balanced",
            random_state=42, n_jobs=-1
        ),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=200, max_depth=5, learning_rate=0.1, random_state=42
        ),
    }

    print("\n── Model Comparison ──")
    best_model_name = None
    best_f1 = 0
    best_pipeline = None
    results = {}

    for name, model in models.items():
        pipeline = Pipeline([
            ("features", feature_union),
            ("classifier", model),
        ])

        # Cross-validation on training set
        cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5,
                                     scoring="f1", n_jobs=-1)
        mean_f1 = cv_scores.mean()
        print(f"  {name:25s} | CV F1: {mean_f1:.4f} (+/- {cv_scores.std():.4f})")

        results[name] = {
            "cv_f1_mean": round(float(mean_f1), 4),
            "cv_f1_std": round(float(cv_scores.std()), 4),
        }

        if mean_f1 > best_f1:
            best_f1 = mean_f1
            best_model_name = name
            best_pipeline = pipeline

    print(f"\n  Best model: {best_model_name} (F1: {best_f1:.4f})")

    # ── Train best model on full training set ──
    print(f"\nTraining {best_model_name} on full training set...")
    best_pipeline.fit(X_train, y_train)

    # ── Evaluate on test set ──
    y_pred = best_pipeline.predict(X_test)

    # Handle predict_proba (not all models support it)
    try:
        y_prob = best_pipeline.predict_proba(X_test)[:, 1]
        roc_auc = round(float(roc_auc_score(y_test, y_prob)), 4)
    except AttributeError:
        y_prob = None
        roc_auc = None

    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"],
                                    output_dict=True)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n── Test Set Results ──")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print(f"Confusion Matrix:")
    print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}  TP={cm[1][1]}")
    if roc_auc:
        print(f"ROC-AUC: {roc_auc}")

    # ── Save Model ──
    os.makedirs(model_dir, exist_ok=True)

    model_path = os.path.join(model_dir, "model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(best_pipeline, f)
    print(f"\nModel saved: {model_path}")

    # Save metadata
    metadata = {
        "model_name": best_model_name,
        "trained_at": datetime.now().isoformat(),
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "class_distribution": {
            "legitimate": int((y == 0).sum()),
            "phishing": int((y == 1).sum()),
        },
        "test_metrics": {
            "accuracy": round(float(report["accuracy"]), 4),
            "precision_phishing": round(float(report["Phishing"]["precision"]), 4),
            "recall_phishing": round(float(report["Phishing"]["recall"]), 4),
            "f1_phishing": round(float(report["Phishing"]["f1-score"]), 4),
            "roc_auc": roc_auc,
        },
        "confusion_matrix": {
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]),
            "false_negatives": int(cm[1][0]),
            "true_positives": int(cm[1][1]),
        },
        "model_comparison": results,
        "feature_config": {
            "tfidf_max_features": 10000,
            "tfidf_ngram_range": [1, 2],
            "structural_features": get_feature_names(),
        },
    }

    meta_path = os.path.join(model_dir, "model_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved: {meta_path}")

    return metadata


# ── CLI ──

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train DetectPhish ML classifier")
    parser.add_argument("--dataset", required=True, help="Path to CSV dataset")
    parser.add_argument("--text-col", default="text", help="Name of text column (default: text)")
    parser.add_argument("--label-col", default="label", help="Name of label column (default: label)")
    parser.add_argument("--output", default=".", help="Output directory for model files")
    args = parser.parse_args()

    df = load_dataset(args.dataset, args.text_col, args.label_col)
    metadata = train_model(df, model_dir=args.output)

    print(f"\n{'='*50}")
    print(f"Training complete!")
    print(f"  Accuracy:  {metadata['test_metrics']['accuracy']}")
    print(f"  Precision: {metadata['test_metrics']['precision_phishing']}")
    print(f"  Recall:    {metadata['test_metrics']['recall_phishing']}")
    print(f"  F1:        {metadata['test_metrics']['f1_phishing']}")
    print(f"{'='*50}")
