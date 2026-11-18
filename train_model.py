"""
Model Training Script for AI Phishing Email Analyzer.
Loads dataset, builds TF-IDF pipeline, trains calibrated classifier,
computes evaluation metrics, and persists artifacts to models/ directory.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score
)
from src.feature_extraction import build_classification_pipeline

DATASET_PATH = os.path.join(os.path.dirname(__file__), "data", "dataset.csv")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.pkl")
METRICS_PATH = os.path.join(MODELS_DIR, "model_metadata.json")


def train():
    os.makedirs(MODELS_DIR, exist_ok=True)
    print("==================================================")
    print("  AI Phishing Email Analyzer - Training Pipeline  ")
    print("==================================================")

    # 1. Load dataset
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}. Run generate_dataset.py first.")

    print(f"[*] Loading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")
    df["text"] = df["subject"] + " " + df["body"]

    X = df["text"].values
    y = df["label"].values.astype(int)

    total_samples = len(df)
    phishing_count = int(np.sum(y == 1))
    legit_count = int(np.sum(y == 0))
    print(f"[+] Total samples: {total_samples} (Phishing: {phishing_count}, Legitimate: {legit_count})")

    # 2. Stratified train/test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # 3. Build & fit pipeline
    print("[*] Training TF-IDF + Calibrated LinearSVC classifier...")
    pipeline = build_classification_pipeline()
    pipeline.fit(X_train, y_train)

    # 4. Evaluation
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_proba))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    print("\n---------------- Model Evaluation ----------------")
    print(f"  Accuracy:         {acc * 100:.2f}%")
    print(f"  Precision:        {prec * 100:.2f}%")
    print(f"  Recall:           {rec * 100:.2f}%")
    print(f"  F1-Score:         {f1 * 100:.2f}%")
    print(f"  ROC-AUC:          {roc_auc:.4f}")
    print(f"  Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("--------------------------------------------------\n")

    # 5. Extract top feature weights
    vectorizer = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["classifier"]
    feature_names = vectorizer.get_feature_names_out()

    coef_list = []
    for cal_clf in clf.calibrated_classifiers_:
        if hasattr(cal_clf.estimator, "coef_"):
            coef_list.append(cal_clf.estimator.coef_[0])
    avg_coef = np.mean(coef_list, axis=0) if coef_list else np.zeros(len(feature_names))

    top_phish_indices = np.argsort(avg_coef)[::-1][:20]
    top_legit_indices = np.argsort(avg_coef)[:20]

    top_phishing_features = [
        {"feature": feature_names[i], "weight": round(float(avg_coef[i]), 3)}
        for i in top_phish_indices if avg_coef[i] > 0
    ]
    top_legitimate_features = [
        {"feature": feature_names[i], "weight": round(float(abs(avg_coef[i])), 3)}
        for i in top_legit_indices if avg_coef[i] < 0
    ]

    # 6. Save model and metadata
    print(f"[*] Saving trained model to {MODEL_PATH}...")
    joblib.dump(pipeline, MODEL_PATH)

    metadata = {
        "algorithm": "TF-IDF + Calibrated Linear Support Vector Machine (LinearSVC)",
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": total_samples,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "phishing_samples": phishing_count,
        "legitimate_samples": legit_count,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": {
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
                "true_positive": tp
            }
        },
        "top_phishing_features": top_phishing_features,
        "top_legitimate_features": top_legitimate_features
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[*] Saved performance metadata to {METRICS_PATH}")
    print("[OK] Model training completed successfully!\n")


if __name__ == "__main__":
    train()
