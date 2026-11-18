"""
Seed Script: Pre-populates the database with initial sample analyses
for immediate portfolio demonstration.
"""

import os
import joblib
from app import load_ml_model, ml_predict_wrapper
from src.preprocessing import parse_email_message
from src.email_analyzer import analyze_email_full
from src.feature_extraction import explain_text_features
from src.database import init_db, save_analysis, get_dashboard_stats

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")


def seed():
    init_db()
    load_ml_model()

    sample_files = [
        "phishing_paypal_urgent.txt",
        "phishing_ceo_wire_fraud.txt",
        "phishing_microsoft_mfa.txt",
        "legitimate_project_status.txt",
        "legitimate_github_notification.txt",
        "legitimate_order_receipt.txt"
    ]

    print("[*] Seeding database with portfolio demonstration emails...")
    pipeline = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

    for fname in sample_files:
        fpath = os.path.join(SAMPLES_DIR, fname)
        if not os.path.exists(fpath):
            continue

        with open(fpath, "r", encoding="utf-8") as f:
            raw = f.read()

        parsed = parse_email_message(raw)
        sender = parsed["sender"]
        subject = parsed["subject"]
        body = parsed["body"]

        result = analyze_email_full(
            sender=sender,
            subject=subject,
            body=body,
            raw_content=raw,
            ml_predict_fn=ml_predict_wrapper
        )

        tokens = {}
        if pipeline is not None:
            tokens = explain_text_features(pipeline, f"{subject} {body}")

        record_data = {
            "sender": sender,
            "subject": subject,
            "body": body,
            "verdict": result["verdict"],
            "risk_level": result["risk_level"],
            "risk_score": result["risk_score"],
            "confidence": result["confidence"],
            "reasons": result["reasons"],
            "recommendations": result["recommendations"],
            "url_data": result["url_data"],
            "sender_data": result["sender_data"],
            "technical_data": result["technical_data"],
            "token_attributions": tokens
        }

        row_id = save_analysis(record_data)
        print(f"  [+] Seeded #{row_id}: [{result['verdict']}] '{subject[:35]}...' ({result['risk_level']} Risk)")

    stats = get_dashboard_stats()
    print(f"\n[OK] Database seeded! Total records: {stats['total_analyzed']} (Phishing: {stats['phishing_count']}, Legit: {stats['legitimate_count']})")


if __name__ == "__main__":
    seed()
