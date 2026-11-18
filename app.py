"""
AI Phishing Email Analyzer - Web Application
Flask backend providing cybersecurity analysis, ML classification,
history management, and model telemetry.
"""

import os
import json
import html
import joblib
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify, abort
)
from werkzeug.utils import secure_filename

from src.preprocessing import parse_email_message, clean_email_text
from src.email_analyzer import analyze_email_full
from src.feature_extraction import explain_text_features
from src.database import (
    init_db, save_analysis, get_analysis,
    get_all_analyses, get_dashboard_stats,
    delete_analysis, clear_all_history
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "models", "model_metadata.json")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cybersecurity-ai-phishing-analyzer-key-2026")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 Megabytes upload limit
ALLOWED_EXTENSIONS = {"txt", "eml"}

# Global ML Pipeline
ml_pipeline = None


def load_ml_model():
    """Load the trained machine learning pipeline from disk."""
    global ml_pipeline
    if os.path.exists(MODEL_PATH):
        try:
            ml_pipeline = joblib.load(MODEL_PATH)
            print(f"[*] ML model successfully loaded from {MODEL_PATH}")
        except Exception as e:
            print(f"[!] Warning: Failed to load model from {MODEL_PATH}: {e}")
            ml_pipeline = None
    else:
        print("[!] Model file not found. Please run train_model.py first.")
        ml_pipeline = None


def ml_predict_wrapper(text: str) -> tuple[str, float]:
    """
    Wrapper function passed into the email analyzer engine.
    Returns (prediction: 'PHISHING' | 'LEGITIMATE', confidence: float 0.0 to 1.0)
    """
    global ml_pipeline
    if ml_pipeline is None:
        return "LEGITIMATE", 0.5

    try:
        proba = ml_pipeline.predict_proba([text])[0]
        # proba[1] is probability of Phishing (class 1)
        phish_prob = float(proba[1])
        if phish_prob >= 0.5:
            return "PHISHING", phish_prob
        else:
            return "LEGITIMATE", float(proba[0])
    except Exception as e:
        print(f"[!] Inference error: {e}")
        return "LEGITIMATE", 0.5


def allowed_file(filename: str) -> bool:
    """Validate uploaded file extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def setup_application():
    """Ensure database and model are initialized."""
    global ml_pipeline
    if ml_pipeline is None:
        load_ml_model()


# -----------------------------------------------------------------------------
# Web Routes
# -----------------------------------------------------------------------------

@app.route("/")
def dashboard():
    """Cybersecurity Dashboard with telemetry and recent scans."""
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    """Analyze Email page: accepts paste inputs or file upload."""
    if request.method == "POST":
        sender = request.form.get("sender", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        raw_email_content = ""

        # Check if file was uploaded
        file = request.files.get("email_file")
        if file and file.filename != "":
            if not allowed_file(file.filename):
                flash("Invalid file format. Only .txt and .eml files are allowed.", "danger")
                return redirect(url_for("analyze"))

            try:
                file_bytes = file.read()
                try:
                    raw_email_content = file_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    raw_email_content = file_bytes.decode("latin1", errors="replace")
                
                # Parse headers and content from uploaded email
                parsed = parse_email_message(raw_email_content)
                if not sender and parsed.get("sender"):
                    sender = parsed["sender"]
                if not subject and parsed.get("subject"):
                    subject = parsed["subject"]
                if not body and parsed.get("body"):
                    body = parsed["body"]
                elif body and parsed.get("body"):
                    body = parsed["body"]  # prefer file content if provided
            except Exception as e:
                flash(f"Error parsing uploaded file: {str(e)}", "danger")
                return redirect(url_for("analyze"))

        # Input validation: At least some content must be present
        if not body and not subject:
            flash("Please provide email text, subject, or upload an email file to analyze.", "warning")
            return redirect(url_for("analyze"))

        # Build raw text representation for technical indicators & HTML safety
        if not raw_email_content:
            raw_email_content = f"From: {sender}\nSubject: {subject}\n\n{body}"

        # Run Comprehensive Cybersecurity & ML Analysis
        analysis_result = analyze_email_full(
            sender=sender,
            subject=subject,
            body=body,
            raw_content=raw_email_content,
            ml_predict_fn=ml_predict_wrapper
        )

        # Feature explainability (word attribution)
        token_attributions = {}
        if ml_pipeline is not None:
            combined_text = f"{subject} {body}"
            token_attributions = explain_text_features(ml_pipeline, combined_text, top_k=6)

        # Package data for database storage
        record_data = {
            "sender": sender,
            "subject": subject if subject else "(No Subject)",
            "body": body,
            "verdict": analysis_result["verdict"],
            "risk_level": analysis_result["risk_level"],
            "risk_score": analysis_result["risk_score"],
            "confidence": analysis_result["confidence"],
            "reasons": analysis_result["reasons"],
            "recommendations": analysis_result["recommendations"],
            "url_data": analysis_result["url_data"],
            "sender_data": analysis_result["sender_data"],
            "technical_data": analysis_result["technical_data"],
            "token_attributions": token_attributions
        }

        # Save to SQLite
        analysis_id = save_analysis(record_data)

        return redirect(url_for("result_view", analysis_id=analysis_id))

    return render_template("analyze.html")


@app.route("/result/<int:analysis_id>")
def result_view(analysis_id: int):
    """Render detailed interactive analysis report."""
    analysis = get_analysis(analysis_id)
    if not analysis:
        flash("Analysis report not found.", "warning")
        return redirect(url_for("dashboard"))

    # Compute token feature explanations for display
    token_attributions = {}
    if ml_pipeline is not None:
        combined_text = f"{analysis.get('subject', '')} {analysis.get('raw_body', '')}"
        token_attributions = explain_text_features(ml_pipeline, combined_text, top_k=6)

    return render_template("result.html", analysis=analysis, token_attributions=token_attributions)


@app.route("/history")
def history():
    """Display searchable analysis history."""
    verdict_filter = request.args.get("verdict", "").strip().upper()
    if verdict_filter not in ["PHISHING", "LEGITIMATE"]:
        verdict_filter = None
    
    analyses = get_all_analyses(limit=100, verdict_filter=verdict_filter)
    return render_template("history.html", analyses=analyses, active_filter=verdict_filter)


@app.route("/history/delete/<int:analysis_id>", methods=["POST"])
def delete_record(analysis_id: int):
    """Delete a single analysis record."""
    delete_analysis(analysis_id)
    flash(f"Analysis #{analysis_id} deleted successfully.", "info")
    return redirect(url_for("history"))


@app.route("/history/clear", methods=["POST"])
def clear_history():
    """Clear all analysis records."""
    clear_all_history()
    flash("Analysis history cleared successfully.", "info")
    return redirect(url_for("history"))


@app.route("/performance")
def performance():
    """Display ML model performance telemetry and confusion matrix."""
    metadata = {}
    if os.path.exists(METADATA_PATH):
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception as e:
            print(f"[!] Error reading metadata: {e}")

    return render_template("performance.html", metadata=metadata)


# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    """Return JSON statistics for charts."""
    return jsonify(get_dashboard_stats())


@app.route("/api/sample/<sample_name>")
def get_sample(sample_name: str):
    """Return pre-configured sample email content for 1-click evaluation."""
    safe_name = secure_filename(sample_name)
    sample_file = os.path.join(SAMPLES_DIR, f"{safe_name}.txt")
    if not os.path.exists(sample_file):
        return jsonify({"error": "Sample not found"}), 404

    try:
        with open(sample_file, "r", encoding="utf-8") as f:
            content = f.read()
        parsed = parse_email_message(content)
        return jsonify({
            "sender": parsed["sender"],
            "subject": parsed["subject"],
            "body": parsed["body"],
            "raw": content
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------------------------------------------------------
# Error Handlers
# -----------------------------------------------------------------------------

@app.errorhandler(413)
def file_too_large(e):
    flash("The uploaded file exceeds the 2MB size limit.", "danger")
    return redirect(url_for("analyze")), 413


@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error_msg="Page not found (404)"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("base.html", error_msg="An unexpected internal server error occurred (500)"), 500


if __name__ == "__main__":
    init_db()
    load_ml_model()
    print("\n============================================================")
    print("  AI Phishing Email Analyzer running on http://127.0.0.1:5000  ")
    print("============================================================\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
