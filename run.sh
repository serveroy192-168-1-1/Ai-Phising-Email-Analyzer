#!/usr/bin/env bash
# ==============================================================================
# AI Phishing Email Analyzer - Linux & macOS Application Launcher
# ==============================================================================

# Activate virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Ensure dependencies and model are present
if [ ! -f "models/phishing_model.pkl" ]; then
    echo "[*] Model not found. Training model first..."
    python3 train_model.py
fi

echo "=================================================="
echo " Starting AI Phishing Email Analyzer on Linux     "
echo " Access URL: http://127.0.0.1:5000                "
echo " Press Ctrl+C to stop server                      "
echo "=================================================="

# Run application
python3 app.py
