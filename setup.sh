#!/usr/bin/env bash
# ==============================================================================
# AI Phishing Email Analyzer - Linux & macOS Automated Setup Script
# ==============================================================================

set -e

echo "=================================================="
echo "   AI Phishing Email Analyzer - Linux Setup       "
echo "=================================================="

# Check for Python 3
if ! command -v python3 &>/dev/null; then
    echo "[!] Error: python3 is not installed or not in PATH."
    echo "    On Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-pip python3-venv"
    exit 1
fi

echo "[*] Python version: $(python3 --version)"

# Create virtual environment if not already present
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment in ./venv..."
    python3 -m venv venv
else
    echo "[*] Virtual environment ./venv already exists."
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip and install dependencies
echo "[*] Installing dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

# Train model
echo "[*] Training machine learning pipeline..."
python train_model.py

# Seed demonstration scans
echo "[*] Seeding database with initial portfolio scans..."
python seed_samples.py

# Run test suite
echo "[*] Running automated test suite..."
pytest -v

echo ""
echo "=================================================="
echo " [OK] Setup completed successfully!"
echo " Start the application with: ./run.sh"
echo " Or run: python app.py"
echo "=================================================="
