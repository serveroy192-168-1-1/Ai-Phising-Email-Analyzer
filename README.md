# 🛡️ AI Phishing Email Analyzer

> An end-to-end, portfolio-ready cybersecurity application that leverages Machine Learning (NLP + TF-IDF + Calibrated SVM) and multi-layered static threat heuristics to analyze emails, predict phishing threats, and provide explainable risk assessments.

---

## 📌 Table of Contents

- [Project Overview](#-project-overview)
- [Problem Statement](#-problem-statement)
- [System Architecture](#-system-architecture)
- [Detection Engine & Multi-Layer Defense](#-detection-engine--multi-layer-defense)
  - [1. Machine Learning Classification](#1-machine-learning-classification)
  - [2. Sender Authentication & Spoofing Detection](#2-sender-authentication--spoofing-detection)
  - [3. Social Engineering & Heuristic Analysis](#3-social-engineering--heuristic-analysis)
  - [4. Static URL Threat Inspection](#4-static-url-threat-inspection)
  - [5. Technical & HTML Indicators](#5-technical--html-indicators)
  - [6. Explainable AI & Composite Risk Scoring](#6-explainable-ai--composite-risk-scoring)
- [Technologies Used](#-technologies-used)
- [Machine Learning Pipeline](#-machine-learning-pipeline)
  - [Dataset](#dataset)
  - [Feature Engineering](#feature-engineering)
  - [Model Evaluation & Telemetry](#model-evaluation--telemetry)
- [Project Directory Structure](#-project-directory-structure)
- [Defensive Security & Privacy](#-defensive-security--privacy)
- [Installation & Setup](#-installation--setup)
  - [Windows Setup](#windows-setup)
  - [Linux / macOS Setup](#linux--macos-setup)
- [How to Run](#-how-to-run)
- [Running Automated Tests](#-running-automated-tests)
- [Application Walkthrough & Features](#-application-walkthrough--features)
- [Limitations & Future Roadmap](#-limitations--future-roadmap)
- [License & Disclaimer](#-license--disclaimer)

---

## 🔍 Project Overview

Phishing remains the **#1 initial attack vector** for corporate breaches, ransomware deployments, and credential thefts. Attackers frequently blend sophisticated psychological triggers (urgency, fear of loss, authority impersonation) with technical tricks (lookalike domains, obscured URLs, free webmail spoofing, display name manipulation).

**AI Phishing Email Analyzer** is a defensive security tool designed to inspect raw emails, extract indicators of compromise (IoCs), classify the message as **PHISHING** or **LEGITIMATE**, and deliver an **explainable report** that non-technical users and security analysts can immediately interpret and act upon.

---

## 🎯 Problem Statement

Traditional email filters often rely purely on static blocklists or simple keyword regex rules (`if "urgent" in text`), which can easily be bypassed by modern polymorphic phishing campaigns and spear-phishing (Business Email Compromise). Conversely, black-box AI tools output a binary score without explaining *why* an email is risky.

**Our Solution:**
1. **Calibrated Machine Learning:** Employs TF-IDF n-gram vectorization with a calibrated Linear Support Vector Machine (`LinearSVC`) yielding probabilistic confidence scores.
2. **Deterministic Cyber Heuristics:** Evaluates domain mismatch, brand impersonation, freemail abuse, raw IP links, anchor-text discrepancies, and hidden HTML.
3. **Composite Explainability:** Breaks down the risk into clear, categorized reasons, highlighting triggering vocabulary and providing actionable defense recommendations.

---

## 🏗️ System Architecture

```text
                               +---------------------------------------+
                               |              User Inputs              |
                               | (Paste text, Subject, Sender, or File)|
                               +---------------------------------------+
                                                   |
                                                   v
                               +---------------------------------------+
                               |     Flask Security & Parsing Layer    |
                               |   (XSS sanitize, MIME/RFC 822 parse)  |
                               +---------------------------------------+
                                                   |
           +-----------------------+---------------+-----------------------+
           |                       |                                       |
           v                       v                                       v
+---------------------+ +---------------------+                 +---------------------+
|   ML NLP Pipeline   | |   Sender Analyzer   |                 | Static URL Analyzer |
| (TF-IDF + Calibrated| | (Brand spoof check,  |                 | (IP links, TLDs,    |
|   Linear SVM model) | |  domain mismatch,   |                 |  anchor mismatch,   |
|                     | |  freemail misuse)   |                 |  obfuscation check) |
+---------------------+ +---------------------+                 +---------------------+
           |                       |                                       |
           +-----------------------+---------------+-----------------------+
                                                   |
                                                   v
                               +---------------------------------------+
                               |  Content & Technical Heuristics       |
                               |  (Urgency, threats, OTP lures, caps)  |
                               +---------------------------------------+
                                                   |
                                                   v
                               +---------------------------------------+
                               |  Composite Risk & Explainability Hub  |
                               |  (Score 0-100, Level, Key Reasons)    |
                               +---------------------------------------+
                                                   |
                         +-------------------------+-------------------------+
                         |                                                   |
                         v                                                   v
           +---------------------------+                       +---------------------------+
           |     SQLite Database       |                       |   Cybersecurity Web UI    |
           |  (Audit history & stats)  |                       |  (Dashboard, Results,     |
           +---------------------------+                       |   Telemetry, Charts)      |
                                                               +---------------------------+
```

---

## 🛡️ Detection Engine & Multi-Layer Defense

The application employs a defense-in-depth architecture consisting of five complementary analysis layers:

### 1. Machine Learning Classification
- Vectorizes normalized email tokens using sublinear TF-IDF scaling and unigram/bigram extraction (`ngram_range=(1, 2)`).
- Classifies the text with a Support Vector Machine calibrated via Platt scaling (`CalibratedClassifierCV`) to output well-calibrated confidence probabilities.
- Features mathematical token attribution to isolate the exact vocabulary exerting positive (phishing) or negative (legitimate) influence.

### 2. Sender Authentication & Spoofing Detection
- **Brand Impersonation:** Detects when a display name references a protected enterprise brand (e.g., `PayPal`, `Microsoft 365`, `Apple`, `Chase`) while the underlying domain belongs to a third party or attacker infrastructure.
- **Display Name Inversion:** Detects when attackers embed a spoofed email address inside the display name string (`"security@paypal.com" <actual_attacker@gmail.com>`).
- **Free-Mail Abuse:** Flags free public webmail providers (`@gmail.com`, `@yahoo.com`, `@outlook.com`) claiming executive or IT security authority.
- **Typosquatting & Lookalike Domains:** Detects character homoglyphs and substitutions (e.g., `paypa1.com`, `micros0ft.com`).

### 3. Social Engineering & Heuristic Analysis
Detects psychological coercion tactics across seven behavioral categories:
- **Urgency & Artificial Deadlines:** `"immediately"`, `"within 24 hours"`, `"action required"`.
- **Account Suspension & Legal Threats:** `"account suspended"`, `"legal action"`, `"law enforcement"`.
- **Credential & Password Harvesting:** `"verify your password"`, `"login credentials"`, `"re-activate profile"`.
- **MFA / OTP Code Solicitation:** `"one-time password"`, `"enter verification code"`, `"2fa token"`.
- **Wire & Cryptocurrency Demands:** `"wire transfer"`, `"bitcoin wallet"`, `"unpaid invoice"`, `"gift card"`.
- **Fabricated Security Notices:** `"unauthorized sign-in detected"`, `"unrecognized IP address"`.
- **Reward / Lottery Scams:** `"you have won"`, `"claim your prize"`, `"unclaimed inheritance"`.

### 4. Static URL Threat Inspection
Performs zero-network static security auditing on every extracted hyperlink:
- **Zero Remote Execution:** Never connects, pings, or resolves target URLs.
- **Deceptive Anchor Text Mismatch:** Detects when the displayed link anchor differs from the destination `href` (e.g., `<a href="http://evil.com">https://paypal.com</a>`).
- **Raw IP Address URLs:** Flags links utilizing direct numeric IPs (e.g., `http://192.168.1.1/login`) instead of registered domains.
- **High-Abuse TLDs:** Identifies domains ending in top abuse extensions (`.xyz`, `.top`, `.buzz`, `.club`, `.work`, `.click`, `.ru`).
- **Excessive Subdomain Depth:** Flags deep subdomain structures designed to emulate official hostnames (`login.paypal.com.attacker.xyz`).
- **Obfuscation Tricks:** Flags credentials embedded via `@` redirection (`https://google.com@evil-site.com`) and excessive hex encoding.

### 5. Technical & HTML Indicators
- **Hidden Text & Obfuscation:** Detects HTML trickery like `display: none`, `font-size: 0px`, and transparent fonts.
- **Screaming Urgency:** Measures excessive uppercase character ratios (>40% capitalization) and abnormal punctuation sequences (`!!!`, `???`).
- **Dangerous Attachment Profiles:** Detects dangerous extensions (`.exe`, `.iso`, `.vbs`, `.scr`, `.bat`, `.docm`) referenced in MIME headers.

### 6. Explainable AI & Composite Risk Scoring
Combines the continuous ML probability (0–50 pts) with deterministic security findings (0–50 pts) into a normalized **0–100 Risk Score**:
- **LOW Risk (0–29):** Authentic corporate or personal communications.
- **MEDIUM Risk (30–59):** Minor policy or protocol anomalies (e.g., insecure HTTP).
- **HIGH Risk (60–79):** Significant urgency, credential harvesting, or brand mismatch.
- **CRITICAL Risk (80–100):** Multiple malicious vectors or explicit deceptive link mismatches.

---

## 💻 Technologies Used

| Layer | Component / Library | Purpose |
| :--- | :--- | :--- |
| **Backend Web Framework** | Python 3.14 / Flask 3.1 | Application routing, security controls, REST endpoints |
| **Machine Learning** | Scikit-learn 1.9 | TF-IDF vectorizer, LinearSVC, CalibratedClassifierCV |
| **Natural Language / NLP** | NLTK 3.9 / Regex | Tokenization, stopword removal, pattern extraction |
| **Data Processing** | Pandas 2.3 & NumPy 2.4 | Dataset handling, array computations, split logic |
| **HTML Parsing & Security** | BeautifulSoup4 4.15 | Safe HTML stripping, link extraction, XSS sanitization |
| **Serialization** | Joblib 1.5 | Model pipeline persistence |
| **Database** | SQLite3 | Persistent analysis history and dashboard metrics |
| **Frontend UI** | HTML5, CSS3, Vanilla JS | Modern cybersecurity dark theme, responsive grid |
| **Visualization** | Chart.js 4.4 | Real-time threat distribution and severity charts |
| **Testing Suite** | Pytest 9.1 | Unit and integration test automation (28 tests) |

---

## 🤖 Machine Learning Pipeline

### Dataset
The training corpus (`data/dataset.csv`) contains 360 balanced, labeled email records:
- **180 Phishing Emails:** Banking suspensions, Microsoft 365 credential harvesting, CEO wire requests (BEC), cryptocurrency wallet alerts, tax refund scams, package delivery fees, and DocuSign lures.
- **180 Legitimate Emails:** Sprint planning notes, GitHub pull requests, Jira updates, flight confirmations, Amazon shipping receipts, team meeting agendas, and newsletters.

### Feature Engineering
- **Preprocessor:** Strips HTML noise, lowercases text, filters English stopwords, and replaces semantic entities with standardized tokens (`token_url`, `token_email`, `token_money`).
- **N-Gram Ranges:** Generates unigrams and bigrams (`(1, 2)`) to capture multi-word threat signatures such as `"verify account"`, `"wire transfer"`, `"unauthorized login"`.
- **Sublinear TF Scaling:** Replaces term frequency $tf$ with $1 + \log(tf)$ to prevent repetitive spam words from skewing predictions.

### Model Evaluation & Telemetry
Evaluated using a stratified 80/20 train/test split:

| Metric | Score | Note |
| :--- | :--- | :--- |
| **Accuracy** | **100.00%** | Test set classification rate |
| **Precision** | **100.00%** | Zero false positives on test set |
| **Recall (Sensitivity)** | **100.00%** | Zero false negatives on test set |
| **F1-Score** | **100.00%** | Harmonic mean of precision and recall |
| **ROC-AUC** | **1.0000** | Perfect discriminatory separation |

#### Confusion Matrix (Test Set: N = 72)
```text
                  Predicted Legitimate    Predicted Phishing
Actual Legitimate         36 (TN)                 0 (FP)
Actual Phishing            0 (FN)                36 (TP)
```

---

## 📁 Project Directory Structure

```text
Ai Phishing/
├── app.py                     # Flask web server, route definitions, security middleware
├── start.bat                  # Windows 1-click launcher script
├── setup.sh                   # Linux & macOS automated setup script
├── run.sh                     # Linux & macOS application launcher script
├── Dockerfile                 # Linux container specification (Python 3.11-slim)
├── docker-compose.yml         # Container orchestration
├── requirements.txt           # Project dependencies
├── train_model.py             # Standalone ML training and evaluation script
├── generate_dataset.py        # Dataset generation utility
├── seed_samples.py            # Pre-populates database with sample scans for demo
├── verify_app.py              # End-to-end route verification script
├── README.md                  # Comprehensive portfolio documentation
│
├── data/
│   ├── dataset.csv            # Labeled training dataset (360 samples)
│   └── phishing_history.db    # SQLite persistent history database
│
├── models/
│   ├── phishing_model.pkl     # Serialized Scikit-Learn pipeline
│   └── model_metadata.json    # Performance metrics, confusion matrix & feature weights
│
├── src/
│   ├── __init__.py
│   ├── preprocessing.py       # HTML stripper, MIME message parser, token cleaner
│   ├── feature_extraction.py  # TF-IDF pipeline builder & token attribution explainer
│   ├── email_analyzer.py      # Sender analyzer, content heuristics, composite risk scorer
│   ├── url_analyzer.py        # Static URL extractor & link security heuristics
│   └── database.py            # SQLite schema initialization and CRUD operations
│
├── templates/
│   ├── base.html              # Cybersecurity base layout with navbar & flash alerts
│   ├── dashboard.html         # Live telemetry cards, Chart.js visuals, recent scans
│   ├── analyze.html           # Submission form, file upload, 1-click sample presets
│   ├── result.html            # Explainable verdict report, URL table, sender breakdown
│   ├── history.html           # Searchable history table with filter & delete actions
│   └── performance.html       # Confusion matrix, metrics cards, top n-gram weights
│
├── static/
│   ├── css/
│   │   └── style.css          # Dark cybersecurity UI theme (Inter + JetBrains Mono)
│   └── js/
│       └── main.js            # Sample auto-loader, drag-and-drop file upload, copy helper
│
├── samples/                   # Ready-to-use demonstration emails
│   ├── phishing_paypal_urgent.txt
│   ├── phishing_ceo_wire_fraud.txt
│   ├── phishing_microsoft_mfa.txt
│   ├── legitimate_project_status.txt
│   ├── legitimate_github_notification.txt
│   └── legitimate_order_receipt.txt
│
└── tests/                     # Automated Pytest test suite (28 passing tests)
    ├── __init__.py
    ├── test_preprocessing.py  # Tests HTML sanitization, tokenization, MIME parser
    ├── test_url_analyzer.py   # Tests IP URLs, obfuscation, anchor mismatch, TLDs
    ├── test_email_analyzer.py # Tests sender spoofing, urgency heuristics, risk scorer
    ├── test_model.py          # Tests ML inference, probability calibration, XAI
    └── test_routes.py         # Tests Flask endpoints, empty inputs, file uploads
```

---

## 🔒 Defensive Security & Privacy

This application was engineered following secure development practices:
- **No Remote Network Calls:** Extracted URLs are parsed strictly using static lexical heuristics. No DNS queries, HTTP pings, or head requests are sent to untrusted attacker servers.
- **XSS Sanitization:** All user-submitted emails, subjects, and extracted URLs are strictly HTML-escaped before rendering in templates. Malicious scripts or iframe injections cannot execute in the browser.
- **File Upload Protection:** Uploads are strictly capped at 2MB (`MAX_CONTENT_LENGTH`), and extensions are whitelisted to `.txt` and `.eml` only.
- **SQL Injection Prevention:** All database operations utilize parameterized queries through SQLite `?` placeholders.
- **100% Local Inference:** No sensitive email text is sent to third-party APIs.

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.10+ (tested and verified on Python 3.14)
- Git (optional)

### Windows Setup

#### Option A: Quick 1-Click Launch (Recommended):
Simply double-click **`start.bat`** (or run it in Command Prompt / PowerShell):
```cmd
start.bat
```
*This automatically verifies Python, activates `venv` if present, trains the ML model and seeds initial data if missing, opens your default web browser to `http://127.0.0.1:5000`, and launches the Flask server!*

#### Option B: Manual Setup:
1. **Clone or navigate to the repository:**
   ```powershell
   cd "d:\Ai Phishing"
   ```

2. **(Optional) Create and activate a virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Train the ML model:**
   ```powershell
   python train_model.py
   ```

5. **(Optional) Seed sample demonstration scans:**
   ```powershell
   python seed_samples.py
   ```

6. **Start the application:**
   ```powershell
   python app.py
   ```

### Linux / macOS Setup

#### Automated One-Line Setup:
```bash
chmod +x setup.sh run.sh
./setup.sh
```

#### Manual Setup:
1. **Navigate to the repository:**
   ```bash
   cd "d:/Ai Phishing"  # or your Linux workspace path
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Train the ML model:**
   ```bash
   python3 train_model.py
   ```

5. **Seed sample demonstration scans:**
   ```bash
   python3 seed_samples.py
   ```

6. **Launch application:**
   ```bash
   ./run.sh
   # or: python3 app.py
   ```

---

### 🐳 Docker & Container Deployment (Linux Container)

You can run the entire application in an isolated Linux container without installing Python or dependencies on the host machine:

#### Using Docker Compose:
```bash
docker-compose up --build
```

#### Using Standard Docker:
```bash
docker build -t ai-phishing-analyzer .
docker run -p 5000:5000 ai-phishing-analyzer
```
Access at `http://127.0.0.1:5000`.

---

## 🚀 How to Run

1. **Start the Flask development server:**
   ```powershell
   python app.py
   ```

2. **Open your web browser:**
   ```text
   http://127.0.0.1:5000
   ```

---

## 🧪 Running Automated Tests

Run the complete Pytest suite to verify text preprocessing, URL heuristics, sender analysis, model inference, and web routes:

```powershell
pytest -v
```

Expected output:
```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1
collected 28 items

tests/test_email_analyzer.py::test_sender_brand_spoofing PASSED          [  3%]
tests/test_email_analyzer.py::test_sender_freemail_abuse PASSED          [  7%]
tests/test_email_analyzer.py::test_sender_typosquatting PASSED           [ 10%]
tests/test_email_analyzer.py::test_content_heuristics_urgency_and_threats PASSED [ 14%]
tests/test_email_analyzer.py::test_technical_indicators PASSED           [ 17%]
tests/test_email_analyzer.py::test_composite_risk_scoring PASSED         [ 21%]
tests/test_model.py::test_model_persistence PASSED                       [ 25%]
tests/test_model.py::test_model_prediction_phishing PASSED               [ 28%]
tests/test_model.py::test_model_prediction_legitimate PASSED             [ 32%]
tests/test_model.py::test_explain_text_features PASSED                   [ 35%]
tests/test_preprocessing.py::test_strip_html PASSED                      [ 39%]
tests/test_preprocessing.py::test_clean_email_text PASSED                [ 42%]
tests/test_preprocessing.py::test_parse_email_message_plain PASSED       [ 46%]
tests/test_preprocessing.py::test_parse_email_message_mime PASSED        [ 50%]
tests/test_preprocessing.py::test_malformed_email PASSED                 [ 53%]
tests/test_routes.py::test_dashboard_route PASSED                        [ 57%]
tests/test_routes.py::test_analyze_page_get PASSED                       [ 60%]
tests/test_routes.py::test_analyze_post_empty_input PASSED               [ 64%]
tests/test_routes.py::test_analyze_post_valid_email PASSED               [ 67%]
tests/test_routes.py::test_file_upload_txt PASSED                        [ 71%]
tests/test_routes.py::test_file_upload_invalid_extension PASSED          [ 75%]
tests/test_routes.py::test_history_page PASSED                           [ 78%]
tests/test_routes.py::test_performance_page PASSED                       [ 82%]
tests/test_routes.py::test_api_sample_endpoint PASSED                    [ 85%]
tests/test_url_analyzer.py::test_extract_urls_from_text_and_html PASSED  [ 89%]
tests/test_url_analyzer.py::test_ip_hostname_detection PASSED            [ 92%]
tests/test_url_analyzer.py::test_suspicious_url_heuristics PASSED        [ 96%]
tests/test_url_analyzer.py::test_analyze_all_urls_aggregation PASSED     [100%]

============================= 28 passed in 2.77s ==============================
```

---

## 🖥️ Application Walkthrough & Features

### 1. Operations Dashboard (`/`)
- Metric cards displaying Total Analyzed, Phishing Detections, Legitimate Emails, and Average Threat Index.
- Interactive Chart.js donut showing Phishing vs. Legitimate ratio.
- Severity bar chart illustrating Low, Medium, High, and Critical distribution.
- Recent analyses summary table with direct links to full reports.

### 2. Threat Inspection Engine (`/analyze`)
- **1-Click Portfolio Presets:** Click any of the 6 preset buttons (e.g. *PayPal Account Suspension*, *CEO Wire Fraud*, *Microsoft MFA Alert*, *Sprint Status*) to instantly populate the form for demonstration.
- Form inputs for Sender, Subject, and Email Body.
- Drag-and-drop file upload accepting `.txt` and `.eml` emails.

### 3. Comprehensive Analysis Report (`/result/<id>`)
- **Verdict Hero Banner:** Prominent `PHISHING` or `LEGITIMATE` badge with calibrated ML confidence % and composite Risk Score (0–100).
- **Key Reasons Checklist:** Clear, bulleted explanations categorizing social engineering, brand spoofing, link risks, and model findings.
- **Protective Action Guidance:** Specific, practical security instructions for end users.
- **Sender Verification Card:** Details originating domain, display name discrepancies, and webmail provider status.
- **Static URL Audit Table:** Shows every link, protocol (HTTP vs HTTPS), IP address status, anchor text mismatches, and specific risk flags.
- **Explainable AI Token Attribution:** Displays which exact keywords exerted mathematical pull toward Phishing or Legitimate classes.
- **Copy Summary Button:** One-click clipboard copy for incident ticketing or email dispatch.

### 4. Analysis History & Audit Logs (`/history`)
- Chronological table of all previous analyses stored in SQLite.
- Verdict filters: All, Phishing Threats Only, Legitimate Clean Only.
- Actions to view full reports or delete individual records.

### 5. Model Telemetry & Metrics (`/performance`)
- Live telemetry from `models/model_metadata.json`.
- Visual 2x2 Confusion Matrix heatmap (True Negatives, False Positives, False Negatives, True Positives).
- Accuracy, Precision, Recall, F1 Score, and ROC-AUC scores.
- Ranked tables displaying top 20 Phishing feature n-grams and top 20 Legitimate feature n-grams.

---

## 📈 Limitations & Future Roadmap

### Current Limitations
- **Static Analysis Only:** Links are analyzed lexically without resolving live DNS records or querying threat intelligence APIs (by design, to avoid network egress during local operation).
- **Homoglyph Scope:** Typosquatting checks currently cover major targeted brands (PayPal, Microsoft, Apple, Google, Amazon, Chase) rather than arbitrary custom dictionaries.

### Future Roadmap
- [ ] Integration with free local DKIM/SPF/DMARC DNS header analyzers.
- [ ] Support for parsing `.msg` (Outlook) binary files.
- [ ] Offline local LLM integration (via Ollama) for conversational email explanation.
- [ ] Automated YARA rule generation based on detected phishing patterns.

---

## ⚖️ License & Disclaimer

This project is released under the **MIT License** for educational and defensive security purposes. It is designed to assist security analysts, developers, and students in understanding email attack vectors and NLP-driven detection techniques. Always adhere to organizational security policies when handling live malicious emails.
