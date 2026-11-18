"""
Verification script: Performs end-to-end HTTP tests against all web application routes.
"""

from app import app, load_ml_model
from src.database import init_db

def run_verification():
    init_db()
    load_ml_model()
    client = app.test_client()

    routes = [
        ("/", "Dashboard"),
        ("/analyze", "Analyze Email"),
        ("/history", "History"),
        ("/performance", "Model Performance"),
        ("/api/stats", "API Stats"),
        ("/result/5", "Result View #5")
    ]

    print("==================================================")
    print("      Verifying AI Phishing Web Application       ")
    print("==================================================")

    all_ok = True
    for route, label in routes:
        res = client.get(route)
        if res.status_code == 200:
            print(f"  [PASS] {label:20} -> {route:15} (Status: 200)")
        else:
            print(f"  [FAIL] {label:20} -> {route:15} (Status: {res.status_code})")
            all_ok = False

    # Test submitting a new email analysis via POST /analyze
    post_res = client.post("/analyze", data={
        "sender": "Security Alert <alert@security-update-center.xyz>",
        "subject": "Immediate Action Required: Your account will be locked",
        "body": "Dear customer, verify your password right now at http://192.168.1.10/login to prevent termination."
    }, follow_redirects=True)

    if post_res.status_code == 200 and b"PHISHING" in post_res.data:
        print("  [PASS] Live Analysis POST   -> /analyze        (Status: 200, Verdict: PHISHING)")
    else:
        print(f"  [FAIL] Live Analysis POST   -> Status {post_res.status_code}")
        all_ok = False

    if all_ok:
        print("\n[SUCCESS] All routes and live analysis pipeline verified successfully!")
    else:
        print("\n[FAILURE] Verification encountered issues.")

if __name__ == "__main__":
    run_verification()
