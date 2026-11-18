"""
Dataset Generation Script for AI Phishing Email Analyzer.
Generates a comprehensive, realistic labeled dataset (300+ entries)
covering diverse phishing attacks and legitimate business/personal emails.
"""

import os
import csv
import random

DATASET_PATH = os.path.join(os.path.dirname(__file__), "data", "dataset.csv")

# Templates for generating diverse training examples
PHISHING_TEMPLATES = [
    # Credential Harvesting & Account Suspension
    ("Your {bank} account has been suspended", "Dear customer, we detected unauthorized login attempts on your {bank} account. To restore access, verify your credentials immediately at http://{spoof_domain}/verify-login or your account will be permanently closed within 24 hours.", 1),
    ("Security Alert: Unauthorized sign-in to your {service} account", "Someone attempted to sign in to your {service} account from an unrecognized IP address (Moscow, Russia). If this was not you, please verify your identity immediately: http://{spoof_domain}/security-check. Failure to respond will lead to account suspension.", 1),
    ("Urgent: Update your {service} billing details", "We were unable to process your monthly subscription for {service}. Your membership is currently on hold. Please update your credit card and billing information here: http://{spoof_domain}/billing-update to avoid service termination.", 1),
    ("Action Required: Your {service} password expires today", "Notice from IT Administration: Your {service} password is scheduled to expire in 2 hours. Keep your current password by verifying your credentials at http://{spoof_domain}/password-sync.", 1),
    ("Final Notice: Verify your {service} account immediately", "This is your final warning regarding unverified profile information on {service}. Please confirm your phone number, password, and security questions at http://{spoof_domain}/validate-profile within 12 hours.", 1),
    
    # Financial & Wire Scams
    ("URGENT: Outstanding Invoice #{num} - Immediate Wire Transfer Required", "Please find attached overdue invoice #{num}. We require immediate payment of $4,850 via wire transfer or ACH. Send remittance confirmation to billing@{spoof_domain}. Failure to pay will result in legal action.", 1),
    ("Wire transfer request for pending vendor contract", "Hi, I am currently in a meeting and cannot take calls. Please process a priority wire transfer of $24,500 to our new supplier account right away. Bank routing details: 021000021. Confirm when completed.", 1),
    ("Overdue payment penalty notice", "Your company account has an overdue balance of $1,290.00. To prevent collection agency referral and credit score penalties, settle the payment now via bitcoin wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.", 1),
    ("Cryptocurrency Wallet Security: {crypto} sync required", "Your {crypto} wallet requires an immediate protocol migration to prevent loss of funds. Input your 12-word recovery seed phrase at http://{spoof_domain}/wallet-recovery to restore your balance.", 1),

    # Package Delivery & Fake Receipts
    ("Delivery Exception: Package #{num} could not be delivered", "Your {courier} parcel could not be delivered due to an incorrect shipping address and unpaid customs fees ($2.95). Update your delivery address and pay the fee at http://{spoof_domain}/track-{num} to avoid package return.", 1),
    ("Order Confirmation: Thank you for purchasing {product}", "Thank you for your order of {product} for $1,499.00 from {retailer}. If you did not authorize this charge, call our dispute center immediately or click http://{spoof_domain}/cancel-order to dispute the charge.", 1),
    ("Your package has been placed on hold", "Important notice regarding delivery #{num}. The courier was unable to verify recipient identity. Please verify your identity and signature here: http://{spoof_domain}/confirm-parcel.", 1),

    # Prizes, Lottery & Tax Scams
    ("Congratulations! You have won the {lottery} prize!", "You were selected as the lucky winner of $850,000 in the {lottery} annual giveaway! To claim your funds, send your full name, bank details, and an administrative fee of $150 to claim@{spoof_domain}.", 1),
    ("Official Notification: Tax Refund of $2,410.50 Approved", "The Internal Revenue Service has calculated an overpayment of $2,410.50 on your tax filing. To deposit the refund directly into your account, submit your SSN and bank details at http://{spoof_domain}/irs-refund.", 1),
    ("Unclaimed Inheritance Notification for {name}", "I represent the estate of a deceased client who shared your surname and left an unclaimed balance of $4.2 million. Contact me confidentially at barrister@{spoof_domain} to arrange transfer.", 1),

    # Office 365 / HR / DocuSign Spoofing
    ("DocuSign: Please review and sign Employee Separation Agreement", "Human Resources has uploaded a confidential document for your review. Please click http://{spoof_domain}/docusign-sign to review and sign before the deadline tomorrow morning.", 1),
    ("Payroll Alert: Direct Deposit Verification Failed", "Your bi-weekly paycheck could not be deposited due to a banking routing error. Re-enter your direct deposit routing and checking account details at http://{spoof_domain}/payroll-verify.", 1),
    ("Mailbox Quota Exceeded: Incoming emails blocked", "Your enterprise email storage is 98% full. Incoming messages are currently being queued. Click http://{spoof_domain}/increase-storage to upgrade your mailbox quota immediately.", 1),
    ("Shared Document: Confidential Q3 Bonus Allocations.xlsx", "A spreadsheet has been shared with you on SharePoint. Sign in with your corporate Microsoft credentials at http://{spoof_domain}/sharepoint-login to view the file.", 1),
]

LEGITIMATE_TEMPLATES = [
    # Work, Engineering & Meetings
    ("Project Sprint Planning - Agenda and Notes", "Hi team, please find attached the agenda for our upcoming Sprint 24 planning session scheduled for tomorrow at 10:00 AM PST. Please review the backlog items in Jira beforehand.", 0),
    ("Code Review: Pull Request #{num} merged into main", "Hey all, I reviewed and merged PR #{num} for the authentication refactor. All unit tests passed in CI/CD pipeline. Let me know if you spot any regressions.", 0),
    ("Weekly Team Sync - Meeting Minutes", "Thanks everyone for joining today's sync. Key takeaways: 1. API migration on track for Friday. 2. Performance benchmarks improved by 15%. Next meeting scheduled for next Tuesday.", 0),
    ("Updated design mockups for user profile settings", "Hi Sarah, I updated the Figma mockups based on user feedback from yesterday's usability tests. Let me know what you think when you have a free moment.", 0),
    ("Reminder: Quarterly OKR review submissions", "Hi everyone, friendly reminder that OKR self-assessments for Q2 are due by the end of this week. Reach out if you have any questions or need clarification.", 0),
    ("Server maintenance scheduled for Saturday 2:00 AM UTC", "Infrastructure notice: We will be performing database kernel updates this Saturday between 2:00 AM and 4:00 AM UTC. Minor read latency may occur. No user-facing downtime expected.", 0),

    # Transactional & Services
    ("Your receipt from {service} for invoice #{num}", "Hello, thanks for your business! Your payment of $19.99 for your monthly {service} subscription was successfully processed. You can download the PDF invoice from your account settings.", 0),
    ("Your {retailer} order #{num} has shipped!", "Good news! Your recent order #{num} containing {product} is on its way. Track your package on our official carrier page using tracking number 1Z999AA10123456784.", 0),
    ("Flight Confirmation: {flight} to San Francisco", "Here is your booking confirmation for your upcoming flight {flight}. Terminal 2, Seat 14B. Online check-in opens 24 hours prior to departure via the airline mobile app.", 0),
    ("Hotel Reservation Confirmed: 2 Nights in Chicago", "Thank you for booking with us. Your reservation for 2 nights starting October 15th is confirmed. Check-in time is 3:00 PM. We look forward to hosting you.", 0),
    ("Your library books are due in 3 days", "This is an automated courtesy notice from the Central City Library. The 2 books currently checked out on your library card are due back by Friday.", 0),

    # Newsletters & Personal
    ("Tech Daily: The latest developments in AI and open source", "Here is your morning digest of tech headlines: Python 3.14 benchmark results, new developments in browser security standards, and open-source vector databases.", 0),
    ("Catching up this weekend?", "Hey! Hope you are having a productive week. Are you free to grab coffee or dinner this Saturday around 4pm? Let me know what works for you.", 0),
    ("Photos from our trip last weekend", "Hi everyone, finally got around to uploading the photos from our camping trip to our shared Google Drive folder. Enjoy looking through them!", 0),
    ("Recipe recommendation for vegetable lasagna", "Hey, here is the lasagna recipe I mentioned the other day. It turned out great! Ingredients: fresh spinach, ricotta cheese, marinara sauce, and whole wheat noodles.", 0),
    ("Volunteer day signup confirmation", "Thank you for volunteering with the community garden clean-up event this Sunday. Please wear comfortable shoes and bring a reusable water bottle.", 0),
]

BANKS = ["Bank of America", "Chase", "Wells Fargo", "Citibank", "Capital One", "HSBC", "Barclays"]
SERVICES = ["PayPal", "Microsoft 365", "Apple ID", "Google Workspace", "Netflix", "Amazon Prime", "Dropbox"]
SPOOF_DOMAINS = ["security-update-center.xyz", "verify-account-portal.top", "login-auth-service.buzz", "bank-secure-alert.online", "account-resolution-dept.cc"]
COURIERS = ["FedEx", "DHL Express", "UPS", "USPS Postal"]
RETAILERS = ["Amazon", "BestBuy", "Walmart", "Apple Store", "Target"]
PRODUCTS = ["Apple MacBook Pro 16", "Samsung 65-inch OLED TV", "Sony WH-1000XM5 Headphones", "iPad Pro 12.9"]
NAMES = ["Mr. John Anderson", "Dr. David Sterling", "Sarah Jenkins", "Michael Chang"]
CRYPTOS = ["Metamask", "Ledger Nano", "TrustWallet", "Coinbase"]
LOTTERIES = ["International Mega Millions", "European Powerball", "Global Lucky Draw"]
FLIGHTS = ["United UA 442", "Delta DL 188", "American Airlines AA 720"]

def generate_full_dataset():
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    rows = []

    # Generate Phishing Examples (~180)
    for _ in range(180):
        tmpl_sub, tmpl_body, label = random.choice(PHISHING_TEMPLATES)
        num = random.randint(100000, 999999)
        sub = tmpl_sub.format(
            bank=random.choice(BANKS),
            service=random.choice(SERVICES),
            spoof_domain=random.choice(SPOOF_DOMAINS),
            courier=random.choice(COURIERS),
            retailer=random.choice(RETAILERS),
            product=random.choice(PRODUCTS),
            name=random.choice(NAMES),
            crypto=random.choice(CRYPTOS),
            lottery=random.choice(LOTTERIES),
            flight=random.choice(FLIGHTS),
            num=num
        )
        body = tmpl_body.format(
            bank=random.choice(BANKS),
            service=random.choice(SERVICES),
            spoof_domain=random.choice(SPOOF_DOMAINS),
            courier=random.choice(COURIERS),
            retailer=random.choice(RETAILERS),
            product=random.choice(PRODUCTS),
            name=random.choice(NAMES),
            crypto=random.choice(CRYPTOS),
            lottery=random.choice(LOTTERIES),
            flight=random.choice(FLIGHTS),
            num=num
        )
        rows.append({"subject": sub, "body": body, "label": label})

    # Generate Legitimate Examples (~180)
    for _ in range(180):
        tmpl_sub, tmpl_body, label = random.choice(LEGITIMATE_TEMPLATES)
        num = random.randint(100000, 999999)
        sub = tmpl_sub.format(
            service=random.choice(SERVICES),
            retailer=random.choice(RETAILERS),
            product=random.choice(PRODUCTS),
            flight=random.choice(FLIGHTS),
            num=num
        )
        body = tmpl_body.format(
            service=random.choice(SERVICES),
            retailer=random.choice(RETAILERS),
            product=random.choice(PRODUCTS),
            flight=random.choice(FLIGHTS),
            num=num
        )
        rows.append({"subject": sub, "body": body, "label": label})

    # Shuffle dataset
    random.seed(42)
    random.shuffle(rows)

    with open(DATASET_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["subject", "body", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Successfully generated {len(rows)} labeled email records into {DATASET_PATH}")

if __name__ == "__main__":
    generate_full_dataset()
