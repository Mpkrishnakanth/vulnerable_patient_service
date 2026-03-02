# ==============================================================
#  TEST SERVICE — vulnerable_patient_service.py
#  FOR TESTING RegXplain ONLY — DO NOT USE IN PRODUCTION
#  Contains intentional violations across GDPR, HIPAA, PCI-DSS,
#  OWASP, NIST, CCPA, GLBA, COPPA, SOC 2, CIS Controls
# ==============================================================

import sqlite3
import smtplib
import logging
import hashlib

# ── VIOLATION 1: Hardcoded Secret (NIST / CIS) ───────────────
SECRET_KEY = "supersecret123"
DATABASE_URL = "sqlite:///patients.db"
API_KEY = "sk-prod-abc123xyz789"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def get_db():
    return sqlite3.connect("patients.db")


# ── VIOLATION 2: SQL Injection (OWASP / GDPR Art.32) ─────────
def get_patient(patient_id):
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM patients WHERE id = {patient_id}"
    cursor.execute(query)
    return cursor.fetchone()


# ── VIOLATION 3: Plaintext Password (HIPAA / GDPR Art.32) ────
def register_user(username, password, email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    )
    conn.commit()
    return {"status": "registered"}


# ── VIOLATION 4: Sensitive Data in Logs (HIPAA / FERPA) ──────
def get_medical_record(patient_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM records WHERE patient_id = ?", (patient_id,))
    record = cursor.fetchone()
    logger.info(f"Fetched patient record: ssn={record[2]}, diagnosis={record[3]}")
    return record


# ── VIOLATION 5: Unencrypted Email Transmission (PCI-DSS) ────
def send_report(email, report_content):
    smtp = smtplib.SMTP("smtp.hospital.com", 25)
    smtp.sendmail("noreply@hospital.com", email, report_content)
    smtp.quit()
    return {"status": "sent"}


# ── VIOLATION 6: Plaintext Card Storage (PCI-DSS) ────────────
def store_payment(patient_id, card_number, cvv, expiry):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT INTO payments (patient_id, card_number, cvv, expiry) VALUES ({patient_id}, {card_number}, {cvv}, '{expiry}')"
    )
    conn.commit()
    return {"status": "stored"}


# ── VIOLATION 7: Weak Cryptography (NIST / ISO 27001) ────────
def hash_password_weak(password):
    return hashlib.md5(password.encode()).hexdigest()


# ── VIOLATION 8: Debug Mode Enabled (CIS / NIST) ─────────────
def start_app():
    from flask import Flask
    app = Flask(__name__)
    app.run(debug=True, host="0.0.0.0", port=5000)


# ── VIOLATION 9: Unmasked SSN in API Response (GLBA) ─────────
def get_patient_profile(patient_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, ssn, account_number FROM patients WHERE id = ?", (patient_id,))
    row = cursor.fetchone()
    return {"name": row[0], "ssn": row[1], "account_number": row[2]}


# ── VIOLATION 10: Missing Rate Limiting on Login (SOC 2) ─────
def login(username, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                   (username, password))
    user = cursor.fetchone()
    if user:
        return {"status": "success", "token": "abc123"}
    return {"status": "failed"}


# ── VIOLATION 11: No Age Verification in Signup (COPPA) ──────
def signup(username, email, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                   (username, email, password))
    conn.commit()
    return {"status": "signed up"}


# ── VIOLATION 12: Missing Data Deletion (GDPR Art.17) ────────
def delete_user(user_id):
    # Returns success but does NOT actually delete
    logger.info(f"Delete requested for user {user_id}")
    return {"status": "success"}
