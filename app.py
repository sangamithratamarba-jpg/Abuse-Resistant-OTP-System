import hashlib
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = "otp.db"
OTP_EXPIRY_SECONDS = 10 * 60
MAX_VERIFY_ATTEMPTS = 5
MAX_SEND_REQUESTS = 3
SEND_WINDOW_SECONDS = 10 * 60

# In-memory rate limiting is explicitly allowed by the assessment.
send_rate = {}
rate_lock = threading.Lock()
db_lock = threading.Lock()


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock:
        conn = get_db()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS otp_codes (
                identifier TEXT PRIMARY KEY,
                code_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.commit()
        conn.close()


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_otp() -> str:
    # Cryptographically secure random 6-digit OTP.
    return f"{secrets.randbelow(1_000_000):06d}"


def clean_send_window(identifier: str, now: int):
    timestamps = send_rate.get(identifier, [])
    timestamps = [
        timestamp for timestamp in timestamps
        if now - timestamp < SEND_WINDOW_SECONDS
    ]
    send_rate[identifier] = timestamps
    return timestamps


@app.post("/auth/send")
def send_otp():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip()

    if not identifier:
        return jsonify({"message": "Identifier is required"}), 400

    now = int(time.time())

    # Max 3 send requests per identifier per 10-minute window.
    with rate_lock:
        timestamps = clean_send_window(identifier, now)

        if len(timestamps) >= MAX_SEND_REQUESTS:
            return jsonify({
                "message": "Too many OTP requests. Try again later."
            }), 429

        timestamps.append(now)

    otp = generate_otp()
    created_at = now
    expires_at = now + OTP_EXPIRY_SECONDS
    code_hash = hash_code(otp)

    # Replace any previous OTP for this identifier.
    with db_lock:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO otp_codes
                (identifier, code_hash, created_at, expires_at, used, attempts)
            VALUES (?, ?, ?, ?, 0, 0)
            ON CONFLICT(identifier) DO UPDATE SET
                code_hash = excluded.code_hash,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                used = 0,
                attempts = 0
            """,
            (identifier, code_hash, created_at, expires_at),
        )
        conn.commit()
        conn.close()

    # Development only: no real SMS/email provider is required by the assessment.
    print(f"[DEV ONLY] OTP for {identifier}: {otp}")

    return jsonify({
        "message": f"OTP sent to {identifier}"
    }), 200


@app.post("/auth/verify")
def verify_otp():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip()
    code = str(data.get("code", "")).strip()

    if not identifier or not code:
        return jsonify({"message": "Identifier and code are required"}), 400

    if len(code) != 6 or not code.isdigit():
        return jsonify({"message": "Invalid or expired code"}), 400

    now = int(time.time())

    with db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM otp_codes WHERE identifier = ?",
            (identifier,),
        ).fetchone()

        if row is None:
            conn.close()
            return jsonify({"message": "Invalid or expired code"}), 400

        if row["used"]:
            conn.close()
            return jsonify({"message": "Invalid or expired code"}), 400

        if now >= row["expires_at"]:
            conn.close()
            return jsonify({"message": "Invalid or expired code"}), 400

        if row["attempts"] >= MAX_VERIFY_ATTEMPTS:
            conn.close()
            return jsonify({
                "message": "Too many incorrect attempts. OTP locked."
            }), 429

        submitted_hash = hash_code(code)

        if not secrets.compare_digest(submitted_hash, row["code_hash"]):
            new_attempts = row["attempts"] + 1

            conn.execute(
                "UPDATE otp_codes SET attempts = ? WHERE identifier = ?",
                (new_attempts, identifier),
            )
            conn.commit()
            conn.close()

            if new_attempts >= MAX_VERIFY_ATTEMPTS:
                return jsonify({
                    "message": "Too many incorrect attempts. OTP locked."
                }), 429

            return jsonify({
                "message": "Invalid or expired code",
                "attempts_remaining": MAX_VERIFY_ATTEMPTS - new_attempts,
            }), 400

        # Successful verification: invalidate immediately.
        conn.execute(
            "UPDATE otp_codes SET used = 1 WHERE identifier = ?",
            (identifier,),
        )
        conn.commit()
        conn.close()

    # Opaque, cryptographically secure session token.
    session_token = secrets.token_urlsafe(32)

    return jsonify({
        "message": "Verified",
        "session_token": session_token,
    }), 200


@app.get("/")
def home():
    return jsonify({
        "message": "Nestack Abuse-Resistant OTP API is running"
    })


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
