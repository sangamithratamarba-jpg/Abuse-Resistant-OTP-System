# Nestack Abuse-Resistant OTP System

A Python Flask + SQLite implementation for the Nestack SDE technical assessment.

## Features

- Cryptographically secure 6-digit OTP generation using `secrets.randbelow()`.
- OTP is stored as a SHA-256 hash, never as plaintext.
- OTP expires after 10 minutes.
- Maximum 5 incorrect verification attempts; the OTP is locked after the fifth.
- Maximum 3 `/auth/send` requests per identifier in a 10-minute window.
- Rate limiting is tracked per identifier, not per IP.
- Successful OTP verification immediately marks the OTP as used.
- A used OTP cannot be verified again.
- Session token is generated using `secrets.token_urlsafe(32)`.
- No authentication library is used.
- SQLite is used for OTP storage.
- OTP is printed to the server console during development instead of sending real SMS/email.

## Setup

### 1. Install Python

Use Python 3.10+.

### 2. Create a virtual environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

macOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run

```bash
python app.py
```

The API will run on:

```text
http://127.0.0.1:5000
```

## API

### POST /auth/send

Request:

```json
{
  "identifier": "user@example.com"
}
```

Success:

```json
{
  "message": "OTP sent to user@example.com"
}
```

The development OTP is printed in the server console.

### POST /auth/verify

Request:

```json
{
  "identifier": "user@example.com",
  "code": "123456"
}
```

Success:

```json
{
  "message": "Verified",
  "session_token": "<random_opaque_string>"
}
```

Incorrect code:

```json
{
  "message": "Invalid or expired code",
  "attempts_remaining": 3
}
```

After five incorrect attempts, the endpoint returns HTTP 429 and the current OTP is locked.

## Security decisions

### CSPRNG

The OTP is generated with:

```python
secrets.randbelow(1_000_000)
```

Python's `secrets` module is designed for security-sensitive random values and is used instead of `random`.

### Hashing

Only the SHA-256 hash of the OTP is stored:

```python
hashlib.sha256(code.encode("utf-8")).hexdigest()
```

The plaintext OTP exists only temporarily while processing the request and is printed only to the development server console.

`secrets.compare_digest()` is used for the hash comparison.

### Rate limiting

Send requests are tracked in an in-memory dictionary:

```text
identifier -> [request timestamps]
```

Only the last 10 minutes are retained. If there are already 3 requests in the window, the fourth request returns HTTP 429.

Incorrect verification attempts are stored with the OTP record in SQLite. The counter is incremented after every incorrect code. The fifth incorrect attempt locks the OTP and returns HTTP 429.

### OTP invalidation

When verification succeeds:

```text
used = 1
```

The next verification attempt is rejected even if the OTP has not reached its 10-minute expiry.

## Threat model / leaked OTP table

If the OTP table were leaked, an attacker would recover:

- the identifier (email/phone);
- creation and expiry timestamps;
- the used flag;
- the failed-attempt counter;
- the SHA-256 hash of the OTP.

The attacker would **not** directly recover the plaintext OTP from the database.

However, a 6-digit OTP has only 1,000,000 possible values. Therefore, hashing alone does not make a six-digit OTP permanently resistant to offline brute force if an attacker has the database. The main online protections in this implementation are the five-attempt verification lock and the send rate limit.

For a production system, a slow password hashing function or an additional server-side secret/pepper could provide stronger protection against database compromise. This assessment specifically requires bcrypt or SHA-256, so SHA-256 is used here.

## Deployment

This project can be deployed to a Python-compatible hosting service.

Important: the assessment requires a live deployment link and a private GitHub repository.

After deployment, the endpoints are:

```text
https://YOUR-DOMAIN/auth/send
https://YOUR-DOMAIN/auth/verify
```

Do not commit real secrets or credentials to GitHub.

## Files

- `app.py` - Flask API and security logic
- `requirements.txt` - Python dependency
- `README.md` - setup and security documentation
