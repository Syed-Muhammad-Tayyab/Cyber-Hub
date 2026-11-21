"""
Cyber Hub Backend - Password hashing & strength checking (Part 2)
Developed by Syed Muhammad Tayyab

Hashing: scrypt (memory-hard KDF, Python standard library - no extra install).
Format stored in DB:  scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64>
Parameters are stored with each hash, so they can be raised later and old
hashes are transparently upgraded on next login (needs_rehash).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import secrets

N, R, P, DKLEN = 2 ** 15, 8, 1, 32          # ~32 MB memory per hash
_MAXMEM = 64 * 1024 * 1024

COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "password1", "111111",
    "iloveyou", "admin", "welcome", "letmein", "monkey", "dragon", "football", "pakistan",
    "qwerty123", "1q2w3e4r", "passw0rd", "superman", "zaq12wsx", "asdfghjkl", "trustno1",
}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(secret.encode(), salt=salt, n=N, r=R, p=P, dklen=DKLEN, maxmem=_MAXMEM)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(dk)}"


def verify_secret(secret: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(secret.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r),
                              p=int(p), dklen=len(base64.b64decode(dk)), maxmem=_MAXMEM)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str) -> bool:
    try:
        _, n, r, p, *_ = stored.split("$")
        return (int(n), int(r), int(p)) != (N, R, P)
    except ValueError:
        return True


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def strength(password: str, username: str | None = None) -> dict:
    """Score 0-4 + entropy estimate + human feedback. Used by the signup form meter."""
    feedback: list[str] = []
    pool = 0
    checks = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    pool += 26 if checks["lower"] else 0
    pool += 26 if checks["upper"] else 0
    pool += 10 if checks["digit"] else 0
    pool += 33 if checks["symbol"] else 0
    entropy = round(len(password) * math.log2(pool), 1) if pool else 0.0

    low = password.lower()
    if low in COMMON or re.sub(r"\d+$", "", low) in COMMON:
        entropy = min(entropy, 10)
        feedback.append("This is one of the most common passwords.")
    if username and username.lower() in low:
        entropy = min(entropy, 20)
        feedback.append("Don't include your username.")
    if re.search(r"(.)\1{2,}", password):
        entropy -= 10
        feedback.append("Avoid repeated characters (aaa, 111).")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)", low):
        entropy -= 10
        feedback.append("Avoid keyboard or number sequences.")
    if len(password) < 8:
        feedback.append("Use at least 8 characters (12+ is better).")
    missing = [k for k, v in checks.items() if not v]
    if missing:
        feedback.append("Add " + ", ".join(missing) + " characters.")

    entropy = max(entropy, 0)
    score = 0 if entropy < 28 else 1 if entropy < 40 else 2 if entropy < 60 else 3 if entropy < 80 else 4
    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    return {"score": score, "label": labels[score], "entropy_bits": entropy,
            "checks": checks, "length": len(password), "feedback": feedback}


def validate_policy(password: str, username: str | None = None) -> None:
    """Minimum policy for account passwords. Raises ValueError with a readable message."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if len(password) > 256:
        raise ValueError("Password is too long (max 256).")
    s = strength(password, username)
    if s["score"] < 2:
        raise ValueError("Password is too weak: " + (" ".join(s["feedback"]) or s["label"]))


def new_recovery_code() -> str:
    raw = secrets.token_hex(5).upper()          # 10 hex chars -> XXXXX-XXXXX
    return f"{raw[:5]}-{raw[5:]}"
