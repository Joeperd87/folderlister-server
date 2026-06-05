# server/trial_store.py — Trial tracking backed by SQLite (via db.py)
# Drop-in replacement for the JSON-file version.

from __future__ import annotations
import hmac, hashlib, os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

from . import db

SECRET = os.getenv("LICENSE_HMAC_SECRET", "CHANGE_ME_DEV_SECRET").encode("utf-8")

# Legacy compat
BASE_DIR = Path(__file__).resolve().parent
TRIAL_FILE = Path(os.getenv("TRIAL_JSON_PATH") or (BASE_DIR / "data" / "trials.json"))


def _hmac(s: str) -> str:
    return "HMAC256:" + hmac.new(SECRET, s.encode("utf-8"), hashlib.sha256).hexdigest()


def _normalize_email(email: str | None) -> str:
    if not email:
        return ""
    s = email.strip().lower()
    if not s or "@" not in s:
        return s

    local, domain = s.split("@", 1)

    if domain.endswith(".gmail.com"):
        domain = "gmail.com"
    if domain == "googlemail.com":
        domain = "gmail.com"

    if domain == "gmail.com":
        if "+" in local:
            local = local.split("+", 1)[0]
        local = local.replace(".", "")

    if domain in ("outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.co.uk"):
        if "+" in local:
            local = local.split("+", 1)[0]

    return f"{local}@{domain}"


def already_had_trial(email: str | None, device_id: str | None, ebay_user: str | None) -> bool:
    em_norm = _normalize_email(email) if email else ""
    checks = []
    if em_norm:
        checks.append(("email", _hmac(em_norm)))
    if device_id:
        checks.append(("device", _hmac(device_id.strip())))
    if ebay_user:
        checks.append(("ebay", _hmac(ebay_user.strip().lower())))

    for hash_type, hash_value in checks:
        if db.trial_check(hash_type, hash_value):
            return True
    return False


def record_trial(email: str | None, device_id: str | None, ebay_user: str | None, license_fingerprint: str) -> None:
    em_norm = _normalize_email(email) if email else ""
    if em_norm:
        db.trial_record("email", _hmac(em_norm), license_fingerprint)
    if device_id:
        db.trial_record("device", _hmac(device_id.strip()), license_fingerprint)
    if ebay_user:
        db.trial_record("ebay", _hmac(ebay_user.strip().lower()), license_fingerprint)
