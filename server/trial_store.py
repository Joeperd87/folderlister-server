from __future__ import annotations
from pathlib import Path
import os, json, hmac, hashlib
from datetime import datetime, timezone
from typing import Dict, Any

BASE_DIR = Path(__file__).resolve().parent
TRIAL_FILE = Path(os.getenv("TRIAL_JSON_PATH") or (BASE_DIR / "data" / "trials.json"))
SECRET = os.getenv("LICENSE_HMAC_SECRET", "CHANGE_ME_DEV_SECRET").encode("utf-8")

def _hmac(s: str) -> str:
    return "HMAC256:" + hmac.new(SECRET, s.encode("utf-8"), hashlib.sha256).hexdigest()

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _load() -> Dict[str, Any]:
    if TRIAL_FILE.exists():
        try:
            return json.loads(TRIAL_FILE.read_text("utf-8") or "{}")
        except Exception:
            return {}
    return {}

def _save(data: Dict[str, Any]) -> None:
    TRIAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = TRIAL_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(TRIAL_FILE)

def already_had_trial(email: str | None, device_id: str | None, ebay_user: str | None) -> bool:
    data = _load()
    e = _hmac(email.strip().lower()) if email else None
    d = _hmac(device_id.strip()) if device_id else None
    u = _hmac(ebay_user.strip().lower()) if ebay_user else None
    for key, val in [("emails", e), ("devices", d), ("ebay", u)]:
        if val and val in data.get(key, {}):
            return True
    return False

def record_trial(email: str | None, device_id: str | None, ebay_user: str | None, license_fingerprint: str) -> None:
    data = _load()
    e = _hmac(email.strip().lower()) if email else None
    d = _hmac(device_id.strip()) if device_id else None
    u = _hmac(ebay_user.strip().lower()) if ebay_user else None
    now = _now_iso()
    if e: data.setdefault("emails", {})[e] = {"first_seen": now, "license_fp": license_fingerprint}
    if d: data.setdefault("devices", {})[d] = {"first_seen": now, "license_fp": license_fingerprint}
    if u: data.setdefault("ebay", {})[u] = {"first_seen": now, "license_fp": license_fingerprint}
    _save(data)
