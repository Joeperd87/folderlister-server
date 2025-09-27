from __future__ import annotations
from pathlib import Path
import time, json, hmac, hashlib, os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

BASE_DIR = Path(__file__).resolve().parent
FILE = Path(os.getenv("LICENSE_JSON_PATH") or (BASE_DIR / "data" / "licenses.json"))
SECRET = os.getenv("LICENSE_HMAC_SECRET", "CHANGE_ME_DEV_SECRET").encode("utf-8")
_CACHE_TTL = float(os.getenv("LICENSE_CACHE_TTL", "10"))

_cache: Dict[str, Any] = {}
_cache_mtime: float = 0.0
_cache_loaded_at: float = 0.0

def _hmac_key(plain: str) -> str:
    digest = hmac.new(SECRET, plain.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"HMAC256:{digest}"

def fingerprint(plain: str) -> str:
    return _hmac_key(plain)[8:18]

def _load_if_stale():
    global _cache, _cache_mtime, _cache_loaded_at
    try:
        mtime = FILE.stat().st_mtime
    except FileNotFoundError:
        _cache, _cache_mtime = {}, 0.0
        return
    now = time.time()
    if (now - _cache_loaded_at) > _CACHE_TTL or mtime != _cache_mtime:
        _cache = json.loads(FILE.read_text("utf-8") or "{}")
        _cache_mtime = mtime
        _cache_loaded_at = now

def _save_all(data: Dict[str, Any]) -> None:
    tmp = FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(FILE)
    # cache meteen verversen
    global _cache, _cache_mtime, _cache_loaded_at
    _cache = data
    _cache_mtime = FILE.stat().st_mtime
    _cache_loaded_at = time.time()

def find_license(plain_key: str) -> Optional[Dict[str, Any]]:
    if not plain_key:
        return None
    _load_if_stale()
    return _cache.get(_hmac_key(plain_key))

def is_valid(rec: Dict[str, Any]) -> bool:
    if not rec or rec.get("status") != "active":
        return False
    exp_s = rec.get("expires_at")
    if not exp_s:
        return False
    try:
        if exp_s.endswith("Z"):
            exp = datetime.fromisoformat(exp_s.replace("Z", "+00:00"))
        else:
            exp = datetime.fromisoformat(exp_s)
    except Exception:
        return False
    return exp > datetime.now(timezone.utc)

def upsert_license_plain(plain_key: str, plan: str, expires_at_iso_utc: str, status: str = "active", **extra):
    FILE.parent.mkdir(parents=True, exist_ok=True)
    data: Dict[str, Any] = {}
    if FILE.exists():
        txt = FILE.read_text("utf-8").strip()
        if txt:
            data = json.loads(txt)
    h = _hmac_key(plain_key)

    existing = data.get(h) or {}

    # behoud lijsten indien niet expliciet meegegeven (en bewaar lege lijsten als [])
    allowed_ebay_users = extra.get("allowed_ebay_users", existing.get("allowed_ebay_users", None))
    allowed_identity_ids = extra.get("allowed_identity_ids", existing.get("allowed_identity_ids", None))

    rec: Dict[str, Any] = {
        "plan": plan,
        "expires_at": expires_at_iso_utc,
        "status": status,
        "created_at": extra.get("created_at", existing.get("created_at")),
        "last_seen_at": extra.get("last_seen_at", existing.get("last_seen_at")),
        "max_accounts": int(extra.get("max_accounts", existing.get("max_accounts") or 1)),
        "owner_email": extra.get("owner_email", existing.get("owner_email")),
        "owner_name": extra.get("owner_name", existing.get("owner_name")),
        "notes": extra.get("notes", existing.get("notes")),
    }
    if allowed_ebay_users is not None:
        rec["allowed_ebay_users"] = list(allowed_ebay_users)
    if allowed_identity_ids is not None:
        rec["allowed_identity_ids"] = list(allowed_identity_ids)

    # None’s eruit (maar NIET voor lijsten – die hebben we al conditioneel gezet)
    rec = {k: v for k, v in rec.items() if v is not None}

    data[h] = rec
    _save_all(data)

# --- detach helpers ---

def detach_ebay_user(plain_key: str, ebay_user: str) -> dict:
    data: Dict[str, Any] = {}
    if FILE.exists():
        txt = FILE.read_text("utf-8").strip()
        if txt:
            data = json.loads(txt)

    h = _hmac_key(plain_key)
    rec = data.get(h)
    if not rec:
        raise ValueError("License not found")

    users: List[str] = rec.get("allowed_ebay_users") or []
    rec["allowed_ebay_users"] = [u for u in users if u != ebay_user]
    data[h] = rec
    _save_all(data)
    return rec

def detach_identity_id(plain_key: str, identity_id: str) -> dict:
    data: Dict[str, Any] = {}
    if FILE.exists():
        txt = FILE.read_text("utf-8").strip()
        if txt:
            data = json.loads(txt)

    h = _hmac_key(plain_key)
    rec = data.get(h)
    if not rec:
        raise ValueError("License not found")

    ids: List[str] = rec.get("allowed_identity_ids") or []
    rec["allowed_identity_ids"] = [i for i in ids if i != identity_id]
    data[h] = rec
    _save_all(data)
    return rec

def set_max_accounts(plain_key: str, new_max: int) -> dict:
    if not isinstance(new_max, int) or new_max < 1:
        raise ValueError("max_accounts must be >= 1")

    data: Dict[str, Any] = {}
    if FILE.exists():
        txt = FILE.read_text("utf-8").strip()
        if txt:
            data = json.loads(txt)

    h = _hmac_key(plain_key)
    rec = data.get(h)
    if not rec:
        raise ValueError("License not found")

    rec["max_accounts"] = int(new_max)
    data[h] = rec
    _save_all(data)
    return rec

# --- attach helpers ---

def attach_ebay_user(plain_key: str, ebay_user: str, max_accounts_default: int = 1) -> dict:
    data: Dict[str, Any] = {}
    if FILE.exists():
        txt = FILE.read_text("utf-8").strip()
        if txt:
            data = json.loads(txt)
    h = _hmac_key(plain_key)
    rec = data.get(h)
    if not rec:
        raise ValueError("License not found")
    if rec.get("status") != "active":
        raise ValueError("License not active")
    slots = int(rec.get("max_accounts") or max_accounts_default or 1)
    lst: List[str] = rec.get("allowed_ebay_users") or []
    if ebay_user not in lst:
        if len(lst) >= slots:
            raise ValueError("Max accounts reached")
        lst.append(ebay_user)
        rec["allowed_ebay_users"] = lst
    data[h] = rec
    _save_all(data)
    return rec

def attach_identity_id(plain_key: str, identity_id: str, username: Optional[str] = None, max_accounts_default: int = 1) -> dict:
    data: Dict[str, Any] = {}
    if FILE.exists():
        txt = FILE.read_text("utf-8").strip()
        if txt:
            data = json.loads(txt)
    h = _hmac_key(plain_key)
    rec = data.get(h)
    if not rec:
        raise ValueError("License not found")
    if rec.get("status") != "active":
        raise ValueError("License not active")

    slots = int(rec.get("max_accounts") or max_accounts_default or 1)

    # Gebruik uitsluitend de identity-lijst als ‘bron van waarheid’
    ids: List[str] = rec.get("allowed_identity_ids") or []
    if identity_id not in ids:
        if len(ids) >= slots:
            raise ValueError("Max accounts reached")
        ids.append(identity_id)
        rec["allowed_identity_ids"] = ids

    # BELANGRIJK: geen username meer bijschrijven → voorkomt dubbele slot-telling
    # (allowed_ebay_users laten we ongemoeid; gating gebruikt ids als die bestaan)

    data[h] = rec
    _save_all(data)
    return rec

