# server/license_store.py — License management backed by SQLite (via db.py)
# Drop-in replacement for the JSON-file version.
# All public functions maintain the same signatures and return shapes.

from __future__ import annotations
import hmac, hashlib, os, json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from . import db

SECRET = os.getenv("LICENSE_HMAC_SECRET", "CHANGE_ME_DEV_SECRET").encode("utf-8")

# Legacy compat: some code imports FILE from license_store
BASE_DIR = Path(__file__).resolve().parent
FILE = Path(os.getenv("LICENSE_JSON_PATH") or (BASE_DIR / "data" / "licenses.json"))


# ─────────────────────────────────────────────────────────────────────────────
# HASHING
# ─────────────────────────────────────────────────────────────────────────────

def _hmac_key(plain: str) -> str:
    digest = hmac.new(SECRET, plain.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"HMAC256:{digest}"


def fingerprint(plain: str) -> str:
    return _hmac_key(plain)[8:18]


# ─────────────────────────────────────────────────────────────────────────────
# DATE PARSING
# ─────────────────────────────────────────────────────────────────────────────

def _parse_expires_at(v):
    if v in (None, "", False):
        return None
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        except Exception:
            return None
    s = str(v).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s.replace(" ", "T"))
    except Exception:
        try:
            dt = datetime.strptime(s, "%Y-%m-%d")
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _row_to_rec(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a database row to the legacy record format expected by app.py."""
    if not row:
        return {}
    rec = {
        "plan": row.get("plan", "launch"),
        "status": row.get("status", "active"),
        "expires_at": row.get("expires_at"),
        "created_at": row.get("created_at"),
        "last_seen_at": row.get("last_seen_at"),
        "max_accounts": int(row.get("max_accounts") or 1),
        "owner_email": row.get("owner_email"),
        "owner_name": row.get("owner_name"),
        "notes": row.get("notes"),
    }

    # Merge meta blob back into the record
    meta = row.get("meta")
    if meta:
        try:
            meta_dict = json.loads(meta) if isinstance(meta, str) else meta
            rec.update(meta_dict)
        except Exception:
            pass

    # Build allowed_ebay_users and allowed_identity_ids from ebay_accounts table
    license_id = row.get("id")
    if license_id:
        accounts = db.ebay_accounts_for_license(license_id)
        ebay_users = [a["ebay_user"] for a in accounts if a.get("ebay_user") and not a["ebay_user"].startswith("_identity_")]
        identity_ids = [a["identity_id"] for a in accounts if a.get("identity_id")]
        identity_usernames = {}
        for a in accounts:
            if a.get("identity_id") and a.get("ebay_user") and not a["ebay_user"].startswith("_identity_"):
                identity_usernames[a["identity_id"]] = a["ebay_user"]

        if ebay_users:
            rec["allowed_ebay_users"] = ebay_users
        if identity_ids:
            rec["allowed_identity_ids"] = identity_ids
        if identity_usernames:
            rec["identity_usernames"] = identity_usernames

    # Remove None values
    rec = {k: v for k, v in rec.items() if v is not None}
    return rec


def _license_id_for_hash(key_hash: str) -> Optional[int]:
    """Get the database id for a license key hash."""
    row = db.license_find(key_hash)
    return row["id"] if row else None


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API (same signatures as the old JSON version)
# ─────────────────────────────────────────────────────────────────────────────

def find_license(plain_key: str) -> Optional[Dict[str, Any]]:
    if not plain_key:
        return None
    row = db.license_find(_hmac_key(plain_key))
    return _row_to_rec(row) if row else None


def is_valid(rec: dict | None) -> bool:
    if not rec:
        return False
    exp = _parse_expires_at(rec.get("expires_at"))
    if not exp:
        return False
    return exp > datetime.now(timezone.utc)


def upsert_license_plain(plain_key: str, plan: str, expires_at_iso_utc: str, status: str = "active", **extra):
    key_hash = _hmac_key(plain_key)
    existing = db.license_find(key_hash)

    # Preserve existing values for fields not explicitly provided
    if existing:
        defaults = {
            "owner_email": existing.get("owner_email"),
            "owner_name": existing.get("owner_name"),
            "max_accounts": existing.get("max_accounts"),
            "notes": existing.get("notes"),
            "created_at": existing.get("created_at"),
            "last_seen_at": existing.get("last_seen_at"),
        }
        for k, v in defaults.items():
            extra.setdefault(k, v)

    # Extract known fields, put the rest in meta
    known = {"owner_email", "owner_name", "max_accounts", "notes", "created_at",
             "last_seen_at", "allowed_ebay_users", "allowed_identity_ids"}
    meta_fields = {k: v for k, v in extra.items() if k not in known and v is not None}

    db.license_upsert(
        key_hash,
        plan=plan,
        expires_at=expires_at_iso_utc,
        status=status,
        owner_email=extra.get("owner_email"),
        owner_name=extra.get("owner_name"),
        max_accounts=int(extra.get("max_accounts") or 1),
        notes=extra.get("notes"),
        created_at=extra.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        last_seen_at=extra.get("last_seen_at"),
        meta=json.dumps(meta_fields) if meta_fields else "{}",
    )


def update_license_meta(plain_key: str, meta: dict) -> dict:
    key_hash = _hmac_key(plain_key)
    row = db.license_find(key_hash)
    if not row:
        raise ValueError("License not found")

    # For simple top-level fields, update directly
    direct_fields = {"last_seen_at", "status", "plan", "owner_email", "owner_name", "notes", "max_accounts"}
    direct_updates = {k: v for k, v in meta.items() if k in direct_fields}
    meta_updates = {k: v for k, v in meta.items() if k not in direct_fields}

    if direct_updates:
        conn = db.get_conn()
        set_clause = ", ".join(f"{k}=?" for k in direct_updates)
        conn.execute(f"UPDATE licenses SET {set_clause} WHERE key_hash=?",
                     (*direct_updates.values(), key_hash))
        conn.commit()

    if meta_updates:
        db.license_update_meta(key_hash, meta_updates)

    return _row_to_rec(db.license_find(key_hash))


def find_active_license_by_email(email: str, exclude_key_hash: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return the active license row owned by ``email``, if any.

    Used on repeat/upgrade purchases so the customer's existing license can
    be upgraded in place instead of a parallel one being minted alongside
    it (which left customers with two active licenses under one email —
    only one of them actually bound to their eBay store). Prefers a license
    that already has an eBay account attached (i.e. one actually in use)
    over a more recently created but unbound one.
    """
    norm = (email or "").strip().lower()
    if not norm:
        return None

    candidates = []
    for row in db.license_list(limit=10000):
        if (row.get("owner_email") or "").strip().lower() != norm:
            continue
        if (row.get("status") or "").lower() != "active":
            continue
        if exclude_key_hash and row.get("key_hash") == exclude_key_hash:
            continue
        candidates.append(row)

    if not candidates:
        return None

    for row in candidates:
        if db.ebay_accounts_for_license(row.get("id")):
            return row

    # db.license_list() orders most-recent-first, so this is the newest
    # active license for this email if none of them are bound yet.
    return candidates[0]


def attach_ebay_user(plain_key: str, ebay_user: str, max_accounts_default: int = 1) -> dict:
    key_hash = _hmac_key(plain_key)
    row = db.license_find(key_hash)
    if not row:
        raise ValueError("License not found")
    if row.get("status") != "active":
        raise ValueError("License not active")

    license_id = row["id"]
    plan = (row.get("plan") or "").lower()
    norm_user = (ebay_user or "").strip().lower()

    # Check if this eBay user is already bound to another license
    if norm_user:
        existing = db.ebay_account_find_by_user(norm_user)
        if existing and existing.get("license_id") != license_id:
            other_status = (existing.get("status") or "active").lower()
            other_plan = (existing.get("plan") or "").lower()
            if plan == "launch":
                if other_plan == "launch" and other_status in ("active", "revoked", "revoked_migrated"):
                    raise ValueError("This eBay account is already bound to another license")
            else:
                if other_status == "active":
                    raise ValueError("This eBay account is already bound to another license")

    # Check account slots
    current_accounts = db.ebay_accounts_for_license(license_id)
    slots = int(row.get("max_accounts") or max_accounts_default or 1)
    existing_users = [a["ebay_user"] for a in current_accounts]
    if ebay_user not in existing_users and len(existing_users) >= slots:
        raise ValueError("Max accounts reached")

    db.ebay_account_attach(license_id, ebay_user)

    # Update meta
    db.license_update_meta(key_hash, {"last_bound_username": ebay_user})

    return _row_to_rec(db.license_find(key_hash))


def attach_identity_id(plain_key: str, identity_id: str, username: Optional[str] = None,
                       max_accounts_default: int = 1) -> dict:
    key_hash = _hmac_key(plain_key)
    row = db.license_find(key_hash)
    if not row:
        raise ValueError("License not found")
    if row.get("status") != "active":
        raise ValueError("License not active")

    license_id = row["id"]
    plan = (row.get("plan") or "").lower()
    ident = (identity_id or "").strip()
    norm_user = (username or "").strip().lower() if username else None

    # Check if identity or username is already bound elsewhere
    if ident:
        existing = db.ebay_account_find_by_identity(ident)
        if existing and existing.get("license_id") != license_id:
            other_status = (existing.get("status") or "active").lower()
            other_plan = (existing.get("plan") or "").lower()
            if plan == "launch":
                if other_plan == "launch" and other_status in ("active", "revoked", "revoked_migrated"):
                    raise ValueError("This eBay account is already bound to another license")
            else:
                if other_status == "active":
                    raise ValueError("This eBay account is already bound to another license")

    if norm_user:
        existing = db.ebay_account_find_by_user(norm_user)
        if existing and existing.get("license_id") != license_id:
            other_status = (existing.get("status") or "active").lower()
            if other_status == "active":
                raise ValueError("This eBay account is already bound to another license")

    # Check account slots
    current_accounts = db.ebay_accounts_for_license(license_id)
    slots = int(row.get("max_accounts") or max_accounts_default or 1)
    existing_identities = [a["identity_id"] for a in current_accounts if a.get("identity_id")]
    if ident not in existing_identities and len(current_accounts) >= slots:
        raise ValueError("Max accounts reached")

    # Attach with username as ebay_user
    ebay_user = username or f"_identity_{ident[:12]}"
    db.ebay_account_attach(license_id, ebay_user, identity_id=ident)

    # Update meta
    meta_update = {"last_bound_identity": ident}
    if username:
        meta_update["last_bound_username"] = username
    db.license_update_meta(key_hash, meta_update)

    return _row_to_rec(db.license_find(key_hash))


def detach_ebay_user(plain_key: str, ebay_user: str) -> dict:
    key_hash = _hmac_key(plain_key)
    row = db.license_find(key_hash)
    if not row:
        raise ValueError("License not found")
    db.ebay_account_detach(row["id"], ebay_user)
    return _row_to_rec(db.license_find(key_hash))


def detach_identity_id(plain_key: str, identity_id: str) -> dict:
    key_hash = _hmac_key(plain_key)
    row = db.license_find(key_hash)
    if not row:
        raise ValueError("License not found")

    # Find account by identity_id and remove it
    conn = db.get_conn()
    conn.execute(
        "DELETE FROM ebay_accounts WHERE license_id=? AND identity_id=?",
        (row["id"], identity_id),
    )
    conn.commit()

    return _row_to_rec(db.license_find(key_hash))


def set_max_accounts(plain_key: str, new_max: int) -> dict:
    if not isinstance(new_max, int) or new_max < 1:
        raise ValueError("max_accounts must be >= 1")
    key_hash = _hmac_key(plain_key)
    row = db.license_find(key_hash)
    if not row:
        raise ValueError("License not found")
    conn = db.get_conn()
    conn.execute("UPDATE licenses SET max_accounts=? WHERE key_hash=?", (new_max, key_hash))
    conn.commit()
    return _row_to_rec(db.license_find(key_hash))
