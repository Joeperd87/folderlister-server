# server/db.py — SQLite database layer for multi-user Folder Lister server
# Replaces all JSON file-based storage with atomic, concurrent-safe database operations.
#
# Design:
#   - SQLite in WAL mode (concurrent reads, serialized writes)
#   - Single connection per thread via threading.local()
#   - All writes use transactions (atomic)
#   - busy_timeout prevents "database is locked" under load
#   - Schema versioned via user_version pragma for future migrations

from __future__ import annotations
import sqlite3
import threading
import os
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("JOEP_DB_PATH") or (BASE_DIR / "data" / "joepienator.db"))

SCHEMA_VERSION = 1

_local = threading.local()


# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    """Get a thread-local SQLite connection with WAL mode and busy timeout."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")       # wait up to 15s for locks
    conn.execute("PRAGMA synchronous=NORMAL")        # safe with WAL, faster than FULL
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA cache_size=-8000")           # 8MB cache
    conn.row_factory = sqlite3.Row
    _local.conn = conn
    return conn


def close_conn():
    """Close the thread-local connection (call on thread shutdown)."""
    conn = getattr(_local, "conn", None)
    if conn:
        try:
            conn.close()
        except Exception:
            pass
        _local.conn = None


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """

-- Licenses: one row per license key
CREATE TABLE IF NOT EXISTS licenses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash        TEXT    UNIQUE NOT NULL,     -- HMAC256:... hash of the plain key
    plan            TEXT    DEFAULT 'launch',
    status          TEXT    DEFAULT 'active',
    owner_email     TEXT,
    owner_name      TEXT,
    max_accounts    INTEGER DEFAULT 1,
    notes           TEXT,
    created_at      TEXT,
    expires_at      TEXT,
    last_seen_at    TEXT,
    meta            TEXT    DEFAULT '{}'          -- JSON blob for flexible/future fields
);

-- eBay accounts linked to a license
CREATE TABLE IF NOT EXISTS ebay_accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id      INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    ebay_user       TEXT    NOT NULL,
    identity_id     TEXT,
    linked_at       TEXT,
    UNIQUE(license_id, ebay_user)
);
CREATE INDEX IF NOT EXISTS idx_ebay_accounts_user ON ebay_accounts(ebay_user);
CREATE INDEX IF NOT EXISTS idx_ebay_accounts_identity ON ebay_accounts(identity_id);

-- OAuth tokens (app tokens + per-user tokens)
CREATE TABLE IF NOT EXISTS tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    context         TEXT    UNIQUE NOT NULL,     -- 'app_PROD', 'user_PROD_username', etc.
    token_type      TEXT,
    access_token    TEXT,
    refresh_token   TEXT,
    expires_at      INTEGER,                     -- unix timestamp
    extra           TEXT    DEFAULT '{}',         -- JSON blob for additional token fields
    updated_at      TEXT
);

-- EPS upload usage tracking (monthly per fingerprint)
CREATE TABLE IF NOT EXISTS eps_usage (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint     TEXT    NOT NULL,
    month           TEXT    NOT NULL,             -- '2026-04-01' (first of month)
    count           INTEGER DEFAULT 0,
    total           INTEGER DEFAULT 0,            -- all-time total
    UNIQUE(fingerprint, month)
);

-- Email verification codes
CREATE TABLE IF NOT EXISTS verify_codes (
    email           TEXT    PRIMARY KEY,
    code            TEXT    NOT NULL,
    expires_at      REAL    NOT NULL,             -- unix timestamp
    attempts        INTEGER DEFAULT 0,
    created_at      TEXT
);

-- Trial tracking (hashed email/device/ebay user)
CREATE TABLE IF NOT EXISTS trials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_type       TEXT    NOT NULL,             -- 'email', 'device', 'ebay'
    hash_value      TEXT    NOT NULL,
    license_fp      TEXT,
    first_seen      TEXT,
    UNIQUE(hash_type, hash_value)
);

-- Rate limiting (scanner, voice demo, etc.)
CREATE TABLE IF NOT EXISTS rate_limits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_hash         TEXT    NOT NULL,
    endpoint        TEXT    NOT NULL,             -- 'scanner', 'voice_demo'
    used_at         REAL    NOT NULL              -- unix timestamp
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup ON rate_limits(ip_hash, endpoint, used_at);

-- Request/event logging (replaces all JSONL files)
CREATE TABLE IF NOT EXISTS request_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    log_type        TEXT    NOT NULL,             -- 'ip', 'scanner', 'email', 'eps'
    ip_hash         TEXT,
    license_fp      TEXT,
    endpoint        TEXT,
    meta            TEXT    DEFAULT '{}'          -- JSON blob
);
CREATE INDEX IF NOT EXISTS idx_request_log_type_ts ON request_log(log_type, ts);
CREATE INDEX IF NOT EXISTS idx_request_log_ip ON request_log(ip_hash, ts);

-- IP bans
CREATE TABLE IF NOT EXISTS ip_bans (
    ip              TEXT    PRIMARY KEY,
    reason          TEXT,
    banned_at       TEXT
);

-- User drafts (per license, per bucket)
CREATE TABLE IF NOT EXISTS drafts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id      INTEGER REFERENCES licenses(id) ON DELETE CASCADE,
    bucket          TEXT    NOT NULL,
    name            TEXT,
    data            TEXT    NOT NULL,             -- JSON blob
    created_at      TEXT,
    updated_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_drafts_license_bucket ON drafts(license_id, bucket);

-- Email templates
CREATE TABLE IF NOT EXISTS email_templates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    UNIQUE NOT NULL,
    subject         TEXT,
    body            TEXT,
    updated_at      TEXT
);

-- OAuth state nonces (short-lived)
CREATE TABLE IF NOT EXISTS oauth_state (
    nonce           TEXT    PRIMARY KEY,
    data            TEXT    NOT NULL,             -- JSON blob
    created_at      REAL   NOT NULL              -- unix timestamp, for cleanup
);

"""


def init_db():
    """Create all tables if they don't exist. Safe to call multiple times."""
    conn = get_conn()
    conn.executescript(_SCHEMA_SQL)
    current_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if current_version < SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_ts() -> float:
    return time.time()


# ─────────────────────────────────────────────────────────────────────────────
# LICENSES
# ─────────────────────────────────────────────────────────────────────────────

def license_upsert(key_hash: str, **fields) -> Dict[str, Any]:
    """Insert or update a license. Returns the full license row as dict."""
    conn = get_conn()
    existing = conn.execute("SELECT * FROM licenses WHERE key_hash=?", (key_hash,)).fetchone()

    if existing:
        updates = {k: v for k, v in fields.items() if v is not None}
        if updates:
            set_clause = ", ".join(f"{k}=?" for k in updates)
            conn.execute(
                f"UPDATE licenses SET {set_clause} WHERE key_hash=?",
                (*updates.values(), key_hash),
            )
            conn.commit()
    else:
        fields["key_hash"] = key_hash
        fields.setdefault("created_at", _now_iso())
        cols = ", ".join(fields.keys())
        placeholders = ", ".join("?" for _ in fields)
        conn.execute(f"INSERT INTO licenses ({cols}) VALUES ({placeholders})", tuple(fields.values()))
        conn.commit()

    row = conn.execute("SELECT * FROM licenses WHERE key_hash=?", (key_hash,)).fetchone()
    return dict(row) if row else {}


def license_find(key_hash: str) -> Optional[Dict[str, Any]]:
    """Find a license by its HMAC hash. Returns dict or None."""
    row = get_conn().execute("SELECT * FROM licenses WHERE key_hash=?", (key_hash,)).fetchone()
    return dict(row) if row else None


def license_update_meta(key_hash: str, meta: dict) -> Dict[str, Any]:
    """Merge meta fields into the license's meta JSON blob."""
    conn = get_conn()
    row = conn.execute("SELECT meta FROM licenses WHERE key_hash=?", (key_hash,)).fetchone()
    if not row:
        raise ValueError("License not found")
    existing_meta = json.loads(row["meta"] or "{}")
    existing_meta.update(meta)
    conn.execute(
        "UPDATE licenses SET meta=? WHERE key_hash=?",
        (json.dumps(existing_meta), key_hash),
    )
    conn.commit()
    return license_find(key_hash) or {}


def license_list(limit: int = 500) -> List[Dict[str, Any]]:
    """List all licenses, most recent first."""
    rows = get_conn().execute(
        "SELECT * FROM licenses ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# EBAY ACCOUNTS
# ─────────────────────────────────────────────────────────────────────────────

def ebay_account_attach(license_id: int, ebay_user: str, identity_id: str = None) -> None:
    """Link an eBay account to a license. Idempotent."""
    conn = get_conn()
    conn.execute(
        """INSERT INTO ebay_accounts (license_id, ebay_user, identity_id, linked_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(license_id, ebay_user) DO UPDATE SET identity_id=COALESCE(excluded.identity_id, identity_id)""",
        (license_id, ebay_user, identity_id, _now_iso()),
    )
    conn.commit()


def ebay_account_detach(license_id: int, ebay_user: str) -> None:
    """Unlink an eBay account from a license."""
    conn = get_conn()
    conn.execute(
        "DELETE FROM ebay_accounts WHERE license_id=? AND ebay_user=?",
        (license_id, ebay_user),
    )
    conn.commit()


def ebay_accounts_for_license(license_id: int) -> List[Dict[str, Any]]:
    """Get all eBay accounts linked to a license."""
    rows = get_conn().execute(
        "SELECT * FROM ebay_accounts WHERE license_id=?", (license_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def ebay_account_find_by_user(ebay_user: str) -> Optional[Dict[str, Any]]:
    """Find which license an eBay user is attached to."""
    row = get_conn().execute(
        "SELECT ea.*, l.key_hash, l.plan, l.status FROM ebay_accounts ea "
        "JOIN licenses l ON ea.license_id = l.id "
        "WHERE ea.ebay_user=?",
        (ebay_user,),
    ).fetchone()
    return dict(row) if row else None


def ebay_account_find_by_identity(identity_id: str) -> Optional[Dict[str, Any]]:
    """Find which license an identity_id is attached to."""
    row = get_conn().execute(
        "SELECT ea.*, l.key_hash, l.plan, l.status FROM ebay_accounts ea "
        "JOIN licenses l ON ea.license_id = l.id "
        "WHERE ea.identity_id=?",
        (identity_id,),
    ).fetchone()
    return dict(row) if row else None


# ─────────────────────────────────────────────────────────────────────────────
# TOKENS
# ─────────────────────────────────────────────────────────────────────────────

def token_get(context: str) -> Optional[Dict[str, Any]]:
    """Get a token by context key."""
    row = get_conn().execute("SELECT * FROM tokens WHERE context=?", (context,)).fetchone()
    return dict(row) if row else None


def token_upsert(context: str, **fields) -> None:
    """Insert or update a token."""
    conn = get_conn()
    fields["context"] = context
    fields["updated_at"] = _now_iso()
    conn.execute(
        """INSERT INTO tokens (context, token_type, access_token, refresh_token, expires_at, extra, updated_at)
           VALUES (:context, :token_type, :access_token, :refresh_token, :expires_at, :extra, :updated_at)
           ON CONFLICT(context) DO UPDATE SET
             token_type=COALESCE(excluded.token_type, token_type),
             access_token=COALESCE(excluded.access_token, access_token),
             refresh_token=COALESCE(excluded.refresh_token, refresh_token),
             expires_at=COALESCE(excluded.expires_at, expires_at),
             extra=COALESCE(excluded.extra, extra),
             updated_at=excluded.updated_at""",
        {
            "context": context,
            "token_type": fields.get("token_type"),
            "access_token": fields.get("access_token"),
            "refresh_token": fields.get("refresh_token"),
            "expires_at": fields.get("expires_at"),
            "extra": json.dumps(fields.get("extra", {})) if isinstance(fields.get("extra"), dict) else fields.get("extra"),
            "updated_at": fields["updated_at"],
        },
    )
    conn.commit()


def token_delete(context: str) -> None:
    """Delete a token."""
    conn = get_conn()
    conn.execute("DELETE FROM tokens WHERE context=?", (context,))
    conn.commit()


def token_list() -> List[Dict[str, Any]]:
    """List all tokens."""
    rows = get_conn().execute("SELECT * FROM tokens").fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# EPS USAGE
# ─────────────────────────────────────────────────────────────────────────────

def eps_get(fingerprint: str, month: str) -> Dict[str, Any]:
    """Get EPS usage for a fingerprint in a given month."""
    row = get_conn().execute(
        "SELECT * FROM eps_usage WHERE fingerprint=? AND month=?",
        (fingerprint, month),
    ).fetchone()
    if row:
        return dict(row)
    return {"fingerprint": fingerprint, "month": month, "count": 0, "total": 0}


def eps_increment(fingerprint: str, month: str, n: int = 1) -> Dict[str, Any]:
    """Atomically increment EPS usage. Returns updated row."""
    conn = get_conn()
    conn.execute(
        """INSERT INTO eps_usage (fingerprint, month, count, total)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(fingerprint, month) DO UPDATE SET
             count = count + excluded.count,
             total = total + excluded.total""",
        (fingerprint, month, n, n),
    )
    conn.commit()
    return eps_get(fingerprint, month)


def eps_reset(fingerprint: str, month: str) -> None:
    """Reset monthly EPS count (not total)."""
    conn = get_conn()
    conn.execute(
        "UPDATE eps_usage SET count=0 WHERE fingerprint=? AND month=?",
        (fingerprint, month),
    )
    conn.commit()


def eps_list(limit: int = 200) -> List[Dict[str, Any]]:
    """List all EPS usage, highest count first."""
    rows = get_conn().execute(
        "SELECT * FROM eps_usage ORDER BY count DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# VERIFY CODES
# ─────────────────────────────────────────────────────────────────────────────

def verify_code_set(email: str, code: str, ttl_seconds: int = 600) -> None:
    """Store a verification code with expiry."""
    conn = get_conn()
    conn.execute(
        """INSERT INTO verify_codes (email, code, expires_at, attempts, created_at)
           VALUES (?, ?, ?, 0, ?)
           ON CONFLICT(email) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at, attempts=0""",
        (email, code, _now_ts() + ttl_seconds, _now_iso()),
    )
    conn.commit()


def verify_code_check(email: str, code: str) -> bool:
    """Check a verification code. Returns True if valid. Increments attempts."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM verify_codes WHERE email=?", (email,)).fetchone()
    if not row:
        return False
    if row["expires_at"] < _now_ts():
        conn.execute("DELETE FROM verify_codes WHERE email=?", (email,))
        conn.commit()
        return False
    conn.execute("UPDATE verify_codes SET attempts=attempts+1 WHERE email=?", (email,))
    conn.commit()
    return row["code"] == code


def verify_code_delete(email: str) -> None:
    """Remove a verification code after successful verification."""
    conn = get_conn()
    conn.execute("DELETE FROM verify_codes WHERE email=?", (email,))
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# TRIALS
# ─────────────────────────────────────────────────────────────────────────────

def trial_check(hash_type: str, hash_value: str) -> bool:
    """Check if a trial exists for this hash."""
    row = get_conn().execute(
        "SELECT 1 FROM trials WHERE hash_type=? AND hash_value=?",
        (hash_type, hash_value),
    ).fetchone()
    return row is not None


def trial_record(hash_type: str, hash_value: str, license_fp: str) -> None:
    """Record a trial usage. Idempotent."""
    conn = get_conn()
    conn.execute(
        """INSERT INTO trials (hash_type, hash_value, license_fp, first_seen)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(hash_type, hash_value) DO NOTHING""",
        (hash_type, hash_value, license_fp, _now_iso()),
    )
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────────────────────────────────────

def rate_limit_check(ip_hash: str, endpoint: str, max_per_day: int, max_per_hour: int = 999) -> Dict[str, Any]:
    """Check and record rate limit. Returns {allowed, count_today, count_hour}."""
    conn = get_conn()
    now = _now_ts()
    cutoff_day = now - 86400
    cutoff_hour = now - 3600

    # Clean old entries (> 48h) to keep table small
    conn.execute(
        "DELETE FROM rate_limits WHERE endpoint=? AND used_at < ?",
        (endpoint, now - 172800),
    )

    count_day = conn.execute(
        "SELECT COUNT(*) FROM rate_limits WHERE ip_hash=? AND endpoint=? AND used_at>?",
        (ip_hash, endpoint, cutoff_day),
    ).fetchone()[0]

    count_hour = conn.execute(
        "SELECT COUNT(*) FROM rate_limits WHERE ip_hash=? AND endpoint=? AND used_at>?",
        (ip_hash, endpoint, cutoff_hour),
    ).fetchone()[0]

    allowed = count_day < max_per_day and count_hour < max_per_hour
    if allowed:
        conn.execute(
            "INSERT INTO rate_limits (ip_hash, endpoint, used_at) VALUES (?, ?, ?)",
            (ip_hash, endpoint, now),
        )

    conn.commit()
    return {"allowed": allowed, "count_today": count_day + (1 if allowed else 0), "count_hour": count_hour + (1 if allowed else 0)}


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def log_event(log_type: str, ip_hash: str = None, license_fp: str = None,
              endpoint: str = None, meta: dict = None) -> None:
    """Append a log entry. Non-blocking, fire-and-forget."""
    conn = get_conn()
    conn.execute(
        "INSERT INTO request_log (ts, log_type, ip_hash, license_fp, endpoint, meta) VALUES (?, ?, ?, ?, ?, ?)",
        (_now_ts(), log_type, ip_hash, license_fp, endpoint, json.dumps(meta or {})),
    )
    conn.commit()


def log_query(log_type: str, limit: int = 200, since_ts: float = None) -> List[Dict[str, Any]]:
    """Query log entries by type."""
    conn = get_conn()
    if since_ts:
        rows = conn.execute(
            "SELECT * FROM request_log WHERE log_type=? AND ts>? ORDER BY ts DESC LIMIT ?",
            (log_type, since_ts, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM request_log WHERE log_type=? ORDER BY ts DESC LIMIT ?",
            (log_type, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def log_cleanup(max_age_days: int = 30) -> int:
    """Remove log entries older than max_age_days. Returns count deleted."""
    conn = get_conn()
    cutoff = _now_ts() - (max_age_days * 86400)
    cur = conn.execute("DELETE FROM request_log WHERE ts < ?", (cutoff,))
    conn.commit()
    return cur.rowcount


# ─────────────────────────────────────────────────────────────────────────────
# IP BANS
# ─────────────────────────────────────────────────────────────────────────────

def ip_ban_check(ip: str) -> bool:
    """Check if an IP is banned."""
    row = get_conn().execute("SELECT 1 FROM ip_bans WHERE ip=?", (ip,)).fetchone()
    return row is not None


def ip_ban_add(ip: str, reason: str = "") -> None:
    """Ban an IP."""
    conn = get_conn()
    conn.execute(
        "INSERT INTO ip_bans (ip, reason, banned_at) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason",
        (ip, reason, _now_iso()),
    )
    conn.commit()


def ip_ban_remove(ip: str) -> None:
    """Unban an IP."""
    conn = get_conn()
    conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,))
    conn.commit()


def ip_ban_list() -> List[Dict[str, Any]]:
    """List all banned IPs."""
    rows = get_conn().execute("SELECT * FROM ip_bans ORDER BY banned_at DESC").fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# DRAFTS
# ─────────────────────────────────────────────────────────────────────────────

def draft_save(bucket: str, name: str, data: dict, license_id: int = None) -> int:
    """Save a draft. Returns the draft id."""
    conn = get_conn()
    now = _now_iso()
    cur = conn.execute(
        "INSERT INTO drafts (license_id, bucket, name, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (license_id, bucket, name, json.dumps(data), now, now),
    )
    conn.commit()
    return cur.lastrowid


def draft_update(draft_id: int, data: dict) -> None:
    """Update an existing draft's data."""
    conn = get_conn()
    conn.execute(
        "UPDATE drafts SET data=?, updated_at=? WHERE id=?",
        (json.dumps(data), _now_iso(), draft_id),
    )
    conn.commit()


def draft_get(draft_id: int) -> Optional[Dict[str, Any]]:
    """Get a single draft by id."""
    row = get_conn().execute("SELECT * FROM drafts WHERE id=?", (draft_id,)).fetchone()
    return dict(row) if row else None


def draft_latest(bucket: str) -> Optional[Dict[str, Any]]:
    """Get the most recent draft for a bucket."""
    row = get_conn().execute(
        "SELECT * FROM drafts WHERE bucket=? ORDER BY updated_at DESC LIMIT 1",
        (bucket,),
    ).fetchone()
    return dict(row) if row else None


def draft_list_by_bucket(bucket: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List drafts for a bucket, most recent first."""
    rows = get_conn().execute(
        "SELECT * FROM drafts WHERE bucket=? ORDER BY updated_at DESC LIMIT ?",
        (bucket, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def draft_delete(draft_id: int) -> None:
    """Delete a draft."""
    conn = get_conn()
    conn.execute("DELETE FROM drafts WHERE id=?", (draft_id,))
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# OAUTH STATE
# ─────────────────────────────────────────────────────────────────────────────

def oauth_state_store(nonce: str, data: dict) -> None:
    """Store an OAuth state nonce."""
    conn = get_conn()
    conn.execute(
        "INSERT INTO oauth_state (nonce, data, created_at) VALUES (?, ?, ?) ON CONFLICT(nonce) DO UPDATE SET data=excluded.data",
        (nonce, json.dumps(data), _now_ts()),
    )
    conn.commit()


def oauth_state_pop(nonce: str) -> Optional[dict]:
    """Retrieve and delete an OAuth state nonce. Returns None if not found or expired."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM oauth_state WHERE nonce=?", (nonce,)).fetchone()
    if not row:
        return None
    conn.execute("DELETE FROM oauth_state WHERE nonce=?", (nonce,))
    # Clean up old nonces (> 1 hour)
    conn.execute("DELETE FROM oauth_state WHERE created_at < ?", (_now_ts() - 3600,))
    conn.commit()
    return json.loads(row["data"])


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

def email_template_get(name: str) -> Optional[Dict[str, Any]]:
    """Get an email template by name."""
    row = get_conn().execute("SELECT * FROM email_templates WHERE name=?", (name,)).fetchone()
    return dict(row) if row else None


def email_template_upsert(name: str, subject: str, body: str) -> None:
    """Insert or update an email template."""
    conn = get_conn()
    conn.execute(
        """INSERT INTO email_templates (name, subject, body, updated_at) VALUES (?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET subject=excluded.subject, body=excluded.body, updated_at=excluded.updated_at""",
        (name, subject, body, _now_iso()),
    )
    conn.commit()


def email_template_list() -> List[Dict[str, Any]]:
    """List all email templates."""
    rows = get_conn().execute("SELECT * FROM email_templates ORDER BY name").fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────────────────────

def startup():
    """Initialize database on server start. Call once."""
    init_db()
