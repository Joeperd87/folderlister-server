#!/usr/bin/env python3
"""
migrate_json_to_db.py — One-time migration from JSON files to SQLite database.

Run on the server ONCE before switching app.py to use db.py:
    cd /srv/joepi
    .venv/bin/python -m server.migrate_json_to_db

Safe to run multiple times — uses INSERT OR IGNORE / ON CONFLICT DO NOTHING
so existing rows are never overwritten.
"""

from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

# Ensure server package is importable
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR.parent))

from server.db import get_conn, init_db, _now_iso

DATA_DIR = BASE_DIR / "data"


def _load_json(filename: str) -> dict:
    """Load a JSON file from the data directory. Returns {} on failure."""
    path = DATA_DIR / filename
    if not path.exists():
        print(f"  SKIP {filename} (not found)")
        return {}
    try:
        text = path.read_text("utf-8").strip()
        return json.loads(text) if text else {}
    except Exception as e:
        print(f"  ERROR loading {filename}: {e}")
        return {}


def _load_jsonl(filename: str) -> list:
    """Load a JSONL file from the data directory. Returns [] on failure."""
    path = DATA_DIR / filename
    if not path.exists():
        print(f"  SKIP {filename} (not found)")
        return []
    lines = []
    try:
        for line in path.read_text("utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except Exception:
                    pass
    except Exception as e:
        print(f"  ERROR loading {filename}: {e}")
    return lines


def migrate_licenses():
    """Migrate licenses.json → licenses + ebay_accounts tables."""
    print("\n--- Migrating licenses ---")
    data = _load_json("licenses.json")
    if not data:
        return

    conn = get_conn()
    count_lic = 0
    count_acct = 0

    for key_hash, rec in data.items():
        if not isinstance(rec, dict):
            continue

        # Build meta blob for extra fields
        known_fields = {"plan", "expires_at", "status", "created_at", "last_seen_at",
                        "max_accounts", "owner_email", "owner_name", "notes",
                        "allowed_ebay_users", "allowed_identity_ids", "identity_usernames",
                        "last_bound_username", "last_bound_identity"}
        meta = {k: v for k, v in rec.items() if k not in known_fields and v is not None}

        try:
            conn.execute(
                """INSERT OR IGNORE INTO licenses
                   (key_hash, plan, status, owner_email, owner_name, max_accounts, notes, created_at, expires_at, last_seen_at, meta)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    key_hash,
                    rec.get("plan", "launch"),
                    rec.get("status", "active"),
                    rec.get("owner_email"),
                    rec.get("owner_name"),
                    int(rec.get("max_accounts") or 1),
                    rec.get("notes"),
                    rec.get("created_at"),
                    rec.get("expires_at"),
                    rec.get("last_seen_at"),
                    json.dumps(meta) if meta else "{}",
                ),
            )
            count_lic += 1
        except Exception as e:
            print(f"  ERROR license {key_hash[:20]}...: {e}")
            continue

        # Get the license id for linking eBay accounts
        row = conn.execute("SELECT id FROM licenses WHERE key_hash=?", (key_hash,)).fetchone()
        if not row:
            continue
        license_id = row[0]

        # Migrate allowed_ebay_users
        for user in (rec.get("allowed_ebay_users") or []):
            if user:
                try:
                    # Check identity_usernames for matching identity_id
                    identity_id = None
                    for iid, uname in (rec.get("identity_usernames") or {}).items():
                        if uname and uname.lower() == user.lower():
                            identity_id = iid
                            break
                    conn.execute(
                        """INSERT OR IGNORE INTO ebay_accounts (license_id, ebay_user, identity_id, linked_at)
                           VALUES (?, ?, ?, ?)""",
                        (license_id, user, identity_id, rec.get("created_at")),
                    )
                    count_acct += 1
                except Exception as e:
                    print(f"  ERROR ebay account {user}: {e}")

        # Migrate allowed_identity_ids (not already linked via username)
        for iid in (rec.get("allowed_identity_ids") or []):
            username = (rec.get("identity_usernames") or {}).get(iid)
            if iid and not username:
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO ebay_accounts (license_id, ebay_user, identity_id, linked_at)
                           VALUES (?, ?, ?, ?)""",
                        (license_id, f"_identity_{iid[:12]}", iid, rec.get("created_at")),
                    )
                    count_acct += 1
                except Exception:
                    pass

    conn.commit()
    print(f"  Migrated {count_lic} licenses, {count_acct} eBay accounts")


def migrate_tokens():
    """Migrate tokens.json → tokens table."""
    print("\n--- Migrating tokens ---")
    data = _load_json("tokens.json")
    if not data:
        return

    conn = get_conn()
    count = 0

    # tokens.json has various structures — flatten all context keys
    for context, val in data.items():
        if not isinstance(val, dict):
            # Top-level simple values (like "user" key pointing to a username string)
            continue

        # Check if this is a token object (has access_token) or a nested container
        if "access_token" in val:
            try:
                extra = {k: v for k, v in val.items()
                         if k not in ("access_token", "refresh_token", "expires_at", "token_type")}
                conn.execute(
                    """INSERT OR IGNORE INTO tokens (context, token_type, access_token, refresh_token, expires_at, extra, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        context,
                        val.get("token_type"),
                        val.get("access_token"),
                        val.get("refresh_token"),
                        val.get("expires_at"),
                        json.dumps(extra) if extra else "{}",
                        _now_iso(),
                    ),
                )
                count += 1
            except Exception as e:
                print(f"  ERROR token {context}: {e}")
        else:
            # Nested: iterate sub-keys
            for sub_key, sub_val in val.items():
                if isinstance(sub_val, dict) and "access_token" in sub_val:
                    full_context = f"{context}_{sub_key}"
                    try:
                        extra = {k: v for k, v in sub_val.items()
                                 if k not in ("access_token", "refresh_token", "expires_at", "token_type")}
                        conn.execute(
                            """INSERT OR IGNORE INTO tokens (context, token_type, access_token, refresh_token, expires_at, extra, updated_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?)""",
                            (
                                full_context,
                                sub_val.get("token_type"),
                                sub_val.get("access_token"),
                                sub_val.get("refresh_token"),
                                sub_val.get("expires_at"),
                                json.dumps(extra) if extra else "{}",
                                _now_iso(),
                            ),
                        )
                        count += 1
                    except Exception as e:
                        print(f"  ERROR token {full_context}: {e}")

    conn.commit()
    print(f"  Migrated {count} tokens")


def migrate_eps_usage():
    """Migrate eps_usage.json → eps_usage table."""
    print("\n--- Migrating EPS usage ---")
    data = _load_json("eps_usage.json")
    if not data:
        return

    conn = get_conn()
    count = 0
    totals = data.get("total_by_fp") or {}

    for fp, row in (data.get("by_fp") or {}).items():
        if not isinstance(row, dict):
            continue
        month = row.get("date", "")
        cnt = int(row.get("count") or 0)
        total = int(totals.get(fp) or 0)
        try:
            conn.execute(
                """INSERT OR IGNORE INTO eps_usage (fingerprint, month, count, total)
                   VALUES (?, ?, ?, ?)""",
                (fp, month, cnt, total),
            )
            count += 1
        except Exception as e:
            print(f"  ERROR eps {fp}: {e}")

    conn.commit()
    print(f"  Migrated {count} EPS usage entries")


def migrate_verify_codes():
    """Migrate verify_codes.json → verify_codes table."""
    print("\n--- Migrating verify codes ---")
    data = _load_json("verify_codes.json")
    if not data:
        return

    conn = get_conn()
    count = 0

    for email, rec in data.items():
        if not isinstance(rec, dict):
            continue
        try:
            expires = float(rec.get("expires_at") or 0)
            if expires < time.time():
                continue  # skip expired codes
            conn.execute(
                "INSERT OR IGNORE INTO verify_codes (email, code, expires_at, attempts) VALUES (?, ?, ?, ?)",
                (email, rec.get("code", ""), expires, int(rec.get("attempts") or 0)),
            )
            count += 1
        except Exception as e:
            print(f"  ERROR verify {email}: {e}")

    conn.commit()
    print(f"  Migrated {count} verify codes")


def migrate_ip_bans():
    """Migrate ip_bans.json → ip_bans table."""
    print("\n--- Migrating IP bans ---")
    data = _load_json("ip_bans.json")
    if not data:
        return

    conn = get_conn()
    count = 0

    # ip_bans.json structure varies — handle both list and dict formats
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                ip = entry.get("ip", "")
                reason = entry.get("reason", "")
            elif isinstance(entry, str):
                ip, reason = entry, ""
            else:
                continue
            if ip:
                conn.execute("INSERT OR IGNORE INTO ip_bans (ip, reason, banned_at) VALUES (?, ?, ?)",
                             (ip, reason, _now_iso()))
                count += 1
    elif isinstance(data, dict):
        for ip, info in data.items():
            reason = info.get("reason", "") if isinstance(info, dict) else str(info)
            conn.execute("INSERT OR IGNORE INTO ip_bans (ip, reason, banned_at) VALUES (?, ?, ?)",
                         (ip, reason, _now_iso()))
            count += 1

    conn.commit()
    print(f"  Migrated {count} IP bans")


def migrate_trials():
    """Migrate trials.json → trials table."""
    print("\n--- Migrating trials ---")
    path = DATA_DIR / "trials.json"
    if not path.exists():
        print("  SKIP trials.json (not found)")
        return

    data = _load_json("trials.json")
    conn = get_conn()
    count = 0

    for hash_type in ("emails", "devices", "ebay"):
        db_type = hash_type.rstrip("s")  # emails→email, devices→device, ebay→ebay
        if db_type == "eba":
            db_type = "ebay"
        for hash_val, info in (data.get(hash_type) or {}).items():
            first_seen = info.get("first_seen", "") if isinstance(info, dict) else ""
            license_fp = info.get("license_fp", "") if isinstance(info, dict) else ""
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO trials (hash_type, hash_value, license_fp, first_seen) VALUES (?, ?, ?, ?)",
                    (db_type, hash_val, license_fp, first_seen),
                )
                count += 1
            except Exception:
                pass

    conn.commit()
    print(f"  Migrated {count} trial records")


def migrate_rate_limits():
    """Migrate scanner_rl.json + voice_demo_rl.json → rate_limits table."""
    print("\n--- Migrating rate limits ---")
    conn = get_conn()
    count = 0

    for filename, endpoint in [("scanner_rl.json", "scanner"), ("voice_demo_rl.json", "voice_demo")]:
        data = _load_json(filename)
        for ip_hash, timestamps in data.items():
            if not isinstance(timestamps, list):
                continue
            for ts in timestamps:
                try:
                    conn.execute(
                        "INSERT INTO rate_limits (ip_hash, endpoint, used_at) VALUES (?, ?, ?)",
                        (ip_hash, endpoint, float(ts)),
                    )
                    count += 1
                except Exception:
                    pass

    conn.commit()
    print(f"  Migrated {count} rate limit entries")


def migrate_logs():
    """Migrate ip_log.jsonl + scanner_log.jsonl → request_log table."""
    print("\n--- Migrating logs ---")
    conn = get_conn()
    count = 0

    for filename, log_type in [("ip_log.jsonl", "ip"), ("scanner_log.jsonl", "scanner")]:
        entries = _load_jsonl(filename)
        for entry in entries:
            ts = float(entry.get("ts") or entry.get("timestamp") or 0)
            ip_hash = entry.get("ip_hash") or entry.get("ip") or ""
            try:
                conn.execute(
                    "INSERT INTO request_log (ts, log_type, ip_hash, endpoint, meta) VALUES (?, ?, ?, ?, ?)",
                    (ts, log_type, ip_hash, entry.get("endpoint") or entry.get("path", ""),
                     json.dumps(entry)),
                )
                count += 1
            except Exception:
                pass

    conn.commit()
    print(f"  Migrated {count} log entries")


def migrate_email_templates():
    """Migrate email_templates.json → email_templates table."""
    print("\n--- Migrating email templates ---")
    data = _load_json("email_templates.json")
    if not data:
        return

    conn = get_conn()
    count = 0

    for name, tpl in data.items():
        if isinstance(tpl, dict):
            subject = tpl.get("subject", "")
            body = tpl.get("body", "")
        elif isinstance(tpl, str):
            subject, body = "", tpl
        else:
            continue
        try:
            conn.execute(
                """INSERT OR IGNORE INTO email_templates (name, subject, body, updated_at)
                   VALUES (?, ?, ?, ?)""",
                (name, subject, body, _now_iso()),
            )
            count += 1
        except Exception as e:
            print(f"  ERROR template {name}: {e}")

    conn.commit()
    print(f"  Migrated {count} email templates")


def migrate_oauth_state():
    """Migrate oauth_state.json → oauth_state table."""
    print("\n--- Migrating OAuth state ---")
    # oauth_state.json might be at BASE_DIR or DATA_DIR
    for path in [BASE_DIR / "oauth_state.json", DATA_DIR / "oauth_state.json"]:
        if path.exists():
            try:
                data = json.loads(path.read_text("utf-8").strip() or "{}")
            except Exception:
                data = {}
            if data:
                conn = get_conn()
                count = 0
                for nonce, val in data.items():
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO oauth_state (nonce, data, created_at) VALUES (?, ?, ?)",
                            (nonce, json.dumps(val) if isinstance(val, dict) else str(val), time.time()),
                        )
                        count += 1
                    except Exception:
                        pass
                conn.commit()
                print(f"  Migrated {count} OAuth state entries from {path.name}")
                return
    print("  SKIP oauth_state.json (not found)")


def main():
    print("=" * 60)
    print("Folder Lister — JSON to SQLite Migration")
    print("=" * 60)
    print(f"Database: {get_conn().execute('PRAGMA database_list').fetchone()[2]}")

    # Initialize schema
    init_db()
    print("Schema initialized (WAL mode, all tables created)")

    # Run all migrations
    migrate_licenses()
    migrate_tokens()
    migrate_eps_usage()
    migrate_verify_codes()
    migrate_ip_bans()
    migrate_trials()
    migrate_rate_limits()
    migrate_logs()
    migrate_email_templates()
    migrate_oauth_state()

    # Summary
    conn = get_conn()
    print("\n" + "=" * 60)
    print("Migration complete. Table counts:")
    for table in ["licenses", "ebay_accounts", "tokens", "eps_usage", "verify_codes",
                   "trials", "rate_limits", "request_log", "ip_bans", "drafts",
                   "email_templates", "oauth_state"]:
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  {table:25s} {count:>6d} rows")

    db_size = Path(conn.execute("PRAGMA database_list").fetchone()[2]).stat().st_size
    print(f"\nDatabase size: {db_size / 1024:.1f} KB")
    print("Done. JSON files are untouched — you can remove them after verifying.")


if __name__ == "__main__":
    main()
