# server/eps_limits.py — EPS upload tracking backed by SQLite (via db.py)
# Drop-in replacement for the JSON-file version.

from __future__ import annotations
import json, os
from datetime import datetime, timezone, date
from typing import Any, Dict, List
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from . import db

# Legacy compat
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
FILE = Path(os.getenv("EPS_USAGE_JSON_PATH") or (DATA_DIR / "eps_usage.json"))


def _current_month_key() -> str:
    tzname = os.getenv("JOEP_USAGE_TZ", "UTC")
    try:
        if ZoneInfo:
            today = datetime.now(ZoneInfo(tzname)).date()
        else:
            today = datetime.now(timezone.utc).date()
    except Exception:
        today = datetime.now(timezone.utc).date()
    return today.replace(day=1).isoformat()


def next_reset_date() -> str:
    tzname = os.getenv("JOEP_USAGE_TZ", "UTC")
    try:
        if ZoneInfo:
            today = datetime.now(ZoneInfo(tzname)).date()
        else:
            today = datetime.now(timezone.utc).date()
    except Exception:
        today = datetime.now(timezone.utc).date()
    if today.month == 12:
        nxt = date(today.year + 1, 1, 1)
    else:
        nxt = date(today.year, today.month + 1, 1)
    return nxt.isoformat()


def _parse_iso(dt: str | None):
    if not dt:
        return None
    try:
        return datetime.fromisoformat(dt.replace("Z", "+00:00"))
    except Exception:
        return None


def plan_is_paid_required(plan: str) -> bool:
    p = (plan or "").lower()
    return p not in ("launch", "trial")


def trial_active(rec: dict) -> bool:
    dt = _parse_iso(rec.get("trial_until_iso_utc") or rec.get("trial_until"))
    return bool(dt and dt > datetime.now(timezone.utc))


def paid_active(rec: dict) -> bool:
    dt = _parse_iso(rec.get("paid_until_iso_utc") or rec.get("paid_until"))
    return bool(dt and dt > datetime.now(timezone.utc))


def assert_can_eps_upload(rec: dict, limit_for_today: int, used_today: int):
    plan = (rec.get("plan") or "").lower()
    if plan == "trial":
        if not trial_active(rec):
            raise PermissionError("trial_expired")
    elif plan_is_paid_required(plan):
        if not paid_active(rec):
            raise PermissionError("subscription_inactive")
    if used_today >= limit_for_today:
        raise PermissionError("daily_quota_exceeded")


def plan_max_accounts() -> dict:
    raw = os.getenv("JOEP_PLAN_MAX_ACCOUNTS_JSON") or ""
    try:
        m = json.loads(raw) if raw else {}
    except Exception:
        m = {}
    if not m:
        m = {"trial": 1, "basic": 1, "pro": 2, "extreme": 5}
    return {(k or "").lower(): v for k, v in m.items()}


def get_usage(fp: str) -> Dict[str, Any]:
    """Get current month usage for a fingerprint."""
    month = _current_month_key()
    row = db.eps_get(fp, month)
    return {"date": month, "count": row.get("count", 0)}


def increment(fp: str, n: int = 1) -> Dict[str, Any]:
    """Atomically increment EPS usage. Returns updated row."""
    month = _current_month_key()
    row = db.eps_increment(fp, month, n)
    return {"date": month, "count": row.get("count", 0)}


def reset(fp: str) -> Dict[str, Any]:
    """Reset monthly EPS count."""
    month = _current_month_key()
    db.eps_reset(fp, month)
    return {"date": month, "count": 0}


def list_usage(limit: int = 200) -> List[Dict[str, Any]]:
    """List all EPS usage, highest count first."""
    rows = db.eps_list(limit)
    out = []
    for r in rows:
        out.append({
            "fp": r.get("fingerprint", ""),
            "date": r.get("month", ""),
            "count": r.get("count", 0),
            "total": r.get("total", 0),
        })
    return out


def plan_limits() -> dict:
    raw = os.getenv("JOEP_PLAN_LIMITS_JSON") or ""
    try:
        env_map = json.loads(raw) if raw else {}
    except Exception:
        env_map = {}
    defaults = {"launch": 75, "trial": 30, "basic": 75, "pro": 150, "extreme": 500}
    return {**defaults, **{(k or "").lower(): v for k, v in (env_map or {}).items()}}


def get_limit_for_record(rec: dict | None):
    if not rec:
        return None
    if "eps_daily_limit" in rec and rec["eps_daily_limit"] is not None:
        try:
            return int(rec["eps_daily_limit"])
        except Exception:
            return rec["eps_daily_limit"]
    plan = (rec.get("plan") or "").strip().lower()
    return plan_limits().get(plan, None)
