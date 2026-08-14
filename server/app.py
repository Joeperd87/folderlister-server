from __future__ import annotations
import email
import re
import threading
from pathlib import Path
from contextvars import ContextVar

# --- Context: per-license + per-session key ---
CURRENT_CTX: ContextVar[str] = ContextVar("CURRENT_CTX", default="")
LAST_CTX:    ContextVar[str] = ContextVar("LAST_CTX", default="")

def _ctx_from_request(request):
    lk = ((request.headers.get("X-License-Key") or request.cookies.get("license_key"))
          or request.query_params.get("lk") or "").strip()
    sid = (request.headers.get("X-Session-Id")
           or request.cookies.get("sid")
           or request.query_params.get("sid") or "").strip()
    return f"{lk}:{sid}"

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None
ROOT = Path(__file__).resolve().parent.parent
if load_dotenv:
    load_dotenv(ROOT / "server" / ".env", override=True)
from zoneinfo import ZoneInfo 
import base64
import json
import time
from typing import Dict, Any, List, Optional
from urllib.parse import quote, urlparse, parse_qs, unquote
import unicodedata
import xml.etree.ElementTree as ET
from fastapi.staticfiles import StaticFiles
import requests
from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Body, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from pydantic import BaseModel
from datetime import timezone
import secrets
from datetime import datetime, timedelta  # (als 'timedelta' nog niet geïmporteerd is)
from .license_store import FILE as LICENSE_FILE, upsert_license_plain, find_license, attach_identity_id, fingerprint, update_license_meta # je gebruikt deze al elders

from .eps_limits import get_usage, get_limit_for_record, plan_max_accounts, next_reset_date
from fastapi.responses import JSONResponse
import os  # voor JOEP_USAGE_TZ
from .license_store import find_license, is_valid, upsert_license_plain, fingerprint, attach_ebay_user, attach_identity_id, detach_ebay_user, detach_identity_id
from .trial_store import already_had_trial, record_trial

from server.web_editor import router as web_router
from fastapi.responses import RedirectResponse
# bovenin bij de imports (robuste import voor zowel 'python -m server.app' als direct run)
from .admin_panel import router as admin_router
import xml.etree.ElementTree as ET
from pydantic import BaseModel
import random, time, json, hmac, hashlib
try:
    from dotenv import load_dotenv
except Exception:
    pass
# --- Mount web editor router if present ---
web_editor_router = None
try:
    from server.web_editor import router as web_editor_router
except Exception:
    try:
        from web_editor import router as web_editor_router
    except Exception:
        web_editor_router = None

from .stripe_webhook import router as stripe_router
from xml.sax.saxutils import escape
from fastapi import Request, Body
# BOVENIN bij imports:
from pathlib import Path

from datetime import datetime
import os, json
import os, smtplib, ssl, socket
from email.message import EmailMessage
from xml.sax.saxutils import escape as _x
import os, json, datetime as _dt
from fastapi import Request, Header
# deduplicated: placeholder imports removed
from fastapi import Body

_ESC = {'"': '&quot;', "'": '&apos;'}


def _xml_escape(v, extra=None):
    """XML escape helper for text and attribute values."""
    s = "" if v is None else str(v)
    ent = dict(_ESC)
    if extra:
        try:
            ent.update(extra)
        except Exception:
            pass
    return escape(s, ent)

APP = FastAPI(title="Joepienator server (OAuth + Taxonomy + Stores + Web + Publish)")
APP.router.redirect_slashes = True   # ← vang ontbrekende/extra slash af
APP.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app = APP

# Initialize SQLite database on startup
from . import db as _db
@app.on_event("startup")
def _startup_db():
    _db.startup()

try:
    if web_editor_router is not None:
        APP.include_router(web_editor_router)
except Exception:
    pass
# ONDER je andere include_router(..):
@app.middleware("http")
async def _ctx_setter(request, call_next):
    try:
        CURRENT_CTX.set(_ctx_from_request(request))
    except Exception:
        pass
    return await call_next(request)

FUTURE_EXP = os.getenv("FUTURE_EXP_LAUNCH", "2099-12-31T00:00:00Z")

# NA het aanmaken van APP/app en DATA:
app.include_router(web_router, prefix="/web")
# ... na app = FastAPI(...)
app.include_router(admin_router)
# JSON uit .env
app.include_router(stripe_router)  # geen prefix="/api"

JOEP_PLAN_LIMITS: Dict[str,int] = json.loads(os.getenv("JOEP_PLAN_LIMITS_JSON", '{}') or '{}')
JOEP_PLAN_MAX_ACCOUNTS: Dict[str,int] = json.loads(os.getenv("JOEP_PLAN_MAX_ACCOUNTS_JSON", '{}') or '{}')
try:
    JOEP_SWITCH_COOLDOWN_DAYS = int(os.getenv("JOEP_SWITCH_COOLDOWN_DAYS", "21"))
except Exception:
    JOEP_SWITCH_COOLDOWN_DAYS = 21

SEND_MIN_COOLDOWN = int(os.environ.get("JOEP_VERIFY_COOLDOWN_SECONDS", "60"))
MAX_PER_HOUR      = int(os.environ.get("JOEP_VERIFY_MAX_PER_HOUR", "5"))
MAX_PER_DAY       = int(os.environ.get("JOEP_VERIFY_MAX_PER_DAY", "10"))

WEB_PUBLISH_MAX_ROWS = int(os.getenv("WEB_PUBLISH_MAX_ROWS", "50") or "50")
BASE = Path(__file__).parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
_DRAFTS_BASE = BASE / "drafts"
_DRAFTS_BASE.mkdir(exist_ok=True)
_LK_HMAC_SECRET = os.getenv("LICENSE_HMAC_SECRET", "CHANGE_ME_DEV_SECRET").encode("utf-8")
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
STATIC_DIR = BASE / "static"
STATIC_DIR.mkdir(exist_ok=True)
APP.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
VERIFY_FILE = BASE / "data" / "verify_codes.json"
OUTBOX_LOG  = BASE / "data" / "email_outbox.log"

def _prefer(*candidates: Path) -> Path:
    for p in candidates:
        if p.exists():
            return p
    return candidates[-1]


SECRETS_FILE = _prefer(DATA / "secrets.json", BASE / "secrets.json")
TOKENS_FILE  = _prefer(BASE / "tokens.json", DATA / "tokens.json")
STATE_FILE   = _prefer(DATA / "oauth_state.json", BASE / "oauth_state.json")

# Per-bestand locks voor thread-safe read-modify-write
_TOKENS_LOCK = threading.Lock()
_STATE_LOCK  = threading.Lock()
_VC_LOCK     = threading.Lock()

AUTH_HOST = {"PROD": "https://auth.ebay.com", "SANDBOX": "https://auth.sandbox.ebay.com"}
API_HOST  = {"PROD": "https://api.ebay.com", "SANDBOX": "https://api.sandbox.ebay.com"}
IDENTITY_HOST = API_HOST
TRADING_ENDPOINT = {"PROD": "https://api.ebay.com/ws/api.dll", "SANDBOX": "https://api.sandbox.ebay.com/ws/api.dll"}

MARKETPLACE_ID = {
    "UK": "EBAY_GB","GB": "EBAY_GB",
    "NL": "EBAY_NL","US": "EBAY_US","DE": "EBAY_DE","FR":"EBAY_FR","IT":"EBAY_IT",
    "ES":"EBAY_ES","IE":"EBAY_IE","BE":"EBAY_BE","AT":"EBAY_AT","AU":"EBAY_AU",
    "CA":"EBAY_CA","PL":"EBAY_PL","CH":"EBAY_CH",
}
TRADING_SITE_ID = {
    "UK":"3","GB":"3","US":"0","DE":"77","NL":"146","FR":"71","IT":"101",
    "ES":"186","IE":"205","BE":"123","AT":"16","AU":"15","CA":"2","PL":"212","CH":"193",
}

USER_SCOPES = [
    "https://api.ebay.com/oauth/api_scope",  # Trading IAF
    "https://api.ebay.com/oauth/api_scope/sell.account.readonly",
    "https://api.ebay.com/oauth/api_scope/sell.stores.readonly",
    "https://api.ebay.com/oauth/api_scope/commerce.identity.readonly",  # <-- nodig voor /commerce/identity/v1/user
]
USER_SCOPE_STR = " ".join(USER_SCOPES)
APP_SCOPE_STR  = "https://api.ebay.com/oauth/api_scope"

# ---- eBay marketplace → site code mapping
_SITE_FROM_MARKETPLACE = {
    "EBAY_US": "US",
    "EBAY_CA": "CA",
    "EBAY_GB": "UK",
    "EBAY_DE": "DE",
    "EBAY_FR": "FR",
    "EBAY_IT": "IT",
    "EBAY_ES": "ES",
    "EBAY_NL": "NL",
    "EBAY_PL": "PL",
    "EBAY_AU": "AU",
    "EBAY_AT": "AT",
    "EBAY_BE": "BE",
    "EBAY_CH": "CH",
    "EBAY_IE": "IE",
}
BASE_DIR    = Path(__file__).resolve().parent  # gebruik jouw bestaande BASE_DIR als die er al is
DATA_DIR    = BASE_DIR / "data"
OUTBOX_LOG  = DATA_DIR / "email_outbox.log"    # compacte regels (grepfriendly)
OUTBOX_DIR  = DATA_DIR / "email_outbox"        # optioneel: losse "eml"-achtige dumps

from datetime import datetime, timezone, timedelta
from . import license_store as LS  # voor cache refresh zoals in admin_panel


PLAN_PRIORITY = {
    "trial": 10,
    "launch": 20,
    "basic":30,
    "pro": 40,
    "extreme": 50,
}

# net onder DATA/STATIC/… definities
IP_LOG_FILE  = DATA / "ip_log.jsonl"
IP_BANS_FILE = DATA / "ip_bans.json"
SCANNER_LOG_FILE = DATA / "scanner_log.jsonl"
SCANNER_RL_FILE  = DATA / "scanner_rl.json"

# Globale fallback-map voor currency per site
_CUR_MAP = {
    "US": "USD",
    "UK": "GBP",
    "GB": "GBP",
    "NL": "EUR",
    "DE": "EUR",
    "FR": "EUR",
    "IT": "EUR",
    "ES": "EUR",
    "IE": "EUR",
    "AT": "EUR",
    "BE": "EUR",
    "PL": "PLN",
    "CH": "CHF",
    "CA": "CAD",
    "AU": "AUD",
}


def _last_draft_site_currency_for_request(request: Request) -> tuple[Optional[str], Optional[str]]:
    """
    Haal (site, currency) uit de laatst geüploade draft voor deze license_key.
    Now reads from database first, falls back to filesystem.
    """
    lk = (
        request.headers.get("X-License-Key")
        or request.cookies.get("license_key")
        or request.query_params.get("lk")
        or ""
    ).strip()

    if not lk:
        return None, None

    def _bucket_for(raw_lk: str) -> str:
        raw = str(raw_lk or "").strip()
        if not raw:
            return "_anon"
        digest = hmac.new(_LK_HMAC_SECRET, raw.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"lk_{digest[:48]}"

    try:
        # Try database first
        bucket = _bucket_for(lk)
        draft = _db.draft_latest(bucket)
        if draft:
            data = json.loads(draft["data"]) if isinstance(draft["data"], str) else draft["data"]
            site = (data.get("site") or "").strip().upper() or None
            currency = (data.get("currency") or "").strip().upper() or None
            return site, currency
        # No draft found in database
        return None, None
    except Exception:
        return None, None


def _effective_site_and_currency(
    user_site: Optional[str] = None,
    payload_site: Optional[str] = None,
    row_site: Optional[str] = None,
    payload_currency: Optional[str] = None,
) -> tuple[str, str]:
    """
    Voorkeurvolgorde:
    1) row_site  (uit rows_builder: row["site_code"])
    2) payload_site (uit draft: payload["site"])
    3) user_site (uit identity / account)
    4) NL / EUR fallback
    """
    # --- site bepalen ---
    site = (row_site or payload_site or user_site or "NL") or "NL"
    site = str(site).strip().upper()
    if not site:
        site = "NL"

    # --- currency bepalen ---
    currency = _CUR_MAP.get(site, "EUR")

    return site, currency

def _client_ip(request: Request) -> str:
    xf = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xf:
        return xf.split(",")[0].strip()
    return (request.client.host if request.client else "unknown")

def _jsonl_append(path: Path, obj: dict, keep_last: int = 5000):
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        # simpele “poor man’s” truncation om ongebreidelde groei te voorkomen
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > keep_last:
            path.write_text("\n".join(lines[-keep_last:]), encoding="utf-8")
    except Exception:
        pass

@app.middleware("http")
async def ip_ban_and_log(request: Request, call_next):
    ip = _client_ip(request)
    # bans check via database
    try:
        if _db.ip_ban_check(ip):
            return JSONResponse({"detail":"ip_banned"}, status_code=403)
    except Exception:
        pass
    # log via database
    try:
        lk = (request.headers.get("X-License-Key") or request.query_params.get("lk") or "").strip()
        lk_masked = (fingerprint(lk) + "...") if lk else ""
        _db.log_event("ip", ip_hash=lk_masked, endpoint=request.url.path, meta={"ip": ip})
    except Exception:
        pass
    return await call_next(request)

def _iso_now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _parse_iso_utc(s: str | None):
    if not s:
        return None
    try:
        ss = s
        if ss.endswith("Z"):
            ss = ss[:-1] + "+00:00"
        dt = datetime.fromisoformat(ss)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def _licenses_load() -> dict:
    from .license_store import FILE as LICENSE_FILE
    try:
        with open(LICENSE_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _licenses_save_and_refresh(data: dict) -> None:
    """Legacy function — no longer needed with database-backed license_store.
    Kept as a no-op for any remaining call sites during migration."""
    pass  # All license operations now go through db.py via license_store.py

# vervang je _cooldown_info door deze minimale versie
def _cooldown_info(rec: dict) -> dict:
    import datetime as _dt
    days = JOEP_SWITCH_COOLDOWN_DAYS
    last = rec.get("last_switch_at")  # ← alleen echte switch
    out = {"cooldown_days": days, "cooldown_active": False}

    if not last:
        return out

    try:
        last_dt = _dt.datetime.fromisoformat(last.replace("Z", ""))
    except Exception:
        return out

    next_allowed = last_dt + _dt.timedelta(days=days)
    now = _dt.datetime.utcnow()
    if now < next_allowed:
        out["cooldown_active"] = True
        out["next_allowed_at"] = next_allowed.isoformat(timespec="minutes")
    return out


# Plan-limieten uit .env; defaults als fallback
def _plan_limits_from_env() -> dict:
    raw = os.getenv("JOEP_PLAN_LIMITS_JSON", "")
    try:
        m = json.loads(raw) if raw else {}
        return {str(k).lower(): int(m[k]) for k in m}
    except Exception:
        # nette defaults
        return {"launch": 75, "trial": 100, "basic": 75, "pro": 150, "extreme": 500}

def _default_plan() -> str:
    return (os.getenv("JOEP_DEFAULT_PLAN") or "trial").lower()


def _norm_email_for_plan(email: str | None) -> str:
    return (email or "").strip().lower()


def _plan_for_license(lk: str, req: Request, x_plan_hdr: str | None) -> str:
    # 1) expliciet meegegeven
    p = (x_plan_hdr or req.query_params.get("plan") or "").strip().lower()
    if p:
        return p

    # 2) basis-licentie uit store
    lic = None
    try:
        lic = find_license(lk)
    except Exception:
        lic = None

    if isinstance(lic, dict):
        base_plan = (lic.get("plan") or lic.get("tier") or "").strip().lower()
        owner = _norm_email_for_plan(lic.get("owner_email"))
        best_plan = base_plan

        if owner:
            try:
                all_lics = _licenses_load()
                for other in all_lics.values():
                    if not isinstance(other, dict):
                        continue
                    if _norm_email_for_plan(other.get("owner_email")) != owner:
                        continue
                    if not is_valid(other):   # gebruikt license_store.is_valid
                        continue

                    p = (other.get("plan") or other.get("tier") or "").strip().lower()
                    if PLAN_PRIORITY.get(p, 0) > PLAN_PRIORITY.get(best_plan, 0):
                        best_plan = p
            except Exception:
                # als dit faalt, val je gewoon terug op base_plan
                pass

        if best_plan:
            return best_plan

    # 3) fallback
    return _default_plan()

def _next_midnight_iso():
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(os.getenv("JOEP_USAGE_TZ", "UTC"))
        now = _dt.datetime.now(tz)
    except Exception:
        now = _dt.datetime.utcnow()
    mid = (now.replace(hour=0, minute=0, second=0, microsecond=0) + _dt.timedelta(days=1))
    return mid.isoformat(timespec="minutes")


def _license_owner_email(rec: dict | None) -> str:
    if not isinstance(rec, dict):
        return ""
    return _norm_email_for_plan(rec.get("owner_email"))


def _licenses_for_shared_usage(rec: dict | None) -> List[dict]:
    if not isinstance(rec, dict):
        return []
    owner = _license_owner_email(rec)
    if not owner:
        return [rec]
    try:
        rows = [
            other
            for other in _licenses_load().values()
            if isinstance(other, dict) and _license_owner_email(other) == owner
        ]
        return rows or [rec]
    except Exception:
        return [rec]


def _month_counter_value(rec: dict | None, value_field: str, month_field: str, now_month: str) -> int:
    if not isinstance(rec, dict):
        return 0
    if (rec.get(month_field) or "") != now_month:
        return 0
    try:
        return max(0, int(rec.get(value_field) or 0))
    except Exception:
        return 0


def _shared_ai_usage_totals(rec: dict | None, now_month: str) -> tuple[int, int, int]:
    rows = _licenses_for_shared_usage(rec)
    total_used = sum(_month_counter_value(row, "ai_calls_used", "ai_calls_month", now_month) for row in rows)
    images_used = sum(_month_counter_value(row, "ai_images_used", "ai_images_month", now_month) for row in rows)
    voice_used = sum(_month_counter_value(row, "ai_voice_used", "ai_voice_month", now_month) for row in rows)
    return total_used, images_used, voice_used


def _eps_usage_key_for_license(
    lk: str,
    rec: dict | None,
    identity_id: str | None = None,
    username: str | None = None,
) -> str:
    """Usage is keyed by the license fingerprint. One license = one
    quota bucket, regardless of how many eBay accounts are bound.

    Earlier this function returned ``ebayid:<id>`` / ``ebayuser:<x>`` /
    ``owner:<email>`` first, which split the same license's usage over
    multiple rows in eps_usage. Admin reset on the license fingerprint
    then silently missed the actual bucket. Migrated 2026-05-18 to a
    single license-fp key; non-fp rows were consolidated into the
    license-fp row and the prefix-keyed code paths removed.

    The identity_id / username arguments are kept in the signature for
    callers that still pass them, but they are ignored.
    """
    if lk:
        return fingerprint(lk)
    return "anon"

@app.post("/license/rebind_to_current")
def license_rebind_to_current(request: Request):
    return license_switch_to_current(request)



@app.post("/license/switch_to_current")
def license_switch_to_current(request: Request):
    # 1) license key ophalen
    lk = (
        (request.headers.get("X-License-Key") or request.cookies.get("license_key"))
        or request.query_params.get("lk") or ""
    ).strip()
    if not lk:
        raise HTTPException(status_code=400, detail="Missing license key")

    rec = find_license(lk)
    if not rec:
        raise HTTPException(status_code=404, detail="License not found")

    # 2) huidige eBay identity ophalen (moet ingelogd zijn)
    uid, uname, _env = _identity_get_user()
    if not (uid or uname):
        raise HTTPException(status_code=401, detail="Please log in to eBay before re-binding.")

    # 3) alleen toestaan wanneer effectief max_accounts == 1
    max_acc = _effective_max_accounts(rec)  # None = onbeperkt
    slots_used = _slots_used(rec)

    if max_acc is None:
        # Onbeperkt: switch heeft geen betekenis
        raise HTTPException(status_code=400, detail={"error": "rebind_not_applicable", "max_accounts": "unlimited"})

    if slots_used < int(max_acc):
        # Er is nog een vrije plek: switch is niet nodig → laat client gewoon attach doen
        raise HTTPException(
            status_code=409,
            detail={"error": "slot_available_no_switch_needed", "slots_used": slots_used, "max_accounts": int(max_acc)}
        )


    # 4) cooldown bewaken (standaard 21 dagen, aanpasbaar via env)
    try:
        cooldown_days = int(os.getenv("JOEP_SWITCH_COOLDOWN_DAYS", "21"))
    except Exception:
        cooldown_days = 21

    last = rec.get("last_switch_at") or rec.get("bound_at")
    if last:
        try:
            last_dt = _dt.datetime.fromisoformat(last.replace("Z", ""))
            elapsed = (_dt.datetime.utcnow() - last_dt).total_seconds()
            required = cooldown_days * 86400
            if elapsed < required:
                remain = int((required - elapsed) // 86400) + (1 if (required - elapsed) % 86400 else 0)
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "switch_cooldown",
                        "cooldown_days": cooldown_days,
                        "days_remaining": remain
                    },
                )
        except Exception:
            # Bij parse-fout niet “gratis” doorlaten: fallback naar blokkeren met 1 dag
            raise HTTPException(status_code=429, detail={"error": "switch_cooldown"})

    # 5) alle bestaande bindingen verwijderen
    try:
        for i in list(rec.get("allowed_identity_ids") or []):
            try:
                detach_identity_id(lk, i)
            except Exception:
                pass
        for u in list(rec.get("allowed_ebay_users") or []):
            try:
                detach_ebay_user(lk, u)
            except Exception:
                pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rebind cleanup failed: {e}")

    # 6) huidige gebruiker binden (voorkeur: identity-id)
    try:
         if uid:
             attach_identity_id(lk, uid, uname, max_accounts_default=1)
         else:
             attach_ebay_user(lk, uname, max_accounts_default=1)
    except Exception as e:
         raise HTTPException(status_code=500, detail=f"Rebind attach failed: {e}")

# 7) timestamp & counter bijwerken (cooldown werkt vanaf nu)
    nowz = _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    rec2 = find_license(lk) or rec
    rec2["last_switch_at"] = nowz
    rec2["switch_count"] = int(rec2.get("switch_count") or 0) + 1
    # persist via store (idempotent – store schrijft terug bij attach; hier nogmaals opslaan indien aanwezig)
    try:
        update_license_meta(lk, {"last_switch_at": nowz, "switch_count": rec2["switch_count"]})
    except Exception:
        pass
    return rec2

@app.get("/web/eps_limits")
def web_eps_limits(
    request: Request,
    lk: str | None = None,
    fp: str | None = None,
    x_license_key: str | None = Header(default=None, convert_underscores=False),
    x_plan: str | None = Header(default=None, convert_underscores=False),
):
    """
    Geeft dag-quota/gebruik terug voor de batterij:
    - quota: uit JOEP_PLAN_LIMITS_JSON per plan
    - used:  via eps_limits.get_usage(key)  (key = fp of lk)
    - left:  quota - used
    - resets_at: volgende middernacht
    """
    # key resolutie
    lk = lk or x_license_key or ""
    rec = None
    try:
        rec = find_license(lk) if lk else None
    except Exception:
        rec = None
    key = fp or _eps_usage_key_for_license(lk, rec) or (request.client.host if request and request.client else "anon")

    # plan → quota
    limits_map = _plan_limits_from_env()
    plan = _plan_for_license(lk, request, x_plan)
    quota = int(limits_map.get(plan, limits_map.get(_default_plan(), 100)))

    # used ophalen
    used = 0
    try:
        import eps_limits
        u = eps_limits.get_usage(key)  # verwacht {"date":"YYYY-MM-DD","count":N}
        used = int(u.get("count") or 0)
    except Exception:
        pass

    left = max(0, quota - max(0, used))
    return {
        "plan": plan,
        "eps_quota": quota,
        "eps_used": max(0, used),
        "eps_left": left,
        "resets_at": _next_midnight_iso(),
        "key": key,  # handig voor debug; mag weg
    }

def _env_bool(name: str, default: bool=False) -> bool:
    v = os.getenv(name, "1" if default else "0").strip().lower()
    return v not in ("0","false","no","off","")
TRIAL_ENABLED = _env_bool("TRIAL_ENABLE", False)

@app.get("/license/options")
def license_options():
    return {"trial_enabled": TRIAL_ENABLED}


def get_plan_limit(plan: str) -> int:
    return int(JOEP_PLAN_LIMITS.get(plan, JOEP_PLAN_LIMITS.get("launch", 75)))

def get_plan_max_accounts(plan: str) -> int:
    return int(JOEP_PLAN_MAX_ACCOUNTS.get(plan, JOEP_PLAN_MAX_ACCOUNTS.get("launch", 1)))

def normalize_plan(p: str | None) -> str:
    p = (p or "launch").strip().lower()
    # aliases indien je ‘basic’ ooit als label gebruikt voor launch
    ALIASES = {"basic":"launch"}
    return ALIASES.get(p, p)

def _ensure_outbox_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
def _log_send(email: str, code: str, *, subject: str = "Your verification code", body_text: str | None = None):
    _ensure_outbox_dirs()
    event = {
        "ts": int(time.time()),
        "to": email,
        "subject": subject,
        "code": code,
        "body": (body_text if body_text is not None else f"Your code: {code}"),
        "type": "verify_send"
    }
    _db.log_event("email", meta=event)

# -- Site-resolver ------------------------------------------------------------
def _read_cfg() -> dict:
    # zelfde plek als waar web_policies z’n config pakt
    return _read_json(SECRETS_FILE.parent / "config.json")

def _effective_site(site_param: Optional[str]) -> str:
    if site_param and site_param.strip():
        return site_param.strip().upper()
    try:
        _uid, _uname, _env, _reg = _identity_get_user_full()
    except Exception:
        pass
    return "NL"


@app.get("/oauth/start/")
def oauth_start_slash(env: str = "PROD", force_login: bool = Query(False)):
    return oauth_start(env=env, force_login=force_login)

@app.get("/oauth/status/")
def oauth_status_slash():
    return oauth_status()

@app.get("/oauth/clear")
@app.get("/oauth/clear/")
def oauth_clear():
    """Wis het opgeslagen user-token zodat de volgende poll 'not authenticated' ziet.
    Gebruik dit vóór een force-login om te voorkomen dat de oude sessie direct terugkomt."""
    tk = _tokens()
    tk.pop("user", None)
    # verwijder ook context-specifieke user-tokens
    for key in [k for k in tk if k not in ("app_PROD", "app_SANDBOX")]:
        tk.pop(key, None)
    _save_tokens(tk)
    return {"ok": True}

# --- Account helpers: idem ---
@app.get("/account/whoami/")
def account_whoami_slash():
    return account_whoami()

@app.get("/account/site/")
def account_site_slash():
    return account_site()

def _site_from_reg_marketplace(mid: str) -> str:
    if not mid:
        return ""
    return _SITE_FROM_MARKETPLACE.get(mid.strip().upper(), "")

def _normalize_site_code(value: str) -> str:
    """Breng elke site-aanduiding terug tot de code die de rest van de
    module gebruikt ('UK', 'US', 'NL', ...).

    Accepteert een marketplace-id ('EBAY_GB'), de ISO-variant ('GB') of de
    site-code zelf ('UK'). Onbekend => "" zodat de caller z'n eigen
    fallback kan pakken. Zonder dit belandt een ruwe
    registrationMarketplaceId in TRADING_SITE_ID.get(...) en valt die
    stilletjes terug op site-id 0 (US)."""
    v = (value or "").strip().upper()
    if not v:
        return ""
    if v in _SITE_FROM_MARKETPLACE:      # EBAY_GB -> UK
        return _SITE_FROM_MARKETPLACE[v]
    if v == "GB":                        # ISO-code van de UK-site
        return "UK"
    return v if v in TRADING_SITE_ID else ""
# ---------------- util store ----------------
def _read_json(p: Path) -> Dict[str, Any]:
    if not p.exists(): return {}
    try: return json.loads(p.read_text(encoding="utf-8"))
    except Exception: return {}

def _write_json(p: Path, data: Dict[str, Any]) -> None:
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(p)

def _now() -> int: return int(time.time())

def _secrets(env: str) -> Dict[str, Optional[str]]:
    s = _read_json(SECRETS_FILE)
    conf = s.get(env.upper()) or {}
    cid = conf.get("client_id"); csec = conf.get("client_secret"); runame = conf.get("ru_name")
    if not cid or not csec or not runame:
        raise HTTPException(400, f"Server not configured with eBay app credentials for {env}")
    # ensure required fields are strings and normalize optional redirect_url to either str or None
    return {
        "client_id": str(cid),
        "client_secret": str(csec),
        "ru_name": str(runame),
        "redirect_url": (str(conf.get("redirect_url")) if conf.get("redirect_url") is not None else None)
    }

def _tokens() -> Dict[str, Any]:
    """Load all tokens — now backed by database.
    Reconstructs the nested {"user": {...}, "contexts": {...}} format
    expected by _get_user() and _set_user_token_ctx().
    """
    rows = _db.token_list()
    result = {}
    contexts = {}
    for r in rows:
        ctx = r["context"]
        tok = {
            "access_token": r.get("access_token"),
            "refresh_token": r.get("refresh_token"),
            "expires_at": r.get("expires_at"),
            "token_type": r.get("token_type"),
        }
        extra = r.get("extra")
        if extra:
            try:
                tok.update(json.loads(extra) if isinstance(extra, str) else extra)
            except Exception:
                pass
        # Context tokens are stored with "ctx_" prefix in the database
        if ctx.startswith("ctx_"):
            contexts[ctx[4:]] = tok
        else:
            result[ctx] = tok
    if contexts:
        result["contexts"] = contexts
    return result

def _save_tokens(d: Dict[str, Any]) -> None:
    """Save tokens dict — now writes to database per context key.
    Handles both flat tokens (user, app_PROD) and nested contexts dict.
    """
    for ctx, val in d.items():
        if ctx == "contexts" and isinstance(val, dict):
            # Nested context tokens: store each with "ctx_" prefix
            for sub_ctx, sub_val in val.items():
                if isinstance(sub_val, dict) and sub_val.get("access_token"):
                    extra = {k: v for k, v in sub_val.items() if k not in ("access_token", "refresh_token", "expires_at", "token_type")}
                    _db.token_upsert(
                        f"ctx_{sub_ctx}",
                        access_token=sub_val.get("access_token"),
                        refresh_token=sub_val.get("refresh_token"),
                        expires_at=sub_val.get("expires_at"),
                        token_type=sub_val.get("token_type"),
                        extra=extra,
                    )
        elif isinstance(val, dict) and "access_token" in val:
            extra = {k: v for k, v in val.items() if k not in ("access_token", "refresh_token", "expires_at", "token_type")}
            _db.token_upsert(
                ctx,
                access_token=val.get("access_token"),
                refresh_token=val.get("refresh_token"),
                expires_at=val.get("expires_at"),
                token_type=val.get("token_type"),
                extra=extra,
            )
def _basic_header(client_id: str, client_secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

def get_app_token(env: str) -> str:
    env = env.upper(); sec = _secrets(env); key = f"app_{env}"
    # Eerst zonder lock snel checken op cache (alleen lezen)
    with _TOKENS_LOCK:
        tk = _tokens()
        cached = tk.get(key) or {}
        if cached.get("access_token") and cached.get("expires_at", 0) > _now() + 60:
            return cached["access_token"]
    # HTTP call buiten de lock
    url = IDENTITY_HOST[env] + "/identity/v1/oauth2/token"
    hdr = {"Authorization": _basic_header(sec["client_id"], sec["client_secret"]), "Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "client_credentials", "scope": APP_SCOPE_STR}
    r = requests.post(url, headers=hdr, data=data, timeout=30)
    if r.status_code >= 400: raise HTTPException(r.status_code, f"App token failed: {r.text}")
    j = r.json()
    with _TOKENS_LOCK:
        tk = _tokens()
        tk[key] = {"access_token": j["access_token"], "expires_at": _now() + int(j.get("expires_in", 7200))}
        _save_tokens(tk)
    return j["access_token"]

def _set_user_token(env: str, access_token: str, refresh_token: Optional[str], expires_in: int) -> None:
    with _TOKENS_LOCK:
        tk = _tokens()
        tk["user"] = {"env": env.upper(), "access_token": access_token, "refresh_token": refresh_token, "expires_at": _now() + int(expires_in)}
        _save_tokens(tk)

def _set_user_token_ctx(ctx: str, env: str, access_token: str, refresh_token: Optional[str], expires_in: int, ebay_user: str | None = None, site: str | None = None, currency: str | None = None) -> None:
    """
    Context-aware token setter used by the OAuth callback; stores the user token
    in a per-license/per-session slot only.  The global tk["user"] is intentionally
    NOT overwritten here — overwriting it caused cross-user data leakage when
    multiple users were connected (each new login replaced the global fallback).
    """
    try:
        with _TOKENS_LOCK:
            tk = _tokens()
            contexts = tk.get("contexts") or {}
            contexts[str(ctx) or ""] = {
                "env": env.upper(),
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": _now() + int(expires_in),
                "ebay_user": ebay_user,
                "site": site,
                "currency": currency,
                "set_at": _now(),
            }
            tk["contexts"] = contexts
            _save_tokens(tk)
    except Exception:
        pass

    try:
        # update ContextVar markers for current/last context
        try:
            LAST_CTX.set(CURRENT_CTX.get())
        except Exception:
            pass
        try:
            CURRENT_CTX.set(str(ctx) or "")
        except Exception:
            pass
    except Exception:
        pass

def _get_user() -> dict:
    tk = _tokens() or {}
    ctx = (CURRENT_CTX.get() or "").strip()
    if ctx:
        # 1. Exact context match (license_key:session_id)
        c = (tk.get("contexts") or {}).get(ctx) or {}
        if c.get("access_token"):
            return {"env": c.get("env") or "PROD",
                    "access_token": c.get("access_token"),
                    "refresh_token": c.get("refresh_token"),
                    "expires_at": c.get("expires_at", 0)}
        # 2. License-key prefix match — handles session ID mismatches (e.g. client
        #    restarted and got a new session ID but same license key).
        #    This NEVER crosses license keys, so it is safe for multi-user setups.
        lk_only = ctx.split(":")[0].strip()
        if lk_only:
            for _ckey, _cv in (tk.get("contexts") or {}).items():
                if str(_ckey or "").split(":")[0].strip() == lk_only and _cv.get("access_token"):
                    return {"env": _cv.get("env") or "PROD",
                            "access_token": _cv.get("access_token"),
                            "refresh_token": _cv.get("refresh_token"),
                            "expires_at": _cv.get("expires_at", 0)}
    # 3. Global fallback — only reached when there is no license key at all
    #    (single-user / legacy mode).  In multi-user setups this slot is no
    #    longer updated, so returning it here is safe.
    return tk.get("user") or {}


def _need_user(env: Optional[str] = None) -> Dict[str, Any]:
    u = _get_user()
    if not u.get("access_token"):
        # Retry once after short delay — handles multi-worker race after fresh OAuth login
        import time as _t
        _t.sleep(0.5)
        # Force fresh read from database (new connection state)
        u = _get_user()
        if not u.get("access_token"):
            raise HTTPException(401, "Not linked — please log in to eBay first.")
    if env and u.get("env") != env.upper(): raise HTTPException(400, f"Linked in {u.get('env')} but requested {env}")
    return u

def ensure_valid_license_only(request: Request):
    lk = ((request.headers.get("X-License-Key") or request.cookies.get("license_key"))
          or request.query_params.get("lk") or "").strip()
    if not lk:
        raise HTTPException(status_code=401, detail="Valid license required")
    rec = find_license(lk)
    if not (rec and is_valid(rec)):
        raise HTTPException(status_code=401, detail="Valid license required")
    return rec

def _refresh_user_if_needed() -> None:
    tk = _tokens() or {}
    ctx = (CURRENT_CTX.get() or "").strip()

    # Use the same lookup logic as _get_user so we always refresh the right token.
    src = None
    save_key: Optional[str] = None   # contexts key to write the refreshed token back to
    use_global = False

    if ctx:
        # 1. Exact match
        _c = (tk.get("contexts") or {}).get(ctx)
        if _c and _c.get("access_token"):
            src = _c
            save_key = ctx
        else:
            # 2. License-key prefix match
            lk_only = ctx.split(":")[0].strip()
            if lk_only:
                for _ck, _cv in (tk.get("contexts") or {}).items():
                    if str(_ck or "").split(":")[0].strip() == lk_only and _cv.get("access_token"):
                        src = _cv
                        save_key = _ck
                        break

    if src is None:
        # 3. Global fallback (legacy / no-license mode)
        src = tk.get("user") or {}
        use_global = True

    if not src or src.get("expires_at", 0) > _now() + 60:
        return

    sec = _secrets((src.get("env") or "PROD").upper())
    url = IDENTITY_HOST[(src.get("env") or "PROD").upper()] + "/identity/v1/oauth2/token"
    hdr = {"Authorization": _basic_header(sec["client_id"], sec["client_secret"]),
           "Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "refresh_token", "refresh_token": src.get("refresh_token") or ""}
    r = requests.post(url, headers=hdr, data=data, timeout=30)
    r.raise_for_status()
    j = r.json()
    new = dict(src, access_token=j["access_token"],
               refresh_token=j.get("refresh_token", src.get("refresh_token")),
               expires_at=_now() + int(j.get("expires_in", 3600)))
    if use_global:
        tk["user"] = new
    else:
        tk.setdefault("contexts", {})[save_key] = new
    _save_tokens(tk)


# ---------------- OAuth endpoints ----------------
@app.get("/oauth/start")
def oauth_start(request: Request, env: str = "PROD", force_login: bool = Query(False)):
    """
    Start the eBay OAuth flow.

    We embed the license/session context into the `state` parameter so the
    callback can store the user token in a per-license/per-session slot.
    """
    env = env.upper()
    sec = _secrets(env)

    import secrets as pysecrets

    # Random nonce – primary key in STATE_FILE
    nonce = pysecrets.token_urlsafe(24)

    # Try to derive context from request (license_key + optional sid)
    try:
        ctx = (_ctx_from_request(request) or "").strip()
    except Exception:
        ctx = ""

    lk = ""
    sid = ""
    if ctx:
        # ctx is "<license_key>:<sid>" or just "<license_key>"
        if ":" in ctx:
            lk, sid = ctx.split(":", 1)
        else:
            lk = ctx

    # Build state string that round-trips via eBay:
    # "<nonce>|env=PROD|lk=...|sid=..."
    parts = [nonce, f"env={env}"]
    if lk:
        parts.append(f"lk={lk}")
    if sid:
        parts.append(f"sid={sid}")
    state = "|".join(parts)

    # Store minimal info server-side (csrf / expiry) via database
    _db.oauth_state_store(state, {"env": env, "ts": _now(), "lk": lk, "sid": sid})

    auth_url = (
        f"{AUTH_HOST[env]}/oauth2/authorize"
        f"?client_id={quote(sec['client_id'])}"
        f"&response_type=code"
        f"&redirect_uri={quote(sec['ru_name'])}"
        f"&scope={quote(USER_SCOPE_STR)}"
        f"&state={quote(state)}"
    )
    if force_login:
        auth_url += "&prompt=login"

    return {"auth_url": auth_url, "url": auth_url}

@app.get("/oauth/start/")
def oauth_start_alias(request: Request, env: str = "PROD", force_login: bool = Query(False)):
    return oauth_start(request=request, env=env, force_login=force_login)

@app.get("/oauth/status")
def oauth_status():
    u = _get_user()
    if not u:
        return {
            "env": None,
            "connected": False,
            "authenticated": False,   # ← toegevoegd
            "expires_at": None,
            "has_refresh": False,
        }
    return {
        "env": u.get("env"),
        "connected": True,
        "authenticated": True,       # ← toegevoegd
        "expires_at": u.get("expires_at"),
        "has_refresh": bool(u.get("refresh_token")),
    }



@app.post("/oauth/refresh")
def oauth_force_refresh(): _refresh_user_if_needed(); return oauth_status()

def _pop_state(state: Optional[str]) -> Optional[str]:
    if not state: return None
    rec = _db.oauth_state_pop(state) or {}
    return rec.get("env")

@app.get("/oauth/callback")
def oauth_callback(
    request: Request,
    code: str = Query(...),
    state: Optional[str] = None,
    env: str = Query("PROD"),
):
    import json, xml.etree.ElementTree as ET, requests, os

    # -- Parse state: haal sid/lk hieruit (fallback op headers/cookies) --
    def _parse_state(s: Optional[str]) -> dict:
        out = {}
        if s:
            for part in s.split("|"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    out[k] = v
        return out

    st = _parse_state(state)
    sid = (st.get("sid") or request.headers.get("X-Session-Id")
           or request.cookies.get("sid") or "").strip()
    lk  = (st.get("lk") or request.headers.get("X-License-Key")
           or request.cookies.get("license_key") or "").strip()
    ctx = f"{lk}:{sid}" if (lk or sid) else ""

    # Zet de CURRENT_CTX op basis van state; headers zijn in callback vaak leeg
    try:
        if ctx:
            CURRENT_CTX.set(ctx)
    except Exception:
        pass

    env = (st.get("env") or _pop_state(state) or env or "PROD").upper()

    # 1) OAuth token ophalen
    sec = _secrets(env)
    url = IDENTITY_HOST[env] + "/identity/v1/oauth2/token"
    hdr = {
        "Authorization": _basic_header(sec["client_id"], sec["client_secret"]),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": sec["ru_name"]}
    r = requests.post(url, headers=hdr, data=data, timeout=30)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"OAuth error from eBay: {r.text}")

    j = r.json()
    access_token  = j["access_token"]
    refresh_token = j.get("refresh_token")
    expires_in    = int(j.get("expires_in", 3600))

    # 2) GetUser (optioneel; mag falen zonder login te breken)
    user_id = ""
    site_code = ""
    currency = "USD"
    reg_country = ""
    seller_country = ""
    try:
        trading_url = "https://api.ebay.com/ws/api.dll" if env == "PROD" else "https://api.sandbox.ebay.com/ws/api.dll"
        t_hdr = {
            "X-EBAY-API-CALL-NAME": "GetUser",
            "X-EBAY-API-COMPATIBILITY-LEVEL": "1207",
            "X-EBAY-API-SITEID": "0",
            "X-EBAY-API-IAF-TOKEN": access_token,
            "Content-Type": "text/xml",
        }
        t_body = """<?xml version="1.0" encoding="utf-8"?>
<GetUserRequest xmlns="urn:ebay:apis:eBLBaseComponents">
  <DetailLevel>ReturnAll</DetailLevel>
</GetUserRequest>"""
        gr = requests.post(trading_url, headers=t_hdr, data=t_body, timeout=30)
        gr.raise_for_status()
        root = ET.fromstring(gr.text)

        _SITE_MAP = {
            "US":"US","UK":"UK","Germany":"DE","France":"FR","Italy":"IT","Spain":"ES","Ireland":"IE",
            "Austria":"AT","Belgium_Dutch":"BE","Belgium_French":"BE","Netherlands":"NL","Poland":"PL",
            "Switzerland":"CH","Canada":"CA","Australia":"AU"
        }
        _CUR_MAP = {
            "US":"USD","UK":"GBP","DE":"EUR","FR":"EUR","IT":"EUR","ES":"EUR","IE":"EUR","AT":"EUR","BE":"EUR",
            "NL":"EUR","PL":"PLN","CH":"CHF","CA":"CAD","AU":"AUD"
        }
        ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
        user_id = (root.findtext("e:User/e:UserID", namespaces=ns) or "").strip()
        site_raw = (root.findtext("e:User/e:Site", namespaces=ns) or "").strip()
        reg_country = (
            root.findtext("e:User/e:RegistrationAddress/e:Country", namespaces=ns)
            or root.findtext("e:User/e:Country", namespaces=ns) or ""
        ).strip()
        seller_country = (root.findtext("e:User/e:SellerInfo/e:SellerPaymentAddress/e:Country", namespaces=ns) or "").strip()
        site_code = _SITE_MAP.get(site_raw, "US")
        currency  = _CUR_MAP.get(site_code, "USD")
    except Exception:
        pass

    # 3) TOKENS ALTIJD OPSLAAN IN DE JUISTE CONTEXT (VOOR RETURN)
    try:
        _set_user_token_ctx(ctx, env, access_token, refresh_token, expires_in,
                            ebay_user=(user_id or None), site=(site_code or None), currency=(currency or None))
    except Exception:
        try:
            _set_user_token(env, access_token, refresh_token, expires_in)
        except Exception:
            pass

    # 4) Toon een nette pagina in de browser; client pollt /oauth/status voor status
    from fastapi.responses import HTMLResponse
    _html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Login successful — Joepienator</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0F5D70;color:#fff;
     display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#124F61;border-radius:16px;padding:48px 56px;text-align:center;
       box-shadow:0 8px 32px rgba(0,0,0,.35);max-width:400px;width:90%}}
.icon{{font-size:64px;margin-bottom:20px}}
h1{{font-size:22px;font-weight:600;margin-bottom:10px}}
p{{font-size:14px;opacity:.75;line-height:1.6}}
.user{{display:inline-block;margin-top:16px;background:#0F5D70;
       border-radius:8px;padding:6px 16px;font-size:13px;opacity:.9}}
</style></head>
<body><div class="card">
  <div class="icon">&#x2705;</div>
  <h1>Login successful!</h1>
  <p>You are now signed in to eBay.<br>You can close this page now.</p>
  {"<div class='user'>"+user_id+"</div>" if user_id else ""}
</div></body></html>"""
    return HTMLResponse(content=_html)


# ---------- helpers ----------
def _jwt_payload(token: str) -> dict:
    try:
        parts = (token or "").split(".")
        if len(parts) < 2: return {}
        seg = parts[1]; pad = "=" * (-len(seg) % 4); raw = base64.urlsafe_b64decode(seg + pad)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}

@app.get("/oauth/callback/")
def oauth_callback_trailing_slash(request: Request, code: str = Query(...), state: Optional[str] = None, env: str = Query("PROD")):
    return oauth_callback(request=request, code=code, state=state, env=env)

@app.get("/oauth/ebay/callback")
def oauth_callback_ebay_alias(request: Request, code: str = Query(...), state: Optional[str] = None, env: str = Query("PROD")):
    return oauth_callback(request=request, code=code, state=state, env=env)

@app.get("/oauth/ebay/callback/")
def oauth_callback_ebay_alias_slash(request: Request, code: str = Query(...), state: Optional[str] = None, env: str = Query("PROD")):
    return oauth_callback(request=request, code=code, state=state, env=env)

@app.get("/oauth/scopes")
def oauth_scopes():
    _refresh_user_if_needed(); u = _need_user(); payload = _jwt_payload(u.get("access_token") or "")
    scopes = payload.get("scp") or payload.get("scope") or []
    if isinstance(scopes, str): scopes = scopes.split()
    return {"env": u.get("env"), "expires_at": u.get("expires_at"), "jwt_like": bool(payload), "scopes": scopes}

# ---------- Commerce Taxonomy (app token) ----------
def _commerce_get(env: str, path: str, params: Dict[str, Any]) -> requests.Response:
    tok = get_app_token(env); url = API_HOST[env] + path
    hdr = {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
    return requests.get(url, headers=hdr, params=params, timeout=30)

@app.get("/taxonomy/search")
def taxonomy_search(request: Request, q: str = Query(..., min_length=1), site: Optional[str] = Query(None)):
    site, _ = _effective_site_and_currency(site, None)
    site = site.upper(); marketplace = MARKETPLACE_ID.get(site)
    if not marketplace: raise HTTPException(400, f"Unknown site {site}")
    env = (_get_user().get("env") or "PROD")
    r1 = _commerce_get(env, "/commerce/taxonomy/v1/get_default_category_tree_id", {"marketplace_id": marketplace})
    if r1.status_code >= 400: raise HTTPException(r1.status_code, r1.text)
    tree_id = (r1.json() or {}).get("categoryTreeId")
    if not tree_id: raise HTTPException(502, "No categoryTreeId")
    r2 = _commerce_get(env, f"/commerce/taxonomy/v1/category_tree/{tree_id}/get_category_suggestions", {"q": q})
    if r2.status_code >= 400: raise HTTPException(r2.status_code, r2.text)
    out: List[Dict[str, Any]] = []
    for item in (r2.json() or {}).get("categorySuggestions", []):
        cat = item.get("category") or {}; cid = cat.get("categoryId"); name = cat.get("categoryName")
        path = " ".join(filter(None, [p.get("categoryName") for p in item.get("categoryTreeNodeAncestors", [])]))
        if cid and name: out.append({"categoryId": cid, "name": name, "path": path})
    return out


# ── Full category tree (cached on server, max age 7 days) ──────────────────

_CAT_TREE_MAX_AGE = 7 * 24 * 3600  # 7 days in seconds

def _cat_tree_file(site: str) -> Path:
    return DATA / f"category_tree_{site.upper()}.json"

def _load_cached_tree(site: str) -> Optional[List[Dict[str, Any]]]:
    p = _cat_tree_file(site)
    if not p.exists():
        return None
    try:
        age = time.time() - p.stat().st_mtime
        if age > _CAT_TREE_MAX_AGE:
            return None
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _save_cached_tree(site: str, data: List[Dict[str, Any]]) -> None:
    p = _cat_tree_file(site)
    try:
        DATA.mkdir(exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception:
        pass

def _flatten_tree_node(node: Dict[str, Any], path_parts: List[str]) -> List[Dict[str, Any]]:
    """Recursively flatten eBay category tree node into leaf categories."""
    out: List[Dict[str, Any]] = []
    cat = node.get("category") or {}
    cid = str(cat.get("categoryId") or "").strip()
    name = str(cat.get("categoryName") or "").strip()
    children = node.get("childCategoryTreeNodes") or []
    current_path = path_parts + ([name] if name else [])
    if not children and cid and name:
        # Leaf node
        out.append({
            "id": cid,
            "name": name,
            "path": " > ".join(current_path[:-1]),  # path without the leaf name itself
            "full_path": " > ".join(current_path),
            "leaf": True,
        })
    for child in children:
        out.extend(_flatten_tree_node(child, current_path))
    return out

@app.get("/web/category-tree")
def web_category_tree(request: Request, site: str = Query("NL"), force: bool = Query(False)):
    """
    Returns a flat list of all leaf categories for the given eBay site.
    Cached server-side for 7 days. Client should also cache locally.
    Response: [{id, name, path, full_path, leaf}]
    """
    site = (site or "NL").strip().upper()
    marketplace = MARKETPLACE_ID.get(site)
    if not marketplace:
        raise HTTPException(400, f"Unknown site: {site}")

    if not force:
        cached = _load_cached_tree(site)
        if cached is not None:
            return {"site": site, "count": len(cached), "categories": cached, "cached": True}

    env = "PROD"  # category tree uses app token, no user needed
    # Step 1: get tree ID
    r1 = _commerce_get(env, "/commerce/taxonomy/v1/get_default_category_tree_id",
                       {"marketplace_id": marketplace})
    if r1.status_code >= 400:
        raise HTTPException(r1.status_code, f"Could not get tree ID: {r1.text[:200]}")
    tree_id = (r1.json() or {}).get("categoryTreeId")
    if not tree_id:
        raise HTTPException(502, "No categoryTreeId returned by eBay")

    # Step 2: fetch full tree (large response ~1-3 MB)
    r2 = _commerce_get(env, f"/commerce/taxonomy/v1/category_tree/{tree_id}", {})
    if r2.status_code >= 400:
        raise HTTPException(r2.status_code, f"Could not fetch category tree: {r2.text[:200]}")

    raw = r2.json() or {}
    root = raw.get("rootCategoryNode") or {}
    leaves = _flatten_tree_node(root, [])

    _save_cached_tree(site, leaves)
    return {"site": site, "count": len(leaves), "categories": leaves, "cached": False}


@app.get("/taxonomy/aspects")
def taxonomy_aspects(request: Request,
                     site: str = Query("UK"),
                     category_id: str = Query(...)):

    site, _ = _effective_site_and_currency(site, None)
    site = site.upper()
    marketplace = MARKETPLACE_ID.get(site)
    if not marketplace:
        raise HTTPException(400, f"Unknown site {site}")

    env = (_get_user().get("env") or "PROD")

    r1 = _commerce_get(
        env,
        "/commerce/taxonomy/v1/get_default_category_tree_id",
        {"marketplace_id": marketplace},
    )
    if r1.status_code >= 400:
        raise HTTPException(r1.status_code, r1.text)

    tree_id = (r1.json() or {}).get("categoryTreeId")
    if not tree_id:
        raise HTTPException(502, "No categoryTreeId")

    r2 = _commerce_get(
        env,
        f"/commerce/taxonomy/v1/category_tree/{tree_id}/get_item_aspects_for_category",
        {"category_id": category_id},
    )
    if r2.status_code >= 400:
        raise HTTPException(r2.status_code, r2.text)

    return r2.json()


# ---------- Item Condition Policies (Commerce Taxonomy) ----------
@app.get("/taxonomy/conditions")
def taxonomy_conditions(request: Request, site: str = Query("UK"), category_id: str = Query(...)):
    """
    Normaliseert eBay 'item condition policies' naar:
    {
      "conditions": [
        {"id":"1000","name":"New","label":"1000-New","allow_description": False},
        ...
      ],
      "condition_required": bool
    }
    """
    site, _ = _effective_site_and_currency(site, None)
    marketplace = MARKETPLACE_ID.get(site)
    if not marketplace:
        raise HTTPException(400, f"Unknown site {site}")

    env = (_get_user().get("env") or "PROD")

    # Use the Sell Metadata API — the correct endpoint for item condition policies.
    # (Commerce Taxonomy API does NOT have get_item_condition_policies.)
    path = f"/sell/metadata/v1/marketplace/{marketplace}/get_item_condition_policies"
    r2 = _commerce_get(env, path, {"category_id": category_id})
    if r2.status_code >= 400:
        raise HTTPException(r2.status_code, r2.text)
    raw = r2.json() or {}

    # Normalise — Sell Metadata API response structure:
    # {"itemConditionPolicies": [{"categoryId":"...", "itemConditions": [
    #   {"conditionDescription":"New", "conditionId":"1000", "conditionHelpText":"...",
    #    "conditionEnabled":"ENABLED"}
    # ], "conditionHelpText":"...", "itemConditionRequired": true}]}
    conds_out = []
    policies = (raw.get("itemConditionPolicies") or [])
    raw_list = []
    required = False
    for pol in policies:
        raw_list = pol.get("itemConditions") or []
        required = bool(pol.get("itemConditionRequired"))
        break  # only one policy block expected per category

    for c in raw_list:
        enabled = str(c.get("conditionEnabled") or "ENABLED").upper()
        if enabled == "DISABLED":
            continue
        cid = str(c.get("conditionId") or c.get("id") or "").strip()
        name = (c.get("conditionDescription") or c.get("conditionName") or c.get("name") or "").strip()
        # conditionDescriptionEnabled: whether the seller can add a condition description
        allow_desc = bool(
            c.get("conditionDescriptionEnabled")
            or c.get("conditionDescriptionAllowed")
            or c.get("allowedForConditionDescription")
        )
        if cid and name:
            conds_out.append({
                "id": cid,
                "name": name,
                "label": f"{cid}-{name}",
                "allow_description": allow_desc,
            })

    return {"conditions": conds_out, "condition_required": required}


# ---------- Stores ----------
def _rest_store_categories(env: str) -> List[Dict[str, Any]]:
    _refresh_user_if_needed(); u = _need_user(env)
    url = API_HOST[env] + "/sell/stores/v1/store/categories"
    hdr = {"Authorization": f"Bearer {u['access_token']}", "Accept": "application/json"}
    r = requests.get(url, headers=hdr, timeout=30)
    if r.status_code == 403: raise HTTPException(403, "Forbidden (scope?) sell.stores.* needed")
    if r.status_code >= 400: raise HTTPException(r.status_code, r.text)
    j = r.json() or {}; tree = j.get("storeCategories") or []
    out: List[Dict[str, Any]] = []
    def walk(nodes, parent):
        for n in nodes or []:
            cid = str(n.get("categoryId") or ""); name = n.get("categoryName") or ""
            if cid and name: out.append({"id": cid, "name": name, "parent_id": parent})
            walk(n.get("childrenCategories") or [], cid)
    walk(tree, None); return out

def _trading_getstore(request:Request, env: str, site: str) -> List[Dict[str, Any]]:
    _refresh_user_if_needed(); u = _need_user(env); site_id = TRADING_SITE_ID.get(site.upper(), "0")
    site, _ = _effective_site_and_currency(site, None)
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GetStoreRequest xmlns="urn:ebay:apis:eBLBaseComponents">
  <CategoryStructureOnly>true</CategoryStructureOnly>
</GetStoreRequest>""".strip()
    headers = {
        "X-EBAY-API-CALL-NAME": "GetStore","X-EBAY-API-SITEID": site_id,"X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],"Content-Type": "text/xml",
    }
    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
    if r.status_code >= 400: raise HTTPException(status_code=r.status_code, detail=r.text)
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError as e:
        raise HTTPException(status_code=502, detail=f"Parse error: {e}\n{r.text}")
    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip().lower()
    if ack == "failure":
        long_msg = root.findtext("e:Errors/e:LongMessage", default="", namespaces=ns)
        raise HTTPException(status_code=502, detail=f"Trading GetStore failure: {long_msg or 'unknown error'}")
    out: List[Dict[str, Any]] = []
    def collect(node, parent_id: Optional[str]):
        cats = node.findall("e:CustomCategories/e:CustomCategory", ns) + node.findall("e:ChildCategory", ns)
        for cat in cats:
            cid = (cat.findtext("e:CategoryID", default="", namespaces=ns) or "").strip()
            name = (cat.findtext("e:Name", default="", namespaces=ns) or "").strip()
            if cid and name:
                out.append({"id": cid, "name": name, "parent_id": parent_id})
                collect(cat, cid)
    store_root = root.find("e:Store", ns)
    if store_root is not None: collect(store_root, None)
    return out

@app.get("/debug/email")
def debug_email():
    return {
        "mode": "smtp" if os.getenv("SMTP_HOST") else "file/dev",
        "SMTP_HOST": os.getenv("SMTP_HOST", ""),
        "SMTP_PORT": os.getenv("SMTP_PORT", ""),
        "SMTP_STARTTLS": os.getenv("SMTP_STARTTLS", ""),
        "SMTP_SSL": os.getenv("SMTP_SSL", ""),
        "SMTP_FROM": os.getenv("SMTP_FROM", ""),
        "DEBUG_EMAIL_TO_CONSOLE": os.getenv("DEBUG_EMAIL_TO_CONSOLE", ""),
    }

@app.get("/stores/categories")
def stores_categories(
    request: Request,
    site: str = Query("UK"),
    prefer: str = Query("rest"),
    debug: bool = Query(False),
    strict: bool = Query(True),
):
    site, _ = _effective_site_and_currency(site, None)
    env = (_get_user().get("env") or "PROD").upper(); prefer = (prefer or "rest").lower().strip()
    def _try_rest() -> List[Dict[str, Any]]:
        try: return _rest_store_categories(env) or []
        except HTTPException as e:
            if debug: raise
            return []
    def _try_trading(site_code: str) -> List[Dict[str, Any]]:
        try: return _trading_getstore(request, env, site_code) or []
        except HTTPException as e:
            if debug: raise
            return []
    if strict:
        # Exact-site mode: never fall back to other marketplaces.
        # Prevents leaking NL/UK categories when user selected ES/FR/DE.
        return _try_trading(site)

    if prefer == "trading":
        for s_try in [site, "UK", "US", "DE"]:
            cats = _try_trading(s_try)
            if cats: return cats
        return []
    cats = _try_rest()
    if not cats:
        for s_try in [site, "UK", "US", "DE"]:
            cats = _try_trading(s_try)
            if cats: break
    return cats


# ---------- Listings (Trading) ----------
@app.get("/web/listings")
def web_listings(
    request: Request,
    site: str = Query("NL"),
    status: str = Query("Unsold"),
    q: str = Query(""),
    page: int = Query(1, ge=1),
    per_page: int = Query(200, ge=1, le=200),
    sort: str = Query("newest", description="newest or oldest"),
    date_from: str = Query("", description="ISO date filter e.g. 2025-01-01"),
    date_to: str = Query("", description="ISO date filter e.g. 2026-12-31"),
):
    """Return a simplified list of listings for the desktop MultiLister UI.

    Output items are normalized to:
      {"sku","title","status","format","price","end_time","item_id"}

    Requires a valid license and a linked eBay account (OAuth token).
    """
    ensure_valid_license_only(request)

    status_in = (status or "Unsold").strip().lower()
    # Empty site means "All sites" — keep it empty so the filter is skipped.
    # Only resolve via _effective_site_and_currency when a specific site is requested.
    site = (site or "").strip().upper()
    if site:
        site, _ = _effective_site_and_currency(site, None)

    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    # For GetMyeBaySelling the site ID only affects the API routing, not the results filter.
    # Use site_id 0 (US/generic) when fetching all sites so we don't limit what eBay returns.
    site_id = TRADING_SITE_ID.get(site, "0") if site else "0"
    def _norm_img_url(u: str) -> str:
        u = (u or "").strip()
        if not u:
            return ""
        # Some Trading responses still contain http:// image URLs.
        # Force https so desktop clients don't hit mixed/redirect edge cases.
        if u.startswith("http://"):
            u = "https://" + u[len("http://"):]
        return u

    def _currency_symbol(code: str) -> str:
        code = (code or "").upper()
        return {"EUR": "€", "GBP": "£", "USD": "$"}.get(code, "")

    def _fmt_price(amount: str | None, cur: str | None) -> str:
        if not amount:
            return ""
        sym = _currency_symbol(cur or "")
        try:
            # Keep 2 decimals if it looks numeric
            v = float(str(amount).strip())
            return f"{sym}{v:.2f}" if sym else f"{v:.2f}"
        except Exception:
            return f"{sym}{amount}" if sym else str(amount)

    # eBay site name (as returned in <Site> XML) → our two-letter code
    _EBAY_SITE_NAME_TO_CODE: Dict[str, str] = {
        "US": "US", "Canada": "CA", "UK": "UK", "eBayMotors": "US",
        "Australia": "AU", "Austria": "AT",
        "Belgium_French": "BE", "Belgium_Dutch": "BE",
        "France": "FR", "Germany": "DE", "Italy": "IT",
        "Netherlands": "NL", "Spain": "ES", "Switzerland": "CH",
        "Sweden": "SE", "Ireland": "IE", "Poland": "PL",
        "HongKong": "HK", "Singapore": "SG", "India": "IN",
    }

    def _call(list_tag: str) -> str:
        """Call GetMyeBaySelling for a single list container tag (ActiveList/UnsoldList/SoldList)."""
        # Date filter XML (EndTimeFrom/EndTimeTo inside the list tag)
        date_filter_xml = ""
        if date_from:
            date_filter_xml += f"\n    <EndTimeFrom>{date_from}T00:00:00.000Z</EndTimeFrom>"
        if date_to:
            date_filter_xml += f"\n    <EndTimeTo>{date_to}T23:59:59.999Z</EndTimeTo>"
        # For UnsoldList, eBay uses DurationInDays instead of EndTime filters
        duration_xml = ""
        if list_tag == "UnsoldList" and not date_from and not date_to:
            duration_xml = "\n    <DurationInDays>60</DurationInDays>"

        xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<GetMyeBaySellingRequest xmlns=\"urn:ebay:apis:eBLBaseComponents\">
  <ErrorLanguage>en_US</ErrorLanguage>
  <WarningLevel>High</WarningLevel>
  <DetailLevel>ReturnAll</DetailLevel>
  <OutputSelector>ItemID</OutputSelector>
  <OutputSelector>Title</OutputSelector>
  <OutputSelector>SellingStatus</OutputSelector>
  <OutputSelector>ListingType</OutputSelector>
  <OutputSelector>ListingDetails</OutputSelector>
  <OutputSelector>GalleryURL</OutputSelector>
  <OutputSelector>PictureDetails</OutputSelector>
  <OutputSelector>Variations</OutputSelector>
  <OutputSelector>Site</OutputSelector>
  <OutputSelector>ItemSpecifics</OutputSelector>
  <OutputSelector>PaginationResult</OutputSelector>
  <{list_tag}>
    <Include>true</Include>{date_filter_xml}{duration_xml}
    <Pagination>
      <EntriesPerPage>{int(per_page)}</EntriesPerPage>
      <PageNumber>{int(page)}</PageNumber>
    </Pagination>
  </{list_tag}>
</GetMyeBaySellingRequest>""".strip()

        headers = {
            "X-EBAY-API-CALL-NAME": "GetMyeBaySelling",
            "X-EBAY-API-SITEID": site_id,
            "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
            "X-EBAY-API-IAF-TOKEN": u["access_token"],
            "Content-Type": "text/xml",
        }
        r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.text

    _pagination_info = {"total_entries": 0, "total_pages": 0}

    def _parse(xml_text: str, section_tag: str, status_label: str) -> List[Dict[str, Any]]:
        nonlocal _pagination_info
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            raise HTTPException(status_code=502, detail=f"Parse error: {e}\n{xml_text[:1000]}")
        ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
        ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip().lower()
        if ack == "failure":
            long_msg = root.findtext("e:Errors/e:LongMessage", default="", namespaces=ns)
            raise HTTPException(status_code=502, detail=f"Trading GetMyeBaySelling failure: {long_msg or 'unknown error'}")

        out: List[Dict[str, Any]] = []
        sec = root.find(f"e:{section_tag}", ns)
        if sec is None:
            return out

        # Extract pagination info from response
        pag = sec.find("e:PaginationResult", ns)
        if pag is not None:
            try:
                _pagination_info["total_entries"] += int(pag.findtext("e:TotalNumberOfEntries", default="0", namespaces=ns) or 0)
                tp = int(pag.findtext("e:TotalNumberOfPages", default="0", namespaces=ns) or 0)
                if tp > _pagination_info["total_pages"]:
                    _pagination_info["total_pages"] = tp
            except Exception:
                pass

        items = sec.findall(".//e:ItemArray/e:Item", ns)
        q_l = (q or "").strip().lower()
        for it in items:
            sku = (it.findtext("e:SKU", default="", namespaces=ns) or "").strip()
            title = (it.findtext("e:Title", default="", namespaces=ns) or "").strip()
            if q_l and (q_l not in sku.lower()) and (q_l not in title.lower()):
                continue

            item_id = (it.findtext("e:ItemID", default="", namespaces=ns) or "").strip()
            listing_type = (it.findtext("e:ListingType", default="", namespaces=ns) or "").strip()
            has_vars = (it.find("e:Variations", ns) is not None)
            fmt = "Auction" if ("chinese" in listing_type.lower() or "auction" in listing_type.lower()) else "Fixed"

            # Determine listing site.
            # Primary: <Site> element (e.g. "Netherlands" → "NL")
            ebay_site_name = (it.findtext("e:Site", default="", namespaces=ns) or "").strip()
            item_site = _EBAY_SITE_NAME_TO_CODE.get(ebay_site_name, "")
            # Fallback: derive from ViewItemURL domain (more reliable for GetMyeBaySelling)
            if not item_site:
                view_url = (it.findtext("e:ListingDetails/e:ViewItemURL", default="", namespaces=ns) or "").lower()
                if "ebay.nl" in view_url:          item_site = "NL"
                elif "ebay.de" in view_url:        item_site = "DE"
                elif "ebay.co.uk" in view_url:     item_site = "UK"
                elif "ebay.fr" in view_url:        item_site = "FR"
                elif "ebay.it" in view_url:        item_site = "IT"
                elif "ebay.es" in view_url:        item_site = "ES"
                elif "ebay.be" in view_url:        item_site = "BE"
                elif "ebay.at" in view_url:        item_site = "AT"
                elif "ebay.ch" in view_url:        item_site = "CH"
                elif "ebay.com.au" in view_url:    item_site = "AU"
                elif "ebay.ca" in view_url:        item_site = "CA"
                elif "ebay.com" in view_url:       item_site = "US"
                else:                              item_site = site.upper()

            # Filter by requested site (skip listings from other sites)
            if site and item_site and item_site != site.upper():
                continue

            # Price: prefer CurrentPrice, fallback to BuyItNowPrice/StartPrice
            cur_price = it.find("e:SellingStatus/e:CurrentPrice", ns)
            if cur_price is None:
                cur_price = it.find("e:BuyItNowPrice", ns)
            if cur_price is None:
                cur_price = it.find("e:StartPrice", ns)
            amount = (cur_price.text if cur_price is not None else "")
            cur = (cur_price.attrib.get("currencyID") if cur_price is not None else "")
            price_s = _fmt_price(amount, cur)

            end_time = (
                it.findtext("e:ListingDetails/e:EndTime", default="", namespaces=ns)
                or it.findtext("e:EndTime", default="", namespaces=ns)
                or ""
            ).strip()


            # Image URLs (used for thumbnails + for converting online items into new drafts)
            imgs = []
            gal = it.findtext("e:GalleryURL", default="", namespaces=ns) or ""
            if gal.strip():
                imgs.append(_norm_img_url(gal))
            for pu in it.findall(".//e:PictureDetails/e:PictureURL", namespaces=ns):
                if pu is not None and (pu.text or "").strip():
                    imgs.append(_norm_img_url(pu.text or ""))
            # de-dup while preserving order
            seen = set()
            imgs = [u for u in imgs if not (u in seen or seen.add(u))]
            thumb_url = imgs[0] if imgs else ""

            # Item specifics (Name → Value pairs from <ItemSpecifics>)
            item_specs: dict[str, str] = {}
            for nvl in it.findall(".//e:ItemSpecifics/e:NameValueList", ns):
                n = (nvl.findtext("e:Name", default="", namespaces=ns) or "").strip()
                v = (nvl.findtext("e:Value", default="", namespaces=ns) or "").strip()
                if n and v:
                    item_specs[n] = v

            out.append(
                {
                    "sku": sku,
                    "title": title,
                    "status": status_label,
                    "format": fmt,
                    "price": price_s,
                    "end_time": end_time,
                    "item_id": item_id,
                    "thumb_url": thumb_url,
                    "has_variations": bool(has_vars),
                    "site": item_site,
                    "item_specifics": item_specs,
                }
            )
        return out

    # Determine which sections to fetch
    sections: List[Tuple[str, str]] = []
    if status_in == "active":
        sections = [("ActiveList", "Active"), ("ScheduledList", "Scheduled")]
    elif status_in == "scheduled":
        sections = [("ScheduledList", "Scheduled")]
    elif status_in == "ended":
        sections = [("SoldList", "Sold"), ("UnsoldList", "Unsold")]
    elif status_in == "all":
        sections = [("ActiveList", "Active"), ("ScheduledList", "Scheduled"), ("SoldList", "Sold"), ("UnsoldList", "Unsold")]
    else:  # default unsold
        sections = [("UnsoldList", "Unsold")]

    items_out: List[Dict[str, Any]] = []
    for tag, label in sections:
        xml_text = _call(tag)
        items_out.extend(_parse(xml_text, tag, label))

    # Sort: newest first (default) or oldest first
    if sort == "newest":
        items_out.sort(key=lambda x: x.get("end_time", ""), reverse=True)
    elif sort == "oldest":
        items_out.sort(key=lambda x: x.get("end_time", ""))

    return {
        "items": items_out,
        "page": page,
        "per_page": per_page,
        "total_entries": _pagination_info["total_entries"],
        "total_pages": _pagination_info["total_pages"],
        "sort": sort,
        "has_more": page < _pagination_info["total_pages"],
    }


@app.get("/web/listings_all")
def web_listings_all(
    request: Request,
    site: str = Query(""),
    status: str = Query("Unsold"),
    sort: str = Query("newest"),
    date_from: str = Query(""),
    date_to: str = Query(""),
    per_page: int = Query(200, ge=1, le=200, description="eBay page size for the internal loop. Lower values exercise the pagination loop on small test accounts."),
):
    """Return ALL listings across every eBay page in one response.

    No q / page params — the client filters and paginates against the full
    set client-side. This fixes the bug where per-page server filtering
    misaligned with the unfiltered total_pages count (filtered page 1 had
    matches, pages 2-N were clickable but empty).

    Payload is slim: item_specifics is stripped to keep the response small.
    For 2800 listings this is roughly 1-2 MB JSON.
    """
    ensure_valid_license_only(request)

    items_all: List[Dict[str, Any]] = []
    page_num = 1
    max_pages_guard = 100  # safety: never loop forever
    while page_num <= max_pages_guard:
        result = web_listings(
            request=request,
            site=site,
            status=status,
            q="",
            page=page_num,
            per_page=per_page,
            sort=sort,
            date_from=date_from,
            date_to=date_to,
        )
        page_items = result.get("items") or []
        items_all.extend(page_items)
        total_pages = int(result.get("total_pages") or 1)
        if page_num >= total_pages or not page_items:
            break
        page_num += 1

    # Strip heavy fields client doesn't need for the list view.
    for it in items_all:
        it.pop("item_specifics", None)

    return {
        "items": items_all,
        "total": len(items_all),
        "pages_fetched": page_num,
    }


@app.get("/web/listing_images")
def web_listing_images(request: Request, item_id: str = Query(...), site: str = Query("NL")):
    ensure_valid_license_only(request)

    site, _ = _effective_site_and_currency(site, None)
    site = (site or "NL").upper()

    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    site_id = TRADING_SITE_ID.get(site.upper(), "0")

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<GetItemRequest xmlns="urn:ebay:apis:eBLBaseComponents">
  <ErrorLanguage>en_US</ErrorLanguage>
  <WarningLevel>High</WarningLevel>
  <DetailLevel>ReturnAll</DetailLevel>
  <IncludeItemSpecifics>true</IncludeItemSpecifics>
  <IncludeVariations>true</IncludeVariations>
  <ItemID>{item_id}</ItemID>
</GetItemRequest>""".strip()

    headers = {
        "X-EBAY-API-CALL-NAME": "GetItem",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }

    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.content)
    def _norm_img_url(u: str) -> str:
        u = (u or "").strip()
        if not u:
            return ""
        if u.startswith("http://"):
            u = "https://" + u[len("http://"):]
        return _normalize_ebayimg_url(u)

    urls = []
    for node in root.findall(".//e:PictureDetails/e:PictureURL", ns):
        t = _norm_img_url(node.text or "")
        if t and t not in urls:
            urls.append(t)

    for node in root.findall(".//e:ExtendedPictureDetails/e:PictureURL", ns):
        t = _norm_img_url(node.text or "")
        if t and t not in urls:
            urls.append(t)

    return {"ok": True, "item_id": item_id, "images": urls}

@app.get("/web/item_specifics")
def web_item_specifics(request: Request, item_id: str = Query(...), site: str = Query("NL")):
    """Return item specifics (NameValueList) for a single eBay item via GetItem."""
    ensure_valid_license_only(request)

    site, _ = _effective_site_and_currency(site, None)
    site = (site or "NL").upper()

    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    site_id = TRADING_SITE_ID.get(site, "0")

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<GetItemRequest xmlns="urn:ebay:apis:eBLBaseComponents">
  <ErrorLanguage>en_US</ErrorLanguage>
  <WarningLevel>High</WarningLevel>
  <DetailLevel>ReturnAll</DetailLevel>
  <IncludeItemSpecifics>true</IncludeItemSpecifics>
  <IncludeVariations>true</IncludeVariations>
  <ItemID>{item_id}</ItemID>
</GetItemRequest>""".strip()

    headers = {
        "X-EBAY-API-CALL-NAME": "GetItem",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }

    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.content)

    item_specs: dict[str, str] = {}
    for nvl in root.findall(".//e:Item/e:ItemSpecifics/e:NameValueList", ns):
        n = (nvl.findtext("e:Name", default="", namespaces=ns) or "").strip()
        v = (nvl.findtext("e:Value", default="", namespaces=ns) or "").strip()
        if n and v:
            item_specs[n] = v

    # DEBUG: return raw XML snippet so we can see what eBay actually sends back
    debug_xml = r.text[:3000] if r.text else ""

    return {"ok": True, "item_id": item_id, "item_specifics": item_specs, "debug_xml": debug_xml}

@app.get("/web/listing_details")
def web_listing_details(request: Request, item_id: str = Query(...), site: str = Query("NL")):
    """Return detailed listing info, including variations (if any), for Manage Listings.

    Used to import an existing multi-variation listing into the MultiLister draft builder.
    """
    ensure_valid_license_only(request)

    site, _ = _effective_site_and_currency(site, None)
    site = (site or "NL").upper()

    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    site_id = TRADING_SITE_ID.get(site.upper(), "0")

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<GetItemRequest xmlns="urn:ebay:apis:eBLBaseComponents">
  <ErrorLanguage>en_US</ErrorLanguage>
  <WarningLevel>High</WarningLevel>
  <DetailLevel>ReturnAll</DetailLevel>
  <IncludeItemSpecifics>true</IncludeItemSpecifics>
  <IncludeVariations>true</IncludeVariations>
  <ItemID>{item_id}</ItemID>
</GetItemRequest>""".strip()

    headers = {
        "X-EBAY-API-CALL-NAME": "GetItem",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }

    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.content)

    def _norm_img_url(u_: str) -> str:
        u_ = (u_ or "").strip()
        if not u_:
            return ""
        if u_.startswith("http://"):
            u_ = "https://" + u_[len("http://"):]
        return _normalize_ebayimg_url(u_)

    title = (root.findtext(".//e:Item/e:Title", default="", namespaces=ns) or "").strip()
    sku = (root.findtext(".//e:Item/e:SKU", default="", namespaces=ns) or "").strip()
    cat_id = (root.findtext(".//e:Item/e:PrimaryCategory/e:CategoryID", default="", namespaces=ns) or "").strip()
    cat_name = (root.findtext(".//e:Item/e:PrimaryCategory/e:CategoryName", default="", namespaces=ns) or "").strip()
    listing_type = (root.findtext(".//e:Item/e:ListingType", default="", namespaces=ns) or "").strip()
    description = (root.findtext(".//e:Item/e:Description", default="", namespaces=ns) or "")
    quantity_raw = (root.findtext(".//e:Item/e:Quantity", default="", namespaces=ns) or "").strip()
    qty_sold = (root.findtext(".//e:Item/e:SellingStatus/e:QuantitySold", default="0", namespaces=ns) or "0").strip()
    try:
        avail_qty = max(0, int(quantity_raw or 0) - int(qty_sold or 0))
    except Exception:
        avail_qty = 0
    start_price_node = root.find(".//e:Item/e:StartPrice", ns)
    start_price = (start_price_node.text if start_price_node is not None else "") or ""
    currency = (start_price_node.attrib.get("currencyID") if start_price_node is not None else "") or ""
    bin_price_node = root.find(".//e:Item/e:BuyItNowPrice", ns)
    bin_price = (bin_price_node.text if bin_price_node is not None else "") or ""
    cond_id = (root.findtext(".//e:Item/e:ConditionID", default="", namespaces=ns) or "").strip()
    cond_name = (root.findtext(".//e:Item/e:ConditionDisplayName", default="", namespaces=ns) or "").strip()
    cond_desc = (root.findtext(".//e:Item/e:ConditionDescription", default="", namespaces=ns) or "").strip()
    store_cat_id = (root.findtext(".//e:Item/e:Storefront/e:StoreCategoryID", default="", namespaces=ns) or "").strip()
    store_cat2_id = (root.findtext(".//e:Item/e:Storefront/e:StoreCategory2ID", default="", namespaces=ns) or "").strip()
    location = (root.findtext(".//e:Item/e:Location", default="", namespaces=ns) or "").strip()
    postal_code = (root.findtext(".//e:Item/e:PostalCode", default="", namespaces=ns) or "").strip()
    duration = (root.findtext(".//e:Item/e:ListingDuration", default="", namespaces=ns) or "").strip()
    listing_site = (root.findtext(".//e:Item/e:Site", default="", namespaces=ns) or "").strip()

    parent_pics: list[str] = []
    for node in root.findall(".//e:Item/e:PictureDetails/e:PictureURL", ns):
        t = _norm_img_url(node.text or "")
        if t and t not in parent_pics:
            parent_pics.append(t)

    # Parent/listing item specifics
    parent_specifics: dict[str, str] = {}
    for nvl in root.findall(".//e:Item/e:ItemSpecifics/e:NameValueList", ns):
        n = (nvl.findtext("e:Name", default="", namespaces=ns) or "").strip()
        if not n:
            continue
        vals = [((v.text or "").strip()) for v in nvl.findall("e:Value", ns)]
        v = next((x for x in vals if x), "")
        if n and v:
            parent_specifics[n] = v

    # Variations
    var_names: list[str] = []
    for node in root.findall(".//e:Item/e:Variations/e:VariationSpecificsSet/e:NameValueList/e:Name", ns):
        n = (node.text or "").strip()
        if n and n not in var_names:
            var_names.append(n)

    # Pictures mapping (usually keyed by a single variation specific name)
    picture_name = (root.findtext(".//e:Item/e:Variations/e:Pictures/e:VariationSpecificName", default="", namespaces=ns) or "").strip()
    picture_sets: dict[str, list[str]] = {}
    for pset in root.findall(".//e:Item/e:Variations/e:Pictures/e:VariationSpecificPictureSet", ns):
        val = (pset.findtext("e:VariationSpecificValue", default="", namespaces=ns) or "").strip()
        if not val:
            continue
        urls: list[str] = []
        for u_node in pset.findall("e:PictureURL", ns):
            t = _norm_img_url(u_node.text or "")
            if t and t not in urls:
                urls.append(t)
        if urls:
            picture_sets[val] = urls

    variations: list[dict] = []
    for v in root.findall(".//e:Item/e:Variations/e:Variation", ns):
        v_sku = (v.findtext("e:SKU", default="", namespaces=ns) or "").strip()
        # eBay returns total Quantity (initial) per variation. Available =
        # Quantity - SellingStatus/QuantitySold. Without subtracting, sold-out
        # variations appear with their original count instead of 0.
        v_qty_raw = (v.findtext("e:Quantity", default="", namespaces=ns) or "").strip()
        v_qty_sold = (v.findtext("e:SellingStatus/e:QuantitySold", default="0", namespaces=ns) or "0").strip()
        try:
            v_qty_avail = max(0, int(v_qty_raw or 0) - int(v_qty_sold or 0))
        except Exception:
            v_qty_avail = 0
        v_qty = str(v_qty_avail)
        v_price_node = v.find("e:StartPrice", ns)
        v_price = (v_price_node.text if v_price_node is not None else "") or ""
        v_cur = (v_price_node.attrib.get("currencyID") if v_price_node is not None else "") or ""

        specifics: dict[str, str] = {}
        for nvl in v.findall(".//e:VariationSpecifics/e:NameValueList", ns):
            n = (nvl.findtext("e:Name", default="", namespaces=ns) or "").strip()
            if not n:
                continue
            val = (nvl.findtext("e:Value", default="", namespaces=ns) or "").strip()
            if val:
                specifics[n] = val

        v_pics: list[str] = []
        if picture_name and picture_sets:
            v_val = specifics.get(picture_name, "")
            if v_val and v_val in picture_sets:
                v_pics = list(picture_sets.get(v_val) or [])

        variations.append(
            {
                "sku": v_sku,
                "quantity": v_qty,
                "start_price": v_price,
                "currency": v_cur,
                "specifics": specifics,
                "picture_urls": v_pics,
            }
        )

    # Remove variation-specific keys from parent specifics
    for _vn in var_names:
        parent_specifics.pop(_vn, None)
    if picture_name:
        parent_specifics.pop(picture_name, None)

    # Extract seller business policies from the listing
    shipping_profile_id = (root.findtext(".//e:Item/e:SellerProfiles/e:SellerShippingProfile/e:ShippingProfileID", default="", namespaces=ns) or "").strip()
    payment_profile_id  = (root.findtext(".//e:Item/e:SellerProfiles/e:SellerPaymentProfile/e:PaymentProfileID",  default="", namespaces=ns) or "").strip()
    return_profile_id   = (root.findtext(".//e:Item/e:SellerProfiles/e:SellerReturnProfile/e:ReturnProfileID",    default="", namespaces=ns) or "").strip()

    return {
        "ok": True,
        "item_id": item_id,
        "title": title,
        "sku": sku,
        "category_id": cat_id,
        "category_name": cat_name,
        "category_display": cat_name,
        "listing_type": listing_type,
        "duration": duration,
        "site": listing_site,
        "description": description,
        "description_html": description,
        "quantity": avail_qty,
        "quantity_total": int(quantity_raw or 0) if quantity_raw else 0,
        "quantity_sold": int(qty_sold or 0) if qty_sold else 0,
        "price": start_price,
        "start_price": start_price,
        "currency": currency,
        "buy_it_now_price": bin_price,
        "condition_id": cond_id,
        "condition_label": cond_name,
        "condition_name": cond_name,
        "condition_description": cond_desc,
        "store_category_id": store_cat_id,
        "store_category_id_2": store_cat2_id,
        "location": location,
        "postal_code": postal_code,
        "has_variations": bool(variations),
        "variation_names": var_names,
        "variation_picture_name": picture_name,
        "picture_sets": picture_sets,
        "parent_pictures": parent_pics,
        "picture_urls": parent_pics,
        "images": parent_pics,
        "parent_specifics": parent_specifics,
        "item_specifics": parent_specifics,
        "itemSpecifics": parent_specifics,
        "variations": variations,
        "shipping_profile": shipping_profile_id,
        "payment_profile": payment_profile_id,
        "return_profile": return_profile_id,
    }


# ---------- Account/site ----------
@app.get("/account/site")
def account_site():
    _refresh_user_if_needed()
    u = _need_user()

    # Gebruik wat je bij login/context hebt gezet, NIET opnieuw uit GetUser mappen
    code = (u.get("site") or "NL").strip().upper()
    currency = (u.get("currency") or "").strip().upper()

    if not currency:
        SITE_TO_CUR = {
            "NL": "EUR", "BE": "EUR", "DE": "EUR", "FR": "EUR",
            "IT": "EUR", "ES": "EUR", "IE": "EUR", "AT": "EUR",
            "PL": "PLN", "CH": "CHF", "UK": "GBP", "US": "USD",
            "CA": "CAD", "AU": "AUD"
        }
        currency = SITE_TO_CUR.get(code, "EUR")

    return {
        "site_label": code,              # puur voor display
        "site_code": code,
        "currency": currency,
        "username": u.get("ebay_user") or "",
    }

from fastapi import HTTPException, Request

def _ensure_bound_license(request: Request) -> tuple[dict, dict]:
    # licentie
    lk = (request.headers.get("X-License-Key") or request.cookies.get("license_key") or request.query_params.get("lk") or "").strip()
    if not lk:
        raise HTTPException(status_code=401, detail="Valid license required")
    rec = find_license(lk)
    if not (rec and is_valid(rec)):
        raise HTTPException(status_code=401, detail="Valid license required")

    # identity
    identity_user_id = ""
    identity_username = ""
    env = "PROD"
    try:
        _refresh_user_if_needed()
        u = _need_user()
        env = (u.get("env") or "PROD").upper()
        base = "https://apiz.ebay.com" if env == "PROD" else "https://apiz.sandbox.ebay.com"
        r_id = requests.get(base + "/commerce/identity/v1/user/", headers={"Authorization": f"Bearer {u['access_token']}"}, timeout=12)
        if r_id.ok:
            j = r_id.json() or {}
            identity_user_id = (j.get("userId") or "").strip()
            identity_username = (j.get("username") or "").strip()
    except Exception:
        pass

    allowed_ids = rec.get("allowed_identity_ids") if "allowed_identity_ids" in rec else None
    allowed_users = rec.get("allowed_ebay_users") if "allowed_ebay_users" in rec else None
    max_acc = int(rec.get("max_accounts") or 1)

    if allowed_ids is not None:
        if not identity_user_id:
            raise HTTPException(401, "Please log in to eBay before using this feature.")
        if identity_user_id not in allowed_ids:
            raise HTTPException(401, "License not bound to this eBay account (id).")
    elif allowed_users is not None:
        if not identity_username:
            raise HTTPException(401, "Please log in to eBay before using this feature.")
        if identity_username not in allowed_users:
            raise HTTPException(401, "License not bound to this eBay account (name).")
    else:
        # eerste gebruik → bind voorkeur identity-id
        if identity_user_id:
            try:
                attach_identity_id(lk, identity_user_id, identity_username, max_accounts_default=max_acc)
                rec = find_license(lk) or rec
            except Exception:
                pass
        elif identity_username:
            try:
                attach_ebay_user(lk, identity_username, max_accounts_default=max_acc)
                rec = find_license(lk) or rec
            except Exception:
                pass
        else:
            raise HTTPException(401, "Please log in to eBay before using this feature.")

    return rec, {"userId": identity_user_id, "username": identity_username, "env": env}

def _effective_max_accounts(rec: dict):
    """Override uit licentie wint; anders plan-default; None = onbeperkt."""
    # 1) expliciet per-licentie
    if "max_accounts" in rec and rec.get("max_accounts") not in (None, ""):
        try:
            return int(rec["max_accounts"])
        except Exception:
            return rec["max_accounts"]  # als iemand iets geks heeft ingevuld

    # 2) plan-default uit env
    plan = (rec.get("plan") or "").strip().lower()
    return plan_max_accounts().get(plan, None)  # None = onbeperkt

def _slots_used(rec: dict) -> int:
    ids   = set(rec.get("allowed_identity_ids") or [])
    users = set(rec.get("allowed_ebay_users") or [])
    meta  = rec.get("identity_usernames") or {}  # id -> username

    # Usernames die al horen bij een allowed id tellen NIET nog eens mee
    usernames_of_ids = { (meta.get(i) or "").strip().lower() for i in ids if meta.get(i) }
    users_effective  = { (u or "").strip() for u in users
                         if (u or "").strip().lower() not in usernames_of_ids }

    return len(ids) + len(users_effective)


@APP.post("/license/attach_current")
def license_attach_current(request: Request):
    lk = (request.headers.get("X-License-Key") or request.cookies.get("license_key")
          or request.query_params.get("lk") or "").strip()
    if not lk:
        raise HTTPException(401, "Valid license required")

    rec = find_license(lk)
    if not (rec and is_valid(rec)):
        raise HTTPException(401, "Valid license required")
    if (rec.get("status") or "active") != "active":
        raise HTTPException(401, "License not active")

    uid, uname, _env = _identity_get_user()
    if not (uid or uname):
        raise HTTPException(401, "Please log in to eBay before attaching.")

    allowed_ids   = set(rec.get("allowed_identity_ids") or [])
    allowed_users = set(rec.get("allowed_ebay_users") or [])
    meta          = rec.get("identity_usernames") or {}  # id -> username

    # 0) Al gebonden? Klaar.
    if (uid and uid in allowed_ids) or (uname and uname in allowed_users) \
       or (uid and meta.get(uid) and meta[uid] in allowed_users):
        return {"ok": True, "already_bound": True}

    # 0b) Pro-downgrade blokkeren: als dit een launch-licentie is, check of de gebruiker
    #     al aan een pro/extreme/higher licentie gekoppeld is → blokkeer.
    plan_this = (rec.get("plan") or "launch").strip().lower()
    if PLAN_PRIORITY.get(plan_this, 0) <= PLAN_PRIORITY.get("launch", 20):
        try:
            all_lics = _licenses_load()
            norm_uid = (uid or "").strip()
            norm_uname = (uname or "").strip().lower()
            for _other_h, other_rec in all_lics.items():
                if not isinstance(other_rec, dict):
                    continue
                if not is_valid(other_rec):
                    continue
                other_plan = (other_rec.get("plan") or "").strip().lower()
                if PLAN_PRIORITY.get(other_plan, 0) <= PLAN_PRIORITY.get("launch", 20):
                    continue  # niet hoger dan launch → geen bezwaar
                other_ids   = set(other_rec.get("allowed_identity_ids") or [])
                other_users = {(u or "").strip().lower() for u in (other_rec.get("allowed_ebay_users") or [])}
                other_meta  = other_rec.get("identity_usernames") or {}
                other_meta_unames = {(v or "").strip().lower() for v in other_meta.values() if v}
                if (norm_uid and norm_uid in other_ids) \
                   or (norm_uname and norm_uname in other_users) \
                   or (norm_uname and norm_uname in other_meta_unames):
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error": "pro_downgrade_blocked",
                            "current_plan": other_plan,
                            "blocked_plan": plan_this,
                            "message": (
                                f"Dit eBay-account ({uname or uid}) is al gekoppeld aan een licentie "
                                f"met een hoger plan ({other_plan}). Koppel het daar eerst los voordat je "
                                f"het aan deze {plan_this}-licentie hangt. Vragen? Mail joep@scheeltwerk.nl."
                            ),
                        },
                    )
        except HTTPException:
            raise
        except Exception:
            pass  # bij onverwachte fout niet blokkeren

    # 1) Slots tellen zonder dubbel (id+username van dezelfde account)
    slots_used = _slots_used(rec)
    max_acc = _effective_max_accounts(rec)  # None = onbeperkt

    # 2) Plek vrij → binden (voorkeur: identity-id)
    if (max_acc is None) or (slots_used < int(max_acc)):
        if uid:
            attach_identity_id(lk, uid, uname, max_accounts_default=max_acc or 1)
        else:
            attach_ebay_user(lk, uname, max_accounts_default=max_acc or 1)
        return {"ok": True}

    # 3) Vol → 409 met leesbare namen + duidelijke uitleg.
    bound_identity = next(iter(allowed_ids), None)
    bound_username = (
        (meta.get(bound_identity) if bound_identity else None)
        or next(iter(allowed_users), None)
        or rec.get("last_bound_username")
    )
    cooldown_days = int(os.getenv("JOEP_SWITCH_COOLDOWN_DAYS", "21"))
    candidate = uname or uid or "het huidige eBay-account"
    bound_label = bound_username or bound_identity or "een ander eBay-account"
    return JSONResponse(
        status_code=409,
        content={
            "error": "max_accounts_reached",
            "max_accounts": int(max_acc),
            "bound_identity": bound_identity,
            "bound_username": bound_username,
            "candidate_username": uname or "",
            "cooldown_days": cooldown_days,
            "message": (
                f"Deze licentie heeft al {int(max_acc)} eBay-account gekoppeld ({bound_label}) "
                f"en kan {candidate} er niet bij hebben. Koppel {bound_label} eerst los via het "
                f"admin-paneel (of vraag een licentie met meer slots aan)."
            ),
        },
    )





@APP.get("/account/whoami")
def account_whoami():
    try:
        user_id, username, env, reg= _identity_get_user_full()
        if not (user_id or username):
            raise HTTPException(status_code=401, detail="Please login to your ebay account")
        return {
            "userId": user_id,
            "username": username,
            "env": env,
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Please login to your ebay account")


# ---------- Media: EPS upload ----------
# ---------- Media: EPS upload ----------
def _eps_upload_trading(env: str, site_code: str, filename: str, content: bytes, picture_name: str | None = None) -> list[str]:
    _refresh_user_if_needed(); u = _need_user(env)
    site_id = TRADING_SITE_ID.get(site_code.upper(), "0")

    xml = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<UploadSiteHostedPicturesRequest xmlns="urn:ebay:apis:eBLBaseComponents">',
        '  <WarningLevel>High</WarningLevel>',
        '  <ExtensionInDays>30</ExtensionInDays>',
    ]
    if picture_name:
        safe_name = str(picture_name).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        xml.append(f"  <PictureName>{safe_name}</PictureName>")
    xml.append('</UploadSiteHostedPicturesRequest>')
    xml_payload = "\n".join(xml)

    headers = {
        "X-EBAY-API-CALL-NAME": "UploadSiteHostedPictures",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "X-EBAY-API-REQUEST-ENCODING": "XML",
        "Accept": "text/xml",
    }
    files = {
        "XMLPayload": ("", xml_payload, "text/xml"),
        "file": (filename or "image.jpg", content, "application/octet-stream"),
    }
    print(f"[SCHED-DIAG] site_code={site_code} site_id={site_id}")
    # Retry up to 3 times on 429 (eBay EPS rate limit) with exponential backoff
    import time as _time
    _last_r = None
    for _attempt in range(4):
        if _attempt > 0:
            _wait = 5 * (2 ** (_attempt - 1))  # 5s, 10s, 20s
            print(f"[EPS] 429 rate-limited by eBay, retrying in {_wait}s (attempt {_attempt+1}/4)")
            _time.sleep(_wait)
        _last_r = requests.post(TRADING_ENDPOINT[env], headers=headers, files=files, timeout=60)
        if _last_r.status_code != 429:
            break
    r = _last_r
    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"EPS upload HTTP error: {r.text}")

    try:
        ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
        root = ET.fromstring(r.content)
        ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip().upper()

        # optioneel: waarschuwingen verzamelen (handig voor debug)
        warnings = []
        for e in root.findall("e:Errors", ns):
            sev = (e.findtext("e:SeverityCode", default="", namespaces=ns) or "").strip().upper()
            if sev == "WARNING":
                code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
                msg  = (e.findtext("e:LongMessage", default="", namespaces=ns) or "").strip() or \
                       (e.findtext("e:ShortMessage", default="", namespaces=ns) or "").strip()
                if msg or code:
                    warnings.append({"code": code, "message": msg})

        if ack == "FAILURE":
            errs = []
            for e in root.findall("e:Errors", ns):
                code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
                msg  = (e.findtext("e:LongMessage", default="", namespaces=ns) or
                        e.findtext("e:ShortMessage", default="", namespaces=ns) or "").strip()
                if msg or code:
                    errs.append(f"{code}: {msg}".strip(": ").strip())
            raise HTTPException(502, "EPS failure: " + (" | ".join(errs) if errs else r.text[:400]))

        urls: list[str] = []
        for uurl in root.findall(".//e:FullURL", ns):
            s = (uurl.text or "").strip()
            if s:
                urls.append(s)

        if not urls:
            raise HTTPException(502, f"EPS: no FullURL found. Raw: {r.text[:400]}")
        return urls

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"EPS parse error: {e}\n{r.text[:400]}")



from typing import Optional
from fastapi import Request, HTTPException, Query, UploadFile, File
import requests
import xml.etree.ElementTree as ET

def _ensure_min_longest_side_500(content: bytes, filename: str) -> tuple[bytes, str | None, dict]:
    """Best-effort enforcement of eBay picture policy (min 500px longest side).

    - If Pillow isn't installed, returns original bytes (no hard failure).
    - If the image is smaller than 500px on its longest side, it will be upscaled.
    - Output is normalized to JPEG to avoid odd format edge cases.
    Returns: (new_content, new_filename_or_None, meta_dict)
    """
    meta: dict = {}
    try:
        from PIL import Image, ImageOps  # type: ignore
        import io

        im = Image.open(io.BytesIO(content))
        im = ImageOps.exif_transpose(im)

        w, h = im.size
        meta["orig_size"] = [int(w), int(h)]
        longest = max(w, h)

        # Normalize to RGB (handle alpha by compositing on white)
        if im.mode in ("RGBA", "LA"):
            bg = Image.new("RGB", im.size, (255, 255, 255))
            bg.paste(im, mask=im.split()[-1])
            im = bg
        elif im.mode != "RGB":
            im = im.convert("RGB")

        resized = False
        if longest and longest < 500:
            scale = 500.0 / float(longest)
            nw = max(1, int(round(w * scale)))
            nh = max(1, int(round(h * scale)))
            im = im.resize((nw, nh), Image.LANCZOS)
            meta["resized_to"] = [int(nw), int(nh)]
            resized = True

        out = io.BytesIO()
        im.save(out, format="JPEG", quality=95, optimize=True)
        new_bytes = out.getvalue()

        # If we resized OR the original name isn't jpg/jpeg, return a suggested .jpg name
        new_name = None
        try:
            low = (filename or "").lower()
            is_jpg = low.endswith(".jpg") or low.endswith(".jpeg")
            if resized or not is_jpg:
                stem = os.path.splitext(filename or "image")[0]
                new_name = (stem or "image") + ".jpg"
        except Exception:
            pass

        meta["pillow"] = True
        return new_bytes, new_name, meta

    except ImportError:
        meta["pillow"] = False
        return content, None, meta
    except Exception as e:
        meta["error"] = str(e)
        return content, None, meta


@APP.post("/media/eps_upload")
async def media_eps_upload(
    request: Request,
    file: UploadFile = File(...),
    site: str = Query(None),
    picture_name: Optional[str] = Query(None),
):
    site = _effective_site(site)
    # licentie
    lk = (request.headers.get("X-License-Key") or request.cookies.get("license_key") or request.query_params.get("lk") or "").strip()
    if not lk:
        raise HTTPException(401, "Valid license required")
    rec = find_license(lk)
    if not (rec and is_valid(rec)):
        raise HTTPException(401, "Valid license required")

    # wie ben ik?
    env = "PROD"
    uid = uname = ""
    try:
        _refresh_user_if_needed()
        u = _need_user()
        env = (u.get("env") or "PROD").upper()
        base = "https://apiz.ebay.com" if env == "PROD" else "https://apiz.sandbox.ebay.com"
        r_id = requests.get(base + "/commerce/identity/v1/user/", headers={"Authorization": f"Bearer {u['access_token']}"}, timeout=12)
        if r_id.ok:
            j = r_id.json() or {}
            uid = (j.get("userId") or "").strip()
            uname = (j.get("username") or "").strip()
        if not uname:
            # fallback Trading → username
            headers = {
                "X-EBAY-API-CALL-NAME": "GetUser",
                "X-EBAY-API-SITEID": "0",
                "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
                "X-EBAY-API-IAF-TOKEN": u["access_token"],
                "Content-Type": "text/xml",
            }
            xml = "<?xml version='1.0' encoding='utf-8'?><GetUserRequest xmlns='urn:ebay:apis:eBLBaseComponents'/>"
            r0 = requests.post(TRADING_ENDPOINT[u["env"]], headers=headers, data=xml.encode("utf-8"), timeout=15)
            ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
            try:
                root = ET.fromstring(r0.text)
                uname = (root.findtext("e:User/e:UserID", default="", namespaces=ns) or "").strip()
            except Exception:
                pass
    except Exception:
        pass

    allowed_ids   = rec.get("allowed_identity_ids") if "allowed_identity_ids" in rec else None
    allowed_users = rec.get("allowed_ebay_users")   if "allowed_ebay_users"   in rec else None
    max_acc = int(rec.get("max_accounts") or 1)

    if allowed_ids is not None:
        if not uid: raise HTTPException(401, "Please log in to eBay before uploading.")
        if uid not in allowed_ids: raise HTTPException(401, "License not bound to this eBay account (id).")
    elif allowed_users is not None:
        if not uname: raise HTTPException(401, "Please log in to eBay before uploading.")
        if uname not in allowed_users: raise HTTPException(401, "License not bound to this eBay account (name).")
    else:
        # eerste gebruik → bind voorkeur identity-id
        if uid:
            try:
                attach_identity_id(lk, uid, uname, max_accounts_default=max_acc)
                rec = find_license(lk) or rec
            except Exception:
                pass
        elif uname:
            try:
                attach_ebay_user(lk, uname, max_accounts_default=max_acc)
                rec = find_license(lk) or rec
            except Exception:
                pass
        else:
            raise HTTPException(401, "Please log in to eBay before uploading.")
    # 3) EPS dag-limiet check
    usage_key = _eps_usage_key_for_license(lk, rec, uid, uname)
    _limit = get_limit_for_record(rec)                # None = onbeperkt
    if _limit is not None:
        st = get_usage(usage_key)
        used = int(st.get("count") or 0)
        if used >= int(_limit):
            # EPS counter is MONTHLY (eps_limits.get_usage buckets per
            # month). Earlier this branch retried-after to next midnight,
            # which lied to the user — quota stayed at 0 until the 1st.
            # Now we point them at the actual monthly reset.
            try:
                from zoneinfo import ZoneInfo
                tzname = os.getenv("JOEP_USAGE_TZ", "UTC")
                now = datetime.now(ZoneInfo(tzname))
            except Exception:
                now = datetime.utcnow()
            if now.month == 12:
                next_reset = now.replace(year=now.year + 1, month=1, day=1,
                                         hour=0, minute=0, second=0, microsecond=0)
            else:
                next_reset = now.replace(month=now.month + 1, day=1,
                                         hour=0, minute=0, second=0, microsecond=0)
            retry_after = max(1, int((next_reset - now).total_seconds()))
            resp = JSONResponse(
                {
                    "ok": False,
                    "detail": "eps_monthly_limit_exceeded",
                    "used_this_month": used,
                    "limit": int(_limit),
                    "retry_after": retry_after,
                    "resets_at": next_reset.isoformat(),
                    # backward compat for older clients
                    "used_today": used,
                },
                status_code=429,
            )
            resp.headers["Retry-After"] = str(retry_after)
            return resp
        # EPS upload
    content = await file.read()

    # Enforce eBay picture policy (min 500px on the longest side) for uploaded images.
    upload_name = file.filename or "image.jpg"
    image_meta = None
    try:
        content, fixed_name, image_meta = _ensure_min_longest_side_500(content, upload_name)
        if fixed_name:
            upload_name = fixed_name
    except Exception as _e:
        image_meta = {"error": str(_e)}

    urls = _eps_upload_trading(env, site, upload_name, content, picture_name)

    # Charge the quota only after a confirmed successful upload — charging
    # before this call meant a failed/timed-out attempt (auth hiccup, eBay
    # error, dropped connection) still consumed the customer's credit, and
    # a client-side retry after a reported "failure" would burn another
    # one even though the first attempt may have gone through server-side.
    if _limit is not None and urls:
        from .eps_limits import increment as _eps_inc
        _eps_inc(usage_key, 1)

    eps_limit = get_limit_for_record(rec) if rec else None
    eps_used = eps_remaining = None
    if rec:
        st = get_usage(usage_key)
        used = int(st.get("count") or 0)
        eps_used = used
        eps_remaining = None if eps_limit is None else max(0, int(eps_limit) - used)

    # ... na het bepalen van: urls, eps_limit, eps_used, eps_remaining
    return {
        "ok": True,
        "image_url": urls[0],          # ← eerste URL
        "all_urls": urls,              # ← alle URL’s uit EPS
        "eps_daily_limit": eps_limit,  # ← handig voor UI
        "eps_used_today": eps_used,
        "eps_remaining_today": eps_remaining,
        "image_meta": image_meta,
    }



@app.post("/web/eps_count_external")
def eps_count_external(request: Request, payload: Dict[str, Any] = Body(...)):
    """Count external-image-host usage toward the monthly EPS counter.

    Used when a listing is published with externally-hosted picture URLs
    (e.g. from an InkFrog CSV import) so no actual EPS upload happens, but
    the seller still gets app-usage tracking. Increments the same monthly
    counter the upload endpoint uses; returns current used/limit/remaining.

    Body: {"count": <int>, "site": <optional>, "env": <optional>}
    """
    lk = (request.headers.get("X-License-Key") or request.cookies.get("license_key")
          or request.query_params.get("lk") or "").strip()
    if not lk:
        raise HTTPException(401, "Valid license required")
    rec = find_license(lk)
    if not (rec and is_valid(rec)):
        raise HTTPException(401, "Valid license required")
    try:
        n = int(payload.get("count") or 0)
    except Exception:
        n = 0
    if n <= 0:
        raise HTTPException(400, "count must be a positive integer")
    n = min(n, 500)  # safety cap per call
    try:
        uid, uname, _env = _identity_get_user()
    except Exception:
        uid = uname = ""
    usage_key = _eps_usage_key_for_license(lk, rec, uid, uname)
    limit = get_limit_for_record(rec)
    st = get_usage(usage_key)
    used = int(st.get("count") or 0)
    if limit is not None and used + n > int(limit):
        return JSONResponse(
            {"ok": False, "detail": "eps_daily_limit_exceeded",
             "used_today": used, "limit": int(limit),
             "remaining": max(0, int(limit) - used)},
            status_code=429,
        )
    from .eps_limits import increment as _eps_inc
    _eps_inc(usage_key, n)
    st = get_usage(usage_key)
    used = int(st.get("count") or 0)
    remaining = None if limit is None else max(0, int(limit) - used)
    return {
        "ok": True,
        "counted": n,
        "eps_daily_limit": limit,
        "eps_used_today": used,
        "eps_remaining_today": remaining,
        "source": "external_host",
    }


@app.get("/license/limits")
def license_limits(license_key: str):
    rec = find_license(license_key or "")
    if not rec or not is_valid(rec):
        raise HTTPException(401, "Valid license required")

    limit = get_limit_for_record(rec)
    usage_key = _eps_usage_key_for_license(license_key or "", rec)
    st = get_usage(usage_key)
    used = int(st.get("count") or 0)
    remaining = None if limit is None else max(0, int(limit) - used)

    return {
        "plan": rec.get("plan"),
        # feitelijk: per maand, maar client kan dit nog steeds lezen
        "eps_daily_limit": limit,
        "eps_used_today": used,
        "eps_remaining_today": remaining,
        "date": st.get("date"),          # bucket-key: 1e van de huidige maand
        "resets_at": next_reset_date(),  # NIEUW: 1e van de volgende maand
    }





@app.get("/")
def root(): return {"ok": True}


# ---------- /web/aspects (simplified for editor) ----------
@app.get("/web/aspects")
def web_aspects(request: Request, site: Optional[str] = Query(None), category_id: str = Query(...)):
    site, _ = _effective_site_and_currency(site, None)
    """
    Normalized response:
    {
      "aspects": [
        {
          "name": "Brand",
          "mode": "select" | "text",
          "required": false,
          "values": ["Nike","Adidas"],
          "aspectValues": [{"value":"Nike"},{"value":"Adidas"}]
        },
        ...
      ]
    }
    """
    raw = taxonomy_aspects(request=request, site=site, category_id=category_id) or {}
    # raw kan {"aspects":[...]} of direct [...] zijn
    src = raw.get("aspects") if isinstance(raw, dict) else raw
    site, _ = _effective_site_and_currency(site, None)
    aspects: list[dict] = []
    try:
        for a in (src or []):
            ac = a.get("aspectConstraint") or {}
            mode_raw = str(ac.get("aspectMode") or "").upper()
            is_select = mode_raw in ("SELECTION_ONLY", "SELECTION_ONLY_OR_FREE_TEXT")
            name = (a.get("localizedAspectName") or a.get("aspectName") or a.get("name") or "").strip()
            # haal waarden eruit ongeacht veldnaamvorm
            raw_vals = a.get("aspectValues") or a.get("values") or []
            vals = []
            for v in raw_vals:
                if isinstance(v, dict):
                    vals.append((v.get("localizedValue") or v.get("value") or v.get("applicableValue") or "").strip())
                else:
                    vals.append(str(v).strip())
            # dedupe + filter leeg
            vals = [s for i, s in enumerate(vals) if s and s not in vals[:i]]

            if not name:
                continue

            aspects.append({
                "name": name,
                "mode": "select" if is_select else "text",
                "required": bool(ac.get("aspectRequired")),
                "values": vals,
                "aspectValues": [{"value": s, "localizedValue": s} for s in vals],
            })
    except Exception:
        pass

    return {"aspects": aspects}

# Variatie-ondersteuning per categorie. Liep eerst via Trading
# GetCategoryFeatures; die call is door eBay uitgezet en antwoordt met
# HTTP 410 en een lege body (gemeten 14-08-2026: GeteBayDetails en GetUser
# geven op hetzelfde token en moment gewoon een nette foutmelding terug,
# GetCategoryFeatures komt niet eens bij de authenticatie aan). Daardoor
# kon de app niet meer vaststellen of een categorie variaties toestaat en
# kreeg de verkoper de melding "probeer over een paar minuten opnieuw",
# wat nooit ging werken. Sell Metadata heeft er een eigen veld voor.
_VARIATIONS_CACHE: Dict[str, Dict[str, Any]] = {}
_VARIATIONS_TTL = 6 * 3600


@app.get("/web/category/variations_enabled")
def web_category_variations_enabled(request: Request,
                                    site: str = Query("NL"),
                                    category_id: str = Query(...)):
    """Ondersteunt deze categorie listings met variaties?

    Voorkomt de verwarrende Trading-fout 'Variations are not available for
    this listing...' door het vooraf te vragen.
    """
    import time as _t
    ensure_valid_license_only(request)

    site, _ = _effective_site_and_currency(site, None)
    site = (site or "NL").upper()

    key = f"{site}|{category_id}"
    hit = _VARIATIONS_CACHE.get(key)
    if hit and (_t.time() - hit.get("_ts", 0)) < _VARIATIONS_TTL:
        return hit["data"]

    marketplace = MARKETPLACE_ID.get(site)
    if not marketplace:
        raise HTTPException(400, f"Unknown site {site}")

    env = (_get_user().get("env") or "PROD")
    path = f"/sell/metadata/v1/marketplace/{marketplace}/get_listing_structure_policies"
    r = _commerce_get(env, path, {"filter": "categoryIds:{" + str(category_id) + "}"})
    if r.status_code >= 400:
        raise HTTPException(r.status_code,
                            f"Could not check variation support for category {category_id} "
                            f"({site}): eBay returned HTTP {r.status_code}.")

    enabled = None
    for pol in (r.json() or {}).get("listingStructurePolicies") or []:
        if str(pol.get("categoryId") or "") == str(category_id):
            enabled = bool(pol.get("variationsSupported"))
            break

    if enabled is None:
        # Categorie zat niet in het antwoord. Niet blokkeren op iets dat we
        # niet weten; de client mag doorgaan en eBay beslist bij publiceren.
        return {"ok": True, "site": site, "category_id": str(category_id),
                "variations_enabled": True, "known": False}

    out = {"ok": True, "site": site, "category_id": str(category_id),
           "variations_enabled": enabled, "known": True}
    _VARIATIONS_CACHE[key] = {"_ts": _t.time(), "data": out}
    return out



# ---------- /web/policies ----------
def _sell_account_get(env: str, path: str, market: str) -> Dict[str, Any]:
    _refresh_user_if_needed(); u = _need_user(env)
    url = API_HOST[env] + path
    hdr = {"Authorization": f"Bearer {u['access_token']}", "Accept": "application/json"}
    params = {"marketplace_id": market}
    r = requests.get(url, headers=hdr, params=params, timeout=30)
    if r.status_code == 403:
        raise HTTPException(403, "Forbidden: need sell.account.readonly scope")
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text)
    return r.json() or {}



def _summarize_return_policy(p: dict) -> str:
    try:
        returns = p.get("returnsAccepted")
        if returns is False:
            return "No returns accepted"
        period = p.get("returnPeriod") or {}
        val = str(period.get("value") or "").strip()
        unit = (period.get("unit") or "").strip().lower()
        if unit == "day" or unit == "days":
            unit_txt = "days"
        elif unit == "month" or unit == "months":
            unit_txt = "months"
        else:
            unit_txt = unit if unit else "days"
        refund = (p.get("refundMethod") or "").replace("_"," ").title()
        payer = p.get("returnShippingCostPayer")
        if payer:
            payer_txt = "buyer" if str(payer).lower()=="buyer" else "seller"
        else:
            payer_txt = "buyer"
        parts = []
        if returns is not False:
            when = (f"{val} {unit_txt}" if val else "").strip()
            if when:
                parts.append(f"Returns within {when}")
            else:
                parts.append("Returns accepted")
        if refund:
            parts.append(f"Refund: {refund}")
        if payer_txt:
            parts.append(f"Return shipping by {payer_txt}")
        intl = p.get("internationalReturnPolicy") or {}
        if intl.get("returnsAccepted") is True and intl.get("returnPeriod"):
            ival = str(intl["returnPeriod"].get("value") or "")
            iunit = (intl["returnPeriod"].get("unit") or "").lower()
            if iunit in ("day","days"):
                iunit = "days"
            parts.append(f"International returns: {ival} {iunit}")
        return "; ".join(parts)
    except Exception:
        return ""

def _summarize_payment_policy(p: dict) -> str:
    try:
        immediate = p.get("immediatePay") or p.get("immediatePayment") or False
        pmts = p.get("paymentMethods") or []
        methods = ", ".join([m.get("paymentMethodType") or "" for m in pmts if m.get("paymentMethodType")]) or "eBay managed payments"
        return f"{methods}; Immediate payment {'required' if immediate else 'not required'}"
    except Exception:
        return ""

def _summarize_fulfillment_policy(p: dict) -> str:
    try:
        h = p.get("handlingTime") or {}
        hval = str(h.get("value") or "")
        hunit = (h.get("unit") or "").lower()
        if hval:
            ht = f"Handling time {hval} {('business days' if 'day' in hunit else hunit or 'days')}"
        else:
            ht = "Handling time: n/a"
        zones = []
        dom = p.get("shippingOptions") or p.get("domesticShippingOptions") or []
        if dom:
            names = [o.get("shippingService", {}).get("shippingServiceCode") or o.get("shippingService", {}).get("shippingCarrierCode") or o.get("shippingService") or "" for o in dom]
            names = [n for n in names if n]
            if names:
                zones.append(f"Domestic: {', '.join(names[:3])}" + ("…" if len(names)>3 else ""))
        intl = p.get("internationalShippingOptions") or []
        if intl:
            names = [o.get("shippingService", {}).get("shippingServiceCode") or o.get("shippingService") or "" for o in intl]
            names = [n for n in names if n]
            if names:
                zones.append(f"International: {', '.join(names[:3])}" + ("…" if len(names)>3 else ""))
        return "; ".join([ht] + zones) if zones else ht
    except Exception:
        return ""

@app.get("/web/policies")
def web_policies(
    request: Request,
    site: Optional[str] = Query(None),
    prefer_store: str = Query("rest"),
):
    # Zorg dat user/token ok is
    user_id, username, env_id, reg = _identity_get_user_full()
    env = (_get_user().get("env") or env_id or "PROD").upper()

    # 1) site bepalen: query-param leidend, anders fallback op reg, dan NL
    site = (site or "").strip().upper()
    if not site:
        site = (reg or "").strip().upper() or "NL"

    market = MARKETPLACE_ID.get(site)
    if not market:
        raise HTTPException(400, f"Unknown site {site}")
    import logging
    logging.warning("WEB_POLICIES: site=%r prefer_store=%r", site, prefer_store)
    out = {"payment": [], "return": [], "shipping": [], "store_categories": [], "defaults": {}}

    # ---- defaults uit config.json ----
    cfg = _read_json(SECRETS_FILE.parent / "config.json")
    out["defaults"] = {
        "shipping_profile": (cfg.get("shipping_profile") or "").strip() or None,
        "return_profile":   (cfg.get("return_profile")   or "").strip() or None,
        "payment_profile":  (cfg.get("payment_profile")  or "").strip() or None,
        "location":         (cfg.get("default_location") or cfg.get("location") or "").strip() or None,
        "condition_id":     (str(cfg.get("default_condition_id") or "").strip() or None),
    }

    
    # ---- Payment policies ----
    try:
        p = _sell_account_get(env, "/sell/account/v1/payment_policy", market)
        for it in p.get("paymentPolicies", []):
            entry = {"id": str(it.get("paymentPolicyId") or ""), "name": it.get("name") or ""}
            entry["text"] = _summarize_payment_policy(it)
            out["payment"].append(entry)
    except HTTPException:
        pass

    # ---- Return policies ----
    try:
        r = _sell_account_get(env, "/sell/account/v1/return_policy", market)
        for it in r.get("returnPolicies", []):
            entry = {"id": str(it.get("returnPolicyId") or ""), "name": it.get("name") or ""}
            entry["text"] = _summarize_return_policy(it)
            out["return"].append(entry)
    except HTTPException:
        pass

    # ---- Fulfillment (shipping) policies ----
    try:
        f = _sell_account_get(env, "/sell/account/v1/fulfillment_policy", market)
        for it in f.get("fulfillmentPolicies", []):
            entry = {"id": str(it.get("fulfillmentPolicyId") or ""), "name": it.get("name") or ""}
            entry["text"] = _summarize_fulfillment_policy(it)
            out["shipping"].append(entry)
    except HTTPException:
        pass
    cats = []
    pref = (prefer_store or "rest").lower().strip()
    if pref == "trading":
        try:
            cats = _trading_getstore(request, env, site.upper())
        except HTTPException:
            cats = []
    else:
        try:
            cats = _rest_store_categories(env)
        except HTTPException:
            cats = []
        if not cats:
            try:
                cats = _trading_getstore(request, env, site.upper())
            except HTTPException:
                cats = []
    out["store_categories"] = cats
    return out


# ── Shipping services lookup via GeteBayDetails ──────────────────────────
# Cached because the catalogue rarely changes; eBay throttles repeated
# GeteBayDetails calls otherwise.
_SHIPPING_SERVICES_CACHE: Dict[tuple, Dict[str, Any]] = {}
_SHIPPING_SERVICES_TTL = 24 * 3600


def _fetch_shipping_service_details_cached(env: str, site: str) -> List[Dict[str, Any]]:
    """Hit Trading API GeteBayDetails with site=seller_site and return
    a parsed list of ShippingServiceDetails entries. Cached 24h per
    (env, site) — eBay's catalogue is stable."""
    key = (env, site.upper())
    entry = _SHIPPING_SERVICES_CACHE.get(key)
    if entry and (time.time() - entry.get("_ts", 0)) < _SHIPPING_SERVICES_TTL:
        return entry["data"]

    xml = ('<?xml version="1.0" encoding="utf-8"?>'
           '<GeteBayDetailsRequest xmlns="urn:ebay:apis:eBLBaseComponents">'
           '<DetailName>ShippingServiceDetails</DetailName>'
           '</GeteBayDetailsRequest>')

    # Geen stille fallback op "0" (US): een onbekende site leverde eerder
    # de Amerikaanse catalogus op zonder dat iemand dat zag.
    site_id = TRADING_SITE_ID.get(site.upper())
    if not site_id:
        raise HTTPException(400, f"Unknown site {site}")
    _refresh_user_if_needed()
    u = _need_user(env)
    headers = {
        "X-EBAY-API-CALL-NAME": "GeteBayDetails",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }
    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text[:500])

    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.content)
    out: List[Dict[str, Any]] = []
    for sd in root.findall("e:ShippingServiceDetails", ns):
        svc = (sd.findtext("e:ShippingService", default="", namespaces=ns) or "").strip()
        if not svc:
            continue
        desc = (sd.findtext("e:Description", default="", namespaces=ns) or svc).strip()
        valid = (sd.findtext("e:ValidForSellingFlow", default="", namespaces=ns) or "").strip().lower() == "true"
        intl = (sd.findtext("e:InternationalService", default="false", namespaces=ns) or "false").strip().lower() == "true"
        cat = (sd.findtext("e:ShippingCategory", default="", namespaces=ns) or "").strip()
        out.append({
            "service": svc,
            "description": desc,
            "valid": valid,
            "international": intl,
            "category": cat,
        })

    _SHIPPING_SERVICES_CACHE[key] = {"_ts": time.time(), "data": out}
    return out


@app.get("/web/shipping_services")
def web_shipping_services(request: Request, site: Optional[str] = Query(None)):
    """Return de shipping-service tokens die geldig zijn als *domestic*
    service op de marketplace waar de advertentie heen gaat.

    ``site`` = doelmarketplace (bv. ``UK``). De gekozen waarde belandt in
    ``<ShippingServiceOptions><ShippingService>`` (zie
    ``_inline_shipping_xml``) en dat is bij eBay uitsluitend het
    binnenlandse slot. Een internationale token daarin geeft altijd
    fout 21916503 "is not a valid domestic Shipping Service" — dus die
    horen hier niet in de lijst, ook niet bij cross-border.

    De catalogus wordt opgehaald voor de doelsite, want eBay valideert de
    token tegen de site waarop gelist wordt, niet tegen het land van de
    verkoper. Bij cross-border blijft "Other" de veilige keuze: de
    carrier-services van het doelland eisen meestal een lokaal adres.
    """
    user_id, username, env_id, reg = _identity_get_user_full()
    env = (_get_user().get("env") or env_id or "PROD").upper()
    seller_site = _normalize_site_code(reg) or "NL"
    dest_site = _normalize_site_code(site or "") or seller_site
    cross_border = (seller_site != dest_site)

    try:
        services = _fetch_shipping_service_details_cached(env, dest_site)
    except HTTPException:
        services = []

    out = []
    for s in services:
        if not s.get("valid"):
            continue
        if s.get("international"):
            continue
        out.append({
            "service": s["service"],
            "description": s["description"],
            "category": s.get("category", ""),
        })

    # eBay's "Other" wordt overal geaccepteerd. Zet 'm altijd bovenaan als
    # veilige keuze, ook als de catalogus 'm ergens in het midden teruggaf.
    out = [x for x in out if x["service"] != "Other"]
    out.insert(0, {"service": "Other", "description": "Other", "category": ""})

    return {
        "seller_site": seller_site,
        "dest_site": dest_site,
        "cross_border": cross_border,
        "services": out,
    }


@app.get("/web/policies/status")
def web_policies_status(request: Request, site: Optional[str] = Query(None)):
    """Lightweight check: does the connected eBay account have business
    policies (any of shipping / payment / return)?

    The client uses this to decide between the "all-inclusive" path
    (listing-settings profile required, policy dropdowns) and the
    "quick post" path (no profile required, inline policy fields in
    the web editor)."""
    user_id, username, env_id, reg = _identity_get_user_full()
    env = (_get_user().get("env") or env_id or "PROD").upper()

    site = (site or "").strip().upper() or (reg or "").strip().upper() or "NL"
    market = MARKETPLACE_ID.get(site)
    if not market:
        raise HTTPException(400, f"Unknown site {site}")

    has_shipping = has_payment = has_return = False
    try:
        f = _sell_account_get(env, "/sell/account/v1/fulfillment_policy", market)
        has_shipping = bool(f.get("fulfillmentPolicies") or [])
    except HTTPException:
        pass
    try:
        p = _sell_account_get(env, "/sell/account/v1/payment_policy", market)
        has_payment = bool(p.get("paymentPolicies") or [])
    except HTTPException:
        pass
    try:
        r = _sell_account_get(env, "/sell/account/v1/return_policy", market)
        has_return = bool(r.get("returnPolicies") or [])
    except HTTPException:
        pass

    return {
        "site": site,
        "has_shipping": has_shipping,
        "has_payment": has_payment,
        "has_return": has_return,
        "has_any": (has_shipping or has_payment or has_return),
        "has_all": (has_shipping and has_payment and has_return),
    }


# ---------- Draft helper ----------
def _draft_bucket_for_lk(raw_lk: str) -> str:
    raw = str(raw_lk or "").strip()
    if not raw:
        return "_anon"
    digest = hmac.new(_LK_HMAC_SECRET, raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"lk_{digest[:48]}"

def _draft_dirs_for_lk(raw_lk: str) -> List[Path]:
    dirs: List[Path] = []
    dirs.append(_DRAFTS_BASE / _draft_bucket_for_lk(raw_lk))
    if raw_lk and _SAFE_SEGMENT_RE.fullmatch(raw_lk):
        # legacy/plain folder support (read path only)
        dirs.append(_DRAFTS_BASE / raw_lk)
    return dirs

def _latest_draft_file_for_lk(raw_lk: str) -> Optional[Path]:
    for d in _draft_dirs_for_lk(raw_lk):
        if not d.exists():
            continue
        cands = sorted((p for p in d.glob("draft_*.json") if p.is_file()), key=lambda x: x.stat().st_mtime, reverse=True)
        if not cands:
            cands = sorted((p for p in d.glob("*.json") if p.is_file()), key=lambda x: x.stat().st_mtime, reverse=True)
        if cands:
            return cands[0]
    return None

@app.get("/web/draft")
def web_draft(request: Request, path: Optional[str] = None):
    # Hardening: ignore arbitrary path input and always scope to caller license.
    lk = (getattr(request.state, "license_key", "") or request.headers.get("X-License-Key") or request.query_params.get("lk") or "").strip()
    p = _latest_draft_file_for_lk(lk)
    if not p:
        return {"rows": [], "path": ""}
    if p.exists():
        try:
            js = json.loads(p.read_text(encoding="utf-8"))
            site     = (js.get("site") or "NL").upper()
            currency = (js.get("currency") or "EUR").upper()
            rows = js.get("rows")
            return {
                "rows": rows,
                "site": site,
                "currency": currency,
                "path": p.name,
            }
        except Exception as e:
            raise HTTPException(400, f"Draft parse error: {e}")
    return {"rows": [], "path": ""}

# --- veilige opslag helper ---
def _safe_json_save(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

# --- Fallback upload endpoint(s) ---
@app.post("/web/draft/upload")
async def web_draft_upload(request: Request, body: dict = Body(...)):
    """
    Ontvangt {"rows":[...], "site":"NL", "currency":"EUR"} en slaat op als:
    server/drafts/<license>/draft_YYYYmmdd_HHMMSS.json
    (license uit header X-License-Key of body.license_key; default: _anon)
    """
    lk = (getattr(request.state, "license_key", "") or request.headers.get("X-License-Key") or body.get("license_key") or "").strip()
    if not lk:
        raise HTTPException(status_code=403, detail="License required")
    bucket = _draft_bucket_for_lk(lk)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = (_DRAFTS_BASE / bucket / f"draft_{ts}.json")
    try:
        payload = dict(body or {})
        payload.pop("license_key", None)
        _safe_json_save(out_path, payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kon draft niet opslaan: {e}")
    return {"ok": True, "path": out_path.name, "bucket": bucket}


# ---------- Trading helpers (AddItem / AddFixedPriceItem) ----------
import requests
import xml.etree.ElementTree as ET

def _identity_get_user() -> tuple[str, str, str]:
    """
    Retourneert (userId, username, env) via Commerce Identity API.
    Vereist user access token met scope 'commerce.identity.readonly'.
    """
    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    base = "https://apiz.ebay.com" if env == "PROD" else "https://apiz.sandbox.ebay.com"
    try:
        r = requests.get(
            base + "/commerce/identity/v1/user/",
            headers={"Authorization": f"Bearer {u['access_token']}"},
            timeout=12,
        )
        # Geen (geldige) login of scope? Geef leeg terug; caller beslist.
        if r.status_code in (401, 403):
            return "", "", env
        r.raise_for_status()
        j = r.json() or {}
        return ( (j.get("userId") or "").strip(),
                 (j.get("username") or "").strip(),
                 env )
    except Exception:
        return "", "", env

def _identity_get_user_full() -> tuple[str, str, str, str]:
    """return (userId, username, env, site_code)

    De vierde waarde is de site-code van het eBay-account ('UK', 'US',
    'NL', ...), niet de ruwe registrationMarketplaceId ('EBAY_GB'). Alle
    callers gebruiken hem als site-code, dus normaliseren gebeurt hier."""
    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    base = "https://apiz.ebay.com" if env == "PROD" else "https://apiz.sandbox.ebay.com"
    user_id = username = reg = ""
    try:
        r = requests.get(
            base + "/commerce/identity/v1/user/",
            headers={"Authorization": f"Bearer {u['access_token']}"},
            timeout=12,
        )
        if r.ok:
            j = r.json() or {}
            user_id = (j.get("userId") or "").strip()
            username = (j.get("username") or "").strip()
            reg = _normalize_site_code(j.get("registrationMarketplaceId") or "")
    except Exception:
        pass
    return user_id, username, env, reg

def _trading_get_username() -> str:
    """Trading GetUser fallback: haalt de (wijzigbare) UserID/username op."""
    _refresh_user_if_needed()
    u = _need_user()
    headers = {
        "X-EBAY-API-CALL-NAME": "GetUser",
        "X-EBAY-API-SITEID": "0",
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }
    xml = "<?xml version='1.0' encoding='utf-8'?><GetUserRequest xmlns='urn:ebay:apis:eBLBaseComponents'/>"
    r0 = requests.post(TRADING_ENDPOINT[u["env"]], headers=headers, data=xml.encode("utf-8"), timeout=30)
    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    try:
        root = ET.fromstring(r0.text)
        return (root.findtext("e:User/e:UserID", default="", namespaces=ns) or "").strip()
    except Exception:
        return ""


def _num(v, default=None):
    try:
        if v is None or v == "":
            return default
        return float(v)
    except Exception:
        return default

def _condition_to_id(cond: str) -> str:
    if not cond: return ""
    m = re.match(r"(\d+)", str(cond))
    return m.group(1) if m else str(cond)

def _seller_profiles_xml(row: Dict[str, Any]) -> str:
    # Inline-policies path wins over any stale profile-IDs left over in
    # the row (e.g. the user has NL policies in cfg but publishes on DE
    # where they have none — _build_item_xml must emit <ShippingDetails>
    # inline, not eBay-invalid NL profile-IDs as <SellerProfiles>).
    if row.get("inline_policies"):
        return ""
    ship = str(row.get("shipping_profile") or "").strip()
    pay  = str(row.get("payment_profile") or "").strip()
    ret  = str(row.get("return_profile") or "").strip()
    if not (ship or pay or ret):
        return ""
    seg = ["<SellerProfiles>"]
    if ship: seg += [f"<SellerShippingProfile><ShippingProfileID>{ship}</ShippingProfileID></SellerShippingProfile>"]
    if pay:  seg += [f"<SellerPaymentProfile><PaymentProfileID>{pay}</PaymentProfileID></SellerPaymentProfile>"]
    if ret:  seg += [f"<SellerReturnProfile><ReturnProfileID>{ret}</ReturnProfileID></SellerReturnProfile>"]
    seg += ["</SellerProfiles>"]
    return "\n".join(seg)


# ---------------------------------------------------------------------------
# Inline policies (Quick-post path for sellers without business policies)
# ---------------------------------------------------------------------------
# Sellers without eBay Business Policies need <ShippingDetails> /
# <ReturnPolicy> / <DispatchTimeMax> emitted inline. _build_item_xml falls
# back to these helpers when _seller_profiles_xml returns "".
#
def _inline_shipping_xml(row: Dict[str, Any], site_code: str, currency: str) -> str:
    """Build <ShippingDetails> for sellers without business policies.

    Default service is "Other": eBay rejects domestic tokens like
    USPSGround when the seller's account country differs from the
    marketplace (e.g. NL seller listing on US site). "Other" is
    universally accepted as a cross-border fallback. The web editor
    dropdown also leads with "Other" for the same reason.
    """
    service = str(row.get("shipping_service") or "").strip() or "Other"
    try:
        cost = float(row.get("shipping_cost") or 0.0)
    except Exception:
        cost = 0.0
    free = bool(row.get("free_shipping")) or cost <= 0.0
    seg = [
        "<ShippingDetails>",
        "<ShippingType>Flat</ShippingType>",
        "<ShippingServiceOptions>",
        "<ShippingServicePriority>1</ShippingServicePriority>",
        f"<ShippingService>{service}</ShippingService>",
        f'<ShippingServiceCost currencyID="{currency}">{cost:.2f}</ShippingServiceCost>',
        f"<FreeShipping>{'true' if free else 'false'}</FreeShipping>",
        "</ShippingServiceOptions>",
        "</ShippingDetails>",
    ]
    return "\n".join(seg)


def _inline_return_policy_xml(row: Dict[str, Any]) -> str:
    """Build <ReturnPolicy> for sellers without business policies.

    Defaults aim at EU compliance (returns accepted, 30 days, money back).
    """
    accepted = row.get("returns_accepted")
    if accepted is None:
        accepted = True
    if not accepted:
        return (
            "<ReturnPolicy>"
            "<ReturnsAcceptedOption>ReturnsNotAccepted</ReturnsAcceptedOption>"
            "</ReturnPolicy>"
        )
    try:
        days = int(row.get("return_period_days") or 30)
    except Exception:
        days = 30
    if days <= 14:
        within = "Days_14"
    elif days <= 30:
        within = "Days_30"
    else:
        within = "Days_60"
    payer = str(row.get("return_shipping_paid_by") or "Buyer").strip().lower()
    payer_xml = "Seller" if payer.startswith("s") else "Buyer"
    seg = [
        "<ReturnPolicy>",
        "<ReturnsAcceptedOption>ReturnsAccepted</ReturnsAcceptedOption>",
        f"<ReturnsWithinOption>{within}</ReturnsWithinOption>",
        f"<ShippingCostPaidByOption>{payer_xml}</ShippingCostPaidByOption>",
        "<RefundOption>MoneyBack</RefundOption>",
        "</ReturnPolicy>",
    ]
    return "\n".join(seg)


def _inline_dispatch_time_xml(row: Dict[str, Any]) -> str:
    try:
        days = int(row.get("dispatch_time_max") or 3)
    except Exception:
        days = 3
    if days < 0:
        days = 0
    if days > 40:
        days = 40
    return f"<DispatchTimeMax>{days}</DispatchTimeMax>"


def _row_wants_inline_policies(row: Dict[str, Any]) -> bool:
    """Strict opt-in: inline policies only fire when the row carries an
    explicit ``inline_policies`` flag (set by the client when the seller
    has no business policies on the active site).

    Why opt-in and not "any row without profile-IDs": a misconfigured
    existing user with policies but a half-filled listing-settings
    profile would otherwise publish silently with default €0 shipping
    instead of getting eBay's "ShippingDetails required" rejection."""
    return bool(row.get("inline_policies"))



def _storefront_xml(row: Dict[str, Any]) -> str:
    """
    Ondersteunt zowel 1e als 2e winkelcategorie:
      - primaire keys: store_category / store_category_id / shop_id
      - secundaire keys: store_category_2 / store_category2 / shop_id_2
    """
    store_cat1 = str(row.get("store_category") or row.get("store_category_id") or row.get("shop_id") or "").strip()
    store_cat2 = str(row.get("store_category_2") or row.get("store_category2") or row.get("shop_id_2") or "").strip()
    if not (store_cat1 or store_cat2):
        return ""
    seg = ["<Storefront>"]
    if store_cat1:
        seg.append(f"<StoreCategoryID>{store_cat1}</StoreCategoryID>")
    if store_cat2:
        seg.append(f"<StoreCategory2ID>{store_cat2}</StoreCategory2ID>")
    seg.append("</Storefront>")
    return "\n".join(seg)





# ─────────────────────────────────────────────────────────────────────────
# Aspect canonicalization
# ─────────────────────────────────────────────────────────────────────────
# eBay's Trading API is case-sensitive on aspect values. A user-typed
# "Near Mint or Better" is rejected even though the canonical eBay value
# is "Near mint or better" (lowercase) — eBay returns a misleading
# "Card Condition (40001) is a required field" error in that case.
#
# We cache the allowed-values list per (site, category) and normalize
# both the aspect name (drop "C:" prefix) and the value (case-insensitive
# match) before building the XML.
_ASPECTS_NORM_CACHE: Dict[str, Dict[str, Any]] = {}
_ASPECTS_NORM_CACHE_TTL = 6 * 3600  # 6 hours

# ─────────────────────────────────────────────────────────────────────────
# ConditionDescriptors (structured condition aspects)
# ─────────────────────────────────────────────────────────────────────────
# eBay added a "ConditionDescriptors" system parallel to the old
# ItemSpecifics aspects. For some categories (notably trading cards) the
# new structured descriptors are *required* at publish time even though
# the old ItemSpecifics aspect with the same display name is still
# advertised by Sell Metadata as merely optional. Trading API rejects
# without the descriptor with a misleading "is a required field" error.
#
# Reference (Ungraded trading cards, ConditionID 4000):
#   ConditionDescriptors.Name=40001  (Card Condition descriptor)
#   ConditionDescriptors.Value=400010..400013  (the four allowed values)
#
# We map the seller's free-text Card Condition value -> Value-ID by
# lowercase lookup, then emit the descriptor XML alongside ConditionID.

# value-name (lowercase) -> Trading API value-ID, per descriptor name-ID
# Hier stonden twee vaste tabellen: welke categorie een descriptor eist, en
# welke waarde-naam bij welk value-ID hoort. Allebei weg, want ze konden niet
# kloppen. Gemeten op 14-08-2026 tegen de live metadata:
#   - 183454 heeft andere value-ID's dan 261328 (400015-400017 vs 400011-400013)
#   - categorie 37566 verschilt zelfs per marketplace: UK gebruikt de ene reeks,
#     US de andere
#   - 183050 ontbrak in de tabel terwijl eBay er wel een descriptor eist
#   - 212 stond erin maar komt in de lijst van eBay niet voor
#   - graded kaarten (2750) waren onmogelijk, want de Grader- en Grade-waarden
#     stonden nergens
#   - op de Amerikaanse marketplace eisen 273 categorieen een descriptor,
#     waarvan 262 muntcategorieen die hier volledig ontbraken
# Alles komt nu per categorie van eBay zelf.
# Waarom live: de waarde-ID's verschillen per categorie én per marketplace.
# Categorie 37566 gebruikt op UK de reeks 400011-400013 en op US 400015-400017,
# en 183454 wijkt op beide af van 261328. Een vaste tabel kan dus niet kloppen.
# Op UK eisen 4 categorieen een descriptor, op US 273 (waarvan 262 munten).
_COND_DESCRIPTORS_CACHE: Dict[str, Dict[str, Any]] = {}
_COND_DESCRIPTORS_TTL = 6 * 3600


def _fetch_condition_descriptors(site: str, category_id: str) -> List[Dict[str, Any]]:
    """Haal de ConditionDescriptors voor een categorie op via Sell Metadata.

    Dezelfde call die _taxonomy_conditions al doet; die leest alleen de
    conditiewaarden uit en negeert het descriptor-deel."""
    import time as _t
    key = f"{(site or '').upper()}|{category_id}"
    hit = _COND_DESCRIPTORS_CACHE.get(key)
    if hit and (_t.time() - hit.get("_ts", 0)) < _COND_DESCRIPTORS_TTL:
        return hit["data"]

    marketplace = MARKETPLACE_ID.get((site or "").upper())
    if not marketplace:
        raise HTTPException(400, f"Unknown site {site}")
    env = (_get_user().get("env") or "PROD")
    path = f"/sell/metadata/v1/marketplace/{marketplace}/get_item_condition_policies"
    r = _commerce_get(env, path, {"filter": "categoryIds:{" + str(category_id) + "}"})
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text[:300])

    out: List[Dict[str, Any]] = []
    for pol in (r.json() or {}).get("itemConditionPolicies") or []:
        # De filter wordt door eBay soms genegeerd; pak alleen onze categorie.
        if str(pol.get("categoryId") or "") != str(category_id):
            continue
        for cond in pol.get("itemConditions") or []:
            for d in cond.get("conditionDescriptors") or []:
                con = d.get("conditionDescriptorConstraint") or {}
                out.append({
                    "condition_id": str(cond.get("conditionId") or ""),
                    "id": str(d.get("conditionDescriptorId") or ""),
                    "name": str(d.get("conditionDescriptorName") or ""),
                    "required": (str(con.get("usage") or "").upper() == "REQUIRED"),
                    "mode": str(con.get("mode") or ""),
                    "values": [
                        {"id": str(v.get("conditionDescriptorValueId") or ""),
                         "name": str(v.get("conditionDescriptorValueName") or "")}
                        for v in (d.get("conditionDescriptorValues") or [])
                    ],
                })

    _COND_DESCRIPTORS_CACHE[key] = {"_ts": _t.time(), "data": out}
    return out


@app.get("/web/condition_descriptors")
def web_condition_descriptors(request: Request,
                              site: str = Query(None),
                              category_id: str = Query(...)):
    """Welke ConditionDescriptors eist eBay voor deze categorie?

    De web editor gebruikt dit om per rij een kolom te tonen voor elk verplicht
    descriptorveld. Zonder die kolom kon de verkoper de waarde nergens invullen
    en faalde publiceren op "Card Condition (40001) is a required field".

    De verkoper kiest een naam, de editor bewaart het bijbehorende value-ID.
    Zo hoeft er nergens een naam terug naar een ID vertaald te worden.
    """
    site, _ = _effective_site_and_currency(site, None)
    try:
        descriptors = _fetch_condition_descriptors(site, category_id)
    except HTTPException:
        descriptors = []
    return {"site": site, "category_id": str(category_id), "descriptors": descriptors}


def _build_condition_descriptors_xml(row: Dict[str, Any], category_id: str,
                                     site: str = "") -> str:
    """Bouw het <ConditionDescriptors>-blok voor categorieen die dat eisen.

    De web editor levert per rij ``condition_descriptors`` aan als
    ``{descriptor_id: value_id}``, met ID's die rechtstreeks van eBay komen.
    Er wordt hier dus niets meer van naam naar ID vertaald: dat ging mis omdat
    dezelfde waarde per categorie en per marketplace een ander ID heeft.

    Oudere drafts droegen de waarde als naam mee in de item specifics. Die
    worden nog omgezet, maar via de live metadata en niet via een vaste tabel.
    """
    pairs: List[tuple[str, str]] = []

    own = row.get("condition_descriptors")
    if isinstance(own, str):
        try:
            own = json.loads(own)
        except Exception:
            own = None
    if isinstance(own, dict):
        for k, v in own.items():
            name_id = re.sub(r"\D", "", str(k or ""))
            value_id = re.sub(r"\D", "", str(v or ""))
            if name_id and value_id:
                pairs.append((name_id, value_id))

    if not pairs:
        pairs = _legacy_descriptor_pairs_from_aspects(row, category_id, site)

    if not pairs:
        return ""
    body = "".join(
        f"<ConditionDescriptor><Name>{n}</Name><Value>{v}</Value></ConditionDescriptor>"
        for n, v in pairs
    )
    return "<ConditionDescriptors>" + body + "</ConditionDescriptors>"


def _legacy_descriptor_pairs_from_aspects(row: Dict[str, Any], category_id: str,
                                          site: str) -> List[tuple[str, str]]:
    """Terugval voor drafts van voor de live-descriptors: de waarde staat daar
    als naam in de item specifics ("Card Condition" -> "Poor"). Zoek naam en
    waarde op in de metadata van eBay zelf."""
    specs = row.get("item_specifics") or row.get("aspects") or {}
    if isinstance(specs, str):
        try:
            specs = json.loads(specs)
        except Exception:
            return []
    if isinstance(specs, list):
        flat: Dict[str, Any] = {}
        for nv in specs:
            if isinstance(nv, dict):
                n = (nv.get("Name") or nv.get("name") or "").strip()
                v = nv.get("Value") or nv.get("value")
                if isinstance(v, list) and v:
                    v = v[0]
                if n:
                    flat[n] = v
        specs = flat
    if not isinstance(specs, dict) or not specs:
        return []

    by_name: Dict[str, str] = {}
    for k, v in specs.items():
        kk = str(k or "").strip()
        if kk.lower().startswith("c:"):
            kk = kk[2:].strip()
        if kk and v not in (None, ""):
            by_name[kk.lower()] = str(v).strip()
    if not by_name:
        return []

    cond_raw = str(row.get("condition_id") or row.get("ConditionID") or "").strip()
    m = re.search(r"\d+", cond_raw)
    cond_id = m.group(0) if m else ""

    try:
        descriptors = _fetch_condition_descriptors(site or "", str(category_id or ""))
    except Exception:
        return []

    out: List[tuple[str, str]] = []
    for d in descriptors:
        if cond_id and d.get("condition_id") and d["condition_id"] != cond_id:
            continue
        wanted = by_name.get(str(d.get("name") or "").lower())
        if not wanted:
            continue
        for val in d.get("values") or []:
            if str(val.get("name") or "").lower() == wanted.lower():
                out.append((str(d.get("id")), str(val.get("id"))))
                break
    return out

# Trading-API-canonical aspect values that override eBay's own Taxonomy API
# output. eBay's Taxonomy returns "Near Mint or Better" (capitalised) but the
# Trading API rejects that exact value and only accepts "Near mint or better"
# (lowercase). This map fixes such inconsistencies for known niche categories.
# Format: { category_id: { aspect_name (lowercase): [canonical values...] } }
_ASPECT_VALUE_OVERRIDES: Dict[str, Dict[str, List[str]]] = {
    # Sports Trading Cards — Singles
    "261328": {
        "card condition": [
            "Near mint or better",
            "Excellent",
            "Very Good",
            "Good",
            "Poor",
            "Authenticated",
            "Graded",
        ],
    },
    # Trading Card Singles (alt cat id)
    "212": {
        "card condition": [
            "Near mint or better",
            "Excellent",
            "Very Good",
            "Good",
            "Poor",
            "Authenticated",
            "Graded",
        ],
    },
}

def _fetch_aspects_for_canonicalization(site: str, category_id: str) -> Dict[str, Dict[str, Any]]:
    """Returns a lookup map: {aspect_name_lower: {"name": canonical, "values": {value_lower: canonical}}}.
    Empty dict on any failure — callers must fall back to passing values through unchanged."""
    import time
    key = f"{(site or '').upper()}|{category_id}"
    rec = _ASPECTS_NORM_CACHE.get(key)
    if rec and (time.time() - rec.get("_ts", 0)) < _ASPECTS_NORM_CACHE_TTL:
        return rec.get("data") or {}

    out: Dict[str, Dict[str, Any]] = {}
    try:
        site_eff = (site or "US").upper()
        marketplace = MARKETPLACE_ID.get(site_eff)
        if not marketplace:
            return {}
        env = (_get_user().get("env") or "PROD")
        r1 = _commerce_get(env, "/commerce/taxonomy/v1/get_default_category_tree_id", {"marketplace_id": marketplace})
        if r1.status_code >= 400:
            return {}
        tree_id = (r1.json() or {}).get("categoryTreeId")
        if not tree_id:
            return {}
        r2 = _commerce_get(env, f"/commerce/taxonomy/v1/category_tree/{tree_id}/get_item_aspects_for_category", {"category_id": category_id})
        if r2.status_code >= 400:
            return {}
        raw = r2.json() or {}
        for a in (raw.get("aspects") or []):
            nm = (a.get("localizedAspectName") or a.get("aspectName") or a.get("name") or "").strip()
            if not nm:
                continue
            val_map: Dict[str, str] = {}
            for v in (a.get("aspectValues") or []):
                if isinstance(v, dict):
                    cv = (v.get("localizedValue") or v.get("value") or "").strip()
                else:
                    cv = str(v).strip()
                if cv:
                    val_map[cv.lower()] = cv
            out[nm.lower()] = {"name": nm, "values": val_map}

        # Apply hardcoded overrides for known eBay Trading-API quirks (e.g.
        # Taxonomy returns "Near Mint or Better" but Trading wants
        # "Near mint or better"). Override REPLACES the values map for the
        # specific aspect — taxonomy result still provides the canonical name.
        ov = _ASPECT_VALUE_OVERRIDES.get(str(category_id))
        if ov:
            for aspect_lower, values in ov.items():
                rec_map = out.get(aspect_lower)
                if not rec_map:
                    rec_map = {"name": aspect_lower.title(), "values": {}}
                    out[aspect_lower] = rec_map
                rec_map["values"] = {str(v).strip().lower(): str(v).strip() for v in values if str(v).strip()}

        _ASPECTS_NORM_CACHE[key] = {"data": out, "_ts": time.time()}
    except Exception:
        return {}
    return out


def _canonicalize_specifics(specs, site: str, category_id: str):
    """Normalize item_specifics:
    - Strip 'C:' prefix from names
    - Match name + value case-insensitively against eBay's allowed-values list
    - Return canonical name and value
    Accepts dict OR list-of-NameValueList. Returns dict.
    Falls through unchanged on any cache miss / exception."""
    if not specs:
        return specs
    aspects_map = _fetch_aspects_for_canonicalization(site, category_id) if (site and category_id) else {}

    # Normalize input shape to a list of (name, value) pairs
    items: List[Tuple[str, Any]] = []
    if isinstance(specs, dict):
        items = list(specs.items())
    elif isinstance(specs, list):
        for nv in specs:
            if not isinstance(nv, dict):
                continue
            n = nv.get("Name") or nv.get("name")
            v = nv.get("Value") or nv.get("value") or nv.get("values")
            if n is not None:
                items.append((n, v))
    else:
        return specs

    out: Dict[str, Any] = {}
    for raw_name, val in items:
        name_clean = str(raw_name or "").strip()
        if name_clean.lower().startswith("c:"):
            name_clean = name_clean[2:].strip()
        if not name_clean:
            continue
        info = aspects_map.get(name_clean.lower())
        canon_name = info["name"] if info else name_clean

        def _canon_value(s: str) -> str:
            sv = str(s or "").strip()
            if not sv:
                return sv
            if info and info.get("values"):
                return info["values"].get(sv.lower(), sv)
            return sv

        if isinstance(val, list):
            new_vals = [v for v in (_canon_value(x) for x in val) if v]
            if new_vals:
                out[canon_name] = new_vals
        else:
            cv = _canon_value(val)
            if cv:
                out[canon_name] = cv
    return out


def _itemspecifics_xml(row):
    specs = row.get("item_specifics") or row.get("ItemSpecifics") or row.get("aspects") or row.get("Aspects") or []

    # 0) JSON-string -> parse
    if isinstance(specs, str):
        s = specs.strip()
        if s and s[0] in "[{":
            try:
                specs = json.loads(s)
            except Exception:
                specs = []  # onleesbaar? overslaan
        else:
            specs = []

    # 1) dict -> lijst van dicts
    if isinstance(specs, dict):
        norm = []
        for k, v in specs.items():
            if v is None or v == "":
                continue
            if isinstance(v, (list, tuple)):
                vals = [str(x) for x in v if x is not None and str(x) != ""]
            else:
                vals = [str(v)]
            if not vals:
                continue
            norm.append({"Name": str(k), "Value": vals})
        specs = norm

    # 2) lijst: filter alleen dictachtige entries; strings/anders overslaan
    if not isinstance(specs, list):
        return ""  # niets bruikbaars

    out = []
    for s in specs:
        if not isinstance(s, dict):
            continue
        name = _x(str(s.get("Name") or s.get("name") or ""), _ESC)
        if not name:
            continue
        if name.lower().startswith("c:"):
            name = name[2:].strip()
        vals = s.get("Value") or s.get("values") or s.get("value")
        if vals is None or vals == "":
            continue
        if not isinstance(vals, (list, tuple)):
            vals = [vals]
        vals = [ _x(str(v), _ESC) for v in vals if v is not None and str(v) != "" ]
        if not vals:
            continue
        nv = "<NameValueList><Name>"+name+"</Name>" + "".join(f"<Value>{v}</Value>" for v in vals) + "</NameValueList>"
        out.append(nv)

    if not out:
        return ""
    return "<ItemSpecifics>" + "".join(out) + "</ItemSpecifics>"


@APP.get("/license/switch/check")
def license_switch_check(request: Request):
    lk = (request.headers.get("X-License-Key") or request.cookies.get("license_key")
          or request.query_params.get("lk") or "").strip()
    if not lk:
        raise HTTPException(401, "Valid license required")
    rec = find_license(lk)
    if not (rec and is_valid(rec)):
        raise HTTPException(401, "Valid license required")

    # Huidige identity
    uid, uname, _env = _identity_get_user()

    # Gebonden sets + usernamen uit id-map
    bound_ids   = set(rec.get("allowed_identity_ids") or [])
    bound_users = set(rec.get("allowed_ebay_users") or [])
    meta        = rec.get("identity_usernames") or {}   # id -> username
    unames_of_ids = { (meta.get(i) or "").strip() for i in bound_ids if meta.get(i) }
    bound_usernames_merged = sorted(u for u in (bound_users | unames_of_ids) if u)

    # Eff. max + slots (zonder dubbel tellen)
    eff_max     = _effective_max_accounts(rec)          # None = onbeperkt
    eff_max_int = None if eff_max is None else int(eff_max)
    slots_used  = _slots_used(rec)                      # helper die id+username dedupet

    base = {
        "bound_identity_ids": list(bound_ids),
        "bound_usernames": bound_usernames_merged,
        "candidate": {"userId": uid, "username": uname},
        "max_accounts_effective": eff_max_int,
        "slots_used": slots_used,
    }

    # Al gebonden aan deze license? → geen switch
    if (uid and uid in bound_ids) or (uname and uname in bound_usernames_merged):
        info = _cooldown_info(rec); info.update(base)
        info["can_switch"] = False
        info["reason"] = "already_bound"
        return info

    # Onbeperkt → switch heeft geen betekenis
    if eff_max is None:
        info = _cooldown_info(rec); info.update(base)
        info["can_switch"] = False
        info["reason"] = "unlimited_no_switch_needed"
        return info

    # Vrije plek → geen switch nodig (client mag gewoon attachen)
    if slots_used < eff_max_int:
        info = _cooldown_info(rec); info.update(base)
        info["can_switch"] = False
        info["reason"] = "slot_available"
        return info

    # Vol → cooldown bepalen
    info = _cooldown_info(rec); info.update(base)
    cooldown_active = bool(info.get("next_allowed_at") or info.get("cooldown_active"))
    if cooldown_active:
        info["can_switch"] = False
        info["reason"] = "cooldown_active"
        return info

    # Vol en geen cooldown → mag switchen
    info["can_switch"] = True
    info["reason"] = "full_can_switch"
    return info


def _contact_location_xml(row: Dict[str, Any], site_code: str, currency: str) -> str:
    loc = (row.get("location") or "Netherlands").strip()
    loc_x = _x(loc, _ESC)

    # Country MUST reflect where the item physically is, not which eBay
    # site we're listing on. Cross-border sellers (e.g. NL seller on UK
    # site) trigger eBay's Item Location Misrepresentation Policy (error
    # 240) when Country and Location don't match. Resolution order:
    #   1. row['country'] if the caller set it explicitly (ISO-2)
    #   2. Heuristic derived from row['location'] string
    #   3. Fall back to the site-code mapping (old behaviour)
    explicit = (row.get("country") or "").strip().upper()
    if explicit and len(explicit) == 2:
        country = explicit
    else:
        loc_to_country = {
            "netherlands": "NL", "nederland": "NL", "holland": "NL",
            "germany": "DE", "deutschland": "DE", "duitsland": "DE",
            "belgium": "BE", "belgie": "BE", "belgië": "BE",
            "united kingdom": "GB", "uk": "GB", "great britain": "GB",
            "england": "GB", "scotland": "GB", "wales": "GB",
            "france": "FR", "frankrijk": "FR",
            "italy": "IT", "italie": "IT", "italië": "IT",
            "spain": "ES", "spanje": "ES",
            "ireland": "IE", "ierland": "IE",
            "austria": "AT", "oostenrijk": "AT",
            "switzerland": "CH", "zwitserland": "CH", "schweiz": "CH", "suisse": "CH",
            "united states": "US", "usa": "US", "us": "US",
            "australia": "AU", "australie": "AU", "australië": "AU",
            "canada": "CA",
        }
        country = loc_to_country.get(loc.lower())
        if not country:
            site2country = {
                "NL":"NL","UK":"GB","GB":"GB","US":"US","DE":"DE","FR":"FR","IT":"IT",
                "ES":"ES","IE":"IE","AT":"AT","CH":"CH","BE":"BE","AU":"AU","CA":"CA"
            }
            country = site2country.get((site_code or "").upper(), "NL")

    parts = [
        f"<Currency>{currency}</Currency>",
        f"<Country>{country}</Country>",
        f"<Location>{loc_x}</Location>",
    ]
    pc = (row.get("postal_code") or row.get("postcode") or "").strip()
    if pc:
        parts.append(f"<PostalCode>{_x(pc, _ESC)}</PostalCode>")
    return "\n".join(parts)



def _format_duration(row: Dict[str, Any]) -> str:
    fmt = (row.get("format") or "Fixed price").lower()
    dur = str(row.get("duration") or "").upper()
    if "AUCTION" in fmt.upper() or "VEILING" in fmt.upper():
        if dur in {"1","3","5","7","10"}:
            return "Days_"+dur
        return "Days_7"
    return "GTC"

def _map_tz_name(tz_name: Optional[str]) -> str:
    if not tz_name:
        return "Europe/Amsterdam"
    name = str(tz_name).strip()
    MAP = {
        # NL/Windows/locale varianten → IANA
        "West-Europa (zomertijd)": "Europe/Amsterdam",
        "West-Europa (standaardtijd)": "Europe/Amsterdam",
        "W. Europe Daylight Time": "Europe/Amsterdam",
        "W. Europe Standard Time": "Europe/Amsterdam",
        "Central European Summer Time": "Europe/Amsterdam",
        "Central European Standard Time": "Europe/Amsterdam",
        "CEST": "Europe/Amsterdam",
        "CET": "Europe/Amsterdam",
    }
    return MAP.get(name, "Europe/Amsterdam")

def _best_tzinfo(tz_name: Optional[str]):
    try:
        # jouw bestaande mapping naar IANA mag blijven
        return ZoneInfo(_map_tz_name(tz_name))  # of ZoneInfo(tz_name) als je die gebruikt
    except Exception:
        # als zoneinfo faalt (zoals nu), val terug op systeem of UTC
        try:
            return datetime.now().astimezone().tzinfo or timezone.utc
        except Exception:
            return timezone.utc

def _schedule_time_xml(val: Optional[str], tz_name: Optional[str] = None) -> str:
    if not val:
        return ""
    s = str(val).strip()

    try:
        # 1) ISO(-ish) → accepteer 'Z' en +offset
        #    Voorbeeld uit jouw log: '2025-10-19T19:31:00.000Z'
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$", s):
            s += ":00"  # seconds aanvullen indien nodig
        dt = None
        try:
            dt = datetime.fromisoformat(s)
        except Exception:
            dt = None

        # 2) NL-formaat fallback: 20-10-2025 08:30(:ss)
        if dt is None:
            m = re.match(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{2,4})[ T](\d{1,2}):(\d{2})(?::(\d{2}))?$", s)
            if m:
                d, mo, y, H, M, S = m.groups()
                y = int(y);  y = (2000 + y) if y < 100 else y
                S = int(S) if S else 0
                dt = datetime(y, int(mo), int(d), int(H), int(M), S)
            else:
                # laatste strohalm: probeer 'YYYY-MM-DD HH:MM'
                m2 = re.match(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$", s)
                if m2:
                    y, mo, d, H, M, S = m2.groups()
                    S = int(S) if S else 0
                    dt = datetime(int(y), int(mo), int(d), int(H), int(M), S)

        if dt is None:
            print(f"[SCHED-DIAG] _schedule_time_xml: unparsable input {val!r}")
            return ""

        # 3) TZ toekennen indien naïef, daarna naar UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_best_tzinfo(tz_name))
        dt_utc = dt.astimezone(timezone.utc)

        return f"<ScheduleTime>{dt_utc.strftime('%Y-%m-%dT%H:%M:%S')}.000Z</ScheduleTime>"

    except Exception as e:
        print(f"[SCHED-DIAG] _schedule_time_xml exception for {val!r}: {e}")
        return ""


# ---- image URL normalization (avoid thumbnail URLs in Trading) ----
def _normalize_ebayimg_url(u: str, *, min_px: int = 500, target_px: int = 1600) -> str:
    """Normalize eBay image URLs to avoid too-small /s-l### variants.

    - Forces https
    - If URL contains /s-l<NUM> and NUM < min_px, upgrades to /s-l<target_px>
    """
    u = (u or "").strip()
    if not u:
        return ""
    if u.startswith("http://"):
        u = "https://" + u[len("http://"):]

    # Upgrade known size segment (works for i.ebayimg.com and similar)
    try:
        m = re.search(r"/s-l(\d+)(?=\.|\?)", u)
        if m:
            n = int(m.group(1))
            if n < int(min_px):
                u = re.sub(r"/s-l\d+(?=\.|\?)", f"/s-l{int(target_px)}", u, count=1)
    except Exception:
        pass

    return u

def _picture_details_xml(row: Dict[str, Any]) -> str:
    # Parent pictures ONLY. Do NOT leak variation picture sets into PictureDetails,
    # otherwise the "main" listing ends up with every variation image (and often thumbnails).
    out = []
    for key in ("picture_urls", "pictures"):
        if isinstance(row.get(key), list):
            out += [u for u in row[key] if u]

    # normalize + de-dup
    seen = set()
    out2 = []
    for u in out:
        nu = _normalize_ebayimg_url(str(u))
        if nu and nu not in seen:
            seen.add(nu)
            out2.append(nu)

    if not out2:
        return ""
    # (eBay allows up to 24; keep it sane)
    out2 = out2[:24]
    return "<PictureDetails>" + "".join(f"<PictureURL>{_xml_escape(u)}</PictureURL>" for u in out2) + "</PictureDetails>"


def _fetch_existing_listing_state(item_id: str) -> Dict[str, Any]:
    """GetItem on a live listing and return a snapshot of the fields the
    revise auto-correct needs to keep server-side SKUs / specifics in sync
    with what eBay has stored:

        {
            "top_level_sku": str,          # Item/SKU on the listing (often empty)
            "variations": [                # Every variation, including any
                {"sku": str, "specifics": {name: value}},   # with empty SKU
                ...
            ],
        }

    Returns an empty dict on any error so the caller can fall back to the
    client-supplied values.
    """
    iid = str(item_id or "").strip()
    if not iid:
        return {}
    try:
        u = _need_user()
    except Exception:
        return {}
    env = (u.get("env") or "PROD").upper()
    site_code = (u.get("site") or "NL").upper()
    site_id = TRADING_SITE_ID.get(site_code, "0")
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<GetItemRequest xmlns="urn:ebay:apis:eBLBaseComponents">'
        '<DetailLevel>ReturnAll</DetailLevel>'
        '<IncludeItemSpecifics>true</IncludeItemSpecifics>'
        f'<ItemID>{iid}</ItemID>'
        '</GetItemRequest>'
    )
    headers = {
        "X-EBAY-API-CALL-NAME": "GetItem",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }
    try:
        r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
        if r.status_code >= 400:
            return {}
        ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
        # IMPORTANT: parse raw bytes, NOT r.text. requests-lib derives the
        # decoding charset from the Content-Type header; eBay sometimes
        # serves the Trading API response with ISO-8859-1 even though the
        # body is UTF-8. Decoding-once-as-Latin-1 turns 'ü' (bytes C3 BC)
        # into the two-codepoint mojibake 'Ã¼' (U+00C3 U+00BC). When that
        # string is then re-emitted in our outgoing XML it gets encoded
        # to UTF-8 a second time (bytes C3 83 C2 BC) — eBay decodes that
        # and sees 'Ã¼' instead of 'ü', so the revise round-trips with
        # corrupted stored values and trips 21916664 ("Variation
        # Specifics Mismatch"). Passing raw bytes lets ElementTree honor
        # the XML declaration's encoding instead.
        root = ET.fromstring(r.content)
    except Exception:
        return {}
    # Top-level Item/SKU. Often empty when the listing was authored via
    # an Excel-style flow that never set a custom label.
    top_level_sku = (root.findtext(".//e:Item/e:SKU", default="", namespaces=ns) or "").strip()
    # All variations — keep empty-SKU ones too, we still need to match
    # them on revise so we don't introduce a placeholder SKU server-side.
    variations: list = []
    for v in root.findall(".//e:Item/e:Variations/e:Variation", ns):
        sku = (v.findtext("e:SKU", default="", namespaces=ns) or "").strip()
        specifics: Dict[str, str] = {}
        for nvl in v.findall(".//e:VariationSpecifics/e:NameValueList", ns):
            n = (nvl.findtext("e:Name", default="", namespaces=ns) or "").strip()
            val = (nvl.findtext("e:Value", default="", namespaces=ns) or "")
            # Preserve internal whitespace — only trim line/tab edges.
            # eBay's stored values may legitimately contain double spaces
            # or trailing punctuation that must round-trip verbatim or
            # revise fails with 21916664.
            val = val.strip("\n\r\t ") if val else ""
            if n and val:
                specifics[n] = val
        variations.append({"sku": sku, "specifics": specifics})
    return {"top_level_sku": top_level_sku, "variations": variations}


def _apply_existing_variation_specifics(row: Dict[str, Any]) -> None:
    """Sync client-supplied row state with what eBay has on the live listing
    so we never accidentally introduce a fresh SKU or rename a stored
    variation's specifics on revise. Without this:

    1. The client builds a top-level parent SKU like ``ML-<timestamp>`` at
       every multilisting build, regardless of whether the target listing
       even has one. eBay's revise treats a *changed* item-level SKU as a
       structural edit and may reject the request.
    2. The client falls back to ``<item_id>-VAR<idx>`` per-variation SKUs
       when importing a listing whose stored variations have empty SKUs.
       eBay then can't match the incoming variations to its stored ones
       (the only signal — SKU — disagrees) and raises 21916664
       ("Variation Specifics Mismatch") + 21920287 ("SKU missing in
       variation") because the *stored* variations still have no SKU.

    The fix mutates ``row`` in place:

    * stamps ``_ebay_top_level_sku`` so ``_build_item_xml`` can forward it
      verbatim or omit the ``<SKU>`` tag when eBay had none.
    * for each client variation that maps to a stored variation (matched
      first by SKU, otherwise by primary spec-value) we overwrite the
      client SKU with eBay's actual SKU (possibly empty) AND the specifics
      values with eBay's verbatim copy.
    * client variations whose specs-values aren't on the live listing are
      treated as newly-added — left untouched so they appear as genuinely
      new variations on revise.

    No-op when the GetItem snapshot fails; the request then flows through
    with whatever the client sent (legacy behavior).
    """
    iid = str(row.get("item_id") or "").strip()
    if not iid:
        return
    vars_ = row.get("variations") or []
    if not isinstance(vars_, list) or not vars_:
        return
    state = _fetch_existing_listing_state(iid)
    if not state:
        return

    # Stamp the top-level SKU even when it's empty — _build_item_xml
    # treats the presence of this key as "trust eBay's stored value over
    # whatever the client cooked up".
    row["_ebay_top_level_sku"] = state.get("top_level_sku", "")

    ebay_vars = state.get("variations") or []
    if not ebay_vars:
        return

    # Two indices over eBay's variations:
    #  - by_sku: cheap exact match for the common case (client kept the SKU).
    #  - by_value: fallback for listings whose stored SKUs are empty
    #    (Excel-builder scenario). Variations must be unique on the value
    #    side, so a single (aspect_name, value) hit unambiguously
    #    identifies the right stored variation.
    by_sku: Dict[str, Dict[str, Any]] = {}
    by_value: Dict[tuple, Dict[str, Any]] = {}
    for ev in ebay_vars:
        s = (ev.get("sku") or "").strip()
        if s:
            by_sku[s.lower()] = ev
        for name, val in (ev.get("specifics") or {}).items():
            by_value.setdefault((name, val), ev)

    sku_overwrites = 0
    value_overwrites = 0
    matched_by_value = 0
    for var in vars_:
        if not isinstance(var, dict):
            continue
        client_sku = str(var.get("sku") or "").strip()
        client_spec = var.get("specifics") or {}
        if not isinstance(client_spec, dict):
            client_spec = {}

        # 1. Try SKU match first (the cheap, exact path).
        ebay_var = by_sku.get(client_sku.lower()) if client_sku else None

        # 2. Fall back to matching by the first non-empty spec-value.
        if ebay_var is None:
            for name, val in client_spec.items():
                if not str(val or "").strip():
                    continue
                ebay_var = by_value.get((name, val))
                if ebay_var is None:
                    # 2b. Demojibake fallback. Bucket items imported BEFORE
                    # the r.text -> r.content encoding fix have UTF-8 bytes
                    # decoded as Latin-1, so an eBay-stored 'ü' (U+00FC)
                    # arrived in the client as 'Ã¼' (U+00C3 U+00BC). Round-
                    # trip via latin-1 -> utf-8 reverses that: encoding
                    # 'Ã¼' as Latin-1 gives bytes C3 BC, decoding those as
                    # UTF-8 yields back 'ü'. We only try this when the raw
                    # match failed, and we keep the demojibake'd string
                    # only if both stages succeed cleanly.
                    try:
                        demoji = val.encode("latin-1").decode("utf-8")
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        demoji = val
                    if demoji != val:
                        ebay_var = by_value.get((name, demoji))
                if ebay_var is not None:
                    matched_by_value += 1
                    break

        if ebay_var is None:
            # New variation the client is adding — leave it untouched so
            # it gets created on eBay's side.
            continue

        # 3. Replace SKU with eBay's stored value (possibly empty so an
        #    eBay-side "no SKU" stays "no SKU"). Without this the client
        #    keeps shipping ML-/-VAR<n> placeholders that eBay reads as
        #    *new* variations + a structural edit.
        ebay_sku = (ebay_var.get("sku") or "").strip()
        if (var.get("sku") or "") != ebay_sku:
            var["sku"] = ebay_sku
            sku_overwrites += 1

        # 4. Overwrite specifics-values with eBay's stored copy. Same
        #    rationale as before — eBay does not let you rename a stored
        #    variation's value on revise.
        merged = dict(client_spec)
        for name, val in (ebay_var.get("specifics") or {}).items():
            if merged.get(name) != val:
                value_overwrites += 1
            merged[name] = val
        var["specifics"] = merged

    if sku_overwrites or value_overwrites or matched_by_value:
        import logging as _lg
        _lg.warning(
            "REVISE_STATE_AUTOCORRECT item_id=%s top_level_sku_from_ebay=%r "
            "sku_overwrites=%d value_overwrites=%d matched_by_value=%d",
            iid, state.get("top_level_sku", ""),
            sku_overwrites, value_overwrites, matched_by_value,
        )


def _variations_xml(row: Dict[str, Any]) -> str:
    """Build <Variations> XML for Trading AddFixedPriceItem."""
    vars_ = row.get("variations") or []
    if not isinstance(vars_, list) or not vars_:
        return ""

    def _to_f(v: Any, default: float = 0.0) -> float:
        try:
            if v is None or v == "":
                return default
            return float(v)
        except Exception:
            return default

    def _to_i(v: Any, default: int = 0) -> int:
        try:
            if v is None or v == "":
                return default
            return int(float(v))
        except Exception:
            return default

    # Determine variation names
    var_names = row.get("variation_names")
    if not (isinstance(var_names, list) and var_names):
        spec0 = (vars_[0] or {}).get("specifics") or {}
        if isinstance(spec0, dict) and spec0:
            var_names = list(spec0.keys())
        else:
            var_names = []
    var_names = [str(n).strip() for n in var_names if str(n).strip()]
    if not var_names:
        return ""

    cur = str(row.get("currency") or "USD").upper()

    # Build VariationSpecificsSet
    values_by_name: Dict[str, list[str]] = {n: [] for n in var_names}
    for v in vars_:
        spec = (v or {}).get("specifics") or {}
        if not isinstance(spec, dict):
            continue
        for n in var_names:
            val = spec.get(n, "")
            val = "" if val is None else str(val).strip()
            if val and val not in values_by_name[n]:
                values_by_name[n].append(val)

    vss_xml = "<VariationSpecificsSet>" + "".join(
        "<NameValueList>"
        f"<Name>{_xml_escape(n)}</Name>"
        + "".join(f"<Value>{_xml_escape(val)}</Value>" for val in values_by_name.get(n, []) if val)
        + "</NameValueList>"
        for n in var_names
    ) + "</VariationSpecificsSet>"

    # Pictures mapping (one attribute only)
    pic_name = str(row.get("variation_picture_name") or (var_names[0] if var_names else "")).strip()
    if pic_name not in var_names:
        pic_name = var_names[0]

    pics_map: Dict[str, list[str]] = {}
    for v in vars_:
        spec = (v or {}).get("specifics") or {}
        if not isinstance(spec, dict):
            continue

        vv = spec.get(pic_name, "")
        vv = "" if vv is None else str(vv).strip()
        if not vv:
            continue

        urls: list[str] = []
        if isinstance((v or {}).get("picture_urls"), list):
            urls += [u for u in v["picture_urls"] if u]
        if isinstance((v or {}).get("pictures"), list):
            urls += [u for u in v["pictures"] if u]

        # normalize + de-dup
        seen = set()
        norm = []
        for u in urls:
            nu = _normalize_ebayimg_url(str(u))
            if nu and nu not in seen:
                seen.add(nu)
                norm.append(nu)

        if norm:
            if vv not in pics_map:
                pics_map[vv] = norm          # keep ALL images for this variation value
            else:
                # merge images from other variations that share the same attribute value
                existing = pics_map[vv]
                for u in norm:
                    if u not in existing:
                        existing.append(u)

    pics_xml = ""
    if pics_map:
        sets = ""
        for vv, urls in pics_map.items():
            urls2 = urls[:12]
            sets += (
                "<VariationSpecificPictureSet>"
                f"<VariationSpecificValue>{_xml_escape(vv)}</VariationSpecificValue>"
                + "".join(f"<PictureURL>{_xml_escape(u)}</PictureURL>" for u in urls2)
                + "</VariationSpecificPictureSet>"
            )
        pics_xml = (
            "<Pictures>"
            f"<VariationSpecificName>{_xml_escape(pic_name)}</VariationSpecificName>"
            f"{sets}"
            "</Pictures>"
        )

    # Individual variations
    var_xml_parts = []
    for idx, v in enumerate(vars_, start=1):
        if not isinstance(v, dict):
            continue
        # Empty SKU is a legitimate value when the live listing's
        # corresponding variation also has none — the revise auto-correct
        # may have overwritten the client's placeholder with eBay's empty
        # SKU. Don't synthesize a "VAR-<idx>" here; that placeholder is
        # what tripped 21916664 + 21920287 for Excel-built listings.
        sku = (v.get("sku") or "").strip()
        qty = _to_i(v.get("quantity"), 0)
        price = _to_f(v.get("start_price"), _to_f(v.get("price"), 0.0))
        spec = v.get("specifics") or {}
        if not isinstance(spec, dict):
            spec = {}

        nvl = "".join(
            "<NameValueList>"
            f"<Name>{_xml_escape(n)}</Name>"
            f"<Value>{_xml_escape(str(spec.get(n,'')).strip())}</Value>"
            "</NameValueList>"
            for n in var_names
            if str(spec.get(n, '')).strip()
        )

        sku_xml = f"<SKU>{_xml_escape(sku)}</SKU>" if sku else ""
        var_xml_parts.append(
            "<Variation>"
            f"{sku_xml}"
            f'<StartPrice currencyID="{_xml_escape(cur)}">{price:.2f}</StartPrice>'
            f"<Quantity>{qty}</Quantity>"
            "<VariationSpecifics>"
            f"{nvl}"
            "</VariationSpecifics>"
            "</Variation>"
        )

    return "<Variations>" + vss_xml + pics_xml + "".join(var_xml_parts) + "</Variations>"

def _build_item_xml(row: Dict[str, Any], site_code: str, currency: str, fixed: bool, tz_name: Optional[str] = None, revise: bool = False) -> str:
    # --- helpers ---
    def x(v: Any) -> str:
        """XML-escape voor tekstvelden (& < > ' ")"""
        if v is None:
            return ""
        return _xml_escape(str(v), {'"': '&quot;', "'": '&apos;'})

    def cdata(html: Any) -> str:
        """Stop (HTML) description in CDATA en neutraliseer ']]>' grens."""
        s = "" if html is None else str(html)
        # splits ']]>' veilig voor XML parsers
        s = s.replace("]]>", "]]]]><![CDATA[>")
        return f"<![CDATA[{s}]]>"

    # --- velden uit row ---
    title = (row.get("title") or "").strip()[:80]
    desc  = (row.get("description_html") or row.get("description") or "")
    cid   = str(row.get("category_id") or "").strip()
    _q_raw = row.get("quantity")
    qty   = int(_q_raw) if _q_raw is not None and str(_q_raw).strip() != "" else 1
    cond  = _condition_to_id(str(row.get("condition_id") or ""))
    start = _num(row.get("price"), None)
    binp  = _num(row.get("buy_it_now_price"), None)
    vatp  = _num(row.get("vat_percent"), None)

    listing_duration = _format_duration(row)

    # ── Variations (multilisting): if present, force Fixed Price + build <Variations>
    is_variation_listing = bool(row.get("variations"))
    vars_xml = ""
    row_for_specifics = row
    # Merge web-editor aspects into ItemSpecifics for Trading XML.
    # The web editor can store values under row['aspects'] (column-style), but Trading requires <ItemSpecifics>.
    try:
        aspects = row.get("aspects") or row.get("Aspects") or {}
        if isinstance(aspects, dict) and aspects:
            # Normalize existing item_specifics into a dict
            specs0 = row_for_specifics.get("item_specifics") or row_for_specifics.get("ItemSpecifics") or {}
            spec_map: dict[str, Any] = {}
            if isinstance(specs0, str):
                s = specs0.strip()
                if s and s[0] in "[{":
                    try:
                        specs0 = json.loads(s)
                    except Exception:
                        specs0 = {}
                else:
                    specs0 = {}
            if isinstance(specs0, dict):
                spec_map.update({str(k): v for k, v in specs0.items()})
            elif isinstance(specs0, list):
                for nv in specs0:
                    if not isinstance(nv, dict):
                        continue
                    name = str(nv.get("Name") or nv.get("name") or "").strip()
                    if not name:
                        continue
                    val = nv.get("Value") or nv.get("value")
                    if isinstance(val, list) and val:
                        spec_map.setdefault(name, val)
                    elif val is not None and val != "":
                        spec_map.setdefault(name, [str(val)])
            # Only fill missing keys from aspects (do not override explicit ItemSpecifics)
            for k, v in aspects.items():
                kk = str(k).strip()
                if not kk or kk in spec_map:
                    continue
                if v is None or v == "":
                    continue
                spec_map[kk] = v
            if spec_map:
                row_for_specifics = dict(row_for_specifics)
                row_for_specifics["item_specifics"] = spec_map
    except Exception:
        pass
    if is_variation_listing:
        fixed = True  # variations only supported on fixed-price listings in Trading API
        # Revise auto-correct: force variation-specifics Values for matched
        # SKUs back to whatever eBay has stored. Client-side normalization
        # (re.sub r'\s+',' ', .lower(), etc.) can collapse a double space
        # or change casing on import, which on revise trips error 21916664
        # ("Variation Specifics Mismatch") because eBay refuses to rename
        # an existing variation's value. Only matched SKUs are touched —
        # new variations and new SKUs flow through unchanged.
        if revise:
            try:
                _apply_existing_variation_specifics(row)
            except Exception as _e:
                # `logging` is shadowed as a local in this function by a
                # later `import logging`; use a fresh local alias.
                import logging as _lg
                _lg.warning("REVISE_SPECIFICS_AUTOCORRECT failed: %s", _e)
        vars_xml = _variations_xml(row)

        # Derive parent qty/price from variants (best-effort)
        try:
            vqty = 0
            vprices = []
            for v in (row.get("variations") or []):
                if not isinstance(v, dict):
                    continue
                try:
                    vqty += int(float(v.get("quantity") or 0))
                except Exception:
                    pass
                try:
                    vp = float(v.get("start_price") or v.get("price") or 0)
                    if vp > 0:
                        vprices.append(vp)
                except Exception:
                    pass
            if vqty > 0:
                qty = vqty
            if vprices:
                start = min(vprices)
        except Exception:
            pass

        # eBay rejects VariationSpecificName inside ItemSpecifics
        banned = [n for n in (row.get("variation_names") or []) if isinstance(n, str) and n.strip()]
        banned_lc = {n.lower() for n in banned}
        if banned_lc:
            row_for_specifics = dict(row)
            ispec = row_for_specifics.get("item_specifics")
            if isinstance(ispec, dict):
                row_for_specifics["item_specifics"] = {k: v for k, v in ispec.items() if str(k).lower() not in banned_lc}
            elif isinstance(ispec, list):
                cleaned = []
                for nv in ispec:
                    if isinstance(nv, dict):
                        name = str(nv.get("name") or nv.get("Name") or "").lower()
                        if name in banned_lc:
                            continue
                    cleaned.append(nv)
                row_for_specifics["item_specifics"] = cleaned
    parts: list[str] = []
    parts.append('<?xml version="1.0" encoding="utf-8"?>')
    _root = ("ReviseFixedPriceItemRequest" if revise else ("AddFixedPriceItemRequest" if fixed else "AddItemRequest"))
    parts.append(f'<{_root} xmlns="urn:ebay:apis:eBLBaseComponents">')
    parts.append('<ErrorLanguage>en_US</ErrorLanguage>')
    parts.append('<WarningLevel>High</WarningLevel>')
    parts.append('<Item>')
    if revise:
        _eid = str(row.get("item_id") or "").strip()
        if _eid:
            parts.append(f'<ItemID>{x(_eid)}</ItemID>')
    parts.append(f'<Title>{x(title)}</Title>')
    # Store code tokens as SKU/CustomLabel so cross-site reposting can reuse them.
    # On revise, prefer eBay's stored top-level SKU (set by the auto-correct
    # in _apply_existing_variation_specifics). When that key is present and
    # empty, drop the <SKU> tag entirely so we never introduce a fresh
    # client-generated identifier like ML-<timestamp> onto a listing that
    # had none — that change would trip eBay's structural-edit checks and
    # contributed to the 21916664 cluster on multi-variation revises.
    if revise and "_ebay_top_level_sku" in row:
        _sku = (row.get("_ebay_top_level_sku") or "").strip()[:50]
    else:
        _sku = str(row.get("custom_label") or row.get("sku") or "").strip()[:50]
    if _sku:
        parts.append(f'<SKU>{x(_sku)}</SKU>')
    # On Revise: skip <Description> by default. eBay keeps the existing
    # description when the element is omitted, which sidesteps the
    # content filter getting stricter over time — a description that
    # was fine at first listing can later trip error 240 ("improper
    # words / policy violation") even when the text didn't change.
    # The client opts back in by setting description_changed=true on
    # the row when the user actually edits the description.
    if (not revise) or row.get("description_changed"):
        parts.append(f'<Description>{cdata(desc)}</Description>')
    if cid:
        parts.append(f'<PrimaryCategory><CategoryID>{cid}</CategoryID></PrimaryCategory>')
    # eBay rejects Item-level <Quantity> when <Variations> is present.
    # Each variation carries its own Quantity; total is derived by eBay.
    # Sending both is a duplicate definition and trips error 240.
    if not is_variation_listing:
        parts.append(f'<Quantity>{qty}</Quantity>')
    parts.append(f'<ListingDuration>{listing_duration}</ListingDuration>')
    # Optionele subblokken (alleen toevoegen als ze iets teruggeven)
    sched_xml = _schedule_time_xml(row.get("schedule_time") or row.get("ScheduleTime"), tz_name)
    if sched_xml:
        parts.append(sched_xml)

    # Skip <Currency>/<Country>/<Location>/<PostalCode> on revise. eBay
    # keeps the existing values when the elements are omitted, so the
    # listing's original country/location stays intact. This avoids
    # accidentally rewriting a working Country (e.g. a listing that was
    # created before our derive-from-Location fix) and avoids re-triggering
    # eBay's Item Location Misrepresentation Policy (error 240) on revise
    # of older listings that have a Country/Location mismatch baked in.
    contact_loc = _contact_location_xml(row, site_code, currency)
    if contact_loc and not revise:
        parts.append(contact_loc)

    seller_profiles = _seller_profiles_xml(row)
    if seller_profiles:
        parts.append(seller_profiles)
        # zorg dat er geen tekst richting ReturnPolicy glipt
        for k in ("return_description", "ReturnDescription", "returnPolicyDescription"):
            row.pop(k, None)
    elif _row_wants_inline_policies(row) and not revise:
        # Quick-post path: seller has no business policies, so emit
        # <ShippingDetails>, <ReturnPolicy> and <DispatchTimeMax> inline.
        # Skipped on revise — eBay rejects policy changes after publish.
        parts.append(_inline_dispatch_time_xml(row))
        parts.append(_inline_shipping_xml(row, site_code, currency))
        parts.append(_inline_return_policy_xml(row))



    storefront_xml = _storefront_xml(row)
    if storefront_xml:
        parts.append(storefront_xml)

    # Canonicalize aspect names + values against eBay's allowed-values list.
    # eBay's Trading API is case-sensitive ("Near Mint or Better" != "Near mint
    # or better") and rejects with a misleading "is a required field" error
    # when the value doesn't match. Also strip stray "C:" prefixes from names.
    try:
        specs_in = row_for_specifics.get("item_specifics")
        canon_cat = str(row_for_specifics.get("category_id") or "")
        canon = _canonicalize_specifics(specs_in, site_code, canon_cat)
        if canon:
            row_for_specifics = dict(row_for_specifics)
            row_for_specifics["item_specifics"] = canon
    except Exception:
        pass

    specifics_xml = _itemspecifics_xml(row_for_specifics)
    if specifics_xml:
        parts.append(specifics_xml)

    # Condition must come before <Variations> per eBay Trading API schema.
    # On Revise: skip <ConditionID> unless the row carries an explicit
    # condition_changed=true flag. eBay keeps the existing condition when
    # the element is omitted, which avoids "ConditionID not valid for
    # category" failures when the imported listing's condition didn't
    # round-trip cleanly (e.g. category 261328 Baseball Cards rejects
    # 1000-New; the client's default fallback to cfg.condition_code used
    # to leak that 1000 into the revise XML).
    if cond and ((not revise) or row.get("condition_changed")):
        parts.append(f"<ConditionID>{cond}</ConditionID>")

    cond_desc = (row.get("condition_description") or "").strip()
    if cond_desc and (not cond or str(cond) != "1000") and ((not revise) or row.get("condition_changed")):
        parts.append(f"<ConditionDescription>{x(cond_desc)}</ConditionDescription>")

    # Structured ConditionDescriptors (trading cards etc. require this
    # alongside ConditionID; the old ItemSpecifics "Card Condition" alone
    # is not sufficient for some niche categories).
    descriptors_xml = _build_condition_descriptors_xml(
        row, str(row.get("category_id") or ""), site)
    if descriptors_xml:
        parts.append(descriptors_xml)

    pictures_xml = _picture_details_xml(row)
    if pictures_xml:
        parts.append(pictures_xml)
    if vars_xml:
        parts.append(vars_xml)

    postal = row.get("postal_code")
    if postal:
        parts.append(f"<PostalCode>{x(str(postal).strip())}</PostalCode>")

    if row.get("private_listing"):
        parts.append("<PrivateListing>true</PrivateListing>")

    if row.get("best_offer_enabled"):
        parts.append("<BestOfferDetails><BestOfferEnabled>true</BestOfferEnabled></BestOfferDetails>")

    reserve = row.get("reserve_price")
    if reserve is not None:
        try:
            parts.append(f"<ReservePrice>{float(reserve):.2f}</ReservePrice>")
        except Exception:
            pass

    # Prijzen: StartPrice altijd; BIN alleen bij Auction.
    # Skip Item-level <StartPrice> when Variations are present — eBay derives
    # the parent price from the variations themselves. Sending both is a
    # duplicate definition and trips error 240.
    if start is not None and not is_variation_listing:
        parts.append(f"<StartPrice>{start:.2f}</StartPrice>")
    if not fixed and binp is not None:
        parts.append(f"<BuyItNowPrice>{binp:.2f}</BuyItNowPrice>")

    if vatp is not None:
        parts.append(f"<VATDetails><VATPercent>{vatp:.2f}</VATPercent></VATDetails>")

    parts.append('</Item>')
    parts.append(f'</{_root}>')
    import os, re, logging
    xml_str = "\n".join(parts) if isinstance(parts, list) else str(parts)

    if os.environ.get("JOEP_DEBUG_XML") == "1":
        # Volledige XML dump
        logging.warning("TRADING_XML_BUILT:\n%s", xml_str)

        # Extra check voor losse & (optioneel)
        m = re.search(r'&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)', xml_str)
        if m:
            i = m.start()
            logging.error("Bare & context: %r", xml_str[max(0, i-80):i+80])

    return xml_str



def _trading_call(env: str, site_code: str, call_name: str, xml_payload: str) -> Dict[str, Any]:
    _refresh_user_if_needed(); u = _need_user(env)
    site_id = TRADING_SITE_ID.get(site_code.upper(), "0")
    headers = {
        "X-EBAY-API-CALL-NAME": call_name,
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }
    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml_payload.encode("utf-8"), timeout=60)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text)
    # Standard eBay multilisting/informational codes that are not actionable errors.
    # 21920200 = "Return Policy Attribute returnDescription Not Valid On This Site"
    # surfaces alongside real errors on UK/NL revises but is itself non-fatal
    # (eBay just ignores returnDescription on EU sites). Filtering it so the
    # actionable error (e.g. 240 title/description policy) isn't drowned out.
    _NOISE_CODES = {"21916618", "21916619", "21917236", "21920200"}
    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.content)
    ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip().upper()
    warnings = []
    for e in root.findall("e:Errors", ns):
        sev = (e.findtext("e:SeverityCode", default="", namespaces=ns) or "").strip().upper()
        if sev == "WARNING":
            code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
            msg  = (e.findtext("e:LongMessage", default="", namespaces=ns) or "").strip() or (e.findtext("e:ShortMessage", default="", namespaces=ns) or "").strip()
            if msg or code:
                warnings.append({"code": code, "message": msg})
    if ack == "FAILURE":
        errs = []
        for e in root.findall("e:Errors", ns):
            code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
            if code in _NOISE_CODES:
                continue
            msg  = (e.findtext("e:LongMessage", default="", namespaces=ns) or e.findtext("e:ShortMessage", default="", namespaces=ns) or "").strip()
            if msg or code: errs.append(f"{code}: {msg}".strip(": ").strip())
        # Dump request + raw eBay response to file. journald collapses
        # multi-KB blobs to "[3.8K blob data]" so we can't read the response
        # there; writing to disk keeps it inspectable.
        try:
            import os as _os, logging as _logging, time as _time
            _log_dir = "/srv/joepi/logs"
            _os.makedirs(_log_dir, exist_ok=True)
            _fname = _os.path.join(_log_dir, f"trading_failure_{int(_time.time())}_{call_name}.xml")
            with open(_fname, "w", encoding="utf-8") as _f:
                _f.write(f"<!-- call={call_name} site={site_code} ack={ack} -->\n")
                _f.write("<!-- ===== REQUEST ===== -->\n")
                _f.write(xml_payload)
                _f.write("\n\n<!-- ===== RESPONSE ===== -->\n")
                _f.write(r.text)
            _logging.warning(
                "TRADING_FAILURE call=%s site=%s codes=%s file=%s",
                call_name, site_code, [str(e_).split(":", 1)[0].strip() for e_ in errs][:5], _fname,
            )
        except Exception:
            pass
        raise HTTPException(502, "Trading failure: " + " | ".join(errs) if errs else r.text[:400])
    item_id = root.findtext(".//e:ItemID", default="", namespaces=ns) or ""
    start_time = (root.findtext("e:StartTime", default="", namespaces=ns) or "").strip()
    end_time   = (root.findtext("e:EndTime",   default="", namespaces=ns) or "").strip()

    return {"ok": True, "item_id": item_id, "start_time": start_time, "end_time": end_time, "warnings": warnings, "raw": r.text[:2000]}

# ---------- Web publish + compat endpoints ----------

# ---------- /web/conditions (voor web editor) ----------
def _trading_condition_values(request: Request, site: str, category_id: str) -> Dict[str, Any]:
    """Second-stage fallback: query Trading API GetCategoryFeatures with
    FeatureID=ConditionValues. Some niche categories (sports cards, certain
    parts subtrees) return a non-standard condition catalogue here that the
    Sell Metadata API doesn't expose. Returns the same shape as
    taxonomy_conditions: {conditions, condition_required}."""
    import logging
    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    site_id = TRADING_SITE_ID.get((site or "US").upper(), "0")

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<GetCategoryFeaturesRequest xmlns="urn:ebay:apis:eBLBaseComponents">
  <ErrorLanguage>en_US</ErrorLanguage>
  <WarningLevel>High</WarningLevel>
  <DetailLevel>ReturnAll</DetailLevel>
  <CategoryID>{category_id}</CategoryID>
  <FeatureID>ConditionValues</FeatureID>
  <FeatureID>ConditionEnabled</FeatureID>
  <FeatureID>ConditionDescriptionEnabled</FeatureID>
</GetCategoryFeaturesRequest>""".strip()

    headers = {
        "X-EBAY-API-CALL-NAME": "GetCategoryFeatures",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }
    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.content)
    ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip().upper()
    if ack == "FAILURE":
        errs = []
        for e in root.findall("e:Errors", ns):
            code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
            msg  = (e.findtext("e:LongMessage", default="", namespaces=ns) or e.findtext("e:ShortMessage", default="", namespaces=ns) or "").strip()
            if msg or code:
                errs.append(f"{code}: {msg}".strip(": ").strip())
        raise HTTPException(502, "Trading failure: " + " | ".join(errs) if errs else "Trading failure")

    conds_out: List[Dict[str, Any]] = []
    cond_required = False
    desc_allowed_default = False
    # Walk the Category > ConditionValues > Condition path
    for cat_node in root.findall(".//e:Category", ns):
        cv_root = cat_node.find("e:ConditionValues", ns)
        if cv_root is not None:
            for cnode in cv_root.findall("e:Condition", ns):
                cid = (cnode.findtext("e:ID", default="", namespaces=ns) or "").strip()
                name = (cnode.findtext("e:DisplayName", default="", namespaces=ns) or "").strip()
                if cid and name:
                    conds_out.append({
                        "id": cid,
                        "name": name,
                        "label": f"{cid}-{name}",
                        "allow_description": False,  # Trading API doesn't expose this per-cond
                    })
        ce = (cat_node.findtext("e:ConditionEnabled", default="", namespaces=ns) or "").strip().lower()
        if ce in ("required",):
            cond_required = True
        cd = (cat_node.findtext("e:ConditionDescriptionEnabled", default="", namespaces=ns) or "").strip().lower()
        if cd in ("true", "1", "yes"):
            desc_allowed_default = True
    if desc_allowed_default:
        for c in conds_out:
            c["allow_description"] = True

    logging.info("[web/conditions] trading-fallback returned %d conditions for cat=%s site=%s", len(conds_out), category_id, site)
    return {"conditions": conds_out, "condition_required": cond_required, "source": "trading"}


# Category-specific condition overrides. eBay's metadata APIs often return
# the wrong / incomplete condition list for niche categories (sports cards,
# graded coins, certain parts subtrees) — they expose the generic 5-item
# set even though the category actually accepts different IDs at publish
# time (verified via eBay File Exchange uploads). When we have authoritative
# data for a category, merge it into the API response so sellers see the
# real options.
#
# Format: { category_id: [ {"id": "...", "name": "...", "label": "...",
#                            "allow_description": bool}, ... ] }
_CONDITION_OVERRIDES: Dict[str, List[Dict[str, Any]]] = {
    # Sports Trading Cards — Singles & Sets
    "261328": [
        {"id": "1000", "name": "New",                "label": "1000-New",                "allow_description": False},
        {"id": "2750", "name": "Like New / Graded",  "label": "2750-Like New / Graded",  "allow_description": True},
        {"id": "4000", "name": "Ungraded",           "label": "4000-Ungraded",           "allow_description": True},
    ],
    "212":    [  # Trading Card Singles
        {"id": "1000", "name": "New",                "label": "1000-New",                "allow_description": False},
        {"id": "2750", "name": "Like New / Graded",  "label": "2750-Like New / Graded",  "allow_description": True},
        {"id": "4000", "name": "Ungraded",           "label": "4000-Ungraded",           "allow_description": True},
    ],
    "183454": [  # Sports Trading Card Singles (alt category id used in some marketplaces)
        {"id": "1000", "name": "New",                "label": "1000-New",                "allow_description": False},
        {"id": "2750", "name": "Like New / Graded",  "label": "2750-Like New / Graded",  "allow_description": True},
        {"id": "4000", "name": "Ungraded",           "label": "4000-Ungraded",           "allow_description": True},
    ],
}

def _apply_condition_overrides(category_id: str, base: Dict[str, Any]) -> Dict[str, Any]:
    """Merge hardcoded overrides into an API condition response.
    Override entries replace any matching ID in the base list and missing
    overrides are appended. The result preserves the base's source/required
    flags but tags the response as 'override' when overrides applied."""
    cid = str(category_id or "").strip()
    overrides = _CONDITION_OVERRIDES.get(cid)
    if not overrides:
        return base
    base_conds = list(base.get("conditions") or [])
    by_id = {str(c.get("id") or ""): dict(c) for c in base_conds}
    for ov in overrides:
        by_id[str(ov.get("id") or "")] = dict(ov)
    merged = list(by_id.values())
    out = dict(base)
    out["conditions"] = merged
    out["source"] = (base.get("source") or "") + "+override" if base.get("source") else "override"
    return out


# In-memory cache for /web/conditions to avoid repeated eBay round-trips.
# Keyed by (site, category_id, env). TTL 6h — condition catalogues change
# rarely. Avoids the 5-15s eBay API hit on every category prefetch.
_CONDITIONS_CACHE: Dict[str, Dict[str, Any]] = {}
_CONDITIONS_CACHE_TTL = 6 * 3600  # 6 hours

def _conditions_cache_get(key: str) -> Optional[Dict[str, Any]]:
    import time
    rec = _CONDITIONS_CACHE.get(key)
    if not rec:
        return None
    if (time.time() - rec.get("_ts", 0)) > _CONDITIONS_CACHE_TTL:
        _CONDITIONS_CACHE.pop(key, None)
        return None
    return rec.get("data")

def _conditions_cache_put(key: str, data: Dict[str, Any]) -> None:
    import time
    _CONDITIONS_CACHE[key] = {"data": data, "_ts": time.time()}


@app.get("/web/conditions")
def web_conditions(request:Request, site: str = Query(None), category_id: str = Query(...)):
    """Return category-specific condition values for the eBay listing flow.

    Strategy: Trading API first (the canonical source per eBay docs for
    category ConditionValues — handles sports cards, parts, niche subtrees
    correctly), Sell Metadata second (richer metadata like
    allow_description, marketplace-language labels). Cached 6h per
    (site, category) pair.
    """
    import logging
    site, _ = _effective_site_and_currency(site, None)

    cache_key = f"{(site or '').upper()}|{str(category_id)}"
    cached = _conditions_cache_get(cache_key)
    if cached is not None:
        return cached

    # Stage 1: Trading API GetCategoryFeatures(ConditionValues) — canonical
    # per-category list including niche values like 4000=Ungraded for
    # sports trading card singles.
    stage1_data = None
    stage1_err  = None
    try:
        stage1_data = _trading_condition_values(request, site=site, category_id=category_id)
    except HTTPException as e:
        stage1_err = str(e.detail)
        logging.info("[web/conditions] stage1 (Trading) failed for cat=%s site=%s: %s", category_id, site, stage1_err)
    except Exception as e:
        stage1_err = repr(e)
        logging.info("[web/conditions] stage1 unexpected for cat=%s site=%s: %r", category_id, site, e)

    if stage1_data and stage1_data.get("conditions"):
        # NOTE: skipping Sell Metadata enrichment here on purpose — it adds
        # a second eBay round-trip on every uncached call (~500ms-2s).
        # allow_description defaults to False and that's OK; the user can
        # still type a condition description manually if needed.
        out = dict(stage1_data)
        out.setdefault("source", "trading")
        out = _apply_condition_overrides(category_id, out)
        _conditions_cache_put(cache_key, out)
        return out

    # Stage 2: Sell Metadata API fallback — for categories where Trading
    # rejects the request or returns nothing.
    try:
        stage2 = taxonomy_conditions(request, site=site, category_id=category_id)
        if stage2 and stage2.get("conditions"):
            out = dict(stage2)
            out.setdefault("source", "metadata")
            out = _apply_condition_overrides(category_id, out)
            _conditions_cache_put(cache_key, out)
            return out
    except HTTPException as e:
        logging.info("[web/conditions] stage2 (Sell Metadata) failed for cat=%s site=%s: %s", category_id, site, e.detail)
    except Exception as e:
        logging.info("[web/conditions] stage2 unexpected error for cat=%s site=%s: %r", category_id, site, e)

    # Both stages empty/failed — but we may still have a hardcoded override
    # for this category (e.g. sports cards) so try that as last resort.
    override_only = _apply_condition_overrides(category_id, {
        "conditions": [],
        "condition_required": False,
        "source": "",
    })
    if override_only.get("conditions"):
        _conditions_cache_put(cache_key, override_only)
        return override_only

    # Both stages empty/failed AND no override — return clean empty list.
    # Don't cache the negative result for long: short-lived cache so a
    # transient failure gets retried within 5 minutes instead of an hour.
    out = {
        "conditions": [],
        "condition_required": False,
        "source": "none",
        "error": stage1_err or "No conditions returned for this category.",
    }
    import time
    _CONDITIONS_CACHE[cache_key] = {"data": out, "_ts": time.time() - (_CONDITIONS_CACHE_TTL - 300)}
    return out

@app.post("/web/publish")
def web_publish(request: Request, payload: Dict[str, Any] = Body(...)):
    # 1) licentie & login
    import logging
    rec = ensure_valid_license_only(request)
    try:
        _refresh_user_if_needed()
        u = _need_user()
    except Exception:
        raise HTTPException(status_code=401, detail="Please log in to eBay before publishing.")

    rows = payload.get("rows") or []
    if not isinstance(rows, list):
        raise HTTPException(status_code=400, detail="rows must be a list")

    # optionele veiligheidslimiet per call (tegen timeouts/abuse)
    max_rows = WEB_PUBLISH_MAX_ROWS or 0
    if max_rows and len(rows) > max_rows:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Too many rows in one publish batch "
                f"(max {max_rows}, got {len(rows)}). "
                "Please publish in smaller chunks."
            ),
        )

    # uit payload (desktop / web-editor)
    raw_payload_site     = (payload.get("site") or "").strip()
    raw_payload_currency = (payload.get("currency") or "").strip()
    payload_tz           = payload.get("timezone") or payload.get("tz")

    env       = (u.get("env") or "PROD").upper()
    user_site = (u.get("site") or "").strip().upper() or None

    payload_site     = raw_payload_site.upper() or None
    payload_currency = raw_payload_currency.upper() or None

    results = []

    for row in rows:
        # per row → rows_builder vult 'site_code' in
        row_site = (str(row.get("site_code") or "").strip().upper() or None)

        site, currency = _effective_site_and_currency(
            user_site=user_site,
            payload_site=payload_site,
            row_site=row_site,
            payload_currency=payload_currency,
        )

        logging.warning(
            "WEB_PUBLISH_ROW: env=%s user_site=%s payload_site=%s row_site=%s final_site=%s currency=%s title=%r",
            env, user_site, payload_site, row_site, site, currency, row.get("title"),
        )
        # DEBUG (2026-05-25): dump first 5 variations + any "Tatra Kolin"
        # match in the incoming payload, so we can see exactly what the
        # client sends as variation-specifics before any server-side
        # transformation. Used to find where the value gets stripped
        # of its trailing price digit. Remove once root cause located.
        try:
            _vars = row.get("variations") or []
            if isinstance(_vars, list):
                logging.warning(
                    "WEB_PUBLISH_VARIATIONS count=%d (first 5 + any 'Tatra Kolin' match):",
                    len(_vars),
                )
                for _i, _v in enumerate(_vars):
                    if not isinstance(_v, dict):
                        continue
                    _sku = str(_v.get("sku") or "").strip()
                    _specs = _v.get("specifics") or {}
                    _hit = "tatra kolin" in (str(_specs) + " " + _sku).lower()
                    if _i < 5 or _hit:
                        logging.warning(
                            "  var[%d] sku=%r specifics=%r",
                            _i, _sku, _specs,
                        )
        except Exception as _e:
            logging.warning("WEB_PUBLISH_VARIATIONS dump failed: %s", _e)

        # 2) policy check
        try:
            _assert_policy_ok_for_site(env, site, str(row.get("return_profile") or "").strip())
        except HTTPException as e:
            results.append({
                "title": row.get("title"),
                "ok": False,
                "error": str(e.detail),
            })
            continue

        fmt   = (row.get("format") or "Fixed price").lower()
        has_vars = bool(row.get("variations"))
        fixed = ("fixed" in fmt) or has_vars
        if has_vars:
            # variations only supported on fixed-price listings; keep UI consistent
            row["format"] = "Fixed price"
        row_tz = row.get("timezone") or row.get("tz") or payload_tz

        # --- duplicate variation-specifics check (error 21916586 prevention) ---
        if has_vars:
            import json as _json
            from collections import defaultdict as _dd
            _spec_groups = _dd(list)
            for _vi, _vv in enumerate(row.get("variations") or []):
                _specs = _vv.get("specifics") or {}
                _key = _json.dumps(_specs, sort_keys=True)
                _spec_groups[_key].append({"index": _vi, "sku": str(_vv.get("sku") or "")})
            _dupes = {k: v for k, v in _spec_groups.items() if len(v) > 1}
            if _dupes:
                _msgs = []
                for _key, _rows in _dupes.items():
                    _specs_display = _json.loads(_key)
                    _row_list = ", ".join(
                        f"row {r['index']+1} (SKU: {r['sku']})".strip() for r in _rows
                    )
                    _msgs.append(f"Duplicate variation specifics {_specs_display} on {_row_list}")
                results.append({
                    "title": row.get("title"),
                    "ok": False,
                    "error": "Duplicate variation specifics found — fix before publishing:\n" + "\n".join(_msgs),
                })
                continue
        # --- end duplicate check ---

        try:
            _has_item_id = bool(str(row.get("item_id") or "").strip())
            _revise = _has_item_id and fixed
            xml  = _build_item_xml(row, site, currency, fixed, tz_name=row_tz, revise=_revise)
            call = "ReviseFixedPriceItem" if _revise else ("AddFixedPriceItem" if fixed else "AddItem")
            res  = _trading_call(env, site, call, xml)
            logging.warning(
                "WEB_PUBLISH_RESULT: call=%s item_id_in=%r item_id_out=%r ok=%s warnings=%s",
                call, str(row.get("item_id") or ""), res.get("item_id"), res.get("ok"), res.get("warnings"),
            )
            results.append({
                "title": row.get("title"),
                "ok": True,
                "is_revise": _revise,
                "item_id": res.get("item_id"),
                "start_time": (res.get("start_time") or row.get("schedule_time")),
                "warnings": res.get("warnings"),
            })
            # Sloot deze rij aan op een eerder AI-voorstel? Leg dan vast wat er
            # daadwerkelijk gepubliceerd is. Dat paar is de hele bedoeling van
            # analysis_id; zonder deze kant heb je voorstellen zonder uitkomst.
            _row_analysis_id = str(row.get("analysis_id") or "").strip()
            if _row_analysis_id:
                _ai_log_published(request, _row_analysis_id, row, site=site,
                                  outcome=("revised" if _revise else "published"))
        except HTTPException as e:
            results.append({
                "title": row.get("title"),
                "ok": False,
                "error": str(e.detail),
            })
        except Exception as e:
            results.append({
                "title": row.get("title"),
                "ok": False,
                "error": f"{type(e).__name__}: {e}",
            })

    return {"ok": True, "count": len(results), "results": results}


@app.get("/web/peek_item/{item_id}")
def web_peek_item(request: Request, item_id: str):
    """Debug helper: run a GetItem on a live eBay listing and return the
    variation specifics as JSON so we can diff against what FolderLister
    is about to send. Used to track down 21916664 (Variation Specifics
    Mismatch) which eBay does NOT pinpoint in its error response.
    Auth: same license/login flow as /web/publish."""
    rec = ensure_valid_license_only(request)
    try:
        _refresh_user_if_needed()
        u = _need_user()
    except Exception:
        raise HTTPException(status_code=401, detail="Please log in to eBay before using peek.")
    env = (u.get("env") or "PROD").upper()
    site_code = (u.get("site") or "NL").upper()
    site_id = TRADING_SITE_ID.get(site_code, "0")
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<GetItemRequest xmlns="urn:ebay:apis:eBLBaseComponents">'
        '<DetailLevel>ReturnAll</DetailLevel>'
        '<IncludeItemSpecifics>true</IncludeItemSpecifics>'
        f'<ItemID>{item_id}</ItemID>'
        '</GetItemRequest>'
    )
    headers = {
        "X-EBAY-API-CALL-NAME": "GetItem",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }
    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=60)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text[:500])
    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.content)
    ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip()
    out: Dict[str, Any] = {
        "ack": ack,
        "item_id": item_id,
        "title": (root.findtext(".//e:Item/e:Title", default="", namespaces=ns) or "").strip(),
        "category_id": (root.findtext(".//e:Item/e:PrimaryCategory/e:CategoryID", default="", namespaces=ns) or "").strip(),
        "site": (root.findtext(".//e:Item/e:Site", default="", namespaces=ns) or "").strip(),
    }
    vss: list = []
    for nvl in root.findall(".//e:Item/e:Variations/e:VariationSpecificsSet/e:NameValueList", ns):
        name = (nvl.findtext("e:Name", default="", namespaces=ns) or "").strip()
        values = [(v.text or "").strip() for v in nvl.findall("e:Value", ns)]
        values = [v for v in values if v]
        vss.append({"name": name, "values": values, "values_count": len(values)})
    out["variation_specifics_set"] = vss
    vars_out: list = []
    for v in root.findall(".//e:Item/e:Variations/e:Variation", ns):
        sku = (v.findtext("e:SKU", default="", namespaces=ns) or "").strip()
        qty = (v.findtext("e:Quantity", default="", namespaces=ns) or "").strip()
        sold = (v.findtext("e:SellingStatus/e:QuantitySold", default="0", namespaces=ns) or "0").strip()
        specifics: Dict[str, str] = {}
        for nvl in v.findall(".//e:VariationSpecifics/e:NameValueList", ns):
            n = (nvl.findtext("e:Name", default="", namespaces=ns) or "").strip()
            val = (nvl.findtext("e:Value", default="", namespaces=ns) or "").strip()
            if n:
                specifics[n] = val
        vars_out.append({"sku": sku, "qty": qty, "sold": sold, "specifics": specifics})
    out["variations"] = vars_out
    out["variations_count"] = len(vars_out)
    errors: list = []
    for e in root.findall("e:Errors", ns):
        code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
        msg = (e.findtext("e:LongMessage", default="", namespaces=ns) or "").strip()
        if code or msg:
            errors.append({"code": code, "message": msg})
    if errors:
        out["errors"] = errors
    return out


# Backwards compatibility: verify/submit (client verwacht deze paden)
@app.post("/listings/verify")
def listings_verify(body: Dict[str, Any] = Body(...)):
    return {"ok": True, "message": "verification skipped", "items": len(body.get("items") or [])}

@app.post("/listings/submit")
def listings_submit(request: Request, body: Dict[str, Any] = Body(...)):
    site     = (body.get("site") or "NL").upper()
    rows     = body.get("items") or body.get("rows") or []
    currency = (body.get("currency") or "EUR").strip().upper()
    tz       = body.get("timezone") or body.get("tz")  # <-- nieuw

    payload = {
        "site": site,
        "currency": currency,
        "interval_minutes": 0,
        "rows": rows,
        "timezone": tz,
    }
    return web_publish(request, payload)



# --- Compatibility aliases for older clients ---

@app.get("/account/policies")
def account_policies(request:Request, site: str = Query("UK"), prefer_store: str = Query("rest")):
    """
    Compat: levert {shipping:[], return:[], payment:[]}
    Hergebruikt de bestaande /web/policies logica.
    """
    data = web_policies(request=request, site=site, prefer_store=prefer_store)  # reuse existing builder
    return {
        "shipping": data.get("shipping", []),
        "return":   data.get("return", []),
        "payment":  data.get("payment", []),
    }

@app.get("/store/categories")
def store_categories(request: Request, site: str = Query("UK"), prefer: str = Query("rest")):
    """
    Compat: enkelvoudig pad; geeft {categories:[...]} terug.
    Hergebruikt /web/policies zodat de shape altijd {id,name} is.
    """
    data = web_policies(request=request, site=site, prefer_store=prefer)
    return {"categories": data.get("store_categories", [])}



# ===== Licensing =====
class LicenseIn(BaseModel):
    license_key: str
    # Optional: when validation has been gated behind email verification, the
    # client passes the verified email (and optional one-time code) so the
    # server can confirm the attempt is human.
    verified_email: str | None = None
    verification_code: str | None = None

class TrialStartIn(BaseModel):
    email: str | None = None
    device_id: str | None = None
    ebay_user: str | None = None
    name: str | None = None

# ... jouw imports bovenin ...


# ====== MODELLEN ======
class LicenseOut(BaseModel):
    valid: bool
    plan: str | None = None
    expires_at: str | None = None
    owner_email: str | None = None
    owner_name: str | None = None
    max_accounts: int | None = None
    # beide lijsten optioneel; we sturen ze alleen wanneer in record aanwezig
    allowed_ebay_users: list[str] | None = None
    allowed_identity_ids: list[str] | None = None


# --- License-validate rate-limiter / anti-bruteforce ----------------------
#
#  Policy (per source-IP, sliding 1-hour window):
#   - 1st attempt is free
#   - 2nd+ attempt requires a verified email (uses /email/verify flow)
#   - 5 failed attempts within 1h triggers a hard cooldown (1h)
#
#  State persists to data/license_attempts.json so a restart doesn't reset
#  the protection. Successful validate clears the IP record.
#
_LICENSE_ATTEMPTS_FILE = ROOT / "server" / "data" / "license_attempts.json"
_LICENSE_ATTEMPTS_LOCK = threading.Lock()
_LICENSE_ATTEMPT_WINDOW_S = 3600          # 1 hour sliding window
_LICENSE_ATTEMPT_HARDLOCK_AT = 5          # block after 5 failures
_LICENSE_ATTEMPT_VERIFY_AT = 3            # require email verify after 3rd fail
                                          # (was 1 — too aggressive; one typo
                                          # locked users into a 401 loop they
                                          # never escaped because the client
                                          # used to swallow verify_required)


def _client_ip(request: Request) -> str:
    fwd = (request.headers.get("X-Forwarded-For") or "").split(",")
    if fwd and fwd[0].strip():
        return fwd[0].strip()
    return (request.client.host if request and request.client else "anon") or "anon"


def _la_load() -> dict:
    try:
        if _LICENSE_ATTEMPTS_FILE.exists():
            return json.loads(_LICENSE_ATTEMPTS_FILE.read_text("utf-8") or "{}")
    except Exception:
        pass
    return {}


def _la_save(d: dict) -> None:
    try:
        _LICENSE_ATTEMPTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _LICENSE_ATTEMPTS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
        tmp.replace(_LICENSE_ATTEMPTS_FILE)
    except Exception:
        pass


def _la_get(ip: str) -> dict:
    """Return the IP record, pruning stale entries automatically."""
    now = int(time.time())
    with _LICENSE_ATTEMPTS_LOCK:
        d = _la_load()
        rec = d.get(ip) or {}
        first = int(rec.get("first_fail_ts") or 0)
        if first and (now - first) > _LICENSE_ATTEMPT_WINDOW_S:
            # Window expired: forget previous failures.
            d.pop(ip, None)
            _la_save(d)
            return {}
        return rec


def _la_record_failure(ip: str) -> dict:
    now = int(time.time())
    with _LICENSE_ATTEMPTS_LOCK:
        d = _la_load()
        rec = d.get(ip) or {}
        first = int(rec.get("first_fail_ts") or 0)
        if not first or (now - first) > _LICENSE_ATTEMPT_WINDOW_S:
            rec = {"failures": 0, "first_fail_ts": now}
        rec["failures"] = int(rec.get("failures") or 0) + 1
        rec["last_fail_ts"] = now
        d[ip] = rec
        _la_save(d)
        return rec


def _la_record_success(ip: str) -> None:
    with _LICENSE_ATTEMPTS_LOCK:
        d = _la_load()
        if ip in d:
            d.pop(ip, None)
            _la_save(d)


def _is_email_verified(email: str) -> bool:
    """Check the existing email-verify store (set by /email/verify/confirm)."""
    try:
        em = _normalize_email(email)
        if not em:
            return False
        with _VC_LOCK:
            rec = _vc_load()
            row = rec.get(em) or {}
            return bool(row.get("verified"))
    except Exception:
        return False


@app.post("/license/validate", response_model=LicenseOut)
def license_validate(payload: LicenseIn, request: Request):
    ip = _client_ip(request)
    state = _la_get(ip)
    failures = int(state.get("failures") or 0)

    # Hard cooldown: too many failures in the window.
    if failures >= _LICENSE_ATTEMPT_HARDLOCK_AT:
        first = int(state.get("first_fail_ts") or 0)
        retry_after = max(60, _LICENSE_ATTEMPT_WINDOW_S - (int(time.time()) - first))
        resp = JSONResponse(
            {
                "valid": False,
                "detail": "too_many_attempts",
                "retry_after": retry_after,
                "hint": "Too many failed attempts. Try again later.",
            },
            status_code=429,
        )
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    # After the first failure: require a verified email before each attempt.
    if failures >= _LICENSE_ATTEMPT_VERIFY_AT:
        v_email = (payload.verified_email or "").strip()
        if not v_email or not _is_email_verified(v_email):
            return JSONResponse(
                {
                    "valid": False,
                    "detail": "verification_required",
                    "verify_required": True,
                    "failures": failures,
                    "hint": (
                        "After one failed attempt you need to verify your email "
                        "before trying another license key."
                    ),
                },
                status_code=401,
            )

    # Strip whitespace defensively — mail clients sometimes paste keys
    # with a leading/trailing space, which otherwise hashes differently
    # and gives a misleading "invalid" result.
    _lk = (payload.license_key or "").strip()
    rec = find_license(_lk)
    ok = bool(rec and is_valid(rec))
    if ok:
        _la_record_success(ip)
        return {
            "valid": True,
            "plan": (rec or {}).get("plan"),
            "expires_at": (rec or {}).get("expires_at"),
            "owner_email": (rec or {}).get("owner_email"),
            "owner_name": (rec or {}).get("owner_name"),
            "max_accounts": int((rec or {}).get("max_accounts") or 1),
            "allowed_ebay_users": (rec or {}).get("allowed_ebay_users") or [],
        }
    # Validation failed: increment counter and tell client what's next.
    state2 = _la_record_failure(ip)
    failures2 = int(state2.get("failures") or 0)
    body = {
        "valid": False,
        "plan": None,
        "expires_at": None,
        "failures": failures2,
        "verify_required": failures2 >= _LICENSE_ATTEMPT_VERIFY_AT,
    }
    if failures2 >= _LICENSE_ATTEMPT_HARDLOCK_AT:
        body["detail"] = "too_many_attempts"
        body["retry_after"] = _LICENSE_ATTEMPT_WINDOW_S
    return body
import os, json, secrets


def _licenses_save(data: dict):
    """JSON van de licencestore wegschrijven + cache van license_store verversen."""
    from .license_store import FILE as LICENSE_FILE
    tmp = LICENSE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(LICENSE_FILE)
    # cache mee updaten zodat find_license() de nieuwe data meteen ziet
    try:
        LS._cache = data
        LS._cache_mtime = LICENSE_FILE.stat().st_mtime
        LS._cache_loaded_at = time.time()
    except Exception:
        pass


def _rekey_if_hmac_for_email(email: str) -> tuple[str | None, dict | None]:
    """
    Vervang één legacy HMAC-store-entry (launch+active voor dit e-mail) door
    een nieuwe plain key. De store key blijft HMAC256:..., maar in het record
    komt 'license_key' met de plain key te staan.
    """
    em = _normalize_email(email)
    data = _licenses_load()
    for old_store_key, rec in list(data.items()):
        owner = _normalize_email(rec.get("owner_email"))
        status = (rec.get("status") or "active").lower()
        if (
            rec.get("plan") == "launch"
            and status == "active"
            and owner == em
            and str(old_store_key).upper().startswith("HMAC")
        ):
            new_key = secrets.token_urlsafe(24)

            # nieuwe record met plain key
            new_rec = dict(rec)
            new_rec["license_key"] = new_key

            # nieuwe HMAC-storekey
            new_store_key = LS._hmac_key(new_key)
            data[new_store_key] = new_rec

            # oude op revoked_migrated zetten
            old_rec = dict(rec)
            old_rec["status"] = "revoked_migrated"
            data[old_store_key] = old_rec

            _licenses_save(data)
            return new_key, new_rec

    return None, None

def _send_welcome_mail(to_email: str) -> None:
    """
    Simple HTML welcome e-mail for new Folder Lister users.
    Uses the same SMTP settings as other mails.
    """
    subject = "Welcome to Folder Lister"

    # Plain-text fallback
    text = """Welcome to Folder Lister

Thanks for signing up to try Folder Lister.

Folder Lister is currently in its launch phase. The goal is simple:
help eBay sellers list in bulk without losing control over their details.

Setup is short and straightforward. For a quick start and more advanced tips,
check the documentation: https://folderlister.com/docs

Need help, ran into something weird, or want to double-check your workflow?
Reach out at support@folderlister.com.

We’re very curious about your experience and do our best to guide you and
make Folder Lister a pleasant tool to work with. Suggestions, tweaks, and
brutally honest feedback are all welcome.

Kind regards,
Joep — Folder Lister
"""

    # Jouw HTML-template 1-op-1 erin
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Welcome to Folder Lister</title>
</head>
<body style="margin:0;padding:0;background:#f5f5f7;font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
    <tr>
      <td align="center" style="padding:24px 12px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:640px;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e2e2e7;">
          <tr>
            <td style="padding:20px 24px 12px 24px;text-align:left;">
              <img src="https://folderlister.com/images/folder_lister_logo.png"
                   alt="Folder Lister"
                   width="80"
                   style="display:block;margin:0 0 12px 0;">
              <h1 style="margin:0 0 8px 0;font-size:22px;line-height:1.3;color:#111827;">
                Welcome to Folder Lister
              </h1>
              <p style="margin:0;font-size:14px;line-height:1.5;color:#4b5563;">
                Thanks for signing up to try Folder Lister.
              </p>
            </td>
          </tr>

          <tr>
            <td style="padding:8px 24px 8px 24px;">
              <p style="margin:0 0 12px 0;font-size:14px;line-height:1.6;color:#374151;">
                Folder Lister is currently in its launch phase. The goal is simple:
                help eBay sellers list in bulk without losing control over their details.
              </p>

              <p style="margin:0 0 12px 0;font-size:14px;line-height:1.6;color:#374151;">
                Setup is intentionally short and straightforward — most of the work comes
                from your own folder structure. For a quick start and more advanced tips,
                please check the documentation:
                <a href="https://folderlister.com/docs" style="color:#2563eb;text-decoration:none;">folderlister.com/docs</a>.
              </p>

              <p style="margin:0 0 12px 0;font-size:14px;line-height:1.6;color:#374151;">
                Need help, ran into something weird, or want to double-check your workflow?
                Reach out any time at
                <a href="mailto:support@folderlister.com" style="color:#2563eb;text-decoration:none;">support@folderlister.com</a>.
              </p>

              <p style="margin:0 0 12px 0;font-size:14px;line-height:1.6;color:#374151;">
                We’re very curious about your experience and do our best to guide you and
                make Folder Lister a pleasant tool to work with. Suggestions, tweaks, and
                brutally honest feedback are all welcome.
              </p>
            </td>
          </tr>

          <tr>
            <td style="padding:8px 24px 20px 24px;">
              <p style="margin:0 0 4px 0;font-size:14px;line-height:1.5;color:#111827;">
                Kind regards,
              </p>
              <p style="margin:0;font-size:14px;line-height:1.5;color:#111827;">
                Joep — Folder Lister
              </p>
            </td>
          </tr>

          <tr>
            <td style="padding:12px 24px 18px 24px;border-top:1px solid #e5e7eb;">
              <p style="margin:0;font-size:11px;line-height:1.5;color:#9ca3af;">
                You’re receiving this email because you created an account or requested access
                to Folder Lister.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    _send_email(to_email, subject, text, html)
def _send_license_mail(email: str, key: str, plan: str, exp_iso: str | None):
    """Stuurt een nette mail met de license + korte instructies."""
    base = os.getenv("PUBLIC_BASE_URL", "https://folderlister.com")
    subject = "Your Folder Lister license key (Launch plan)"
    exp_text = exp_iso or "no expiry"

    text = f"""Hi,

Here is your Folder Lister license key:

{key}

Plan: {plan} — until {exp_text}

How to activate:
1) Open the app (Folder Lister).
2) Click the menu at the top-center (it shows “Logged in … / Logged off”).
3) Log in to eBay in the app.
4) Click the menu at the top-center again
5) Choose “Enter license key…”.
6) Paste the key and confirm.
7) On your first publish/upload, the license binds to your account.

Download & help:
- Website: {base}/
- documentation: {base}/docs/

If you didn’t request this, ignore this email.

— Joepienator
"""

    html = f"""<div style="font-family:system-ui,Segoe UI,Arial,sans-serif">
  <p>Here is your Folder Lister license key:</p>
  <p style="font-size:18px;font-weight:700;background:#111;color:#fff;display:inline-block;padding:10px 14px;border-radius:8px">{key}</p>
  <p>Plan: <b>{plan}</b> — until <b>{exp_text}</b></p>

  <h3 style="margin-top:20px">How to activate</h3>
  <ol>
    <li>Open the app (Folder Lister).</li>
    <li>Click the menu at the top-center (it shows “Logged in … / Logged off”).</li>
    <li>Log in to eBay in the app and accept Folderlister on your account.</li>
    <li>Click the menu at the top-center again</li>
    <li>Choose <b>“Enter license key…”</b>, paste the key, and confirm.</li>
    <li>On your first publish/upload, the license binds to your account.</li>
  </ol>

  <p>Download &amp; help: <a href="{base}/">{base}</a></p>

               <p style="margin:0 0 12px 0;font-size:14px;line-height:1.6;color:#374151;">
                Need help, ran into something weird, or want to double-check your workflow?
                Reach out any time at
                <a href="mailto:support@folderlister.com" style="color:#2563eb;text-decoration:none;">support@folderlister.com</a>.
              </p>
  <p style="color:#666">If you didn’t request this, you can ignore this email.</p>
</div>"""

    try:
        _send_email(email, subject, text, html)  # ← jouw bestaande mailer
    except Exception as e:
        # Loggen is genoeg; de API-call blijft gewoon 200
        print("WARN send_email failed:", e)

class LaunchStartIn(BaseModel):
    email: str | None = None
    owner_name: str | None = None
    license_key: str | None = None   # optioneel: zelf een key doorgeven
    device_id: str | None = None     # optioneeel, voor logging/koppeling
    ebay_user: str | None = None     # optioneel, fallback koppeling

# --- helpers (zet ze ergens boven je endpoint) ---
def _data_dir() -> str:
    return os.path.dirname(LICENSE_FILE)  # /srv/joepi/server/data

def _load_json(path: str | Path) -> dict:
    try:
        p = Path(path) if not isinstance(path, Path) else path
        with p.open("r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _normalize_email(raw: str | None) -> str:
    """
    Maak e-mail adressen 'stabiel' voor licenties / trials:
    - lower-case
    - @googlemail.com en *@.gmail.com → @gmail.com
    - Gmail: '+'-tag weg en punten in local-part negeren
    - En voor een paar grote providers: '+'-tag strippen
    """
    if not raw:
        return ""
    s = raw.strip().lower()
    if not s or "@" not in s:
        return s

    local, domain = s.split("@", 1)

    # gmail domeinvarianten
    if domain.endswith(".gmail.com"):
        domain = "gmail.com"
    if domain == "googlemail.com":
        domain = "gmail.com"

    # Gmail: plus-tag weg + punten negeren
    if domain == "gmail.com":
        if "+" in local:
            local = local.split("+", 1)[0]
        local = local.replace(".", "")

    # andere grote providers: alleen plus-tag weg
    if domain in ("outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.co.uk"):
        if "+" in local:
            local = local.split("+", 1)[0]

    return f"{local}@{domain}"

def _find_active_launch_by_email(email: str) -> tuple[str | None, dict | None]:
    """Zoek een ACTIEVE launch-licentie voor dit e-mail.

    Checkt eerst de (legacy) JSON-store, en dan ook SQLite — SQLite is de
    autoritatieve bron voor alle nieuwere activaties, maar bewaart nooit de
    plain key (alleen de HMAC-hash). Een match die alleen in SQLite bestaat
    krijgt dus de marker ``sqlite_only`` mee, zodat de aanroeper weet dat de
    key niet opnieuw gemaild kan worden — en in elk geval geen tweede,
    dubbele licentie voor hetzelfde e-mailadres aanmaakt.
    """
    em = _normalize_email(email)
    if not em:
        return (None, None)
    data = _load_json(LICENSE_FILE)
    for key, rec in (data.items() if isinstance(data, dict) else []):
        owner = _normalize_email(rec.get("owner_email"))
        if (rec.get("plan") == "launch"
            and (rec.get("status") or "active") == "active"
            and owner == em):
            return (key, rec)

    try:
        from .license_store import find_active_license_by_email as _find_sql
        row = _find_sql(em)
        if row and (row.get("plan") or "").lower() == "launch" and (row.get("status") or "active").lower() == "active":
            return (row["key_hash"], {**row, "sqlite_only": True})
    except Exception:
        pass
    return (None, None)

def _assert_email_verified_if_required(email: str):
    need = os.getenv("REQUIRE_EMAIL_VERIFIED_FOR_LAUNCH", "").strip().lower()
    if need in ("", "0", "false", "no", "off", "none"):
        return
    em = _normalize_email(email)
    vc_path = os.path.join(_data_dir(), "verify_codes.json")
    vc = _load_json(vc_path)
    row = vc.get(em, {})
    if not row or not row.get("verified", False):
        raise HTTPException(status_code=428, detail="email_verification_required")

# --- COMPLETE vervanging: launch start endpoint ---
@APP.post("/license/launch/start")
def license_launch_start(payload: dict = Body(...), request: Request = None):
    """
    Idempotent: max 1 launch license per e-mail. Stuurt altijd een e-mail met de key.
    E-mailverificatie afdwingen via REQUIRE_EMAIL_VERIFIED_FOR_LAUNCH=1.
    """
    raw_email = (payload.get("email") or "").strip()
    email = _normalize_email(raw_email)
    owner_name = (payload.get("owner_name") or None)

    if not email:
        raise HTTPException(400, "email_required")
    _assert_email_verified_if_required(email)

    # 1) Re-use bestaande key voor dit e-mail
    existing_key, existing = _find_active_launch_by_email(email)
    if existing_key and existing and existing.get("sqlite_only"):
        # Al een actieve licentie, maar alleen bekend in SQLite -> de plain
        # key is niet meer te achterhalen (nooit opgeslagen, alleen de hash).
        # Geen nieuwe licentie aanmaken (dat zou een duplicaat voor hetzelfde
        # e-mailadres opleveren) -- alleen melden dat er al een bestaat.
        return {
            "ok": True,
            "sent_to": None,
            "note": "existing_license_found_no_resend",
            "detail": (
                "An active license already exists for this email address. "
                "We can't resend the original key automatically -- check your "
                "inbox for the original activation email, or contact "
                "support@folderlister.com if you can't find it."
            ),
        }
    if existing_key and existing:
        migrated = False
        plain = existing.get("license_key")

        # Legacy: oude HMAC-entry zonder license_key → éénmalig migreren
        if not plain and str(existing_key).upper().startswith("HMAC"):
            migrated_key, migrated_rec = _rekey_if_hmac_for_email(email)
            if migrated_key:
                plain = migrated_key
                existing = migrated_rec
                migrated = True

        # Als we nu een plain key hebben, die altijd gebruiken
        if plain:
            _send_license_mail(
                raw_email or email,
                plain,
                "launch",
                existing.get("expires_at"),
            )
            return {
                "ok": True,
                "sent_to": raw_email or email,
                "note": "existing_launch_migrated_to_plain" if migrated else "existing_launch_reused",
            }

        # Fallback: extreem oude situatie → stuur wat we hebben (zou zelden moeten gebeuren)
        _send_license_mail(
            raw_email or email,
            existing_key,
            "launch",
            existing.get("expires_at"),
        )
        return {
            "ok": True,
            "sent_to": raw_email or email,
            "note": "existing_launch_reused",
        }
    # 1b) Geen áctieve licentie, maar wél een oude voor dit e-mail → re-activate + hergebruiken
    data = _load_json(LICENSE_FILE)
    if isinstance(data, dict):
        for store_key, rec in data.items():
            owner = _normalize_email(rec.get("owner_email"))
            if (rec.get("plan") == "launch" and owner == email):
                # Reactivate als hij niet actief is
                status = (rec.get("status") or "active").lower()
                if status != "active":
                    rec["status"] = "active"
                    data[store_key] = rec
                    _licenses_save(data)

                # Special case: oude HMAC-keys alsnog migreren
                if str(store_key).upper().startswith("HMAC"):
                    migrated_key, migrated_rec = _rekey_if_hmac_for_email(email)
                    if migrated_key:
                        _send_license_mail(
                            raw_email or email,
                            migrated_key,
                            "launch",
                            migrated_rec.get("expires_at"),
                        )
                        return {
                            "ok": True,
                            "sent_to": raw_email or email,
                            "note": "existing_launch_reactivated_migrated",
                        }

                # Normaal: bestaande plain key opnieuw mailen
                plain_key = rec.get("license_key") or store_key
                _send_license_mail(
                    raw_email or email,
                    plain_key,
                    "launch",
                    rec.get("expires_at"),
                )
                return {
                    "ok": True,
                    "sent_to": raw_email or email,
                    "note": "existing_launch_reactivated",
                }



    # 2) Nieuwe key uitgeven
    key = secrets.token_urlsafe(24)

    upsert_license_plain(
        plain_key=key,
        plan="launch",
        expires_at_iso_utc=FUTURE_EXP,
        status="active",
        owner_email=email,          # genormaliseerd
        owner_name=owner_name,
    )

    _send_license_mail(raw_email or email, key, "launch", FUTURE_EXP)
    return {"ok": True, "sent_to": raw_email or email, "note": "launch_created"}



@APP.post("/api/license/launch/start")
def license_launch_start_api(payload: dict = Body(...), request: Request = None):
    return license_launch_start(payload, request)



VERIFY_TTL = int(os.environ.get("JOEP_VERIFY_TTL_SECONDS", "900"))  # 900s = 15 min
@APP.post("/license/trial/start")
def license_trial_start(payload: TrialStartIn):

    def _vc_is_verified(email: str) -> bool:
        rec = _vc_load()
        em  = _normalize_email(email)
        row = rec.get(em)
        GRACE = int(os.environ.get("JOEP_VERIFY_GRACE_SECONDS", "86400"))
        now = int(time.time())
        return bool(row and row.get("verified") is True and now <= int(row.get("expires", 0)) + GRACE)

    if not TRIAL_ENABLED:
    # Niet per ongeluk verklappen waarom; 403 is prima.
        raise HTTPException(status_code=403, detail="trial_disabled")

    if payload.email and not _vc_is_verified(payload.email):
        raise HTTPException(428, "email_verification_required")   # 428 Precondition Required

    uid, uname, _env = _identity_get_user()   # <- bestaat al in je app
    ebay_user_effective = payload.ebay_user or (uname or None)

    # >>> gebruik nu óók de identity-username in de reuse-check
    if already_had_trial(payload.email, payload.device_id, ebay_user_effective):
        raise HTTPException(status_code=409, detail="Trial has already been used for this account/device.")

    key = secrets.token_urlsafe(24)
    exp = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    upsert_license_plain(key, plan="trial", expires_at_iso_utc=exp, status="active",
                         notes="trial", owner_email=(payload.email or None), owner_name=(payload.name or None),
                         max_accounts=1)

    # >>> registreer óók de effectieve ebay-user (niet alleen payload.ebay_user)
    record_trial(payload.email, payload.device_id, ebay_user_effective, fingerprint(key))

    # bestaand auto-attach blok kun je laten staan:
    try:
        if uid:
            attach_ebay_user(key, uname, max_accounts_default=1)      
        elif uname:
            attach_identity_id(key, uid, uname, max_accounts_default=1)
        elif payload.ebay_user:
            attach_ebay_user(key, payload.ebay_user, max_accounts_default=1)
    except Exception:
        pass

    return {"ok": True, "license_key": key, "expires_at": exp, "plan": "trial"}


@app.get("/license/status", response_model=LicenseOut)
def license_status(request: Request):
    lk = (request.headers.get("X-License-Key") or "").strip()
    rec = find_license(lk) if lk else None
    ok = bool(rec and is_valid(rec))
    out = {
        "valid": ok,
        "plan": (rec or {}).get("plan"),
        "expires_at": (rec or {}).get("expires_at"),
        "owner_email": (rec or {}).get("owner_email"),
        "owner_name": (rec or {}).get("owner_name"),
        "max_accounts": int((rec or {}).get("max_accounts") or 1) if rec else 1,
    }
    # Alleen keys meesturen als ze in het record bestaan → behoud None vs []
    if rec and ("allowed_identity_ids" in rec):
        out["allowed_identity_ids"] = rec.get("allowed_identity_ids") or []
    if rec and ("allowed_ebay_users" in rec):
        out["allowed_ebay_users"] = rec.get("allowed_ebay_users") or []
    return out


class AttachEbayIn(BaseModel):
    ebay_user: str

@app.get("/license/cookie")
def license_cookie(license_key: str | None = None, lk: str | None = None):
    key = (license_key or lk or "").strip()
    if not key:
        return JSONResponse({"detail": "license_key ontbreekt"}, status_code=400)
    resp = RedirectResponse(url="/web/editor")
    resp.set_cookie("license_key", key, httponly=True, secure=True, samesite="lax", max_age=60*60*24*30)
    return resp

@app.post("/license/attach_ebay_user", response_model=LicenseOut)
def license_attach_ebay(request: Request, payload: AttachEbayIn):
    lk = (request.headers.get("X-License-Key") or "").strip()
    if not lk:
        raise HTTPException(status_code=401, detail="Licentiesleutel ontbreekt.")
    try:
        rec = attach_ebay_user(lk, payload.ebay_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    ok = bool(rec and is_valid(rec))
    return {"valid": ok,
            "plan": rec.get("plan"),
            "expires_at": rec.get("expires_at"),
            "owner_email": rec.get("owner_email"),
            "owner_name": rec.get("owner_name"),
            "max_accounts": int(rec.get("max_accounts") or 1),
            "allowed_ebay_users": rec.get("allowed_ebay_users") or []}

# Enforce license on /web/*
# Enforce license on /web/*
# app.py
from fastapi import Request
from fastapi.responses import JSONResponse
import json

@app.middleware("http")
async def _enforce_license(request: Request, call_next):
    path = request.url.path

    # whitelists (docs/static/openapi/licensing itself)
    if path.startswith("/license") or path.startswith("/static") or path.startswith("/stripe") or path.startswith("/docs") or path == "/openapi.json":
        return await call_next(request)

    if path.startswith("/web/scanner") or path == "/web/voice-demo" or path.startswith("/web/scheeltwerk"):
        return await call_next(request)

    if path.startswith("/web"):
        # 1) header
        lk = (request.headers.get("X-License-Key") or "").strip()

        # 2) query (?license_key=... of ?lk=...)
        if not lk:
            lk = (request.query_params.get("license_key") or request.query_params.get("lk") or "").strip()

        # 3) body (JSON) bij POST/PUT/PATCH
        if not lk and request.method in {"POST", "PUT", "PATCH"}:
            ctype = request.headers.get("content-type", "")
            if "application/json" in ctype:
                body_bytes = await request.body()
                try:
                    data = json.loads(body_bytes or b"{}")
                    lk = (data.get("license_key") or "").strip()
                except Exception:
                    pass
                # heel belangrijk: body terugzetten voor het endpoint
                request._body = body_bytes

        rec = find_license(lk) if lk else None
        if not (rec and is_valid(rec)):
            return JSONResponse({"detail": "Licentie ongeldig of verlopen."}, status_code=403)

        # last_seen_at bijwerken als de licentie geldig is
        try:
            nowz = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            update_license_meta(lk, {"last_seen_at": nowz})
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Failed to update last_seen_at for %s", lk)

        # (optioneel) eBay-enforcement hier
        request.state.license_key = lk
        request.state.license = rec

    # ... je bestaande licentiecheck hierboven ...


    return await call_next(request)

# ===== end Licensing =====

# ===== E-mail =====
def _vc_load():
    try:
        txt = VERIFY_FILE.read_text("utf-8") if VERIFY_FILE.exists() else ""
        return json.loads((txt or "").strip() or "{}")
    except Exception:
        return {}


def _vc_save(d):
    VERIFY_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = VERIFY_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    tmp.replace(VERIFY_FILE)

class VerifySendIn(BaseModel):
    email: str

class VerifyConfirmIn(BaseModel):
    email: str
    code: str


LAST_EMAIL_DEBUG = {"mode": None, "host": None, "port": None, "from": None,
                    "to": None, "starttls": None, "ssl": None,
                    "error": None, "sent": False}

def _as_bool(v: str | None, default=False):
    if v is None or v == "": return default
    return str(v).strip().lower() in ("1","true","yes","y","on")

def _send_email(to_addr: str, subject: str, body: str, html: str | None = None,
                 extra_headers: dict | None = None) -> None:
    import os, smtplib, ssl
    from email.message import EmailMessage

    host = os.getenv("SMTP_HOST", "127.0.0.1")
    port = int(os.getenv("SMTP_PORT", "25"))
    use_starttls = os.getenv("SMTP_STARTTLS", "0") == "1"
    use_ssl      = os.getenv("SMTP_SSL", "0") == "1"
    user = (os.getenv("SMTP_USER") or "").strip()
    pw   = (os.getenv("SMTP_PASS") or "").strip()
    sender = os.getenv("SMTP_FROM") or "noreply@folderlister.com"

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_addr
    msg["Subject"] = subject
    for k, v in (extra_headers or {}).items():
        msg[k] = v
    msg.set_content(body if body is not None else "")
    if html:
        try:
            msg.add_alternative(html, subtype="html")
        except Exception:
            # fallback: strip simple tags and append to plain body if add_alternative fails
            try:
                import re as _re
                plain_html = _re.sub(r"<[^>]+>", "", html)
                msg.set_content((body or "") + "\n\n" + plain_html)
            except Exception:
                pass

    if use_ssl:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as s:
            if user and pw:
                s.login(user, pw)
            s.send_message(msg)
        return

    with smtplib.SMTP(host, port, timeout=20) as s:
        s.ehlo()
        # STARTTLS alleen als je dat expliciet wil én de server het adverteert
        if use_starttls and "starttls" in s.esmtp_features:
            ctx = ssl.create_default_context()
            s.starttls(context=ctx)
            s.ehlo()
        # AUTH alleen als je credentials hebt én de server AUTH ondersteunt
        if user and pw and "auth" in s.esmtp_features:
            s.login(user, pw)
        s.send_message(msg)

_EMAIL_OPTOUTS_FILE = LICENSE_FILE.parent / "email_optouts.json"
_EMAIL_OPTOUTS_LOCK = threading.Lock()

def _load_email_optouts() -> set[str]:
    try:
        if _EMAIL_OPTOUTS_FILE.exists():
            data = json.loads(_EMAIL_OPTOUTS_FILE.read_text("utf-8") or "[]")
            if isinstance(data, list):
                return {str(e).strip().lower() for e in data if e}
    except Exception:
        pass
    return set()

def is_email_opted_out(email: str) -> bool:
    return (email or "").strip().lower() in _load_email_optouts()

def add_email_optout(email: str) -> None:
    email = (email or "").strip().lower()
    if not email:
        return
    with _EMAIL_OPTOUTS_LOCK:
        emails = _load_email_optouts()
        emails.add(email)
        tmp = _EMAIL_OPTOUTS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(emails), indent=2), encoding="utf-8")
        tmp.replace(_EMAIL_OPTOUTS_FILE)

def unsubscribe_token(email: str) -> str:
    raw = f"unsub:{(email or '').strip().lower()}"
    return hmac.new(_LK_HMAC_SECRET, raw.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

def verify_unsubscribe_token(email: str, token: str) -> bool:
    if not token:
        return False
    return hmac.compare_digest(unsubscribe_token(email), str(token))

def unsubscribe_link(email: str) -> str:
    from urllib.parse import quote
    return f"https://folderlister.com/api/unsubscribe?email={quote((email or '').strip().lower())}&token={unsubscribe_token(email)}"

@APP.get("/api/unsubscribe")
@APP.post("/api/unsubscribe")
@APP.get("/unsubscribe")
@APP.post("/unsubscribe")
def api_unsubscribe(email: str = Query(...), token: str = Query(...)):
    from fastapi.responses import HTMLResponse
    email = (email or "").strip().lower()
    if not email or not verify_unsubscribe_token(email, token):
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;padding:40px;text-align:center'>"
            "<h2>Invalid or expired unsubscribe link</h2>"
            "<p>If you still want to stop receiving emails, contact support@folderlister.com.</p>"
            "</body></html>",
            status_code=400,
        )
    add_email_optout(email)
    return HTMLResponse(
        "<html><body style='font-family:sans-serif;padding:40px;text-align:center'>"
        "<h2>You've been unsubscribed</h2>"
        f"<p>{email} will no longer receive product update emails from Folder Lister.</p>"
        "</body></html>"
    )

@APP.post("/api/email/verify/send")
@APP.post("/email/verify/send")
def email_verify_send(body: VerifySendIn, request: Request):
    email = _normalize_email(body.email)
    if not email:
        raise HTTPException(400, "email required")
    now = int(time.time())
    code = f"{random.randint(0, 999999):06d}"
    send_email = False
    with _VC_LOCK:
        rec = _vc_load()
        row = rec.get(email) or {}

        # cooldown
        last = int(row.get("last_send_ts", 0))
        if now - last < SEND_MIN_COOLDOWN:
            retry = SEND_MIN_COOLDOWN - (now - last)
            resp = JSONResponse({"ok": False, "detail": "cooldown_active", "retry_after": retry}, status_code=429)
            resp.headers["Retry-After"] = str(retry)
            return resp

        # rolling windows
        hist = [t for t in (row.get("send_history") or []) if now - int(t) <= 86400]
        per_hour = len([t for t in hist if now - int(t) <= 3600])
        per_day  = len(hist)

        if per_hour >= MAX_PER_HOUR or per_day >= MAX_PER_DAY:
            resp = JSONResponse({"ok": False, "detail": "rate_limited"}, status_code=429)
            resp.headers["Retry-After"] = "3600"
            return resp

        hist.append(now)
        row.update({"code": code, "created": now, "expires": now + VERIFY_TTL,
                    "tries": 0, "last_send_ts": now, "send_history": hist})
        rec[email] = row
        _vc_save(rec)
        send_email = True

    if send_email:
        if os.environ.get("DEBUG_EMAIL_TO_CONSOLE", "0") == "1":
            _log_send(email, code)
        else:
            _send_email(to_addr=email, subject="Your verification code", body=f"Your code: {code}")
    return {"ok": True}

MAX_TRIES = int(os.environ.get("JOEP_VERIFY_MAX_TRIES", "5"))

@APP.post("/api/email/verify/confirm")
@APP.post("/email/verify/confirm")
def email_verify_confirm(body: VerifyConfirmIn):
    email = _normalize_email(body.email)
    code  = (body.code or "").strip()
    if not email or not code:
        raise HTTPException(400, "email_and_code_required")
    with _VC_LOCK:
        rec   = _vc_load()
        row   = rec.get(email) or {}

        now = int(time.time())
        if not row or now > int(row.get("expires", 0)):
            raise HTTPException(400, "invalid_or_expired")

        tries = int(row.get("tries", 0))
        if tries >= MAX_TRIES:
            raise HTTPException(429, "too_many_attempts")

        if row.get("code") != code:
            backoff = min(60, 2 ** tries)
            row["tries"] = tries + 1
            rec[email] = row
            _vc_save(rec)
            resp = JSONResponse({"ok": False, "detail": "wrong_code", "backoff": backoff}, status_code=400)
            return resp

        # correct
        row.update({"verified": True})
        rec[email] = row
        _vc_save(rec)
    return {"ok": True}






def _sell_account_list_return_policies(env: str, site: str) -> dict:
    """List return policies for a marketplace and return JSON."""
    market = MARKETPLACE_ID.get(site.upper())
    return _sell_account_get(env, "/sell/account/v1/return_policy", market)

def _sell_account_get_return_policy_by_id(env: str, site: str, policy_id: str) -> dict:
    """Fetch policy by ID by listing all and selecting the one with matching ID."""
    try:
        data = _sell_account_list_return_policies(env, site) or {}
        items = data.get("returnPolicies", []) or []
        for it in items:
            if str(it.get("returnPolicyId") or "") == str(policy_id):
                return it
        return {}
    except HTTPException:
        return {}

# ===== AI Quota helpers =====
# Limits are read from .env so you can tune them without code changes:
#   AI_QUOTA_LAUNCH=100
#   AI_QUOTA_PRO=10000
#   AI_QUOTA_TRIAL=20   (optional, defaults to 0 = no AI for trial)

def _ai_quota_limit(plan: str) -> int:
    """Return monthly AI call limit for the given plan name."""
    plan = (plan or "").lower()
    if "extreme" in plan:
        default = 2_000
        env_key = "AI_QUOTA_EXTREME"
    elif "pro" in plan:
        default = 10_000
        env_key = "AI_QUOTA_PRO"
    elif "launch" in plan:
        default = 100
        env_key = "AI_QUOTA_LAUNCH"
    elif "trial" in plan:
        default = 20
        env_key = "AI_QUOTA_TRIAL"
    else:
        default = 0
        env_key = ""
    try:
        return int(os.getenv(env_key, default)) if env_key else default
    except Exception:
        return default


def _check_and_increment_ai_quota(request: Request, kind: str = "other") -> None:
    """
    Check whether the calling license has AI calls remaining this month.
    Increment the counter. Raises HTTP 429 if quota exceeded.
    kind: "image" | "voice" | "other"  — tracked separately for usage overview.
    """
    rec = getattr(request.state, "license", None)
    lk  = getattr(request.state, "license_key", None)
    if not rec or not lk:
        raise HTTPException(403, "Licentie niet gevonden.")

    plan = (rec.get("plan") or rec.get("product") or "").lower()
    limit = _ai_quota_limit(plan)

    now_month = datetime.now(timezone.utc).strftime("%Y-%m")
    total_used, _images_used, _voice_used = _shared_ai_usage_totals(rec, now_month)

    if limit == 0:
        raise HTTPException(
            429,
            f"AI-beschrijvingsassistent is niet beschikbaar voor plan '{plan}'. "
            "Upgrade naar Launch of Pro om AI te gebruiken."
        )

    if total_used >= limit:
        raise HTTPException(
            429,
            f"Je hebt je maandelijkse AI-limiet bereikt ({limit} calls voor plan '{plan}'). "
            "Limiet reset op de 1e van de volgende maand."
        )

    # Increment total + per-kind counter
    current_total = _month_counter_value(rec, "ai_calls_used", "ai_calls_month", now_month)
    updates: dict = {
        "ai_calls_used": current_total + 1,
        "ai_calls_month": now_month,
    }
    if kind == "image":
        img_used = _month_counter_value(rec, "ai_images_used", "ai_images_month", now_month)
        updates["ai_images_used"]  = img_used + 1
        updates["ai_images_month"] = now_month
    elif kind == "voice":
        v_used = _month_counter_value(rec, "ai_voice_used", "ai_voice_month", now_month)
        updates["ai_voice_used"]  = v_used + 1
        updates["ai_voice_month"] = now_month
    update_license_meta(lk, updates)


# ═════════════════════════════════════════════════════════════════════════════
# AI-trainingsdata: voorstel gekoppeld aan wat er gepubliceerd werd
# ═════════════════════════════════════════════════════════════════════════════
# Elke AI-call krijgt een analysis_id terug. De desktop-app bewaart dat op de
# rij en stuurt het mee bij publiceren. Het paar (wat stelde de AI voor, wat
# publiceerde de verkoper) is het enige signaal dat vertelt of een suggestie
# deugde; losse AI-antwoorden zonder uitkomst leren je niets.
#
# Alles loopt via db.log_event, dus het landt in request_log en is uit te lezen
# vanuit het admin panel. Fire-and-forget: loggen mag een AI-call nooit breken.
#
# Bewust NIET opgeslagen:
#   - image_b64: die blobs maken van de logtabel een fotoarchief.
#   - de ruwe user_instruction: vrije tekst die klanten zelf intypen.
# Call sites geven daarom zelf een opgeschoonde inputs-dict door, zodat per
# endpoint zichtbaar is wat er wel en niet bewaard wordt.

_AI_LOG_ANALYSIS = "ai_analysis"
_AI_LOG_PUBLISHED = "ai_published"


def _new_analysis_id() -> str:
    return secrets.token_hex(16)


def _ai_license_fp(request: Request) -> str:
    """Stabiele, niet-herleidbare sleutel per licentie. Zelfde fingerprint-functie
    als de rest van de server, zodat je per gebruiker kunt filteren zonder de
    licentiesleutel zelf op te slaan."""
    try:
        lk = getattr(request.state, "license_key", None)
        return fingerprint(lk) if lk else ""
    except Exception:
        return ""


def _ai_log_analysis(request: Request, analysis_id: str, kind: str,
                     inputs: Dict[str, Any], output: Dict[str, Any]) -> None:
    try:
        _db.log_event(
            _AI_LOG_ANALYSIS,
            ip_hash=fingerprint(_client_ip(request)),
            license_fp=_ai_license_fp(request),
            endpoint=kind,
            meta={"analysis_id": analysis_id, "inputs": inputs, "output": output},
        )
    except Exception:
        pass


def _ai_log_published(request: Request, analysis_id: str, row: Dict[str, Any],
                      site: str = "", outcome: str = "published") -> None:
    """Leg vast wat er uiteindelijk de deur uit ging voor een eerder AI-voorstel."""
    try:
        specifics = row.get("item_specifics") or row.get("aspects") or {}
        if not isinstance(specifics, dict):
            specifics = {}
        _db.log_event(
            _AI_LOG_PUBLISHED,
            ip_hash=fingerprint(_client_ip(request)),
            license_fp=_ai_license_fp(request),
            endpoint=outcome,
            meta={
                "analysis_id": analysis_id,
                "site": site or str(row.get("site_code") or ""),
                "final": {
                    "title": str(row.get("title") or "")[:300],
                    "category_id": str(row.get("category_id") or ""),
                    "condition_id": str(row.get("condition_id") or ""),
                    "price": row.get("price"),
                    "quantity": row.get("quantity"),
                    "item_specifics": {str(k): str(v)[:200] for k, v in list(specifics.items())[:60]},
                },
            },
        )
    except Exception:
        pass


@app.get("/license/ai_limits")
def ai_limits_endpoint(license_key: str = "", lk: str = ""):
    """Return monthly AI-credit usage for this license key."""
    key = (license_key or lk or "").strip()
    if not key:
        raise HTTPException(400, "license_key required")
    rec = find_license(key)
    if not rec:
        raise HTTPException(404, "License not found")

    plan  = (rec.get("plan") or rec.get("product") or "").lower()
    limit = _ai_quota_limit(plan)
    now_month = datetime.now(timezone.utc).strftime("%Y-%m")

    total_used, images_used, voice_used = _shared_ai_usage_totals(rec, now_month)

    effective_used = max(total_used, images_used + voice_used)
    left = max(0, limit - effective_used) if limit > 0 else None

    from .eps_limits import next_reset_date
    return {
        "quota":        limit,
        "total_used":   effective_used,
        "images_used":  images_used,
        "voice_used":   voice_used,
        "left":         left,
        "is_unlimited": limit >= 10_000,
        "reset_date":   next_reset_date(),
        "plan":         plan,
        "month":        now_month,
    }


# ===== AI Description Analyzer =====

class _AnalyzeDescIn(BaseModel):
    title: str = ""
    description: str = ""
    aspects: List[Dict[str, Any]] = []  # [{name, values: [], required: bool}]
    target_site: str = "NL"
    target_language: str = ""
    current_values: Dict[str, Any] = {}
    condition_options: List[Dict[str, Any]] = []
    user_instruction: str = ""   # extra writing instruction from the seller
    # De client stuurt deze al mee, maar zonder veld hier gooide pydantic ze weg.
    # Ze worden (nog) niet in de prompt gebruikt; ze staan hier zodat een
    # gelogde analyse per categorie te groeperen is.
    category_id: str = ""
    category_name: str = ""


_AI_SITE_LANGUAGE: Dict[str, str] = {
    "NL": "nl-NL",
    "BE": "nl-BE",
    "DE": "de-DE",
    "AT": "de-AT",
    "CH": "de-CH",
    "FR": "fr-FR",
    "IT": "it-IT",
    "ES": "es-ES",
    "UK": "en-GB",
    "GB": "en-GB",
    "US": "en-US",
    "CA": "en-CA",
    "AU": "en-AU",
}


def _target_language_for_site(site: str, fallback: str = "en-GB") -> str:
    return _AI_SITE_LANGUAGE.get(str(site or "").strip().upper(), fallback)


def _norm_match_text(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return " ".join(s.split())


# Bidirectional aliases for canonical-equivalent labels. The LEFT and RIGHT
# of each pair are treated as the same value: "Medium" matches "M" and vice
# versa. Only short, unambiguous, label-equivalent pairs belong here -- never
# concept substitutions like "metal"->"Steel".
_VALUE_ALIASES: List[tuple[str, str]] = [
    # Clothing sizes (numeric letters <-> spelled out)
    ("xxs", "extra extra small"), ("xs", "extra small"),
    ("s", "small"), ("m", "medium"), ("l", "large"),
    ("xl", "extra large"), ("xxl", "extra extra large"),
    ("xxxl", "3xl"), ("2xl", "xxl"), ("3xl", "xxxl"),
    # Country codes (most common -> full eBay label)
    ("uk", "united kingdom"), ("gb", "united kingdom"),
    ("us", "united states"), ("usa", "united states"),
    ("nl", "netherlands"), ("de", "germany"), ("fr", "france"),
    ("it", "italy"), ("es", "spain"), ("be", "belgium"),
    ("at", "austria"), ("ch", "switzerland"), ("ie", "ireland"),
    ("pl", "poland"), ("se", "sweden"), ("dk", "denmark"),
    ("no", "norway"), ("fi", "finland"), ("pt", "portugal"),
    ("cz", "czech republic"), ("au", "australia"), ("ca", "canada"),
    ("jp", "japan"), ("cn", "china"), ("hk", "hong kong"),
    # Yes/No-style booleans
    ("yes", "y"), ("no", "n"),
]
# Build a lookup that maps either side -> a set of equivalent normalised forms.
_ALIAS_LOOKUP: Dict[str, set] = {}
for _a, _b in _VALUE_ALIASES:
    _ALIAS_LOOKUP.setdefault(_a, set()).add(_b)
    _ALIAS_LOOKUP.setdefault(_b, set()).add(_a)


def _expand_aliases(norm_value: str) -> set:
    """Return all normalised equivalents for a normalised value (incl. itself)."""
    out = {norm_value}
    seen = {norm_value}
    queue = [norm_value]
    while queue:
        cur = queue.pop()
        for nxt in _ALIAS_LOOKUP.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                out.add(nxt)
                queue.append(nxt)
    return out


def _match_allowed_value(value: Any, allowed: List[str]) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    lower_raw = raw.lower()
    for opt in allowed:
        if opt.lower() == lower_raw:
            return opt

    norm_raw = _norm_match_text(raw)
    for opt in allowed:
        norm_opt = _norm_match_text(opt)
        if norm_opt and norm_opt == norm_raw:
            return opt

    # Alias pass: "Medium" -> "M", "UK" -> "United Kingdom", etc.
    raw_aliases = _expand_aliases(norm_raw)
    for opt in allowed:
        norm_opt = _norm_match_text(opt)
        if not norm_opt:
            continue
        if norm_opt in raw_aliases:
            return opt
        # Also check the opt's own aliases — handles cases where allowed list
        # has spelled-out form but user spoke the abbreviation.
        if _expand_aliases(norm_opt) & raw_aliases:
            return opt
    return None

@app.post("/web/ai/analyze_description")
async def analyze_description(body: _AnalyzeDescIn, request: Request):
    """
    Text-only AI extraction: description + category aspects → structured specifics.
    Uses OpenAI gpt-4o-mini with Structured Outputs (same as describe-item, no audio).
    Values MUST be from the allowed list (exact case match) or null.
    """
    _check_and_increment_ai_quota(request, kind="image")
    analysis_id = _new_analysis_id()
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(503, "AI-service niet geconfigureerd (geen OPENAI_API_KEY op de server).")

    try:
        from openai import OpenAI as _OpenAI
    except ImportError:
        raise HTTPException(503, "openai SDK niet geïnstalleerd op de server.")

    oai = _OpenAI(api_key=api_key)
    target_site = (body.target_site or "NL").strip().upper() or "NL"
    target_language = (body.target_language or "").strip() or _target_language_for_site(target_site)
    current_values = body.current_values or {}
    condition_options = [c for c in (body.condition_options or []) if isinstance(c, dict)]
    condition_labels = [str(c.get("label") or "").strip() for c in condition_options if str(c.get("label") or "").strip()]

    # Build aspect lines for the prompt
    aspect_lines = ""
    allowed_map: Dict[str, List[str]] = {}
    for asp in body.aspects:
        name = str(asp.get("name") or "").strip()
        if not name:
            continue
        values = [str(v) for v in (asp.get("values") or []) if str(v).strip()]
        allowed_map[name] = values
        imp = "required" if asp.get("required") else "optional"
        if values:
            shown = values[:40]
            suffix = f" (+{len(values)-40} meer)" if len(values) > 40 else ""
            aspect_lines += f"- {name} [{imp}]: {', '.join(shown)}{suffix}\n"
        else:
            aspect_lines += f"- {name} [{imp}]: (vrij tekstveld)\n"

    if not aspect_lines:
        aspect_lines = "(geen categorie-aspecten beschikbaar)\n"

    system_prompt = (
        "Je bent een eBay listing-assistent. "
        "Extraheer itemgegevens uitsluitend op basis van de beschrijving en het meegegeven schema. "
        "De output moet in de taal van de doelmarktplaats staan. "
        "Vertaal dus impliciet naar de target language wanneer de invoer in een andere taal is. "
        "Geef drie beschrijvingsvarianten terug: "
        "(1) description_suggestion: vlotte, aangenaam leesbare listingtekst. "
        "Geen verzonnen feiten, geen marketingtaal over de koper ('uniek voor liefhebbers', 'perfect cadeau'). "
        "Mag narratief zijn zolang alles feitelijk onderbouwd is. "
        "(2) factual_description_suggestion: strikt feitelijke opsomming, droge stijl, alleen wat letterlijk aanwezig is. "
        "Geen verhaal, geen interpretatie, geen sfeer. "
        "(3) seo_description_suggestion: SEO-vriendelijke variant die natuurlijk leest en geen feiten verzint. "
        "Geef ook title_suggestion terug als een sterke eBay-titel van maximaal 80 tekens. "
        "Zet de belangrijkste zoekwoorden vooraan: merk, item type, model/serie/franchise, daarna pas variantdetails zoals maat, kleur, materiaal of schaal. "
        "Gebruik alleen feitelijk onderbouwde woorden, geen stopwoorden of verkooppraat. "
        "Als de huidige titel al slim en bruikbaar is, verbeter hem dan licht in plaats van hem volledig te herschrijven. "
        "Gebruik de meegegeven titel als baseline voor de item-identiteit wanneer die al bruikbaar is. "
        "Behoud de kernwoorden uit die basistitel, vooral merk, itemtype en franchise/model, tenzij de rest van de input die duidelijk tegenspreekt. "
        "Gebruik de beschrijving vooral om te verfijnen of corrigeren, niet om de hoofdidentiteit te vervangen door een klein detail zoals alleen schaal, maat, kleur of conditie. "
        "Noem quantity, voorraad, stock count of beschikbaar aantal nooit in description_suggestion, factual_description_suggestion of seo_description_suggestion. "
        "quantity_suggestion mag wel apart worden teruggegeven als veldsuggestie, maar hoort niet thuis in de beschrijvingsteksten. "
        "Als er condition_options zijn meegegeven, kies condition_suggestion alleen uit die lijst. "
        "Gebruik bij selectievelden altijd exact een allowed value uit het schema. "
        "Je mag een specific afleiden uit de betekenis van de beschrijving, ook als de specific-naam zelf niet wordt genoemd. "
        "Als de gebruiker een breed concept noemt en de allowed list bevat alleen specifiekere subtypes, kies dan het meest waarschijnlijke subtype als sensible default. "
        "Voorbeeld: gebruiker zegt 'metaal' / 'metal' en allowed list bevat Steel/Iron/Aluminium maar geen Metal -> kies Steel als default (Steel is een metaal). "
        "Als er meerdere even waarschijnlijke kandidaten zijn, kies de eerste alfabetische. "
        "UITZONDERING -- Country of origin aspect: dit aspect heet per site verschillend ('Country/Region of Manufacture', 'Country of Origin', 'Land van herkomst', 'Pays de fabrication', etc.). "
        "Detecteer het uit triggerwoorden in de input: 'land', 'country', 'herkomst', 'gemaakt in', 'made in', 'origin', 'pays'. Vul daar de juiste aspect-key voor in. "
        "Voor dit aspect mag je de gangbare landnaam canoniek maken in de target_language. "
        "Voorbeeld: 'america' / 'amerika' / 'USA' -> 'Verenigde Staten' (op NL site) of 'United States' (op Engelse site). "
        "'holland' -> 'Netherlands' / 'Nederland'. 'duitsland' / 'germany' -> 'Germany' / 'Duitsland'. "
        "'GB' / 'UK' -> 'United Kingdom' / 'Verenigd Koninkrijk'. "
        "Gebruik altijd de canonieke vorm zoals een eBay-listing die zou tonen in de target_language. "
        "Verzin geen feiten. Geef prijs/qty alleen terug als expliciet genoemd. "
        "Als de verkoperinstructie feitelijke defaults of expliciete feiten bevat, behandel die dan als high-priority context voor condition, prijs, quantity, title en specifics, "
        "tenzij de beschrijving of current_values dat duidelijk tegenspreken. "
        "Gebruik een feitelijke verkoperinstructie dus niet alleen voor schrijfstijl, maar ook voor de inhoudelijke extractie."
    )
    if body.user_instruction and body.user_instruction.strip():
        system_prompt += f" Verkoperinstructie (kan schrijfstijl én feitelijke defaults bevatten): {body.user_instruction.strip()}"
    user_content = json.dumps({
        "title": body.title or "",
        "description": body.description or "",
        "target_site": target_site,
        "target_language": target_language,
        "current_values": current_values,
        "condition_options": condition_options,
        "item_specifics_schema": aspect_lines,
        "seller_instruction": body.user_instruction or "",
    }, ensure_ascii=False)

    # Re-use _DESCRIBE_ITEM_SCHEMA for consistent Structured Output
    try:
        resp = oai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_content},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "folderlister_item_extract",
                    "strict": True,
                    "schema": _DESCRIBE_ITEM_SCHEMA,
                },
            },
            temperature=0.1,
        )
        result = json.loads(resp.choices[0].message.content)
    except Exception as exc:
        raise HTTPException(502, f"AI extractie mislukt: {exc}")

    # Post-process: snap to allowed values without silently dropping. The LLM is
    # now instructed to return the user's literal value; we map it to the allowed
    # list here and expose both the raw and mapped value plus a taxonomy_match flag.
    clean_specifics: Dict[str, str] = {}
    clean_confidence: Dict[str, float] = {}
    spec_meta: List[Dict[str, Any]] = []
    for sp in result.get("specifics") or []:
        name = str(sp.get("name") or "").strip()
        val  = sp.get("value")
        conf = float(sp.get("confidence") or 0.0)
        if not name or not val:
            continue
        raw_val = str(val).strip()
        allowed = allowed_map.get(name, [])
        if allowed:
            match = _match_allowed_value(raw_val, allowed)
            if match:
                clean_specifics[name] = match
                clean_confidence[name] = conf
                spec_meta.append({
                    "name": name, "value": match, "raw_value": raw_val,
                    "confidence": conf, "taxonomy_match": True,
                    "allowed_sample": allowed[:8],
                })
            else:
                # Don't write to clean_specifics (so live drafts stay clean) but
                # surface the raw value so the client can show a review prompt
                # instead of silently dropping it.
                spec_meta.append({
                    "name": name, "value": None, "raw_value": raw_val,
                    "confidence": conf, "taxonomy_match": False,
                    "allowed_sample": allowed[:8],
                })
        else:
            clean_specifics[name] = raw_val
            clean_confidence[name] = conf
            spec_meta.append({
                "name": name, "value": raw_val, "raw_value": raw_val,
                "confidence": conf, "taxonomy_match": True,
                "allowed_sample": [],
            })

    flat_response = {
        "analysis_id": analysis_id,
        "specifics": clean_specifics,
        "confidence": clean_confidence,
        "specifics_meta": spec_meta,
        "description_suggestion": result.get("description_suggestion") or "",
        "factual_description_suggestion": result.get("factual_description_suggestion") or "",
        "seo_description_suggestion": result.get("seo_description_suggestion") or "",
        "condition_suggestion": _match_allowed_value(result.get("condition_suggestion"), condition_labels) if condition_labels else result.get("condition_suggestion"),
        "condition_confidence": 0.0,
        "price_suggestion": result.get("price_suggestion"),
        "price_confidence": 0.0,
        "quantity_suggestion": result.get("quantity_suggestion"),
        "quantity_confidence": 0.0,
        "title_suggestion": result.get("title_suggestion"),
        "title_confidence": 0.0,
    }
    # v2: attach normalized candidates for resolver consumption
    try:
        from .ai_resolver import normalize_text_extract_to_candidates  # type: ignore[import]
        flat_response["candidates"] = [
            c.to_dict() for c in normalize_text_extract_to_candidates(
                {**flat_response, "specifics": [
                    {"name": k, "value": v, "confidence": clean_confidence.get(k, 0.7)}
                    for k, v in clean_specifics.items()
                ]},
                allowed_values=allowed_map,
            )
        ]
    except Exception:
        flat_response["candidates"] = []

    _ai_log_analysis(request, analysis_id, "analyze_description", {
        "title": str(body.title or "")[:300],
        "description": str(body.description or "")[:2000],
        "category_id": str(getattr(body, "category_id", "") or ""),
        "category_name": str(getattr(body, "category_name", "") or ""),
        "target_site": target_site,
        "target_language": target_language,
        "aspect_names": list(allowed_map.keys())[:60],
        "n_condition_options": len(condition_labels),
        "has_user_instruction": bool(str(getattr(body, "user_instruction", "") or "").strip()),
    }, flat_response)
    return flat_response


# ===== AI Voice → Describe Item =====

# JSON schema for Structured Outputs (OpenAI strict mode)
def _normalize_ai_text_list(raw_values: Any, *, limit: int = 8) -> List[str]:
    if isinstance(raw_values, str):
        raw_values = [raw_values]
    if not isinstance(raw_values, list):
        raw_values = []

    out: List[str] = []
    seen: set = set()
    for value in raw_values:
        text = re.sub(r"\s+", " ", str(value or "")).strip(" \t-,:;")
        if len(text) < 2:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _normalize_ai_category_candidates(
    raw_candidates: Any,
    *,
    fallback_label: str = "",
    fallback_confidence: int = 0,
) -> List[Dict[str, Any]]:
    if isinstance(raw_candidates, dict):
        raw_candidates = (
            raw_candidates.get("category_candidates")
            or raw_candidates.get("candidates")
            or raw_candidates.get("items")
            or []
        )
    if not isinstance(raw_candidates, list):
        raw_candidates = []

    normalized: List[Dict[str, Any]] = []
    seen_labels: set = set()

    def _add_candidate(raw_label: Any, raw_conf: Any, raw_reason: Any, raw_terms: Any) -> None:
        label = re.sub(r"\s+", " ", str(raw_label or "")).strip(" \t-,:;")
        if len(label) < 2:
            return
        key = label.lower()
        if key in seen_labels:
            return
        seen_labels.add(key)
        try:
            conf = int(float(raw_conf or 0))
        except Exception:
            conf = 0
        conf = max(0, min(100, conf))
        reasons = _normalize_ai_text_list(raw_reason, limit=4)
        terms = _normalize_ai_text_list([label] + list(raw_terms or []), limit=6)
        normalized.append({
            "label": label,
            "confidence": conf,
            "reason": reasons,
            "search_terms": terms,
        })

    for candidate in raw_candidates:
        if not isinstance(candidate, dict):
            continue
        _add_candidate(
            candidate.get("label") or candidate.get("query") or candidate.get("name"),
            candidate.get("confidence") or candidate.get("score"),
            candidate.get("reason") or candidate.get("reasons"),
            candidate.get("search_terms") or candidate.get("terms") or [],
        )

    if fallback_label:
        _add_candidate(fallback_label, fallback_confidence, [], [fallback_label])

    normalized.sort(key=lambda c: (-int(c.get("confidence") or 0), str(c.get("label") or "").lower()))
    return normalized[:5]


def _flatten_ai_category_search_terms(
    category_candidates: Any,
    raw_terms: Any = None,
    *,
    limit: int = 12,
) -> List[str]:
    out = _normalize_ai_text_list(raw_terms, limit=limit)
    seen = {str(v).lower() for v in out}
    for candidate in list(category_candidates or []):
        if not isinstance(candidate, dict):
            continue
        for term in [candidate.get("label")] + list(candidate.get("search_terms") or []):
            text = re.sub(r"\s+", " ", str(term or "")).strip(" \t-,:;")
            if len(text) < 2:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(text)
            if len(out) >= limit:
                return out
    return out


_DESCRIBE_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "transcript": {"type": "string"},
        "language": {"type": "string"},
        "title_suggestion": {"type": "string"},
        "description_suggestion": {"type": "string"},
        "factual_description_suggestion": {"type": "string"},
        "seo_description_suggestion": {"type": "string"},
        "condition_suggestion": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "price_suggestion": {"anyOf": [{"type": "number"}, {"type": "null"}]},
        "quantity_suggestion": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
        "specifics": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "value": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "importance": {"type": "string", "enum": ["required", "recommended", "optional"]},
                    "confidence": {"type": "number"},
                    "apply": {"type": "boolean"},
                },
                "required": ["name", "value", "importance", "confidence", "apply"],
                "additionalProperties": False,
            },
        },
        "missing_required": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "array", "items": {"type": "string"}},
        "category_candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                    "reason": {"type": "array", "items": {"type": "string"}},
                    "search_terms": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["label", "confidence", "reason", "search_terms"],
                "additionalProperties": False,
            },
        },
        "search_terms": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "transcript", "language", "title_suggestion",
        "description_suggestion", "factual_description_suggestion", "seo_description_suggestion",
        "condition_suggestion",
        "price_suggestion", "quantity_suggestion", "specifics",
        "missing_required", "notes", "category_candidates", "search_terms",
    ],
    "additionalProperties": False,
}


@app.post("/web/ai/describe-item")
async def describe_item(
    request: Request,
    audio: UploadFile = File(...),
    language: str = Form("nl-NL"),
    target_site: str = Form("NL"),
    target_language: str = Form(""),
    title_hint: str = Form(""),
    category_id: str = Form(""),
    category_name: str = Form(""),
    profile_name: str = Form(""),
    item_specifics_schema: str = Form("[]"),
    condition_options: str = Form("[]"),
    user_instruction: str = Form(""),
    current_values: str = Form("{}"),
):
    """
    1. Transcribe audio with gpt-4o-mini-transcribe
    2. Extract structured listing data via gpt-4o-mini Structured Outputs
    Returns a fully typed JSON response matching _DESCRIBE_ITEM_SCHEMA.
    """
    _check_and_increment_ai_quota(request, kind="voice")
    analysis_id = _new_analysis_id()
    import tempfile

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(503, "AI-service niet geconfigureerd (geen OPENAI_API_KEY op de server).")

    try:
        from openai import OpenAI as _OpenAI  # lazy import
    except ImportError:
        raise HTTPException(503, "openai SDK niet geïnstalleerd op de server.")

    oai = _OpenAI(api_key=api_key)
    target_site = (target_site or "NL").strip().upper() or "NL"
    target_language = (target_language or "").strip() or _target_language_for_site(target_site)

    # ── Step 1: Transcribe ──────────────────────────────────────────────────
    raw_audio = await audio.read()
    tmp_path = None
    try:
        suffix = "." + (audio.filename or "audio.wav").rsplit(".", 1)[-1].lower()
        if suffix not in (".wav", ".mp3", ".m4a", ".ogg", ".webm", ".flac"):
            suffix = ".wav"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(raw_audio)
            tmp_path = tmp.name

        with open(tmp_path, "rb") as f:
            tr = oai.audio.transcriptions.create(
                model="gpt-4o-mini-transcribe",
                file=f,
                language=language.split("-")[0] if language else "nl",
            )
        transcript = (getattr(tr, "text", None) or "").strip()
    except Exception as exc:
        raise HTTPException(502, f"Transcriptie mislukt: {exc}")
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    # ── Step 2: Extract structured data ────────────────────────────────────
    try:
        schema_list = json.loads(item_specifics_schema or "[]")
    except Exception:
        schema_list = []
    try:
        cur_vals = json.loads(current_values or "{}")
    except Exception:
        cur_vals = {}
    try:
        cond_options = json.loads(condition_options or "[]")
    except Exception:
        cond_options = []
    condition_labels = [str(c.get("label") or "").strip() for c in (cond_options or []) if str(c.get("label") or "").strip()]

    # Build allowed-values table for the prompt
    asp_lines = ""
    for asp in schema_list:
        name = str(asp.get("name") or "").strip()
        if not name:
            continue
        vals = [str(v) for v in (asp.get("allowed_values") or []) if str(v).strip()]
        imp = str(asp.get("importance") or "optional")
        if vals:
            shown = vals[:40]
            suffix_v = f" (+{len(vals)-40} meer)" if len(vals) > 40 else ""
            asp_lines += f"- {name} [{imp}]: {', '.join(shown)}{suffix_v}\n"
        else:
            asp_lines += f"- {name} [{imp}]: (vrij tekstveld)\n"

    system_prompt = (
        "Je bent een eBay listing-assistent voor FolderLister. "
        "Extraheer itemgegevens uitsluitend op basis van de transcript, titelverwijzing en het meegegeven schema. "
        "De transcript kan in een andere taal zijn dan de doelmarktplaats. "
        "Zet de betekenis daarom om naar de taal van de doelmarktplaats voordat je item specifics teruggeeft. "
        "Geef drie beschrijvingsvarianten terug: "
        "(1) description_suggestion: vlotte, aangenaam leesbare listingtekst. "
        "Geen verzonnen feiten, geen marketingtaal over de koper ('uniek voor liefhebbers', 'perfect cadeau'). "
        "Mag narratief zijn zolang alles feitelijk onderbouwd is. "
        "(2) factual_description_suggestion: strikt feitelijke opsomming, droge stijl, alleen wat letterlijk is gezegd. "
        "Geen verhaal, geen interpretatie, geen sfeer. "
        "(3) seo_description_suggestion: SEO-vriendelijke variant die natuurlijk leest en geen feiten verzint. "
        "Geef ook title_suggestion terug als een sterke eBay-titel van maximaal 80 tekens. "
        "Zet de belangrijkste zoekwoorden vooraan: merk, item type, model/serie/franchise, daarna pas variantdetails zoals maat, kleur, materiaal of schaal. "
        "Gebruik alleen feitelijk onderbouwde woorden, geen stopwoorden of verkooppraat. "
        "Als de huidige titel al slim en bruikbaar is, verbeter hem dan licht in plaats van hem volledig te herschrijven. "
        "Gebruik title_hint als baseline voor de item-identiteit wanneer die al op een echte itemtitel lijkt. "
        "Behoud de kernwoorden uit die basistitel, vooral merk, itemtype en franchise/model, tenzij de transcript die duidelijk tegenspreekt. "
        "Gebruik de transcript vooral om details te verfijnen of corrigeren, niet om de hoofdidentiteit te vervangen door een klein detail zoals alleen schaal, maat, kleur of conditie. "
        "Noem quantity, voorraad, stock count of beschikbaar aantal nooit in description_suggestion, factual_description_suggestion of seo_description_suggestion. "
        "quantity_suggestion mag wel apart worden teruggegeven als veldsuggestie, maar hoort niet thuis in de beschrijvingsteksten. "
        "Als er condition_options zijn meegegeven, kies condition_suggestion alleen uit die lijst. "
        "Gebruik alleen allowed values wanneer die beschikbaar zijn, en geef die exact terug zoals in het schema. "
        "Je mag een specific afleiden uit de betekenis van een zin, ook als de specific-naam zelf niet letterlijk is gezegd. "
        "Als de spreker een breed concept noemt en de allowed list bevat alleen specifiekere subtypes, kies dan het meest waarschijnlijke subtype als sensible default. "
        "Voorbeeld: spreker zegt 'metaal' / 'metal' en allowed list bevat Steel/Iron/Aluminium maar geen Metal -> kies Steel als default (Steel is een metaal). "
        "Als er meerdere even waarschijnlijke kandidaten zijn, kies de eerste alfabetische. "
        "UITZONDERING -- Country of origin aspect: dit aspect heet per site verschillend ('Country/Region of Manufacture', 'Country of Origin', 'Land van herkomst', 'Pays de fabrication', etc.). "
        "Detecteer het uit triggerwoorden in de transcript: 'land', 'country', 'herkomst', 'gemaakt in', 'made in', 'origin', 'pays'. Vul daar de juiste aspect-key voor in. "
        "Voor dit aspect mag je de gangbare landnaam canoniek maken in de target_language. "
        "Voorbeeld: spreker zegt 'america' / 'amerika' / 'USA' -> 'Verenigde Staten' (op NL site) of 'United States' (op Engelse site). "
        "'holland' -> 'Netherlands' / 'Nederland'. 'duitsland' / 'germany' -> 'Germany' / 'Duitsland'. "
        "'GB' / 'UK' -> 'United Kingdom' / 'Verenigd Koninkrijk'. "
        "Gebruik altijd de canonieke vorm zoals een eBay-listing die zou tonen in de target_language. "
        "Geef ontbrekende required specifics terug in missing_required. "
        "Geef prijs/qty alleen terug als ze expliciet zijn genoemd of duidelijk afleidbaar zijn. "
        "Geef daarnaast category_candidates terug: maximaal 5 korte zoekfrasen die een verkoper in de eBay "
        "categoriezoeker voor de doelmarktplaats zou typen. Sorteer best-first. "
        "Elke candidate moet label, confidence, reason en search_terms bevatten. "
        "reason moet kort en feitelijk zijn en alleen verwijzen naar wat letterlijk in transcript of titel zit. "
        "search_terms moet 1-4 alternatieve korte zoekfrasen bevatten. "
        "Geef ook search_terms op rootniveau terug als platte, ontdubbelde lijst. "
        "Als de verkoperinstructie feitelijke defaults of expliciete feiten bevat, behandel die dan als high-priority context voor condition, prijs, quantity, title en specifics, "
        "tenzij transcript of current_values dat duidelijk tegenspreken."
    )
    _eff_instruction = (user_instruction or "").strip()
    if _eff_instruction:
        system_prompt += f" Verkoperinstructie (kan schrijfstijl én feitelijke defaults bevatten): {_eff_instruction}"

    user_payload = {
        "transcript": transcript,
        "language": language,
        "target_site": target_site,
        "target_language": target_language,
        "title_hint": title_hint,
        "category_name": category_name,
        "profile_name": profile_name,
        "current_values": cur_vals,
        "condition_options": cond_options,
        "item_specifics_schema": asp_lines or "(geen schema beschikbaar)",
        "seller_instruction": _eff_instruction,
    }

    try:
        resp = oai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "folderlister_item_extract",
                    "strict": True,
                    "schema": _DESCRIBE_ITEM_SCHEMA,
                },
            },
            temperature=0.1,
        )
        result = json.loads(resp.choices[0].message.content)
    except Exception as exc:
        raise HTTPException(502, f"AI extractie mislukt: {exc}")

    # Post-process: snap to allowed values without silently substituting. Each spec
    # carries raw_value (what the speaker said, after the LLM's literal-extraction
    # rule) and value (snapped to allowed list if a clean match exists). When the
    # spoken value does NOT match the allowed list, we preserve raw_value and set
    # taxonomy_match=False so the client can prompt the user instead of dropping
    # silently or accepting a closest-match substitution.
    clean_specifics = []
    allowed_by_name: Dict[str, List[str]] = {
        str(a.get("name") or ""): [str(v) for v in (a.get("allowed_values") or []) if str(v).strip()]
        for a in schema_list if str(a.get("name") or "").strip()
    }
    for sp in result.get("specifics") or []:
        name = str(sp.get("name") or "").strip()
        val = sp.get("value")
        allowed = allowed_by_name.get(name, [])
        raw_val = str(val).strip() if val else ""
        sp["raw_value"] = raw_val
        if val and allowed:
            match = _match_allowed_value(val, allowed)
            sp["value"] = match  # None if no match
            sp["taxonomy_match"] = bool(match)
            sp["allowed_sample"] = allowed[:8]
            sp["apply"] = bool(match and float(sp.get("confidence") or 0) >= 0.4)
        else:
            sp["taxonomy_match"] = bool(val)  # free-text aspect counts as match
            sp["allowed_sample"] = []
            sp["apply"] = bool(val and float(sp.get("confidence") or 0) >= 0.4)
        clean_specifics.append(sp)

    result["specifics"] = clean_specifics
    result["condition_suggestion"] = _match_allowed_value(result.get("condition_suggestion"), condition_labels) if condition_labels else result.get("condition_suggestion")
    category_candidates = _normalize_ai_category_candidates(result.get("category_candidates"))
    result["category_candidates"] = category_candidates
    result["search_terms"] = _flatten_ai_category_search_terms(category_candidates, result.get("search_terms"))
    # v2: attach normalized candidates for resolver consumption
    try:
        from .ai_resolver import normalize_voice_extract_to_candidates  # type: ignore[import]
        result["candidates"] = [
            c.to_dict() for c in normalize_voice_extract_to_candidates(
                result, allowed_values=allowed_by_name,
            )
        ]
    except Exception:
        result["candidates"] = []

    result["analysis_id"] = analysis_id
    # De transcript is wat de verkoper zelf heeft ingesproken; die bewaren we
    # wel (het is de input van de extractie), de audio zelf niet.
    _ai_log_analysis(request, analysis_id, "describe-item", {
        "transcript": str(result.get("transcript") or "")[:2000],
        "language": str(language or ""),
        "title_hint": str(title_hint or "")[:300],
        "category_id": str(category_id or ""),
        "category_name": str(category_name or ""),
        "profile_name": str(profile_name or ""),
        "target_site": target_site,
        "target_language": target_language,
        "aspect_names": list(allowed_by_name.keys())[:60],
        "n_condition_options": len(condition_labels),
        "has_user_instruction": bool(str(user_instruction or "").strip()),
    }, result)
    return result


# ── Image facts response schema ──────────────────────────────────────────────
_ANALYZE_IMAGES_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "facts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "key":      {"type": "string"},
                    "value":    {"type": "string"},
                    "accuracy": {"type": "integer", "minimum": 0, "maximum": 100},
                },
                "required": ["key", "value", "accuracy"],
                "additionalProperties": False,
            },
        },
        "category_candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                    "reason": {"type": "array", "items": {"type": "string"}},
                    "search_terms": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["label", "confidence", "reason", "search_terms"],
                "additionalProperties": False,
            },
        },
        "search_terms": {"type": "array", "items": {"type": "string"}},
        "title_suggestion": {"type": "string"},
        "title_confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "predicted_category":   {"type": ["string", "null"]},
        "category_confidence":  {"type": "integer", "minimum": 0, "maximum": 100},
        "condition_suggestion": {"type": ["string", "null"]},
        "condition_accuracy":   {"type": "integer", "minimum": 0, "maximum": 100},
    },
    "required": ["facts", "category_candidates", "search_terms", "title_suggestion", "title_confidence", "predicted_category", "category_confidence",
                 "condition_suggestion", "condition_accuracy"],
    "additionalProperties": False,
}


@app.post("/web/ai/analyze-images")
async def analyze_images_endpoint(
    request: Request,
    image_urls: str = Form("[]"),     # JSON list of URL strings
    image_b64: str = Form("[]"),      # JSON list of base64 strings (data:image/... or raw)
    title_hint: str = Form(""),
    category_hint: str = Form(""),
    category_id: str = Form(""),
    category_name: str = Form(""),
    aspects_schema: str = Form("[]"), # JSON list of {name, allowed_values}
    target_site: str = Form("NL"),
    condition_options: str = Form("[]"),
    user_instruction: str = Form(""),
):
    """
    Vision-based item facts extractor. Returns structured facts with accuracy scores.
    Only states what is visually verifiable — no marketing language, no buyer assumptions.
    """
    _check_and_increment_ai_quota(request, kind="image")
    analysis_id = _new_analysis_id()

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(503, "AI service not configured (no OPENAI_API_KEY on server).")
    try:
        from openai import OpenAI as _OpenAI
    except ImportError:
        raise HTTPException(503, "openai SDK not installed on server.")
    oai = _OpenAI(api_key=api_key)

    try:
        urls: List[str] = json.loads(image_urls or "[]") or []
    except Exception:
        urls = []
    try:
        b64_list: List[str] = json.loads(image_b64 or "[]") or []
    except Exception:
        b64_list = []
    try:
        schema_list: List[Dict[str, Any]] = json.loads(aspects_schema or "[]") or []
    except Exception:
        schema_list = []
    try:
        cond_opts = json.loads(condition_options or "[]") or []
    except Exception:
        cond_opts = []
    condition_labels = [str(c.get("label") or "").strip() for c in cond_opts if str(c.get("label") or "").strip()]

    # Build aspect hint for the prompt (name + allowed values)
    asp_lines = ""
    allowed_by_name: Dict[str, List[str]] = {}
    for asp in schema_list:
        name = str(asp.get("name") or "").strip()
        if not name:
            continue
        vals = [str(v) for v in (asp.get("allowed_values") or []) if str(v).strip()]
        allowed_by_name[name] = vals
        if vals:
            shown = vals[:30]
            suffix_v = f" (+{len(vals)-30} more)" if len(vals) > 30 else ""
            asp_lines += f"- {name}: {', '.join(shown)}{suffix_v}\n"
        else:
            asp_lines += f"- {name}: (free text)\n"

    # Build the image content blocks (max 6 images total: prefer URLs, fallback base64)
    image_content: List[Dict[str, Any]] = []
    for url in urls[:6]:
        url = str(url or "").strip()
        if url:
            image_content.append({
                "type": "image_url",
                "image_url": {"url": url, "detail": "low"},
            })
    # Fill remaining slots with base64
    remaining = 6 - len(image_content)
    for raw in b64_list[:remaining]:
        raw = str(raw or "").strip()
        if not raw:
            continue
        if not raw.startswith("data:"):
            raw = f"data:image/jpeg;base64,{raw}"
        image_content.append({
            "type": "image_url",
            "image_url": {"url": raw, "detail": "low"},
        })

    if not image_content:
        raise HTTPException(400, "No images provided.")

    target_language = _target_language_for_site(target_site)
    _lang_names = {
        "nl-NL": "Dutch", "nl-BE": "Dutch",
        "de-DE": "German", "de-AT": "German", "de-CH": "German",
        "fr-FR": "French", "it-IT": "Italian", "es-ES": "Spanish",
        "en-GB": "English", "en-US": "English", "en-CA": "English", "en-AU": "English",
    }
    lang_name = _lang_names.get(target_language, "English")
    lang_rule = (
        f"9. CRITICAL: You MUST write ALL fact keys, fact values, and condition labels in "
        f"{lang_name} (eBay site {target_site}). Use exact {lang_name} eBay aspect names as keys.\n"
        f"10. For predicted_category: return 1-3 keywords a seller would TYPE in the eBay {target_site} "
        f"category search box in {lang_name}. Rules:\n"
        f"    - Use the item's PURPOSE/CONTEXT, not just its physical form.\n"
        f"    - A vintage/branded car logo pin/badge (AC Cobra, Ford, etc.) → 'badge verzameling' or 'speldje auto' — NOT 'speld' or 'sieraden'\n"
        f"    - A military pin/badge → 'speldje militair' or 'badge militair'\n"
        f"    - Any pin/badge WITH a visible brand logo or text → always use 'badge' or 'speldje' + context word, never 'speld' alone\n"
        f"    - A men's denim jacket (man visible in image) → 'spijkerjas heren' not 'jas'\n"
        f"    - A women's dress → 'jurk dames'\n"
        f"    - A collector coin → 'munt verzameling'\n"
        f"    - Never use generic single words like 'speld' or 'jas' alone.\n"
        f"    - Never use sieraden/jewelry for items that are clearly branded collectibles (car logos, sports teams, military).\n"
        f"    - Base the category on what you SEE in the images. The title hint may be a filename/code — ignore it if it looks like codes or numbers."
    ) if lang_name != "English" else (
        "9. Use exact English eBay aspect names as keys.\n"
        "10. For predicted_category: return 1-3 keywords a seller would TYPE in the eBay "
        "category search box. Rules:\n"
        "    - Use the item's PURPOSE/CONTEXT visible in the images, not just its physical form.\n"
        "    - A vintage/branded car logo pin/badge → 'badge collectible' or 'car badge pin' — NOT generic 'pin' or 'badge' alone\n"
        "    - A military pin/badge → 'military badge pin'\n"
        "    - Any pin WITH a visible brand logo/text → use 'badge' + context, never generic 'pin' alone\n"
        "    - A men's denim jacket (man visible) → 'mens denim jacket' not 'jacket'\n"
        "    - A collector coin → 'coin collectible'\n"
        "    - Never classify branded collectible badges as jewelry/fashion accessories.\n"
        "    - Base the category on what you SEE in the images. The title hint may be a filename/code — ignore it if it looks like codes or numbers."
    )

    system_prompt = (
        "You are a visual product analyst for eBay listings. "
        "Analyze the provided images and extract ONLY visually verifiable facts. "
        "Rules:\n"
        "1. State ONLY what is directly observable in the images — no assumptions, no guesses.\n"
        "2. Be exact about colours: if the item is blue, say 'Blue'. If it has a red stripe, say 'Blue with red stripe'.\n"
        "3. Assign accuracy (0-100) based on visual certainty:\n"
        "   - 90-100: Crystal clear and unambiguous (colour, object type, printed text)\n"
        "   - 70-89: Clearly visible but minor interpretation involved\n"
        "   - 50-69: Estimated/inferred (era based on style, material from appearance)\n"
        "   - Below 50: Do NOT include the fact.\n"
        "4. NEVER include marketing language, buyer assumptions, or phrases like "
        "'unique for collectors', 'perfect gift', 'must-have', 'rare find'.\n"
        "5. For size/dimensions: only include if there is a clear size reference in the image "
        "(e.g. a ruler, coin, or known object for scale).\n"
        "6. For era/year: only include if a date is visible in the image, or the style is very distinctive (accuracy ≤ 70).\n"
        "7. For condition: only estimate if clearly visible (obvious wear, damage, or mint state).\n"
        "8. For clothing: ALWAYS note the visible gender of the model wearing it (man/vrouw/heren/dames). "
        "If no model is visible, note the cut/style (slim fit, wide cut, etc.).\n"
        "9. Choose values from the allowed list when one is provided. "
        "If you observe a broad concept and the allowed list only contains specific subtypes, pick the most likely subtype as a sensible default. "
        "Example: you see metal but cannot tell which kind, allowed list is Steel/Iron/Aluminium but not Metal -> pick Steel as default (Steel is a metal). "
        "If multiple candidates are equally likely, pick the alphabetically first.\n"
        "10. EXCEPTION -- Country of origin aspect: this aspect varies by site ('Country/Region of Manufacture', 'Country of Origin', 'Land van herkomst', etc.). "
        "Detect it from triggers like 'land', 'country', 'herkomst', 'made in', 'origin'. "
        "For this aspect you MAY canonicalize a country name into the target_language. E.g. a US flag visible -> 'Verenigde Staten' on a Dutch site, 'United States' on an English site; "
        "UK flag -> 'Verenigd Koninkrijk' / 'United Kingdom'; Netherlands flag -> 'Nederland' / 'Netherlands'. "
        "Use the canonical name an eBay listing would display in target_language.\n"
        + lang_rule + "\n"
        "11. Return title_suggestion as a strong eBay title of max 80 characters based primarily on the images.\n"
        "12. Put the most important search words first: brand, item type, model/series/franchise, then only useful variant details.\n"
        "13. If title_hint already looks like a strong real item title and matches the images, improve it lightly instead of replacing it.\n"
        "14. Do not let a minor detail such as scale, size, color, or condition become the main title unless the item identity is otherwise unknown.\n"
        "15. Return category_candidates with up to 5 short eBay category-search phrases, ordered best-first.\n"
        "16. Each category candidate must contain label, confidence, reason, and search_terms.\n"
        "17. reason must be 1-3 short visual clues grounded in the images only.\n"
        "18. search_terms must contain 1-4 alternative short search phrases a seller might try.\n"
        "19. Copy the best candidate label into predicted_category and its confidence into category_confidence.\n"
        "20. Return search_terms as a flat deduplicated list of the strongest short search phrases."
    )

    # Build context for the user prompt
    # Title hint may be a filename/code (e.g. "[ve3]G395") — treat it as a weak hint only.
    # The visual content of the images is the primary source of truth for category decisions.
    context_parts = []
    if category_hint:
        context_parts.append(f"Category hint (if set by user): {category_hint}")
    if category_name:
        context_parts.append(f"Selected eBay category name: {category_name}")
    if category_id:
        context_parts.append(f"Selected eBay category id: {category_id}")
    if title_hint:
        # Warn GPT that the title might be a code, not a real product name
        context_parts.append(
            f"Item name hint (may be a filename/code — use ONLY if it looks like a real product name, "
            f"otherwise rely on the images): {title_hint}"
        )
    if asp_lines:
        context_parts.append(f"Available eBay aspect names (use these as keys when they match):\n{asp_lines}")
    if condition_labels:
        context_parts.append(f"Condition options (use exact label): {', '.join(condition_labels)}")
    if user_instruction and user_instruction.strip():
        context_parts.append(f"Seller instruction: {user_instruction.strip()}")

    asp_hint = ("\n\n" + "\n".join(context_parts)) if context_parts else ""

    user_content: List[Dict[str, Any]] = [
        {"type": "text", "text": f"Analyze these product images and return structured facts.{asp_hint}"},
    ] + image_content

    try:
        resp = oai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "image_facts_extract",
                    "strict": True,
                    "schema": _ANALYZE_IMAGES_SCHEMA,
                },
            },
            max_tokens=1024,
            temperature=0.1,
        )
        result = json.loads(resp.choices[0].message.content)
    except Exception as exc:
        raise HTTPException(502, f"Image analysis failed: {exc}")

    # Post-process: match facts keys/values to allowed eBay values where possible.
    # Always preserve the raw observed value so the client can show user-vs-mapped
    # mismatches instead of silently substituting "metal" -> "Steel".
    clean_facts = []
    for fact in result.get("facts") or []:
        key = str(fact.get("key") or "").strip()
        val = str(fact.get("value") or "").strip()
        acc = int(fact.get("accuracy") or 0)
        if not key or not val or acc < 50:
            continue
        raw_val = val
        allowed = allowed_by_name.get(key, [])
        taxonomy_match = False
        if allowed:
            matched = _match_allowed_value(val, allowed)
            if matched:
                val = matched
                taxonomy_match = True
                acc = min(98, acc + 5)
            else:
                # Keep raw value visible; flag as unmatched so client can prompt user.
                taxonomy_match = False
        else:
            # Free-text aspect; no taxonomy to match against.
            taxonomy_match = True
        clean_facts.append({
            "key": key, "value": val, "raw_value": raw_val,
            "accuracy": acc, "taxonomy_match": taxonomy_match,
            "allowed_sample": allowed[:8] if allowed else [],
        })

    # Snap condition to allowed list
    cond_sug = result.get("condition_suggestion")
    if cond_sug and condition_labels:
        cond_sug = _match_allowed_value(cond_sug, condition_labels)

    category_candidates = _normalize_ai_category_candidates(
        result.get("category_candidates"),
        fallback_label=result.get("predicted_category") or "",
        fallback_confidence=int(result.get("category_confidence") or 0),
    )
    top_category = category_candidates[0]["label"] if category_candidates else result.get("predicted_category")
    top_confidence = int(category_candidates[0]["confidence"] or 0) if category_candidates else int(result.get("category_confidence") or 0)
    search_terms = _flatten_ai_category_search_terms(category_candidates, result.get("search_terms"))

    image_response: Dict[str, Any] = {
        "analysis_id": analysis_id,
        "facts": clean_facts,
        "category_candidates": category_candidates,
        "search_terms": search_terms,
        "title_suggestion": result.get("title_suggestion") or "",
        "title_confidence": int(result.get("title_confidence") or 0),
        "predicted_category": top_category,
        "category_confidence": top_confidence,
        "condition_suggestion": cond_sug,
        "condition_accuracy": int(result.get("condition_accuracy") or 0),
    }
    # v2: attach image-safe normalized candidates (price/qty are silently excluded)
    try:
        from .ai_resolver import normalize_image_facts_to_candidates  # type: ignore[import]
        cond_cands_raw = []
        if cond_sug:
            cond_cands_raw = [{"value": cond_sug, "accuracy": int(result.get("condition_accuracy") or 0)}]
        image_response["candidates"] = [
            c.to_dict() for c in normalize_image_facts_to_candidates(
                clean_facts,
                condition_candidates=cond_cands_raw,
                title_hint=image_response["title_suggestion"],
                title_confidence=image_response["title_confidence"],
            )
        ]
    except Exception:
        image_response["candidates"] = []

    # image_urls wel, image_b64 alleen als aantal: zie de toelichting bij
    # _ai_log_analysis. user_instruction blijft een boolean, geen inhoud.
    _ai_log_analysis(request, analysis_id, "analyze-images", {
        "image_urls": [str(u) for u in urls[:6]],
        "n_image_b64": len(b64_list[:6]),
        "title_hint": str(title_hint or "")[:300],
        "category_id": str(category_id or ""),
        "category_name": str(category_name or ""),
        "target_site": str(target_site or ""),
        "aspect_names": list(allowed_by_name.keys())[:60],
        "n_condition_options": len(condition_labels),
        "has_user_instruction": bool(str(user_instruction or "").strip()),
    }, image_response)
    return image_response


# ═════════════════════════════════════════════════════════════════════════════
# v2 AI Resolver — central field-resolution endpoint
# ═════════════════════════════════════════════════════════════════════════════

class _ResolveIn(BaseModel):
    """
    Accepts pre-extracted candidate lists from all extractors and resolves them
    into a single ListingResolutionResult.
    Candidates format: list of CandidateValue dicts (see ai_resolver.py).
    """
    candidates: List[Dict[str, Any]] = []
    required_specifics: List[str] = []
    review_threshold: float = 0.55
    auto_apply_threshold: float = 0.72


@app.post("/web/ai/resolve")
async def ai_resolve_fields(body: _ResolveIn, request: Request):
    """
    v2 central resolver endpoint.
    Accepts a flat list of CandidateValue dicts, resolves per field,
    and returns a ListingResolutionResult.

    This is the single source of truth for field-level decisions.
    The UI can use resolved_fields / resolved_specifics for provenance display.
    """
    try:
        from .ai_resolver import (  # type: ignore[import]
            CandidateValue as _CV,
            resolve_all_fields,
        )
    except ImportError:
        try:
            from ai_resolver import CandidateValue as _CV, resolve_all_fields  # type: ignore[import]
        except ImportError:
            raise HTTPException(500, "ai_resolver module not available")

    # Rebuild CandidateValue objects from dicts
    candidates = []
    for raw in (body.candidates or []):
        if not isinstance(raw, dict):
            continue
        try:
            c = _CV(
                field_name=str(raw.get("field_name") or ""),
                value=str(raw.get("value") or ""),
                normalized_value=raw.get("normalized_value"),
                source=str(raw.get("source") or ""),
                source_detail=str(raw.get("source_detail") or ""),
                field_kind=str(raw.get("field_kind") or "other"),
                raw_confidence=float(raw.get("raw_confidence") or 0.0),
                base_source_weight=float(raw.get("base_source_weight") or 0.0),
                evidence_quality=float(raw.get("evidence_quality") or 0.75),
                profile_mode=raw.get("profile_mode"),
                profile_fit_score=float(raw.get("profile_fit_score") or 1.0),
                explicitly_stated=bool(raw.get("explicitly_stated")),
                visually_verified=bool(raw.get("visually_verified")),
                resolver_eligible=bool(raw.get("resolver_eligible", True)),
                evidence=list(raw.get("evidence") or []),
            )
            candidates.append(c)
        except Exception:
            continue

    result = resolve_all_fields(
        candidates,
        required_specifics=list(body.required_specifics or []),
        review_threshold=float(body.review_threshold or 0.55),
        auto_apply_threshold=float(body.auto_apply_threshold or 0.72),
    )
    return result.to_dict()


def _site_allows_return_instructions(site: str) -> bool:
    # Conservative allow-list; UK/NL/DE/FR/IT/ES meestal niet.
    return site.upper() in ("US",)

def _assert_policy_ok_for_site(env: str, site: str, return_profile_id: str):
    if not return_profile_id:
        return
    rp = _sell_account_get_return_policy_by_id(env, site, return_profile_id) or {}
    instr = (rp.get("returnInstructions") or rp.get("description") or "").strip()
    if instr and not _site_allows_return_instructions(site):
        name = rp.get("name") or f"ID {return_profile_id}"
        raise HTTPException(
            422,
            f"Selected return policy “{name}” contains Return Instructions, which are not allowed on {site}. "
            f"Clear that text in eBay Business Policies or choose another policy."
        )




# PUBLIC SCANNER  —  /web/scanner/*
BROWSE_API_BASE = "https://api.ebay.com/buy/browse/v1"
_EBAY_DOMAIN_TO_SITE = {
    "ebay.nl": "NL",
    "ebay.de": "DE",
    "ebay.com": "US",
    "ebay.co.uk": "UK",
    "ebay.fr": "FR",
    "ebay.it": "IT",
    "ebay.es": "ES",
    "ebay.be": "BE",
    "ebay.at": "AT",
    "ebay.com.au": "AU",
    "ebay.ca": "CA",
    "ebay.pl": "PL",
    "ebay.ch": "CH",
    "ebay.ie": "IE",
}
_SCANNER_RL_LOCK = threading.Lock()  # also guards SCANNER_RL_FILE reads/writes
_SCANNER_ASPECT_SYNONYMS: Dict[str, set[str]] = {
    # Core identifiers
    "brand": {"merk", "manufacturer", "make", "marke", "fabrikant"},
    "merk": {"brand", "manufacturer", "make", "marke", "fabrikant"},
    "manufacturer": {"brand", "merk", "make", "fabrikant"},
    "mpn": {"part number", "manufacturer part number", "artikelnummer", "modelnummer"},
    "ean": {"upc", "isbn", "gtin", "barcode"},
    "model": {"modelnummer", "model number"},
    # Appearance
    "color": {"colour", "kleur", "farbe", "primary colour", "primary color", "hoofdkleur"},
    "colour": {"color", "kleur", "farbe", "primary colour", "primary color", "hoofdkleur"},
    "kleur": {"color", "colour", "farbe", "primary colour", "primary color", "hoofdkleur"},
    "primary colour": {"color", "colour", "kleur", "hoofdkleur"},
    "material": {"materiaal", "fabric", "stoff", "outer shell material", "buitenmateriaal"},
    "materiaal": {"material", "fabric", "stoff", "outer shell material"},
    "outer shell material": {"material", "materiaal", "fabric", "buitenmateriaal"},
    "fabric type": {"stoftype", "material", "materiaal"},
    "pattern": {"patroon", "motief", "design"},
    "patroon": {"pattern", "motief", "design"},
    # Size & dimensions
    "size": {"maat", "groesse", "grosse", "gr size", "kledingmaat"},
    "maat": {"size", "groesse", "grosse", "kledingmaat"},
    "size type": {"maattype", "type maat"},
    "length": {"lengte", "lange"},
    "width": {"breedte", "breite"},
    "height": {"hoogte", "hohe"},
    # Clothing specifics
    "department": {"afdeling", "abteilung", "geschikt voor"},
    "afdeling": {"department", "abteilung", "geschikt voor"},
    "style": {"stijl", "stil", "model"},
    "stijl": {"style", "stil"},
    "type": {"soort", "typ"},
    "soort": {"type", "typ"},
    "sleeve length": {"mouwlengte", "armellange"},
    "mouwlengte": {"sleeve length", "armellange"},
    "neckline": {"halslijn", "ausschnitt"},
    "occasion": {"gelegenheid", "anlass"},
    "gelegenheid": {"occasion", "anlass"},
    "season": {"seizoen", "saison"},
    "seizoen": {"season", "saison"},
    "vintage": {"vintage"},
    "theme": {"thema", "theme"},
    "thema": {"theme"},
    "features": {"kenmerken", "eigenschappen", "merkmale"},
    "kenmerken": {"features", "eigenschappen"},
    "closure": {"sluiting", "verschluss"},
    "sluiting": {"closure", "verschluss"},
    "accents": {"accenten", "akzente"},
    "lining material": {"voeringsmateriaal", "futtermaterial"},
    "product line": {"productlijn", "produktlinie"},
    "garment care": {"wasvoorschrift", "pflegehinweis"},
    "fit": {"pasvorm", "passform"},
    "pasvorm": {"fit", "passform"},
    "inseam": {"binnenbeenlengte"},
    "rise": {"taillehoogte"},
    "unit quantity": {"eenheidshoeveelheid", "quantity", "aantal"},
    "unit type": {"eenheidstype"},
    # Condition & origin
    "condition": {"staat", "conditie", "zustand"},
    "staat": {"condition", "conditie", "zustand"},
    "country of origin": {"made in", "origin", "herkomst", "land van herkomst", "ursprungsland", "country region of manufacture"},
    "country region of manufacture": {"country of origin", "made in", "land van herkomst", "herkomst"},
    "land van herkomst": {"country of origin", "made in", "herkomst", "country region of manufacture"},
    "made in": {"country of origin", "origin", "herkomst", "land van herkomst"},
    # Quantity
    "quantity": {"unit quantity", "amount", "aantal", "qty", "hoeveelheid"},
    "aantal": {"quantity", "unit quantity", "amount", "qty"},
}


def _scanner_rate_check(ip: str) -> Dict[str, Any]:
    """Rate-limit scanner by IP. Backed by SQLite — survives restarts and works multi-worker."""
    ip_key = fingerprint(ip)
    rl = _db.rate_limit_check(ip_key, "scanner", max_per_day=15, max_per_hour=5)
    return {"allowed": rl["allowed"], "scans_today": rl["count_today"], "scans_this_hour": rl["count_hour"]}


def _scanner_norm_text(value: Any) -> str:
    txt = str(value or "").strip().lower()
    if not txt:
        return ""
    txt = unicodedata.normalize("NFKD", txt).encode("ascii", "ignore").decode("ascii")
    txt = re.sub(r"[^a-z0-9]+", " ", txt)
    return re.sub(r"\s+", " ", txt).strip()


def _scanner_key_variants(value: Any) -> set[str]:
    base = _scanner_norm_text(value)
    if not base:
        return set()
    variants = {base}
    variants.update(_SCANNER_ASPECT_SYNONYMS.get(base, set()))
    for key, syns in _SCANNER_ASPECT_SYNONYMS.items():
        if base == key or base in syns:
            variants.add(key)
            variants.update(syns)
    return {_scanner_norm_text(v) for v in variants if _scanner_norm_text(v)}


def _scanner_value_matches(value: Any, allowed_values: list[str]) -> bool:
    candidate = _scanner_norm_text(value)
    if not candidate:
        return False
    allowed_norm = {_scanner_norm_text(v) for v in (allowed_values or []) if _scanner_norm_text(v)}
    if not allowed_norm:
        return False
    if candidate in allowed_norm:
        return True
    for part in [p.strip() for p in re.split(r"[,/;|]+", candidate) if p.strip()]:
        if part in allowed_norm:
            return True
    for allowed in allowed_norm:
        if candidate == allowed or candidate in allowed or allowed in candidate:
            return True
    return False


def _parse_ebay_item_id(raw: str) -> Optional[str]:
    raw = (raw or "").strip()
    if raw.isdigit() and 8 <= len(raw) <= 13:
        return raw
    try:
        parsed = urlparse(raw if raw.startswith("http") else "https://" + raw)
        m = re.search(r"/itm/(?:[^/?#]+/)?(\d{8,13})(?:[/?#]|$)", parsed.path or "")
        if m:
            return m.group(1)
        qs = parse_qs(parsed.query or "")
        for key in ("item", "itm", "ItemID", "itemid", "itemId"):
            vals = qs.get(key) or []
            if vals:
                val = str(vals[0] or "").strip()
                if val.isdigit() and 8 <= len(val) <= 13:
                    return val
    except Exception:
        pass
    for candidate in [raw, unquote(raw)]:
        m = re.search(r"/itm/(?:[^/?#]+/)?(\d{8,13})", candidate)
        if m:
            return m.group(1)
        m = re.search(r"[?&](?:item|itm|ItemID|itemid)=(\d{8,13})", candidate, re.IGNORECASE)
        if m:
            return m.group(1)
    m = re.search(r"(?<![/\d])(\d{8,13})(?![/\d])", raw)
    return m.group(1) if m else None


def _detect_site_from_url(url: str) -> str:
    url_l = str(url or "").lower()
    for domain, site_code in _EBAY_DOMAIN_TO_SITE.items():
        if domain in url_l:
            return site_code
    return "NL"


def _scanner_build_listing_url(raw_input: str, site_code: str, item_id: str) -> str:
    raw = str(raw_input or "").strip()
    if raw.startswith("http") and "/itm/" in raw:
        try:
            parsed = urlparse(raw)
            return f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path}"
        except Exception:
            return raw
    domain = {
        "NL": "www.ebay.nl",
        "DE": "www.ebay.de",
        "UK": "www.ebay.co.uk",
        "US": "www.ebay.com",
        "FR": "www.ebay.fr",
        "IT": "www.ebay.it",
        "ES": "www.ebay.es",
        "BE": "www.ebay.be",
        "AT": "www.ebay.at",
        "CA": "www.ebay.ca",
        "AU": "www.ebay.com.au",
        "PL": "www.ebay.pl",
        "CH": "www.ebay.ch",
        "IE": "www.ebay.ie",
    }.get((site_code or "NL").upper(), "www.ebay.nl")
    return f"https://{domain}/itm/{item_id}"


def _scanner_extract_handling_time(listing_url: str) -> Dict[str, Any]:
    if not listing_url:
        return {"days": None, "text": "", "source": ""}
    try:
        r = requests.get(
            listing_url,
            timeout=12,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept-Language": "en-US,en;q=0.7,nl-NL;q=0.6,de-DE;q=0.6",
            },
        )
        if r.status_code >= 400:
            return {"days": None, "text": "", "source": ""}
        html = r.text or ""
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
    except Exception:
        return {"days": None, "text": "", "source": ""}

    patterns = [
        (r"DispatchTimeMax[^0-9]{0,40}(\d{1,2})(?:\.0)?", "dispatch_time_max"),
        (r"dispatch(?:es|ed)?\s+within\s+(\d{1,2})(?:\s*[-–to]+\s*(\d{1,2}))?\s+business\s+days?", "dispatch_text"),
        (r"(?:verzonden|verstuurd)\s+binnen\s+(\d{1,2})(?:\s*[-–]\s*(\d{1,2}))?\s+werkdagen?", "dispatch_text"),
        (r"binnen\s+(\d{1,2})(?:\s*[-–]\s*(\d{1,2}))?\s+werkdagen\s+verzonden", "dispatch_text"),
        (r"versand\s+innerhalb\s+von\s+(\d{1,2})(?:\s*[-–]\s*(\d{1,2}))?\s+werktagen?", "dispatch_text"),
        (r"expedie(?:e|é)e?\s+sous\s+(\d{1,2})(?:\s*[-–]\s*(\d{1,2}))?\s+jours?\s+ouvrables?", "dispatch_text"),
    ]

    for pattern, source in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            continue
        first = int(m.group(1))
        second = int(m.group(2)) if m.lastindex and m.lastindex >= 2 and m.group(2) else None
        days = max(first, second or first)
        text_value = m.group(0).strip()
        return {"days": days, "text": text_value, "source": source}

    return {"days": None, "text": "", "source": ""}


def _scanner_recent_fetch_logged(ip: str, window_seconds: int = 1800) -> bool:
    """Check if this IP did a scanner fetch recently. Uses database."""
    try:
        ip_hash = fingerprint(ip)
        since = time.time() - window_seconds
        rows = _db.log_query("scanner", limit=50, since_ts=since)
        for r in rows:
            meta = r.get("meta")
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            if str((meta or {}).get("ip_hash") or r.get("ip_hash") or "") == ip_hash:
                return True
    except Exception:
        return False
    return False


def _scanner_clean_html_text(value: str) -> str:
    txt = re.sub(r"<[^>]+>", " ", str(value or ""))
    txt = txt.replace("&nbsp;", " ")
    txt = txt.replace("&amp;", "&")
    txt = txt.replace("&quot;", "\"")
    txt = txt.replace("&#39;", "'")
    txt = re.sub(r"\s+", " ", txt)
    return txt.strip(" \t\r\n:-")


def _scanner_extract_specifics_from_listing_html(listing_url: str) -> Dict[str, str]:
    if not listing_url:
        return {}
    try:
        r = requests.get(
            listing_url,
            timeout=12,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept-Language": "en-US,en;q=0.7,nl-NL;q=0.6,de-DE;q=0.6",
            },
        )
        if r.status_code >= 400:
            return {}
        html = r.text or ""
    except Exception:
        return {}

    out: Dict[str, str] = {}
    pair_patterns = [
        re.compile(
            r'ux-labels-values__labels-content[^>]*>(.*?)</(?:div|dt)>.*?ux-labels-values__values-content[^>]*>(.*?)</(?:div|dd)>',
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            r'<dt[^>]*>\s*.*?ux-textspans[^>]*>(.*?)</span>.*?</dt>\s*<dd[^>]*>\s*.*?ux-textspans[^>]*>(.*?)</span>',
            re.IGNORECASE | re.DOTALL,
        ),
    ]
    for pattern in pair_patterns:
        for match in pattern.finditer(html):
            key = _scanner_clean_html_text(match.group(1))
            val = _scanner_clean_html_text(match.group(2))
            if not key or not val:
                continue
            if len(key) > 64 or len(val) > 180:
                continue
            if key.lower() in {"condition description", "notes", "seller notes"}:
                continue
            out.setdefault(key, val)
        if out:
            break

    return out


def _scanner_enrich_specifics_from_browse(data: Dict[str, Any], specifics: Dict[str, str]) -> Dict[str, str]:
    enriched = dict(specifics or {})
    direct_map = {
        "Brand": data.get("brand"),
        "MPN": data.get("mpn"),
        "GTIN": data.get("gtin"),
        "Color": data.get("color"),
        "Size": data.get("size"),
        "Size Type": data.get("sizeType"),
        "Size System": data.get("sizeSystem"),
        "Material": data.get("material"),
    }
    for key, raw in direct_map.items():
        val = str(raw or "").strip()
        if val and key not in enriched:
            enriched[key] = val
    return enriched


def _scanner_fetch_taxonomy_aspects(site: str, category_id: str) -> list[dict]:
    site_code, _ = _effective_site_and_currency(site, None)
    site_code = (site_code or "NL").upper()
    marketplace = MARKETPLACE_ID.get(site_code)
    if not marketplace or not category_id:
        return []
    try:
        r1 = _commerce_get("PROD", "/commerce/taxonomy/v1/get_default_category_tree_id", {"marketplace_id": marketplace})
        if r1.status_code >= 400:
            return []
        tree_id = (r1.json() or {}).get("categoryTreeId")
        if not tree_id:
            return []
        r2 = _commerce_get("PROD", f"/commerce/taxonomy/v1/category_tree/{tree_id}/get_item_aspects_for_category", {"category_id": category_id})
        if r2.status_code >= 400:
            return []
        raw = r2.json() or {}
        src = raw.get("aspects") if isinstance(raw, dict) else raw
        return [a for a in (src or []) if isinstance(a, dict)]
    except Exception:
        return []


def _build_scanner_taxonomy_summary(site: str, category_id: str, specifics: Dict[str, str]) -> Dict[str, Any]:
    raw_aspects = _scanner_fetch_taxonomy_aspects(site, category_id)
    if not raw_aspects:
        return {"checked": False}

    taxonomy_aspects: list[dict] = []
    matched_by_name: Dict[str, dict] = {}
    for raw in raw_aspects:
        ac = raw.get("aspectConstraint") or {}
        values_raw = raw.get("aspectValues") or raw.get("values") or []
        values: list[str] = []
        for item in values_raw:
            if isinstance(item, dict):
                val = str(item.get("localizedValue") or item.get("value") or item.get("applicableValue") or "").strip()
            else:
                val = str(item or "").strip()
            if val and val not in values:
                values.append(val)
        name = str(raw.get("localizedAspectName") or raw.get("aspectName") or raw.get("name") or "").strip()
        if not name:
            continue
        aspect_entry = {
            "name": name,
            "required": bool(ac.get("aspectRequired")),
            "mode": str(ac.get("aspectMode") or "").upper(),
            "values": values,
        }
        taxonomy_aspects.append(aspect_entry)
        for variant in _scanner_key_variants(name):
            matched_by_name.setdefault(variant, aspect_entry)

    present_names: set[str] = set()
    matched_specifics = 0
    unmatched_specifics: list[str] = []
    selection_checked = 0
    selection_valid = 0
    selection_issues: list[str] = []

    for raw_key, raw_value in (specifics or {}).items():
        value = str(raw_value or "").strip()
        if not value:
            continue
        matched = None
        for variant in _scanner_key_variants(raw_key):
            matched = matched_by_name.get(variant)
            if matched:
                break
        if not matched:
            unmatched_specifics.append(str(raw_key or "").strip())
            continue
        matched_specifics += 1
        present_names.add(str(matched["name"]))
        values = list(matched.get("values") or [])
        mode = str(matched.get("mode") or "")
        if values and mode in {"SELECTION_ONLY", "SELECTION_ONLY_OR_FREE_TEXT"}:
            selection_checked += 1
            if _scanner_value_matches(value, values):
                selection_valid += 1
            else:
                selection_issues.append(f"{matched['name']}: {value}")

    required = [a for a in taxonomy_aspects if a.get("required")]
    optional = [a for a in taxonomy_aspects if not a.get("required")]
    required_missing = [str(a["name"]) for a in required if str(a["name"]) not in present_names]
    required_present = len(required) - len(required_missing)
    optional_present = sum(1 for a in optional if str(a["name"]) in present_names)
    optional_target = min(max(len(optional), 0), 8)

    return {
        "checked": True,
        "aspect_total": len(taxonomy_aspects),
        "required_total": len(required),
        "required_present": required_present,
        "required_missing": required_missing[:8],
        "optional_total": len(optional),
        "optional_present": optional_present,
        "optional_target": optional_target,
        "matched_specifics": matched_specifics,
        "unmatched_specifics": unmatched_specifics[:8],
        "selection_fields_checked": selection_checked,
        "selection_fields_valid": selection_valid,
        "selection_fields_invalid": max(0, selection_checked - selection_valid),
        "selection_value_issues": selection_issues[:8],
        "aspect_names_sample": [str(a["name"]) for a in taxonomy_aspects[:16]],
    }


def _score_from_ratio(value: float, low: float, high: float) -> float:
    if value <= low:
        return 0.0
    if value >= high:
        return 10.0
    return round(((value - low) / (high - low)) * 10.0, 1)


def _analyse_scanner_image(content: bytes) -> Dict[str, Any]:
    try:
        from PIL import Image, ImageOps, ImageStat, ImageFilter  # type: ignore
        import io
    except ImportError:
        return {"ok": False, "error": "Pillow not available", "probe_only": True, "analysis_mode": "none"}

    try:
        pil_img = Image.open(io.BytesIO(content))
        pil_img = ImageOps.exif_transpose(pil_img).convert("RGB")
        width, height = pil_img.size
        longest = max(width, height)

        gray = pil_img.convert("L")
        gray_stat = ImageStat.Stat(gray)
        brightness_mean = float(gray_stat.mean[0] or 0.0)
        brightness_std = float(gray_stat.stddev[0] or 0.0)

        edge_img = gray.filter(ImageFilter.FIND_EDGES)
        edge_stat = ImageStat.Stat(edge_img)
        edge_strength = float((edge_stat.mean[0] or 0.0) + (edge_stat.stddev[0] or 0.0))
        sharpness_score = round(max(0.0, min(10.0, (edge_strength - 8.0) / 4.0)), 1)

        brightness_score = round(max(0.0, min(10.0, 10.0 - (abs(brightness_mean - 168.0) / 12.0))), 1)
        contrast_score = round(_score_from_ratio(brightness_std, 18.0, 60.0), 1)

        sample = pil_img.resize((160, 160))
        pixels = list(sample.getdata())
        border_pixels: list[tuple[int, int, int]] = []
        subject_pixels = 0
        for y in range(160):
            for x in range(160):
                idx = y * 160 + x
                px = pixels[idx]
                if x < 18 or y < 18 or x >= 142 or y >= 142:
                    border_pixels.append(px)
        if border_pixels:
            br = sum(px[0] for px in border_pixels) / len(border_pixels)
            bg = sum(px[1] for px in border_pixels) / len(border_pixels)
            bb = sum(px[2] for px in border_pixels) / len(border_pixels)
        else:
            br = bg = bb = 240.0
        border_uniformity = (
            sum(abs(px[0] - br) + abs(px[1] - bg) + abs(px[2] - bb) for px in border_pixels) / max(len(border_pixels), 1)
        ) / 3.0
        near_white_ratio = sum(
            1 for px in border_pixels if px[0] > 225 and px[1] > 225 and px[2] > 225
        ) / max(len(border_pixels), 1)

        for px in pixels:
            diff = (abs(px[0] - br) + abs(px[1] - bg) + abs(px[2] - bb)) / 3.0
            if diff > 32:
                subject_pixels += 1
        subject_ratio = subject_pixels / max(len(pixels), 1)

        # Background: primary signal is uniformity (any clean background),
        # near-white is a bonus — a clean grey or cream backdrop is still good.
        uniformity_score = max(0.0, min(10.0, 10.0 - (border_uniformity / 5.0)))
        white_bonus = min(3.0, near_white_ratio * 4.0)
        background_score = round(min(10.0, uniformity_score * 0.75 + white_bonus), 1)
        if 0.18 <= subject_ratio <= 0.78:
            framing_score = 10.0
        elif 0.10 <= subject_ratio <= 0.90:
            framing_score = 7.0
        elif 0.05 <= subject_ratio <= 0.96:
            framing_score = 4.0
        else:
            framing_score = 2.0

        overall_visual_score = round(
            (sharpness_score * 0.35)
            + (brightness_score * 0.2)
            + (contrast_score * 0.15)
            + (background_score * 0.15)
            + (framing_score * 0.15),
            1,
        )

        return {
            "ok": True,
            "probe_only": False,
            "analysis_mode": "full",
            "width": width,
            "height": height,
            "longest_side": longest,
            "sharpness_score": sharpness_score,
            "brightness_score": brightness_score,
            "contrast_score": contrast_score,
            "background_score": background_score,
            "subject_framing_score": round(framing_score, 1),
            "visual_quality_score": overall_visual_score,
            "brightness_mean": round(brightness_mean, 1),
            "border_white_pct": round(near_white_ratio * 100.0, 1),
            "subject_fill_pct": round(subject_ratio * 100.0, 1),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:120], "probe_only": True, "analysis_mode": "error"}


@app.get("/web/scanner/fetch")
def scanner_fetch(
    request: Request,
    q: str = Query(..., description="eBay listing URL or item ID"),
    site: str = Query("", description="Optional site override (NL/DE/UK/US/...)"),
):
    ip = _client_ip(request)
    rl = _scanner_rate_check(ip)
    if not rl["allowed"]:
        raise HTTPException(
            429,
            detail={
                "error": "rate_limit",
                "scans_today": rl["scans_today"],
                "message": "Daily scan limit reached. Try again tomorrow.",
            },
        )

    site_code = (site or "").strip().upper() or _detect_site_from_url(q)
    item_id = _parse_ebay_item_id(q)
    if not item_id:
        raise HTTPException(400, detail={"error": "invalid_id", "message": "Could not find a valid eBay item ID in the input."})

    marketplace = MARKETPLACE_ID.get(site_code or "NL", MARKETPLACE_ID.get("NL"))
    browse_url = f"{BROWSE_API_BASE}/item/get_item_by_legacy_id"
    headers_browse = {
        "Authorization": f"Bearer {get_app_token('PROD')}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-EBAY-C-MARKETPLACE-ID": marketplace,
    }

    try:
        r = requests.get(browse_url, headers=headers_browse, params={"legacy_item_id": item_id}, timeout=20)
    except requests.exceptions.Timeout:
        raise HTTPException(504, detail={"error": "timeout", "message": "eBay API timed out. Please try again."})
    except Exception as exc:
        raise HTTPException(502, detail={"error": "fetch_failed", "message": str(exc)[:160]})

    if r.status_code == 404:
        # Fallback for cases where the legacy bridge is incomplete but direct REST itemId still resolves.
        browse_item_id = f"v1|{item_id}|0"
        try:
            r = requests.get(f"{BROWSE_API_BASE}/item/{browse_item_id}", headers=headers_browse, timeout=20)
        except requests.exceptions.Timeout:
            raise HTTPException(504, detail={"error": "timeout", "message": "eBay API timed out. Please try again."})
        except Exception as exc:
            raise HTTPException(502, detail={"error": "fetch_failed", "message": str(exc)[:160]})

    if r.status_code == 404:
        raise HTTPException(404, detail={"error": "not_found", "message": "Listing not found. Check that the item is still live."})
    if r.status_code == 410:
        raise HTTPException(404, detail={"error": "not_found", "message": "This listing has ended or been removed."})

    # Multi-variation listings: eBay returns error 11006 and tells us to use item_group endpoint
    if r.status_code >= 400:
        try:
            err_body = r.json()
            errors = err_body.get("errors") or []
            for err in errors:
                if err.get("errorId") == 11006:
                    # Extract item_group_id from the error parameters
                    group_id = None
                    for p in (err.get("parameters") or []):
                        href = str(p.get("value") or "")
                        m = re.search(r"item_group_id=(\d+)", href)
                        if m:
                            group_id = m.group(1)
                            break
                    if not group_id:
                        group_id = item_id  # fallback: try legacy ID as group ID
                    try:
                        r = requests.get(
                            f"{BROWSE_API_BASE}/item/get_items_by_item_group",
                            headers=headers_browse,
                            params={"item_group_id": group_id},
                            timeout=20,
                        )
                        if r.status_code < 400:
                            group_data = r.json() or {}
                            items = group_data.get("items") or []
                            if items:
                                # Use first item but merge common data from group if available
                                data = items[0]
                                # Add common images / description from parent if present
                                common = group_data.get("commonDescriptions") or []
                                if common and not data.get("description"):
                                    data["description"] = common[0].get("description") or ""
                                break
                    except Exception:
                        pass
            else:
                raise HTTPException(r.status_code, detail={"error": "ebay_error", "message": r.text[:300]})
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(r.status_code, detail={"error": "ebay_error", "message": r.text[:300]})
    else:
        data = r.json() or {}

    if not isinstance(data, dict) or not data:
        data = r.json() if r.status_code < 400 else {}
    data = data or {}
    title = str(data.get("title") or "").strip()
    if not title:
        raise HTTPException(404, detail={"error": "not_found", "message": "Listing not found or no title was returned."})

    description_html = str(data.get("description") or data.get("shortDescription") or "").strip()
    description_text = re.sub(r"<[^>]+>", " ", description_html)
    description_text = re.sub(r"\s{2,}", " ", description_text).strip()

    images: list[str] = []
    primary_img = str((data.get("image") or {}).get("imageUrl") or "").strip()
    if primary_img:
        images.append(primary_img)
    for item in (data.get("additionalImages") or []):
        image_url = str((item or {}).get("imageUrl") or "").strip()
        if image_url and image_url not in images:
            images.append(image_url)

    specifics: Dict[str, str] = {}
    for aspect in (data.get("localizedAspects") or []):
        name = str((aspect or {}).get("name") or "").strip()
        value = str((aspect or {}).get("value") or "").strip()
        if name and value and name not in specifics:
            specifics[name] = value
    specifics = _scanner_enrich_specifics_from_browse(data, specifics)

    price_node = data.get("price") or {}
    shipping_opts = data.get("shippingOptions") or []
    shipping_opt = shipping_opts[0] if shipping_opts else {}
    shipping_cost_node = shipping_opt.get("shippingCost") or {}
    return_terms = data.get("returnTerms") or {}
    return_period = return_terms.get("returnPeriod") or {}
    category_list = data.get("categories") or []
    category_node = category_list[0] if category_list else {}
    category_id = str(data.get("categoryId") or (category_node or {}).get("categoryId") or "").strip()
    category_name = str((category_node or {}).get("categoryName") or "").strip()
    if not category_name:
        raw_path = str(data.get("categoryPath") or "").strip()
        if raw_path:
            category_name = raw_path.split("|")[-1].strip()
    category_path = (
        str(data.get("categoryPath") or "").strip()
        or str((category_node or {}).get("categoryPath") or "").strip()
        or str((data.get("categoryPath") or "")).strip()
    )

    buying_options = [str(v or "").strip() for v in (data.get("buyingOptions") or []) if str(v or "").strip()]
    if "FIXED_PRICE" in buying_options:
        listing_type = "FixedPriceItem"
    elif "AUCTION" in buying_options:
        listing_type = "Chinese"
    else:
        listing_type = buying_options[0] if buying_options else ""

    availability = (data.get("estimatedAvailabilities") or [{}])[0]
    quantity = str((availability or {}).get("estimatedAvailableQuantity") or "").strip()
    listing_url = str(data.get("itemWebUrl") or "").strip() or _scanner_build_listing_url(q, site_code, item_id)
    html_specifics = _scanner_extract_specifics_from_listing_html(listing_url)
    for key, value in (html_specifics or {}).items():
        if key and value and key not in specifics:
            specifics[key] = value
    taxonomy_summary = _build_scanner_taxonomy_summary(site_code, category_id, specifics) if category_id else {"checked": False}
    handling_info = _scanner_extract_handling_time(listing_url)

    _db.log_event(
        "scanner",
        ip_hash=fingerprint(ip),
        endpoint="/web/scanner/fetch",
        meta={
            "item_id": item_id,
            "site": site_code,
            "title": title[:100],
            "price": str(price_node.get("value") or "").strip(),
            "currency": str(price_node.get("currency") or "").strip(),
            "image_count": len(images),
            "specifics_count": len(specifics),
            "category_id": category_id,
            "category_name": category_name,
            "taxonomy_checked": bool(taxonomy_summary.get("checked")),
            "handling_source": str(handling_info.get("source") or ""),
            "ip_hash": fingerprint(ip),
        },
    )

    returns_accepted_raw = str(return_terms.get("returnsAccepted") or "").strip().lower()

    return {
        "ok": True,
        "item_id": item_id,
        "site": site_code,
        "scans_today": rl["scans_today"] + 1,
        "listing": {
            "title": title,
            "description_text": description_text,
            "description_length_words": len(description_text.split()) if description_text else 0,
            "images": images,
            "image_count": len(images),
            "specifics": specifics,
            "specifics_count": len(specifics),
            "price_value": str(price_node.get("value") or "").strip(),
            "price_currency": str(price_node.get("currency") or "").strip(),
            "shipping_type": str(shipping_opt.get("shippingCostType") or "").strip(),
            "shipping_cost": str(shipping_cost_node.get("value") or "").strip(),
            "returns_accepted": "ReturnsAccepted" if returns_accepted_raw in {"true", "1", "returnsaccepted", "yes"} else "ReturnsNotAccepted",
            "returns_within": f"{str(return_period.get('value') or '').strip()} {str(return_period.get('unit') or '').strip()}".strip(),
            "refund": str(return_terms.get("refundMethod") or "").strip(),
            "condition_id": str(data.get("conditionId") or "").strip(),
            "condition_display": str(data.get("condition") or "").strip(),
            "handling_time_days": handling_info.get("days"),
            "handling_time_text": str(handling_info.get("text") or "").strip(),
            "handling_time_source": str(handling_info.get("source") or "").strip(),
            "listing_type": listing_type,
            "quantity": quantity,
            "category_id": category_id,
            "category_name": category_name,
            "category_path": category_path,
            "listing_url": listing_url,
            "taxonomy_summary": taxonomy_summary,
        },
    }


@app.post("/web/scanner/analyze-image")
async def scanner_analyze_image(request: Request):
    ip = _client_ip(request)
    if not _scanner_recent_fetch_logged(ip):
        raise HTTPException(429, detail={"error": "rate_limit", "message": "Run a listing scan before image analysis."})

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    url = str(body.get("url") or "").strip()
    if not url or not url.startswith("http"):
        raise HTTPException(400, detail={"error": "invalid_url", "message": "A public image URL is required."})

    # eBay CDN can block bare server requests — use realistic browser headers
    try:
        img_r = requests.get(
            url,
            timeout=12,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": "https://www.ebay.com/",
                "Sec-Fetch-Dest": "image",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        img_r.raise_for_status()
        content_type = (img_r.headers.get("content-type") or "").lower()
        if "image" not in content_type and len(img_r.content) < 1000:
            return {"ok": False, "error": f"Not an image (content-type: {content_type})", "probe_only": True, "analysis_mode": "fetch_error"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:120], "probe_only": True, "analysis_mode": "fetch_error"}

    result = _analyse_scanner_image(img_r.content)
    if not result.get("width") and not result.get("height"):
        result["width"] = 0
        result["height"] = 0
        result["longest_side"] = 0
    return result


# ─────────────────────────────────────────────────────────────────────────────
# VOICE DEMO — public lead-magnet on homepage
# ─────────────────────────────────────────────────────────────────────────────

VOICE_DEMO_RL_FILE = DATA / "voice_demo_rl.json"


def _voice_demo_rate_check(ip: str) -> dict:
    """Max 3 voice demo uses per day per IP. Backed by SQLite."""
    ip_key = fingerprint(ip)
    rl = _db.rate_limit_check(ip_key, "voice_demo", max_per_day=3)
    return {"allowed": rl["allowed"], "uses_today": rl["count_today"]}


_VOICE_DEMO_SYSTEM = """You are an eBay listing assistant for Folder Lister.

The seller is listing a decorative ceramic vase. Image analysis has already identified these visible attributes:
- Item type: Decorative Vase
- Material: Ceramic / Pottery
- Primary colour: Blue and white
- Pattern: Hand-painted floral motif, Delft style
- Shape: Round body with narrow neck, approx 18 cm tall

The seller will now add details by voice that the camera cannot see: condition, era, exact dimensions, country of origin, brand/maker, price, or any other relevant details.

From the transcript below, extract item specifics and generate three description versions:
- description_raw: the seller's own spoken words cleaned up into readable sentences. Do NOT rewrite or add marketing language. Keep the seller's original phrasing, just fix grammar and remove filler words like "um" or "uh". This should read like the seller wrote it themselves.
- description_seo: rewritten for eBay search — keyword-rich, structured, professional. Include category-relevant search terms, mention the material, style and condition prominently. If the seller provided a description_prompt, follow those instructions for tone and structure.
- description_factual: brief factual listing — bullet points with dimensions, condition, material, origin, era. Nothing decorative, just facts.

Also suggest an eBay title (max 80 chars, no ALL CAPS, no filler words).

Only use facts the seller actually stated or that were identified from the image. For specifics already known from the image, include them with source "image". For new facts from voice, use source "voice". Do not invent details the seller did not mention."""

_VOICE_DEMO_SCHEMA = {
    "type": "object",
    "properties": {
        "title_suggestion": {"type": "string"},
        "description_raw": {"type": "string"},
        "description_seo": {"type": "string"},
        "description_factual": {"type": "string"},
        "condition": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "price": {"anyOf": [{"type": "number"}, {"type": "null"}]},
        "specifics": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "value": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "source": {"type": "string", "enum": ["image", "voice"]},
                },
                "required": ["name", "value", "source"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["title_suggestion", "description_raw", "description_seo", "description_factual", "condition", "price", "specifics"],
    "additionalProperties": False,
}


@app.post("/web/voice-demo")
async def voice_demo_endpoint(request: Request):
    ip = _client_ip(request)
    rl = _voice_demo_rate_check(ip)
    if not rl["allowed"]:
        raise HTTPException(429, detail={"error": "rate_limit", "uses_today": rl["uses_today"],
                                          "message": "Daily demo limit reached (3/day). Download Folder Lister for unlimited voice listings."})

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail={"error": "invalid_json"})

    transcript = str(body.get("transcript") or "").strip()
    if not transcript or len(transcript) < 5:
        raise HTTPException(400, detail={"error": "empty_transcript", "message": "Voice note too short. Try describing condition, origin, or dimensions."})

    desc_prompt = str(body.get("description_prompt") or "").strip()

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(503, detail={"error": "ai_unavailable", "message": "AI service not configured."})

    try:
        from openai import OpenAI as _OpenAI
    except ImportError:
        raise HTTPException(503, detail={"error": "ai_unavailable", "message": "AI library not available."})

    user_msg = f"Seller voice transcript:\n\n{transcript}"
    if desc_prompt:
        user_msg += f"\n\nSeller description prompt (follow this for the SEO description style): {desc_prompt}"

    oai = _OpenAI(api_key=api_key)
    try:
        resp = oai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _VOICE_DEMO_SYSTEM},
                {"role": "user", "content": user_msg},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "voice_demo_result",
                    "strict": True,
                    "schema": _VOICE_DEMO_SCHEMA,
                },
            },
            temperature=0.15,
        )
        result = json.loads(resp.choices[0].message.content)
    except Exception as exc:
        raise HTTPException(502, detail={"error": "ai_failed", "message": str(exc)[:120]})

    return {"ok": True, "result": result, "uses_today": rl["uses_today"]}


# ── Scheeltwerk.nl (separate module) ──
try:
    from .scheeltwerk_api import router as scheeltwerk_router
    APP.include_router(scheeltwerk_router)
except Exception:
    pass

