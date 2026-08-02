# server/admin_panel.py
from __future__ import annotations
import os
from .eps_limits import list_usage as eps_list_usage, plan_max_accounts, reset as eps_reset, get_usage as eps_get_usage, get_limit_for_record, plan_limits
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Dict, Any, List, Optional
import time, json, threading

_IP_BANS_LOCK = threading.Lock()
import os, hmac, hashlib, secrets, time
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse



# ---- imports uit store ----
from .license_store import FILE as LICENSE_FILE, find_license, is_valid, upsert_license_plain  # type: ignore

# Optioneel aanwezige helpers (gebruik ze als ze er zijn; anders val terug op raw update)
try:
    from .license_store import detach_ebay_user as _store_detach_ebay_user  # type: ignore
except Exception:
    _store_detach_ebay_user = None
try:
    from .license_store import set_max_accounts as _store_set_max_accounts  # type: ignore
except Exception:
    _store_set_max_accounts = None

# Voor cache refresh na raw write
from . import license_store as LS  # type: ignore
#from .app import _send_email as _admin_send_email  # bestaande mailer hergebruiken
from .eps_limits import FILE as EPS_FILE  # pad naar eps_usage.json
from pathlib import Path
from datetime import datetime, timezone, timedelta

REMINDER_DAYS = int(os.getenv("REMINDER_DAYS", "7"))
ADMIN_UI_USER   = os.getenv("ADMIN_UI_USER", "joeperd87")
ADMIN_UI_TOKEN  = os.getenv("ADMIN_UI_TOKEN", "")  # je huidige admin_ui_token
ADMIN_SESS_TTL  = int(os.getenv("ADMIN_SESSION_TTL_SECONDS", "228800"))  # 8 uur
ADMIN_SESS_SEC  = os.getenv("JOEP_SECURE_COOKIES", "1") != "0"
ADMIN_SESS_KEY  = os.getenv("ADMIN_SESSION_SECRET", "") or secrets.token_hex(32)
# IP bestanden naast je licentie-store
IP_LOG_FILE      = LICENSE_FILE.parent / "ip_log.jsonl"
IP_BANS_FILE     = LICENSE_FILE.parent / "ip_bans.json"
SCANNER_LOG_FILE = LICENSE_FILE.parent / "scanner_log.jsonl"
EMAIL_TEMPLATES_FILE = LICENSE_FILE.parent / "email_templates.json"

_DEFAULT_WELCOME_SUBJECT = "Welcome to Folder Lister"
_DEFAULT_WELCOME_TEXT = """Welcome to Folder Lister

Thanks for signing up to try Folder Lister.

Folder Lister is currently in its launch phase. The goal is simple:
help eBay sellers list in bulk without losing control over their details.

Setup is short and straightforward. For a quick start and more advanced tips,
check the documentation: https://folderlister.com/docs

Need help, ran into something weird, or want to double-check your workflow?
Reach out at support@folderlister.com.

We're very curious about your experience and do our best to guide you and
make Folder Lister a pleasant tool to work with. Suggestions, tweaks, and
brutally honest feedback are all welcome.

Kind regards,
Joep — Folder Lister
"""
_DEFAULT_WELCOME_HTML = """<!doctype html>
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
                   alt="Folder Lister" width="80"
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
                Setup is intentionally short and straightforward. For a quick start and more
                advanced tips, check the documentation:
                <a href="https://folderlister.com/docs" style="color:#2563eb;text-decoration:none;">folderlister.com/docs</a>.
              </p>
              <p style="margin:0 0 12px 0;font-size:14px;line-height:1.6;color:#374151;">
                Need help, ran into something weird, or want to double-check your workflow?
                Reach out at <a href="mailto:support@folderlister.com" style="color:#2563eb;text-decoration:none;">support@folderlister.com</a>.
              </p>
              <p style="margin:0 0 12px 0;font-size:14px;line-height:1.6;color:#374151;">
                We're very curious about your experience and do our best to guide you and
                make Folder Lister a pleasant tool to work with. Suggestions, tweaks, and
                brutally honest feedback are all welcome.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 24px 20px 24px;">
              <p style="margin:0 0 4px 0;font-size:14px;color:#111827;">Kind regards,</p>
              <p style="margin:0;font-size:14px;color:#111827;">Joep — Folder Lister</p>
            </td>
          </tr>
          <tr>
            <td style="padding:12px 24px 18px 24px;border-top:1px solid #e5e7eb;">
              <p style="margin:0;font-size:11px;color:#9ca3af;">
                You're receiving this email because you created an account or requested access to Folder Lister.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

def _load_email_template(name: str) -> dict:
    """Laad een e-mailtemplate uit het bestand; val terug op de ingebouwde default."""
    try:
        if EMAIL_TEMPLATES_FILE.exists():
            data = json.loads(EMAIL_TEMPLATES_FILE.read_text("utf-8") or "{}")
            rec = data.get(name) or {}
            if rec.get("html") or rec.get("subject"):
                return rec
    except Exception:
        pass
    if name == "welcome":
        return {"subject": _DEFAULT_WELCOME_SUBJECT, "html": _DEFAULT_WELCOME_HTML, "text": _DEFAULT_WELCOME_TEXT}
    return {}

def _save_email_template(name: str, subject: str, html: str, text: str = "") -> None:
    """Sla een e-mailtemplate op in het bestand."""
    try:
        data: dict = {}
        if EMAIL_TEMPLATES_FILE.exists():
            data = json.loads(EMAIL_TEMPLATES_FILE.read_text("utf-8") or "{}")
        data[name] = {"subject": subject, "html": html, "text": text}
        tmp = EMAIL_TEMPLATES_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(EMAIL_TEMPLATES_FILE)
    except Exception as e:
        raise RuntimeError(f"Could not save email template: {e}")

router = APIRouter(prefix="/admin", tags=["admin"])

def _sess_sign(user: str, issued_s: str, nonce: str) -> str:
    msg = f"{user}|{issued_s}|{nonce}".encode("utf-8")
    sig = hmac.new(ADMIN_SESS_KEY.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return sig

def _sess_issue(user: str) -> str:
    issued = str(int(time.time()))
    nonce  = secrets.token_hex(8)
    sig    = _sess_sign(user, issued, nonce)
    return f"{user}.{issued}.{nonce}.{sig}"

def _sess_verify(cookie_val: str) -> bool:
    try:
        user, issued, nonce, sig = cookie_val.split(".", 3)
    except Exception:
        return False
    if user != ADMIN_UI_USER:
        return False
    if sig != _sess_sign(user, issued, nonce):
        return False
    # TTL
    try:
        if (time.time() - int(issued)) > ADMIN_SESS_TTL:
            return False
    except Exception:
        return False
    return True

def _admin_logged_in(req: Request) -> bool:
    c = req.cookies.get("admin_session")
    return bool(c and _sess_verify(c))

def _set_admin_cookie(resp, session_value: str):
    resp.set_cookie(
        "admin_session", session_value,
        max_age=ADMIN_SESS_TTL,
        httponly=True,
        secure=ADMIN_SESS_SEC,
        samesite="Strict",
        path="/api/admin"
    )



def _admin_send_email(*args, **kwargs):
    # lazy import om circular import te vermijden
    from .app import _send_email
    return _send_email(*args, **kwargs)

def _require_admin(req: Request):
    # 1) geldige sessie-cookie vereist
    if _admin_logged_in(req):
        return
    # 2) alleen nog backward-compat als je ECHT een token hebt gezet
    tok = (req.query_params.get("token") or req.headers.get("X-Admin-Token") or "").strip()
    if tok and ADMIN_UI_TOKEN and tok == ADMIN_UI_TOKEN:
        return
    raise HTTPException(status_code=401, detail="unauthorized")

# ---- helpers om store te lezen/schrijven ----
def _read_store() -> Dict[str, Any]:
    """Return all licenses keyed by HMAC-key hash.

    The DB-migration moved license storage from a JSON file to SQLite. This
    function used to read only the JSON file, which caused new (DB-only)
    users to be invisible in the admin panel. We now read both sources and
    merge them so every license shows up.
    """
    out: Dict[str, Any] = {}

    # 1) JSON store (legacy / pre-migration data)
    try:
        if LICENSE_FILE.exists():
            txt = LICENSE_FILE.read_text("utf-8").strip()
            if txt:
                out.update(json.loads(txt))
    except Exception:
        pass

    # 2) SQLite store (current source of truth for all new activations)
    try:
        from . import db as _db  # type: ignore
        from .license_store import _row_to_rec as _to_rec  # type: ignore
        for row in _db.license_list(limit=10000):
            kh = row.get("key_hash")
            if not kh:
                continue
            rec = _to_rec(row) or {}
            # Preserve fingerprint hint so list_licenses can still derive it
            if "_fingerprint" not in rec:
                rec["_fingerprint"] = kh[8:18] if isinstance(kh, str) and kh.startswith("HMAC256:") else (kh or "")[:12]
            # SQLite is authoritative — overwrite any stale JSON dupes
            out[kh] = rec
    except Exception as _e:
        # Niet failen op admin-load als DB tijdelijk weg is
        try:
            import logging; logging.getLogger("admin").exception("license DB load failed")
        except Exception:
            pass

    return out

_DB_DIRECT_COLS = ("plan", "status", "owner_email", "owner_name",
                   "max_accounts", "expires_at", "notes")
_DB_META_FIELDS = ("eps_daily_limit", "ai_daily_limit",
                   "allowed_ebay_users", "allowed_identity_ids",
                   "eps_period", "ai_period")


def _sync_record_to_db(key_hash: str, rec: Dict[str, Any]) -> None:
    """Mirror a JSON-store edit into SQLite for records that exist there.

    `_read_store` treats SQLite as authoritative, so a `_write_store`
    that only touched JSON would silently lose its edits on next read
    (e.g. admin changes max_accounts → JSON updated, DB unchanged → UI
    reloads from DB → looks like nothing happened). This helper writes
    direct-mapped columns + folds extra fields into the `meta` JSON.
    """
    if not isinstance(rec, dict) or not key_hash:
        return
    try:
        from . import db as _db
    except Exception:
        return
    try:
        existing = _db.license_find(key_hash)
    except Exception:
        existing = None
    if not existing:
        return  # JSON-only record (legacy); leave DB alone

    updates: Dict[str, Any] = {}
    for fld in _DB_DIRECT_COLS:
        if fld in rec:
            updates[fld] = rec[fld]

    extra: Dict[str, Any] = {}
    for k in _DB_META_FIELDS:
        if k in rec:
            extra[k] = rec[k]
    if extra:
        try:
            cur_meta = json.loads(existing.get("meta") or "{}")
            if not isinstance(cur_meta, dict):
                cur_meta = {}
        except Exception:
            cur_meta = {}
        cur_meta.update(extra)
        updates["meta"] = json.dumps(cur_meta)

    if updates:
        try:
            _db.license_upsert(key_hash, **updates)
        except Exception:
            import logging
            logging.getLogger("admin").exception(
                "license_upsert failed for %s", key_hash[:24]
            )


def _write_store(data: Dict[str, Any]) -> None:
    tmp = LICENSE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(LICENSE_FILE)
    # cache verversen
    try:
        LS._cache = data
        LS._cache_mtime = LICENSE_FILE.stat().st_mtime
        LS._cache_loaded_at = time.time()
    except Exception:
        pass

    # Mirror to SQLite so edits to DB-only licenses actually stick.
    # (JSON-only records — pre-migration — are skipped by the helper.)
    for kh, rec in data.items():
        _sync_record_to_db(kh, rec)

def _admin_send_email(to: str, subject: str, body: str, html: str | None = None,
                       extra_headers: dict | None = None) -> None:
    """Generic mailer for bulk/reminder mails, same SMTP settings as welcome mail."""
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
    msg["To"] = to
    msg["Subject"] = subject
    for k, v in (extra_headers or {}).items():
        msg[k] = v
    msg.set_content(body or "")
    if html:
        msg.add_alternative(html, subtype="html")

    ctx = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=ctx) as s:
            if user and pw:
                s.login(user, pw)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port) as s:
            if use_starttls:
                s.starttls(context=ctx)
            if user and pw:
                s.login(user, pw)
            s.send_message(msg)

def _resolve_key_by_id_or_fp(data: Dict[str, Any], ident: str) -> str:
    """Zoek de juiste storesleutel (HMAC) bij meegegeven id/fingerprint/prefix."""
    ident = (ident or "").strip()
    if not ident:
        raise ValueError("missing id")
    il = ident.lower()

    # 1) exact key
    if ident in data:
        return ident

    # 2) key-prefix match
    for k in data.keys():
        kl = k.lower()
        if kl.startswith(il) or il.startswith(kl):
            return k

    # 3) match op HMAC-afgeleide fingerprint (k[8:18])
    if len(ident) == 10:
        for k in data.keys():
            if isinstance(k, str) and k.startswith("HMAC256:"):
                if k[8:18].lower() == il:
                    return k

    # 4) match op opgeslagen _fingerprint (als aanwezig)
    for k, rec in data.items():
        fp = (rec.get("_fingerprint") or "").lower()
        if fp and (fp == il or fp.startswith(il) or il.startswith(fp)):
            return k

    raise ValueError("license id not found")

def _fp_from_key_and_rec(store_key: str, rec: Dict[str,Any]) -> str | None:
    if isinstance(rec, dict) and rec.get("_fingerprint"):
        return str(rec["_fingerprint"])
    if isinstance(store_key, str) and store_key.startswith("HMAC256:"):
        return store_key[8:18]
    return None

def _eps_purge_fp(fp: str) -> None:
    """Verwijder EPS-usage state voor deze fingerprint (alleen 'vandaag')."""
    try:
        raw = json.loads(EPS_FILE.read_text("utf-8") or "{}")
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    by = raw.get("by_fp") or {}
    if fp in by:
        by.pop(fp, None)
        raw["by_fp"] = by
        tmp = EPS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(EPS_FILE)
    # (Als je later totals/history toevoegt, kun je die hier ook schonen)

def _now_utc_iso():
    return datetime.now(timezone.utc).isoformat()

def _parse_iso(s: str | None):
    if not s: return None
    try:
        return datetime.fromisoformat(s.replace("Z","+00:00"))
    except Exception:
        return None

# ----------------- admin UI -----------------
@router.get("/login")
def admin_login_page(request: Request):
    if _admin_logged_in(request):
        return RedirectResponse(url="/api/admin/ui", status_code=302)
    # Minimal, eigen stijl behouden
    html = f"""
<!doctype html><meta charset="utf-8">
<title>Admin Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<style>
  body{{font-family:system-ui,Segoe UI,Inter,Arial,sans-serif;background:#0b0f14;color:#e8eef5;display:flex;align-items:center;justify-content:center;min-height:100vh}}
  .card{{background:#121822;border:1px solid #1b2433;border-radius:12px;padding:24px;box-shadow:0 8px 30px rgba(0,0,0,.35);width:360px}}
  label{{display:block;margin:10px 0 6px;color:#9fb0c3}}
  input[type=text],input[type=password]{{width:100%;padding:10px;border-radius:10px;border:1px solid #253144;background:#0f1520;color:#e8eef5}}
  button{{margin-top:14px;width:100%;padding:12px;border-radius:12px;border:0;background:#148CA0;color:white;font-weight:600;cursor:pointer}}
  .muted{{color:#9fb0c3;font-size:.9rem;margin-top:6px}}
</style>
<form class="card" method="post" action="/api/admin/login">
  <h2 style="margin:0 0 8px">Admin</h2>
  <div class="muted">Login met je gebruikersnaam en admin token.</div>
  <label>Gebruikersnaam</label>
  <input name="user" type="text" autocomplete="username" value="{ADMIN_UI_USER}">
  <label>Admin token</label>
  <input name="token" type="password" autocomplete="current-password" placeholder="••••••••••">
  <button type="submit">Login</button>
</form>
"""
    return HTMLResponse(html, headers={"Cache-Control":"no-store"})

@router.post("/login")
def admin_login_submit(user: str = Form(""), token: str = Form(""), request: Request = None):
    u = (user or "").strip()
    t = (token or "").strip()
    if not (u and t and ADMIN_UI_TOKEN and u == ADMIN_UI_USER and t == ADMIN_UI_TOKEN):
        return HTMLResponse("<p style='color:#e33'>Invalid credentials</p><a href='/api/admin/login'>Back</a>", status_code=401, headers={"Cache-Control":"no-store"})
    sess = _sess_issue(u)
    resp = RedirectResponse(url="/api/admin/ui", status_code=302)
    _set_admin_cookie(resp, sess)
    resp.headers["Cache-Control"] = "no-store"
    return resp

@router.get("/logout")
def admin_logout():
    resp = RedirectResponse(url="/api/admin/login", status_code=302)
    resp.delete_cookie("admin_session", path="/api/admin")
    return resp

def _send_welcome_mail(to_email: str) -> None:
    import os, smtplib, ssl
    from email.message import EmailMessage

    host = os.getenv("SMTP_HOST", "127.0.0.1")
    port = int(os.getenv("SMTP_PORT", "25"))
    use_starttls = os.getenv("SMTP_STARTTLS", "0") == "1"
    use_ssl      = os.getenv("SMTP_SSL", "0") == "1"
    user = (os.getenv("SMTP_USER") or "").strip()
    pw   = (os.getenv("SMTP_PASS") or "").strip()
    sender = os.getenv("SMTP_FROM") or "noreply@folderlister.com"

    tpl = _load_email_template("welcome")
    subject = tpl.get("subject") or _DEFAULT_WELCOME_SUBJECT
    html    = tpl.get("html")    or _DEFAULT_WELCOME_HTML
    text    = tpl.get("text")    or _DEFAULT_WELCOME_TEXT

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    ctx = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=ctx) as s:
            if user and pw:
                s.login(user, pw)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port) as s:
            if use_starttls:
                s.starttls(context=ctx)
            if user and pw:
                s.login(user, pw)
            s.send_message(msg)
            
@router.post("/bulk/update")
def admin_bulk_update(req: Request, payload: dict):
    _require_admin(req)
    ids = payload.get("ids") or []
    if not ids:
        raise HTTPException(400, "ids required")

    data = _read_store()
    changed = 0
    for ident in ids:
        try:
            key = _resolve_key_by_id_or_fp(data, ident)
        except Exception:
            continue
        rec = dict(data.get(key) or {})

        # velden conditioneel bijwerken
        for fld in ["plan","expires_at","status","owner_email","owner_name"]:
            if payload.get(fld) not in (None,""):
                val = payload.get(fld)
                rec[fld] = (val.lower() if fld=="plan" and isinstance(val,str) else val)

        if "max_accounts" in payload and str(payload.get("max_accounts")).strip() != "":
            try:
                rec["max_accounts"] = int(payload.get("max_accounts"))
            except Exception:
                pass

        if "eps_daily_limit" in payload:
            v = payload.get("eps_daily_limit")
            if v in (None,""):
                rec.pop("eps_daily_limit", None)
            else:
                try: rec["eps_daily_limit"] = int(v)
                except Exception: rec["eps_daily_limit"] = v

        data[key] = rec
        changed += 1

    _write_store(data)
    return {"ok": True, "changed": changed}

@router.post("/bulk/welcome")
def admin_bulk_welcome(req: Request, payload: dict):
    _require_admin(req)
    ids = payload.get("ids") or []
    if not ids:
        raise HTTPException(400, "ids required")

    data = _read_store()
    sent = 0
    skipped = []
    for ident in ids:
        try:
            key = _resolve_key_by_id_or_fp(data, ident)
        except Exception:
            skipped.append({"id": ident, "reason": "not_found"})
            continue

        rec = data.get(key) or {}
        to  = (rec.get("owner_email") or "").strip()
        if not to:
            skipped.append({"id": ident, "reason": "no_email"})
            continue

        try:
            _send_welcome_mail(to)
            sent += 1
        except Exception as e:
            skipped.append({"id": ident, "reason": f"send_error:{e}"})

    return {"ok": True, "sent": sent, "skipped": skipped}

@router.post("/bulk/email")
def admin_bulk_email(req: Request, payload: dict):
    _require_admin(req)
    ids = payload.get("ids") or []
    subject = (payload.get("subject") or "").strip()
    body    = (payload.get("body") or "").strip()
    html    = (payload.get("html") or "").strip() or None
    if not ids or not subject or (not body and not html):
        raise HTTPException(400, "ids, subject en body of html vereist")

    # lazy import om circular import te vermijden (zelfde patroon als _admin_send_email)
    from .app import is_email_opted_out, unsubscribe_link

    data = _read_store()
    sent = 0; skipped = []
    for ident in ids:
        try:
            key = _resolve_key_by_id_or_fp(data, ident)
        except Exception:
            skipped.append({"id": ident, "reason": "not_found"}); continue
        rec = data.get(key) or {}
        to  = (rec.get("owner_email") or "").strip()
        if not to:
            skipped.append({"id": ident, "reason": "no_email"}); continue
        if is_email_opted_out(to):
            skipped.append({"id": ident, "reason": "unsubscribed"}); continue

        # Real, per-recipient unsubscribe link (not a mailto: instruction) so it
        # actually works, plus List-Unsubscribe headers for one-click support
        # in Gmail/Outlook -- both matter for spam placement, not just courtesy.
        link = unsubscribe_link(to)
        this_body = body
        this_html = html
        if this_body:
            this_body = this_body + (
                "\n\n---\nYou're receiving this because you're a FolderLister user.\n"
                f"Unsubscribe: {link}"
            )
        if this_html:
            unsub_row = (
                '<tr><td style="padding:12px 24px 16px 24px;border-top:1px solid #e5e7eb;">'
                '<p style="margin:0;font-size:11px;color:#9ca3af;">'
                "You're receiving this because you're a FolderLister user. "
                f'<a href="{link}" style="color:#9ca3af;">Unsubscribe</a>.</p></td></tr>'
            )
            this_html = (
                this_html.replace("</body>", unsub_row + "</body>")
                if "</body>" in this_html else this_html + unsub_row
            )

        try:
            _admin_send_email(
                to, subject, this_body, this_html,
                extra_headers={
                    "List-Unsubscribe": f"<{link}>",
                    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                },
            )  # gebruikt jouw SMTP settings
            sent += 1
        except Exception as e:
            skipped.append({"id": ident, "reason": f"send_error:{e}"})
    return {"ok": True, "sent": sent, "skipped": skipped}

@router.post("/bulk/delete")
def admin_bulk_delete(req: Request, payload: dict):
    _require_admin(req)
    ids = payload.get("ids") or []
    if not ids:
        raise HTTPException(400, "ids required")
    data = _read_store()
    removed = 0
    keys_to_delete_db: List[str] = []
    for ident in ids:
        try:
            key = _resolve_key_by_id_or_fp(data, ident)
        except Exception:
            continue
        rec = data.get(key) or {}
        fp  = _fp_from_key_and_rec(key, rec)
        if key in data:
            del data[key]; removed += 1
        if key:
            keys_to_delete_db.append(key)
        if fp: _eps_purge_fp(fp)
    _write_store(data)
    # Ook uit SQLite verwijderen
    if keys_to_delete_db:
        try:
            from . import db as _db  # type: ignore
            conn = _db.get_conn()
            for kh in keys_to_delete_db:
                conn.execute("DELETE FROM licenses WHERE key_hash=?", (kh,))
            conn.commit()
        except Exception:
            try:
                import logging; logging.getLogger("admin").exception("bulk license SQLite delete failed")
            except Exception:
                pass
    return {"ok": True, "removed": removed}

def _licenses_expiring_within(days: int) -> list[dict]:
    data = _read_store()
    out = []
    now = datetime.now(timezone.utc)
    until = now + timedelta(days=days)
    for k, rec in data.items():
        exp = _parse_iso(rec.get("expires_at"))
        if not exp: continue
        if now <= exp <= until and (rec.get("status","active") == "active"):
            fp = _fp_from_key_and_rec(k, rec)
            out.append({
                "id": k, "fingerprint": fp, "owner_email": rec.get("owner_email"),
                "plan": rec.get("plan"), "expires_at": rec.get("expires_at"),
                "name": rec.get("owner_name")
            })
    return out

@router.get("/reminders/preview")
def admin_reminders_preview(req: Request, days: Optional[int] = None):
    _require_admin(req)
    d = int(days or REMINDER_DAYS)
    return {"days": d, "items": _licenses_expiring_within(d)}

@router.post("/reminders/send")
def admin_reminders_send(req: Request, payload: dict):
    _require_admin(req)
    d = int(payload.get("days") or REMINDER_DAYS)
    items = _licenses_expiring_within(d)
    if not items: return {"ok": True, "sent": 0}

    data = _read_store()
    sent = 0; skipped = []
    for it in items:
        k = it["id"]; rec = data.get(k) or {}
        # dubbele reminders tegenhouden: “exp_reminder_for” bewaren
        already_for = (rec.get("exp_reminder_for") or "").strip()
        if already_for == (it.get("expires_at") or ""):
            skipped.append({"id": k, "reason": "already_sent"}); continue

        to = (it.get("owner_email") or "").strip()
        if not to:
            skipped.append({"id": k, "reason": "no_email"}); continue

        # simpele template
        subject = "Your Folder Lister license is expiring soon"
        exp_txt = it.get("expires_at")
        plan    = (it.get("plan") or "license")
        plan_title = plan.title()

        # Optioneel: waar de gebruiker z’n licentie beheert
        manage_url = os.getenv("FOLDERLISTER_MANAGE_URL", "https://folderlister.com/account")

        body = f"""Hi,

        Your {plan_title} will expire on {exp_txt}.
        Please renew or request a new plan to keep publishing.

        — Joepienator
        """

        html = f"""\
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Folder Lister — license expiring</title>
        </head>
        <body style="margin:0;padding:0;background:#F2EADC;">
          <!-- Preheader (hidden) -->
          <div style="display:none;max-height:0;overflow:hidden;">
            Heads up: your {plan_title} expires on {exp_txt}. Renew to keep publishing.
          </div>

          <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#F2EADC;">
            <tr>
              <td align="center" style="padding:24px;">
                <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width:640px;background:#ffffff;border-radius:16px;border:1px solid #eaeaea;">
                  <tr>
                    <td style="padding:24px 24px 10px;border-bottom:3px solid #148CA0;">
                      <div style="font:700 18px system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#0b0f14;">Folder Lister</div>
                      <div style="font:500 12px system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#6b788b;">Fast bulk eBay listing</div>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:24px;">
                      <h1 style="margin:0 0 8px;font:800 22px system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#0b0f14;">Your license is expiring soon</h1>
                      <p style="margin:0 0 14px;font:400 15px/1.6 system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#3f4650;">
                        Your <span style="font-weight:600">{plan_title}</span> will expire on
                        <span style="font-weight:700">{exp_txt}</span>.
                      </p>

                      <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 16px;">
                        <tr>
                          <td style="background:#EFF9FB;border:1px solid #CBE8EE;border-radius:10px;padding:12px 14px;font:500 13px system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#0b0f14;">
                            Keep your publishing flow uninterrupted — renew before the date.
                          </td>
                        </tr>
                      </table>

                      <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 18px;">
                        <tr>
                          <td align="center">
                            <a href="{manage_url}" style="display:inline-block;background:#148CA0;color:#ffffff;text-decoration:none;font:700 14px system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:12px 20px;border-radius:12px;">
                              Renew / Manage license
                            </a>
                          </td>
                        </tr>
                      </table>

                      <p style="margin:0 0 8px;font:400 13px/1.6 system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#6b788b;">
                        Prefer a different plan? You can switch anytime in your account.
                      </p>
                      <p style="margin:0;font:400 13px/1.6 system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#6b788b;">
                        If you've already renewed, you can ignore this message.
                      </p>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:16px 24px;border-top:1px solid #eee;">
                      <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
                        <tr>
                          <td style="font:400 12px system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#6b788b;">
                            Need help? Reply to this email or visit
                            <a href="https://folderlister.com" style="color:#148CA0;text-decoration:none;">folderlister.com</a>.
                          </td>
                          <td align="right" style="font:600 12px system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#0b0f14;">
                            — Joepienator
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>

                </table>
                <div style="height:24px;line-height:24px">&zwnj;</div>
              </td>
            </tr>
          </table>
        </body>
        </html>"""
        try:
            _admin_send_email(to, subject, body, html)
            # markering opslaan
            rec["exp_reminder_last_sent"] = _now_utc_iso()
            rec["exp_reminder_for"] = exp_txt
            data[k] = rec
            sent += 1
        except Exception as e:
            skipped.append({"id": k, "reason": f"send_error:{e}"})
    _write_store(data)
    return {"ok": True, "sent": sent, "skipped": skipped}

def _load_jsonl(path: Path, limit: int = 500):
    out = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f.readlines()[-limit:]:
                try: out.append(json.loads(line))
                except Exception: pass
    except Exception:
        pass
    return out

@router.get("/ip/list")
def admin_ip_list(req: Request, limit: int = 500):
    _require_admin(req)
    return {"items": _load_jsonl(IP_LOG_FILE, limit=limit)}

@router.get("/ip/bans")
def admin_ip_bans(req: Request):
    _require_admin(req)
    from . import db as _db
    bans = _db.ip_ban_list()
    return {"bans": [b["ip"] for b in bans]}

@router.post("/ip/ban")
def admin_ip_ban(req: Request, payload: dict):
    _require_admin(req)
    ip = (payload.get("ip") or "").strip()
    if not ip: raise HTTPException(400, "ip required")
    from . import db as _db
    _db.ip_ban_add(ip, reason=payload.get("reason", "admin"))
    bans = _db.ip_ban_list()
    return {"ok": True, "bans": [b["ip"] for b in bans]}

@router.post("/ip/unban")
def admin_ip_unban(req: Request, payload: dict):
    _require_admin(req)
    ip = (payload.get("ip") or "").strip()
    from . import db as _db
    _db.ip_ban_remove(ip)
    bans = _db.ip_ban_list()
    return {"ok": True, "bans": [b["ip"] for b in bans]}

@router.get("/_debug_limits")
def admin_debug_limits(req: Request):
    _require_admin(req)
    import os
    from .eps_limits import plan_limits
    return {
        "env_raw": os.getenv("JOEP_PLAN_LIMITS_JSON"),
        "parsed": plan_limits(),
    }

@router.get("/usage")
def admin_usage_list(req: Request, limit: int = 200):
    _require_admin(req)
    items = eps_list_usage(limit=limit)

    # licentie-store inladen — merged uit JSON én SQLite zodat
    # SQLite-only licenses ook getoond worden (plan/owner/etc.).
    data = _read_store()

    # plan defaults (voor referentie)
    defaults = plan_limits()

    out = []
    for row in items:
        fp = row.get("fp")
        # zoek bijbehorende licentie op basis van fingerprint (HMAC256:<10>...)
        lic = None
        for k, v in data.items():
            if isinstance(k, str) and k.startswith("HMAC256:") and k[8:18] == fp:
                lic = v; break

        # bereken effectieve limiet (override > plan-default)
        eff = get_limit_for_record(lic)  # None = onbeperkt
        override = None if not isinstance(lic, dict) else lic.get("eps_daily_limit", None)
        plan = (lic or {}).get("plan")
        plan_default = defaults.get((plan or "").lower()) if plan else None

        out.append({
            "fp": fp,
            "date": row.get("date"),
            "count": row.get("count"),
            "plan": plan,
            "owner_email": (lic or {}).get("owner_email"),
            "expires_at": (lic or {}).get("expires_at"),
            # laat beide zien, dan is het helder:
            "eps_daily_limit_effective": eff,        # ← wat écht geldt (bv. 30)
            "eps_daily_limit_override": override,    # ← wat in record staat (vaak null)
            "plan_default_limit": plan_default       # ← uit JOEP_PLAN_LIMITS_JSON
        })

    return {"items": out}


def _resolve_license_fp(ident: str) -> str:
    """Resolve a 10-char license fingerprint from an id / fp / HMAC key.

    Usage is keyed by license fingerprint since the 2026-05-18 bucket
    migration, so only one fp per license is needed.
    """
    data = _read_store()
    if len(ident) == 10:
        for k in data.keys():
            if isinstance(k, str) and k.startswith("HMAC256:") and k[8:18] == ident:
                return ident
        # Direct fp typed even if not in store — caller may still want it
        return ident
    for k in data.keys():
        if k == ident and isinstance(k, str) and k.startswith("HMAC256:"):
            return k[8:18]
    raise HTTPException(404, "license not found")


@router.post("/usage/reset")
def admin_usage_reset(req: Request, payload: dict):
    _require_admin(req)
    ident = (payload.get("id") or "").strip()
    if not ident:
        raise HTTPException(400, "id required")
    fp = _resolve_license_fp(ident)
    row = eps_reset(fp)
    row["fp"] = fp
    return {"ok": True, "row": row}


@router.get("/usage/for/{ident}")
def admin_usage_for(req: Request, ident: str):
    _require_admin(req)
    fp = _resolve_license_fp(ident)
    row = eps_get_usage(fp)
    row["fp"] = fp
    return row

def _find_license_record(ident: str) -> Optional[dict]:
    """Return license_record for a given id/fp/hash, or None.

    Uses _read_store so SQLite-only licenses are also resolvable —
    not just legacy JSON entries.
    """
    data = _read_store()
    if len(ident) == 10:
        for k, v in data.items():
            fp = k[8:18] if k.startswith("HMAC256:") else k
            if fp == ident:
                return v
        return None
    # try id field
    for k, v in data.items():
        if isinstance(v, dict) and (v.get("id") == ident or k == ident):
            return v
    return None


@router.get("/usage/ai")
def admin_ai_usage_list(req: Request, limit: int = 200):
    """List AI credit usage for all licenses — reads from database."""
    _require_admin(req)
    from . import db as _db
    from datetime import datetime, timezone
    now_month = datetime.now(timezone.utc).strftime("%Y-%m")
    licenses = _db.license_list(limit=limit)
    rows = []
    for lic in licenses:
        # AI usage is stored in the meta JSON blob
        meta = {}
        try:
            meta = json.loads(lic.get("meta") or "{}") if isinstance(lic.get("meta"), str) else (lic.get("meta") or {})
        except Exception:
            meta = {}
        stored_month  = meta.get("ai_calls_month") or ""
        total_used    = int(meta.get("ai_calls_used") or 0)
        if stored_month != now_month:
            total_used = 0
        img_month   = meta.get("ai_images_month") or ""
        images_used = int(meta.get("ai_images_used") or 0)
        if img_month != now_month:
            images_used = 0
        v_month    = meta.get("ai_voice_month") or ""
        voice_used = int(meta.get("ai_voice_used") or 0)
        if v_month != now_month:
            voice_used = 0
        effective = max(total_used, images_used + voice_used)
        if effective == 0:
            continue
        from .app import _ai_quota_limit  # type: ignore
        plan  = (lic.get("plan") or "").lower()
        limit_v = _ai_quota_limit(plan)
        rows.append({
            "id":          lic.get("key_hash", "")[:18],
            "email":       lic.get("owner_email") or "",
            "plan":        plan,
            "quota":       limit_v,
            "total_used":  effective,
            "images_used": images_used,
            "voice_used":  voice_used,
            "month":       now_month,
        })
    rows.sort(key=lambda r: r["total_used"], reverse=True)
    return rows


@router.get("/usage/ai/for/{ident}")
def admin_ai_usage_for(req: Request, ident: str):
    _require_admin(req)
    rec = _find_license_record(ident)
    if not rec:
        raise HTTPException(404, "license not found")
    from datetime import datetime, timezone
    now_month = datetime.now(timezone.utc).strftime("%Y-%m")
    stored_month  = rec.get("ai_calls_month") or ""
    total_used    = int(rec.get("ai_calls_used") or 0)
    if stored_month != now_month:
        total_used = 0
    img_month   = rec.get("ai_images_month") or ""
    images_used = int(rec.get("ai_images_used") or 0)
    if img_month != now_month:
        images_used = 0
    v_month    = rec.get("ai_voice_month") or ""
    voice_used = int(rec.get("ai_voice_used") or 0)
    if v_month != now_month:
        voice_used = 0
    effective = max(total_used, images_used + voice_used)
    from .app import _ai_quota_limit  # type: ignore
    plan = (rec.get("plan") or "").lower()
    return {
        "id":          rec.get("id") or ident,
        "email":       rec.get("email") or "",
        "plan":        plan,
        "quota":       _ai_quota_limit(plan),
        "total_used":  effective,
        "images_used": images_used,
        "voice_used":  voice_used,
        "month":       now_month,
    }


@router.post("/usage/ai/reset")
def admin_ai_usage_reset(req: Request, payload: dict):
    _require_admin(req)
    ident = (payload.get("id") or "").strip()
    if not ident:
        raise HTTPException(400, "id required")
    try:
        with open(LICENSE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except Exception:
        data = {}
    target_key = None
    for k, v in data.items():
        if not isinstance(v, dict):
            continue
        fp = k[8:18] if k.startswith("HMAC256:") else k
        if fp == ident or v.get("id") == ident or k == ident:
            target_key = k
            break
    if not target_key:
        raise HTTPException(404, "license not found")
    data[target_key].update({
        "ai_calls_used":   0,
        "ai_images_used":  0,
        "ai_voice_used":   0,
        "ai_calls_month":  "",
        "ai_images_month": "",
        "ai_voice_month":  "",
    })
    try:
        tmp = LICENSE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(LICENSE_FILE)
        try:
            LS._cache.clear()
        except Exception:
            pass
    except Exception as exc:
        raise HTTPException(500, str(exc))
    return {"ok": True, "id": ident}


@router.get("/_plan_defaults")
def admin_plan_defaults(req: Request):
    _require_admin(req)
    from .eps_limits import plan_limits, plan_max_accounts
    return {
        "plan_limits": plan_limits(),
        "plan_max_accounts": plan_max_accounts(),
    }

@router.post("/email/welcome")
def admin_email_welcome(req: Request, payload: dict):
    _require_admin(req)
    email = (payload.get("email") or "").strip()
    if not email:
        raise HTTPException(400, "email required")
    _send_welcome_mail(email)
    return {"ok": True}

@router.get("/email/template/welcome")
def admin_get_welcome_template(req: Request):
    _require_admin(req)
    tpl = _load_email_template("welcome")
    return {
        "subject": tpl.get("subject") or _DEFAULT_WELCOME_SUBJECT,
        "html":    tpl.get("html")    or _DEFAULT_WELCOME_HTML,
        "text":    tpl.get("text")    or _DEFAULT_WELCOME_TEXT,
    }

@router.post("/email/template/welcome")
def admin_save_welcome_template(req: Request, payload: dict):
    _require_admin(req)
    subject = (payload.get("subject") or "").strip()
    html    = (payload.get("html")    or "").strip()
    text    = (payload.get("text")    or "").strip()
    if not subject or not html:
        raise HTTPException(400, "subject and html are required")
    _save_email_template("welcome", subject, html, text)
    return {"ok": True}

@router.post("/email/template/welcome/reset")
def admin_reset_welcome_template(req: Request):
    _require_admin(req)
    _save_email_template("welcome", _DEFAULT_WELCOME_SUBJECT, _DEFAULT_WELCOME_HTML, _DEFAULT_WELCOME_TEXT)
    return {"ok": True}


@router.post("/license/issue")
def admin_issue(req: Request, payload: dict):
    _require_admin(req)
    import secrets
    plan = (payload.get("plan") or "").strip().lower()
    if not plan:
        raise HTTPException(400, "plan required")
    owner_email = (payload.get("owner_email") or "").strip() or None
    owner_name  = (payload.get("owner_name") or "").strip() or None
    expires_at  = (payload.get("expires_at") or "").strip() or None
    notes       = (payload.get("notes") or "").strip() or None
    eps_limit   = payload.get("eps_daily_limit", None)
    max_accounts = int(payload.get("max_accounts") or 1)

    key = secrets.token_urlsafe(24)
    rec = upsert_license_plain(key, plan=plan, expires_at_iso_utc=expires_at, status="active",
                               notes=notes, owner_email=owner_email, owner_name=owner_name, max_accounts=max_accounts)

    # optioneel eps_daily_limit opslaan
    if eps_limit not in (None, ""):
        try:
            with open(LICENSE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            data = {}
        from .license_store import _hmac_key as _hk  # type: ignore
        store_key = _hk(key)
        row = data.get(store_key) or rec
        try:
            row["eps_daily_limit"] = int(eps_limit)
        except Exception:
            row["eps_daily_limit"] = eps_limit
        data[store_key] = row
        # _write_store bestaat al in dit bestand
        _write_store(data)
        rec = row

    return {"license_key": key, "fingerprint": (store_key[8:18] if 'store_key' in locals() else None), "record": rec}

@router.get("/scanner/stats")
def admin_scanner_stats(req: Request):
    """Scanner analytics — session-authenticated."""
    _require_admin(req)
    try:
        from . import db as _db
        rows = _db.log_query("scanner", limit=5000)
        entries = []
        for r in rows:
            meta = r.get("meta", "{}")
            if isinstance(meta, str):
                try: meta = json.loads(meta)
                except Exception: meta = {}
            meta["ts"] = r.get("ts", 0)
            meta["ip_hash"] = meta.get("ip_hash") or r.get("ip_hash", "")
            entries.append(meta)
    except Exception:
        entries = []

    now = int(time.time())
    day_s, week_s, month_s = 86400, 7 * 86400, 30 * 86400

    def _in(secs): return [e for e in entries if now - e.get("ts", 0) <= secs]
    def _uips(lst): return len(set(e.get("ip_hash", "") for e in lst))

    today_e = _in(day_s); week_e = _in(week_s); month_e = _in(month_s)

    from collections import Counter
    item_ctr = Counter(
        f"{e.get('item_id','')} — {(e.get('title') or '')[:55]}"
        for e in entries
    )
    top_items = [{"label": k, "count": v} for k, v in item_ctr.most_common(15)]

    daily: dict = {}
    for e in entries:
        ts = e.get("ts", 0)
        if now - ts > month_s:
            continue
        d = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        daily[d] = daily.get(d, 0) + 1

    site_ctr = Counter(e.get("site", "?") for e in entries)

    return {
        "total": len(entries),
        "today": len(today_e),
        "week":  len(week_e),
        "month": len(month_e),
        "unique_ips_today": _uips(today_e),
        "unique_ips_week":  _uips(week_e),
        "top_items":        top_items,
        "daily":            [{"date": d, "n": c} for d, c in sorted(daily.items())],
        "by_site":          dict(site_ctr.most_common()),
    }


def render_admin_html_somehow():
  html = """<!doctype html>
<meta charset="utf-8">
<title>FolderLister – Admin</title>
<style>
  :root { --c: #148CA0; }
  html,body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin:0; background:#0b0f14; color:#e6edf3; }
  header { background: var(--c); color:#fff; padding:12px 16px; font-weight:600; display:flex; align-items:center; justify-content:space-between; }
  main { padding:16px; max-width: 1200px; margin: 0 auto; }
  section { background:#121821; border:1px solid #1f2a37; border-radius:10px; padding:12px; margin:12px 0; }
  h2 { margin:4px 0 10px; }
  input, select, button { padding:8px; border-radius:8px; border:1px solid #2b3a4a; background:#0d141c; color:#e6edf3; }
  button { background: var(--c); border:none; cursor:pointer; }
  button.secondary { background: #1f2a37; }
  button.danger { background:#b91c1c; }
  table { border-collapse: collapse; width:100%; }
  th, td { border-bottom:1px solid #1f2a37; padding:6px 8px; text-align:left; vertical-align: top; }
  th { color:#93c5fd; position:sticky; top:0; background:#0b0f14; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
  small { opacity: .8; }
  .muted { opacity:.7; }
</style>
<header>
  <div>Joepienator – Admin</div>
  <div class="mono muted" id="tokinfo"></div>
</header>
<main>
<section>
  <h2>Quick e-mail actions</h2>
  <div class="row">
    <input id="welcome_email" placeholder="user@example.com" style="min-width:260px">
    <button type="button" onclick="sendWelcomeMail()">Send welcome mail</button>
  </div>
  <small class="muted" id="welcome_status"></small>
</section>

<section>
  <h2 style="cursor:pointer;user-select:none" onclick="toggleWelcomeEditor()">
    ✉️ Welcome mail template <small class="muted" id="welcome_editor_toggle">[klik om te openen]</small>
  </h2>
  <div id="welcome_editor_wrap" style="display:none">
    <div class="row" style="margin-bottom:8px">
      <label style="width:60px;flex-shrink:0">Subject</label>
      <input id="tpl_subject" style="flex:1;min-width:300px">
    </div>
    <div style="margin-bottom:6px">
      <label>HTML body</label><br>
      <textarea id="tpl_html" style="width:100%;height:380px;font-family:monospace;font-size:12px;margin-top:4px"></textarea>
    </div>
    <div style="margin-bottom:6px">
      <label>Plaintext body (optioneel)</label><br>
      <textarea id="tpl_text" style="width:100%;height:120px;font-family:monospace;font-size:12px;margin-top:4px"></textarea>
    </div>
    <div class="row" style="gap:8px;margin-bottom:6px">
      <button onclick="saveWelcomeTemplate()">Opslaan</button>
      <button class="secondary" onclick="previewWelcomeTemplate()">Preview</button>
      <button class="secondary" onclick="resetWelcomeTemplate()">Reset naar default</button>
    </div>
    <small class="muted" id="tpl_status"></small>
  </div>
</section>

  <section>
    <div class="row">
      <input id="q" placeholder="Zoek (email, plan, fingerprint…)" style="min-width:280px">
      <button onclick="loadList()">Laden</button>
      <button class="secondary" onclick="document.getElementById('q').value='';loadList()">Clear</button>
    </div>
    <div class="row" style="margin-top:10px; gap:10px; align-items:flex-end">
  <button class="secondary" onclick="bulkEmail()">Email selected</button>
  <button class="secondary" onclick="bulkWelcome()">Welcome selected</button>
  <input id="bulk_plan" placeholder="plan (launch/pro/.)" style="width:160px">
  <input id="bulk_exp" placeholder="expires ISO (YYYY-MM-DDTHH:MM:SSZ)" style="min-width:280px">
  <input id="bulk_max" placeholder="max_accounts" style="width:120px">
  <input id="bulk_eps" placeholder="eps_daily_limit (blank=clear)" style="width:160px">
  <button onclick="bulkUpdate()">Apply to selected</button>
  <button class="danger" onclick="bulkDelete()">Delete selected</button>
</div>

<div class="row" style="margin-top:10px; gap:10px; align-items:flex-end">
  <input id="rem_days" placeholder="Reminder days" value="7" style="width:120px">
  <button onclick="remPrev()">Reminders: Preview</button>
  <button onclick="remSend()">Reminders: Send</button>
</div>

<div class="row" style="margin-top:10px; gap:10px; align-items:flex-end">
  <button onclick="loadIpList()">IP list</button>
  <button onclick="loadIpBans()">IP bans</button>
  <input id="ip_in" placeholder="IP to ban/unban" style="width:200px">
  <button onclick="banIp()">Ban</button>
  <button onclick="unbanIp()">Unban</button>
</div>

<!-- Email compose modal -->
<div id="email_modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:9999;align-items:center;justify-content:center;">
  <div style="background:#1a1f2e;border:1px solid #374151;border-radius:12px;padding:24px;width:700px;max-width:95vw;max-height:92vh;overflow-y:auto;display:flex;flex-direction:column;gap:12px;">
    <h3 style="margin:0;color:#f9fafb;">Email selected users</h3>
    <label style="color:#9ca3af;font-size:13px;">Subject
      <input id="em_subject" style="display:block;width:100%;margin-top:4px;box-sizing:border-box;font-size:14px;" placeholder="Subject">
    </label>
    <label style="color:#9ca3af;font-size:13px;">Plain text body
      <textarea id="em_body" style="display:block;width:100%;height:200px;margin-top:4px;box-sizing:border-box;font-family:monospace;font-size:13px;resize:vertical;" placeholder="Plain text body…"></textarea>
    </label>
    <label style="color:#9ca3af;font-size:13px;">HTML body <span style="font-size:11px;color:#6b7280;">(optioneel — laat leeg om plain text te gebruiken)</span>
      <textarea id="em_html" style="display:block;width:100%;height:240px;margin-top:4px;box-sizing:border-box;font-family:monospace;font-size:12px;resize:vertical;" placeholder="<p>HTML versie…</p>"></textarea>
    </label>
    <p style="margin:0;font-size:12px;color:#6b7280;">Een unsubscribe-link wordt automatisch toegevoegd aan elke mail.</p>
    <div style="display:flex;gap:8px;justify-content:flex-end;align-items:center;">
      <small id="em_status" style="color:#ef4444;flex:1;"></small>
      <button class="secondary" onclick="document.getElementById('email_modal').style.display='none'">Annuleren</button>
      <button id="em_send_btn" onclick="submitBulkEmail()">Verstuur</button>
    </div>
  </div>
</div>

<pre id="bulk_out" class="mono" style="max-height:220px; overflow:auto; background:#0b0f14; padding:8px; border-radius:8px;"></pre>

    <div style="overflow:auto; max-height: 54vh; margin-top:10px;">
      <table id="tbl"><thead>
        <tr>
          <th><input type="checkbox" id="sel_all" onclick="toggleAll(this)"></th>
          <th>Owner</th>
          <th>Plan / Status</th>
          <th>Created</th>
          <th>Expires</th>
          <th>EPS used (month / total)</th>
          <th>AI used (month / limit)</th>
          <th>Ebay users & limits</th>
          <th>EPS/day</th>
          <th>Last seen</th>
          <th>Fingerprint</th>
        </tr></thead><tbody></tbody></table>
    </div>
  </section>

  <section>
    <h2>Upsert (met plain key)</h2>
    <div class="row">
      <input id="key" placeholder="Plain key">
      <input id="plan" placeholder="Plan (trial/basic/pro/extreme)" value="basic" style="width:160px">
      <input id="exp" placeholder="Expires (UTC ISO, bv 2026-01-01T00:00:00Z)" style="min-width:280px">
      <select id="status"><option>active</option><option>disabled</option><option>suspended</option></select>
      <input id="email" placeholder="Owner email">
      <input id="name" placeholder="Owner name">
      <input id="maxacc" placeholder="Max accounts" value="1" style="width:120px">
      <button onclick="upsert()">Opslaan</button>
    </div>
    <div class="mono" id="upsert_out"></div>
  </section>

  <section>
    <h2>Wijzig / verwijder (op ID)</h2>
    <div class="row">
      <input id="id" placeholder="HMAC id of fingerprint">
      <input id="u_plan" placeholder="Plan">
      <input id="u_exp" placeholder="Expires (UTC ISO)">
      <select id="u_status"><option value="">(ongewijzigd)</option><option>active</option><option>disabled</option><option>suspended</option></select>
      <input id="u_email" placeholder="Owner email">
      <input id="u_name" placeholder="Owner name">
      <input id="u_maxacc" placeholder="Max accounts">
      <button onclick="updateById()">Bijwerken</button>
      <button onclick="delById()" class="danger">Verwijderen</button>
    </div>
    <div class="mono" id="update_out"></div>
  </section>
  <section>
  <h2>EPS Usage & Limits</h2>
  <div class="row">
    <input id="eps_id" placeholder="License id or fingerprint (10 chars)" style="min-width:280px">
    <button onclick="epsGet()">Get usage</button>
    <button class="secondary" onclick="epsReset()">Reset today</button>
  </div>
  <pre id="eps_out" class="mono" style="max-height:220px; overflow:auto; background:#0b0f14; padding:8px; border-radius:8px;"></pre>
  <div class="row" style="margin-top:8px;">
    <input id="eps_limit_in" placeholder="Set eps_daily_limit (number or blank to clear)" style="min-width:280px">
    <button onclick="epsSetLimit()">Apply to ID</button>
  </div>
  <div style="margin-top:12px;">
    <button onclick="epsList()">List top usage</button>
    <pre id="eps_list" class="mono" style="max-height:240px; overflow:auto; background:#0b0f14; padding:8px; border-radius:8px;"></pre>
  </div>
</section>

<section style="border-top:2px solid #3d7ab5; margin-top:16px; padding-top:16px;">
  <h2 style="color:#3d7ab5;">🤖 AI Credits (maand)</h2>
  <p style="color:#6c88a0; font-size:13px; margin:0 0 10px;">
    1 credit per image-analyse · 1 credit per voice-opname · reset op 1e van de maand
  </p>
  <div class="row">
    <input id="ai_id" placeholder="License id of fingerprint (10 tekens)" style="min-width:280px">
    <button onclick="aiGet()">Get usage</button>
    <button class="secondary" onclick="aiReset()" style="background:#c04c2a;">Reset credits</button>
  </div>
  <pre id="ai_out" class="mono" style="max-height:220px; overflow:auto; background:#0b0f14; padding:8px; border-radius:8px;"></pre>
  <div style="margin-top:12px;">
    <button onclick="aiList()">List alle AI-gebruikers (deze maand)</button>
    <pre id="ai_list" class="mono" style="max-height:300px; overflow:auto; background:#0b0f14; padding:8px; border-radius:8px;"></pre>
  </div>
</section>

<section>
  <h2 style="cursor:pointer;user-select:none" onclick="toggleScanner()">
    📊 Scanner Analytics <small class="muted" id="scanner_toggle">[klik om te laden]</small>
  </h2>
  <div id="scanner_wrap" style="display:none">
    <div id="scanner_summary" class="row" style="gap:20px;margin-bottom:14px;flex-wrap:wrap"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div>
        <div style="color:#93c5fd;font-size:12px;margin-bottom:6px;font-weight:600">SCANS PER DAY (last 30 days)</div>
        <canvas id="scanner_chart" height="140" style="background:#0b0f14;border-radius:8px;width:100%"></canvas>
      </div>
      <div>
        <div style="color:#93c5fd;font-size:12px;margin-bottom:6px;font-weight:600">BY SITE</div>
        <div id="scanner_sites" class="mono" style="font-size:12px"></div>
        <div style="color:#93c5fd;font-size:12px;margin:10px 0 6px;font-weight:600">TOP SCANNED ITEMS</div>
        <div id="scanner_top" style="font-size:12px;max-height:260px;overflow:auto"></div>
      </div>
    </div>
  </div>
</section>

</main>
<script>
  const TOKEN = new URLSearchParams(location.search).get('token') || '';
  document.getElementById('tokinfo').textContent = TOKEN ? ('token=' + TOKEN) : '(geen token)';

async function j(url, method='GET', body=null) {
  const h = {'Content-Type':'application/json'};
  const needApi = location.pathname.startsWith('/api/');
  let u = (needApi && url.startsWith('/admin/')) ? ('/api' + url) : url;
  if (TOKEN) u += (u.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(TOKEN);
  const res = await fetch(u, {method, headers:h, body: body? JSON.stringify(body):null});
  if (!res.ok) {
    let t = await res.text();
    try { t = (JSON.parse(t).detail || t); } catch(_){}
    throw new Error(t || (res.status + ' ' + res.statusText));
  }
  const ct = res.headers.get('content-type') || '';
  return ct.startsWith('application/json') ? await res.json() : await res.text();
}
  let PLAN_MAX = {};

  async function loadPlanDefaults() {
    try {
      const d = await j('/admin/_plan_defaults');   // j() regelt de /api-prefix indien nodig
      PLAN_MAX = d.plan_max_accounts || {};
    } catch (e) {
      PLAN_MAX = {};
    }
  }

  function wirePlanAutoFill() {
    const planInput   = document.getElementById('plan');
    const maxAccInput = document.getElementById('max_accounts');
    if (!planInput || !maxAccInput) return;

    function syncMax() {
      const p = (planInput.value || '').trim().toLowerCase();
      const def = PLAN_MAX[p]; // getal of null (∞)
      if (def === undefined) return; // onbekend plan → niets doen
      if (maxAccInput.value === '' || maxAccInput.dataset.autofill === '1') {
        maxAccInput.value = (def == null ? '' : String(def));   // leeg = onbeperkt
        maxAccInput.placeholder = (def == null ? '∞' : String(def));
        maxAccInput.dataset.autofill = '1';
      }
    }

    planInput.addEventListener('change', syncMax);
    planInput.addEventListener('blur',   syncMax);
    maxAccInput.addEventListener('input', () => { maxAccInput.dataset.autofill = '0'; });

    // eerste keer invullen
    syncMax();
  }

  // bij UI-load
  loadPlanDefaults().then(wirePlanAutoFill);

  async function epsGet(){ const id = eps_id.value.trim(); const out = await j('/admin/usage/for/'+encodeURIComponent(id)); eps_out.textContent = JSON.stringify(out, null, 2); }
  async function epsReset(){ const id = eps_id.value.trim(); const out = await j('/admin/usage/reset','POST',{id}); eps_out.textContent = JSON.stringify(out, null, 2); }
  async function epsList(){ const out = await j('/admin/usage?limit=100'); eps_list.textContent = JSON.stringify(out, null, 2); }

  async function aiGet(){
    const id = document.getElementById('ai_id').value.trim();
    if (!id) { alert('Vul een license id of fingerprint in'); return; }
    try { const out = await j('/admin/usage/ai/for/'+encodeURIComponent(id)); document.getElementById('ai_out').textContent = JSON.stringify(out, null, 2); }
    catch(e) { document.getElementById('ai_out').textContent = 'Fout: ' + (e&&e.message?e.message:e); }
  }
  async function aiReset(){
    const id = document.getElementById('ai_id').value.trim();
    if (!id) { alert('Vul een license id of fingerprint in'); return; }
    if (!confirm('AI credits resetten voor ' + id + '?')) return;
    try { const out = await j('/admin/usage/ai/reset','POST',{id}); document.getElementById('ai_out').textContent = JSON.stringify(out, null, 2); }
    catch(e) { document.getElementById('ai_out').textContent = 'Fout: ' + (e&&e.message?e.message:e); }
  }
  async function aiList(){
    try { const out = await j('/admin/usage/ai?limit=200'); document.getElementById('ai_list').textContent = JSON.stringify(out, null, 2); }
    catch(e) { document.getElementById('ai_list').textContent = 'Fout: ' + (e&&e.message?e.message:e); }
  }
  async function epsSetLimit(){
    const id = (document.getElementById('id').value.trim() || eps_id.value.trim());
    const v  = eps_limit_in.value.trim();
    const out = await j('/admin/license/update-by-id','POST', {id, eps_daily_limit: v});
    alert('Updated. New eps_daily_limit=' + out.eps_daily_limit);
  }
function selectedIds(){
  return Array.from(document.querySelectorAll('input.sel:checked'))
    .map(el => el.getAttribute('data-id')).filter(Boolean);
}
function toggleAll(master){
  const on = !!master.checked;
  document.querySelectorAll('input.sel').forEach(el => el.checked = on);
}

async function bulkUpdate(){
  try{
    const ids = selectedIds();
    const payload = {
      ids,
      plan: document.getElementById('bulk_plan').value.trim() || null,
      expires_at: document.getElementById('bulk_exp').value.trim() || null,
      max_accounts: document.getElementById('bulk_max').value.trim(),
      eps_daily_limit: document.getElementById('bulk_eps').value.trim()
    };
    const out = await j('/admin/bulk/update','POST',payload);
    bulk_out.textContent = JSON.stringify(out,null,2);
    await loadList();
  }catch(e){ alert('Bulk update failed: ' + (e && e.message ? e.message : e)); }
}

async function bulkDelete(){
  try{
    const ids = selectedIds();
    if (!ids.length) return alert('No selection');
    if (!confirm('Delete selected licenses? EPS counters for those fingerprints will be purged.')) return;
    const out = await j('/admin/bulk/delete','POST',{ids});
    bulk_out.textContent = JSON.stringify(out,null,2);
    await loadList();
  }catch(e){ alert('Bulk delete failed: ' + (e && e.message ? e.message : e)); }
}

async function bulkEmail(){
  const ids = selectedIds();
  if (!ids.length) return alert('No selection');
  window._bulkEmailIds = ids;
  document.getElementById('em_subject').value = '';
  document.getElementById('em_body').value = '';
  document.getElementById('em_html').value = '';
  document.getElementById('em_status').textContent = '';
  document.getElementById('email_modal').style.display = 'flex';
  setTimeout(() => document.getElementById('em_subject').focus(), 50);
}

async function remPrev(){
  try{
    const days = parseInt(document.getElementById('rem_days').value || '7', 10);
    const out = await j('/admin/reminders/preview?days='+days);
    bulk_out.textContent = JSON.stringify(out,null,2);
  }catch(e){ alert('Preview failed: ' + (e && e.message ? e.message : e)); }
}
async function remSend(){
  try{
    const days = parseInt(document.getElementById('rem_days').value || '7', 10);
    const out = await j('/admin/reminders/send','POST',{days});
    bulk_out.textContent = JSON.stringify(out,null,2);
  }catch(e){ alert('Send failed: ' + (e && e.message ? e.message : e)); }
}

async function loadIpList(){ const out = await j('/admin/ip/list'); bulk_out.textContent = JSON.stringify(out,null,2); }
async function loadIpBans(){ const out = await j('/admin/ip/bans'); bulk_out.textContent = JSON.stringify(out,null,2); }
async function banIp(){ const ip = ip_in.value.trim(); if (!ip) return; const out = await j('/admin/ip/ban','POST',{ip}); bulk_out.textContent = JSON.stringify(out,null,2); }
async function unbanIp(){ const ip = ip_in.value.trim(); if (!ip) return; const out = await j('/admin/ip/unban','POST',{ip}); bulk_out.textContent = JSON.stringify(out,null,2); }

// Scanner analytics
let scannerLoaded = false;
async function toggleScanner(){
  const wrap = document.getElementById('scanner_wrap');
  const toggle = document.getElementById('scanner_toggle');
  if (wrap.style.display === 'none') {
    wrap.style.display = 'block';
    toggle.textContent = '[verbergen]';
    if (!scannerLoaded) {
      try {
        const d = await j('/admin/scanner/stats');
        scannerLoaded = true;
        // Summary cards
        const sum = document.getElementById('scanner_summary');
        sum.innerHTML = [
          {l:'Today', v:d.today, c:'#4ade80'},
          {l:'Week', v:d.week, c:'#60a5fa'},
          {l:'Month', v:d.month, c:'#c084fc'},
          {l:'Total', v:d.total, c:'#fbbf24'},
          {l:'IPs today', v:d.unique_ips_today, c:'#f87171'},
        ].map(x => '<div style="background:#1e293b;padding:12px 16px;border-radius:8px;min-width:80px"><div style="color:'+x.c+';font-size:24px;font-weight:700">'+x.v+'</div><div style="color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.08em">'+x.l+'</div></div>').join('');
        // Sites
        const sites = document.getElementById('scanner_sites');
        sites.innerHTML = Object.entries(d.by_site||{}).map(([s,n]) => '<div>'+s+': <strong>'+n+'</strong></div>').join('');
        // Top items
        const top = document.getElementById('scanner_top');
        top.innerHTML = (d.top_items||[]).map(t => '<div style="margin-bottom:4px"><strong>'+t.count+'x</strong> '+t.label+'</div>').join('');
        // Chart
        const canvas = document.getElementById('scanner_chart');
        if (canvas && d.daily && d.daily.length) {
          const ctx = canvas.getContext('2d');
          const W = canvas.width = canvas.offsetWidth;
          const H = canvas.height = 140;
          const days = d.daily;
          const maxN = Math.max(...days.map(x=>x.n), 1);
          const barW = Math.max(4, (W - 20) / days.length - 2);
          ctx.clearRect(0, 0, W, H);
          days.forEach((day, i) => {
            const h = (day.n / maxN) * (H - 24);
            const x = 10 + i * (barW + 2);
            ctx.fillStyle = '#3b82f6';
            ctx.fillRect(x, H - 12 - h, barW, h);
            if (days.length <= 14) {
              ctx.fillStyle = '#475569';
              ctx.font = '9px sans-serif';
              ctx.fillText(day.date.slice(5), x, H - 2);
            }
          });
        }
      } catch(e) {
        document.getElementById('scanner_summary').textContent = 'Error: ' + (e.message||e);
      }
    }
  } else {
    wrap.style.display = 'none';
    toggle.textContent = '[klik om te laden]';
  }
}

async function loadList(){
  try{
    const q  = (document.getElementById('q')?.value || '').trim();
    const data = await j('/admin/licenses' + (q ? ('?q=' + encodeURIComponent(q)) : ''));
    const tb = document.querySelector('#tbl tbody');
    if (!tb) throw new Error('#tbl tbody not found');
    tb.innerHTML = '';

    for (const r of data){
      try {
        // ===== per rij: gebruik 1 stabiele variabelenaam
        const row = document.createElement('tr');

        // stabiele sleutel voor knoppen / bulkselectie
        const licKey = r._hmac || r.id || r.key || '';
        const fp = r._fingerprint
          || (licKey && licKey.startsWith('HMAC256:') ? licKey.slice(8,18)
          : (licKey ? licKey.slice(0,12) : '—'));


        // owner/plan/exp
        const owner   = (r.owner_email || r.owner_name || '—');
        const plan    = (r.plan || '—') + ' / ' + (r.status || 'active');
        const exp     = r.expires_at || '—';
        const created = r.created_at ? String(r.created_at).slice(0, 10) : '—';
        const last    = r.last_seen_at ? String(r.last_seen_at).slice(0, 10) : '—';

        // EPS limieten (effectief/override/plan)
        const eff = (r.eps_daily_limit_effective == null ? '∞' : r.eps_daily_limit_effective);
        const ov  = (r.eps_daily_limit_override  == null ? '—' : r.eps_daily_limit_override);
        const pd  = (r.plan_default_limit        == null ? '—' : r.plan_default_limit);

        // EPS verbruik (huidige maand / lifetime)
        const epsMonth = (r.eps_month_count == null ? 0 : r.eps_month_count);
        const epsTotal = (r.eps_total_count == null ? 0 : r.eps_total_count);

        // AI verbruik (huidige maand) + limiet
        const aiTotal  = (r.ai_total_used  == null ? 0 : r.ai_total_used);
        const aiImages = (r.ai_images_used == null ? 0 : r.ai_images_used);
        const aiVoice  = (r.ai_voice_used  == null ? 0 : r.ai_voice_used);
        const aiLimit  = (r.ai_quota_limit == null ? 0 : r.ai_quota_limit);


        // identities/users
        const ids   = Array.isArray(r.allowed_identity_ids) ? r.allowed_identity_ids : [];
        const users = Array.isArray(r.allowed_ebay_users)   ? r.allowed_ebay_users   : [];
        const map   = r.identity_usernames || {};
        const max   = parseInt(r.max_accounts || '1', 10);
        const active = ids.length || users.length;

        // === checkbox kolom
        const tdSel = document.createElement('td');
        tdSel.innerHTML = `<input type="checkbox" class="sel" data-id="${licKey || fp}">`;
        row.appendChild(tdSel);

        // === owner / plan / created / expires
        const tdOwner   = document.createElement('td'); tdOwner.textContent   = owner;
        const tdPlan    = document.createElement('td'); tdPlan.textContent    = plan;
        const tdCreated = document.createElement('td'); tdCreated.textContent = created;
        const tdExp     = document.createElement('td'); tdExp.textContent     = exp;
        const tdLast    = document.createElement('td'); tdLast.textContent = last;

        // === users/ids + max-zetter
        const tdUsers = document.createElement('td');
        const tdEpsUsage = document.createElement('td');
        tdEpsUsage.innerHTML = `${epsMonth} <span class="muted">/ ${epsTotal}</span>`;
        const tdAiUsage = document.createElement('td');
        const aiLimitTxt = aiLimit > 0 ? aiLimit : '—';
        tdAiUsage.innerHTML = `${aiTotal} <span class="muted">/ ${aiLimitTxt}</span>`
          + `<div class="muted" style="font-size:.78rem">img ${aiImages} · voice ${aiVoice}</div>`;
        const usersHtml = users.length
          ? users.map(u => `${u} <button onclick="detachUser('${licKey}','${u}')">Detach</button>`).join('<br>')
          : '<span class="muted">—</span>';
        const identitiesHtml = ids.length
          ? ids.map(id => {
              const label = map[id] || (id ? id.slice(0,12) : '—');
              return `${label} <button onclick="detachIdentity('${licKey}','${id}')">Detach</button>`;
            }).join('<br>')
          : '<span class="muted">—</span>';

        // toon identities eerst als ze bestaan, anders usernames
        const showIdentitiesFirst = ids.length >= users.length;
        tdUsers.innerHTML = `
          <div>${ showIdentitiesFirst ? identitiesHtml : usersHtml }</div>
          <div style="margin-top:6px">
            <small>Active: ${active} / ${max}</small>
            &nbsp;
            <input id="mx-${fp}" type="number" min="1" value="${max}" style="width:90px">
            <button onclick="setMax('${licKey}','mx-${fp}')">Set</button>
          </div>
        `;

        // === EPS kolom
        const tdEps = document.createElement('td');
        tdEps.innerHTML = `${eff}<div class="muted">(override: ${ov}, plan: ${pd})</div>`;

        // === fingerprint kolom
        const tdFp = document.createElement('td'); tdFp.className='mono'; tdFp.textContent = fp;

        // === append in vaste volgorde
        row.appendChild(tdOwner);
        row.appendChild(tdPlan);
        row.appendChild(tdCreated);
        row.appendChild(tdExp);
        row.appendChild(tdEpsUsage);
        row.appendChild(tdAiUsage);
        row.appendChild(tdUsers);
        row.appendChild(tdEps);   // EPS/day
        row.appendChild(tdLast);
        row.appendChild(tdFp);
        tb.appendChild(row);
      } catch (rowErr) {
        console.warn('Row render failed:', rowErr, r);
        // sla alleen de kapotte rij over; niet de hele lijst
      }
    }
  } catch(e){
    alert('Load failed: ' + (e && e.message ? e.message : e));
  }
}
window.loadList = loadList;  // zorg dat onclick="..." 'm vindt

// identity-detach handler (POST naar nieuwe route)
async function detachIdentity(id_fp, identityId){
  try{
    await j('/admin/license/detach_identity', 'POST', { id: id_fp, identity_id: identityId });
    await loadList();
  } catch(e){
    alert('Detach identity failed: ' + (e && e.message ? e.message : e));
  }
}
window.detachIdentity = detachIdentity; // globaal voor onclick=


// Zorg dat deze handler bestaat (identity detach)
async function detachIdentity(id_fp, identityId){
  try{
    await j('/admin/license/detach_identity', 'POST', { id: id_fp, identity_id: identityId });
    await loadList();
  } catch(e){
    alert('Detach identity failed: ' + (e && e.message ? e.message : e));
  }
}
window.detachIdentity = detachIdentity;  // globaal maken voor onclick=



  async function upsert(){
    try{
      const payload = {
        plain_key: document.getElementById('key').value.trim(),
        plan: document.getElementById('plan').value.trim() || 'basic',
        expires_at: document.getElementById('exp').value.trim(),
        status: document.getElementById('status').value.trim(),
        owner_email: document.getElementById('email').value.trim() || null,
        owner_name: document.getElementById('name').value.trim() || null,
        max_accounts: parseInt(document.getElementById('maxacc').value || '1', 10)
      };
      const out = await j('/admin/license/upsert', 'POST', payload);
      document.getElementById('upsert_out').textContent = JSON.stringify(out, null, 2);
      await loadList();
    } catch(e){ alert('Upsert failed: ' + (e && e.message ? e.message : e)); }
  }

  async function updateById(){
    try{
      const payload = {
        id: document.getElementById('id').value.trim(),
        plan: document.getElementById('u_plan').value.trim() || null,
        expires_at: document.getElementById('u_exp').value.trim() || null,
        status: document.getElementById('u_status').value.trim() || null,
        owner_email: document.getElementById('u_email').value.trim() || null,
        owner_name: document.getElementById('u_name').value.trim() || null,
        max_accounts: document.getElementById('u_maxacc').value.trim() || null
      };
      const out = await j('/admin/license/update-by-id', 'POST', payload);
      document.getElementById('update_out').textContent = JSON.stringify(out, null, 2);
      await loadList();
    } catch(e){ alert('Update failed: ' + (e && e.message ? e.message : e)); }
  }

  async function delById(){
    try{
      const id = document.getElementById('id').value.trim();
      const out = await j('/admin/license/'+encodeURIComponent(id), 'DELETE');
      document.getElementById('update_out').textContent = JSON.stringify(out, null, 2);
      await loadList();
    } catch(e){ alert('Delete failed: ' + (e && e.message ? e.message : e)); }
  }

  async function detachUser(id_fp, user){
    try{
      await j('/admin/license/detach_ebay_user', 'POST', { id: id_fp, ebay_user: user });
      await loadList();
    } catch(e){ alert('Detach failed: ' + (e && e.message ? e.message : e)); }
  }

  async function setMax(id_fp, inputId){
    try{
      const val = parseInt(document.getElementById(inputId).value || '1', 10);
      if (!val || val < 1) return;
      await j('/admin/license/set_max_accounts', 'POST', { id: id_fp, max_accounts: val });
      await loadList();
    } catch(e){ alert('Set max failed: ' + (e && e.message ? e.message : e)); }
  }

  // global voor inline onclick=
  window.loadList = loadList; window.upsert = upsert; window.updateById = updateById;
  window.delById = delById; window.detachUser = detachUser; window.setMax = setMax;

  // enter = zoeken
  const _q = document.getElementById('q'); if (_q) _q.addEventListener('keydown', e => { if (e.key==='Enter') loadList(); });

  loadList();
  (() => {
  const $ = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  // Fallback fetch helper als je 'j' niet hebt:
  if (!window.j) {
    window.j = async (path, method='GET', json=null) => {
      const opt = { method, headers: {'Content-Type':'application/json'} };
      if (json) opt.body = JSON.stringify(json);
      const res = await fetch(path, opt);
      const txt = await res.text();
      if (!res.ok) throw new Error(txt || res.statusText);
      try { return JSON.parse(txt); } catch { return txt; }
    };
  }
  async function sendWelcomeMail() {
    const email  = ($('#welcome_email')?.value || '').trim();
    const status = $('#welcome_status');
    if (status) status.textContent = '';
    if (!email) {
      if (status) status.textContent = 'Please enter an e-mail address.';
      return;
    }
    try {
      await j('/admin/email/welcome', 'POST', { email });
      if (status) status.textContent = 'Welcome mail sent.';
    } catch (e) {
      if (status) status.textContent = 'Failed: ' + (e && e.message ? e.message : e);
    }
  }

  // === Globale helpers voor inline onclick ===
  window.toggleAll = (master) => {
    $$('.sel').forEach(el => el.checked = master.checked);
  };
  window.selectedIds = () =>
    $$('.sel:checked').map(el => el.dataset.id).filter(Boolean);

  window.bulkEmail = () => {
    const ids = window.selectedIds(); if (!ids.length) return alert('No selection');
    window._bulkEmailIds = ids;
    document.getElementById('em_subject').value = '';
    document.getElementById('em_body').value = '';
    document.getElementById('em_html').value = '';
    document.getElementById('em_status').textContent = '';
    document.getElementById('email_modal').style.display = 'flex';
    setTimeout(() => document.getElementById('em_subject').focus(), 50);
  };

  window.submitBulkEmail = async () => {
    const ids = window._bulkEmailIds || [];
    const subject = document.getElementById('em_subject').value.trim();
    const body    = document.getElementById('em_body').value.trim();
    const html    = document.getElementById('em_html').value.trim();
    const status  = document.getElementById('em_status');
    if (!subject || (!body && !html)) { status.textContent = 'Subject en body zijn verplicht.'; return; }
    const btn = document.getElementById('em_send_btn');
    btn.disabled = true; btn.textContent = 'Bezig…';
    try {
      const out = await j('/admin/bulk/email', 'POST', {ids, subject, body, html});
      document.getElementById('email_modal').style.display = 'none';
      const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out, null, 2);
    } catch(e) {
      status.textContent = 'Fout: ' + (e && e.message ? e.message : e);
    } finally {
      btn.disabled = false; btn.textContent = 'Verstuur';
    }
  };
  window.bulkWelcome = async () => {
    const ids = window.selectedIds(); if (!ids.length) return alert('No selection');
    const out = await j('/admin/bulk/welcome', 'POST', { ids });
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out, null, 2);
  };
  window.bulkUpdate = async () => {
    const ids = window.selectedIds(); if (!ids.length) return alert('No selection');
    const payload = {
      ids,
      plan: ($('#bulk_plan')?.value || '').trim() || null,
      expires_at: ($('#bulk_exp')?.value || '').trim() || null,
      max_accounts: ($('#bulk_max')?.value || '').trim(),
      eps_daily_limit: ($('#bulk_eps')?.value || '').trim()
    };
    const out = await j('/admin/bulk/update','POST',payload);
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
    if (window.loadList) window.loadList();
  };

  window.bulkDelete = async () => {
    const ids = window.selectedIds(); if (!ids.length) return alert('No selection');
    if (!confirm('Delete selected licenses? EPS counters for those fingerprints will be purged.')) return;
    const out = await j('/admin/bulk/delete','POST',{ids});
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
    if (window.loadList) window.loadList();
  };

  window.remPrev = async () => {
    const days = parseInt($('#rem_days')?.value || '7', 10);
    const out = await j('/admin/reminders/preview?days='+days);
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
  };
  window.remSend = async () => {
    const days = parseInt($('#rem_days')?.value || '7', 10);
    const out = await j('/admin/reminders/send','POST',{days});
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
  };

  window.loadIpList = async () => {
    const out = await j('/admin/ip/list');
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
  };
  window.loadIpBans = async () => {
    const out = await j('/admin/ip/bans');
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
  };
  window.banIp = async () => {
    const ip = ($('#ip_in')?.value || '').trim(); if (!ip) return;
    const out = await j('/admin/ip/ban','POST',{ip});
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
  };
  window.unbanIp = async () => {
    const ip = ($('#ip_in')?.value || '').trim(); if (!ip) return;
    const out = await j('/admin/ip/unban','POST',{ip});
    const box = $('#bulk_out'); if (box) box.textContent = JSON.stringify(out,null,2);
  };

  // Fail-safe: als je nog géén loadList had, zorg dan dat de knop werkt
  window.loadList = window.loadList || (async () => { location.reload(); });
  window.sendWelcomeMail = sendWelcomeMail;

  // ---- Welcome template editor ----
  let _welcomeEditorOpen = false;
  async function toggleWelcomeEditor() {
    const wrap = $('#welcome_editor_wrap');
    const lbl  = $('#welcome_editor_toggle');
    _welcomeEditorOpen = !_welcomeEditorOpen;
    wrap.style.display = _welcomeEditorOpen ? '' : 'none';
    lbl.textContent = _welcomeEditorOpen ? '[klik om te sluiten]' : '[klik om te openen]';
    if (_welcomeEditorOpen && !$('#tpl_subject').value) {
      try {
        const d = await j('/admin/email/template/welcome', 'GET');
        $('#tpl_subject').value = d.subject || '';
        $('#tpl_html').value    = d.html    || '';
        $('#tpl_text').value    = d.text    || '';
      } catch(e) { $('#tpl_status').textContent = 'Laden mislukt: ' + e; }
    }
  }
  async function saveWelcomeTemplate() {
    const st = $('#tpl_status');
    st.textContent = 'Opslaan…';
    try {
      await j('/admin/email/template/welcome', 'POST', {
        subject: $('#tpl_subject').value,
        html:    $('#tpl_html').value,
        text:    $('#tpl_text').value,
      });
      st.textContent = 'Opgeslagen ✓';
    } catch(e) { st.textContent = 'Fout: ' + e; }
  }
  function previewWelcomeTemplate() {
    const html = $('#tpl_html').value;
    if (!html) { alert('HTML is leeg'); return; }
    const w = window.open('', '_blank');
    w.document.open();
    w.document.write(html);
    w.document.close();
  }
  async function resetWelcomeTemplate() {
    if (!confirm('Weet je zeker dat je de template terugzet naar de default?')) return;
    const st = $('#tpl_status');
    st.textContent = 'Resetten…';
    try {
      await j('/admin/email/template/welcome/reset', 'POST', {});
      const d = await j('/admin/email/template/welcome', 'GET');
      $('#tpl_subject').value = d.subject || '';
      $('#tpl_html').value    = d.html    || '';
      $('#tpl_text').value    = d.text    || '';
      st.textContent = 'Teruggezet naar default ✓';
    } catch(e) { st.textContent = 'Fout: ' + e; }
  }
  window.toggleWelcomeEditor = toggleWelcomeEditor;
  window.saveWelcomeTemplate = saveWelcomeTemplate;
  window.previewWelcomeTemplate = previewWelcomeTemplate;
  window.resetWelcomeTemplate = resetWelcomeTemplate;
})();
</script>
"""
  return HTMLResponse(
    html,
    headers={"Cache-Control":"no-store","Referrer-Policy":"no-referrer"}
)

# ----------------- admin endpoints -----------------
@router.get("/ui")
def admin_ui(request: Request, token: str | None = None):
    # éénmalig: ?token=… omzetten naar sessie-cookie
    if token and ADMIN_UI_TOKEN and token == ADMIN_UI_TOKEN:
        sess = _sess_issue(ADMIN_UI_USER)
        resp = RedirectResponse(url="/api/admin/ui", status_code=302)
        _set_admin_cookie(resp, sess)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # zonder sessie: naar login
    if not _admin_logged_in(request):
        return RedirectResponse(url="/api/admin/login", status_code=302)

    # render UI (let op: niet dubbel in HTMLResponse wikkelen als je helper dat al doet)
    return render_admin_html_somehow()

@router.get("/licenses")
def list_licenses(req: Request, q: Optional[str] = None) -> List[Dict[str, Any]]:
    _require_admin(req)
    data = _read_store()
    out: List[Dict[str, Any]] = []
    ql = (q or "").strip().lower()
        # EPS-usage in één keer ophalen (huidige maand + lifetime total).
    # eps_list_usage retourneert één rij per (fp, month). Een fp die in
    # meerdere maanden heeft geuploaded heeft dus meerdere rijen.
    # Een naïeve {fp: r} dict overschrijft per fp en houdt willekeurig
    # één maand over (SQLite SELECT zonder ORDER BY = unspecified order),
    # waardoor recente uploads na een reset onzichtbaar konden zijn in
    # het admin panel terwijl de DB en de user-UI ze wel zagen.
    # Daarom per fp aggregeren: huidige maand voor 'count', som over alle
    # maanden voor 'total'.
    eps_rows = eps_list_usage(10000)
    _eps_now_month = datetime.now(timezone.utc).strftime("%Y-%m-01")
    eps_map: Dict[str, Dict[str, int]] = {}
    for _r in eps_rows:
        _fp = str(_r.get("fp") or "")
        if not _fp:
            continue
        _entry = eps_map.setdefault(_fp, {"count": 0, "total": 0})
        try:
            _entry["total"] += int(_r.get("total") or 0)
        except Exception:
            pass
        if str(_r.get("date") or "") == _eps_now_month:
            try:
                _entry["count"] = int(_r.get("count") or 0)
            except Exception:
                pass

    # AI-quota limieten per plan — spiegelt _ai_quota_limit() uit app.py
    def _ai_limit_for_plan(plan: str) -> int:
        p = (plan or "").lower()
        try:
            if "extreme" in p:
                return int(os.getenv("AI_QUOTA_EXTREME", "2000"))
            if "pro" in p:
                return int(os.getenv("AI_QUOTA_PRO", "10000"))
            if "launch" in p:
                return int(os.getenv("AI_QUOTA_LAUNCH", "100"))
            if "trial" in p:
                return int(os.getenv("AI_QUOTA_TRIAL", "20"))
        except Exception:
            pass
        return 0

    # Huidige maand voor AI-tellers (formaat YYYY-MM zoals app.py gebruikt)
    _now_month_ai = datetime.now(timezone.utc).strftime("%Y-%m")

    for k, rec in data.items():
        row = {
            "plan": rec.get("plan"),
            "status": rec.get("status"),
            "expires_at": rec.get("expires_at"),
            "created_at": rec.get("created_at"),
            "owner_email": rec.get("owner_email"),
            "owner_name": rec.get("owner_name"),
            "allowed_identity_ids": rec.get("allowed_identity_ids") or None,
            "identity_usernames": rec.get("identity_usernames") or {},
            "max_accounts": rec.get("max_accounts") or 1,
            "allowed_ebay_users": rec.get("allowed_ebay_users") or [],
            "last_seen_at": rec.get("last_seen_at"),
            "_fingerprint": rec.get("_fingerprint") or (k[8:18] if isinstance(k, str) and k.startswith("HMAC256:") else k[:12]),
            "_hmac": k,
        }
        plmap = getattr(list_licenses, "_plmap", None) or plan_limits()
        setattr(list_licenses, "_plmap", plmap)

        plan_key   = str(rec.get("plan") or "").lower()
        pd         = plmap.get(plan_key, None)   # plan default
        ov_raw     = rec.get("eps_daily_limit", None)
        try:
            ov = int(ov_raw) if ov_raw not in (None, "") else None
        except Exception:
            ov = None
        eff = ov if ov is not None else pd

        row["plan_default_limit"]        = pd
        row["eps_daily_limit_override"]  = ov
        row["eps_daily_limit_effective"] = eff
        # ── EPS aggregeren over alle mogelijke keys voor deze license ──
        # Uploads worden onder verschillende keys gelogd (ebayid:, ebayuser:,
        # owner:, of de 10-char fingerprint) — afhankelijk van wat er actief is.
        fp = row.get("_fingerprint") or _fp_from_key_and_rec(k, rec) or ""
        _eps_keys: List[str] = []
        for _iid in (rec.get("allowed_identity_ids") or []):
            if _iid:
                _eps_keys.append(f"ebayid:{_iid}")
        for _u in (rec.get("allowed_ebay_users") or []):
            if _u:
                _eps_keys.append(f"ebayuser:{str(_u).lower()}")
        _oe = (rec.get("owner_email") or "").strip().lower()
        if _oe:
            _eps_keys.append(f"owner:{_oe}")
        if fp:
            _eps_keys.append(str(fp))

        _mc_eps, _tc_eps, _seen_eps = 0, 0, set()
        for _kk in _eps_keys:
            if _kk in _seen_eps:
                continue
            _seen_eps.add(_kk)
            _u_row = eps_map.get(_kk)
            if not _u_row:
                continue
            try: _mc_eps += int(_u_row.get("count") or 0)
            except Exception: pass
            try: _tc_eps += int(_u_row.get("total") or 0)
            except Exception: pass
        row["eps_month_count"] = _mc_eps
        row["eps_total_count"] = _tc_eps

        # ── AI-tellers uit license meta (huidige maand) ──
        def _ai_mc(_rec, _fld, _mfld):
            if not isinstance(_rec, dict):
                return 0
            if (_rec.get(_mfld) or "") != _now_month_ai:
                return 0
            try:
                return max(0, int(_rec.get(_fld) or 0))
            except Exception:
                return 0
        row["ai_total_used"]  = _ai_mc(rec, "ai_calls_used",  "ai_calls_month")
        row["ai_images_used"] = _ai_mc(rec, "ai_images_used", "ai_images_month")
        row["ai_voice_used"]  = _ai_mc(rec, "ai_voice_used",  "ai_voice_month")
        row["ai_quota_limit"] = _ai_limit_for_plan(plan_key)
        if ql:
            hay = " ".join([
                str(row.get("owner_email") or ""),
                str(row.get("owner_name") or ""),
                str(row.get("plan") or ""),
                str(row.get("status") or ""),
                str(row.get("expires_at") or ""),
                str(row.get("_fingerprint") or ""),
                
                str(k or ""),
            ]).lower()
            if ql not in hay:
                continue
        out.append(row)
    return out

@router.post("/license/upsert")
def admin_upsert(req: Request, payload: dict):
    _require_admin(req)
    plain = (payload.get("plain_key") or "").strip()
    if not plain:
        raise HTTPException(status_code=400, detail="plain_key required")
    # doorgeven wat is ingevuld
    expires_at_iso_utc = payload.get("expires_at") or payload.get("exp") or None
    plan_lower = (payload.get("plan") or "").strip().lower()
    raw_max = (payload.get("max_accounts") or "").strip()
    if raw_max:
        max_acc = int(raw_max)
    else:
    # Plan-default gebruiken (fallback naar 1 als plan onbekend)
      max_acc = int(plan_max_accounts().get(plan_lower) or 1)
    rec = upsert_license_plain(
        plain_key=plain,
        plan=(payload.get("plan") or "").strip().lower() or "basic",
        expires_at_iso_utc=expires_at_iso_utc,
        status=(payload.get("status") or None),
        owner_email=(payload.get("owner_email") or None),
        owner_name=(payload.get("owner_name") or None),
        max_accounts=max_acc,
    )
    return rec

@router.post("/license/update-by-id")
def admin_update_by_id(req: Request, payload: dict):
    _require_admin(req)

    ident = (payload.get("id") or "").strip()
    if not ident:
        raise HTTPException(status_code=400, detail="id required")

    data = _read_store()
    try:
        key = _resolve_key_by_id_or_fp(data, ident)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    rec = dict(data.get(key) or {})
    plan_before = (rec.get("plan") or "").strip().lower()

    # simpele tekstvelden
    for fld in ["expires_at", "status", "owner_email", "owner_name"]:
        val = payload.get(fld)
        if val is not None and val != "":
            rec[fld] = val

    # plan (normaliseren)
    plan_after = plan_before
    new_plan_raw = (payload.get("plan") or "").strip()
    if new_plan_raw:
        plan_after = new_plan_raw.lower()
        rec["plan"] = plan_after

    # max_accounts
    raw_max = (payload.get("max_accounts") or "").strip()
    if raw_max != "":
        # expliciet gezet → wint
        try:
            rec["max_accounts"] = int(raw_max)
        except Exception:
            # als iemand iets niet-numerieks invult, laat 'm dan staan of negeer;
            # hier kiezen we voor 'laten staan' voor transparantie
            rec["max_accounts"] = raw_max
    else:
        # leeg gelaten: alleen auto-invullen met plan-default als plan wijzigt
        # of als max_accounts-veld expliciet aanwezig maar leeg is meegestuurd
        if ("plan" in payload and plan_after != plan_before) or ("max_accounts" in payload):
            default_max = plan_max_accounts().get(plan_after, None)  # None = onbeperkt
            if default_max is None:
                rec.pop("max_accounts", None)  # onbeperkt → veld weglaten
            else:
                rec["max_accounts"] = int(default_max)

    # eps_daily_limit override (zoals je had)
    if "eps_daily_limit" in payload:
        v = payload.get("eps_daily_limit")
        if v in (None, ""):
            rec.pop("eps_daily_limit", None)   # override wissen → terug naar plan-default
        else:
            try:
                rec["eps_daily_limit"] = int(v)
            except Exception:
                rec["eps_daily_limit"] = v

    data[key] = rec
    _write_store(data)
    return rec


@router.delete("/license/{ident}")
def admin_delete(req: Request, ident: str):
    _require_admin(req)
    data = _read_store()
    try:
        key = _resolve_key_by_id_or_fp(data, ident)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    if key in data:
        del data[key]
        _write_store(data)
    # Ook uit SQLite verwijderen (cascadeert naar ebay_accounts via FK)
    try:
        from . import db as _db  # type: ignore
        _db.get_conn().execute("DELETE FROM licenses WHERE key_hash=?", (key,))
        _db.get_conn().commit()
    except Exception as _e:
        try:
            import logging; logging.getLogger("admin").exception("license SQLite delete failed for %s", key)
        except Exception:
            pass
    return {"ok": True}

# --------- NIEUW: detach user & set max (id of plain_key) ---------
def _detach_sqlite_ebay(key_hash: str, ebay_user: str | None = None, identity_id: str | None = None) -> None:
    """Mirror the JSON-store detach onto the SQLite ebay_accounts table.

    Without this, /license/attach_current still sees the eBay-user bound
    (find_license reads from SQLite via license_store) and refuses to
    rebind. JSON-only writes silently desync the two stores — that bug is
    exactly the same category as the stripe_webhook one we fixed earlier.
    Swallow errors so admin actions never break when the row is already
    gone (e.g. detach called twice).
    """
    import logging as _lg
    try:
        from . import db as _db
        row = _db.license_find(key_hash)
        if not row:
            return
        lic_id = row.get("id")
        if not lic_id:
            return
        if identity_id:
            # Match on identity_id directly; license_id+identity_id is the
            # safe scope so we never wipe another customer's row.
            conn = _db.get_conn()
            conn.execute(
                "DELETE FROM ebay_accounts WHERE license_id=? AND identity_id=?",
                (lic_id, identity_id),
            )
            conn.commit()
        if ebay_user:
            _db.ebay_account_detach(lic_id, ebay_user)
    except Exception as _e:
        _lg.warning("admin detach SQLite mirror failed key_hash=%s ebay_user=%r identity_id=%r: %s",
                    key_hash[:16] + "...", ebay_user, identity_id, _e)


@router.post("/license/detach_identity")
def admin_detach_identity(req: Request, payload: dict):
    _require_admin(req)
    ident = (payload.get("id") or "").strip()           # HMAC/licentie-id
    iid   = (payload.get("identity_id") or "").strip()  # eBay identityId
    if not ident or not iid:
        raise HTTPException(status_code=400, detail="id and identity_id required")

    data = _read_store()
    try:
        key = _resolve_key_by_id_or_fp(data, ident)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    rec = data.get(key) or {}
    # verwijder uit allowed_identity_ids (JSON-store)
    ids = rec.get("allowed_identity_ids") or []
    rec["allowed_identity_ids"] = [x for x in ids if x != iid]
    # verwijder eventuele labelmapping; onthoud de ebay_user voor SQLite-mirror
    m = rec.get("identity_usernames")
    ebay_user_for_mirror = None
    if isinstance(m, dict) and iid in m:
        ebay_user_for_mirror = (m.get(iid) or "").strip() or None
        del m[iid]
        rec["identity_usernames"] = m

    data[key] = rec
    _write_store(data)

    # Mirror naar SQLite zodat /license/attach_current de wijziging ziet.
    _detach_sqlite_ebay(key, ebay_user=ebay_user_for_mirror, identity_id=iid)

    return {
        "ok": True,
        "allowed_identity_ids": rec.get("allowed_identity_ids") or [],
        "identity_usernames": rec.get("identity_usernames") or {},
        "allowed_ebay_users": rec.get("allowed_ebay_users") or [],
        "max_accounts": rec.get("max_accounts") or 1,
    }

@router.post("/license/detach_ebay_user")
def admin_detach_ebay_user(req: Request, payload: dict):
    _require_admin(req)
    plain = (payload.get("plain_key") or "").strip()
    user  = (payload.get("ebay_user") or "").strip()
    ident = (payload.get("id") or "").strip()
    if not user:
        raise HTTPException(status_code=400, detail="ebay_user required")

    # 1) als store-helper bestaat en plain_key is meegegeven → gebruik helper.
    #    Daarna ook SQLite mirrorren: license_store.detach_ebay_user updatet
    #    de JSON-file, niet de SQLite tabel waar attach_current uit leest.
    if plain and _store_detach_ebay_user:
        rec = _store_detach_ebay_user(plain, user)  # type: ignore
        try:
            from .license_store import _hmac_key as _hk
            _detach_sqlite_ebay(_hk(plain), ebay_user=user)
        except Exception:
            pass
        return {
            "ok": True,
            "allowed_ebay_users": rec.get("allowed_ebay_users") or [],
            "max_accounts": rec.get("max_accounts") or 1
        }

    # 2) raw update via id/hmac
    data = _read_store()
    try:
        key = _resolve_key_by_id_or_fp(data, ident)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    rec = data.get(key) or {}
    users = rec.get("allowed_ebay_users") or []
    rec["allowed_ebay_users"] = [u for u in users if u != user]
    data[key] = rec
    _write_store(data)

    # Mirror naar SQLite — zonder dit blijft attach_current "slot bezet" zien.
    _detach_sqlite_ebay(key, ebay_user=user)

    return {
        "ok": True,
        "allowed_ebay_users": rec.get("allowed_ebay_users") or [],
        "max_accounts": rec.get("max_accounts") or 1
    }

@router.post("/license/set_max_accounts")
def admin_set_max_accounts(req: Request, payload: dict):
    _require_admin(req)
    plain = (payload.get("plain_key") or "").strip()
    ident = (payload.get("id") or "").strip()
    try:
        new_max = int(payload.get("max_accounts"))
    except Exception:
        raise HTTPException(status_code=400, detail="max_accounts must be an integer")
    if new_max < 1:
        raise HTTPException(status_code=400, detail="max_accounts must be >= 1")

    # 1) als store-helper bestaat en plain_key meegegeven → helper
    if plain and _store_set_max_accounts:
        rec = _store_set_max_accounts(plain, new_max)  # type: ignore
        return {
            "ok": True,
            "max_accounts": rec.get("max_accounts") or new_max,
            "allowed_ebay_users": rec.get("allowed_ebay_users") or []
        }

    # 2) raw update via id/hmac
    data = _read_store()
    try:
        key = _resolve_key_by_id_or_fp(data, ident)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    rec = data.get(key) or {}
    rec["max_accounts"] = int(new_max)
    data[key] = rec
    _write_store(data)

    return {
        "ok": True,
        "max_accounts": rec.get("max_accounts") or new_max,
        "allowed_ebay_users": rec.get("allowed_ebay_users") or []
    }

@router.post("/maintenance/cleanup_empty")
def admin_cleanup_empty(req: Request):
    _require_admin(req)
    data = _read_store()
    before = len(data)
    def is_empty(rec):
        if not isinstance(rec, dict) or not rec:
            return True
        # “leeg” = geen relevante waarden
        keys = ("plan","status","owner_email","owner_name","allowed_identity_ids","allowed_ebay_users","max_accounts")
        return not any(rec.get(k) for k in keys)
    for k in list(data.keys()):
        if is_empty(data[k]):
            del data[k]
    _write_store(data)
    return {"ok": True, "removed": before - len(data), "left": len(data)}

