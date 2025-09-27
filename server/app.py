from __future__ import annotations
import re
from datetime import datetime
from zoneinfo import ZoneInfo 
import base64
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import quote
import xml.etree.ElementTree as ET
from fastapi.staticfiles import StaticFiles
import requests
from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import Request, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import secrets
from .license_store import find_license, is_valid, upsert_license_plain, fingerprint, attach_ebay_user, attach_identity_id
from .trial_store import already_had_trial, record_trial
from dotenv import load_dotenv
from server.web_editor import router as web_router
from fastapi.responses import RedirectResponse
# bovenin bij de imports (robuste import voor zowel 'python -m server.app' als direct run)
from .admin_panel import router as admin_router
import xml.etree.ElementTree as ET


# --- Mount web editor router if present ---
web_editor_router = None
try:
    from server.web_editor import router as web_editor_router
except Exception:
    try:
        from web_editor import router as web_editor_router
    except Exception:
        web_editor_router = None

from fastapi import Request, Body
from datetime import datetime
import os, json


ROOT = Path(__file__).resolve().parent.parent  # .. (projectroot)
load_dotenv(ROOT / ".env", override=True)

APP = FastAPI(title="Joepienator server (OAuth + Taxonomy + Stores + Web + Publish)")
APP.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app = APP
try:
    if web_editor_router is not None:
        APP.include_router(web_editor_router)
except Exception:
    pass


# NA het aanmaken van APP/app en DATA:
app.include_router(web_router, prefix="/web")
# ... na app = FastAPI(...)
app.include_router(admin_router)


BASE = Path(__file__).parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
STATIC_DIR = BASE / "static"
STATIC_DIR.mkdir(exist_ok=True)
APP.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

def _prefer(*candidates: Path) -> Path:
    for p in candidates:
        if p.exists():
            return p
    return candidates[-1]

SECRETS_FILE = _prefer(DATA / "secrets.json", BASE / "secrets.json")
TOKENS_FILE  = _prefer(BASE / "tokens.json", DATA / "tokens.json")
STATE_FILE   = _prefer(DATA / "oauth_state.json", BASE / "oauth_state.json")

AUTH_HOST = {"PROD": "https://auth.ebay.com", "SANDBOX": "https://auth.sandbox.ebay.com"}
API_HOST  = {"PROD": "https://api.ebay.com", "SANDBOX": "https://api.sandbox.ebay.com"}
IDENTITY_HOST = API_HOST
TRADING_ENDPOINT = {"PROD": "https://api.ebay.com/ws/api.dll", "SANDBOX": "https://api.sandbox.ebay.com/ws/api.dll"}

MARKETPLACE_ID = {
    "UK": "EBAY_GB","NL": "EBAY_NL","US": "EBAY_US","DE": "EBAY_DE","FR":"EBAY_FR","IT":"EBAY_IT","ES":"EBAY_ES","IE":"EBAY_IE"
}
TRADING_SITE_ID = {"UK":"3","US":"0","DE":"77","NL":"146","FR":"71","IT":"101","ES":"186","IE":"205"}

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

# -- Site-resolver ------------------------------------------------------------
def _read_cfg() -> dict:
    # zelfde plek als waar web_policies z’n config pakt
    return _read_json(SECRETS_FILE.parent / "config.json")

def _effective_site(site_param: Optional[str]) -> str:
    # 1) expliciet meegegeven wint altijd
    if site_param and site_param.strip():
        return site_param.strip().upper()
    # 2) config.json site (wat jij na login bijwerkt)
    try:
        cfg = _read_cfg()
        s = (cfg.get("site") or "").strip().upper()
        if s:
            return s
    except Exception:
        pass
    # 3) account/identity (registrationMarketplaceId → site_code)
    try:
        _uid, _uname, _env, _reg, site_code = _identity_get_user_full()
        if site_code:
            return site_code.strip().upper()
    except Exception:
        pass
    # 4) allerlaatste fallback
    return "NL"


def _site_from_reg_marketplace(mid: str) -> str:
    if not mid: 
        return ""
    return _SITE_FROM_MARKETPLACE.get(mid.strip().upper(), "")
# ---------------- util store ----------------
def _read_json(p: Path) -> Dict[str, Any]:
    if not p.exists(): return {}
    try: return json.loads(p.read_text(encoding="utf-8"))
    except Exception: return {}

def _write_json(p: Path, data: Dict[str, Any]) -> None:
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _now() -> int: return int(time.time())

def _secrets(env: str) -> Dict[str, str]:
    s = _read_json(SECRETS_FILE)
    conf = s.get(env.upper()) or {}
    cid = conf.get("client_id"); csec = conf.get("client_secret"); runame = conf.get("ru_name")
    if not cid or not csec or not runame:
        raise HTTPException(400, f"Server not configured with eBay app credentials for {env}")
    return {"client_id": cid, "client_secret": csec, "ru_name": runame, "redirect_url": conf.get("redirect_url")}

def _tokens() -> Dict[str, Any]: return _read_json(TOKENS_FILE)
def _save_tokens(d: Dict[str, Any]) -> None: _write_json(TOKENS_FILE, d)
def _basic_header(client_id: str, client_secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

def get_app_token(env: str) -> str:
    env = env.upper(); sec = _secrets(env); tk = _tokens(); key = f"app_{env}"
    cached = tk.get(key) or {}
    if cached.get("access_token") and cached.get("expires_at", 0) > _now() + 60:
        return cached["access_token"]
    url = IDENTITY_HOST[env] + "/identity/v1/oauth2/token"
    hdr = {"Authorization": _basic_header(sec["client_id"], sec["client_secret"]), "Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "client_credentials", "scope": APP_SCOPE_STR}
    r = requests.post(url, headers=hdr, data=data, timeout=30)
    if r.status_code >= 400: raise HTTPException(r.status_code, f"App token failed: {r.text}")
    j = r.json()
    tk[key] = {"access_token": j["access_token"], "expires_at": _now() + int(j.get("expires_in", 7200))}
    _save_tokens(tk)
    return j["access_token"]

def _set_user_token(env: str, access_token: str, refresh_token: Optional[str], expires_in: int) -> None:
    tk = _tokens()
    tk["user"] = {"env": env.upper(), "access_token": access_token, "refresh_token": refresh_token, "expires_at": _now() + int(expires_in)}
    _save_tokens(tk)

def _get_user() -> Dict[str, Any]: return _tokens().get("user") or {}

def _need_user(env: Optional[str] = None) -> Dict[str, Any]:
    u = _get_user()
    if not u.get("access_token"): raise HTTPException(401, "Not linked")
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
    u = _get_user()
    if not u or u.get("expires_at", 0) > _now() + 60: return
    sec = _secrets(u["env"])
    url = IDENTITY_HOST[u["env"]] + "/identity/v1/oauth2/token"
    hdr = {"Authorization": _basic_header(sec["client_id"], sec["client_secret"]), "Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "refresh_token", "refresh_token": u.get("refresh_token") or ""}
    r = requests.post(url, headers=hdr, data=data, timeout=30)
    if r.status_code >= 400:
        tk = _tokens(); tk.pop("user", None); _save_tokens(tk); raise HTTPException(r.status_code, f"Refresh failed: {r.text}")
    j = r.json()
    _set_user_token(u["env"], j["access_token"], j.get("refresh_token", u.get("refresh_token")), int(j.get("expires_in", 3600)))

# ---------------- OAuth endpoints ----------------
@app.get("/oauth/start")
def oauth_start(env: str = "PROD"):
    env = env.upper(); sec = _secrets(env)
    import secrets as pysecrets
    state = pysecrets.token_urlsafe(24)
    st = _read_json(STATE_FILE); st[state] = {"env": env, "ts": _now()}; _write_json(STATE_FILE, st)
    auth_url = (
        f"{AUTH_HOST[env]}/oauth2/authorize"
        f"?client_id={quote(sec['client_id'])}"
        f"&response_type=code"
        f"&redirect_uri={quote(sec['ru_name'])}"
        f"&scope={quote(USER_SCOPE_STR)}"
        f"&state={quote(state)}"
    )
    return {"auth_url": auth_url, "url": auth_url}

@app.get("/oauth/status")
def oauth_status():
    u = _get_user()
    if not u:
        return {"env": None, "connected": False, "expires_at": None, "has_refresh": False}
    return {"env": u.get("env"), "connected": True, "expires_at": u.get("expires_at"), "has_refresh": bool(u.get("refresh_token"))}

@app.post("/oauth/refresh")
def oauth_force_refresh(): _refresh_user_if_needed(); return oauth_status()

def _pop_state(state: Optional[str]) -> Optional[str]:
    if not state: return None
    st = _read_json(STATE_FILE); rec = (st.pop(state, None) or {}); _write_json(STATE_FILE, st); return rec.get("env")

@app.get("/oauth/callback")
def oauth_callback(code: str = Query(...), state: Optional[str] = None, env: str = Query("PROD")):
    env = (_pop_state(state) or env or "PROD").upper()
    sec = _secrets(env)
    url = IDENTITY_HOST[env] + "/identity/v1/oauth2/token"
    hdr = {"Authorization": _basic_header(sec["client_id"], sec["client_secret"]), "Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": sec["ru_name"]}
    r = requests.post(url, headers=hdr, data=data, timeout=30)
    if r.status_code >= 400: raise HTTPException(r.status_code, f"OAuth error from eBay: {r.text}")
    j = r.json(); _set_user_token(env, j["access_token"], j.get("refresh_token"), int(j.get("expires_in", 3600)))
    return {"ok": True, "env": env}

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
def oauth_callback_trailing_slash(code: str = Query(...), state: Optional[str] = None, env: str = Query("PROD")):
    return oauth_callback(code=code, state=state, env=env)

@app.get("/oauth/ebay/callback")
def oauth_callback_ebay_alias(code: str = Query(...), state: Optional[str] = None, env: str = Query("PROD")):
    return oauth_callback(code=code, state=state, env=env)

@app.get("/oauth/ebay/callback/")
def oauth_callback_ebay_alias_slash(code: str = Query(...), state: Optional[str] = None, env: str = Query("PROD")):
    return oauth_callback(code=code, state=state, env=env)

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
def taxonomy_search(q: str = Query(..., min_length=1), site: Optional[str] = Query(None)):
    site = _effective_site(site)
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

@app.get("/taxonomy/aspects")
def taxonomy_aspects(site: str = Query("UK"), category_id: str = Query(...)):
    site = _effective_site(site)
    site = site.upper(); marketplace = MARKETPLACE_ID.get(site)
    if not marketplace: raise HTTPException(400, f"Unknown site {site}")
    env = (_get_user().get("env") or "PROD")
    r1 = _commerce_get(env, "/commerce/taxonomy/v1/get_default_category_tree_id", {"marketplace_id": marketplace})
    if r1.status_code >= 400: raise HTTPException(r1.status_code, r1.text)
    tree_id = (r1.json() or {}).get("categoryTreeId")
    if not tree_id: raise HTTPException(502, "No categoryTreeId")
    r2 = _commerce_get(env, f"/commerce/taxonomy/v1/category_tree/{tree_id}/get_item_aspects_for_category", {"category_id": category_id})
    if r2.status_code >= 400: raise HTTPException(r2.status_code, r2.text)
    return r2.json()

# ---------- Item Condition Policies (Commerce Taxonomy) ----------
@app.get("/taxonomy/conditions")
def taxonomy_conditions(site: str = Query("UK"), category_id: str = Query(...)):
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
    site = _effective_site(site)
    marketplace = MARKETPLACE_ID.get(site)
    if not marketplace:
        raise HTTPException(400, f"Unknown site {site}")

    env = (_get_user().get("env") or "PROD")

    # 1) tree id
    r1 = _commerce_get(env, "/commerce/taxonomy/v1/get_default_category_tree_id",
                       {"marketplace_id": marketplace})
    if r1.status_code >= 400:
        raise HTTPException(r1.status_code, r1.text)
    tree_id = (r1.json() or {}).get("categoryTreeId")
    if not tree_id:
        raise HTTPException(502, "No categoryTreeId")

    # 2) item condition policies
    path = f"/commerce/taxonomy/v1/category_tree/{tree_id}/get_item_condition_policies"
    r2 = _commerce_get(env, path, {"category_id": category_id})
    if r2.status_code >= 400:
        raise HTTPException(r2.status_code, r2.text)
    raw = r2.json() or {}

    # 3) normaliseren
    conds_out = []
    # De structuur verschilt per release; probeer robuust te lezen:
    raw_list = (raw.get("itemConditionPolicies")
                or raw.get("itemConditionPolicy")
                or raw.get("itemConditions")
                or [])

    for c in raw_list:
        # veelvoorkomend: {"conditionId":"1000","conditionName":"New", "usagePolicies":[{"conditionDescriptionAllowed":false}]}
        cid = str(c.get("conditionId") or c.get("id") or "").strip()
        name = (c.get("conditionName") or c.get("name") or "").strip()
        allow_desc = False
        # usage policies kan per condition of bovenliggend object staan
        ups = c.get("usagePolicies") or []
        for u in ups:
            if u.get("conditionDescriptionAllowed") is True:
                allow_desc = True
        # fallback: soms zit het onder "additionalInfo" of "allowedForConditionDescription"
        if not allow_desc and (c.get("conditionDescriptionAllowed") is True
                               or c.get("allowedForConditionDescription") is True):
            allow_desc = True

        if cid and name:
            conds_out.append({
                "id": cid,
                "name": name,
                "label": f"{cid}-{name}",
                "allow_description": bool(allow_desc)
            })

    # condition required op diverse plekken:
    required = bool(raw.get("itemConditionRequired")
                    or raw.get("conditionRequired")
                    or raw.get("isConditionRequired"))

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

def _trading_getstore(env: str, site: str) -> List[Dict[str, Any]]:
    _refresh_user_if_needed(); u = _need_user(env); site_id = TRADING_SITE_ID.get(site.upper(), "0")
    site = _effective_site(site)
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
        root = ET.fromstring(r.text)
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

@app.get("/stores/categories")
def stores_categories(site: str = Query("UK"), prefer: str = Query("rest"), debug: bool = Query(False)):
    site = _effective_site(site)
    env = (_get_user().get("env") or "PROD").upper(); prefer = (prefer or "rest").lower().strip()
    def _try_rest() -> List[Dict[str, Any]]:
        try: return _rest_store_categories(env) or []
        except HTTPException as e:
            if debug: raise
            return []
    def _try_trading(site_code: str) -> List[Dict[str, Any]]:
        try: return _trading_getstore(env, site_code) or []
        except HTTPException as e:
            if debug: raise
            return []
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

# ---------- Account/site ----------
@app.get("/account/site")
def account_site():
    _refresh_user_if_needed(); u = _need_user()
    env = u["env"]
    headers = {
        "X-EBAY-API-CALL-NAME": "GetUser",
        "X-EBAY-API-SITEID": "0",
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "Content-Type": "text/xml",
    }
    xml = """<?xml version="1.0" encoding="utf-8"?>
<GetUserRequest xmlns="urn:ebay:apis:eBLBaseComponents">
  <DetailLevel>ReturnAll</DetailLevel>
</GetUserRequest>""".strip()
    r = requests.post(TRADING_ENDPOINT[env], headers=headers, data=xml.encode("utf-8"), timeout=30)
    if r.status_code >= 400: raise HTTPException(r.status_code, r.text)
    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    try:
        root = ET.fromstring(r.text)
        reg_site = (root.findtext("e:User/e:Site", default="", namespaces=ns) or "").strip()
        currency = (root.findtext("e:User/e:SellerInfo/e:StoreCurrency", default="", namespaces=ns) or "").strip() \
                   or (root.findtext("e:User/e:SellerInfo/e:CheckoutMessage/e:CurrencyID", default="", namespaces=ns) or "").strip()
    except Exception:
        user_id = (root.findtext("e:User/e:UserID", default="", namespaces=ns) or "").strip()
        reg_site = ""
        currency = ""
    SITE_MAP = {
        "US": ("US","USD"), "UK": ("UK","GBP"), "Germany": ("DE","EUR"), "Netherlands": ("NL","EUR"),
        "France": ("FR","EUR"), "Italy": ("IT","EUR"), "Spain": ("ES","EUR"), "Ireland": ("IE","EUR"),
        "Poland": ("PL","PLN"), "Switzerland": ("CH","CHF"), "Austria": ("AT","EUR"), "Belgium": ("BE","EUR"),
        "Canada": ("CA","CAD"), "Australia": ("AU","AUD"),
    }
    code, cur_fallback = SITE_MAP.get(reg_site, ("NL","EUR"))
    if code == "NL": currency = "EUR"
    return {"site_label": reg_site or "Netherlands", "site_code": code, "currency": currency or cur_fallback, "username": user_id}

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



@APP.post("/license/attach_current")
def license_attach_current(request: Request):
    lk = (request.headers.get("X-License-Key") or request.cookies.get("license_key") or request.query_params.get("lk") or "").strip()
    if not lk:
        raise HTTPException(401, "Valid license required")
    rec = find_license(lk)
    if not (rec and is_valid(rec)):
        raise HTTPException(401, "Valid license required")

    uid, uname, env = _identity_get_user()
    if not (uid or uname):
        raise HTTPException(401, "Please log in to eBay before attaching.")

    # slots bepalen ZONDER dubbel te tellen:
    if "allowed_identity_ids" in rec:
        slots_used = len(rec.get("allowed_identity_ids") or [])
    else:
        slots_used = len(rec.get("allowed_ebay_users") or [])

    if slots_used >= int(rec.get("max_accounts") or 1):
        raise HTTPException(409, "Max accounts reached")

    # voorkeur: identity-id
    try:
        if uid:
            attach_identity_id(lk, uid, uname, max_accounts_default=int(rec.get("max_accounts") or 1))
        else:
            attach_ebay_user(lk, uname, max_accounts_default=int(rec.get("max_accounts") or 1))
    except Exception as e:
        raise HTTPException(500, f"Attach failed: {e}")

    return find_license(lk) or rec


@APP.get("/account/whoami")
def account_whoami():
    try:
        user_id, username, env, reg, site_code = _identity_get_user_full()
        if not (user_id or username):
            raise HTTPException(status_code=401, detail="Please login to your ebay account")
        return {
            "userId": user_id,
            "username": username,
            "env": env,
            "registrationMarketplaceId": reg,
            "site_code": site_code,   # ← hier pakken clients ‘m op
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Please login to your ebay account")


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
    xml.append("</UploadSiteHostedPicturesRequest>")
    xml_payload = "\n".join(xml)
    headers = {
        "X-EBAY-API-CALL-NAME": "UploadSiteHostedPictures",
        "X-EBAY-API-SITEID": site_id,
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-IAF-TOKEN": u["access_token"],
        "X-EBAY-API-REQUEST-ENCODING": "XML",
        "Accept": "text/xml",
    }
    files = {"XMLPayload": ("", xml_payload, "text/xml"), "file": (filename or "image.jpg", content, "application/octet-stream")}
    r = requests.post(TRADING_ENDPOINT[env], headers=headers, files=files, timeout=60)
    if r.status_code >= 400: raise HTTPException(r.status_code, f"EPS upload HTTP error: {r.text}")
    try:
        ns = {"e": "urn:ebay:apis:eBLBaseComponents"}; root = ET.fromstring(r.text)
        ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip().upper()
        if ack == "FAILURE":
            errs = []
            for e in root.findall("e:Errors", ns):
                code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
                msg  = (e.findtext("e:LongMessage", default="", namespaces=ns) or e.findtext("e:ShortMessage", default="", namespaces=ns) or "").strip()
                if msg or code: errs.append(f"{code}: {msg}".strip(": ").strip())
            raise HTTPException(502, "EPS failure: " + (" | ".join(errs) if errs else r.text[:400]))
        urls = []
        for uurl in root.findall(".//e:FullURL", ns):
            s = (uurl.text or "").strip()
            if s: urls.append(s)
        if not urls: raise HTTPException(502, f"EPS: no FullURL found. Raw: {r.text[:400]}")
        return urls
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"EPS parse error: {e}\n{r.text[:400]}")


from typing import Optional
from fastapi import Request, HTTPException, Query, UploadFile, File
import requests
import xml.etree.ElementTree as ET

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

    # EPS upload
    content = await file.read()
    urls = _eps_upload_trading(env, site, file.filename or "image.jpg", content, picture_name)
    return {"image_url": urls[0], "all_urls": urls, "site": site, "env": env}






@app.get("/")
def root(): return {"ok": True}

# ---------- /web/aspects (simplified for editor) ----------
@app.get("/web/aspects")
def web_aspects(site: Optional[str] = Query(None), category_id: str = Query(...)):
    site = _effective_site(site)
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
    raw = taxonomy_aspects(site=site, category_id=category_id) or {}
    # raw kan {"aspects":[...]} of direct [...] zijn
    src = raw.get("aspects") if isinstance(raw, dict) else raw
    site = _effective_site(site)
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
def web_policies(site: Optional[str] = Query(None), prefer_store: str = Query("rest")):
    site = _effective_site(site)
    env = (_get_user().get("env") or "PROD").upper()
    market = MARKETPLACE_ID.get(site)
    if not market:
        raise HTTPException(400, f"Unknown site {site}")

    out = {"payment": [], "return": [], "shipping": [], "store_categories": [], "defaults": {}}

    # ---- defaults uit config.json ----
    cfg = _read_json(SECRETS_FILE.parent / "config.json")
    # Deze keys mag je in je config opnemen (optioneel):
    out["defaults"] = {
        "shipping_profile": (cfg.get("shipping_profile") or "").strip() or None,
        "return_profile":   (cfg.get("return_profile") or "").strip() or None,
        "payment_profile":  (cfg.get("payment_profile") or "").strip() or None,
        "location":         (cfg.get("default_location") or cfg.get("location") or "").strip() or None,
        # optioneel kun je een default condition id meesturen:
        "condition_id":     (str(cfg.get("default_condition_id") or "").strip() or None)
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
# ---- Store categories (REST → fallback Trading) ----
    cats = []
    pref = (prefer_store or "rest").lower().strip()
    if pref == "trading":
        try:
            cats = _trading_getstore(env, site.upper())
        except HTTPException:
            cats = []
    else:
        try:
            cats = _rest_store_categories(env)
        except HTTPException:
            cats = []
        if not cats:
            try:
                cats = _trading_getstore(env, site.upper())
            except HTTPException:
                cats = []
    out["store_categories"] = cats
    return out


# ---------- Draft helper ----------
@app.get("/web/draft")
def web_draft(path: Optional[str] = None):
    p = Path(path) if path else (DATA / "draft.json")
    if p.exists():
        try:
            js = json.loads(p.read_text(encoding="utf-8"))
            return {"rows": js.get("rows") or [], "path": str(p)}
        except Exception as e:
            raise HTTPException(400, f"Draft parse error: {e}")
    return {"rows": [], "path": str(p)}

# --- veilige opslag helper ---
def _safe_json_save(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

# --- Fallback upload endpoint(s) ---
@app.post("/web/draft/upload")
async def web_draft_upload(request: Request, body: dict = Body(...)):
    """
    Ontvangt {"rows":[...], "site":"NL", "currency":"EUR"} en slaat op als:
    server/drafts/<license>/draft_YYYYmmdd_HHMMSS.json
    (license uit header X-License-Key of body.license_key; default: _anon)
    """
    lk = (request.headers.get("X-License-Key") or body.get("license_key") or "_anon").strip() or "_anon"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = (BASE / "drafts" / lk / f"draft_{ts}.json")
    try:
        _safe_json_save(out_path, body)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kon draft niet opslaan: {e}")
    return {"ok": True, "path": str(out_path)}

# optionele alias met trailing slash
@app.post("/web/draft/upload/")
async def web_draft_upload_alias(request: Request, body: dict = Body(...)):
    return await web_draft_upload(request, body)

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

def _identity_get_user_full() -> tuple[str, str, str, str, str]:
    """return (userId, username, env, registrationMarketplaceId, site_code)"""
    _refresh_user_if_needed()
    u = _need_user()
    env = (u.get("env") or "PROD").upper()
    base = "https://apiz.ebay.com" if env == "PROD" else "https://apiz.sandbox.ebay.com"
    user_id = username = reg = site_code = ""
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
            reg = (j.get("registrationMarketplaceId") or "").strip()
            site_code = _site_from_reg_marketplace(reg)
    except Exception:
        pass
    return user_id, username, env, reg, site_code

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



def _itemspecifics_xml(row: Dict[str, Any]) -> str:
    asp = row.get("aspects") or {}
    if not asp: return ""
    parts = ["<ItemSpecifics>"]
    for k, v in asp.items():
        # Excel/web-editor kan "C: Brand" sturen -> strip 'C:' prefix
        name = re.sub(r"^C:\s*", "", str(k)).strip()
        if not name: continue
        if v is None or v == "":
            continue
        vals = v if isinstance(v, list) else [v]
        parts.append("<NameValueList>")
        parts.append(f"<Name>{name}</Name>")
        for vv in vals:
            parts.append(f"<Value>{vv}</Value>")
        parts.append("</NameValueList>")
    parts.append("</ItemSpecifics>")
    return "\n".join(parts)

def _picture_details_xml(row: Dict[str, Any]) -> str:
    urls = []
    if isinstance(row.get("picture_urls"), list):
        urls += [u for u in row["picture_urls"] if u]
    if isinstance(row.get("pictures"), list):
        urls += [u for u in row["pictures"] if u]
    urls = list(dict.fromkeys(urls))  # dedupe
    if not urls:
        return ""
    parts = ["<PictureDetails>"] + [f"<PictureURL>{u}</PictureURL>" for u in urls] + ["</PictureDetails>"]
    return "\n".join(parts)

def _contact_location_xml(row: Dict[str, Any], site_code: str, currency: str) -> str:
    loc = (row.get("location") or "").strip() or "Netherlands"

    site2country = {
        "NL":"NL","UK":"GB","GB":"GB","US":"US","DE":"DE","FR":"FR","IT":"IT",
        "ES":"ES","IE":"IE","AT":"AT","CH":"CH","BE":"BE","AU":"AU","CA":"CA"
    }
    country = site2country.get((site_code or "").upper(), "NL")

    parts = [
        f"<Currency>{currency}</Currency>",
        f"<Country>{country}</Country>",
        f"<Location>{loc}</Location>",
        "<DispatchTimeMax>3</DispatchTimeMax>",
    ]
    # optioneel: postcode meesturen als beschikbaar
    pc = (row.get("postal_code") or row.get("postcode") or "").strip()
    if pc:
        parts.append(f"<PostalCode>{pc}</PostalCode>")
    return "\n".join(parts)


def _format_duration(row: Dict[str, Any]) -> str:
    fmt = (row.get("format") or "Fixed price").lower()
    dur = str(row.get("duration") or "").upper()
    if "AUCTION" in fmt.upper() or "VEILING" in fmt.upper():
        if dur in {"1","3","5","7","10"}:
            return "Days_"+dur
        return "Days_7"
    return "GTC"

def _best_tzinfo(preferred_tz: Optional[str]):
    """
    Bepaal een bruikbare tzinfo:
      - eerst proberen met IANA naam uit preferred_tz (bv. 'Europe/Amsterdam', 'America/New_York')
      - anders server-lokaal (astimezone)
      - anders UTC
    """
    if preferred_tz:
        try:
            return ZoneInfo(preferred_tz)
        except Exception:
            pass
    try:
        tz = datetime.now().astimezone().tzinfo
        if tz is not None:
            return tz
    except Exception:
        pass
    return ZoneInfo("UTC")


def _schedule_time_xml(val: Optional[str], tz_name: Optional[str] = None) -> str:
    """
    Input (voorbeelden):
      '2025-08-29T08:08'                      → naïef (lokale/meegegeven TZ)
      '2025-08-29T08:08:30'
      '2025-08-29T08:08Z'                     → al UTC
      '2025-08-29T08:08:00+02:00'             → met offset
    Output: <ScheduleTime>YYYY-MM-DDTHH:MM:SS.000Z</ScheduleTime>
    """
    if not val:
        return ""
    s = str(val).strip()
    try:
        if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$", s):
            s += ":00"                                # seconds aanvullen
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"                     # 'Z' → +00:00 voor fromisoformat

        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            tzinfo = _best_tzinfo(tz_name)            # bv. 'Europe/Amsterdam'
            dt = dt.replace(tzinfo=tzinfo)
        dt_utc = dt.astimezone(ZoneInfo("UTC"))
        return f"<ScheduleTime>{dt_utc.strftime('%Y-%m-%dT%H:%M:%S')}.000Z</ScheduleTime>"
    except Exception:
        return ""  # liever geen ScheduleTime dan een crash

def _picture_details_xml(row: Dict[str, Any]) -> str:
    urls = []
    if isinstance(row.get("picture_urls"), list):
        urls += [u for u in row["picture_urls"] if u]
    if isinstance(row.get("pictures"), list):
        urls += [u for u in row["pictures"] if u]
    # duplicates eruit
    urls = list(dict.fromkeys(urls))
    if not urls:
        return ""
    parts = ["<PictureDetails>"]
    for u in urls:
        parts.append(f"<PictureURL>{u}</PictureURL>")
    parts.append("</PictureDetails>")
    return "\n".join(parts)

from fastapi import HTTPException, Request

from fastapi import HTTPException, Request

def _build_item_xml(row: Dict[str, Any], site_code: str, currency: str, fixed: bool, tz_name: Optional[str] = None) -> str:
    title = (row.get("title") or "").strip()[:80]
    desc  = (row.get("description_html") or row.get("description") or "").strip()
    cid   = str(row.get("category_id") or "").strip()
    qty   = int(row.get("quantity") or 1)
    cond  = _condition_to_id(str(row.get("condition_id") or ""))
    start = _num(row.get("price"), None)
    binp  = _num(row.get("buy_it_now_price"), None)
    vatp  = _num(row.get("vat_percent"), None)

    listing_duration = _format_duration(row)
    parts = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f'<{"AddFixedPriceItemRequest" if fixed else "AddItemRequest"} xmlns="urn:ebay:apis:eBLBaseComponents">',
        '<ErrorLanguage>en_US</ErrorLanguage>',
        '<WarningLevel>High</WarningLevel>',
        '<Item>',
        f'<Title>{title}</Title>',
        f'<Description><![CDATA[{desc}]]></Description>',
        f'<PrimaryCategory><CategoryID>{cid}</CategoryID></PrimaryCategory>',
        f'<Quantity>{qty}</Quantity>',
        f'<ListingDuration>{listing_duration}</ListingDuration>',
        _schedule_time_xml(row.get("schedule_time"), tz_name),   # <-- zet geplande tijd in UTC
        _contact_location_xml(row, site_code, currency),
        _seller_profiles_xml(row),
        _storefront_xml(row),
        _itemspecifics_xml(row),
        _picture_details_xml(row),
    ]
    if cond:
        parts.append(f"<ConditionID>{cond}</ConditionID>")
    if row.get("condition_description"):
        cd = str(row.get("condition_description")).strip()
        if cd:
            parts.append(f"<ConditionDescription>{cd}</ConditionDescription>")
        # Optional advanced fields
    if row.get("postal_code"):
        parts.append(f"<PostalCode>{str(row.get('postal_code')).strip()}</PostalCode>")
    if row.get("private_listing"):
        parts.append("<PrivateListing>true</PrivateListing>")  # boolean veld
    if row.get("best_offer_enabled"):
        parts.append("<BestOfferDetails><BestOfferEnabled>true</BestOfferEnabled></BestOfferDetails>")
    if row.get("reserve_price") is not None:
        try:
            rp = float(row.get("reserve_price"))
            parts.append(f"<ReservePrice>{rp:.2f}</ReservePrice>")
        except Exception:
            pass

    if fixed:
        if start is not None:
            parts.append(f"<StartPrice>{start:.2f}</StartPrice>")
    else:
        if start is not None:
            parts.append(f"<StartPrice>{start:.2f}</StartPrice>")
        if binp is not None:
            parts.append(f"<BuyItNowPrice>{binp:.2f}</BuyItNowPrice>")

    if vatp is not None:
        parts.append(f"<VATDetails><VATPercent>{vatp:.2f}</VATPercent></VATDetails>")
    # condition description
    cond_desc = (row.get("condition_description") or "").strip()
    if cond_desc:
        parts.append(f"<ConditionDescription>{cond_desc}</ConditionDescription>")

    parts += ['</Item>', '</'+("AddFixedPriceItemRequest" if fixed else "AddItemRequest")+'>']
    return "\n".join([p for p in parts if p])

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
    ns = {"e": "urn:ebay:apis:eBLBaseComponents"}
    root = ET.fromstring(r.text)
    ack = (root.findtext("e:Ack", default="", namespaces=ns) or "").strip().upper()
    if ack == "FAILURE":
        errs = []
        for e in root.findall("e:Errors", ns):
            code = (e.findtext("e:ErrorCode", default="", namespaces=ns) or "").strip()
            msg  = (e.findtext("e:LongMessage", default="", namespaces=ns) or e.findtext("e:ShortMessage", default="", namespaces=ns) or "").strip()
            if msg or code: errs.append(f"{code}: {msg}".strip(": ").strip())
        raise HTTPException(502, "Trading failure: " + " | ".join(errs) if errs else r.text[:400])
    item_id = root.findtext(".//e:ItemID", default="", namespaces=ns) or ""
    return {"ok": True, "item_id": item_id, "raw": r.text[:2000]}

# ---------- Web publish + compat endpoints ----------

# ---------- /web/conditions (voor web editor) ----------
@app.get("/web/conditions")
def web_conditions(site: str = Query(None), category_id: str = Query(...)):
    site = _effective_site(site)
    
    try:
        data = taxonomy_conditions(site=site, category_id=category_id)
        return data
    except HTTPException as e:
        # Geen harde fout naar front-end; liever lege lijst
        return {"conditions": [], "condition_required": False, "error": str(e.detail)}

@app.post("/web/publish")
def web_publish(request: Request, payload: Dict[str, Any] = Body(...)):
    rec = ensure_valid_license_only(request)  # helper: valide licentie
    try:
        _refresh_user_if_needed()
        _ = _need_user()  # ingelogd?
    except Exception:
        raise HTTPException(status_code=401, detail="Please log in to eBay before publishing.")
    site = (payload.get("site") or "NL").upper()
    currency = payload.get("currency") or "EUR"
    rows = payload.get("rows") or []
    payload_tz = payload.get("timezone") or payload.get("tz")  # <-- nieuw
    if not isinstance(rows, list): raise HTTPException(400, "rows must be a list")

    env = (_get_user().get("env") or "PROD").upper()
    results = []
    for row in rows:
        fmt = (row.get("format") or "Fixed price").lower()
        fixed = ("fixed" in fmt)
        row_tz = row.get("timezone") or row.get("tz") or payload_tz  # <-- per-rij override
        xml = _build_item_xml(row, site, currency, fixed, tz_name=row_tz)  # <-- meegeven
        call = "AddFixedPriceItem" if fixed else "AddItem"
        try:
            res = _trading_call(env, site, call, xml)
            results.append({"title": row.get("title"), "ok": True, "item_id": res.get("item_id")})
        except HTTPException as e:
            results.append({"title": row.get("title"), "ok": False, "error": str(e.detail)})
        except Exception as e:
            results.append({"title": row.get("title"), "ok": False, "error": str(e)})
    return {"ok": True, "count": len(results), "results": results}

# Backwards compatibility: verify/submit (client verwacht deze paden)
@app.post("/listings/verify")
def listings_verify(body: Dict[str, Any] = Body(...)):
    return {"ok": True, "message": "verification skipped", "items": len(body.get("items") or [])}

@app.post("/listings/submit")
def listings_submit(body: Dict[str, Any] = Body(...)):
    site = (body.get("site") or "NL").upper()
    rows = body.get("items") or body.get("rows") or []
    currency = body.get("currency") or "EUR"
    tz = body.get("timezone") or body.get("tz")  # <-- nieuw
    # Hergebruik web_publish met tz
    return web_publish({"site": site, "currency": currency, "interval_minutes": 0, "rows": rows, "timezone": tz})


# --- Compatibility aliases for older clients ---

@app.get("/account/policies")
def account_policies(site: str = Query("UK"), prefer_store: str = Query("rest")):
    """
    Compat: levert {shipping:[], return:[], payment:[]}
    Hergebruikt de bestaande /web/policies logica.
    """
    data = web_policies(site=site, prefer_store=prefer_store)  # reuse existing builder
    return {
        "shipping": data.get("shipping", []),
        "return":   data.get("return", []),
        "payment":  data.get("payment", []),
    }

@app.get("/store/categories")
def store_categories(site: str = Query("UK"), prefer: str = Query("rest")):
    """
    Compat: enkelvoudig pad; geeft {categories:[...]} terug.
    Hergebruikt /web/policies zodat de shape altijd {id,name} is.
    """
    data = web_policies(site=site, prefer_store=prefer)
    return {"categories": data.get("store_categories", [])}



# ===== Licensing =====
class LicenseIn(BaseModel):
    license_key: str

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


@app.post("/license/validate", response_model=LicenseOut)
def license_validate(payload: LicenseIn):
    rec = find_license(payload.license_key or "")
    ok = bool(rec and is_valid(rec))
    return {"valid": ok,
            "plan": (rec or {}).get("plan"),
            "expires_at": (rec or {}).get("expires_at"),
            "owner_email": (rec or {}).get("owner_email"),
            "owner_name": (rec or {}).get("owner_name"),
            "max_accounts": int((rec or {}).get("max_accounts") or 1),
            "allowed_ebay_users": (rec or {}).get("allowed_ebay_users") or []}

@APP.post("/license/trial/start")
def license_trial_start(payload: TrialStartIn):
    if already_had_trial(payload.email, payload.device_id, payload.ebay_user):
        raise HTTPException(status_code=409, detail="Trial is al gebruikt voor dit account/apparaat.")
    key = secrets.token_urlsafe(24)
    exp = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    upsert_license_plain(key, plan="trial", expires_at_iso_utc=exp, status="active",
                         notes="trial", owner_email=(payload.email or None), owner_name=(payload.name or None),
                         max_accounts=1)
    record_trial(payload.email, payload.device_id, payload.ebay_user, fingerprint(key))

    # Probeer direct te binden (identity-id > username > payload.ebay_user)
    uid, uname, _env = _identity_get_user()
    try:
        if uid:
            attach_identity_id(key, uid, uname, max_accounts_default=1)
        elif uname:
            attach_ebay_user(key, uname, max_accounts_default=1)
        elif payload.ebay_user:
            attach_ebay_user(key, payload.ebay_user, max_accounts_default=1)
    except Exception:
        pass  # niet hard falen; gates handhaven later

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
    if path.startswith("/license") or path.startswith("/static") or path.startswith("/docs") or path == "/openapi.json":
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

        # (optioneel) eBay-enforcement hier
        request.state.license_key = lk
        request.state.license = rec
    # ... je bestaande licentiecheck hierboven ...


    return await call_next(request)

# ===== end Licensing =====
