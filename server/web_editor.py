# server/web_editor.py
from __future__ import annotations
from fastapi import APIRouter, HTTPException
import os, json, requests
import json
import glob
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


from fastapi import APIRouter, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

router = APIRouter()

# =============================================================================
# Client bridge (optioneel) + fallbacks
# =============================================================================
try:
    # Als je een eigen clientlib hebt kun je die gebruiken
    from api.server_client import ServerConfig, fetch_item_aspects, detect_account_site  # type: ignore
except Exception:
    @dataclass
    class ServerConfig:
        base_url: str
        license_key: Optional[str] = None
        timeout: int = 30

        @classmethod
        def from_config(cls, path: str = "config.json") -> "ServerConfig":
            base = os.environ.get("JOEP_SERVER", "http://127.0.0.1:8000")
            lk = os.environ.get("JOEP_LICENSE_KEY")
            timeout = int(os.environ.get("JOEP_TIMEOUT", "30"))
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f) or {}
                srv = cfg.get("server") or {}
                base = (srv.get("base_url") or base).strip()
                lk = (srv.get("license_key") or lk)
                timeout = int(srv.get("timeout_seconds") or timeout)
            except Exception:
                pass
            return cls(base.rstrip("/"), lk, timeout)

    def detect_account_site(_sc: Optional[ServerConfig] = None) -> Dict[str, Any]:
        # Lees top-level "site" en "currency" uit config.json
        cfg = _read_cfg()
        site = (cfg.get("site") or "NL").upper()
        _SITE_TO_CUR = {
            "NL":"EUR","BE":"EUR","DE":"EUR","FR":"EUR","IT":"EUR","ES":"EUR","IE":"EUR","AT":"EUR","PL":"PLN","CH":"CHF",
            "UK":"GBP","GB":"GBP",
            "US":"USD","CA":"CAD","AU":"AUD"
        }
        currency = (cfg.get("currency") or _SITE_TO_CUR.get(site, "USD")).upper()
        return {"site_code": site, "site_label": site, "currency": currency}


    def fetch_item_aspects(sc: ServerConfig, site: str, category_id: str | int) -> Dict[str, Any]:
        # Probeer backend (optioneel)
        try:
            import requests
            url = sc.base_url.rstrip("/") + "/taxonomy/aspects"
            r = requests.get(url, params={"site": site, "category_id": str(category_id)}, timeout=sc.timeout)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {"aspects": []}

# =============================================================================
# Helpers
# =============================================================================

def _read_cfg() -> dict:
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def _latest_draft_path_for(lk: Optional[str]) -> Optional[str]:
    """
    Als lk is meegegeven: zoek ALLEEN in server/drafts/<lk>/.
    Als lk niet is meegegeven: zoek in server/drafts/ (globaal).
    """
    base = os.path.join("server", "drafts")
    if lk:
        patt = os.path.join(base, lk, "*.json")
        cands = sorted(glob.glob(patt), key=os.path.getmtime, reverse=True)
        return cands[0] if cands else None
    patt = os.path.join(base, "*.json")
    cands = sorted(glob.glob(patt), key=os.path.getmtime, reverse=True)
    return cands[0] if cands else None

def _site_info() -> Dict[str, str]:
    # Lees ALLEEN top-level "site" en "currency" uit config.json
    cfg = _read_cfg()
    site = (cfg.get("site") or "NL").upper()

    # Val terug op currency mapping per site
    _SITE_TO_CUR = {
        "NL":"EUR","BE":"EUR","DE":"EUR","FR":"EUR","IT":"EUR","ES":"EUR","IE":"EUR","AT":"EUR","PL":"PLN","CH":"CHF",
        "UK":"GBP","GB":"GBP",
        "US":"USD","CA":"CAD","AU":"AUD"
    }
    currency = (cfg.get("currency") or _SITE_TO_CUR.get(site, "USD")).upper()

    # Label simpel houden (geen ‘action_settings’ meer)
    return {"site_code": site, "currency": currency, "site_label": site}


# Alias voor clients die /web/session/site verwachten
SITE_TO_MP = {
    "UK": "EBAY_GB", "NL": "EBAY_NL", "DE": "EBAY_DE", "US": "EBAY_US",
    "FR": "EBAY_FR", "IT": "EBAY_IT", "ES": "EBAY_ES", "AU": "EBAY_AU"
}

@router.get("/web/session/site")
def web_session_site():
    """
    Geeft de ingelogde site terug (uit detect_account_site/_site_info).
    """
    info = _site_info()  # gebruikt detect_account_site indien aanwezig, anders config fallback
    site = (info.get("site_code") or "NL").upper()
    mp = SITE_TO_MP.get(site, "EBAY_GB")
    return {"site": site, "marketplace_id": mp, "source": "account/site"}
# =============================================================================
# Routes: HTML Editor
# =============================================================================
@router.get("/web/oauth/start")
def web_oauth_start(request: Request):
    """
    Proxy naar bestaande /oauth/start die JSON teruggeeft; deze route doet een echte redirect.
    Handig als je /oauth/start nu JSON toont in de browser.
    """
    # Bepaal eigen base-url (http(s)://host:port/)
    base = str(request.base_url).rstrip("/")
    try:
        r = requests.get(base + "/oauth/start", timeout=10)  # jouw bestaande endpoint met JSON
        r.raise_for_status()
        js = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OAuth start failed: {e}")

    url = js.get("auth_url") or js.get("url")
    if not url:
        raise HTTPException(status_code=500, detail="OAuth start didn't return an auth_url")
    return RedirectResponse(url=url, status_code=307)

@router.get("/web/editor", response_class=HTMLResponse)
def web_editor() -> HTMLResponse:
    html = r"""
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<title>Joepienator – Web Editor</title>
<meta name="viewport" content="width=device-width, initial-scale=1">

<style>
  /* ====== Joepienator compact palette ====== */
  :root{
    --SURFACE:#0F5D70;
    --SURFACE_ELEV:#124F61;
    --SURFACE_HI:#196D84;
    --TEXT:#D0E0E6;
    --MUTED:#CFE6EC;
    --ACCENT:#FDB913;
    --BORDER:#144a59;
    --BG:#0F5D70;
    --CARD:#0f2e36;
    --WHITE:#ffffff;
  }

  *{box-sizing:border-box}
  html,body{height:100%}
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;color:var(--TEXT);background:var(--BG)}

  #bootBanner{position:fixed;top:8px;left:8px;z-index:9999;background:var(--SURFACE_HI);color:var(--TEXT);padding:4px 8px;border-radius:6px;font-size:12px}
  #errOverlay{position:fixed;left:0;right:0;bottom:0;background:#b00020;color:#fff;padding:8px 12px;z-index:10000;display:none;font:12px/1.4 system-ui,Segoe UI,Roboto,Arial}
  #errOverlay pre{white-space:pre-wrap;margin:0}

  header{background:var(--SURFACE);color:var(--TEXT);padding:10px 12px;display:flex;align-items:center;gap:12px;border-bottom:2px solid var(--SURFACE_HI)}
  header img{height:28px;display:block}
  header h1{font-size:18px;margin:0;font-weight:700;letter-spacing:.2px}
  .pill{background:var(--ACCENT);color:#1c1c1c;padding:2px 10px;border-radius:999px;font-size:12px}

  #controls{background:var(--SURFACE_ELEV);padding:10px 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-bottom:1px solid var(--BORDER)}
  label{font-size:13px}
  .muted{color:var(--MUTED)}

  button{padding:8px 12px;border-radius:10px;border:1px solid #00000022;cursor:pointer;background:var(--SURFACE_HI);color:var(--TEXT)}
  button.yellow{background:var(--ACCENT);color:#1c1c1c;border-color:#e1b100;font-weight:600}
  button.dark{background:#0e2b33;color:var(--TEXT);border-color:#00000055}
  button:disabled{opacity:.55;cursor:not-allowed}

  input[type=text],input[type=number],input[type=datetime-local],select{
    padding:6px 8px;border-radius:8px;border:1px solid var(--BORDER);
    background:#0f2e36;color:var(--TEXT)
  }

  #grid{height:calc(100vh - 260px);overflow:auto}
  table{border-collapse:collapse;min-width:2600px;width:100%;font-size:14px;color:var(--TEXT)}
  th,td{border:1px solid var(--BORDER);padding:4px 6px;vertical-align:top;background:#0f2e36;line-height:1.25}

  th{
    background:var(--SURFACE_HI);
    color:var(--TEXT);
    position:sticky;
    top:0;
    z-index:3;
    border:1px solid var(--BORDER);
  }
  th.sortable{cursor:pointer;user-select:none}

  /* compacte rijen */
  td textarea{min-height:64px}
  .num{text-align:right}

  /* sticky linker kolommen */
  .selbox{width:32px;text-align:center;background:#0f2e36; position:sticky; left:0; z-index:2}
  .thumb{width:112px;background:#0f2e36; position:sticky; left:32px; z-index:2}
  .thumb img{display:block; max-width:96px; max-height:72px; object-fit:cover; border-radius:6px}
  .thumb .noimg{font-size:12px;color:#9bbbc4}
  .thumb .count{font-size:11px;color:#9bbbc4;margin-top:2px}
  .thumb .mini{display:flex;gap:4px;margin-top:2px;flex-wrap:wrap}
  .thumb .mini img{width:22px;height:22px;object-fit:cover;border-radius:4px;border:1px solid var(--BORDER)}

  .wideTitle{min-width:520px}
  .colCat{min-width:240px}
  .colPrice{min-width:120px}
  .colSmall{min-width:98px}
  .colAspect{min-width:220px}
  .policy-select{ min-width:240px; }

  .toolbar-check{display:inline-flex;align-items:center;gap:8px;margin-left:8px}

  /* overlay dialog */
  .dlg{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;z-index:50}
  .dlg .card{background:#0f2e36;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,.35);max-width:900px;width:min(90vw,1100px);color:var(--TEXT)}
  .card header{background:var(--SURFACE_ELEV);color:var(--TEXT);border-bottom:1px solid var(--BORDER);padding:10px 14px;display:flex;justify-content:space-between;align-items:center}
  .card .body{padding:12px 14px;max-height:70vh;overflow:auto}
  .card footer{padding:10px 14px;border-top:1px solid var(--BORDER);display:flex;gap:8px;justify-content:flex-end}
  .card h3{margin:0;font-size:16px}

  .html-preview{border:1px solid var(--BORDER);border-radius:8px;padding:10px;min-height:140px;background:#0f2e36}

  .colgrid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:6px 14px}

  /* Publish overlay */
  #pubOverlay{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:9998}
  #pubOverlay .box{background:var(--SURFACE_ELEV);color:var(--TEXT);padding:18px 22px;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,.4);display:flex;align-items:center;gap:12px}
  .spinner{width:18px;height:18px;border:3px solid #ffffff55;border-top-color:var(--ACCENT);border-radius:50%;animation:spin 1s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div id="bootBanner">Booting…</div>
<div id="errOverlay"><pre id="errText"></pre></div>

<header>
  <img src="/static/logo.png" alt="logo" onerror="this.style.display='none'">
  <h1>Joepienator – Web Editor</h1>
  <span id="site" class="pill">…</span>
</header>

<div id="controls">
  <button id="editHtml">Edit HTML…</button>
  <button id="publishSel" class="dark">Publish selected</button>
  <button id="publishAll" class="yellow">Publish ALL</button>

  <label class="toolbar-check"><input id="checkAll" type="checkbox" checked> Check all</label>
  <label class="toolbar-check"><input id="toggleHidden" type="checkbox" checked> Show hidden fields</label>
  <button id="btnColumns">Columns</button>

  <!-- BULK editor -->
  <div style="flex-basis:100%"></div>
  <label for="bulkField">Bulk:</label>
  <select id="bulkField"></select>
  <span id="bulkValueWrap">
    <input id="bulkValue" type="text" placeholder="value…" style="min-width:220px">
  </span>
  <button id="bulkApply">Apply to selected</button>

  <span id="status" class="muted" style="margin-left:auto"></span>
</div>

<div id="grid"></div>

<!-- Image manager dialog -->
<div id="dlgImages" class="dlg" role="dialog" aria-modal="true">
  <div class="card">
    <header>
      <h3>Manage pictures</h3>
      <button id="imgClose">Close</button>
    </header>
    <div class="body">
      <div id="imgList" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px"></div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input id="imgUrl" type="text" placeholder="Paste image URL…" style="min-width:420px">
        <button id="btnAddUrl">Add URL</button>
        <input id="imgFile" type="file" accept="image/*">
        <button id="btnUpload">Upload to eBay (EPS)</button>
      </div>
    </div>
    <footer>
      <button id="imgDone" class="dark">Done</button>
    </footer>
  </div>
</div>

<!-- Columns dialog -->
<div id="dlgColumns" class="dlg" role="dialog" aria-modal="true">
  <div class="card">
    <header>
      <h3>Columns</h3>
      <button id="colClose">Close</button>
    </header>
    <div class="body">
      <div id="colGrid" class="colgrid"></div>
    </div>
    <footer>
      <button id="colReset">Reset</button>
      <button id="colApply" class="dark">Apply</button>
    </footer>
  </div>
</div>

<!-- Publish overlay -->
<div id="pubOverlay"><div class="box"><div class="spinner"></div><div id="pubText">Publishing…</div></div></div>

<script>
(function(){
  'use strict';

  function showErr(msg){
    try{
      const o = document.getElementById('errOverlay');
      const t = document.getElementById('errText');
      if(o && t){ t.textContent = String(msg||''); o.style.display='block'; }
    }catch(_){}
  }
  window.addEventListener('error', (e)=>showErr(e.message||e.error||'JS error'));
  window.addEventListener('unhandledrejection', (e)=>showErr(e.reason && (e.reason.message||e.reason) || 'Promise rejection'));
  console.log('[editor] script start');

  // ------------------- state -------------------
  const params = new URLSearchParams(location.search);
  const LK = (params.get('lk') || '').trim();

  const CONDITIONS_CACHE = {}; // key: SITE|categoryId -> [{id,name,label,allow_description}]
  let SITE = 'NL';
  let CURRENCY = 'EUR';
  let lastRows = [];
  let table, cols;
  let INTERVAL_MIN = 0;
  let GLOBAL_START_DT = null; // Date of null

  const sortState = { key: null, dir: 1 };
  const ASPECT_CACHE = {};
  const POL = { shipping: [], ret: [], pay: [], store_categories: [], defaults: {} };

  let SHOW_HIDDEN = true; // alle kolommen standaard zichtbaar
  let CURRENT_IMG_ROW = null;

  const PREF_KEY = 'joep.columns.v2';
  let hiddenColsPref = JSON.parse(localStorage.getItem(PREF_KEY) || '[]');

  // ------------------- utils -------------------
  function $(id){ return document.getElementById(id); }
  function status(msg){ const el=$('status'); if(el) el.textContent = msg || ''; }
  function jsonError(r){
    return r.text().then(tx => {
      try { const j = JSON.parse(tx); throw new Error(j.detail || tx); }
      catch(_) { throw new Error(tx); }
    });
  }
function getJSON(url){
  const headers = { 'Accept':'application/json' };
  if (LK) headers['X-License-Key'] = LK;
  return fetch(url, { headers, cache: 'no-store' })
    .then(r => r.ok ? r.json() : jsonError(r));
}
function postJSON(url, body){
  const headers = { 'Content-Type':'application/json', 'Accept':'application/json' };
  if (LK) headers['X-License-Key'] = LK;
  const payload = body || {};
  if (LK && payload.license_key == null) payload.license_key = LK; // body fallback
  return fetch(url, { method:'POST', headers, body: JSON.stringify(payload) })
    .then(r => r.ok ? r.json() : jsonError(r));
}

  function keyCache(cat){ return SITE + '|' + String(cat || ''); }
  function keyCond(cat){ return SITE + '|' + String(cat || ''); }

  function firstImage(row){
    const arr = Array.isArray(row.pictures) && row.pictures.length ? row.pictures
              : (Array.isArray(row.picture_urls) && row.picture_urls.length ? row.picture_urls : []);
    return arr.length ? arr[0] : null;
  }
  function allImages(row){
    let u = [];
    if (Array.isArray(row.picture_urls)) u = u.concat(row.picture_urls);
    if (Array.isArray(row.pictures)) u = u.concat(row.pictures);
    return Array.from(new Set(u.filter(Boolean)));
  }
  function openSellerHubAfterPublish(rows) {
  // Als alle rijen een schedule_time hebben → Scheduled; anders Active
  const allScheduled = rows.length > 0 && rows.every(r => !!r.schedule_time);

  // Site → TLD mapping
  const tldMap = {
    NL: "nl", BE: "be", DE: "de", FR: "fr", IT: "it", ES: "es",
    AT: "at", CH: "ch", IE: "ie",
    UK: "co.uk", GB: "co.uk",
    US: "com", CA: "ca", AU: "com.au"
  };
  const site = (typeof SITE === "string" ? SITE.toUpperCase() : "US");
  const tld  = tldMap[site] || "com";

  const page = allScheduled ? "scheduled" : "active";
  const url  = `https://www.ebay.${tld}/sh/lst/${page}`;
  window.open(url, "_blank", "noopener");
}

  // ====== time helpers (TZ-safe) ======
  function pad2(n){ return String(n).padStart(2,'0'); }

  // "YYYY-MM-DDTHH:MM[Z|±HH:MM]" -> lokale input "YYYY-MM-DDTHH:MM"
  function localInputFromAny(s){
    if (!s) return '';
    const z = String(s);
    if (/Z$/i.test(z) || /[+-]\d{2}:?\d{2}$/.test(z)){
      const d = new Date(z);
      if (isNaN(d)) return '';
      return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
    }
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(z)) return z;
    const m = z.match(/^(\d{2})-(\d{2})-(\d{4})[ T](\d{2}):(\d{2})$/);
    if (m) return `${m[3]}-${m[2]}-${m[1]}T${m[4]}:${m[5]}`;
    return '';
  }
  // "YYYY-MM-DDTHH:MM" (lokaal) -> Date in local TZ
  function parseLocalMinute(s){
    if(!s) return null;
    const m = String(s).trim().match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})$/);
    if(!m) return null;
    const y=+m[1], mo=(+m[2])-1, d=+m[3], h=+m[4], mi=+m[5];
    return new Date(y,mo,d,h,mi,0,0);
  }
  // Date -> "YYYY-MM-DDTHH:MM" (lokaal)
  function localMinuteStr(d){
    return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  // Date -> "YYYY-MM-DDTHH:MM:00Z" (UTC)
  function utcMinuteIso(d){
    return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth()+1)}-${pad2(d.getUTCDate())}T${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:00Z`;
  }
  // Normaliseer row.schedule_time naar UTC en bump zo nodig naar “nu+1m”
  function ensureUtcSchedule(row){
    const v = row.schedule_time;
    if (!v){ row.schedule_time_utc = null; return; }
    let d = null;
    if (/Z$/i.test(v) || /[+-]\d{2}:?\d{2}$/.test(v)) d = new Date(v);
    else d = parseLocalMinute(v);
    if (!d || isNaN(d.getTime())){ row.schedule_time_utc = null; return; }

    const now = new Date();
    if (d.getTime() < now.getTime() + 60*1000){
      d = new Date(now.getTime() + 60*1000);
      row._schedule_bumped = true;
    }
    row.schedule_time_utc = utcMinuteIso(d);
    row.schedule_time = row.schedule_time_utc; // keep single source for server
  }

  // ------------------- site/policies/aspects/conditions -------------------
  function loadSite(){
    return getJSON('/account/site')
      .then(js => {
        SITE = (js.site_code || 'NL').toUpperCase();
        CURRENCY = (js.currency || 'EUR').toUpperCase();
        const s = $('site');
        if (s) s.textContent = SITE + ' (' + CURRENCY + ')';
      })
      .catch(() => {});
  }

  function normalizeAspectPayload(js){
    const out = {};
    const arr = Array.isArray(js.aspects) ? js.aspects : [];
    for (const a0 of arr){
      const a = a0 || {};
      const nm = a.name || a.localizedAspectName || a.aspectName || '';
      if (!nm) continue;
      const vals = [];
      if (Array.isArray(a.values)){
        for (const v of a.values){
          if (typeof v === 'string') vals.push(v);
          else if (v && typeof v==='object'){
            const vv = v.value || v.localizedValue || v.valueName || '';
            if (vv) vals.push(vv);
          }
        }
      } else if (Array.isArray(a.aspectValues)){
        for (const w of a.aspectValues){
          const vv = (w||{}).value || (w||{}).localizedValue || (w||{}).valueName || '';
          if (vv) vals.push(vv);
        }
      }
      out[nm] = vals;
    }
    return out;
  }

  function loadPolicies(){
    return getJSON('/web/policies?site='+encodeURIComponent(SITE)+'&prefer_store=trading')
      .then(js => {
        POL.shipping = js.shipping || [];
        POL.ret = js.return || [];
        POL.pay = js.payment || [];
        POL.store_categories = js.store_categories || [];
      })
      .catch(() => {})
      .then(() => {
        return getJSON('/web/policy_defaults').then(j => {
          POL.defaults = j.defaults || {};
        }).catch(()=>{});
      });
  }

  function applyPolicyAndLocationDefaults(rows){
    const d = POL.defaults || {};
    for (const r of rows){
      if (!r.shipping_profile && d.shipping_profile) r.shipping_profile = d.shipping_profile;
      if (!r.return_profile   && d.return_profile)   r.return_profile   = d.return_profile;
      if (!r.payment_profile  && d.payment_profile)  r.payment_profile  = d.payment_profile;
      if (!r.location         && d.location)         r.location         = d.location;
      if (!r.condition_id     && d.condition_id)     r.condition_id     = d.condition_id;
    }
  }

  function ensureAspectsFor(categoryId){
    if (!categoryId) return Promise.resolve();
    const k = keyCache(categoryId);
    if (ASPECT_CACHE[k]) return Promise.resolve();
    const url = '/web/aspects?site='+encodeURIComponent(SITE)+'&category_id='+encodeURIComponent(categoryId);
    return getJSON(url)
      .then(js => { ASPECT_CACHE[k] = normalizeAspectPayload(js); })
      .catch(() => { ASPECT_CACHE[k] = {}; });
  }

  function getAspectList(cat, taxonomyName){
    const m = ASPECT_CACHE[keyCache(cat)] || {};
    return m[taxonomyName] || [];
  }
  // === add below getConditionList ===

// Normalizes any incoming condition value to a valid UI label from `allowedList`.
// Accepts label ("1000-New"), id ("1000"), name ("New"), or strings starting with the id ("1000 - New").
function normalizeConditionValue(val, allowedList){
  if (!val) return '';
  const list = Array.isArray(allowedList) ? allowedList : [];
  const s = String(val).trim();
  if (!s) return '';

  // 1) exact label match
  if (list.some(o => o.label === s)) return s;

  // 2) exact id match
  let hit = list.find(o => String(o.id) === s);
  if (hit) return hit.label;

  // 3) exact name match (fallback when API provides .name)
  hit = list.find(o => (o.name || '').toLowerCase() === s.toLowerCase());
  if (hit) return hit.label;

  // 4) value starts with numeric id: "1000-New", "1000 : New"
  const m = s.match(/^(\d+)/);
  if (m){
    hit = list.find(o => String(o.id) === m[1]);
    if (hit) return hit.label;
  }
  // No valid mapping -> empty (UI will pick first allowed later)
  return '';
}

// Some eBay conditions do NOT allow a free-form description field.
// We check by condition id; allowedList items may include { id, label, allow_description }.
function conditionAllowsDescription(label, allowedList){
  const list = Array.isArray(allowedList) ? allowedList : [];
  const id = (String(label || '').match(/^(\d+)/) || [,''])[1];
  const e = list.find(o => String(o.id) === id) || list.find(o => o.label === label);
  return !!(e && e.allow_description);
}

  function ensureConditionsFor(categoryId){
    if (!categoryId) return Promise.resolve();
    const k = keyCond(categoryId);
    if (CONDITIONS_CACHE[k]) return Promise.resolve();
    const url = '/web/conditions?site='+encodeURIComponent(SITE)+'&category_id='+encodeURIComponent(categoryId);
    return getJSON(url)
      .then(js => { CONDITIONS_CACHE[k] = Array.isArray(js.conditions) ? js.conditions : []; })
      .catch(() => { CONDITIONS_CACHE[k] = []; });
  }

  function ensureAspectsAndConditionsMany(cats){
    const uniq = {}; (cats||[]).forEach(c => { if (c) uniq[c]=1; });
    const list = Object.keys(uniq);
    return Promise.all(list.map(cid => Promise.all([ ensureAspectsFor(cid), ensureConditionsFor(cid) ])));
  }

  function getConditionList(cat){
    return CONDITIONS_CACHE[keyCond(cat)] || [];
  }

  function getDurations(fmt){
    const f = String(fmt||'').toLowerCase();
    return (f.includes('auction')) ? ['1','3','5','7','10'] : ['GTC'];
  }

  // ------------------- columns model -------------------
  const ADVANCED_KEYS = [
    'shipping_profile','return_profile','payment_profile',
    'shop_id','shop_id_2',
    'location','postal_code',
    'format','duration','buy_it_now_price','vat_percent','condition_id','condition_description',
    'best_offer_enabled','private_listing','reserve_price',
    'schedule_time','description_html'
  ];

  function baseColumns(rows){
    const seen = {};
    for (const r of rows){
      const a = r.aspects || {};
      for (const k in a){ if (k.indexOf('C:') === 0) seen[k] = 1; }
    }
    const aspectKeys = Object.keys(seen).sort();

    const cols = [
      {title:'', key:'_sel', type:'sel', cls:'selbox', sticky:true},
      {title:'Image', key:'_thumb', type:'thumb', cls:'thumb', sticky:true},
      {title:'Title', key:'title', type:'text', cls:'wideTitle', sortable:true},
      {title:'Category ID', key:'category_id', type:'text', cls:'colCat', sortable:true},
      {title:'Qty', key:'quantity', type:'int', cls:'colSmall', sortable:true},
      {title:'Start price', key:'price', type:'num', cls:'colPrice', sortable:true},
    ];
    for (const k of aspectKeys){
      cols.push({title:k, key:'aspects.'+k, type:'aspect', cls:'colAspect', sortable:true});
    }
    return cols;
  }

  function extraColumns(){
    return [
      {title:'Shipping policy', key:'shipping_profile', type:'policy', policy:'shipping', cls:'colCat'},
      {title:'Return policy',   key:'return_profile',   type:'policy', policy:'return',   cls:'colCat'},
      {title:'Payment policy',  key:'payment_profile',  type:'policy', policy:'payment',  cls:'colCat'},
      {title:'Shop ID',         key:'shop_id',          type:'storeid', cls:'colCat'},
      {title:'Shop ID 2',       key:'shop_id_2',        type:'storeid2', cls:'colCat'},

      {title:'Location',        key:'location',         type:'text',    cls:'colCat'},
      {title:'Postal code',     key:'postal_code',      type:'text',    cls:'colSmall'},

      {title:'Format',          key:'format',           type:'select',  values:['Auction','Fixed price'], cls:'colSmall'},
      {title:'Duration',        key:'duration',         type:'select-dyn', cls:'colSmall'},

      {title:'BIN price',       key:'buy_it_now_price', type:'num',     cls:'colPrice'},
      {title:'Reserve price',   key:'reserve_price',    type:'num',     cls:'colPrice'},
      {title:'VAT %',           key:'vat_percent',      type:'num',     cls:'colSmall'},

      {title:'Condition',       key:'condition_id',     type:'select',  cls:'colSmall'},
      {title:'Condition description', key:'condition_description', type:'conddesc', cls:'colCat', hidden:true},

      {title:'Best offer enabled', key:'best_offer_enabled', type:'bool', cls:'colSmall'},
      {title:'Private listing',    key:'private_listing',  type:'bool', cls:'colSmall'},

      {title:'Schedule',        key:'schedule_time',    type:'datetime', cls:'colCat'},
      {title:'Description (HTML)', key:'description_html', type:'textarea', cls:'colCat'}
    ];
  }

  function buildColumns(rows){
    const base = baseColumns(rows);
    const adv = extraColumns();
    const merged = SHOW_HIDDEN ? base.concat(adv) : base;
    return merged.filter(c =>
      c.key === '_sel' || c.key === '_thumb' || hiddenColsPref.indexOf(c.key) === -1
    );
  }

  // ------------------- render -------------------
  function buildHeader(theTable, colsArr){
    const tr = document.createElement('tr');
    for (let c of colsArr){
      const th = document.createElement('th');
      th.textContent = c.title;
      if (c.cls) th.classList.add(c.cls);
      if (c.sortable){
        th.classList.add('sortable');
        th.addEventListener('click', () => sortBy(c.key));
      }
      if (c.sticky){
        if (c.cls === 'selbox'){ th.style.left='0'; th.style.position='sticky'; th.style.zIndex='4'; }
        if (c.cls === 'thumb'){ th.style.left='32px'; th.style.position='sticky'; th.style.zIndex='4'; }
      }
      tr.appendChild(th);
    }
    theTable.tHead.appendChild(tr);
  }

  function renderBody(){
    const tbody = table.tBodies[0];
    tbody.innerHTML = '';
    for (let i=0;i<lastRows.length;i++){
      const r = lastRows[i];
      const tr = document.createElement('tr');

      for (let ci=0; ci<cols.length; ci++){
        const c = cols[ci];
        const td = document.createElement('td');
        if (c.cls) td.classList.add(c.cls);
        if (c.sticky){
          if (c.cls === 'selbox'){ td.style.left='0'; td.style.position='sticky'; td.style.zIndex='3'; }
          if (c.cls === 'thumb'){ td.style.left='32px'; td.style.position='sticky'; td.style.zIndex='3'; }
        }

        (function(col, row, cell, rowTr){
          function put(el){ cell.innerHTML=''; cell.appendChild(el); }

          if (col.type === 'sel'){
            const cb = document.createElement('input'); cb.type = 'checkbox'; cb.className = 'rowSel'; cb.checked = true;
            put(cb); return;
          }

          if (col.type === 'thumb'){
            const u0 = firstImage(row);
            const wrap = document.createElement('div');
            if (u0){
              const a = document.createElement('a'); a.href = u0; a.target = '_blank'; a.rel = 'noreferrer';
              const img = document.createElement('img'); img.src = u0; img.alt = 'thumb';
              a.appendChild(img); wrap.appendChild(a);
            }else{
              const d = document.createElement('div'); d.className='noimg'; d.textContent='(no image)'; wrap.appendChild(d);
            }
            const all = allImages(row);
            if (all.length){
              const mini = document.createElement('div'); mini.className='mini';
              for (const u of all.slice(0,4)){
                const im = document.createElement('img'); im.src = u; mini.appendChild(im);
              }
              wrap.appendChild(mini);
              const cnt = document.createElement('div'); cnt.className='count'; cnt.textContent = all.length + ' img';
              wrap.appendChild(cnt);
            }
            const btn = document.createElement('button'); btn.textContent='Manage';
            btn.addEventListener('click', () => openImageDlg(row));
            wrap.appendChild(btn);
            put(wrap); return;
          }

          if (col.type === 'textarea'){
            const box = document.createElement('div');
            const ta = document.createElement('textarea');
            ta.style.width = '100%';
            ta.value = row[col.key] || '';
            ta.addEventListener('input', () => { row[col.key] = ta.value; });

            const tools = document.createElement('div');
            tools.style.display='flex'; tools.style.gap='8px'; tools.style.marginTop='4px';
            const btnPrev = document.createElement('button'); btnPrev.textContent='Preview';
            btnPrev.addEventListener('click', () => openHtmlPreview(row, col.key));
            const btnExpand = document.createElement('button'); btnExpand.textContent='Expand';
            const btnCollapse = document.createElement('button'); btnCollapse.textContent='Collapse';
            btnExpand.addEventListener('click', () => { ta.style.minHeight='220px'; });
            btnCollapse.addEventListener('click', () => { ta.style.minHeight='64px'; });
            tools.appendChild(btnPrev); tools.appendChild(btnExpand); tools.appendChild(btnCollapse);

            box.appendChild(ta); box.appendChild(tools);
            put(box); return;
          }

          if (col.type === 'bool'){
            const cb = document.createElement('input'); cb.type='checkbox';
            cb.checked = !!row[col.key];
            cb.addEventListener('change', () => { row[col.key] = cb.checked; });
            put(cb); return;
          }

          if (col.type === 'num'){
            const np = document.createElement('input'); np.type='number'; np.step='0.01'; np.className='num';
            np.value = (row[col.key] != null ? row[col.key] : '');
            np.addEventListener('input', () => { row[col.key] = (np.value === '' ? null : parseFloat(np.value)); });
            put(np); return;
          }

          if (col.type === 'int'){
            const ip = document.createElement('input'); ip.type='number'; ip.step='1'; ip.min='0'; ip.className='intonly num';
            ip.value = (row[col.key] != null ? row[col.key] : '');
            ip.addEventListener('input', () => {
              let v = parseInt(ip.value || '0', 10); if (isNaN(v)) v = 0; ip.value = String(v); row[col.key] = v;
            });
            put(ip); return;
          }

          if (col.type === 'datetime'){
            const dt = document.createElement('input');
            dt.type = 'datetime-local';
            (function(){
              const v = row[col.key] || '';
              const inp = localInputFromAny(v);
              if (inp) dt.value = inp;
            })();
            dt.addEventListener('input', () => { if (dt.value) row[col.key] = dt.value; });
            put(dt); return;
          }

          if (col.type === 'select'){
            const sel = document.createElement('select');

            if (col.key === 'condition_id'){
              const allowed = getConditionList(row.category_id);
              if (allowed.length){
                for (const cnd of allowed){ sel.appendChild(new Option(cnd.label, cnd.label)); }
                const norm = normalizeConditionValue(row[col.key] || row['condition'], allowed) || allowed[0].label;
                row[col.key] = norm;
                sel.value = norm;
                sel.addEventListener('change', () => {
                  row[col.key] = sel.value;
                  const can = conditionAllowsDescription(sel.value, allowed);
                  const input = rowTr.querySelector('textarea[data-col="condition_description"],input[data-col="condition_description"]');
                  if (input){ input.disabled = !can; if (!can) input.value=''; }
                });
              } else {
                const vals = [
                  '1000-New','1500-New other (see details)','1750-New with defects','2000-Manufacturer refurbished',
                  '2500-Seller refurbished','2750-Like New','3000-Used','4000-Very Good',
                  '5000-Good','6000-Acceptable','7000-For parts or not working'
                ];
                for (const v of vals) sel.appendChild(new Option(v, v));
                sel.value = row[col.key] || '';
                sel.addEventListener('change', () => { row[col.key] = sel.value; });
              }
            }
            else if (col.key === 'format'){
              ['Auction','Fixed price'].forEach(v => sel.appendChild(new Option(v, v)));
              sel.value = row[col.key] || 'Fixed price';
              sel.addEventListener('change', () => {
                row[col.key] = sel.value;
                const dsel = rowTr.querySelector('select[data-col="duration"]');
                if (dsel){
                  const vals = getDurations(row.format);
                  dsel.innerHTML = ''; vals.forEach(v => dsel.appendChild(new Option(v,v)));
                  if (vals.indexOf(String(row.duration)) === -1){ row.duration = vals[0]; dsel.value = row.duration; }
                }
              });
            }
            else {
              (col.values || []).forEach(v => sel.appendChild(new Option(v,v)));
              sel.value = row[col.key] || '';
              sel.addEventListener('change', () => { row[col.key] = sel.value; });
            }
            put(sel); return;
          }

          if (col.type === 'select-dyn'){
            const d = document.createElement('select'); d.setAttribute('data-col','duration');
            const vals = getDurations(row.format || 'Fixed price');
            for (let vv of vals) d.appendChild(new Option(vv, vv));
            d.value = (row.duration && vals.indexOf(String(row.duration)) !== -1) ? String(row.duration) : vals[0];
            row.duration = d.value;
            d.addEventListener('change', () => { row.duration = d.value; });
            put(d); return;
          }

          if (col.type === 'policy'){
            const kind = col.policy;
            const list = (kind==='shipping') ? POL.shipping : ((kind==='return') ? POL.ret : POL.pay);
            const ps = document.createElement('select');
            ps.className = 'policy-select';
            ps.appendChild(new Option('',''));
            for (const it of list){ ps.appendChild(new Option(it.name+' ['+it.id+']', it.id)); }
            const rawVal = row[col.key];
            if (rawVal != null){
              const v = String(rawVal).trim();
              const byId = list.find(x => String(x.id) === v);
              const byName = list.find(x => (x.name||'').toLowerCase() === v.toLowerCase());
              if (byId) ps.value = byId.id;
              else if (byName) ps.value = byName.id;
            }
            ps.addEventListener('change', () => { row[col.key] = ps.value || null; });
            put(ps); return;
          }

          if (col.type === 'storeid'){
            const sc = document.createElement('select');
            sc.className = 'policy-select';
            sc.appendChild(new Option('',''));
            const cats = POL.store_categories || [];
            for (const it of cats){ sc.appendChild(new Option(it.name+' ['+it.id+']', it.id)); }
            const rawVal = row.shop_id || row.store_category || row.store_category_id;
            if (rawVal != null){
              const v = String(rawVal).trim();
              const byId = cats.find(x => String(x.id) === v);
              const byName = cats.find(x => (x.name||'').toLowerCase() === v.toLowerCase());
              if (byId) sc.value = byId.id;
              else if (byName) sc.value = byName.id;
            }
            sc.addEventListener('change', () => {
              row.shop_id = sc.value || null;
              row.store_category = sc.value || null;
            });
            put(sc); return;
          }

          if (col.type === 'storeid2'){
            const sc2 = document.createElement('select'); sc2.className='policy-select'; sc2.appendChild(new Option('',''));
            for (const it of (POL.store_categories || [])){ sc2.appendChild(new Option(it.name+' ['+it.id+']', it.id)); }
            sc2.value = row.shop_id_2 || row.store_category_2 || row.store_category2 || '';
            sc2.addEventListener('change', () => {
              row.shop_id_2 = sc2.value || null;
              row.store_category_2 = sc2.value || null;
              row.store_category2 = sc2.value || null;
            });
            put(sc2); return;
          }

          if (col.type === 'aspect'){
            const colKeyName = col.key.slice(8);
            const aspLookupName = (col.title || colKeyName).replace(/^C:\s*/, '').trim();
            const list = getAspectList(row.category_id, aspLookupName);
            if (list.length){
              const as = document.createElement('select'); as.appendChild(new Option('',''));
              for (const v of list) as.appendChild(new Option(v, v));
              as.value = (row.aspects || {})[colKeyName] || '';
              as.addEventListener('change', () => {
                row.aspects = row.aspects || {};
                row.aspects[colKeyName] = as.value || null;
              });
              put(as);
            } else {
              const tx = document.createElement('input'); tx.type='text';
              tx.value = (row.aspects || {})[colKeyName] || '';
              tx.placeholder = '(geen lijst; typ vrije waarde)';
              tx.addEventListener('input', () => {
                row.aspects = row.aspects || {};
                row.aspects[colKeyName] = tx.value;
              });
              put(tx);
            }
            return;
          }

          if (col.type === 'conddesc'){
            const ta = document.createElement('textarea');
            ta.setAttribute('data-col', 'condition_description');
            ta.value = row[col.key] || '';
            const allowed = getConditionList(row.category_id);
            if (allowed.length){
              const can = conditionAllowsDescription(row['condition_id'] || '', allowed);
              ta.disabled = !can;
            }
            ta.addEventListener('input', () => { row[col.key] = ta.value; });
            put(ta); return;
          }

          const ipt = document.createElement('input'); ipt.type='text';
          const isAspect = col.key.indexOf('aspects.') === 0;
          ipt.value = (isAspect ? ((row.aspects || {})[col.key.slice(8)] || '') : (row[col.key] || ''));
          ipt.addEventListener('input', () => {
            if (isAspect){
              row.aspects = row.aspects || {};
              row.aspects[col.key.slice(8)] = ipt.value;
            } else {
              row[col.key] = ipt.value;
              if (col.key === 'category_id'){
                ensureAspectsFor(ipt.value).then(() => renderTable(lastRows));
              }
            }
          });
          put(ipt);
        })(c, r, td, tr);

        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }

    const ca = $('checkAll');
    if (ca && ca.checked){
      document.querySelectorAll('input.rowSel').forEach(cb => cb.checked = true);
    }
  }

  function renderTable(rows){
    const grid = $('grid');
    if (!grid){ console.warn('#grid ontbreekt'); return; }
    grid.innerHTML = '';

    if (!rows || !rows.length){
      grid.innerHTML = '<div style="padding:12px;color:#9bbbc4;">Geen rijen om te tonen.</div>';
      return;
    }
    cols = buildColumns(rows);
    table = document.createElement('table');
    const thead = document.createElement('thead'); const tbody = document.createElement('tbody');
    table.appendChild(thead); table.appendChild(tbody);
    buildHeader(table, cols);
    grid.appendChild(table);
    renderBody();
    buildColumnsDialog();
    buildBulkFieldList();
  }

  // ------------------- sort/select -------------------
  function sortBy(key){
    let dir = 1;
    if (sortState.key === key) dir = -sortState.dir;
    sortState.key = key; sortState.dir = dir;

    lastRows.sort((a,b) => {
      function val(x){
        if (key.indexOf('aspects.') === 0){
          const nm = key.slice(8); return (x.aspects || {})[nm] || '';
        }
        return x[key] || '';
      }
      const va = val(a), vb = val(b);
      const na = parseFloat(va), nb = parseFloat(vb);
      if (!isNaN(na) && !isNaN(nb)) return dir * (na - nb);
      return dir * String(va).localeCompare(String(vb));
    });
    renderBody();
  }

  function selectedRows(){
    const out = [];
    if (!table || !table.tBodies[0]) return out;
    const trs = table.tBodies[0].rows;
    for (let i=0;i<trs.length;i++){
      const cb = trs[i].querySelector('input.rowSel');
      if (cb && cb.checked) out.push(lastRows[i]);
    }
    return out;
  }

  // ------------------- columns dialog -------------------
  function allColumnDefs(){
    const base = baseColumns(lastRows);
    const adv = extraColumns();
    return base.concat(adv);
  }

  function buildColumnsDialog(){
    const grid = $('colGrid'); grid.innerHTML = '';
    const defs = allColumnDefs().filter(c => c.key !== '_sel' && c.key !== '_thumb');
    defs.forEach(col => {
      const id = 'col_' + col.key.replace(/[^a-z0-9_]/ig,'_');
      const wrap = document.createElement('label');
      wrap.style.display='flex'; wrap.style.alignItems='center'; wrap.style.gap='8px';
      const cb = document.createElement('input'); cb.type='checkbox';
      cb.id = id;
      cb.checked = hiddenColsPref.indexOf(col.key) === -1;
      cb.dataset.key = col.key;
      wrap.appendChild(cb);
      wrap.appendChild(document.createTextNode(col.title));
      grid.appendChild(wrap);
    });
  }

  function openColumns(){ $('dlgColumns').style.display='flex'; }
  function closeColumns(){ $('dlgColumns').style.display='none'; }

  $('btnColumns').addEventListener('click', openColumns);
  $('colClose').addEventListener('click', closeColumns);
  $('colReset').addEventListener('click', () => {
    hiddenColsPref = [];
    localStorage.setItem(PREF_KEY, JSON.stringify(hiddenColsPref));
    buildColumnsDialog(); renderTable(lastRows);
  });
  $('colApply').addEventListener('click', () => {
    const checks = Array.from(document.querySelectorAll('#colGrid input[type=checkbox]'));
    const hidden = [];
    for (const c of checks){
      if (!c.checked) hidden.push(c.dataset.key);
    }
    hiddenColsPref = hidden;
    localStorage.setItem(PREF_KEY, JSON.stringify(hiddenColsPref));
    closeColumns(); renderTable(lastRows);
  });

  // ------------------- BULK editor -------------------
  function buildBulkFieldList(){
    const sel = $('bulkField'); if (!sel) return;
    sel.innerHTML = '';

    const base = [
      ['title','Title'], ['category_id','Category ID'], ['quantity','Qty'], ['price','Start price'],
      ['buy_it_now_price','BIN price'], ['reserve_price','Reserve price'], ['vat_percent','VAT %'],
      ['condition_id','Condition'], ['condition_description','Condition description'],
      ['format','Format'], ['duration','Duration'],
      ['shipping_profile','Shipping policy'], ['return_profile','Return policy'], ['payment_profile','Payment policy'],
      ['shop_id','Shop ID'], ['shop_id_2','Shop ID 2'],
      ['location','Location'], ['postal_code','Postal code'],
      ['best_offer_enabled','Best offer enabled'], ['private_listing','Private listing'],
      ['schedule_time','Schedule'], ['description_html','Description (HTML)']
    ];
    for (let [key, lbl] of base) sel.appendChild(new Option(lbl, key));

    const aspKeys = {};
    for (let r of lastRows){ const a = r.aspects || {}; for (let k in a) aspKeys[k] = 1; }
    for (let k of Object.keys(aspKeys).sort()){
      sel.appendChild(new Option(k, 'aspects.'+k));
    }
    refreshBulkValueInput();
  }

  function refreshBulkValueInput(){
    const fieldSel = $('bulkField'); if (!fieldSel) return;
    const current = $('bulkValue'); if (!current) return;

    const field = fieldSel.value || '';
    function swap(el){ el.id='bulkValue'; current.replaceWith(el); }

    if (field==='shipping_profile' || field==='return_profile' || field==='payment_profile' || field==='shop_id' || field==='shop_id_2'){
      let list = [];
      if (field==='shipping_profile') list = POL.shipping;
      else if (field==='return_profile') list = POL.ret;
      else if (field==='payment_profile') list = POL.pay;
      else list = (POL.store_categories||[]).map(x => ({id:x.id, name:x.name}));
      const sel = document.createElement('select');
      sel.appendChild(new Option('',''));
      for (const it of list) sel.appendChild(new Option(it.name+' ['+it.id+']', it.id));
      swap(sel); return;
    }

    if (field==='condition_id'){
      const allowed = getConditionList((selectedRows()[0]||{}).category_id || (lastRows[0]||{}).category_id);
      const opts = allowed.length ? allowed.map(o => o.label) : [
        '1000-New','1500-New other (see details)','1750-New with defects','2000-Manufacturer refurbished',
        '2500-Seller refurbished','2750-Like New','3000-Used','4000-Very Good',
        '5000-Good','6000-Acceptable','7000-For parts or not working'
      ];
      const sel = document.createElement('select');
      sel.appendChild(new Option('',''));
      for (const o of opts) sel.appendChild(new Option(o, o));
      swap(sel); return;
    }

    if (field==='format'){
      const sel = document.createElement('select');
      ['Auction','Fixed price'].forEach(v => sel.appendChild(new Option(v, v)));
      swap(sel); return;
    }

    if (field==='duration'){
      const rows = selectedRows();
      let fmt = (rows.length ? rows[0].format : (lastRows[0] && lastRows[0].format)) || 'Fixed price';
      const vals = getDurations(fmt);
      const sel = document.createElement('select');
      for (const v of vals) sel.appendChild(new Option(v, v));
      swap(sel); return;
    }

    if (field==='best_offer_enabled' || field==='private_listing'){
      const sel = document.createElement('select');
      sel.appendChild(new Option('false','false'));
      sel.appendChild(new Option('true','true'));
      swap(sel); return;
    }

    if (field.indexOf('aspects.') === 0){
      const key = field.slice(8);
      const cat = (selectedRows()[0]||{}).category_id || (lastRows[0]||{}).category_id || null;
      const lookupName = String(key).replace(/^C:\s*/,'').trim();
      const list = getAspectList(cat, lookupName);
      if (list.length){
        const sel = document.createElement('select');
        sel.appendChild(new Option('',''));
        for (const v of list) sel.appendChild(new Option(v, v));
        swap(sel); return;
      }
    }

    if (current.tagName.toLowerCase() !== 'input'){
      const ip = document.createElement('input'); ip.type='text'; ip.style.minWidth='220px';
      swap(ip);
    }
  }

  $('bulkField').addEventListener('change', refreshBulkValueInput);
  $('bulkApply').addEventListener('click', () => {
    const fieldEl = $('bulkField'); const valEl = $('bulkValue');
    if (!fieldEl || !valEl){ alert('Bulk controls ontbreken.'); return; }
    const field = fieldEl.value; const valRaw = valEl.value;
    const rows = selectedRows();
    if (!rows.length){ alert('Selecteer rijen.'); return; }

    for (let r of rows){
      if (field.indexOf('aspects.') === 0){
        const k = field.slice(8); r.aspects = r.aspects || {}; r.aspects[k] = valRaw || null;
      } else if (field === 'quantity'){
        r.quantity = parseInt(valRaw || '0', 10) || 0;
      } else if (field === 'price' || field === 'buy_it_now_price' || field==='reserve_price' || field === 'vat_percent'){
        r[field] = (valRaw === '' ? null : parseFloat(valRaw));
      } else if (field === 'shipping_profile' || field === 'return_profile' || field === 'payment_profile'){
        r[field] = valRaw || null;
      } else if (field === 'shop_id'){
        r.shop_id = valRaw || null; r.store_category = valRaw || null;
      } else if (field === 'shop_id_2'){
        r.shop_id_2 = valRaw || null; r.store_category_2 = valRaw || null; r.store_category2 = valRaw || null;
      } else if (field === 'best_offer_enabled' || field === 'private_listing'){
        r[field] = (String(valRaw).toLowerCase() === 'true');
      } else {
        r[field] = valRaw || '';
      }
    }
    renderBody();
  });

  // ------------------- image manager -------------------
  function openImageDlg(row){
    CURRENT_IMG_ROW = row;
    const dl = $('dlgImages'); dl.style.display='flex';
    renderImgList();
  }
  function closeImageDlg(){ $('dlgImages').style.display='none'; CURRENT_IMG_ROW = null; }
  function renderImgList(){
    const box = $('imgList'); box.innerHTML='';
    if (!CURRENT_IMG_ROW) return;
    const imgs = allImages(CURRENT_IMG_ROW);
    imgs.forEach((u) => {
      const item = document.createElement('div'); item.style.position='relative';
      const im = document.createElement('img'); im.src=u; im.style.width='120px'; im.style.height='90px'; im.style.objectFit='cover'; im.style.display='block'; im.style.border='1px solid var(--BORDER)'; im.style.borderRadius='6px';
      const del = document.createElement('button'); del.textContent='×'; del.title='Delete'; del.style.position='absolute'; del.style.top='-8px'; del.style.right='-8px'; del.style.borderRadius='12px'; del.style.width='24px'; del.style.height='24px';
      del.addEventListener('click', () => {
        const a = CURRENT_IMG_ROW.picture_urls || []; const b = CURRENT_IMG_ROW.pictures || [];
        CURRENT_IMG_ROW.picture_urls = a.filter(x => x !== u);
        CURRENT_IMG_ROW.pictures = b.filter(x => x !== u);
        renderImgList(); renderBody();
      });
      item.appendChild(im); item.appendChild(del); box.appendChild(item);
    });
  }
  $('imgClose').addEventListener('click', closeImageDlg);
  $('imgDone').addEventListener('click', closeImageDlg);
  $('btnAddUrl').addEventListener('click', () => {
    if (!CURRENT_IMG_ROW) return;
    const v = ($('imgUrl').value || '').trim(); if (!v) return;
    CURRENT_IMG_ROW.picture_urls = (CURRENT_IMG_ROW.picture_urls || []).concat([v]);
    renderImgList(); renderBody(); $('imgUrl').value='';
  });
  $('btnUpload').addEventListener('click', async () => {
    if (!CURRENT_IMG_ROW) return;
    const f = $('imgFile').files[0]; if (!f){ alert('Kies een bestand.'); return; }
    const fd = new FormData();
    fd.append('file', f, f.name);
    fd.append('site', SITE);
    try{
      const r = await fetch('/media/eps_upload?site='+encodeURIComponent(SITE), { method:'POST', body:fd });
      if (!r.ok){ const tx = await r.text(); throw new Error(tx); }
      const js = await r.json();
      const url = js.image_url || (js.all_urls && js.all_urls[0]);
      if (url){
        CURRENT_IMG_ROW.picture_urls = (CURRENT_IMG_ROW.picture_urls || []).concat([url]);
        renderImgList(); renderBody();
      }
    }catch(e){ alert('Upload failed: '+(e.message||e)); }
  });

  // ------------------- html preview -------------------
  function openHtmlPreview(row, key){
    const dlg = document.createElement('div');
    dlg.className='dlg'; dlg.style.display='flex';
    dlg.innerHTML = `
      <div class="card">
        <header>
          <h3>Description preview</h3>
          <button data-act="close">Close</button>
        </header>
        <div class="body">
          <div style="display:flex;gap:14px;flex-wrap:wrap">
            <div style="flex:1;min-width:320px">
              <div class="muted" style="margin-bottom:6px">HTML source</div>
              <textarea id="src" style="width:100%;min-height:260px">${(row[key]||'').replace(/</g,'&lt;')}</textarea>
            </div>
            <div style="flex:1.2;min-width:360px">
              <div class="muted" style="margin-bottom:6px">Preview</div>
              <div id="prev" class="html-preview"></div>
            </div>
          </div>
        </div>
        <footer>
          <button data-act="apply" class="dark">Apply</button>
        </footer>
      </div>`;
    document.body.appendChild(dlg);

    const src = dlg.querySelector('#src'); const prev = dlg.querySelector('#prev');
    function render(){ try{ prev.innerHTML = src.value; }catch(_){ prev.textContent='(preview error)'; } }
    render();
    src.addEventListener('input', render);

    dlg.addEventListener('click', (ev) => {
      const act = ev.target && ev.target.getAttribute && ev.target.getAttribute('data-act');
      if (act === 'close'){ document.body.removeChild(dlg); }
      if (act === 'apply'){
        row[key] = src.value; document.body.removeChild(dlg); renderBody();
      }
    });
  }

  // ------------------- data flow -------------------
  function build(query){
    if (query === undefined) query = '';
    const sep = (query.indexOf('?') >= 0) ? '&' : '?';
    const q2 = query + (LK ? (sep + 'lk=' + encodeURIComponent(LK)) : '');

    status('Loading draft…');
    return getJSON('/web/draft' + q2)
      .then(d => {
        lastRows = (d.rows || []).map(r => {
          r = r || {};
          r.aspects = r.aspects || {};

          if (!r.shipping_profile && r.shipping_policy) r.shipping_profile = r.shipping_policy;
          if (!r.return_profile && r.return_policy)     r.return_profile  = r.return_policy;
          if (!r.payment_profile && r.payment_policy)   r.payment_profile = r.payment_policy;
          if (!r.condition_id && r.condition)           r.condition_id    = r.condition;

          const sid = (r.shop_id != null && r.shop_id !== '') ? r.shop_id
                    : (r.store_category || r.store_category_id || null);
          r.shop_id = sid || null;
          r.store_category = sid || null;

          const sid2 = r.shop_id_2 || r.store_category_2 || r.store_category2 || null;
          r.shop_id_2 = sid2 || null;
          r.store_category_2 = sid2 || null;
          r.store_category2 = sid2 || null;

          return r;
        });
        try{
          if (d && d.schedule){
            const im = parseInt(d.schedule.interval_minutes || d.schedule.intervalMinutes || 0, 10);
            if (!isNaN(im)) INTERVAL_MIN = Math.max(0, im);
            const sd = d.schedule.start_datetime || d.schedule.startDatetime || null;
            if (sd){
              const dt = parseLocalMinute(sd) || new Date(sd);
              if (dt && !isNaN(dt.getTime())) GLOBAL_START_DT = dt;
            }
          }
        }catch(_){}

        const cats = [];
        for (const r of lastRows) if (r.category_id) cats.push(r.category_id);
        return ensureAspectsAndConditionsMany(cats);
      })
      .then(() => loadPolicies())
      .then(() => {
        applyPolicyAndLocationDefaults(lastRows);

        // Normaliseer condition naar toegestane label
        for (const r of lastRows){
          const allowed = getConditionList(r.category_id);
          if (allowed.length){
            const cur = r.condition_id || r.condition;
            const norm = normalizeConditionValue(cur, allowed);
            r.condition_id = norm || allowed[0].label;
          }
        }

        renderTable(lastRows);
        status('Loaded ' + lastRows.length + ' rows');

        const bb=document.getElementById('bootBanner');
        if (bb) bb.style.display='none';
      })
      .catch(e => {
        status('Error: ' + (e.message||e));
        showErr('Draft laden mislukt: ' + (e.message||e));
      });
  }

  function showPublishOverlay(txt){ $('pubText').textContent = txt || 'Publishing…'; $('pubOverlay').style.display='flex'; }
  function hidePublishOverlay(){ $('pubOverlay').style.display='none'; }

  function publish(rows){
    function _allImages(r){
      let u = [];
      if (Array.isArray(r?.picture_urls)) u = u.concat(r.picture_urls);
      if (Array.isArray(r?.pictures))     u = u.concat(r.pictures);
      return Array.from(new Set(u.filter(Boolean)));
    }
    function _getCategoryId(r){
      const keys = ['category_id','categoryId','CategoryID','primary_category_id','primaryCategoryId','category'];
      for (const k of keys){ if (r && r[k] != null) return r[k]; }
      if (r && r.category_mapping){
        const cm = r.category_mapping;
        if (cm.category_id != null) return cm.category_id;
        if (cm.categoryId != null)  return cm.categoryId;
      }
      return null;
    }
    function _markRow(idx, msg){
      try{
        if (typeof highlightRowError === 'function') highlightRowError(idx, msg);
        const tr = document.querySelector(`tr[data-row="${idx}"]`);
        if (tr){ tr.classList.add('error'); tr.title = msg || ''; }
      }catch(_){}
    }
    function _normalizeRow(r){
      const o = r;

      let cat = _getCategoryId(r);
      if (cat != null){
        const v = String(cat).trim();
        if (v){ o.category_id = v; o.categoryId = v; }
      }

      let shop1 = r.shop_id ?? r.shopId ?? r.store_id ?? r.storeId ?? null;
      if (!shop1 && r.category_mapping){
        shop1 = r.category_mapping.shop_id ?? r.category_mapping.shopId ?? null;
      }
      if (shop1 != null){
        const v = String(shop1).trim();
        if (v){ o.shop_id = v; o.shopId = v; }
      }

      let shop2 = r.shop_id_2 ?? r.shopId2 ?? r.store_id_2 ?? r.storeId2 ?? null;
      if (!shop2 && r.category_mapping){
        shop2 = r.category_mapping.shop_id_2 ?? r.category_mapping.shopId2 ?? null;
      }
      if (shop2 != null){
        const v2 = String(shop2).trim();
        if (v2){ o.shop_id_2 = v2; o.shopId2 = v2; }
      }

      let cond = r.condition_id ?? r.condition_code ?? r.condition ?? null;
      if (!cond && r.category_mapping){
        cond = r.category_mapping.condition_id ?? r.category_mapping.condition ?? null;
      }
      if (cond != null){
        const c = String(cond).trim();
        if (c){ o.condition_id = c; o.condition_code = c; }
      }

      let specs = r.item_specifics ?? r.specifics ?? r.ItemSpecifics ?? null;
      if (!specs && r.category_mapping){
        specs = r.category_mapping.item_specifics ?? r.category_mapping.specifics ?? null;
      }
      if (specs != null){
        o.item_specifics = specs;
        if (o.specifics == null) o.specifics = specs;
      }

      const fmt = String(r?.listing_type ?? r?.listingType ?? r?.format ?? '').toLowerCase();
      if (fmt === 'auction'){
        o.quantity = 1;
      }
      return o;
    }

    // Validation
    const _errors = [];
    (rows || []).forEach((r, i) => {
      let bad = null;
      const title = (r?.title ?? '').toString();
      if (!title) bad = 'Title is required.';
      else if (title.length > 80) bad = `Title exceeds 80 characters (${title.length}).`;

      const imgs = _allImages(r);
      if (!bad && imgs.length < 1) bad = 'At least one image is required.';

      const cat = _getCategoryId(r);
      const catStr = String(cat ?? '').trim();
      if (!bad && (!catStr || !/^[0-9]+$/.test(catStr))){
        bad = 'Valid numeric category_id is required.';
      }

      const fmt = String(r?.listing_type ?? r?.listingType ?? r?.format ?? '').toLowerCase();
      if (!bad && fmt === 'auction' && String(r?.quantity ?? '').trim() !== '1'){
        bad = 'Quantity must be 1 for Auction (will be set to 1).';
      }

      if (bad) _errors.push({ index:i, message:bad });
    });
    if (_errors.length){
      try { document.querySelectorAll('tr.error').forEach(el => { el.classList.remove('error'); el.title=''; }); } catch(_){}
      _errors.forEach(e => _markRow(e.index, e.message));
      let m = 'Validation failed — nothing was sent:\n\n';
      _errors.slice(0,50).forEach(e=>{
        const t = (window.lastRows?.[e.index]?.title) || '(no title)';
        m += `#${e.index+1}: ${t} — ${e.message}\n`;
      });
      alert(m);
      try{ status('Validation failed.'); }catch(_){}
      return Promise.resolve({ ok:false, message:'client validation failed', errors:_errors });
    }

    // ===== Auction interval & TZ normalization =====
    // base: eerste rij met schedule, anders GLOBAL_START_DT, anders nu+30m
    let base = null;
    for (const r of rows){
      if (r.schedule_time){
        const dt = parseLocalMinute(r.schedule_time) || new Date(r.schedule_time);
        if (dt && !isNaN(dt.getTime())) { base = dt; break; }
      }
    }
    if (!base){
      base = GLOBAL_START_DT || new Date(Date.now() + 30*60*1000);
    }

    // Offset per auction
    let idxAuction = 0;
    for (const r of rows){
      const fmt = String(r?.listing_type ?? r?.listingType ?? r?.format ?? '').toLowerCase();
      if (fmt === 'auction' && INTERVAL_MIN > 0){
        const dt = new Date(base.getTime() + idxAuction * INTERVAL_MIN * 60*1000);
        r.schedule_time = localMinuteStr(dt); // laat UI/normalize de TZ doen
        idxAuction += 1;
      }
    }

    // Convert to UTC + bump if needed (after conversion)
    let bumpedCount = 0;
    rows.forEach(r => {
      ensureUtcSchedule(r);
      if (r._schedule_bumped) bumpedCount++;
    });

    // Normalize rows BEFORE sending
    rows = (rows || []).map(_normalizeRow);

    if (!rows || !rows.length){ alert('Selecteer rijen.'); return; }
    let clientTZ = null;
    try { clientTZ = Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch(_){}

    if (bumpedCount > 0){
      alert(`${bumpedCount} listing(s) had a scheduled time in the past (after timezone conversion). They were moved to “now”.`);
    }

    // Overlay on
    showPublishOverlay('Publishing to eBay…');
    status('Publishing ' + rows.length + ' rows…');

    const interval =
      (POL.defaults && (parseInt(POL.defaults.interval_minutes,10) ||
                        parseInt((POL.defaults.schedule||{}).interval_minutes,10))) || 0;

    postJSON('/web/publish', {
      site: SITE,
      currency: CURRENCY,
      interval_minutes: interval,
      timezone: clientTZ,
      rows: rows
    })
  .then(res => {
    hidePublishOverlay();
    if (!res || res.ok !== true) {
      status('Failed');
      alert('Publish failed (no response).');
      return;
    }
    const items = Array.isArray(res.results) ? res.results : [];
    const okN   = items.filter(x => x && x.ok).length;
    const fail  = items.filter(x => !x || x.ok === false);

    let msg = `Published: ${okN}/${items.length} OK.`;
    if (fail.length) {
      const lines = fail.slice(0, 5).map(x =>
        `• ${x?.title || '(no title)'} — ${x?.error || 'unknown error'}`
      );
      msg += `\n\nFailures:\n${lines.join('\n')}`;
    }
    alert(msg);

    // Open de juiste eBay pagina:
    // -> alleen naar "scheduled" als ÁLLE listings gepland zijn; anders "active"
    const allScheduled = (rows || []).length > 0 && (rows || []).every(r => !!r.schedule_time);

    const tldMap = {
      NL:'nl', BE:'be', DE:'de', FR:'fr', IT:'it', ES:'es',
      AT:'at', CH:'ch', IE:'ie',
      UK:'co.uk', GB:'co.uk',
      US:'com', CA:'ca', AU:'com.au'
    };
    const site = (typeof SITE === 'string' ? SITE.toUpperCase() : 'US');
    const tld  = tldMap[site] || 'com';

    const page = allScheduled ? 'scheduled' : 'active';   // <-- was 'sche'
    const url  = `https://www.ebay.${tld}/sh/lst/${page}`;

    if (confirm(`Open your ${page} listings on eBay ${site}?`)) {
      window.open(url, '_blank', 'noopener');
    }
      })
      }

  // ------------------- html editor for description -------------------
  function editHtmlSelected(){
    const rows = selectedRows(); if (!rows.length){ alert('Selecteer minstens 1 rij.'); return; }
    const initial = rows[0].description_html || '';

    const dlg = document.createElement('div');
    dlg.className = 'dlg'; dlg.style.display='flex';
    dlg.innerHTML = `<div class="card">
      <header><h3>Edit HTML</h3><button data-act="close">Close</button></header>
      <div class="body">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px">
          <textarea id="edHtml" style="min-height:300px; font-family: Consolas, monospace; font-size:13px;">${initial}</textarea>
          <div id="edPrev" class="html-preview"></div>
        </div>
      </div>
      <footer><button data-act="apply" class="dark">Apply to selected</button></footer>
    </div>`;
    document.body.appendChild(dlg);
    const ta = dlg.querySelector('#edHtml'); const pv = dlg.querySelector('#edPrev');
    const render = ()=>{ try{ pv.innerHTML = ta.value; }catch(_){ pv.textContent = '(preview error)'; } };
    render();
    ta.addEventListener('input', render);
    dlg.addEventListener('click', (ev) => {
      const act = ev.target && ev.target.getAttribute && ev.target.getAttribute('data-act');
      if (act === 'close'){ document.body.removeChild(dlg); }
      if (act === 'apply'){
        const v = ta.value;
        rows.forEach(r => { r.description_html = v; });
        document.body.removeChild(dlg);
        renderBody();
      }
    });
  }
  document.getElementById('editHtml').addEventListener('click', editHtmlSelected);

  // ------------------- events (toolbar) -------------------
  $('publishAll').addEventListener('click', () => publish(lastRows.slice()));
  $('publishSel').addEventListener('click', () => publish(selectedRows()));
  $('toggleHidden').checked = SHOW_HIDDEN;
  $('toggleHidden').addEventListener('change', () => { SHOW_HIDDEN = $('toggleHidden').checked; renderTable(lastRows); });
  $('checkAll').checked = true;
  $('checkAll').addEventListener('change', () => {
    const on = $('checkAll').checked;
    document.querySelectorAll('input.rowSel').forEach(cb => cb.checked = on);
  });

  // ------------------- init -------------------
  try{
    const bb=document.getElementById('bootBanner');
    if(bb) bb.textContent='UI geladen…';
  }catch(_){}
  console.log('[editor] init wired');
  loadSite().then(() => build());
})();
</script>
</body>
</html>"""
    return HTMLResponse(html)

# =============================================================================
# Data endpoints used by the editor
# =============================================================================

@router.get("/web/draft")
def web_draft(path: Optional[str] = Query(None), lk: Optional[str] = Query(None)):
    """
    Draft laden:
      - ?lk=... zoekt uitsluitend in server/drafts/<lk>/ (nieuwste .json)
      - zonder ?lk zoekt in server/drafts/
      - ?path=... kan een exact bestand of een map zijn (dan nieuwste kiezen)
    """
    chosen: Optional[str] = None
    if path:
        p = path.strip()
        if os.path.isdir(p):
            cands = sorted(glob.glob(os.path.join(p, "*.json")), key=os.path.getmtime, reverse=True)
            chosen = cands[0] if cands else None
        else:
            chosen = p
    else:
        chosen = _latest_draft_path_for(lk)
        if not chosen and not lk:
            chosen = _latest_draft_path_for(None)

    if not chosen or not os.path.exists(chosen):
        detail = "Geen draft gevonden"
        if lk:
            detail += f" voor license '{lk}'"
        raise HTTPException(status_code=404, detail=detail + ".")

    with open(chosen, "r", encoding="utf-8") as f:
        data = json.load(f) or {}
    rows = data.get("rows") or []
    site = (data.get("site") or "NL").upper()
    currency = (data.get("currency") or "EUR").upper()
    return {"rows": rows, "site": site, "currency": currency, "path": chosen}

@router.post("/web/draft/upload")
def web_draft_upload(payload: Dict[str, Any]):
    """
    Ontvangt draft JSON van de client en schrijft dit weg in server/drafts/
    (eventueel per license_key). Response bevat pad van het weggeschreven bestand.
    """
    os.makedirs("server/drafts", exist_ok=True)
    lk = (payload or {}).get("license_key") or ""
    sub = os.path.join("server", "drafts", lk) if lk else os.path.join("server", "drafts")
    os.makedirs(sub, exist_ok=True)
    import time, json as _json
    ts = time.strftime("%Y%m%d-%H%M%S")
    fn = os.path.join(sub, f"draft-{ts}.json")
    with open(fn, "w", encoding="utf-8") as f:
        _json.dump(payload, f, ensure_ascii=False, indent=2)
    return {"ok": True, "path": fn}

@router.get("/web/conditions")
def web_conditions(site: str = Query("NL"), category_id: str = Query(...)):
    """
    Vereenvoudigde conditions per categorie.
    Houdt nu een veilige fallback aan (zelfde lijst voor alle categorieën),
    maar retourneert ook 'allow_description' zodat de UI het veld kan
    enablen/disablen. Later kun je dit vervangen door echte eBay metadata.
    """
    # Fallback lijst (veelgebruikte ID's)
    conditions = [
        {"id":"1000","name":"New","label":"1000-New","allow_description": False},
        {"id":"1500","name":"New other (see details)","label":"1500-New other (see details)","allow_description": True},
        {"id":"1750","name":"New with defects","label":"1750-New with defects","allow_description": True},
        {"id":"2000","name":"Manufacturer refurbished","label":"2000-Manufacturer refurbished","allow_description": True},
        {"id":"2500","name":"Seller refurbished","label":"2500-Seller refurbished","allow_description": True},
        {"id":"2750","name":"Like New","label":"2750-Like New","allow_description": True},
        {"id":"3000","name":"Used","label":"3000-Used","allow_description": True},
        {"id":"4000","name":"Very Good","label":"4000-Very Good","allow_description": True},
        {"id":"5000","name":"Good","label":"5000-Good","allow_description": True},
        {"id":"6000","name":"Acceptable","label":"6000-Acceptable","allow_description": True},
        {"id":"7000","name":"For parts or not working","label":"7000-For parts or not working","allow_description": True},
    ]
    return {"site": site.upper(), "category_id": str(category_id), "conditions": conditions}

@router.get("/web/policies_dummy")
def web_policies(site: str = Query("NL"), prefer_store: str = Query("trading")):
    """Compat endpoint voor front-end. Levert lijsten (kunnen leeg zijn) en defaults uit config.json."""
    cfg = _read_cfg()
    defaults = {
        "shipping_profile": cfg.get("shipping_profile"),
        "return_profile":   cfg.get("return_profile"),
        "payment_profile":  cfg.get("payment_profile"),
        "location":         cfg.get("location"),
        "condition_id":     cfg.get("condition_id") or cfg.get("condition"),
    }
    return {
        "shipping": [],
        "return":   [],
        "payment":  [],
        "store_categories": [],
        "defaults": defaults,
        "site": site.upper()
    }
@router.get("/web/policy_defaults")
def web_policy_defaults():
    """
    Lees defaults uit config.json zodat de editor die kan toepassen
    wanneer de draft zelf geen waardes heeft.
    Toegestane keys: shipping_profile, return_profile, payment_profile, location, condition_id
    """
    cfg = _read_cfg()
    d = {
        "shipping_profile": cfg.get("shipping_profile"),
        "return_profile":   cfg.get("return_profile"),
        "payment_profile":  cfg.get("payment_profile"),
        "location":         cfg.get("location"),
        "condition_id":     cfg.get("condition_id") or cfg.get("condition"),
    }
    # strip lege strings -> None
    for k,v in list(d.items()):
        if isinstance(v, str) and not v.strip():
            d[k] = None
    return {"defaults": d}

# Compat: sommige clients roepen /account/site aan
@router.get("/account/site")
def account_site_passthrough():
    return _site_info()
