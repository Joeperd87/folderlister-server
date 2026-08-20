# server/web_editor.py
from __future__ import annotations
from fastapi import APIRouter, HTTPException
import os, json, requests, hmac, hashlib, re
import json
import glob
from pathlib import Path
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

_BASE = Path(__file__).resolve().parent
_DRAFTS_BASE = _BASE / "drafts"
_DRAFTS_BASE.mkdir(parents=True, exist_ok=True)
_LK_HMAC_SECRET = os.getenv("LICENSE_HMAC_SECRET", "CHANGE_ME_DEV_SECRET").encode("utf-8")
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

def _draft_bucket_for_lk(raw_lk: str) -> str:
    raw = str(raw_lk or "").strip()
    if not raw:
        return "_anon"
    digest = hmac.new(_LK_HMAC_SECRET, raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"lk_{digest[:48]}"

def _draft_dirs_for_lk(raw_lk: Optional[str]) -> List[Path]:
    raw = str(raw_lk or "").strip()
    dirs: List[Path] = [_DRAFTS_BASE / _draft_bucket_for_lk(raw)]
    if raw and _SAFE_SEGMENT_RE.fullmatch(raw):
        # legacy/plain folder support (read compatibility only)
        dirs.append(_DRAFTS_BASE / raw)
    return dirs

def _latest_draft_path_for(lk: Optional[str]) -> Optional[str]:
    for d in _draft_dirs_for_lk(lk):
        if not d.exists():
            continue
        cands = sorted((p for p in d.glob("draft_*.json") if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)
        if not cands:
            cands = sorted((p for p in d.glob("draft-*.json") if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)
        if not cands:
            cands = sorted((p for p in d.glob("*.json") if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)
        if cands:
            return str(cands[0])
    return None

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
<title>Folder Lister – Web Editor</title>
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
  #reviseBanner{display:none;background:#d97706;color:#1c1c1c;padding:3px 12px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.2px}

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

  /* per-category sections (single-mode) */
  .cat-section-hdr{
    padding:6px 10px; margin:10px 0 0 0;
    background:var(--SURFACE_ELEV); color:var(--ACCENT);
    font-weight:600; font-size:13px; border-radius:6px 6px 0 0;
    border-left:3px solid var(--ACCENT);
  }
  .cat-section-table{ margin-bottom:18px; }

  .toolbar-check{display:inline-flex;align-items:center;gap:8px;margin-left:8px}

  /* overlay dialog */
  .dlg{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;align-items:center;justify-content:center;z-index:50}
  .batch-row{padding:8px 10px;border-radius:8px;background:var(--SURFACE_HI);cursor:pointer;border:1px solid transparent}
  .batch-row:hover{border-color:var(--ACCENT)}
  .batch-row.active{border-color:var(--ACCENT);background:var(--SURFACE_ELEV)}
  .batch-main{font-size:13px;font-weight:600}
  .batch-meta{font-size:11px;color:var(--MUTED);margin-top:2px}
  #dlgImages{z-index:60}
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
    #pubOverlay .col{display:flex;flex-direction:column;gap:6px;flex:1}
  .pub-prog{
    width:260px;
    max-width:100%;
    height:6px;
    border-radius:999px;
    background:#ffffff22;
    overflow:hidden;
    margin-top:6px;
  }
  .pub-prog .inner{
    height:100%;
    width:0%;
    background:var(--ACCENT);
    transition:width .25s ease-out;
  }

</style>
</head>
<body>
<div id="bootBanner">Booting…</div>
<div id="errOverlay"><pre id="errText"></pre></div>

<header>
  <img src="/images/folder_lister_logo.png" alt="logo" onerror="this.style.display='none'">
  <h1>FolderLister – Web Editor</h1>
  <span id="site" class="pill">…</span>
  <span id="modeBadge" class="pill" style="display:none">MultiListing</span>
  <span id="reviseBanner">✏️ EDIT MODE — revising existing listing</span>
</header>

<div id="controls">
  <button id="editHtml">Edit HTML…</button>
  <button id="publishSel" class="dark">Publish selected</button>
  <button id="publishAll" class="yellow">Publish ALL</button>

  <label class="toolbar-check"><input id="checkAll" type="checkbox" checked> Check all</label>
  <label class="toolbar-check"><input id="toggleHidden" type="checkbox" checked> Show hidden fields</label>
  <button id="btnColumns">Columns</button>
  <button id="btnBatches" title="Open an earlier batch of this account">Batches...</button>
  <button id="btnVariations" style="display:none">Variations…</button>
  <button id="btnTogglePublished" style="display:none" title="Toon/verberg al gepubliceerde items van deze sessie">Show published (0)</button>

  <!-- BULK editor -->
  <div style="flex-basis:100%"></div>
  <label for="bulkField">Bulk:</label>
  <select id="bulkField"></select>
  <span id="bulkValueWrap">
    <input id="bulkValue" type="text" placeholder="value…" style="min-width:220px">
    <input id="bulkValue2" type="text" placeholder="replace with… (leave empty to strip)" style="min-width:220px;display:none;margin-left:4px">
  </span>
  <button id="bulkApply">Apply to selected</button>

  <span id="status" class="muted" style="margin-left:auto"></span>
</div>

<!-- Quick-post setup (shown when seller has no eBay business policies) -->
<div id="quickPostPanel" style="display:none;background:#1a3d2a;border-bottom:2px solid #FDB913;padding:10px 16px;color:#e6f0e8;font-size:13px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">
    <span style="font-weight:700;color:#FDB913">Quick post setup</span>
    <span style="opacity:.8">No eBay business policies found for <strong id="qpSite"></strong>. Fill these in to publish right away — they apply to all rows.</span>
    <a id="qpEbayLink" href="#" target="_blank" style="color:#ffd;text-decoration:underline;white-space:nowrap;margin-left:auto">Or create proper policies on eBay →</a>
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;align-items:end">
    <label style="display:flex;flex-direction:column;gap:2px">
      <span>Shipping service <span style="color:#ff6">*</span></span>
      <select id="qpShipService"></select>
    </label>
    <label style="display:flex;flex-direction:column;gap:2px">
      <span>Shipping cost (<span id="qpCurSym">€</span>) <span style="color:#ff6">*</span></span>
      <input id="qpShipCost" type="number" min="0" step="0.01" placeholder="6.95">
    </label>
    <label style="display:flex;align-items:center;gap:6px;padding-bottom:6px">
      <input id="qpFreeShip" type="checkbox"> Free shipping
    </label>
    <label style="display:flex;flex-direction:column;gap:2px">
      <span>Handling time (days) <span style="color:#ff6">*</span></span>
      <select id="qpDispatch">
        <option value="1">1</option><option value="2" selected>2</option>
        <option value="3">3</option><option value="5">5</option>
        <option value="10">10</option>
      </select>
    </label>
    <label style="display:flex;align-items:center;gap:6px;padding-bottom:6px">
      <input id="qpReturns" type="checkbox" checked> Accept returns
    </label>
    <label style="display:flex;flex-direction:column;gap:2px">
      <span>Return period</span>
      <select id="qpReturnDays">
        <option value="14">14 days</option>
        <option value="30" selected>30 days</option>
        <option value="60">60 days</option>
      </select>
    </label>
    <label style="display:flex;flex-direction:column;gap:2px">
      <span>Return shipping paid by</span>
      <select id="qpReturnPayer">
        <option value="Buyer" selected>Buyer</option>
        <option value="Seller">Seller</option>
      </select>
    </label>
    <label style="display:flex;flex-direction:column;gap:2px">
      <span>Location (city) <span style="color:#ff6">*</span></span>
      <input id="qpLocation" type="text" placeholder="Amsterdam">
    </label>
    <label style="display:flex;flex-direction:column;gap:2px">
      <span>Postal code <span style="color:#ff6">*</span></span>
      <input id="qpPostal" type="text" placeholder="1011AB">
    </label>
  </div>
  <div id="qpError" style="display:none;margin-top:8px;color:#ffb3b3;font-weight:600"></div>
</div>

<div id="grid"></div>

<!-- Big loading overlay (shown while /web/draft fetches and rows render) -->
<div id="loadingOverlay" style="position:fixed;inset:0;background:rgba(15,29,35,.78);display:none;align-items:center;justify-content:center;z-index:9999;flex-direction:column;gap:14px;color:#fff;font-family:Inter,system-ui,sans-serif">
  <div style="width:54px;height:54px;border:5px solid rgba(255,255,255,.18);border-top-color:#f0cf6d;border-radius:50%;animation:flSpin 0.85s linear infinite"></div>
  <div id="loadingOverlayText" style="font-size:15px;font-weight:600;letter-spacing:.02em">Loading draft…</div>
  <div id="loadingOverlaySub" style="font-size:12px;color:#b8cdd4;max-width:420px;text-align:center;line-height:1.5">Fetching listings from the server. Larger drafts can take a few seconds.</div>
</div>
<style>
  @keyframes flSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
</style>

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

<!-- Variations dialog -->
<div id="dlgVars" class="dlg" role="dialog" aria-modal="true">
  <div class="card" style="max-width:1100px">
    <header>
      <h3>Variations</h3>
      <button id="varClose">Close</button>
    </header>
    <div class="body">
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px">
        <label>Attribute 1 name<br><input id="varName1" type="text" style="min-width:220px"></label>
        <label>Attribute 2 name (optional)<br><input id="varName2" type="text" style="min-width:220px"></label>
        <label>Picture attribute<br><select id="varPicName" style="min-width:180px"></select></label>
        <button id="varApplyNames">Apply names</button>
        <button id="varAdd">Add variation</button>
      </div>

      <!-- Bulk editor for this variation set (separate from the main-grid bulk editor) -->
      <div style="margin-bottom:10px;padding:8px 10px;border:1px solid #222;border-radius:8px">
        <div style="font-weight:700;margin-bottom:8px">Bulk edit (applies to all rows below)</div>
        <div style="display:flex;gap:16px;flex-wrap:wrap">
          <div style="display:flex;gap:8px;align-items:flex-end;padding-right:16px;border-right:1px solid #222">
            <label>SKU<br><input id="varBulkSku" type="text" placeholder="e.g. SHELF 1-BOX 3 {n}" style="min-width:220px"></label>
            <button id="varBulkSkuApply">Apply</button>
          </div>
          <div style="display:flex;gap:8px;align-items:flex-end">
            <label>Title — find<br><input id="varBulkFind" type="text" placeholder="find text…" style="min-width:160px"></label>
            <label>Replace with<br><input id="varBulkReplace" type="text" placeholder="leave empty to strip" style="min-width:160px"></label>
            <button id="varBulkReplaceApply">Apply</button>
          </div>
        </div>
      </div>

      <div style="overflow:auto;max-height:55vh;border:1px solid #222;border-radius:12px">
        <table class="grid" style="width:100%">
          <thead>
            <tr>
              <th style="width:24px"><input type="checkbox" id="varSelectAll" title="Select all" checked></th>
              <th style="width:28px" title="Sleep rijen om volgorde te wijzigen">&#9776;</th>
              <th style="width:140px">SKU</th>
              <th style="width:180px" id="thA1">Attr1</th>
              <th style="width:180px" id="thA2">Attr2</th>
              <th style="width:110px">Price</th>
              <th style="width:80px">Qty</th>
              <th style="width:120px">Images</th>
              <th style="width:90px"></th>
            </tr>
          </thead>
          <tbody id="varTbody"></tbody>
        </table>
      </div>
    </div>
    <footer>
      <button id="varDone" class="dark">Done</button>
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

<!-- Batches dialog -->
<div id="dlgBatches" class="dlg" role="dialog" aria-modal="true">
  <div class="card" style="width:min(90vw,620px)">
    <header>
      <h3>Batches</h3>
      <button id="batchClose">Close</button>
    </header>
    <div class="body">
      <div class="muted" style="margin-bottom:8px;font-size:12px">
        Your saved batches, newest first. Opening one replaces what is on screen &mdash;
        nothing goes to eBay until you press Publish.
      </div>
      <div id="batchList" style="max-height:296px;overflow-y:auto;display:flex;flex-direction:column;gap:6px"></div>
      <div id="batchNote" class="muted" style="margin-top:8px;font-size:11px"></div>
    </div>
  </div>
</div>

<!-- Publish overlay -->
<!-- Publish overlay -->
<div id="pubOverlay">
  <div class="box">
    <div class="spinner"></div>
    <div class="col">
      <div id="pubText">Publishing…</div>
      <div id="pubProg" class="pub-prog">
        <div class="inner"></div>
      </div>
      <div id="pubProgLabel" class="muted" style="font-size:12px;margin-top:2px;text-align:right"></div>
    </div>
  </div>
</div>


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
  let _noPolicies = false; // set true when no business policies found for this site
  const _EBAY_DOMAIN = {
    NL:'www.ebay.nl', DE:'www.ebay.de', UK:'www.ebay.co.uk', GB:'www.ebay.co.uk',
    US:'www.ebay.com', FR:'www.ebay.fr', IT:'www.ebay.it', ES:'www.ebay.es',
    BE:'www.ebay.be', AT:'www.ebay.at', AU:'www.ebay.com.au', CA:'www.ebay.ca',
    PL:'www.ebay.pl', CH:'www.ebay.ch', IE:'www.ebay.ie',
  };
  function _ebayPoliciesUrl(site){
    const dom = _EBAY_DOMAIN[site] || 'www.ebay.com';
    return 'https://' + dom + '/bp/manage';
  }
  let lastRows = [];
  let showPublishedRows = false; // false = published items hidden, true = visible (toggled)
  function updatePublishedToggle() {
    const btn = document.getElementById('btnTogglePublished');
    if (!btn) return;
    const n = (lastRows || []).filter(r => r && r._published).length;
    if (n === 0) {
      btn.style.display = 'none';
      return;
    }
    btn.style.display = '';
    btn.textContent = (showPublishedRows ? 'Hide published (' : 'Show published (') + n + ')';
  }
  let table, cols;
  let catSections = [];   // [{catId, catDisplay, rows, cols, table}] – single-mode only
  let singleModeActive = false;
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
  function showLoading(msg, sub){
    const ov = document.getElementById('loadingOverlay');
    const tx = document.getElementById('loadingOverlayText');
    const sb = document.getElementById('loadingOverlaySub');
    if (!ov) return;
    if (tx && msg !== undefined) tx.textContent = msg || 'Loading…';
    if (sb && sub !== undefined) sb.textContent = sub || '';
    ov.style.display = 'flex';
  }
  function hideLoading(){
    const ov = document.getElementById('loadingOverlay');
    if (ov) ov.style.display = 'none';
  }
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
      console.log('Account site info (ignored):', js);
      // SITE/CURRENCY NIET meer aanpassen hier
    })
    .catch(err => console.warn('detectAccountSite failed', err));
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

  // ─── Quick-post setup (inline policies for sellers without business policies) ────────────
  // Per-site default shipping services. Must match _INLINE_SHIPPING_DEFAULTS in app.py.
  // Shipping services come from the server (GeteBayDetails for the site
  // being listed on, domestic services only — this value goes into eBay's
  // domestic ShippingServiceOptions). Cached in memory per site.
  // Static fallback only used if the network call fails — "Other" alone
  // is universally accepted by eBay, so it's a safe minimum.
  const QP_SHIP_FALLBACK = [['Other','Other (universal)']];
  const QP_SHIP_CACHE = {}; // site → [[value, label], ...]
  function _qpFetchShippingServices(site){
    if (QP_SHIP_CACHE[site]) return Promise.resolve(QP_SHIP_CACHE[site]);
    return getJSON('/web/shipping_services?site='+encodeURIComponent(site))
      .then(js => {
        const list = (js && Array.isArray(js.services)) ? js.services : [];
        const pairs = list.map(s => [s.service, s.description || s.service]);
        if (!pairs.length) return QP_SHIP_FALLBACK;
        QP_SHIP_CACHE[site] = pairs;
        return pairs;
      })
      .catch(() => QP_SHIP_FALLBACK);
  }
  const CURRENCY_SYMBOL = { EUR:'€', GBP:'£', USD:'$', PLN:'zł', CHF:'CHF', CAD:'CA$', AUD:'A$' };

  function _qpLocalStorageKey(site){ return 'qp_defaults_' + (site||'NL').toUpperCase(); }
  function _qpLoadDefaults(site){
    try {
      const raw = localStorage.getItem(_qpLocalStorageKey(site));
      if (raw) return JSON.parse(raw) || {};
    } catch(_){}
    return {};
  }
  function _qpSaveDefaults(site, obj){
    try { localStorage.setItem(_qpLocalStorageKey(site), JSON.stringify(obj || {})); } catch(_){}
  }

  function _qpPopulateShippingDropdown(){
    const sel = document.getElementById('qpShipService');
    if (!sel) return;
    // Show "Loading..." until the GeteBayDetails fetch returns; the
    // catalogue is cached after the first call so subsequent opens
    // are instant.
    sel.innerHTML = '';
    sel.appendChild(new Option('Loading shipping services…', '', true, true));
    _qpFetchShippingServices(SITE).then(opts => {
      sel.innerHTML = '';
      for (const [val, lbl] of opts) {
        sel.appendChild(new Option(lbl, val));
      }
      // Re-apply persisted defaults now the list is populated.
      try { _qpApplyDefaults(); } catch(_){}
    });
  }

  function _qpApplyDefaults(){
    const d = _qpLoadDefaults(SITE);
    const set = (id, val) => { const el = document.getElementById(id); if (el && val !== undefined && val !== null && val !== '') el.value = val; };
    const setChk = (id, val) => { const el = document.getElementById(id); if (el && typeof val === 'boolean') el.checked = val; };
    // Een eerder opgeslagen service kan uit de lijst verdwenen zijn (bv. een
    // internationale token die nooit geldig was als domestic service). Dan
    // niet toepassen, anders staat de dropdown leeg; laat 'Other' staan.
    const sel = document.getElementById('qpShipService');
    if (sel && d.shipping_service &&
        Array.from(sel.options).some(o => o.value === d.shipping_service)) {
      sel.value = d.shipping_service;
    }
    set('qpShipCost', d.shipping_cost);
    setChk('qpFreeShip', !!d.free_shipping);
    set('qpDispatch', d.dispatch_time_max);
    if (typeof d.returns_accepted === 'boolean') setChk('qpReturns', d.returns_accepted);
    set('qpReturnDays', d.return_period_days);
    set('qpReturnPayer', d.return_shipping_paid_by);
    set('qpLocation', d.location);
    set('qpPostal', d.postal_code);
  }

  function _qpCollect(){
    const free = !!document.getElementById('qpFreeShip').checked;
    return {
      inline_policies: true,
      shipping_service: document.getElementById('qpShipService').value || 'Other',
      shipping_cost: free ? 0 : (parseFloat(document.getElementById('qpShipCost').value) || 0),
      free_shipping: free,
      dispatch_time_max: parseInt(document.getElementById('qpDispatch').value, 10) || 3,
      returns_accepted: !!document.getElementById('qpReturns').checked,
      return_period_days: parseInt(document.getElementById('qpReturnDays').value, 10) || 30,
      return_shipping_paid_by: document.getElementById('qpReturnPayer').value || 'Buyer',
      location: (document.getElementById('qpLocation').value || '').trim(),
      postal_code: (document.getElementById('qpPostal').value || '').trim(),
    };
  }

  function _qpValidate(){
    const v = _qpCollect();
    const issues = [];
    if (!v.shipping_service) issues.push('Shipping service');
    if (!v.free_shipping && !(v.shipping_cost >= 0)) issues.push('Shipping cost');
    if (!(v.dispatch_time_max > 0)) issues.push('Handling time');
    if (!v.location) issues.push('Location');
    if (!v.postal_code) issues.push('Postal code');
    const err = document.getElementById('qpError');
    if (issues.length) {
      err.textContent = 'Still missing: ' + issues.join(', ');
      err.style.display = '';
      return null;
    }
    err.style.display = 'none';
    return v;
  }

  // Per-site postcode hints — eBay rejects letters in DE/US/PL postcodes.
  const QP_POSTAL_HINTS = {
    NL: '1011AB', BE: '1000', DE: '10115', FR: '75001', IT: '00100',
    ES: '28001', AT: '1010', UK: 'SW1A 1AA', GB: 'SW1A 1AA',
    US: '10001', IE: 'D01 ABCD', PL: '00-001', CH: '8001',
  };

  function _showQuickPostPanel(show){
    _noPolicies = show;
    const panel = document.getElementById('quickPostPanel');
    if (!panel) return;
    if (show) {
      document.getElementById('qpSite').textContent = SITE;
      const lnk = document.getElementById('qpEbayLink');
      if (lnk) lnk.href = _ebayPoliciesUrl(SITE);
      const sym = CURRENCY_SYMBOL[CURRENCY] || CURRENCY;
      const cs = document.getElementById('qpCurSym'); if (cs) cs.textContent = sym;
      const pc = document.getElementById('qpPostal');
      if (pc) pc.placeholder = QP_POSTAL_HINTS[SITE] || '';
      _qpPopulateShippingDropdown();
      _qpApplyDefaults();
      panel.style.display = '';
    } else {
      panel.style.display = 'none';
    }
  }

  // Kept for backward compat with older code paths that may call this name.
  function _showNoPoliciesBanner(show){ _showQuickPostPanel(show); }

  function loadPolicies(){
    return getJSON('/web/policies?site='+encodeURIComponent(SITE)+'&prefer_store=trading')
      .then(js => {
        POL.shipping = js.shipping || [];
        POL.ret = js.return || [];
        POL.pay = js.payment || [];
        POL.store_categories = js.store_categories || [];
        // Authoritative no-policies check via dedicated endpoint (cheaper +
        // avoids racing with store-category fetches in /web/policies).
        getJSON('/web/policies/status?site='+encodeURIComponent(SITE))
          .then(st => { _showQuickPostPanel(!(st && st.has_any)); })
          .catch(() => { _showQuickPostPanel(!POL.shipping.length && !POL.ret.length && !POL.pay.length); });
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

  // ─── ConditionDescriptors (bv. Card Condition, Grader, Coin Condition) ────
  // eBay eist deze bij bepaalde categorieen naast de gewone conditie. Ze zijn
  // GEEN item specifics: alles in row.aspects gaat mee als <ItemSpecifics> en
  // wordt daar geweigerd. We schrijven naar row.condition_descriptors, als
  // {descriptor_id: value_id}. De ID's komen rechtstreeks van eBay, want
  // dezelfde waarde heeft per categorie en per marketplace een ander ID.
  const COND_DESC_CACHE = {};   // site|categorie -> [descriptor, ...]

  function ensureConditionDescriptorsFor(categoryId){
    if (!categoryId) return Promise.resolve();
    const k = keyCache(categoryId);
    if (COND_DESC_CACHE[k]) return Promise.resolve();
    const url = '/web/condition_descriptors?site=' + encodeURIComponent(SITE)
              + '&category_id=' + encodeURIComponent(categoryId);
    return getJSON(url)
      .then(js => { COND_DESC_CACHE[k] = (js && Array.isArray(js.descriptors)) ? js.descriptors : []; })
      .catch(() => { COND_DESC_CACHE[k] = []; });
  }

  function getConditionDescriptors(cat){ return COND_DESC_CACHE[keyCache(cat)] || []; }

  // Alleen het conditie-ID uit "4000-Ungraded" of "4000".
  function conditionIdOf(row){
    const m = String(row && (row.condition_id || row.condition) || '').match(/\d+/);
    return m ? m[0] : '';
  }

  // De descriptor die bij deze rij hoort: juiste categorie en juiste conditie.
  function descriptorForRow(row, descriptorId){
    const cid = conditionIdOf(row);
    for (const d of getConditionDescriptors(row.category_id)){
      if (String(d.id) !== String(descriptorId)) continue;
      if (d.condition_id && cid && String(d.condition_id) !== cid) continue;
      return d;
    }
    return null;
  }

  // Bouwt de cel voor één descriptor. Staat los van de render-lus omdat hij
  // ook opnieuw aangeroepen moet worden als de conditie op de rij verandert:
  // Card Condition hoort bij Ungraded, Grader en Grade bij Graded.
  function buildDescriptorControl(row, did){
    const d = descriptorForRow(row, did);
    if (!d){
      const all = getConditionDescriptors(row.category_id)
                    .filter(x => String(x.id) === String(did));
      const needs = all.map(x => x.condition_id).filter(Boolean);
      const span = document.createElement('span');
      span.textContent = '-';
      span.style.color = 'var(--MUTED)';
      span.title = needs.length
        ? ('Alleen van toepassing bij conditie ' + needs.join(' of ')
           + '. Deze rij staat op ' + (conditionIdOf(row) || 'geen conditie') + '.')
        : 'Niet van toepassing op deze rij.';
      return span;
    }
    const sel = document.createElement('select');
    sel.appendChild(new Option('', ''));
    for (const v of (d.values || [])) sel.appendChild(new Option(v.name, v.id));
    sel.value = (row.condition_descriptors || {})[did] || '';
    sel.title = d.name + ' is verplicht voor deze categorie en conditie';
    sel.addEventListener('change', () => {
      row.condition_descriptors = row.condition_descriptors || {};
      if (sel.value) row.condition_descriptors[did] = sel.value;
      else delete row.condition_descriptors[did];
    });
    return sel;
  }

  // Na een conditiewijziging: cellen opnieuw tekenen en waarden weggooien die
  // bij de nieuwe conditie niet meer horen. Anders stuur je een Card Condition
  // mee op een kaart die inmiddels als graded staat.
  function refreshDescriptorCells(rowTr, row){
    if (!rowTr) return;
    const stored = row.condition_descriptors || {};
    for (const did of Object.keys(stored)){
      if (!descriptorForRow(row, did)) delete stored[did];
    }
    rowTr.querySelectorAll('td[data-conddesc]').forEach(td => {
      td.innerHTML = '';
      td.appendChild(buildDescriptorControl(row, td.dataset.conddesc));
    });
  }

  function descriptorColumnsForRows(rows){
    const byId = {};
    for (const r of (rows || [])){
      for (const d of getConditionDescriptors(r.category_id)){
        if (!d.required) continue;                      // optionele overslaan
        if (String(d.mode || '') === 'FREE_TEXT') continue;  // geen keuzelijst
        byId[String(d.id)] = d.name || String(d.id);
      }
    }
    return Object.keys(byId).sort().map(id => ({
      title: byId[id], key: 'conddesc.' + id, type: 'descriptor',
      cls: 'colAspect', sortable: false
    }));
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
    return Promise.all(list.map(cid => Promise.all([
      ensureAspectsFor(cid), ensureConditionsFor(cid), ensureConditionDescriptorsFor(cid)
    ])));
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
      {title:'SKU', key:'sku', type:'text', cls:'colCat', sortable:true},
      {title:'Category ID', key:'category_id', type:'text', cls:'colCat', sortable:true},
      {title:'Qty', key:'quantity', type:'int', cls:'colSmall', sortable:true},
      {title:'Start price', key:'price', type:'num', cls:'colPrice', sortable:true},
    ];

    // If this draft contains variations, show an explicit column.
    const hasVars = (rows || []).some(r => Array.isArray(r.variations) && r.variations.length > 0);
    if(hasVars){
      cols.push({title:'Variations', key:'_vars', type:'vars', cls:'colSmall', sortable:false});
    }
    for (const k of aspectKeys){
      cols.push({title:k, key:'aspects.'+k, type:'aspect', cls:'colAspect', sortable:true});
    }
    for (const c of descriptorColumnsForRows(rows)) cols.push(c);
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

  // When the seller has no listing-settings profile on any row, force
  // these columns to stay visible regardless of SHOW_HIDDEN /
  // hiddenColsPref — otherwise the user has nowhere to set auction vs
  // fixed-price, listing duration, BIN price or scheduled start.
  const QP_FORCE_VISIBLE_KEYS = ['format','duration','buy_it_now_price','schedule_time'];

  function _anyRowHasProfile(rows){
    return (rows || []).some(r => r && (
      String(r.shipping_profile || '').trim() ||
      String(r.return_profile   || '').trim() ||
      String(r.payment_profile  || '').trim()
    ));
  }

  function buildColumns(rows){
    const base = baseColumns(rows);
    const adv = extraColumns();
    const merged = SHOW_HIDDEN ? base.concat(adv) : base;
    const noProfileMode = _noPolicies || !_anyRowHasProfile(rows);
    const forced = noProfileMode ? QP_FORCE_VISIBLE_KEYS : [];

    // If columns we want to force aren't already in the visible list
    // (e.g. SHOW_HIDDEN is off), splice them in from extraColumns.
    if (forced.length && !SHOW_HIDDEN) {
      const have = new Set(merged.map(c => c.key));
      for (const c of adv) {
        if (forced.indexOf(c.key) !== -1 && !have.has(c.key)) merged.push(c);
      }
    }

    return merged.filter(c =>
      c.key === '_sel' || c.key === '_thumb' ||
      forced.indexOf(c.key) !== -1 ||              // bypass user-hide pref for critical cols
      hiddenColsPref.indexOf(c.key) === -1
    );
  }

  // ------------------- single-mode helpers -------------------
  function isSingleMode(rows){
    return (rows || []).some(r => r.row_schema_version === 2);
  }

  function baseColumnsNoAspects(rows){
    return buildColumns(rows).filter(c => c.type !== 'aspect');
  }

  function aspectColumnsForRows(rowsForCat){
    const seen = {};
    for (const r of rowsForCat){
      const a = r.aspects || {};
      for (const k in a){ if (k.indexOf('C:') === 0) seen[k] = 1; }
    }
    return Object.keys(seen).sort().map(k => ({
      title: k, key: 'aspects.'+k, type:'aspect', cls:'colAspect', sortable:true
    })).concat(descriptorColumnsForRows(rowsForCat));
  }

  function renderSingleModeTables(rows, grid){
    const groups = {};
    const order = [];
    for (const r of rows){
      const catId = String(r.category_id || '');
      if (!groups[catId]){
        const catDisplay = r.category_display || r.category_name || catId || '(no category)';
        groups[catId] = {catId, catDisplay, rows: []};
        order.push(catId);
      }
      groups[catId].rows.push(r);
    }
    catSections = [];
    for (const catId of order){
      const g = groups[catId];
      const hdr = document.createElement('div');
      hdr.className = 'cat-section-hdr';
      hdr.textContent = g.catDisplay + (g.catId ? '  [' + g.catId + ']' : '');
      grid.appendChild(hdr);

      const baseCols = baseColumnsNoAspects(rows);
      const aspCols = aspectColumnsForRows(g.rows);
      const secCols = baseCols.concat(aspCols);

      const tbl = document.createElement('table');
      tbl.className = 'cat-section-table';
      tbl.appendChild(document.createElement('thead'));
      tbl.appendChild(document.createElement('tbody'));
      buildHeader(tbl, secCols);
      grid.appendChild(tbl);

      const sec = {catId, catDisplay: g.catDisplay, rows: g.rows, cols: secCols, table: tbl};
      catSections.push(sec);
    }
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

  function renderBody(secOverride){
    // In single-mode with no explicit section, re-render all sections
    if (!secOverride && singleModeActive){
      for (const sec of catSections) renderBody(sec);
      return;
    }
    const allTargetRows = secOverride ? secOverride.rows        : lastRows;
    // Verberg in deze sessie al gepubliceerde rijen, tenzij gebruiker ze wil zien
    const targetRows  = (typeof showPublishedRows !== 'undefined' && showPublishedRows)
                        ? allTargetRows
                        : allTargetRows.filter(r => !(r && r._published));
    const targetCols  = secOverride ? secOverride.cols        : cols;
    const tbody       = secOverride ? secOverride.table.tBodies[0] : table.tBodies[0];
    tbody.innerHTML = '';
    for (let i=0;i<targetRows.length;i++){
      const r = targetRows[i];
      const tr = document.createElement('tr');
      tr.__rowObj = r;

      for (let ci=0; ci<targetCols.length; ci++){
        const c = targetCols[ci];
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

          if (col.type === 'vars'){
            const n = (row && Array.isArray(row.variations)) ? row.variations.length : 0;
            const wrap = document.createElement('div');
            const btn = document.createElement('button');
            btn.textContent = n ? `Edit (${n})` : 'Edit';
            btn.disabled = !n;
            btn.addEventListener('click', () => openVarDlg(row));
            wrap.appendChild(btn);
            put(wrap); return;
          }

          if (col.type === 'textarea'){
            const box = document.createElement('div');
            const ta = document.createElement('textarea');
            ta.style.width = '100%';
            ta.value = row[col.key] || '';
            ta.addEventListener('input', () => {
              row[col.key] = ta.value;
              // User edited the description → server must actually
              // send the new content on revise (default is to skip
              // <Description> to avoid eBay's content-filter 240).
              if (col.key === 'description_html') row.description_changed = true;
            });

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
            if ((col.key === 'price') && (typeof ismulti === 'function') && ismulti(row)) {
              const d = document.createElement('div'); d.className='muted'; d.textContent='—';
              d.title = 'Price is set per variation';
              put(d); return;
            }
            const np = document.createElement('input'); np.type='number'; np.step='0.01'; np.className='num';
            np.value = (row[col.key] != null ? row[col.key] : '');
            np.addEventListener('input', () => { row[col.key] = (np.value === '' ? null : parseFloat(np.value)); });
            put(np); return;
          }

          if (col.type === 'int'){
            if ((col.key === 'quantity') && (typeof ismulti === 'function') && ismulti(row)) {
              const d = document.createElement('div'); d.className='muted'; d.textContent='—';
              d.title = 'Quantity is set per variation';
              put(d); return;
            }
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
                  // Flag so the server actually sends <ConditionID> on
                  // revise (default = skip, eBay keeps existing).
                  row.condition_changed = true;
                  const can = conditionAllowsDescription(sel.value, allowed);
                  const input = rowTr.querySelector('textarea[data-col="condition_description"],input[data-col="condition_description"]');
                  if (input){ input.disabled = !can; if (!can) input.value=''; }
                  // Welke ConditionDescriptors gelden, hangt af van de conditie.
                  // Zonder dit bleef "Card Condition" een streepje nadat je de
                  // rij op Ungraded zette.
                  refreshDescriptorCells(rowTr, row);
                });
              } else {
                const vals = [
                  '1000-New','1500-New other (see details)','1750-New with defects','2000-Manufacturer refurbished',
                  '2500-Seller refurbished','2750-Like New','3000-Used','4000-Very Good',
                  '5000-Good','6000-Acceptable','7000-For parts or not working'
                ];
                for (const v of vals) sel.appendChild(new Option(v, v));
                sel.value = row[col.key] || '';
                sel.addEventListener('change', () => {
                  row[col.key] = sel.value;
                  row.condition_changed = true;
                  refreshDescriptorCells(rowTr, row);
                });
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

          if (col.type === 'descriptor'){
            // eBay's ConditionDescriptors. Bewust NIET in row.aspects: alles
            // daar gaat mee als <ItemSpecifics> en wordt daar geweigerd.
            // We bewaren het value-ID, niet de naam, want dezelfde waarde
            // heeft per categorie en marketplace een ander ID.
            const did = col.key.slice(9);
            cell.dataset.conddesc = did;
            put(buildDescriptorControl(row, did));
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
      const scope = secOverride ? secOverride.table : document;
      scope.querySelectorAll('input.rowSel').forEach(cb => cb.checked = true);
    }
  }

  function renderTable(rows){
    const grid = $('grid');
    if (!grid){ console.warn('#grid ontbreekt'); return; }
    grid.innerHTML = '';
    catSections = [];
    singleModeActive = false;

    if (!rows || !rows.length){
      grid.innerHTML = '<div style="padding:12px;color:#9bbbc4;">Geen rijen om te tonen.</div>';
      return;
    }

    if (isSingleMode(rows)){
      singleModeActive = true;
      renderSingleModeTables(rows, grid);
      for (const sec of catSections) renderBody(sec);
      buildColumnsDialog();
      buildBulkFieldList();
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
  function _cmpVal(x, key){
    if (key.indexOf('aspects.') === 0){ const nm = key.slice(8); return (x.aspects || {})[nm] || ''; }
    return x[key] || '';
  }

  function sortBy(key){
    let dir = 1;
    if (sortState.key === key) dir = -sortState.dir;
    sortState.key = key; sortState.dir = dir;

    const cmp = (a, b) => {
      const va = _cmpVal(a, key), vb = _cmpVal(b, key);
      const na = parseFloat(va), nb = parseFloat(vb);
      if (!isNaN(na) && !isNaN(nb)) return dir * (na - nb);
      return dir * String(va).localeCompare(String(vb));
    };

    if (singleModeActive){
      for (const sec of catSections){ sec.rows.sort(cmp); renderBody(sec); }
      return;
    }
    lastRows.sort(cmp);
    renderBody();
  }

  function selectedRows(){
    const out = [];
    // single-mode: scan all section tables via __rowObj on each TR
    if (singleModeActive){
      document.querySelectorAll('#grid input.rowSel').forEach(cb => {
        if (cb.checked){ const tr = cb.closest('tr'); if (tr && tr.__rowObj) out.push(tr.__rowObj); }
      });
      return out;
    }
    if (!table || !table.tBodies[0]) return out;
    const trs = table.tBodies[0].rows;
    for (let i=0;i<trs.length;i++){
      const cb = trs[i].querySelector('input.rowSel');
      if (cb && cb.checked) out.push(trs[i].__rowObj || lastRows[i]);
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
  $('btnVariations').addEventListener('click', () => {
    const r = selectedRows().find(x => x && Array.isArray(x.variations) && x.variations.length) || (lastRows || []).find(x => x && Array.isArray(x.variations) && x.variations.length);
    if (r) openVarDlg(r);
    else alert('No variations in current draft.');
  });
  $('varClose').addEventListener('click', closeVarDlg);
  $('varDone').addEventListener('click', closeVarDlg);
  $('varApplyNames').addEventListener('click', applyVarNames);
  $('varAdd').addEventListener('click', addVariation);
  $('varPicName').addEventListener('change', () => {
    if (CURRENT_VAR_ROW) CURRENT_VAR_ROW.variation_picture_name = $('varPicName').value;
  });
  function _escapeRegExp(s){ return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function selectedVarRows(){
    if (!CURRENT_VAR_ROW) return [];
    const vars = CURRENT_VAR_ROW.variations || [];
    const out = [];
    document.querySelectorAll('#varTbody input.varRowSel').forEach(cb => {
      if (!cb.checked) return;
      const idx = parseInt(cb.dataset.varIdx, 10);
      if (!Number.isNaN(idx) && vars[idx]) out.push(vars[idx]);
    });
    return out;
  }

  // If the bulk find/replace produces the same Attr1 value on more than one
  // row (easy to hit when stripping a shared prefix off imported titles),
  // eBay rejects the whole listing as a duplicate variation. Disambiguate
  // by appending " B", " C", ... to repeats instead of letting that happen silently.
  function _disambiguateVarNames(n1Key, editedVars, allVars){
    const seen = {};
    allVars.forEach(v => {
      if (editedVars.includes(v)) return;
      const val = String((v.specifics || {})[n1Key] ?? '').trim();
      if (val) seen[val] = (seen[val] || 0) + 1;
    });
    const letters = 'BCDEFGHIJKLMNOPQRSTUVWXYZ';
    editedVars.forEach(v => {
      v.specifics = v.specifics || {};
      const val = String(v.specifics[n1Key] ?? '').trim();
      if (!val) return;
      const count = seen[val] || 0;
      if (count > 0){
        const letter = letters[count - 1] || ('#' + (count + 1));
        v.specifics[n1Key] = val + ' ' + letter;
      }
      seen[val] = count + 1;
    });
  }

  $('varSelectAll').addEventListener('change', () => {
    const on = $('varSelectAll').checked;
    document.querySelectorAll('#varTbody input.varRowSel').forEach(cb => { cb.checked = on; });
  });
  $('varBulkSkuApply').addEventListener('click', () => {
    if (!CURRENT_VAR_ROW) return;
    const tmpl = $('varBulkSku').value || '';
    if (!tmpl){ alert('Enter a SKU template first.'); return; }
    const vars = selectedVarRows();
    if (!vars.length){ alert('Select at least one row first.'); return; }
    vars.forEach((v, idx) => { v.sku = tmpl.replace(/\{n\}/g, String(idx + 1)); });
    renderVarDlg();
  });
  $('varBulkReplaceApply').addEventListener('click', () => {
    if (!CURRENT_VAR_ROW) return;
    const find = $('varBulkFind').value || '';
    if (!find){ alert('Enter text to find first.'); return; }
    const repl = ($('varBulkReplace').value || '').replace(/\$/g, '$$$$');
    const vars = selectedVarRows();
    if (!vars.length){ alert('Select at least one row first.'); return; }
    const re = new RegExp(_escapeRegExp(find), 'gi');
    vars.forEach(v => {
      v.specifics = v.specifics || {};
      for (const k of Object.keys(v.specifics)){
        v.specifics[k] = String(v.specifics[k] ?? '').replace(re, repl);
      }
    });
    const n1Key = ($('varName1').value || '').trim() || _inferVarNames(CURRENT_VAR_ROW)[0] || 'Option';
    const allVars = CURRENT_VAR_ROW.variations || [];
    _disambiguateVarNames(n1Key, vars, allVars);
    renderVarDlg();
  });

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
      ['title','Title'], ['title_find_replace','Title — Find & Replace'],
      ['sku_template','SKU — Template'],
      ['category_id','Category ID'], ['quantity','Qty'], ['price','Start price'],
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

    const val2 = $('bulkValue2');
    if (val2) val2.style.display = (field === 'title_find_replace') ? 'inline-block' : 'none';

    if (field==='title_find_replace' || field==='sku_template'){
      let ip = current;
      if (ip.tagName.toLowerCase() !== 'input'){
        ip = document.createElement('input'); ip.type='text'; ip.style.minWidth='220px';
        swap(ip);
      }
      ip.value = '';
      ip.placeholder = (field==='title_find_replace')
        ? 'find text (e.g. shared prefix)…'
        : 'template, use {n} for sequence, e.g. SHELF 1-BOX 3 {n}';
      if (val2) val2.value = '';
      return;
    }

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

    let skuCounter = 0;
    for (let r of rows){
      if (field === 'title_find_replace'){
        const find = valRaw || '';
        const val2El = $('bulkValue2');
        const repl = (val2El ? val2El.value : '').replace(/\$/g, '$$$$');
        if (find) r.title = String(r.title || '').replace(new RegExp(_escapeRegExp(find), 'gi'), repl);
      } else if (field === 'sku_template'){
        // Row-level SKU only -- variation SKUs are edited separately in the
        // Variations dialog's own bulk editor, with its own counter, so the
        // two numbering sequences never mix.
        const tmpl = valRaw || '';
        skuCounter += 1;
        r.sku = tmpl.replace(/\{n\}/g, String(skuCounter));
      } else if (field.indexOf('aspects.') === 0){
        const k = field.slice(8); // Aspects: prefer r.aspects; fallback to item_specifics/specifics (dict only)
let asp = r.aspects;
if (!asp || typeof asp !== 'object' || Array.isArray(asp)) asp = null;
if (!asp){
  const cand = r.item_specifics ?? r.specifics ?? r.ItemSpecifics ?? null;
  if (cand && typeof cand === 'object' && !Array.isArray(cand)) asp = cand;
}
r.aspects = asp || {}; r.aspects[k] = valRaw || null;
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
      // Conditie in bulk gewijzigd? Gooi descriptorwaarden weg die bij de
      // nieuwe conditie niet meer horen. renderBody() hieronder tekent de
      // cellen opnieuw, maar ruimt de opgeslagen waarden niet op.
      if (field === 'condition_id'){
        const stored = r.condition_descriptors || {};
        for (const did of Object.keys(stored)){
          if (!descriptorForRow(r, did)) delete stored[did];
        }
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

  // --- Variations editor (MultiListing) ---
  let CURRENT_VAR_ROW = null;
  let VAR_OLD_NAMES = [];

  function _rowHasVars(r){
    return r && Array.isArray(r.variations) && r.variations.length > 0;
  }

  // Backward-compat alias: older builds referenced `ismulti(row)`.
  function ismulti(r){
    return _rowHasVars(r);
  }
  function updateVarButton(){
    const btn = $('btnVariations');
    if(!btn) return;
    const has = (lastRows || []).some(r => _rowHasVars(r));
    btn.style.display = has ? '' : 'none';
    btn.disabled = !has;
    const mb = $('modeBadge');
    if(mb) mb.style.display = has ? '' : 'none';
  }

  function openVarDlg(row){
    if(!_rowHasVars(row)){ alert('This row has no variations.'); return; }
    CURRENT_VAR_ROW = row;
    VAR_OLD_NAMES = Array.isArray(row.variation_names) ? row.variation_names.slice(0) : [];
    $('dlgVars').style.display = 'flex';
    renderVarDlg();
  }
  function closeVarDlg(){
    $('dlgVars').style.display = 'none';
    CURRENT_VAR_ROW = null;
    VAR_OLD_NAMES = [];
    updateVarButton();
    renderBody();
  }

  function _inferVarNames(row){
    const names = Array.isArray(row.variation_names) ? row.variation_names.slice(0) : [];
    if(names.length >= 1) return names;
    const v0 = (row.variations || [])[0] || {};
    const specs = v0.specifics || {};
    const keys = Object.keys(specs);
    if(keys.length) return keys.slice(0,2);
    return ['Option'];
  }

  function applyVarNames(){
    if(!CURRENT_VAR_ROW) return;
    const n1 = ($('varName1').value || '').trim() || 'Option';
    const n2 = ($('varName2').value || '').trim();
    const newNames = n2 ? [n1, n2] : [n1];

    const oldNames = VAR_OLD_NAMES && VAR_OLD_NAMES.length ? VAR_OLD_NAMES.slice(0) : _inferVarNames(CURRENT_VAR_ROW);

    // Remap specifics by position (old[0]->new[0], old[1]->new[1])
    (CURRENT_VAR_ROW.variations || []).forEach(v => {
      v.specifics = v.specifics || {};
      const s = v.specifics;
      const ns = {};
      if(oldNames[0]) ns[newNames[0]] = s[oldNames[0]] ?? s[newNames[0]] ?? '';
      if(newNames.length > 1){
        if(oldNames[1]) ns[newNames[1]] = s[oldNames[1]] ?? s[newNames[1]] ?? '';
      }
      // keep any extra keys that aren't the old name slots
      Object.keys(s).forEach(k=>{
        if(k === oldNames[0] || k === oldNames[1]) return;
        if(k === newNames[0] || k === newNames[1]) return;
        ns[k] = s[k];
      });
      v.specifics = ns;
    });

    CURRENT_VAR_ROW.variation_names = newNames;

    // Update picture name select
    const picSel = $('varPicName');
    const desired = (picSel.value || '').trim();
    if(desired && newNames.includes(desired)) CURRENT_VAR_ROW.variation_picture_name = desired;
    else CURRENT_VAR_ROW.variation_picture_name = newNames[0];

    VAR_OLD_NAMES = newNames.slice(0);
    renderVarDlg();
  }

  function addVariation(){
    if(!CURRENT_VAR_ROW) return;
    const names = _inferVarNames(CURRENT_VAR_ROW);
    const n1 = ($('varName1').value || '').trim() || names[0] || 'Option';
    const n2 = ($('varName2').value || '').trim();
    const specs = {};
    specs[n1] = '';
    if(n2) specs[n2] = '';
    const start = (CURRENT_VAR_ROW.start_price ?? CURRENT_VAR_ROW.price ?? '');
    const qty = (CURRENT_VAR_ROW.quantity ?? CURRENT_VAR_ROW.qty ?? 1);
    (CURRENT_VAR_ROW.variations = CURRENT_VAR_ROW.variations || []).push({
      sku: '',
      // canonical keys (server expects these)
      start_price: start,
      quantity: qty,
      // legacy mirrors (older editor builds)
      price: start,
      qty: qty,
      specifics: specs,
      picture_urls: []
    });
    renderVarDlg();
  }

  function removeVariation(idx){
    if(!CURRENT_VAR_ROW) return;
    const vars = CURRENT_VAR_ROW.variations || [];
    if(idx < 0 || idx >= vars.length) return;
    vars.splice(idx, 1);
    renderVarDlg();
  }

  function renderVarDlg(){
    if(!CURRENT_VAR_ROW) return;

    const names = _inferVarNames(CURRENT_VAR_ROW);
    const n1 = ($('varName1').value || '').trim() || names[0] || 'Option';
    const n2 = ($('varName2').value || '').trim() || (names[1] || '');

    $('varName1').value = n1;
    $('varName2').value = n2;

    $('thA1').textContent = n1;
    $('thA2').textContent = n2 ? n2 : '(none)';

    // Picture attribute options
    const picSel = $('varPicName');
    picSel.innerHTML = '';
    const opts = [n1].concat(n2 ? [n2] : []);
    opts.forEach(o=>{
      const op = document.createElement('option');
      op.value = o; op.textContent = o;
      picSel.appendChild(op);
    });
    const curPic = (CURRENT_VAR_ROW.variation_picture_name || n1).trim();
    if(opts.includes(curPic)) picSel.value = curPic;
    else picSel.value = n1;

    const tbody = $('varTbody');
    tbody.innerHTML = '';

    const vars = CURRENT_VAR_ROW.variations || [];
    vars.forEach((v, idx) => {
      v.specifics = v.specifics || {};
      if(v.specifics[n1] === undefined) v.specifics[n1] = '';
      if(n2 && v.specifics[n2] === undefined) v.specifics[n2] = '';

      const tr = document.createElement('tr');

      // Drag/drop reorder. eBay shows variations in the order they
      // arrive in the AddFixedPriceItem/ReviseFixedPriceItem XML, so
      // rearranging the array here is enough — the server's
      // _variations_xml already preserves array order.
      tr.draggable = true;
      tr.dataset.varIdx = String(idx);
      tr.style.cursor = 'grab';
      tr.addEventListener('dragstart', (e) => {
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', String(idx));
        tr.style.opacity = '0.4';
      });
      tr.addEventListener('dragend', () => { tr.style.opacity = ''; });
      tr.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        tr.style.borderTop = '2px solid var(--ACCENT)';
      });
      tr.addEventListener('dragleave', () => { tr.style.borderTop = ''; });
      tr.addEventListener('drop', (e) => {
        e.preventDefault();
        tr.style.borderTop = '';
        const fromIdx = parseInt(e.dataTransfer.getData('text/plain'), 10);
        const toIdx = parseInt(tr.dataset.varIdx, 10);
        if (Number.isNaN(fromIdx) || Number.isNaN(toIdx) || fromIdx === toIdx) return;
        const arr = CURRENT_VAR_ROW.variations || [];
        const [moved] = arr.splice(fromIdx, 1);
        arr.splice(toIdx, 0, moved);
        renderVarDlg();
      });

      // Selection checkbox (drives the bulk-edit box above)
      const tdSel = document.createElement('td');
      const cbSel = document.createElement('input');
      cbSel.type = 'checkbox';
      cbSel.className = 'varRowSel';
      cbSel.dataset.varIdx = String(idx);
      cbSel.checked = true;
      tdSel.appendChild(cbSel);
      tr.appendChild(tdSel);

      // Drag handle cell (visual hint — actual drag is on the whole tr)
      const tdDrag = document.createElement('td');
      tdDrag.textContent = '☰';
      tdDrag.title = 'Sleep om volgorde te wijzigen';
      tdDrag.style.cursor = 'grab';
      tdDrag.style.color = 'var(--MUTED)';
      tdDrag.style.userSelect = 'none';
      tdDrag.style.padding = '0 6px';
      tr.appendChild(tdDrag);

      function tdInput(val, onChange, widthPx){
        const td = document.createElement('td');
        const inp = document.createElement('input');
        inp.type = 'text';
        inp.value = val ?? '';
        if(widthPx) inp.style.width = widthPx + 'px';
        inp.addEventListener('input', ()=>onChange(inp.value));
        td.appendChild(inp);
        return td;
      }

      tr.appendChild(tdInput(v.sku || '', (x)=>{ v.sku = x; }, 130));
      tr.appendChild(tdInput(v.specifics[n1] || '', (x)=>{ v.specifics[n1] = x; }, 170));

      if(n2){
        tr.appendChild(tdInput(v.specifics[n2] || '', (x)=>{ v.specifics[n2] = x; }, 170));
      } else {
        const td = document.createElement('td');
        td.textContent = '';
        tr.appendChild(td);
      }

      const curPrice = (v.start_price ?? v.price ?? '');
      const curQty   = (v.quantity ?? v.qty ?? '');
      tr.appendChild(tdInput(curPrice, (x)=>{ v.start_price = x; v.price = x; }, 100));
      tr.appendChild(tdInput(curQty,   (x)=>{ v.quantity = x;  v.qty = x;  }, 70));

      // Images
      const tdImg = document.createElement('td');
      const btn = document.createElement('button');
      // Make sure variations also have the legacy alias `pictures` (UI uses it in several places)
      if ((!Array.isArray(v.pictures) || !v.pictures.length) && Array.isArray(v.picture_urls) && v.picture_urls.length){
        v.pictures = v.picture_urls.slice(0);
      }

      const count = (v.pictures || []).length;
      btn.textContent = `Images (${count})`;
      btn.addEventListener('click', ()=>openImageDlg(v));
      tdImg.appendChild(btn);
      tr.appendChild(tdImg);

      // Remove
      const tdRm = document.createElement('td');
      const br = document.createElement('button');
      br.textContent = 'Remove';
      br.className = 'red';
      br.addEventListener('click', ()=>removeVariation(idx));
      tdRm.appendChild(br);
      tr.appendChild(tdRm);

      tbody.appendChild(tr);
    });
  }
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
    const f = $('imgFile').files[0];
    if (!f) { alert('Choose File.'); return; }

    const fd = new FormData();
    fd.append('file', f, f.name);
    fd.append('site', SITE);

    // license-header + fallback als query-param
    const headers = {};
    let url = '/media/eps_upload?site=' + encodeURIComponent(SITE);
    if (LK) {
      headers['X-License-Key'] = LK;
      url += '&lk=' + encodeURIComponent(LK);
    }

    try{
      const r = await fetch(url, { method: 'POST', body: fd, headers });
      if (!r.ok){
        const tx = await r.text();
        throw new Error(tx || ('HTTP ' + r.status));
      }
      const js  = await r.json();
      const urlOut = js.image_url || (js.all_urls && js.all_urls[0]);
      if (urlOut){
        CURRENT_IMG_ROW.picture_urls = (CURRENT_IMG_ROW.picture_urls || []).concat([urlOut]);
        renderImgList();
        renderBody();
      }
    }catch(e){
      alert('Upload failed: ' + (e.message || e));
    }
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

  // ------------------- batch picker -------------------
  // Which batch is on screen, so the list can mark it. Filled by build().
  let CURRENT_DRAFT_ID = null;

  function escB(v){
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function fmtWhen(iso){
    if (!iso) return '';
    try {
      const d = new Date(/Z$/.test(iso) ? iso : (iso + 'Z'));
      if (isNaN(d.getTime())) return iso;
      return d.toLocaleString([], {day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit'});
    } catch(_){ return iso; }
  }

  function openBatches(){
    const list = $('batchList'), note = $('batchNote');
    list.innerHTML = '<div class="muted" style="padding:10px">Loading...</div>';
    note.textContent = '';
    $('dlgBatches').style.display = 'flex';
    getJSON('/web/drafts')
      .then(d => {
        const items = (d && d.drafts) || [];
        if (!items.length){
          list.innerHTML = '<div class="muted" style="padding:10px">No saved batches yet.</div>';
          return;
        }
        list.innerHTML = items.map(it => {
          const active = (CURRENT_DRAFT_ID != null && String(it.id) === String(CURRENT_DRAFT_ID));
          const label = it.title ? it.title : '(untitled batch)';
          const n = Number(it.items || 0);
          const meta = fmtWhen(it.saved_at) + ' - ' + n + (n === 1 ? ' item' : ' items')
                     + (active ? ' - open now' : '');
          return '<div class="batch-row' + (active ? ' active' : '') + '" data-id="' + escB(it.id) + '">'
               + '<div class="batch-main">' + escB(label) + '</div>'
               + '<div class="batch-meta">' + escB(meta) + '</div>'
               + '</div>';
        }).join('');
        note.textContent = 'The last ' + (d.keep || items.length)
                         + ' batches are kept; older ones are removed automatically.';
      })
      .catch(e => {
        list.innerHTML = '<div class="muted" style="padding:10px">Could not load batches: '
                       + escB((e && e.message) || e) + '</div>';
      });
  }

  function closeBatches(){ $('dlgBatches').style.display = 'none'; }

  $('btnBatches').addEventListener('click', openBatches);
  $('batchClose').addEventListener('click', closeBatches);
  $('dlgBatches').addEventListener('click', (ev) => {
    if (ev.target === $('dlgBatches')) { closeBatches(); return; }
    const row = ev.target && ev.target.closest ? ev.target.closest('.batch-row') : null;
    if (!row) return;
    const id = row.getAttribute('data-id');
    if (!id) return;
    closeBatches();
    build('?draft_id=' + encodeURIComponent(id));
  });

  // ------------------- data flow -------------------
  function build(query){
    if (query === undefined) query = '';
    const sep = (query.indexOf('?') >= 0) ? '&' : '?';
    const q2 = query + (LK ? (sep + 'lk=' + encodeURIComponent(LK)) : '');

    status('Loading draft…');
    showLoading('Loading draft…', 'Fetching listings from the server. Larger drafts can take a few seconds.');
    return getJSON('/web/draft' + q2)
      .then(d => {
        SITE     = (d.site     || 'NL').toUpperCase();
        CURRENCY = (d.currency || 'EUR').toUpperCase();
        CURRENT_DRAFT_ID = (d.draft_id != null ? d.draft_id : null);

        console.log('Draft site/currency:', SITE, CURRENCY);

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

// Ensure all taxonomy aspect keys exist (so the editor shows ALL item-specific columns)
try{
  for (const r of lastRows){
    const cat = r.category_id || null;
    if (!cat) continue;
    const m = ASPECT_CACHE[keyCache(cat)] || {};
    r.aspects = r.aspects || {};
    for (const nm in m){
      const base = String(nm||'').trim();
      if (!base) continue;
      const k = base.toLowerCase().startsWith('c:') ? base : ('C:'+base);
      if (r.aspects[k] === undefined) r.aspects[k] = '';
    }
  }
}catch(_){}

        try { showLoading('Rendering rows…', 'Drawing ' + lastRows.length + ' rows. Hang on for the bigger ones.'); } catch(_){}
        renderTable(lastRows);
        status('Loaded ' + lastRows.length + ' rows');
        try { hideLoading(); } catch(_){}

        const bb=document.getElementById('bootBanner');
        if (bb) bb.style.display='none';

        // Show EDIT MODE banner if any row has item_id (= ReviseFixedPriceItem mode)
        try {
          const reviseId = (lastRows || []).map(r => String(r?.item_id ?? '').trim()).find(v => v) || '';
          const rb = document.getElementById('reviseBanner');
          if (rb) {
            if (reviseId) {
              rb.textContent = `✏️ EDIT MODE — revising existing listing ${reviseId}`;
              rb.style.display = 'inline-block';
            } else {
              rb.style.display = 'none';
            }
          }
        } catch(_){}
      })
      .catch(e => {
        status('Error: ' + (e.message||e));
        try { hideLoading(); } catch(_){}
        showErr('Draft laden mislukt: ' + (e.message||e));
      });
  }

  function setPublishOverlayProgress(done, total){
    const bar  = $('pubProg');
    const inner = bar && bar.querySelector('.inner');
    const lbl  = $('pubProgLabel');
    if (!bar || !inner || !total) return;

    const pct = Math.max(0, Math.min(100, Math.round((done * 100) / total)));
    inner.style.width = pct + '%';
    if (lbl) lbl.textContent = pct + '% completed';
  }

  function showPublishOverlay(txt){
    $('pubText').textContent = txt || 'Publishing…';
    const bar  = $('pubProg');
    const inner = bar && bar.querySelector('.inner');
    const lbl  = $('pubProgLabel');
    if (inner) inner.style.width = '0%';
    if (lbl) lbl.textContent = '';
    $('pubOverlay').style.display = 'flex';
  }

  function hidePublishOverlay(){
    $('pubOverlay').style.display = 'none';
  }


  function publish(rows){
    // Quick-post path: validate the inline-policy panel, then inject the
    // fields into every row before sending to /web/publish.
    let _qpFields = null;
    if (_noPolicies) {
      _qpFields = _qpValidate();
      if (!_qpFields) {
        try { document.getElementById('quickPostPanel').scrollIntoView({behavior:'smooth', block:'center'}); } catch(_){}
        status('Quick post setup incomplete — fill in the highlighted fields.');
        return;
      }
      // Persist for the next session so the user does not retype.
      _qpSaveDefaults(SITE, _qpFields);
      for (const r of (rows || [])) {
        if (!r) continue;
        // Don't overwrite per-row values the user may have edited.
        for (const k in _qpFields) {
          if (r[k] === undefined || r[k] === null || r[k] === '') r[k] = _qpFields[k];
        }
      }
    }
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

// Mirror edited aspects back into item_specifics so the server publishes what you see.
const asp2 = r.aspects;
if (asp2 && typeof asp2 === 'object' && !Array.isArray(asp2)){
  if (!o.item_specifics || typeof o.item_specifics !== 'object' || Array.isArray(o.item_specifics)) o.item_specifics = {};
  for (const k in asp2){
    const v = asp2[k];
    if (v == null || String(v).trim() === ''){
      delete o.item_specifics[k];
    } else {
      o.item_specifics[k] = v;
    }
  }
  if (o.specifics == null) o.specifics = o.item_specifics;
}

      const fmt = String(r?.listing_type ?? r?.listingType ?? r?.format ?? '').toLowerCase();
      if (fmt === 'auction'){
        o.quantity = 1;
      }

      // Preserve item_id so ReviseFixedPriceItem works (edit existing listing)
      const eid = String(r?.item_id ?? r?.ItemID ?? r?.itemId ?? '').trim();
      if (eid) o.item_id = eid;

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

    // ---- batching: stuur in kleinere porties naar /web/publish ----
    const BATCH_SIZE = 20;  // kun je later tweaken
    const total      = rows.length;
    let allResults   = [];

    (async () => {
      try {
        for (let i = 0; i < total; i += BATCH_SIZE) {
          const batch      = rows.slice(i, i + BATCH_SIZE);
          const doneAfter  = i + batch.length;
          const batchIndex = (i / BATCH_SIZE) + 1;


          status(`Publishing ${doneAfter}/${total} rows… (batch ${batchIndex})`);
          setPublishOverlayProgress(doneAfter, total);

          const res = await postJSON('/web/publish', {
            site: SITE,
            currency: CURRENCY,
            interval_minutes: interval,
            timezone: clientTZ,
            rows: batch
          });

          if (!res || res.ok !== true) {
            hidePublishOverlay();
            status('Failed');

            const extra =
              (res && (res.detail || res.error) && String(res.detail || res.error)) ||
              'Publish failed (no response).';

            alert(`Publish failed for batch ${batchIndex}.\n\n${extra}`);
            return;
          }

          const items = Array.isArray(res.results) ? res.results : [];
          allResults  = allResults.concat(items);
        }
      } catch (err) {
        console.error(err);
        hidePublishOverlay();
        status('Failed');
        alert('Publish failed (network error while talking to the server).');
        return;
      }

      // ---- alle batches klaar: zelfde resultaatlogica als voorheen ----
      setPublishOverlayProgress(total, total);
      hidePublishOverlay();

      const items = allResults;
      const okN   = items.filter(x => x && x.ok).length;
      const fail  = items.filter(x => !x || x.ok === false);
      const revised = items.filter(x => x && x.ok && x.is_revise).length;
      const created = items.filter(x => x && x.ok && !x.is_revise).length;

      // Markeer geslaagde items als gepubliceerd op de bron-rijen — zodat ze
      // verdwijnen uit de hoofdlijst en niet per ongeluk dubbel ge-upload worden.
      try {
        for (let i = 0; i < items.length && i < rows.length; i++) {
          const r   = rows[i];
          const res = items[i];
          if (r && res && res.ok) {
            r._published = true;
            if (res.item_id) r._published_item_id = res.item_id;
          }
        }
        updatePublishedToggle();
        renderBody();
      } catch (e) { console.warn('mark published failed:', e); }

      let msg = `Published: ${okN}/${items.length} OK.`;
      if (revised > 0 && created > 0) msg += `\n(${revised} revised, ${created} created)`;
      else if (revised > 0) msg += `\n(${revised} existing listing${revised>1?'s':''} revised ✏️)`;
      else if (created > 0) msg += `\n(${created} new listing${created>1?'s':''} created)`;
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

      const page = allScheduled ? 'scheduled' : 'active';
      const url  = `https://www.ebay.${tld}/sh/lst/${page}`;

      if (confirm(`Open your ${page} listings on eBay ${site}?`)) {
        window.open(url, '_blank', 'noopener');
      }
    })();
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
        rows.forEach(r => {
          r.description_html = v;
          // User-applied description — mark so the server sends the
          // new content on revise (default is to skip <Description>).
          r.description_changed = true;
        });
        document.body.removeChild(dlg);
        renderBody();
      }
    });
  }
  document.getElementById('editHtml').addEventListener('click', editHtmlSelected);

  // ------------------- events (toolbar) -------------------
  // Publish ALL: alleen rijen die nog niet gepubliceerd zijn deze sessie
  $('publishAll').addEventListener('click', () => publish(lastRows.filter(r => !(r && r._published))));
  $('publishSel').addEventListener('click', () => publish(selectedRows()));

  // Toggle voor zichtbaarheid van al gepubliceerde rijen
  const _btnTP = document.getElementById('btnTogglePublished');
  if (_btnTP) {
    _btnTP.addEventListener('click', () => {
      showPublishedRows = !showPublishedRows;
      updatePublishedToggle();
      renderBody();
    });
  }
  $('toggleHidden').checked = SHOW_HIDDEN;
  $('toggleHidden').addEventListener('change', () => { SHOW_HIDDEN = $('toggleHidden').checked; renderTable(lastRows); });
  $('checkAll').checked = true;
  $('checkAll').addEventListener('change', () => {
    const on = $('checkAll').checked;
    document.querySelectorAll('input.rowSel').forEach(cb => cb.checked = on);
  });

  // Shift-click range select on row checkboxes
  let _lastCheckedCb = null;
  document.addEventListener('click', e => {
    const cb = e.target;
    if (!cb || cb.type !== 'checkbox' || !cb.classList.contains('rowSel')) return;
    if (e.shiftKey && _lastCheckedCb && _lastCheckedCb !== cb) {
      const all = Array.from(document.querySelectorAll('input.rowSel'));
      const a = all.indexOf(_lastCheckedCb), b = all.indexOf(cb);
      if (a !== -1 && b !== -1) {
        const lo = Math.min(a, b), hi = Math.max(a, b);
        for (let i = lo; i <= hi; i++) all[i].checked = cb.checked;
      }
    }
    _lastCheckedCb = cb;
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

# How many batches we keep per license. The picker shows five at a time and
# scrolls to the rest; everything older is dropped on the next save. Drafts are
# fat (a few hundred KB each, occasionally over a megabyte), so an unbounded
# history costs real disk for a history nobody opens.
_DRAFT_KEEP = 20


def _summarize_draft_payload(data: Any) -> tuple:
    """(item_count, title_hint) for the batch picker."""
    try:
        if isinstance(data, str):
            data = json.loads(data or "{}")
        rows = (data or {}).get("rows") or []
        first = rows[0] if rows else {}
        title = str(first.get("title") or first.get("clean_title") or "").strip()
        return len(rows), title[:120]
    except Exception:
        return 0, ""


@router.get("/web/drafts")
def web_drafts(request: Request, lk: Optional[str] = Query(None)):
    """List this license's recent batches for the picker in the editor.

    Returns summaries only — never the payload, see db.draft_list_summaries.
    """
    lk_eff = (
        getattr(request.state, "license_key", "")
        or request.headers.get("X-License-Key")
        or lk
        or ""
    ).strip()
    if not lk_eff:
        raise HTTPException(status_code=403, detail="License required")

    bucket = _draft_bucket_for_lk(lk_eff)
    from . import db as _db

    out = []
    for row in _db.draft_list_summaries(bucket, limit=_DRAFT_KEEP):
        count = row.get("item_count")
        title = row.get("title_hint")
        if count is None:
            # Saved before the picker existed: summarize once and store it, so
            # the next listing does not have to read this payload again.
            full = _db.draft_get(row["id"]) or {}
            count, title = _summarize_draft_payload(full.get("data"))
            try:
                _db.draft_set_summary(row["id"], count, title)
            except Exception:
                pass
        out.append({
            "id": row.get("id"),
            "name": row.get("name"),
            "saved_at": row.get("updated_at") or row.get("created_at"),
            "items": int(count or 0),
            "title": title or "",
            "size_kb": round(float(row.get("size_bytes") or 0) / 1024.0, 1),
        })
    return {"drafts": out, "keep": _DRAFT_KEEP}


@router.get("/web/draft")
def web_draft(request: Request, path: Optional[str] = Query(None), lk: Optional[str] = Query(None),
              draft_id: Optional[int] = Query(None)):
    """
    Draft laden — database-backed.
    Falls back to filesystem for legacy drafts that haven't been migrated yet.

    Without draft_id you get the most recent batch (the old behaviour). With
    draft_id you get that specific batch, provided it belongs to this license.
    """
    _ = path
    lk_eff = (
        getattr(request.state, "license_key", "")
        or request.headers.get("X-License-Key")
        or lk
        or ""
    ).strip()

    bucket = _draft_bucket_for_lk(lk_eff)

    # Try database first
    from . import db as _db
    if draft_id:
        candidate = _db.draft_get(int(draft_id))
        # The id is a plain auto-increment integer, so anyone could guess a
        # neighbour's. Only serve it when it sits in this license's bucket.
        if not candidate or candidate.get("bucket") != bucket:
            raise HTTPException(status_code=404, detail="Batch not found for this license.")
        draft = candidate
    else:
        draft = _db.draft_latest(bucket)
    if draft:
        try:
            data = json.loads(draft["data"]) if isinstance(draft["data"], str) else draft["data"]
        except Exception:
            data = {}
        rows = data.get("rows") or []
        site = (data.get("site") or "NL").upper()
        currency = (data.get("currency") or "EUR").upper()
        return {"rows": rows, "site": site, "currency": currency,
                "path": draft.get("name", "db"), "draft_id": draft.get("id"),
                "saved_at": draft.get("updated_at") or draft.get("created_at")}

    # Fallback: legacy filesystem drafts
    chosen = _latest_draft_path_for(lk_eff)
    if not chosen or not os.path.exists(chosen):
        detail = "Geen draft gevonden"
        if lk_eff:
            detail += " for this license"
        raise HTTPException(status_code=404, detail=detail + ".")

    with open(chosen, "r", encoding="utf-8") as f:
        data = json.load(f) or {}
    rows = data.get("rows") or []
    site = (data.get("site") or "NL").upper()
    currency = (data.get("currency") or "EUR").upper()
    return {"rows": rows, "site": site, "currency": currency, "path": os.path.basename(chosen)}

@router.post("/web/draft/upload")
def web_draft_upload(request: Request, payload: Dict[str, Any]):
    """
    Ontvangt draft JSON van de client en slaat op in de database.
    """
    lk = (
        getattr(request.state, "license_key", "")
        or request.headers.get("X-License-Key")
        or (payload or {}).get("license_key")
        or ""
    ).strip()
    if not lk:
        raise HTTPException(status_code=403, detail="License required")
    bucket = _draft_bucket_for_lk(lk)
    import time
    ts = time.strftime("%Y%m%d-%H%M%S")
    body = dict(payload or {})
    body.pop("license_key", None)

    from . import db as _db
    count, title = _summarize_draft_payload(body)
    draft_id = _db.draft_save(bucket=bucket, name=f"draft-{ts}", data=body,
                              item_count=count, title_hint=title)
    # Keep the history bounded; the picker only reaches back _DRAFT_KEEP batches.
    try:
        _db.draft_prune_bucket(bucket, keep=_DRAFT_KEEP)
    except Exception:
        pass
    return {"ok": True, "path": f"draft-{ts}", "bucket": bucket, "draft_id": draft_id}

@router.get("/web/conditions_dummy")
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
