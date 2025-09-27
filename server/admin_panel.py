# server/admin_panel.py
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Dict, Any, List, Optional
import time, json

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

router = APIRouter(prefix="/admin", tags=["admin"])

# ---- simpele guard (token in query of header) ----
ADMIN_UI_TOKEN = "joep"  # zet dit uit config/env in jouw project

def _require_admin(req: Request):
    if not ADMIN_UI_TOKEN:
        return
    tok = (
        req.query_params.get("token")
        or req.headers.get("x-admin-token")
        or req.cookies.get("admin_token")
        or ""
    ).strip()
    if tok != ADMIN_UI_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")

# ---- helpers om store te lezen/schrijven ----
def _read_store() -> Dict[str, Any]:
    txt = LICENSE_FILE.read_text("utf-8").strip() if LICENSE_FILE.exists() else ""
    return json.loads(txt) if txt else {}

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
    # 3) match op opgeslagen _fingerprint (als aanwezig)
    for k, rec in data.items():
        fp = (rec.get("_fingerprint") or "").lower()
        if fp and (fp == il or fp.startswith(il) or il.startswith(fp)):
            return k
    raise ValueError("license id not found")

# ----------------- admin UI -----------------
@router.get("/ui")
def admin_ui(req: Request):
    _require_admin(req)
    html = """<!doctype html>
<meta charset="utf-8">
<title>Joepienator – Admin</title>
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
    <div class="row">
      <input id="q" placeholder="Zoek (email, plan, fingerprint…)" style="min-width:280px">
      <button onclick="loadList()">Laden</button>
      <button class="secondary" onclick="document.getElementById('q').value='';loadList()">Clear</button>
    </div>
    <div style="overflow:auto; max-height: 54vh; margin-top:10px;">
      <table id="tbl"><thead>
        <tr>
          <th>Owner</th>
          <th>Plan / Status</th>
          <th>Expires</th>
          <th>Ebay users & limits</th>
          <th>Fingerprint</th>
        </tr></thead><tbody></tbody></table>
    </div>
  </section>

  <section>
    <h2>Upsert (met plain key)</h2>
    <div class="row">
      <input id="key" placeholder="Plain key">
      <input id="plan" placeholder="Plan (basic/pro)" value="basic" style="width:120px">
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
</main>
<script>
  const TOKEN = new URLSearchParams(location.search).get('token') || '';
  document.getElementById('tokinfo').textContent = TOKEN ? ('token=' + TOKEN) : '(geen token)';

  async function j(url, method='GET', body=null) {
    const h = {'Content-Type':'application/json'};
    let u = url;
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

async function loadList(){
  try{
    const q = document.getElementById('q').value.trim();
    const data = await j('/admin/licenses' + (q ? ('?q=' + encodeURIComponent(q)) : ''));
    const tb = document.querySelector('#tbl tbody'); 
    tb.innerHTML='';

    for (const r of data){
      const tr = document.createElement('tr');

      const owner = (r.owner_email || r.owner_name || '—');
      const plan  = (r.plan || '—') + ' / ' + (r.status || 'active');
      const exp   = r.expires_at || '—';

      const idKey = r._hmac || r.id || r.key || '';
      const fp    = r._fingerprint || (idKey ? idKey.slice(0,12) : '—');

      const users = r.allowed_ebay_users || [];             // ← eerst usernames
      const ids   = (r.allowed_identity_ids ?? null);       // null/undefined of []
      const map   = r.identity_usernames || {};             // { identityId: username }

      const showUsersFirst = users.length > 0;
      const max   = parseInt(r.max_accounts || '1', 10);
      const active = showUsersFirst ? users.length : (Array.isArray(ids) ? ids.length : 0);

      const tdOwner = document.createElement('td'); tdOwner.textContent = owner;
      const tdPlan  = document.createElement('td'); tdPlan.textContent  = plan;
      const tdExp   = document.createElement('td'); tdExp.textContent   = exp;

      const tdUsers = document.createElement('td');

      // builders met Detach-knoppen
      const usersHtml = users.length
        ? users.map(u => `${u} <button onclick="detachUser('${idKey}','${u}')">Detach</button>`).join('<br>')
        : '<span class="muted">—</span>';

      const identitiesHtml = (Array.isArray(ids) && ids.length > 0)
        ? ids.map(id => {
            const label = map[id] || (id ? id.slice(0,12) : '—'); // username tonen; fallback: verkort id
            return `${label} <button onclick="detachIdentity('${idKey}','${id}')">Detach</button>`;
          }).join('<br>')
        : '<span class="muted">—</span>';

      tdUsers.innerHTML = `
        <div>
          ${ showUsersFirst ? usersHtml : identitiesHtml }
        </div>
        <div style="margin-top:6px">
          <small>Active: ${active} / ${max}</small>
          &nbsp;
          <input id="mx-${fp}" type="number" min="1" value="${max}" style="width:90px">
          <button onclick="setMax('${idKey}','mx-${fp}')">Set</button>
        </div>
      `;

      const tdFp = document.createElement('td'); tdFp.className='mono'; tdFp.textContent = fp;

      tr.appendChild(tdOwner);
      tr.appendChild(tdPlan);
      tr.appendChild(tdExp);
      tr.appendChild(tdUsers);
      tr.appendChild(tdFp);
      tb.appendChild(tr);
    }
  } catch(e){
    alert('Load failed: ' + (e && e.message ? e.message : e));
  }
}

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
</script>
"""
    return HTMLResponse(html)

# ----------------- admin endpoints -----------------

@router.get("/licenses")
def list_licenses(req: Request, q: Optional[str] = None) -> List[Dict[str, Any]]:
    _require_admin(req)
    data = _read_store()
    out: List[Dict[str, Any]] = []
    ql = (q or "").strip().lower()

    for k, rec in data.items():
        row = {
            "plan": rec.get("plan"),
            "status": rec.get("status"),
            "expires_at": rec.get("expires_at"),
            "owner_email": rec.get("owner_email"),
            "owner_name": rec.get("owner_name"),
            "allowed_identity_ids": rec.get("allowed_identity_ids") or None,
            "identity_usernames": rec.get("identity_usernames") or {},
            "max_accounts": rec.get("max_accounts") or 1,
            "allowed_ebay_users": rec.get("allowed_ebay_users") or [],
            "_fingerprint": rec.get("_fingerprint") or (k[:12]),
            "_hmac": k,  # ← voor acties gebruiken we deze
        }
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
    rec = upsert_license_plain(
        plain_key=plain,
        plan=(payload.get("plan") or None),
        expires_at_iso_utc=expires_at_iso_utc,
        status=(payload.get("status") or None),
        owner_email=(payload.get("owner_email") or None),
        owner_name=(payload.get("owner_name") or None),
        max_accounts=int(payload.get("max_accounts") or 1),
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

    rec = data.get(key) or {}
    for fld in ["plan", "expires_at", "status", "owner_email", "owner_name"]:
        val = payload.get(fld)
        if val is not None and val != "":
            rec[fld] = val
    if (payload.get("max_accounts") or "").strip():
        try:
            rec["max_accounts"] = int(payload.get("max_accounts"))
        except Exception:
            pass

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
    return {"ok": True}

# --------- NIEUW: detach user & set max (id of plain_key) ---------
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
    # verwijder uit allowed_identity_ids
    ids = rec.get("allowed_identity_ids") or []
    rec["allowed_identity_ids"] = [x for x in ids if x != iid]
    # verwijder eventuele labelmapping
    m = rec.get("identity_usernames")
    if isinstance(m, dict) and iid in m:
        del m[iid]
        rec["identity_usernames"] = m

    data[key] = rec
    _write_store(data)
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

    # 1) als store-helper bestaat en plain_key is meegegeven → gebruik helper
    if plain and _store_detach_ebay_user:
        rec = _store_detach_ebay_user(plain, user)  # type: ignore
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
