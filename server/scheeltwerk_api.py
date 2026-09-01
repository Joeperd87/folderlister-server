# server/scheeltwerk_api.py — Scheeltwerk.nl API endpoints
# Separate from Folderlister. Mounted as a router in app.py.

from __future__ import annotations
import os, json, time, re, uuid, html
from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
import requests as http_requests

from . import db as _db
from .license_store import fingerprint

router = APIRouter(prefix="/web/scheeltwerk", tags=["scheeltwerk"])


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    xf = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xf:
        return xf.split(",")[0].strip()
    return (request.client.host if request.client else "unknown")


def _resend_mail(to: str, subject: str, html: str, from_addr: str = "Joep Litjens <joep@scheeltwerk.nl>") -> bool:
    """Send email via Resend API. Returns True on success."""
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        return False
    try:
        r = http_requests.post("https://api.resend.com/emails", timeout=15,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"from": from_addr, "to": [to], "subject": subject, "html": html})
        return r.status_code < 300
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# BRAINSTORM INTAKE
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/brainstorm")
async def scheeltwerk_brainstorm(request: Request):
    """Intake for brainstorm requests from scheeltwerk.nl."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="Invalid JSON")

    naam = str(body.get("naam") or "").strip()
    email = str(body.get("email") or "").strip()
    if not naam or not email:
        raise HTTPException(400, detail="Naam en e-mailadres zijn verplicht.")

    # Log the lead
    _db.log_event("scheeltwerk_brainstorm", ip_hash=fingerprint(_client_ip(request)), meta={
        "naam": naam,
        "email": email,
        "bedrijf": str(body.get("bedrijf") or "").strip(),
        "website": str(body.get("website") or "").strip(),
        "vastlopen": str(body.get("vastlopen") or "").strip(),
        "tools": str(body.get("tools") or "").strip(),
        "contact_voorkeur": str(body.get("contact_voorkeur") or "").strip(),
    })

    # Notify Joep
    bedrijf = str(body.get("bedrijf") or "").strip()
    vastlopen = str(body.get("vastlopen") or "").strip()
    _resend_mail(
        to="joep@scheeltwerk.nl",
        subject=f"Nieuwe brainstorm aanvraag: {naam} ({bedrijf})",
        html=f"""<h2>Nieuwe brainstorm aanvraag via scheeltwerk.nl</h2>
<p><strong>Naam:</strong> {naam}<br>
<strong>E-mail:</strong> {email}<br>
<strong>Bedrijf:</strong> {bedrijf}<br>
<strong>Website:</strong> {str(body.get('website') or '-')}<br>
<strong>Contact voorkeur:</strong> {str(body.get('contact_voorkeur') or '-')}<br>
<strong>Tools:</strong> {str(body.get('tools') or '-')}</p>
<p><strong>Waar loopt deze persoon op vast:</strong><br>{vastlopen or '-'}</p>"""
    )

    # Send confirmation to the requester
    _resend_mail(
        to=email,
        subject="Je brainstorm-aanvraag is ontvangen \u2014 Scheeltwerk",
        html=f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1d21">
<h2 style="color:#e07830">Bedankt, {naam}!</h2>
<p>Je brainstorm-aanvraag is ontvangen. Ik neem binnen 1-2 werkdagen contact op om een moment in te plannen.</p>
<p>Geen pitch, gewoon een goed gesprek over waar werk scheelt.</p>
<p style="margin-top:24px;color:#4a5060;font-size:14px">\u2014 Joep Litjens<br>scheeltwerk.nl</p>
</div>"""
    )

    return {"ok": True}


# ───────────────────────────────────────────────────────────────────────────
# SCAN CACHE (SQLite, shared across uvicorn workers)
# ───────────────────────────────────────────────────────────────────────────

_CACHE_TABLE_READY = False


def _ensure_cache_table() -> None:
    global _CACHE_TABLE_READY
    if _CACHE_TABLE_READY:
        return
    try:
        conn = _db.get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scheeltwerk_scan_cache (
                token TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                data_json TEXT NOT NULL
            )
        """)
        conn.commit()
        _CACHE_TABLE_READY = True
    except Exception:
        pass


def _cache_set(token: str, data: Dict[str, Any]) -> None:
    _ensure_cache_table()
    try:
        conn = _db.get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO scheeltwerk_scan_cache (token, ts, data_json) VALUES (?, ?, ?)",
            (token, time.time(), json.dumps(data, ensure_ascii=False)),
        )
        cutoff = time.time() - 3600
        conn.execute("DELETE FROM scheeltwerk_scan_cache WHERE ts < ?", (cutoff,))
        conn.commit()
    except Exception:
        pass


def _cache_get(token: str) -> Optional[Dict[str, Any]]:
    _ensure_cache_table()
    try:
        conn = _db.get_conn()
        row = conn.execute(
            "SELECT ts, data_json FROM scheeltwerk_scan_cache WHERE token = ?",
            (token,),
        ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    ts = row[0] if not hasattr(row, "keys") else row["ts"]
    data_json = row[1] if not hasattr(row, "keys") else row["data_json"]
    if time.time() - ts > 3600:
        return None
    try:
        return json.loads(data_json)
    except Exception:
        return None


# ───────────────────────────────────────────────────────────────────────────
# WEBSITE SCAN — prompt focused on site-observable signals (leads + conversion)
# ───────────────────────────────────────────────────────────────────────────

_SCAN_SYSTEM = """Je bent een scherpe digitale strateeg die in 30 seconden een website beoordeelt op concrete lead- en conversiekansen.

BELANGRIJK: je output mag ALLEEN gebaseerd zijn op wat zichtbaar is op de website. Niet op aannames over hoe het bedrijf intern werkt. Niet op speculatieve pijnpunten. Geen claims over CRM, interne planning, backoffice of teamcoordinatie.

Focus uitsluitend op:
- leadgeneratie
- conversieverbetering op de website
- interactieve website-tools of paginas die passen bij het aanbod
- duidelijke drempels of gemiste kansen in de funnel

Toegestane observaties op basis van de website:
- wat het aanbod is
- voor wie
- welke koopdrempels zichtbaar zijn
- informatiegebrek op de pagina
- offerte-frictie
- keuze-onzekerheid bij bezoekers
- gebrek aan hulpmiddelen in de klantreis
- onduidelijke CTA-structuur
- weinig segmentatie of intake

Geef exact de volgende output:

1. "observatie" - 1 tot 3 zinnen over wat opvalt aan de site, doelgroep en gemiste lead- of conversiekans. Nuchter, geloofwaardig, alleen gebaseerd op wat zichtbaar is. Geen marketingtaal.

2. "idee_1" - een concreet interactief website-idee of lead magnet. Denk aan: calculator, keuzehulp, intake tool, planner, configurator, quick scan, checklist, offertehulp, vergelijker, beslishulp. Met velden: titel, type, wat_het_doet, waarde, waarom_deze_site, hoe_het_werkt_globaal, volgende_stap.

3. "idee_2" - een conversie- of funnelverbetering op de site. Bijvoorbeeld: slimmer formulier, beter CTA-pad, landingspagina-concept, keuzehulp, trust-verbetering, offertestap, segmentatieflow, inspiratie-naar-offerte-flow. Met velden: titel, type, wat_het_verbetert, waarde, waarom_deze_site, hoe_het_werkt_globaal, volgende_stap.

4. "extra_ideeen" - 4 tot 6 aanvullende richtingen als korte spar-ideeen. Elk met titel + exact 1 regel omschrijving. Moeten onderling verschillend zijn en aanvullend voelen - geen herhaling van idee_1 en idee_2.

Verboden:
- doen alsof je interne bedrijfsproblemen zeker weet
- speculeren over backoffice / CRM / personeelsplanning / team-coordinatie
- overdreven zinnen als "dit sluit perfect aan"
- te vaak "specifiek voor deze sector" als dat niet bijzonder is
- generieke AI-buzzwords
- algemene business-ideeen zonder koppeling aan de site
- safe standaard-suggesties (chatbot, generieke efficiencycalculator, factuurverwerking)

Kwaliteit:
- scherp
- concreet
- geloofwaardig
- commercieel interessant
- site-specifiek
- geen consultant-jargon
- "dit zou echt op deze site kunnen werken"

Tone of voice:
- nuchter, slim, helder
- alsof een scherpe digitale strateeg de site bekijkt en meteen 2 tot 6 bruikbare kansen ziet
- Nederlands, praktisch

Controleer voor je antwoord: is elk idee echt afgeleid van wat ik op de site zie? Zou dit net zo goed op 50 andere sites passen? Zo ja: herschrijf tot het scherp aansluit."""

_SCAN_SCHEMA = {
    "type": "object",
    "properties": {
        "observatie": {"type": "string"},
        "idee_1": {
            "type": "object",
            "properties": {
                "titel": {"type": "string"},
                "type": {"type": "string"},
                "wat_het_doet": {"type": "string"},
                "waarde": {"type": "string"},
                "waarom_deze_site": {"type": "string"},
                "hoe_het_werkt_globaal": {"type": "string"},
                "volgende_stap": {"type": "string"},
            },
            "required": ["titel", "type", "wat_het_doet", "waarde", "waarom_deze_site", "hoe_het_werkt_globaal", "volgende_stap"],
            "additionalProperties": False,
        },
        "idee_2": {
            "type": "object",
            "properties": {
                "titel": {"type": "string"},
                "type": {"type": "string"},
                "wat_het_verbetert": {"type": "string"},
                "waarde": {"type": "string"},
                "waarom_deze_site": {"type": "string"},
                "hoe_het_werkt_globaal": {"type": "string"},
                "volgende_stap": {"type": "string"},
            },
            "required": ["titel", "type", "wat_het_verbetert", "waarde", "waarom_deze_site", "hoe_het_werkt_globaal", "volgende_stap"],
            "additionalProperties": False,
        },
        "extra_ideeen": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "titel": {"type": "string"},
                    "regel": {"type": "string"},
                },
                "required": ["titel", "regel"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["observatie", "idee_1", "idee_2", "extra_ideeen"],
    "additionalProperties": False,
}


def _fetch_site_text(url: str) -> str:
    try:
        r = http_requests.get(url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (compatible; ScheeltwerkBot/1.0; +https://scheeltwerk.nl)"
        })
        r.raise_for_status()
        html_text = r.text[:15000]
        text = re.sub(r"<script[^>]*>.*?</script>", " ", html_text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()[:4000]
    except Exception as exc:
        raise HTTPException(400, detail={"message": f"Website niet bereikbaar: {str(exc)[:100]}"})
    if len(text) < 50:
        raise HTTPException(400, detail={"message": "Niet genoeg inhoud gevonden op deze website."})
    return text


def _run_llm_scan(url: str, text: str, domain: str) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(503, detail={"message": "AI service niet beschikbaar."})
    try:
        from openai import OpenAI as _OpenAI
    except ImportError:
        raise HTTPException(503, detail={"message": "AI library niet beschikbaar."})

    oai = _OpenAI(api_key=api_key)
    try:
        resp = oai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _SCAN_SYSTEM},
                {"role": "user", "content": f"Website: {domain}\nURL: {url}\n\nInhoud van de website:\n\n{text}"},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "scheeltwerk_scan_result",
                    "strict": True,
                    "schema": _SCAN_SCHEMA,
                },
            },
            temperature=0.3,
        )
        return json.loads(resp.choices[0].message.content)
    except Exception as exc:
        raise HTTPException(502, detail={"message": f"Analyse mislukt: {str(exc)[:100]}"})


def _build_idea_card(idea: Dict[str, Any], *, is_conversie: bool = False, border_color: str = "#e07830") -> str:
    label = "Conversie" if is_conversie else "Lead-tool"
    label_bg = "#1a1d21" if is_conversie else "#fdf0e6"
    label_fg = "#fff" if is_conversie else "#b35a18"
    werking_label = "Wat het verbetert" if is_conversie else "Wat het doet"
    werking_value = idea.get("wat_het_verbetert" if is_conversie else "wat_het_doet", "")
    return f"""
<div style="margin-bottom:28px;border-left:4px solid {border_color};padding-left:16px;">
  <div style="margin-bottom:8px">
    <span style="display:inline-block;padding:3px 10px;border-radius:999px;background:{label_bg};color:{label_fg};font-size:11px;font-weight:700;text-transform:uppercase;margin-right:6px">{label}</span>
    <span style="display:inline-block;padding:3px 10px;border-radius:999px;background:#f4f3f0;color:#4a5060;font-size:11px;font-weight:700;text-transform:uppercase">{idea.get('type', '')}</span>
  </div>
  <h3 style="margin:0 0 10px;color:#1a1d21;font-size:1.2rem">{idea.get('titel', '')}</h3>
  <p style="color:#4a5060;margin:0 0 10px"><strong>{werking_label}:</strong> {werking_value}</p>
  <p style="color:#4a5060;margin:0 0 10px"><strong>Waarde:</strong> {idea.get('waarde', '')}</p>
  <p style="color:#4a5060;margin:0 0 10px"><strong>Waarom dit past bij deze site:</strong> {idea.get('waarom_deze_site', '')}</p>
  <p style="color:#4a5060;margin:0 0 10px"><strong>Hoe het globaal werkt:</strong> {idea.get('hoe_het_werkt_globaal', '')}</p>
  <p style="color:#4a5060;margin:0"><strong>Eerste logische stap:</strong> {idea.get('volgende_stap', '')}</p>
</div>"""


def _build_extra_list(extra: list) -> str:
    if not extra:
        return ""
    items = ""
    for item in extra[:6]:
        titel = item.get("titel", "").strip()
        regel = item.get("regel", "").strip()
        if not titel:
            continue
        items += f'<li style="margin-bottom:8px"><strong>{titel}</strong> &mdash; <span style="color:#4a5060">{regel}</span></li>'
    if not items:
        return ""
    return f"""
<div style="margin-top:28px;padding:18px;background:#faf8f4;border:1px solid #d8d4cc;border-radius:8px">
  <p style="margin:0 0 12px;font-size:.95rem;font-weight:700;color:#1a1d21;text-transform:uppercase;letter-spacing:.04em">Extra denkrichtingen</p>
  <ul style="margin:0;padding-left:18px;color:#1a1d21;font-size:.92rem;line-height:1.5">{items}</ul>
</div>"""


def _build_customer_email(result: Dict[str, Any], domain: str) -> str:
    observatie = result.get("observatie", "")
    idee_1 = result.get("idee_1") or {}
    idee_2 = result.get("idee_2") or {}
    extra = result.get("extra_ideeen") or []

    card_1 = _build_idea_card(idee_1, is_conversie=False, border_color="#e07830")
    card_2 = _build_idea_card(idee_2, is_conversie=True, border_color="#1a1d21")
    extra_html = _build_extra_list(extra)

    return f"""<div style="font-family:sans-serif;max-width:640px;margin:0 auto;color:#1a1d21">
<h1 style="color:#e07830;margin-bottom:8px">Scheeltwerk site-scan voor {domain}</h1>
<p style="color:#4a5060;margin-bottom:24px;font-size:.98rem;line-height:1.5">{observatie}</p>

{card_1}

{card_2}

{extra_html}

<div style="margin-top:32px;padding:24px;background:#1a1d21;border-radius:12px;text-align:center">
  <h3 style="color:#fff;margin:0 0 8px">Een van deze kansen laten bouwen?</h3>
  <p style="color:rgba(255,255,255,.7);margin:0 0 16px;font-size:14px">Plan een gratis brainstorm. Dan bespreken we hoe je dit concreet in je website krijgt.</p>
  <a href="https://scheeltwerk.nl/brainstorm" style="display:inline-block;padding:12px 28px;background:#e07830;color:#fff;border-radius:8px;text-decoration:none;font-weight:700">Plan een brainstorm</a>
</div>

<p style="margin-top:24px;color:#4a5060;font-size:13px">&mdash; Joep Litjens<br>scheeltwerk.nl</p>
</div>"""


def _build_admin_email(result: Dict[str, Any], domain: str, url: str, email: str, naam: str) -> str:
    observatie = result.get("observatie", "")
    idee_1 = result.get("idee_1") or {}
    idee_2 = result.get("idee_2") or {}
    extra = result.get("extra_ideeen") or []

    card_1 = _build_idea_card(idee_1, is_conversie=False, border_color="#e07830")
    card_2 = _build_idea_card(idee_2, is_conversie=True, border_color="#1a1d21")
    extra_html = _build_extra_list(extra)

    return f"""<div style="font-family:sans-serif;max-width:720px;margin:0 auto;color:#1a1d21">
<div style="background:#fdf0e6;padding:16px;border-radius:8px;margin-bottom:24px">
  <p style="margin:0;font-size:13px;color:#4a5060"><strong>Admin copy voor {domain}</strong></p>
  <p style="margin:4px 0 0;font-size:13px;color:#4a5060">Klant: {naam or '(geen naam)'} &lt;{email}&gt; &middot; URL: {url}</p>
</div>
<h1 style="color:#e07830;margin-bottom:8px">{domain}</h1>
<p style="color:#4a5060;margin-bottom:24px">{observatie}</p>

{card_1}

{card_2}

{extra_html}

<p style="margin-top:24px;color:#9aa0aa;font-size:12px">Dit is dezelfde output die de klant heeft ontvangen.</p>
</div>"""


def _send_scan_emails_bg(result, domain, url, email, naam):
    """Background task: build + send both emails after the HTTP response is returned."""
    try:
        customer_html = _build_customer_email(result, domain)
        _resend_mail(to=email, subject=f"Site-scan: 2 kansen voor {domain}", html=customer_html)
    except Exception:
        pass
    try:
        admin_html = _build_admin_email(result, domain, url, email, naam)
        _resend_mail(
            to="jlitjens@gmail.com",
            subject=f"[ADMIN] Scan {domain} ({email})",
            html=admin_html,
        )
    except Exception:
        pass


# ───────────────────────────────────────────────────────────────────────────
# TWO-STEP ENDPOINTS: /preview-scan + /mail-uitwerking
# ───────────────────────────────────────────────────────────────────────────

@router.post("/preview-scan")
async def scheeltwerk_preview_scan(request: Request):
    """Step 1: URL only. Returns observatie + 2 idea previews + scan_token."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail={"message": "Invalid JSON"})
    url = str(body.get("url") or "").strip()
    if not url:
        raise HTTPException(400, detail={"message": "Website URL is verplicht."})
    if not url.startswith("http"):
        url = "https://" + url

    ip = _client_ip(request)
    ip_key = fingerprint(ip)
    hour_ago = time.time() - 3600
    conn = _db.get_conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM request_log WHERE log_type=? AND ts>? AND meta LIKE ?",
        ("scheeltwerk_preview", hour_ago, f"%{ip_key}%"),
    ).fetchone()[0]
    if count >= 10:
        raise HTTPException(429, detail={"message": "Te veel scans vanaf dit IP. Probeer later opnieuw."})

    try:
        domain = url.split("//")[-1].split("/")[0].replace("www.", "")
    except Exception:
        domain = url

    text = _fetch_site_text(url)
    result = _run_llm_scan(url, text, domain)

    token = uuid.uuid4().hex
    _cache_set(token, {
        "url": url,
        "domain": domain,
        "result": result,
        "ip_key": ip_key,
    })

    _db.log_event("scheeltwerk_preview", ip_hash=ip_key, meta={
        "url": url, "domain": domain,
    })

    idee_1 = result.get("idee_1") or {}
    idee_2 = result.get("idee_2") or {}

    preview_1 = {
        "titel": idee_1.get("titel", ""),
        "type": idee_1.get("type", ""),
        "wat_het_doet": idee_1.get("wat_het_doet", ""),
        "waarde": idee_1.get("waarde", ""),
    }
    preview_2 = {
        "titel": idee_2.get("titel", ""),
        "type": idee_2.get("type", ""),
        "wat_het_verbetert": idee_2.get("wat_het_verbetert", ""),
        "waarde": idee_2.get("waarde", ""),
    }

    return {
        "ok": True,
        "scan_token": token,
        "domain": domain,
        "observatie": result.get("observatie", ""),
        "idee_1": preview_1,
        "idee_2": preview_2,
    }


@router.post("/mail-uitwerking")
async def scheeltwerk_mail_uitwerking(request: Request, background_tasks: BackgroundTasks):
    """Step 2: scan_token + email. Validates fast, queues emails as background task."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail={"message": "Invalid JSON"})
    token = str(body.get("scan_token") or "").strip()
    email = str(body.get("email") or "").strip()
    naam = str(body.get("naam") or "").strip()

    if not token or not email:
        raise HTTPException(400, detail={"message": "Scan token en e-mailadres zijn verplicht."})

    entry = _cache_get(token)
    if not entry:
        raise HTTPException(400, detail={"message": "Scan is verlopen. Doe de scan opnieuw."})

    email_key = fingerprint(email.lower().strip())
    conn = _db.get_conn()
    week_ago = time.time() - 604800
    existing = conn.execute(
        "SELECT COUNT(*) FROM request_log WHERE log_type='scheeltwerk_scan' AND ts>? AND meta LIKE ?",
        (week_ago, f"%{email_key}%"),
    ).fetchone()[0]
    if existing > 0:
        raise HTTPException(429, detail={"message": "Je hebt deze week al een uitwerking aangevraagd. Plan een brainstorm om de details te bespreken."})

    url = entry.get("url", "")
    domain = entry.get("domain", "")
    result = entry.get("result") or {}

    # Log the lead immediately (before email fires) so duplicate rapid clicks hit the rate limit
    _db.log_event("scheeltwerk_scan", ip_hash=entry.get("ip_key"), meta={
        "url": url, "domain": domain, "email": email, "naam": naam,
        "email_key": email_key,
    })

    # Fire emails in the background so the HTTP response returns immediately.
    # Prevents proxy timeouts and the "Scan is verlopen" false negatives caused by slow Resend calls.
    background_tasks.add_task(_send_scan_emails_bg, result, domain, url, email, naam)

    return {"ok": True, "domain": domain}


# ───────────────────────────────────────────────────────────────────────────
# PRIJPAGINA INTAKEHULP
# ───────────────────────────────────────────────────────────────────────────

_INTAKE_CATALOG: Optional[Dict[str, Any]] = None


def _load_intake_catalog() -> Dict[str, Any]:
    """Load the controlled ScheeltWerk possibilities catalog once per worker."""
    global _INTAKE_CATALOG
    if _INTAKE_CATALOG is not None:
        return _INTAKE_CATALOG
    path = os.path.join(os.path.dirname(__file__), "scheeltwerk_intake_catalog.json")
    try:
        with open(path, "r", encoding="utf-8") as catalog_file:
            loaded = json.load(catalog_file)
        if not isinstance(loaded, dict) or not isinstance(loaded.get("categories"), list):
            raise ValueError("invalid catalog")
        _INTAKE_CATALOG = loaded
    except Exception:
        _INTAKE_CATALOG = {"categories": []}
    return _INTAKE_CATALOG


def _intake_items() -> Dict[str, Dict[str, Any]]:
    items: Dict[str, Dict[str, Any]] = {}
    for category in _load_intake_catalog().get("categories") or []:
        category_title = str(category.get("title") or "")
        for item in category.get("items") or []:
            item_id = str(item.get("id") or "").strip()
            if not item_id:
                continue
            items[item_id] = {
                "id": item_id,
                "title": str(item.get("title") or ""),
                "benefit": str(item.get("benefit") or ""),
                "control": str(item.get("control") or ""),
                "tags": [str(tag) for tag in (item.get("tags") or [])][:12],
                "category": category_title,
            }
    return items


def _intake_catalog_prompt() -> str:
    """Keep the model grounded in the small, verified options catalog."""
    compact = []
    for item in _intake_items().values():
        compact.append({
            "id": item["id"],
            "titel": item["title"],
            "categorie": item["category"],
            "tags": item["tags"],
        })
    return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))


_INTAKE_SCHEMA = {
    "type": "object",
    "properties": {
        "reply": {"type": "string"},
        "summary": {"type": "string"},
        "suggestion_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
        "question": {"type": "string"},
        "answer_options": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
        "can_submit": {"type": "boolean"},
        "needs_connection_check": {"type": "boolean"},
        "lookup_program": {"type": "string"},
        "lookup_goal": {"type": "string"},
    },
    "required": [
        "reply", "summary", "suggestion_ids", "question", "answer_options",
        "can_submit", "needs_connection_check", "lookup_program", "lookup_goal",
    ],
    "additionalProperties": False,
}


_INTAKE_SYSTEM = """Je bent de rustige intakehulp van ScheeltWerk, van Joep Litjens.

Je praat nuchter Nederlands, direct en behulpzaam. De bezoeker is koning: hij kan altijd stoppen of zijn vraag doorsturen. Je bent geen verkoper en geen technische chatbot.

Doel: begrijp welk terugkerend handwerk, zoekwerk, overtypen of wachten de bezoeker wil verminderen. Kies alleen uit de gecontroleerde catalogus hieronder. Geef maximaal drie suggestie-id's. Stel maximaal één vraag tegelijk en alleen als die een prijsinschatting duidelijker maakt. Na twee tot vier bruikbare antwoorden zet je can_submit op true en nodig je rustig uit om Joep vrijblijvend mee te laten kijken.

Zeg geen definitieve prijs, doorlooptijd of gegarandeerde koppeling. Gebruik geen API-, workflow- of architectuurtaal tenzij de bezoeker zelf over koppelen of een API begint. Bij betalingen, boekingen, klantcommunicatie, offertes, ERP, planning, productie, publiceren of verwijderen noem je kort dat een medewerker controleert of goedkeurt.

Als iemand een concreet programma noemt EN vraagt of een koppeling of gegevensuitwisseling mogelijk is, zet needs_connection_check op true met de programmanaam en het doel. Anders false met lege strings. De aparte officiële controle doet de server; doe zelf geen feitelijke bewering over die koppeling.

Gebruik geen marketingtaal. Zinnen die passen: "Dat zou werk kunnen schelen.", "Ik kijk even welke route hierbij past.", "Dat moet nog even worden gecontroleerd."

Gecontroleerde catalogus: """


def _run_intake_ai(message: str, history: list, selected_ids: list) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(503, detail={"message": "De hulp is nu even niet beschikbaar."})
    try:
        from openai import OpenAI as _OpenAI
    except ImportError:
        raise HTTPException(503, detail={"message": "De hulp is nu even niet beschikbaar."})

    clean_history = []
    for entry in history[-8:]:
        if not isinstance(entry, dict):
            continue
        role = "Bezoeker" if entry.get("role") == "visitor" else "Hulp"
        content = str(entry.get("content") or "").strip()[:1200]
        if content:
            clean_history.append(f"{role}: {content}")
    selected = [item_id for item_id in selected_ids if item_id in _intake_items()][:8]
    prompt = (
        _INTAKE_SYSTEM + _intake_catalog_prompt() +
        "\n\nGesprek tot nu toe:\n" + ("\n".join(clean_history) or "(nieuw gesprek)") +
        "\n\nBezoeker zegt nu:\n" + message +
        "\n\nEerder gekozen mogelijkheden:\n" + (", ".join(selected) or "geen")
    )
    try:
        client = _OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=os.getenv("SCHEELTWERK_INTAKE_MODEL", "gpt-4.1-mini"),
            messages=[
                {"role": "system", "content": "Geef uitsluitend JSON volgens het schema."},
                {"role": "user", "content": prompt},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "scheeltwerk_intake_reply", "strict": True, "schema": _INTAKE_SCHEMA},
            },
            temperature=0.2,
        )
        return json.loads(response.choices[0].message.content or "{}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, detail={"message": f"De hulp kan nu niet meedenken: {str(exc)[:120]}"})


_CONNECTION_LOOKUP_SCHEMA = {
    "type": "object",
    "properties": {
        "reply": {"type": "string"},
        "found_official_route": {"type": "boolean"},
        "source_url": {"type": "string"},
        "source_label": {"type": "string"},
    },
    "required": ["reply", "found_official_route", "source_url", "source_label"],
    "additionalProperties": False,
}


def _run_official_connection_check(program: str, goal: str) -> Dict[str, Any]:
    """Use web search only to find a first-party API/import/export route."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return {}
    try:
        from openai import OpenAI as _OpenAI
        client = _OpenAI(api_key=api_key)
        response = client.responses.create(
            model=os.getenv("SCHEELTWERK_INTAKE_LOOKUP_MODEL", "gpt-4.1-mini"),
            tools=[{"type": "web_search", "search_context_size": "low"}],
            input=(
                "Zoek alleen op de officiële website, helpomgeving of ontwikkelaarsdocumentatie van "
                f"{program}. Onderzoek alleen of er een officiële API, import, export of integratie "
                f"bestaat voor deze wens: {goal}. Gebruik geen blogs, forums of partners als bron. "
                "Geef een kort, nuchter Nederlands antwoord. Als je geen officiële route kunt bevestigen, "
                "zeg dat eerlijk. Zeg nooit dat een koppeling gegarandeerd werkt. "
                "Begin het antwoord met 'Ik heb even op de officiële website gekeken.' of, als geen bron "
                "bevestigd is, 'Ik heb even gezocht naar een officiële route.'"
            ),
            text={"format": {"type": "json_schema", "name": "scheeltwerk_connection_check", "strict": True, "schema": _CONNECTION_LOOKUP_SCHEMA}},
            store=False,
        )
        result = json.loads(response.output_text or "{}")
        if not re.match(r"^https://", str(result.get("source_url") or ""), flags=re.IGNORECASE):
            result["source_url"] = ""
            result["source_label"] = ""
        return result
    except Exception:
        return {
            "reply": "Ik kon de officiële koppelingsroute nu niet goed controleren. Joep kan dit nog gericht voor je nakijken.",
            "found_official_route": False,
            "source_url": "",
            "source_label": "",
        }


def _intake_rate_limit(request: Request, log_type: str, limit: int) -> str:
    ip_key = fingerprint(_client_ip(request))
    try:
        conn = _db.get_conn()
        hour_ago = time.time() - 3600
        count = conn.execute(
            "SELECT COUNT(*) FROM request_log WHERE log_type=? AND ts>? AND meta LIKE ?",
            (log_type, hour_ago, f"%{ip_key}%"),
        ).fetchone()[0]
        if count >= limit:
            raise HTTPException(429, detail={"message": "Je hebt de hulp net al vaak gebruikt. Stuur je vraag gerust door, dan kijkt Joep ernaar."})
    except HTTPException:
        raise
    except Exception:
        pass
    return ip_key


@router.post("/intake-assistant")
async def scheeltwerk_intake_assistant(request: Request):
    """One short, catalog-bound reply for the price-page intake helper."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail={"message": "Ongeldige aanvraag."})
    message = str(body.get("message") or "").strip()
    if not message or len(message) > 3000:
        raise HTTPException(400, detail={"message": "Beschrijf in één of een paar zinnen wat je wilt automatiseren."})
    history = body.get("history") if isinstance(body.get("history"), list) else []
    selected_ids = body.get("selected_suggestions") if isinstance(body.get("selected_suggestions"), list) else []
    ip_key = _intake_rate_limit(request, "scheeltwerk_intake_reply", 20)
    result = _run_intake_ai(message, history, selected_ids)
    items = _intake_items()
    suggestion_ids = []
    for item_id in result.get("suggestion_ids") or []:
        if item_id in items and item_id not in suggestion_ids:
            suggestion_ids.append(item_id)
    suggestions = [items[item_id] for item_id in suggestion_ids[:3]]
    connection_check = None
    if result.get("needs_connection_check") and str(result.get("lookup_program") or "").strip():
        connection_check = _run_official_connection_check(
            str(result.get("lookup_program") or "").strip()[:160],
            str(result.get("lookup_goal") or message).strip()[:700],
        )
    _db.log_event("scheeltwerk_intake_reply", ip_hash=ip_key, meta={
        "ip_key": ip_key, "selected": suggestion_ids, "connection_check": bool(connection_check),
    })
    return {
        "ok": True,
        "reply": str(result.get("reply") or ""),
        "summary": str(result.get("summary") or message)[:1800],
        "suggestions": suggestions,
        "question": str(result.get("question") or ""),
        "answer_options": [str(option)[:140] for option in (result.get("answer_options") or [])[:3]],
        "can_submit": bool(result.get("can_submit")),
        "connection_check": connection_check,
    }


@router.post("/intake-versturen")
async def scheeltwerk_intake_versturen(request: Request):
    """Mail the human-readable intake summary to Joep and the visitor."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail={"message": "Ongeldige aanvraag."})
    email = str(body.get("email") or "").strip()
    summary = str(body.get("summary") or "").strip()
    if not email or "@" not in email or not summary:
        raise HTTPException(400, detail={"message": "E-mailadres en omschrijving zijn nodig om je vraag door te sturen."})
    if len(summary) > 2200:
        raise HTTPException(400, detail={"message": "Je omschrijving is te lang. Maak hem iets korter en probeer opnieuw."})
    ip_key = _intake_rate_limit(request, "scheeltwerk_intake_sent", 8)
    name = str(body.get("naam") or "").strip()[:160]
    company = str(body.get("bedrijf") or "").strip()[:160]
    selected_ids = body.get("selected_suggestions") if isinstance(body.get("selected_suggestions"), list) else []
    items = _intake_items()
    selected_titles = [items[item_id]["title"] for item_id in selected_ids if item_id in items][:8]
    checks = body.get("connection_checks") if isinstance(body.get("connection_checks"), list) else []
    safe_summary = html.escape(summary).replace("\n", "<br>")
    safe_checks = []
    for check in checks[:3]:
        if not isinstance(check, dict):
            continue
        reply = html.escape(str(check.get("reply") or ""))
        source = str(check.get("source_url") or "").strip()
        if re.match(r"^https://", source, flags=re.IGNORECASE):
            label = html.escape(str(check.get("source_label") or "officiële documentatie"))
            reply += f' <a href="{html.escape(source, quote=True)}">{label}</a>'
        if reply:
            safe_checks.append(f"<li>{reply}</li>")
    checks_html = "<ul>" + "".join(safe_checks) + "</ul>" if safe_checks else "-"
    _db.log_event("scheeltwerk_intake_sent", ip_hash=ip_key, meta={
        "ip_key": ip_key, "email_key": fingerprint(email.lower()), "selected": selected_titles, "company": company,
    })
    _resend_mail(
        to="joep@scheeltwerk.nl",
        subject=f"Nieuwe prijsinschatting: {name or email} ({company or 'geen bedrijf'})",
        html=f"""<h2>Nieuwe vrijblijvende prijsinschatting via scheeltwerk.nl</h2>
<p><strong>Naam:</strong> {html.escape(name or '-')}<br>
<strong>E-mail:</strong> {html.escape(email)}<br>
<strong>Bedrijf:</strong> {html.escape(company or '-')}</p>
<p><strong>Samenvatting:</strong><br>{safe_summary}</p>
<p><strong>Gekozen richtingen:</strong><br>{html.escape(', '.join(selected_titles) or '-')}</p>
<p><strong>Officiële koppelingschecks:</strong><br>{checks_html}</p>""",
    )
    greeting = f", {html.escape(name)}" if name else ""
    _resend_mail(
        to=email,
        subject="Je vraag voor een prijsinschatting is ontvangen — ScheeltWerk",
        html=f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1d21">
<h2 style="color:#e07830">Bedankt{greeting}.</h2>
<p>Ik heb je vraag ontvangen. Ik kijk wat een logische eerste stap is en stuur je binnen enkele dagen een vrijblijvende inschatting.</p>
<p style="margin-top:24px;color:#4a5060;font-size:14px">— Joep Litjens<br>scheeltwerk.nl</p>
</div>""",
    )
    return {"ok": True}
