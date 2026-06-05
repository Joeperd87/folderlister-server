# server/stripe_webhook.py
"""
Stripe webhook handler voor Folder Lister Pro abonnementen.

Afgehandelde events:
  - checkout.session.completed      → Pro-licentie aanmaken + mail sturen
  - customer.subscription.deleted   → Licentie op 'expired' zetten
  - invoice.payment_failed          → (optioneel) waarschuwingsmail

Configuratie via .env:
  STRIPE_SECRET_KEY        sk_test_... of sk_live_...
  STRIPE_WEBHOOK_SECRET    whsec_...   (uit Stripe Dashboard → Webhooks)
  STRIPE_PRO_PRICE_ID      price_1TAX12RyLVOsdCDq9V3B7EsP
  STRIPE_PRO_PLAN_NAME     pro          (plan-label in license_store)
  STRIPE_PRO_EPS_LIMIT     1500         (images per maand)
  PUBLIC_BASE_URL          https://folderlister.com

Installeren:
  pip install stripe
"""

from __future__ import annotations

import json
import os
import secrets
import time
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import stripe
from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse

# ── Importeer jouw bestaande helpers ──────────────────────────────────────────
from .license_store import upsert_license_plain, find_license, fingerprint

log = logging.getLogger(__name__)

router = APIRouter()

# ── Configuratie ──────────────────────────────────────────────────────────────
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
WEBHOOK_SECRET   = os.getenv("STRIPE_WEBHOOK_SECRET", "")
PRO_PRICE_ID     = os.getenv("STRIPE_PRO_PRICE_ID", "price_1TAX12RyLVOsdCDq9V3B7EsP")
PRO_PLAN_NAME    = os.getenv("STRIPE_PRO_PLAN_NAME", "pro")
PRO_EPS_LIMIT    = int(os.getenv("STRIPE_PRO_EPS_LIMIT", "1500"))
BASE_URL         = os.getenv("PUBLIC_BASE_URL", "https://folderlister.com")

# Hoelang een Pro-licentie geldig is na aanmaken (ruim, Stripe stuurt toch cancel-event)
PRO_EXPIRES_YEARS = 10


# ─────────────────────────────────────────────────────────────────────────────
# Interne helpers
# ─────────────────────────────────────────────────────────────────────────────

def _far_future_iso() -> str:
    """Expiry-datum ver in de toekomst (Stripe beheert de echte termijn)."""
    dt = datetime.now(timezone.utc).replace(year=datetime.now().year + PRO_EXPIRES_YEARS)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _send_email(to_addr: str, subject: str, body: str, html: Optional[str] = None) -> None:
    """Zelfde SMTP-helper als in app.py — gekopieerd zodat de router zelfstandig werkt."""
    import smtplib, ssl
    from email.message import EmailMessage

    host        = os.getenv("SMTP_HOST", "127.0.0.1")
    port        = int(os.getenv("SMTP_PORT", "25"))
    use_ssl     = os.getenv("SMTP_SSL", "0") == "1"
    use_tls     = os.getenv("SMTP_STARTTLS", "0") == "1"
    user        = (os.getenv("SMTP_USER") or "").strip()
    pw          = (os.getenv("SMTP_PASS") or "").strip()
    sender      = os.getenv("SMTP_FROM", "noreply@folderlister.com")

    msg = EmailMessage()
    msg["From"]    = sender
    msg["To"]      = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        try:
            msg.add_alternative(html, subtype="html")
        except Exception:
            pass

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as s:
                if user and pw:
                    s.login(user, pw)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.ehlo()
                if use_tls and "starttls" in s.esmtp_features:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if user and pw and "auth" in s.esmtp_features:
                    s.login(user, pw)
                s.send_message(msg)
    except Exception as e:
        log.error("SMTP send failed to %s: %s", to_addr, e)


def _send_pro_license_mail(email: str, key: str, customer_name: Optional[str] = None) -> None:
    """Stuurt de Pro-licentie key naar de koper."""
    name_line = f"Hi {customer_name}," if customer_name else "Hi,"
    subject = "Your Folder Lister Pro license key"

    text = f"""{name_line}

Thank you for subscribing to Folder Lister Pro!

Your license key:

{key}

Plan: Pro — {PRO_EPS_LIMIT} image uploads per month

How to activate:
1) Open the Folder Lister app.
2) Click the menu at the top-center.
3) Log in to eBay if you haven't already.
4) Click the menu again → "Enter license key…"
5) Paste the key and confirm.

Documentation: {BASE_URL}/docs
Support: support@folderlister.com

If you didn't make this purchase, please contact us immediately.

— Folder Lister
"""

    html = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Your Folder Lister Pro license</title></head>
<body style="margin:0;padding:0;background:#f5f5f7;font-family:system-ui,-apple-system,sans-serif;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
    <tr><td align="center" style="padding:24px 12px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
             style="max-width:600px;background:#fff;border-radius:12px;border:1px solid #e2e2e7;overflow:hidden;">

        <tr><td style="padding:24px 28px 12px;">
          <img src="{BASE_URL}/images/folder_lister_logo.png" alt="Folder Lister" width="72"
               style="display:block;margin:0 0 16px;">
          <h1 style="margin:0 0 6px;font-size:20px;color:#111;">{name_line}</h1>
          <p style="margin:0;font-size:14px;color:#555;">
            Thank you for subscribing to <strong>Folder Lister Pro</strong>.
          </p>
        </td></tr>

        <tr><td style="padding:16px 28px;">
          <p style="margin:0 0 8px;font-size:13px;color:#374151;">Your license key:</p>
          <p style="font-size:16px;font-weight:700;background:#111;color:#fff;
                    display:inline-block;padding:10px 16px;border-radius:8px;
                    letter-spacing:.03em;margin:0 0 16px;">{key}</p>
          <p style="margin:0 0 4px;font-size:13px;color:#374151;">
            Plan: <strong>Pro</strong> &mdash; {PRO_EPS_LIMIT} image uploads / month
          </p>
        </td></tr>

        <tr><td style="padding:0 28px 16px;">
          <h3 style="margin:0 0 8px;font-size:14px;color:#111;">How to activate</h3>
          <ol style="margin:0;padding-left:18px;font-size:13px;color:#374151;line-height:1.7;">
            <li>Open the <strong>Folder Lister</strong> app.</li>
            <li>Click the menu at the top-center.</li>
            <li>Log in to eBay if you haven't already.</li>
            <li>Click the menu again &rarr; <strong>"Enter license key&hellip;"</strong></li>
            <li>Paste the key and confirm.</li>
          </ol>
        </td></tr>

        <tr><td style="padding:12px 28px 20px;">
          <p style="margin:0 0 6px;font-size:13px;color:#374151;">
            📄 <a href="{BASE_URL}/docs" style="color:#2563eb;">Documentation</a>
            &nbsp;|&nbsp;
            ✉️ <a href="mailto:support@folderlister.com" style="color:#2563eb;">support@folderlister.com</a>
          </p>
        </td></tr>

        <tr><td style="padding:12px 28px 16px;border-top:1px solid #e5e7eb;">
          <p style="margin:0;font-size:11px;color:#9ca3af;">
            You're receiving this because you purchased Folder Lister Pro.
            If this wasn't you, contact us immediately.
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    _send_email(email, subject, text, html)


def _find_license_hash_by_stripe_customer(customer_id: str) -> Optional[str]:
    """Scan the licenses table for a record whose notes-JSON references the
    given Stripe ``customer_id`` and return its ``key_hash``.

    Used by both the provision (idempotency check) and deactivate paths.
    Returns ``None`` when no matching license exists or scanning fails.
    """
    import json as _json
    from . import db as _db
    try:
        for rec in _db.license_list(limit=10000):
            notes_raw = rec.get("notes") or ""
            try:
                notes = _json.loads(notes_raw) if notes_raw.strip().startswith("{") else {}
            except Exception:
                notes = {}
            if notes.get("stripe_customer_id") == customer_id:
                return rec.get("key_hash")
    except Exception as e:
        log.warning("Could not scan licenses for stripe_customer_id %s: %s", customer_id, e)
    return None


def _provision_pro_license(
    email: str,
    customer_id: str,
    subscription_id: str,
    customer_name: Optional[str] = None,
) -> str:
    """
    Maak een nieuwe Pro-licentie aan voor deze Stripe customer, of geef een
    idempotente no-op als er al eentje bestaat voor hetzelfde
    ``customer_id``. Stuurt bij creatie de key per e-mail.

    Retourneert de plain license key bij nieuwe aanmaak, of een lege string
    wanneer dit een replay-event is van een al-geprovisioneerde customer
    (we kunnen de plain key niet meer reconstrueren uit de DB, dus we
    re-emailen niet en laten 't aan admin over om handmatig opnieuw uit
    te geven als de klant erom vraagt).
    """
    # Idempotentie: Stripe levert webhook-events at-least-once en kan ze
    # opnieuw versturen (bv. na een 500 in een eerdere afhandeling).
    # Bestaande Pro-licentie voor deze customer → niets opnieuw doen.
    existing_hash = _find_license_hash_by_stripe_customer(customer_id)
    if existing_hash:
        log.info(
            "Pro license already exists for stripe_customer %s (key_hash=%s) — "
            "skipping re-provisioning; plain key cannot be recovered from DB",
            customer_id, existing_hash[:16] + "...",
        )
        return ""

    # Nieuwe key aanmaken
    key = secrets.token_urlsafe(24)
    notes_json = json.dumps({
        "stripe_customer_id":     customer_id,
        "stripe_subscription_id": subscription_id,
        "stripe_price_id":        PRO_PRICE_ID,
        "provisioned_at":         datetime.now(timezone.utc).isoformat(),
    })

    upsert_license_plain(
        plain_key          = key,
        plan               = PRO_PLAN_NAME,
        expires_at_iso_utc = _far_future_iso(),
        status             = "active",
        owner_email        = email,
        owner_name         = customer_name,
        notes              = notes_json,
    )

    # eps_daily_limit is een Pro-specifieke override; in de DB hangt 'ie
    # onder de meta-JSON van de licentie. update_license_meta merget 'm in
    # zonder andere meta-velden te overschrijven.
    try:
        from .license_store import update_license_meta
        update_license_meta(key, {"eps_daily_limit": PRO_EPS_LIMIT})
    except Exception as e:
        log.warning("Could not set eps_daily_limit meta for new pro key: %s", e)

    log.info("Pro license provisioned for %s (customer %s)", email, customer_id)
    _send_pro_license_mail(email, key, customer_name)
    return key


def _deactivate_pro_license(customer_id: str, subscription_id: str) -> None:
    """Zet de Pro-licentie op 'expired' wanneer Stripe het abonnement
    annuleert. No-op als geen licentie aan deze customer_id gekoppeld is."""
    from . import db as _db
    key_hash = _find_license_hash_by_stripe_customer(customer_id)
    if not key_hash:
        log.warning(
            "customer.subscription.deleted for unknown stripe_customer %s (sub %s) — "
            "no license to deactivate",
            customer_id, subscription_id,
        )
        return
    try:
        _db.license_upsert(
            key_hash,
            status="expired",
            expires_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        log.info(
            "Deactivated Pro license for customer %s (sub %s, key_hash=%s)",
            customer_id, subscription_id, key_hash[:16] + "...",
        )
    except Exception as e:
        log.error(
            "Error deactivating license for customer %s (sub %s): %s",
            customer_id, subscription_id, e,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    """
    Stripe stuurt hier POST-requests naartoe voor alle subscription-events.
    Verifieer altijd de handtekening — zonder STRIPE_WEBHOOK_SECRET weigert dit endpoint.
    """
    if not WEBHOOK_SECRET:
        log.error("STRIPE_WEBHOOK_SECRET is not set — webhook disabled")
        raise HTTPException(status_code=500, detail="Webhook not configured")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError as e:
        log.warning("Stripe webhook signature invalid: %s", e)
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as e:
        log.error("Stripe webhook parse error: %s", e)
        raise HTTPException(status_code=400, detail=str(e))

    event_type = event["type"]
    data_obj   = event["data"]["object"]

    log.info("Stripe event: %s  id=%s", event_type, event.get("id"))

    # ── checkout.session.completed ────────────────────────────────────────────
    if event_type == "checkout.session.completed":
        mode = data_obj.get("mode")
        if mode != "subscription":
            return {"ok": True, "skipped": "not_subscription"}

        email           = (data_obj.get("customer_details") or {}).get("email") or data_obj.get("customer_email") or ""
        customer_id     = data_obj.get("customer") or ""
        subscription_id = data_obj.get("subscription") or ""
        customer_name   = (data_obj.get("customer_details") or {}).get("name") or None

        if not email or not customer_id:
            log.error("checkout.session.completed missing email or customer_id — skipping")
            return {"ok": False, "detail": "missing_email_or_customer"}

        try:
            _provision_pro_license(email, customer_id, subscription_id, customer_name)
        except Exception as e:
            log.error("Failed to provision Pro license for %s: %s", email, e)
            # Retourneer 200 zodat Stripe niet blijft retrien; log het probleem
            return JSONResponse({"ok": False, "detail": str(e)}, status_code=200)

    # ── customer.subscription.deleted ─────────────────────────────────────────
    elif event_type == "customer.subscription.deleted":
        customer_id     = data_obj.get("customer") or ""
        subscription_id = data_obj.get("id") or ""
        _deactivate_pro_license(customer_id, subscription_id)

    # ── invoice.payment_failed (optioneel) ────────────────────────────────────
    elif event_type == "invoice.payment_failed":
        email       = (data_obj.get("customer_email") or "")
        customer_id = data_obj.get("customer") or ""
        log.warning("Payment failed for customer %s (%s)", customer_id, email)
        # Hier kun je een waarschuwingsmail sturen als je wilt.

    # Alle andere events negeren we gewoon
    return {"ok": True, "event": event_type}


@router.get("/stripe/checkout")
async def stripe_create_checkout(
    request:  Request,
    email:    Optional[str] = Query(None),
):
    """
    Maakt een Stripe Checkout Session aan en redirect de gebruiker daarheen.
    Gebruik: <a href="/stripe/checkout?email=klant@voorbeeld.nl">Koop Pro</a>

    Of zonder email: Stripe vraagt het zelf.
    """
    if not stripe.api_key:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    params: dict = {
        "mode":       "subscription",
        "line_items": [{"price": PRO_PRICE_ID, "quantity": 1}],
        "success_url": f"{BASE_URL}/api/stripe/success?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url":  f"{BASE_URL}/#pricing",
        "allow_promotion_codes": True,
        "billing_address_collection": "auto",
        "tax_id_collection": {"enabled": True},   # BTW-nummer voor bedrijven
    }
    if email:
        params["customer_email"] = email

    try:
        session = stripe.checkout.Session.create(**params)
    except stripe.error.StripeError as e:
        log.error("Stripe checkout session creation failed: %s", e)
        raise HTTPException(status_code=502, detail=str(e))

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=session.url, status_code=303)


@router.get("/stripe/success", response_class=HTMLResponse)
async def stripe_success(session_id: Optional[str] = Query(None)):
    """
    Succespagina na betaling.
    Stripe stuurt de klant hierheen met ?session_id=...
    De licentie is al aangemaakt via de webhook — deze pagina informeert alleen.
    """
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Payment successful — Folder Lister Pro</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
      background: #f5f5f7;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }}
    .card {{
      background: #fff;
      border-radius: 16px;
      border: 1px solid #e2e2e7;
      max-width: 520px;
      width: 100%;
      padding: 40px 36px;
      text-align: center;
    }}
    .icon {{ font-size: 56px; margin-bottom: 20px; }}
    h1 {{ font-size: 22px; color: #111; margin-bottom: 10px; }}
    p  {{ font-size: 14px; color: #555; line-height: 1.6; margin-bottom: 12px; }}
    .key-note {{
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 13px;
      color: #166534;
      margin: 16px 0;
    }}
    a.btn {{
      display: inline-block;
      margin-top: 20px;
      padding: 10px 24px;
      background: #C76A47;
      color: #fff;
      text-decoration: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🎉</div>
    <h1>Payment successful!</h1>
    <p>Welcome to <strong>Folder Lister Pro</strong>.</p>
    <div class="key-note">
      ✉️ Your license key has been sent to your email address.<br>
      Check your inbox (and spam folder, just in case).
    </div>
    <p>
      Once you have the key, open Folder Lister, go to the menu
      at the top-center → <strong>"Enter license key…"</strong> and paste it in.
    </p>
    <p>
      Questions? <a href="mailto:support@folderlister.com">support@folderlister.com</a>
    </p>
    <a class="btn" href="{BASE_URL}">Back to Folder Lister</a>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)
