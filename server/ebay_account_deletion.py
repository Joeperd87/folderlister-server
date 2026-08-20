"""eBay Marketplace Account Deletion endpoint helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Callable

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,80}$")
_KEY_CACHE: dict[str, tuple[float, dict]] = {}


def validate_configuration(token: str, endpoint: str) -> None:
    if not _TOKEN_RE.fullmatch(token or ""):
        raise ValueError("EBAY_ACCOUNT_DELETION_TOKEN must be 32-80 letters, digits, _ or -")
    if not (endpoint or "").startswith("https://"):
        raise ValueError("EBAY_ACCOUNT_DELETION_ENDPOINT must be a public HTTPS URL")


def challenge_response(challenge_code: str, token: str, endpoint: str) -> str:
    validate_configuration(token, endpoint)
    if not challenge_code:
        raise ValueError("challenge_code required")
    return hashlib.sha256((challenge_code + token + endpoint).encode("utf-8")).hexdigest()


def _decode_signature_header(value: str) -> dict:
    try:
        decoded = base64.b64decode(value, validate=True).decode("ascii")
        parsed = json.loads(decoded)
    except Exception as exc:
        raise ValueError("invalid X-EBAY-SIGNATURE header") from exc
    if not parsed.get("kid") or not parsed.get("signature"):
        raise ValueError("incomplete X-EBAY-SIGNATURE header")
    return parsed


def _public_key(kid: str, app_token: str, api_base: str) -> dict:
    cached = _KEY_CACHE.get(kid)
    if cached and cached[0] > time.time():
        return cached[1]
    response = requests.get(
        f"{api_base.rstrip('/')}/commerce/notification/v1/public_key/{kid}",
        headers={"Authorization": f"Bearer {app_token}", "Accept": "application/json"},
        timeout=15,
    )
    response.raise_for_status()
    result = response.json()
    _KEY_CACHE[kid] = (time.time() + 3600, result)
    return result


def verify_signature(
    message: dict,
    signature_header: str,
    app_token_factory: Callable[[], str],
    api_base: str = "https://api.ebay.com",
) -> bool:
    """Validate the ECC signature exactly as eBay's official SDK does."""
    header = _decode_signature_header(signature_header)
    key_info = _public_key(str(header["kid"]), app_token_factory(), api_base)
    digest_name = str(header.get("digest") or key_info.get("digest") or "SHA1").upper()
    digest = {"SHA1": hashes.SHA1(), "SHA256": hashes.SHA256()}.get(digest_name)
    if digest is None:
        raise ValueError(f"unsupported eBay signature digest: {digest_name}")

    key_text = str(key_info.get("key") or "")
    if "\n" not in key_text:
        key_text = key_text.replace("-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n")
        key_text = key_text.replace("-----END PUBLIC KEY-----", "\n-----END PUBLIC KEY-----")
    public_key = serialization.load_pem_public_key(key_text.encode("ascii"))
    signature = base64.b64decode(str(header["signature"]), validate=True)
    canonical = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        public_key.verify(signature, canonical, ec.ECDSA(digest))
        return True
    except InvalidSignature:
        return False
