#!/usr/bin/env python3
"""
Joepienator License Admin CLI
- Beheer licenties in server/data/licenses.json (of eigen pad).
- HMAC: gebruikt LICENSE_HMAC_SECRET (zelfde als de server!).
- Alle tijden in UTC, ISO-8601 met "Z".

Voorbeelden:
  python license_admin.py list
  python license_admin.py create PLAINK3Y 30 trial --owner-email user@example.com --slots 1
  python license_admin.py extend PLAINK3Y 90
  python license_admin.py convert PLAINK3Y 365 pro --slots 2
  python license_admin.py set-slots PLAINK3Y 3
  python license_admin.py add-ebay PLAINK3Y ebay-username
  python license_admin.py rm-ebay PLAINK3Y ebay-username
  python license_admin.py owner PLAINK3Y user@example.com "User Name"
  python license_admin.py revoke PLAINK3Y
  python license_admin.py reinstate PLAINK3Y
  python license_admin.py set-expiry PLAINK3Y 2026-01-31
  python license_admin.py set-status PLAINK3Y active
  python license_admin.py show PLAINK3Y
"""
from __future__ import annotations
import argparse, os, json, sys, hmac, hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
ROOT = Path(__file__).resolve().parent.parent  # .. (projectroot)
load_dotenv(ROOT / ".env", override=True)

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "server" / "data" / "licenses.json"
SECRET = os.getenv("LICENSE_HMAC_SECRET", "CHANGE_ME_DEV_SECRET").encode("utf-8")

def _hmac_key(plain: str) -> str:
    digest = hmac.new(SECRET, plain.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"HMAC256:{digest}"

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _parse_date(s: str) -> datetime:
    # Accept YYYY-MM-DD or full ISO
    try:
        if 'T' in s:
            if s.endswith('Z'):
                return datetime.fromisoformat(s.replace('Z', '+00:00'))
            return datetime.fromisoformat(s)
        return datetime.fromisoformat(s + "T00:00:00+00:00")
    except Exception as e:
        raise SystemExit(f"Bad date format: {s} ({e})")

def load_file(path: Path) -> dict:
    if path.exists():
        txt = path.read_text("utf-8").strip()
        return json.loads(txt) if txt else {}
    return {}

def save_file(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)

def cmd_list(args):
    data = load_file(args.file)
    if not data:
        print("(no licenses)", file=sys.stderr)
        return
    # table header
    print(f"{'FINGERPRINT':<12} {'PLAN':<8} {'EXPIRES_AT(UTC)':<20} {'STATUS':<8} {'SLOTS':<5} {'OWNER_EMAIL'}")
    for hk, rec in data.items():
        fp = hk.split(":")[-1][:10]
        plan = rec.get("plan","")
        exp = rec.get("expires_at","")
        status = rec.get("status","")
        slots = int(rec.get("max_accounts") or 1)
        owner = rec.get("owner_email","")
        print(f"{fp:<12} {plan:<8} {exp:<20} {status:<8} {slots:<5} {owner}")

def cmd_show(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr)
        sys.exit(1)
    out = {"hashed_key": hk, **rec}
    print(json.dumps(out, indent=2))

def cmd_create(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    if hk in data:
        print("already exists; use convert/extend/owner/set-slots instead", file=sys.stderr)
        sys.exit(1)
    exp = _iso(datetime.now(timezone.utc) + timedelta(days=args.days))
    rec = {
        "plan": args.plan,
        "expires_at": exp,
        "status": "active",
        "created_at": _now_iso(),
        "max_accounts": int(args.slots),
    }
    if args.owner_email:
        rec["owner_email"] = args.owner_email
    if args.owner_name:
        rec["owner_name"] = args.owner_name
    data[hk] = rec
    save_file(args.file, data)
    print(f"OK created {hk} exp={exp} plan={args.plan} slots={args.slots}")

def cmd_extend(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    # extend from current expiry if future, else from now
    try:
        exp = rec.get("expires_at","")
        base = datetime.fromisoformat(exp.replace('Z', '+00:00')) if exp else datetime.now(timezone.utc)
    except Exception:
        base = datetime.now(timezone.utc)
    if base < datetime.now(timezone.utc):
        base = datetime.now(timezone.utc)
    new_exp = _iso(base + timedelta(days=args.days))
    rec["expires_at"] = new_exp
    data[hk] = rec
    save_file(args.file, data)
    print(f"OK extended to {new_exp}")

def cmd_convert(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk) or {}
    new_exp = _iso(datetime.now(timezone.utc) + timedelta(days=args.days))
    rec.update({
        "plan": args.plan,
        "expires_at": new_exp,
        "status": "active",
        "max_accounts": int(args.slots),
    })
    data[hk] = rec
    save_file(args.file, data)
    print(f"OK plan={args.plan} exp={new_exp} slots={args.slots}")

def cmd_set_slots(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    rec["max_accounts"] = int(args.slots)
    data[hk] = rec
    save_file(args.file, data)
    print(f"OK slots={args.slots}")

def cmd_add_ebay(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    slots = int(rec.get("max_accounts") or 1)
    lst = rec.get("allowed_ebay_users") or []
    if args.username in lst:
        print("already present"); return
    if len(lst) >= slots:
        print(f"max accounts reached ({slots})", file=sys.stderr); sys.exit(1)
    lst.append(args.username)
    rec["allowed_ebay_users"] = lst
    data[hk] = rec
    save_file(args.file, data)
    print("OK added", args.username)

def cmd_rm_ebay(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    lst = rec.get("allowed_ebay_users") or []
    if args.username in lst:
        lst = [u for u in lst if u != args.username]
        rec["allowed_ebay_users"] = lst or None
        data[hk] = rec
        save_file(args.file, data)
        print("OK removed", args.username)
    else:
        print("not present")

def cmd_owner(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    rec["owner_email"] = args.email
    if args.name:
        rec["owner_name"] = args.name
    data[hk] = rec
    save_file(args.file, data)
    print("OK owner set", args.email, args.name or "")

def cmd_revoke(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    rec["status"] = "revoked"
    data[hk] = rec
    save_file(args.file, data)
    print("OK revoked")

def cmd_reinstate(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    rec["status"] = "active"
    data[hk] = rec
    save_file(args.file, data)
    print("OK active")

def cmd_set_expiry(args):
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    exp = _iso(_parse_date(args.date))
    rec["expires_at"] = exp
    data[hk] = rec
    save_file(args.file, data)
    print("OK expires_at=", exp)

def cmd_set_status(args):
    if args.status not in ("active","revoked"):
        print("status must be 'active' or 'revoked'", file=sys.stderr); sys.exit(1)
    data = load_file(args.file)
    hk = _hmac_key(args.plain_key)
    rec = data.get(hk)
    if not rec:
        print("not found", file=sys.stderr); sys.exit(1)
    rec["status"] = args.status
    data[hk] = rec
    save_file(args.file, data)
    print("OK status=", args.status)

def make_parser():
    p = argparse.ArgumentParser(description="Joepienator License Admin")
    p.add_argument("--file", type=Path, default=DEFAULT_FILE, help=f"path to licenses.json (default: {DEFAULT_FILE})")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list"); s.set_defaults(func=cmd_list)
    s = sub.add_parser("show"); s.add_argument("plain_key"); s.set_defaults(func=cmd_show)
    s = sub.add_parser("create")
    s.add_argument("plain_key"); s.add_argument("days", type=int); s.add_argument("plan")
    s.add_argument("--owner-email"); s.add_argument("--owner-name"); s.add_argument("--slots", type=int, default=1)
    s.set_defaults(func=cmd_create)
    s = sub.add_parser("extend"); s.add_argument("plain_key"); s.add_argument("days", type=int); s.set_defaults(func=cmd_extend)
    s = sub.add_parser("convert"); s.add_argument("plain_key"); s.add_argument("days", type=int); s.add_argument("plan"); s.add_argument("--slots", type=int, default=1); s.set_defaults(func=cmd_convert)
    s = sub.add_parser("set-slots"); s.add_argument("plain_key"); s.add_argument("slots", type=int); s.set_defaults(func=cmd_set_slots)
    s = sub.add_parser("add-ebay"); s.add_argument("plain_key"); s.add_argument("username"); s.set_defaults(func=cmd_add_ebay)
    s = sub.add_parser("rm-ebay"); s.add_argument("plain_key"); s.add_argument("username"); s.set_defaults(func=cmd_rm_ebay)
    s = sub.add_parser("owner"); s.add_argument("plain_key"); s.add_argument("email"); s.add_argument("name", nargs="?"); s.set_defaults(func=cmd_owner)
    s = sub.add_parser("revoke"); s.add_argument("plain_key"); s.set_defaults(func=cmd_revoke)
    s = sub.add_parser("reinstate"); s.add_argument("plain_key"); s.set_defaults(func=cmd_reinstate)
    s = sub.add_parser("set-expiry"); s.add_argument("plain_key"); s.add_argument("date"); s.set_defaults(func=cmd_set_expiry)
    s = sub.add_parser("set-status"); s.add_argument("plain_key"); s.add_argument("status"); s.set_defaults(func=cmd_set_status)
    return p

def main():
    args = make_parser().parse_args()
    args.file = args.file.resolve()
    args.func(args)

if __name__ == "__main__":
    main()