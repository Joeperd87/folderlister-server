# Joepienator — License Admin (CLI)

**Locatie:** `tools/license_admin.py`  
**Vereist:** dezelfde `LICENSE_HMAC_SECRET` als de server (anders matcht je key niet).

## Snel starten
```bash
# Windows PowerShell (voorbeeld)
$env:LICENSE_HMAC_SECRET="CHANGE_ME_DEV_SECRET"
python tools/license_admin.py list
```

## Veelgebruikte commando's
```bash
# Maak of converteer (plan & vervaldatum)
python tools/license_admin.py create PLAINK3Y 30 trial --owner-email user@example.com --slots 1
python tools/license_admin.py convert PLAINK3Y 365 pro --slots 2

# Verleng
python tools/license_admin.py extend PLAINK3Y 90

# Slots en eBay-koppeling
python tools/license_admin.py set-slots PLAINK3Y 3
python tools/license_admin.py add-ebay PLAINK3Y ebay-username
python tools/license_admin.py rm-ebay  PLAINK3Y ebay-username

# Eigenaar
python tools/license_admin.py owner PLAINK3Y user@example.com "User Name"

# Status / vervaldatum
python tools/license_admin.py set-status PLAINK3Y active
python tools/license_admin.py set-expiry PLAINK3Y 2026-01-31

# Introspectie
python tools/license_admin.py show PLAINK3Y
python tools/license_admin.py list
```

## Pad naar `licenses.json`
Standaard kijkt de CLI naar `server/data/licenses.json` relatief t.o.v. dit script.  
Anders: `--file "C:\pad\naar\server\data\licenses.json"`

## Tip
Zorg dat de server en deze CLI dezelfde **`LICENSE_HMAC_SECRET`** gebruiken; anders vindt de server je records niet (HMAC verschilt).