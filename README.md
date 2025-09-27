# Joepienator EPS Starter (Hybride)

Dit pakket bevat:
- **server/**: FastAPI demo-licentieserver + EPS-proxy endpoint (`/media/upload`).
- **client/**: Python client die afbeeldingen via de server uploadt, URL's cachet, en CSV schrijft.
- **Beschrijving tags**: Gebruik `{{picture1}}`, `{{picture2}}`, ... in je template; deze worden vervangen door `<img>`-tags.

## Snel starten

### Server
```bash
cd server
pip install fastapi uvicorn pydantic
export JOEP_LICENSE_SECRET="change-me"
export JOEP_VALID_KEYS="TEST-KEY-123"
uvicorn app:app --reload --port 8000
```

### Client
```bash
cd client
pip install requests
export JOEP_SERVER="http://localhost:8000"
export JOEP_LICENSE_KEY="TEST-KEY-123"
export JOEP_INPUT_FOLDER="/pad/naar/afbeeldingen"
export JOEP_OUTPUT_CSV="output.csv"
export JOEP_DESC_TEMPLATE="<p>Hoofdbeeld: {{picture1}}</p>"
python main.py
```

De client uploadt de beelden via de server en zet de geretourneerde URL's in de CSV (kolom L). De beschrijving (kolom O) bevat de ingevulde template.

## Belangrijk
- `/media/upload` is een **placeholder**. In productie moet je hier de **eBay EPS/Media API** aanroepen met jouw app-keys en de echte afbeelding-URL teruggeven.
- Licenties zijn demotisch; vervang door JWT's + database.
- Caching gebeurt op bestands-hash, zodat dezelfde afbeelding niet dubbel wordt geüpload.

## Beschrijvingstags
- `{{picture1}}`, `{{picture2}}`, ... worden vervangen door `<img src="...">` in de beschrijving.
- Afbeeldings-URL's komen uit de EPS-upload die de client via de server doet.
