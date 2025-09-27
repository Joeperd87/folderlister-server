# Server (demo)

FastAPI-licentieserver + EPS-proxy (demo).

## Run
```bash
pip install fastapi uvicorn pydantic
export JOEP_LICENSE_SECRET="change-me"
export JOEP_VALID_KEYS="TEST-KEY-123"
uvicorn app:app --reload --port 8000
```
