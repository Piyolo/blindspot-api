# BlindSpot API (backend)

FastAPI backend for BlindSpot — household object detection for the visually
impaired. Phase 0 skeleton: health endpoints and a Neon/PgBouncer-safe
asyncpg database layer.

## Local setup (Windows PowerShell, from `backend/`)

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest
```

## Local run

```powershell
$env:DATABASE_URL = "<your dev database url>"
.\.venv\Scripts\python -m uvicorn app.main:app --reload
```

Endpoints: `GET /api/v1/health`, `GET /api/v1/health/db`.

## Deploy (Render)

Service name: `blindspot-api`. Configure these environment variables (names
only — values live in Render's dashboard / local `.env`, never in git):

- `DATABASE_URL`
- `JWT_SECRET`

Copy `.env.example` to `.env` for local values (`.env` is gitignored).
