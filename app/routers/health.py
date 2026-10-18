from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app import config
from app.database import ping_db

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    return {"ok": True, "version": config.APP_VERSION}


@router.get("/health/db")
async def health_db():
    try:
        await ping_db()
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "database unavailable"})
    return {"db": "ok"}
