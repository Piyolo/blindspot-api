from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import config, database
from app.models import Base
from app.routers import auth, health

_VALUE_ERROR_PREFIX = "Value error, "


@asynccontextmanager
async def lifespan(_: FastAPI):
    engine = database.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="BlindSpot API", version=config.APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """String-shaped 400 for every request-validation error.

    The error body is always ``{"detail": "<string>"}`` — never pydantic's
    list-shaped 422. Errors raised as ``ValueError`` by the copy-deck
    validators arrive from pydantic as ``"Value error, <message>"``; the
    wrapper is stripped so the app hears exactly the copy-deck message.

    ``request`` is unused (kept for the handler signature); the function is
    module-level so it is unit-testable without a real request.
    """
    errors = exc.errors()
    message = str(errors[0].get("msg") or "") if errors else ""
    if message.startswith(_VALUE_ERROR_PREFIX):
        message = message[len(_VALUE_ERROR_PREFIX):]
    if not message:
        message = "Invalid request"
    return JSONResponse(status_code=400, content={"detail": message})


app.add_exception_handler(RequestValidationError, validation_exception_handler)
