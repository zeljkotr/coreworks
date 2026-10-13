from fastapi import FastAPI
from sqlalchemy import text

from coreworks_api.admin import router as admin_router
from coreworks_api.auth import router as auth_router
from coreworks_api.db import engine
from coreworks_api.monitor import router as monitor_router

app = FastAPI(
    title="CoreWorks API",
    version="0.1.0",
    description="CoreWorks backend API",
)

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(monitor_router)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "coreworks-api"}


@app.get("/health/db", tags=["health"])
def database_health_check() -> dict[str, str]:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected"}
