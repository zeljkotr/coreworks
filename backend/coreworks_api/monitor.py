from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from coreworks_api.auth import get_current_user
from coreworks_api.db import engine

router = APIRouter(prefix="/monitor", tags=["monitoring"])


@router.get("/status")
def monitor_status(
    _current_user=Depends(get_current_user),
) -> dict:
    checked_at = datetime.now(timezone.utc).isoformat()

    checks = [
        {
            "name": "CoreWorks API",
            "status": "ok",
            "message": "API je dostupna.",
        }
    ]

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar_one()
        database_check = {
            "name": "PostgreSQL",
            "status": "ok",
            "message": "Konekcija sa bazom je uspešna.",
        }
    except SQLAlchemyError:
        database_check = {
            "name": "PostgreSQL",
            "status": "error",
            "message": "Nije moguće povezivanje sa bazom podataka.",
        }

    checks.append(database_check)
    return {
        "checked_at": checked_at,
        "status": (
            "ok"
            if all(check["status"] == "ok" for check in checks)
            else "error"
        ),
        "checks": checks,
    }
