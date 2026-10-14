from datetime import datetime, timezone
import ipaddress
import re
import socket

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from coreworks_api.auth import get_current_user
from coreworks_api.db import engine

router = APIRouter(prefix="/monitor", tags=["monitoring"])


class HostCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)


def _validate_host(host: str) -> str:
    host = host.strip()
    if (
        not host
        or any(char.isspace() for char in host)
        or any(char in host for char in "/@?#")
        or not re.fullmatch(r"[A-Za-z0-9_.:-]+", host)
    ):
        raise HTTPException(
            status_code=422,
            detail="Unesite ispravnu IP adresu ili DNS naziv, bez protokola i putanje.",
        )

    # Reject unspecified and multicast IP addresses.
    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast:
            raise HTTPException(status_code=422, detail="Nevažeća ciljna IP adresa.")
    except ValueError:
        pass

    return host


def _check_tcp(host: str, port: int) -> dict:
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return {
                "status": "ok",
                "message": f"TCP port {port} je dostupan.",
                "checked_at": checked_at,
            }
    except (OSError, TimeoutError):
        return {
            "status": "error",
            "message": f"Host ili TCP port {port} nije dostupan.",
            "checked_at": checked_at,
        }


def _database_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Monitor trenutno ne može da pristupi bazi podataka.",
    )


@router.get("/hosts")
def list_hosts(current_user=Depends(get_current_user)) -> dict:
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text("""
                    SELECT id, name, host, port, created_at
                    FROM coreworks_monitor_hosts
                    WHERE owner_id = :owner_id
                    ORDER BY name, id
                """),
                {"owner_id": current_user.id},
            ).mappings().all()
    except SQLAlchemyError:
        raise _database_error() from None

    hosts = []
    for row in rows:
        item = {
            "id": row["id"],
            "name": row["name"],
            "host": row["host"],
            "port": row["port"],
            "created_at": row["created_at"],
        }
        item.update(_check_tcp(row["host"], row["port"]))
        hosts.append(item)

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "total": len(hosts),
        "hosts": hosts,
    }


@router.post("/hosts", status_code=201)
def add_host(
    request: HostCreate,
    current_user=Depends(get_current_user),
) -> dict:
    name = request.name.strip()
    host = _validate_host(request.host)

    if not name:
        raise HTTPException(status_code=422, detail="Naziv hosta je obavezan.")

    try:
        with engine.begin() as connection:
            row = connection.execute(
                text("""
                    INSERT INTO coreworks_monitor_hosts
                        (owner_id, name, host, port)
                    VALUES (:owner_id, :name, :host, :port)
                    RETURNING id, name, host, port, created_at
                """),
                {
                    "owner_id": current_user.id,
                    "name": name,
                    "host": host,
                    "port": request.port,
                },
            ).mappings().one()
    except IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Ovaj host i port su već registrovani kod vašeg korisnika.",
        ) from None
    except SQLAlchemyError:
        raise _database_error() from None

    result = dict(row)
    result.update(_check_tcp(host, request.port))
    return result


@router.delete("/hosts/{host_id}", status_code=204)
def delete_host(
    host_id: int,
    current_user=Depends(get_current_user),
) -> None:
    try:
        with engine.begin() as connection:
            result = connection.execute(
                text("""
                    DELETE FROM coreworks_monitor_hosts
                    WHERE id = :host_id AND owner_id = :owner_id
                """),
                {"host_id": host_id, "owner_id": current_user.id},
            )
            if result.rowcount == 0:
                # Do not reveal whether another user owns this ID.
                raise HTTPException(status_code=404, detail="Host nije pronađen.")
    except SQLAlchemyError:
        raise _database_error() from None


@router.get("/status")
def monitor_status(_current_user=Depends(get_current_user)) -> dict:
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
        checks.append({
            "name": "PostgreSQL",
            "status": "ok",
            "message": "Konekcija sa bazom je uspešna.",
        })
    except SQLAlchemyError:
        checks.append({
            "name": "PostgreSQL",
            "status": "error",
            "message": "Nije moguće povezivanje sa bazom podataka.",
        })

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": (
            "ok" if all(item["status"] == "ok" for item in checks) else "error"
        ),
        "checks": checks,
    }
