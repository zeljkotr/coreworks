"""Authenticated ingestion and retrieval of remote Monitor agent metrics."""

from datetime import datetime, timezone
import hashlib
import json
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from coreworks_api.auth import get_current_user
from coreworks_api.db import engine

router = APIRouter(prefix="/monitor", tags=["monitor-agent"])
AGENT_VERSION = "1.0.0"


class DiskMetric(BaseModel):
    mountpoint: str = Field(min_length=1, max_length=512)
    total_bytes: int = Field(ge=0)
    used_bytes: int = Field(ge=0)
    free_bytes: int = Field(ge=0)


class MetricsPayload(BaseModel):
    cpu_percent: float = Field(ge=0, le=100)
    memory_total_bytes: int = Field(ge=0)
    memory_used_bytes: int = Field(ge=0)
    disk: list[DiskMetric] = Field(max_length=64)
    uptime_seconds: int = Field(ge=0)
    os_name: str = Field(min_length=1, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    agent_version: str = Field(min_length=1, max_length=40)


def _db_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Monitor trenutno ne može da pristupi bazi podataka.",
    )


@router.post("/hosts/{host_id}/agent-token")
def issue_agent_token(
    host_id: int,
    current_user=Depends(get_current_user),
) -> dict:
    """Rotate a host's agent token. The cleartext token is returned only once."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    try:
        with engine.begin() as connection:
            result = connection.execute(
                text("""
                    UPDATE coreworks_monitor_hosts
                    SET agent_token_hash = :token_hash,
                        agent_last_seen_at = NULL
                    WHERE id = :host_id AND owner_id = :owner_id
                    RETURNING id, name, host
                """),
                {
                    "token_hash": token_hash,
                    "host_id": host_id,
                    "owner_id": current_user.id,
                },
            ).mappings().first()
            if result is None:
                raise HTTPException(status_code=404, detail="Host nije pronađen.")
    except SQLAlchemyError:
        raise _db_error() from None

    return {
        "host_id": result["id"],
        "host_name": result["name"],
        "token": token,
        "agent_version": AGENT_VERSION,
        "message": "Token se prikazuje samo sada. Sačuvajte ga bezbedno.",
    }


@router.post("/agent/metrics")
def receive_agent_metrics(
    payload: MetricsPayload,
    authorization: str | None = Header(default=None),
) -> dict:
    """Agent endpoint: authenticate by per-host bearer token and save metrics."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Agent bearer token je obavezan.")

    token = authorization[7:].strip()
    if not token or len(token) > 512:
        raise HTTPException(status_code=401, detail="Nevažeći agent token.")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    disk_data = [disk.model_dump() for disk in payload.disk]
    for disk in disk_data:
        if disk["used_bytes"] > disk["total_bytes"]:
            raise HTTPException(status_code=422, detail="Nevažeći podaci o disku.")
        if disk["free_bytes"] > disk["total_bytes"]:
            raise HTTPException(status_code=422, detail="Nevažeći podaci o disku.")

    if payload.memory_used_bytes > payload.memory_total_bytes:
        raise HTTPException(status_code=422, detail="Nevažeći podaci o memoriji.")

    try:
        with engine.begin() as connection:
            host = connection.execute(
                text("""
                    SELECT id
                    FROM coreworks_monitor_hosts
                    WHERE agent_token_hash = :token_hash
                """),
                {"token_hash": token_hash},
            ).mappings().first()

            if host is None:
                raise HTTPException(status_code=401, detail="Agent token nije važeći.")

            connection.execute(
                text("""
                    INSERT INTO coreworks_monitor_metrics (
                        host_id, cpu_percent, memory_total_bytes,
                        memory_used_bytes, disk, uptime_seconds,
                        os_name, hostname, agent_version
                    ) VALUES (
                        :host_id, :cpu_percent, :memory_total_bytes,
                        :memory_used_bytes, CAST(:disk AS jsonb), :uptime_seconds,
                        :os_name, :hostname, :agent_version
                    )
                """),
                {
                    "host_id": host["id"],
                    "cpu_percent": payload.cpu_percent,
                    "memory_total_bytes": payload.memory_total_bytes,
                    "memory_used_bytes": payload.memory_used_bytes,
                    "disk": json.dumps(disk_data),
                    "uptime_seconds": payload.uptime_seconds,
                    "os_name": payload.os_name,
                    "hostname": payload.hostname,
                    "agent_version": payload.agent_version,
                },
            )
            connection.execute(
                text("""
                    UPDATE coreworks_monitor_hosts
                    SET agent_last_seen_at = :now,
                        agent_version = :version,
                        agent_os = :os_name
                    WHERE id = :host_id
                """),
                {
                    "now": datetime.now(timezone.utc),
                    "version": payload.agent_version,
                    "os_name": payload.os_name,
                    "host_id": host["id"],
                },
            )
    except HTTPException:
        raise
    except SQLAlchemyError:
        raise _db_error() from None

    return {"accepted": True}


@router.get("/hosts/{host_id}/metrics")
def get_host_metrics(
    host_id: int,
    limit: int = Query(default=60, ge=1, le=500),
    current_user=Depends(get_current_user),
) -> dict:
    """Return latest sample and history only for a host owned by the caller."""
    try:
        with engine.connect() as connection:
            host = connection.execute(
                text("""
                    SELECT id, name, host, port, agent_last_seen_at,
                           agent_version, agent_os
                    FROM coreworks_monitor_hosts
                    WHERE id = :host_id AND owner_id = :owner_id
                """),
                {"host_id": host_id, "owner_id": current_user.id},
            ).mappings().first()

            if host is None:
                raise HTTPException(status_code=404, detail="Host nije pronađen.")

            rows = connection.execute(
                text("""
                    SELECT id, recorded_at, cpu_percent,
                           memory_total_bytes, memory_used_bytes, disk,
                           uptime_seconds, os_name, hostname, agent_version
                    FROM coreworks_monitor_metrics
                    WHERE host_id = :host_id
                    ORDER BY recorded_at DESC, id DESC
                    LIMIT :limit
                """),
                {"host_id": host_id, "limit": limit},
            ).mappings().all()
    except HTTPException:
        raise
    except SQLAlchemyError:
        raise _db_error() from None

    history = [dict(row) for row in rows]
    for item in history:
        if item["recorded_at"] is not None:
            item["recorded_at"] = item["recorded_at"].isoformat()
    latest = history[0] if history else None

    return {
        "host": {
            "id": host["id"],
            "name": host["name"],
            "host": host["host"],
            "port": host["port"],
            "agent_last_seen_at": (
                host["agent_last_seen_at"].isoformat()
                if host["agent_last_seen_at"] else None
            ),
            "agent_version": host["agent_version"],
            "agent_os": host["agent_os"],
            "agent_connected": bool(
                host["agent_last_seen_at"]
                and (datetime.now(timezone.utc) - host["agent_last_seen_at"]).total_seconds() < 120
            ),
        },
        "latest": latest,
        "history": history,
    }


@router.get("/agent.py", include_in_schema=False)
def download_agent() -> FileResponse:
    """Download the agent source used by the host installation instructions."""
    from pathlib import Path

    agent_path = Path(__file__).resolve().parents[1] / "agent" / "coreworks_monitor_agent.py"
    if not agent_path.is_file():
        raise HTTPException(status_code=404, detail="Agent paket nije dostupan.")
    return FileResponse(
        agent_path,
        media_type="text/x-python",
        filename="coreworks_monitor_agent.py",
    )
