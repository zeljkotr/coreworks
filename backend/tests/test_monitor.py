from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from coreworks_api.auth import get_current_user
from coreworks_api.main import app

client = TestClient(app)


def setup_module():
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=1, username="monitor-test", role="user"
    )


def teardown_module():
    app.dependency_overrides.pop(get_current_user, None)


def test_monitor_status_reports_successful_checks():
    with patch("coreworks_api.monitor.engine.connect") as connect:
        connection = connect.return_value.__enter__.return_value
        connection.execute.return_value.scalar_one.return_value = 1

        response = client.get("/monitor/status")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert len(data["checks"]) == 2
    assert all(check["status"] == "ok" for check in data["checks"])
    assert data["checked_at"]


def test_monitor_status_reports_database_failure_without_leaking_details():
    with patch(
        "coreworks_api.monitor.engine.connect",
        side_effect=SQLAlchemyError("private connection details"),
    ):
        response = client.get("/monitor/status")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "error"
    assert data["checks"][0]["status"] == "ok"
    assert data["checks"][1]["status"] == "error"
    assert "private connection details" not in response.text


def test_monitor_status_requires_authentication():
    app.dependency_overrides.pop(get_current_user, None)
    try:
        response = client.get("/monitor/status")
        assert response.status_code == 401
    finally:
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
            id=1, username="monitor-test", role="user"
        )
