from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from coreworks_api.auth import get_current_user
from coreworks_api.main import app
from coreworks_api.monitor import _check_tcp

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


def test_tcp_check_reports_available_remote_service():
    with patch("coreworks_api.monitor.socket.create_connection"):
        result = _check_tcp("192.0.2.10", 22)
    assert result["status"] == "ok"
    assert "22" in result["message"]


def test_tcp_check_reports_unavailable_remote_service():
    with patch(
        "coreworks_api.monitor.socket.create_connection",
        side_effect=OSError("connection refused"),
    ):
        result = _check_tcp("192.0.2.10", 22)
    assert result["status"] == "error"
    assert result["checked_at"]


def test_registered_hosts_endpoint_requires_authentication():
    app.dependency_overrides.pop(get_current_user, None)
    try:
        response = client.get("/monitor/hosts")
        assert response.status_code == 401
    finally:
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
            id=1, username="monitor-test", role="user"
        )


def test_list_hosts_query_is_scoped_to_current_owner():
    from coreworks_api.monitor import list_hosts

    with patch("coreworks_api.monitor.engine.connect") as connect:
        connection = connect.return_value.__enter__.return_value
        connection.execute.return_value.mappings.return_value.all.return_value = []
        result = list_hosts(SimpleNamespace(id=41))

    assert result["total"] == 0
    statement = str(connection.execute.call_args.args[0])
    params = connection.execute.call_args.args[1]
    assert "WHERE owner_id = :owner_id" in statement
    assert params == {"owner_id": 41}


def test_add_host_stores_current_owner():
    from coreworks_api.monitor import add_host, HostCreate

    with patch("coreworks_api.monitor.engine.begin") as begin, patch(
        "coreworks_api.monitor._check_tcp",
        return_value={"status": "ok", "message": "reachable", "checked_at": "now"},
    ):
        connection = begin.return_value.__enter__.return_value
        connection.execute.return_value.mappings.return_value.one.return_value = {
            "id": 5,
            "name": "My host",
            "host": "192.0.2.10",
            "port": 22,
            "created_at": None,
        }
        add_host(
            HostCreate(name="My host", host="192.0.2.10", port=22),
            SimpleNamespace(id=41),
        )

    statement = str(connection.execute.call_args.args[0])
    params = connection.execute.call_args.args[1]
    assert "owner_id" in statement
    assert params["owner_id"] == 41


def test_delete_host_query_requires_current_owner():
    from coreworks_api.monitor import delete_host

    with patch("coreworks_api.monitor.engine.begin") as begin:
        connection = begin.return_value.__enter__.return_value
        connection.execute.return_value.rowcount = 1
        delete_host(5, SimpleNamespace(id=41))

    statement = str(connection.execute.call_args.args[0])
    params = connection.execute.call_args.args[1]
    assert "id = :host_id AND owner_id = :owner_id" in statement
    assert params == {"host_id": 5, "owner_id": 41}
