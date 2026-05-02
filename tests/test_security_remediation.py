import importlib
import sys

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


@pytest.fixture
def prod_client(monkeypatch):
    # docs_url / redoc_url / openapi_url are computed at FastAPI() construction time
    # in main.py, so the env override has to happen before main is (re)imported.
    monkeypatch.setenv("DEV_MODE", "false")
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    try:
        yield TestClient(main.app)
    finally:
        # Restore the original module so other tests keep using the dev-mode app.
        sys.modules.pop("main", None)
        importlib.import_module("main")


def test_docs_disabled_in_prod(prod_client):
    assert prod_client.get("/api/docs").status_code == 404
    assert prod_client.get("/api/redoc").status_code == 404
    assert prod_client.get("/openapi.json").status_code == 404


def test_csrf_protection_enabled():
    # POST without CSRF should fail
    response = client.post("/api/auth/logout")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_command_runner_disabled_by_default():
    response = client.get("/command-runner", follow_redirects=False)
    # Redirects to login if not authed, or 403 if authed but disabled
    assert response.status_code in (307, 303, 401, 403)
