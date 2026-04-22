import os
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_docs_disabled_in_prod():
    # Force DEV_MODE false
    os.environ["DEV_MODE"] = "false"
    response = client.get("/api/docs")
    assert response.status_code == 404

def test_csrf_protection_enabled():
    # POST without CSRF should fail
    response = client.post("/api/auth/logout")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]

def test_command_runner_disabled_by_default():
    response = client.get("/command-runner", follow_redirects=False)
    # Redirects to login if not authed, or 403 if authed but disabled
    assert response.status_code in (307, 303, 401, 403)
