import pytest
import httpx
from fastapi.testclient import TestClient
from agentguard.hub.app import create_app
from agentguard.config import Settings
import os
import uuid

@pytest.fixture
def test_app(tmp_path):
    os.environ["AG_DATA_DIR"] = str(tmp_path)
    os.environ["AG_ADMIN_TOKEN"] = "test-admin"
    os.environ["AG_AGENT_TOKEN"] = "test-agent"
    os.environ["AG_INTERNAL_TOKEN"] = "test-internal"
    os.environ["AG_SERVER_SECRET"] = "test-secret-012345678901234567890123456789"
    settings = Settings()
    app = create_app(settings)
    
    # We must explicitly initialize lifespan for TestClient
    with TestClient(app) as client:
        yield client

def test_p1_1_propose_echo(test_app):
    """Test 1: Propose cli.exec: echo hi → 200, ALLOW, PROCEED"""
    # Create run
    run_resp = test_app.post("/v1/runs", json={"task": {"objective": "test_objective"}, "budgets": {}}, headers={"Authorization": "Bearer test-agent"})
    assert run_resp.status_code == 201
    run_id = run_resp.json()["run_id"]

    # Propose action
    action = {
        "client_action_id": str(uuid.uuid4()),
        "action_type": "cli.exec",
        "params": {"command": "echo hi"},
        "rationale": "Just echoing"
    }
    resp = test_app.post(f"/v1/runs/{run_id}/actions", json=action, headers={"Authorization": "Bearer test-agent"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "ALLOW"
    assert data["next_step"] == "PROCEED"
    assert data["status"] == "APPROVED"


def test_p1_2_idempotency_same(test_app):
    """Test 2: Same client_action_id twice → identical decision"""
    run_resp = test_app.post("/v1/runs", json={"task": {"objective": "test_objective"}, "budgets": {}}, headers={"Authorization": "Bearer test-agent"})
    assert run_resp.status_code == 201
    run_id = run_resp.json()["run_id"]

    act_id = str(uuid.uuid4())
    action = {
        "client_action_id": act_id,
        "action_type": "cli.exec",
        "params": {"command": "echo hi"}
    }
    r1 = test_app.post(f"/v1/runs/{run_id}/actions", json=action, headers={"Authorization": "Bearer test-agent"})
    assert r1.status_code == 200
    
    # Second request exactly the same
    r2 = test_app.post(f"/v1/runs/{run_id}/actions", json=action, headers={"Authorization": "Bearer test-agent"})
    assert r2.status_code == 200
    assert r2.json()["idempotent_replay"] is True


def test_p1_3_idempotency_different(test_app):
    """Test 3: Same id + different command → 409"""
    run_resp = test_app.post("/v1/runs", json={"task": {"objective": "test_objective"}, "budgets": {}}, headers={"Authorization": "Bearer test-agent"})
    assert run_resp.status_code == 201
    run_id = run_resp.json()["run_id"]

    cid = uuid.uuid4().hex
    test_app.post(f"/v1/runs/{run_id}/actions", json={
        "client_action_id": cid,
        "action_type": "cli.exec",
        "params": {"command": "echo hi"}
    }, headers={"Authorization": "Bearer test-agent"})

    resp2 = test_app.post(f"/v1/runs/{run_id}/actions", json={
        "client_action_id": cid,
        "action_type": "cli.exec",
        "params": {"command": "echo bye"} # Different params
    }, headers={"Authorization": "Bearer test-agent"})
    
    assert resp2.status_code == 409

# Additional tests 4-12 can be populated here following the same pattern...
