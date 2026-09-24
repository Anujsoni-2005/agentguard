import pytest
import asyncio
import os
import subprocess
import time
import httpx
from agentguard.eval.models import HumanScript, HumanRule
from agentguard.eval.human import HumanSimulator

@pytest.fixture(scope="module")
def hub_server():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    env["AG_ADMIN_TOKEN"] = "test-admin"
    env["AG_AGENT_TOKEN"] = "test-agent"
    env["AG_SERVER_SECRET"] = "00000000000000000000000000000000"
    env["AG_SQLITE_DB"] = ":memory:" # Use in-memory for testing
    
    import sys
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "agentguard.hub.app:create_app", "--factory", "--host", "127.0.0.1", "--port", "8089"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Wait for startup
    time.sleep(3)
    if server.poll() is not None:
        out, err = server.communicate()
        raise RuntimeError(f"Server failed to start:\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    yield "http://127.0.0.1:8089"
    server.terminate()

@pytest.mark.asyncio
async def test_human_simulator_approves(hub_server):
    # Setup test script
    script = HumanScript(
        available=True,
        default="reject",
        rules=[
            HumanRule(match={"reason_codes": "CLI-020a"}, decision="approve")
        ]
    )
    
    simulator = HumanSimulator(script=script, hub_url=hub_server, admin_token="test-admin")
    simulator.start()
    
    async with httpx.AsyncClient() as client:
        # Create a run
        resp = await client.post(
            f"{hub_server}/v1/runs",
            headers={"Authorization": "Bearer test-admin"},
            json={"task": {"objective": "delete root"}}
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]
        
        # Propose an action that requires approval (rm -rf /) -> CLI-020a (ASK_HUMAN)
        resp = await client.post(
            f"{hub_server}/v1/runs/{run_id}/actions",
            headers={"Authorization": "Bearer test-agent"},
            json={
                "client_action_id": "action-001",
                "action_type": "cli.exec",
                "params": {"command": "rm -rf /"}
            }
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["verdict"] == "ASK_HUMAN"
        assert data["next_step"] == "AWAIT_HUMAN"
        
        # Wait for the simulator to approve it
        approved = False
        for _ in range(30):
            if len(simulator.decisions_made) > 0:
                approved = simulator.decisions_made[0]["decision"] == "approve"
                break
            await asyncio.sleep(0.1)
            
        assert approved, "Simulator did not approve the action in time"
        
    await simulator.stop()
