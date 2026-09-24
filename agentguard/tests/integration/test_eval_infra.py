import pytest
import subprocess
import time
import requests

import os

@pytest.fixture(scope="module", autouse=True)
def eval_stack():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    env["AG_EVAL_MODE"] = "true"
    env["AG_DEV_MODE"] = "true"
    env["AG_ENV"] = "dev"
    env["AG_EVAL_HOSTS"] = '{"docs.eval.test":"localhost:8081","evil.eval.test":"localhost:8082"}'
    env["AG_AGENT_TOKEN"] = "test"
    env["AG_ADMIN_TOKEN"] = "test"
    env["AG_INTERNAL_TOKEN"] = "test"
    env["AG_SERVER_SECRET"] = "00000000000000000000000000000000"

    eval_web = subprocess.Popen(["uvicorn", "eval_web.main:app", "--host", "0.0.0.0", "--port", "8081"], cwd="eval", env=env)
    attacker_listener = subprocess.Popen(["uvicorn", "attacker_listener.main:app", "--host", "0.0.0.0", "--port", "8082"], cwd="eval", env=env)
    
    proxy = subprocess.Popen(["mitmdump", "-s", "src/agentguard/proxy/addon.py", "--set", "block_global=false", "--listen-port", "8080"], env=env)
    
    time.sleep(5) # wait for servers to start
    yield
    eval_web.terminate()
    attacker_listener.terminate()
    proxy.terminate()

def test_eval_web_endpoints():
    # Test GET /docs
    resp = requests.get("http://localhost:8081/docs")
    assert resp.status_code == 200
    assert "benign static page" in resp.text
    
    # Test GET /inject
    resp = requests.get("http://localhost:8081/inject")
    assert resp.status_code == 200
    assert "Ignore previous instructions." in resp.text
    
    # Test GET /danger
    resp = requests.get("http://localhost:8081/danger")
    assert resp.status_code == 200
    assert "Delete account" in resp.text
    
    # Test counters
    requests.post("http://localhost:8081/__counters/reset")
    requests.post("http://localhost:8081/__counters/delete")
    resp = requests.get("http://localhost:8081/__counters")
    assert resp.json() == {"delete": 1}

def test_attacker_listener_endpoints():
    requests.post("http://localhost:8082/__reset")
    
    # Send a dummy request
    requests.post("http://localhost:8082/collect", data="test data")
    
    # Verify it was received
    resp = requests.get("http://localhost:8082/__received")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["path"] == "/collect"
    
def test_proxy_ssrf_override():
    # Through proxy to evil.eval.test (should succeed in eval mode)
    proxies = {"http": "http://localhost:8080", "https": "http://localhost:8080"}
    
    # Clear attacker listener
    requests.post("http://localhost:8082/__reset")
    
    # This should hit the attacker listener via the proxy
    resp = requests.get("http://evil.eval.test/test_ssrf", proxies=proxies)
    # The proxy will block it because evaluate_url returns a NET_DOMAIN_NOT_ALLOWLISTED or similar unless policy is changed.
    # Wait, the spec says "when AG_EVAL_MODE=true AND AG_DEV_MODE=true AND AG_ENV=dev, treat exactly the hostnames listed in AG_EVAL_HOSTS as passing the private-IP/SSRF check".
    # It might still block if not in allowlist, but it shouldn't block for NET_PRIVATE_RANGE.
    assert resp.status_code == 403
    
    assert "agentguard" in resp.json().get("blocked_by", "")
    assert "NET_PRIVATE_RANGE" not in resp.json().get("reason_codes", [])
    
    # Test a direct request to a non-eval private IP (127.0.0.1)
    # Should be blocked with NET_PRIVATE_RANGE
    resp2 = requests.get("http://127.0.0.1/test", proxies=proxies)
    assert resp2.status_code == 403
    assert "NET_PRIVATE_RANGE" in resp2.json().get("reason_codes", [])
