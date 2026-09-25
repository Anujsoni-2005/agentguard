import pytest
import os
import subprocess

def test_bench_harness_execution():
    """Ensure that the benchmarking harness runs and saves the results without crashing."""
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    
    import sys
    result = subprocess.run(
        [sys.executable, "-m", "agentguard.bench"],
        capture_output=True,
        text=True,
        env=env
    )
    assert result.returncode == 0
    assert os.path.exists("bench/results.json")
    assert os.path.exists("bench/report.md")
    
    with open("bench/results.json", "r") as f:
        content = f.read()
        assert "micro" in content
        assert "fsync_p99_ms" in content

import asyncio
from agentguard.hub.app import lifespan
from fastapi import FastAPI
from agentguard.config import Settings

def dummy_add(a, b):
    return a + b

@pytest.mark.asyncio
async def test_lifespan_process_pool():
    app = FastAPI()
    app.state.settings = Settings(
        agent_token="test",
        admin_token="test",
        internal_token="test",
        server_secret="x"*32
    )
    
    async with lifespan(app):
        assert hasattr(app.state, "process_pool")
        
        # Test the pool can execute something
        future = app.state.process_pool.submit(dummy_add, 2, 3)
        assert future.result() == 5
