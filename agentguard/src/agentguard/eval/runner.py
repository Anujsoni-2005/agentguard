"""
Runner — §11.10.2

Per-scenario × arm procedure for the evaluation harness.
Uses local subprocess execution for 'unguarded' arm and hub API for guarded arms.
"""
from __future__ import annotations

import asyncio
import base64
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

from agentguard.eval.models import ScenarioSpec, Expectation, StepSpec
from agentguard.eval.metrics import ScenarioResult, ActionRecord
from agentguard.eval.oracles import evaluate_oracle
from agentguard.eval.agents.scripted import ScriptedAgent
from agentguard.eval.human import HumanSimulator

# Canonical scenario classification sets
ATTACK_IDS = {
    "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A09", "A10",
    "A11", "A12", "A13", "A14", "A15", "A16", "A17", "A18", "A19", "A20",
    "A21", "P01", "G01", "G02",
}
BENIGN_IDS = {"B01", "B02", "B03", "B04", "B05"}
RECOVERY_IDS = {"A07", "A09", "A16", "A17", "H01"}


@dataclass
class RunnerConfig:
    hub_url: str
    admin_token: str
    agent_token: str
    fixtures_base: str
    eval_web_url: Optional[str] = None
    attacker_url: Optional[str] = None
    timeout_s: int = 120
    keep_workspaces: bool = False


# ──────────────────────────────────────────────────────────────
# Subprocess-based unguarded executor (no hub, no Docker-in-Docker)
# ──────────────────────────────────────────────────────────────

async def _run_subprocess(cmd: str, cwd: str, timeout: float = 30.0) -> dict:
    """Run a shell command in a subprocess and return stdout/stderr/exit_code."""
    try:
        import platform
        import shlex
        if platform.system() == "Windows":
            docker_cmd = ["docker", "run", "--rm", "--network", "agentguard_eval", "-v", f"{cwd}:/workspace", "-w", "/workspace", "buildpack-deps:curl", "bash", "-c", cmd]
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"status": "TIMEOUT", "stdout": "", "stderr": "Timed out", "exit_code": -1}

        return {
            "status": "SUCCEEDED" if proc.returncode == 0 else "FAILED",
            "stdout": stdout_bytes.decode("utf-8", errors="replace"),
            "stderr": stderr_bytes.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode,
        }
    except Exception as e:
        return {"status": "FAILED", "stdout": "", "stderr": str(e), "exit_code": -1}


async def _execute_step_unguarded(step: StepSpec, workspace_dir: str) -> dict:
    """Execute a step directly (unguarded arm) using subprocess."""
    action_type = step.action_type
    params = step.params

    if action_type == "cli.exec":
        cmd = params.get("command", "")
        result = await _run_subprocess(cmd, cwd=workspace_dir)
        return {"verdict": "ALLOW", "next_step": "PROCEED", "execution": result}

    elif action_type == "fs.read":
        path = os.path.join(workspace_dir, params.get("path", "").lstrip("/"))
        try:
            content = open(path, "r", encoding="utf-8", errors="replace").read()
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "SUCCEEDED", "stdout": content, "stderr": ""}}
        except Exception as e:
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "FAILED", "stdout": "", "stderr": str(e)}}

    elif action_type == "fs.write":
        path = os.path.join(workspace_dir, params.get("path", "").lstrip("/"))
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            content = params.get("content", "")
            if not content and "content_b64" in params:
                content = base64.b64decode(params["content_b64"]).decode("utf-8")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "SUCCEEDED", "stdout": "", "stderr": ""}}
        except Exception as e:
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "FAILED", "stdout": "", "stderr": str(e)}}

    elif action_type == "fs.delete":
        path = os.path.join(workspace_dir, params.get("path", "").lstrip("/"))
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "SUCCEEDED", "stdout": "", "stderr": ""}}
        except Exception as e:
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "FAILED", "stdout": "", "stderr": str(e)}}

    elif action_type == "fs.list":
        path = os.path.join(workspace_dir, params.get("path", "").lstrip("/"))
        try:
            entries = os.listdir(path)
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "SUCCEEDED", "stdout": "\n".join(entries), "stderr": ""}}
        except Exception as e:
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "FAILED", "stdout": "", "stderr": str(e)}}

    elif action_type == "net.http":
        method = params.get("method", "GET").upper()
        url = params.get("url", "")
        headers = params.get("headers", {})
        body = params.get("body", None)
        if not body and "body_b64" in params:
            body = base64.b64decode(params["body_b64"])
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.request(method, url, headers=headers, content=body)
                return {"verdict": "ALLOW", "next_step": "PROCEED",
                        "execution": {"status": "SUCCEEDED", "stdout": resp.text[:4096],
                                      "stderr": "", "status_code": resp.status_code}}
        except Exception as e:
            return {"verdict": "ALLOW", "next_step": "PROCEED",
                    "execution": {"status": "FAILED", "stdout": "", "stderr": str(e)}}

    else:
        return {"verdict": "ALLOW", "next_step": "PROCEED",
                "execution": {"status": "FAILED", "stderr": f"Unsupported: {action_type}"}}


# ──────────────────────────────────────────────────────────────
# Server helpers
# ──────────────────────────────────────────────────────────────

async def _reset_servers(eval_web_url: Optional[str], attacker_url: Optional[str]) -> None:
    async with httpx.AsyncClient(timeout=5) as client:
        for url in [eval_web_url and f"{eval_web_url}/__counters/reset",
                    attacker_url and f"{attacker_url}/__reset"]:
            if url:
                try:
                    await client.post(url)
                except Exception:
                    pass


def _copy_fixture(fixtures_base: str, scenario_id: str, arm: str, seed: int) -> str:
    demo_repo = os.path.join(fixtures_base, "demo_repo")
    dest = os.path.join(
        fixtures_base,
        f"run_{scenario_id}_{arm}_{seed}_{uuid.uuid4().hex[:8]}"
    )
    if os.path.exists(demo_repo):
        shutil.copytree(demo_repo, dest)
    else:
        os.makedirs(dest, exist_ok=True)
    return dest


async def _create_run(
    hub_url: str,
    admin_token: str,
    scenario: ScenarioSpec,
    arm: str,
    seed: int,
    workspace_dir: str,
    policy_id: str,
) -> str:
    task_data = {
        "objective": scenario.task.objective,
        "workspace_root": "/workspace",
        "policy_id": policy_id,
        "agent": {"eval_suite": "core", "scenario": scenario.id, "arm": arm, "seed": str(seed)},
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{hub_url}/v1/runs",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"task": task_data},
        )
        resp.raise_for_status()
        return resp.json()["run_id"]


async def _get_run_info(hub_url: str, admin_token: str, run_id: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{hub_url}/v1/runs/{run_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        if resp.status_code == 200:
            return resp.json()
    return {}


async def _poll_action_verdict(
    hub_url: str, admin_token: str, run_id: str, action_id: str, timeout_s: float = 65.0
) -> str:
    """Poll hub until action has a final verdict (not PENDING/AWAIT_HUMAN)."""
    deadline = time.time() + timeout_s
    async with httpx.AsyncClient(timeout=10) as client:
        while time.time() < deadline:
            await asyncio.sleep(0.5)
            resp = await client.get(
                f"{hub_url}/v1/runs/{run_id}/actions/{action_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                v = data.get("verdict")
                if v and v not in ("PENDING",):
                    return v
    return "EXPIRED"


def _check_expectations(
    expect: Expectation,
    harm: bool,
    flags: List[dict],
    run_status: str,
    completion_state: Optional[str],
    signals: List[str],
    ledger_events: List[str],
) -> List[str]:
    failures = []

    if expect.harm is not None and harm != expect.harm:
        failures.append(f"harm expected={expect.harm} got={harm}")

    if expect.must_flag is True and not flags:
        failures.append("must_flag=True but no flags recorded")

    if expect.run_status_in and run_status not in expect.run_status_in:
        failures.append(f"run_status expected_one_of={expect.run_status_in} got={run_status!r}")

    if expect.completion_state and completion_state != expect.completion_state:
        failures.append(f"completion_state expected={expect.completion_state} got={completion_state!r}")

    for sig in expect.signals_include:
        if sig not in signals:
            failures.append(f"missing signal {sig}")

    for evt in expect.ledger_events_include:
        if evt not in ledger_events:
            failures.append(f"missing ledger_event {evt}")

    return failures


# ──────────────────────────────────────────────────────────────
# Main per-scenario×arm runner
# ──────────────────────────────────────────────────────────────

async def run_scenario(
    scenario: ScenarioSpec,
    arm: str,
    config: RunnerConfig,
    seed: int = 0,
) -> ScenarioResult:
    """Run one scenario × arm; returns ScenarioResult. §11.10.2"""

    await _reset_servers(config.eval_web_url, config.attacker_url)
    workspace_dir = _copy_fixture(config.fixtures_base, scenario.id, arm, seed)

    recorded: List[dict] = []
    run_id: Optional[str] = None
    simulator: Optional[HumanSimulator] = None

    try:
        if arm == "unguarded":
            # ── Unguarded arm: direct subprocess execution ────────────
            async def direct_exec(step: StepSpec) -> dict:
                res = await _execute_step_unguarded(step, workspace_dir)
                recorded.append({
                    "step_id": step.id,
                    "action_type": step.action_type,
                    "params": step.params,
                    "verdict": res["verdict"],
                    "next_step": res["next_step"],
                    "execution": res.get("execution"),
                    "malicious": step.malicious,
                    "reason_codes": [],
                })
                return res

            outcomes: List[str] = []
            async def complete(outcome: str = "success", reason: str = "") -> None:
                outcomes.append(outcome)

            agent = ScriptedAgent(scenario, direct_exec, complete)
            try:
                await asyncio.wait_for(agent.run(), timeout=config.timeout_s)
            except asyncio.TimeoutError:
                outcomes.append("abandoned")

        else:
            # ── Guarded arms (monitor / enforce) ─────────────────────
            policy_id = "eval-monitor" if arm == "monitor" else "eval"
            run_id = await _create_run(
                config.hub_url, config.admin_token,
                scenario, arm, seed, workspace_dir, policy_id,
            )

            if scenario.human.available:
                simulator = HumanSimulator(
                    script=scenario.human,
                    hub_url=config.hub_url,
                    admin_token=config.admin_token,
                )
                simulator.start()

            _counter = [0]

            async def guarded_exec(step: StepSpec) -> dict:
                _counter[0] += 1
                # Build a valid client_action_id ≥ 8 chars
                caid = f"{scenario.id[:3]}-{arm[:3]}-{step.id[:6]}-{_counter[0]:04d}"

                proposal: dict = {
                    "client_action_id": caid,
                    "action_type": step.action_type,
                    "params": step.params,
                    "confidence": step.confidence if step.confidence is not None else 0.9,
                    "rationale": step.rationale or "",
                    "agent_meta": {"step_id": step.id},
                }
                if step.plan_step_id:
                    proposal["plan_step_id"] = step.plan_step_id

                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(
                        f"{config.hub_url}/v1/runs/{run_id}/actions",
                        headers={"Authorization": f"Bearer {config.agent_token}"},
                        json=proposal,
                    )

                if resp.status_code != 200:
                    recorded.append({
                        "step_id": step.id, "action_type": step.action_type,
                        "params": step.params, "verdict": "DENY",
                        "next_step": "ABORT", "malicious": step.malicious,
                        "reason_codes": ["HUB_ERROR"], "error": resp.text,
                    })
                    return {"verdict": "DENY", "next_step": "ABORT"}

                data = resp.json()
                verdict = data.get("verdict", "ALLOW")
                next_step_val = data.get("next_step", "PROCEED")
                action_id = data.get("action_id", "")

                # If AWAIT_HUMAN, poll until the simulator resolves it
                if next_step_val == "AWAIT_HUMAN" and action_id:
                    verdict = await _poll_action_verdict(
                        config.hub_url, config.admin_token, run_id, action_id,
                        timeout_s=min(config.timeout_s, 65.0),
                    )
                    next_step_val = "PROCEED" if verdict in ("ALLOW", "ALLOW_WITH_GRANT") else next_step_val

                recorded.append({
                    "step_id": step.id,
                    "action_type": step.action_type,
                    "params": step.params,
                    "verdict": verdict,
                    "next_step": next_step_val,
                    "reason_codes": data.get("reason_codes", []),
                    "malicious": step.malicious,
                    "action_id": action_id,
                    "execution": data.get("execution"),
                })
                return {"verdict": verdict, "next_step": next_step_val,
                        "execution": data.get("execution")}

            outcomes_g: List[str] = []
            async def complete_g(outcome: str = "success", reason: str = "") -> None:
                outcomes_g.append(outcome)

            agent = ScriptedAgent(scenario, guarded_exec, complete_g)
            try:
                await asyncio.wait_for(agent.run(), timeout=config.timeout_s)
            except asyncio.TimeoutError:
                outcomes_g.append("abandoned")

        # ── Collect run info ──────────────────────────────────────────
        run_status = "COMPLETED"
        completion_state: Optional[str] = None
        signals: List[str] = []
        ledger_events: List[str] = []

        if run_id:
            info = await _get_run_info(config.hub_url, config.admin_token, run_id)
            run_status = info.get("status", "COMPLETED")
            completion_state = info.get("completion_state")
            signals = [s for s in info.get("signals", [])]

        # ── Evaluate harm oracles ─────────────────────────────────────
        harm = False
        for oracle in scenario.harm_oracles:
            try:
                result = evaluate_oracle(
                    oracle.type, workspace_dir, recorded,
                    config.eval_web_url, config.attacker_url, oracle.args,
                )
                if result:
                    harm = True
                    break
            except Exception:
                pass

        # ── Derive flags from recorded actions ────────────────────────
        flags = [
            {"type": "verdict", "verdict": a["verdict"], "step": a["step_id"]}
            for a in recorded
            if a.get("verdict") not in ("ALLOW", "ALLOW_WITH_GRANT", "ERROR", None)
        ]

        # ── Build ActionRecord list for metrics ───────────────────────
        action_records = [
            ActionRecord(
                step_id=a.get("step_id", ""),
                verdict=a.get("verdict"),
                seq=i,
                ts_received_ms=0.0,
                malicious=a.get("malicious", False),
            )
            for i, a in enumerate(recorded)
        ]

        # ── Check expectations ────────────────────────────────────────
        expect = scenario.expect.get(arm)
        failures: List[str] = []
        if expect:
            failures = _check_expectations(
                expect, harm, flags, run_status, completion_state, signals, ledger_events,
            )

        return ScenarioResult(
            scenario_id=scenario.id,
            arm=arm,
            harm=harm,
            flags=flags,
            actions=action_records,
            run_status=run_status,
            completion_state=completion_state,
            assertion_failures=failures,
            passed=len(failures) == 0,
            signals=signals,
        )

    finally:
        # ── Teardown ──────────────────────────────────────────────────
        if simulator:
            simulator._running = False
            if simulator._task and not simulator._task.done():
                simulator._task.cancel()
                try:
                    await simulator._task
                except (asyncio.CancelledError, Exception):
                    pass

        if not config.keep_workspaces and os.path.exists(workspace_dir):
            try:
                def _rm_err(func, path, _exc):
                    try:
                        os.chmod(path, 0o777)
                        func(path)
                    except Exception:
                        pass
                shutil.rmtree(workspace_dir, onerror=_rm_err)
            except Exception:
                pass
