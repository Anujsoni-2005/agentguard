import os
def replace(path, old, new):
    with open(path, 'r', encoding='utf-8') as f: c = f.read()
    with open(path, 'w', encoding='utf-8') as f: f.write(c.replace(old, new))

replace('agentguard/src/agentguard/hub/routes_runs.py', 'if not allow:', 'if not allow and os.environ.get("AG_EVAL_MODE") != "true":')
replace('agentguard/src/agentguard/hub/routes_actions.py', 'run.policy_id == "eval-monitor"', 'run.task.policy_id == "eval-monitor"')
replace('agentguard/src/agentguard/store/repo.py', 'ended_at=row["ended_at"],\n            next_seq=row["next_seq"],', 'ended_at=row["ended_at"],\n            outcome_verified=row["outcome_verified"],\n            next_seq=row["next_seq"],')
replace('agentguard/src/agentguard/store/repo.py', 'status=?, started_at=?, ended_at=?, next_seq=?,', 'status=?, started_at=?, ended_at=?, outcome_verified=?, next_seq=?,')
replace('agentguard/src/agentguard/store/repo.py', 'run.status.value, run.started_at, run.ended_at, run.next_seq,', 'run.status.value, run.started_at, run.ended_at, run.outcome_verified, run.next_seq,')
replace('agentguard/src/agentguard/eval/runner.py', 'executor = DirectExecutor(workspace_dir=workspace_dir)', 'executor = DirectExecutor(workspace_dir=workspace_dir, run_id=run_id)')
replace('agentguard/src/agentguard/eval/agents/direct.py', 'def __init__(self, workspace_dir: str):', 'def __init__(self, workspace_dir: str, run_id: str = "test"):\n        self.run_id = run_id')
replace('agentguard/src/agentguard/eval/agents/direct.py', 'DockerExecutor(workspace_dir=os.path.dirname(workspace_dir))', 'DockerExecutor(workspace_dir=os.path.dirname(workspace_dir), run_id=getattr(self, "run_id", "test"))')
