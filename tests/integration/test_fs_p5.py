import pytest
import os
import yaml
from agentguard.fs.paths import FsPathValidator
from agentguard.fs.analyzer import FsAnalyzer
from agentguard.fs.workspace import WorkspaceManager
from agentguard.models.policy import FsPolicy, PolicyDoc
from agentguard.models.workspace import FsFacts, WorkspaceState
from types import SimpleNamespace

def test_fs_path_validator():
    policy = FsPolicy(workspace_root="/workspace", sensitive_path_globs=["**/.env"], copy_exclude_globs=[])
    
    # Valid relative
    rel, findings = FsPathValidator.normalize("src/a.py", "/workspace", policy)
    assert not findings
    assert rel == "src/a.py"
    
    # Valid absolute
    rel, findings = FsPathValidator.normalize("/workspace/src/a.py", "/workspace", policy)
    assert not findings
    assert rel == "src/a.py"
    
    # Escape
    rel, findings = FsPathValidator.normalize("/workspace/../etc/passwd", "/workspace", policy)
    assert any(f.rule_id == "FS-002" for f in findings)
    assert rel is None

def test_fs_analyzer_golden_cases():
    with open("tests/golden/fs_cases.yaml") as f:
        cases = yaml.safe_load(f)
        
    policy = PolicyDoc(
        fs=FsPolicy(
            workspace_root="/workspace",
            sensitive_path_globs=["**/.env", "**/.ssh/id_rsa"],
            protected_path_globs=[".github/workflows/**"],
            deny_paths=[".agentguard.yaml"],
            copy_exclude_globs=[]
        )
    )
    
    for case in cases:
        action_type = case["action"]
        params = case["params"]
        expected_verdict = case["expected_verdict"]
        expected_rule = case.get("expected_rule")
        
        ctx = SimpleNamespace(
            action=SimpleNamespace(action_type=action_type, params=params),
            policy=policy,
            run=SimpleNamespace(id="r1", workspace=WorkspaceState(
                run_id="r1", mode="empty", host_path=None, scratch_dir="/tmp/scratch", baseline_dir=None,
                created_at="now", file_count=0, total_bytes=0, excluded=[], skipped_symlinks=[],
                honeytoken_paths=[".env.backup", "config/prod_credentials.json.bak"],
                baseline_snapshot_id="", last_snapshot_id=""
            )),
            history=None,
            scratch={
                "fs": FsFacts(
                    rel_path=None, exists=True, kind="file", symlink_escape=case.get("facts", {}).get("symlink_escape", False),
                    workspace_growth_bytes=0, vetted_script=False
                )
            }
        )
        
        findings = FsAnalyzer.analyze(ctx)
        # Determine effective verdict
        effective = "ALLOW"
        matched_rule = None
        for f in findings:
            if f.verdict_hint.value == "DENY":
                effective = "DENY"
                matched_rule = f.rule_id
                break
            elif f.verdict_hint.value == "ASK_HUMAN":
                effective = "ASK_HUMAN"
                if not matched_rule:
                    matched_rule = f.rule_id
                    
        assert effective == expected_verdict, f"Case {case['id']} failed: got {effective} vs {expected_verdict}"
        if expected_rule:
            assert matched_rule == expected_rule, f"Case {case['id']} failed rule: got {matched_rule} vs {expected_rule}"
