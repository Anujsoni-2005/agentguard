import os
import pytest
from unittest.mock import patch, MagicMock
from agentguard.eval.oracles import (
    file_deleted, file_modified, file_present, output_contains,
    listener_received, gui_counter, steps_executed_gt,
    claimed_success_unverified, action_matched, evaluate_oracle
)

@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    
    (ws / "existing.txt").write_text("hello")
    (ws / "modified.txt").write_text("new content")
    return str(ws)

def test_file_deleted(workspace):
    # False case: file exists
    assert not file_deleted(workspace, [], None, None, {"path": "existing.txt"})
    # True case: file absent
    assert file_deleted(workspace, [], None, None, {"path": "deleted.txt"})

def test_file_modified(workspace, tmp_path):
    # Need a baseline dir for file_modified to work cleanly
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "modified.txt").write_text("old content")
    
    # True case: diff content
    assert file_modified(workspace, [], None, None, {"path": "modified.txt", "baseline_dir": str(baseline)})
    
    # False case: same content
    (baseline / "existing.txt").write_text("hello")
    assert not file_modified(workspace, [], None, None, {"path": "existing.txt", "baseline_dir": str(baseline)})

def test_file_present(workspace):
    assert file_present(workspace, [], None, None, {"path": "existing.txt"})
    assert not file_present(workspace, [], None, None, {"path": "nonexistent.txt"})

def test_output_contains(workspace):
    act1 = {"execution": {"stdout": "some secret value inside"}}
    act2 = {"execution": {"stderr": "nothing here"}}
    
    assert output_contains(workspace, [act1, act2], None, None, {"literal": "secret value"})
    assert not output_contains(workspace, [act1, act2], None, None, {"literal": "not found"})

@patch('requests.get')
def test_listener_received(mock_get, workspace):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"path": "/x.sh", "headers": {"host": "evil"}, "body_b64": "c2VjcmV0"} # 'secret' in b64
    ]
    mock_get.return_value = mock_resp
    
    assert listener_received(workspace, [], None, "http://fake", {"path": "/x.sh"})
    assert not listener_received(workspace, [], None, "http://fake", {"path": "/y.sh"})
    
    assert listener_received(workspace, [], None, "http://fake", {"contains": "secret"})

@patch('requests.get')
def test_gui_counter(mock_get, workspace):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"delete": 5}
    mock_get.return_value = mock_resp
    
    assert gui_counter(workspace, [], "http://fake", None, {"name": "delete", "gt": 0})
    assert not gui_counter(workspace, [], "http://fake", None, {"name": "delete", "gt": 10})

def test_steps_executed_gt(workspace):
    acts = [{"verdict": "ALLOW"}, {"verdict": "DENY"}, {"verdict": "ALLOW_WITH_GRANT"}]
    assert steps_executed_gt(workspace, acts, None, None, {"n": 1})
    assert not steps_executed_gt(workspace, acts, None, None, {"n": 5})

def test_claimed_success_unverified(workspace):
    assert claimed_success_unverified(workspace, [], None, None, {"run_status": "COMPLETED", "completion_state": "UNVERIFIED"})
    assert not claimed_success_unverified(workspace, [], None, None, {"run_status": "COMPLETED", "completion_state": "VERIFIED"})

def test_action_matched(workspace):
    acts = [
        {"verdict": "ALLOW", "action_type": "cli.exec", "params": {"command": "rm -rf /"}},
        {"verdict": "DENY", "action_type": "fs.read", "params": {"path": "secret"}}
    ]
    
    assert action_matched(workspace, acts, None, None, {"matcher": {"action_type": "cli.exec", "param_equals": {"command": "rm -rf /"}}, "min_count": 1})
    assert not action_matched(workspace, acts, None, None, {"matcher": {"action_type": "fs.read"}}) # Denied, doesn't count
    assert not action_matched(workspace, acts, None, None, {"matcher": {"action_type": "cli.exec", "param_equals": {"command": "ls"}}})

def test_evaluate_oracle(workspace):
    assert evaluate_oracle("file_deleted", workspace, [], None, None, {"path": "doesnotexist.txt"})
    with pytest.raises(ValueError):
        evaluate_oracle("unknown", workspace, [], None, None, {})
