import pytest
from unittest.mock import MagicMock
from agentguard.telemetry.anomaly import AnomalyEngine, Signal
from agentguard.models.policy import AnomalyPolicy
from agentguard.registry import ActionType

def make_obs_args(seq, fp, outcome="OK", out_hash=None, dur_ms=10, ws_epoch=1, action_type=ActionType.CLI_EXEC, target_host=None):
    action = MagicMock()
    action.seq = seq
    action.fingerprint = fp
    action.proposal.action_type = action_type
    action.params = MagicMock()
    if action_type == ActionType.NET_HTTP and target_host:
        action.params.url = f"https://{target_host}/path"
    elif action_type == ActionType.CLI_EXEC:
        action.params.command = "dummy"
        
    action.findings = []
    action.reason_codes = []
    action.result = None
    
    scratch = {}
    if action_type == ActionType.CLI_EXEC and target_host:
        scratch["cli_ir"] = {"static_hosts": [target_host]}
        
    return {
        "action": action,
        "scratch": scratch,
        "outcome": outcome,
        "out_hash": out_hash,
        "dur_ms": dur_ms,
        "ws_epoch": ws_epoch
    }

def test_anm_001_repeat_failure():
    engine = AnomalyEngine(AnomalyPolicy(repeat_fail_consecutive_warn=3, repeat_fail_trip_count=5, repeat_fail_window_s=60))
    fp = "fp1"
    
    # 1. X-F x3 within 20s -> WARN
    # We mock time.monotonic in the test or we just let it run fast?
    # Actually time.monotonic() is called inside observe(). We should patch it.
    import time
    with pytest.MonkeyPatch.context() as m:
        t = 100.0
        m.setattr(time, "monotonic", lambda: t)
        
        args = make_obs_args(1, fp, "FAIL")
        s1 = engine.observe(**args)
        assert not s1
        
        t += 5
        s2 = engine.observe(**args)
        assert not s2
        
        t += 5
        s3 = engine.observe(**args)
        assert len(s3) == 1
        assert s3[0].id == "ANM-001" and s3[0].level == "WARN"
        
        # 2. X-F x5 within 50s -> TRIP
        t += 10
        s4 = engine.observe(**args)
        t += 10
        s5 = engine.observe(**args)
        
        assert len(s5) == 1
        assert s5[0].id == "ANM-001" and s5[0].level == "TRIP"

def test_anm_001_spread_over_90s():
    engine = AnomalyEngine(AnomalyPolicy(repeat_fail_consecutive_warn=3, repeat_fail_trip_count=5, repeat_fail_window_s=60))
    fp = "fp2"
    import time
    with pytest.MonkeyPatch.context() as m:
        t = 100.0
        m.setattr(time, "monotonic", lambda: t)
        
        args = make_obs_args(1, fp, "FAIL")
        for i in range(5):
            t += 20 # 5 spread over 80s -> 4 intervals of 20s = 80s (window is 60s)
            s = engine.observe(**args)
            if i == 2:
                # 3rd occurrence
                assert any(sig.level == "WARN" for sig in s)
            
        # At 5th, the first one is at t=120, last is at t=200. Window 60s covers t=140 to 200, which is 4 items. So no trip.
        assert not any(sig.level == "TRIP" for sig in s)

def test_anm_001_interleave():
    engine = AnomalyEngine(AnomalyPolicy(repeat_fail_consecutive_warn=3, repeat_fail_trip_count=5, repeat_fail_window_s=60))
    import time
    with pytest.MonkeyPatch.context() as m:
        m.setattr(time, "monotonic", lambda: 100.0)
        
        args_x = make_obs_args(1, "fpX", "FAIL")
        args_y = make_obs_args(2, "fpY", "OK")
        
        engine.observe(**args_x)
        engine.observe(**args_y)
        engine.observe(**args_x)
        engine.observe(**args_y)
        s = engine.observe(**args_x)
        
        assert any(sig.id == "ANM-001" and sig.level == "WARN" for sig in s)

def test_anm_002_same_output():
    engine = AnomalyEngine(AnomalyPolicy(repeat_same_output_warn=3, repeat_same_output_trip=6))
    import time
    with pytest.MonkeyPatch.context() as m:
        m.setattr(time, "monotonic", lambda: 100.0)
        args = make_obs_args(1, "ls_fp", outcome="OK", out_hash="hash1", ws_epoch=1)
        
        s = []
        for _ in range(6):
            s = engine.observe(**args)
            
        assert any(sig.id == "ANM-002" and sig.level == "TRIP" for sig in s)
        
def test_anm_002_ws_epoch_reset():
    engine = AnomalyEngine(AnomalyPolicy(repeat_same_output_warn=3, repeat_same_output_trip=6))
    import time
    with pytest.MonkeyPatch.context() as m:
        m.setattr(time, "monotonic", lambda: 100.0)
        args1 = make_obs_args(1, "ls_fp", outcome="OK", out_hash="hash1", ws_epoch=1)
        args2 = make_obs_args(1, "ls_fp", outcome="OK", out_hash="hash1", ws_epoch=2)
        
        for _ in range(3):
            engine.observe(**args1)
        for _ in range(3):
            s = engine.observe(**args2)
            
        # Because ws_epoch changes, it resets
        assert not any(sig.id == "ANM-002" and sig.level == "TRIP" for sig in s)

def test_anm_004_oscillation():
    engine = AnomalyEngine(AnomalyPolicy())
    import time
    with pytest.MonkeyPatch.context() as m:
        m.setattr(time, "monotonic", lambda: 100.0)
        
        # A,B,A,B
        for i in range(2):
            engine.observe(**make_obs_args(1, "fpA"))
            s = engine.observe(**make_obs_args(2, "fpB"))
            
        assert any(sig.id == "ANM-004" and sig.level == "WARN" for sig in s)
        
        for i in range(2):
            engine.observe(**make_obs_args(1, "fpA"))
            s = engine.observe(**make_obs_args(2, "fpB"))
            
        assert any(sig.id == "ANM-004" and sig.level == "TRIP" for sig in s)

def test_anm_004_silent_on_p1():
    engine = AnomalyEngine(AnomalyPolicy())
    import time
    with pytest.MonkeyPatch.context() as m:
        m.setattr(time, "monotonic", lambda: 100.0)
        
        s = []
        for _ in range(4):
            s = engine.observe(**make_obs_args(1, "fpA"))
            
        assert not any(sig.id == "ANM-004" for sig in s)

def test_anm_009_evasion():
    engine = AnomalyEngine(AnomalyPolicy())
    import time
    with pytest.MonkeyPatch.context() as m:
        m.setattr(time, "monotonic", lambda: 100.0)
        
        # First, deny a CLI exec that targets evil.example
        args_deny = make_obs_args(1, "fp1", outcome="DENIED", action_type=ActionType.CLI_EXEC, target_host="evil.example")
        f = MagicMock()
        f.severity = 80
        args_deny["action"].findings = [f]
        
        engine.observe(**args_deny)
        
        # Then, another action (HTTP) to the same target
        args_http = make_obs_args(2, "fp2", outcome="OK", action_type=ActionType.NET_HTTP, target_host="evil.example")
        s = engine.observe(**args_http)
        assert any(sig.id == "ANM-009" and sig.level == "WARN" for sig in s)
        
        # Then another one
        args_http2 = make_obs_args(3, "fp3", outcome="OK", action_type=ActionType.NET_HTTP, target_host="evil.example")
        s2 = engine.observe(**args_http2)
        assert any(sig.id == "ANM-009" and sig.level == "ESCALATE" for sig in s2)
