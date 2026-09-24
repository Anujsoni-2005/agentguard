"""
Tests for eval/metrics.py — §11.14 tests 7 & 8.
"""
import math
import pytest
from agentguard.eval.metrics import (
    wilson, harm_rate, prevention_rate, detection_rate,
    false_block_rate, task_success, recovery_success,
    audit_completeness, compute_all_metrics,
    ScenarioResult, ActionRecord
)


# ─────────────────────────────────────────────────────────────
# Wilson interval — §11.14 test 7
# ─────────────────────────────────────────────────────────────

def test_wilson_zero_of_twenty():
    lo, hi = wilson(0, 20)
    assert lo == pytest.approx(0.0, abs=0.01)
    assert hi == pytest.approx(0.161, abs=0.01)

def test_wilson_twenty_of_twenty():
    lo, hi = wilson(20, 20)
    assert lo == pytest.approx(0.839, abs=0.01)
    assert hi == pytest.approx(1.0, abs=0.01)

def test_wilson_ten_of_twenty():
    lo, hi = wilson(10, 20)
    assert lo == pytest.approx(0.299, abs=0.01)
    assert hi == pytest.approx(0.701, abs=0.01)

def test_wilson_zero_denominator():
    lo, hi = wilson(0, 0)
    assert lo == 0.0
    assert hi == 1.0


# ─────────────────────────────────────────────────────────────
# Synthetic metric tests — §11.14 test 8
# ─────────────────────────────────────────────────────────────

ATTACK_IDS = {"A01", "A02", "A03"}
BENIGN_IDS = {"B01", "B02"}
RECOVERY_IDS = {"A07"}

def make_results():
    return [
        # Attack scenarios — unguarded: all harmed
        ScenarioResult("A01", "unguarded", harm=True),
        ScenarioResult("A02", "unguarded", harm=True),
        ScenarioResult("A03", "unguarded", harm=True),
        # Attack scenarios — enforce: none harmed
        ScenarioResult("A01", "enforce", harm=False, flags=[{"type": "verdict"}], passed=True),
        ScenarioResult("A02", "enforce", harm=False, flags=[{"type": "verdict"}], passed=True),
        ScenarioResult("A03", "enforce", harm=False, flags=[{"type": "verdict"}], passed=True),
        # Attack scenarios — monitor: harm=true but flagged
        ScenarioResult("A01", "monitor", harm=False, flags=[{"type": "verdict"}]),
        ScenarioResult("A02", "monitor", harm=True, flags=[{"type": "verdict"}]),
        ScenarioResult("A03", "monitor", harm=True, flags=[{"type": "verdict"}]),
        # Benign — unguarded
        ScenarioResult("B01", "unguarded", harm=False, run_status="COMPLETED",
                       actions=[ActionRecord("s1", "ALLOW", 1, 100.0)]),
        ScenarioResult("B02", "unguarded", harm=False, run_status="COMPLETED",
                       actions=[ActionRecord("s1", "ALLOW", 1, 100.0)]),
        # Benign — enforce (all ALLOWed)
        ScenarioResult("B01", "enforce", harm=False, run_status="COMPLETED",
                       actions=[ActionRecord("s1", "ALLOW", 1, 100.0)]),
        ScenarioResult("B02", "enforce", harm=False, run_status="COMPLETED",
                       actions=[ActionRecord("s1", "ALLOW", 1, 100.0)]),
        # Recovery
        ScenarioResult("A07", "enforce", harm=False, run_status="COMPLETED", passed=True),
    ]


def test_harm_rate_unguarded():
    results = make_results()
    assert harm_rate(results, "unguarded", ATTACK_IDS) == pytest.approx(1.0)

def test_harm_rate_enforce():
    results = make_results()
    assert harm_rate(results, "enforce", ATTACK_IDS) == pytest.approx(0.0)

def test_prevention_rate():
    results = make_results()
    pr = prevention_rate(results, ATTACK_IDS)
    assert pr == pytest.approx(1.0)  # 1 - 0/1

def test_prevention_rate_undefined_when_no_unguarded_harm():
    results = [
        ScenarioResult("A01", "unguarded", harm=False),
        ScenarioResult("A01", "enforce", harm=False),
    ]
    assert prevention_rate(results, {"A01"}) is None

def test_detection_rate():
    results = make_results()
    # All 3 monitor results have flags
    rate = detection_rate(results, ATTACK_IDS, arm="monitor")
    assert rate == pytest.approx(1.0)

def test_false_block_rate_clean():
    results = make_results()
    fb = false_block_rate(results, BENIGN_IDS, arm="enforce")
    assert fb["deny"] == pytest.approx(0.0)
    assert fb["ask_per_task"] == pytest.approx(0.0)

def test_false_block_rate_with_denies():
    results = [
        ScenarioResult("B01", "enforce", harm=False, run_status="COMPLETED", actions=[
            ActionRecord("s1", "DENY", 1, 100.0),
            ActionRecord("s2", "ALLOW", 2, 200.0),
        ]),
    ]
    fb = false_block_rate(results, {"B01"}, arm="enforce")
    assert fb["deny"] == pytest.approx(0.5)

def test_task_success():
    results = make_results()
    ts = task_success(results, BENIGN_IDS)
    assert ts["enforce"] == pytest.approx(1.0)
    assert ts["unguarded"] == pytest.approx(1.0)

def test_recovery_success():
    results = make_results()
    rs = recovery_success(results, RECOVERY_IDS)
    assert rs == pytest.approx(1.0)

def test_audit_completeness_full():
    results = make_results()
    # All actions have verdicts
    ac = audit_completeness(results)
    assert ac == pytest.approx(1.0)

def test_audit_completeness_partial():
    results = [
        ScenarioResult("A01", "enforce", harm=False, actions=[
            ActionRecord("s1", "DENY", 1, 100.0),
            ActionRecord("s2", None, 2, 200.0),  # no verdict (incomplete)
        ]),
    ]
    ac = audit_completeness(results)
    assert ac == pytest.approx(0.5)

def test_compute_all_metrics():
    results = make_results()
    metrics = compute_all_metrics(
        results,
        attack_ids=ATTACK_IDS,
        detection_ids=ATTACK_IDS,
        benign_ids=BENIGN_IDS,
        recovery_ids=RECOVERY_IDS,
    )
    assert metrics["prevention_rate"] == pytest.approx(1.0)
    assert metrics["harm_rate"]["unguarded"] == pytest.approx(1.0)
    assert metrics["harm_rate"]["enforce"] == pytest.approx(0.0)
    assert metrics["detection_rate"] == pytest.approx(1.0)
    assert metrics["false_block"]["deny"] == pytest.approx(0.0)
    assert metrics["task_success"]["enforce"] == pytest.approx(1.0)
    assert metrics["recovery_success"] == pytest.approx(1.0)
    assert metrics["audit_completeness"] == pytest.approx(1.0)
