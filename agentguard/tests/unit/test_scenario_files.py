"""
Tests that all scenario YAML files in eval/scenarios/ validate against ScenarioSpec.
"""
import os
import pytest
from agentguard.eval.loader import load_scenarios

SCENARIOS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "eval", "scenarios"))

def test_all_scenarios_validate():
    """Every YAML in eval/scenarios/ must load without ValidationError."""
    scenarios = load_scenarios(SCENARIOS_DIR)
    assert len(scenarios) > 0, f"No scenarios loaded from {SCENARIOS_DIR}"

def test_mvp_scenarios_present():
    """All required MVP scenarios must be present."""
    scenarios = load_scenarios(SCENARIOS_DIR)
    ids = {s.id for s in scenarios}
    required_mvp = {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A09", "A10",
                    "A16", "A17", "H01", "B01", "B02", "B03", "B05"}
    missing = required_mvp - ids
    assert not missing, f"Missing MVP scenario IDs: {missing}"

def test_all_scenarios_have_expect():
    """Every scenario must have an expect block."""
    scenarios = load_scenarios(SCENARIOS_DIR)
    for s in scenarios:
        assert s.expect, f"Scenario {s.id} has no expect block"

def test_harm_scenarios_have_oracles():
    """Attack scenarios must have harm_oracles."""
    scenarios = load_scenarios(SCENARIOS_DIR)
    attack_ids = {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A09", "A10"}
    for s in scenarios:
        if s.id in attack_ids:
            assert s.harm_oracles, f"Attack scenario {s.id} has no harm_oracles"

def test_scenario_ids_unique():
    """Scenario IDs must be unique."""
    scenarios = load_scenarios(SCENARIOS_DIR)
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids)), "Duplicate scenario IDs found"

def test_eval_list_tiers():
    """Can list scenarios by tier MVP."""
    scenarios = load_scenarios(SCENARIOS_DIR)
    mvp = [s for s in scenarios if s.tier == "MVP"]
    assert len(mvp) >= 12, f"Expected at least 12 MVP scenarios, got {len(mvp)}"
