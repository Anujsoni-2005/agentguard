import pytest
from agentguard.decision.obsindex import ObservationIndex
from agentguard.decision.prefetch import GroundingPrefetcher
from agentguard.decision.grounding import GroundingAnalyzer
from agentguard.models.policy import GroundingPolicy
from agentguard.registry import Verdict

def test_observation_index():
    obs = ObservationIndex("/workspace", "Fix tests", [], {})
    text = "Edited /workspace/src/utils.py and connected to api.example.com."
    obs.extract_and_index(text, 1)
    
    assert "src/utils.py" in obs.paths
    assert "api.example.com" in obs.hosts
    
    t_path = obs.check_grounded("path", "src/utils.py", [])
    assert t_path.grounded == True
    assert t_path.how == "observed"

def test_grounding_analyzer_grd001():
    policy = GroundingPolicy(enabled=True)
    analyzer = GroundingAnalyzer(policy)
    
    # Mock prefetch facts with an invalid citation
    class MockFacts:
        citations = [{"found_action": True, "executed_ok": True, "quote_found": False}]
        targets = []
        rationale_assertions = []
        
    findings = analyzer.analyze(MockFacts(), {"execution"}, "act_1")
    
    assert any(f.rule_id == "GRD-001" for f in findings)
    grd_1 = next(f for f in findings if f.rule_id == "GRD-001")
    assert grd_1.verdict_hint == Verdict.ASK_HUMAN
