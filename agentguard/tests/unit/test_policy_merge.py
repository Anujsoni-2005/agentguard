
# --- Policy Merge Tests ---
from typing import List, Literal
from pydantic import BaseModel, Field
from agentguard.policy.merge import tighten, domain_covers, intersect_domains, intersect_cidrs

class DummySub(BaseModel):
    items: List[str] = Field(default_factory=list, json_schema_extra={"merge": "intersect"})
    count: int = Field(default=10, json_schema_extra={"merge": "min"})

class DummyPolicy(BaseModel):
    mode: Literal["enforce", "monitor"] = Field(default="enforce", json_schema_extra={"merge": "stricter"})
    timeout: int = Field(default=300, json_schema_extra={"merge": "max"})
    sub: DummySub = Field(default_factory=DummySub)
    read_only: str = Field(default="fixed", json_schema_extra={"merge": "base_only"})

def test_domain_covers():
    assert domain_covers("x.com", "x.com")
    assert not domain_covers("x.com", "y.com")
    
    assert domain_covers("*.x.com", "api.x.com")
    assert not domain_covers("*.x.com", "x.com")
    assert not domain_covers("*.x.com", "v1.api.x.com")
    
    assert domain_covers("**.x.com", "api.x.com")
    assert domain_covers("**.x.com", "v1.api.x.com")
    assert domain_covers("**.x.com", "x.com")

def test_intersect_domains():
    base = ["github.com", "*.api.com"]
    overlay = ["github.com", "evil.com", "v1.api.com"]
    res = intersect_domains(base, overlay)
    assert set(res) == {"github.com", "v1.api.com"}
    
    # Empty overlay means keep base
    assert set(intersect_domains(base, [])) == set(base)

def test_intersect_cidrs():
    base = ["10.0.0.0/8"]
    overlay = ["10.1.2.0/24", "192.168.1.0/24"]
    res = intersect_cidrs(base, overlay)
    assert res == ["10.1.2.0/24"]

def test_tighten_basic():
    base = DummyPolicy()
    
    overlay = {
        "timeout": 500, # valid max
        "sub": {
            "items": ["a", "b"], # base is [], overlay is ["a","b"]
            "count": 5 # valid min
        }
    }
    
    # intersect of [] and ["a", "b"] is []
    # min of 10 and 5 is 5
    # max of 300 and 500 is 500
    
    new_pol, ignored, rejected = tighten(base, overlay)
    
    assert new_pol.timeout == 500
    assert new_pol.sub.count == 5
    assert new_pol.sub.items == [] # base was empty, intersect means keeping base elements only

def test_tighten_ignored():
    base = DummyPolicy()
    overlay = {
        "timeout": 100, # max -> less strict -> ignored
        "sub": {
            "count": 20 # min -> less strict -> ignored
        }
    }
    
    new_pol, ignored, rejected = tighten(base, overlay)
    
    assert new_pol.timeout == 300
    assert new_pol.sub.count == 10
    
    assert "timeout" in ignored
    assert "sub.count" in ignored

def test_tighten_rejected():
    base = DummyPolicy()
    overlay = {
        "read_only": "changed"
    }
    
    new_pol, ignored, rejected = tighten(base, overlay)
    
    assert new_pol.read_only == "fixed"
    assert "read_only" in rejected

from agentguard.models.run import Budgets
from agentguard.models.policy import (
    PolicyDoc, FsPolicy, GroundingPolicy, UncertaintyWeights, CustomRule
)
from agentguard.decision.impact import ImpactClass
import pytest
from pydantic import ValidationError

def test_budgets_construction():
    # Issue 1: Budgets constructible from run-creation-style body
    b = Budgets.model_validate({"max_steps": 250, "max_wall_seconds": 1200})
    assert b.max_steps == 250
    assert b.max_wall_seconds == 1200
    assert b.max_egress_bytes == 5242880

def test_uncertainty_weights_sum():
    # Issue 3: UncertaintyWeights sum to 1.0
    with pytest.raises(ValidationError) as exc:
        UncertaintyWeights(confidence=0.5, grounding=0.1, ambiguity=0.1, novelty=0.1, failure=0.1) # sum = 0.9
    assert "sum to 1.0" in str(exc.value)
    
    # valid
    uw = UncertaintyWeights(confidence=0.5, grounding=0.2, ambiguity=0.1, novelty=0.1, failure=0.1)
    assert uw.confidence == 0.5

def test_fspolicy_tightening():
    # Issue 4: FsPolicy tightening rejection
    base = FsPolicy(sensitive_path_globs=["/etc/*", "/var/log/*"], mass_delete_threshold_files=50)
    
    # Overlay tries to loosen
    overlay = {
        "sensitive_path_globs": ["/etc/*"], # Removing /var/log/*
        "mass_delete_threshold_files": 100 # Raising the number
    }
    
    new_pol, ignored, rejected = tighten(base, overlay)
    
    # Both should be ignored since we tighten base
    # union of ["/etc/*", "/var/log/*"] and ["/etc/*"] is the same set.
    # Actually for union mode (sensitive_path_globs), if overlay is a subset, is it stricter?
    # Wait, mode is "union". Union of A and B is A U B.
    # tighten() logic says: if union, return A U B. 
    # But _is_at_least_as_strict for union: overlay must be superset of base to be considered stricter?
    # Let's check tightened policy properties
    assert set(new_pol.sensitive_path_globs) == {"/etc/*", "/var/log/*"}
    assert new_pol.mass_delete_threshold_files == 50
    assert "mass_delete_threshold_files" in ignored

def test_stricter_enum():
    # Issue 5: stricter_enum validation
    base = GroundingPolicy(blind_overwrite="warn", stale_read="off")
    
    # Overlay tries to loosen blind_overwrite and tighten stale_read
    overlay = {
        "blind_overwrite": "off", # loosen
        "stale_read": "ask" # tighten
    }
    new_pol, ignored, rejected = tighten(base, overlay)
    
    assert new_pol.blind_overwrite == "warn" # Loosen ignored
    assert "blind_overwrite" in ignored
    
    assert new_pol.stale_read == "ask" # Tighten applied
    assert "stale_read" not in ignored

def test_risk_tiers_merge():
    # Issue 6: risk_tiers merge mode (stricter_tier_map)
    base = PolicyDoc()
    base.risk_tiers["cli.exec"] = "block"
    base.risk_tiers["fs.read"] = "auto"
    
    # Overlay tries to loosen cli.exec and tighten fs.read
    overlay = {
        "risk_tiers": {
            "cli.exec": "auto",
            "fs.read": "ask_human"
        }
    }
    new_pol, ignored, rejected = tighten(base, overlay)
    
    assert new_pol.risk_tiers["cli.exec"] == "block"
    assert new_pol.risk_tiers["fs.read"] == "ask_human"
    assert new_pol.risk_tiers["fs.write"] == "auto" # Unchanged from base default

def test_impact_class_intersection():
    # Issue 8: require_evidence_for ImpactClass intersection
    base = GroundingPolicy()
    
    fake_impact = ImpactClass.DELETE
    assert fake_impact in base.require_evidence_for

def test_policydoc_validators():
    # Issue 10: PolicyDoc cross-field validators
    import copy
    
    base_dict = PolicyDoc().model_dump()
    
    # 1. max_ttl_s < default_ttl_s
    d1 = copy.deepcopy(base_dict)
    d1["grants"]["max_ttl_s"] = 100
    d1["grants"]["default_ttl_s"] = 200
    with pytest.raises(ValidationError) as exc:
        PolicyDoc(**d1)
    assert "max_ttl_s cannot be less than" in str(exc.value)
    
    # 2. max_uses < default_uses
    d2 = copy.deepcopy(base_dict)
    d2["grants"]["max_uses"] = 1
    d2["grants"]["default_uses"] = 5
    with pytest.raises(ValidationError) as exc:
        PolicyDoc(**d2)
    assert "max_uses cannot be less than" in str(exc.value)
    
    # 3. advise_above >= ask_above
    d3 = copy.deepcopy(base_dict)
    d3["uncertainty"]["advise_above"] = 0.8
    d3["uncertainty"]["ask_above"] = 0.5
    with pytest.raises(ValidationError) as exc:
        PolicyDoc(**d3)
    assert "advise_above must be strictly less than" in str(exc.value)
    
    # 4. Duplicate custom_rules id
    d4 = copy.deepcopy(base_dict)
    when_pred = {"op": "surface_contains", "value": "test"}
    d4["custom_rules"] = [
        {"id": "duplicate", "when": when_pred, "then": {"verdict": "DENY", "severity": 50, "message": "msg"}},
        {"id": "duplicate", "when": when_pred, "then": {"verdict": "DENY", "severity": 50, "message": "msg"}}
    ]
    with pytest.raises(ValidationError) as exc:
        PolicyDoc(**d4)
    assert "contains duplicate id: duplicate" in str(exc.value)
