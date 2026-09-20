
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
