import pytest
from pydantic import ValidationError
from agentguard.policy.predicate import (
    Predicate, AllPredicate, AnyPredicate, NotPredicate,
    SurfaceRegexPredicate, SurfaceContainsPredicate
)
from agentguard.models.policy import CustomRule

def test_predicate_valid_nesting():
    # Valid nesting: all -> any -> not -> surface_contains
    rule = CustomRule(
        id="test_rule",
        when={
            "op": "all",
            "conditions": [
                {
                    "op": "any",
                    "conditions": [
                        {
                            "op": "not",
                            "condition": {
                                "op": "surface_contains",
                                "value": "test"
                            }
                        }
                    ]
                }
            ]
        },
        then={"verdict": "DENY", "severity": 50, "message": "msg"}
    )
    assert isinstance(rule.when, AllPredicate)
    assert len(rule.when.conditions) == 1
    assert isinstance(rule.when.conditions[0], AnyPredicate)

def test_predicate_depth_limit():
    # Nesting depth > 6 should fail
    deep_when = {"op": "surface_contains", "value": "x"}
    for _ in range(7):
        deep_when = {"op": "not", "condition": deep_when}
        
    with pytest.raises(ValidationError) as exc_info:
        CustomRule(
            id="test_rule",
            when=deep_when,
            then={"verdict": "DENY", "severity": 50, "message": "msg"}
        )
    assert "Predicate nesting depth exceeds 6" in str(exc_info.value)

def test_predicate_node_limit():
    # Node count > 50 should fail
    conditions = [{"op": "surface_contains", "value": str(i)} for i in range(51)]
    when = {"op": "all", "conditions": conditions}
    
    with pytest.raises(ValidationError) as exc_info:
        CustomRule(
            id="test_rule",
            when=when,
            then={"verdict": "DENY", "severity": 50, "message": "msg"}
        )
    assert "Predicate exceeds max nodes of 50" in str(exc_info.value)

def test_predicate_invalid_regex_rejected_at_validation():
    # If re2 is installed, it should reject catastrophic or invalid regex
    # For testing, we just check an invalid syntax like (missing paren
    with pytest.raises(ValidationError) as exc_info:
        SurfaceRegexPredicate(op="surface_regex", pattern="(abc")
    err_str = str(exc_info.value)
    assert "Invalid re2 regex pattern" in err_str or "google-re2 library is required" in err_str
