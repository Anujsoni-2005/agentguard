from typing import Literal, Union, List, Any, Dict, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator

class PredicateBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
class AllPredicate(PredicateBase):
    op: Literal["all"]
    conditions: List['Predicate'] = Field(min_length=1)

class AnyPredicate(PredicateBase):
    op: Literal["any"]
    conditions: List['Predicate'] = Field(min_length=1)

class NotPredicate(PredicateBase):
    op: Literal["not"]
    condition: 'Predicate'

class ActionTypeInPredicate(PredicateBase):
    op: Literal["action_type_in"]
    values: List[str] = Field(min_length=1)

class SurfaceRegexPredicate(PredicateBase):
    op: Literal["surface_regex"]
    pattern: str
    
    @model_validator(mode="after")
    def validate_re2(self) -> 'SurfaceRegexPredicate':
        try:
            import re2  # type: ignore
        except ImportError:
            raise ValueError("google-re2 library is required for surface_regex predicate")
        try:
            re2.compile(self.pattern)
        except re2.error as e:
            raise ValueError(f"Invalid re2 regex pattern '{self.pattern}': {e}")
        return self

class SurfaceContainsPredicate(PredicateBase):
    op: Literal["surface_contains"]
    value: str

class SurfaceGlobPredicate(PredicateBase):
    op: Literal["surface_glob"]
    pattern: str

class ParamEqPredicate(PredicateBase):
    op: Literal["param_eq"]
    param: str
    value: Any

class ParamInPredicate(PredicateBase):
    op: Literal["param_in"]
    param: str
    values: List[Any]

class HostInPredicate(PredicateBase):
    op: Literal["host_in"]
    hosts: List[str]

class RiskAtLeastPredicate(PredicateBase):
    op: Literal["risk_at_least"]
    threshold: int

class CounterGtePredicate(PredicateBase):
    op: Literal["counter_gte"]
    counter: str
    threshold: int

class TaintGtePredicate(PredicateBase):
    op: Literal["taint_gte"]
    threshold: int

class ConfidenceLtPredicate(PredicateBase):
    op: Literal["confidence_lt"]
    threshold: float

class TimeWindowPredicate(PredicateBase):
    op: Literal["time_window"]
    start_utc_time: str
    end_utc_time: str

class FlagPredicate(PredicateBase):
    op: Literal["flag"]
    name: str
    value: bool

Predicate = Union[
    AllPredicate, AnyPredicate, NotPredicate,
    ActionTypeInPredicate, SurfaceRegexPredicate, SurfaceContainsPredicate, SurfaceGlobPredicate,
    ParamEqPredicate, ParamInPredicate, HostInPredicate, RiskAtLeastPredicate,
    CounterGtePredicate, TaintGtePredicate, ConfidenceLtPredicate, TimeWindowPredicate, FlagPredicate
]

AllPredicate.model_rebuild()
AnyPredicate.model_rebuild()
NotPredicate.model_rebuild()
