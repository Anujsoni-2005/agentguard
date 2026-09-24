"""
AgentGuard Policy Merge Logic (§7.3)
"""
from __future__ import annotations

import ipaddress
import copy
from typing import Any, Dict, List, Set, TypeVar

from pydantic import BaseModel
from agentguard.registry import Verdict

T = TypeVar('T', bound=BaseModel)


def domain_covers(base_pattern: str, test_pattern: str) -> bool:
    """
    Check if a base domain pattern covers a test pattern (§7.3.2).
    Supported: x.com (exact), *.x.com (sub), **.x.com (deep)
    """
    def parse(p: str) -> tuple[str, str]:
        if p.startswith("**."):
            return "deep", p[3:]
        if p.startswith("*."):
            return "sub", p[2:]
        return "exact", p

    base_kind, base_suffix = parse(base_pattern)
    test_kind, test_suffix = parse(test_pattern)

    if base_kind == "exact":
        return test_kind == "exact" and base_suffix == test_suffix

    if base_kind == "sub":
        if test_kind == "exact":
            if test_suffix.endswith("." + base_suffix):
                prefix = test_suffix[:-len("." + base_suffix)]
                return "." not in prefix
            return False
        if test_kind == "sub":
            return test_suffix == base_suffix
        return False

    if base_kind == "deep":
        if test_kind == "exact":
            return test_suffix == base_suffix or test_suffix.endswith("." + base_suffix)
        if test_kind in ("sub", "deep"):
            return test_suffix == base_suffix or test_suffix.endswith("." + base_suffix)

    return False


def intersect_domains(base: List[str], overlay: List[str]) -> List[str]:
    if not overlay:
        return list(base)
    result = []
    for o in overlay:
        if any(domain_covers(b, o) for b in base):
            result.append(o)
    return result


def intersect_cidrs(base: List[str], overlay: List[str]) -> List[str]:
    if not overlay:
        return list(base)
    result = []
    for o in overlay:
        try:
            o_net = ipaddress.ip_network(o)
        except ValueError:
            continue
        for b in base:
            try:
                b_net = ipaddress.ip_network(b)
                if o_net.subnet_of(b_net):
                    result.append(o)
                    break
            except ValueError:
                continue
    return result


def _is_at_least_as_strict(mode: str, base_val: Any, overlay_val: Any, field_info: Any = None) -> bool:
    if overlay_val is None:
        return True
    
    if mode == "min":
        return overlay_val <= base_val if base_val is not None else True
    elif mode == "max":
        return overlay_val >= base_val if base_val is not None else True
    elif mode == "union":
        if isinstance(base_val, (list, set)) and isinstance(overlay_val, (list, set)):
            return set(base_val).issubset(set(overlay_val))
        return False
    elif mode == "intersect":
        if isinstance(base_val, (list, set)) and isinstance(overlay_val, (list, set)):
            return set(overlay_val).issubset(set(base_val))
        return False
    elif mode == "or":
        return bool(overlay_val) >= bool(base_val)
    elif mode == "and":
        return bool(overlay_val) <= bool(base_val)
    elif mode == "or_allowlist":
        if base_val == "allowlist":
            return True
        return overlay_val == "allowlist"
    elif mode == "stricter_tier_map":
        return True # Handled per-key in merge_field
    elif mode == "stricter_verdict":
        return True # Handled per-key in merge_field
    elif mode == "intersect_domains":
        return set(intersect_domains(base_val, overlay_val)) == set(overlay_val)
    elif mode == "intersect_cidrs":
        return set(intersect_cidrs(base_val, overlay_val)) == set(overlay_val)
    elif mode == "union_map":
        return all(set(base_val.get(k, [])).issubset(set(v)) for k, v in overlay_val.items())
    elif mode == "base_only":
        return base_val == overlay_val
    elif mode == "add_only_rules":
        return True # Handled manually
    elif mode == "stricter_enum":
        if field_info is None or not field_info.json_schema_extra or not isinstance(field_info.json_schema_extra, dict) or "order" not in field_info.json_schema_extra:
            raise ValueError(f"stricter_enum field missing 'order' in json_schema_extra")
        order = field_info.json_schema_extra["order"]
        try:
            b_idx = order.index(base_val)
            o_idx = order.index(overlay_val)
            return bool(o_idx >= b_idx)
        except ValueError:
            return False
    elif mode == "stricter":
        return True # Fallback
    
    return True


def merge_field(mode: str, base_val: Any, overlay_val: Any, field_info: Any = None) -> Any:
    if overlay_val is None:
        return copy.deepcopy(base_val)
    if base_val is None and overlay_val is not None:
        # If base is None but overlay isn't, and mode allows tightening from infinity/any
        if mode in ("min", "max", "intersect", "union", "intersect_domains", "intersect_cidrs"):
            return copy.deepcopy(overlay_val)
        return copy.deepcopy(base_val) # For others, maybe base is strictly None?
        
    if mode == "min":
        if base_val is None: return overlay_val
        return min(base_val, overlay_val)
    elif mode == "max":
        if base_val is None: return overlay_val
        return max(base_val, overlay_val)
    elif mode == "union":
        s = set(base_val) | set(overlay_val)
        return list(s) if isinstance(base_val, list) else s
    elif mode == "intersect":
        s = set(base_val) & set(overlay_val)
        return list(s) if isinstance(base_val, list) else s
    elif mode == "or":
        return bool(base_val) or bool(overlay_val)
    elif mode == "and":
        return bool(base_val) and bool(overlay_val)
    elif mode == "or_allowlist":
        if base_val == "allowlist" or overlay_val == "allowlist":
            return "allowlist"
        return base_val
    elif mode == "stricter_tier_map":
        order = {"auto": 0, "ask_human": 1, "block": 2}
        out = dict(base_val)
        for k, v in overlay_val.items():
            if order.get(v, 0) > order.get(out.get(k, "auto"), 0):
                out[k] = v
        return out
    elif mode == "stricter_verdict":
        order = {"ALLOW": 0, "ASK_HUMAN": 1, "DENY": 2, "HALT": 3}
        out = dict(base_val)
        for k, v in overlay_val.items():
            if order.get(v, 0) > order.get(out.get(k, "ALLOW"), 0):
                out[k] = v
        return out
    elif mode == "intersect_domains":
        return intersect_domains(base_val, overlay_val)
    elif mode == "intersect_cidrs":
        return intersect_cidrs(base_val, overlay_val)
    elif mode == "union_map":
        out = dict(base_val)
        for k, v in overlay_val.items():
            out[k] = list(set(out.get(k, [])) | set(v))
        return out
    elif mode == "base_only":
        return base_val
    elif mode == "stricter_enum":
        if field_info is None or not field_info.json_schema_extra or not isinstance(field_info.json_schema_extra, dict) or "order" not in field_info.json_schema_extra:
            raise ValueError(f"stricter_enum field missing 'order' in json_schema_extra")
        order = field_info.json_schema_extra["order"]
        try:
            b_idx = order.index(base_val)
            o_idx = order.index(overlay_val)
            return overlay_val if o_idx > b_idx else base_val
        except ValueError:
            return base_val
    elif mode == "add_only_rules":
        # For custom_rules, handled in `tighten`
        return base_val
    else:
        return overlay_val


def tighten(base: T, overlay: Dict[str, Any]) -> tuple[T, List[str], List[str]]:
    """
    Tighten-only merge of `overlay` onto `base` (a BaseModel).
    Returns (new_model, ignored_paths, rejected_paths).
    """
    ignored = []
    rejected = []

    def recursive_merge(b_model: BaseModel, o_dict: Dict[str, Any], path_prefix: str) -> BaseModel:
        out_data = b_model.model_dump()
        fields = b_model.model_fields

        for k, v in o_dict.items():
            if k not in fields:
                continue
            
            b_val = getattr(b_model, k)

            if isinstance(v, dict) and isinstance(b_val, BaseModel):
                # Recurse unconditionally into sub-models
                new_sub = recursive_merge(b_val, v, f"{path_prefix}{k}.")
                out_data[k] = new_sub
                continue
                
            field_info = fields[k]
            mode = None
            if field_info.json_schema_extra and isinstance(field_info.json_schema_extra, dict) and "merge" in field_info.json_schema_extra:
                mode = str(field_info.json_schema_extra["merge"])
            
            if mode is None:
                continue # Ignore primitive fields without a merge mode



            # Special case for custom rules
            if mode == "add_only_rules":
                if b_val is None: b_val = []
                base_ids = {r.id for r in b_val}
                new_rules = []
                for r_dict in v:
                    if r_dict.get("id") in base_ids:
                        rejected.append(f"{path_prefix}{k}[id={r_dict.get('id')}]")
                    else:
                        new_rules.append(r_dict)
                out_data[k] = b_val + new_rules
                continue

            if mode == "base_only":
                if v != b_val:
                    rejected.append(f"{path_prefix}{k}")
                continue
            
            # Check if strict
            if not _is_at_least_as_strict(mode, b_val, v, field_info):
                ignored.append(f"{path_prefix}{k}")
                continue
            
            out_data[k] = merge_field(mode, b_val, v, field_info)

        # Validate with the new data
        return b_model.__class__.model_validate(out_data)

    new_model = recursive_merge(base, overlay, "")
    return new_model, ignored, rejected

