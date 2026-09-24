"""
AgentGuard Policy Snapshot Compiler (§7.4)
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple
from pydantic import BaseModel

from agentguard.models.policy import PolicyDoc, PluginRef
from agentguard.policy.merge import tighten

class CompiledNetLists:
    """Stub for now, will implement trie matching logic later if needed for net rules"""
    pass

class CompiledRuleSet:
    """Stub for rule set compilation (§6.5)"""
    pass

class LoadedPlugin:
    """Stub for WASM plugin (§7.7)"""
    pass

@dataclass(frozen=True)
class PolicySnapshot:
    doc: PolicyDoc
    policy_hash: str
    rules_hash: str
    ruleset: CompiledRuleSet
    net_lists: CompiledNetLists
    plugins: Tuple[LoadedPlugin, ...]
    sources: Tuple[Dict[str, Any], ...]
    built_at: str

    @property
    def cli(self): return self.doc.cli
    @property
    def net(self): return self.doc.net
    @property
    def fs(self): return self.doc.fs
    @property
    def gui(self): return self.doc.gui
    @property
    def rules(self): return self.doc.rules
    @property
    def grants(self): return self.doc.grants
    @property
    def risk_tiers(self): return self.doc.risk_tiers
    @property
    def mode(self): return self.doc.mode


class SnapshotCache:
    _cache: Dict[Tuple[int, str, str, str], PolicySnapshot] = {}

    @classmethod
    def get(cls, key) -> PolicySnapshot | None:
        return cls._cache.get(key)

    @classmethod
    def set(cls, key, val: PolicySnapshot):
        if len(cls._cache) >= 64:
            # simple eviction
            cls._cache.pop(next(iter(cls._cache)))
        cls._cache[key] = val


def _canonical_json(model: BaseModel) -> str:
    # Deterministic JSON representation
    return model.model_dump_json(exclude_unset=True)


def build_snapshot(
    base: PolicyDoc,
    overlay: Dict[str, Any],
    overrides: Dict[str, Any],
    packs: List[Any],
    now: str
) -> PolicySnapshot:
    """
    Builds the immutable PolicySnapshot (§7.4).
    """
    sources = [{"kind": "base", "version": base.version}]
    
    # 1. Tighten-merge layers
    eff1, ignored_overlay, rej_overlay = tighten(base, overlay)
    if overlay:
        sources.append({"kind": "repo_overlay"})
        
    eff2, ignored_overrides, rej_overrides = tighten(eff1, overrides)
    if overrides:
        sources.append({"kind": "run_overrides"})

    doc = eff2
    
    # 2. If accept_pack_allow_additions is true
    # We will stub this logic since packs aren't fully implemented here
    # (requires active packs and capability 'allow')
    if doc.accept_pack_allow_additions:
        pass # To be implemented when packs are passed properly
    
    # 3. Ensure fs.sensitive_path_globs ⊇ cli.sensitive_path_globs
    union_globs = set(doc.fs.sensitive_path_globs) | set(doc.cli.sensitive_path_globs)
    # Re-assign via a dict update to bypass immutability logic if any, but PolicyDoc is mutable until we freeze
    doc.fs.sensitive_path_globs = list(union_globs)
    doc.cli.sensitive_path_globs = list(union_globs)

    # 4. Compile net_lists & plugins
    net_lists = CompiledNetLists()
    loaded_plugins = tuple()
    
    # 5. Freeze, hash, cache
    rules_hash = "stub" # compute from active packs later
    policy_hash = hashlib.sha256((_canonical_json(doc) + rules_hash).encode('utf-8')).hexdigest()
    
    snap = PolicySnapshot(
        doc=doc, # in reality, should be deeply immutable
        policy_hash=policy_hash,
        rules_hash=rules_hash,
        ruleset=CompiledRuleSet(),
        net_lists=net_lists,
        plugins=loaded_plugins,
        sources=tuple(sources),
        built_at=now
    )
    
    # Cache key: (base_version, overlay_sha, overrides_sha, rules_hash)
    overlay_sha = hashlib.sha256(json.dumps(overlay, sort_keys=True).encode()).hexdigest() if overlay else ""
    overrides_sha = hashlib.sha256(json.dumps(overrides, sort_keys=True).encode()).hexdigest() if overrides else ""
    SnapshotCache.set((base.version, overlay_sha, overrides_sha, rules_hash), snap)
    
    return snap
