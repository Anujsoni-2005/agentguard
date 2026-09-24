"""
Observation index & provenance — §10.4
"""

import re
import posixpath
from typing import Literal, Dict, Set, List
from pydantic import BaseModel

class TargetProvenance(BaseModel):
    kind: Literal["path", "host", "url"]
    value: str
    grounded: bool
    how: Literal["observed", "created", "objective", "known", "baseline_only", "none"]
    first_seen_seq: int | None = None

class GroundingFacts(BaseModel):
    citations: list[dict] = []
    targets: list[TargetProvenance] = []
    last_read_sha: dict[str, dict] = {}
    current_sha: dict[str, str | None] = {}
    created_by_agent: list[str] = []
    rationale_assertions: list[dict] = []
    tokens_indexed: int = 0

class ObservationIndex:
    def __init__(self, workspace_root: str, objective: str, known_paths: List[str], baseline_manifest: Dict[str, str]):
        self.workspace_root = workspace_root
        self.objective = objective.lower()
        self.known_paths = [self._normalize_path(p) for p in known_paths]
        self.baseline_manifest = {self._normalize_path(p): sha for p, sha in baseline_manifest.items()}
        
        self.paths: Dict[str, int] = {}
        self.names: Dict[str, int] = {}
        self.hosts: Dict[str, int] = {}
        self.urls: Dict[str, int] = {}
        self.dirs_listed: Set[str] = set()
        
        self.tokens_indexed = 0
        self.index_max_tokens = 100000

    def _normalize_path(self, path: str) -> str:
        if path.startswith(self.workspace_root):
            path = path[len(self.workspace_root):]
        path = posixpath.normpath(path)
        if path.startswith("./"):
            path = path[2:]
        elif path.startswith("/"):
            path = path[1:]
        return path

    def extract_and_index(self, text: str, seq: int):
        # Paths
        path_pattern = r"(?<![\w/.-])(/?(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]+/?)"
        for match in re.finditer(path_pattern, text):
            p = self._normalize_path(match.group(1))
            if p not in self.paths:
                self.paths[p] = seq
                self.tokens_indexed += 1
                
        # Hosts
        host_pattern = r"\b(?:[a-z0-9\-]+\.)+[a-z]{2,}\b"
        for match in re.finditer(host_pattern, text.lower()):
            h = match.group(0)
            if h not in self.hosts:
                self.hosts[h] = seq
                self.tokens_indexed += 1
                
        # URLs
        url_pattern = r"https?://[^\s\"\'<>)]+"
        for match in re.finditer(url_pattern, text):
            u = match.group(0)
            if u not in self.urls:
                self.urls[u] = seq
                self.tokens_indexed += 1
                
    def check_grounded(self, kind: Literal["path", "host", "url"], value: str, created_by_agent: List[str]) -> TargetProvenance:
        if kind == "path":
            p = self._normalize_path(value)
            if p in self.paths:
                return TargetProvenance(kind=kind, value=value, grounded=True, how="observed", first_seen_seq=self.paths[p])
            if p in created_by_agent:
                return TargetProvenance(kind=kind, value=value, grounded=True, how="created")
            if p in self.objective or posixpath.basename(p) in self.objective:
                return TargetProvenance(kind=kind, value=value, grounded=True, how="objective")
            if p in self.known_paths:
                return TargetProvenance(kind=kind, value=value, grounded=True, how="known")
            if p in self.baseline_manifest:
                return TargetProvenance(kind=kind, value=value, grounded=False, how="baseline_only")
            return TargetProvenance(kind=kind, value=value, grounded=False, how="none")
            
        elif kind == "host":
            h = value.lower()
            if h in self.hosts:
                return TargetProvenance(kind=kind, value=value, grounded=True, how="observed", first_seen_seq=self.hosts[h])
            if h in self.objective:
                return TargetProvenance(kind=kind, value=value, grounded=True, how="objective")
            return TargetProvenance(kind=kind, value=value, grounded=False, how="none")
            
        elif kind == "url":
            if value in self.urls:
                return TargetProvenance(kind=kind, value=value, grounded=True, how="observed", first_seen_seq=self.urls[value])
            # Check host grounded and path segment in URL prefix
            # simplified:
            return TargetProvenance(kind=kind, value=value, grounded=False, how="none")
            
        return TargetProvenance(kind=kind, value=value, grounded=False, how="none")
