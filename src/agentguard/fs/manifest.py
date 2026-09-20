"""
AgentGuard Workspace Manifest Computation (§4.3.2)
"""
import os
import hashlib
import unicodedata
from typing import Dict, Optional, Tuple, List

from agentguard.models.workspace import ManifestEntry

class WorkspaceTooLargeError(Exception):
    pass

Manifest = Dict[str, ManifestEntry]

def _hash_file(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1048576): # 1 MiB chunks
            hasher.update(chunk)
    return hasher.hexdigest()

def build_manifest(root: str, prev: Optional[Manifest], hash_cache: Dict[str, Tuple[int, int, str]]) -> Manifest:
    """
    Builds a manifest for a given root directory.
    hash_cache maps rel_path -> (size, mtime_ns, sha256)
    """
    manifest: Manifest = {}
    entries_count = 0
    max_entries = 50000

    def scan_dir(current_path: str, rel_prefix: str):
        nonlocal entries_count
        
        try:
            with os.scandir(current_path) as it:
                for entry in it:
                    if entries_count >= max_entries:
                        raise WorkspaceTooLargeError("Manifest exceeded 50,000 entries")
                    
                    name = unicodedata.normalize("NFC", entry.name)
                    rel_path = f"{rel_prefix}/{name}" if rel_prefix else name
                    
                    if rel_path == ".agentguard-internal":
                        continue
                        
                    entries_count += 1
                    stat = entry.stat(follow_symlinks=False)
                    
                    if entry.is_symlink():
                        target = os.readlink(entry.path)
                        manifest[rel_path] = ManifestEntry(k="l", s="", z=0, m=stat.st_mode, l=target)
                    elif entry.is_file(follow_symlinks=False):
                        size = stat.st_size
                        mtime = stat.st_mtime_ns
                        
                        sha256 = ""
                        if rel_path in hash_cache:
                            c_size, c_mtime, c_sha = hash_cache[rel_path]
                            if c_size == size and c_mtime == mtime:
                                sha256 = c_sha
                                
                        if not sha256:
                            try:
                                sha256 = _hash_file(entry.path)
                                hash_cache[rel_path] = (size, mtime, sha256)
                            except OSError:
                                sha256 = "" # unreadable file
                                
                        manifest[rel_path] = ManifestEntry(k="f", s=sha256, z=size, m=stat.st_mode)
                    elif entry.is_dir(follow_symlinks=False):
                        manifest[rel_path] = ManifestEntry(k="d", s="", z=0, m=stat.st_mode)
                        scan_dir(entry.path, rel_path)
        except OSError:
            pass # ignore unreadable directories

    scan_dir(root, "")
    return manifest
