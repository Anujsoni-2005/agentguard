"""
AgentGuard Workspace Diffing (§4.3.3)
"""
import difflib
import hashlib
from typing import Optional, Dict, Any

def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    
    # Check undecodable percentage
    try:
        sample.decode("utf-8")
        return False
    except UnicodeDecodeError:
        decoded = sample.decode("utf-8", errors="replace")
        undecodable = decoded.count("\ufffd")
        return (undecodable / len(sample)) >= 0.05

def unified_diff(old: Optional[bytes], new: Optional[bytes], path: str) -> Dict[str, Any]:
    old_b = old or b""
    new_b = new or b""
    
    old_sha256 = hashlib.sha256(old_b).hexdigest() if old is not None else None
    new_sha256 = hashlib.sha256(new_b).hexdigest() if new is not None else None
    
    if _is_binary(old_b) or _is_binary(new_b):
        return {
            "binary": True,
            "old_sha256": old_sha256,
            "new_sha256": new_sha256,
            "old_size": len(old_b) if old is not None else None,
            "new_size": len(new_b) if new is not None else None,
            "text": None,
            "added": 0,
            "removed": 0,
            "truncated": False
        }

    old_text = old_b.decode("utf-8", errors="replace")
    new_text = new_b.decode("utf-8", errors="replace")
    
    old_lines = old_text.splitlines(True) if old is not None else []
    new_lines = new_text.splitlines(True) if new is not None else []
    
    fromfile = f"a/{path}" if old is not None else "/dev/null"
    tofile = f"b/{path}" if new is not None else "/dev/null"
    
    diff_gen = difflib.unified_diff(old_lines, new_lines, fromfile=fromfile, tofile=tofile, n=3)
    
    added = 0
    removed = 0
    text_lines = []
    truncated = False
    size = 0
    
    for line in diff_gen:
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
            
        if not truncated:
            text_lines.append(line)
            size += len(line.encode("utf-8"))
            if len(text_lines) >= 4000 or size >= 204800:
                truncated = True
                text_lines.append("\n[... diff truncated by AgentGuard ...]\n")
                
    diff_text = "".join(text_lines)
    
    # Redact secrets (Assuming a global redactor for now or caller applies it)
    # diff_text = Redactor.redact(diff_text)
    
    return {
        "binary": False,
        "old_sha256": old_sha256,
        "new_sha256": new_sha256,
        "old_size": len(old_b) if old is not None else None,
        "new_size": len(new_b) if new is not None else None,
        "text": diff_text,
        "added": added,
        "removed": removed,
        "truncated": truncated
    }
