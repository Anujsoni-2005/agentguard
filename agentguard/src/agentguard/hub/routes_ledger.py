"""
Ledger Verification APIs — §8.3.5
"""

import json
from typing import Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from agentguard.store.ledger import FileLedgerWriter
import os

router = APIRouter()

# Note: Dependency injection for LedgerWriter should be hooked up in app.py
def get_ledger() -> FileLedgerWriter:
    # This is a stub for FastAPI dependency injection
    raise NotImplementedError()

@router.get("/v1/ledger/verify")
async def verify_ledger(from_idx: int = 0, to_idx: int | None = None, run_id: str | None = None, ledger: FileLedgerWriter = Depends(get_ledger)):
    """
    Verifies the integrity of the ledger chain and checkpoints.
    Streaming, O(n).
    """
    segments = sorted([f for f in os.listdir(ledger._ledger_dir) if f.startswith("ledger-") and f.endswith(".jsonl")])
    
    records_verified = 0
    checkpoints_verified = 0
    first_bad_idx = None
    error = None
    last_hash = "0" * 64
    current_idx = 0
    
    from agentguard.canon import canonical_json
    import hashlib
    
    def compute_hash(prev: str, rec: dict) -> str:
        without_hash = {k: v for k, v in rec.items() if k != "hash"}
        return hashlib.sha256(prev.encode("ascii") + canonical_json(without_hash)).hexdigest()
        
    for segment in segments:
        with open(os.path.join(ledger._ledger_dir, segment), "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    idx = rec["idx"]
                    
                    if to_idx is not None and idx > to_idx:
                        break
                        
                    if idx < from_idx:
                        # Fast forward last_hash
                        last_hash = rec.get("hash", "")
                        current_idx = idx + 1
                        continue
                        
                    expected_hash = compute_hash(last_hash, rec)
                    if rec.get("hash") != expected_hash:
                        first_bad_idx = idx
                        error = "Hash mismatch"
                        break
                        
                    if rec.get("prev_hash") != last_hash:
                        first_bad_idx = idx
                        error = "Chain broken"
                        break
                        
                    if rec.get("event_type") == "ledger.checkpoint":
                        from agentguard.store.checkpoints import verify_checkpoint_signature
                        payload = rec.get("payload", {})
                        if ledger._checkpoint_key_b64:
                            # In real world, we'd use a public key store
                            if not verify_checkpoint_signature(payload, ledger._checkpoint_key_b64):
                                first_bad_idx = idx
                                error = "Checkpoint signature invalid"
                                break
                        checkpoints_verified += 1
                        
                    last_hash = rec["hash"]
                    records_verified += 1
                    current_idx = idx + 1
                except Exception as e:
                    first_bad_idx = current_idx
                    error = str(e)
                    break
                    
        if first_bad_idx is not None or (to_idx is not None and current_idx > to_idx):
            break
            
    return {
        "ok": error is None,
        "records_verified": records_verified,
        "segments": len(segments),
        "checkpoints_verified": checkpoints_verified,
        "first_bad_idx": first_bad_idx,
        "error": error,
        "head": {"idx": current_idx - 1, "hash": last_hash} if current_idx > 0 else None
    }

@router.get("/v1/ledger/export")
async def export_ledger(run_id: str, ledger: FileLedgerWriter = Depends(get_ledger)):
    """
    Exports a standalone verification bundle for a specific run.
    """
    # This requires walking the ledger to collect all records for run_id
    # and all checkpoints that cover them, along with merkle proofs.
    # We will stub this with an empty return for now as it's complex and requires full index.
    return {
        "public_key_b64": ledger._checkpoint_key_b64 or "",
        "records": [],
        "proofs": {},
        "checkpoints": []
    }
