#!/usr/bin/env python3
"""
Standalone offline verification for AgentGuard ledger bundles.
Usage: verify_bundle.py <bundle.json>
"""

import sys
import json
import hashlib
import nacl.signing
import nacl.encoding

def _round_floats(obj):
    if isinstance(obj, float):
        return round(obj, 6)
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(item) for item in obj]
    return obj

def canonical_json(obj):
    rounded = _round_floats(obj)
    return json.dumps(
        rounded,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

def compute_hash(prev_hash, record_dict):
    without_hash = {k: v for k, v in record_dict.items() if k != "hash"}
    return hashlib.sha256(prev_hash.encode("ascii") + canonical_json(without_hash)).hexdigest()

def verify_merkle_proof(leaf_hash, path, root):
    current = hashlib.sha256(b"\x00" + bytes.fromhex(leaf_hash)).digest()
    for node in path:
        sibling = bytes.fromhex(node["hash"])
        hasher = hashlib.sha256()
        if node["side"] == "L":
            hasher.update(b"\x01" + sibling + current)
        else:
            hasher.update(b"\x01" + current + sibling)
        current = hasher.digest()
    return current.hex() == root

def main():
    if len(sys.argv) < 2:
        print("Usage: verify_bundle.py <bundle.json>")
        sys.exit(1)
        
    bundle_path = sys.argv[1]
    with open(bundle_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
        
    pk_b64 = bundle.get("public_key_b64")
    if not pk_b64:
        print("Error: Missing public key")
        sys.exit(1)
        
    vk = nacl.signing.VerifyKey(pk_b64, encoder=nacl.encoding.Base64Encoder)
    
    # 1. Verify Checkpoints
    checkpoints = {c["idx"]: c for c in bundle.get("checkpoints", [])}
    for c in checkpoints.values():
        sig_b64 = c["sig_b64"]
        sig_bytes = nacl.encoding.Base64Encoder.decode(sig_b64)
        
        canon_payload = {k: v for k, v in c.items() if k not in ("sig_b64", "key_id", "idx")}
        canon = canonical_json(canon_payload)
        
        try:
            vk.verify(canon, sig_bytes)
        except Exception:
            print(f"Error: Invalid signature for checkpoint covering {c.get('first_idx')} - {c.get('last_idx')}")
            sys.exit(1)
            
    # 2. Verify Records
    for rec in bundle.get("records", []):
        idx = str(rec["idx"])
        # Check own hash
        expected_hash = compute_hash(rec["prev_hash"], rec)
        if rec["hash"] != expected_hash:
            print(f"Error: Hash mismatch for record {idx}")
            sys.exit(1)
            
        # Check proof
        proof = bundle.get("proofs", {}).get(idx)
        if not proof:
            print(f"Error: Missing proof for record {idx}")
            sys.exit(1)
            
        cp_idx = proof["checkpoint"]["idx"]
        cp = checkpoints.get(cp_idx)
        if not cp:
            print(f"Error: Checkpoint {cp_idx} missing from bundle")
            sys.exit(1)
            
        if not verify_merkle_proof(rec["hash"], proof["path"], cp["merkle_root"]):
            print(f"Error: Invalid Merkle proof for record {idx}")
            sys.exit(1)
            
    print("OK")
    sys.exit(0)

if __name__ == "__main__":
    main()
