"""
Ledger Checkpoints — §8.3.3
"""

import hashlib
import json
from pydantic import BaseModel
import nacl.signing
import nacl.encoding
from agentguard.canon import canonical_json

class CheckpointRecord(BaseModel):
    first_idx: int
    last_idx: int
    count: int
    merkle_root: str
    prev_checkpoint_hash: str
    key_id: str
    sig_b64: str

def compute_merkle_root(hashes: list[str]) -> str:
    """
    Computes an RFC 6962 style Merkle root.
    Leaves are `sha256(0x00 || bytes.fromhex(record.hash))`.
    Internal nodes are `sha256(0x01 || left || right)`.
    If odd nodes, the last node is promoted unchanged.
    """
    if not hashes:
        return "0" * 64
        
    # Convert hex hashes to leaf nodes
    nodes = []
    for h in hashes:
        leaf_hasher = hashlib.sha256()
        leaf_hasher.update(b"\x00" + bytes.fromhex(h))
        nodes.append(leaf_hasher.digest())
        
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                internal_hasher = hashlib.sha256()
                internal_hasher.update(b"\x01" + nodes[i] + nodes[i+1])
                next_level.append(internal_hasher.digest())
            else:
                next_level.append(nodes[i])
        nodes = next_level
        
    return nodes[0].hex()

def sign_checkpoint(payload: dict, signing_key: nacl.signing.SigningKey) -> tuple[str, str]:
    """
    Signs the canonical JSON of the checkpoint payload (without sig_b64 and key_id).
    Returns (key_id, sig_b64).
    """
    verify_key = signing_key.verify_key
    pub_bytes = verify_key.encode(encoder=nacl.encoding.RawEncoder)
    key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    
    canon = canonical_json(payload)
    signed = signing_key.sign(canon)
    sig_b64 = nacl.encoding.Base64Encoder.encode(signed.signature).decode("ascii")
    
    return key_id, sig_b64

def verify_checkpoint_signature(payload: dict, verify_key_b64: str) -> bool:
    """
    Verifies a checkpoint signature.
    """
    try:
        sig_b64 = payload["sig_b64"]
        sig_bytes = nacl.encoding.Base64Encoder.decode(sig_b64)
        
        canon_payload = {k: v for k, v in payload.items() if k not in ("sig_b64", "key_id")}
        canon = canonical_json(canon_payload)
        
        vk = nacl.signing.VerifyKey(verify_key_b64, encoder=nacl.encoding.Base64Encoder)
        vk.verify(canon, sig_bytes)
        return True
    except Exception:
        return False
