import pytest
from agentguard.models.rules import RulePackEnvelope, TrustKey
from agentguard.policy.verifier import RulePackVerifier

def test_verifier_schema_error():
    verifier = RulePackVerifier({})
    # Not JSON
    res = verifier.verify(b"not json", "test")
    assert res["status"] == "error"
    assert res["stage"] == "schema"

def test_verifier_untrusted_key():
    verifier = RulePackVerifier({})
    
    payload = b'{"payload": {"schema_version": 1, "pack_id": "test-pack", "name": "t", "version": "1.0.0", "publisher": "p", "published_at": "2024-01-01T00:00:00Z", "rules": []}, "signature": {"alg": "ed25519", "key_id": "unknown-key", "sig_b64": "xxx"}}'
    
    res = verifier.verify(payload, "test")
    assert res["status"] == "error"
    assert res["stage"] == "trust"
    assert "Key ID not trusted" in res["errors"][0]

def test_verifier_revoked_key():
    trust_keys = {
        "bad-key": TrustKey(
            key_id="bad-key",
            publisher="p",
            public_key_b64="xxx",
            allowed_pack_ids="*",
            not_before="2020",
            added_by="me",
            added_at="2020",
            revoked=True,
            revoked_at="2024"
        )
    }
    verifier = RulePackVerifier(trust_keys)
    
    payload = b'{"payload": {"schema_version": 1, "pack_id": "test-pack", "name": "t", "version": "1.0.0", "publisher": "p", "published_at": "2024-01-01T00:00:00Z", "rules": []}, "signature": {"alg": "ed25519", "key_id": "bad-key", "sig_b64": "xxx"}}'
    
    res = verifier.verify(payload, "test")
    assert res["status"] == "error"
    assert res["stage"] == "trust"
    assert "Key is revoked" in res["errors"][0]
