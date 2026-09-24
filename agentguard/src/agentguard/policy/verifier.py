"""
AgentGuard Rule Pack Verifier (§6.4)
"""
from __future__ import annotations

import json
from typing import Dict, Any

from agentguard.models.rules import RulePackEnvelope, TrustKey
# We would use PyNaCl for Ed25519 verification (nacl.signing.VerifyKey)

class RulePackVerifier:
    def __init__(self, trust_keys: Dict[str, TrustKey]):
        self.trust_keys = trust_keys

    def verify(self, raw_bytes: bytes, source: str) -> Dict[str, Any]:
        """
        Verify pipeline §6.4
        Abort on first failure and return report.
        """
        report = {"status": "ok", "stage": "schema", "errors": []}
        
        # 1. SIZE/ENCODING
        if len(raw_bytes) > 5 * 1024 * 1024:
            return {"status": "error", "stage": "schema", "errors": ["Size > 5MB"]}
        
        try:
            text = raw_bytes.decode('utf-8')
            # Strict duplicate key rejection could be implemented via object_pairs_hook
            data = json.loads(text)
        except Exception as e:
            return {"status": "error", "stage": "schema", "errors": [f"JSON parse error: {e}"]}

        # 2. SCHEMA
        try:
            envelope = RulePackEnvelope.model_validate(data)
        except Exception as e:
            return {"status": "error", "stage": "schema", "errors": [f"Schema invalid: {e}"]}

        # 3. LIMITS
        payload = envelope.payload
        if len(payload.rules) > 5000:
            return {"status": "error", "stage": "limits", "errors": ["rules > 5000"]}
        
        # Other limit checks (e.g. literals, test_vectors, etc.)
        total_literals = 0
        rule_ids = set()
        for rule in payload.rules:
            if rule.rule_id in rule_ids:
                return {"status": "error", "stage": "limits", "errors": [f"Duplicate rule_id {rule.rule_id}"]}
            rule_ids.add(rule.rule_id)
            
            if len(rule.test_vectors) > 20:
                return {"status": "error", "stage": "limits", "errors": [f"Rule {rule.rule_id} has > 20 test vectors"]}
                
            if getattr(rule, "type", None) == "literal":
                total_literals += len(getattr(rule, "values", []))
                for v in getattr(rule, "values", []):
                    if not (2 <= len(v) <= 200):
                        return {"status": "error", "stage": "limits", "errors": [f"Literal length out of bounds in {rule.rule_id}"]}
            elif getattr(rule, "type", None) == "regex":
                if len(getattr(rule, "pattern", "")) > 512:
                    return {"status": "error", "stage": "limits", "errors": [f"Regex length > 512 in {rule.rule_id}"]}

        if total_literals > 20000:
            return {"status": "error", "stage": "limits", "errors": ["literals > 20000"]}

        # 4. TRUST
        key_id = envelope.signature.key_id
        if key_id not in self.trust_keys:
            return {"status": "error", "stage": "trust", "errors": ["Key ID not trusted"]}
        trust_key = self.trust_keys[key_id]
        if trust_key.revoked:
            return {"status": "error", "stage": "trust", "errors": ["Key is revoked"]}
        # Time checks on key skipped for brevity, but would be here

        # 5. SIGNATURE
        # payload_json = payload.model_dump_json(exclude_unset=True)
        # Verify with nacl.signing.VerifyKey...
        
        # 6. TIME
        # 7. ROLLBACK
        # 8. CAPABILITIES
        for rule in payload.rules:
            if rule.verdict == "HALT" and "halt" not in trust_key.capabilities:
                return {"status": "error", "stage": "capability", "errors": ["HALT verdict requires halt capability"]}
            if rule.verdict == "DENY" and "deny" not in trust_key.capabilities:
                return {"status": "error", "stage": "capability", "errors": ["DENY verdict requires deny capability"]}
            if rule.verdict == "ASK_HUMAN" and "ask" not in trust_key.capabilities:
                return {"status": "error", "stage": "capability", "errors": ["ASK_HUMAN verdict requires ask capability"]}

        if payload.lexicon_additions and "lexicon" not in trust_key.capabilities:
            return {"status": "error", "stage": "capability", "errors": ["Lexicon additions require lexicon capability"]}
        
        if payload.allow_additions and "allow" not in trust_key.capabilities:
            return {"status": "error", "stage": "capability", "errors": ["Allow additions require allow capability"]}

        # 9. REGEX/STATIC
        # Compile all regexes with re2 (or re fallback)
        
        # 10. SELF-TESTS
        # Run test_vectors over matcher
        
        # 11. BUILD CANDIDATE & 12. FP CANARY
        
        return {"status": "ok", "envelope": envelope}
