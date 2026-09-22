"""
Grounding Prefetcher — §10.5
"""

import re
import unicodedata
from typing import Any, List, Dict
from agentguard.decision.obsindex import GroundingFacts, ObservationIndex

def normalize_text(text: str) -> str:
    # NFKC, collapse whitespace, casefold
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r'\s+', ' ', text)
    return text.casefold()

class GroundingPrefetcher:
    def __init__(self, obs_index: ObservationIndex, action_history: List[dict]):
        self.obs_index = obs_index
        self.action_history = {a["action_id"]: a for a in action_history}
        self.quote_min_len = 10

    def prefetch(self, ctx_scratch: Dict[str, Any], evidence_refs: List[dict], rationale: str, current_seq: int) -> GroundingFacts | None:
        facts = GroundingFacts()
        
        # 1. Evidence refs
        for ref in evidence_refs[:10]:
            action_id = ref.get("action_id", "")
            quote = ref.get("quote")
            
            action = self.action_history.get(action_id)
            if not action:
                facts.citations.append({"found_action": False, "executed_ok": False, "quote_found": False, "age_actions": None})
                continue
                
            executed_ok = action.get("status") == "SUCCEEDED"
            age = current_seq - action.get("seq", current_seq)
            
            if quote:
                if len(quote) < self.quote_min_len:
                    quote_found = None
                else:
                    output = action.get("output", "")
                    quote_found = normalize_text(quote) in normalize_text(output)
            else:
                quote_found = None
                
            facts.citations.append({
                "found_action": True,
                "executed_ok": executed_ok,
                "quote_found": quote_found,
                "age_actions": age
            })
            
        # 2. Targets: skip for mock but should extract from ctx
        # 3. fs.write/fs.delete
        # 4. Rationale assertions
        if rationale:
            facts.rationale_assertions = self._check_rationale(rationale, current_seq)
            
        return facts

    def _check_rationale(self, rationale: str, current_seq: int) -> List[dict]:
        assertions = []
        if re.search(r"(?i)\b(all\s+)?(unit\s+)?tests?\s+(now\s+|are\s+|have\s+)?(pass(ed|es|ing)?|green)\b", rationale):
            # Check contradiction: most recent test runner failed
            contradicted = False
            for a in sorted(self.action_history.values(), key=lambda x: x.get("seq", 0), reverse=True):
                if a.get("action_type") == "cli.exec":
                    argv = a.get("argv_norm", [])
                    if argv and argv[0] in ("pytest", "python", "npm", "go", "cargo", "make", "tox"):
                        if a.get("status") in ("FAILED", "TIMED_OUT") or a.get("exit_code", 0) != 0:
                            contradicted = True
                            break
                        if a.get("status") == "SUCCEEDED" and a.get("exit_code", 0) == 0:
                            break # Confirmed pass
            assertions.append({"claim": "tests_pass", "contradicted": contradicted})
            
        return assertions
