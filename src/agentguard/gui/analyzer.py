"""
GUI Analyzer — §5.5
"""
import re
import unicodedata
from urllib.parse import urlparse
from agentguard.gui.models import ElementFacts, PageFacts, Snapshot
from agentguard.models.policy import GuiPolicy

BENIGN_TERMS = {"cancel", "close", "back", "ok", "no", "dismiss", "learn more"}

def normalize_text(text: str) -> str:
    """Normalize text per §5.5.1"""
    if not text:
        return ""
    # NFKC
    nfkc = unicodedata.normalize("NFKC", text)
    # casefold
    folded = nfkc.casefold()
    # remove zero-width/bidi
    folded = re.sub(r'[\u200B-\u200F\u202A-\u202E]', '', folded)
    # collapse whitespace and strip punctuation/emoji
    folded = re.sub(r'[^\w\s]', ' ', folded)
    folded = re.sub(r'\s+', ' ', folded).strip()
    return folded

def get_tokens(text: str) -> set[str]:
    """Get tokens for matching length >= 3"""
    return {t for t in text.split() if len(t) >= 3}

def tokenize_attribute(text: str) -> set[str]:
    """Split id/class/name/data-* with [-_/. ] and camelCase"""
    if not text:
        return set()
    # Split camelCase
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1 \2', text)
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1 \2', s1).casefold()
    # Split by delimiters
    tokens = re.split(r'[-_/. ]+', s2)
    return {t for t in tokens if t}

def check_lexicon(facts: ElementFacts, policy: GuiPolicy) -> set[str]:
    """Check lexicon hits across all fields §5.5.1"""
    hits = set()
    
    # Text fields
    texts = [facts.name, facts.text, facts.attrs.get("aria-label"), facts.attrs.get("title"), facts.attrs.get("value")]
    normalized_texts = {normalize_text(t) for t in texts if t}
    
    # Attribute fields
    attr_tokens = set()
    for attr in ["id", "class", "name", "data-testid", "data-action"]:
        attr_tokens.update(tokenize_attribute(facts.attrs.get(attr, "")))
        
    # URL paths
    if facts.href_abs:
        parsed = urlparse(facts.href_abs)
        attr_tokens.update(tokenize_attribute(parsed.path))
    if facts.form_action:
        parsed = urlparse(facts.form_action)
        attr_tokens.update(tokenize_attribute(parsed.path))
        
    for category, terms in policy.lexicon.items():
        for term in terms:
            term_norm = normalize_text(term)
            if not term_norm:
                continue
            # Check text exact/word boundary
            for text in normalized_texts:
                if re.search(rf'\b{re.escape(term_norm)}\b', text):
                    hits.add(category)
                    break
            if category in hits:
                continue
            # Check attribute tokens
            if term_norm in attr_tokens:
                hits.add(category)
                
    # Precision guards
    if "publish" in hits and len(hits) == 1:
        if facts.role == "link" and not facts.form_action: # Simplified same-origin check for link
            # Assume it's a plain navigation if no form action
            hits.remove("publish")
        elif facts.role == "textbox":
            hits.remove("publish")
            
    return hits

def name_text_mismatch(facts: ElementFacts, lexicon_hits: set[str]) -> bool:
    """§5.5.3 name_text_mismatch computation"""
    A_raw = facts.attrs.get("aria-label") or facts.attrs.get("title") or facts.name
    V_raw = facts.text
    
    if not A_raw or not V_raw:
        return False
        
    A = normalize_text(A_raw)
    V = normalize_text(V_raw)
    
    if not A or not V:
        return False
        
    A_tokens = get_tokens(A)
    V_tokens = get_tokens(V)
    
    # Mismatch = share no token of length >= 3
    if A_tokens and V_tokens and not A_tokens.intersection(V_tokens):
        # AND (A hits benign while V hits danger, or vice versa)
        A_benign = any(re.search(rf'\b{re.escape(b)}\b', A) for b in BENIGN_TERMS)
        V_benign = any(re.search(rf'\b{re.escape(b)}\b', V) for b in BENIGN_TERMS)
        
        # If one is benign, we need the other to hit a lexicon danger category
        # But for V, we already know if the element hit any danger category via lexicon_hits (approximate, but we can refine)
        # Actually spec: "A hits benign term set while V hits any lexicon category, or vice-versa"
        return (A_benign and bool(lexicon_hits)) or (V_benign and bool(lexicon_hits))
        
    return False

class GuiAnalyzer:
    def __init__(self, policy: GuiPolicy):
        self.policy = policy
        
    def evaluate(self, action_type: str, params: dict, snapshot_found: bool, stale: bool, facts: ElementFacts | None, page: PageFacts) -> dict:
        findings = []
        verdict = "ALLOW"
        severity = 0
        
        # GUI-000
        if facts is None or not snapshot_found:
            return {"verdict": "DENY", "severity": 40, "reasons": ["GUI_STALE_SNAPSHOT"], "next_step": "REPLAN"}
            
        # GUI-080
        if stale:
            return {"verdict": "DENY", "severity": 30, "reasons": ["GUI_STALE_SNAPSHOT"], "next_step": None}
            
        is_state_changing = facts.role in {"button", "link", "menuitem", "checkbox", "switch", "option", "tab"}
        lexicon_hits = check_lexicon(facts, self.policy)
        
        # GUI-010 Deceptive
        if action_type in {"gui.click", "gui.type"}:
            deceptive = False
            if not facts.visible or facts.opacity < 0.05 or facts.bbox[2] < 4 or facts.bbox[3] < 4:
                deceptive = True
            elif action_type == "gui.click" and (not facts.in_viewport or facts.covered):
                deceptive = True
            elif name_text_mismatch(facts, lexicon_hits):
                deceptive = True
                
            if deceptive:
                findings.append(("DENY", 80, "GUI_DECEPTIVE_ELEMENT"))
                
        # GUI-011 Deceptive cross-origin iframe
        if action_type == "gui.click" and is_state_changing:
            # Assuming facts.ancestors would denote if in iframe. Simplification for now.
            pass
            
        # GUI-001 Red zone
        if action_type == "gui.click" and is_state_changing and lexicon_hits:
            for hit in lexicon_hits:
                v, s = self.policy.category_verdicts.get(hit, ("ASK_HUMAN", 50))
                if hit == "financial" and self.policy.block_financial:
                    v, s = "DENY", 85
                findings.append((v, s, f"GUI_RED_ZONE_{hit.upper()}"))
                
                # GUI-002 Form POST modifier
                is_submit = facts.input_type in {"submit", "button", "image"} or (facts.role == "button" and facts.form_method in {"POST", None})
                if is_submit:
                    findings.append((v, min(100, s + 10), f"GUI_RED_ZONE_{hit.upper()}")) # Add +10 severity
                    
        # GUI-030 Cross-origin submit
        if action_type == "gui.click" and (facts.input_type in {"submit", "button", "image"} or facts.form_action):
            target_url = facts.form_action
            if target_url:
                parsed_target = urlparse(target_url)
                parsed_page = urlparse(page.url)
                if parsed_target.hostname and parsed_page.hostname and parsed_target.hostname != parsed_page.hostname:
                    # In full impl, check NetPolicy.allow_domains.
                    findings.append(("ASK_HUMAN", 70, "GUI_CROSS_ORIGIN_SUBMIT"))
                    
        # GUI-031 File upload
        if action_type == "gui.click" and (facts.input_type == "file" or facts.attrs.get("type") == "file"):
            findings.append(("DENY", 80, "GUI_FILE_UPLOAD"))
            
        # GUI-040 Credential typing
        if action_type == "gui.type":
            if facts.input_type == "password" or facts.attrs.get("autocomplete") in {"current-password", "new-password", "cc-number", "cc-csc", "cc-exp", "one-time-code"}:
                if not self.policy.allow_credential_typing:
                    findings.append(("DENY", 85, "GUI_CREDENTIAL_FIELD"))
                    
        # Aggregate findings
        reasons = []
        for v, s, r in findings:
            if v == "DENY":
                verdict = "DENY"
            elif v == "ASK_HUMAN" and verdict != "DENY":
                verdict = "ASK_HUMAN"
            severity = max(severity, s)
            reasons.append(r)
            
        return {"verdict": verdict, "severity": severity, "reasons": list(set(reasons))}
