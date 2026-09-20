"""
AgentGuard Payload Scanning §3.7
"""
import re
import math
from typing import List, Tuple, Dict, Any, Optional
from collections import defaultdict
from agentguard.models.common import Finding
from agentguard.net.models import NetPolicy
from agentguard.ids import finding_id

def luhn_checksum(card_number: str) -> bool:
    digits = [int(x) for x in card_number[::-1]]
    total = sum(digits[0::2])
    for d in digits[1::2]:
        d = d * 2
        total += d if d < 10 else d - 9
    return total % 10 == 0

def luhn_valid(card: str) -> bool:
    clean = re.sub(r'[\s-]', '', card)
    if not (13 <= len(clean) <= 19):
        return False
    # IIN prefix checks
    if not re.match(r'^(4|5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[0-1]\d|2720|34|37|6011|65|35|62|30|36|38)', clean):
        return False
    return luhn_checksum(clean)

def verhoeff_validate(aadhaar: str) -> bool:
    clean = re.sub(r'\s', '', aadhaar)
    if len(clean) != 12: return False
    d = (
        (0,1,2,3,4,5,6,7,8,9),
        (1,2,3,4,0,6,7,8,9,5),
        (2,3,4,0,1,7,8,9,5,6),
        (3,4,0,1,2,8,9,5,6,7),
        (4,0,1,2,3,9,5,6,7,8),
        (5,9,8,7,6,0,4,3,2,1),
        (6,5,9,8,7,1,0,4,3,2),
        (7,6,5,9,8,2,1,0,4,3),
        (8,7,6,5,9,3,2,1,0,4),
        (9,8,7,6,5,4,3,2,1,0)
    )
    p = (
        (0,1,2,3,4,5,6,7,8,9),
        (1,5,7,6,2,8,3,0,9,4),
        (5,8,0,3,7,9,6,1,4,2),
        (8,9,1,6,0,4,3,5,2,7),
        (9,4,5,3,1,2,6,8,7,0),
        (4,2,8,6,5,7,3,9,0,1),
        (2,7,9,3,8,0,6,4,1,5),
        (7,0,4,6,9,1,3,2,5,8)
    )
    inv = (0,4,3,2,1,5,6,7,8,9)
    c = 0
    for i, num in enumerate(clean[::-1]):
        c = d[c][p[i % 8][int(num)]]
    return c == 0

PII_PATTERNS = {
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "aadhaar": re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),
    "pan_in": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws.{0,20}(secret|sk).{0,20}['\":=\s]([A-Za-z0-9/+=]{40})\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)[\"'\s:=]{1,4}([A-Za-z0-9_\-\.]{20,})"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
}

def shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

class Redactor:
    def __init__(self, policy: NetPolicy):
        self.policy = policy

    def scan_and_redact(self, text: str, surface: str) -> Tuple[str, List[Finding]]:
        if not text:
            return text, []
            
        findings = []
        matches_found = defaultdict(list)
        emails = set()
        
        # We need to process sequentially and replace without shifting remaining offsets.
        # A simple way is to replace after finding.
        for kind in self.policy.pii_rules_enabled:
            if kind == "email_bulk":
                for m in PII_PATTERNS["email"].finditer(text):
                    emails.add(m.group(0).lower())
                if len(emails) >= 5:
                    findings.append(self._create_finding(kind, surface, len(emails)))
                    # Replace all emails
                    text = PII_PATTERNS["email"].sub("[REDACTED:email_bulk]", text)
                continue

            if kind not in PII_PATTERNS:
                continue
                
            pattern = PII_PATTERNS[kind]
            
            def repl(m: re.Match) -> str:
                val = m.group(0)
                # Validation rules
                if kind == "credit_card" and not luhn_valid(val): return val
                if kind == "aadhaar" and not verhoeff_validate(val): return val
                if kind == "pan_in" and val[3] not in "PCHFATBLJG": return val
                
                # It's a valid match
                matches_found[kind].append(val)
                return f"[REDACTED:{kind}]"
                
            text = pattern.sub(repl, text)
            
            if matches_found[kind]:
                findings.append(self._create_finding(kind, surface, len(matches_found[kind])))
                
        # High entropy check (optional)
        # Note: In production we'd chunk by non-alnum, but simple regex here:
        for m in re.finditer(r"[A-Za-z0-9+/=_-]{%d,}" % self.policy.entropy_min_len, text):
            val = m.group(0)
            if shannon_entropy(val) >= self.policy.entropy_threshold_bits:
                findings.append(Finding(
                    finding_id=finding_id(), source="net", rule_id="NET-021",
                    reason_code="NET_HIGH_ENTROPY_EGRESS", severity=60, verdict_hint="ASK_HUMAN",
                    message="High entropy token detected",
                    evidence={"surface": surface, "preview": "[REDACTED]"}
                ))
                text = text.replace(val, "[REDACTED:high_entropy]")

        return text, findings

    def _create_finding(self, kind: str, surface: str, count: int) -> Finding:
        verdict = self.policy.pii_verdicts.get(kind, "ASK_HUMAN")
        severity = 90 if verdict == "DENY" else 60
        reason = "NET_PII_EGRESS" if kind in ("ssn","credit_card","aadhaar","pan_in","email_bulk") else "NET_SECRET_EGRESS"
        return Finding(
            finding_id=finding_id(), source="net", rule_id="NET-020",
            reason_code=reason, severity=severity, verdict_hint=verdict,
            message=f"Detected {kind}",
            evidence={"kind": kind, "surface": surface, "count": count, "preview": f"[REDACTED:{kind}]"}
        )
