"""
AgentGuard Taint Tracking §3.8
"""
import re
from typing import List
from dataclasses import dataclass

@dataclass
class TaintScan:
    level: int
    reasons: List[str]
    excerpts: List[str]

TAINT_PATTERNS = [
    ("T1", re.compile(r"ignore (all|any|the)? ?(previous|prior|above|earlier) (instructions?|prompts?|rules?)", re.IGNORECASE), 2),
    ("T2", re.compile(r"disregard (the )?(system|previous|above) (prompt|instructions?)", re.IGNORECASE), 2),
    ("T3", re.compile(r"(you are|act as|pretend to be) (now )?(in )?(developer mode|dan|an? (unrestricted|jailbroken))", re.IGNORECASE), 2),
    ("T4", re.compile(r"(reveal|print|show|send|post|upload|exfiltrate|leak).{0,60}(system prompt|api[_ -]?keys?|secrets?|credentials|passwords?|\.env|ssh key)", re.IGNORECASE), 2),
    ("T5", re.compile(r"new (instructions?|task|objective):|\[\s*(system|assistant|developer)\s*\]|<\s*/?\s*(system|assistant|instructions?)\s*>", re.IGNORECASE), 1),
    ("T6", re.compile(r"[\u200B-\u200F\u2028-\u202E\u2060\uFEFF\u2066-\u2069]{3,}"), 1),
    ("T7", re.compile(r"(display:\s*none|visibility:\s*hidden|font-size:\s*0|opacity:\s*0|aria-hidden|<!--.*?-->).{0,100}(ignore|instruction|assistant|agent|ai\b|llm)", re.IGNORECASE | re.DOTALL), 2),
    ("T8", re.compile(r"(?:<img[^>]+src=|<a[^>]+href=)[\"']([^\"']{30,}|[^\"']*(?:\{\{|\$\{)[^\"']*)[\"']", re.IGNORECASE), 1),
    ("T9", re.compile(r"(execute|run|curl|wget|download and run).{0,40}(this|the following) (command|script|code)", re.IGNORECASE), 1),
    ("T10", re.compile(r"(decode|base64).{0,80}([A-Za-z0-9+/]{200,})", re.IGNORECASE), 1),
]

def scan_response(content_type: str, body_text: str, url: str) -> TaintScan:
    """Scan response text for prompt injection patterns."""
    score = 0
    reasons = []
    excerpts = []
    
    for pid, pattern, weight in TAINT_PATTERNS:
        match = pattern.search(body_text)
        if match:
            score += weight
            reasons.append(pid)
            if len(excerpts) < 3:
                start = max(0, match.start() - 40)
                end = min(len(body_text), match.end() + 40)
                excerpts.append(body_text[start:end])
                
    level = 2 if score >= 3 else 1 if score >= 1 else 0
    return TaintScan(level=level, reasons=reasons, excerpts=excerpts)
