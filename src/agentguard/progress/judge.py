"""
LLM Judge Client — §9.7
"""

import json
from typing import Protocol, Literal, Any
from pydantic import BaseModel

class JudgeRaw(BaseModel):
    text: str
    tokens_in: int
    tokens_out: int

class JudgeClient(Protocol):
    async def complete(self, *, system: str, user: str, max_tokens: int, timeout_s: float) -> JudgeRaw: ...

class MockJudgeClient:
    async def complete(self, *, system: str, user: str, max_tokens: int, timeout_s: float) -> JudgeRaw:
        # For testing purposes, mock returning a valid JSON matching criteria.
        # This will be replaced by actual clients (anthropic, openai) in production.
        return JudgeRaw(
            text='{"relevance": 0.8, "on_track": "yes", "reason": "Looks good", "suggested_next": "Continue"}',
            tokens_in=100,
            tokens_out=30
        )

def parse_judge_output(raw: JudgeRaw) -> dict[str, Any] | None:
    try:
        data = json.loads(raw.text)
        if not isinstance(data, dict):
            return None
        
        # Strict schema validation
        allowed_keys = {"relevance", "on_track", "reason", "suggested_next"}
        if set(data.keys()) != allowed_keys:
            return None
            
        rel = float(data["relevance"])
        if not (0.0 <= rel <= 1.0):
            return None
            
        on_track = data["on_track"]
        if on_track not in {"yes", "drifting", "no"}:
            return None
            
        return {
            "relevance": round(rel, 1),
            "on_track": on_track,
            "reason": str(data["reason"])[:200],
            "suggested_next": str(data["suggested_next"])[:200]
        }
    except Exception:
        return None
