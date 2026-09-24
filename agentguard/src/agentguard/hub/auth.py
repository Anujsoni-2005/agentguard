"""
Authentication — §0.9

Three bearer tokens compared with hmac.compare_digest.
Missing/invalid → 401 UNAUTHENTICATED.
Wrong role → 403 FORBIDDEN.
WebSocket: ?token=<admin token>.
"""

from __future__ import annotations

import hmac
from typing import Literal

from fastapi import Depends, HTTPException, Request

import structlog

logger = structlog.get_logger(__name__)

Role = Literal["agent", "admin", "internal"]


def _get_token(request: Request) -> str:
    """Extract bearer token from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "UNAUTHENTICATED", "message": "Missing or invalid Authorization header", "details": {}, "request_id": ""}},
        )
    return auth[7:]


def _resolve_role(token: str, settings: object) -> Role:
    """Resolve a token to a role using hmac.compare_digest."""
    if hmac.compare_digest(token, getattr(settings, "agent_token", "")):
        return "agent"
    if hmac.compare_digest(token, getattr(settings, "admin_token", "")):
        return "admin"
    if hmac.compare_digest(token, getattr(settings, "internal_token", "")):
        return "internal"
    raise HTTPException(
        status_code=401,
        detail={"error": {"code": "UNAUTHENTICATED", "message": "Invalid token", "details": {}, "request_id": ""}},
    )


def require_role(*allowed: Role):
    """FastAPI dependency that checks the caller has one of the allowed roles."""

    async def _check(request: Request) -> Role:
        settings = request.app.state.settings
        token = _get_token(request)
        role = _resolve_role(token, settings)
        if role not in allowed:
            raise HTTPException(
                status_code=403,
                detail={"error": {"code": "FORBIDDEN", "message": f"Role '{role}' not allowed", "details": {}, "request_id": ""}},
            )
        return role

    return Depends(_check)
