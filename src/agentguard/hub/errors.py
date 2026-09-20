"""
Error handling — §0.6

Structured error responses in the AgentGuard envelope format.
All non-2xx responses use: {"error":{"code":"..","message":"..","details":{},"request_id":"req_..."}}

A DENY/HALT/ASK_HUMAN verdict is NOT an HTTP error (§0.6).
"""

from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from agentguard.ids import request_id
from agentguard.registry import HTTP_ERROR_STATUS


class AgentGuardError(HTTPException):
    """Structured error with spec-defined code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict | None = None,
        req_id: str | None = None,
    ) -> None:
        status = HTTP_ERROR_STATUS.get(code, 500)
        self.error_body = {
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
                "request_id": req_id or request_id(),
            }
        }
        super().__init__(status_code=status, detail=self.error_body)


async def agentguard_exception_handler(
    request: Request, exc: AgentGuardError
) -> JSONResponse:
    """Return structured error JSON with X-Request-Id header."""
    req_id = exc.error_body["error"]["request_id"]
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.error_body,
        headers={"X-Request-Id": req_id},
    )
