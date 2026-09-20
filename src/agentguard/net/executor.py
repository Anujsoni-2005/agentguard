"""
AgentGuard Network Executor §3.9
"""
import httpx
import hashlib
from urllib.parse import urljoin
from typing import Dict, Any, Tuple, List, Optional
from agentguard.net.models import NetPolicy
from agentguard.net.analyzer import evaluate_url
from agentguard.net.taint import scan_response
from agentguard.net.scanner import Redactor

async def execute_http(
    run_id: str, 
    token: str, 
    method: str, 
    url: str, 
    headers: dict, 
    body: Optional[bytes], 
    timeout_s: int, 
    policy: NetPolicy,
    ca_path: str
) -> Tuple[str, Dict[str, Any], bool, List[str], str, bool]:
    
    safe_headers = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in ("proxy-authorization", "connection", "upgrade", "transfer-encoding", "content-length", "host"):
            continue
        if "\r" in v or "\n" in v:
            continue
        safe_headers[k] = v
        
    if "user-agent" not in {k.lower() for k in safe_headers}:
        safe_headers["User-Agent"] = "AgentGuard-Agent/1.0"
        
    proxy_url = f"http://{run_id}:{token}@proxy:8899"
    
    current_url = url
    current_method = method
    redirects = []
    redactor = Redactor(policy)
    
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url, 
            verify=ca_path, 
            follow_redirects=False,
            timeout=httpx.Timeout(timeout_s),
            http2=False
        ) as client:
            
            for hop in range(policy.max_redirects + 1):
                async with client.stream(current_method, current_url, headers=safe_headers, content=body if hop==0 else None) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                        next_url = urljoin(current_url, resp.headers["location"])
                        
                        method_after = current_method
                        if resp.status_code == 303:
                            method_after = "GET"
                        elif resp.status_code in (301, 302) and current_method == "POST":
                            method_after = "GET"
                            
                        findings, _ = evaluate_url(next_url, method_after, policy)
                        if any(f.verdict_hint != "ALLOW" for f in findings):
                            return "FAILED", {"redirect_blocked": [f.reason_code for f in findings], "reason": "NET_REDIRECT_DENIED"}, False, [], "", False
                            
                        if hop == policy.max_redirects:
                            return "FAILED", {"reason": "NET_REDIRECT_LIMIT"}, False, [], "", False
                            
                        redirects.append(next_url)
                        current_url = next_url
                        current_method = method_after
                        continue
                        
                    body_bytes = bytearray()
                    truncated = False
                    async for chunk in resp.aiter_bytes():
                        body_bytes.extend(chunk)
                        if len(body_bytes) > policy.max_response_bytes:
                            body_bytes = body_bytes[:policy.max_response_bytes]
                            truncated = True
                            break
                            
                    content_type = resp.headers.get("content-type", "")
                    is_textual = any(t in content_type for t in ("text/", "application/json", "application/xml", "+json", "+xml"))
                    
                    meta = {
                        "status_code": resp.status_code,
                        "final_url": current_url,
                        "redirects": redirects,
                        "content_type": content_type,
                        "resp_headers": {k: v for k, v in resp.headers.items() if k.lower() in ("content-type", "content-length", "location", "retry-after")}
                    }
                    
                    if is_textual:
                        body_text = body_bytes.decode(errors="replace")
                        body_text, _ = redactor.scan_and_redact(body_text, "body")
                        taint = scan_response(content_type, body_text, current_url)
                        return "SUCCEEDED", meta, taint.level > 0, taint.reasons, body_text, truncated
                    else:
                        meta["body_omitted"] = "binary"
                        meta["body_sha256"] = hashlib.sha256(body_bytes).hexdigest()
                        return "SUCCEEDED", meta, False, [], "", truncated
                        
    except Exception as e:
        return "FAILED", {"error": type(e).__name__, "reason": "EXECUTOR_UNAVAILABLE"}, False, [], "", False
