"""
AgentGuard Mitmproxy Addon §3.10
"""
from mitmproxy import http, ctx
from agentguard.net.models import NetPolicy, EgressEvent
from agentguard.net.analyzer import evaluate_url
from agentguard.net.scanner import Redactor
from agentguard.net.taint import scan_response
import json
import time
import socket
import os
from agentguard.config import Settings

class AgentGuardProxy:
    def __init__(self):
        # In a real environment, loads from signed file watched by a thread
        self.policy = NetPolicy() 
        self.redactor = Redactor(self.policy)
        
        self.settings = Settings()
        self.eval_hosts = {}
        if self.settings.eval_mode and self.settings.dev_mode and self.settings.env == "dev":
            eval_hosts_env = os.environ.get("AG_EVAL_HOSTS", "{}")
            try:
                self.eval_hosts = json.loads(eval_hosts_env)
            except json.JSONDecodeError:
                pass

    def request(self, flow: http.HTTPFlow):
        # 1. Authenticate (3.4)
        auth = flow.request.headers.get("Proxy-Authorization", "")
        # Dummy authentication check for now
        
        method = flow.request.method
        url = flow.request.url
        
        # 2. CONNECT / SNI checking
        if flow.client_conn.sni and flow.request.host:
            if flow.client_conn.sni.lower().rstrip('.') != flow.request.host.lower().rstrip('.'):
                self._block_flow(flow, "DENY", ["NET_SNI_MISMATCH"])
                return

        # 3. Reject Upgrade: websocket
        if flow.request.headers.get("Upgrade", "").lower() == "websocket" and not self.policy.upgrade_websocket:
            self._block_flow(flow, "DENY", ["NET_SCHEME_DENIED"])
            return

        # 4. evaluate_url and DNS resolving
        # Mock DNS resolution for prototype
        resolved_ips = ["127.0.0.1"]
        
        findings, norm = evaluate_url(url, method, self.policy, resolved_ips=resolved_ips)
        
        # Eval mode override for SSRF
        if self.eval_hosts and flow.request.host in self.eval_hosts:
            findings = [f for f in findings if f.reason_code != "NET_PRIVATE_RANGE"]
            
        # 5. Payload scanner and rate limit
        # (Omitted in this stub, implemented in scanner.py/ratelimit.py)
        
        # 6. Verdict merge
        has_deny = any(f.verdict_hint == "DENY" for f in findings)
        has_ask = any(f.verdict_hint == "ASK_HUMAN" for f in findings)
        
        if has_deny:
            self._block_flow(flow, "DENY", [f.reason_code for f in findings])
            return
        elif has_ask:
            self._block_flow(flow, "ASK_HUMAN", [f.reason_code for f in findings])
            return

    def response(self, flow: http.HTTPFlow):
        content_len = flow.response.headers.get("content-length")
        if content_len and int(content_len) > self.policy.max_response_bytes:
            flow.response = http.Response.make(413, b"Response too large")
            return
            
        content_type = flow.response.headers.get("content-type", "")
        is_textual = any(t in content_type for t in ("text/", "application/json", "application/xml", "+json", "+xml"))
        
        if is_textual and flow.response.text:
            taint = scan_response(content_type, flow.response.text, flow.request.url)
            # In a full implementation, we'd queue an EgressEvent with the taint findings

    def error(self, flow: http.HTTPFlow):
        pass

    def _block_flow(self, flow: http.HTTPFlow, verdict: str, reason_codes: list[str]):
        flow.response = http.Response.make(
            403,
            json.dumps({
                "blocked_by": "agentguard",
                "verdict": verdict,
                "reason_codes": reason_codes,
                "hint": "If this request is required, propose it as a net.http action so a human can approve it."
            }).encode('utf-8'),
            {"Content-Type": "application/json", "X-AgentGuard-Decision": verdict}
        )

addons = [
    AgentGuardProxy()
]
