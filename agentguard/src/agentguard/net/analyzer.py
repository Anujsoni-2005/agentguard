"""
AgentGuard URL Analyzer §3.5
"""
import urllib.parse
import ipaddress
import socket
import idna
import re
from typing import List, Optional, Tuple

from agentguard.net.models import NetPolicy, NormalizedUrl
from agentguard.models.common import Finding
from agentguard.ids import finding_id
from agentguard.protocols import Analyzer, AnalysisContext

# Ahocorasick trie logic for domain matching
import ahocorasick

def is_mixed_script(host: str) -> bool:
    """Basic mixed script detection (Latin + Cyrillic/Greek)."""
    # A true implementation would use unicodedata.name to check script blocks.
    # For this prototype, we'll do a simple regex check for Cyrillic/Greek
    has_latin = bool(re.search(r'[a-zA-Z]', host))
    has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', host))
    has_greek = bool(re.search(r'[\u0370-\u03FF]', host))
    return has_latin and (has_cyrillic or has_greek)

def build_domain_trie(domains: List[str]) -> ahocorasick.Automaton:
    # Build suffix trie over reversed labels
    # e.g., example.com -> com.example
    # *.example.com -> com.example.*
    trie = ahocorasick.Automaton()
    for d in domains:
        d = d.lower()
        if d.startswith('**.'):
            # match apex and all subdomains
            apex = d[3:]
            trie.add_word(".".join(apex.split('.')[::-1]) + ".__all__", ("**", apex))
        elif d.startswith('*.'):
            apex = d[2:]
            trie.add_word(".".join(apex.split('.')[::-1]) + ".__sub__", ("*", apex))
        else:
            trie.add_word(".".join(d.split('.')[::-1]) + ".__exact__", ("exact", d))
    trie.make_automaton()
    return trie

def check_domain_match(host: str, trie: ahocorasick.Automaton) -> bool:
    # Reverse host labels
    reversed_host = ".".join(host.split('.')[::-1])
    # Very simplified check for prototype: we just check if it matches the trie logic
    # In a full implementation, we'd traverse the trie label by label.
    for kind, apex in trie.values():
        if kind == "exact" and host == apex: return True
        if kind == "*" and host.endswith("." + apex) and host.count('.') == apex.count('.') + 1: return True
        if kind == "**" and (host == apex or host.endswith("." + apex)): return True
    return False

def check_ip_private(ip: ipaddress._BaseAddress) -> bool:
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    # Extra ranges specified in 3.5
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.IPv4Network('192.0.0.0/24') or ip in ipaddress.IPv4Network('198.18.0.0/15'):
            return True
    return False

def normalize_and_check_ip(host: str) -> Tuple[bool, Optional[ipaddress._BaseAddress]]:
    try:
        ip = ipaddress.ip_address(host)
        return True, ip
    except ValueError:
        pass
    
    # Try legacy forms via inet_aton
    try:
        packed = socket.inet_aton(host)
        ip = ipaddress.IPv4Address(packed)
        return True, ip
    except socket.error:
        pass
    return False, None

def evaluate_url(url: str, method: str, policy: NetPolicy, *, resolved_ips: Optional[List[str]] = None) -> Tuple[List[Finding], Optional[NormalizedUrl]]:
    findings = []
    
    # 1. Scheme/Syntax
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    
    if scheme not in policy.allowed_schemes:
        if scheme in ("ws", "wss") and policy.upgrade_websocket:
            pass
        else:
            findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-001", reason_code="NET_SCHEME_DENIED", severity=85, verdict_hint="DENY", message=f"Scheme {scheme} not allowed"))
            
    if "@" in parsed.netloc:
        findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-002", reason_code="NET_USERINFO_IN_URL", severity=85, verdict_hint="DENY", message="Userinfo in URL"))
        
    # Smuggling checks
    host_path = parsed.netloc + parsed.path
    if "\\" in host_path or re.search(r'[\s\x00-\x1F\x7F]', host_path) or "%00" in host_path or "%0d%0a" in host_path.lower():
        findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-002", reason_code="NET_SMUGGLING_DETECTED", severity=85, verdict_hint="DENY", message="Request smuggling detected"))
        
    # 2. Host normalization
    host = parsed.hostname or ""
    host = host.rstrip('.').lower()
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
        
    punycode = host
    is_ip = False
    ip_obj = None
    
    try:
        is_ip, ip_obj = normalize_and_check_ip(host)
        if is_ip:
            punycode = str(ip_obj)
        else:
            # IDNA
            try:
                punycode_bytes = idna.encode(host, uts46=True)
                punycode = punycode_bytes.decode('ascii')
                if is_mixed_script(host) or (host.startswith("xn--") and is_mixed_script(idna.decode(host))):
                    findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-003", reason_code="NET_HOMOGRAPH", severity=85, verdict_hint="DENY", message="Homograph attack detected"))
            except idna.IDNAError:
                findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-003", reason_code="NET_HOMOGRAPH", severity=85, verdict_hint="DENY", message="Invalid IDNA host"))
    except Exception:
        pass
        
    # 3. IP Literal Policy
    if is_ip:
        if policy.block_ip_literals:
            allowed = False
            for cidr in policy.allow_ip_cidrs:
                if ip_obj in ipaddress.ip_network(cidr):
                    allowed = True
                    break
            if not allowed:
                findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-004", reason_code="NET_IP_LITERAL", severity=88, verdict_hint="DENY", message="IP literals blocked"))
                
        if check_ip_private(ip_obj):
            findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-005", reason_code="NET_PRIVATE_RANGE", severity=95, verdict_hint="DENY", message="Private IP range blocked"))
    else:
        if punycode in ("localhost", "metadata.google.internal", "instance-data") or punycode.endswith((".localhost", ".local", ".internal")):
            findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-005", reason_code="NET_PRIVATE_RANGE", severity=95, verdict_hint="DENY", message="Internal hostname blocked"))

    # If steps 2-3 failed, skip 5-6
    garbage_host = any(f.rule_id in ("NET-003", "NET-004", "NET-005") for f in findings)
    
    # 4. Port
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in policy.allowed_ports:
        findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-006", reason_code="NET_PORT_DENIED", severity=80, verdict_hint="DENY", message=f"Port {port} denied"))
        
    # 5. Domain lists
    if not garbage_host and not is_ip:
        deny_trie = build_domain_trie(policy.deny_domains)
        allow_trie = build_domain_trie(policy.allow_domains)
        
        if check_domain_match(punycode, deny_trie):
            findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-007", reason_code="NET_DOMAIN_DENIED", severity=90, verdict_hint="DENY", message="Domain in deny list"))
        elif not check_domain_match(punycode, allow_trie):
            findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-008", reason_code="NET_DOMAIN_NOT_ALLOWLISTED", severity=55, verdict_hint="ASK_HUMAN", message="Domain not allowlisted"))

    # 6. Method
    if not garbage_host:
        method = method.upper()
        if method not in policy.read_methods:
            write_trie = build_domain_trie(policy.write_allow_domains)
            if not (not is_ip and check_domain_match(punycode, write_trie)):
                findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-009", reason_code="NET_METHOD_REQUIRES_APPROVAL", severity=55, verdict_hint="ASK_HUMAN", message="Method requires approval"))
                
    # 8. DNS Pinning
    if resolved_ips:
        for rip in resolved_ips:
            try:
                rip_obj = ipaddress.ip_address(rip)
                if check_ip_private(rip_obj):
                    findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-005", reason_code="NET_PRIVATE_RANGE", severity=95, verdict_hint="DENY", message="Resolved IP in private range"))
            except ValueError:
                pass
                
    # 9. Query/Path Scan (Entropy heuristics)
    path_query = urllib.parse.quote(urllib.parse.unquote(parsed.path)) + ("?" + parsed.query if parsed.query else "")
    if len(url) > 2048:
        # Simplistic entropy check for URL
        from agentguard.net.scanner import shannon_entropy
        if shannon_entropy(path_query) >= 3.8:
            findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-021", reason_code="NET_HIGH_ENTROPY_EGRESS", severity=70, verdict_hint="ASK_HUMAN", message="High entropy in long URL"))
            
    if not is_ip:
        # Check subdomains for entropy > 3.8 and length > 40
        labels = punycode.split('.')
        for label in labels[:-2]: # Skip eTLD+1 roughly
            if len(label) > 40:
                from agentguard.net.scanner import shannon_entropy
                if shannon_entropy(label) >= 3.8:
                    findings.append(Finding(finding_id=finding_id(), source="net", rule_id="NET-021", reason_code="NET_DNS_EXFIL", severity=80, verdict_hint="DENY", message="High entropy subdomain label"))
    
    canonical = f"{scheme}://{punycode}"
    if not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        canonical += f":{port}"
    canonical += urllib.parse.quote(urllib.parse.unquote(parsed.path))
    if parsed.query:
        canonical += "?" + parsed.query
        
    norm_url = NormalizedUrl(
        original=url,
        scheme=scheme,
        host=punycode,
        port=port,
        path=parsed.path,
        query=parsed.query,
        is_ip=is_ip,
        ip=ip_obj,
        canonical=canonical
    )
    
    return findings, norm_url

class NetAnalyzer(Analyzer):
    @property
    def id(self) -> str: return "NetAnalyzer"
    @property
    def timeout_ms(self) -> int: return 100
    
    def analyze(self, ctx: AnalysisContext) -> List[Finding]:
        # Handle dict or proper model depending on serialization state
        params = ctx.action.params
        if isinstance(params, dict):
            url = params.get("url", "")
            method = params.get("method", "GET")
            body_b64 = params.get("body_b64")
        else:
            if not hasattr(params, "url"):
                return []
            url = params.url
            method = params.method
            body_b64 = getattr(params, "body_b64", None)
            
        policy = NetPolicy() # Default policy for now
        findings, norm = evaluate_url(url, method, policy)
        
        if body_b64 and policy.scan_request_bodies:
            import base64
            from agentguard.net.scanner import Redactor
            try:
                body_bytes = base64.b64decode(body_b64)
                body_text = body_bytes.decode('utf-8', errors='replace')
                redactor = Redactor(policy)
                _, body_findings = redactor.scan_and_redact(body_text, "body")
                findings.extend(body_findings)
            except Exception:
                pass
                
        # Scan URL
        from agentguard.net.scanner import Redactor
        redactor = Redactor(policy)
        _, url_findings = redactor.scan_and_redact(url, "url")
        findings.extend(url_findings)
        
        return findings
