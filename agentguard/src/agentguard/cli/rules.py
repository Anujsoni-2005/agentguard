import re
from typing import List, Optional
from agentguard.models.common import Finding
from agentguard.ids import finding_id as gen_finding_id
from .ir import CommandIR, SimpleCmd, CliPolicy
from agentguard.net.models import NetPolicy
from agentguard.net.analyzer import evaluate_url

def _check_honeytokens(ir: CommandIR, run_flags: dict, execution_stdout: str | None = None) -> List[Finding]:
    """CLI-032: honeytoken access — always DENY, never a soft ask."""
    honeytokens = run_flags.get("honeytokens", []) if run_flags else []
    if not honeytokens:
        return []

    findings = []
    hit_paths = set()

    # Hook 1: pre-execution path match (any argv value matching a planted path)
    for cmd in ir.commands:
        for arg in getattr(cmd, "argv", []):
            arg_text = arg.text if hasattr(arg, "text") else str(arg)
            normalized = arg_text
            if normalized.startswith("./"):
                normalized = normalized[2:]
            elif normalized.startswith("/"):
                normalized = normalized[1:]
            print(f"DEBUG HT: normalized={normalized}, hts={[h.get('path') for h in honeytokens]}")
            for ht in honeytokens:
                ht_path = ht.get("path", "")
                ht_norm = ht_path.lstrip("/").removeprefix("./")
                if normalized == ht_norm or normalized.endswith("/" + ht_norm):
                    print(f"DEBUG HT: Match! {ht_path}")
                    hit_paths.add(ht_path)

    # Hook 2 (Prismor-style fallback): post-execution marker scan in stdout,
    # catches indirect/obfuscated reads the path check misses
    if execution_stdout:
        for ht in honeytokens:
            marker = ht.get("marker", "")
            if marker and marker in execution_stdout:
                hit_paths.add(ht.get("path", "<unknown>"))

    if hit_paths:
        findings.append(Finding(
            finding_id=gen_finding_id(), source="cli", rule_id="CLI-032",
            reason_code="FS_HONEYTOKEN_ACCESS", severity=95, verdict_hint="DENY",
            message=f"Access to a planted decoy secret ({', '.join(sorted(hit_paths))}) — compromise indicator",
        ))
    return findings

def evaluate_rules(ir: CommandIR, policy: CliPolicy, net_policy: Optional[NetPolicy] = None, run_flags: Optional[dict] = None) -> List[Finding]:
    findings = []
    if not ir.parse_ok:
        # Covered in prechecks / parser
        pass
        
    for cmd in ir.commands:
        findings.extend(_evaluate_cmd(cmd, policy, ir, net_policy))
        
    findings.extend(_check_honeytokens(ir, run_flags or {}))
    return findings

def _evaluate_cmd(cmd: SimpleCmd, policy: CliPolicy, ir: CommandIR, net_policy: Optional[NetPolicy]) -> List[Finding]:
    findings = []
    
    # CLI-040: Sudo/doas
    if cmd.basename in ("sudo", "doas", "su", "pkexec") or any(w in ("sudo", "doas", "su", "pkexec") for w in cmd.wrappers):
        findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-040", reason_code="CLI_FORBIDDEN_COMMAND", severity=90, verdict_hint="DENY", message="Privilege escalation not allowed"))
        
    # CLI-020a: rm -rf /
    if cmd.basename == "rm":
        has_r = False
        target_root = False
        for arg in cmd.argv:
            if arg.text.startswith("-") and "r" in arg.text:
                has_r = True
            elif arg.text in ("/", policy.sandbox_home, policy.workspace_root) or arg.text.startswith("/*"):
                target_root = True
                
        if has_r and target_root:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-020", reason_code="CLI_DESTRUCTIVE", severity=100, verdict_hint="HALT", message="Destructive recursive remove of root/home"))

    # CLI-010: curl | sh
    if cmd.basename in ("sh", "bash", "zsh", "python", "node", "ruby", "perl"):
        # Very simple check for pipeline
        if cmd.ctx.pipeline_pos is not None and cmd.ctx.pipeline_pos > 0:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-010", reason_code="CLI_PIPE_TO_SHELL", severity=95, verdict_hint="DENY", message="Piping to interpreter"))

    # CLI-013: base64 | sh
    # Covered by pipeline check above for MVP

    # CLI-030: Reading secrets
    if cmd.basename in ("cat", "head", "tail", "less", "more", "grep", "rg"):
        for arg in cmd.argv:
            if not arg.text.startswith("-"):
                # Secret paths
                if "/etc/shadow" in arg.text or "/.ssh/" in arg.text or "/id_rsa" in arg.text:
                    findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-030", reason_code="CLI_READ_SECRET", severity=85, verdict_hint="DENY", message="Reading system secret"))
                elif ".env" in arg.text and policy.ask_on_workspace_secret_files:
                    findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-030", reason_code="CLI_READ_SECRET", severity=55, verdict_hint="ASK_HUMAN", message="Reading workspace secret"))

    # CLI-050: pip install -i
    if cmd.basename == "pip" and any(arg.text == "install" for arg in cmd.argv):
        for arg in cmd.argv:
            if arg.text.startswith("-i") or arg.text.startswith("--index-url") or arg.text.startswith("--extra-index-url"):
                findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-050", reason_code="CLI_UNTRUSTED_PACKAGE", severity=80, verdict_hint="DENY", message="Untrusted package index"))

    # CLI-091: docker run --privileged
    if cmd.basename == "docker" and any(arg.text == "run" for arg in cmd.argv):
        if any(arg.text == "--privileged" or arg.text.startswith("-v") and "/:/host" in arg.text for arg in cmd.argv):
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-091", reason_code="CLI_DOCKER_ESCAPE", severity=90, verdict_hint="DENY", message="Docker escape attempt"))

    # CLI-090: git push --force
    if cmd.basename == "git" and any(arg.text == "push" for arg in cmd.argv):
        if any("force" in arg.text or arg.text.startswith("-f") for arg in cmd.argv):
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-090", reason_code="CLI_DESTRUCTIVE", severity=70, verdict_hint="DENY", message="Force push forbidden"))

    # CLI-080: Network exfiltration via curl/wget/nc
    if cmd.basename in ("curl", "wget", "nc", "socat") or any(w in ("curl", "wget", "nc", "socat") for w in cmd.wrappers):
        is_listener = any(arg.text in ("-l", "-L", "--listen", "-lp") for arg in cmd.argv)
        if is_listener:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-080", reason_code="CLI_REVERSE_SHELL", severity=90, verdict_hint="DENY", message="Network listener setup not allowed"))
        
        if net_policy:
            for arg in cmd.argv:
                if arg.text.startswith("-") or arg.text.startswith("@"):
                    continue
                text = arg.text
                if "." in text or "localhost" in text or "://" in text:
                    url = text if "://" in text else f"http://{text}"
                    net_findings, _ = evaluate_url(url, "GET", net_policy)
                    for f in net_findings:
                        if f.verdict_hint in ("DENY", "HALT", "ASK_HUMAN"):
                            vh = "DENY" if f.verdict_hint == "ASK_HUMAN" else f.verdict_hint
                            findings.append(Finding(
                                finding_id=gen_finding_id(), source="cli", rule_id="CLI-080", 
                                reason_code="CLI_UNTRUSTED_NETWORK", severity=f.severity, 
                                verdict_hint=vh, 
                                message=f"Untrusted network destination in command: {f.message}"
                            ))

    return findings
