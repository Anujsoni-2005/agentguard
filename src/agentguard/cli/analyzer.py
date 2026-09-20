import time
from typing import List, Optional
from agentguard.protocols import Analyzer, AnalysisContext
from agentguard.models.common import Finding
from agentguard.ids import finding_id as gen_finding_id
from .ir import CliPolicy
from .parser import CliParser
from .rules import evaluate_rules

class CliAnalyzer(Analyzer):
    def __init__(self, policy: Optional[CliPolicy] = None):
        self.policy = policy or CliPolicy()

    @property
    def id(self) -> str:
        return "cli"

    @property
    def handles(self) -> set[str]:
        return {"cli.exec"}

    @property
    def timeout_ms(self) -> int:
        return 100

    def analyze(self, ctx: AnalysisContext) -> List[Finding]:
        command_str = getattr(ctx.action.params, "command", None)
        if command_str is None and isinstance(ctx.action.params, dict):
            command_str = ctx.action.params.get("command")
            
        if not command_str:
            return [Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-000", reason_code="SCHEMA_INVALID", severity=100, verdict_hint="DENY", message="Missing command")]
        
        parser = CliParser(self.policy)
        ir, parse_findings = parser.parse(command_str)
        
        # Publish IR for later stages
        ctx.scratch["cli_ir"] = ir
        
        if any(f.verdict_hint in ("DENY", "HALT") for f in parse_findings):
            return parse_findings
            
        rule_findings = evaluate_rules(ir, self.policy)
        return parse_findings + rule_findings
