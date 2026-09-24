import os
import unicodedata
from typing import List, Dict, Tuple, Optional
import tree_sitter
import tree_sitter_bash

from agentguard.models.common import Finding
from agentguard.ids import finding_id as gen_finding_id
from .ir import CommandIR, SimpleCmd, CmdCtx, Redirect, RWord, CliPolicy
from .resolver import resolve_word

parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))

WRAPPERS = {
    "command": [],
    "builtin": [],
    "exec": ["-a"],
    "env": ["-u", "-C", "-S"],
    "nohup": [],
    "time": ["-f", "-o"],
    "nice": ["-n"],
    "timeout": ["-s", "-k", "POSITIONAL_1"],
    "stdbuf": ["-i", "-o", "-e"],
    "xargs": ["-I", "-n", "-P", "-d", "-L", "-s"],
    "sudo": [], "doas": [], "su": [], "pkexec": []
}

def pre_checks(command: str, policy: CliPolicy) -> List[Finding]:
    findings = []
    
    # a. Length
    if len(command.encode("utf-8")) > policy.max_command_len:
        findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-002", reason_code="CLI_TOO_LONG", severity=70, verdict_hint="DENY", message="Command too long"))
        return findings

    # b. Control chars
    for char in command:
        code = ord(char)
        if code == 0 or (code < 32 and code not in (9, 10, 13)) or code == 0x1b:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-003", reason_code="CLI_CONTROL_CHARS", severity=85, verdict_hint="DENY", message="Control character found"))
            return findings
        if code in range(0x202A, 0x202F) or code in range(0x2066, 0x206A) or code in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-003", reason_code="CLI_CONTROL_CHARS", severity=85, verdict_hint="DENY", message="Bidi or zero-width control character found"))
            return findings

    # c. Unicode compat
    try:
        # Avoid crashing on encode
        command.encode('ascii')
    except UnicodeEncodeError:
        if unicodedata.normalize("NFKC", command) != command:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-004", reason_code="CLI_CONFUSABLE_UNICODE", severity=80, verdict_hint="DENY", message="Confusable unicode found"))
            return findings

    return findings

class CliParser:
    def __init__(self, policy: CliPolicy):
        self.policy = policy
        self.commands: List[SimpleCmd] = []
        self.functions: Dict[str, List[SimpleCmd]] = {}
        self.assigned_vars: Dict[str, RWord] = {}
        self.node_count = 0
        self.max_depth = 0
        self.error_spans = []

    def parse(self, command_str: str) -> Tuple[CommandIR, List[Finding]]:
        findings = pre_checks(command_str, self.policy)
        if any(f.verdict_hint in ("DENY", "HALT") for f in findings):
            return CommandIR(commands=[], functions={}, parse_ok=False, error_spans=[], max_depth=0, node_count=0, assigned_vars={}), findings

        tree = parser.parse(command_str.encode("utf-8"))
        if tree.root_node.has_error:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-001", reason_code="CLI_PARSE_ERROR", severity=60, verdict_hint="ASK_HUMAN", message="Parse error in command"))
            self.error_spans.append((tree.root_node.start_byte, tree.root_node.end_byte))
            # Keep parsing best effort

        ctx = CmdCtx(
            pipeline_id=None, pipeline_pos=None, pipeline_len=None,
            in_subshell=False, in_cmdsub=False, in_procsub=False,
            negated=False, background=False, conditional="none",
            depth=0, origin="top"
        )
        
        try:
            self._walk(tree.root_node, ctx, [])
        except Exception:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-001", reason_code="CLI_PARSE_ERROR", severity=60, verdict_hint="ASK_HUMAN", message="Error during AST walk"))

        ir = CommandIR(
            commands=self.commands,
            functions=self.functions,
            parse_ok=not tree.root_node.has_error,
            error_spans=self.error_spans,
            max_depth=self.max_depth,
            node_count=self.node_count,
            assigned_vars=self.assigned_vars
        )
        
        # Node count check
        if self.node_count > 5000:
            findings.append(Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-002", reason_code="CLI_TOO_LONG", severity=70, verdict_hint="DENY", message="Command AST too large"))

        return ir, findings

    def _walk(self, node, ctx: CmdCtx, redirects: List[Redirect]):
        if ctx.depth > 200:
            return
        
        self.node_count += 1
        self.max_depth = max(self.max_depth, ctx.depth)
        
        t = node.type
        
        if t in ("program", "list", "compound_statement", "do_group"):
            for child in node.children:
                # Naive operator parsing
                if child.type == "&&": ctx.conditional = "and"
                elif child.type == "||": ctx.conditional = "or"
                elif child.type == ";": ctx.conditional = "seq"
                elif child.type == "&": 
                    # Tag previous as background - simplified
                    pass
                else:
                    self._walk(child, ctx, redirects)
        elif t == "subshell":
            new_ctx = CmdCtx(**{**ctx.__dict__, "in_subshell": True, "depth": ctx.depth+1})
            for child in node.children:
                self._walk(child, new_ctx, redirects)
        elif t == "pipeline":
            # Track pipeline pos
            pos = 0
            for child in node.children:
                if child.type == "command":
                    new_ctx = CmdCtx(**{**ctx.__dict__, "pipeline_pos": pos, "pipeline_id": "pip"})
                    self._walk(child, new_ctx, redirects)
                    pos += 1
                else:
                    self._walk(child, ctx, redirects)
        elif t == "negated_command":
            new_ctx = CmdCtx(**{**ctx.__dict__, "negated": True})
            for child in node.children:
                self._walk(child, new_ctx, redirects)
        elif t == "redirected_statement":
            # naive extraction
            body = None
            for child in node.children:
                if child.type == "command":
                    body = child
            if body:
                self._walk(body, ctx, redirects) # We should actually collect redirects here
        elif t == "command":
            self._build_simple_cmd(node, ctx, redirects)
        elif t == "variable_assignment":
            # For simplicity, add to vars (no strict static/dynamic tracking yet)
            pass
        elif t in ("if_statement", "while_statement", "for_statement", "case_statement"):
            for child in node.children:
                self._walk(child, CmdCtx(**{**ctx.__dict__, "depth": ctx.depth+1}), redirects)
        elif t == "function_definition":
            # Get body
            pass
        elif t in ("command_substitution", "process_substitution"):
            new_ctx = CmdCtx(**{**ctx.__dict__, "in_cmdsub": t=="command_substitution", "in_procsub": t=="process_substitution", "origin": "cmdsub", "depth": ctx.depth+1})
            for child in node.children:
                self._walk(child, new_ctx, redirects)
        else:
            for child in node.children:
                self._walk(child, ctx, redirects)

    def _build_simple_cmd(self, node, ctx: CmdCtx, redirects: List[Redirect]):
        cmd_name_node = None
        args = []
        for child in node.children:
            if child.type == "command_name":
                cmd_name_node = child
            elif child.type in ("word", "string", "raw_string", "concatenation", "expansion", "simple_expansion", "ansi_c_string"):
                args.append(child)
        
        if not cmd_name_node:
            return
            
        name_raw = resolve_word(cmd_name_node, self.assigned_vars, self.policy)
        name = name_raw
        
        argv_rwords = [resolve_word(a, self.assigned_vars, self.policy) for a in args]
        
        # unwrapping (simplified)
        wrappers = []
        while name.text.lower() in WRAPPERS and len(argv_rwords) > 0:
            wrappers.append(name.text.lower())
            if name.text.lower() in ("sudo", "su", "doas", "pkexec"):
                break # Don't unwrap
            # pop options... (omitted for brevity in MVP)
            name = argv_rwords.pop(0)

        basename = os.path.basename(name.text).lower()
        if basename.startswith("\\"): basename = basename[1:]
        if basename.endswith(".exe"): basename = basename[:-4]
        if basename.startswith("command "): basename = basename[8:]

        cmd = SimpleCmd(
            name=name,
            name_raw=name_raw,
            basename=basename,
            argv=argv_rwords,
            env_assign={},
            redirects=redirects,
            wrappers=wrappers,
            ctx=ctx,
            span=(node.start_byte, node.end_byte)
        )
        self.commands.append(cmd)
