import re
from typing import Dict, List, Optional
from .ir import RWord, CliPolicy

def resolve_word(node, vars: Dict[str, RWord], policy: CliPolicy) -> RWord:
    """Resolve a tree-sitter node into an RWord"""
    node_type = node.type
    text = node.text.decode("utf-8", errors="replace")
    span = (node.start_byte, node.end_byte)

    if node_type == "word":
        # Handle backslashes
        # A simple replacement for `\x` -> `x`
        res = re.sub(r"\\(.)", r"\1", text)
        res = res.replace("\\\n", "")
        has_glob = bool(re.search(r"(?<!\\)[*?\[]", res))
        kinds = set()
        
        if res.startswith("~"):
            # Very simplistic tilde expansion
            res = policy.sandbox_home + res[1:]
            kinds.add("tilde")
            
        return RWord(text=res, static=True, has_glob=has_glob, kinds=frozenset(kinds), span=span)

    elif node_type == "raw_string":
        # Strip quotes
        if text.startswith("'") and text.endswith("'"):
            text = text[1:-1]
        return RWord(text=text, static=True, has_glob=False, kinds=frozenset(), span=span)

    elif node_type == "string":
        # We need to process children
        static = True
        has_glob = False
        kinds = set()
        out = ""
        for child in node.children:
            if child.type == "string_content":
                part = child.text.decode("utf-8", errors="replace")
                part = re.sub(r'\\(["\\$`])', r'\1', part)
                out += part
            else:
                rw = resolve_word(child, vars, policy)
                out += rw.text
                if not rw.static:
                    static = False
                if rw.has_glob:
                    has_glob = True
                kinds.update(rw.kinds)
                
        return RWord(text=out, static=static, has_glob=has_glob, kinds=frozenset(kinds), span=span)

    elif node_type == "ansi_c_string":
        # Simplistic decode (could be more robust)
        val = text
        if val.startswith("$'") and val.endswith("'"):
            val = val[2:-1]
        val = val.encode("latin1", "backslashreplace").decode("unicode_escape", "replace")
        return RWord(text=val, static=True, has_glob=False, kinds=frozenset(), span=span)

    elif node_type == "concatenation":
        out = ""
        static = True
        has_glob = False
        kinds = set()
        for child in node.children:
            rw = resolve_word(child, vars, policy)
            out += rw.text
            if not rw.static:
                static = False
            if rw.has_glob:
                has_glob = True
            kinds.update(rw.kinds)
        return RWord(text=out, static=static, has_glob=has_glob, kinds=frozenset(kinds), span=span)

    elif node_type in ("simple_expansion", "expansion"):
        # e.g., $VAR or ${VAR}
        var_name = text.lstrip("$").strip("{}")
        
        # Check for modifiers (very simplistic check)
        if any(c in var_name for c in (":", "#", "%", "/", "!", "[", "@", "*", "-")):
            return RWord(text=text, static=False, has_glob=False, kinds=frozenset({"var"}), span=span)
            
        if var_name in ("HOME", "~"):
            return RWord(text=policy.sandbox_home, static=True, has_glob=False, kinds=frozenset(), span=span)
        if var_name == "PWD":
            return RWord(text=policy.workspace_root, static=True, has_glob=False, kinds=frozenset(), span=span)
        if var_name == "USER":
            return RWord(text="agent", static=True, has_glob=False, kinds=frozenset(), span=span)
            
        if var_name in vars and vars[var_name].static:
            val = vars[var_name]
            return RWord(text=val.text, static=True, has_glob=val.has_glob, kinds=val.kinds, span=span)
            
        return RWord(text=text, static=False, has_glob=False, kinds=frozenset({"var"}), span=span)

    elif node_type == "command_substitution":
        return RWord(text=text, static=False, has_glob=False, kinds=frozenset({"cmdsub"}), span=span)
        
    elif node_type == "process_substitution":
        return RWord(text=text, static=False, has_glob=False, kinds=frozenset({"procsub"}), span=span)
        
    elif node_type == "arithmetic_expansion":
        return RWord(text=text, static=False, has_glob=False, kinds=frozenset({"arith"}), span=span)
        
    elif node_type == "brace_expression":
        # Simplified: we do not fully expand it here. 
        # For prototype, we mark it dynamic so that we don't accidentally allow things.
        return RWord(text=text, static=False, has_glob=False, kinds=frozenset({"brace"}), span=span)
        
    elif node_type == "number":
        return RWord(text=text, static=True, has_glob=False, kinds=frozenset(), span=span)

    else:
        # Fallback
        return RWord(text=text, static=False, has_glob=False, kinds=frozenset(), span=span)
