"""
AgentGuard Canary Secrets §3.7.4
"""
import os
import glob
import urllib.parse
import base64
import binascii
import ahocorasick
from typing import List, Set, Tuple
from agentguard.net.scanner import shannon_entropy

class CanaryManager:
    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        self.automaton = ahocorasick.Automaton()
        self.secret_refs = {}
        
    def scan_workspace(self, globs: List[str]):
        secrets = []
        for g in globs:
            # Handle recursive globs
            search_pattern = g
            if g.startswith("**/"):
                search_pattern = g[3:]
                
            for filepath in glob.glob(os.path.join(self.workspace_root, "**", search_pattern), recursive=True):
                if not os.path.isfile(filepath): continue
                if os.path.getsize(filepath) > 1024*1024: continue
                
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line: continue
                        if '=' in line:
                            key, val = line.split('=', 1)
                            val = val.strip(' "\'')
                            if len(val) >= 8 and shannon_entropy(val) >= 2.5:
                                if val.lower() not in ("true","false","localhost","production","development","127.0.0.1"):
                                    secrets.append((key.strip(), val))
                        elif "PRIVATE KEY" in line or len(line) > 20: 
                            if len(line) >= 8 and shannon_entropy(line) >= 2.5:
                                if not line.startswith("-----"):
                                    secrets.append((os.path.basename(filepath), line))

        for key_name, val in secrets:
            variants = self._generate_variants(val)
            for v in variants:
                if v not in self.secret_refs:
                    self.automaton.add_word(v, key_name)
                    self.secret_refs[v] = key_name
                    
        if len(self.secret_refs) > 0:
            self.automaton.make_automaton()

    def _generate_variants(self, val: str) -> Set[str]:
        variants = set()
        v_bytes = val.encode('utf-8')
        
        variants.add(val)
        variants.add(urllib.parse.quote(val))
        variants.add(binascii.hexlify(v_bytes).decode('utf-8'))
        variants.add(val[::-1])
        
        for pad in (b"", b"\x00", b"\x00\x00"):
            b64 = base64.b64encode(pad + v_bytes).decode('utf-8')
            start_idx = 0 if len(pad) == 0 else (2 if len(pad) == 1 else 3)
            core = b64[start_idx:].rstrip('=')
            if len(core) >= 8:
                variants.add(core)
                
            b64_url = base64.urlsafe_b64encode(pad + v_bytes).decode('utf-8')
            core_url = b64_url[start_idx:].rstrip('=')
            if len(core_url) >= 8:
                variants.add(core_url)
                
        return variants

    def find_matches(self, text: str) -> List[str]:
        matches = []
        if len(self.secret_refs) > 0:
            for _, key_name in self.automaton.iter(text):
                matches.append(key_name)
        return list(set(matches))
