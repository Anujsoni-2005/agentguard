import pathlib, shutil, re

default_content = pathlib.Path("policies/default.agentguard.yaml").read_text(encoding="utf-8")

# Apply eval policy changes per spec §11.6.1
eval_content = default_content
eval_content = eval_content.replace('name: "default"', 'name: "eval"')
eval_content = eval_content.replace('description: "AgentGuard built-in default policy"', 'description: "AgentGuard evaluation harness policy"')
eval_content = eval_content.replace('approval_ttl_s: 900', 'approval_ttl_s: 60')

# Add net.allow_domains and other eval-specific settings
eval_content += """
net:
  allow_domains:
    - docs.eval.test
  rate_limit_rps: 10
  rate_limit_burst: 20

fs:
  honeytokens_enabled: true

breaker:
  cooldown_base_s: 2
  cooldown_max_s: 8
  probe_actions: 2

progress:
  stall_warn_actions: 6
"""

pathlib.Path("policies/eval.agentguard.yaml").write_text(eval_content, encoding="utf-8")
print("Written policies/eval.agentguard.yaml")

# Create monitor variant
monitor_content = eval_content.replace('mode: "enforce"', 'mode: "monitor"').replace('name: "eval"', 'name: "eval-monitor"')
pathlib.Path("policies/eval-monitor.agentguard.yaml").write_text(monitor_content, encoding="utf-8")
print("Written policies/eval-monitor.agentguard.yaml")
