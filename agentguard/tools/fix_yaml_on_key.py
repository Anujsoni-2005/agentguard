import os
import re

scenarios_dir = "eval/scenarios"
for fname in sorted(os.listdir(scenarios_dir)):
    if not fname.endswith(".yaml"):
        continue
    path = os.path.join(scenarios_dir, fname)
    with open(path, encoding="utf-8") as f:
        content = f.read()
    # YAML parses bare 'on' key as boolean True. Quote it everywhere.
    # Replace '    on: ' or '    on:\n' with '    "on": '
    pattern = re.compile(r'^(\s+)on:(\s)', re.MULTILINE)
    fixed = pattern.sub(r'\1"on":\2', content)
    if fixed != content:
        with open(path, "w", encoding="utf-8") as f:
            f.write(fixed)
        print("Fixed:", fname)
    else:
        print("No change:", fname)
