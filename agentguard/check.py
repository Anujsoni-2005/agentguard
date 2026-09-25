import json
import glob
files = sorted(glob.glob(r'E:\New folder\agentguard\results\run-*\results.json'))
with open(files[-1], encoding='utf-8') as f:
    data = json.load(f)
for s in data['scenarios']:
    if s['id'] in ['A01', 'B01']:
        print(f"==== {s['id']} {s['arm']} ====")
        print(json.dumps(s.get('assertion_failures', []), indent=2))
