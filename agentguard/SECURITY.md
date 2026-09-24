# AgentGuard Security & Honesty

AgentGuard is designed to be an extremely fast and reliable local boundary for LLM agents, intercepting rogue or damaging behaviors *before* they are sent to tools.

## Honest Limits (Scope Boundaries)
AgentGuard evaluates intentions against an observable boundary. It is **NOT**:
1. **A full sandbox replacement:** The Guard assumes that tools like `cli.exec` and `gui.navigate` operate inside an isolated Linux container / VM. It does NOT containerize Python for you. Escaping the underlying Sandbox via zero-days is outside AgentGuard's threat model.
2. **A semantic interpreter:** The Guard evaluates the exact arguments sent. If an LLM uses a benign tool to accomplish a malicious goal by tricking an external API, AgentGuard will only catch it if the URL or arguments trigger the Lexicon or URL blocklist.
3. **An anti-virus engine:** We scan file writes for exact string matches and secrets, but we do not do heuristic malware detection on compiled binaries.

## Security Hardening Checklist (Section 12.5)
Before running AgentGuard in a production environment:

- [ ] **Rotate the Hub Token:** Do not use default `AG_ADMIN_TOKEN` or `AG_AGENT_TOKEN`.
- [ ] **Provision dedicated Ed25519 Keys:** Do not rely on the auto-generated ledger keys for true tamper-evidence in production. Set `AG_LEDGER_PRIVATE_KEY`.
- [ ] **Set explicit proxy boundaries:** Ensure that the underlying `playwright` instances and `python` executors enforce network isolation matching the `NetPolicy`.
- [ ] **Strict O_APPEND filesystems:** The Ledger assumes that the OS prevents malicious truncations by non-root users.
- [ ] **Limit Concurrency:** Tune `AG_MAX_CONCURRENT_RUNS` to prevent DoS attacks against the hub itself.

## Reporting Vulnerabilities
If you discover a bypass in the `Analyzer` logic or a weakness in the `Ledger` cryptography, please report it via [security@example.com] or open a private advisory on GitHub. We aim to respond to high-severity logic bypasses within 48 hours.
