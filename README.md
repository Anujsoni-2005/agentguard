# AgentGuard — Autonomous AI System Supervisor and Guardrail

Production-grade backend prototype implementing out-of-band, brokered execution
with deterministic static analysis, a tamper-evident audit ledger, and human-in-the-loop
approval for high-risk agent actions.

## Quick Start

```bash
make setup      # venv + deps + pre-commit
make secrets    # generate AG_* tokens
make up         # docker compose (hub + proxy + sandbox network)
```

## Architecture

See `AGENTGUARD_SPEC_PART_*.md` for the full specification.

## Known Limits (§12.5.2)

1. **Docker socket exposure** — root-equivalent on host; use disposable VM.
2. **Containers are not VMs** — kernel escapes out of scope.
3. **Static shell analysis is not a proof of safety** — sandbox + proxy is the guarantee.
4. **TLS interception** requires CA in sandbox; cert-pinning clients fail closed.
5. **Ledger tamper-evidence, not tamper-proof** — external anchoring is roadmap.
6. **Heuristic checks** can be wrong; they only escalate or advise, never grant power.
7. **Chromium runs with `--no-sandbox`** inside a hardened container.
